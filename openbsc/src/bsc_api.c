/* GSM 08.08 like API for OpenBSC. The bridge from MSC to BSC */

/* (C) 2010 by Holger Hans Peter Freyther
 * (C) 2010 by On-Waves
 * (C) 2009 by Harald Welte <laforge@gnumonks.org>
 *
 * All Rights Reserved
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 */

#include <openbsc/bsc_api.h>
#include <openbsc/bsc_rll.h>
#include <openbsc/gsm_data.h>
#include <openbsc/signal.h>
#include <openbsc/abis_rsl.h>
#include <openbsc/chan_alloc.h>
#include <openbsc/handover.h>
#include <openbsc/debug.h>

#include <osmocore/protocol/gsm_08_08.h>

#include <osmocore/talloc.h>

static LLIST_HEAD(sub_connections);

static void rll_ind_cb(struct gsm_lchan *, uint8_t, void *, enum bsc_rllr_ind);
static void send_sapi_reject(struct gsm_subscriber_connection *conn, int link_id);

/* GSM 08.08 3.2.2.33 */
static u_int8_t lchan_to_chosen_channel(struct gsm_lchan *lchan)
{
	u_int8_t channel_mode = 0, channel = 0;

	switch (lchan->tch_mode) {
	case GSM48_CMODE_SPEECH_V1:
	case GSM48_CMODE_SPEECH_EFR:
	case GSM48_CMODE_SPEECH_AMR:
		channel_mode = 0x9;
		break;
	case GSM48_CMODE_SIGN:
		channel_mode = 0x8;
		break;
	case GSM48_CMODE_DATA_14k5:
		channel_mode = 0xe;
		break;
	case GSM48_CMODE_DATA_12k0:
		channel_mode = 0xb;
		break;
	case GSM48_CMODE_DATA_6k0:
		channel_mode = 0xc;
		break;
	case GSM48_CMODE_DATA_3k6:
		channel_mode = 0xd;
		break;
	}

	switch (lchan->type) {
	case GSM_LCHAN_NONE:
		channel = 0x0;
		break;
	case GSM_LCHAN_SDCCH:
		channel = 0x1;
		break;
	case GSM_LCHAN_TCH_F:
		channel = 0x8;
		break;
	case GSM_LCHAN_TCH_H:
		channel = 0x9;
		break;
	case GSM_LCHAN_UNKNOWN:
		LOGP(DMSC, LOGL_ERROR, "Unknown lchan type: %p\n", lchan);
		break;
	}

	return channel_mode << 4 | channel;
}

static u_int8_t chan_mode_to_speech(struct gsm_lchan *lchan)
{
	int mode = 0;

	switch (lchan->tch_mode) {
	case GSM48_CMODE_SPEECH_V1:
		mode = 1;
		break;
	case GSM48_CMODE_SPEECH_EFR:
		mode = 0x11;
		break;
	case GSM48_CMODE_SPEECH_AMR:
		mode = 0x21;
		break;
	case GSM48_CMODE_SIGN:
	case GSM48_CMODE_DATA_14k5:
	case GSM48_CMODE_DATA_12k0:
	case GSM48_CMODE_DATA_6k0:
	case GSM48_CMODE_DATA_3k6:
	default:
		LOGP(DMSC, LOGL_ERROR, "Using non speech mode: %d\n", mode);
		return 0;
		break;
	}

	/* assume to always do AMR HR on any TCH type */
	if (lchan->type == GSM_LCHAN_TCH_H ||
	    lchan->tch_mode == GSM48_CMODE_SPEECH_AMR)
		mode |= 0x4;

        return mode;
}


struct gsm_subscriber_connection *subscr_con_allocate(struct gsm_lchan *lchan)
{
	struct gsm_subscriber_connection *conn;

	conn = talloc_zero(lchan->ts->trx->bts->network, struct gsm_subscriber_connection);
	if (!conn)
		return NULL;

	/* Configure the time and start it so it will be closed */
	conn->lchan = lchan;
	conn->bts = lchan->ts->trx->bts;
	lchan->conn = conn;
	llist_add_tail(&conn->entry, &sub_connections);
	return conn;
}

/* TODO: move subscriber put here... */
void subscr_con_free(struct gsm_subscriber_connection *conn)
{
	struct gsm_lchan *lchan;


	if (!conn)
		return;


	if (conn->subscr) {
		subscr_put(conn->subscr);
		conn->subscr = NULL;
	}


	if (conn->ho_lchan)
		LOGP(DNM, LOGL_ERROR, "The ho_lchan should have been cleared.\n");

	llist_del(&conn->entry);

	lchan = conn->lchan;
	talloc_free(conn);

	if (lchan)
		lchan->conn = NULL;
}

int bsc_api_init(struct gsm_network *network, struct bsc_api *api)
{
	network->bsc_api = api;
	return 0;
}

int gsm0808_submit_dtap(struct gsm_subscriber_connection *conn,
			struct msgb *msg, int link_id)
{
	uint8_t sapi = link_id & 0x7;
	msg->lchan = conn->lchan;
	msg->trx = msg->lchan->ts->trx;

	msg->l3h = msg->data;
	if (conn->lchan->sapis[sapi] == LCHAN_SAPI_UNUSED) {
		OBSC_LINKID_CB(msg) = link_id;
		if (rll_establish(msg->lchan, sapi, rll_ind_cb, msg) != 0) {
			msgb_free(msg);
			send_sapi_reject(conn, link_id);
			return -1;
		}
		return 0;
	} else {
		return rsl_data_request(msg, link_id);
	}
}

/**
 * Send a GSM08.08 Assignment Request. Right now this does not contain the
 * audio codec type or the allowed rates for the config.
 */
int gsm0808_assign_req(struct gsm_subscriber_connection *conn, int chan_type, int audio)
{
	struct bsc_api *api;
	api = conn->bts->network->bsc_api;

	api->assign_fail(conn, 0, NULL);
	return 0;
}

int gsm0808_page(struct gsm_bts *bts, unsigned int page_group, unsigned int mi_len,
		 uint8_t *mi, int chan_type)
{
	return rsl_paging_cmd(bts, page_group, mi_len, mi, chan_type);
}

/* dequeue messages to layer 4 */
int bsc_upqueue(struct gsm_network *net)
{
	struct gsm_mncc *mncc;
	struct msgb *msg;
	int work = 0;

	if (net)
		while ((msg = msgb_dequeue(&net->upqueue))) {
			mncc = (struct gsm_mncc *)msg->data;
			if (net->mncc_recv)
				net->mncc_recv(net, mncc->msg_type, mncc);
			work = 1; /* work done */
			talloc_free(msg);
		}

	return work;
}

static void dispatch_dtap(struct gsm_subscriber_connection *conn,
			  uint8_t link_id, struct msgb *msg)
{
	struct bsc_api *api = msg->lchan->ts->trx->bts->network->bsc_api;
	struct gsm48_hdr *gh;
	uint8_t pdisc;
	int rc;

	if (msgb_l3len(msg) < sizeof(*gh)) {
		LOGP(DMSC, LOGL_ERROR, "Message too short for a GSM48 header.\n");
		return;
	}

	gh = msgb_l3(msg);
	pdisc = gh->proto_discr & 0x0f;
	switch (pdisc) {
	case GSM48_PDISC_RR:
		switch (gh->msg_type) {
		case GSM48_MT_RR_CIPH_M_COMPL:
			if (api->cipher_mode_compl)
				return api->cipher_mode_compl(conn, msg,
						conn->lchan->encr.alg_id);
			break;
		case GSM48_MT_RR_ASS_COMPL:
			LOGP(DMSC, LOGL_ERROR, "Assignment command is not handled.\n");
			break;
		case GSM48_MT_RR_ASS_FAIL:
			LOGP(DMSC, LOGL_ERROR, "Assignment failure is not handled.\n");
			break;
		case GSM48_MT_RR_CHAN_MODE_MODIF_ACK:
			rc = gsm48_rx_rr_modif_ack(msg);
			if (rc < 0 && api->assign_fail) {
				api->assign_fail(conn,
						 GSM0808_CAUSE_NO_RADIO_RESOURCE_AVAILABLE,
						 NULL);
			} else if (rc >= 0 && api->assign_compl)
				api->assign_compl(conn, 0,
						  lchan_to_chosen_channel(conn->lchan),
						  conn->lchan->encr.alg_id,
						  chan_mode_to_speech(conn->lchan));
			return;
			break;
		}
		break;
	case GSM48_PDISC_MM:
		break;
	}

	/* default case */
	if (api->dtap)
		api->dtap(conn, link_id, msg);
}

int gsm0408_rcvmsg(struct msgb *msg, uint8_t link_id)
{
	int rc;
	struct bsc_api *api = msg->lchan->ts->trx->bts->network->bsc_api;
	struct gsm_lchan *lchan;

	lchan = msg->lchan;
	if (lchan->state != LCHAN_S_ACTIVE) {
		LOGP(DRSL, LOGL_ERROR, "Got data in non active state. discarding.\n");
		return -1;
	}


	if (lchan->conn) {
		dispatch_dtap(lchan->conn, link_id, msg);
	} else {
		rc = BSC_API_CONN_POL_REJECT;
		lchan->conn = subscr_con_allocate(msg->lchan);

		if (lchan->conn)
			rc = api->compl_l3(lchan->conn, msg, 0);

		if (rc != BSC_API_CONN_POL_ACCEPT) {
			subscr_con_free(lchan->conn);
			lchan_release(lchan, 0, 0);
		}
	}

	return 0;
}

int gsm0808_cipher_mode(struct gsm_subscriber_connection *conn, int cipher,
			const uint8_t *key, int len, int include_imeisv)
{
	return -1;
}

/*
 * Release all occupied RF Channels but stay around for more.
 */
int gsm0808_clear(struct gsm_subscriber_connection *conn)
{
	if (conn->ho_lchan)
		bsc_clear_handover(conn);

	if (conn->lchan) {
		lchan_release(conn->lchan, 1, 0);
		conn->lchan->conn = NULL;
	}

	conn->lchan = NULL;
	conn->ho_lchan = NULL;
	conn->bts = NULL;

	return 0;
}

static void send_sapi_reject(struct gsm_subscriber_connection *conn, int link_id)
{
	struct bsc_api *api;

	if (!conn)
		return;

	api = conn->bts->network->bsc_api;
	if (!api || !api->sapi_n_reject)
		return;

	api->sapi_n_reject(conn, link_id);
}

static void rll_ind_cb(struct gsm_lchan *lchan, uint8_t link_id, void *_data, enum bsc_rllr_ind rllr_ind)
{
	struct msgb *msg = _data;

	switch (rllr_ind) {
	case BSC_RLLR_IND_EST_CONF:
		rsl_data_request(msg, OBSC_LINKID_CB(msg));
		break;
	case BSC_RLLR_IND_REL_IND:
	case BSC_RLLR_IND_ERR_IND:
	case BSC_RLLR_IND_TIMEOUT:
		send_sapi_reject(lchan->conn, OBSC_LINKID_CB(msg));
		msgb_free(msg);
		break;
	}
}

static int bsc_handle_lchan_signal(unsigned int subsys, unsigned int signal,
				   void *handler_data, void *signal_data)
{
	struct bsc_api *bsc;
	struct gsm_lchan *lchan;
	struct gsm_subscriber_connection *conn;
	int destruct = 1;

	if (subsys != SS_LCHAN || signal != S_LCHAN_UNEXPECTED_RELEASE)
		return 0;

	lchan = (struct gsm_lchan *)signal_data;
	if (!lchan || !lchan->conn)
		return 0;

	bsc = lchan->ts->trx->bts->network->bsc_api;
	if (!bsc)
		return 0;

	conn = lchan->conn;
	if (bsc->clear_request)
		destruct = bsc->clear_request(conn, 0);

	/* now give up all channels */
	if (conn->lchan == lchan)
		conn->lchan = NULL;
	if (conn->ho_lchan == lchan)
		conn->ho_lchan = NULL;
	gsm0808_clear(conn);

	if (destruct)
		subscr_con_free(conn);

	return 0;
}

static __attribute__((constructor)) void on_dso_load_bsc(void)
{
	register_signal_handler(SS_LCHAN, bsc_handle_lchan_signal, NULL);
}
