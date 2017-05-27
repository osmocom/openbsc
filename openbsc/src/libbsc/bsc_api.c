/* GSM 08.08 like API for OpenBSC. The bridge from MSC to BSC */

/* (C) 2010-2011 by Holger Hans Peter Freyther
 * (C) 2010-2011 by On-Waves
 * (C) 2009 by Harald Welte <laforge@gnumonks.org>
 *
 * All Rights Reserved
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include <openbsc/bsc_api.h>
#include <openbsc/bsc_rll.h>
#include <openbsc/gsm_data.h>
#include <openbsc/gsm_subscriber.h>
#include <openbsc/signal.h>
#include <openbsc/abis_rsl.h>
#include <openbsc/chan_alloc.h>
#include <openbsc/handover.h>
#include <openbsc/debug.h>
#include <openbsc/gsm_04_08.h>
#include <openbsc/trau_mux.h>

#include <osmocom/gsm/protocol/gsm_08_08.h>
#include <osmocom/gsm/gsm48.h>

#include <osmocom/core/talloc.h>

#define GSM0808_T10_VALUE    6, 0


static void rll_ind_cb(struct gsm_lchan *, uint8_t, void *, enum bsc_rllr_ind);
static void send_sapi_reject(struct gsm_subscriber_connection *conn, int link_id);
static void handle_release(struct gsm_subscriber_connection *conn, struct bsc_api *bsc, struct  gsm_lchan *lchan);
static void handle_chan_ack(struct gsm_subscriber_connection *conn, struct bsc_api *bsc, struct  gsm_lchan *lchan);
static void handle_chan_nack(struct gsm_subscriber_connection *conn, struct bsc_api *bsc, struct  gsm_lchan *lchan);

/* GSM 08.08 3.2.2.33 */
static uint8_t lchan_to_chosen_channel(struct gsm_lchan *lchan)
{
	uint8_t channel_mode = 0, channel = 0;

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
	default:
		LOGP(DMSC, LOGL_ERROR, "Unknown lchan type: %p\n", lchan);
		break;
	}

	return channel_mode << 4 | channel;
}

static uint8_t chan_mode_to_speech(struct gsm_lchan *lchan)
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

static void assignment_t10_timeout(void *_conn)
{
	struct bsc_api *api;
	struct gsm_subscriber_connection *conn =
		(struct gsm_subscriber_connection *) _conn;

	LOGP(DMSC, LOGL_ERROR, "Assignment T10 timeout on %p\n", conn);

	/*
	 * normal release on the secondary channel but only if the
	 * secondary_channel has not been released by the handle_chan_nack.
	 */
	if (conn->secondary_lchan)
		lchan_release(conn->secondary_lchan, 0, RSL_REL_LOCAL_END);
	conn->secondary_lchan = NULL;

	/* inform them about the failure */
	api = conn->network->bsc_api;
	api->assign_fail(conn, GSM0808_CAUSE_NO_RADIO_RESOURCE_AVAILABLE, NULL);
}

/*! \brief Determine and apply AMR multi-rate configuration to lchan
 *  Determine which AMR multi-rate configuration to use and apply it to
 *  the lchan (so it can be communicated to BTS and MS during channel
 *  activation.
 *  \param[in] conn subscriber connection (used to resolve bsc_api)
 *  \param[out] lchan logical channel to which to apply mr config
 *  \param[in] full_rate whether to use full-rate (1) or half-rate (0) config
 */
static void handle_mr_config(struct gsm_subscriber_connection *conn,
			     struct gsm_lchan *lchan, int full_rate)
{
	struct bsc_api *api;
	api = conn->network->bsc_api;
	struct amr_multirate_conf *mr;
	struct gsm48_multi_rate_conf *mr_conf;

	/* BSC api override for this method, used in OsmoBSC mode with
	 * bsc_mr_config() to use MSC-specific/specified configuration */
	if (api->mr_config)
		return api->mr_config(conn, lchan, full_rate);

	/* NITB case: use the BTS-specic multi-rate configuration from
	 * the vty/configuration file */
	if (full_rate)
		mr = &lchan->ts->trx->bts->mr_full;
	else
		mr = &lchan->ts->trx->bts->mr_half;

	mr_conf = (struct gsm48_multi_rate_conf *) mr->gsm48_ie;
	mr_conf->ver = 1;

	/* default, if no AMR codec defined */
	if (!mr->gsm48_ie[1]) {
		mr_conf->icmi = 1;
		mr_conf->m5_90 = 1;
	}
	/* store encoded MR config IE lchan for both MS (uplink) and BTS
	 * (downlink) directions */
	gsm48_multirate_config(lchan->mr_ms_lv, mr, mr->ms_mode);
	gsm48_multirate_config(lchan->mr_bts_lv, mr, mr->bts_mode);
}

/*
 * Start a new assignment and make sure that it is completed within T10 either
 * positively, negatively or by the timeout.
 *
 *  1.) allocate a new lchan
 *  2.) copy the encryption key and other data from the
 *      old to the new channel.
 *  3.) RSL Channel Activate this channel and wait
 *
 * -> Signal handler for the LCHAN
 *  4.) Send GSM 04.08 assignment command to the MS
 *
 * -> Assignment Complete/Assignment Failure
 *  5.) Release the SDCCH, continue signalling on the new link
 */
static int handle_new_assignment(struct gsm_subscriber_connection *conn, int chan_mode, int full_rate)
{
	struct gsm_lchan *new_lchan;
	int chan_type;

	chan_type = full_rate ? GSM_LCHAN_TCH_F : GSM_LCHAN_TCH_H;

	new_lchan = lchan_alloc(conn->bts, chan_type, 0);

	if (!new_lchan) {
		LOGP(DMSC, LOGL_NOTICE, "No free channel.\n");
		return -1;
	}

	/* copy old data to the new channel */
	memcpy(&new_lchan->encr, &conn->lchan->encr, sizeof(new_lchan->encr));
	new_lchan->ms_power = conn->lchan->ms_power;
	new_lchan->bs_power = conn->lchan->bs_power;
	new_lchan->rqd_ta = conn->lchan->rqd_ta;

	/* copy new data to it */
	new_lchan->tch_mode = chan_mode;
	new_lchan->rsl_cmode = RSL_CMOD_SPD_SPEECH;

	/* handle AMR correctly */
	if (chan_mode == GSM48_CMODE_SPEECH_AMR)
		handle_mr_config(conn, new_lchan, full_rate);

	if (rsl_chan_activate_lchan(new_lchan, 0x1, 0) < 0) {
		LOGP(DHO, LOGL_ERROR, "could not activate channel\n");
		lchan_free(new_lchan);
		return -1;
	}

	/* remember that we have the channel */
	conn->secondary_lchan = new_lchan;
	new_lchan->conn = conn;

	rsl_lchan_set_state(new_lchan, LCHAN_S_ACT_REQ);
	return 0;
}

struct gsm_subscriber_connection *bsc_subscr_con_allocate(struct gsm_lchan *lchan)
{
	struct gsm_subscriber_connection *conn;
	struct gsm_network *net = lchan->ts->trx->bts->network;

	conn = talloc_zero(net, struct gsm_subscriber_connection);
	if (!conn)
		return NULL;

	conn->network = net;
	conn->lchan = lchan;
	conn->bts = lchan->ts->trx->bts;
	conn->via_ran = RAN_GERAN_A;
	lchan->conn = conn;
	llist_add_tail(&conn->entry, &net->subscr_conns);
	return conn;
}

void bsc_subscr_con_free(struct gsm_subscriber_connection *conn)
{
	if (!conn)
		return;


	if (conn->subscr) {
		subscr_put(conn->subscr);
		conn->subscr = NULL;
	}


	if (conn->ho_lchan) {
		LOGP(DNM, LOGL_ERROR, "The ho_lchan should have been cleared.\n");
		conn->ho_lchan->conn = NULL;
	}

	if (conn->lchan) {
		LOGP(DNM, LOGL_ERROR, "The lchan should have been cleared.\n");
		conn->lchan->conn = NULL;
	}

	if (conn->secondary_lchan) {
		LOGP(DNM, LOGL_ERROR, "The secondary_lchan should have been cleared.\n");
		conn->secondary_lchan->conn = NULL;
	}

	llist_del(&conn->entry);
	talloc_free(conn);
}

int bsc_api_init(struct gsm_network *network, struct bsc_api *api)
{
	network->bsc_api = api;
	return 0;
}

/*! \brief process incoming 08.08 DTAP from MSC (send via BTS to MS) */
int gsm0808_submit_dtap(struct gsm_subscriber_connection *conn,
			struct msgb *msg, int link_id, int allow_sacch)
{
	uint8_t sapi;


	if (!conn->lchan) {
		LOGP(DMSC, LOGL_ERROR,
		     "Called submit dtap without an lchan.\n");
		msgb_free(msg);
		return -1;
	}

	sapi = link_id & 0x7;
	msg->lchan = conn->lchan;
	msg->dst = msg->lchan->ts->trx->rsl_link;

	/* If we are on a TCH and need to submit a SMS (on SAPI=3) we need to use the SACH */
	if (allow_sacch && sapi != 0) {
		if (conn->lchan->type == GSM_LCHAN_TCH_F || conn->lchan->type == GSM_LCHAN_TCH_H)
			link_id |= 0x40;
	}

	msg->l3h = msg->data;
	/* is requested SAPI already up? */
	if (conn->lchan->sapis[sapi] == LCHAN_SAPI_UNUSED) {
		/* Establish L2 for additional SAPI */
		OBSC_LINKID_CB(msg) = link_id;
		if (rll_establish(msg->lchan, sapi, rll_ind_cb, msg) != 0) {
			msgb_free(msg);
			send_sapi_reject(conn, link_id);
			return -1;
		}
		return 0;
	} else {
		/* Directly forward via RLL/RSL to BTS */
		return rsl_data_request(msg, link_id);
	}
}

/*
 * \brief Check if the given channel is compatible with the mode/fullrate
 */
static int chan_compat_with_mode(struct gsm_lchan *lchan, int chan_mode, int full_rate)
{
	switch (chan_mode) {
	case GSM48_CMODE_SIGN:
		/* signalling is always possible */
		return 1;
	case GSM48_CMODE_SPEECH_V1:
	case GSM48_CMODE_SPEECH_AMR:
	case GSM48_CMODE_DATA_3k6:
	case GSM48_CMODE_DATA_6k0:
		/* these services can all run on TCH/H, but we may have
		 * an explicit override by the 'full_rate' argument */
		switch (lchan->type) {
		case GSM_LCHAN_TCH_F:
			return 1;
		case GSM_LCHAN_TCH_H:
			if (full_rate)
				return 0;
			else
				return 1;
			break;
		default:
			return 0;
		}
		break;
	case GSM48_CMODE_DATA_12k0:
	case GSM48_CMODE_DATA_14k5:
	case GSM48_CMODE_SPEECH_EFR:
		/* these services all explicitly require a TCH/F */
		if (lchan->type == GSM_LCHAN_TCH_F)
			return 1;
		else
			return 0;
		break;
	}

	return 0;
}

/**
 * Send a GSM08.08 Assignment Request. Right now this does not contain the
 * audio codec type or the allowed rates for the config. It is assumed that
 * this is for audio handling only. In case the current channel does not allow
 * the selected mode a new one will be allocated.
 *
 * TODO: Add multirate configuration, make it work for more than audio.
 */
int gsm0808_assign_req(struct gsm_subscriber_connection *conn, int chan_mode, int full_rate)
{
	struct bsc_api *api;
	api = conn->network->bsc_api;

	if (!chan_compat_with_mode(conn->lchan, chan_mode, full_rate)) {
		if (handle_new_assignment(conn, chan_mode, full_rate) != 0)
			goto error;
	} else {
		if (chan_mode == GSM48_CMODE_SPEECH_AMR)
			handle_mr_config(conn, conn->lchan, full_rate);

		LOGP(DMSC, LOGL_NOTICE,
		     "Sending %s ChanModify for speech: %s on channel %s\n",
		     gsm_lchan_name(conn->lchan),
		     get_value_string(gsm48_chan_mode_names, chan_mode),
		     get_value_string(gsm_chan_t_names, conn->lchan->type));
		gsm48_lchan_modify(conn->lchan, chan_mode);
	}

	/* we will now start the timer to complete the assignment */
	osmo_timer_setup(&conn->T10, assignment_t10_timeout, conn);
	osmo_timer_schedule(&conn->T10, GSM0808_T10_VALUE);
	return 0;

error:
	api->assign_fail(conn, 0, NULL);
	return -1;
}

int gsm0808_page(struct gsm_bts *bts, unsigned int page_group, unsigned int mi_len,
		 uint8_t *mi, int chan_type)
{
	return rsl_paging_cmd(bts, page_group, mi_len, mi, chan_type, false);
}

static void handle_ass_compl(struct gsm_subscriber_connection *conn,
			     struct msgb *msg)
{
	struct gsm48_hdr *gh;
	struct bsc_api *api = conn->network->bsc_api;

	if (conn->secondary_lchan != msg->lchan) {
		LOGP(DMSC, LOGL_ERROR, "Assignment Compl should occur on second lchan.\n");
		return;
	}

	gh = msgb_l3(msg);
	if (msgb_l3len(msg) - sizeof(*gh) != 1) {
		LOGP(DMSC, LOGL_ERROR, "Assignment Compl invalid: %zu\n",
		     msgb_l3len(msg) - sizeof(*gh));
		return;
	}

	/* switch TRAU muxer for E1 based BTS from one channel to another */
	if (is_e1_bts(conn->bts))
		switch_trau_mux(conn->lchan, conn->secondary_lchan);

	/* swap channels */
	osmo_timer_del(&conn->T10);

	lchan_release(conn->lchan, 0, RSL_REL_LOCAL_END);
	conn->lchan = conn->secondary_lchan;
	conn->secondary_lchan = NULL;

	if (is_ipaccess_bts(conn->bts) && conn->lchan->tch_mode != GSM48_CMODE_SIGN)
		rsl_ipacc_crcx(conn->lchan);

	api->assign_compl(conn, gh->data[0],
			  lchan_to_chosen_channel(conn->lchan),
			  conn->lchan->encr.alg_id,
			  chan_mode_to_speech(conn->lchan));
}

static void handle_ass_fail(struct gsm_subscriber_connection *conn,
			    struct msgb *msg)
{
	struct bsc_api *api = conn->network->bsc_api;
	uint8_t *rr_failure;
	struct gsm48_hdr *gh;


	if (conn->lchan != msg->lchan) {
		LOGP(DMSC, LOGL_ERROR, "Assignment failure should occur on primary lchan.\n");
		return;
	}

	/* stop the timer and release it */
	osmo_timer_del(&conn->T10);
	lchan_release(conn->secondary_lchan, 0, RSL_REL_LOCAL_END);
	conn->secondary_lchan = NULL;

	gh = msgb_l3(msg);
	if (msgb_l3len(msg) - sizeof(*gh) != 1) {
		LOGP(DMSC, LOGL_ERROR, "assignment failure unhandled: %zu\n",
		     msgb_l3len(msg) - sizeof(*gh));
		rr_failure = NULL;
	} else {
		rr_failure = &gh->data[0];
	}

	api->assign_fail(conn,
			 GSM0808_CAUSE_RADIO_INTERFACE_MESSAGE_FAILURE,
			 rr_failure);
}

static void handle_classmark_chg(struct gsm_subscriber_connection *conn,
				 struct msgb *msg)
{
	struct bsc_api *api = msg->lchan->ts->trx->bts->network->bsc_api;
	struct gsm48_hdr *gh = msgb_l3(msg);
	unsigned int payload_len = msgb_l3len(msg) - sizeof(*gh);
	uint8_t cm2_len, cm3_len = 0;
	uint8_t *cm2, *cm3 = NULL;

	DEBUGP(DRR, "CLASSMARK CHANGE ");

	/* classmark 2 */
	cm2_len = gh->data[0];
	cm2 = &gh->data[1];
	DEBUGPC(DRR, "CM2(len=%u) ", cm2_len);

	if (payload_len > cm2_len + 1) {
		/* we must have a classmark3 */
		if (gh->data[cm2_len+1] != 0x20) {
			DEBUGPC(DRR, "ERR CM3 TAG\n");
			return;
		}
		if (cm2_len > 3) {
			DEBUGPC(DRR, "CM2 too long!\n");
			return;
		}

		cm3_len = gh->data[cm2_len+2];
		cm3 = &gh->data[cm2_len+3];
		if (cm3_len > 14) {
			DEBUGPC(DRR, "CM3 len %u too long!\n", cm3_len);
			return;
		}
		DEBUGPC(DRR, "CM3(len=%u)\n", cm3_len);
	}
	api->classmark_chg(conn, cm2, cm2_len, cm3, cm3_len);
}

/* Chapter 9.1.16 Handover complete */
static void handle_rr_ho_compl(struct msgb *msg)
{
	struct lchan_signal_data sig;
	struct gsm48_hdr *gh = msgb_l3(msg);

	DEBUGP(DRR, "HANDOVER COMPLETE cause = %s\n",
		rr_cause_name(gh->data[0]));

	sig.lchan = msg->lchan;
	sig.mr = NULL;
	osmo_signal_dispatch(SS_LCHAN, S_LCHAN_HANDOVER_COMPL, &sig);
	/* FIXME: release old channel */
}

/* Chapter 9.1.17 Handover Failure */
static void handle_rr_ho_fail(struct msgb *msg)
{
	struct lchan_signal_data sig;
	struct gsm48_hdr *gh = msgb_l3(msg);

	DEBUGP(DRR, "HANDOVER FAILED cause = %s\n",
		rr_cause_name(gh->data[0]));

	sig.lchan = msg->lchan;
	sig.mr = NULL;
	osmo_signal_dispatch(SS_LCHAN, S_LCHAN_HANDOVER_FAIL, &sig);
	/* FIXME: release allocated new channel */
}


static void dispatch_dtap(struct gsm_subscriber_connection *conn,
			  uint8_t link_id, struct msgb *msg)
{
	struct bsc_api *api = msg->lchan->ts->trx->bts->network->bsc_api;
	struct gsm48_hdr *gh;
	uint8_t pdisc;
	uint8_t msg_type;
	int rc;

	if (msgb_l3len(msg) < sizeof(*gh)) {
		LOGP(DMSC, LOGL_ERROR, "Message too short for a GSM48 header.\n");
		return;
	}

	gh = msgb_l3(msg);
	pdisc = gsm48_hdr_pdisc(gh);
	msg_type = gsm48_hdr_msg_type(gh);

	/* the idea is to handle all RR messages here, and only hand
	 * MM/CC/SMS-CP/LCS up to the MSC.  Some messages like PAGING
	 * RESPONSE or CM SERVICE REQUEST will not be covered here, as
	 * they are only possible in the first L3 message of each L2
	 * channel, i.e. 'conn' will not exist and gsm0408_rcvmsg()
	 * will call api->compl_l3() for it */
	switch (pdisc) {
	case GSM48_PDISC_RR:
		switch (msg_type) {
		case GSM48_MT_RR_GPRS_SUSP_REQ:
			DEBUGP(DRR, "%s\n",
			       gsm48_rr_msg_name(GSM48_MT_RR_GPRS_SUSP_REQ));
			break;
		case GSM48_MT_RR_STATUS:
			LOGP(DRR, LOGL_NOTICE, "%s (cause: %s)\n",
			     gsm48_rr_msg_name(GSM48_MT_RR_GPRS_SUSP_REQ),
			     rr_cause_name(gh->data[0]));
			break;
		case GSM48_MT_RR_MEAS_REP:
			/* This shouldn't actually end up here, as RSL treats
			* L3 Info of 08.58 MEASUREMENT REPORT different by calling
			* directly into gsm48_parse_meas_rep */
			LOGP(DMEAS, LOGL_ERROR, "DIRECT GSM48 MEASUREMENT REPORT ?!? ");
			break;
		case GSM48_MT_RR_HANDO_COMPL:
			handle_rr_ho_compl(msg);
			break;
		case GSM48_MT_RR_HANDO_FAIL:
			handle_rr_ho_fail(msg);
			break;
		case GSM48_MT_RR_CIPH_M_COMPL:
			if (api->cipher_mode_compl)
				api->cipher_mode_compl(conn, msg,
						conn->lchan->encr.alg_id);
			break;
		case GSM48_MT_RR_ASS_COMPL:
			handle_ass_compl(conn, msg);
			break;
		case GSM48_MT_RR_ASS_FAIL:
			handle_ass_fail(conn, msg);
			break;
		case GSM48_MT_RR_CHAN_MODE_MODIF_ACK:
			osmo_timer_del(&conn->T10);
			rc = gsm48_rx_rr_modif_ack(msg);
			if (rc < 0) {
				api->assign_fail(conn,
						 GSM0808_CAUSE_NO_RADIO_RESOURCE_AVAILABLE,
						 NULL);
			} else if (rc >= 0) {
				api->assign_compl(conn, 0,
						  lchan_to_chosen_channel(conn->lchan),
						  conn->lchan->encr.alg_id,
						  chan_mode_to_speech(conn->lchan));
			}
			break;
		case GSM48_MT_RR_CLSM_CHG:
			handle_classmark_chg(conn, msg);
			break;
		case GSM48_MT_RR_APP_INFO:
			/* Passing RR APP INFO to MSC, not quite
			 * according to spec */
			if (api->dtap)
				api->dtap(conn, link_id, msg);
			break;
		default:
			/* Normally, a MSC should never receive RR
			 * messages, but we'd rather forward what we
			 * don't know than drop it... */
			LOGP(DRR, LOGL_NOTICE,
			     "BSC: Passing %s 04.08 RR message to MSC\n",
			     gsm48_rr_msg_name(msg_type));
			if (api->dtap)
				api->dtap(conn, link_id, msg);
		}
		break;
	default:
		if (api->dtap)
			api->dtap(conn, link_id, msg);
		break;
	}
}

/*! \brief RSL has received a DATA INDICATION with L3 from MS */
int gsm0408_rcvmsg(struct msgb *msg, uint8_t link_id)
{
	int rc;
	struct bsc_api *api = msg->lchan->ts->trx->bts->network->bsc_api;
	struct gsm_lchan *lchan;

	lchan = msg->lchan;
	if (lchan->state != LCHAN_S_ACTIVE) {
		LOGP(DRSL, LOGL_INFO, "Got data in non active state(%s), "
		     "discarding.\n", gsm_lchans_name(lchan->state));
		return -1;
	}


	if (lchan->conn) {
		/* if we already have a connection, forward via DTAP to
		 * MSC */
		dispatch_dtap(lchan->conn, link_id, msg);
	} else {
		/* allocate a new connection */
		rc = BSC_API_CONN_POL_REJECT;
		lchan->conn = bsc_subscr_con_allocate(msg->lchan);
		if (!lchan->conn) {
			lchan_release(lchan, 1, RSL_REL_NORMAL);
			return -1;
		}

		/* fwd via bsc_api to send COMPLETE L3 INFO to MSC */
		rc = api->compl_l3(lchan->conn, msg, 0);

		if (rc != BSC_API_CONN_POL_ACCEPT) {
			lchan->conn->lchan = NULL;
			bsc_subscr_con_free(lchan->conn);
			lchan_release(lchan, 1, RSL_REL_NORMAL);
		}
	}

	return 0;
}

/*! \brief We received a GSM 08.08 CIPHER MODE from the MSC */
int gsm0808_cipher_mode(struct gsm_subscriber_connection *conn, int cipher,
			const uint8_t *key, int len, int include_imeisv)
{
	if (cipher > 0 && key == NULL) {
		LOGP(DRSL, LOGL_ERROR, "Need to have an encrytpion key.\n");
		return -1;
	}

	if (len > MAX_A5_KEY_LEN) {
		LOGP(DRSL, LOGL_ERROR, "The key is too long: %d\n", len);
		return -1;
	}

	conn->lchan->encr.alg_id = RSL_ENC_ALG_A5(cipher);
	if (key) {
		conn->lchan->encr.key_len = len;
		memcpy(conn->lchan->encr.key, key, len);
	}

	return gsm48_send_rr_ciph_mode(conn->lchan, include_imeisv);
}

/*
 * Release all occupied RF Channels but stay around for more.
 */
int gsm0808_clear(struct gsm_subscriber_connection *conn)
{
	if (conn->ho_lchan)
		bsc_clear_handover(conn, 1);

	if (conn->secondary_lchan)
		lchan_release(conn->secondary_lchan, 0, RSL_REL_LOCAL_END);

	if (conn->lchan)
		lchan_release(conn->lchan, 1, RSL_REL_NORMAL);

	conn->lchan = NULL;
	conn->secondary_lchan = NULL;
	conn->ho_lchan = NULL;
	conn->bts = NULL;

	osmo_timer_del(&conn->T10);

	return 0;
}

static void send_sapi_reject(struct gsm_subscriber_connection *conn, int link_id)
{
	struct bsc_api *api;

	if (!conn)
		return;

	api = conn->network->bsc_api;
	if (!api || !api->sapi_n_reject)
		return;

	api->sapi_n_reject(conn, link_id);
}

static void rll_ind_cb(struct gsm_lchan *lchan, uint8_t link_id, void *_data, enum bsc_rllr_ind rllr_ind)
{
	struct msgb *msg = _data;

	/*
	 * There seems to be a small window that the RLL timer can
	 * fire after a lchan_release call and before the S_CHALLOC_FREED
	 * is called. Check if a conn is set before proceeding.
	 */
	if (!lchan->conn)
		return;

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
	struct lchan_signal_data *lchan_data;

	if (subsys != SS_LCHAN)
		return 0;


	lchan_data = signal_data;
	if (!lchan_data->lchan || !lchan_data->lchan->conn)
		return 0;

	lchan = lchan_data->lchan;
	bsc = lchan->ts->trx->bts->network->bsc_api;
	if (!bsc)
		return 0;

	switch (signal) {
	case S_LCHAN_UNEXPECTED_RELEASE:
		handle_release(lchan->conn, bsc, lchan);
		break;
	case S_LCHAN_ACTIVATE_ACK:
		handle_chan_ack(lchan->conn, bsc, lchan);
		break;
	case S_LCHAN_ACTIVATE_NACK:
		handle_chan_nack(lchan->conn, bsc, lchan);
		break;
	}

	return 0;
}

static void handle_release(struct gsm_subscriber_connection *conn,
			   struct bsc_api *bsc, struct gsm_lchan *lchan)
{
	int destruct = 1;

	if (conn->secondary_lchan == lchan) {
		osmo_timer_del(&conn->T10);
		conn->secondary_lchan = NULL;

		bsc->assign_fail(conn,
				 GSM0808_CAUSE_RADIO_INTERFACE_FAILURE,
				 NULL);
	}

	/* clear the connection now */
	if (bsc->clear_request)
		destruct = bsc->clear_request(conn, 0);

	/* now give up all channels */
	if (conn->lchan == lchan)
		conn->lchan = NULL;
	if (conn->ho_lchan == lchan) {
		bsc_clear_handover(conn, 0);
		conn->ho_lchan = NULL;
	}
	lchan->conn = NULL;

	gsm0808_clear(conn);

	if (destruct)
		bsc_subscr_con_free(conn);
}

static void handle_chan_ack(struct gsm_subscriber_connection *conn,
			    struct bsc_api *api, struct gsm_lchan *lchan)
{
	if (conn->secondary_lchan != lchan)
		return;

	LOGP(DMSC, LOGL_NOTICE, "Sending assignment on chan: %p\n", lchan);
	gsm48_send_rr_ass_cmd(conn->lchan, lchan, lchan->ms_power);
}

static void handle_chan_nack(struct gsm_subscriber_connection *conn,
			     struct bsc_api *api, struct gsm_lchan *lchan)
{
	if (conn->secondary_lchan != lchan)
		return;

	LOGP(DMSC, LOGL_ERROR, "Channel activation failed. Waiting for timeout now\n");
	conn->secondary_lchan->conn = NULL;
	conn->secondary_lchan = NULL;
}

static __attribute__((constructor)) void on_dso_load_bsc(void)
{
	osmo_signal_register_handler(SS_LCHAN, bsc_handle_lchan_signal, NULL);
}

