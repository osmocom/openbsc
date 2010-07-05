/* GSM 08.08 like API for OpenBSC. The bridge from MSC to BSC */

/* (C) 2010 by Holger Hans Peter Freyther
 * (C) 2010 by On Waves
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

#include <osmocore/talloc.h>

static void rll_ind_cb(struct gsm_lchan *, uint8_t, void *, enum bsc_rllr_ind);
static void send_sapi_reject(struct gsm_subscriber_connection *conn, int link_id);

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
		api->dtap(lchan->conn, msg);
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

int gsm0808_clear(struct gsm_subscriber_connection* conn)
{
	struct gsm_lchan *lchan;

	bsc_clear_handover(conn);

	lchan = conn->lchan;
	subscr_con_free(conn);
	lchan_release(lchan, 1, 0);
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

	if (subsys != SS_LCHAN || signal != S_LCHAN_UNEXPECTED_RELEASE)
		return 0;

	lchan = (struct gsm_lchan *)signal_data;
	if (!lchan || !lchan->conn)
		return 0;

	bsc = lchan->ts->trx->bts->network->bsc_api;
	if (!bsc || !bsc->clear_request)
		return 0;

	bsc->clear_request(lchan->conn, 0);
	subscr_con_free(lchan->conn);
	return 0;
}

static __attribute__((constructor)) void on_dso_load_bsc(void)
{
	register_signal_handler(SS_LCHAN, bsc_handle_lchan_signal, NULL);
}
