/* (C) 2009-2015 by Holger Hans Peter Freyther <zecke@selfish.org>
 * (C) 2009-2011 by On-Waves
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

#include <openbsc/osmo_bsc.h>
#include <openbsc/bsc_msc_data.h>
#include <openbsc/debug.h>

#include <openbsc/gsm_04_80.h>

#include <osmocom/gsm/protocol/gsm_08_08.h>
#include <osmocom/gsm/gsm0808.h>

#include <osmocom/sccp/sccp.h>
#include <openbsc/osmo_bsc_sigtran.h>

#define return_when_not_connected(conn) \
	if (!conn->sccp_con) {\
		LOGP(DMSC, LOGL_ERROR, "MSC Connection not present.\n"); \
		return; \
	}

#define return_when_not_connected_val(conn, ret) \
	if (!conn->sccp_con) {\
		LOGP(DMSC, LOGL_ERROR, "MSC Connection not present.\n"); \
		return ret; \
	}

#define queue_msg_or_return(resp) \
	if (!resp) { \
		LOGP(DMSC, LOGL_ERROR, "Failed to allocate response.\n"); \
		return; \
	} \
	osmo_bsc_sigtran_send(conn->sccp_con, resp);

static int bsc_clear_request(struct gsm_subscriber_connection *conn, uint32_t cause);
static int complete_layer3(struct gsm_subscriber_connection *conn,
			   struct msgb *msg, struct bsc_msc_data *msc);

static uint16_t get_network_code_for_msc(struct bsc_msc_data *msc)
{
	if (msc->core_mnc != -1)
		return msc->core_mnc;
	return msc->network->network_code;
}

static uint16_t get_country_code_for_msc(struct bsc_msc_data *msc)
{
	if (msc->core_mcc != -1)
		return msc->core_mcc;
	return msc->network->country_code;
}

static uint16_t get_lac_for_msc(struct bsc_msc_data *msc, struct gsm_bts *bts)
{
	if (msc->core_lac != -1)
		return msc->core_lac;
	return bts->location_area_code;
}

static uint16_t get_ci_for_msc(struct bsc_msc_data *msc, struct gsm_bts *bts)
{
	if (msc->core_ci != -1)
		return msc->core_ci;
	return bts->cell_identity;
}

static void bsc_maybe_lu_reject(struct gsm_subscriber_connection *conn, int con_type, int cause)
{
	struct msgb *msg;

	/* ignore cm service request or such */
	if (con_type != FLT_CON_TYPE_LU)
		return;

	msg = gsm48_create_loc_upd_rej(cause);
	if (!msg) {
		LOGP(DMM, LOGL_ERROR, "Failed to create msg for LOCATION UPDATING REJECT.\n");
		return;
	}

	msg->lchan = conn->lchan;
	gsm0808_submit_dtap(conn, msg, 0, 0);
}

static int bsc_filter_initial(struct osmo_bsc_data *bsc,
				struct bsc_msc_data *msc,
				struct gsm_subscriber_connection *conn,
				struct msgb *msg, char **imsi, int *con_type,
				int *lu_cause)
{
	struct bsc_filter_request req;
	struct bsc_filter_reject_cause cause;
	struct gsm48_hdr *gh = msgb_l3(msg);
	int rc;

	req.ctx = conn;
	req.black_list = NULL;
	req.access_lists = bsc_access_lists();
	req.local_lst_name = msc->acc_lst_name;
	req.global_lst_name = conn->bts->network->bsc_data->acc_lst_name;
	req.bsc_nr = 0;

	rc = bsc_msg_filter_initial(gh, msgb_l3len(msg), &req,
				con_type, imsi, &cause);
	*lu_cause = cause.lu_reject_cause;
	return rc;
}

static int bsc_filter_data(struct gsm_subscriber_connection *conn,
				struct msgb *msg, int *lu_cause)
{
	struct bsc_filter_request req;
	struct gsm48_hdr *gh = msgb_l3(msg);
	struct bsc_filter_reject_cause cause;
	int rc;

	req.ctx = conn;
	req.black_list = NULL;
	req.access_lists = bsc_access_lists();
	req.local_lst_name = conn->sccp_con->msc->acc_lst_name;
	req.global_lst_name = conn->bts->network->bsc_data->acc_lst_name;
	req.bsc_nr = 0;

	rc = bsc_msg_filter_data(gh, msgb_l3len(msg), &req,
				&conn->sccp_con->filter_state,
				&cause);
	*lu_cause = cause.lu_reject_cause;
	return rc;
}

static void bsc_sapi_n_reject(struct gsm_subscriber_connection *conn, int dlci)
{
	struct msgb *resp;
	return_when_not_connected(conn);

	LOGP(DMSC, LOGL_NOTICE, "Tx MSC SAPI N REJECT DLCI=0x%02x\n", dlci);

	resp = gsm0808_create_sapi_reject(dlci);
	queue_msg_or_return(resp);
}

static void bsc_cipher_mode_compl(struct gsm_subscriber_connection *conn,
				  struct msgb *msg, uint8_t chosen_encr)
{
	struct msgb *resp;
	return_when_not_connected(conn);

	LOGP(DMSC, LOGL_DEBUG, "CIPHER MODE COMPLETE from MS, forwarding to MSC\n");
	resp = gsm0808_create_cipher_complete(msg, chosen_encr);
	queue_msg_or_return(resp);
}

static void bsc_send_ussd_no_srv(struct gsm_subscriber_connection *conn,
				 struct msgb *msg, const char *text)
{
	struct gsm48_hdr *gh;
	int8_t pdisc;
	uint8_t mtype;
	int drop_message = 1;

	if (!text)
		return;

	if (!msg || msgb_l3len(msg) < sizeof(*gh))
		return;

	gh = msgb_l3(msg);
	pdisc = gsm48_hdr_pdisc(gh);
	mtype = gsm48_hdr_msg_type(gh);

	/* Is CM service request? */
	if (pdisc == GSM48_PDISC_MM && mtype == GSM48_MT_MM_CM_SERV_REQ) {
		struct gsm48_service_request *cm;

		cm = (struct gsm48_service_request *) &gh->data[0];

		/* Is type SMS or call? */
		if (cm->cm_service_type == GSM48_CMSERV_SMS)
			drop_message = 0;
		else if (cm->cm_service_type == GSM48_CMSERV_MO_CALL_PACKET)
			drop_message = 0;
	}

	if (drop_message) {
		LOGP(DMSC, LOGL_DEBUG, "Skipping (not sending) USSD message: '%s'\n", text);
		return;
	}

	LOGP(DMSC, LOGL_INFO, "Sending CM Service Accept\n");
	gsm48_tx_mm_serv_ack(conn);

	LOGP(DMSC, LOGL_INFO, "Sending USSD message: '%s'\n", text);
	bsc_send_ussd_notify(conn, 1, text);
	bsc_send_ussd_release_complete(conn);
}

/*
 * Instruct to reserve data for a new connectiom, create the complete
 * layer three message, send it to open the connection.
 */
static int bsc_compl_l3(struct gsm_subscriber_connection *conn, struct msgb *msg,
			uint16_t chosen_channel)
{
	struct bsc_msc_data *msc;

	LOGP(DMSC, LOGL_INFO, "Tx MSC COMPL L3\n");

	/* find the MSC link we want to use */
	msc = bsc_find_msc(conn, msg);
	if (!msc) {
		LOGP(DMSC, LOGL_ERROR, "Failed to find a MSC for a connection.\n");
		bsc_send_ussd_no_srv(conn, msg,
				     conn->bts->network->bsc_data->ussd_no_msc_txt);
		return -1;
	}

	return complete_layer3(conn, msg, msc);
}

static int complete_layer3(struct gsm_subscriber_connection *conn,
			   struct msgb *msg, struct bsc_msc_data *msc)
{
	int con_type, rc, lu_cause;
	char *imsi = NULL;
	struct timeval tv;
	struct msgb *resp;
	uint16_t network_code;
	uint16_t country_code;
	uint16_t lac;
	uint16_t ci;
	enum bsc_con ret;
	int send_ping = msc->advanced_ping;

	/* Advanced ping/pong handling */
	if (osmo_timer_pending(&msc->pong_timer))
		send_ping = 0;
	if (msc->ping_timeout <= 0)
		send_ping = 0;
	if (send_ping && osmo_timer_remaining(&msc->ping_timer, NULL, &tv) == -1)
		send_ping = 0;

	/* Check the filter */
	rc = bsc_filter_initial(msc->network->bsc_data, msc, conn, msg,
				&imsi, &con_type, &lu_cause);
	if (rc < 0) {
		bsc_maybe_lu_reject(conn, con_type, lu_cause);
		return BSC_API_CONN_POL_REJECT;
	}

	/* allocate resource for a new connection */
	//ret = bsc_create_new_connection(conn, msc, send_ping);
	ret = osmo_bsc_sigtran_new_conn(conn, msc);

	if (ret != BSC_CON_SUCCESS) {
		/* allocation has failed */
		if (ret == BSC_CON_REJECT_NO_LINK)
			bsc_send_ussd_no_srv(conn, msg, msc->ussd_msc_lost_txt);
		else if (ret == BSC_CON_REJECT_RF_GRACE)
			bsc_send_ussd_no_srv(conn, msg, msc->ussd_grace_txt);

		return BSC_API_CONN_POL_REJECT;
	}

	if (imsi)
		conn->sccp_con->filter_state.imsi = talloc_steal(conn, imsi);
	conn->sccp_con->filter_state.con_type = con_type;

	/* check return value, if failed check msg for and send USSD */

	network_code = get_network_code_for_msc(conn->sccp_con->msc);
	country_code = get_country_code_for_msc(conn->sccp_con->msc);
	lac = get_lac_for_msc(conn->sccp_con->msc, conn->bts);
	ci = get_ci_for_msc(conn->sccp_con->msc, conn->bts);

	bsc_scan_bts_msg(conn, msg);

	resp = gsm0808_create_layer3(msg, network_code, country_code, lac, ci);
	if (!resp) {
		LOGP(DMSC, LOGL_DEBUG, "Failed to create layer3 message.\n");
		sccp_connection_free(conn->sccp_con->sccp);
		osmo_bsc_sigtran_del_conn(conn->sccp_con);
		return BSC_API_CONN_POL_REJECT;
	}

	if (osmo_bsc_sigtran_open_conn(conn->sccp_con, resp) != 0) {
		sccp_connection_free(conn->sccp_con->sccp);
		osmo_bsc_sigtran_del_conn(conn->sccp_con);
		msgb_free(resp);
		return BSC_API_CONN_POL_REJECT;
	}

	return BSC_API_CONN_POL_ACCEPT;
}

/*
 * Plastic surgery... we want to give up the current connection
 */
static int move_to_msc(struct gsm_subscriber_connection *_conn,
		       struct msgb *msg, struct bsc_msc_data *msc)
{
	struct osmo_bsc_sccp_con *old_con = _conn->sccp_con;

	/*
	 * 1. Give up the old connection.
	 * This happens by sending a clear request to the MSC,
	 * it should end with the MSC releasing the connection.
	 */
	old_con->conn = NULL;
	bsc_clear_request(_conn, 0);

	/*
	 * 2. Attempt to create a new connection to the local
	 * MSC. If it fails the caller will need to handle this
	 * properly.
	 */
	_conn->sccp_con = NULL;
	if (complete_layer3(_conn, msg, msc) != BSC_API_CONN_POL_ACCEPT) {
		gsm0808_clear(_conn);
		bsc_subscr_con_free(_conn);
		return 1;
	}

	return 2;
}

static int handle_cc_setup(struct gsm_subscriber_connection *conn,
			   struct msgb *msg)
{
	struct gsm48_hdr *gh = msgb_l3(msg);
	uint8_t pdisc = gsm48_hdr_pdisc(gh);
	uint8_t mtype = gsm48_hdr_msg_type(gh);

	struct bsc_msc_data *msc;
	struct gsm_mncc_number called;
	struct tlv_parsed tp;
	unsigned payload_len;

	char _dest_nr[35];

	/*
	 * Do we have a setup message here? if not return fast.
	 */
	if (pdisc != GSM48_PDISC_CC || mtype != GSM48_MT_CC_SETUP)
		return 0;

	payload_len = msgb_l3len(msg) - sizeof(*gh);

	tlv_parse(&tp, &gsm48_att_tlvdef, gh->data, payload_len, 0, 0);
	if (!TLVP_PRESENT(&tp, GSM48_IE_CALLED_BCD)) {
		LOGP(DMSC, LOGL_ERROR, "Called BCD not present in setup.\n");
		return -1;
	}

	memset(&called, 0, sizeof(called));
	gsm48_decode_called(&called,
			    TLVP_VAL(&tp, GSM48_IE_CALLED_BCD) - 1);

	if (called.plan != 1 && called.plan != 0)
		return 0;

	if (called.plan == 1 && called.type == 1) {
		_dest_nr[0] = _dest_nr[1] = '0';
		memcpy(_dest_nr + 2, called.number, sizeof(called.number));
	} else
		memcpy(_dest_nr, called.number, sizeof(called.number));

	/*
	 * Check if the connection should be moved...
	 */
	llist_for_each_entry(msc, &conn->bts->network->bsc_data->mscs, entry) {
		if (msc->type != MSC_CON_TYPE_LOCAL)
			continue;
		if (!msc->local_pref)
			continue;
		if (regexec(&msc->local_pref_reg, _dest_nr, 0, NULL, 0) != 0)
			continue;

		return move_to_msc(conn, msg, msc);
	}

	return 0;
}


static void bsc_dtap(struct gsm_subscriber_connection *conn, uint8_t link_id, struct msgb *msg)
{
	int lu_cause;
	struct msgb *resp;
	return_when_not_connected(conn);

	LOGP(DMSC, LOGL_INFO, "Tx MSC DTAP LINK_ID=0x%02x\n", link_id);

	/*
	 * We might want to move this connection to a new MSC. Ask someone
	 * to handle it. If it was handled we will return.
	 */
	if (handle_cc_setup(conn, msg) >= 1)
		return;

	/* Check the filter */
	if (bsc_filter_data(conn, msg, &lu_cause) < 0) {
		bsc_maybe_lu_reject(conn,
					conn->sccp_con->filter_state.con_type,
					lu_cause);
		bsc_clear_request(conn, 0);
		return;
	}

	bsc_scan_bts_msg(conn, msg);

	resp = gsm0808_create_dtap(msg, link_id);
	queue_msg_or_return(resp);
}

static void bsc_assign_compl(struct gsm_subscriber_connection *conn, uint8_t rr_cause,
			     uint8_t chosen_channel, uint8_t encr_alg_id,
			     uint8_t speech_model)
{
	struct msgb *resp;
	return_when_not_connected(conn);

	if (is_ipaccess_bts(conn->bts) && conn->sccp_con->rtp_ip) {
		/* NOTE: In a network that makes use of an IPA base station
		 * and AoIP, we have to wait until the BTS reports its RTP
		 * IP/Port combination back to BSC via RSL. Unfortunately, the
		 * IPA protocol sends its Abis assignment complete message
		 * before it sends its RTP IP/Port via IPACC. So we will now
		 * postpone the AoIP assignment completed message until we
		 * know the RTP IP/Port combination. */
		LOGP(DMSC, LOGL_INFO, "POSTPONE MSC ASSIGN COMPL\n");
		conn->lchan->abis_ip.ass_compl.rr_cause = rr_cause;
		conn->lchan->abis_ip.ass_compl.chosen_channel = chosen_channel;
		conn->lchan->abis_ip.ass_compl.encr_alg_id = encr_alg_id;
		conn->lchan->abis_ip.ass_compl.speech_mode = speech_model;
		conn->lchan->abis_ip.ass_compl.valid = true;

	} else {
		/* NOTE: Send the A assignment complete message immediately. */
		LOGP(DMSC, LOGL_INFO, "Tx MSC ASSIGN COMPL\n");
		resp = gsm0808_create_assignment_completed(rr_cause, chosen_channel,
							   encr_alg_id, speech_model);
		queue_msg_or_return(resp);
	}
}

static void bsc_assign_fail(struct gsm_subscriber_connection *conn,
			    uint8_t cause, uint8_t *rr_cause)
{
	struct msgb *resp;
	return_when_not_connected(conn);

	LOGP(DMSC, LOGL_INFO, "Tx MSC ASSIGN FAIL\n");

	resp = gsm0808_create_assignment_failure(cause, rr_cause);
	queue_msg_or_return(resp);
}

static int bsc_clear_request(struct gsm_subscriber_connection *conn, uint32_t cause)
{
	struct osmo_bsc_sccp_con *sccp;
	struct msgb *resp;
	return_when_not_connected_val(conn, 1);

	LOGP(DMSC, LOGL_INFO, "Tx MSC CLEAR REQUEST\n");

	/*
	 * Remove the connection from BSC<->SCCP part, the SCCP part
	 * will either be cleared by channel release or MSC disconnect
	 */
	sccp = conn->sccp_con;
	sccp->conn = NULL;
	conn->sccp_con = NULL;

	resp = gsm0808_create_clear_rqst(GSM0808_CAUSE_RADIO_INTERFACE_FAILURE);
	if (!resp) {
		LOGP(DMSC, LOGL_ERROR, "Failed to allocate response.\n");
		return 1;
	}

	osmo_bsc_sigtran_send(sccp, resp);
	return 1;
}

static void bsc_cm_update(struct gsm_subscriber_connection *conn,
			  const uint8_t *cm2, uint8_t cm2_len,
			  const uint8_t *cm3, uint8_t cm3_len)
{
	struct msgb *resp;
	return_when_not_connected(conn);

	resp = gsm0808_create_classmark_update(cm2, cm2_len, cm3, cm3_len);

	queue_msg_or_return(resp);
}

static void bsc_mr_config(struct gsm_subscriber_connection *conn,
				struct gsm_lchan *lchan, int full_rate)
{
	struct bsc_msc_data *msc;
	struct gsm48_multi_rate_conf *ms_conf, *bts_conf;

	if (!conn->sccp_con) {
		LOGP(DMSC, LOGL_ERROR,
		     "No msc data available on conn %p. Audio will be broken.\n",
		     conn);
		return;
	}

	msc = conn->sccp_con->msc;

	/* initialize the data structure */
	lchan->mr_ms_lv[0] = sizeof(*ms_conf);
	lchan->mr_bts_lv[0] = sizeof(*bts_conf);
	ms_conf = (struct gsm48_multi_rate_conf *) &lchan->mr_ms_lv[1];
	bts_conf = (struct gsm48_multi_rate_conf *) &lchan->mr_bts_lv[1];
	memset(ms_conf, 0, sizeof(*ms_conf));
	memset(bts_conf, 0, sizeof(*bts_conf));

	bts_conf->ver = ms_conf->ver = 1;
	bts_conf->icmi = ms_conf->icmi = 1;

	/* maybe gcc see's it is copy of _one_ byte */
	bts_conf->m4_75 = ms_conf->m4_75 = msc->amr_conf.m4_75;
	bts_conf->m5_15 = ms_conf->m5_15 = msc->amr_conf.m5_15;
	bts_conf->m5_90 = ms_conf->m5_90 = msc->amr_conf.m5_90;
	bts_conf->m6_70 = ms_conf->m6_70 = msc->amr_conf.m6_70;
	bts_conf->m7_40 = ms_conf->m7_40 = msc->amr_conf.m7_40;
	bts_conf->m7_95 = ms_conf->m7_95 = msc->amr_conf.m7_95;
	if (full_rate) {
		bts_conf->m10_2 = ms_conf->m10_2 = msc->amr_conf.m10_2;
		bts_conf->m12_2 = ms_conf->m12_2 = msc->amr_conf.m12_2;
	}

	/* now copy this into the bts structure */
	memcpy(lchan->mr_bts_lv, lchan->mr_ms_lv, sizeof(lchan->mr_ms_lv));
}

static struct bsc_api bsc_handler = {
	.sapi_n_reject = bsc_sapi_n_reject,
	.cipher_mode_compl = bsc_cipher_mode_compl,
	.compl_l3 = bsc_compl_l3,
	.dtap = bsc_dtap,
	.assign_compl = bsc_assign_compl,
	.assign_fail = bsc_assign_fail,
	.clear_request = bsc_clear_request,
	.classmark_chg = bsc_cm_update,
	.mr_config = bsc_mr_config,
};

struct bsc_api *osmo_bsc_api()
{
	return &bsc_handler;
}
