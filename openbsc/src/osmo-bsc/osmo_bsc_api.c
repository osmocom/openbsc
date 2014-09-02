/* (C) 2009-2011 by Holger Hans Peter Freyther <zecke@selfish.org>
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
#include <openbsc/osmo_msc_data.h>
#include <openbsc/debug.h>

#include <openbsc/gsm_04_80.h>

#include <osmocom/gsm/protocol/gsm_08_08.h>
#include <osmocom/gsm/gsm0808.h>

#include <osmocom/sccp/sccp.h>

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
	bsc_queue_for_msc(conn->sccp_con, resp);

static int bsc_clear_request(struct gsm_subscriber_connection *conn, uint32_t cause);
static int complete_layer3(struct gsm_subscriber_connection *conn,
			   struct msgb *msg, struct osmo_msc_data *msc);

static uint16_t get_network_code_for_msc(struct osmo_msc_data *msc)
{
	if (msc->core_ncc != -1)
		return msc->core_ncc;
	return msc->network->network_code;
}

static uint16_t get_country_code_for_msc(struct osmo_msc_data *msc)
{
	if (msc->core_mcc != -1)
		return msc->core_mcc;
	return msc->network->country_code;
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
	pdisc = gh->proto_discr & 0x0f;
	mtype = gh->msg_type & 0xbf;

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
	gsm0480_send_ussdNotify(conn, 1, text);
	gsm0480_send_releaseComplete(conn);
}

/*
 * Instruct to reserve data for a new connectiom, create the complete
 * layer three message, send it to open the connection.
 */
static int bsc_compl_l3(struct gsm_subscriber_connection *conn, struct msgb *msg,
			uint16_t chosen_channel)
{
	struct osmo_msc_data *msc;

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
			   struct msgb *msg, struct osmo_msc_data *msc)
{
	struct timeval tv;
	struct msgb *resp;
	uint16_t network_code;
	uint16_t country_code;
	enum bsc_con ret;
	int send_ping = msc->advanced_ping;

	/* Advanced ping/pong handling */
	if (osmo_timer_pending(&msc->pong_timer))
		send_ping = 0;
	if (msc->ping_timeout == 0)
		send_ping = 0;
	if (send_ping && osmo_timer_remaining(&msc->ping_timer, NULL, &tv) == -1)
		send_ping = 0;

	/* allocate resource for a new connection */
	ret = bsc_create_new_connection(conn, msc, send_ping);

	if (ret != BSC_CON_SUCCESS) {
		/* allocation has failed */
		if (ret == BSC_CON_REJECT_NO_LINK)
			bsc_send_ussd_no_srv(conn, msg, msc->ussd_msc_lost_txt);
		else if (ret == BSC_CON_REJECT_RF_GRACE)
			bsc_send_ussd_no_srv(conn, msg, msc->ussd_grace_txt);

		return BSC_API_CONN_POL_REJECT;
	}

	/* check return value, if failed check msg for and send USSD */

	network_code = get_network_code_for_msc(conn->sccp_con->msc);
	country_code = get_country_code_for_msc(conn->sccp_con->msc);

	bsc_scan_bts_msg(conn, msg);
	resp = gsm0808_create_layer3(msg, network_code, country_code,
				     conn->bts->location_area_code,
				     conn->bts->cell_identity);
	if (!resp) {
		LOGP(DMSC, LOGL_DEBUG, "Failed to create layer3 message.\n");
		sccp_connection_free(conn->sccp_con->sccp);
		bsc_delete_connection(conn->sccp_con);
		return BSC_API_CONN_POL_REJECT;
	}

	if (bsc_open_connection(conn->sccp_con, resp) != 0) {
		sccp_connection_free(conn->sccp_con->sccp);
		bsc_delete_connection(conn->sccp_con);
		msgb_free(resp);
		return BSC_API_CONN_POL_REJECT;
	}

	return BSC_API_CONN_POL_ACCEPT;
}

/*
 * Plastic surgery... we want to give up the current connection
 */
static int move_to_msc(struct gsm_subscriber_connection *_conn,
		       struct msgb *msg, struct osmo_msc_data *msc)
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
		subscr_con_free(_conn);
		return 1;
	}

	return 2;
}

static int handle_cc_setup(struct gsm_subscriber_connection *conn,
			   struct msgb *msg)
{
	struct gsm48_hdr *gh = msgb_l3(msg);
	uint8_t pdisc = gh->proto_discr & 0x0f;
	uint8_t mtype = gh->msg_type & 0xbf;

	struct osmo_msc_data *msc;
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
	struct msgb *resp;
	return_when_not_connected(conn);

	LOGP(DMSC, LOGL_INFO, "Tx MSC DTAP LINK_ID=0x%02x\n", link_id);

	/*
	 * We might want to move this connection to a new MSC. Ask someone
	 * to handle it. If it was handled we will return.
	 */
	if (handle_cc_setup(conn, msg) >= 1)
		return;

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

	LOGP(DMSC, LOGL_INFO, "Tx MSC ASSIGN COMPL\n");

	resp = gsm0808_create_assignment_completed(rr_cause, chosen_channel,
						   encr_alg_id, speech_model);
	queue_msg_or_return(resp);
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

	bsc_queue_for_msc(sccp, resp);
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
			  struct gsm48_multi_rate_conf *conf)
{
	struct osmo_msc_data *msc;

	if (!conn->sccp_con) {
		LOGP(DMSC, LOGL_ERROR,
		     "No msc data available on conn %p. Audio will be broken.\n",
		     conn);
		return;
	}

	msc = conn->sccp_con->msc;

	conf->ver = 1;
	conf->icmi = 1;

	/* maybe gcc see's it is copy of _one_ byte */
	conf->m4_75 = msc->amr_conf.m4_75;
	conf->m5_15 = msc->amr_conf.m5_15;
	conf->m5_90 = msc->amr_conf.m5_90;
	conf->m6_70 = msc->amr_conf.m6_70;
	conf->m7_40 = msc->amr_conf.m7_40;
	conf->m7_95 = msc->amr_conf.m7_95;
	conf->m10_2 = msc->amr_conf.m10_2;
	conf->m12_2 = msc->amr_conf.m12_2;
}

static struct bsc_api bsc_handler = {
	.sapi_n_reject = bsc_sapi_n_reject,
	.cipher_mode_compl = bsc_cipher_mode_compl,
	.compl_l3 = bsc_compl_l3,
	.dtap  = bsc_dtap,
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
