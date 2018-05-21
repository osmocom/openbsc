/* GSM Subscriber Update Protocol */

/* (C) 2015 by Ivan Klyuchnikov <kluchnikovi@gmail.com>
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

#include <openbsc/gsm_sup.h>
#include <osmocom/gsm/tlv.h>
#include <openbsc/gsm_subscriber.h>
#include <openbsc/gsm_04_08.h>
#include <openbsc/debug.h>
#include <openbsc/db.h>
#include <openbsc/chan_alloc.h>
#include <osmocom/gsm/protocol/gsm_04_08_gprs.h>
#include <osmocom/gsm/gsup.h>
#include <openbsc/gsup_client.h>
#include <openbsc/osmo_msc.h>
#include <openbsc/gprs_utils.h>
#include <openbsc/ussd.h>
#include <openbsc/gsm_04_11.h>
#include <openbsc/transaction.h>
#include <osmocom/gsm/protocol/gsm_04_11.h>
#include <osmocom/gsm/gsm0411_utils.h>

#if 0
enum {
    FMAP_MSISDN        = 0x80
};

static int subscr_uss_message(struct msgb *msg,
			      struct ss_request *req,
			      const char* extention)
{
	size_t bcd_len = 0;
	uint8_t *gsup_indicator;

	gsup_indicator = msgb_put(msg, 4);

	/* First byte should always be OSMO_GSUP_MSGT_MAP */
	gsup_indicator[0] = OSMO_GSUP_MSGT_MAP;
	gsup_indicator[1] = req->message_type;
	/* TODO ADD tid */
	gsup_indicator[2] = req->component_type;

	/* invokeId */
	msgb_tlv_put(msg, GSM0480_COMPIDTAG_INVOKE_ID, 1, &req->invoke_id);

	/* opCode */
	msgb_tlv_put(msg, GSM0480_OPERATION_CODE, 1, &req->opcode);

	if (req->ussd_text_len > 0) {
		msgb_tlv_put(msg, ASN1_OCTET_STRING_TAG, req->ussd_text_len + 1, &req->ussd_text_language);
	}

	if (extention) {
		uint8_t bcd_buf[32];
		bcd_len = gsm48_encode_bcd_number(bcd_buf, sizeof(bcd_buf), 0,
						  extention);
		msgb_tlv_put(msg, FMAP_MSISDN, bcd_len - 1, &bcd_buf[1]);
	}

	/* fill actual length */
	gsup_indicator[3] = 3 + 3 + (req->ussd_text_len + 1 + 2) + (bcd_len + 2);;

	/* wrap with GSM0480_CTYPE_INVOKE */
	// gsm0480_wrap_invoke(msg, req->opcode, invoke_id);
	// gsup_indicator = msgb_push(msgb, 1);
	// gsup_indicator[0] = OSMO_GSUP_MSGT_MAP;
	return 0;
}


int subscr_tx_uss_message(struct ss_request *req,
			  struct gsm_subscriber *subscr)
{
	struct msgb *msg = gsup_client_msgb_alloc();
	if (!msg)
		return -ENOMEM;

	//GSM0480_OP_CODE_PROCESS_USS_REQ
	subscr_uss_message(msg, req, subscr->extension);

	return gsup_client_send(subscr->group->net->ussd_sup_client, msg);
}


static int rx_uss_message_parse(struct ss_request *ss,
				const uint8_t* data,
				size_t len,
				char* extention,
				size_t extention_len)
{
	const uint8_t* const_data = data;

	if (len < 1 + 2 + 3 + 3)
		return -1;

	/* skip OSMO_GSUP_MSGT_MAP */
	ss->message_type = *(++const_data);
	ss->component_type = *(++const_data);
	const_data += 2;

	//
	if (*const_data != GSM0480_COMPIDTAG_INVOKE_ID) {
		return -1;
	}
	const_data += 2;
	ss->invoke_id = *const_data;
	const_data++;

	//
	if (*const_data != GSM0480_OPERATION_CODE) {
		return -1;
	}
	const_data += 2;
	ss->opcode = *const_data;
	const_data++;


	while (const_data - data < len) {
		uint8_t len;
		switch (*const_data) {
		case ASN1_OCTET_STRING_TAG:
			ss->ussd_text_len = len = (*(++const_data) - 1);
			ss->ussd_text_language = *(++const_data);
			memcpy(ss->ussd_text,
				++const_data,
				(len > MAX_LEN_USSD_STRING) ? MAX_LEN_USSD_STRING : len);
			const_data += len;
			break;

		case FMAP_MSISDN:
			len = *(++const_data);
			gsm48_decode_bcd_number(extention,
						extention_len,
						const_data,
						0);
			const_data += len + 1;
			break;
		default:
			DEBUGP(DMM, "Unknown code: %d\n", *const_data);
			return -1;
		}
	}

	return 0;
}

static int rx_uss_message(const uint8_t* data, size_t len)
{
	char extention[32] = {0};
	struct ss_request ss;
	memset(&ss, 0, sizeof(ss));

	if (rx_uss_message_parse(&ss, data, len, extention, sizeof(extention))) {
		LOGP(DSUP, LOGL_ERROR, "Can't parse uss message\n");
		return -1;
	}

	LOGP(DSUP, LOGL_ERROR, "Got invoke_id=0x%02x opcode=0x%02x facility=0x%02x text=%s\n",
	     ss.invoke_id, ss.opcode, ss.component_type, ss.ussd_text);

	return on_ussd_response(&ss, extention);
}
#endif

int subscr_tx_sms_message(struct gsm_subscriber *subscr,
                          struct gsm411_rp_hdr *rph)
{
	uint8_t *data;
	struct msgb *msg = gsup_client_msgb_alloc();
	if (!msg)
		return -ENOMEM;

	msgb_put_u8(msg, OSMO_GSUP_MSGT_SMS);

	if (subscr->extension) {
		uint8_t bcd_buf[32];
		int bcd_len = gsm48_encode_bcd_number(bcd_buf, sizeof(bcd_buf),
		                                      0, subscr->extension);
		msgb_tlv_put(msg, 0x82, bcd_len - 1, &bcd_buf[1]);
	}
	msgb_put_u8(msg, rph->msg_type);
	msgb_put_u8(msg, rph->msg_ref);

	data = msgb_put(msg, rph->len - 2);
	memcpy(data, rph->data, rph->len - 2);

	return gsup_client_send(subscr->group->net->sms_client, msg);
}

static int rx_sms_message(struct gsup_client *sup_client,
                          const uint8_t* data, size_t data_len)
{

	int rc;
	char extension[15];
	uint8_t *value;
	size_t value_len;
	int offset = 1;
	uint8_t *rp_hdr = (uint8_t*)data + offset;
	data_len -= 1;

	rc =  osmo_match_shift_tlv(&rp_hdr, &data_len, 0x82, &value, &value_len);

	if (rc <= 0)
		return -GMM_CAUSE_INV_MAND_INFO;

	if (value_len * 2 + 1 > ARRAY_SIZE(extension))
		return -GMM_CAUSE_INV_MAND_INFO;

	/* Note that gsm48_decode_bcd_number expects the number of encoded MSISDN
	 * octets in the first octet. By coincidence (the TLV encoding) the byte
	 * before the value part already contains this length so we can use it
	 * here.
	 */
	OSMO_ASSERT(value[-1] == value_len);
	gsm48_decode_bcd_number(extension, ARRAY_SIZE(extension), value - 1, 0);
	offset += 2 + value_len;

	struct msgb *msg = gsm411_msgb_alloc();
	uint8_t *rp_msg;
	rp_msg = (uint8_t *)msgb_put(msg, data_len);
	memcpy(rp_msg, data + offset, data_len);

	struct gsm_subscriber *subscr;
	struct gsm_network *net = sup_client->net;
	subscr = subscr_get_by_extension(net->subscr_group, extension);
	if (!subscr) {
		msgb_free(msg);
		return -GMM_CAUSE_IMSI_UNKNOWN;
	}
	return gsm411_send_rp_msg_subscr(subscr, msg);
}

void init_charging_session_id(struct gsm_network *network)
{
	network->session_id.h = (uint32_t)time(NULL);
	network->session_id.l = 0;
}
struct charging_session_id get_charging_session_id(struct gsm_network *network)
{
	struct charging_session_id id;

	if (++network->session_id.l == 0) /* overflow */
		++network->session_id.h;
	id.h = network->session_id.h;
	id.l = network->session_id.l;

	return id;
}

static void encode_sms_charging_info(struct msgb *msg, struct gsm_trans *trans)
{
	uint8_t bcd_buf[32];
	size_t bcd_len;
	struct gsm_sms *gsms = trans->sms.sms;

	/* SMS: destination address (MSISDN): [Pres: M] [Format: TLV] [Length: 0-9] */
	bcd_len = gsm48_encode_bcd_number(bcd_buf, sizeof(bcd_buf), 0, gsms->dst.addr);
	msgb_tlv_put(msg, OSMO_GSUP_MSISDN_IE, bcd_len - 1, &bcd_buf[1]);

	/* SMS: rp msg ref: [Pres: M] [Format: V] [Length: 1] */
	msgb_put_u8(msg, trans->msg_ref);

	/* SMS: tp msg ref: [Pres: M] [Format: V] [Length: 1] */
	msgb_put_u8(msg, gsms->msg_ref);
}

int tx_reserve_units_request(enum osmo_gsup_charging_message_type msg_type,
			      enum osmo_gsup_charging_request_type request_type,
			      enum osmo_charging_service_type service_type,
			      struct gsm_trans *trans, uint32_t service_units)
{
	uint8_t bcd_buf[32];
	size_t bcd_len;
	struct msgb *msg = gsup_client_msgb_alloc();

	if (!msg)
		return -ENOMEM;
	if (!trans->subscr->extension)
		return -1;

	if (request_type == OSMO_GSUP_MSGT_REQUEST_TYPE_INITIAL)
		trans->session_id = get_charging_session_id(trans->net);

	/* Message type: [Pres: M] [Format: V] [Length: 1] */
	msgb_put_u8(msg, msg_type);

	/* Session id: [Pres: M] [Format: V] [Length: 8] */
	msgb_put_u32(msg, trans->session_id.h);
	msgb_put_u32(msg, trans->session_id.l);

	/* Request type: [Pres: M] [Format: V] [Length: 1] */
	msgb_put_u8(msg, request_type);

	/* Service type: [Pres: M] [Format: V] [Length: 1] */
	msgb_put_u8(msg, service_type);

	/* Subscriber Identifier (MSISDN): [Pres: M] [Format: TLV] [Length: 0-9] */
	bcd_len = gsm48_encode_bcd_number(bcd_buf, sizeof(bcd_buf),
					  0, trans->subscr->extension);
	msgb_tlv_put(msg, OSMO_GSUP_MSISDN_IE, bcd_len - 1, &bcd_buf[1]);

	/* Service units [Pres: M] [Format: V] [Length: 4] */
	msgb_put_u32(msg, service_units);

	/* Encode Service Information */
	switch (service_type) {
	case OSMO_CHARGING_SERVICE_TYPE_SMS:
		encode_sms_charging_info(msg, trans);
		break;
	default:
		msgb_free(msg);
		return -EINVAL;
	}

	switch (request_type) {
	case OSMO_GSUP_MSGT_REQUEST_TYPE_INITIAL:
		LOGGSESSIONP(LOGL_NOTICE, trans->session_id,
			"Tx: Reserve Units Request: type = INITIAL, service = %d,"
			" subscriber_id = %s, requested_units = %d, desr_addr = %s,"
			" rp_msg_ref = %d, tp_msg_ref = %d\n",
			service_type, trans->subscr->extension, service_units,
			trans->sms.sms->dst.addr, trans->msg_ref, trans->sms.sms->msg_ref);
		break;
	case OSMO_GSUP_MSGT_REQUEST_TYPE_TERMINATION:
		LOGGSESSIONP(LOGL_NOTICE, trans->session_id,
			"Tx: Reserve Units Request: type = TERMINATION, service = %d,"
			" subscriber_id = %s, used_units = %d, desr_addr = %s,"
			" rp_msg_ref = %d, tp_msg_ref = %d\n",
			service_type, trans->subscr->extension, service_units,
			trans->sms.sms->dst.addr, trans->msg_ref, trans->sms.sms->msg_ref);
		break;
	default:
		LOGGSESSIONP(LOGL_NOTICE, trans->session_id,
			"Tx: Reserve Units Request with unsupported type = %d\n", request_type);
	}

	return gsup_client_send(trans->net->sms_ctf, msg);
}

static int osmo_gsup_reserve_units_response_decode(const uint8_t *const_data,
		size_t data_len, struct osmo_gsup_reserve_units_response *response)
{
	int rc;
	uint8_t *data = (uint8_t *)const_data;
	uint8_t *value;

	/* Message type: [Pres: M] [Format: V] [Length: 1] */
	rc = osmo_shift_v_fixed(&data, &data_len, 1, &value);
	if (rc < 0)
		return -GMM_CAUSE_INV_MAND_INFO;
	response->message_type = osmo_decode_big_endian(value, 1);

	/* Session id: [Pres: M] [Format: V] [Length: 8] */
	rc = osmo_shift_v_fixed(&data, &data_len, 4, &value);
	if (rc < 0)
		return -GMM_CAUSE_INV_MAND_INFO;
	response->session_id.h = osmo_decode_big_endian(value, 4);
	rc = osmo_shift_v_fixed(&data, &data_len, 4, &value);
	if (rc < 0)
		return -GMM_CAUSE_INV_MAND_INFO;
	response->session_id.l = osmo_decode_big_endian(value, 4);

	/* Request type: [Pres: M] [Format: V] [Length: 1] */
	rc = osmo_shift_v_fixed(&data, &data_len, 1, &value);
	if (rc < 0)
		return -GMM_CAUSE_INV_MAND_INFO;
	response->request_type = osmo_decode_big_endian(value, 1);

	/* Result code: [Pres: M] [Format: V] [Length: 4] */
	rc = osmo_shift_v_fixed(&data, &data_len, 4, &value);
	if (rc < 0)
		return -GMM_CAUSE_INV_MAND_INFO;
	response->result_code = osmo_decode_big_endian(value, 4);

	if (response->request_type == OSMO_GSUP_MSGT_REQUEST_TYPE_INITIAL) {
		/* Service units: [Pres: O] [Format: V] [Length: 4] */
		rc = osmo_shift_v_fixed(&data, &data_len, 4, &value);
		if (rc < 0)
			return -GMM_CAUSE_INV_MAND_INFO;
		response->service_units = osmo_decode_big_endian(value, 4);
	}

	return 0;
}

static int rx_sms_reserve_units_response_init(struct gsm_network *net,
			struct osmo_gsup_reserve_units_response *response)
{
	struct gsm_trans *trans;
	struct gsm_sms *gsms;

	trans = trans_find_by_session_id(net, GSM48_PDISC_SMS, response->session_id);
	if (!trans) {
		LOGGSESSIONP(LOGL_ERROR, response->session_id,
			"Can't find transaction for Session Id from Reserve Units Response Initial\n");
		return -EINVAL;
	}

	gsms = trans->sms.sms;

	switch (response->result_code) {
	case OSMO_CHARGING_RESULT_CODE_SUCCESS:
		if (response->service_units == 1) {
			return gsm340_rx_tpdu(trans);
		} else {
			LOGGSESSIONP(LOGL_ERROR, response->session_id,
				"Received Service Units = %d in Reserve Units Response Initial\n",
				response->result_code);
			tx_reserve_units_request(OSMO_GSUP_MSGT_RESERVE_UNITS_REQUEST,
						 OSMO_GSUP_MSGT_REQUEST_TYPE_TERMINATION,
						 OSMO_CHARGING_SERVICE_TYPE_SMS,
						 trans, 0);
			trans->sms.sms = NULL;
			sms_free(gsms);
			return gsm411_send_rp_error(trans, trans->msg_ref,
						    GSM411_RP_CAUSE_MO_CALL_BARRED);
		}
	case OSMO_CHARGING_RESULT_CODE_CREDIT_LIMIT_REACHED:
		trans->sms.sms = NULL;
		sms_free(gsms);
		return gsm411_send_rp_error(trans, trans->msg_ref,
						GSM411_RP_CAUSE_MO_CALL_BARRED);
	default:
		LOGGSESSIONP(LOGL_ERROR, response->session_id,
			"Received Result Code %d in Reserve Units Response Initial\n",
			response->result_code);
		trans->sms.sms = NULL;
		sms_free(gsms);
		return gsm411_send_rp_error(trans, trans->msg_ref,
						GSM411_RP_CAUSE_MO_NET_OUT_OF_ORDER);
	}
}

static int rx_sms_reserve_units_response_term(struct gsm_network *net,
			struct osmo_gsup_reserve_units_response *response)
{
	switch (response->result_code) {
	case OSMO_CHARGING_RESULT_CODE_SUCCESS:
		break;
	default:
		LOGGSESSIONP(LOGL_ERROR, response->session_id,
			"Received Result Code %d in Reserve Units Response Termination\n",
			response->result_code);
	}
	return 0;
}

static int rx_sms_reserve_units_response(struct gsm_network *net,
			struct osmo_gsup_reserve_units_response *response)
{
	switch (response->request_type) {
	case OSMO_GSUP_MSGT_REQUEST_TYPE_INITIAL:
		LOGGSESSIONP(LOGL_NOTICE, response->session_id,
			"Rx: Reserve Units Response: type = INITIAL, result_code = %d, granted_units = %d\n",
			response->result_code, response->service_units);
		return rx_sms_reserve_units_response_init(net, response);
	case OSMO_GSUP_MSGT_REQUEST_TYPE_TERMINATION:
		LOGGSESSIONP(LOGL_NOTICE, response->session_id,
			"Rx: Reserve Units Response: type = TERMINATION, result_code = %d\n",
			response->result_code);
		return rx_sms_reserve_units_response_term(net, response);
	case OSMO_GSUP_MSGT_REQUEST_TYPE_UPDATE:
	case OSMO_GSUP_MSGT_REQUEST_TYPE_EVENT:
	default:
		LOGGSESSIONP(LOGL_NOTICE, response->session_id,
			"Received unsupported Request Type %d in Reserve Units Response message\n",
			response->request_type);
		return -EINVAL;
	}
}

static int rx_reserve_units_response(struct gsup_client *sup_client,
				const uint8_t* const_data, size_t data_len)
{
	int rc;
	struct gsm_network *net = sup_client->net;
	struct osmo_gsup_reserve_units_response response = {0};

	rc = osmo_gsup_reserve_units_response_decode(const_data, data_len, &response);
	if (rc < 0) {
		LOGGSESSIONP(LOGL_ERROR, response.session_id,
			"decoding Reserve Units Response message fails with error '%s' (%d)\n",
			get_value_string(gsm48_gmm_cause_names, -rc), -rc);
		return rc;
	}

	return rx_sms_reserve_units_response(net, &response);
}


static int subscr_tx_sup_message(struct gsup_client *sup_client,
								 struct gsm_subscriber *subscr,
								 struct osmo_gsup_message *gsup_msg)
{
	struct msgb *msg = gsup_client_msgb_alloc();

	if (strlen(gsup_msg->imsi) == 0 && subscr)
		strncpy(gsup_msg->imsi, subscr->imsi, sizeof(gsup_msg->imsi) - 1);

	osmo_gsup_encode(msg, gsup_msg);

	LOGGSUBSCRP(LOGL_INFO, subscr,
		    "Sending SUP, will send: %s\n", msgb_hexdump(msg));

	if (!sup_client) {
		msgb_free(msg);
		return -ENOTSUP;
	}

	return gsup_client_send(sup_client, msg);
}

/*
int subscr_query_auth_info(struct gsm_subscriber *subscr)
{
	struct osmo_gsup_message gsup_msg = {0};

	LOGGSUBSCRP(LOGL_INFO, subscr,
		"subscriber auth info is not available\n");

	gsup_msg.message_type = OSMO_GSUP_MSGT_SEND_AUTH_INFO_REQUEST;
	return subscr_tx_sup_message(subscr->group->net->hlr_sup_client, subscr, &gsup_msg);
}
*/
int subscr_location_update(struct gsm_subscriber *subscr)
{
	struct osmo_gsup_message gsup_msg = {0};

	LOGGSUBSCRP(LOGL_INFO, subscr,
		"subscriber data is not available\n");

	gsup_msg.message_type = OSMO_GSUP_MSGT_UPDATE_LOCATION_REQUEST;
	return subscr_tx_sup_message(subscr->group->net->hlr_sup_client, subscr, &gsup_msg);
}

int subscr_purge_ms(struct gsm_subscriber *subscr)
{
	struct osmo_gsup_message gsup_msg = {0};
	gsup_msg.message_type = OSMO_GSUP_MSGT_PURGE_MS_REQUEST;
	return subscr_tx_sup_message(subscr->group->net->hlr_sup_client, subscr, &gsup_msg);
}

static int subscr_tx_sup_error_reply(struct gsup_client *sup_client,
									 struct gsm_subscriber *subscr,
									 struct osmo_gsup_message *gsup_orig,
									 enum gsm48_gmm_cause cause)
{
	struct osmo_gsup_message gsup_reply = {0};

	strncpy(gsup_reply.imsi, gsup_orig->imsi, sizeof(gsup_reply.imsi) - 1);
	gsup_reply.cause = cause;
	gsup_reply.message_type =
		OSMO_GSUP_TO_MSGT_ERROR(gsup_orig->message_type);

	return subscr_tx_sup_message(sup_client, subscr, &gsup_reply);
}

/*
static int subscr_handle_sup_auth_res(struct gsup_client *sup_client,
									   struct gsm_subscriber *subscr,
									   struct osmo_gsup_message *gsup_msg)
{
	struct gsm_subscriber_connection *conn = connection_for_subscr(subscr);
	struct gsm_security_operation *op;


	LOGGSUBSCRP(LOGL_INFO, subscr,
		"Got SendAuthenticationInfoResult, num_auth_vectors = %zu\n",
		gsup_msg->num_auth_vectors);

	if (gsup_msg->num_auth_vectors > 0) {
		op = conn->sec_operation;
		memcpy(&op->atuple, gsup_msg->auth_vectors, sizeof(struct gsm_auth_vectors));
		db_sync_lastauthtuple_for_subscr(&op->atuple, subscr);
		gsm48_tx_mm_auth_req(conn, op->atuple.rand, op->atuple.key_seq);
	}

	return 0;
}
*/

static int subscr_handle_sup_upd_loc_res(struct gsm_subscriber *subscr,
									struct osmo_gsup_message *gsup_msg)
{
	uint8_t msisdn_lv[10];

	if (!subscr->group) {
		LOGGSUBSCRP(LOGL_ERROR, subscr,
			"Update location result was received, but LUR procedure timedout.\n");
		return -1;
	}

	if (gsup_msg->msisdn_enc) {
		if (gsup_msg->msisdn_enc_len > sizeof(msisdn_lv) - 1) {
			LOGP(DSUP, LOGL_ERROR, "MSISDN too long (%zu)\n",
				gsup_msg->msisdn_enc_len);
			return -1;
		} else {
			msisdn_lv[0] = gsup_msg->msisdn_enc_len;
			memcpy(msisdn_lv+1, gsup_msg->msisdn_enc,
				gsup_msg->msisdn_enc_len);
			gsm48_decode_bcd_number(subscr->extension, sizeof(subscr->extension),
																	msisdn_lv,0);
			db_sync_subscriber(subscr);
		}
	}

	struct gsm_subscriber_connection *conn = connection_for_subscr(subscr);

	if (conn) {
		if (conn->loc_operation)
			conn->loc_operation->waiting_for_remote_accept = 0;
		gsm0408_authorize(conn,NULL);
	}

	return 0;
}

static int subscr_handle_sup_purge_ms_res(struct gsm_subscriber *subscr,
									struct osmo_gsup_message *gsup_msg)
{
	LOGP(DSUP, LOGL_INFO, "SUP PURGE MS result OK for IMSI:%s\n", subscr->imsi);
	return 0;
}

static int check_cause(int cause)
{
	switch (cause) {
	case GMM_CAUSE_IMSI_UNKNOWN ... GMM_CAUSE_ILLEGAL_ME:
	case GMM_CAUSE_GPRS_NOTALLOWED ... GMM_CAUSE_NO_GPRS_PLMN:
		return EACCES;

	case GMM_CAUSE_MSC_TEMP_NOTREACH ... GMM_CAUSE_CONGESTION:
		return EHOSTUNREACH;

	case GMM_CAUSE_SEM_INCORR_MSG ... GMM_CAUSE_PROTO_ERR_UNSPEC:
	default:
		return EINVAL;
	}
}

static int subscr_handle_sup_upd_loc_err(struct gsm_subscriber *subscr,
									struct osmo_gsup_message *gsup_msg)
{
	int cause_err;
	struct gsm_subscriber_connection *conn = connection_for_subscr(subscr);

	cause_err = check_cause(gsup_msg->cause);

	LOGGSUBSCRP(LOGL_DEBUG, subscr,
		"Update location has failed with cause %d, handled as: %s\n",
		gsup_msg->cause, strerror(cause_err));

	switch (cause_err) {
	case EACCES:
		LOGGSUBSCRP(LOGL_NOTICE, subscr,
			"GSM update location failed, access denied, "
			"MM cause = '%s' (%d)\n",
			get_value_string(gsm48_gmm_cause_names, gsup_msg->cause),
			gsup_msg->cause);
		gsm0408_loc_upd_rej(conn, gsup_msg->cause);
		release_loc_updating_req(conn, 0);
		break;

	case EHOSTUNREACH:
		LOGGSUBSCRP(LOGL_NOTICE, subscr,
			"GSM update location failed, MM cause = '%s' (%d)\n",
			get_value_string(gsm48_gmm_cause_names, gsup_msg->cause),
			gsup_msg->cause);
		// TODO: Try to find subscriber in local HLR?
		gsm0408_loc_upd_rej(conn, gsup_msg->cause);
		release_loc_updating_req(conn, 0);
		break;

	default:
	case EINVAL:
		LOGGSUBSCRP(LOGL_ERROR, subscr,
			"SUP protocol remote error, MM cause = '%s' (%d)\n",
			get_value_string(gsm48_gmm_cause_names, gsup_msg->cause),
			gsup_msg->cause);
		break;
	}

	return -gsup_msg->cause;
}

/*
static int subscr_handle_sup_auth_err(struct gsm_subscriber *subscr,
					    struct osmo_gsup_message *gsup_msg)
{
	int cause_err;
	struct gsm_subscriber_connection *conn = connection_for_subscr(subscr);
	gsm_cbfn *cb = conn->sec_operation->cb;

	cause_err = check_cause(gsup_msg->cause);

	LOGGSUBSCRP(LOGL_DEBUG, subscr,
		"Send authentication info has failed with cause %d, "
		"handled as: %s\n",
		gsup_msg->cause, strerror(cause_err));

	switch (cause_err) {
	case EACCES:
		LOGGSUBSCRP(LOGL_NOTICE, subscr,
			"GSM send auth info req failed, access denied, "
			"MM cause = '%s' (%d)\n",
			get_value_string(gsm48_gmm_cause_names, gsup_msg->cause),
			gsup_msg->cause);
		if (cb)
			cb(GSM_HOOK_RR_SECURITY, GSM_SECURITY_AUTH_FAILED,
			   NULL, conn, conn->sec_operation->cb_data);
		release_security_operation(conn);
		break;

	case EHOSTUNREACH:
		LOGGSUBSCRP(LOGL_NOTICE, subscr,
			"GSM send auth info req failed, MM cause = '%s' (%d)\n",
			get_value_string(gsm48_gmm_cause_names, gsup_msg->cause),
			gsup_msg->cause);
		// TODO: Try to resend auth request?
		if (cb)
			cb(GSM_HOOK_RR_SECURITY, GSM_SECURITY_AUTH_FAILED,
			   NULL, conn, conn->sec_operation->cb_data);
		release_security_operation(conn);
		break;

	default:
	case EINVAL:
		LOGGSUBSCRP(LOGL_ERROR, subscr,
			"SUP protocol remote error, MM cause = '%s' (%d)\n",
			get_value_string(gsm48_gmm_cause_names, gsup_msg->cause),
			gsup_msg->cause);
		break;
	}

	return -gsup_msg->cause;
}
*/
static int subscr_handle_unknown_imsi(struct gsup_client *sup_client,
									  struct osmo_gsup_message *gsup_msg)
{
	if (OSMO_GSUP_IS_MSGT_REQUEST(gsup_msg->message_type)) {
		subscr_tx_sup_error_reply(sup_client, NULL, gsup_msg,
						GMM_CAUSE_IMSI_UNKNOWN);
		LOGP(DSUP, LOGL_NOTICE,
		     "Unknown IMSI %s, discarding SUP request "
		     "of type 0x%02x\n",
		     gsup_msg->imsi, gsup_msg->message_type);
	} else if (OSMO_GSUP_IS_MSGT_ERROR(gsup_msg->message_type)) {
		LOGP(DSUP, LOGL_NOTICE,
		     "Unknown IMSI %s, discarding SUP error "
		     "of type 0x%02x, cause '%s' (%d)\n",
		     gsup_msg->imsi, gsup_msg->message_type,
		     get_value_string(gsm48_gmm_cause_names, gsup_msg->cause),
		     gsup_msg->cause);
	} else {
		LOGP(DSUP, LOGL_NOTICE,
		     "Unknown IMSI %s, discarding SUP response "
		     "of type 0x%02x\n",
		     gsup_msg->imsi, gsup_msg->message_type);
	}

	return -GMM_CAUSE_IMSI_UNKNOWN;
}

static int subscr_rx_sup_message(struct gsup_client *sup_client, struct msgb *msg)
{
	uint8_t *data = msgb_l2(msg);
	size_t data_len = msgb_l2len(msg);
	int rc = 0;

	struct osmo_gsup_message gsup_msg = {0};
	struct gsm_subscriber *subscr;

	if (*data == OSMO_GSUP_MSGT_SMS) {
		return rx_sms_message(sup_client, data, data_len);
	}

	if (*data == OSMO_GSUP_MSGT_RESERVE_UNITS_RESPONSE) {
		return rx_reserve_units_response(sup_client, data, data_len);
	}

	rc = osmo_gsup_decode(data, data_len, &gsup_msg);
	if (rc < 0) {
		LOGP(DSUP, LOGL_ERROR,
		     "decoding SUP message fails with error '%s' (%d)\n",
		     get_value_string(gsm48_gmm_cause_names, -rc), -rc);
		return rc;
	}

	if (!gsup_msg.imsi[0]) {
		LOGP(DSUP, LOGL_ERROR, "Missing IMSI in SUP message\n");

		if (OSMO_GSUP_IS_MSGT_REQUEST(gsup_msg.message_type))
			subscr_tx_sup_error_reply(sup_client, NULL, &gsup_msg,
							GMM_CAUSE_INV_MAND_INFO);
		return -GMM_CAUSE_INV_MAND_INFO;
	}

	if (!gsup_msg.cause && OSMO_GSUP_IS_MSGT_ERROR(gsup_msg.message_type))
		gsup_msg.cause = GMM_CAUSE_NET_FAIL;

	subscr = subscr_get_by_imsi(NULL, gsup_msg.imsi);

	if (!subscr) {
		return subscr_handle_unknown_imsi(sup_client, &gsup_msg);
	}

	LOGGSUBSCRP(LOGL_INFO, subscr,
		"Received SUP message of type 0x%02x\n", gsup_msg.message_type);

	switch (gsup_msg.message_type) {
/*
	case OSMO_GSUP_MSGT_SEND_AUTH_INFO_RESULT:
		rc = subscr_handle_sup_auth_res(sup_client, subscr, &gsup_msg);
		break;

	case OSMO_GSUP_MSGT_SEND_AUTH_INFO_ERROR:
		rc = subscr_handle_sup_auth_err(subscr, &gsup_msg);
		break;
*/
	case OSMO_GSUP_MSGT_UPDATE_LOCATION_RESULT:
		rc = subscr_handle_sup_upd_loc_res(subscr, &gsup_msg);
		break;

	case OSMO_GSUP_MSGT_UPDATE_LOCATION_ERROR:
		rc = subscr_handle_sup_upd_loc_err(subscr, &gsup_msg);
		break;

	case OSMO_GSUP_MSGT_LOCATION_CANCEL_REQUEST:
	case OSMO_GSUP_MSGT_PURGE_MS_ERROR:
	case OSMO_GSUP_MSGT_PURGE_MS_RESULT:
		rc = subscr_handle_sup_purge_ms_res(subscr, &gsup_msg);
		break;

	case OSMO_GSUP_MSGT_SEND_AUTH_INFO_RESULT:
	case OSMO_GSUP_MSGT_SEND_AUTH_INFO_ERROR:
	case OSMO_GSUP_MSGT_INSERT_DATA_REQUEST:
	case OSMO_GSUP_MSGT_DELETE_DATA_REQUEST:
		LOGGSUBSCRP(LOGL_ERROR, subscr,
			"Rx SUP message type %d not yet implemented\n",
			gsup_msg.message_type);
		subscr_tx_sup_error_reply(sup_client, subscr, &gsup_msg,
						GMM_CAUSE_MSGT_NOTEXIST_NOTIMPL);
		rc = -GMM_CAUSE_MSGT_NOTEXIST_NOTIMPL;
		break;

	default:
		LOGGSUBSCRP(LOGL_ERROR, subscr,
			"Rx SUP message type %d not valid at SGSN\n",
			gsup_msg.message_type);
		if (OSMO_GSUP_IS_MSGT_REQUEST(gsup_msg.message_type))
			subscr_tx_sup_error_reply(sup_client, subscr, &gsup_msg,
							GMM_CAUSE_MSGT_NOTEXIST_NOTIMPL);
		rc = -GMM_CAUSE_MSGT_NOTEXIST_NOTIMPL;
		break;
	};

	subscr_put(subscr);

	return rc;
}

int sup_read_cb(struct gsup_client *sup_client, struct msgb *msg)
{
	int rc;

	rc = subscr_rx_sup_message(sup_client, msg);
	msgb_free(msg);
	if (rc < 0)
		return -1;

	return rc;
}
