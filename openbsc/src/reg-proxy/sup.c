#include <openbsc/sup_server.h>
#include <openbsc/gsup_client.h>
#include <openbsc/reg_proxy.h>
#include <openbsc/debug.h>
#include <osmocom/gsm/gsup.h>
#include <openbsc/sip.h>
#include <openbsc/sup.h>
#include <openbsc/gsm_04_08.h>
#include <osmocom/gsm/gsm0480.h>
#include <openbsc/ussd.h>

static int handle_sup_upd_loc_req(struct gsm_sup_server *sup_server,
									struct osmo_gsup_message *sup_msg)
{
	int rc = 0;
	struct reg_proxy *reg = sup_server->app;
	struct sip_client *sip_client = reg->sip_client;
	osip_t *osip = reg->osip;
	LOGGSUPP(LOGL_INFO, sup_msg,
		"Try to send sip_register 0x%02x\n", sup_msg->message_type);
	rc = tx_sip_register(sip_client, osip, sup_msg->imsi, sip_client->expires_time);
	LOGGSUPP(LOGL_INFO, sup_msg,
		"Sip_register was send 0x%02x\n", sup_msg->message_type);
	return rc;
}

static int handle_sup_purge_ms_req(struct gsm_sup_server *sup_server,
									struct osmo_gsup_message *sup_msg)
{
	int rc = 0;
	struct reg_proxy *reg = sup_server->app;
	struct sip_client *sip_client = reg->sip_client;
	osip_t *osip = reg->osip;
	LOGGSUPP(LOGL_INFO, sup_msg,
		"Try to send sip_register (cancellation) 0x%02x\n", sup_msg->message_type);
	rc = tx_sip_register(sip_client, osip, sup_msg->imsi, 0);
	LOGGSUPP(LOGL_INFO, sup_msg,
		"Sip_register (cancellation) was send 0x%02x\n", sup_msg->message_type);
	return rc;
}

#if 0
static int handle_sup_ss(struct gsm_sup_server *sup_server,
			 struct ss_request *ss,
			 const char* extention)
{
	int rc = 0;
	struct reg_proxy *reg = sup_server->app;
	struct sip_client *sip_client = reg->sip_client;
	osip_t *osip = reg->osip;

	LOGP(DGPRS, LOGL_INFO,
		"Try to send sip_register 0x%02x\n", ss->message_type);
	rc = tx_ss_handle(sip_client, osip, ss, extention);
	LOGP(DGPRS, LOGL_INFO,
		"Sip_register was send 0x%02x\n", ss->message_type);
	return rc;
}

enum {
    FMAP_MSISDN        = 0x80
};
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
			len = *(++const_data);
			strncpy((char*)ss->ussd_text,
				(const char*)++const_data,
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
		//msgb_tlv_put(msg, ASN1_OCTET_STRING_TAG, 1, &req->ussd_text_language);
		msgb_tlv_put(msg, ASN1_OCTET_STRING_TAG, req->ussd_text_len, req->ussd_text);
	}

	if (extention) {
		uint8_t bcd_buf[32];
		bcd_len = gsm48_encode_bcd_number(bcd_buf, sizeof(bcd_buf), 0,
						  extention);
		msgb_tlv_put(msg, FMAP_MSISDN, bcd_len - 1, &bcd_buf[1]);
	}

	/* fill actual length */
	gsup_indicator[3] = 3 + 3 + (req->ussd_text_len + 2) + (bcd_len + 2);

	/* wrap with GSM0480_CTYPE_INVOKE */
	// gsm0480_wrap_invoke(msg, req->opcode, invoke_id);
	// gsup_indicator = msgb_push(msgb, 1);
	// gsup_indicator[0] = OSMO_GSUP_MSGT_MAP;
	return 0;
}

static int rx_sup_uss_message(struct gsm_sup_server *sup_server, const uint8_t* data, size_t len)
{
	char extention[32] = {0};
	struct ss_request ss;
	memset(&ss, 0, sizeof(ss));


	if (rx_uss_message_parse(&ss, data, len, extention, sizeof(extention))) {
		LOGP(DSUP, LOGL_ERROR, "Can't parse uss message\n");
		return -1;
	}

	LOGP(DSUP, LOGL_ERROR, "Got mtype=0x%02x invoke_id=0x%02x opcode=0x%02x component_type=0x%02x text=%s\n",
	     ss.message_type, ss.invoke_id, ss.opcode, ss.component_type, ss.ussd_text);

	handle_sup_ss(sup_server, &ss, extention);

	return 0;
#if 0
	if (strcmp((const char*)ss.ussd_text, "*#100#") == 0) {
		ss.ussd_text_len = snprintf(ss.ussd_text,
					    sizeof(ss.ussd_text),
					    "Your extention is %s",
					    extention);

		/* Last message in the transaction */
		ss.message_type = GSM0480_MTYPE_RELEASE_COMPLETE;
		ss.component_type = GSM0480_CTYPE_RETURN_RESULT;
	} else if (strcmp((const char*)ss.ussd_text, "*#101#") == 0) {
		ss.ussd_text_len = snprintf(ss.ussd_text,
					    sizeof(ss.ussd_text),
					    "Select option:\n1) Option 1\n2) Option 2");

		ss.message_type = GSM0480_MTYPE_FACILITY;
		ss.component_type = GSM0480_CTYPE_INVOKE;
		ss.opcode = GSM0480_OP_CODE_USS_REQUEST;
	} else {
		if (ss.component_type == GSM0480_CTYPE_RETURN_RESULT &&
				ss.opcode == GSM0480_OP_CODE_USS_REQUEST) {
			// Menu selected
			char buffer[160];
			strncpy(buffer, ss.ussd_text, sizeof(buffer));
			ss.ussd_text_len = snprintf(ss.ussd_text,
						    sizeof(ss.ussd_text),
						    "You've selected \"%s\"",
						    buffer);

			ss.message_type = GSM0480_MTYPE_RELEASE_COMPLETE;
			ss.component_type = GSM0480_CTYPE_RETURN_RESULT;
			ss.opcode = GSM0480_OP_CODE_PROCESS_USS_REQ;
		} else {
			ss.ussd_text_len = 0;
			ss.message_type = GSM0480_MTYPE_RELEASE_COMPLETE;
			ss.component_type = GSM0480_CTYPE_REJECT;
		}
	}

	if (ss.ussd_text_len > sizeof(ss.ussd_text))
		ss.ussd_text_len = sizeof(ss.ussd_text);

	struct msgb *msg = gsup_client_msgb_alloc();
	subscr_uss_message(msg,
			   &ss,
			   (extention[0] == 0) ? NULL : extention);
	LOGP(DGPRS, LOGL_INFO,
	     "Sending USS, will send: %s\n", msgb_hexdump(msg));

	if (!sup_server) {
		msgb_free(msg);
		return -ENOTSUP;
	}
	return sup_server_send(sup_server, msg);
#endif
}

#endif

int rx_sup_message(struct gsm_sup_server *sup_server, struct msgb *msg)
{
	uint8_t *data = msgb_l2(msg);
	size_t data_len = msgb_l2len(msg);
	int rc = 0;

	struct osmo_gsup_message sup_msg = {0};
	//struct gsm_subscriber *subscr;
#if 0
    if (*data == OSMO_GSUP_MSGT_MAP) {
	LOGP(DSUP, LOGL_INFO,
		   "Receive USS: %s\n", msgb_hexdump(msg));

	return rx_sup_uss_message(sup_server, data, data_len);
    }
#endif
	rc = osmo_gsup_decode(data, data_len, &sup_msg);
	if (rc < 0) {
		LOGP(DSUP, LOGL_ERROR,
		     "decoding SUP message fails with error '%s' (%d)\n",
		     get_value_string(gsm48_gmm_cause_names, -rc), -rc);
		return rc;
	}

	if (!sup_msg.imsi[0]) {
		LOGP(DSUP, LOGL_ERROR, "Missing IMSI in SUP message\n");

//		if (OSMO_GSUP_IS_MSGT_REQUEST(gsup_msg.message_type))
//			subscr_tx_sup_error_reply(sup_client, NULL, &gsup_msg,
//							GMM_CAUSE_INV_MAND_INFO);
		return -GMM_CAUSE_INV_MAND_INFO;
	}

//	if (!gsup_msg.cause && OSMO_GSUP_IS_MSGT_ERROR(gsup_msg.message_type))
//		gsup_msg.cause = GMM_CAUSE_NET_FAIL;

//	subscr = subscr_get_by_imsi(NULL, gsup_msg.imsi);

//	if (!subscr) {
//		return subscr_handle_unknown_imsi(sup_client, &gsup_msg);
//	}

	LOGGSUPP(LOGL_INFO, &sup_msg,
		"Received SUP message of type 0x%02x\n", sup_msg.message_type);

	switch (sup_msg.message_type) {
	case OSMO_GSUP_MSGT_UPDATE_LOCATION_REQUEST:
		rc = handle_sup_upd_loc_req(sup_server, &sup_msg);
		break;

	case OSMO_GSUP_MSGT_SEND_AUTH_INFO_REQUEST:
		//FIXME!!!!
		//rc = subscr_handle_sup_auth_req(sup_server, &sup_msg);
		rc = handle_sup_upd_loc_req(sup_server, &sup_msg);
		break;
		
	case OSMO_GSUP_MSGT_LOCATION_CANCEL_ERROR:
	case OSMO_GSUP_MSGT_LOCATION_CANCEL_RESULT:
	case OSMO_GSUP_MSGT_PURGE_MS_REQUEST:
		rc = handle_sup_purge_ms_req(sup_server, &sup_msg);
		break;

	case OSMO_GSUP_MSGT_INSERT_DATA_ERROR:
	case OSMO_GSUP_MSGT_INSERT_DATA_RESULT:
		LOGGSUPP(LOGL_ERROR, &sup_msg,
			"Rx SUP message type %d not yet implemented\n",
			sup_msg.message_type);
		//tx_sup_error_reply(sup_server, &sup_msg,
		//				GMM_CAUSE_MSGT_NOTEXIST_NOTIMPL);
		rc = -GMM_CAUSE_MSGT_NOTEXIST_NOTIMPL;
		break;

	default:
		LOGGSUPP(LOGL_ERROR, &sup_msg,
			"Rx SUP message type %d not valid\n",
			sup_msg.message_type);
		rc = -GMM_CAUSE_MSGT_NOTEXIST_NOTIMPL;
		break;
	};

	//subscr_put(subscr);

	return rc;
}

static int tx_sup_message(struct gsm_sup_server *sup_server,
								 struct osmo_gsup_message *sup_msg)
{
	struct msgb *msg = gsup_client_msgb_alloc();
	printf("tx_sup_message \n");

	osmo_gsup_encode(msg, sup_msg);
	
	printf("tx_sup_message encoded\n");


	LOGGSUPP(LOGL_INFO, sup_msg,
		    "Sending SUP, will send: %s\n", msgb_hexdump(msg));

	if (!sup_server) {
		msgb_free(msg);
		return -ENOTSUP;
	}
	printf("tx_sup_message lets try to send\n");
	return sup_server_send(sup_server, msg);
}

int handle_location_update_result(struct gsm_sup_server *sup_server,
								 char *imsi, char *msisdn)
{
	struct osmo_gsup_message gsup_msg = {0};
	u_int8_t msisdn_enc[9];

	gsup_msg.message_type = OSMO_GSUP_MSGT_UPDATE_LOCATION_RESULT;
	printf("handle_location_update_result 1\n");

	memcpy(gsup_msg.imsi, imsi, 17);
	printf("handle_location_update_result %d  len = %d 2\n", gsup_msg.msisdn_enc, strlen(msisdn));

	if (strcmp(imsi, msisdn) != 0) {
		gsm48_encode_bcd_number(msisdn_enc, 9, 0, msisdn);
		(&gsup_msg)->msisdn_enc = msisdn_enc + 1;
		gsup_msg.msisdn_enc_len = msisdn_enc[0];
		printf("handle_location_update_result %d %d\n", gsup_msg.msisdn_enc_len, gsup_msg.msisdn_enc);
	}

	return tx_sup_message(sup_server, &gsup_msg);
}

int handle_purge_ms_result(struct gsm_sup_server *sup_server,
								 char *imsi)
{
	struct osmo_gsup_message gsup_msg = {0};
	gsup_msg.message_type = OSMO_GSUP_MSGT_PURGE_MS_RESULT;
	memcpy(gsup_msg.imsi, imsi, 17);
	return tx_sup_message(sup_server, &gsup_msg);
}

static int sup_read_cb(struct gsm_sup_server *sup_server, struct msgb *msg)
{
	int rc;

	printf("Got message from nitb!\n");

	rc = rx_sup_message(sup_server, msg);
	msgb_free(msg);
	if (rc < 0)
		return -1;

	return rc;
}

int sup_server_init(struct reg_proxy *reg)
{
	const char *addr_str;

	addr_str = "127.0.0.1";

	reg->sup_server = sup_server_create(addr_str, 8183, &sup_read_cb, reg);

	if (!reg->sup_server)
		return -1;

	return 1;
}
