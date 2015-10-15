#include <openbsc/sup_server.h>
#include <openbsc/reg_proxy.h>
#include <openbsc/debug.h>
#include <openbsc/gprs_gsup_messages.h>
#include <openbsc/sip.h>
#include <openbsc/sup.h>

static int handle_sup_upd_loc_req(struct gsm_sup_server *sup_server,
									struct gprs_gsup_message *sup_msg)
{
	int rc = 0;
	struct reg_proxy *reg = sup_server->app;
	struct sip_client *sip_client = reg->sip_client;
	osip_t *osip = reg->osip;
	LOGGSUPP(LOGL_INFO, sup_msg,
		"Try to send sip_register 0x%02x\n", sup_msg->message_type);
	rc = tx_sip_register(sip_client, osip, sup_msg->imsi);
	LOGGSUPP(LOGL_INFO, sup_msg,
		"Sip_register was send 0x%02x\n", sup_msg->message_type);
	return rc;
}

int rx_sup_message(struct gsm_sup_server *sup_server, struct msgb *msg)
{
	uint8_t *data = msgb_l2(msg);
	size_t data_len = msgb_l2len(msg);
	int rc = 0;

	struct gprs_gsup_message sup_msg = {0};
	//struct gsm_subscriber *subscr;

	rc = gprs_gsup_decode(data, data_len, &sup_msg);
	if (rc < 0) {
		LOGP(DSUP, LOGL_ERROR,
		     "decoding SUP message fails with error '%s' (%d)\n",
		     get_value_string(gsm48_gmm_cause_names, -rc), -rc);
		return rc;
	}

	if (!sup_msg.imsi[0]) {
		LOGP(DSUP, LOGL_ERROR, "Missing IMSI in SUP message\n");

//		if (GPRS_GSUP_IS_MSGT_REQUEST(gsup_msg.message_type))
//			subscr_tx_sup_error_reply(sup_client, NULL, &gsup_msg,
//							GMM_CAUSE_INV_MAND_INFO);
		return -GMM_CAUSE_INV_MAND_INFO;
	}

//	if (!gsup_msg.cause && GPRS_GSUP_IS_MSGT_ERROR(gsup_msg.message_type))
//		gsup_msg.cause = GMM_CAUSE_NET_FAIL;

//	subscr = subscr_get_by_imsi(NULL, gsup_msg.imsi);

//	if (!subscr) {
//		return subscr_handle_unknown_imsi(sup_client, &gsup_msg);
//	}

	LOGGSUPP(LOGL_INFO, &sup_msg,
		"Received SUP message of type 0x%02x\n", sup_msg.message_type);

	switch (sup_msg.message_type) {
	case GPRS_GSUP_MSGT_UPDATE_LOCATION_REQUEST:
		rc = handle_sup_upd_loc_req(sup_server, &sup_msg);
		break;

	case GPRS_GSUP_MSGT_SEND_AUTH_INFO_REQUEST:
		//FIXME!!!!
		//rc = subscr_handle_sup_auth_req(sup_server, &sup_msg);
		rc = handle_sup_upd_loc_req(sup_server, &sup_msg);
		break;
		
	case GPRS_GSUP_MSGT_LOCATION_CANCEL_ERROR:
	case GPRS_GSUP_MSGT_LOCATION_CANCEL_RESULT:
	case GPRS_GSUP_MSGT_PURGE_MS_REQUEST:
	case GPRS_GSUP_MSGT_INSERT_DATA_ERROR:
	case GPRS_GSUP_MSGT_INSERT_DATA_RESULT:
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

	return
	
	
	 rc;
}

static int tx_sup_message(struct gsm_sup_server *sup_server,
								 struct gprs_gsup_message *sup_msg)
{
	struct msgb *msg = gprs_gsup_msgb_alloc();
	printf("tx_sup_message \n");

	gprs_gsup_encode(msg, sup_msg);
	
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
	struct gprs_gsup_message gsup_msg = {0};
	u_int8_t msisdn_enc[9];

	gsup_msg.message_type = GPRS_GSUP_MSGT_UPDATE_LOCATION_RESULT;
	printf("handle_location_update_result 1\n");

	memcpy(gsup_msg.imsi, imsi, 17);
	printf("handle_location_update_result %d  len = %d 2\n", gsup_msg.msisdn_enc, strlen(msisdn));

	gsm48_encode_bcd_number(msisdn_enc, 9, 0, msisdn);
	gsup_msg.msisdn_enc = msisdn_enc + 1;
	gsup_msg.msisdn_enc_len = msisdn_enc[0];
	printf("handle_location_update_result %d %d\n", gsup_msg.msisdn_enc_len, gsup_msg.msisdn_enc);
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
