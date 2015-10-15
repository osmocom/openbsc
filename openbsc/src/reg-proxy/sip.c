#include <openbsc/sip_client.h>
#include <openbsc/reg_proxy.h>
#include <openbsc/sup.h>
#include <osip2/osip.h>


#define MESSAGE_MAX_LENGTH 4000
#define MAX_ADDR_STR 128
#define MESSAGE_ENTRY_MAX_LENGTH 256
#define SIP_URI_SCHEME "sip"
#define SIP_VERSION "SIP/2.0"
#define EXPIRES_TIME_INSECS 3600
#define SIP_ALLOW "REGISTER, INVITE, INFO, ACK, CANCEL, BYE"




int sip_send(struct sip_client *sip_client, osip_t *osip,
             osip_message_t *msg, osip_fsm_type_t transaction_type)
{
	int status;
	osip_transaction_t *transaction;
	osip_event_t *sip_event;

	status = osip_transaction_init(&transaction, transaction_type, osip, msg);
	if (status) {
		printf("Failed to init transaction %d",status);
		return -1;
	}

	osip_transaction_set_your_instance(transaction, sip_client);

	sip_event = osip_new_outgoing_sipmessage(msg);
	if (!sip_event) {
		printf("Can't allocate message");
		osip_message_free(msg);
		return -1;
	}

	sip_event->transactionid = transaction->transactionid;

	status = osip_message_force_update(msg);

	if (status) {
		printf("Failed force update %d",status);
		osip_message_free(msg);
		return -1;
	}
	
	status = osip_transaction_add_event(transaction, sip_event);

	if (status) {
		printf("Can't add event %d",status);
		osip_message_free(msg);
		return -1;
	}

	printf("Event added, waiting message to send ..... %d\n",status);

	return 0;

}

int tx_sip_register(struct sip_client *sip_client, osip_t *osip, char *imsi)
{
	osip_message_t *reg_msg;

	static int seq_num = 1;
	char *call_id_num = NULL;
	char *seq_num_str = NULL;
	osip_call_id_t *call_id;
	char tmp[MESSAGE_ENTRY_MAX_LENGTH];
	osip_cseq_t *cseq;
	char src_port[6];

	if (osip_message_init(&reg_msg)) {
		OSIP_TRACE(osip_trace(__FILE__,__LINE__,OSIP_BUG,NULL,"Can't init message!\n"));
		return -1;
	}
	osip_message_set_method(reg_msg, osip_strdup("REGISTER"));

	/////
	osip_uri_init(&(reg_msg->req_uri));
	osip_uri_set_scheme(reg_msg->req_uri, SIP_URI_SCHEME);
	osip_uri_set_host (reg_msg->req_uri, sip_client->dst_ip);
	//if (osip_uri_parse(reg_msg->req_uri, SIP_SERVER)) {
	//	OSIP_TRACE(osip_trace(__FILE__,__LINE__,OSIP_BUG,NULL,"uri parse failed!\n"));
	//	osip_message_free(reg_msg);
	//	return -1;
	//}
	////////
	osip_message_set_version(reg_msg, osip_strdup(SIP_VERSION));
	//osip_message_set_status_code(reg_msg, 0);
	//osip_message_set_reason_phrase(reg_msg, NULL);

	sprintf(tmp, "<sip:%s@%s>", imsi, sip_client->dst_ip);
	osip_message_set_to(reg_msg, tmp);
	sprintf(tmp, "<sip:%s@%s>;tag=%u", imsi, sip_client->dst_ip, osip_build_random_number());
	osip_message_set_from(reg_msg, tmp);

	if (osip_call_id_init(&call_id)) {
		OSIP_TRACE(osip_trace(__FILE__,__LINE__,OSIP_BUG,NULL,"call id failed!\n"));
		osip_message_free(reg_msg);
		return -1;
	}
	call_id_num = (char *)osip_malloc(MAX_ADDR_STR);
	sprintf(call_id_num, "%u", osip_build_random_number());
	osip_call_id_set_number(call_id, call_id_num);
	reg_msg->call_id = call_id;

	if (osip_cseq_init(&cseq)) {
		OSIP_TRACE(osip_trace(__FILE__,__LINE__,OSIP_BUG,NULL,"seq init failed!\n"));
		osip_message_free(reg_msg);
		return -1;
	}

	if (seq_num < (1<<30)) {
		seq_num++;
	}
	else {
		seq_num = 1;
	}

	seq_num_str = (char *)osip_malloc(11);
	sprintf(seq_num_str,"%i", seq_num);
	osip_cseq_set_number(cseq, seq_num_str);
	osip_cseq_set_method(cseq, osip_strdup("REGISTER"));
	reg_msg->cseq = cseq;

	osip_message_set_max_forwards(reg_msg, "70");

	sprintf(src_port, "%u", sip_client->src_port);
	sprintf(tmp, "SIP/2.0/%s %s:%s;branch=z9hG4bK%u", "TCP", sip_client->src_ip,
                                          src_port, osip_build_random_number());
	osip_message_set_via(reg_msg, tmp);

	sprintf(tmp, "<sip:%s@%s:%s>", imsi, sip_client->src_ip, src_port);
	osip_message_set_contact(reg_msg, tmp);

	sprintf(tmp, "%i", EXPIRES_TIME_INSECS);
	osip_message_set_expires(reg_msg, tmp);

	osip_message_set_content_length(reg_msg, "0");

	osip_message_set_allow(reg_msg, SIP_ALLOW);

	printf("REG message ready, try to send\n");

	if (sip_send(sip_client, osip, reg_msg, NICT)) {
		printf("Error sending message!");
		return -1;
	}

	return 0;
}

int rx_sip_message(struct sip_client *sip_client, struct msgb *msg)
{
	char sip_msg[MESSAGE_MAX_LENGTH];
	osip_event_t *sipevent;
	struct reg_proxy *reg = sip_client->data;

	printf("processSipMsg: RECEIVED MSG\n");
	strncpy(sip_msg, (char*)msg->data,msg->data_len);
	printf("processSipMsg: sip_msg = %s\n", sip_msg);

	sipevent= osip_parse(sip_msg,msg->data_len);
	if((sipevent==NULL)||(sipevent->sip==NULL)) {
		printf("Could not parse SIP message\n");
		osip_event_free(sipevent);
		return -1;
	}

	if (osip_find_transaction_and_add_event(reg->osip,sipevent)) {
		printf("New transaction!\n");
		if (MSG_IS_REQUEST(sipevent->sip)) {
			printf("Got New Request:%s\n",sip_msg);
		} else if (MSG_IS_RESPONSE(sipevent->sip)) {
			printf("Got New Response:%s\n",sip_msg);
		} else {
			printf("Unsupported message:%s\n",sip_msg);
			osip_event_free(sipevent);
		}
	}
	return 0;
}

static int sip_read_cb(struct sip_client *sip_client, struct msgb *msg)
{
	int rc;
	rc = rx_sip_message(sip_client, msg);
	msgb_free(msg);
	return rc;
}


int sip_cb_send(osip_transaction_t *tr, osip_message_t *sip_msg, char *host, int port, int out_socket)
{

	size_t msg_len;
	char *msg_p;
	struct msgb *msg = sip_msgb_alloc();

	struct sip_client *sip_client = osip_transaction_get_your_instance(tr);
	printf("SIP Send Msg\n");
	
	if(osip_message_to_str(sip_msg, &msg_p, &msg_len) != 0){
		printf("SIP failed to convert message\n");
		return -1;
	}
	printf("SIP convert message ok\n");

	if (!msg_p) {
		printf("SIP msg_p = NULL fail!\n");
		return -1;
	}

	printf("SIP msg_p != NULL OK!, msg_len = %d\n", msg_len);
	memcpy(msg->data, (uint8_t*)msg_p, msg_len);
	msg->data_len = msg_len;
	msg->len += msg_len;
	printf("SIP ready to send msg via IPA\n");
	return sip_client_send(sip_client, msg);
}


void sip_cb_rcv1xx(int type, osip_transaction_t *pott,osip_message_t *pomt)
{
	printf("OSIP_NICT_STATUS_1XX_RECEIVED\n");
}

void sip_cb_rcv2xx(int type, osip_transaction_t *tr, osip_message_t *sip_msg)
{
	printf("OSIP_NICT_STATUS_2XX_RECEIVED\n");
	osip_contact_t *contact;
	osip_to_t* to;
	struct sip_client *sip_client = osip_transaction_get_your_instance(tr);
	struct reg_proxy *reg = sip_client->data;
	char imsi[17];
	char msisdn[15];
	osip_message_get_contact(sip_msg, 0, &contact);
	memcpy(msisdn, contact->url->username, 15);
	
	to = osip_message_get_to(sip_msg);
	memcpy(imsi, to->url->username, 17);

	printf("OSIP_NICT_STATUS_2XX_RECEIVED imsi = %s \n", imsi);
	printf("OSIP_NICT_STATUS_2XX_RECEIVED msisdn = %d \n", msisdn);
	printf("OSIP_NICT_STATUS_2XX_RECEIVED msisdn = %s \n", msisdn);


	handle_location_update_result(reg->sup_server, imsi, msisdn);

}

void sip_cb_rcv2xx_again(int type, osip_transaction_t *pott,osip_message_t *pomt)
{
	printf("OSIP_NICT_STATUS_2XX_RECEIVED_AGAIN\n");
}

void sip_cb_rcv3xx(int type, osip_transaction_t *pott,osip_message_t *pomt)
{
	printf("OSIP_NICT_STATUS_3XX_RECEIVED\n");
}

void sip_cb_rcv4xx(int type, osip_transaction_t *pott,osip_message_t *pomt)
{
	printf("OSIP_NICT_STATUS_4XX_RECEIVED\n");
}
void sip_cb_rcv5xx(int type, osip_transaction_t *pott,osip_message_t *pomt)
{
	printf("OSIP_NICT_STATUS_5XX_RECEIVED\n");
}
void sip_cb_rcv6xx(int type, osip_transaction_t *pott,osip_message_t *pomt)
{
	printf("OSIP_NICT_STATUS_6XX_RECEIVED\n");
}


void sip_set_cbs(osip_t *osip)
{
	osip_set_cb_send_message(osip, sip_cb_send);
	osip_set_message_callback (osip, OSIP_NICT_STATUS_1XX_RECEIVED, sip_cb_rcv1xx);
	osip_set_message_callback (osip, OSIP_NICT_STATUS_2XX_RECEIVED, sip_cb_rcv2xx);
	osip_set_message_callback (osip, OSIP_NICT_STATUS_2XX_RECEIVED_AGAIN, sip_cb_rcv2xx_again);
	osip_set_message_callback (osip, OSIP_NICT_STATUS_3XX_RECEIVED, sip_cb_rcv3xx);
	osip_set_message_callback (osip, OSIP_NICT_STATUS_4XX_RECEIVED, sip_cb_rcv4xx);
	osip_set_message_callback (osip, OSIP_NICT_STATUS_5XX_RECEIVED, sip_cb_rcv5xx);
	osip_set_message_callback (osip, OSIP_NICT_STATUS_6XX_RECEIVED, sip_cb_rcv6xx);
}


int sip_client_init(struct reg_proxy *reg, const char *src_ip, u_int16_t src_port,
                                           const char *dst_ip, u_int16_t dst_port)
{

	reg->sip_client = sip_client_create(src_ip, src_port, dst_ip, dst_port,
                                                        &sip_read_cb, reg);
	if (!reg->sip_client)
		return -1;

	if (osip_init(&reg->osip)!=0)
		return -1;

	sip_set_cbs(reg->osip);

	return 1;
}
