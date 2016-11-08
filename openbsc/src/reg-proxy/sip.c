#include <openbsc/sip_client.h>
#include <openbsc/reg_proxy.h>
#include <openbsc/sup.h>
#include <osmocom/gsm/gsm0480.h>
#include <osip2/osip.h>
#include <osip2/osip_dialog.h>
#include <osip2/osip_fifo.h>
#include <osip2/osip_time.h>
#include <assert.h>

#define MESSAGE_MAX_LENGTH 4000
#define MAX_ADDR_STR 128
#define MESSAGE_ENTRY_MAX_LENGTH 256
#define SIP_URI_SCHEME "sip"
#define SIP_VERSION "SIP/2.0"
#define EXPIRES_TIME_INSECS 3600
#define SIP_ALLOW "REGISTER, INVITE, INFO, ACK, CANCEL, BYE"



int get_seqnum(void)
{
	static int seq_num = 1;
	if (seq_num < (1<<30)) {
		seq_num++;
	}
	else {
		seq_num = 1;
	}
	return seq_num;
}

int sip_send(struct sip_client *sip_client, osip_t *osip,
             osip_message_t *msg, osip_fsm_type_t transaction_type)
{
	int status;
	osip_transaction_t *transaction;
	osip_event_t *sip_event;

	status = osip_transaction_init(&transaction, transaction_type, osip, msg);
	if (status) {
		printf("Failed to init transaction %d",status);
		osip_message_free(msg);
		return -1;
	}

	osip_transaction_set_your_instance(transaction, sip_client);
	osip_transaction_set_reserved6(transaction, osip);

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
	osip_uri_set_scheme(reg_msg->req_uri, osip_strdup(SIP_URI_SCHEME));
	osip_uri_set_host(reg_msg->req_uri, osip_strdup(sip_client->dst_ip));
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

	seq_num_str = (char *)osip_malloc(11);
	sprintf(seq_num_str,"%i", get_seqnum());
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

	sprintf(tmp, "%i",  sip_client->expires_time);
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
	int err;
	struct sip_client *sip_client = osip_transaction_get_your_instance(tr);
	printf("SIP Send Msg\n");
	
	if ((err = osip_message_to_str(sip_msg, &msg_p, &msg_len)) != 0){
		osip_message_free(sip_msg);
		msgb_free(msg);
		printf("SIP failed to convert message: %d\n", err);
		return -1;
	}
	printf("SIP convert message ok\n");

	if (!msg_p) {
		msgb_free(msg);
		osip_message_free(sip_msg);
		printf("SIP msg_p = NULL fail!\n");
		return -1;
	}

	if (sip_client == NULL) {
		osip_dialog_t* diag = (osip_dialog_t* )sip_msg->application_data;
		if (diag == NULL) {
			msgb_free(msg);
			osip_free(msg_p);
			osip_message_free(sip_msg);
			printf("Unable to send:\n%s\n", msg_p);
			return -1;
		}
		sip_client = (struct sip_client *)diag->your_instance;
	}

	printf("SIP msg_p != NULL OK!, msg_len = %d\n", msg_len);
	memcpy(msg->data, (uint8_t*)msg_p, msg_len);
	msg->data_len = msg_len;
	msg->len += msg_len;
	printf("SIP ready to send msg via IPA\n");
	osip_free(msg_p);
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
	char imsi[16];
	char msisdn[16];
	osip_message_get_contact(sip_msg, 0, &contact);
	memcpy(msisdn, contact->url->username, 16);
	
	to = osip_message_get_to(sip_msg);
	memcpy(imsi, to->url->username, 16);
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



void sip_cb_ict_rcv2xx(int type, osip_transaction_t *tr, osip_message_t *sip_msg)
{
	printf("OSIP_ICT_STATUS_2XX_RECEIVED\n");
	//osip_contact_t *contact;
	osip_to_t* to;
	osip_from_t* from;
	struct sip_client *sip_client = osip_transaction_get_your_instance(tr);
	osip_t* osip = osip_transaction_get_reserved6(tr);

	//struct reg_proxy *reg = sip_client->data;

	//char request[32];
	char from_str[32];
	char to_str[32];
	int rc;

	//osip_message_get_contact(sip_msg, 0, &contact);
	//strncpy(request, contact->url->username, sizeof(request));

	from = osip_message_get_from(sip_msg);
	strncpy(from_str, from->url->username, sizeof(from_str));

	to = osip_message_get_to(sip_msg);
	strncpy(to_str, to->url->username, sizeof(to_str));

	printf("FROM: %s TO: %s\n", from_str, to_str);
	osip_dialog_t *dialog;
	if (MSG_IS_RESPONSE_FOR(sip_msg, "INVITE")) {
		//dialog = my_application_search_existing_dialog(sip_msg);
		//if (dialog == NULL) //NO EXISTING DIALOG
		{
			int err = osip_dialog_init_as_uac(&dialog, sip_msg);
			if (err) {
				printf("Can't osip_dialog_init_as_uac %d\n", err);
			}
			//my_application_add_existing_dialog(dialog);
		}
	}
	dialog->your_instance = sip_client;

	osip_message_t *ack_msg;
	if (osip_message_init(&ack_msg)) {
		OSIP_TRACE(osip_trace(__FILE__,__LINE__,OSIP_BUG,NULL,"Can't init message!\n"));
		return;
	}

	osip_message_set_method(ack_msg, osip_strdup("ACK"));

	osip_uri_init(&(ack_msg->req_uri));
	osip_uri_set_scheme(ack_msg->req_uri, osip_strdup(SIP_URI_SCHEME));
	osip_uri_set_username(ack_msg->req_uri, osip_strdup(to_str));
	osip_uri_set_host(ack_msg->req_uri, osip_strdup(sip_client->dst_ip));

	osip_message_set_version(ack_msg, osip_strdup(SIP_VERSION));

	//osip_message_set_to(ack_msg, to->displayname);
	//osip_message_set_from(ack_msg, from->displayname);
	osip_from_clone(from, &ack_msg->from);
	osip_to_clone(to, &ack_msg->to);

	rc = osip_call_id_clone(sip_msg->call_id, &(ack_msg->call_id));
	assert (rc == 0);

	osip_cseq_t* cseq;
	rc = osip_cseq_init(&cseq);
	assert (rc == 0);

	//char* seq_num_str = (char *)osip_malloc(11);
	//sprintf(seq_num_str,"%i", atoi(sip_msg->cseq->number) + 1); // Hardcoded
	osip_cseq_set_number(cseq, osip_strdup(sip_msg->cseq->number));
	osip_cseq_set_method(cseq, osip_strdup("ACK"));
	ack_msg->cseq = cseq;

	osip_message_set_max_forwards(ack_msg, "70");

	char tmp[MESSAGE_ENTRY_MAX_LENGTH];
	snprintf(tmp, sizeof(tmp), "SIP/2.0/%s %s:%s;branch=z9hG4bK-%u",
		 "TCP",
		 //from->url->host,
		 //from->url->port,
		 "127.0.0.1",
		 "5150",
		 osip_build_random_number());

	osip_message_set_via(ack_msg, tmp);

	char src_port[7];
	snprintf(src_port, sizeof(src_port), "%u", sip_client->src_port);
	snprintf(tmp, sizeof(tmp), "<sip:ussd_sip@%s:%s>", sip_client->src_ip, src_port);
	osip_message_set_contact(ack_msg, tmp);

	snprintf(tmp, sizeof(tmp), "%i", EXPIRES_TIME_INSECS);
	osip_message_set_expires(ack_msg, tmp);

	osip_message_set_content_length(ack_msg, "0");
	ack_msg->application_data = dialog;


	int status;
	osip_transaction_t *transaction;
	status = osip_transaction_init(&transaction, ICT, osip, ack_msg);
	if (status) {
		printf("Failed to init transaction %d\n", status);
		return ;
	}

	osip_transaction_set_your_instance(transaction, sip_client);
	osip_transaction_set_reserved5(transaction, dialog);
	osip_transaction_set_reserved6(transaction, osip);

	osip_event_t *sip_event = osip_new_outgoing_sipmessage(ack_msg);
	if (!sip_event) {
		printf("Can't allocate message\n");
		osip_message_free(ack_msg);
		return ;
	}

	sip_event->transactionid = transaction->transactionid;
	status = osip_message_force_update(ack_msg);
	if (status) {
		printf("Failed force update %d\n",status);
		osip_message_free(ack_msg);
		return;
	}

	status = osip_transaction_add_event(transaction, sip_event);
	if (status) {
		printf("Can't add event %d\n",status);
		osip_message_free(ack_msg);
		return;
	}

	osip_ict_execute(osip);
//	osip_start_ack_retransmissions(transaction,
//				       dialog, ack_msg, to->url->host,
//				       (to->url->port) ? atoi(to->url->port) : 5060, -1);

}

void sip_cb_ict_rcv1xx(int type, osip_transaction_t *pott,osip_message_t *pomt)
{
	printf("OSIP_ICT_STATUS_1XX_RECEIVED\n");
}
void sip_cb_ict_rcv2xx_again(int type, osip_transaction_t *pott,osip_message_t *pomt)
{
	printf("OSIP_ICT_STATUS_2XX_RECEIVED_AGAIN\n");
}
void sip_cb_ict_rcv3456xx(int type, osip_transaction_t *pott,osip_message_t *pomt)
{
	printf("OSIP_ICT_STATUS_3456XX_RECEIVED\n");
}

void sip_cb_ict_kill_transaction(int type, osip_transaction_t *tr)
{
	printf("OSIP_ICT_KILL_TRANSACTION\n");
	//int i = osip_remove_transaction (osip_transaction_get_reserved6(tr), tr);
	//i = osip_transaction_free2(tr);
	//if (i != 0) fprintf(stderr, "cannot remove transaction\n");
	printf("KILLED TRANSACTION\n");
}

void cb_transport_error(int type, osip_transaction_t *a, int error)
{
	printf("OSIP_ICT_TRANSPORT_ERROR trnasaction: %p error: %d\n",
	       a, error);
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

	osip_set_message_callback (osip, OSIP_ICT_STATUS_1XX_RECEIVED, sip_cb_ict_rcv1xx);
	osip_set_message_callback (osip, OSIP_ICT_STATUS_2XX_RECEIVED, sip_cb_ict_rcv2xx);
	osip_set_message_callback (osip, OSIP_ICT_STATUS_2XX_RECEIVED_AGAIN, sip_cb_ict_rcv2xx_again);
	osip_set_message_callback (osip, OSIP_ICT_STATUS_3XX_RECEIVED, sip_cb_ict_rcv3456xx);
	osip_set_message_callback (osip, OSIP_ICT_STATUS_4XX_RECEIVED, sip_cb_ict_rcv3456xx);
	osip_set_message_callback (osip, OSIP_ICT_STATUS_5XX_RECEIVED, sip_cb_ict_rcv3456xx);
	osip_set_message_callback (osip, OSIP_ICT_STATUS_6XX_RECEIVED, sip_cb_ict_rcv3456xx);

	osip_set_kill_transaction_callback(osip, OSIP_ICT_KILL_TRANSACTION, sip_cb_ict_kill_transaction);

	osip_set_transport_error_callback(osip, OSIP_ICT_TRANSPORT_ERROR, cb_transport_error);

	//osip_set_kill_transaction_callback(osip ,OSIP_NIST_KILL_TRANSACTION, &cb_ist_kill_transaction);
	//osip_set_kill_transaction_callback(osip ,OSIP_NICT_KILL_TRANSACTION, &cb_nict_kill_transaction);
	//osip_set_kill_transaction_callback(osip ,OSIP_NIST_KILL_TRANSACTION, &cb_nist_kill_transaction);

}


int sip_client_init(struct reg_proxy *reg, const char *src_ip, u_int16_t src_port,
						 const char *dst_ip, u_int16_t dst_port, int expires_time)
{

	reg->sip_client = sip_client_create(src_ip, src_port, dst_ip, dst_port, expires_time,
                                                        &sip_read_cb, reg);
	if (!reg->sip_client)
		return -1;

	if (osip_init(&reg->osip)!=0)
		return -1;

	sip_set_cbs(reg->osip);

	return 1;
}



// USSD part
#define MAX_USSD_CONTENT 1000

int tx_ss_handle(struct sip_client *sip_client, osip_t *osip, struct ss_request *ss,
		 const char *extention)
{
	osip_message_t *reg_msg;

	//static int seq_num = 1;
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
	osip_message_set_method(reg_msg, osip_strdup("INVITE"));

	/////
	osip_uri_init(&(reg_msg->req_uri));
	osip_uri_set_scheme(reg_msg->req_uri, osip_strdup(SIP_URI_SCHEME));
	osip_uri_set_username(reg_msg->req_uri, osip_strdup(ss->ussd_text));
	osip_uri_set_host(reg_msg->req_uri, osip_strdup(sip_client->dst_ip));
	osip_message_set_version(reg_msg, osip_strdup(SIP_VERSION));


	sprintf(tmp, "<sip:%s@%s>", ss->ussd_text, sip_client->dst_ip);
	osip_message_set_to(reg_msg, tmp);

	sprintf(tmp, "<sip:%s@%s>;tag=%u", extention, sip_client->dst_ip, osip_build_random_number());
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

	seq_num_str = (char *)osip_malloc(11);
	sprintf(seq_num_str,"%i", 1); // Hardcoded
	osip_cseq_set_number(cseq, seq_num_str);
	osip_cseq_set_method(cseq, osip_strdup("INVITE"));
	reg_msg->cseq = cseq;

	osip_message_set_max_forwards(reg_msg, "70");

	snprintf(src_port, sizeof(src_port), "%u", sip_client->src_port);
	snprintf(tmp, sizeof(tmp), "SIP/2.0/%s %s:%s;branch=z9hG4bK-%u", "TCP", sip_client->src_ip,
					  src_port, osip_build_random_number());
	osip_message_set_via(reg_msg, tmp);

	snprintf(tmp, sizeof(tmp), "<sip:ussd_sip@%s:%s>", sip_client->src_ip, src_port);
	osip_message_set_contact(reg_msg, tmp);

	snprintf(tmp, sizeof(tmp), "%i", EXPIRES_TIME_INSECS);
	osip_message_set_expires(reg_msg, tmp);

	// Content
	char content[MAX_USSD_CONTENT];
	int content_len = snprintf(content, sizeof(content),
				   "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
				   "<ussd-data>\n"
				   " <language>%s</language>\n"
				   " <ussd-string>%s</ussd-string>\n"
				   "</ussd-data>",
				   "en",
				   ss->ussd_text);

	snprintf(tmp, sizeof(tmp), "%i", content_len);
	osip_message_set_content_length(reg_msg, tmp);
	osip_message_set_content_type(reg_msg, "application/vnd.3gpp.ussd+xml");

	osip_message_set_body(reg_msg, content, content_len);

	//osip_message_set_allow(reg_msg, SIP_ALLOW);

	printf("REG message ready, try to send\n");

	if (sip_send(sip_client, osip, reg_msg, ICT)) {
		printf("Error sending message!");
		return -1;
	}

	return 0;

}
