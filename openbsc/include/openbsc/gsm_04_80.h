#ifndef _GSM_04_80_H
#define _GSM_04_80_H

#include <osmocom/core/msgb.h>
#include <osmocom/gsm/protocol/gsm_04_80.h>
#include <osmocom/gsm/gsm0480.h>

struct gsm_subscriber_connection;

int gsm0480_send_ussd_response(struct gsm_subscriber_connection *conn,
			       const struct msgb *in_msg,
			       int response_text_len,
			       uint8_t response_lang,
			       const char* response_text,
			       const struct ussd_request *req,
			       uint8_t code,
			       uint8_t ctype,
			       uint8_t mtype);
int gsm0480_send_ussd_reject(struct gsm_subscriber_connection *conn,
			     const struct msgb *msg, 
			     const struct ussd_request *request);

int msc_send_ussd_notify(struct gsm_subscriber_connection *conn, int level,
			 const char *text);
int msc_send_ussd_release_complete(struct gsm_subscriber_connection *conn);

int bsc_send_ussd_notify(struct gsm_subscriber_connection *conn, int level,
			 const char *text);
int bsc_send_ussd_release_complete(struct gsm_subscriber_connection *conn);

#endif
