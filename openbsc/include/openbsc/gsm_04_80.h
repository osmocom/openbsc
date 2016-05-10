#ifndef _GSM_04_80_H
#define _GSM_04_80_H

#include <osmocom/core/msgb.h>
#include <osmocom/gsm/protocol/gsm_04_80.h>
#include <osmocom/gsm/gsm0480.h>

struct gsm_subscriber_connection;

int gsm0480_send_ussd_response(struct gsm_subscriber_connection *conn,
			       const struct msgb *in_msg, const char* response_text, 
			       const struct ussd_request *req);
int gsm0480_send_ussd_reject(struct gsm_subscriber_connection *conn,
			     const struct msgb *msg, 
			     const struct ussd_request *request);

struct msgb *gsm0480_gen_ussdNotify(int level, const char *text);
struct msgb *gsm0480_gen_releaseComplete(void);

int msc_gsm0480_send_ussdNotify(struct gsm_subscriber_connection *conn,
				int level, const char *text);
int msc_gsm0480_send_releaseComplete(struct gsm_subscriber_connection *conn);

/* TODO: move to a bsc_*.h file? */
int bsc_gsm0480_send_ussdNotify(struct gsm_subscriber_connection *conn,
				int level, const char *text);
int bsc_gsm0480_send_releaseComplete(struct gsm_subscriber_connection *conn);

#endif
