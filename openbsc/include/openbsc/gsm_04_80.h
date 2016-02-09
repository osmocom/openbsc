#ifndef _GSM_04_80_H
#define _GSM_04_80_H

#include <osmocom/core/msgb.h>
#include <osmocom/gsm/protocol/gsm_04_80.h>
#include <osmocom/gsm/gsm0480.h>

struct gsm_subscriber_connection;

int gsm0480_send_component(struct gsm_subscriber_connection *conn,
			   struct msgb *msg,
			   struct ss_header* reqhdr);

int gsm0480_send_ussd_reject(struct gsm_subscriber_connection *conn,
			     uint8_t invoke_id,
			     uint8_t transaction_id);

struct msgb *gsm0480_compose_ussd_component(struct ss_request* req);



int msc_send_ussd_notify(struct gsm_subscriber_connection *conn, int level,
			 const char *text);
int msc_send_ussd_release_complete(struct gsm_subscriber_connection *conn);

int bsc_send_ussd_notify(struct gsm_subscriber_connection *conn, int level,
			 const char *text);
int bsc_send_ussd_release_complete(struct gsm_subscriber_connection *conn);

#endif
