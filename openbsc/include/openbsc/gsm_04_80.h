#ifndef _GSM_04_80_H
#define _GSM_04_80_H

#include <osmocom/core/msgb.h>
#include <osmocom/gsm/protocol/gsm_04_80.h>
#include <osmocom/gsm/protocol/gsm_09_02.h>
#include <osmocom/gsm/gsm0480.h>

static inline unsigned char *msgb_wrap_with_TL(struct msgb *msgb, uint8_t tag)
{
	uint8_t *data = msgb_push(msgb, 2);

	data[0] = tag;
	data[1] = msgb->len - 2;
	return data;
}

static inline unsigned char *msgb_push_TLV1(struct msgb *msgb, uint8_t tag,
					    uint8_t value)
{
	uint8_t *data = msgb_push(msgb, 3);

	data[0] = tag;
	data[1] = 1;
	data[2] = value;
	return data;
}

struct gsm_subscriber_connection;

int gsm0480_send_ussd_response(struct gsm_subscriber_connection *conn,
			       const char* response_text,
			       const struct ss_request *req);
int gsm0480_send_ss_return_result(struct gsm_subscriber_connection *conn,
				  const struct ss_request *req,
				  struct msgb *msg);
int gsm0480_send_ss_reject(struct gsm_subscriber_connection *conn,
			   const struct ss_request *request,
			   uint8_t problem_category,
			   uint8_t problem_code);
int gsm0480_send_ss_return_error(struct gsm_subscriber_connection *conn,
				 const struct ss_request *req,
				 uint8_t error_code,
				 struct msgb *parameters);

int gsm0480_send_ussdNotify(struct gsm_subscriber_connection *conn, int level, const char *text);
int gsm0480_send_releaseComplete(struct gsm_subscriber_connection *conn);

#endif
