#ifndef _GSM_04_11_H
#define _GSM_04_11_H

#include <osmocom/gsm/protocol/gsm_04_11.h>

struct vlr_subscr;
struct gsm_subscriber_connection;
struct gsm_trans;

#define UM_SAPI_SMS 3	/* See GSM 04.05/04.06 */

/* SMS deliver PDU */
struct sms_deliver {
	uint8_t mti:2;		/* message type indicator */
	uint8_t mms:1;		/* more messages to send */
	uint8_t rp:1;		/* reply path */
	uint8_t udhi:1;	/* user data header indicator */
	uint8_t sri:1;		/* status report indication */
	uint8_t *orig_addr;	/* originating address */
	uint8_t pid;		/* protocol identifier */
	uint8_t dcs;		/* data coding scheme */
				/* service centre time stamp */
	uint8_t ud_len;	/* user data length */
	uint8_t *user_data;	/* user data */

	uint8_t msg_ref;	/* message reference */
	uint8_t *smsc;
};

struct msgb;

int gsm0411_rcv_sms(struct gsm_subscriber_connection *conn, struct msgb *msg);

struct gsm_sms *sms_alloc(void);
void sms_free(struct gsm_sms *sms);
struct gsm_sms *sms_from_text(struct vlr_subscr *receiver,
			      struct vlr_subscr *sender,
			      int dcs, const char *text);

void _gsm411_sms_trans_free(struct gsm_trans *trans);
int gsm411_send_sms_subscr(struct vlr_subscr *vsub,
			   struct gsm_sms *sms);
int gsm411_send_sms(struct gsm_subscriber_connection *conn,
		    struct gsm_sms *sms);
void gsm411_sapi_n_reject(struct gsm_subscriber_connection *conn);

uint8_t sms_next_rp_msg_ref(uint8_t *next_rp_ref);

int gsm411_send_rp_ack(struct gsm_trans *trans, uint8_t msg_ref);
int gsm411_send_rp_error(struct gsm_trans *trans, uint8_t msg_ref,
			 uint8_t cause);

#endif
