#ifndef _GSM_04_11_H
#define _GSM_04_11_H

#include <osmocore/protocol/gsm_04_11.h>

#define UM_SAPI_SMS 3	/* See GSM 04.05/04.06 */

/* SMS deliver PDU */
struct sms_deliver {
	u_int8_t mti:2;		/* message type indicator */
	u_int8_t mms:1;		/* more messages to send */
	u_int8_t rp:1;		/* reply path */
	u_int8_t udhi:1;	/* user data header indicator */
	u_int8_t sri:1;		/* status report indication */
	u_int8_t *orig_addr;	/* originating address */
	u_int8_t pid;		/* protocol identifier */
	u_int8_t dcs;		/* data coding scheme */
				/* service centre time stamp */
	u_int8_t ud_len;	/* user data length */
	u_int8_t *user_data;	/* user data */

	u_int8_t msg_ref;	/* message reference */
	u_int8_t *smsc;
};

struct msgb;

int gsm0411_rcv_sms(struct gsm_subscriber_connection *conn, struct msgb *msg);

struct gsm_sms *sms_alloc(void);
void sms_free(struct gsm_sms *sms);

void _gsm411_sms_trans_free(struct gsm_trans *trans);
int gsm411_send_sms_subscr(struct gsm_subscriber *subscr,
			   struct gsm_sms *sms);
int gsm411_send_sms(struct gsm_subscriber_connection *conn,
		    struct gsm_sms *sms);
void gsm411_sapi_n_reject(struct gsm_subscriber_connection *conn);
#endif
