#ifndef _GSM_04_11_H
#define _GSM_04_11_H

/* GSM TS 04.11  definitions */

/* Chapter 8.1.2 (refers to GSM 04.07 Chapter 11.2.3.1.1 */
#define GSM411_PDISC_SMS	0x09

/* Chapter 8.1.3 */
#define GSM411_MT_CP_DATA	0x01
#define GSM411_MT_CP_ACK	0x04
#define GSM411_MT_CP_ERROR	0x10

enum gsm411_cp_ie {
	GSM411_CP_IE_USER_DATA		= 0x01,	/* 8.1.4.1 */
	GSM411_CP_IE_CAUSE		= 0x02,	/* 8.1.4.2. */
};

/* Chapter 8.2.2 */
#define GSM411_MT_RP_DATA_MO	0x00
#define GSM411_MT_RP_DATA_MT	0x01
#define GSM411_MT_RP_ACK_MO	0x02
#define GSM411_MT_RP_ACK_MT	0x03
#define GSM411_MT_RP_ERROR_MO	0x04
#define GSM411_MT_RP_ERROR_MT	0x04
#define GSM411_MT_RP_SMMA_MO	0x05

enum gsm411_rp_ie {
	GSM411_IE_RP_USER_DATA		= 0x41,	/* 8.2.5.3 */
	GSM411_IE_RP_CAUSE		= 0x42,	/* 8.2.5.4 */
};

/* Chapter 8.2.1 */
struct gsm411_rp_hdr {
	u_int8_t len;
	u_int8_t msg_type;
	u_int8_t msg_ref;
	u_int8_t data[0];
} __attribute__ ((packed));

/* SMS submit PDU */
struct sms_submit {
	u_int8_t *smsc;
	u_int8_t mti:2;
	u_int8_t mms:1;
	u_int8_t vpf:2;
	u_int8_t sri:1;
	u_int8_t udhi:1;
	u_int8_t rp:1;
	u_int8_t msg_ref;
	u_int8_t *dest_addr;
	u_int8_t pid;
	u_int8_t dcs;
	u_int8_t vp;
	u_int8_t ud_len;
	u_int8_t *user_data;
};

/* SMS deliver PDU */
struct sms_deliver {
	u_int8_t *smsc;
	u_int8_t mti:2;
	u_int8_t rd:1;
	u_int8_t vpf:2;
	u_int8_t srr:1;
	u_int8_t udhi:1;
	u_int8_t rp:1;
	u_int8_t msg_ref;
	u_int8_t *orig_addr;
	u_int8_t pid;
	u_int8_t dcs;
	u_int8_t vp;
	u_int8_t ud_len;
	u_int8_t *user_data;
};

struct msgb;

int gsm0411_rcv_sms(struct msgb *msg);

int gsm0411_send_sms(struct gsm_lchan *lchan, struct sms_deliver *sms);

struct msgb *gsm411_msgb_alloc(void);
int gsm0411_sendmsg(struct msgb *msg);

#endif
