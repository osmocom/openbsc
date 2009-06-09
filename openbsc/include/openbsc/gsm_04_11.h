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

/* our own enum, not related to on-air protocol */
enum sms_alphabet {
	DCS_NONE,
	DCS_7BIT_DEFAULT,
	DCS_UCS2,
	DCS_8BIT_DATA,
};

/* SMS submit PDU */
struct sms_submit {
	u_int8_t *smsc;
	u_int8_t mti:2;
	u_int8_t vpf:2;
	u_int8_t msg_ref;
	u_int8_t pid;
	u_int8_t dcs;
	u_int8_t *vp;
	u_int8_t ud_len;
	u_int8_t *user_data;

	/* interpreted */
	u_int8_t mms:1;
	u_int8_t sri:1;
	u_int8_t udhi:1;
	u_int8_t rp:1;
	enum sms_alphabet alphabet;
	char dest_addr[20+1];	/* DA LV is 12 bytes max, i.e. 10 bytes BCD == 20 bytes string */
	unsigned long validity_mins;
	char decoded[256];
};

/* GSM 03.40 / Chapter 9.2.3.1: TP-Message-Type-Indicator */
#define GSM340_SMS_DELIVER_SC2MS	0x00
#define GSM340_SMS_DELIVER_REP_MS2SC	0x00
#define GSM340_SMS_STATUS_REP_SC2MS	0x02
#define GSM340_SMS_COMMAND_MS2SC	0x02
#define GSM340_SMS_SUBMIT_MS2SC		0x01
#define GSM340_SMS_SUBMIT_REP_SC2MS	0x01
#define GSM340_SMS_RESSERVED		0x03

/* GSM 03.40 / Chapter 9.2.3.2: TP-More-Messages-to-Send */
#define GSM340_TP_MMS_MORE		0
#define GSM340_TP_MMS_NO_MORE		1

/* GSM 03.40 / Chapter 9.2.3.3: TP-Validity-Period-Format */
#define GSM340_TP_VPF_NONE		0
#define GSM340_TP_VPF_RELATIVE		2
#define GSM340_TP_VPF_ENHANCED		1
#define GSM340_TP_VPF_ABSOLUTE		3

/* GSM 03.40 / Chapter 9.2.3.4: TP-Status-Report-Indication */
#define GSM340_TP_SRI_NONE		0
#define GSM340_TP_SRI_PRESENT		1

/* GSM 03.40 / Chapter 9.2.3.5: TP-Status-Report-Request */
#define GSM340_TP_SRR_NONE		0
#define GSM340_TP_SRR_REQUESTED		1

/* GSM 03.40 / Chapter 9.2.3.9: TP-Protocol-Identifier */
/* telematic interworking (001 or 111 in bits 7-5) */
#define GSM340_TP_PID_IMPLICIT		0x00
#define GSM340_TP_PID_TELEX		0x01
#define GSM340_TP_PID_FAX_G3		0x02
#define GSM340_TP_PID_FAX_G4		0x03
#define GSM340_TP_PID_VOICE		0x04
#define GSM430_TP_PID_ERMES		0x05
#define GSM430_TP_PID_NATIONAL_PAGING	0x06
#define GSM430_TP_PID_VIDEOTEX		0x07
#define GSM430_TP_PID_TELETEX_UNSPEC	0x08
#define GSM430_TP_PID_TELETEX_PSPDN	0x09
#define GSM430_TP_PID_TELETEX_CSPDN	0x0a
#define GSM430_TP_PID_TELETEX_PSTN	0x0b
#define GSM430_TP_PID_TELETEX_ISDN	0x0c
#define GSM430_TP_PID_TELETEX_UCI	0x0d
#define GSM430_TP_PID_MSG_HANDLING	0x10
#define GSM430_TP_PID_MSG_X400		0x11
#define GSM430_TP_PID_EMAIL		0x12
#define GSM430_TP_PID_GSM_MS		0x1f
/* if bit 7 = 0 and bit 6 = 1 */
#define GSM430_TP_PID_SMS_TYPE_0	0
#define GSM430_TP_PID_SMS_TYPE_1	1
#define GSM430_TP_PID_SMS_TYPE_2	2
#define GSM430_TP_PID_SMS_TYPE_3	3
#define GSM430_TP_PID_SMS_TYPE_4	4
#define GSM430_TP_PID_SMS_TYPE_5	5
#define GSM430_TP_PID_SMS_TYPE_6	6
#define GSM430_TP_PID_SMS_TYPE_7	7
#define GSM430_TP_PID_RETURN_CALL_MSG	0x1f
#define GSM430_TP_PID_ME_DATA_DNLOAD	0x3d
#define GSM430_TP_PID_ME_DE_PERSONAL	0x3e
#define GSM430_TP_PID_ME_SIM_DNLOAD	0x3f

/* GSM 03.38 Chapter 4: SMS Data Coding Scheme */
#define GSM338_DCS_00_

#define GSM338_DCS_1110_7BIT		(0 << 2)
#define GSM338_DCS_1111_7BIT		(0 << 2)
#define GSM338_DCS_1111_8BIT_DATA	(1 << 2)
#define GSM338_DCS_1111_CLASS0		0
#define GSM338_DCS_1111_CLASS1_ME	1
#define GSM338_DCS_1111_CLASS2_SIM	2
#define GSM338_DCS_1111_CLASS3_TE	3	/* See TS 07.05 */


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
