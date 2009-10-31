#ifndef _GSM48_GPRS_H
#define _GSM48_GPRS_H

/* Table 10.4 / 10.4a, GPRS Mobility Management (GMM) */
#define GSM48_MT_GMM_ATTACH_REQ		0x01
#define GSM48_MT_GMM_ATTACH_ACK		0x02
#define GSM48_MT_GMM_ATTACH_COMPL	0x03
#define GSM48_MT_GMM_ATTACH_REJ		0x04
#define GSM48_MT_GMM_DETACH_REQ		0x05
#define GSM48_MT_GMM_DETACH_ACK		0x06

#define GSM48_MT_GMM_RA_UPD_REQ		0x08
#define GSM48_MT_GMM_RA_UPD_ACK		0x09
#define GSM48_MT_GMM_RA_UPD_COMPL	0x0a
#define GSM48_MT_GMM_RA_UPD_REJ		0x0b

#define GSM48_MT_GMM_PTMSI_REALL_CMD	0x10
#define GSM48_MT_GMM_PTMSI_REALL_COMPL	0x11
#define GSM48_MT_GMM_AUTH_CIPH_REQ	0x12
#define GSM48_MT_GMM_AUTH_CIPH_RESP	0x13
#define GSM48_MT_GMM_AUTH_CIPH_REJ	0x14
#define GSM48_MT_GMM_ID_REQ		0x15
#define GSM48_MT_GMM_ID_RESP		0x16
#define GSM48_MT_GMM_STATUS		0x20
#define GSM48_MT_GMM_INFO		0x21

/* Table 10.4a, GPRS Session Management (GSM) */
#define GSM48_MT_GSM_ACT_PDP_REQ	0x41
#define GSM48_MT_GSM_ACT_PDP_ACK	0x42
#define GSM48_MT_GSM_ACT_PDP_REJ	0x43
#define GSM48_MT_GSM_REQ_PDP_ACT	0x44
#define GSM48_MT_GSM_REQ_PDP_ACT_REJ	0x45
#define GSM48_MT_GSM_DEACT_PDP_REQ	0x46
#define GSM48_MT_GSM_DEACT_PDP_ACK	0x47
#define GSM48_MT_GSM_ACT_AA_PDP_REQ	0x50
#define GSM48_MT_GSM_ACT_AA_PDP_ACK	0x51
#define GSM48_MT_GSM_ACT_AA_PDP_REJ	0x52
#define GSM48_MT_GSM_DEACT_AA_PDP_REQ	0x53
#define GSM48_MT_GSM_DEACT_AA_PDP_ACK	0x54
#define GSM48_MT_GSM_STATUS		0x55

/* Chapter 10.5.5.2 / Table 10.5.135 */
#define GPRS_ATT_T_ATTACH		1
#define GPRS_ATT_T_ATT_WHILE_IMSI	2
#define GPRS_ATT_T_COMBINED		3

/* Chapter 10.5.5.18 / Table 105.150 */
#define GPRS_UPD_T_RA			0
#define GPRS_UPD_T_RA_LA		1
#define GPRS_UPD_T_RA_LA_IMSI_ATT	2
#define GPRS_UPD_T_PERIODIC		3


/* Chapter 10.4.4.15 */
struct gsm48_ra_id {
	u_int8_t digits[3];	/* MCC + MNC BCD digits */
	u_int16_t lac;		/* Location Area Code */
	u_int8_t rac;		/* Routing Area Code */
} __attribute__ ((packed));

/* Chapter 9.4.15 / Table 9.4.15 */
struct gsm48_ra_upd_ack {
	u_int8_t force_stby:4,	/* 10.5.5.7 */
		 upd_result:4;	/* 10.5.5.17 */
	u_int8_t ra_upd_timer;	/* 10.5.7.3 */
	struct gsm48_ra_id ra_id; /* 10.5.5.15 */
	u_int8_t data[0];
} __attribute__((packed));

/* Chapter 10.5.7.3 */
enum gsm48_gprs_tmr_unit {
	GPRS_TMR_2SECONDS	= 0 << 5,
	GPRS_TMR_MINUTE		= 1 << 5,
	GPRS_TMR_6MINUTE	= 2 << 5,
	GPRS_TMR_DEACTIVATED	= 3 << 5,
};

/* Chapter 9.4.2 / Table 9.4.2 */
struct gsm48_attach_ack {
	u_int8_t force_stby:4,	/* 10.5.5.7 */
		 att_result:4;	/* 10.5.5.1 */
	u_int8_t ra_upd_timer;	/* 10.5.7.3 */
	u_int8_t radio_prio;	/* 10.5.7.2 */
	struct gsm48_ra_id ra_id; /* 10.5.5.15 */
	u_int8_t data[0];
} __attribute__((packed));

/* Chapter 10.5.5.14 / Table 10.5.147 */
enum gsm48_gmm_cause {
	GMM_CAUSE_IMSI_UNKNOWN		= 0x02,
	GMM_CAUSE_ILLEGAL_MS		= 0x03,
	GMM_CAUSE_ILLEGAL_ME		= 0x06,
	GMM_CAUSE_GPRS_NOTALLOWED	= 0x07,
	GMM_CAUSE_GPRS_OTHER_NOTALLOWED	= 0x08,
	GMM_CAUSE_MS_ID_NOT_DERIVED	= 0x09,
	GMM_CAUSE_IMPL_DETACHED		= 0x0a,
	GMM_CAUSE_PLMN_NOTALLOWED	= 0x0b,
	GMM_CAUSE_LA_NOTALLOWED		= 0x0c,
	GMM_CAUSE_ROAMING_NOTALLOWED	= 0x0d,
	GMM_CAUSE_NO_GPRS_PLMN		= 0x0e,
	GMM_CAUSE_MSC_TEMP_NOTREACH	= 0x10,
	GMM_CAUSE_NET_FAIL		= 0x11,
	GMM_CAUSE_CONGESTION		= 0x16,
	GMM_CAUSE_SEM_INCORR_MSG	= 0x5f,
	GMM_CAUSE_INV_MAND_INFO		= 0x60,
	GMM_CAUSE_MSGT_NOTEXIST_NOTIMPL	= 0x61,
	GMM_CAUSE_MSGT_INCOMP_P_STATE	= 0x62,
	GMM_CAUSE_IE_NOTEXIST_NOTIMPL	= 0x63,
	GMM_CAUSE_COND_IE_ERR		= 0x64,
	GMM_CAUSE_MSG_INCOMP_P_STATE	= 0x64,
	GMM_CAUSE_PROTO_ERR_UNSPEC	= 0x6f,
};

/* GSM TS 03.03 Chapter 2.6 */
enum gprs_tlli_tyoe {
	TLLI_LOCAL,
	TLLI_FOREIGN,
	TLLI_RANDOM,
	TLLI_AUXILIARY,
	TLLI_RESERVED,
};

int gprs_tlli_type(u_int32_t tlli);


#endif /* _GSM48_GPRS_H */
