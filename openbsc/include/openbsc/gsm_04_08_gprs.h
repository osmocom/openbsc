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

enum gsm48_gprs_ie_mm {
	GSM48_IE_GMM_TIMER_READY	= 0x17, /* 10.5.7.3 */
	GSM48_IE_GMM_PTMSI_SIG		= 0x19,	/* 10.5.5.8 */
	GSM48_IE_GMM_AUTH_RAND		= 0x21, /* 10.5.3.1 */
	GSM48_IE_GMM_AUTH_SRES		= 0x22, /* 10.5.3.2 */
	GSM48_IE_GMM_IMEISV		= 0x23, /* 10.5.1.4 */
	GSM48_IE_GMM_DRX_PARAM		= 0x27,	/* 10.5.5.6 */
	GSM48_IE_GMM_MS_NET_CAPA	= 0x31,	/* 10.5.5.12 */
};

enum gsm48_gprs_ie_sm {
	GSM48_IE_GSM_APN		= 0x28,	/* 10.5.6.1 */
	GSM48_IE_GSM_PROTO_CONF_OPT	= 0x27,	/* 10.5.6.3 */
	GSM48_IE_GSM_PDP_ADDR		= 0x2b, /* 10.5.6.4 */
	GSM48_IE_GSM_AA_TMR		= 0x29,	/* 10.5.7.3 */
	GSM48_IE_GSM_NAME_FULL		= 0x43, /* 10.5.3.5a */
	GSM48_IE_GSM_NAME_SHORT		= 0x45, /* 10.5.3.5a */
	GSM48_IE_GSM_TIMEZONE		= 0x46, /* 10.5.3.8 */
	GSM48_IE_GSM_UTC_AND_TZ		= 0x47, /* 10.5.3.9 */
	GSM48_IE_GSM_LSA_ID		= 0x48, /* 10.5.3.11 */
};

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
	u_int8_t att_result:4,	/* 10.5.5.7 */
		 force_stby:4;	/* 10.5.5.1 */
	u_int8_t ra_upd_timer;	/* 10.5.7.3 */
	u_int8_t radio_prio;	/* 10.5.7.2 */
	struct gsm48_ra_id ra_id; /* 10.5.5.15 */
	u_int8_t data[0];
} __attribute__((packed));

/* Chapter 9.5.1 / Table 9.5.1 */
struct gsm48_act_pdp_ctx_req {
	u_int8_t req_nsapi;
	u_int8_t req_llc_sapi;
	u_int8_t req_qos_lv[4];
	u_int8_t data[0];
} __attribute__((packed));

/* Chapter 9.5.2 / Table 9.5.2 */
struct gsm48_act_pdp_ctx_ack {
	u_int8_t llc_sapi;
	u_int8_t qos_lv[4];
	u_int8_t radio_prio:4,
		 spare:4;
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
	GMM_CAUSE_MSG_INCOMP_P_STATE	= 0x65,
	GMM_CAUSE_PROTO_ERR_UNSPEC	= 0x6f,
};

/* Chapter 10.4.6.6 / Table 10.5.157 */
enum gsm48_gsm_cause {
	GSM_CAUSE_INSUFF_RSRC		= 0x1a,
	GSM_CAUSE_MISSING_APN		= 0x1b,
	GSM_CAUSE_UNKNOWN_PDP		= 0x1c,
	GSM_CAUSE_AUTH_FAILED		= 0x1d,
	GSM_CAUSE_ACT_REJ_GGSN		= 0x1e,
	GSM_CAUSE_ACT_REJ_UNSPEC	= 0x1f,
	GSM_CAUSE_SERV_OPT_NOTSUPP	= 0x20,
	GSM_CAUSE_REQ_SERV_OPT_NOTSUB	= 0x21,
	GSM_CAUSE_SERV_OPT_TEMP_OOO	= 0x22,
	GSM_CAUSE_NSAPI_IN_USE		= 0x23,
	GSM_CAUSE_DEACT_REGULAR		= 0x24,
	GSM_CAUSE_QOS_NOT_ACCEPTED	= 0x25,
	GSM_CAUSE_NET_FAIL		= 0x26,
	GSM_CAUSE_REACT_RQD		= 0x27,
	GSM_CAUSE_FEATURE_NOTSUPP	= 0x28,
	GSM_CAUSE_INVALID_TRANS_ID	= 0x51,
	GSM_CAUSE_SEM_INCORR_MSG	= 0x5f,
	GSM_CAUSE_INV_MAND_INFO		= 0x60,
	GSM_CAUSE_MSGT_NOTEXIST_NOTIMPL	= 0x61,
	GSM_CAUSE_MSGT_INCOMP_P_STATE	= 0x62,
	GSM_CAUSE_IE_NOTEXIST_NOTIMPL	= 0x63,
	GSM_CAUSE_COND_IE_ERR		= 0x64,
	GSM_CAUSE_MSG_INCOMP_P_STATE	= 0x65,
	GSM_CAUSE_PROTO_ERR_UNSPEC	= 0x6f,
};

/* Section 6.1.2.2: Session management states on the network side */
enum gsm48_pdp_state {
	PDP_S_INACTIVE,
	PDP_S_ACTIVE_PENDING,
	PDP_S_ACTIVE,
	PDP_S_INACTIVE_PENDING,
	PDP_S_MODIFY_PENDING,
};

int gprs_tlli_type(u_int32_t tlli);

struct gsm_bts *gsm48_bts_by_ra_id(struct gsm_network *net,
				   const u_int8_t *buf, unsigned int len);

#endif /* _GSM48_GPRS_H */
