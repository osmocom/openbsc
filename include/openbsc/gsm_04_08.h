#ifndef _GSM_04_08_H
#define _GSM_04_08_H

/* GSM TS 04.08  definitions */

/* Chapter 10.5.2.5 */
struct gsm48_chan_desc {
	u_int8_t chan_nr;
	union {
		struct {
			u_int8_t maio_high:4,
				 h:1,
				 tsc:3;
			u_int8_t hsn:6,
				 maio_low:2;
		} h1;
		struct {
			u_int8_t arfcn_high:2,
				 spare:2,
				 h:1,
				 tsc:3;
			u_int8_t arfcn_low;
		} h0;
	};
} __attribute__ ((packed));

/* Chapter 10.5.2.30 */
struct gsm48_req_ref {
	u_int8_t ra;
	u_int8_t t3_high:3,
		 t1_:5;
	u_int8_t t2:5,
		 t3_low:3;
} __attribute__ ((packed));

/* Chapter 9.1.18 */
struct gsm48_imm_ass {
	u_int8_t l2_plen;
	u_int8_t proto_discr;
	u_int8_t msg_type;
	u_int8_t page_mode;
	struct gsm48_chan_desc chan_desc;
	struct gsm48_req_ref req_ref;
	u_int8_t timing_advance;
	u_int8_t mob_alloc_len;
	u_int8_t mob_alloc[0];
} __attribute__ ((packed));

/* Chapter 10.5.1.3 */
struct gsm48_loc_area_id {
	u_int8_t digits[3];	/* BCD! */
	u_int16_t lac;
} __attribute__ ((packed));

/* Section 9.2.15 */
struct gsm48_loc_upd_req {
	u_int8_t type:4,
		 key_seq:4;
	struct gsm48_loc_area_id lai;
	u_int8_t classmark1;
	u_int8_t mi_len;
	u_int8_t mi[0];
} __attribute__ ((packed));

/* Section 10.1 */
struct gsm48_hdr {
	u_int8_t proto_discr;
	u_int8_t msg_type;
	u_int8_t data[0];
} __attribute__ ((packed));

/* Section 9.1.3x System information Type header */
struct gsm48_system_information_type_header {
	u_int8_t l2_plen;
	u_int8_t rr_protocol_discriminator :4,
		skip_indicator:4; 
	u_int8_t system_information;
} __attribute__ ((packed));

struct gsm48_rach_control {
	u_int8_t re :1,
		 cell_bar :1,
		 tx_integer :4,
		 max_trans :2;
	u_int8_t t2;
	u_int8_t t3;
} __attribute__ ((packed));

/* Section 9.1.31 System information Type 1 */
struct gsm48_system_information_type_1 {
	struct gsm48_system_information_type_header header;
	u_int8_t cell_channel_description[16];
	struct gsm48_rach_control rach_control;
	u_int8_t s1_reset;
} __attribute__ ((packed));

/* Section 9.1.32 System information Type 2 */
struct gsm48_system_information_type_2 {
	struct gsm48_system_information_type_header header;
	u_int8_t bcch_frequency_list[16];
	u_int8_t ncc_permitted;
	struct gsm48_rach_control rach_control;
} __attribute__ ((packed));

/* Section 9.1.35 System information Type 3 */
struct gsm48_system_information_type_3 {
	struct gsm48_system_information_type_header header;
	u_int16_t cell_identity;
	struct gsm48_loc_area_id lai;
	u_int8_t control_channel_description[3];
	u_int8_t cell_options;
	u_int8_t cell_selection[2];
	struct gsm48_rach_control rach_control;
	u_int8_t s3_reset_octets[4];
} __attribute__ ((packed));

/* Section 9.1.36 System information Type 4 */
struct gsm48_system_information_type_4 {
	struct gsm48_system_information_type_header header;
	struct gsm48_loc_area_id lai;
	u_int8_t cell_selection[2];
	struct gsm48_rach_control rach_control;
	/*	optional CBCH conditional CBCH... followed by
		mandantory SI 4 Reset Octets
	 */
	u_int8_t data[0];
} __attribute__ ((packed));

/* Section 9.1.37 System information Type 5 */
struct gsm48_system_information_type_5 {
	u_int8_t rr_protocol_discriminator :4,
		skip_indicator:4; 
	u_int8_t system_information;
	u_int8_t bcch_frequency_list[16];
} __attribute__ ((packed));

/* Section 9.1.40 System information Type 6 */
struct gsm48_system_information_type_6 {
	u_int8_t rr_protocol_discriminator :4,
		skip_indicator:4; 
	u_int8_t system_information;
	u_int8_t cell_identity[2];
	struct gsm48_loc_area_id lai;
	u_int8_t cell_options;
	u_int8_t ncc_permitted;
	u_int8_t si_6_reset[0];
} __attribute__ ((packed));

/* Section 10.2 + GSM 04.07 12.2.3.1.1 */
#define GSM48_PDISC_GROUP_CC	0x00
#define GSM48_PDISC_BCAST_CC	0x01
#define GSM48_PDISC_PDSS1	0x02
#define GSM48_PDISC_CC		0x03
#define GSM48_PDISC_PDSS2	0x04
#define GSM48_PDISC_MM		0x05
#define GSM48_PDISC_RR		0x06
#define GSM48_PDISC_MM_GPRS	0x08
#define GSM48_PDISC_SMS		0x09
#define GSM48_PDISC_SM_GPRS	0x0a
#define GSM48_PDISC_NC_SS	0x0b
#define GSM48_PDISC_LOC		0x0c
#define GSM48_PDISC_MASK	0x0f

/* Section 10.4 */
#define GSM48_MT_RR_INIT_REQ		0x3c
#define GSM48_MT_RR_ADD_ASS		0x3b
#define GSM48_MT_RR_IMM_ASS		0x3f
#define GSM48_MT_RR_IMM_ASS_EXT		0x39
#define GSM48_MT_RR_IMM_ASS_REJ		0x3a

#define GSM48_MT_RR_CIPH_M_CMD		0x35
#define GSM48_MT_RR_CIPH_M_COMPL	0x32

#define GSM48_MT_RR_CFG_CHG_CMD		0x30
#define GSM48_MT_RR_CFG_CHG_ACK		0x31
#define GSM48_MT_RR_CFG_CHG_REJ		0x33

#define GSM48_MT_RR_ASS_CMD		0x2e
#define GSM48_MT_RR_ASS_COMPL		0x29
#define GSM48_MT_RR_ASS_FAIL		0x2f
#define GSM48_MT_RR_HANDO_CMD		0x2b
#define GSM48_MT_RR_HANDO_COMPL		0x2c
#define GSM48_MT_RR_HANDO_FAIL		0x28
#define GSM48_MT_RR_HANDO_INFO		0x2d

#define GSM48_MT_RR_CELL_CHG_ORDER	0x08
#define GSM48_MT_RR_PDCH_ASS_CMD	0x23

#define GSM48_MT_RR_CHAN_REL		0x0d
#define GSM48_MT_RR_PART_REL		0x0a
#define GSM48_MT_RR_PART_REL_COMP	0x0f

#define GSM48_MT_RR_PAG_REQ_1		0x21
#define GSM48_MT_RR_PAG_REQ_2		0x22
#define GSM48_MT_RR_PAG_REQ_3		0x24
#define GSM48_MT_RR_PAG_RESP		0x27
#define GSM48_MT_RR_NOTIF_NCH		0x20
#define GSM48_MT_RR_NOTIF_FACCH		0x25
#define GSM48_MT_RR_NOTIF_RESP		0x26

#define GSM48_MT_RR_SYSINFO_8		0x18
#define GSM48_MT_RR_SYSINFO_1		0x19
#define GSM48_MT_RR_SYSINFO_2		0x1a
#define GSM48_MT_RR_SYSINFO_3		0x1b
#define GSM48_MT_RR_SYSINFO_4		0x1c
#define GSM48_MT_RR_SYSINFO_5		0x1d
#define GSM48_MT_RR_SYSINFO_6		0x1e
#define GSM48_MT_RR_SYSINFO_7		0x1f

#define GSM48_MT_RR_SYSINFO_2bis	0x02
#define GSM48_MT_RR_SYSINFO_2ter	0x03
#define GSM48_MT_RR_SYSINFO_5bis	0x05
#define GSM48_MT_RR_SYSINFO_5ter	0x06
#define GSM48_MT_RR_SYSINFO_9		0x04
#define GSM48_MT_RR_SYSINFO_13		0x00

#define GSM48_MT_RR_SYSINFO_16		0x3d
#define GSM48_MT_RR_SYSINFO_17		0x3e

#define GSM48_MT_RR_CHAN_MODE_MODIF	0x10
#define GSM48_MT_RR_STATUS		0x12
#define GSM48_MT_RR_CHAN_MODE_MODIF_ACK	0x17
#define GSM48_MT_RR_FREQ_REDEF		0x14
#define GSM48_MT_RR_MEAS_REP		0x15
#define GSM48_MT_RR_CLSM_CHG		0x16
#define GSM48_MT_RR_CLSM_ENQ		0x13
#define GSM48_MT_RR_EXT_MEAS_REP	0x36
#define GSM48_MT_RR_EXT_MEAS_REP_ORD	0x37
#define GSM48_MT_RR_GPRS_SUSP_REQ	0x34

#define GSM48_MT_RR_VGCS_UPL_GRANT	0x08
#define GSM48_MT_RR_UPLINK_RELEASE	0x0e
#define GSM48_MT_RR_UPLINK_FREE		0x0c
#define GSM48_MT_RR_UPLINK_BUSY		0x2a
#define GSM48_MT_RR_TALKER_IND		0x11

#define GSM48_MT_RR_APP_INFO		0x38

/* Table 10.2/3GPP TS 04.08 */
#define GSM48_MT_MM_IMSI_DETACH_IND	0x01
#define GSM48_MT_MM_LOC_UPD_ACCEPT	0x02
#define GSM48_MT_MM_LOC_UPD_REJECT	0x04
#define GSM48_MT_MM_LOC_UPD_REQUEST	0x08

#define GSM48_MT_MM_AUTH_REJ		0x11
#define GSM48_MT_MM_AUTH_REQ		0x12
#define GSM48_MT_MM_AUTH_RESP		0x14
#define GSM48_MT_MM_ID_REQ		0x18
#define GSM48_MT_MM_ID_RESP		0x19
#define GSM48_MT_MM_TMSI_REALL_CMD	0x1a
#define GSM48_MT_MM_TMSI_REALL_COMPL	0x1b

#define GSM48_MT_MM_CM_SERV_ACC		0x21
#define GSM48_MT_MM_CM_SERV_REJ		0x22
#define GSM48_MT_MM_CM_SERV_ABORT	0x23
#define GSM48_MT_MM_CM_SERV_REQ		0x24
#define GSM48_MT_MM_CM_SERV_PROMPT	0x25
#define GSM48_MT_MM_CM_REEST_REQ	0x28
#define GSM48_MT_MM_ABORT		0x29

#define GSM48_MT_MM_NULL		0x30
#define GSM48_MT_MM_STATUS		0x31
#define GSM48_MT_MM_INFO		0x32

/* Table 10.3/3GPP TS 04.08 */
#define GSM48_MT_CC_ALERTING		0x01
#define GSM48_MT_CC_CALL_CONF		0x08
#define GSM48_MT_CC_CALL_PROC		0x02
#define GSM48_MT_CC_CONNECT		0x07
#define GSM48_MT_CC_CONNECT_ACK		0x0f
#define GSM48_MT_CC_EMERG_SETUP		0x0e
#define GSM48_MT_CC_PROGRESS		0x03
#define GSM48_MT_CC_ESTAB		0x04
#define GSM48_MT_CC_ESTAB_CONF		0x06
#define GSM48_MT_CC_RECALL		0x0b
#define GSM48_MT_CC_START_CC		0x09
#define GSM48_MT_CC_SETUP		0x05

#define GSM48_MT_CC_MODIFY		0x17
#define GSM48_MT_CC_MODIFY_COMPL	0x1f
#define GSM48_MT_CC_MODIFY_REJECT	0x13
#define GSM48_MT_CC_USER_INFO		0x10
#define GSM48_MT_CC_HOLD		0x18
#define GSM48_MT_CC_HOLD_ACK		0x19
#define GSM48_MT_CC_HOLD_REJ		0x1a
#define GSM48_MT_CC_RETR		0x1c
#define GSM48_MT_CC_RETR_ACK		0x1d
#define GSM48_MT_CC_RETR_REJ		0x1e

#define GSM48_MT_CC_DISCONNECT		0x25
#define GSM48_MT_CC_RELEASE		0x2d
#define GSM48_MT_CC_RELEASE_COMPL	0xea

#define GSM48_MT_CC_CONG_CTRL		0x39
#define GSM48_MT_CC_NOTIFY		0x3e
#define GSM48_MT_CC_STATUS		0x3d
#define GSM48_MT_CC_STATUS_ENQ		0x34
#define GSM48_MT_CC_START_DTMF		0x35
#define GSM48_MT_CC_STOP_DTMF		0x31
#define GSM48_MT_CC_STOP_DTMF_ACK	0x32
#define GSM48_MT_CC_START_DTMF_ACK	0x36
#define GSM48_MT_CC_START_DTMF_REJ	0x37
#define GSM48_MT_CC_FACILITY		0x3a

/* FIXME: Table 10.4 / 10.4a (GPRS) */

/* Section 10.5.2.26, Table 10.5.64 */
#define GSM48_PM_MASK		0x03
#define GSM48_PM_NORMAL		0x00
#define GSM48_PM_EXTENDED	0x01
#define GSM48_PM_REORG		0x02
#define GSM48_PM_SAME		0x03

/* Table 10.5.4 */
#define GSM_MI_TYPE_MASK	0x07
#define GSM_MI_TYPE_NONE	0x00
#define GSM_MI_TYPE_IMSI	0x01
#define GSM_MI_TYPE_IMEI	0x02
#define GSM_MI_TYPE_IMEISV	0x03
#define GSM_MI_TYPE_TMSI	0x04
#define GSM_MI_ODD		0x08

#define GSM48_IE_MOBILE_ID	0x17

/* Section 10.5.4.11 / Table 10.5.122 */
#define GSM48_CAUSE_CS_GSM	0x60

enum gsm48_cause_loc {
	GSM48_CAUSE_LOC_USER		= 0x00,
	GSM48_CAUSE_LOC_PRN_S_LU	= 0x01,
	GSM48_CAUSE_LOC_PUN_S_LU	= 0x02,
	GSM48_CAUSE_LOC_TRANS_NET	= 0x03,
	GSM48_CAUSE_LOC_PUN_S_RU	= 0x04,
	GSM48_CAUSE_LOC_PRN_S_RU	= 0x05,
	/* not defined */
	GSM48_CAUSE_LOC_INN_NET		= 0x07,
	GSM48_CAUSE_LOC_NET_BEYOND	= 0x0a,
};

/* Annex G, GSM specific cause values for mobility management */
enum gsm48_reject_value {
	GSM48_REJECT_IMSI_UNKNOWN_IN_HLR	= 2,
	GSM48_REJECT_ILLEGAL_MS			= 3,
	GSM48_REJECT_IMSI_UNKNOWN_IN_VLR	= 4,
	GSM48_REJECT_IMEI_NOT_ACCEPTED		= 5,
	GSM48_REJECT_ILLEGAL_ME			= 6,
	GSM48_REJECT_PLMN_NOT_ALLOWED		= 11,
	GSM48_REJECT_LOC_NOT_ALLOWED		= 12,
	GSM48_REJECT_ROAMING_NOT_ALLOWED	= 13,
	GSM48_REJECT_NETWORK_FAILURE		= 17,
	GSM48_REJECT_CONGESTION			= 22,
	GSM48_REJECT_SRV_OPT_NOT_SUPPORTED	= 32,
	GSM48_REJECT_RQD_SRV_OPT_NOT_SUPPORTED	= 33,
	GSM48_REJECT_SRV_OPT_TMP_OUT_OF_ORDER	= 34,
	GSM48_REJECT_CALL_CAN_NOT_BE_IDENTIFIED	= 38,
	GSM48_REJECT_INCORRECT_MESSAGE		= 95,
	GSM48_REJECT_INVALID_MANDANTORY_INF	= 96,
	GSM48_REJECT_MSG_TYPE_NOT_IMPLEMENTED	= 97,
	GSM48_REJECT_MSG_TYPE_NOT_COMPATIBLE	= 98,
	GSM48_REJECT_INF_ELEME_NOT_IMPLEMENTED	= 99,
	GSM48_REJECT_CONDTIONAL_IE_ERROR	= 100,
	GSM48_REJECT_MSG_NOT_COMPATIBLE		= 101,
	GSM48_REJECT_PROTOCOL_ERROR		= 111,

	/* according to G.6 Additional cause codes for GMM */
	GSM48_REJECT_GPRS_NOT_ALLOWED		= 7,
	GSM48_REJECT_SERVICES_NOT_ALLOWED	= 8,
	GSM48_REJECT_MS_IDENTITY_NOT_DERVIVABLE = 9,
	GSM48_REJECT_IMPLICITLY_DETACHED	= 10,
	GSM48_REJECT_GPRS_NOT_ALLOWED_IN_PLMN	= 14,
	GSM48_REJECT_MSC_TMP_NOT_REACHABLE	= 16,
};


struct msgb;
struct gsm_bts;

void gsm0408_allow_everyone(int allow);
int gsm0408_rcvmsg(struct msgb *msg);
void gsm0408_generate_lai(struct gsm48_loc_area_id *lai48, u_int16_t mcc, 
		u_int16_t mnc, u_int16_t lac);
int gsm48_cc_tx_setup(struct gsm_lchan *lchan);
enum gsm_chan_t get_ctype_by_chreq(struct gsm_bts *bts, u_int8_t ra);
enum gsm_chreq_reason_t get_reason_by_chreq(struct gsm_bts *bts, u_int8_t ra);


#endif
