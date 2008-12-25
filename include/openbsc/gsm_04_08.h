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
};

/* Chapter 10.5.2.30 */
struct gsm48_req_ref {
	u_int8_t ra;
	u_int8_t t3_high:3,
		 t1_:5;
	u_int8_t t2:5,
		 t3_low:3;
};

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
};

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
	u_int8_t ie_mi;
	u_int8_t mi_len;
	u_int8_t mi[0];
} __attribute__ ((packed));

/* Section 10.1 */
struct gsm48_hdr {
	u_int8_t proto_discr;
	u_int8_t msg_type;
	u_int8_t data[0];
} __attribute__ ((packed));

/* Section 10.2 */
#define GSM48_PDISC_CC		0x02
#define GSM48_PDISC_MM		0x05
#define GSM48_PDISC_RR		0x06
#define GSM48_PDISC_MM_GPRS	0x08
#define GSM48_PDISC_SM		0x0a

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

struct msgb;
struct gsm_bts;

int gsm0408_rcvmsg(struct msgb *msg);
enum gsm_chan_t get_ctype_by_chreq(struct gsm_bts *bts, u_int8_t ra);


#endif
