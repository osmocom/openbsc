/* GSM Radio Signalling Link messages on the A-bis interface 
 * 3GPP TS 08.58 version 8.6.0 Release 1999 / ETSI TS 100 596 V8.6.0 */

/* (C) 2008 by Harald Welte <laforge@gnumonks.org>
 * All Rights Reserved
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 */

#ifndef _RSL_H
#define _RSL_H

struct abis_rsl_common_hdr {
	u_int8_t	msg_discr;
	u_int8_t	msg_type;
	u_int8_t	data[0];
} __attribute__ ((packed));

/* Chapter 8.3 */
struct abis_rsl_rll_hdr {
	struct abis_rsl_common_hdr c;
	u_int8_t	ie_chan;
	u_int8_t	chan_nr;
	u_int8_t	ie_link_id;
	u_int8_t	link_id;
	u_int8_t	data[0];
} __attribute__ ((packed));

/* Chapter 8.3 and 8.4 */
struct abis_rsl_dchan_hdr {
	struct abis_rsl_common_hdr c;
	u_int8_t	ie_chan;
	u_int8_t	chan_nr;
	u_int8_t	data[0];
} __attribute__ ((packed));


/* Chapter 9.1 */
#define ABIS_RSL_MDISC_RLL		0x02
#define ABIS_RSL_MDISC_DED_CHAN		0x08
#define ABIS_RSL_MDISC_COM_CHAN		0x0c
#define ABIS_RSL_MDISC_TRX		0x10
#define ABIS_RSL_MDISC_LOC		0x20

#define ABIS_RSL_MDISC_IS_TRANSP(x)	(x & 0x01)

/* Chapter 9.2 */
enum abis_rsl_msgtype {
	/* Radio Link Layer Management */
	RSL_MT_DATA_REQ			= 0x01,
	RSL_MT_DATA_IND,
	RSL_MT_ERROR_IND,
	RSL_MT_EST_REQ,
	RSL_MT_EST_CONF,
	RSL_MT_EST_IND,
	RSL_MT_REL_REQ,
	RSL_MT_REL_CONF,
	RSL_MT_REL_IND,
	RSL_MT_UNIT_DATA_REQ,
	RSL_MT_UNIT_DATA_IND,		/* 0x0b */

	/* Common Channel Management / TRX Management */
	RSL_MT_BCCH_INFO			= 0x11,
	RSL_MT_CCCH_LOAD_IND,
	RSL_MT_CHAN_RQD,
	RSL_MT_DELETE_IND,
	RSL_MT_PAGING_CMD,
	RSL_MT_IMMEDIATE_ASSIGN_CMD,
	RSL_MT_SMS_BC_REQ,
	/* empty */
	RSL_MT_RF_RES_IND			= 0x19,
	RSL_MT_SACCH_FILL,
	RSL_MT_OVERLOAD,
	RSL_MT_ERROR_REPORT,
	RSL_MT_SMS_BC_CMD,
	RSL_MT_CBCH_LOAD_IND,
	RSL_MT_NOT_CMD,			/* 0x1f */

	/* Dedicate Channel Management */
	RSL_MT_CHAN_ACTIV			= 0x21,
	RSL_MT_CHAN_ACTIV_ACK,
	RSL_MT_CHAN_ACTIV_NACK,
	RSL_MT_CONN_FAIL,
	RSL_MT_DEACTIVATE_SACCH,
	RSL_MT_ENCR_CMD,
	RSL_MT_HANDO_DET,
	RSL_MT_MEAS_RES,
	RSL_MT_MODE_MODIFY_REQ,
	RSL_MT_MODE_MODIFY_ACK,
	RSL_MT_MODE_MODIFY_NACK,
	RSL_MT_PHY_CONTEXT_REQ,
	RSL_MT_PHY_CONTEXT_CONF,
	RSL_MT_RF_CHAN_REL,
	RSL_MT_MS_POWER_CONTROL,
	RSL_MT_BS_POWER_CONTROL,		/* 0x30 */
	RSL_MT_PREPROC_CONFIG,
	RSL_MT_PREPROC_MEAS_RES,
	RSL_MT_RF_CHAN_REL_ACK,
	RSL_MT_SACCH_INFO_MODIFY,
	RSL_MT_TALKER_DET,
	RSL_MT_LISTENER_DET,
	RSL_MT_REMOTE_CODEC_CONF_REP,
	RSL_MT_RTD_REP,
	RSL_MT_PRE_HANDO_NOTIF,
	RSL_MT_MR_CODEC_MOD_REQ,
	RSL_MT_MR_CODEC_MOD_ACK,
	RSL_MT_MR_CODEC_MOD_NACK,
	RSL_MT_MR_CODEC_MOD_PER,
	RSL_MT_TFO_REP,
	RSL_MT_TFO_MOD_REQ,		/* 0x3f */
};

/* Chapter 9.3 */
enum abis_rsl_ie {
	RSL_IE_CHAN_NR			= 0x01,
	RSL_IE_LINK_IDENT,
	RSL_IE_ACT_TYPE,
	RSL_IE_BS_POWER,
	RSL_IE_CHAN_IDENT,
	RSL_IE_CHAN_MODE,
	RSL_IE_ENCR_INFO,
	RSL_IE_FRAME_NUMBER,
	RSL_IE_HANDO_REF,
	RSL_IE_L1_INFO,
	RSL_IE_L3_INFO,
	RSL_IE_MS_IDENTITY,
	RSL_IE_MS_POWER,
	RSL_IE_PAGING_GROUP,
	RSL_IE_PAGING_LOAD,
	RSL_IE_PYHS_CONTEXT		= 0x10,
	RSL_IE_ACCESS_DELAY,
	RSL_IE_RACH_LOAD,
	RSL_IE_REQ_REFERENCE,
	RSL_IE_RELEASE_MODE,
	RSL_IE_RESOURCE_INFO,
	RSL_IE_RLM_CAUSE,
	RSL_IE_STARTNG_TIME,
	RSL_IE_TIMING_ADVANCE,
	RSL_IE_UPLINK_MEAS,
	RSL_IE_CAUSE,
	RSL_IE_MEAS_RES_NR,
	RSL_IE_MSG_ID,
	/* reserved */
	RSL_IE_SYSINFO_TYPE		= 0x1e,
	RSL_IE_MS_POWER_PARAM,
	RSL_IE_BS_POWER_PARAM,
	RSL_IE_PREPROC_PARAM,
	RSL_IE_PREPROC_MEAS,
	RSL_IE_IMM_ASS_INFO,		/* Phase 1 (3.6.0), later Full below */
	RSL_IE_SMSCB_INFO		= 0x24,
	RSL_IE_MS_TIMING_OFFSET,
	RSL_IE_ERR_MSG,
	RSL_IE_FULL_BCCH_INFO,
	RSL_IE_CHAN_NEEDED,
	RSL_IE_CB_CMD_TYPE,
	RSL_IE_SMSCB_MSG,
	RSL_IE_FULL_IMM_ASS_INFO,
	RSL_IE_SACCH_INFO,
	RSL_IE_CBCH_LOAD_INFO,
	RSL_IE_SMSCB_CHAN_INDICATOR,
	RSL_IE_GROUP_CALL_REF,
	RSL_IE_CHAN_DESC,
	RSL_IE_NCH_DRX_INFO,
	RSL_IE_CMD_INDICATOR,
	RSL_IE_EMLPP_PRIO,
	RSL_IE_UIC,
	RSL_IE_MAIN_CHAN_REF,
	RSL_IE_MR_CONFIG,
	RSL_IE_MR_CONTROL,
	RSL_IE_SUP_CODEC_TYPES,
	RSL_IE_CODEC_CONFIG,
	RSL_IE_RTD,
	RSL_IE_TFO_STATUS,
	RSL_IE_LLP_APDU,
};

/* Chapter 9.3.1 */
#define RSL_CHAN_NR_MASK	0xf8
#define RSL_CHAN_Bm_ACCHs	0x08
#define RSL_CHAN_Lm_ACCHs	0x10	/* .. 0x18 */
#define RSL_CHAN_SDCCH4_ACCH	0x20	/* .. 0x38 */
#define RSL_CHAN_SDCCH8_ACCH	0x40	/* ...0x78 */
#define RSL_CHAN_BCCH		0x80
#define RSL_CHAN_RACH		0x88
#define RSL_CHAN_PCH_AGCH	0x90

/* Chapter 9.3.3 */
#define RSL_ACT_TYPE_INITIAL	0x00
#define RSL_ACT_TYPE_REACT	0x80
#define RSL_ACT_INTRA_IMM_ASS	0x00
#define RSL_ACT_INTRA_NORM_ASS	0x01
#define RSL_ACT_INTER_ASYNC	0x02
#define RSL_ACT_INTER_SYNC	0x03
#define RSL_ACT_SECOND_ADD	0x04
#define RSL_ACT_SECOND_MULTI	0x05

/* Chapter 9.3.6 */
struct rsl_ie_chan_mode {
	u_int8_t dtx_dtu;
	u_int8_t spd_ind;
	u_int8_t chan_rt;
	u_int8_t chan_rate;
} __attribute__ ((packed));
#define RSL_CMOD_DTXu		0x01	/* uplink */
#define RSL_CMOD_DTXd		0x02	/* downlink */
#define RSL_CMOD_SPD_SPEECH	0x01
#define RSL_CMOD_SPD_DATA	0x02
#define RSL_CMOD_SPD_SIGN	0x03
#define RSL_CMOD_CRT_SDCCH	0x01
#define RSL_CMOD_CRT_TCH_Bm	0x08	/* full-rate */
#define RSL_CMOD_CRT_TCH_Lm	0x09	/* half-rate */
/* FIXME: More CRT types */
#define RSL_CMOD_SP_GSM1	0x01
#define RSL_CMOD_SP_GSM2	0x11
#define RSL_CMOD_SP_GSM3	0x21

/* Chapter 9.3.5 */
struct rsl_ie_chan_ident {
	/* GSM 04.08 10.5.2.5 */
	struct {
		u_int8_t iei;
		u_int8_t chan_nr;	/* enc_chan_nr */
		u_int8_t oct3;
		u_int8_t oct4;
	} chan_desc;
#if 0	/* spec says we need this but Abissim doesn't use it */
	struct {
		u_int8_t tag;
		u_int8_t len;
	} mobile_alloc;
#endif
} __attribute__ ((packed));

/* Chapter 9.3.30 */
#define RSL_SYSTEM_INFO_8	0x00
#define RSL_SYSTEM_INFO_1	0x01
#define RSL_SYSTEM_INFO_2	0x02
#define RSL_SYSTEM_INFO_3	0x03
#define RSL_SYSTEM_INFO_4	0x04
#define RSL_SYSTEM_INFO_5	0x05
#define RSL_SYSTEM_INFO_6	0x06
#define RSL_SYSTEM_INFO_7	0x07
#define RSL_SYSTEM_INFO_16	0x08
#define RSL_SYSTEM_INFO_17	0x09
#define RSL_SYSTEM_INFO_2bis	0x0a
#define RSL_SYSTEM_INFO_2ter	0x0b
#define RSL_SYSTEM_INFO_5bis	0x0d
#define RSL_SYSTEM_INFO_5ter	0x0e
#define RSL_SYSTEM_INFO_10	0x0f
#define REL_EXT_MEAS_ORDER	0x47
#define RSL_MEAS_INFO		0x48
#define RSL_SYSTEM_INFO_13	0x28
#define RSL_SYSTEM_INFO_2quater	0x29
#define RSL_SYSTEM_INFO_9	0x2a
#define RSL_SYSTEM_INFO_18	0x2b
#define RSL_SYSTEM_INFO_19	0x2c
#define RSL_SYSTEM_INFO_20	0x2d

/* Chapter 9.3.40 */
#define RSL_CHANNEED_ANY	0x00
#define RSL_CHANNEED_SDCCH	0x01
#define RSL_CHANNEED_TCH_F	0x02
#define RSL_CHANNEED_TCH_ForH	0x03


#include "msgb.h"

int rsl_bcch_info(struct gsm_bts *bts, u_int8_t type,
		  const u_int8_t *data, int len);
int rsl_sacch_filling(struct gsm_bts *bts, u_int8_t type, 
		      const u_int8_t *data, int len);
int rsl_chan_activate(struct gsm_bts *bts, u_int8_t chan_nr,
		      u_int8_t act_type,
		      struct rsl_ie_chan_mode *chan_mode,
		      struct rsl_ie_chan_ident *chan_ident,
		      u_int8_t bs_power, u_int8_t ms_power,
		      u_int8_t ta);
int rsl_chan_activate_tch_f(struct gsm_bts_trx_ts *ts);
int rsl_chan_activate_sdcch(struct gsm_bts_trx_ts *ts);
int rsl_chan_release(struct gsm_lchan *lchan);
int rsl_paging_cmd(struct gsm_bts *bts, u_int8_t paging_group, u_int8_t len,
		   u_int8_t *ms_ident, u_int8_t chan_needed);
int rsl_paging_cmd_imsi(struct gsm_bts *bts, u_int8_t chan_needed, const char *imsi_str);
int rsl_imm_assign_cmd(struct gsm_bts *bts, u_int8_t len, u_int8_t *val);

int rsl_data_request(struct msgb *msg, u_int8_t link_id);

int abis_rsl_rcvmsg(struct msgb *msg);

/* to be provided by external code */
int abis_rsl_sendmsg(struct msgb *msg);

#endif /* RSL_MT_H */

