/* GSM Radio Signalling Link messages on the A-bis interface 
 * 3GPP TS 08.58 version 8.6.0 Release 1999 / ETSI TS 100 596 V8.6.0 */

/* (C) 2008-2009 by Harald Welte <laforge@gnumonks.org>
 *
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

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <openbsc/gsm_data.h>
#include <openbsc/gsm_04_08.h>
#include <openbsc/gsm_utils.h>
#include <openbsc/abis_rsl.h>
#include <openbsc/chan_alloc.h>
#include <openbsc/bsc_rll.h>
#include <openbsc/debug.h>
#include <openbsc/tlv.h>
#include <openbsc/paging.h>
#include <openbsc/signal.h>
#include <openbsc/meas_rep.h>
#include <openbsc/rtp_proxy.h>

#define RSL_ALLOC_SIZE		1024
#define RSL_ALLOC_HEADROOM	128

#define MAX(a, b) (a) >= (b) ? (a) : (b)

static const struct tlv_definition rsl_att_tlvdef = {
	.def = {
		[RSL_IE_CHAN_NR]		= { TLV_TYPE_TV },
		[RSL_IE_LINK_IDENT]		= { TLV_TYPE_TV },
		[RSL_IE_ACT_TYPE]		= { TLV_TYPE_TV },
		[RSL_IE_BS_POWER]		= { TLV_TYPE_TV },
		[RSL_IE_CHAN_IDENT]		= { TLV_TYPE_TLV },
		[RSL_IE_CHAN_MODE]		= { TLV_TYPE_TLV },
		[RSL_IE_ENCR_INFO]		= { TLV_TYPE_TLV },
		[RSL_IE_FRAME_NUMBER]		= { TLV_TYPE_FIXED, 2 },
		[RSL_IE_HANDO_REF]		= { TLV_TYPE_TV },
		[RSL_IE_L1_INFO]		= { TLV_TYPE_FIXED, 2 },
		[RSL_IE_L3_INFO]		= { TLV_TYPE_TL16V },
		[RSL_IE_MS_IDENTITY]		= { TLV_TYPE_TLV },
		[RSL_IE_MS_POWER]		= { TLV_TYPE_TV },
		[RSL_IE_PAGING_GROUP]		= { TLV_TYPE_TV },
		[RSL_IE_PAGING_LOAD]		= { TLV_TYPE_FIXED, 2 },
		[RSL_IE_PYHS_CONTEXT]		= { TLV_TYPE_TLV },
		[RSL_IE_ACCESS_DELAY]		= { TLV_TYPE_TV },
		[RSL_IE_RACH_LOAD]		= { TLV_TYPE_TLV },
		[RSL_IE_REQ_REFERENCE]		= { TLV_TYPE_FIXED, 3 },
		[RSL_IE_RELEASE_MODE]		= { TLV_TYPE_TV },
		[RSL_IE_RESOURCE_INFO]		= { TLV_TYPE_TLV },
		[RSL_IE_RLM_CAUSE]		= { TLV_TYPE_TLV },
		[RSL_IE_STARTNG_TIME]		= { TLV_TYPE_FIXED, 2 },
		[RSL_IE_TIMING_ADVANCE]		= { TLV_TYPE_TV },
		[RSL_IE_UPLINK_MEAS]		= { TLV_TYPE_TLV },
		[RSL_IE_CAUSE]			= { TLV_TYPE_TLV },
		[RSL_IE_MEAS_RES_NR]		= { TLV_TYPE_TV },
		[RSL_IE_MSG_ID]			= { TLV_TYPE_TV },
		[RSL_IE_SYSINFO_TYPE]		= { TLV_TYPE_TV },
		[RSL_IE_MS_POWER_PARAM]		= { TLV_TYPE_TLV },
		[RSL_IE_BS_POWER_PARAM]		= { TLV_TYPE_TLV },
		[RSL_IE_PREPROC_PARAM]		= { TLV_TYPE_TLV },
		[RSL_IE_PREPROC_MEAS]		= { TLV_TYPE_TLV },
		[RSL_IE_IMM_ASS_INFO]		= { TLV_TYPE_TLV },
		[RSL_IE_SMSCB_INFO]		= { TLV_TYPE_FIXED, 23 },
		[RSL_IE_MS_TIMING_OFFSET]	= { TLV_TYPE_TV },
		[RSL_IE_ERR_MSG]		= { TLV_TYPE_TLV },
		[RSL_IE_FULL_BCCH_INFO]		= { TLV_TYPE_TLV },
		[RSL_IE_CHAN_NEEDED]		= { TLV_TYPE_TV },
		[RSL_IE_CB_CMD_TYPE]		= { TLV_TYPE_TV },
		[RSL_IE_SMSCB_MSG]		= { TLV_TYPE_TLV },
		[RSL_IE_FULL_IMM_ASS_INFO]	= { TLV_TYPE_TLV },
		[RSL_IE_SACCH_INFO]		= { TLV_TYPE_TLV },
		[RSL_IE_CBCH_LOAD_INFO]		= { TLV_TYPE_TV },
		[RSL_IE_SMSCB_CHAN_INDICATOR]	= { TLV_TYPE_TV },
		[RSL_IE_GROUP_CALL_REF]		= { TLV_TYPE_TLV },
		[RSL_IE_CHAN_DESC]		= { TLV_TYPE_TLV },
		[RSL_IE_NCH_DRX_INFO]		= { TLV_TYPE_TLV },
		[RSL_IE_CMD_INDICATOR]		= { TLV_TYPE_TLV },
		[RSL_IE_EMLPP_PRIO]		= { TLV_TYPE_TV },
		[RSL_IE_UIC]			= { TLV_TYPE_TLV },
		[RSL_IE_MAIN_CHAN_REF]		= { TLV_TYPE_TV },
		[RSL_IE_MR_CONFIG]		= { TLV_TYPE_TLV },
		[RSL_IE_MR_CONTROL]		= { TLV_TYPE_TV },
		[RSL_IE_SUP_CODEC_TYPES]	= { TLV_TYPE_TLV },
		[RSL_IE_CODEC_CONFIG]		= { TLV_TYPE_TLV },
		[RSL_IE_RTD]			= { TLV_TYPE_TV },
		[RSL_IE_TFO_STATUS]		= { TLV_TYPE_TV },
		[RSL_IE_LLP_APDU]		= { TLV_TYPE_TLV },
		[RSL_IE_SIEMENS_MRPCI]		= { TLV_TYPE_TV },
		[RSL_IE_IPAC_PROXY_UDP]		= { TLV_TYPE_FIXED, 2 },
		[RSL_IE_IPAC_BSCMPL_TOUT]	= { TLV_TYPE_TV },
		[RSL_IE_IPAC_REMOTE_IP]		= { TLV_TYPE_FIXED, 4 },
		[RSL_IE_IPAC_REMOTE_PORT]	= { TLV_TYPE_FIXED, 2 },
		[RSL_IE_IPAC_RTP_PAYLOAD]	= { TLV_TYPE_TV },
		[RSL_IE_IPAC_LOCAL_PORT]	= { TLV_TYPE_FIXED, 2 },
		[RSL_IE_IPAC_SPEECH_MODE]	= { TLV_TYPE_TV },
		[RSL_IE_IPAC_LOCAL_IP]		= { TLV_TYPE_FIXED, 4 },
		[RSL_IE_IPAC_CONN_ID]		= { TLV_TYPE_FIXED, 2 },
		[RSL_IE_IPAC_RTP_CSD_FMT]	= { TLV_TYPE_TV },
		[RSL_IE_IPAC_RTP_JIT_BUF]	= { TLV_TYPE_FIXED, 2 },
		[RSL_IE_IPAC_RTP_COMPR]		= { TLV_TYPE_TV },
		[RSL_IE_IPAC_RTP_PAYLOAD2]	= { TLV_TYPE_TV },
		[RSL_IE_IPAC_RTP_MPLEX]		= { TLV_TYPE_FIXED, 8 },
		[RSL_IE_IPAC_RTP_MPLEX_ID]	= { TLV_TYPE_TV },
	},
};
#define rsl_tlv_parse(dec, buf, len)     \
			tlv_parse(dec, &rsl_att_tlvdef, buf, len, 0, 0)

static u_int8_t mdisc_by_msgtype(u_int8_t msg_type)
{
	/* mask off the transparent bit ? */
	msg_type &= 0xfe;

	if ((msg_type & 0xf0) == 0x00)
		return ABIS_RSL_MDISC_RLL;
	if ((msg_type & 0xf0) == 0x10) {
		if (msg_type >= 0x19 && msg_type <= 0x22)
			return ABIS_RSL_MDISC_TRX;
		else
			return ABIS_RSL_MDISC_COM_CHAN;
	}
	if ((msg_type & 0xe0) == 0x20)
		return ABIS_RSL_MDISC_DED_CHAN;
	
	return ABIS_RSL_MDISC_LOC;
}

static inline void init_dchan_hdr(struct abis_rsl_dchan_hdr *dh,
				  u_int8_t msg_type)
{
	dh->c.msg_discr = mdisc_by_msgtype(msg_type);
	dh->c.msg_type = msg_type;
	dh->ie_chan = RSL_IE_CHAN_NR;
}

static inline void init_llm_hdr(struct abis_rsl_rll_hdr *dh,
				  u_int8_t msg_type)
{
	/* dh->c.msg_discr = mdisc_by_msgtype(msg_type); */
	dh->c.msg_discr = ABIS_RSL_MDISC_RLL;
	dh->c.msg_type = msg_type;
	dh->ie_chan = RSL_IE_CHAN_NR;
	dh->ie_link_id = RSL_IE_LINK_IDENT;
}


/* encode channel number as per Section 9.3.1 */
u_int8_t rsl_enc_chan_nr(u_int8_t type, u_int8_t subch, u_int8_t timeslot)
{
	u_int8_t ret;

	ret = (timeslot & 0x07) | type;
	
	switch (type) {
	case RSL_CHAN_Lm_ACCHs:
		subch &= 0x01;
		break;
	case RSL_CHAN_SDCCH4_ACCH:
		subch &= 0x07;
		break;
	case RSL_CHAN_SDCCH8_ACCH:
		subch &= 0x07;
		break;
	default:
		/* no subchannels allowed */
		subch = 0x00;
		break;
	}
	ret |= (subch << 3);

	return ret;
}

/* determine logical channel based on TRX and channel number IE */
struct gsm_lchan *lchan_lookup(struct gsm_bts_trx *trx, u_int8_t chan_nr)
{
	struct gsm_lchan *lchan;
	u_int8_t ts_nr = chan_nr & 0x07;
	u_int8_t cbits = chan_nr >> 3;
	u_int8_t lch_idx;
	struct gsm_bts_trx_ts *ts = &trx->ts[ts_nr];

	if (cbits == 0x01) {
		lch_idx = 0;	/* TCH/F */	
		if (ts->pchan != GSM_PCHAN_TCH_F &&
		    ts->pchan != GSM_PCHAN_PDCH &&
		    ts->pchan != GSM_PCHAN_TCH_F_PDCH)
			LOGP(DRSL, LOGL_ERROR, "chan_nr=0x%02x but pchan=%u\n",
				chan_nr, ts->pchan);
	} else if ((cbits & 0x1e) == 0x02) {
		lch_idx = cbits & 0x1;	/* TCH/H */
		if (ts->pchan != GSM_PCHAN_TCH_H)
			LOGP(DRSL, LOGL_ERROR, "chan_nr=0x%02x but pchan=%u\n",
				chan_nr, ts->pchan);
	} else if ((cbits & 0x1c) == 0x04) {
		lch_idx = cbits & 0x3;	/* SDCCH/4 */
		if (ts->pchan != GSM_PCHAN_CCCH_SDCCH4)
			LOGP(DRSL, LOGL_ERROR, "chan_nr=0x%02x but pchan=%u\n",
				chan_nr, ts->pchan);
	} else if ((cbits & 0x18) == 0x08) {
		lch_idx = cbits & 0x7;	/* SDCCH/8 */
		if (ts->pchan != GSM_PCHAN_SDCCH8_SACCH8C)
			LOGP(DRSL, LOGL_ERROR, "chan_nr=0x%02x but pchan=%u\n",
				chan_nr, ts->pchan);
	} else if (cbits == 0x10 || cbits == 0x11 || cbits == 0x12) {
		lch_idx = 0;
		if (ts->pchan != GSM_PCHAN_CCCH &&
		    ts->pchan != GSM_PCHAN_CCCH_SDCCH4)
			LOGP(DRSL, LOGL_ERROR, "chan_nr=0x%02x but pchan=%u\n",
				chan_nr, ts->pchan);
		/* FIXME: we should not return first sdcch4 !!! */
	} else {
		LOGP(DRSL, LOGL_ERROR, "unknown chan_nr=0x%02x\n", chan_nr);
		return NULL;
	}

	lchan = &ts->lchan[lch_idx];

	return lchan;
}

/* See Table 10.5.25 of GSM04.08 */
u_int8_t lchan2chan_nr(const struct gsm_lchan *lchan)
{
	struct gsm_bts_trx_ts *ts = lchan->ts;
	u_int8_t cbits, chan_nr;

	switch (ts->pchan) {
	case GSM_PCHAN_TCH_F:
	case GSM_PCHAN_PDCH:
	case GSM_PCHAN_TCH_F_PDCH:
		cbits = 0x01;
		break;
	case GSM_PCHAN_TCH_H:
		cbits = 0x02;
		cbits += lchan->nr;
		break;
	case GSM_PCHAN_CCCH_SDCCH4:
		cbits = 0x04;
		cbits += lchan->nr;
		break;
	case GSM_PCHAN_SDCCH8_SACCH8C:
		cbits = 0x08;
		cbits += lchan->nr;
		break;
	default:
	case GSM_PCHAN_CCCH:
		cbits = 0x10;
		break;
	}

	chan_nr = (cbits << 3) | (ts->nr & 0x7);

	return chan_nr;
}

/* As per TS 03.03 Section 2.2, the IMSI has 'not more than 15 digits' */
u_int64_t str_to_imsi(const char *imsi_str)
{
	u_int64_t ret;

	ret = strtoull(imsi_str, NULL, 10);

	return ret;
}

/* Table 5 Clause 7 TS 05.02 */
unsigned int n_pag_blocks(int bs_ccch_sdcch_comb, unsigned int bs_ag_blks_res)
{
	if (!bs_ccch_sdcch_comb)
		return 9 - bs_ag_blks_res;
	else
		return 3 - bs_ag_blks_res;
}

/* Chapter 6.5.2 of TS 05.02 */
unsigned int get_ccch_group(u_int64_t imsi, unsigned int bs_cc_chans,
			    unsigned int n_pag_blocks)
{
	return (imsi % 1000) % (bs_cc_chans * n_pag_blocks) / n_pag_blocks;
}

/* Chapter 6.5.2 of TS 05.02 */
unsigned int get_paging_group(u_int64_t imsi, unsigned int bs_cc_chans,
			      int n_pag_blocks)
{
	return (imsi % 1000) % (bs_cc_chans * n_pag_blocks) % n_pag_blocks;
}

static struct msgb *rsl_msgb_alloc(void)
{
	return msgb_alloc_headroom(RSL_ALLOC_SIZE, RSL_ALLOC_HEADROOM,
				   "RSL");
}

#define MACBLOCK_SIZE	23
static void pad_macblock(u_int8_t *out, const u_int8_t *in, int len)
{
	memcpy(out, in, len);

	if (len < MACBLOCK_SIZE)
		memset(out+len, 0x2b, MACBLOCK_SIZE-len);
}

/* Chapter 9.3.7: Encryption Information */
static int build_encr_info(u_int8_t *out, struct gsm_lchan *lchan)
{
	*out++ = lchan->encr.alg_id & 0xff;
	if (lchan->encr.key_len)
		memcpy(out, lchan->encr.key, lchan->encr.key_len);
	return lchan->encr.key_len + 1;
}


static const char *rsl_err_vals[0xff] = {
	[RSL_ERR_RADIO_IF_FAIL] =	"Radio Interface Failure",
	[RSL_ERR_RADIO_LINK_FAIL] =	"Radio Link Failure",
	[RSL_ERR_HANDOVER_ACC_FAIL] =	"Handover Access Failure",
	[RSL_ERR_TALKER_ACC_FAIL] =	"Talker Access Failure",
	[RSL_ERR_OM_INTERVENTION] =	"O&M Intervention",
	[RSL_ERR_NORMAL_UNSPEC] =	"Normal event, unspecified",
	[RSL_ERR_T_MSRFPCI_EXP] =	"Siemens: T_MSRFPCI Expired",
	[RSL_ERR_EQUIPMENT_FAIL] =	"Equipment Failure",
	[RSL_ERR_RR_UNAVAIL] =		"Radio Resource not available",
	[RSL_ERR_TERR_CH_FAIL] =	"Terrestrial Channel Failure",
	[RSL_ERR_CCCH_OVERLOAD] =	"CCCH Overload",
	[RSL_ERR_ACCH_OVERLOAD] =	"ACCH Overload",
	[RSL_ERR_PROCESSOR_OVERLOAD] =	"Processor Overload",
	[RSL_ERR_RES_UNAVAIL] =		"Resource not available, unspecified",
	[RSL_ERR_TRANSC_UNAVAIL] =	"Transcoding not available",
	[RSL_ERR_SERV_OPT_UNAVAIL] =	"Service or Option not available",
	[RSL_ERR_ENCR_UNIMPL] =		"Encryption algorithm not implemented",
	[RSL_ERR_SERV_OPT_UNIMPL] =	"Service or Option not implemented",
	[RSL_ERR_RCH_ALR_ACTV_ALLOC] =	"Radio channel already activated",
	[RSL_ERR_INVALID_MESSAGE] =	"Invalid Message, unspecified",
	[RSL_ERR_MSG_DISCR] =		"Message Discriminator Error",
	[RSL_ERR_MSG_TYPE] =		"Message Type Error",
	[RSL_ERR_MSG_SEQ] =		"Message Sequence Error",
	[RSL_ERR_IE_ERROR] =		"General IE error",
	[RSL_ERR_MAND_IE_ERROR] =	"Mandatory IE error",
	[RSL_ERR_OPT_IE_ERROR] =	"Optional IE error",
	[RSL_ERR_IE_NONEXIST] =		"IE non-existent",
	[RSL_ERR_IE_LENGTH] =		"IE length error",
	[RSL_ERR_IE_CONTENT] =		"IE content error",
	[RSL_ERR_PROTO] =		"Protocol error, unspecified",
	[RSL_ERR_INTERWORKING] =	"Interworking error, unspecified",
};

static const char *rsl_err_name(u_int8_t err)
{
	if (rsl_err_vals[err])
		return rsl_err_vals[err];
	else
		return "unknown";
}

static void print_rsl_cause(const u_int8_t *cause_v, u_int8_t cause_len)
{
	int i;

	DEBUGPC(DRSL, "CAUSE=0x%02x(%s) ",
		cause_v[0], rsl_err_name(cause_v[0]));
	for (i = 1; i < cause_len-1; i++) 
		DEBUGPC(DRSL, "%02x ", cause_v[i]);
}

/* Send a BCCH_INFO message as per Chapter 8.5.1 */
int rsl_bcch_info(struct gsm_bts_trx *trx, u_int8_t type,
		  const u_int8_t *data, int len)
{
	struct abis_rsl_dchan_hdr *dh;
	struct msgb *msg = rsl_msgb_alloc();

	dh = (struct abis_rsl_dchan_hdr *) msgb_put(msg, sizeof*dh);
	init_dchan_hdr(dh, RSL_MT_BCCH_INFO);
	dh->chan_nr = RSL_CHAN_BCCH;

	msgb_tv_put(msg, RSL_IE_SYSINFO_TYPE, type);
	msgb_tlv_put(msg, RSL_IE_FULL_BCCH_INFO, len, data);

	msg->trx = trx;

	return abis_rsl_sendmsg(msg);
}

int rsl_sacch_filling(struct gsm_bts_trx *trx, u_int8_t type, 
		      const u_int8_t *data, int len)
{
	struct abis_rsl_common_hdr *ch;
	struct msgb *msg = rsl_msgb_alloc();

	ch = (struct abis_rsl_common_hdr *) msgb_put(msg, sizeof(*ch));
	ch->msg_discr = ABIS_RSL_MDISC_TRX;
	ch->msg_type = RSL_MT_SACCH_FILL;

	msgb_tv_put(msg, RSL_IE_SYSINFO_TYPE, type);
	msgb_tl16v_put(msg, RSL_IE_L3_INFO, len, data);

	msg->trx = trx;

	return abis_rsl_sendmsg(msg);
}

int rsl_chan_bs_power_ctrl(struct gsm_lchan *lchan, unsigned int fpc, int db)
{
	struct abis_rsl_dchan_hdr *dh;
	struct msgb *msg;
	u_int8_t chan_nr = lchan2chan_nr(lchan);

	db = abs(db);
	if (db > 30)
		return -EINVAL;

	msg = rsl_msgb_alloc();

	lchan->bs_power = db/2;
	if (fpc)
		lchan->bs_power |= 0x10;
	
	dh = (struct abis_rsl_dchan_hdr *) msgb_put(msg, sizeof(*dh));
	init_dchan_hdr(dh, RSL_MT_BS_POWER_CONTROL);
	dh->chan_nr = chan_nr;

	msgb_tv_put(msg, RSL_IE_BS_POWER, lchan->bs_power);

	msg->trx = lchan->ts->trx;

	return abis_rsl_sendmsg(msg);
}

int rsl_chan_ms_power_ctrl(struct gsm_lchan *lchan, unsigned int fpc, int dbm)
{
	struct abis_rsl_dchan_hdr *dh;
	struct msgb *msg;
	u_int8_t chan_nr = lchan2chan_nr(lchan);
	int ctl_lvl;

	ctl_lvl = ms_pwr_ctl_lvl(lchan->ts->trx->bts->band, dbm);
	if (ctl_lvl < 0)
		return ctl_lvl;

	msg = rsl_msgb_alloc();

	lchan->ms_power = ctl_lvl;

	if (fpc)
		lchan->ms_power |= 0x20;
	
	dh = (struct abis_rsl_dchan_hdr *) msgb_put(msg, sizeof(*dh));
	init_dchan_hdr(dh, RSL_MT_MS_POWER_CONTROL);
	dh->chan_nr = chan_nr;

	msgb_tv_put(msg, RSL_IE_MS_POWER, lchan->ms_power);

	msg->trx = lchan->ts->trx;

	return abis_rsl_sendmsg(msg);
}

static int channel_mode_from_lchan(struct rsl_ie_chan_mode *cm,
				   struct gsm_lchan *lchan)
{
	memset(cm, 0, sizeof(cm));

	/* FIXME: what to do with data calls ? */
	cm->dtx_dtu = 0x00;

	/* set TCH Speech/Data */
	cm->spd_ind = lchan->rsl_cmode;

	if (lchan->rsl_cmode == RSL_CMOD_SPD_SIGN &&
	    lchan->tch_mode != GSM48_CMODE_SIGN)
		LOGP(DRSL, LOGL_ERROR, "unsupported: rsl_mode == signalling, "
			"but tch_mode != signalling\n");

	switch (lchan->type) {
	case GSM_LCHAN_SDCCH:
		cm->chan_rt = RSL_CMOD_CRT_SDCCH;
		break;
	case GSM_LCHAN_TCH_F:
		cm->chan_rt = RSL_CMOD_CRT_TCH_Bm;
		break;
	case GSM_LCHAN_TCH_H:
		cm->chan_rt = RSL_CMOD_CRT_TCH_Lm;
		break;
	case GSM_LCHAN_NONE:
	case GSM_LCHAN_UNKNOWN:
	default:
		return -EINVAL;
	}

	switch (lchan->tch_mode) {
	case GSM48_CMODE_SIGN:
		cm->chan_rate = 0;
		break;
	case GSM48_CMODE_SPEECH_V1:
		cm->chan_rate = RSL_CMOD_SP_GSM1;
		break;
	case GSM48_CMODE_SPEECH_EFR:
		cm->chan_rate = RSL_CMOD_SP_GSM2;
		break;
	case GSM48_CMODE_SPEECH_AMR:
		cm->chan_rate = RSL_CMOD_SP_GSM3;
		break;
	case GSM48_CMODE_DATA_14k5:
		cm->chan_rate = RSL_CMOD_SP_NT_14k5;
		break;
	case GSM48_CMODE_DATA_12k0:
		cm->chan_rate = RSL_CMOD_SP_NT_12k0;
		break;
	case GSM48_CMODE_DATA_6k0:
		cm->chan_rate = RSL_CMOD_SP_NT_6k0;
		break;
	default:
		return -EINVAL;
	}

	return 0;
}

/* Chapter 8.4.1 */
#if 0
int rsl_chan_activate(struct gsm_bts_trx *trx, u_int8_t chan_nr,
		      u_int8_t act_type,
		      struct rsl_ie_chan_mode *chan_mode,
		      struct rsl_ie_chan_ident *chan_ident,
		      u_int8_t bs_power, u_int8_t ms_power,
		      u_int8_t ta)
{
	struct abis_rsl_dchan_hdr *dh;
	struct msgb *msg = rsl_msgb_alloc();

	dh = (struct abis_rsl_dchan_hdr *) msgb_put(msg, sizeof(*dh));
	init_dchan_hdr(dh, RSL_MT_CHAN_ACTIV);
	dh->chan_nr = chan_nr;

	msgb_tv_put(msg, RSL_IE_ACT_TYPE, act_type);
	/* For compatibility with Phase 1 */
	msgb_tlv_put(msg, RSL_IE_CHAN_MODE, sizeof(*chan_mode),
		     (u_int8_t *) chan_mode);
	msgb_tlv_put(msg, RSL_IE_CHAN_IDENT, 4,
		     (u_int8_t *) chan_ident);
#if 0
	msgb_tlv_put(msg, RSL_IE_ENCR_INFO, 1,
		     (u_int8_t *) &encr_info);
#endif
	msgb_tv_put(msg, RSL_IE_BS_POWER, bs_power);
	msgb_tv_put(msg, RSL_IE_MS_POWER, ms_power);
	msgb_tv_put(msg, RSL_IE_TIMING_ADVANCE, ta);

	msg->trx = trx;

	return abis_rsl_sendmsg(msg);
}
#endif

int rsl_chan_activate_lchan(struct gsm_lchan *lchan, u_int8_t act_type, 
			    u_int8_t ta, u_int8_t ho_ref)
{
	struct abis_rsl_dchan_hdr *dh;
	struct msgb *msg;
	int rc;

	u_int8_t chan_nr = lchan2chan_nr(lchan);
	u_int16_t arfcn = lchan->ts->trx->arfcn;
	struct rsl_ie_chan_mode cm;
	struct rsl_ie_chan_ident ci;

	rc = channel_mode_from_lchan(&cm, lchan);
	if (rc < 0)
		return rc;

	memset(&ci, 0, sizeof(ci));
	ci.chan_desc.iei = 0x64;
	ci.chan_desc.chan_nr = chan_nr;
	ci.chan_desc.oct3 = (lchan->ts->trx->bts->tsc << 5) | ((arfcn & 0x3ff) >> 8);
	ci.chan_desc.oct4 = arfcn & 0xff;

	msg = rsl_msgb_alloc();
	dh = (struct abis_rsl_dchan_hdr *) msgb_put(msg, sizeof(*dh));
	init_dchan_hdr(dh, RSL_MT_CHAN_ACTIV);
	dh->chan_nr = chan_nr;

	msgb_tv_put(msg, RSL_IE_ACT_TYPE, act_type);
	msgb_tlv_put(msg, RSL_IE_CHAN_MODE, sizeof(cm),
		     (u_int8_t *) &cm);
	/* For compatibility with Phase 1 */
	msgb_tlv_put(msg, RSL_IE_CHAN_IDENT, 4,
		     (u_int8_t *) &ci);

	if (lchan->encr.alg_id > RSL_ENC_ALG_A5(0)) {
		u_int8_t encr_info[MAX_A5_KEY_LEN+2];
		rc = build_encr_info(encr_info, lchan);
		if (rc > 0)
			msgb_tlv_put(msg, RSL_IE_ENCR_INFO, rc, encr_info);
	}

	switch (act_type) {
	case RSL_ACT_INTER_ASYNC:
	case RSL_ACT_INTER_SYNC:
		msgb_tv_put(msg, RSL_IE_HANDO_REF, ho_ref);
		break;
	default:
		break;
	}

	msgb_tv_put(msg, RSL_IE_BS_POWER, lchan->bs_power);
	msgb_tv_put(msg, RSL_IE_MS_POWER, lchan->ms_power);
	msgb_tv_put(msg, RSL_IE_TIMING_ADVANCE, ta);

	msg->trx = lchan->ts->trx;

	return abis_rsl_sendmsg(msg);
}

/* Chapter 8.4.9: Modify channel mode on BTS side */
int rsl_chan_mode_modify_req(struct gsm_lchan *lchan)
{
	struct abis_rsl_dchan_hdr *dh;
	struct msgb *msg;
	int rc;

	u_int8_t chan_nr = lchan2chan_nr(lchan);
	struct rsl_ie_chan_mode cm;

	rc = channel_mode_from_lchan(&cm, lchan);
	if (rc < 0)
		return rc;

	msg = rsl_msgb_alloc();
	dh = (struct abis_rsl_dchan_hdr *) msgb_put(msg, sizeof(*dh));
	init_dchan_hdr(dh, RSL_MT_MODE_MODIFY_REQ);
	dh->chan_nr = chan_nr;

	msgb_tlv_put(msg, RSL_IE_CHAN_MODE, sizeof(cm),
		     (u_int8_t *) &cm);

	if (lchan->encr.alg_id > RSL_ENC_ALG_A5(0)) {
		u_int8_t encr_info[MAX_A5_KEY_LEN+2];
		rc = build_encr_info(encr_info, lchan);
		if (rc > 0)
			msgb_tlv_put(msg, RSL_IE_ENCR_INFO, rc, encr_info);
	}

	if (lchan->tch_mode == GSM48_CMODE_SPEECH_AMR) {
		msgb_tlv_put(msg, RSL_IE_MR_CONFIG, sizeof(lchan->mr_conf),
			     (u_int8_t *) &lchan->mr_conf);
	}

	msg->trx = lchan->ts->trx;

	return abis_rsl_sendmsg(msg);
}

/* Chapter 8.4.6: Send the encryption command with given L3 info */
int rsl_encryption_cmd(struct msgb *msg)
{
	struct abis_rsl_dchan_hdr *dh;
	struct gsm_lchan *lchan = msg->lchan;
	u_int8_t chan_nr = lchan2chan_nr(lchan);
	u_int8_t encr_info[MAX_A5_KEY_LEN+2];
	u_int8_t l3_len = msg->len;
	int rc;

	/* First push the L3 IE tag and length */
	msgb_tv16_push(msg, RSL_IE_L3_INFO, l3_len);

	/* then the link identifier (SAPI0, main sign link) */
	msgb_tv_push(msg, RSL_IE_LINK_IDENT, 0);

	/* then encryption information */
	rc = build_encr_info(encr_info, lchan);
	if (rc <= 0)
		return rc;
	msgb_tlv_push(msg, RSL_IE_ENCR_INFO, rc, encr_info);

	/* and finally the DCHAN header */
	dh = (struct abis_rsl_dchan_hdr *) msgb_push(msg, sizeof(*dh));
	init_dchan_hdr(dh, RSL_MT_ENCR_CMD);
	dh->chan_nr = chan_nr;

	msg->trx = lchan->ts->trx;

	return abis_rsl_sendmsg(msg);
}

/* Chapter 8.4.5 / 4.6: Deactivate the SACCH after 04.08 RR CHAN RELEASE */
int rsl_deact_sacch(struct gsm_lchan *lchan)
{
	struct abis_rsl_dchan_hdr *dh;
	struct msgb *msg = rsl_msgb_alloc();

	dh = (struct abis_rsl_dchan_hdr *) msgb_put(msg, sizeof(*dh));
	init_dchan_hdr(dh, RSL_MT_DEACTIVATE_SACCH);
	dh->chan_nr = lchan2chan_nr(lchan);

	msg->lchan = lchan;
	msg->trx = lchan->ts->trx;

	DEBUGP(DRSL, "DEACTivate SACCH CMD channel=%s chan_nr=0x%02x\n",
		gsm_ts_name(lchan->ts), dh->chan_nr);

	return abis_rsl_sendmsg(msg);
}

/* Chapter 8.4.14 / 4.7: Tell BTS to release the radio channel */
int rsl_rf_chan_release(struct gsm_lchan *lchan)
{
	struct abis_rsl_dchan_hdr *dh;
	struct msgb *msg = rsl_msgb_alloc();

	dh = (struct abis_rsl_dchan_hdr *) msgb_put(msg, sizeof(*dh));
	init_dchan_hdr(dh, RSL_MT_RF_CHAN_REL);
	dh->chan_nr = lchan2chan_nr(lchan);

	msg->lchan = lchan;
	msg->trx = lchan->ts->trx;

	DEBUGP(DRSL, "RF Channel Release CMD channel=%s chan_nr=0x%02x\n",
		gsm_ts_name(lchan->ts), dh->chan_nr);

	/* BTS will respond by RF CHAN REL ACK */
	return abis_rsl_sendmsg(msg);
}

int rsl_paging_cmd(struct gsm_bts *bts, u_int8_t paging_group, u_int8_t len,
		   u_int8_t *ms_ident, u_int8_t chan_needed)
{
	struct abis_rsl_dchan_hdr *dh;
	struct msgb *msg = rsl_msgb_alloc();

	dh = (struct abis_rsl_dchan_hdr *) msgb_put(msg, sizeof(*dh));
	init_dchan_hdr(dh, RSL_MT_PAGING_CMD);
	dh->chan_nr = RSL_CHAN_PCH_AGCH;

	msgb_tv_put(msg, RSL_IE_PAGING_GROUP, paging_group);
	msgb_tlv_put(msg, RSL_IE_MS_IDENTITY, len-2, ms_ident+2);
	msgb_tv_put(msg, RSL_IE_CHAN_NEEDED, chan_needed);

	msg->trx = bts->c0;

	return abis_rsl_sendmsg(msg);
}

int rsl_paging_cmd_subscr(struct gsm_bts *bts, u_int8_t chan_need,
			  struct gsm_subscriber *subscr)
{
#if 0
	u_int8_t mi[128];
	unsigned int mi_len;
	u_int8_t paging_group;
#endif

	return -1;
}

int imsi_str2bcd(u_int8_t *bcd_out, const char *str_in)
{
	int i, len = strlen(str_in);

	for (i = 0; i < len; i++) {
		int num = str_in[i] - 0x30;
		if (num < 0 || num > 9)
			return -1;
		if (i % 2 == 0)
			bcd_out[i/2] = num;
		else
			bcd_out[i/2] |= (num << 4);
	}

	return 0;
}

/* Chapter 8.5.6 */
int rsl_imm_assign_cmd(struct gsm_bts *bts, u_int8_t len, u_int8_t *val)
{
	struct msgb *msg = rsl_msgb_alloc();
	struct abis_rsl_dchan_hdr *dh;
	u_int8_t buf[MACBLOCK_SIZE];

	dh = (struct abis_rsl_dchan_hdr *) msgb_put(msg, sizeof(*dh));
	init_dchan_hdr(dh, RSL_MT_IMMEDIATE_ASSIGN_CMD);
	dh->chan_nr = RSL_CHAN_PCH_AGCH;

	switch (bts->type) {
	case GSM_BTS_TYPE_BS11:
		msgb_tlv_put(msg, RSL_IE_IMM_ASS_INFO, len, val);
		break;
	default:
		/* If phase 2, construct a FULL_IMM_ASS_INFO */
		pad_macblock(buf, val, len);
		msgb_tlv_put(msg, RSL_IE_FULL_IMM_ASS_INFO, MACBLOCK_SIZE, buf);
		break;
	}

	msg->trx = bts->c0;

	return abis_rsl_sendmsg(msg);
}

/* Send Siemens specific MS RF Power Capability Indication */
int rsl_siemens_mrpci(struct gsm_lchan *lchan, struct rsl_mrpci *mrpci)
{
	struct msgb *msg = rsl_msgb_alloc();
	struct abis_rsl_dchan_hdr *dh;

	dh = (struct abis_rsl_dchan_hdr *) msgb_put(msg, sizeof(*dh));
	init_dchan_hdr(dh, RSL_MT_SIEMENS_MRPCI);
	dh->c.msg_discr = ABIS_RSL_MDISC_DED_CHAN;
	dh->chan_nr = lchan2chan_nr(lchan);
	msgb_tv_put(msg, RSL_IE_SIEMENS_MRPCI, *(u_int8_t *)mrpci);

	DEBUGP(DRSL, "channel=%s chan_nr=0x%02x TX Siemens MRPCI 0x%02x\n",
		gsm_ts_name(lchan->ts), dh->chan_nr, *(u_int8_t *)mrpci);

	msg->trx = lchan->ts->trx;

	return abis_rsl_sendmsg(msg);
}


/* Send "DATA REQUEST" message with given L3 Info payload */
/* Chapter 8.3.1 */
int rsl_data_request(struct msgb *msg, u_int8_t link_id)
{
	u_int8_t l3_len = msg->tail - (u_int8_t *)msgb_l3(msg);
	struct abis_rsl_rll_hdr *rh;

	if (msg->lchan == NULL) {
		LOGP(DRSL, LOGL_ERROR, "cannot send DATA REQUEST to unknown lchan\n");
		return -EINVAL;
	}

	/* First push the L3 IE tag and length */
	msgb_tv16_push(msg, RSL_IE_L3_INFO, l3_len);

	/* Then push the RSL header */
	rh = (struct abis_rsl_rll_hdr *) msgb_push(msg, sizeof(*rh));
	init_llm_hdr(rh, RSL_MT_DATA_REQ);
	rh->c.msg_discr |= ABIS_RSL_MDISC_TRANSP;
	rh->chan_nr = lchan2chan_nr(msg->lchan);
	rh->link_id = link_id;

	msg->trx = msg->lchan->ts->trx;

	return abis_rsl_sendmsg(msg);
}

/* Send "ESTABLISH REQUEST" message with given L3 Info payload */
/* Chapter 8.3.1 */
int rsl_establish_request(struct gsm_lchan *lchan, u_int8_t link_id)
{
	struct msgb *msg = rsl_msgb_alloc();
	struct abis_rsl_rll_hdr *rh;

	rh = (struct abis_rsl_rll_hdr *) msgb_put(msg, sizeof(*rh));
	init_llm_hdr(rh, RSL_MT_EST_REQ);
	//rh->c.msg_discr |= ABIS_RSL_MDISC_TRANSP;
	rh->chan_nr = lchan2chan_nr(lchan);
	rh->link_id = link_id;

	msg->trx = lchan->ts->trx;

	return abis_rsl_sendmsg(msg);
}

/* Chapter 8.3.7 Request the release of multiframe mode of RLL connection.
   This is what higher layers should call.  The BTS then responds with
   RELEASE CONFIRM, which we in turn use to trigger RSL CHANNEL RELEASE,
   which in turn is acknowledged by RSL CHANNEL RELEASE ACK, which calls
   lchan_free() */
int rsl_release_request(struct gsm_lchan *lchan, u_int8_t link_id)
{
	struct msgb *msg = rsl_msgb_alloc();
	struct abis_rsl_rll_hdr *rh;

	rh = (struct abis_rsl_rll_hdr *) msgb_put(msg, sizeof(*rh));
	init_llm_hdr(rh, RSL_MT_REL_REQ);
	//rh->c.msg_discr |= ABIS_RSL_MDISC_TRANSP;
	rh->chan_nr = lchan2chan_nr(lchan);
	rh->link_id = link_id;
	msgb_tv_put(msg, RSL_IE_RELEASE_MODE, 0);	/* normal release */

	msg->trx = lchan->ts->trx;

	return abis_rsl_sendmsg(msg);
}

/* Chapter 8.4.2: Channel Activate Acknowledge */
static int rsl_rx_chan_act_ack(struct msgb *msg)
{
	struct abis_rsl_dchan_hdr *rslh = msgb_l2(msg);

	/* BTS has confirmed channel activation, we now need
	 * to assign the activated channel to the MS */
	if (rslh->ie_chan != RSL_IE_CHAN_NR)
		return -EINVAL;

	dispatch_signal(SS_LCHAN, S_LCHAN_ACTIVATE_ACK, msg->lchan);

	return 0;
}

/* Chapter 8.4.3: Channel Activate NACK */
static int rsl_rx_chan_act_nack(struct msgb *msg)
{
	struct abis_rsl_dchan_hdr *dh = msgb_l2(msg);
	struct tlv_parsed tp;

	/* BTS has rejected channel activation ?!? */
	if (dh->ie_chan != RSL_IE_CHAN_NR)
		return -EINVAL;

	rsl_tlv_parse(&tp, dh->data, msgb_l2len(msg)-sizeof(*dh));
	if (TLVP_PRESENT(&tp, RSL_IE_CAUSE))
		print_rsl_cause(TLVP_VAL(&tp, RSL_IE_CAUSE),
				TLVP_LEN(&tp, RSL_IE_CAUSE));

	dispatch_signal(SS_LCHAN, S_LCHAN_ACTIVATE_NACK, msg->lchan);

	lchan_free(msg->lchan);
	return 0;
}

/* Chapter 8.4.4: Connection Failure Indication */
static int rsl_rx_conn_fail(struct msgb *msg)
{
	struct abis_rsl_dchan_hdr *dh = msgb_l2(msg);
	struct tlv_parsed tp;

	/* FIXME: print which channel */
	LOGP(DRSL, LOGL_NOTICE, "CONNECTION FAIL: RELEASING\n");

	rsl_tlv_parse(&tp, dh->data, msgb_l2len(msg)-sizeof(*dh));

	if (TLVP_PRESENT(&tp, RSL_IE_CAUSE))
		print_rsl_cause(TLVP_VAL(&tp, RSL_IE_CAUSE),
				TLVP_LEN(&tp, RSL_IE_CAUSE));

	/* FIXME: only free it after channel release ACK */
	return rsl_rf_chan_release(msg->lchan);
}

static void print_meas_rep_uni(struct gsm_meas_rep_unidir *mru,
				const char *prefix)
{
	DEBUGPC(DMEAS, "RXL-FULL-%s=%3ddBm RXL-SUB-%s=%3ddBm ",
		prefix, rxlev2dbm(mru->full.rx_lev),
		prefix, rxlev2dbm(mru->sub.rx_lev));
	DEBUGPC(DMEAS, "RXQ-FULL-%s=%d RXQ-SUB-%s=%d ",
		prefix, mru->full.rx_qual, prefix, mru->sub.rx_qual);
}

static void print_meas_rep(struct gsm_meas_rep *mr)
{
	int i;

	DEBUGP(DMEAS, "MEASUREMENT RESULT NR=%d ", mr->nr);

	if (mr->flags & MEAS_REP_F_DL_DTX)
		DEBUGPC(DMEAS, "DTXd ");

	print_meas_rep_uni(&mr->ul, "ul");
	DEBUGPC(DMEAS, "BS_POWER=%d ", mr->bs_power);
	if (mr->flags & MEAS_REP_F_MS_TO)
		DEBUGPC(DMEAS, "MS_TO=%d ", mr->ms_timing_offset);

	if (mr->flags & MEAS_REP_F_MS_L1) {
		DEBUGPC(DMEAS, "L1_MS_PWR=%3ddBm ", mr->ms_l1.pwr);
		DEBUGPC(DMEAS, "L1_FPC=%u ",
			mr->flags & MEAS_REP_F_FPC ? 1 : 0);
		DEBUGPC(DMEAS, "L1_TA=%u ", mr->ms_l1.ta);
	}

	if (mr->flags & MEAS_REP_F_UL_DTX)
		DEBUGPC(DMEAS, "DTXu ");
	if (mr->flags & MEAS_REP_F_BA1)
		DEBUGPC(DMEAS, "BA1 ");
	if (!(mr->flags & MEAS_REP_F_DL_VALID))
		DEBUGPC(DMEAS, "NOT VALID ");
	else
		print_meas_rep_uni(&mr->dl, "dl");

	DEBUGPC(DMEAS, "NUM_NEIGH=%u\n", mr->num_cell);
	if (mr->num_cell == 7)
		return;
	for (i = 0; i < mr->num_cell; i++) {
		struct gsm_meas_rep_cell *mrc = &mr->cell[i];
		DEBUGP(DMEAS, "ARFCN=%u BSIC=%u => %d dBm\n", mrc->arfcn, mrc->bsic,
			rxlev2dbm(mrc->rxlev));
	}
}

static int rsl_rx_meas_res(struct msgb *msg)
{
	struct abis_rsl_dchan_hdr *dh = msgb_l2(msg);
	struct tlv_parsed tp;
	struct gsm_meas_rep *mr = lchan_next_meas_rep(msg->lchan);
	u_int8_t len;
	const u_int8_t *val;
	int rc;

	memset(mr, 0, sizeof(*mr));
	mr->lchan = msg->lchan;

	rsl_tlv_parse(&tp, dh->data, msgb_l2len(msg)-sizeof(*dh));

	if (!TLVP_PRESENT(&tp, RSL_IE_MEAS_RES_NR) ||
	    !TLVP_PRESENT(&tp, RSL_IE_UPLINK_MEAS) ||
	    !TLVP_PRESENT(&tp, RSL_IE_BS_POWER))
		return -EIO;

	/* Mandatory Parts */
	mr->nr = *TLVP_VAL(&tp, RSL_IE_MEAS_RES_NR);

	len = TLVP_LEN(&tp, RSL_IE_UPLINK_MEAS);
	val = TLVP_VAL(&tp, RSL_IE_UPLINK_MEAS);
	if (len >= 3) {
		if (val[0] & 0x40)
			mr->flags |= MEAS_REP_F_DL_DTX;
		mr->ul.full.rx_lev = val[0] & 0x3f;
		mr->ul.sub.rx_lev = val[1] & 0x3f;
		mr->ul.full.rx_qual = val[2]>>3 & 0x7;
		mr->ul.sub.rx_qual = val[2] & 0x7;
	}

	mr->bs_power = *TLVP_VAL(&tp, RSL_IE_BS_POWER);

	/* Optional Parts */
	if (TLVP_PRESENT(&tp, RSL_IE_MS_TIMING_OFFSET))
		mr->ms_timing_offset =
			*TLVP_VAL(&tp, RSL_IE_MS_TIMING_OFFSET);

	if (TLVP_PRESENT(&tp, RSL_IE_L1_INFO)) {
		val = TLVP_VAL(&tp, RSL_IE_L1_INFO);
		mr->flags |= MEAS_REP_F_MS_L1;
		mr->ms_l1.pwr = ms_pwr_dbm(msg->trx->bts->band, val[0] >> 3);
		if (val[0] & 0x04)
			mr->flags |= MEAS_REP_F_FPC;
		mr->ms_l1.ta = val[1];
	}
	if (TLVP_PRESENT(&tp, RSL_IE_L3_INFO)) {
		msg->l3h = (u_int8_t *) TLVP_VAL(&tp, RSL_IE_L3_INFO);
		rc = gsm48_parse_meas_rep(mr, msg);
		if (rc < 0)
			return rc;
	}

	print_meas_rep(mr);

	dispatch_signal(SS_LCHAN, S_LCHAN_MEAS_REP, mr);

	return 0;
}

/* Chapter 8.4.7 */
static int rsl_rx_hando_det(struct msgb *msg)
{
	struct abis_rsl_dchan_hdr *dh = msgb_l2(msg);
	struct tlv_parsed tp;

	DEBUGP(DRSL, "HANDOVER DETECT ");

	rsl_tlv_parse(&tp, dh->data, msgb_l2len(msg)-sizeof(*dh));

	if (TLVP_PRESENT(&tp, RSL_IE_ACCESS_DELAY))
		DEBUGPC(DRSL, "access delay = %u\n",
			*TLVP_VAL(&tp, RSL_IE_ACCESS_DELAY));
	else
		DEBUGPC(DRSL, "\n");

	dispatch_signal(SS_LCHAN, S_LCHAN_HANDOVER_DETECT, msg->lchan);

	return 0;
}

static int abis_rsl_rx_dchan(struct msgb *msg)
{
	struct abis_rsl_dchan_hdr *rslh = msgb_l2(msg);
	int rc = 0;
	char *ts_name;

	msg->lchan = lchan_lookup(msg->trx, rslh->chan_nr);
	ts_name = gsm_ts_name(msg->lchan->ts);

	if (rslh->c.msg_type != RSL_MT_MEAS_RES)
		DEBUGP(DRSL, "channel=%s chan_nr=0x%02x ", ts_name, rslh->chan_nr);

	switch (rslh->c.msg_type) {
	case RSL_MT_CHAN_ACTIV_ACK:
		DEBUGPC(DRSL, "CHANNEL ACTIVATE ACK\n");
		rc = rsl_rx_chan_act_ack(msg);
		break;
	case RSL_MT_CHAN_ACTIV_NACK:
		DEBUGPC(DRSL, "CHANNEL ACTIVATE NACK\n");
		rc = rsl_rx_chan_act_nack(msg);
		break;
	case RSL_MT_CONN_FAIL:
		rc = rsl_rx_conn_fail(msg);
		break;
	case RSL_MT_MEAS_RES:
		rc = rsl_rx_meas_res(msg);
		break;
	case RSL_MT_HANDO_DET:
		rc = rsl_rx_hando_det(msg);
		break;
	case RSL_MT_RF_CHAN_REL_ACK:
		DEBUGPC(DRSL, "RF CHANNEL RELEASE ACK\n");
		lchan_free(msg->lchan);
		break;
	case RSL_MT_MODE_MODIFY_ACK:
		DEBUGPC(DRSL, "CHANNEL MODE MODIFY ACK\n");
		break;
	case RSL_MT_MODE_MODIFY_NACK:
		DEBUGPC(DRSL, "CHANNEL MODE MODIFY NACK\n");
		break;
	case RSL_MT_IPAC_PDCH_ACT_ACK:
		DEBUGPC(DRSL, "IPAC PDCH ACT ACK\n");
		break;
	case RSL_MT_IPAC_PDCH_ACT_NACK:
		DEBUGPC(DRSL, "IPAC PDCH ACT NACK\n");
		break;
	case RSL_MT_IPAC_PDCH_DEACT_ACK:
		DEBUGPC(DRSL, "IPAC PDCH DEACT ACK\n");
		break;
	case RSL_MT_IPAC_PDCH_DEACT_NACK:
		DEBUGPC(DRSL, "IPAC PDCH DEACT NACK\n");
		break;
	case RSL_MT_PHY_CONTEXT_CONF:
	case RSL_MT_PREPROC_MEAS_RES:
	case RSL_MT_TALKER_DET:
	case RSL_MT_LISTENER_DET:
	case RSL_MT_REMOTE_CODEC_CONF_REP:
	case RSL_MT_MR_CODEC_MOD_ACK:
	case RSL_MT_MR_CODEC_MOD_NACK:
	case RSL_MT_MR_CODEC_MOD_PER:
		DEBUGPC(DRSL, "Unimplemented Abis RSL DChan msg 0x%02x\n",
			rslh->c.msg_type);
		break;
	default:
		DEBUGPC(DRSL, "unknown Abis RSL DChan msg 0x%02x\n",
			rslh->c.msg_type);
		return -EINVAL;
	}

	return rc;
}

static int rsl_rx_error_rep(struct msgb *msg)
{
	struct abis_rsl_common_hdr *rslh = msgb_l2(msg);
	struct tlv_parsed tp;

	LOGP(DRSL, LOGL_ERROR, "ERROR REPORT ");

	rsl_tlv_parse(&tp, rslh->data, msgb_l2len(msg)-sizeof(*rslh));

	if (TLVP_PRESENT(&tp, RSL_IE_CAUSE))
		print_rsl_cause(TLVP_VAL(&tp, RSL_IE_CAUSE),
				TLVP_LEN(&tp, RSL_IE_CAUSE));

	LOGPC(DRSL, LOGL_ERROR, "\n");

	return 0;
}

static int abis_rsl_rx_trx(struct msgb *msg)
{
	struct abis_rsl_common_hdr *rslh = msgb_l2(msg);
	int rc = 0;

	switch (rslh->msg_type) {
	case RSL_MT_ERROR_REPORT:
		rc = rsl_rx_error_rep(msg);
		break;
	case RSL_MT_RF_RES_IND:
		/* interference on idle channels of TRX */
		//DEBUGP(DRSL, "TRX: RF Interference Indication\n");
		break;
	case RSL_MT_OVERLOAD:
		/* indicate CCCH / ACCH / processor overload */ 
		LOGP(DRSL, LOGL_ERROR, "TRX: CCCH/ACCH/CPU Overload\n");
		break;
	default:
		DEBUGP(DRSL, "Unknown Abis RSL TRX message type 0x%02x\n",
			rslh->msg_type);
		return -EINVAL;
	}
	return rc;
}

/* If T3101 expires, we never received a response to IMMEDIATE ASSIGN */
static void t3101_expired(void *data)
{
	struct gsm_lchan *lchan = data;

	rsl_rf_chan_release(lchan);
}

/* MS has requested a channel on the RACH */
static int rsl_rx_chan_rqd(struct msgb *msg)
{
	struct gsm_bts *bts = msg->trx->bts;
	struct abis_rsl_dchan_hdr *rqd_hdr = msgb_l2(msg);
	struct gsm48_req_ref *rqd_ref;
	struct gsm48_imm_ass ia;
	enum gsm_chan_t lctype;
	enum gsm_chreq_reason_t chreq_reason;
	struct gsm_lchan *lchan;
	u_int8_t rqd_ta;
	int ret;

	u_int16_t arfcn;
	u_int8_t ts_number, subch;

	/* parse request reference to be used in immediate assign */
	if (rqd_hdr->data[0] != RSL_IE_REQ_REFERENCE)
		return -EINVAL;

	rqd_ref = (struct gsm48_req_ref *) &rqd_hdr->data[1];

	/* parse access delay and use as TA */
	if (rqd_hdr->data[sizeof(struct gsm48_req_ref)+1] != RSL_IE_ACCESS_DELAY)
		return -EINVAL;
	rqd_ta = rqd_hdr->data[sizeof(struct gsm48_req_ref)+2];

	/* determine channel type (SDCCH/TCH_F/TCH_H) based on
	 * request reference RA */
	lctype = get_ctype_by_chreq(bts, rqd_ref->ra, bts->network->neci);
	chreq_reason = get_reason_by_chreq(bts, rqd_ref->ra, bts->network->neci);

	/* check availability / allocate channel */
	lchan = lchan_alloc(bts, lctype);
	if (!lchan) {
		DEBUGP(DRSL, "CHAN RQD: no resources for %s 0x%x\n",
			gsm_lchan_name(lctype), rqd_ref->ra);
		/* FIXME: send some kind of reject ?!? */
		return -ENOMEM;
	}

	ts_number = lchan->ts->nr;
	arfcn = lchan->ts->trx->arfcn;
	subch = lchan->nr;
	
	lchan->encr.alg_id = RSL_ENC_ALG_A5(0);	/* no encryption */
	lchan->ms_power = ms_pwr_ctl_lvl(bts->band, bts->ms_max_power);
	lchan->bs_power = 0; /* 0dB reduction, output power = Pn */
	lchan->rsl_cmode = RSL_CMOD_SPD_SIGN;
	lchan->tch_mode = GSM48_CMODE_SIGN;
	rsl_chan_activate_lchan(lchan, 0x00, rqd_ta, 0);

	/* create IMMEDIATE ASSIGN 04.08 messge */
	memset(&ia, 0, sizeof(ia));
	ia.l2_plen = 0x2d;
	ia.proto_discr = GSM48_PDISC_RR;
	ia.msg_type = GSM48_MT_RR_IMM_ASS;
	ia.page_mode = GSM48_PM_SAME;
	ia.chan_desc.chan_nr = lchan2chan_nr(lchan);
	ia.chan_desc.h0.h = 0;
	ia.chan_desc.h0.arfcn_high = arfcn >> 8;
	ia.chan_desc.h0.arfcn_low = arfcn & 0xff;
	ia.chan_desc.h0.tsc = bts->tsc;
	/* use request reference extracted from CHAN_RQD */
	memcpy(&ia.req_ref, rqd_ref, sizeof(ia.req_ref));
	ia.timing_advance = rqd_ta;
	ia.mob_alloc_len = 0;

	DEBUGP(DRSL, "Activating ARFCN(%u) TS(%u) SS(%u) lctype %s "
		"chan_nr=0x%02x r=%s ra=0x%02x\n",
		arfcn, ts_number, subch, gsm_lchan_name(lchan->type),
		ia.chan_desc.chan_nr, gsm_chreq_name(chreq_reason),
		rqd_ref->ra);

	/* Start timer T3101 to wait for GSM48_MT_RR_PAG_RESP */
	lchan->T3101.cb = t3101_expired;
	lchan->T3101.data = lchan;
	bsc_schedule_timer(&lchan->T3101, bts->network->T3101, 0);

	/* send IMMEDIATE ASSIGN CMD on RSL to BTS (to send on CCCH to MS) */
	ret = rsl_imm_assign_cmd(bts, sizeof(ia), (u_int8_t *) &ia);

	return ret;
}

/* MS has requested a channel on the RACH */
static int rsl_rx_ccch_load(struct msgb *msg)
{
	struct abis_rsl_dchan_hdr *rslh = msgb_l2(msg);
	u_int16_t pg_buf_space;
	u_int16_t rach_slot_count = -1;
	u_int16_t rach_busy_count = -1;
	u_int16_t rach_access_count = -1;

	switch (rslh->data[0]) {
	case RSL_IE_PAGING_LOAD:
		pg_buf_space = rslh->data[1] << 8 | rslh->data[2];
		paging_update_buffer_space(msg->trx->bts, pg_buf_space);
		break;
	case RSL_IE_RACH_LOAD:
		if (msg->data_len >= 7) {
			rach_slot_count = rslh->data[2] << 8 | rslh->data[3];
			rach_busy_count = rslh->data[4] << 8 | rslh->data[5];
			rach_access_count = rslh->data[6] << 8 | rslh->data[7];
		}
		break;
	default:
		break;
	}

	return 0;
}

static int abis_rsl_rx_cchan(struct msgb *msg)
{
	struct abis_rsl_dchan_hdr *rslh = msgb_l2(msg);
	int rc = 0;

	msg->lchan = lchan_lookup(msg->trx, rslh->chan_nr);

	switch (rslh->c.msg_type) {
	case RSL_MT_CHAN_RQD:
		/* MS has requested a channel on the RACH */
		rc = rsl_rx_chan_rqd(msg);
		break;
	case RSL_MT_CCCH_LOAD_IND:
		/* current load on the CCCH */
		rc = rsl_rx_ccch_load(msg);
		break;
	case RSL_MT_DELETE_IND:
		/* CCCH overloaded, IMM_ASSIGN was dropped */
	case RSL_MT_CBCH_LOAD_IND:
		/* current load on the CBCH */
		LOGP(DRSL, LOGL_NOTICE, "Unimplemented Abis RSL TRX message "
			"type 0x%02x\n", rslh->c.msg_type);
		break;
	default:
		LOGP(DRSL, LOGL_NOTICE, "Unknown Abis RSL TRX message type "
			"0x%02x\n", rslh->c.msg_type);
		return -EINVAL;
	}

	return rc;
}

static int rsl_rx_rll_err_ind(struct msgb *msg)
{
	struct abis_rsl_rll_hdr *rllh = msgb_l2(msg);
	u_int8_t *rlm_cause = rllh->data;

	LOGP(DRLL, LOGL_ERROR, "ERROR INDICATION cause=0x%02x\n", rlm_cause[1]);

	rll_indication(msg->lchan, rllh->link_id, BSC_RLLR_IND_ERR_IND);
		
	if (rlm_cause[1] == RLL_CAUSE_T200_EXPIRED)
		return rsl_rf_chan_release(msg->lchan);

	return 0;
}

/*	ESTABLISH INDICATION, LOCATION AREA UPDATE REQUEST 
	0x02, 0x06,
	0x01, 0x20,
	0x02, 0x00,
	0x0b, 0x00, 0x0f, 0x05, 0x08, ... */

static int abis_rsl_rx_rll(struct msgb *msg)
{
	struct abis_rsl_rll_hdr *rllh = msgb_l2(msg);
	int rc = 0;
	char *ts_name;
	u_int8_t sapi = rllh->link_id & 7;

	msg->lchan = lchan_lookup(msg->trx, rllh->chan_nr);
	ts_name = gsm_ts_name(msg->lchan->ts);
	DEBUGP(DRLL, "channel=%s chan_nr=0x%02x sapi=%u ", ts_name,
		rllh->chan_nr, sapi);
	
	switch (rllh->c.msg_type) {
	case RSL_MT_DATA_IND:
		DEBUGPC(DRLL, "DATA INDICATION\n");
		if (msgb_l2len(msg) > 
		    sizeof(struct abis_rsl_common_hdr) + sizeof(*rllh) &&
		    rllh->data[0] == RSL_IE_L3_INFO) {
			msg->l3h = &rllh->data[3];
			return gsm0408_rcvmsg(msg, rllh->link_id);
		}
		break;
	case RSL_MT_EST_IND:
		DEBUGPC(DRLL, "ESTABLISH INDICATION\n");
		/* lchan is established, stop T3101 */
		msg->lchan->sapis[rllh->link_id & 0x7] = LCHAN_SAPI_MS;
		bsc_del_timer(&msg->lchan->T3101);
		if (msgb_l2len(msg) > 
		    sizeof(struct abis_rsl_common_hdr) + sizeof(*rllh) &&
		    rllh->data[0] == RSL_IE_L3_INFO) {
			msg->l3h = &rllh->data[3];
			return gsm0408_rcvmsg(msg, rllh->link_id);
		}
		break;
	case RSL_MT_EST_CONF:
		DEBUGPC(DRLL, "ESTABLISH CONFIRM\n");
		msg->lchan->sapis[rllh->link_id & 0x7] = LCHAN_SAPI_NET;
		rll_indication(msg->lchan, rllh->link_id,
				  BSC_RLLR_IND_EST_CONF);
		break;
	case RSL_MT_REL_IND:
		/* BTS informs us of having received  DISC from MS */
		DEBUGPC(DRLL, "RELEASE INDICATION\n");
		msg->lchan->sapis[rllh->link_id & 0x7] = LCHAN_SAPI_UNUSED;
		rll_indication(msg->lchan, rllh->link_id,
				  BSC_RLLR_IND_REL_IND);
		/* we can now releae the channel on the BTS/Abis side */
		/* FIXME: officially we need to start T3111 and wait for
		 * some grace period */
		rsl_rf_chan_release(msg->lchan);
		break;
	case RSL_MT_REL_CONF:
		/* BTS informs us of having received UA from MS,
		 * in response to DISC that we've sent earlier */
		DEBUGPC(DRLL, "RELEASE CONFIRMATION\n");
		msg->lchan->sapis[rllh->link_id & 0x7] = LCHAN_SAPI_UNUSED;
		/* we can now releae the channel on the BTS/Abis side */
		/* FIXME: officially we need to start T3111 and wait for
		 * some grace period */
		rsl_rf_chan_release(msg->lchan);
		break;
	case RSL_MT_ERROR_IND:
		rc = rsl_rx_rll_err_ind(msg);
		break;
	case RSL_MT_UNIT_DATA_IND:
		LOGP(DRLL, LOGL_NOTICE, "unimplemented Abis RLL message "
			"type 0x%02x\n", rllh->c.msg_type);
		break;
	default:
		LOGP(DRLL, LOGL_NOTICE, "unknown Abis RLL message "
			"type 0x%02x\n", rllh->c.msg_type);
	}
	return rc;
}

static u_int8_t ipa_smod_s_for_lchan(struct gsm_lchan *lchan)
{
	switch (lchan->tch_mode) {
	case GSM48_CMODE_SPEECH_V1:
		switch (lchan->type) {
		case GSM_LCHAN_TCH_F:
			return 0x00;
		case GSM_LCHAN_TCH_H:
			return 0x03;
		default:
			break;
		}
	case GSM48_CMODE_SPEECH_EFR:
		switch (lchan->type) {
		case GSM_LCHAN_TCH_F:
			return 0x01;
		/* there's no half-rate EFR */
		default:
			break;
		}
	case GSM48_CMODE_SPEECH_AMR:
		switch (lchan->type) {
		case GSM_LCHAN_TCH_F:
			return 0x02;
		case GSM_LCHAN_TCH_H:
			return 0x05;
		default:
			break;
		}
	default:
		break;
	}
	LOGP(DRSL, LOGL_ERROR, "Cannot determine ip.access speech mode for "
		"tch_mode == 0x%02x\n", lchan->tch_mode);
	return 0;
}

/* ip.access specific RSL extensions */
static void ipac_parse_rtp(struct gsm_lchan *lchan, struct tlv_parsed *tv)
{
	struct in_addr ip;
	u_int16_t port, conn_id;

	if (TLVP_PRESENT(tv, RSL_IE_IPAC_LOCAL_IP)) {
		ip.s_addr = *((u_int32_t *) TLVP_VAL(tv, RSL_IE_IPAC_LOCAL_IP));
		DEBUGPC(DRSL, "LOCAL_IP=%s ", inet_ntoa(ip));
		lchan->abis_ip.bound_ip = ntohl(ip.s_addr);
	}

	if (TLVP_PRESENT(tv, RSL_IE_IPAC_LOCAL_PORT)) {
		port = *((u_int16_t *) TLVP_VAL(tv, RSL_IE_IPAC_LOCAL_PORT));
		port = ntohs(port);
		DEBUGPC(DRSL, "LOCAL_PORT=%u ", port);
		lchan->abis_ip.bound_port = port;
	}

	if (TLVP_PRESENT(tv, RSL_IE_IPAC_CONN_ID)) {
		conn_id = *((u_int16_t *) TLVP_VAL(tv, RSL_IE_IPAC_CONN_ID));
		conn_id = ntohs(conn_id);
		DEBUGPC(DRSL, "CON_ID=%u ", conn_id);
		lchan->abis_ip.conn_id = conn_id;
	}

	if (TLVP_PRESENT(tv, RSL_IE_IPAC_RTP_PAYLOAD2)) {
		lchan->abis_ip.rtp_payload2 =
				*TLVP_VAL(tv, RSL_IE_IPAC_RTP_PAYLOAD2);
		DEBUGPC(DRSL, "RTP_PAYLOAD2=0x%02x ",
			lchan->abis_ip.rtp_payload2);
	}

	if (TLVP_PRESENT(tv, RSL_IE_IPAC_SPEECH_MODE)) {
		lchan->abis_ip.speech_mode =
				*TLVP_VAL(tv, RSL_IE_IPAC_SPEECH_MODE);
		DEBUGPC(DRSL, "speech_mode=0x%02x ",
			lchan->abis_ip.speech_mode);
	}

	if (TLVP_PRESENT(tv, RSL_IE_IPAC_REMOTE_IP)) {
		ip.s_addr = *((u_int32_t *) TLVP_VAL(tv, RSL_IE_IPAC_REMOTE_IP));
		DEBUGPC(DRSL, "REMOTE_IP=%s ", inet_ntoa(ip));
		lchan->abis_ip.connect_ip = ntohl(ip.s_addr);
	}

	if (TLVP_PRESENT(tv, RSL_IE_IPAC_REMOTE_PORT)) {
		port = *((u_int16_t *) TLVP_VAL(tv, RSL_IE_IPAC_REMOTE_PORT));
		port = ntohs(port);
		DEBUGPC(DRSL, "REMOTE_PORT=%u ", port);
		lchan->abis_ip.connect_port = port;
	}
}

int rsl_ipacc_crcx(struct gsm_lchan *lchan)
{
	struct msgb *msg = rsl_msgb_alloc();
	struct abis_rsl_dchan_hdr *dh;

	dh = (struct abis_rsl_dchan_hdr *) msgb_put(msg, sizeof(*dh));
	init_dchan_hdr(dh, RSL_MT_IPAC_CRCX);
	dh->c.msg_discr = ABIS_RSL_MDISC_IPACCESS;
	dh->chan_nr = lchan2chan_nr(lchan);

	/* 0x1- == receive-only, 0x-1 == EFR codec */
	lchan->abis_ip.speech_mode = 0x10 | ipa_smod_s_for_lchan(lchan);
	msgb_tv_put(msg, RSL_IE_IPAC_SPEECH_MODE, lchan->abis_ip.speech_mode);

	DEBUGP(DRSL, "channel=%s chan_nr=0x%02x IPAC_BIND "
		"speech_mode=0x%02x\n", gsm_ts_name(lchan->ts),
		dh->chan_nr, lchan->abis_ip.speech_mode);

	msg->trx = lchan->ts->trx;

	return abis_rsl_sendmsg(msg);
}

int rsl_ipacc_mdcx(struct gsm_lchan *lchan, u_int32_t ip, u_int16_t port,
		   u_int8_t rtp_payload2)
{
	struct msgb *msg = rsl_msgb_alloc();
	struct abis_rsl_dchan_hdr *dh;
	u_int32_t *att_ip;
	struct in_addr ia;

	dh = (struct abis_rsl_dchan_hdr *) msgb_put(msg, sizeof(*dh));
	init_dchan_hdr(dh, RSL_MT_IPAC_MDCX);
	dh->c.msg_discr = ABIS_RSL_MDISC_IPACCESS;
	dh->chan_nr = lchan2chan_nr(lchan);

	/* we need to store these now as MDCX_ACK does not return them :( */
	lchan->abis_ip.rtp_payload2 = rtp_payload2;
	lchan->abis_ip.connect_port = port;
	lchan->abis_ip.connect_ip = ip;

	/* 0x0- == both directions, 0x-1 == EFR codec */
	lchan->abis_ip.speech_mode = 0x00 | ipa_smod_s_for_lchan(lchan);

	ia.s_addr = htonl(ip);
	DEBUGP(DRSL, "channel=%s chan_nr=0x%02x IPAC_MDCX "
		"IP=%s PORT=%d RTP_PAYLOAD2=%d CONN_ID=%d speech_mode=0x%02x\n",
		gsm_ts_name(lchan->ts), dh->chan_nr, inet_ntoa(ia), port,
		rtp_payload2, lchan->abis_ip.conn_id, lchan->abis_ip.speech_mode);

	msgb_tv16_put(msg, RSL_IE_IPAC_CONN_ID, lchan->abis_ip.conn_id);
	msgb_v_put(msg, RSL_IE_IPAC_REMOTE_IP);
	att_ip = (u_int32_t *) msgb_put(msg, sizeof(ip));
	*att_ip = ia.s_addr;
	msgb_tv16_put(msg, RSL_IE_IPAC_REMOTE_PORT, port);
	msgb_tv_put(msg, RSL_IE_IPAC_SPEECH_MODE, lchan->abis_ip.speech_mode);
	if (rtp_payload2)
		msgb_tv_put(msg, RSL_IE_IPAC_RTP_PAYLOAD2, rtp_payload2);
	
	msg->trx = lchan->ts->trx;

	return abis_rsl_sendmsg(msg);
}

int rsl_ipacc_pdch_activate(struct gsm_lchan *lchan)
{
	struct msgb *msg = rsl_msgb_alloc();
	struct abis_rsl_dchan_hdr *dh;

	dh = (struct abis_rsl_dchan_hdr *) msgb_put(msg, sizeof(*dh));
	init_dchan_hdr(dh, RSL_MT_IPAC_PDCH_ACT);
	dh->c.msg_discr = ABIS_RSL_MDISC_DED_CHAN;
	dh->chan_nr = lchan2chan_nr(lchan);

	DEBUGP(DRSL, "channel=%s chan_nr=0x%02x IPAC_PDCH_ACT\n",
		gsm_ts_name(lchan->ts), dh->chan_nr);

	msg->trx = lchan->ts->trx;

	return abis_rsl_sendmsg(msg);
}

static int abis_rsl_rx_ipacc_crcx_ack(struct msgb *msg)
{
	struct abis_rsl_dchan_hdr *dh = msgb_l2(msg);
	struct tlv_parsed tv;
	struct gsm_lchan *lchan = msg->lchan;

	/* the BTS has acknowledged a local bind, it now tells us the IP
	* address and port number to which it has bound the given logical
	* channel */

	rsl_tlv_parse(&tv, dh->data, msgb_l2len(msg)-sizeof(*dh));
	if (!TLVP_PRESENT(&tv, RSL_IE_IPAC_LOCAL_PORT) ||
	    !TLVP_PRESENT(&tv, RSL_IE_IPAC_LOCAL_IP) ||
	    !TLVP_PRESENT(&tv, RSL_IE_IPAC_CONN_ID)) {
		LOGP(DRSL, LOGL_NOTICE, "mandatory IE missing");
		return -EINVAL;
	}

	ipac_parse_rtp(lchan, &tv);

	/* in case we don't use direct BTS-to-BTS RTP */
	if (!ipacc_rtp_direct) {
		int rc;
		/* the BTS has successfully bound a TCH to a local ip/port,
		 * which means we can connect our UDP socket to it */
		if (lchan->abis_ip.rtp_socket) {
			rtp_socket_free(lchan->abis_ip.rtp_socket);
			lchan->abis_ip.rtp_socket = NULL;
		}

		lchan->abis_ip.rtp_socket = rtp_socket_create();
		if (!lchan->abis_ip.rtp_socket)
			goto out_err;

		rc = rtp_socket_connect(lchan->abis_ip.rtp_socket,
				   lchan->abis_ip.bound_ip,
				   lchan->abis_ip.bound_port);
		if (rc < 0)
			goto out_err;
	}

	dispatch_signal(SS_ABISIP, S_ABISIP_CRCX_ACK, msg->lchan);

	return 0;
out_err:
	return -EIO;
}

static int abis_rsl_rx_ipacc_mdcx_ack(struct msgb *msg)
{
	struct abis_rsl_dchan_hdr *dh = msgb_l2(msg);
	struct tlv_parsed tv;
	struct gsm_lchan *lchan = msg->lchan;

	/* the BTS has acknowledged a remote connect request and
	 * it now tells us the IP address and port number to which it has
	 * connected the given logical channel */

	rsl_tlv_parse(&tv, dh->data, msgb_l2len(msg)-sizeof(*dh));
	ipac_parse_rtp(lchan, &tv);
	dispatch_signal(SS_ABISIP, S_ABISIP_MDCX_ACK, msg->lchan);

	return 0;
}

static int abis_rsl_rx_ipacc_dlcx_ind(struct msgb *msg)
{
	struct abis_rsl_dchan_hdr *dh = msgb_l2(msg);
	struct tlv_parsed tv;
	struct gsm_lchan *lchan = msg->lchan;

	rsl_tlv_parse(&tv, dh->data, msgb_l2len(msg)-sizeof(*dh));

	if (TLVP_PRESENT(&tv, RSL_IE_CAUSE))
		print_rsl_cause(TLVP_VAL(&tv, RSL_IE_CAUSE),
				TLVP_LEN(&tv, RSL_IE_CAUSE));

	/* the BTS tells us a RTP stream has been disconnected */
	if (lchan->abis_ip.rtp_socket) {
		rtp_socket_free(lchan->abis_ip.rtp_socket);
		lchan->abis_ip.rtp_socket = NULL;
	}

	dispatch_signal(SS_ABISIP, S_ABISIP_DLCX_IND, msg->lchan);

	return 0;
}

static int abis_rsl_rx_ipacc(struct msgb *msg)
{
	struct abis_rsl_rll_hdr *rllh = msgb_l2(msg);
	int rc = 0;

	msg->lchan = lchan_lookup(msg->trx, rllh->chan_nr);
	DEBUGP(DRSL, "channel=%s chan_nr=0x%02x ",
		gsm_ts_name(msg->lchan->ts), rllh->chan_nr);
	
	switch (rllh->c.msg_type) {
	case RSL_MT_IPAC_CRCX_ACK:
		DEBUGPC(DRSL, "IPAC_CRCX_ACK ");
		rc = abis_rsl_rx_ipacc_crcx_ack(msg);
		break;
	case RSL_MT_IPAC_CRCX_NACK:
		/* somehow the BTS was unable to bind the lchan to its local
		 * port?!? */
		DEBUGPC(DRSL, "IPAC_CRCX_NACK ");
		break;
	case RSL_MT_IPAC_MDCX_ACK:
		/* the BTS tells us that a connect operation was successful */
		DEBUGPC(DRSL, "IPAC_MDCX_ACK ");
		rc = abis_rsl_rx_ipacc_mdcx_ack(msg);
		break;
	case RSL_MT_IPAC_MDCX_NACK:
		/* somehow the BTS was unable to connect the lchan to a remote
		 * port */
		DEBUGPC(DRSL, "IPAC_MDCX_NACK ");
		break;
	case RSL_MT_IPAC_DLCX_IND:
		DEBUGPC(DRSL, "IPAC_DLCX_IND ");
		rc = abis_rsl_rx_ipacc_dlcx_ind(msg);
		break;
	default:
		LOGP(DRSL, LOGL_NOTICE, "Unknown ip.access msg_type 0x%02x",
			rllh->c.msg_type);
		break;
	}
	DEBUGPC(DRSL, "\n");

	return rc;
}


/* Entry-point where L2 RSL from BTS enters */
int abis_rsl_rcvmsg(struct msgb *msg)
{
	struct abis_rsl_common_hdr *rslh = msgb_l2(msg)	;
	int rc = 0;

	switch (rslh->msg_discr & 0xfe) {
	case ABIS_RSL_MDISC_RLL:
		rc = abis_rsl_rx_rll(msg);
		break;
	case ABIS_RSL_MDISC_DED_CHAN:
		rc = abis_rsl_rx_dchan(msg);
		break;
	case ABIS_RSL_MDISC_COM_CHAN:
		rc = abis_rsl_rx_cchan(msg);
		break;
	case ABIS_RSL_MDISC_TRX:
		rc = abis_rsl_rx_trx(msg);
		break;
	case ABIS_RSL_MDISC_LOC:
		LOGP(DRSL, LOGL_NOTICE, "unimplemented RSL msg disc 0x%02x\n",
			rslh->msg_discr);
		break;
	case ABIS_RSL_MDISC_IPACCESS:
		rc = abis_rsl_rx_ipacc(msg);
		break;
	default:
		LOGP(DRSL, LOGL_NOTICE, "unknown RSL message discriminator "
			"0x%02x\n", rslh->msg_discr);
		return -EINVAL;
	}
	msgb_free(msg);
	return rc;
}


/* Section 3.3.2.3 TS 05.02. I think this looks like a table */
int rsl_ccch_conf_to_bs_cc_chans(int ccch_conf)
{
	switch (ccch_conf) {
	case RSL_BCCH_CCCH_CONF_1_NC:
		return 1;
	case RSL_BCCH_CCCH_CONF_1_C:
		return 1;
	case RSL_BCCH_CCCH_CONF_2_NC:
		return 2;
	case RSL_BCCH_CCCH_CONF_3_NC:
		return 3;
	case RSL_BCCH_CCCH_CONF_4_NC:
		return 4;
	default:
		return -1;
	}
}

/* Section 3.3.2.3 TS 05.02 */
int rsl_ccch_conf_to_bs_ccch_sdcch_comb(int ccch_conf)
{
	switch (ccch_conf) {
	case RSL_BCCH_CCCH_CONF_1_NC:
		return 0;
	case RSL_BCCH_CCCH_CONF_1_C:
		return 1;
	case RSL_BCCH_CCCH_CONF_2_NC:
		return 0;
	case RSL_BCCH_CCCH_CONF_3_NC:
		return 0;
	case RSL_BCCH_CCCH_CONF_4_NC:
		return 0;
	default:
		return -1;
	}
}

/* From Table 10.5.33 of GSM 04.08 */
int rsl_number_of_paging_subchannels(struct gsm_bts *bts)
{
	if (bts->si_common.chan_desc.ccch_conf == RSL_BCCH_CCCH_CONF_1_C) {
		return MAX(1, (3 - bts->si_common.chan_desc.bs_ag_blks_res))
			* (bts->si_common.chan_desc.bs_pa_mfrms + 2);
	} else {
		return (9 - bts->si_common.chan_desc.bs_ag_blks_res)
			* (bts->si_common.chan_desc.bs_pa_mfrms + 2);
	}
}
