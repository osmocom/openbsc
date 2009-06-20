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
#include <openbsc/abis_rsl.h>
#include <openbsc/chan_alloc.h>
#include <openbsc/debug.h>
#include <openbsc/tlv.h>
#include <openbsc/paging.h>
#include <openbsc/signal.h>

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
		[RSL_IE_IPAC_REMOTE_IP]		= { TLV_TYPE_FIXED, 4 },
		[RSL_IE_IPAC_REMOTE_PORT]	= { TLV_TYPE_FIXED, 2 },
		[RSL_IE_IPAC_LOCAL_IP]		= { TLV_TYPE_FIXED, 4 },
		[RSL_IE_IPAC_LOCAL_PORT]	= { TLV_TYPE_FIXED, 2 },
		[0xf4]				= { TLV_TYPE_TV },
		[0xf8]				= { TLV_TYPE_FIXED, 2 },
		[0xfc]				= { TLV_TYPE_TV },
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
		if (ts->pchan != GSM_PCHAN_TCH_F)
			fprintf(stderr, "chan_nr=0x%02x but pchan=%u\n",
				chan_nr, ts->pchan);
	} else if ((cbits & 0x1e) == 0x02) {
		lch_idx = cbits & 0x1;	/* TCH/H */
		if (ts->pchan != GSM_PCHAN_TCH_H)
			fprintf(stderr, "chan_nr=0x%02x but pchan=%u\n",
				chan_nr, ts->pchan);
	} else if ((cbits & 0x1c) == 0x04) {
		lch_idx = cbits & 0x3;	/* SDCCH/4 */
		if (ts->pchan != GSM_PCHAN_CCCH_SDCCH4)
			fprintf(stderr, "chan_nr=0x%02x but pchan=%u\n",
				chan_nr, ts->pchan);
	} else if ((cbits & 0x18) == 0x08) {
		lch_idx = cbits & 0x7;	/* SDCCH/8 */
		if (ts->pchan != GSM_PCHAN_SDCCH8_SACCH8C)
			fprintf(stderr, "chan_nr=0x%02x but pchan=%u\n",
				chan_nr, ts->pchan);
	} else if (cbits == 0x10 || cbits == 0x11 || cbits == 0x12) {
		lch_idx = 0;
		if (ts->pchan != GSM_PCHAN_CCCH &&
		    ts->pchan != GSM_PCHAN_CCCH_SDCCH4)
			fprintf(stderr, "chan_nr=0x%02x but pchan=%u\n",
				chan_nr, ts->pchan);
		/* FIXME: we should not return first sdcch4 !!! */
	} else {
		fprintf(stderr, "unknown chan_nr=0x%02x\n", chan_nr);
		return NULL;
	}

	lchan = &ts->lchan[lch_idx];

	return lchan;
}

u_int8_t lchan2chan_nr(struct gsm_lchan *lchan)
{
	struct gsm_bts_trx_ts *ts = lchan->ts;
	u_int8_t cbits, chan_nr;

	switch (ts->pchan) {
	case GSM_PCHAN_TCH_F:
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
	return msgb_alloc_headroom(RSL_ALLOC_SIZE, RSL_ALLOC_HEADROOM);
}

#define MACBLOCK_SIZE	23
static void pad_macblock(u_int8_t *out, const u_int8_t *in, int len)
{
	memcpy(out, in, len);

	if (len < MACBLOCK_SIZE)
		memset(out+len, 0x2b, MACBLOCK_SIZE-len);
}

static void print_rsl_cause(u_int8_t *cause_tlv)
{
	u_int8_t cause_len;
	int i;

	if (cause_tlv[0] != RSL_IE_CAUSE)
		return;

	cause_len = cause_tlv[1];
	DEBUGPC(DRSL, "CAUSE: ");
	for (i = 0; i < cause_len; i++) 
		DEBUGPC(DRSL, "%02x ", cause_tlv[2+i]);
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
	struct msgb *msg = rsl_msgb_alloc();
	u_int8_t chan_nr = lchan2chan_nr(lchan);

	db = abs(db);
	if (db > 30)
		return -EINVAL;

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

/* determine power control level for given dBm value, as indicated
 * by the tables in chapter 4.1.1 of GSM TS 05.05 */
static int ms_pwr_ctl_lvl(struct gsm_bts *bts, unsigned int dbm)
{
	switch (bts->band) {
	case GSM_BAND_400:
	case GSM_BAND_900:
	case GSM_BAND_850:
		if (dbm >= 39)
			return 0;
		else if (dbm < 5)
			return 19;
		else
			return 2 + ((39 - dbm) / 2);
		break;
	case GSM_BAND_1800:
		if (dbm >= 36)
			return 29;
		else if (dbm >= 34)	
			return 30;
		else if (dbm >= 32)
			return 31;
		else
			return (30 - dbm) / 2;
		break;
	case GSM_BAND_1900:
		if (dbm >= 33)
			return 30;
		else if (dbm >= 32)
			return 31;
		else
			return (30 - dbm) / 2;
		break;
	}
	return -EINVAL;
}

int rsl_chan_ms_power_ctrl(struct gsm_lchan *lchan, unsigned int fpc, int dbm)
{
	struct abis_rsl_dchan_hdr *dh;
	struct msgb *msg = rsl_msgb_alloc();
	u_int8_t chan_nr = lchan2chan_nr(lchan);
	int ctl_lvl;

	ctl_lvl = ms_pwr_ctl_lvl(lchan->ts->trx->bts, dbm);
	if (ctl_lvl < 0)
		return ctl_lvl;

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
			    u_int8_t ta, u_int8_t mode)
{
	struct abis_rsl_dchan_hdr *dh;
	struct msgb *msg = rsl_msgb_alloc();

	u_int8_t chan_nr = lchan2chan_nr(lchan);
	u_int16_t arfcn = lchan->ts->trx->arfcn;
	struct rsl_ie_chan_mode cm;
	struct rsl_ie_chan_ident ci;

	memset(&cm, 0, sizeof(cm));
	/* FIXME: what to do with data calls ? */
	cm.dtx_dtu = 0x00;
	switch (lchan->type) {
	case GSM_LCHAN_SDCCH:
		cm.spd_ind = RSL_CMOD_SPD_SIGN;
		cm.chan_rt = RSL_CMOD_CRT_SDCCH;
		cm.chan_rate = 0x00;
		break;
	case GSM_LCHAN_TCH_F:
		cm.chan_rt = RSL_CMOD_CRT_TCH_Bm;
		switch (mode) {
		case RSL_CMOD_SPD_SIGN:
			cm.spd_ind = RSL_CMOD_SPD_SIGN;
			cm.chan_rate = 0x00;
			break;
		case RSL_CMOD_SPD_SPEECH:
			cm.spd_ind = RSL_CMOD_SPD_SPEECH;
			cm.chan_rate = RSL_CMOD_SP_GSM2;
			break;
		}
		break;
	case GSM_LCHAN_TCH_H:
		DEBUGP(DRSL, "Unimplemented TCH_H activation\n");
		return -1;
	case GSM_LCHAN_UNKNOWN:
	case GSM_LCHAN_NONE:
		return -1;
	}

	memset(&ci, 0, sizeof(ci));
	ci.chan_desc.iei = 0x64;
	ci.chan_desc.chan_nr = chan_nr;
	ci.chan_desc.oct3 = (lchan->ts->trx->bts->tsc << 5) | ((arfcn & 0x3ff) >> 8);
	ci.chan_desc.oct4 = arfcn & 0xff;

	dh = (struct abis_rsl_dchan_hdr *) msgb_put(msg, sizeof(*dh));
	init_dchan_hdr(dh, RSL_MT_CHAN_ACTIV);
	dh->chan_nr = chan_nr;

	msgb_tv_put(msg, RSL_IE_ACT_TYPE, act_type);
	/* For compatibility with Phase 1 */
	msgb_tlv_put(msg, RSL_IE_CHAN_MODE, sizeof(cm),
		     (u_int8_t *) &cm);
	msgb_tlv_put(msg, RSL_IE_CHAN_IDENT, 4,
		     (u_int8_t *) &ci);
#if 0
	msgb_tlv_put(msg, RSL_IE_ENCR_INFO, 1,
		     (u_int8_t *) &encr_info);
#endif
	msgb_tv_put(msg, RSL_IE_BS_POWER, lchan->bs_power);
	msgb_tv_put(msg, RSL_IE_MS_POWER, lchan->ms_power);
	msgb_tv_put(msg, RSL_IE_TIMING_ADVANCE, ta);

	msg->trx = lchan->ts->trx;

	return abis_rsl_sendmsg(msg);
}

/* Chapter 8.4.9 */
int rsl_chan_mode_modify_req(struct gsm_lchan *lchan)
{
	struct abis_rsl_dchan_hdr *dh;
	struct msgb *msg = rsl_msgb_alloc();

	u_int8_t chan_nr = lchan2chan_nr(lchan);
	struct rsl_ie_chan_mode cm;

	memset(&cm, 0, sizeof(cm));

	/* FIXME: what to do with data calls ? */
	cm.dtx_dtu = 0x00;
	switch (lchan->type) {
	/* todo more modes */
	case GSM_LCHAN_TCH_F:
		cm.spd_ind = RSL_CMOD_SPD_SPEECH;
		cm.chan_rt = RSL_CMOD_CRT_TCH_Bm;
		switch(lchan->tch_mode) {
		case GSM48_CMODE_SPEECH_V1:
			cm.chan_rate = RSL_CMOD_SP_GSM1;
			break;
		case GSM48_CMODE_SPEECH_EFR:
			cm.chan_rate = RSL_CMOD_SP_GSM2;
			break;
		default:
			DEBUGP(DRSL, "Unimplemented channel modification\n");
			return -1;
		}
		break;
	default:
		DEBUGP(DRSL, "Unimplemented channel modification\n");
		return -1;
	}

	dh = (struct abis_rsl_dchan_hdr *) msgb_put(msg, sizeof(*dh));
	init_dchan_hdr(dh, RSL_MT_MODE_MODIFY_REQ);
	dh->chan_nr = chan_nr;

	msgb_tlv_put(msg, RSL_IE_CHAN_MODE, sizeof(cm),
		     (u_int8_t *) &cm);
#if 0
	msgb_tlv_put(msg, RSL_IE_ENCR_INFO, 1,
		     (u_int8_t *) &encr_info);
#endif

	msg->trx = lchan->ts->trx;

	return abis_rsl_sendmsg(msg);
}

/* Chapter 9.1.7 of 04.08 */
int rsl_chan_release(struct gsm_lchan *lchan)
{
	struct abis_rsl_dchan_hdr *dh;
	struct msgb *msg = rsl_msgb_alloc();

	dh = (struct abis_rsl_dchan_hdr *) msgb_put(msg, sizeof(*dh));
	init_dchan_hdr(dh, RSL_MT_RF_CHAN_REL);
	dh->chan_nr = lchan2chan_nr(lchan);

	msg->lchan = lchan;
	msg->trx = lchan->ts->trx;

	DEBUGP(DRSL, "Channel Release CMD channel=%s chan_nr=0x%02x\n",
		gsm_ts_name(lchan->ts), dh->chan_nr);

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

/* Send "DATA REQUEST" message with given L3 Info payload */
/* Chapter 8.3.1 */
int rsl_data_request(struct msgb *msg, u_int8_t link_id)
{
	u_int8_t l3_len = msg->tail - (u_int8_t *)msgb_l3(msg);
	struct abis_rsl_rll_hdr *rh;

	if (msg->lchan == NULL) {
		fprintf(stderr, "cannot send DATA REQUEST to unknown lchan\n");
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

/* Chapter 8.4.2: Channel Activate Acknowledge */
static int rsl_rx_chan_act_ack(struct msgb *msg)
{
	struct abis_rsl_dchan_hdr *rslh = msgb_l2(msg);

	/* BTS has confirmed channel activation, we now need
	 * to assign the activated channel to the MS */
	if (rslh->ie_chan != RSL_IE_CHAN_NR)
		return -EINVAL;
	
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
		DEBUGPC(DRSL, "CAUSE=0x%02x ", *TLVP_VAL(&tp, RSL_IE_CAUSE));
	
	return 0;
}

/* Chapter 8.4.4: Connection Failure Indication */
static int rsl_rx_conn_fail(struct msgb *msg)
{
	struct abis_rsl_dchan_hdr *dh = msgb_l2(msg);
	struct tlv_parsed tp;

	DEBUGPC(DRSL, "CONNECTION FAIL: ");
	print_rsl_cause(dh->data);

	rsl_tlv_parse(&tp, dh->data, msgb_l2len(msg)-sizeof(*dh));

	if (msg->trx->bts->type == GSM_BTS_TYPE_BS11) {
		/* FIXME: we have no idea what cause 0x18 is !!! */
		if (TLVP_PRESENT(&tp, RSL_IE_CAUSE) &&
		    TLVP_LEN(&tp, RSL_IE_CAUSE) >= 1 &&
		    *TLVP_VAL(&tp, RSL_IE_CAUSE) == 0x18) {
			if (msg->lchan->use_count > 0) {
				DEBUGPC(DRSL, "Cause 0x18 IGNORING, lchan in use! (%d times)\n", msg->lchan->use_count);
				return 0;
			}
		}
	}

	DEBUGPC(DRSL, "RELEASING.\n");

	/* FIXME: only free it after channel release ACK */
	return rsl_chan_release(msg->lchan);
}

static int rsl_rx_meas_res(struct msgb *msg)
{
	struct abis_rsl_dchan_hdr *dh = msgb_l2(msg);
	struct tlv_parsed tp;

	DEBUGPC(DRSL, "MEASUREMENT RESULT ");
	rsl_tlv_parse(&tp, dh->data, msgb_l2len(msg)-sizeof(*dh));

	if (TLVP_PRESENT(&tp, RSL_IE_MEAS_RES_NR))
		DEBUGPC(DRSL, "NR=%d ", *TLVP_VAL(&tp, RSL_IE_MEAS_RES_NR));
	if (TLVP_PRESENT(&tp, RSL_IE_UPLINK_MEAS)) {
		u_int8_t len = TLVP_LEN(&tp, RSL_IE_UPLINK_MEAS);
		const u_int8_t *val = TLVP_VAL(&tp, RSL_IE_UPLINK_MEAS);
		if (len >= 3) {
			if (val[0] & 0x40)
				DEBUGPC(DRSL, "DTXd ");
			DEBUGPC(DRSL, "RXL-FULL-up=%d RXL-SUB-up=%d ",
				val[0] & 0x3f, val[1] & 0x3f);
			DEBUGPC(DRSL, "RXQ-FULL-up=%d RXQ-SUB-up=%d ",
				val[2]>>3 & 0x7, val[2] & 0x7);
		}
	}
	if (TLVP_PRESENT(&tp, RSL_IE_BS_POWER))
		DEBUGPC(DRSL, "BS_POWER=%d ", *TLVP_VAL(&tp, RSL_IE_BS_POWER));
	if (TLVP_PRESENT(&tp, RSL_IE_MS_TIMING_OFFSET))
		DEBUGPC(DRSL, "MS_TO=%d ", 
			*TLVP_VAL(&tp, RSL_IE_MS_TIMING_OFFSET));
	if (TLVP_PRESENT(&tp, RSL_IE_L1_INFO))
		DEBUGPC(DRSL, "L1 ");
	if (TLVP_PRESENT(&tp, RSL_IE_L3_INFO)) {
		DEBUGPC(DRSL, "L3\n");
		msg->l3h = TLVP_VAL(&tp, RSL_IE_L3_INFO);
		return gsm0408_rcvmsg(msg);
	} else
		DEBUGPC(DRSL, "\n");

	return 0;
}

static int abis_rsl_rx_dchan(struct msgb *msg)
{
	struct abis_rsl_dchan_hdr *rslh = msgb_l2(msg);
	int rc = 0;
	char *ts_name;

	msg->lchan = lchan_lookup(msg->trx, rslh->chan_nr);
	ts_name = gsm_ts_name(msg->lchan->ts);

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

	DEBUGP(DRSL, "ERROR REPORT ");
	print_rsl_cause(rslh->data);
	DEBUGPC(DRSL, "\n");

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
		DEBUGP(DRSL, "TRX: CCCH/ACCH/CPU Overload\n");
		break;
	default:
		DEBUGP(DRSL, "Unknown Abis RSL TRX message type 0x%02x\n",
			rslh->msg_type);
		return -EINVAL;
	}
	return rc;
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
	lctype = get_ctype_by_chreq(bts, rqd_ref->ra);
	chreq_reason = get_reason_by_chreq(bts, rqd_ref->ra);

	/* check availability / allocate channel */
	lchan = lchan_alloc(bts, lctype);
	if (!lchan) {
		fprintf(stderr, "CHAN RQD: no resources\n");
		/* FIXME: send some kind of reject ?!? */
		return -ENOMEM;
	}

	ts_number = lchan->ts->nr;
	arfcn = lchan->ts->trx->arfcn;
	subch = lchan->nr;
	
	lchan->ms_power = lchan->bs_power = 0x0f; /* 30dB reduction */
	rsl_chan_activate_lchan(lchan, 0x00, rqd_ta, RSL_CMOD_SPD_SIGN);

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
	ia.chan_desc.h0.tsc = 7;
	/* use request reference extracted from CHAN_RQD */
	memcpy(&ia.req_ref, rqd_ref, sizeof(ia.req_ref));
	ia.timing_advance = rqd_ta;
	ia.mob_alloc_len = 0;

	DEBUGP(DRSL, "Activating ARFCN(%u) TS(%u) SS(%u) lctype %s "
		"chan_nr=0x%02x r=%s ra=0x%02x\n",
		arfcn, ts_number, subch, gsm_lchan_name(lchan->type),
		ia.chan_desc.chan_nr, gsm_chreq_name(chreq_reason),
		rqd_ref->ra);

	/* FIXME: Start timer T3101 to wait for GSM48_MT_RR_PAG_RESP */

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
		fprintf(stderr, "Unimplemented Abis RSL TRX message type "
			"0x%02x\n", rslh->c.msg_type);
		break;
	default:
		fprintf(stderr, "Unknown Abis RSL TRX message type 0x%02x\n",
			rslh->c.msg_type);
		return -EINVAL;
	}

	return rc;
}

static int rsl_rx_rll_err_ind(struct msgb *msg)
{
	struct abis_rsl_rll_hdr *rllh = msgb_l2(msg);
	u_int8_t *rlm_cause = rllh->data;

	DEBUGPC(DRLL, "cause=0x%02x", rlm_cause[1]);
		
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

	msg->lchan = lchan_lookup(msg->trx, rllh->chan_nr);
	ts_name = gsm_ts_name(msg->lchan->ts);
	DEBUGP(DRLL, "channel=%s chan_nr=0x%02x ", ts_name, rllh->chan_nr);
	
	switch (rllh->c.msg_type) {
	case RSL_MT_DATA_IND:
		DEBUGPC(DRLL, "DATA INDICATION\n");
		if (msgb_l2len(msg) > 
		    sizeof(struct abis_rsl_common_hdr) + sizeof(*rllh) &&
		    rllh->data[0] == RSL_IE_L3_INFO) {
			msg->l3h = &rllh->data[3];
			return gsm0408_rcvmsg(msg);
		}
		break;
	case RSL_MT_EST_IND:
		DEBUGPC(DRLL, "ESTABLISH INDICATION\n");
		if (msgb_l2len(msg) > 
		    sizeof(struct abis_rsl_common_hdr) + sizeof(*rllh) &&
		    rllh->data[0] == RSL_IE_L3_INFO) {
			msg->l3h = &rllh->data[3];
			return gsm0408_rcvmsg(msg);
		}
		break;
	case RSL_MT_REL_IND:
		DEBUGPC(DRLL, "RELEASE INDICATION ");
		break;
	case RSL_MT_REL_CONF:
		DEBUGPC(DRLL, "RELEASE CONFIRMATION ");
		break;
	case RSL_MT_ERROR_IND:
		DEBUGPC(DRLL, "ERROR INDICATION ");
		rc = rsl_rx_rll_err_ind(msg);
		break;
	case RSL_MT_UNIT_DATA_IND:
		DEBUGPC(DRLL, "unimplemented Abis RLL message type 0x%02x ",
			rllh->c.msg_type);
		break;
	default:
		DEBUGPC(DRLL, "unknown Abis RLL message type 0x%02x ",
			rllh->c.msg_type);
	}
	DEBUGPC(DRLL, "\n");
	return rc;
}

/* ip.access specific RSL extensions */
int rsl_ipacc_bind(struct gsm_lchan *lchan)
{
	struct msgb *msg = rsl_msgb_alloc();
	struct abis_rsl_dchan_hdr *dh;

	dh = (struct abis_rsl_dchan_hdr *) msgb_put(msg, sizeof(*dh));
	init_dchan_hdr(dh, RSL_MT_IPAC_BIND);
	dh->c.msg_discr = ABIS_RSL_MDISC_IPACCESS;
	dh->chan_nr = lchan2chan_nr(lchan);

	msg->trx = lchan->ts->trx;

	return abis_rsl_sendmsg(msg);
}

int rsl_ipacc_connect(struct gsm_lchan *lchan, u_int32_t ip, u_int16_t port, u_int16_t f8, u_int8_t fc)
{
	struct msgb *msg = rsl_msgb_alloc();
	struct abis_rsl_dchan_hdr *dh;
	u_int8_t *att_f8, *att_ip, *att_port;

	dh = (struct abis_rsl_dchan_hdr *) msgb_put(msg, sizeof(*dh));
	init_dchan_hdr(dh, RSL_MT_IPAC_CONNECT);
	dh->c.msg_discr = ABIS_RSL_MDISC_IPACCESS;
	dh->chan_nr = lchan2chan_nr(lchan);

	att_f8 = msgb_put(msg, sizeof(f8)+1);
	att_f8[0] = 0xf8;
	att_f8[1] = f8 >> 8;
	att_f8[2] = f8 & 0xff;

	att_ip = msgb_put(msg, sizeof(ip)+1);
	att_ip[0] = RSL_IE_IPAC_REMOTE_IP;
	att_ip[1] = ip >> 24;
	att_ip[2] = ip >> 16;
	att_ip[3] = ip >> 8;
	att_ip[4] = ip & 0xff;
	//att_ip[4] = 11;

	att_port = msgb_put(msg, sizeof(port)+1);
	att_port[0] = RSL_IE_IPAC_REMOTE_PORT;
	att_port[1] = port >> 8;
	att_port[2] = port & 0xff;

	msgb_tv_put(msg, 0xf4, 1);	/* F4 01 */
	msgb_tv_put(msg, 0xfc, fc);	/* FC 7F */
	msg->trx = lchan->ts->trx;

	return abis_rsl_sendmsg(msg);
}

static int abis_rsl_rx_ipacc_bindack(struct msgb *msg)
{
	struct abis_rsl_dchan_hdr *dh = msgb_l2(msg);
	struct tlv_parsed tv;
	struct gsm_bts_trx_ts *ts = msg->lchan->ts;
	struct in_addr ip;
	u_int16_t port, attr_f8;

	/* the BTS has acknowledged a local bind, it now tells us the IP
	* address and port number to which it has bound the given logical
	* channel */

	rsl_tlv_parse(&tv, dh->data, msgb_l2len(msg)-sizeof(*dh));
	if (!TLVP_PRESENT(&tv, RSL_IE_IPAC_LOCAL_PORT) ||
	    !TLVP_PRESENT(&tv, RSL_IE_IPAC_LOCAL_IP) ||
	    !TLVP_PRESENT(&tv, 0xfc) ||
	    !TLVP_PRESENT(&tv, 0xf8)) {
		DEBUGPC(DRSL, "mandatory IE missing");
		return -EINVAL;
	}
	ip.s_addr = *((u_int32_t *) TLVP_VAL(&tv, RSL_IE_IPAC_LOCAL_IP));
	port = *((u_int16_t *) TLVP_VAL(&tv, RSL_IE_IPAC_LOCAL_PORT));
	attr_f8 = *((u_int16_t *) TLVP_VAL(&tv, 0xf8));

	DEBUGPC(DRSL, "IP=%s PORT=%d FC=%d F8=%d",
		inet_ntoa(ip), ntohs(port), *TLVP_VAL(&tv, 0xfc),
		ntohs(attr_f8));

	/* update our local information about this TS */
	ts->abis_ip.bound_ip = ntohl(ip.s_addr);
	ts->abis_ip.bound_port = ntohs(port);
	ts->abis_ip.attr_f8 = ntohs(attr_f8);
	ts->abis_ip.attr_fc = *TLVP_VAL(&tv, 0xfc);

	dispatch_signal(SS_ABISIP, S_ABISIP_BIND_ACK, msg->lchan);

	return 0;
}

static int abis_rsl_rx_ipacc_disc_ind(struct msgb *msg)
{
	struct abis_rsl_dchan_hdr *dh = msgb_l2(msg);
	struct tlv_parsed tv;

	rsl_tlv_parse(&tv, dh->data, msgb_l2len(msg)-sizeof(*dh));
	if (!TLVP_PRESENT(&tv, RSL_IE_CAUSE)) {
		DEBUGPC(DRSL, "mandatory IE missing! ");
		return -EINVAL;
	}

	DEBUGPC(DRSL, "cause=0x%02x ", *TLVP_VAL(&tv, RSL_IE_CAUSE));

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
	case RSL_MT_IPAC_BIND_ACK:
		DEBUGPC(DRSL, "IPAC_BIND_ACK ");
		rc = abis_rsl_rx_ipacc_bindack(msg);
		break;
	case RSL_MT_IPAC_BIND_NACK:
		/* somehow the BTS was unable to bind the lchan to its local
		 * port?!? */
		DEBUGPC(DRSL, "IPAC_BIND_NACK ");
		break;
	case RSL_MT_IPAC_CONNECT_ACK:
		/* the BTS tells us that a connect operation was successful */
		DEBUGPC(DRSL, "IPAC_CONNECT_ACK ");
		break;
	case RSL_MT_IPAC_CONNECT_NACK:
		/* somehow the BTS was unable to connect the lchan to a remote
		 * port */
		DEBUGPC(DRSL, "IPAC_CONNECT_NACK ");
		break;
	case RSL_MT_IPAC_DISCONNECT_IND:
		DEBUGPC(DRSL, "IPAC_DISCONNECT_IND ");
		rc = abis_rsl_rx_ipacc_disc_ind(msg);
		break;
	default:
		DEBUGPC(DRSL, "Unknown ip.access msg_type 0x%02x", rllh->c.msg_type);
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
		fprintf(stderr, "unimplemented RSL msg disc 0x%02x\n",
			rslh->msg_discr);
		break;
	case ABIS_RSL_MDISC_IPACCESS:
		rc = abis_rsl_rx_ipacc(msg);
		break;
	default:
		fprintf(stderr, "unknown RSL message discriminator 0x%02x\n",
			rslh->msg_discr);
		return -EINVAL;
	}
	msgb_free(msg);
	return rc;
}


/* Section 3.3.2.3 . I think this looks like a table */
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
	if (bts->chan_desc.ccch_conf == RSL_BCCH_CCCH_CONF_1_C) {
		return MAX(1, (3 - bts->chan_desc.bs_ag_blks_res))
			* (bts->chan_desc.bs_pa_mfrms + 2);
	} else {
		return (9 - bts->chan_desc.bs_ag_blks_res)
			* (bts->chan_desc.bs_pa_mfrms + 2);
	}
}
