/* GSM Radio Signalling Link messages on the A-bis interface 
 * 3GPP TS 08.58 version 8.6.0 Release 1999 / ETSI TS 100 596 V8.6.0 */

/* (C) 2008 by Harald Welte <laforge@gnumonks.org>
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

#include <openbsc/gsm_data.h>
#include <openbsc/gsm_04_08.h>
#include <openbsc/abis_rsl.h>
#include <openbsc/chan_alloc.h>
#include <openbsc/debug.h>
#include <openbsc/tlv.h>

#define RSL_ALLOC_SIZE		1024
#define RSL_ALLOC_HEADROOM	128

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

/* Send a BCCH_INFO message as per Chapter 8.5.1 */
int rsl_bcch_info(struct gsm_bts *bts, u_int8_t type,
		  const u_int8_t *data, int len)
{
	struct abis_rsl_dchan_hdr *dh;
	struct msgb *msg = rsl_msgb_alloc();

	dh = (struct abis_rsl_dchan_hdr *) msgb_put(msg, sizeof*dh);
	init_dchan_hdr(dh, RSL_MT_BCCH_INFO);
	dh->chan_nr = RSL_CHAN_BCCH;

	msgb_tv_put(msg, RSL_IE_SYSINFO_TYPE, type);
	msgb_tlv_put(msg, RSL_IE_FULL_BCCH_INFO, len, data);

	msg->trx = bts->c0;

	return abis_rsl_sendmsg(msg);
}

int rsl_sacch_filling(struct gsm_bts *bts, u_int8_t type, 
		      const u_int8_t *data, int len)
{
	struct abis_rsl_common_hdr *ch;
	struct msgb *msg = rsl_msgb_alloc();

	ch = (struct abis_rsl_common_hdr *) msgb_put(msg, sizeof(*ch));
	ch->msg_discr = ABIS_RSL_MDISC_TRX;
	ch->msg_type = RSL_MT_SACCH_FILL;

	msgb_tv_put(msg, RSL_IE_SYSINFO_TYPE, type);
	msgb_tl16v_put(msg, RSL_IE_L3_INFO, len, data);

	msg->trx = bts->c0;

	return abis_rsl_sendmsg(msg);
}

/* Chapter 8.4.1 */
int rsl_chan_activate(struct gsm_bts *bts, u_int8_t chan_nr,
		      u_int8_t act_type,
		      struct rsl_ie_chan_mode *chan_mode,
		      struct rsl_ie_chan_ident *chan_ident,
		      u_int8_t bs_power, u_int8_t ms_power,
		      u_int8_t ta)
{
	struct abis_rsl_dchan_hdr *dh;
	struct msgb *msg = rsl_msgb_alloc();
	u_int8_t encr_info = 0x01;

	dh = (struct abis_rsl_dchan_hdr *) msgb_put(msg, sizeof(*dh));
	init_dchan_hdr(dh, RSL_MT_CHAN_ACTIV);
	dh->chan_nr = chan_nr;

	msgb_tv_put(msg, RSL_IE_ACT_TYPE, act_type);
	/* For compatibility with Phase 1 */
	msgb_tlv_put(msg, RSL_IE_CHAN_MODE, sizeof(*chan_mode),
		     (u_int8_t *) chan_mode);
	msgb_tlv_put(msg, RSL_IE_CHAN_IDENT, 4,
		     (u_int8_t *) chan_ident);
	/* FIXME: this shoould be optional */
#if 0
	msgb_tlv_put(msg, RSL_IE_ENCR_INFO, 1,
		     (u_int8_t *) &encr_info);
	msgb_tv_put(msg, RSL_IE_BS_POWER, bs_power);
#endif
	msgb_tv_put(msg, RSL_IE_MS_POWER, ms_power);
	msgb_tv_put(msg, RSL_IE_TIMING_ADVANCE, ta);

	return abis_rsl_sendmsg(msg);
}

#define TSC	7

int rsl_chan_activate_lchan(struct gsm_lchan *lchan, u_int8_t act_type, u_int8_t ta)
{
	struct abis_rsl_dchan_hdr *dh;
	struct msgb *msg = rsl_msgb_alloc();
	/* FXIME: don't hardcode these!! */
	u_int8_t encr_info = 0x01;
	u_int8_t ms_power = 0x0f;
	u_int8_t bs_power = 0x01;

	u_int8_t chan_nr = lchan2chan_nr(lchan);
	u_int16_t arfcn = lchan->ts->trx->arfcn;
	struct rsl_ie_chan_mode cm;
	struct rsl_ie_chan_ident ci;

	/* FIXME: what to do with data calls ? */
	cm.dtx_dtu = 0x00;
	switch (lchan->type) {
	case GSM_LCHAN_SDCCH:
		cm.spd_ind = RSL_CMOD_SPD_SIGN;
		cm.chan_rt = RSL_CMOD_CRT_SDCCH;
		cm.chan_rate = 0x00;
		break;
	case GSM_LCHAN_TCH_F:
		cm.spd_ind = RSL_CMOD_SPD_SPEECH;
		cm.chan_rt = RSL_CMOD_CRT_TCH_Bm;
		cm.chan_rate = 0x11; /* speech coding alg version 2*/
		break;
	}

	ci.chan_desc.iei = 0x64;
	ci.chan_desc.chan_nr = chan_nr;
	ci.chan_desc.oct3 = (TSC << 5) | ((arfcn & 0x3ff) >> 8);
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
	/* FIXME: this shoould be optional */
#if 0
	msgb_tlv_put(msg, RSL_IE_ENCR_INFO, 1,
		     (u_int8_t *) &encr_info);
	msgb_tv_put(msg, RSL_IE_BS_POWER, bs_power);
#endif
	msgb_tv_put(msg, RSL_IE_MS_POWER, ms_power);
	msgb_tv_put(msg, RSL_IE_TIMING_ADVANCE, ta);

	return abis_rsl_sendmsg(msg);
}

int rsl_chan_release(struct gsm_lchan *lchan)
{
	struct abis_rsl_dchan_hdr *dh;
	struct msgb *msg = rsl_msgb_alloc();

	dh = (struct abis_rsl_dchan_hdr *) msgb_put(msg, sizeof(*dh));
	init_dchan_hdr(dh, RSL_MT_RF_CHAN_REL);
	dh->chan_nr = lchan2chan_nr(lchan);

	msg->lchan = lchan;
	msg->trx = lchan->ts->trx;

	DEBUGP(DRSL, "Channel Release CMD, chan_nr=0x%02x\n", dh->chan_nr);

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

# if 0
int rsl_paging_cmd_imsi(struct gsm_bts *bts, u_int8_t chan_needed, const char *imsi_str)
{
	/* FIXME: derive the MS Identity */
	return rsl_paging_cmd(bts, paging_group, x, y, chan_needed);
}
#endif

/* Chapter 8.5.6 */
int rsl_imm_assign_cmd(struct gsm_bts *bts, u_int8_t len, u_int8_t *val)
{
	struct msgb *msg = rsl_msgb_alloc();
	struct abis_rsl_dchan_hdr *dh;

	dh = (struct abis_rsl_dchan_hdr *) msgb_put(msg, sizeof(*dh));
	init_dchan_hdr(dh, RSL_MT_IMMEDIATE_ASSIGN_CMD);
	dh->chan_nr = RSL_CHAN_PCH_AGCH;

	/* If phase 2, FULL_IMM_ASS_INFO */

	msgb_tlv_put(msg, RSL_IE_IMM_ASS_INFO, len, val);

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
	
	DEBUGP(DRSL, "Channel Activate ACK Channel 0x%02x\n", rslh->chan_nr);

	return 0;
}

/* Chapter 8.4.3: Channel Activate NACK */
static int rsl_rx_chan_act_nack(struct msgb *msg)
{
	struct abis_rsl_dchan_hdr *rslh = msgb_l2(msg);

	/* BTS has confirmed channel activation, we now need
	 * to assign the activated channel to the MS */
	if (rslh->ie_chan != RSL_IE_CHAN_NR)
		return -EINVAL;
	
	DEBUGP(DRSL, "Channel Activate NACK Channel 0x%02x\n", rslh->chan_nr);

	return 0;
}

static int abis_rsl_rx_dchan(struct msgb *msg)
{
	struct abis_rsl_dchan_hdr *rslh = msgb_l2(msg);
	int rc = 0;

	msg->lchan = lchan_lookup(msg->trx, rslh->chan_nr);

	switch (rslh->c.msg_type) {
	case RSL_MT_CHAN_ACTIV_ACK:
		rc = rsl_rx_chan_act_ack(msg);
		rc = rsl_rx_chan_act_ack(msg);
		break;
	case RSL_MT_CHAN_ACTIV_NACK:
		rc = rsl_rx_chan_act_nack(msg);
		break;
	case RSL_MT_CONN_FAIL:
		DEBUGP(DRSL, "Connection Fail, release channel\n");
		rc = rsl_chan_release(msg->lchan);
		/* only free it after channel release ACK */
		break;
	case RSL_MT_MEAS_RES:
		DEBUGP(DRSL, "Measurement Result\n");
		break;
	case RSL_MT_RF_CHAN_REL_ACK:
		DEBUGP(DRSL, "RF CHANNEL RELEASE ACK chan_nr=0x%02x\n", rslh->chan_nr);
		lchan_free(msg->lchan);
		break;
	case RSL_MT_MODE_MODIFY_ACK:
	case RSL_MT_MODE_MODIFY_NACK:
	case RSL_MT_PHY_CONTEXT_CONF:
	case RSL_MT_PREPROC_MEAS_RES:
	case RSL_MT_TALKER_DET:
	case RSL_MT_LISTENER_DET:
	case RSL_MT_REMOTE_CODEC_CONF_REP:
	case RSL_MT_MR_CODEC_MOD_ACK:
	case RSL_MT_MR_CODEC_MOD_NACK:
	case RSL_MT_MR_CODEC_MOD_PER:
		fprintf(stderr, "Unimplemented Abis RSL DChan msg 0x%02x\n",
			rslh->c.msg_type);
		break;
	default:
		fprintf(stderr, "unknown Abis RSL DChan msg 0x%02x\n",
			rslh->c.msg_type);
		return -EINVAL;
	}
	return rc;
}

static int rsl_rx_error_rep(struct msgb *msg)
{
	struct abis_rsl_common_hdr *rslh = msgb_l2(msg);
	u_int8_t cause_len;

	if (rslh->data[0] != RSL_IE_CAUSE)
		return -EINVAL;

	cause_len = rslh->data[1];
	fprintf(stdout, "RSL ERROR REPORT, Cause ");
	hexdump(&rslh->data[2], cause_len);

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
	case RSL_MT_OVERLOAD:
		/* indicate CCCH / ACCH / processor overload */ 
		fprintf(stderr, "Unimplemented Abis RSL TRX message type 0x%02x\n",
			rslh->msg_type);
		break;
	default:
		fprintf(stderr, "Unknown Abis RSL TRX message type 0x%02x\n",
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
	struct gsm_lchan *lchan;
	u_int8_t rqd_ta;

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
	
	rsl_chan_activate_lchan(lchan, 0x00, rqd_ta);

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

	DEBUGP(DRSL, "Activating ARFCN(%u) TS(%u) SS(%u) lctype %u chan_nr=0x%02x\n",
		arfcn, ts_number, subch, lchan->type, ia.chan_desc.chan_nr);

	/* send IMMEDIATE ASSIGN CMD on RSL to BTS (to send on CCCH to MS) */
	return rsl_imm_assign_cmd(bts, sizeof(ia), (u_int8_t *) &ia);
}

static int abis_rsl_rx_cchan(struct msgb *msg)
{
	struct abis_rsl_dchan_hdr *rslh = msgb_l2(msg)	;
	int rc = 0;

	msg->lchan = lchan_lookup(msg->trx, rslh->chan_nr);

	switch (rslh->c.msg_type) {
	case RSL_MT_CHAN_RQD:
		/* MS has requested a channel on the RACH */
		rc = rsl_rx_chan_rqd(msg);
		break;
	case RSL_MT_DELETE_IND:
		/* CCCH overloaded, IMM_ASSIGN was dropped */
	case RSL_MT_CBCH_LOAD_IND:
		/* current load on the CBCH */
	case RSL_MT_CCCH_LOAD_IND:
		/* current load on the CCCH */
		fprintf(stderr, "Unimplemented Abis RSL TRX message type 0x%02x\n",
			rslh->c.msg_type);
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

	DEBUGP(DRLL, "RLL ERROR INDICATION: chan_nr=0x%02x cause=0x%02x\n",
		rllh->chan_nr, rlm_cause[1]);
		
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
	int rc;

	msg->lchan = lchan_lookup(msg->trx, rllh->chan_nr);
	
	switch (rllh->c.msg_type) {
	case RSL_MT_DATA_IND:
		DEBUGP(DRLL, "DATA INDICATION chan_nr=0x%02x\n", rllh->chan_nr);
		/* FIXME: Verify L3 info element */
		msg->l3h = &rllh->data[3];
		rc = gsm0408_rcvmsg(msg);
		break;
	case RSL_MT_EST_IND:
		DEBUGP(DRLL, "ESTABLISH INDICATION chan_nr=0x%02x\n", rllh->chan_nr);
		/* FIXME: Verify L3 info element */
		msg->l3h = &rllh->data[3];
		rc = gsm0408_rcvmsg(msg);
		break;
	case RSL_MT_REL_IND:
		DEBUGP(DRLL, "RELEASE INDICATION chan_nr=0x%02x\n", rllh->chan_nr);
		break;
	case RSL_MT_REL_CONF:
		DEBUGP(DRLL, "RELEASE CONFIRMATION chan_nr=0x%02x\n", rllh->chan_nr);
		break;
	case RSL_MT_ERROR_IND:
		rc = rsl_rx_rll_err_ind(msg);
		break;
	case RSL_MT_UNIT_DATA_IND:
		fprintf(stderr, "unimplemented Abis RLL message type 0x%02x\n",
			rllh->c.msg_type);
		break;
	default:
		fprintf(stderr, "unknown Abis RLL message type 0x%02x\n",
			rllh->c.msg_type);
	}
	return rc;
}

/* Entry-point where L2 RSL from BTS enters */
int abis_rsl_rcvmsg(struct msgb *msg)
{
	struct abis_rsl_common_hdr *rslh = msgb_l2(msg)	;
	unsigned int l2_len = (void *)msg->tail - msgb_l2(msg);
	int rc;

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
	default:
		fprintf(stderr, "unknown RSL message discriminator 0x%02x\n",
			rslh->msg_discr);
		return -EINVAL;
	}
	msgb_free(msg);
	return rc;
}
