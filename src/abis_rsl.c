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

#include <stdio.h>
#include <errno.h>
#include <sys/types.h>

#include "gsm_data.h"
#include "gsm_04_08.h"
#include "abis_rsl.h"
#include "debug.h"
#include "tlv.h"

#define RSL_ALLOC_SIZE	1024

static u_int8_t mdisc_by_msgtype(u_int8_t msg_type)
{
	/* mask off the transparent bit ? */
	msg_type &= 0xfe;

	if (msg_type & 0xf0 == 0x00)
		return ABIS_RSL_MDISC_RLL;
	if (msg_type & 0xf0 == 0x10) {
		if (msg_type >= 0x19 && msg_type <= 0x22)
			return ABIS_RSL_MDISC_TRX;
		else
			return ABIS_RSL_MDISC_COM_CHAN;
	}
	if (msg_type & 0xc == 0x00)
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

/* Send a BCCH_INFO message as per Chapter 8.5.1 */
int rsl_bcch_info(struct gsm_bts *bts, u_int8_t type,
		  const u_int8_t *data, int len)
{
	struct abis_rsl_dchan_hdr *dh;
	struct msgb *msg = msgb_alloc(RSL_ALLOC_SIZE);

	dh = (struct abis_rsl_dchan_hdr *) msgb_put(msg, sizeof*dh);
	init_dchan_hdr(dh, RSL_MT_BCCH_INFO);
	dh->chan_nr = RSL_CHAN_BCCH;

	msgb_tv_put(msg, RSL_IE_SYSINFO_TYPE, type);
	msgb_tlv_put(msg, RSL_IE_FULL_BCCH_INFO, len, data);

	return abis_rsl_sendmsg(bts, msg);
}

int rsl_sacch_filling(struct gsm_bts *bts, u_int8_t type, 
		      const u_int8_t *data, int len)
{
	struct abis_rsl_common_hdr *ch;
	struct msgb *msg = msgb_alloc(RSL_ALLOC_SIZE);

	ch = (struct abis_rsl_common_hdr *) msgb_put(msg, sizeof(*ch));
	ch->msg_discr = ABIS_RSL_MDISC_TRX;
	ch->msg_type = RSL_MT_SACCH_FILL;

	msgb_tv_put(msg, RSL_IE_SYSINFO_TYPE, type);
	msgb_tlv_put(msg, RSL_IE_L3_INFO, len, data);

	return abis_rsl_sendmsg(bts, msg);
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
	struct msgb *msg = msgb_alloc(RSL_ALLOC_SIZE);
	u_int8_t encr_info = 0x01;

	dh = (struct abis_rsl_dchan_hdr *) msgb_put(msg, sizeof(*dh));
	init_dchan_hdr(dh, RSL_MT_CHAN_ACTIV);
	dh->chan_nr = chan_nr;

	msgb_tv_put(msg, RSL_IE_ACT_TYPE, act_type);
	/* For compatibility with Phase 1 */
	msgb_tlv_put(msg, RSL_IE_CHAN_MODE, sizeof(*chan_mode),
		     (u_int8_t *) chan_mode);
	msgb_tlv_put(msg, RSL_IE_CHAN_IDENT, 4,
		     (u_int8_t *) &chan_ident);
	/* FIXME: this shoould be optional */
	msgb_tlv_put(msg, RSL_IE_ENCR_INFO, 1,
		     (u_int8_t *) &encr_info);
	msgb_tv_put(msg, RSL_IE_BS_POWER, bs_power);
	msgb_tv_put(msg, RSL_IE_MS_POWER, ms_power);
	msgb_tv_put(msg, RSL_IE_TIMING_ADVANCE, ta);

	return abis_rsl_sendmsg(bts, msg);
}

#define TSC	7

int rsl_chan_activate_tch_f(struct gsm_bts_trx_ts *ts)
{
	u_int8_t chan_nr = rsl_enc_chan_nr(RSL_CHAN_Bm_ACCHs, 0, ts->nr);
	u_int16_t arfcn = ts->trx->arfcn;
	struct rsl_ie_chan_mode cm;
	struct rsl_ie_chan_ident ci;

	cm.dtx_dtu = 0;
	cm.spd_ind = RSL_CMOD_SPD_SPEECH;
	cm.chan_rt = RSL_CMOD_CRT_TCH_Bm;
	cm.chan_rate = RSL_CMOD_SP_GSM1;

	ci.chan_desc.iei = 0x64;
	ci.chan_desc.chan_nr = chan_nr;
	/* FIXME: this doesn't support hopping */
	ci.chan_desc.oct3 = (TSC << 5) | ((arfcn & 0x3ff) >> 8);
	ci.chan_desc.oct4 = arfcn & 0xff;
#if 0
	ci.mobile_alloc.tag = 0x72;
	ci.mobile_alloc.len = 0;	/* as per Section 9.3.5 */
#endif

	return rsl_chan_activate(ts->trx->bts, chan_nr, 0x01, &cm, &ci, 0x01, 0x0f, 0x00);
}

int rsl_chan_activate_sdcch(struct gsm_bts_trx_ts *ts)
{
	u_int8_t chan_nr = rsl_enc_chan_nr(RSL_CHAN_SDCCH4_ACCH, 0, ts->nr);
	u_int16_t arfcn = ts->trx->arfcn;
	struct rsl_ie_chan_mode cm;
	struct rsl_ie_chan_ident ci;

	cm.dtx_dtu = 0x00;
	cm.spd_ind = RSL_CMOD_SPD_SIGN;
	cm.chan_rt = RSL_CMOD_CRT_SDCCH;
	cm.chan_rate = 0x00;

	ci.chan_desc.iei = 0x64;
	ci.chan_desc.chan_nr = chan_nr;
	ci.chan_desc.oct3 = (TSC << 5) | ((arfcn & 0x3ff) >> 8);
	ci.chan_desc.oct4 = arfcn & 0xff;

	/* FIXME: we're sending BS power IE, whcih Abissim doesn't */
	return rsl_chan_activate(ts->trx->bts, chan_nr, 0x00, &cm, &ci, 0x01, 0x0f, 0x00);
}

int rsl_chan_release(struct gsm_bts_trx_ts *ts, u_int8_t chan_nr)
{
	struct abis_rsl_dchan_hdr *dh;
	struct msgb *msg = msgb_alloc(RSL_ALLOC_SIZE);

	dh = (struct abis_rsl_dchan_hdr *) msgb_put(msg, sizeof(*dh));
	init_dchan_hdr(dh, RSL_MT_RF_CHAN_REL);
	dh->chan_nr = chan_nr;

	return abis_rsl_sendmsg(ts->trx->bts, msg);
}

int rsl_paging_cmd(struct gsm_bts *bts, u_int8_t paging_group, u_int8_t len,
		   u_int8_t *ms_ident, u_int8_t chan_needed)
{
	struct abis_rsl_dchan_hdr *dh;
	struct msgb *msg = msgb_alloc(RSL_ALLOC_SIZE);

	dh = (struct abis_rsl_dchan_hdr *) msgb_put(msg, sizeof(*dh));
	init_dchan_hdr(dh, RSL_MT_PAGING_CMD);
	dh->chan_nr = RSL_CHAN_PCH_AGCH;

	msgb_tv_put(msg, RSL_IE_PAGING_GROUP, paging_group);
	msgb_tlv_put(msg, RSL_IE_MS_IDENTITY, len, ms_ident);
	msgb_tv_put(msg, RSL_IE_CHAN_NEEDED, chan_needed);

	return abis_rsl_sendmsg(bts, msg);
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

int rsl_imm_assign_cmd(struct gsm_bts *bts, u_int8_t len, u_int8_t *val)
{
	struct msgb *msg = msgb_alloc(RSL_ALLOC_SIZE);
	struct abis_rsl_dchan_hdr *dh;

	dh = (struct abis_rsl_dchan_hdr *) msgb_put(msg, sizeof(*dh));
	init_dchan_hdr(dh, RSL_MT_IMMEDIATE_ASSIGN_CMD);
	dh->chan_nr = RSL_CHAN_PCH_AGCH;

	/* If phase 2, FULL_IMM_ASS_INFO */

	msgb_tlv_put(msg, RSL_IE_IMM_ASS_INFO, len, val);

	return abis_rsl_sendmsg(bts, msg);
}

/* Chapter 8.3.1 */
int rsl_data_request(struct gsm_bts *bts, struct msgb *msg)
{
	/* FIXME: prepend RSL header to layer 3 message */
	u_int8_t len = msg->len;
	struct abis_rsl_rll_hdr *rh;

	msgb_tv_push(msg, RSL_IE_L3_INFO, len);

	rh = (struct abis_rsl_rll_hdr *) msgb_push(msg, sizeof(*rh));
	init_llm_hdr(rh, RSL_MT_DATA_REQ);
	rh->chan_nr = RSL_CHAN_SDCCH4_ACCH;	/* FIXME: don't harcode */

	return abis_rsl_sendmsg(bts, msg);
}

static int abis_rsl_rx_dchan(struct msgb *msg)
{
	struct abis_rsl_common_hdr *rslh = msgb_l2(msg)	;

	switch (rslh->msg_type) {
	case RSL_MT_CHAN_ACTIV_ACK:
	case RSL_MT_CHAN_ACTIV_NACK:
	case RSL_MT_CONN_FAIL:
	case RSL_MT_MEAS_RES:
	case RSL_MT_MODE_MODIFY_ACK:
	case RSL_MT_MODE_MODIFY_NACK:
	case RSL_MT_PHY_CONTEXT_CONF:
	case RSL_MT_PREPROC_MEAS_RES:
	case RSL_MT_RF_CHAN_REL_ACK:
	case RSL_MT_TALKER_DET:
	case RSL_MT_LISTENER_DET:
	case RSL_MT_REMOTE_CODEC_CONF_REP:
	case RSL_MT_MR_CODEC_MOD_ACK:
	case RSL_MT_MR_CODEC_MOD_NACK:
	case RSL_MT_MR_CODEC_MOD_PER:
		fprintf(stderr, "Unimplemented Abis RSL DChan msg 0x%02x\n",
			rslh->msg_type);
		break;
	default:
		fprintf(stderr, "unknown Abis RSL DChan msg 0x%02x\n",
			rslh->msg_type);
		return -EINVAL;
	}
}

static int abis_rsl_rx_trx(struct msgb *msg)
{
	struct abis_rsl_common_hdr *rslh = msgb_l2(msg)	;

	switch (rslh->msg_type) {
	case RSL_MT_RF_RES_IND:
		/* interference on idle channels of TRX */
	case RSL_MT_OVERLOAD:
		/* indicate CCCH / ACCH / processor overload */ 
	case RSL_MT_ERROR_REPORT:
		fprintf(stderr, "Unimplemented Abis RSL TRX message type 0x%02x\n",
			rslh->msg_type);
		break;
	default:
		fprintf(stderr, "Unknown Abis RSL TRX message type 0x%02x\n",
			rslh->msg_type);
		return -EINVAL;
	}

}

static int rsl_rx_chan_rqd(struct msgb *msg)
{
	struct gsm_bts *bts = msg->bts_link->bts;
	struct gsm48_imm_ass ia;
	u_int16_t arfcn;
	u_int8_t ts_number, subch;

	/* MS has requested a channel on the RACH */
	/* parse channel number, request reference, access delay */
	/* FIXME: check permission/availability */
	ts_number = 0;
	arfcn = HARDCODED_ARFCN;
	subch = 0;
	
	/* send CHANNEL ACTIVATION on RSL to BTS */
	rsl_chan_activate_sdcch(&bts->trx[0].ts[ts_number]);

	/* create IMMEDIATE ASSIGN 04.08 messge */
	memset(&ia, 0, sizeof(ia));
	ia.l2_plen = 0x2d;
	ia.proto_discr = GSM48_PDISC_RR;
	ia.msg_type = GSM48_MT_RR_IMM_ASS;
	ia.page_mode = GSM48_PM_NORMAL;
	ia.chan_desc.chan_nr = rsl_enc_chan_nr(RSL_CHAN_SDCCH4_ACCH, subch, ts_number);
	ia.chan_desc.h0.h = 0;
	ia.chan_desc.h0.arfcn_high = arfcn >> 8;
	ia.chan_desc.h0.arfcn_low = arfcn & 0xff;
	ia.chan_desc.h0.tsc = 7;
	/* FIXME: use real request reference extracted from CHAN_RQD */
	ia.req_ref.ra = 0x80 | 0x1e;
	ia.req_ref.t2 = 0x0c;
	ia.req_ref.t1_ = 0x12;
	ia.req_ref.t3_low = 0x19 & 3;
	ia.req_ref.t3_high = 0x19 >> 3;
	ia.timing_advance = 0;
	ia.mob_alloc_len = 0;

	/* send IMMEDIATE ASSIGN CMD on RSL to BTS (to send on CCCH to MS) */
	return rsl_imm_assign_cmd(bts, sizeof(ia), (u_int8_t *) &ia);
}

static int abis_rsl_rx_cchan(struct msgb *msg)
{
	struct abis_rsl_common_hdr *rslh = msgb_l2(msg)	;
	int rc;

	switch (rslh->msg_type) {
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
			rslh->msg_type);
		break;
	default:
		fprintf(stderr, "Unknown Abis RSL TRX message type 0x%02x\n",
			rslh->msg_type);
		return -EINVAL;
	}
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
	
	switch (rllh->c.msg_type) {
	case RSL_MT_DATA_IND:
		DEBUGP(DRLL, "DATA INDICATION\n");
		/* FIXME: parse L3 info element */
		rc = gsm0408_rcvmsg(msg);
		break;
	case RSL_MT_EST_IND:
		DEBUGP(DRLL, "ESTABLISH INDICATION\n");
		/* FIXME: parse L3 info element */
		rc = gsm0408_rcvmsg(msg);
		break;
	case RSL_MT_ERROR_IND:
	case RSL_MT_REL_IND:
	case RSL_MT_UNIT_DATA_IND:
		fprintf(stderr, "unimplemented Abis RLL message type 0x%02x\n",
			rllh->c.msg_type);
		break;
	default:
		fprintf(stderr, "unknown Abis RLL message type 0x%02x\n",
			rllh->c.msg_type);
	}
}

/* Entry-point where L2 RSL from BTS enters */
int abis_rsl_rx(struct msgb *msg)
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
	case ABIS_RSL_MDISC_TRX:
		rc = abis_rsl_rx_cchan(msg);
		break;
	case ABIS_RSL_MDISC_LOC:
	default:
		fprintf(stderr, "unknown RSL message discriminator 0x%02x\n",
			rslh->msg_discr);
		return -EINVAL;
	}
}
