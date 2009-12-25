/* GSM Mobile Radio Interface Layer 3 messages on the A-bis interface
 * 3GPP TS 04.08 version 7.21.0 Release 1998 / ETSI TS 100 940 V7.21.0
 * utility functions
 */

/* (C) 2008-2009 by Harald Welte <laforge@gnumonks.org>
 * (C) 2008, 2009 by Holger Hans Peter Freyther <zecke@selfish.org>
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
#include <netinet/in.h>

#include <openbsc/msgb.h>
#include <openbsc/debug.h>
#include <openbsc/gsm_04_08.h>
#include <openbsc/transaction.h>
#include <openbsc/paging.h>
#include <openbsc/signal.h>

#define GSM48_ALLOC_SIZE	1024
#define GSM48_ALLOC_HEADROOM	128

/* should ip.access BTS use direct RTP streams between each other (1),
 * or should OpenBSC always act as RTP relay/proxy in between (0) ? */
int ipacc_rtp_direct = 1;


const char *gsm0408_cc_msg_names[] = {
	"unknown 0x00",
	"ALERTING",
	"CALL_PROC",
	"PROGRESS",
	"ESTAB",
	"SETUP",
	"ESTAB_CONF",
	"CONNECT",
	"CALL_CONF",
	"START_CC",
	"unknown 0x0a",
	"RECALL",
	"unknown 0x0c",
	"unknown 0x0d",
	"EMERG_SETUP",
	"CONNECT_ACK",
	"USER_INFO",
	"unknown 0x11",
	"unknown 0x12",
	"MODIFY_REJECT",
	"unknown 0x14",
	"unknown 0x15",
	"unknown 0x16",
	"MODIFY",
	"HOLD",
	"HOLD_ACK",
	"HOLD_REJ",
	"unknown 0x1b",
	"RETR",
	"RETR_ACK",
	"RETR_REJ",
	"MODIFY_COMPL",
	"unknown 0x20",
	"unknown 0x21",
	"unknown 0x22",
	"unknown 0x23",
	"unknown 0x24",
	"DISCONNECT",
	"unknown 0x26",
	"unknown 0x27",
	"unknown 0x28",
	"unknown 0x29",
	"RELEASE_COMPL",
	"unknown 0x2b",
	"unknown 0x2c",
	"RELEASE",
	"unknown 0x2e",
	"unknown 0x2f",
	"unknown 0x30",
	"STOP_DTMF",
	"STOP_DTMF_ACK",
	"unknown 0x33",
	"STATUS_ENQ",
	"START_DTMF",
	"START_DTMF_ACK",
	"START_DTMF_REJ",
	"unknown 0x38",
	"CONG_CTRL",
	"FACILITY",
	"unknown 0x3b",
	"STATUS",
	"unknown 0x3c",
	"NOTIFY",
	"unknown 0x3f",
};


struct msgb *gsm48_msgb_alloc(void)
{
	return msgb_alloc_headroom(GSM48_ALLOC_SIZE, GSM48_ALLOC_HEADROOM,
				   "GSM 04.08");
}

int gsm48_sendmsg(struct msgb *msg, struct gsm_trans *trans)
{
	struct gsm48_hdr *gh = (struct gsm48_hdr *) msg->data;

	/* if we get passed a transaction reference, do some common
	 * work that the caller no longer has to do */
	if (trans) {
		gh->proto_discr = trans->protocol | (trans->transaction_id << 4);
		msg->lchan = trans->lchan;
	}

	if (msg->lchan) {
		msg->trx = msg->lchan->ts->trx;

		if ((gh->proto_discr & GSM48_PDISC_MASK) == GSM48_PDISC_CC)
			DEBUGP(DCC, "(bts %d trx %d ts %d ti %02x) "
				"Sending '%s' to MS.\n", msg->trx->bts->nr,
				msg->trx->nr, msg->lchan->ts->nr,
				gh->proto_discr & 0xf0,
				gsm0408_cc_msg_names[gh->msg_type & 0x3f]);
		else
			DEBUGP(DCC, "(bts %d trx %d ts %d pd %02x) "
				"Sending 0x%02x to MS.\n", msg->trx->bts->nr,
				msg->trx->nr, msg->lchan->ts->nr,
				gh->proto_discr, gh->msg_type);
	}

	msg->l3h = msg->data;

	return rsl_data_request(msg, 0);
}

static void to_bcd(u_int8_t *bcd, u_int16_t val)
{
	bcd[2] = val % 10;
	val = val / 10;
	bcd[1] = val % 10;
	val = val / 10;
	bcd[0] = val % 10;
	val = val / 10;
}

static char bcd2char(u_int8_t bcd)
{
	if (bcd < 0xa)
		return '0' + bcd;
	else
		return 'A' + (bcd - 0xa);
}

/* only works for numbers in ascci */
static u_int8_t char2bcd(char c)
{
	return c - 0x30;
}


void gsm0408_generate_lai(struct gsm48_loc_area_id *lai48, u_int16_t mcc,
			 u_int16_t mnc, u_int16_t lac)
{
	u_int8_t bcd[3];

	to_bcd(bcd, mcc);
	lai48->digits[0] = bcd[0] | (bcd[1] << 4);
	lai48->digits[1] = bcd[2];

	to_bcd(bcd, mnc);
	/* FIXME: do we need three-digit MNC? See Table 10.5.3 */
#if 0
	lai48->digits[1] |= bcd[2] << 4;
	lai48->digits[2] = bcd[0] | (bcd[1] << 4);
#else
	lai48->digits[1] |= 0xf << 4;
	lai48->digits[2] = bcd[1] | (bcd[2] << 4);
#endif

	lai48->lac = htons(lac);
}

int gsm48_generate_mid_from_tmsi(u_int8_t *buf, u_int32_t tmsi)
{
	u_int32_t *tptr = (u_int32_t *) &buf[3];

	buf[0] = GSM48_IE_MOBILE_ID;
	buf[1] = GSM48_TMSI_LEN;
	buf[2] = 0xf0 | GSM_MI_TYPE_TMSI;
	*tptr = htonl(tmsi);

	return 7;
}

int gsm48_generate_mid_from_imsi(u_int8_t *buf, const char *imsi)
{
	unsigned int length = strlen(imsi), i, off = 0;
	u_int8_t odd = (length & 0x1) == 1;

	buf[0] = GSM48_IE_MOBILE_ID;
	buf[2] = char2bcd(imsi[0]) << 4 | GSM_MI_TYPE_IMSI | (odd << 3);

	/* if the length is even we will fill half of the last octet */
	if (odd)
		buf[1] = (length + 1) >> 1;
	else
		buf[1] = (length + 2) >> 1;

	for (i = 1; i < buf[1]; ++i) {
		u_int8_t lower, upper;

		lower = char2bcd(imsi[++off]);
		if (!odd && off + 1 == length)
			upper = 0x0f;
		else
			upper = char2bcd(imsi[++off]) & 0x0f;

		buf[2 + i] = (upper << 4) | lower;
	}

	return 2 + buf[1];
}

/* Section 9.1.8 / Table 9.9 */
struct chreq {
	u_int8_t val;
	u_int8_t mask;
	enum chreq_type type;
};

/* If SYSTEM INFORMATION TYPE 4 NECI bit == 1 */
static const struct chreq chreq_type_neci1[] = {
	{ 0xa0, 0xe0, CHREQ_T_EMERG_CALL },
	{ 0xc0, 0xe0, CHREQ_T_CALL_REEST_TCH_F },
	{ 0x68, 0xfc, CHREQ_T_CALL_REEST_TCH_H },
	{ 0x6c, 0xfc, CHREQ_T_CALL_REEST_TCH_H_DBL },
	{ 0xe0, 0xe0, CHREQ_T_SDCCH },
	{ 0x40, 0xf0, CHREQ_T_VOICE_CALL_TCH_H },
	{ 0x50, 0xf0, CHREQ_T_DATA_CALL_TCH_H },
	{ 0x00, 0xf0, CHREQ_T_LOCATION_UPD },
	{ 0x10, 0xf0, CHREQ_T_SDCCH },
	{ 0x80, 0xe0, CHREQ_T_PAG_R_ANY_NECI1 },
	{ 0x20, 0xf0, CHREQ_T_PAG_R_TCH_F },
	{ 0x30, 0xf0, CHREQ_T_PAG_R_TCH_FH },
	{ 0x67, 0xff, CHREQ_T_LMU },
	{ 0x60, 0xf9, CHREQ_T_RESERVED_SDCCH },
	{ 0x61, 0xfb, CHREQ_T_RESERVED_SDCCH },
	{ 0x63,	0xff, CHREQ_T_RESERVED_SDCCH },
	{ 0x7f, 0xff, CHREQ_T_RESERVED_IGNORE },
};

/* If SYSTEM INFORMATION TYPE 4 NECI bit == 0 */
static const struct chreq chreq_type_neci0[] = {
	{ 0xa0, 0xe0, CHREQ_T_EMERG_CALL },
	{ 0xc0, 0xe0, CHREQ_T_CALL_REEST_TCH_H },
	{ 0xe0, 0xe0, CHREQ_T_TCH_F },
	{ 0x50, 0xf0, CHREQ_T_DATA_CALL_TCH_H },
	{ 0x00, 0xe0, CHREQ_T_LOCATION_UPD },
	{ 0x80, 0xe0, CHREQ_T_PAG_R_ANY_NECI0 },
	{ 0x20, 0xf0, CHREQ_T_PAG_R_TCH_F },
	{ 0x30, 0xf0, CHREQ_T_PAG_R_TCH_FH },
	{ 0x67, 0xff, CHREQ_T_LMU },
	{ 0x60, 0xf9, CHREQ_T_RESERVED_SDCCH },
	{ 0x61, 0xfb, CHREQ_T_RESERVED_SDCCH },
	{ 0x63,	0xff, CHREQ_T_RESERVED_SDCCH },
	{ 0x7f, 0xff, CHREQ_T_RESERVED_IGNORE },
};

static const enum gsm_chan_t ctype_by_chreq[] = {
	[CHREQ_T_EMERG_CALL]		= GSM_LCHAN_TCH_F,
	[CHREQ_T_CALL_REEST_TCH_F]	= GSM_LCHAN_TCH_F,
	[CHREQ_T_CALL_REEST_TCH_H]	= GSM_LCHAN_TCH_H,
	[CHREQ_T_CALL_REEST_TCH_H_DBL]	= GSM_LCHAN_TCH_H,
	[CHREQ_T_SDCCH]			= GSM_LCHAN_SDCCH,
	[CHREQ_T_TCH_F]			= GSM_LCHAN_TCH_F,
	[CHREQ_T_VOICE_CALL_TCH_H]	= GSM_LCHAN_TCH_H,
	[CHREQ_T_DATA_CALL_TCH_H]	= GSM_LCHAN_TCH_H,
	[CHREQ_T_LOCATION_UPD]		= GSM_LCHAN_SDCCH,
	[CHREQ_T_PAG_R_ANY_NECI1]	= GSM_LCHAN_SDCCH,
	[CHREQ_T_PAG_R_ANY_NECI0]	= GSM_LCHAN_SDCCH,
	[CHREQ_T_PAG_R_TCH_F]		= GSM_LCHAN_TCH_F,
	[CHREQ_T_PAG_R_TCH_FH]		= GSM_LCHAN_TCH_F,
	[CHREQ_T_LMU]			= GSM_LCHAN_SDCCH,
	[CHREQ_T_RESERVED_SDCCH]	= GSM_LCHAN_SDCCH,
	[CHREQ_T_RESERVED_IGNORE]	= GSM_LCHAN_UNKNOWN,
};

static const enum gsm_chreq_reason_t reason_by_chreq[] = {
	[CHREQ_T_EMERG_CALL]		= GSM_CHREQ_REASON_EMERG,
	[CHREQ_T_CALL_REEST_TCH_F]	= GSM_CHREQ_REASON_CALL,
	[CHREQ_T_CALL_REEST_TCH_H]	= GSM_CHREQ_REASON_CALL,
	[CHREQ_T_CALL_REEST_TCH_H_DBL]	= GSM_CHREQ_REASON_CALL,
	[CHREQ_T_SDCCH]			= GSM_CHREQ_REASON_OTHER,
	[CHREQ_T_TCH_F]			= GSM_CHREQ_REASON_OTHER,
	[CHREQ_T_VOICE_CALL_TCH_H]	= GSM_CHREQ_REASON_CALL,
	[CHREQ_T_DATA_CALL_TCH_H]	= GSM_CHREQ_REASON_OTHER,
	[CHREQ_T_LOCATION_UPD]		= GSM_CHREQ_REASON_LOCATION_UPD,
	[CHREQ_T_PAG_R_ANY_NECI1]	= GSM_CHREQ_REASON_PAG,
	[CHREQ_T_PAG_R_ANY_NECI0]	= GSM_CHREQ_REASON_PAG,
	[CHREQ_T_PAG_R_TCH_F]		= GSM_CHREQ_REASON_PAG,
	[CHREQ_T_PAG_R_TCH_FH]		= GSM_CHREQ_REASON_PAG,
	[CHREQ_T_LMU]			= GSM_CHREQ_REASON_OTHER,
	[CHREQ_T_RESERVED_SDCCH]	= GSM_CHREQ_REASON_OTHER,
	[CHREQ_T_RESERVED_IGNORE]	= GSM_CHREQ_REASON_OTHER,
};

enum gsm_chan_t get_ctype_by_chreq(struct gsm_bts *bts, u_int8_t ra, int neci)
{
	int i;
	int length;
	const struct chreq *chreq;

	if (neci) {
		chreq = chreq_type_neci1;
		length = ARRAY_SIZE(chreq_type_neci1);
	} else {
		chreq = chreq_type_neci0;
		length = ARRAY_SIZE(chreq_type_neci0);
	}


	for (i = 0; i < length; i++) {
		const struct chreq *chr = &chreq[i];
		if ((ra & chr->mask) == chr->val)
			return ctype_by_chreq[chr->type];
	}
	LOGP(DRR, LOGL_ERROR, "Unknown CHANNEL REQUEST RQD 0x%02x\n", ra);
	return GSM_LCHAN_SDCCH;
}

enum gsm_chreq_reason_t get_reason_by_chreq(struct gsm_bts *bts, u_int8_t ra, int neci)
{
	int i;
	int length;
	const struct chreq *chreq;

	if (neci) {
		chreq = chreq_type_neci1;
		length = ARRAY_SIZE(chreq_type_neci1);
	} else {
		chreq = chreq_type_neci0;
		length = ARRAY_SIZE(chreq_type_neci0);
	}

	for (i = 0; i < length; i++) {
		const struct chreq *chr = &chreq[i];
		if ((ra & chr->mask) == chr->val)
			return reason_by_chreq[chr->type];
	}
	LOGP(DRR, LOGL_ERROR, "Unknown CHANNEL REQUEST REASON 0x%02x\n", ra);
	return GSM_CHREQ_REASON_OTHER;
}

/* 7.1.7 and 9.1.7: RR CHANnel RELease */
int gsm48_send_rr_release(struct gsm_lchan *lchan)
{
	struct msgb *msg = gsm48_msgb_alloc();
	struct gsm48_hdr *gh = (struct gsm48_hdr *) msgb_put(msg, sizeof(*gh));
	u_int8_t *cause;

	msg->lchan = lchan;
	gh->proto_discr = GSM48_PDISC_RR;
	gh->msg_type = GSM48_MT_RR_CHAN_REL;

	cause = msgb_put(msg, 1);
	cause[0] = GSM48_RR_CAUSE_NORMAL;

	DEBUGP(DRR, "Sending Channel Release: Chan: Number: %d Type: %d\n",
		lchan->nr, lchan->type);

	/* Send actual release request to MS */
	gsm48_sendmsg(msg, NULL);
	/* FIXME: Start Timer T3109 */

	/* Deactivate the SACCH on the BTS side */
	return rsl_deact_sacch(lchan);
}

/* Convert Mobile Identity (10.5.1.4) to string */
int gsm48_mi_to_string(char *string, const int str_len, const u_int8_t *mi, const int mi_len)
{
	int i;
	u_int8_t mi_type;
	char *str_cur = string;
	u_int32_t tmsi;

	mi_type = mi[0] & GSM_MI_TYPE_MASK;

	switch (mi_type) {
	case GSM_MI_TYPE_NONE:
		break;
	case GSM_MI_TYPE_TMSI:
		/* Table 10.5.4.3, reverse generate_mid_from_tmsi */
		if (mi_len == GSM48_TMSI_LEN && mi[0] == (0xf0 | GSM_MI_TYPE_TMSI)) {
			memcpy(&tmsi, &mi[1], 4);
			tmsi = ntohl(tmsi);
			return snprintf(string, str_len, "%u", tmsi);
		}
		break;
	case GSM_MI_TYPE_IMSI:
	case GSM_MI_TYPE_IMEI:
	case GSM_MI_TYPE_IMEISV:
		*str_cur++ = bcd2char(mi[0] >> 4);

                for (i = 1; i < mi_len; i++) {
			if (str_cur + 2 >= string + str_len)
				return str_cur - string;
			*str_cur++ = bcd2char(mi[i] & 0xf);
			/* skip last nibble in last input byte when GSM_EVEN */
			if( (i != mi_len-1) || (mi[0] & GSM_MI_ODD))
				*str_cur++ = bcd2char(mi[i] >> 4);
		}
		break;
	default:
		break;
	}
	*str_cur++ = '\0';

	return str_cur - string;
}


int send_siemens_mrpci(struct gsm_lchan *lchan,
		       u_int8_t *classmark2_lv)
{
	struct rsl_mrpci mrpci;

	if (classmark2_lv[0] < 2)
		return -EINVAL;

	mrpci.power_class = classmark2_lv[1] & 0x7;
	mrpci.vgcs_capable = classmark2_lv[2] & (1 << 1);
	mrpci.vbs_capable = classmark2_lv[2] & (1 <<2);
	mrpci.gsm_phase = (classmark2_lv[1]) >> 5 & 0x3;

	return rsl_siemens_mrpci(lchan, &mrpci);
}

int gsm48_paging_extract_mi(struct msgb *msg, char *mi_string, u_int8_t *mi_type)
{
	struct gsm48_hdr *gh = msgb_l3(msg);
	u_int8_t *classmark2_lv = gh->data + 1;
	u_int8_t *mi_lv = gh->data + 2 + *classmark2_lv;
	*mi_type = mi_lv[1] & GSM_MI_TYPE_MASK;

	return gsm48_mi_to_string(mi_string, GSM48_MI_SIZE, mi_lv+1, *mi_lv);
}

int gsm48_handle_paging_resp(struct msgb *msg, struct gsm_subscriber *subscr)
{
	struct gsm_bts *bts = msg->lchan->ts->trx->bts;
	struct gsm48_hdr *gh = msgb_l3(msg);
	u_int8_t *classmark2_lv = gh->data + 1;
	struct paging_signal_data sig_data;

	if (is_siemens_bts(bts))
		send_siemens_mrpci(msg->lchan, classmark2_lv);

	if (!msg->lchan->subscr) {
		msg->lchan->subscr = subscr;
	} else if (msg->lchan->subscr != subscr) {
		LOGP(DRR, LOGL_ERROR, "<- Channel already owned by someone else?\n");
		subscr_put(subscr);
		return -EINVAL;
	} else {
		DEBUGP(DRR, "<- Channel already owned by us\n");
		subscr_put(subscr);
		subscr = msg->lchan->subscr;
	}

	sig_data.subscr = subscr;
	sig_data.bts	= msg->lchan->ts->trx->bts;
	sig_data.lchan	= msg->lchan;

	bts->network->stats.paging.completed++;

	dispatch_signal(SS_PAGING, S_PAGING_COMPLETED, &sig_data);

	/* Stop paging on the bts we received the paging response */
	paging_request_stop(msg->trx->bts, subscr, msg->lchan);
	return 0;
}

/* Chapter 9.1.9: Ciphering Mode Command */
int gsm48_send_rr_ciph_mode(struct gsm_lchan *lchan, int want_imeisv)
{
	struct msgb *msg = gsm48_msgb_alloc();
	struct gsm48_hdr *gh;
	u_int8_t ciph_mod_set;

	msg->lchan = lchan;

	DEBUGP(DRR, "TX CIPHERING MODE CMD\n");

	if (lchan->encr.alg_id <= RSL_ENC_ALG_A5(0))
		ciph_mod_set = 0;
	else
		ciph_mod_set = (lchan->encr.alg_id-2)<<1 | 1;

	gh = (struct gsm48_hdr *) msgb_put(msg, sizeof(*gh) + 1);
	gh->proto_discr = GSM48_PDISC_RR;
	gh->msg_type = GSM48_MT_RR_CIPH_M_CMD;
	gh->data[0] = (want_imeisv & 0x1) << 4 | (ciph_mod_set & 0xf);

	return rsl_encryption_cmd(msg);
}

static void gsm48_cell_desc(struct gsm48_cell_desc *cd,
			    const struct gsm_bts *bts)
{
	cd->ncc = (bts->bsic >> 3 & 0x7);
	cd->bcc = (bts->bsic & 0x7);
	cd->arfcn_hi = bts->c0->arfcn >> 8;
	cd->arfcn_lo = bts->c0->arfcn & 0xff;
}

static void gsm48_chan_desc(struct gsm48_chan_desc *cd,
			    const struct gsm_lchan *lchan)
{
	u_int16_t arfcn = lchan->ts->trx->arfcn & 0x3ff;

	cd->chan_nr = lchan2chan_nr(lchan);
	cd->h0.tsc = lchan->ts->trx->bts->tsc;
	cd->h0.h = 0;
	cd->h0.arfcn_high = arfcn >> 8;
	cd->h0.arfcn_low = arfcn & 0xff;
}

/* Chapter 9.1.15: Handover Command */
int gsm48_send_ho_cmd(struct gsm_lchan *old_lchan, struct gsm_lchan *new_lchan,
		      u_int8_t power_command, u_int8_t ho_ref)
{
	struct msgb *msg = gsm48_msgb_alloc();
	struct gsm48_hdr *gh = (struct gsm48_hdr *) msgb_put(msg, sizeof(*gh));
	struct gsm48_ho_cmd *ho =
		(struct gsm48_ho_cmd *) msgb_put(msg, sizeof(*ho));

	msg->lchan = old_lchan;
	gh->proto_discr = GSM48_PDISC_RR;
	gh->msg_type = GSM48_MT_RR_HANDO_CMD;

	/* mandatory bits */
	gsm48_cell_desc(&ho->cell_desc, new_lchan->ts->trx->bts);
	gsm48_chan_desc(&ho->chan_desc, new_lchan);
	ho->ho_ref = ho_ref;
	ho->power_command = power_command;

	/* FIXME: optional bits for type of synchronization? */

	return gsm48_sendmsg(msg, NULL);
}

/* Chapter 9.1.2: Assignment Command */
int gsm48_send_rr_ass_cmd(struct gsm_lchan *lchan, u_int8_t power_command)
{
	struct msgb *msg = gsm48_msgb_alloc();
	struct gsm48_hdr *gh = (struct gsm48_hdr *) msgb_put(msg, sizeof(*gh));
	struct gsm48_ass_cmd *ass =
		(struct gsm48_ass_cmd *) msgb_put(msg, sizeof(*ass));

	DEBUGP(DRR, "-> ASSIGNMENT COMMAND tch_mode=0x%02x\n", lchan->tch_mode);

	msg->lchan = lchan;
	gh->proto_discr = GSM48_PDISC_RR;
	gh->msg_type = GSM48_MT_RR_ASS_CMD;

	/*
	 * fill the channel information element, this code
	 * should probably be shared with rsl_rx_chan_rqd(),
	 * gsm48_tx_chan_mode_modify. But beware that 10.5.2.5
	 * 10.5.2.5.a have slightly different semantic for
	 * the chan_desc. But as long as multi-slot configurations
	 * are not used we seem to be fine.
	 */
	gsm48_chan_desc(&ass->chan_desc, lchan);
	ass->power_command = power_command;

	/* in case of multi rate we need to attach a config */
	if (lchan->tch_mode == GSM48_CMODE_SPEECH_AMR) {
		if (lchan->mr_conf.ver == 0) {
			LOGP(DRR, LOGL_ERROR, "BUG: Using multirate codec "
				"without multirate config.\n");
		} else {
			u_int8_t *data = msgb_put(msg, 4);
			data[0] = GSM48_IE_MUL_RATE_CFG;
			data[1] = 0x2;
			memcpy(&data[2], &lchan->mr_conf, 2);
		}
	}

	return gsm48_sendmsg(msg, NULL);
}

/* 9.1.5 Channel mode modify: Modify the mode on the MS side */
int gsm48_tx_chan_mode_modify(struct gsm_lchan *lchan, u_int8_t mode)
{
	struct msgb *msg = gsm48_msgb_alloc();
	struct gsm48_hdr *gh = (struct gsm48_hdr *) msgb_put(msg, sizeof(*gh));
	struct gsm48_chan_mode_modify *cmm =
		(struct gsm48_chan_mode_modify *) msgb_put(msg, sizeof(*cmm));
	u_int16_t arfcn = lchan->ts->trx->arfcn & 0x3ff;

	DEBUGP(DRR, "-> CHANNEL MODE MODIFY mode=0x%02x\n", mode);

	lchan->tch_mode = mode;
	msg->lchan = lchan;
	gh->proto_discr = GSM48_PDISC_RR;
	gh->msg_type = GSM48_MT_RR_CHAN_MODE_MODIF;

	/* fill the channel information element, this code
	 * should probably be shared with rsl_rx_chan_rqd() */
	cmm->chan_desc.chan_nr = lchan2chan_nr(lchan);
	cmm->chan_desc.h0.tsc = lchan->ts->trx->bts->tsc;
	cmm->chan_desc.h0.h = 0;
	cmm->chan_desc.h0.arfcn_high = arfcn >> 8;
	cmm->chan_desc.h0.arfcn_low = arfcn & 0xff;
	cmm->mode = mode;

	/* in case of multi rate we need to attach a config */
	if (lchan->tch_mode == GSM48_CMODE_SPEECH_AMR) {
		if (lchan->mr_conf.ver == 0) {
			LOGP(DRR, LOGL_ERROR, "BUG: Using multirate codec "
				"without multirate config.\n");
		} else {
			u_int8_t *data = msgb_put(msg, 4);
			data[0] = GSM48_IE_MUL_RATE_CFG;
			data[1] = 0x2;
			memcpy(&data[2], &lchan->mr_conf, 2);
		}
	}

	return gsm48_sendmsg(msg, NULL);
}

int gsm48_lchan_modify(struct gsm_lchan *lchan, u_int8_t lchan_mode)
{
	int rc;

	rc = gsm48_tx_chan_mode_modify(lchan, lchan_mode);
	if (rc < 0)
		return rc;

	return rc;
}

int gsm48_rx_rr_modif_ack(struct msgb *msg)
{
	int rc;
	struct gsm48_hdr *gh = msgb_l3(msg);
	struct gsm48_chan_mode_modify *mod =
				(struct gsm48_chan_mode_modify *) gh->data;

	DEBUGP(DRR, "CHANNEL MODE MODIFY ACK\n");

	if (mod->mode != msg->lchan->tch_mode) {
		LOGP(DRR, LOGL_ERROR, "CHANNEL MODE change failed. Wanted: %d Got: %d\n",
			msg->lchan->tch_mode, mod->mode);
		return -1;
	}

	/* update the channel type */
	switch (mod->mode) {
	case GSM48_CMODE_SIGN:
		msg->lchan->rsl_cmode = RSL_CMOD_SPD_SIGN;
		break;
	case GSM48_CMODE_SPEECH_V1:
	case GSM48_CMODE_SPEECH_EFR:
	case GSM48_CMODE_SPEECH_AMR:
		msg->lchan->rsl_cmode = RSL_CMOD_SPD_SPEECH;
		break;
	case GSM48_CMODE_DATA_14k5:
	case GSM48_CMODE_DATA_12k0:
	case GSM48_CMODE_DATA_6k0:
	case GSM48_CMODE_DATA_3k6:
		msg->lchan->rsl_cmode = RSL_CMOD_SPD_DATA;
		break;
	}

	/* We've successfully modified the MS side of the channel,
	 * now go on to modify the BTS side of the channel */
	rc = rsl_chan_mode_modify_req(msg->lchan);

	/* FIXME: we not only need to do this after mode modify, but
	 * also after channel activation */
	if (is_ipaccess_bts(msg->lchan->ts->trx->bts) && mod->mode != GSM48_CMODE_SIGN)
		rsl_ipacc_crcx(msg->lchan);
	return rc;
}

int gsm48_parse_meas_rep(struct gsm_meas_rep *rep, struct msgb *msg)
{
	struct gsm48_hdr *gh = msgb_l3(msg);
	unsigned int payload_len = msgb_l3len(msg) - sizeof(*gh);
	u_int8_t *data = gh->data;
	struct gsm_bts *bts = msg->lchan->ts->trx->bts;
	struct bitvec *nbv = &bts->si_common.neigh_list;
	struct gsm_meas_rep_cell *mrc;

	if (gh->msg_type != GSM48_MT_RR_MEAS_REP)
		return -EINVAL;

	if (data[0] & 0x80)
		rep->flags |= MEAS_REP_F_BA1;
	if (data[0] & 0x40)
		rep->flags |= MEAS_REP_F_UL_DTX;
	if ((data[1] & 0x40) == 0x00)
		rep->flags |= MEAS_REP_F_DL_VALID;

	rep->dl.full.rx_lev = data[0] & 0x3f;
	rep->dl.sub.rx_lev = data[1] & 0x3f;
	rep->dl.full.rx_qual = (data[3] >> 4) & 0x7;
	rep->dl.sub.rx_qual = (data[3] >> 1) & 0x7;

	rep->num_cell = ((data[3] >> 6) & 0x3) | ((data[2] & 0x01) << 2);
	if (rep->num_cell < 1 || rep->num_cell > 6)
		return 0;

	/* an encoding nightmare in perfection */
	mrc = &rep->cell[0];
	mrc->rxlev = data[3] & 0x3f;
	mrc->neigh_idx = data[4] >> 3;
	mrc->arfcn = bitvec_get_nth_set_bit(nbv, mrc->neigh_idx + 1);
	mrc->bsic = ((data[4] & 0x07) << 3) | (data[5] >> 5);
	if (rep->num_cell < 2)
		return 0;

	mrc = &rep->cell[1];
	mrc->rxlev = ((data[5] & 0x1f) << 1) | (data[6] >> 7);
	mrc->neigh_idx = (data[6] >> 2) & 0x1f;
	mrc->arfcn = bitvec_get_nth_set_bit(nbv, mrc->neigh_idx + 1);
	mrc->bsic = ((data[6] & 0x03) << 4) | (data[7] >> 4);
	if (rep->num_cell < 3)
		return 0;

	mrc = &rep->cell[2];
	mrc->rxlev = ((data[7] & 0x0f) << 2) | (data[8] >> 6);
	mrc->neigh_idx = (data[8] >> 1) & 0x1f;
	mrc->arfcn = bitvec_get_nth_set_bit(nbv, mrc->neigh_idx + 1);
	mrc->bsic = ((data[8] & 0x01) << 6) | (data[9] >> 3);
	if (rep->num_cell < 4)
		return 0;

	mrc = &rep->cell[3];
	mrc->rxlev = ((data[9] & 0x07) << 3) | (data[10] >> 5);
	mrc->neigh_idx = data[10] & 0x1f;
	mrc->arfcn = bitvec_get_nth_set_bit(nbv, mrc->neigh_idx + 1);
	mrc->bsic = data[11] >> 2;
	if (rep->num_cell < 5)
		return 0;

	mrc = &rep->cell[4];
	mrc->rxlev = ((data[11] & 0x03) << 4) | (data[12] >> 4);
	mrc->neigh_idx = ((data[12] & 0xf) << 1) | (data[13] >> 7);
	mrc->arfcn = bitvec_get_nth_set_bit(nbv, mrc->neigh_idx + 1);
	mrc->bsic = (data[13] >> 1) & 0x3f;
	if (rep->num_cell < 6)
		return 0;

	mrc = &rep->cell[5];
	mrc->rxlev = ((data[13] & 0x01) << 5) | (data[14] >> 3);
	mrc->neigh_idx = ((data[14] & 0x07) << 2) | (data[15] >> 6);
	mrc->arfcn = bitvec_get_nth_set_bit(nbv, mrc->neigh_idx + 1);
	mrc->bsic = data[15] & 0x3f;

	return 0;
}

