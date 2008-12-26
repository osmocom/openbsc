/* GSM Mobile Radio Interface Layer 3 messages on the A-bis interface 
 * 3GPP TS 04.08 version 7.21.0 Release 1998 / ETSI TS 100 940 V7.21.0 */

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
#include <string.h>
#include <errno.h>

#include <openbsc/msgb.h>
#include <openbsc/debug.h>
#include <openbsc/gsm_data.h>
#include <openbsc/gsm_subscriber.h>
#include <openbsc/gsm_04_08.h>
#include <openbsc/abis_rsl.h>

#define GSM48_ALLOC_SIZE	1024
#define GSM48_ALLOC_HEADROOM	128

struct gsm_lai {
	u_int16_t mcc;
	u_int16_t mnc;
	u_int16_t lac;
};

static void parse_lai(struct gsm_lai *lai, const struct gsm48_loc_area_id *lai48)
{
	u_int8_t dig[4];

	/* MCC */
	dig[1] = lai48->digits[0] & 0x0f;
	dig[2] = lai48->digits[0] >> 4;
	dig[3] = lai48->digits[1] & 0x0f;
	lai->mcc = dig[3] * 100 + dig[2];

	/* MNC */
	dig[1] = lai48->digits[1] >> 4;
	dig[2] = lai48->digits[2] & 0x0f;
	dig[3] = lai48->digits[2] >> 4;
	lai->mnc = dig[3] * 100 + dig[2];

	lai->lac = lai48->lac;
}

static void to_bcd(u_int8_t *bcd, u_int16_t val)
{
	bcd[0] = val % 10;
	val = val / 10;
	bcd[1] = val % 10;
	val = val / 10;
	bcd[2] = val % 10;
	val = val / 10;
}

static void generate_lai(struct gsm48_loc_area_id *lai48, u_int16_t mcc, 
			 u_int16_t mnc, u_int16_t lac)
{
	u_int8_t bcd[3];

	to_bcd(bcd, mcc);
	lai48->digits[0] = bcd[0] | (bcd[1] << 4);
	lai48->digits[1] = bcd[2];

	to_bcd(bcd, mnc);
	lai48->digits[1] |= bcd[2] << 4;
	lai48->digits[2] = bcd[0] | (bcd[1] << 4);
	
	lai48->lac = lac;
}

#define TMSI_LEN	4
#define MID_TMSI_LEN	(TMSI_LEN + 2)

static void generate_mid_from_tmsi(u_int8_t *buf, u_int8_t *tmsi_bcd)
{
	buf[0] = MID_TMSI_LEN;
	buf[1] = 0xf0 | GSM_MI_TYPE_TMSI;
	buf[2] = tmsi_bcd[0];
	buf[3] = tmsi_bcd[1];
	buf[4] = tmsi_bcd[2];
	buf[5] = tmsi_bcd[3];
}

static struct msgb *gsm48_msgb_alloc(void)
{
	return msgb_alloc_headroom(GSM48_ALLOC_SIZE, GSM48_ALLOC_HEADROOM);
}

static int gsm0408_sendmsg(struct msgb *msg)
{
	if (msg->lchan)
		msg->trx = msg->lchan->ts->trx;

	return rsl_data_request(msg, 0);
}

static int gsm0408_rcv_cc(struct msgb *msg)
{
	struct gsm48_hdr *gh = msgb_l3(msg);

	switch (gh->msg_type & 0xbf) {
	case GSM48_MT_CC_CALL_CONF:
		/* Response to SETUP */
		DEBUGP(DCC, "CALL CONFIRM\n");
		break;
	case GSM48_MT_CC_RELEASE_COMPL:
		DEBUGP(DCC, "RELEASE COMPLETE\n");
		break;
	case GSM48_MT_CC_ALERTING:
		DEBUGP(DCC, "ALERTING\n");
		break;
	case GSM48_MT_CC_CONNECT:
		DEBUGP(DCC, "CONNECT\n");
		/* need to respond with CONNECT_ACK */
		break;
	case GSM48_MT_CC_RELEASE:
		DEBUGP(DCC, "RELEASE\n");
		/* need to respond with RELEASE_COMPLETE */
		break;
	case GSM48_MT_CC_EMERG_SETUP:
		//DEBUGP(DCC, "EMERGENCY SETUP\n");
	case GSM48_MT_CC_SETUP:
		//DEBUGP(DCC, "SETUP\n");
		/* FIXME: continue with CALL_PROCEEDING, ALERTING, CONNECT, RELEASE_COMPLETE */
	default:
		fprintf(stderr, "Unimplemented GSM 04.08 msg type 0x%02x\n",
			gh->msg_type);
		break;
	}

	return 0;
}

/* Chapter 9.2.14 : Send LOCATION UPDATE REJECT */
int gsm0408_loc_upd_rej(struct gsm_lchan *lchan, u_int8_t cause)
{
	struct msgb *msg = gsm48_msgb_alloc();
	struct gsm48_hdr *gh;
	
	msg->lchan = lchan;

	gh = (struct gsm48_hdr *) msgb_put(msg, sizeof(*gh) + 1);
	gh->proto_discr = GSM48_PDISC_MM;
	gh->msg_type = GSM48_MT_MM_LOC_UPD_ACCEPT;
	gh->data[0] = cause;

	DEBUGP(DMM, "-> LOCATION UPDATE REJECT\n");

	return gsm0408_sendmsg(msg);
}

/* Chapter 9.2.13 : Send LOCATION UPDATE ACCEPT */
int gsm0408_loc_upd_acc(struct gsm_lchan *lchan, u_int8_t *tmsi)
{
	struct gsm_bts *bts = lchan->ts->trx->bts;
	struct msgb *msg = gsm48_msgb_alloc();
	struct gsm48_hdr *gh;
	struct gsm48_loc_area_id *lai;
	u_int8_t *mid;
	
	msg->lchan = lchan;

	gh = (struct gsm48_hdr *) msgb_put(msg, sizeof(*gh));
	gh->proto_discr = GSM48_PDISC_MM;
	gh->msg_type = GSM48_MT_MM_LOC_UPD_ACCEPT;

	lai = (struct gsm48_loc_area_id *) msgb_put(msg, sizeof(*lai));
	generate_lai(lai, bts->network->country_code,
		     bts->network->network_code, bts->location_area_code);

	mid = msgb_put(msg, MID_TMSI_LEN);
	generate_mid_from_tmsi(mid, tmsi);

	DEBUGP(DMM, "-> LOCATION UPDATE ACCEPT\n");

	return gsm0408_sendmsg(msg);
}

/* Chapter 9.2.15 */
static int mm_loc_upd_req(struct msgb *msg)
{
	struct gsm48_hdr *gh = msgb_l3(msg);
	struct gsm_bts *bts = msg->trx->bts;
	struct gsm48_loc_upd_req *lu;
	struct gsm_subscriber *subscr;
	u_int8_t mi_type;

 	lu = (struct gsm48_loc_upd_req *) gh->data;

	mi_type = lu->mi[0] & GSM_MI_TYPE_MASK;

	switch (mi_type) {
	case GSM_MI_TYPE_IMSI:
		/* look up subscriber based on IMSI */
		subscr = subscr_get_by_imsi(&lu->mi[1]);
		break;	
	case GSM_MI_TYPE_TMSI:
		/* look up the subscriber based on TMSI, request IMSI if it fails */
		subscr = subscr_get_by_tmsi(&lu->mi[1]);
		if (!subscr) {
			/* FIXME: send IDENTITY REQUEST message to get IMSI */
			//gsm0408_identity_request(...GSM_MI_TYPE_IMSI);
		}
		break;
	case GSM_MI_TYPE_IMEI:
	case GSM_MI_TYPE_IMEISV:
		/* no sim card... FIXME: what to do ? */
		fprintf(stderr, "Unimplemented mobile identity type\n");
		break;
	default:	
		fprintf(stderr, "Unknown mobile identity type\n");
		break;
	}

	if (!subscr) {
		/* 0x16 is congestion */
		gsm0408_loc_upd_rej(msg->lchan, 0x16);
		return -EINVAL;
	}

	msg->lchan->subscr = subscr;
	subscr_update(subscr, bts);

	return gsm0408_loc_upd_acc(msg->lchan, subscr->tmsi);
}

static int gsm0408_rcv_mm(struct msgb *msg)
{
	struct gsm48_hdr *gh = msgb_l3(msg);
	int rc;

	switch (gh->msg_type & 0xbf) {
	case GSM48_MT_MM_LOC_UPD_REQUEST:
		DEBUGP(DMM, "LOCATION UPDATE REQUEST\n");
		rc = mm_loc_upd_req(msg);
		break;
	case GSM48_MT_MM_ID_RESP:
	case GSM48_MT_MM_TMSI_REALL_COMPL:
	case GSM48_MT_MM_AUTH_RESP:
	case GSM48_MT_MM_IMSI_DETACH_IND:
	case GSM48_MT_MM_CM_SERV_REQ:
	case GSM48_MT_MM_CM_REEST_REQ:
		fprintf(stderr, "Unimplemented GSM 04.08 MM msg type 0x%02x\n",
			gh->msg_type);
		break;
	default:
		fprintf(stderr, "Unknown GSM 04.08 MM msg type 0x%02x\n",
			gh->msg_type);
		break;
	}

	return rc;
}
static int gsm0408_rcv_rr(struct msgb *msg)
{
	struct gsm48_hdr *gh = msgb_l3(msg);

	switch (gh->msg_type) {
	case GSM48_MT_RR_CLSM_CHG:
		DEBUGP(DRR, "CLASSMARK CHANGE\n");
		/* FIXME: what to do ?!? */
		break;
	case GSM48_MT_RR_PAG_RESP:
	default:
		fprintf(stderr, "Unimplemented GSM 04.08 msg type 0x%02x\n",
			gh->msg_type);
		break;
	}

	return 0;
}

/* here we pass in a msgb from the RSL->RLL.  We expect the l3 pointer to be set */
int gsm0408_rcvmsg(struct msgb *msg)
{
	struct gsm48_hdr *gh = msgb_l3(msg);
	u_int8_t pdisc = gh->proto_discr & 0x0f;
	int rc = 0;
	
	switch (pdisc) {
	case GSM48_PDISC_CC:
		rc = gsm0408_rcv_cc(msg);
		break;
	case GSM48_PDISC_MM:
		rc = gsm0408_rcv_mm(msg);
		break;
	case GSM48_PDISC_RR:
		rc = gsm0408_rcv_rr(msg);
		break;
	case GSM48_PDISC_MM_GPRS:
	case GSM48_PDISC_SM:
		fprintf(stderr, "Unimplemented GSM 04.08 discriminator 0x%02d\n",
			pdisc);
		break;
	default:
		fprintf(stderr, "Unknown GSM 04.08 discriminator 0x%02d\n",
			pdisc);
		break;
	}

	return rc;
}

enum chreq_type {
	CHREQ_T_EMERG_CALL,
	CHREQ_T_CALL_REEST_TCH_F,
	CHREQ_T_CALL_REEST_TCH_H,
	CHREQ_T_CALL_REEST_TCH_H_DBL,
	CHREQ_T_SDCCH,
	CHREQ_T_TCH_F,
	CHREQ_T_VOICE_CALL_TCH_H,
	CHREQ_T_DATA_CALL_TCH_H,
	CHREQ_T_LOCATION_UPD,
	CHREQ_T_PAG_R_ANY,
	CHREQ_T_PAG_R_TCH_F,
	CHREQ_T_PAG_R_TCH_FH,
};

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
	{ 0x80, 0xe0, CHREQ_T_PAG_R_ANY },
	{ 0x20, 0xf0, CHREQ_T_PAG_R_TCH_F },
	{ 0x30, 0xf0, CHREQ_T_PAG_R_TCH_FH },
};

/* If SYSTEM INFORMATION TYPE 4 NECI bit == 0 */
static const struct chreq chreq_type_neci0[] = {
	{ 0xa0, 0xe0, CHREQ_T_EMERG_CALL },
	{ 0xc0, 0xe0, CHREQ_T_CALL_REEST_TCH_H },
	{ 0xe0, 0xe0, CHREQ_T_TCH_F },
	{ 0x50, 0xf0, CHREQ_T_DATA_CALL_TCH_H },
	{ 0x00, 0xe0, CHREQ_T_LOCATION_UPD },
	{ 0x80, 0xe0, CHREQ_T_PAG_R_ANY },
	{ 0x20, 0xf0, CHREQ_T_PAG_R_TCH_F },
	{ 0x30, 0xf0, CHREQ_T_PAG_R_TCH_FH },
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
	[CHREQ_T_PAG_R_ANY]		= GSM_LCHAN_SDCCH,
	[CHREQ_T_PAG_R_TCH_F]		= GSM_LCHAN_TCH_F,
	[CHREQ_T_PAG_R_TCH_FH]		= GSM_LCHAN_TCH_F,
};

enum gsm_chan_t get_ctype_by_chreq(struct gsm_bts *bts, u_int8_t ra)
{
	int i;
	/* FIXME: determine if we set NECI = 0 in the BTS SI4 */

	for (i = 0; i < ARRAY_SIZE(chreq_type_neci0); i++) {
		const struct chreq *chr = &chreq_type_neci0[i];
		if ((ra & chr->mask) == chr->val)
			return ctype_by_chreq[chr->type];
	}
	fprintf(stderr, "Unknown CHANNEL REQUEST RQD 0x%02x\n", ra);
	return GSM_LCHAN_SDCCH;
}
