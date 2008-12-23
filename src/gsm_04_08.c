/* GSM Mobile Radio Interface Layer 3 messages on the A-bis interface 
 * 3GPP TS 04.08 version 7.21.0 Release 1998 / ETSI TS 100 940 V7.21.0 */

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
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include "msgb.h"
#include "debug.h"
#include "gsm_data.h"
#include "gsm_subscriber.h"
#include "gsm_04_08.h"

#define GSM0408_ALLOC_SIZE	1024

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
	lai48->digits[2] |= bcd[2] << 4;
	lai48->digits[3] = bcd[0] | (bcd[1] << 4);
	
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

static int gsm0408_sendmsg(struct msgb *msg)
{
	/* FIXME: set data pointer to beginning of L3 data object */

	return rsl_data_request(msg);
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
}

/* Chapter 9.2.14 : Send LOCATION UPDATE REJECT */
int gsm0408_loc_upd_rej(struct gsm_bts_link *bts_link, u_int8_t cause)
{
	struct msgb *msg = msgb_alloc(GSM0408_ALLOC_SIZE);
	struct gsm48_hdr *gh;
	
	msg->bts_link = bts_link;

	gh = (struct gsm48_hdr *) msgb_put(msg, sizeof(*gh) + 1);
	gh->proto_discr = GSM48_PDISC_MM;
	gh->msg_type = GSM48_MT_MM_LOC_UPD_ACCEPT;
	gh->data[0] = cause;

	DEBUGP(DMM, "-> LOCATION UPDATE REJECT\n");

	return gsm0408_sendmsg(msg);
}

/* Chapter 9.2.13 : Send LOCATION UPDATE ACCEPT */
int gsm0408_loc_upd_acc(struct gsm_bts_link *bts_link, u_int8_t *tmsi)
{
	struct gsm_bts *bts = bts_link->bts;
	struct msgb *msg = msgb_alloc(GSM0408_ALLOC_SIZE);
	struct gsm48_hdr *gh;
	struct gsm48_loc_area_id *lai;
	u_int8_t *mid;
	
	msg->bts_link = bts_link;

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
	struct gsm_bts *bts = msg->bts_link->bts;
	struct gsm48_loc_upd_req *lu;
	struct gsm_subscriber *subscr;

	u_int8_t mi_type = lu->mi[0] & GSM_MI_TYPE_MASK;

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
		gsm0408_loc_upd_rej(msg->bts_link, 0x16);
		return -EINVAL;
	}

	subscr_update(subscr, bts);
	return gsm0408_loc_upd_acc(msg->bts_link, subscr->tmsi);
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
	int rc;
	
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
