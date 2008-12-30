/* GSM Mobile Radio Interface Layer 3 messages on the A-bis interface 
 * 3GPP TS 04.08 version 7.21.0 Release 1998 / ETSI TS 100 940 V7.21.0 */

/* (C) 2008 by Harald Welte <laforge@gnumonks.org>
 * (C) 2008 by Holger Hans Peter Freyther <zecke@selfish.org>
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
#include <netinet/in.h>

#include <openbsc/db.h>
#include <openbsc/msgb.h>
#include <openbsc/debug.h>
#include <openbsc/gsm_data.h>
#include <openbsc/gsm_subscriber.h>
#include <openbsc/gsm_04_11.h>
#include <openbsc/gsm_04_08.h>
#include <openbsc/abis_rsl.h>

#define GSM48_ALLOC_SIZE	1024
#define GSM48_ALLOC_HEADROOM	128

static int gsm48_tx_simple(struct gsm_lchan *lchan,
			   u_int8_t pdisc, u_int8_t msg_type);
static void schedule_reject(struct gsm_lchan *lchan);

struct gsm_lai {
	u_int16_t mcc;
	u_int16_t mnc;
	u_int16_t lac;
};

static int authorize_everonye = 0;
void gsm0408_allow_everyone(int everyone)
{
	printf("Allowing everyone?\n");
	authorize_everonye = everyone;
}

static int authorize_subscriber(struct gsm_subscriber *subscriber)
{
	if (!subscriber)
		return 0;

	if (authorize_everonye)
		return 1;

	return subscriber->authorized;
}


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
	bcd[2] = val % 10;
	val = val / 10;
	bcd[1] = val % 10;
	val = val / 10;
	bcd[0] = val % 10;
	val = val / 10;
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

#define TMSI_LEN	5
#define MID_TMSI_LEN	(TMSI_LEN + 2)

int generate_mid_from_tmsi(u_int8_t *buf, u_int32_t tmsi)
{
	u_int32_t *tptr = (u_int32_t *) &buf[3];

	buf[0] = GSM48_IE_MOBILE_ID;
	buf[1] = TMSI_LEN;
	buf[2] = 0xf0 | GSM_MI_TYPE_TMSI;
	*tptr = htonl(tmsi);

	return 7;
}

static struct msgb *gsm48_msgb_alloc(void)
{
	return msgb_alloc_headroom(GSM48_ALLOC_SIZE, GSM48_ALLOC_HEADROOM);
}

static int gsm48_sendmsg(struct msgb *msg)
{
	struct gsm48_hdr *gh = (struct gsm48_hdr *) msg->data;

	if (msg->lchan) {
		msg->trx = msg->lchan->ts->trx;

		if ((gh->proto_discr & GSM48_PDISC_MASK) == GSM48_PDISC_CC) {
			/* Send a 04.08 call control message, add transaction
			 * ID and TI flag */
			gh->proto_discr |= msg->lchan->call.transaction_id;

			/* GSM 04.07 Section 11.2.3.1.3 */
			switch (msg->lchan->call.type) {
			case GSM_CT_MO:
				gh->proto_discr |= 0x80;
				break;
			case GSM_CT_MT:
				break;
			}
		}
	}

	msg->l3h = msg->data;

	return rsl_data_request(msg, 0);
}


/* Chapter 9.2.14 : Send LOCATION UPDATING REJECT */
int gsm0408_loc_upd_rej(struct gsm_lchan *lchan, u_int8_t cause)
{
	struct msgb *msg = gsm48_msgb_alloc();
	struct gsm48_hdr *gh;
	
	msg->lchan = lchan;

	gh = (struct gsm48_hdr *) msgb_put(msg, sizeof(*gh) + 1);
	gh->proto_discr = GSM48_PDISC_MM;
	gh->msg_type = GSM48_MT_MM_LOC_UPD_REJECT;
	gh->data[0] = cause;

	DEBUGP(DMM, "-> LOCATION UPDATING REJECT\n");

	return gsm48_sendmsg(msg);
}

/* Chapter 9.2.13 : Send LOCATION UPDATE ACCEPT */
int gsm0408_loc_upd_acc(struct gsm_lchan *lchan, u_int32_t tmsi)
{
	struct gsm_bts *bts = lchan->ts->trx->bts;
	struct msgb *msg = gsm48_msgb_alloc();
	struct gsm48_hdr *gh;
	struct gsm48_loc_area_id *lai;
	u_int8_t *mid;
	int ret;
	
	msg->lchan = lchan;

	gh = (struct gsm48_hdr *) msgb_put(msg, sizeof(*gh));
	gh->proto_discr = GSM48_PDISC_MM;
	gh->msg_type = GSM48_MT_MM_LOC_UPD_ACCEPT;

	lai = (struct gsm48_loc_area_id *) msgb_put(msg, sizeof(*lai));
	gsm0408_generate_lai(lai, bts->network->country_code,
		     bts->network->network_code, bts->location_area_code);

	mid = msgb_put(msg, MID_TMSI_LEN);
	generate_mid_from_tmsi(mid, tmsi);

	lchan->pending_update_request = 0;
	DEBUGP(DMM, "-> LOCATION UPDATE ACCEPT\n");

	ret = gsm48_sendmsg(msg);

	/* inform the upper layer on the progress */
	if (bts->network->update_request)
		(*bts->network->update_request)(bts, tmsi, 1);

	return ret;
}

static char bcd2char(u_int8_t bcd)
{
	if (bcd < 0xa)
		return '0' + bcd;
	else
		return 'A' + (bcd - 0xa);
}

/* 10.5.1.4 */
static int mi_to_string(char *string, int str_len, u_int8_t *mi, int mi_len)
{
	int i;
	u_int8_t mi_type;
	char *str_cur = string;

	mi_type = mi[0] & GSM_MI_TYPE_MASK;

	switch (mi_type) {
	case GSM_MI_TYPE_NONE:
		break;
	case GSM_MI_TYPE_TMSI:
		for (i = 1; i < mi_len - 1; i++) {
			if (str_cur + 2 >= string + str_len)
				return str_cur - string;
			*str_cur++ = bcd2char(mi[i] >> 4);
			*str_cur++ = bcd2char(mi[i] & 0xf);
		}
		break;
	case GSM_MI_TYPE_IMSI:
	case GSM_MI_TYPE_IMEI:
	case GSM_MI_TYPE_IMEISV:
		if (mi[0] & GSM_MI_ODD)
			*str_cur++ = bcd2char(mi[0] >> 4);
	
		for (i = 1; i < mi_len - 1; i++) {
			if (str_cur + 2 >= string + str_len)
				return str_cur - string;
			*str_cur++ = bcd2char(mi[i] & 0xf);
			*str_cur++ = bcd2char(mi[i] >> 4);
		}
		break;
	default:
		break;
	}

	*str_cur++ = '\0';
	return str_cur - string;
}

/* Chapter 9.2.10 */
static int mm_tx_identity_req(struct gsm_lchan *lchan, u_int8_t id_type)
{
	struct msgb *msg = gsm48_msgb_alloc();
	struct gsm48_hdr *gh;

	msg->lchan = lchan;

	gh = (struct gsm48_hdr *) msgb_put(msg, sizeof(*gh) + 1);
	gh->proto_discr = GSM48_PDISC_MM;
	gh->msg_type = GSM48_MT_MM_ID_REQ;
	gh->data[0] = id_type;

	return gsm48_sendmsg(msg);
}

#define MI_SIZE 32

/* Chapter 9.2.11 */
static int mm_rx_id_resp(struct msgb *msg)
{
	struct gsm48_hdr *gh = msgb_l3(msg);
	struct gsm_lchan *lchan = msg->lchan;
	u_int8_t mi_type = gh->data[1] & GSM_MI_TYPE_MASK;
	char mi_string[MI_SIZE];
	u_int32_t tmsi;

	mi_to_string(mi_string, sizeof(mi_string), &gh->data[1], gh->data[0]);
	DEBUGP(DMM, "IDENTITY RESPONSE: mi_type=0x%02x MI(%s)\n",
		mi_type, mi_string);

	switch (mi_type) {
	case GSM_MI_TYPE_IMSI:
		if (!lchan->subscr)
			lchan->subscr = db_create_subscriber(mi_string);

		/* We have a pending UPDATING REQUEST handle it now */
		if (lchan->pending_update_request) {
			if (authorize_subscriber(lchan->subscr)) {
				db_subscriber_alloc_tmsi(lchan->subscr);
				tmsi = strtoul(lchan->subscr->tmsi, NULL, 10);
				return gsm0408_loc_upd_acc(msg->lchan, tmsi);
			} else {
				schedule_reject(lchan);
			}
		}
		break;
	case GSM_MI_TYPE_IMEI:
	case GSM_MI_TYPE_IMEISV:
		/* update subscribe <-> IMEI mapping */
		if (lchan->subscr)
			db_subscriber_assoc_imei(lchan->subscr, mi_string);
		break;
	}
	return 0;
}


static void loc_upd_rej_cb(void *data)
{
	struct gsm_lchan *lchan = data;

	gsm0408_loc_upd_rej(lchan, 0x16);
	rsl_chan_release(lchan);
}

static void schedule_reject(struct gsm_lchan *lchan)
{
    lchan->timer.cb = loc_upd_rej_cb;
    lchan->timer.data = lchan;
    lchan->pending_update_request = 0;
    schedule_timer(&lchan->timer, 1, 0);
}

#define MI_SIZE 32
/* Chapter 9.2.15 */
static int mm_rx_loc_upd_req(struct msgb *msg)
{
	struct gsm48_hdr *gh = msgb_l3(msg);
	struct gsm_bts *bts = msg->trx->bts;
	struct gsm48_loc_upd_req *lu;
	struct gsm_subscriber *subscr;
	struct gsm_lchan *lchan = msg->lchan;
	u_int8_t mi_type;
	u_int32_t tmsi;
	char mi_string[MI_SIZE];
	int rc;

 	lu = (struct gsm48_loc_upd_req *) gh->data;

	mi_type = lu->mi[0] & GSM_MI_TYPE_MASK;

	mi_to_string(mi_string, sizeof(mi_string), lu->mi, lu->mi_len);

	DEBUGP(DMM, "LUPDREQ: mi_type=0x%02x MI(%s)\n", mi_type, mi_string);
	switch (mi_type) {
	case GSM_MI_TYPE_IMSI:
		/* we always want the IMEI, too */
		rc = mm_tx_identity_req(lchan, GSM_MI_TYPE_IMEISV);
		/* look up subscriber based on IMSI */
		subscr = db_create_subscriber(mi_string);
		break;
	case GSM_MI_TYPE_TMSI:
		/* we always want the IMEI, too */
		rc = mm_tx_identity_req(lchan, GSM_MI_TYPE_IMEISV);
		/* look up the subscriber based on TMSI, request IMSI if it fails */
		subscr = subscr_get_by_tmsi(lu->mi);
		if (!subscr) {
			/* send IDENTITY REQUEST message to get IMSI */
			rc = mm_tx_identity_req(lchan, GSM_MI_TYPE_IMSI);
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

	lchan->subscr = subscr;

	/* we know who we deal with and don't want him */
	if (subscr && !authorize_subscriber(subscr)) {
		schedule_reject(lchan);
		return 0;
	} else if (!subscr) {
		/* we have asked for the imsi and should get a
		 * IDENTITY RESPONSE */
		lchan->pending_update_request = 1;
		return 0;
	}

	db_subscriber_alloc_tmsi(subscr);
	subscr_update(subscr, bts);

	tmsi = strtoul(subscr->tmsi, NULL, 10);

	return gsm0408_loc_upd_acc(lchan, tmsi);
}

static int gsm48_tx_mm_serv_ack(struct gsm_lchan *lchan)
{
	DEBUGP(DMM, "-> CM SERVICE ACK\n");
	return gsm48_tx_simple(lchan, GSM48_PDISC_MM, GSM48_MT_MM_CM_SERV_ACC);
}
		
static int gsm48_rx_mm_serv_req(struct msgb *msg)
{
	struct gsm48_hdr *gh = msgb_l3(msg);
	u_int8_t serv_type = gh->data[0] & 0x0f;

	DEBUGP(DMM, "<- CM SERVICE REQUEST serv_type=0x%02x\n", serv_type);

	return gsm48_tx_mm_serv_ack(msg->lchan);
}

static int gsm0408_rcv_mm(struct msgb *msg)
{
	struct gsm48_hdr *gh = msgb_l3(msg);
	int rc;

	switch (gh->msg_type & 0xbf) {
	case GSM48_MT_MM_LOC_UPD_REQUEST:
		DEBUGP(DMM, "LOCATION UPDATING REQUEST\n");
		rc = mm_rx_loc_upd_req(msg);
		break;
	case GSM48_MT_MM_ID_RESP:
		rc = mm_rx_id_resp(msg);
		break;
	case GSM48_MT_MM_CM_SERV_REQ:
		rc = gsm48_rx_mm_serv_req(msg);
		break;
	case GSM48_MT_MM_STATUS:
		DEBUGP(DMM, "MM STATUS: FIXME parse error cond.\n");
		break;
	case GSM48_MT_MM_CM_REEST_REQ:
	case GSM48_MT_MM_TMSI_REALL_COMPL:
	case GSM48_MT_MM_AUTH_RESP:
	case GSM48_MT_MM_IMSI_DETACH_IND:
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
	case GSM48_MT_RR_GPRS_SUSP_REQ:
		DEBUGP(DRR, "GRPS SUSPEND REQUEST\n");
		break;
	case GSM48_MT_RR_PAG_RESP:
	default:
		fprintf(stderr, "Unimplemented GSM 04.08 msg type 0x%02x\n",
			gh->msg_type);
		break;
	}

	return 0;
}

/* Call Control */

static int gsm48_cc_tx_status(struct gsm_lchan *lchan)
{
	struct msgb *msg = gsm48_msgb_alloc();
	struct gsm48_hdr *gh = (struct gsm48_hdr *) msgb_put(msg, sizeof(*gh));
	u_int8_t *cause, *call_state;

	gh->proto_discr = GSM48_PDISC_CC;

	msg->lchan = lchan;

	gh->msg_type = GSM48_MT_CC_STATUS;

	cause = msgb_put(msg, 3);
	cause[0] = 2;
	cause[1] = GSM48_CAUSE_CS_GSM | GSM48_CAUSE_LOC_USER;
	cause[2] = 0x80 | 30;	/* response to status inquiry */

	call_state = msgb_put(msg, 1);
	call_state[0] = 0xc0 | 0x00;

	return gsm48_sendmsg(msg);
}

static int gsm48_tx_simple(struct gsm_lchan *lchan,
			   u_int8_t pdisc, u_int8_t msg_type)
{
	struct msgb *msg = gsm48_msgb_alloc();
	struct gsm48_hdr *gh = (struct gsm48_hdr *) msgb_put(msg, sizeof(*gh));

	msg->lchan = lchan;

	gh->proto_discr = pdisc;
	gh->msg_type = msg_type;

	return gsm48_sendmsg(msg);
}

static int gsm48_cc_rx_status_enq(struct msgb *msg)
{
	return gsm48_cc_tx_status(msg->lchan);
}

static int gsm48_cc_rx_setup(struct msgb *msg)
{
	return gsm48_tx_simple(msg->lchan, GSM48_PDISC_CC,
			       GSM48_MT_CC_CALL_CONF);
}

int gsm48_cc_tx_setup(struct gsm_lchan *lchan)
{
	struct msgb *msg = gsm48_msgb_alloc();
	struct gsm48_hdr *gh;
	struct gsm_call *call = &lchan->call;

	gh = (struct gsm48_hdr *) msgb_put(msg, sizeof(*gh) + 8);

	call->type = GSM_CT_MT;
	msg->lchan = lchan;

	gh->proto_discr = GSM48_PDISC_CC;
	gh->msg_type = GSM48_MT_CC_SETUP;
	gh->data[0] = 0x34;
	gh->data[1] = 0x00;
	gh->data[2] = 0x5c;
	gh->data[3] = 0x04;
	gh->data[4] = 0xb9;
	gh->data[5] = 0x83;
	gh->data[6] = 0x32;
	gh->data[7] = 0x24;

	DEBUGP(DCC, "Sending SETUP\n");

	return gsm48_sendmsg(msg);
}

static int gsm0408_rcv_cc(struct msgb *msg)
{
	struct gsm48_hdr *gh = msgb_l3(msg);
	u_int8_t msg_type = gh->msg_type & 0xbf;
	struct gsm_call *call = &msg->lchan->call;
	struct gsm_network *network = msg->lchan->ts->trx->bts->network;
	int rc = 0;

	switch (msg_type) {
	case GSM48_MT_CC_CALL_CONF:
		/* Response to SETUP */
		DEBUGP(DCC, "CALL CONFIRM\n");
		break;
	case GSM48_MT_CC_RELEASE_COMPL:
		/* Answer from MS to RELEASE */
		DEBUGP(DCC, "RELEASE COMPLETE (state->NULL)\n");
		if (network->call_state_changed)
			(*network->call_state_changed)(msg->lchan, call->state);
		call->state = GSM_CSTATE_NULL;
		break;
	case GSM48_MT_CC_ALERTING:
		DEBUGP(DCC, "ALERTING\n");
		break;
	case GSM48_MT_CC_CONNECT:
		DEBUGP(DCC, "CONNECT\n");
		/* MT: need to respond with CONNECT_ACK */
		rc = gsm48_tx_simple(msg->lchan, GSM48_PDISC_CC,
				     GSM48_MT_CC_CONNECT_ACK);
		break;
	case GSM48_MT_CC_CONNECT_ACK:
		/* MO: Answer to CONNECT */
		call->state = GSM_CSTATE_ACTIVE;
		DEBUGP(DCC, "CONNECT_ACK (state->ACTIVE)\n");
		break;
	case GSM48_MT_CC_RELEASE:
		DEBUGP(DCC, "RELEASE\n");
		/* need to respond with RELEASE_COMPLETE */
		break;
	case GSM48_MT_CC_STATUS_ENQ:
		rc = gsm48_cc_rx_status_enq(msg);
		break;
	case GSM48_MT_CC_DISCONNECT:
		/* Section 5.4.3.2 */
		DEBUGP(DCC, "DISCONNECT (state->RELEASE_REQ)\n");
		call->state = GSM_CSTATE_RELEASE_REQ;
		/* FIXME: clear the network connection */
		rc = gsm48_tx_simple(msg->lchan, GSM48_PDISC_CC,
				     GSM48_MT_CC_RELEASE);
		break;
	case GSM48_MT_CC_SETUP:
		call->type = GSM_CT_MO;
		call->state = GSM_CSTATE_INITIATED;
		call->transaction_id = gh->proto_discr & 0xf0;
		DEBUGP(DCC, "SETUP(tid=0x%02x)\n", call->transaction_id);
		rc = gsm48_tx_simple(msg->lchan, GSM48_PDISC_CC,
				     GSM48_MT_CC_CONNECT);
		/* FIXME: continue with CALL_PROCEEDING, ALERTING, CONNECT, RELEASE_COMPLETE */
		break;
	case GSM48_MT_CC_EMERG_SETUP:
		DEBUGP(DCC, "EMERGENCY SETUP\n");
		/* FIXME: continue with CALL_PROCEEDING, ALERTING, CONNECT, RELEASE_COMPLETE */
		break;
	default:
		fprintf(stderr, "Unimplemented GSM 04.08 msg type 0x%02x\n",
			msg_type);
		break;
	}

	return rc;
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
	case GSM48_PDISC_SMS:
		rc = gsm0411_rcv_sms(msg);
		break;
	case GSM48_PDISC_MM_GPRS:
	case GSM48_PDISC_SM_GPRS:
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

static const enum gsm_chreq_reason_t reason_by_chreq[] = {
	[CHREQ_T_EMERG_CALL]		= GSM_CHREQ_REASON_EMERG,
	[CHREQ_T_CALL_REEST_TCH_F]	= GSM_CHREQ_REASON_CALL,
	[CHREQ_T_CALL_REEST_TCH_H]	= GSM_CHREQ_REASON_CALL,
	[CHREQ_T_CALL_REEST_TCH_H_DBL]	= GSM_CHREQ_REASON_CALL,
	[CHREQ_T_SDCCH]			= GSM_CHREQ_REASON_OTHER,
	[CHREQ_T_TCH_F]			= GSM_CHREQ_REASON_OTHER,
	[CHREQ_T_VOICE_CALL_TCH_H]	= GSM_CHREQ_REASON_OTHER,
	[CHREQ_T_DATA_CALL_TCH_H]	= GSM_CHREQ_REASON_OTHER,
	[CHREQ_T_LOCATION_UPD]		= GSM_CHREQ_REASON_LOCATION_UPD,
	[CHREQ_T_PAG_R_ANY]		= GSM_CHREQ_REASON_PAG,
	[CHREQ_T_PAG_R_TCH_F]		= GSM_CHREQ_REASON_PAG,
	[CHREQ_T_PAG_R_TCH_FH]		= GSM_CHREQ_REASON_PAG,
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

enum gsm_chreq_reason_t get_reason_by_chreq(struct gsm_bts *bts, u_int8_t ra)
{
	int i;
	/* FIXME: determine if we set NECI = 0 in the BTS SI4 */

	for (i = 0; i < ARRAY_SIZE(chreq_type_neci0); i++) {
		const struct chreq *chr = &chreq_type_neci0[i];
		if ((ra & chr->mask) == chr->val)
			return reason_by_chreq[chr->type];
	}
	fprintf(stderr, "Unknown CHANNEL REQUEST REASON 0x%02x\n", ra);
	return GSM_CHREQ_REASON_OTHER;
}
