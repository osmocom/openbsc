/* Point-to-Point (PP) Short Message Service (SMS)
 * Support on Mobile Radio Interface
 * 3GPP TS 04.11 version 7.1.0 Release 1998 / ETSI TS 100 942 V7.1.0 */

/* (C) 2008 by Daniel Willmann <daniel@totalueberwachung.de>
 * (C) 2009 by Harald Welte <laforge@gnumonks.org>
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
#include <time.h>
#include <netinet/in.h>

#include <openbsc/msgb.h>
#include <openbsc/tlv.h>
#include <openbsc/debug.h>
#include <openbsc/gsm_data.h>
#include <openbsc/gsm_subscriber.h>
#include <openbsc/gsm_04_11.h>
#include <openbsc/gsm_04_08.h>
#include <openbsc/gsm_utils.h>
#include <openbsc/abis_rsl.h>
#include <openbsc/signal.h>
#include <openbsc/db.h>
#include <openbsc/talloc.h>
#include <openbsc/transaction.h>
#include <openbsc/paging.h>
#include <openbsc/bsc_rll.h>
#include <openbsc/chan_alloc.h>

#define GSM411_ALLOC_SIZE	1024
#define GSM411_ALLOC_HEADROOM	128

#define UM_SAPI_SMS 3	/* See GSM 04.05/04.06 */

void *tall_gsms_ctx;
static u_int32_t new_callref = 0x40000001;

static const struct value_string cp_cause_strs[] = {
	{ GSM411_CP_CAUSE_NET_FAIL,	"Network Failure" },
	{ GSM411_CP_CAUSE_CONGESTION,	"Congestion" },
	{ GSM411_CP_CAUSE_INV_TRANS_ID,	"Invalid Transaction ID" },
	{ GSM411_CP_CAUSE_SEMANT_INC_MSG, "Semantically Incorrect Message" },
	{ GSM411_CP_CAUSE_INV_MAND_INF,	"Invalid Mandatory Information" },
	{ GSM411_CP_CAUSE_MSGTYPE_NOTEXIST, "Message Type doesn't exist" },
	{ GSM411_CP_CAUSE_MSG_INCOMP_STATE, 
				"Message incompatible with protocol state" },
	{ GSM411_CP_CAUSE_IE_NOTEXIST,	"IE does not exist" },
	{ GSM411_CP_CAUSE_PROTOCOL_ERR,	"Protocol Error" },
	{ 0, 0 }
};

static const struct value_string rp_cause_strs[] = {
	{ GSM411_RP_CAUSE_MO_NUM_UNASSIGNED, "(MO) Number not assigned" },
	{ GSM411_RP_CAUSE_MO_OP_DET_BARR, "(MO) Operator determined barring" },
	{ GSM411_RP_CAUSE_MO_CALL_BARRED, "(MO) Call barred" },
	{ GSM411_RP_CAUSE_MO_SMS_REJECTED, "(MO) SMS rejected" },
	{ GSM411_RP_CAUSE_MO_DEST_OUT_OF_ORDER, "(MO) Destination out of order" },
	{ GSM411_RP_CAUSE_MO_UNIDENTIFIED_SUBSCR, "(MO) Unidentified subscriber" },
	{ GSM411_RP_CAUSE_MO_FACILITY_REJ, "(MO) Facility reject" },
	{ GSM411_RP_CAUSE_MO_UNKNOWN_SUBSCR, "(MO) Unknown subscriber" },
	{ GSM411_RP_CAUSE_MO_NET_OUT_OF_ORDER, "(MO) Network out of order" },
	{ GSM411_RP_CAUSE_MO_TEMP_FAIL, "(MO) Temporary failure" },
	{ GSM411_RP_CAUSE_MO_CONGESTION, "(MO) Congestion" },
	{ GSM411_RP_CAUSE_MO_RES_UNAVAIL, "(MO) Resource unavailable" },
	{ GSM411_RP_CAUSE_MO_REQ_FAC_NOTSUBSCR, "(MO) Requested facility not subscribed" },
	{ GSM411_RP_CAUSE_MO_REQ_FAC_NOTIMPL, "(MO) Requested facility not implemented" },
	{ GSM411_RP_CAUSE_MO_INTERWORKING, "(MO) Interworking" },
	/* valid only for MT */
	{ GSM411_RP_CAUSE_MT_MEM_EXCEEDED, "(MT) Memory Exceeded" },
	/* valid for both directions */
	{ GSM411_RP_CAUSE_INV_TRANS_REF, "Invalid Transaction Reference" },
	{ GSM411_RP_CAUSE_SEMANT_INC_MSG, "Semantically Incorrect Message" },
	{ GSM411_RP_CAUSE_INV_MAND_INF, "Invalid Mandatory Information" },
	{ GSM411_RP_CAUSE_MSGTYPE_NOTEXIST, "Message Type non-existant" },
	{ GSM411_RP_CAUSE_MSG_INCOMP_STATE, "Message incompatible with protocol state" },
	{ GSM411_RP_CAUSE_IE_NOTEXIST, "Information Element not existing" },
	{ GSM411_RP_CAUSE_PROTOCOL_ERR, "Protocol Error" },
	{ 0, NULL }
};

struct gsm_sms *sms_alloc(void)
{
	return talloc_zero(tall_gsms_ctx, struct gsm_sms);
}

void sms_free(struct gsm_sms *sms)
{
	/* drop references to subscriber structure */
	if (sms->sender)
		subscr_put(sms->sender);
	if (sms->receiver)
		subscr_put(sms->receiver);

	talloc_free(sms);
}

struct msgb *gsm411_msgb_alloc(void)
{
	return msgb_alloc_headroom(GSM411_ALLOC_SIZE, GSM411_ALLOC_HEADROOM,
				   "GSM 04.11");
}

static int gsm411_sendmsg(struct msgb *msg, u_int8_t link_id)
{
	if (msg->lchan)
		msg->trx = msg->lchan->ts->trx;

	msg->l3h = msg->data;

	DEBUGP(DSMS, "GSM4.11 TX %s\n", hexdump(msg->data, msg->len));

	return rsl_data_request(msg, link_id);
}

/* SMC TC1* is expired */
static void cp_timer_expired(void *data)
{
	struct gsm_trans *trans = data;

	DEBUGP(DSMS, "SMC Timer TC1* is expired, calling trans_free()\n");
	/* FIXME: we need to re-transmit the last CP-DATA 1..3 times */
	trans_free(trans);
}

/* Prefix msg with a 04.08/04.11 CP header */
static int gsm411_cp_sendmsg(struct msgb *msg, struct gsm_trans *trans,
			     u_int8_t msg_type)
{
	struct gsm48_hdr *gh;

	gh = (struct gsm48_hdr *) msgb_push(msg, sizeof(*gh));
	/* Outgoing needs the highest bit set */
	gh->proto_discr = trans->protocol | (trans->transaction_id<<4);
	gh->msg_type = msg_type;

	/* assign the outgoing lchan */
	msg->lchan = trans->lchan;

	/* mobile originating */
	switch (gh->msg_type) {
	case GSM411_MT_CP_DATA:
		/* 5.2.3.1.2: enter MO-wait for CP-ack */
		/* 5.2.3.2.3: enter MT-wait for CP-ACK */
		trans->sms.cp_state = GSM411_CPS_WAIT_CP_ACK;
		trans->sms.cp_timer.data = trans;
		trans->sms.cp_timer.cb = cp_timer_expired;
		/* 5.3.2.1: Set Timer TC1A */
		bsc_schedule_timer(&trans->sms.cp_timer, GSM411_TMR_TC1A);
		DEBUGP(DSMS, "TX: CP-DATA ");
		break;
	case GSM411_MT_CP_ACK:
		DEBUGP(DSMS, "TX: CP-ACK ");
		break;
	case GSM411_MT_CP_ERROR:
		DEBUGP(DSMS, "TX: CP-ERROR ");
		break;
	}

	DEBUGPC(DSMS, "trans=%x\n", trans->transaction_id);

	return gsm411_sendmsg(msg, trans->sms.link_id);
}

/* Prefix msg with a RP-DATA header and send as CP-DATA */
static int gsm411_rp_sendmsg(struct msgb *msg, struct gsm_trans *trans,
			     u_int8_t rp_msg_type, u_int8_t rp_msg_ref)
{
	struct gsm411_rp_hdr *rp;
	u_int8_t len = msg->len;

	/* GSM 04.11 RP-DATA header */
	rp = (struct gsm411_rp_hdr *)msgb_push(msg, sizeof(*rp));
	rp->len = len + 2;
	rp->msg_type = rp_msg_type;
	rp->msg_ref = rp_msg_ref; /* FIXME: Choose randomly */

	return gsm411_cp_sendmsg(msg, trans, GSM411_MT_CP_DATA);
}

/* Turn int into semi-octet representation: 98 => 0x89 */
static u_int8_t bcdify(u_int8_t value)
{
	u_int8_t ret;

	ret = value / 10;
	ret |= (value % 10) << 4;

	return ret;
}

/* Turn semi-octet representation into int: 0x89 => 98 */
static u_int8_t unbcdify(u_int8_t value)
{
	u_int8_t ret;

	if ((value & 0x0F) > 9 || (value >> 4) > 9)
		LOGP(DSMS, LOGL_ERROR, 
		     "unbcdify got too big nibble: 0x%02X\n", value);

	ret = (value&0x0F)*10;
	ret += value>>4;

	return ret;
}

/* Generate 03.40 TP-SCTS */
static void gsm340_gen_scts(u_int8_t *scts, time_t time)
{
	struct tm *tm = localtime(&time);

	*scts++ = bcdify(tm->tm_year % 100);
	*scts++ = bcdify(tm->tm_mon + 1);
	*scts++ = bcdify(tm->tm_mday);
	*scts++ = bcdify(tm->tm_hour);
	*scts++ = bcdify(tm->tm_min);
	*scts++ = bcdify(tm->tm_sec);
	*scts++ = bcdify(tm->tm_gmtoff/(60*15));
}

/* Decode 03.40 TP-SCTS (into utc/gmt timestamp) */
static time_t gsm340_scts(u_int8_t *scts)
{
	struct tm tm;

	u_int8_t yr = unbcdify(*scts++);

	if (yr <= 80)
		tm.tm_year = 100 + yr;
	else
		tm.tm_year = yr;
	tm.tm_mon  = unbcdify(*scts++) - 1;
	tm.tm_mday = unbcdify(*scts++);
	tm.tm_hour = unbcdify(*scts++);
	tm.tm_min  = unbcdify(*scts++);
	tm.tm_sec  = unbcdify(*scts++);
	/* according to gsm 03.40 time zone is
	   "expressed in quarters of an hour" */
	tm.tm_gmtoff = unbcdify(*scts++) * 15*60;

	return mktime(&tm);
}

/* Return the default validity period in minutes */
static unsigned long gsm340_vp_default(void)
{
	unsigned long minutes;
	/* Default validity: two days */
	minutes = 24 * 60 * 2;
	return minutes;
}

/* Decode validity period format 'relative' */
static unsigned long gsm340_vp_relative(u_int8_t *sms_vp)
{
	/* Chapter 9.2.3.12.1 */
	u_int8_t vp;
	unsigned long minutes;

	vp = *(sms_vp);
	if (vp <= 143)
		minutes = vp + 1 * 5;
	else if (vp <= 167)
		minutes = 12*60 + (vp-143) * 30;
	else if (vp <= 196)
		minutes = vp-166 * 60 * 24;
	else
		minutes = vp-192 * 60 * 24 * 7;
	return minutes;
}

/* Decode validity period format 'absolute' */
static unsigned long gsm340_vp_absolute(u_int8_t *sms_vp)
{
	/* Chapter 9.2.3.12.2 */
	time_t expires, now;
	unsigned long minutes;

	expires = gsm340_scts(sms_vp);
	now = mktime(gmtime(NULL));
	if (expires <= now)
		minutes = 0;
	else
		minutes = (expires-now)/60;
	return minutes;
}

/* Decode validity period format 'relative in integer representation' */
static unsigned long gsm340_vp_relative_integer(u_int8_t *sms_vp)
{
	u_int8_t vp;
	unsigned long minutes;
	vp = *(sms_vp);
	if (vp == 0) {
		LOGP(DSMS, LOGL_ERROR,
		     "reserved relative_integer validity period\n");
		return gsm340_vp_default();
	}
	minutes = vp/60;
	return minutes;
}

/* Decode validity period format 'relative in semi-octet representation' */
static unsigned long gsm340_vp_relative_semioctet(u_int8_t *sms_vp)
{
	unsigned long minutes;
	minutes = unbcdify(*sms_vp++)*60;  /* hours */
	minutes += unbcdify(*sms_vp++);    /* minutes */
	minutes += unbcdify(*sms_vp++)/60; /* seconds */
	return minutes;
}

/* decode validity period. return minutes */
static unsigned long gsm340_validity_period(u_int8_t sms_vpf, u_int8_t *sms_vp)
{
	u_int8_t fi; /* functionality indicator */

	switch (sms_vpf) {
	case GSM340_TP_VPF_RELATIVE:
		return gsm340_vp_relative(sms_vp);
	case GSM340_TP_VPF_ABSOLUTE:
		return gsm340_vp_absolute(sms_vp);
	case GSM340_TP_VPF_ENHANCED:
		/* Chapter 9.2.3.12.3 */
		fi = *sms_vp++;
		/* ignore additional fi */
		if (fi & (1<<7)) sms_vp++;
		/* read validity period format */
		switch (fi & 0b111) {
		case 0b000:
			return gsm340_vp_default(); /* no vpf specified */
		case 0b001:
			return gsm340_vp_relative(sms_vp);
		case 0b010:
			return gsm340_vp_relative_integer(sms_vp);
		case 0b011:
			return gsm340_vp_relative_semioctet(sms_vp);
		default:
			/* The GSM spec says that the SC should reject any
			   unsupported and/or undefined values. FIXME */
			LOGP(DSMS, LOGL_ERROR,
			     "Reserved enhanced validity period format\n");
			return gsm340_vp_default();
		}
	case GSM340_TP_VPF_NONE:
	default:
		return gsm340_vp_default();
	}
}

/* determine coding alphabet dependent on GSM 03.38 Section 4 DCS */
enum sms_alphabet gsm338_get_sms_alphabet(u_int8_t dcs)
{
	u_int8_t cgbits = dcs >> 4;
	enum sms_alphabet alpha = DCS_NONE;

	if ((cgbits & 0xc) == 0) {
		if (cgbits & 2)
			LOGP(DSMS, LOGL_NOTICE,
			     "Compressed SMS not supported yet\n");

		switch ((dcs >> 2)&0x03) {
		case 0:
			alpha = DCS_7BIT_DEFAULT;
			break;
		case 1:
			alpha = DCS_8BIT_DATA;
			break;
		case 2:
			alpha = DCS_UCS2;
			break;
		}
	} else if (cgbits == 0xc || cgbits == 0xd)
		alpha = DCS_7BIT_DEFAULT;
	else if (cgbits == 0xe)
		alpha = DCS_UCS2;
	else if (cgbits == 0xf) {
		if (dcs & 4)
			alpha = DCS_8BIT_DATA;
		else
			alpha = DCS_7BIT_DEFAULT;
	}

	return alpha;
}

static int gsm340_rx_sms_submit(struct msgb *msg, struct gsm_sms *gsms)
{
	if (db_sms_store(gsms) != 0) {
		LOGP(DSMS, LOGL_ERROR, "Failed to store SMS in Database\n");
		return GSM411_RP_CAUSE_MO_NET_OUT_OF_ORDER;
	}
	/* dispatch a signal to tell higher level about it */
	dispatch_signal(SS_SMS, S_SMS_SUBMITTED, gsms);
	/* try delivering the SMS right now */
	//gsm411_send_sms_subscr(gsms->receiver, gsms);

	return 0;
}

/* generate a TPDU address field compliant with 03.40 sec. 9.1.2.5 */
static int gsm340_gen_oa(u_int8_t *oa, unsigned int oa_len,
			 struct gsm_subscriber *subscr)
{
	int len_in_bytes;

	oa[1] = 0xb9; /* networks-specific number, private numbering plan */

	len_in_bytes = encode_bcd_number(oa, oa_len, 1, subscr->extension);

	/* GSM 03.40 tells us the length is in 'useful semi-octets' */
	oa[0] = strlen(subscr->extension) & 0xff;

	return len_in_bytes;
}

/* generate a msgb containing a TPDU derived from struct gsm_sms,
 * returns total size of TPDU */
static int gsm340_gen_tpdu(struct msgb *msg, struct gsm_sms *sms)
{
	u_int8_t *smsp;
	u_int8_t oa[12];	/* max len per 03.40 */
	u_int8_t oa_len = 0;
	u_int8_t octet_len;
	unsigned int old_msg_len = msg->len;

	/* generate first octet with masked bits */
	smsp = msgb_put(msg, 1);
	/* TP-MTI (message type indicator) */
	*smsp = GSM340_SMS_DELIVER_SC2MS;
	/* TP-MMS (more messages to send) */
	if (0 /* FIXME */)
		*smsp |= 0x04;
	/* TP-SRI(deliver)/SRR(submit) */
	if (sms->status_rep_req)
		*smsp |= 0x20;
	/* TP-UDHI (indicating TP-UD contains a header) */
	if (sms->ud_hdr_ind)
		*smsp |= 0x40;
#if 0
	/* TP-RP (indicating that a reply path exists) */
	if (sms->
		*smsp |= 0x80;
#endif
	
	/* generate originator address */
	oa_len = gsm340_gen_oa(oa, sizeof(oa), sms->sender);
	smsp = msgb_put(msg, oa_len);
	memcpy(smsp, oa, oa_len);

	/* generate TP-PID */
	smsp = msgb_put(msg, 1);
	*smsp = sms->protocol_id;

	/* generate TP-DCS */
	smsp = msgb_put(msg, 1);
	*smsp = sms->data_coding_scheme;

	/* generate TP-SCTS */
	smsp = msgb_put(msg, 7);
	gsm340_gen_scts(smsp, time(NULL));

	/* generate TP-UDL */
	smsp = msgb_put(msg, 1);
	*smsp = sms->user_data_len;

	/* generate TP-UD */
	switch (gsm338_get_sms_alphabet(sms->data_coding_scheme)) {
	case DCS_7BIT_DEFAULT:
		octet_len = sms->user_data_len*7/8;
		if (sms->user_data_len*7%8 != 0)
			octet_len++;
		/* Warning, user_data_len indicates the amount of septets
		 * (characters), we need amount of octets occupied */
		smsp = msgb_put(msg, octet_len);
		memcpy(smsp, sms->user_data, octet_len);
		break;
	case DCS_UCS2:
	case DCS_8BIT_DATA:
		smsp = msgb_put(msg, sms->user_data_len);
		memcpy(smsp, sms->user_data, sms->user_data_len);
		break;
	default:
		LOGP(DSMS, LOGL_NOTICE, "Unhandled Data Coding Scheme: 0x%02X\n",
		     sms->data_coding_scheme);
		break;
	}

	return msg->len - old_msg_len;
}

/* process an incoming TPDU (called from RP-DATA) 
 * return value > 0: RP CAUSE for ERROR; < 0: silent error; 0 = success */ 
static int gsm340_rx_tpdu(struct msgb *msg)
{
	struct gsm_bts *bts = msg->lchan->ts->trx->bts;
	u_int8_t *smsp = msgb_sms(msg);
	struct gsm_sms *gsms;
	u_int8_t sms_mti, sms_mms, sms_vpf, sms_alphabet, sms_rp;
	u_int8_t *sms_vp;
	u_int8_t da_len_bytes;
	u_int8_t address_lv[12]; /* according to 03.40 / 9.1.2.5 */
	int rc = 0;

	counter_inc(bts->network->stats.sms.submitted);

	gsms = sms_alloc();
	if (!gsms)
		return GSM411_RP_CAUSE_MO_NET_OUT_OF_ORDER;

	/* invert those fields where 0 means active/present */
	sms_mti = *smsp & 0x03;
	sms_mms = !!(*smsp & 0x04);
	sms_vpf = (*smsp & 0x18) >> 3;
	gsms->status_rep_req = (*smsp & 0x20);
	gsms->ud_hdr_ind = (*smsp & 0x40);
	sms_rp  = (*smsp & 0x80);

	smsp++;
	gsms->msg_ref = *smsp++;

	/* length in bytes of the destination address */
	da_len_bytes = 2 + *smsp/2 + *smsp%2;
	if (da_len_bytes > 12) {
		LOGP(DSMS, LOGL_ERROR, "Destination Address > 12 bytes ?!?\n");
		rc = GSM411_RP_CAUSE_SEMANT_INC_MSG;
		goto out;
	}
	memset(address_lv, 0, sizeof(address_lv));
	memcpy(address_lv, smsp, da_len_bytes);
	/* mangle first byte to reflect length in bytes, not digits */
	address_lv[0] = da_len_bytes - 1;
	/* convert to real number */
	decode_bcd_number(gsms->dest_addr, sizeof(gsms->dest_addr), address_lv, 1);
	smsp += da_len_bytes;

	gsms->protocol_id = *smsp++;
	gsms->data_coding_scheme = *smsp++;

	sms_alphabet = gsm338_get_sms_alphabet(gsms->data_coding_scheme);

	switch (sms_vpf) {
	case GSM340_TP_VPF_RELATIVE:
		sms_vp = smsp++;
		break;
	case GSM340_TP_VPF_ABSOLUTE:
	case GSM340_TP_VPF_ENHANCED:
		sms_vp = smsp;
		/* the additional functionality indicator... */
		if (sms_vpf == GSM340_TP_VPF_ENHANCED && *smsp & (1<<7))
			smsp++;
		smsp += 7;
		break;
	case GSM340_TP_VPF_NONE:
		sms_vp = 0;
		break;
	default:
		LOGP(DSMS, LOGL_NOTICE, 
		     "SMS Validity period not implemented: 0x%02x\n", sms_vpf);
		return GSM411_RP_CAUSE_MO_NET_OUT_OF_ORDER;
	}
	gsms->user_data_len = *smsp++;
	if (gsms->user_data_len) {
		memcpy(gsms->user_data, smsp, gsms->user_data_len);

		switch (sms_alphabet) {
		case DCS_7BIT_DEFAULT:
			gsm_7bit_decode(gsms->text, smsp, gsms->user_data_len);
			break;
		case DCS_8BIT_DATA:
		case DCS_UCS2:
		case DCS_NONE:
			break;
		}
	}

	gsms->sender = subscr_get(msg->lchan->subscr);

	LOGP(DSMS, LOGL_INFO, "RX SMS: Sender: %s, MTI: 0x%02x, VPF: 0x%02x, "
	     "MR: 0x%02x PID: 0x%02x, DCS: 0x%02x, DA: %s, "
	     "UserDataLength: 0x%02x, UserData: \"%s\"\n",
	     subscr_name(gsms->sender), sms_mti, sms_vpf, gsms->msg_ref,
	     gsms->protocol_id, gsms->data_coding_scheme, gsms->dest_addr,
	     gsms->user_data_len,
			sms_alphabet == DCS_7BIT_DEFAULT ? gsms->text : 
				hexdump(gsms->user_data, gsms->user_data_len));

	gsms->validity_minutes = gsm340_validity_period(sms_vpf, sms_vp);

	dispatch_signal(SS_SMS, 0, gsms);

	/* determine gsms->receiver based on dialled number */
	gsms->receiver = subscr_get_by_extension(bts->network, gsms->dest_addr);
	if (!gsms->receiver) {
		rc = 1; /* cause 1: unknown subscriber */
		counter_inc(bts->network->stats.sms.no_receiver);
		goto out;
	}

	switch (sms_mti) {
	case GSM340_SMS_SUBMIT_MS2SC:
		/* MS is submitting a SMS */
		rc = gsm340_rx_sms_submit(msg, gsms);
		break;
	case GSM340_SMS_COMMAND_MS2SC:
	case GSM340_SMS_DELIVER_REP_MS2SC:
		LOGP(DSMS, LOGL_NOTICE, "Unimplemented MTI 0x%02x\n", sms_mti);
		rc = GSM411_RP_CAUSE_IE_NOTEXIST;
		break;
	default:
		LOGP(DSMS, LOGL_NOTICE, "Undefined MTI 0x%02x\n", sms_mti);
		rc = GSM411_RP_CAUSE_IE_NOTEXIST;
		break;
	}

	if (!rc && !gsms->receiver)
		rc = GSM411_RP_CAUSE_MO_NUM_UNASSIGNED;

out:
	sms_free(gsms);

	return rc;
}

static int gsm411_send_rp_ack(struct gsm_trans *trans, u_int8_t msg_ref)
{
	struct msgb *msg = gsm411_msgb_alloc();

	DEBUGP(DSMS, "TX: SMS RP ACK\n");

	return gsm411_rp_sendmsg(msg, trans, GSM411_MT_RP_ACK_MT, msg_ref);
}

static int gsm411_send_rp_error(struct gsm_trans *trans,
				u_int8_t msg_ref, u_int8_t cause)
{
	struct msgb *msg = gsm411_msgb_alloc();

	msgb_tv_put(msg, 1, cause);

	LOGP(DSMS, LOGL_NOTICE, "TX: SMS RP ERROR, cause %d (%s)\n", cause,
		get_value_string(rp_cause_strs, cause));

	return gsm411_rp_sendmsg(msg, trans, GSM411_MT_RP_ERROR_MT, msg_ref);
}

/* Receive a 04.11 TPDU inside RP-DATA / user data */
static int gsm411_rx_rp_ud(struct msgb *msg, struct gsm_trans *trans,
			  struct gsm411_rp_hdr *rph,
			  u_int8_t src_len, u_int8_t *src,
			  u_int8_t dst_len, u_int8_t *dst,
			  u_int8_t tpdu_len, u_int8_t *tpdu)
{
	int rc = 0;

	if (src_len && src)
		LOGP(DSMS, LOGL_ERROR, "RP-DATA (MO) with SRC ?!?\n");

	if (!dst_len || !dst || !tpdu_len || !tpdu) {
		LOGP(DSMS, LOGL_ERROR,
			"RP-DATA (MO) without DST or TPDU ?!?\n");
		gsm411_send_rp_error(trans, rph->msg_ref,
				     GSM411_RP_CAUSE_INV_MAND_INF);
		return -EIO;
	}
	msg->smsh = tpdu;

	DEBUGP(DSMS, "DST(%u,%s)\n", dst_len, hexdump(dst, dst_len));

	rc = gsm340_rx_tpdu(msg);
	if (rc == 0)
		return gsm411_send_rp_ack(trans, rph->msg_ref);
	else if (rc > 0)
		return gsm411_send_rp_error(trans, rph->msg_ref, rc);
	else
		return rc;
}

/* Receive a 04.11 RP-DATA message in accordance with Section 7.3.1.2 */
static int gsm411_rx_rp_data(struct msgb *msg, struct gsm_trans *trans,
			     struct gsm411_rp_hdr *rph)
{
	u_int8_t src_len, dst_len, rpud_len;
	u_int8_t *src = NULL, *dst = NULL , *rp_ud = NULL;

	/* in the MO case, this should always be zero length */
	src_len = rph->data[0];
	if (src_len)
		src = &rph->data[1];

	dst_len = rph->data[1+src_len];
	if (dst_len)
		dst = &rph->data[1+src_len+1];

	rpud_len = rph->data[1+src_len+1+dst_len];
	if (rpud_len)
		rp_ud = &rph->data[1+src_len+1+dst_len+1];

	DEBUGP(DSMS, "RX_RP-DATA: src_len=%u, dst_len=%u ud_len=%u\n",
		src_len, dst_len, rpud_len);
	return gsm411_rx_rp_ud(msg, trans, rph, src_len, src, dst_len, dst,
				rpud_len, rp_ud);
}

/* Receive a 04.11 RP-ACK message (response to RP-DATA from us) */
static int gsm411_rx_rp_ack(struct msgb *msg, struct gsm_trans *trans,
			    struct gsm411_rp_hdr *rph)
{
	struct gsm_sms *sms = trans->sms.sms;

	/* Acnkowledgement to MT RP_DATA, i.e. the MS confirms it
	 * successfully received a SMS.  We can now safely mark it as
	 * transmitted */

	if (!trans->sms.is_mt) {
		LOGP(DSMS, LOGL_ERROR, "RX RP-ACK on a MO transfer ?\n");
		return gsm411_send_rp_error(trans, rph->msg_ref,
					    GSM411_RP_CAUSE_MSG_INCOMP_STATE);
	}

	if (!sms) {
		LOGP(DSMS, LOGL_ERROR, "RX RP-ACK but no sms in transaction?!?\n");
		return gsm411_send_rp_error(trans, rph->msg_ref,
					    GSM411_RP_CAUSE_PROTOCOL_ERR);
	}

	/* mark this SMS as sent in database */
	db_sms_mark_sent(sms);

	dispatch_signal(SS_SMS, S_SMS_DELIVERED, sms);

	sms_free(sms);
	trans->sms.sms = NULL;

	/* check for more messages for this subscriber */
	sms = db_sms_get_unsent_for_subscr(msg->lchan->subscr);
	if (sms)
		gsm411_send_sms_lchan(msg->lchan, sms);

	/* free the transaction here */
	trans_free(trans);

	/* release channel if done */
	if (!sms)
		rsl_release_request(msg->lchan, trans->sms.link_id);

	return 0;
}

static int gsm411_rx_rp_error(struct msgb *msg, struct gsm_trans *trans,
			      struct gsm411_rp_hdr *rph)
{
	struct gsm_network *net = trans->lchan->ts->trx->bts->network;
	struct gsm_sms *sms = trans->sms.sms;
	u_int8_t cause_len = rph->data[0];
	u_int8_t cause = rph->data[1];

	/* Error in response to MT RP_DATA, i.e. the MS did not
	 * successfully receive the SMS.  We need to investigate
	 * the cause and take action depending on it */

	LOGP(DSMS, LOGL_NOTICE, "%s: RX SMS RP-ERROR, cause %d:%d (%s)\n",
	     subscr_name(msg->lchan->subscr), cause_len, cause,
	     get_value_string(rp_cause_strs, cause));

	if (!trans->sms.is_mt) {
		LOGP(DSMS, LOGL_ERROR, "RX RP-ERR on a MO transfer ?\n");
#if 0
		return gsm411_send_rp_error(trans, rph->msg_ref,
					    GSM411_RP_CAUSE_MSG_INCOMP_STATE);
#endif
	}

	if (!sms) {
		LOGP(DSMS, LOGL_ERROR,
			"RX RP-ERR, but no sms in transaction?!?\n");
		return -EINVAL;
#if 0
		return gsm411_send_rp_error(trans, rph->msg_ref,
					    GSM411_RP_CAUSE_PROTOCOL_ERR);
#endif
	}

	if (cause == GSM411_RP_CAUSE_MT_MEM_EXCEEDED) {
		/* MS has not enough memory to store the message.  We need
		 * to store this in our database and wati for a SMMA message */
		/* FIXME */
		dispatch_signal(SS_SMS, S_SMS_MEM_EXCEEDED, trans->subscr);
		counter_inc(net->stats.sms.rp_err_mem);
	} else
		counter_inc(net->stats.sms.rp_err_other);

	sms_free(sms);
	trans->sms.sms = NULL;

	//trans_free(trans);

	return 0;
}

static int gsm411_rx_rp_smma(struct msgb *msg, struct gsm_trans *trans,
			     struct gsm411_rp_hdr *rph)
{
	struct gsm_sms *sms;
	int rc;

	rc = gsm411_send_rp_ack(trans, rph->msg_ref);
	trans->sms.rp_state = GSM411_RPS_IDLE;

	/* MS tells us that it has memory for more SMS, we need
	 * to check if we have any pending messages for it and then
	 * transfer those */
	dispatch_signal(SS_SMS, S_SMS_SMMA, trans->subscr);

	/* check for more messages for this subscriber */
	sms = db_sms_get_unsent_for_subscr(msg->lchan->subscr);
	if (sms)
		gsm411_send_sms_lchan(msg->lchan, sms);
	else
		rsl_release_request(msg->lchan, trans->sms.link_id);

	return rc;
}

static int gsm411_rx_cp_data(struct msgb *msg, struct gsm48_hdr *gh,
			     struct gsm_trans *trans)
{
	struct gsm411_rp_hdr *rp_data = (struct gsm411_rp_hdr*)&gh->data;
	u_int8_t msg_type =  rp_data->msg_type & 0x07;
	int rc = 0;

	switch (msg_type) {
	case GSM411_MT_RP_DATA_MO:
		DEBUGP(DSMS, "RX SMS RP-DATA (MO)\n");
		/* start TR2N and enter 'wait to send RP-ACK state' */
		trans->sms.rp_state = GSM411_RPS_WAIT_TO_TX_RP_ACK;
		rc = gsm411_rx_rp_data(msg, trans, rp_data);
		break;
	case GSM411_MT_RP_ACK_MO:
		DEBUGP(DSMS,"RX SMS RP-ACK (MO)\n");
		rc = gsm411_rx_rp_ack(msg, trans, rp_data);
		break;
	case GSM411_MT_RP_SMMA_MO:
		DEBUGP(DSMS, "RX SMS RP-SMMA\n");
		/* start TR2N and enter 'wait to send RP-ACK state' */
		trans->sms.rp_state = GSM411_RPS_WAIT_TO_TX_RP_ACK;
		rc = gsm411_rx_rp_smma(msg, trans, rp_data);
		break;
	case GSM411_MT_RP_ERROR_MO:
		rc = gsm411_rx_rp_error(msg, trans, rp_data);
		break;
	default:
		LOGP(DSMS, LOGL_NOTICE, "Invalid RP type 0x%02x\n", msg_type);
		rc = gsm411_send_rp_error(trans, rp_data->msg_ref,
					  GSM411_RP_CAUSE_MSGTYPE_NOTEXIST);
		break;
	}

	return rc;
}

/* send CP-ACK to given transaction */
static int gsm411_tx_cp_ack(struct gsm_trans *trans)
{
	struct msgb *msg = gsm411_msgb_alloc();
	int rc;

	rc = gsm411_cp_sendmsg(msg, trans, GSM411_MT_CP_ACK);

	if (trans->sms.is_mt) {
		/* If this is a MT SMS DELIVER, we can clear transaction here */
		trans->sms.cp_state = GSM411_CPS_IDLE;
		//trans_free(trans);
	}

	return rc;
}

static int gsm411_tx_cp_error(struct gsm_trans *trans, u_int8_t cause)
{
	struct msgb *msg = gsm411_msgb_alloc();
	u_int8_t *causep;

	LOGP(DSMS, LOGL_NOTICE, "TX CP-ERROR, cause %d (%s)\n", cause,
		get_value_string(cp_cause_strs, cause));

	causep = msgb_put(msg, 1);
	*causep = cause;

	return gsm411_cp_sendmsg(msg, trans, GSM411_MT_CP_ERROR);
}

/* Entry point for incoming GSM48_PDISC_SMS from abis_rsl.c */
int gsm0411_rcv_sms(struct msgb *msg, u_int8_t link_id)
{
	struct gsm48_hdr *gh = msgb_l3(msg);
	u_int8_t msg_type = gh->msg_type;
	u_int8_t transaction_id = ((gh->proto_discr >> 4) ^ 0x8); /* flip */
	struct gsm_lchan *lchan = msg->lchan;
	struct gsm_trans *trans;
	int rc = 0;

	if (!lchan->subscr)
		return -EIO;
		/* FIXME: send some error message */

	DEBUGP(DSMS, "trans_id=%x ", transaction_id);
	trans = trans_find_by_id(lchan->subscr, GSM48_PDISC_SMS,
				 transaction_id);
	if (!trans) {
		DEBUGPC(DSMS, "(new) ");
		trans = trans_alloc(lchan->subscr, GSM48_PDISC_SMS,
				    transaction_id, new_callref++);
		if (!trans) {
			DEBUGPC(DSMS, "No memory for trans\n");
			/* FIXME: send some error message */
			return -ENOMEM;
		}
		trans->sms.cp_state = GSM411_CPS_IDLE;
		trans->sms.rp_state = GSM411_RPS_IDLE;
		trans->sms.is_mt = 0;
		trans->sms.link_id = link_id;

		trans->lchan = lchan;
		use_lchan(lchan);
	}

	switch(msg_type) {
	case GSM411_MT_CP_DATA:
		DEBUGPC(DSMS, "RX SMS CP-DATA\n");

		/* 5.4: For MO, if a CP-DATA is received for a new
		 * transaction, equals reception of an implicit
		 * last CP-ACK for previous transaction */
		if (trans->sms.cp_state == GSM411_CPS_IDLE) {
			int i;
			struct gsm_trans *ptrans;

			/* Scan through all remote initiated transactions */
			for (i=8; i<15; i++) {
				if (i == transaction_id)
					continue;

				ptrans = trans_find_by_id(lchan->subscr,
				                          GSM48_PDISC_SMS, i);
				if (!ptrans)
					continue;

				DEBUGP(DSMS, "Implicit CP-ACK for trans_id=%x\n", i);

				/* Finish it for good */
				bsc_del_timer(&ptrans->sms.cp_timer);
				ptrans->sms.cp_state = GSM411_CPS_IDLE;
				trans_free(ptrans);
			}
		}

		/* 5.2.3.1.3: MO state exists when SMC has received
		 * CP-DATA, including sending of the assoc. CP-ACK */
		/* 5.2.3.2.4: MT state exists when SMC has received
		 * CP-DATA, including sending of the assoc. CP-ACK */
		trans->sms.cp_state = GSM411_CPS_MM_ESTABLISHED;

		/* SMC instance acknowledges the CP-DATA frame */
		gsm411_tx_cp_ack(trans);
		
		rc = gsm411_rx_cp_data(msg, gh, trans);
#if 0
		/* Send CP-ACK or CP-ERORR in response */
		if (rc < 0) {
			rc = gsm411_tx_cp_error(trans, GSM411_CP_CAUSE_NET_FAIL);
		} else
			rc = gsm411_tx_cp_ack(trans);
#endif
		break;
	case GSM411_MT_CP_ACK:
		/* previous CP-DATA in this transaction was confirmed */
		DEBUGPC(DSMS, "RX SMS CP-ACK\n");
		/* 5.2.3.1.3: MO state exists when SMC has received CP-ACK */
		/* 5.2.3.2.4: MT state exists when SMC has received CP-ACK */
		trans->sms.cp_state = GSM411_CPS_MM_ESTABLISHED;
		/* Stop TC1* after CP-ACK has been received */
		bsc_del_timer(&trans->sms.cp_timer);

		if (!trans->sms.is_mt) {
			/* FIXME: we have sont one CP-DATA, which was now
			 * acknowledged.  Check if we want to transfer more,
			 * i.e. multi-part message */
			trans->sms.cp_state = GSM411_CPS_IDLE;
			trans_free(trans);
		}
		break;
	case GSM411_MT_CP_ERROR:
		DEBUGPC(DSMS, "RX SMS CP-ERROR, cause %d (%s)\n", gh->data[0],
			get_value_string(cp_cause_strs, gh->data[0]));
		bsc_del_timer(&trans->sms.cp_timer);
		trans->sms.cp_state = GSM411_CPS_IDLE;
		trans_free(trans);
		break;
	default:
		DEBUGPC(DSMS, "RX Unimplemented CP msg_type: 0x%02x\n", msg_type);
		rc = gsm411_tx_cp_error(trans, GSM411_CP_CAUSE_MSGTYPE_NOTEXIST);
		trans->sms.cp_state = GSM411_CPS_IDLE;
		trans_free(trans);
		break;
	}

	return rc;
}

#if 0
/* Test TPDU - ALL YOUR */
static u_int8_t tpdu_test[] = {
	0x04, 0x04, 0x81, 0x32, 0x24, 0x00, 0x00, 0x80, 0x21, 0x03, 0x41, 0x24,
	0x32, 0x40, 0x1F, 0x41, 0x26, 0x13, 0x94, 0x7D, 0x56, 0xA5, 0x20, 0x28,
	0xF2, 0xE9, 0x2C, 0x82, 0x82, 0xD2, 0x22, 0x48, 0x58, 0x64, 0x3E, 0x9D,
	0x47, 0x10, 0xF5, 0x09, 0xAA, 0x4E, 0x01
};
#endif

/* Take a SMS in gsm_sms structure and send it through an already
 * existing lchan. We also assume that the caller ensured this lchan already
 * has a SAPI3 RLL connection! */
int gsm411_send_sms_lchan(struct gsm_lchan *lchan, struct gsm_sms *sms)
{
	struct msgb *msg = gsm411_msgb_alloc();
	struct gsm_trans *trans;
	u_int8_t *data, *rp_ud_len;
	u_int8_t msg_ref = 42;
	int transaction_id;
	int rc;

	transaction_id = trans_assign_trans_id(lchan->subscr, GSM48_PDISC_SMS, 0);
	if (transaction_id == -1) {
		LOGP(DSMS, LOGL_ERROR, "No available transaction ids\n");
		return -EBUSY;
	}

	msg->lchan = lchan;

	DEBUGP(DSMS, "send_sms_lchan()\n");

	/* FIXME: allocate transaction with message reference */
	trans = trans_alloc(lchan->subscr, GSM48_PDISC_SMS,
			    transaction_id, new_callref++);
	if (!trans) {
		LOGP(DSMS, LOGL_ERROR, "No memory for trans\n");
		/* FIXME: send some error message */
		return -ENOMEM;
	}
	trans->sms.cp_state = GSM411_CPS_IDLE;
	trans->sms.rp_state = GSM411_RPS_IDLE;
	trans->sms.is_mt = 1;
	trans->sms.sms = sms;
	trans->sms.link_id = UM_SAPI_SMS;	/* FIXME: main or SACCH ? */

	trans->lchan = lchan;
	use_lchan(lchan);

	/* Hardcode SMSC Originating Address for now */
	data = (u_int8_t *)msgb_put(msg, 8);
	data[0] = 0x07;	/* originator length == 7 */
	data[1] = 0x91; /* type of number: international, ISDN */
	data[2] = 0x44; /* 447785016005 */
	data[3] = 0x77;
	data[4] = 0x58;
	data[5] = 0x10;
	data[6] = 0x06;
	data[7] = 0x50;

	/* Hardcoded Destination Address */
	data = (u_int8_t *)msgb_put(msg, 1);
	data[0] = 0;	/* destination length == 0 */

	/* obtain a pointer for the rp_ud_len, so we can fill it later */
	rp_ud_len = (u_int8_t *)msgb_put(msg, 1);

#if 1
	/* generate the 03.40 TPDU */
	rc = gsm340_gen_tpdu(msg, sms);
	if (rc < 0) {
		msgb_free(msg);
		return rc;
	}

	*rp_ud_len = rc;
#else
	data = msgb_put(msg, sizeof(tpdu_test));
	memcpy(data, tpdu_test, sizeof(tpdu_test));
	*rp_ud_len = sizeof(tpdu_test);
#endif

	DEBUGP(DSMS, "TX: SMS DELIVER\n");

	counter_inc(lchan->ts->trx->bts->network->stats.sms.delivered);

	return gsm411_rp_sendmsg(msg, trans, GSM411_MT_RP_DATA_MT, msg_ref);
	/* FIXME: enter 'wait for RP-ACK' state, start TR1N */
}

/* RLL SAPI3 establish callback. Now we have a RLL connection and
 * can deliver the actual message */
static void rll_ind_cb(struct gsm_lchan *lchan, u_int8_t link_id,
			void *_sms, enum bsc_rllr_ind type)
{
	struct gsm_sms *sms = _sms;

	DEBUGP(DSMS, "rll_ind_cb(lchan=%p, link_id=%u, sms=%p, type=%u\n",
		lchan, link_id, sms, type);

	switch (type) {
	case BSC_RLLR_IND_EST_CONF:
		gsm411_send_sms_lchan(lchan, sms);
		break;
	case BSC_RLLR_IND_REL_IND:
	case BSC_RLLR_IND_ERR_IND:
	case BSC_RLLR_IND_TIMEOUT:
		sms_free(sms);
		break;
	}
}

/* paging callback. Here we get called if paging a subscriber has
 * succeeded or failed. */
static int paging_cb_send_sms(unsigned int hooknum, unsigned int event,
			      struct msgb *msg, void *_lchan, void *_sms)
{
	struct gsm_lchan *lchan = _lchan;
	struct gsm_sms *sms = _sms;
	int rc;

	DEBUGP(DSMS, "paging_cb_send_sms(hooknum=%u, event=%u, msg=%p,"
		"lchan=%p, sms=%p)\n", hooknum, event, msg, lchan, sms);

	if (hooknum != GSM_HOOK_RR_PAGING)
		return -EINVAL;

	switch (event) {
	case GSM_PAGING_SUCCEEDED:
		/* Paging aborted without lchan ?!? */
		if (!lchan) {
			sms_free(sms);
			rc = -EIO;
			break;
		}
		/* Establish a SAPI3 RLL connection for SMS */
		rc = rll_establish(lchan, UM_SAPI_SMS, rll_ind_cb, sms);
		break;
	case GSM_PAGING_EXPIRED:
		sms_free(sms);
		rc = -ETIMEDOUT;
		break;
	default:
		rc = -EINVAL;
		break;
	}

	return rc;
}

/* high-level function to send a SMS to a given subscriber. The function
 * will take care of paging the subscriber, establishing the RLL SAPI3
 * connection, etc. */
int gsm411_send_sms_subscr(struct gsm_subscriber *subscr,
			   struct gsm_sms *sms)
{
	struct gsm_lchan *lchan;
	int rc;

	/* check if we already have an open lchan to the subscriber.
	 * if yes, send the SMS this way */
	lchan = lchan_for_subscr(subscr);
	if (lchan)
		return rll_establish(lchan, UM_SAPI_SMS,
				     rll_ind_cb, sms);

	/* if not, we have to start paging */
	rc = paging_request(subscr->net, subscr, RSL_CHANNEED_SDCCH,
			    paging_cb_send_sms, sms);
	if (rc <= 0)
		sms_free(sms);

	return 0;
}

static int subscr_sig_cb(unsigned int subsys, unsigned int signal,
			 void *handler_data, void *signal_data)
{
	struct gsm_subscriber *subscr;
	struct gsm_lchan *lchan;
	struct gsm_sms *sms;

	switch (signal) {
	case S_SUBSCR_ATTACHED:
		/* A subscriber has attached. Check if there are
		 * any pending SMS for him to be delivered */
		subscr = signal_data;
		lchan = lchan_for_subscr(subscr);
		if (!lchan)
			break;
		sms = db_sms_get_unsent_for_subscr(subscr);
		if (!sms)
			break;
		/* Establish a SAPI3 RLL connection for SMS */
		rll_establish(lchan, UM_SAPI_SMS, rll_ind_cb, sms);
		break;
	default:
		break;
	}
	return 0;
}

void _gsm411_sms_trans_free(struct gsm_trans *trans)
{
	bsc_del_timer(&trans->sms.cp_timer);
}

static __attribute__((constructor)) void on_dso_load_sms(void)
{
	register_signal_handler(SS_SUBSCR, subscr_sig_cb, NULL);
}
