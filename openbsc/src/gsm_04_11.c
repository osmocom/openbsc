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

#define GSM411_ALLOC_SIZE	1024
#define GSM411_ALLOC_HEADROOM	128

static void *tall_sms_ctx;
static void *tall_gsms_ctx;

struct msgb *gsm411_msgb_alloc(void)
{
	return msgb_alloc_headroom(GSM411_ALLOC_SIZE, GSM411_ALLOC_HEADROOM,
				   "GSM 04.11");
}

int gsm0411_sendmsg(struct msgb *msg)
{
	if (msg->lchan)
		msg->trx = msg->lchan->ts->trx;

	msg->l3h = msg->data;

	return rsl_data_request(msg, 0);
}


#if 0
static u_int8_t gsm0411_tpdu_from_sms(u_int8_t *tpdu, struct sms_deliver *sms)
{
}
#endif

static unsigned long gsm340_validity_period(struct sms_submit *sms)
{
	u_int8_t vp;
	unsigned long minutes;

	switch (sms->vpf) {
	case GSM340_TP_VPF_RELATIVE:
		/* Chapter 9.2.3.12.1 */
		vp = *(sms->vp);
		if (vp <= 143)
			minutes = vp + 1 * 5;
		else if (vp <= 167)
			minutes = 12*60 + (vp-143) * 30;
		else if (vp <= 196)
			minutes = vp-166 * 60 * 24;
		else
			minutes = vp-192 * 60 * 24 * 7;
		break;
	case GSM340_TP_VPF_ABSOLUTE:
		/* Chapter 9.2.3.12.2 */
		/* FIXME: like service center time stamp */
		DEBUGP(DSMS, "VPI absolute not implemented yet\n");
		break;
	case GSM340_TP_VPF_ENHANCED:
		/* Chapter 9.2.3.12.3 */
		/* FIXME: implementation */
		DEBUGP(DSMS, "VPI enhanced not implemented yet\n");
		break;
	}
	return minutes;
}

/* determine coding alphabet dependent on GSM 03.38 Section 4 DCS */
enum sms_alphabet gsm338_get_sms_alphabet(u_int8_t dcs)
{
	u_int8_t cgbits = dcs >> 4;
	enum sms_alphabet alpha = DCS_NONE;

	if ((cgbits & 0xc) == 0) {
		if (cgbits & 2)
			DEBUGP(DSMS, "Compressed SMS not supported yet\n");

		switch (dcs & 3) {
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

static int gsm340_rx_sms_submit(struct msgb *msg, struct sms_submit *sms,
				struct gsm_sms *gsms)
{
	if (db_sms_store(gsms) != 0) {
		DEBUGP(DSMS, "Failed to store SMS in Database\n");
		talloc_free(sms);
		talloc_free(gsms);
		return -EIO;
	}
	return 0;
}

/* process an incoming TPDU (called from RP-DATA) */
static int gsm340_rx_tpdu(struct msgb *msg)
{
	struct gsm_bts *bts = msg->lchan->ts->trx->bts;
	u_int8_t *smsp = msgb_sms(msg);
	struct sms_submit *sms;
	struct gsm_sms *gsms;
	u_int8_t da_len_bytes;
	u_int8_t address_lv[12]; /* according to 03.40 / 9.1.2.5 */
	int rc = 0;

	if (!tall_sms_ctx)
		tall_sms_ctx = talloc_named_const(tall_bsc_ctx, 1,
						  "sms_submit");

	sms = talloc(tall_sms_ctx, struct sms_submit);
	if (!sms)
		return -ENOMEM;
	memset(sms, 0, sizeof(*sms));

	if (!tall_gsms_ctx)
		tall_gsms_ctx = talloc_named_const(tall_bsc_ctx, 1,
						   "sms");

	gsms = talloc(tall_gsms_ctx, struct gsm_sms);
	if (!gsms) {
		talloc_free(sms);
		return -ENOMEM;
	}
	memset(gsms, 0, sizeof(*gsms));

	/* invert those fields where 0 means active/present */
	sms->mti = *smsp & 0x03;
	sms->mms = !!(*smsp & 0x04);
	sms->vpf = (*smsp & 0x18) >> 3;
	sms->sri = !!(*smsp & 0x20);
	sms->udhi= !!(*smsp & 0x40);
	sms->rp  = !!(*smsp & 0x80);

	smsp++;
	sms->msg_ref = *smsp++;

	/* length in bytes of the destination address */
	da_len_bytes = 2 + *smsp/2 + *smsp%2;
	if (da_len_bytes > 12) {
		DEBUGP(DSMS, "Destination Address > 12 bytes ?!?\n");
		rc = -EIO;
		goto out;
	}
	memset(address_lv, 0, sizeof(address_lv));
	memcpy(address_lv, smsp, da_len_bytes);
	/* mangle first byte to reflect length in bytes, not digits */
	address_lv[0] = da_len_bytes - 1;
	/* convert to real number */
	decode_bcd_number(sms->dest_addr, sizeof(sms->dest_addr), address_lv, 1);

	smsp += da_len_bytes;

	sms->pid = *smsp++;

	sms->dcs = *smsp++;
	sms->alphabet = gsm338_get_sms_alphabet(sms->dcs);

	switch (sms->vpf) {
	case GSM340_TP_VPF_RELATIVE:
		sms->vp = smsp++;
		break;
	case GSM340_TP_VPF_ABSOLUTE:
	case GSM340_TP_VPF_ENHANCED:
		sms->vp = smsp;
		smsp += 7;
		break;
	default:
		DEBUGP(DSMS, "SMS Validity period not implemented: 0x%02x\n",
				sms->vpf);
	}
	sms->ud_len = *smsp++;
	if (sms->ud_len)
		sms->user_data = smsp;
	else
		sms->user_data = NULL;

	if (sms->ud_len) {
		switch (sms->alphabet) {
		case DCS_7BIT_DEFAULT:
			gsm_7bit_decode(sms->decoded, smsp, sms->ud_len);
			break;
		case DCS_8BIT_DATA:
		case DCS_UCS2:
		case DCS_NONE:
			memcpy(sms->decoded,  sms->user_data, sms->ud_len);
			break;
		}
	}

	DEBUGP(DSMS, "SMS:\nMTI: 0x%02x, VPF: 0x%02x, MR: 0x%02x "
			"PID: 0x%02x, DCS: 0x%02x, DA: %s, UserDataLength: 0x%02x "
			"UserData: \"%s\"\n", sms->mti, sms->vpf, sms->msg_ref,
			sms->pid, sms->dcs, sms->dest_addr, sms->ud_len,
			sms->alphabet == DCS_7BIT_DEFAULT ? sms->decoded : hexdump(sms->user_data, sms->ud_len));

	dispatch_signal(SS_SMS, 0, sms);

	gsms->sender = msg->lchan->subscr;
	/* FIXME: sender refcount */

	/* determine gsms->receiver based on dialled number */
	gsms->receiver = subscr_get_by_extension(bts->network, sms->dest_addr);
	if (!gsms->receiver) {
		rc = 1; /* cause 1: unknown subscriber */
		goto out;
	}

	if (sms->user_data)
		strncpy(gsms->text, sms->decoded, sizeof(gsms->text));

	switch (sms->mti) {
	case GSM340_SMS_SUBMIT_MS2SC:
		/* MS is submitting a SMS */
		rc = gsm340_rx_sms_submit(msg, sms, gsms);
		break;
	case GSM340_SMS_COMMAND_MS2SC:
	case GSM340_SMS_DELIVER_REP_MS2SC:
		DEBUGP(DSMS, "Unimplemented MTI 0x%02x\n", sms->mti);
		break;
	default:
		DEBUGP(DSMS, "Undefined MTI 0x%02x\n", sms->mti);
		break;
	}

out:
	talloc_free(gsms);
	talloc_free(sms);

	return rc;
}

static int gsm411_send_rp_ack(struct gsm_lchan *lchan, u_int8_t trans_id,
		u_int8_t msg_ref)
{
	struct msgb *msg = gsm411_msgb_alloc();
	struct gsm48_hdr *gh;
	struct gsm411_rp_hdr *rp;

	msg->lchan = lchan;

	gh = (struct gsm48_hdr *) msgb_put(msg, sizeof(*gh));
	// Outgoing needs the highest bit set
	gh->proto_discr = GSM48_PDISC_SMS | trans_id<<4 | 0x80;
	gh->msg_type = GSM411_MT_CP_DATA;

	rp = (struct gsm411_rp_hdr *)msgb_put(msg, sizeof(*rp));
	rp->len = 2;
	rp->msg_type = GSM411_MT_RP_ACK_MT;
	rp->msg_ref = msg_ref;

	DEBUGP(DSMS, "TX: SMS RP ACK\n");

	return gsm0411_sendmsg(msg);
}

static int gsm411_send_rp_error(struct gsm_lchan *lchan, u_int8_t trans_id,
		u_int8_t msg_ref, u_int8_t cause)
{
	struct msgb *msg = gsm411_msgb_alloc();
	struct gsm48_hdr *gh;
	struct gsm411_rp_hdr *rp;

	msg->lchan = lchan;

	gh = (struct gsm48_hdr *) msgb_put(msg, sizeof(*gh));
	// Outgoing needs the highest bit set
	gh->proto_discr = GSM48_PDISC_SMS | trans_id<<4 | 0x80;
	gh->msg_type = GSM411_MT_CP_DATA;

	rp = (struct gsm411_rp_hdr *)msgb_put(msg, sizeof(*rp));
	rp->msg_type = GSM411_MT_RP_ERROR_MT;
	rp->msg_ref = msg_ref;
	msgb_tv_put(msg, 1, cause);

	DEBUGP(DSMS, "TX: SMS RP ERROR (cause %02d)\n", cause);

	return gsm0411_sendmsg(msg);
}

/* Receive a 04.11 TPDU inside RP-DATA / user data */
static int gsm411_rx_rp_ud(struct msgb *msg, struct gsm411_rp_hdr *rph,
			  u_int8_t src_len, u_int8_t *src,
			  u_int8_t dst_len, u_int8_t *dst,
			  u_int8_t tpdu_len, u_int8_t *tpdu)
{
	struct gsm48_hdr *gh = msgb_l3(msg);
	u_int8_t trans_id = gh->proto_discr >> 4;
	int rc = 0;

	if (src_len && src)
		DEBUGP(DSMS, "RP-DATA (MO) with SRC ?!?\n");

	if (!dst_len || !dst || !tpdu_len || !tpdu) {
		DEBUGP(DSMS, "RP-DATA (MO) without DST or TPDU ?!?\n");
		return -EIO;
	}
	msg->smsh = tpdu;

	DEBUGP(DSMS, "DST(%u,%s)\n", dst_len, hexdump(dst, dst_len));
	//return gsm411_send_rp_error(msg->lchan, trans_id, rph->msg_ref, rc);

	rc = gsm340_rx_tpdu(msg);
	if (rc == 0)
		return gsm411_send_rp_ack(msg->lchan, trans_id, rph->msg_ref);
	else if (rc > 0)
		return gsm411_send_rp_error(msg->lchan, trans_id, rph->msg_ref, rc);
	else
		return rc;
}

/* Receive a 04.11 RP-DATA message in accordance with Section 7.3.1.2 */
static int gsm411_rx_rp_data(struct msgb *msg, struct gsm411_rp_hdr *rph)
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

	DEBUGP(DSMS, "RX_RP-DATA: src_len=%u, dst_len=%u ud_len=%u\n", src_len, dst_len, rpud_len);
	return gsm411_rx_rp_ud(msg, rph, src_len, src, dst_len, dst,
				rpud_len, rp_ud);
}

static int gsm411_rx_cp_data(struct msgb *msg, struct gsm48_hdr *gh)
{
	struct gsm411_rp_hdr *rp_data = (struct gsm411_rp_hdr*)&gh->data;
	u_int8_t msg_type =  rp_data->msg_type & 0x07;
	int rc = 0;

	switch (msg_type) {
	case GSM411_MT_RP_DATA_MO:
		DEBUGP(DSMS, "SMS RP-DATA (MO)\n");
		rc = gsm411_rx_rp_data(msg, rp_data);
		break;
	case GSM411_MT_RP_ACK_MO:
		/* Acnkowledgement to MT RP_DATA */
	case GSM411_MT_RP_ERROR_MO:
		/* Error in response to MT RP_DATA */
	case GSM411_MT_RP_SMMA_MO:
		/* MS tells us that it has memory for more SMS, we need
		 * to check if we have any pending messages for it and then
		 * transfer those */
		DEBUGP(DSMS, "Unimplemented RP type 0x%02x\n", msg_type);
		break;
	default:
		DEBUGP(DSMS, "Invalid RP type 0x%02x\n", msg_type);
		break;
	}

	return rc;
}

int gsm0411_rcv_sms(struct msgb *msg)
{
	struct gsm48_hdr *gh = msgb_l3(msg);
	u_int8_t msg_type = gh->msg_type;
	int rc = 0;

	switch(msg_type) {
	case GSM411_MT_CP_DATA:
		DEBUGP(DSMS, "SMS CP-DATA\n");
		rc = gsm411_rx_cp_data(msg, gh);
		break;
	case GSM411_MT_CP_ACK:
		DEBUGP(DSMS, "SMS CP-ACK\n");
		break;
	case GSM411_MT_CP_ERROR:
		DEBUGP(DSMS, "SMS CP-ERROR, cause 0x%02x\n", gh->data[0]);
		break;
	default:
		DEBUGP(DSMS, "Unimplemented CP msg_type: 0x%02x\n", msg_type);
		break;
	}


	return rc;
}

/* Test TPDU - 25c3 welcome */
#if 0
static u_int8_t tpdu_test[] = {
	0x04, 0x04, 0x81, 0x32, 0x24, 0x00, 0x00, 0x80, 0x21, 0x92, 0x90, 0x32,
	0x24, 0x40, 0x4D, 0xB2, 0xDA, 0x70, 0xD6, 0x9A, 0x97, 0xE5, 0xF6, 0xF4,
	0xB8, 0x0C, 0x0A, 0xBB, 0xDD, 0xEF, 0xBA, 0x7B, 0x5C, 0x6E, 0x97, 0xDD,
	0x74, 0x1D, 0x08, 0xCA, 0x2E, 0x87, 0xE7, 0x65, 0x50, 0x98, 0x4E, 0x2F,
	0xBB, 0xC9, 0x20, 0x3A, 0xBA, 0x0C, 0x3A, 0x4E, 0x9B, 0x20, 0x7A, 0x98,
	0xBD, 0x06, 0x85, 0xE9, 0xA0, 0x58, 0x4C, 0x37, 0x83, 0x81, 0xD2, 0x6E,
	0xD0, 0x34, 0x1C, 0x66, 0x83, 0x62, 0x21, 0x90, 0xAE, 0x95, 0x02
};
#else
/* Test TPDU - ALL YOUR */
static u_int8_t tpdu_test[] = {
	0x04, 0x04, 0x81, 0x32, 0x24, 0x00, 0x00, 0x80, 0x21, 0x03, 0x41, 0x24,
	0x32, 0x40, 0x1F, 0x41, 0x26, 0x13, 0x94, 0x7D, 0x56, 0xA5, 0x20, 0x28,
	0xF2, 0xE9, 0x2C, 0x82, 0x82, 0xD2, 0x22, 0x48, 0x58, 0x64, 0x3E, 0x9D,
	0x47, 0x10, 0xF5, 0x09, 0xAA, 0x4E, 0x01
};
#endif

int gsm0411_send_sms(struct gsm_lchan *lchan, struct sms_deliver *sms)
{
	struct msgb *msg = gsm411_msgb_alloc();
	struct gsm48_hdr *gh;
	struct gsm411_rp_hdr *rp;
	u_int8_t *data;

	msg->lchan = lchan;

	gh = (struct gsm48_hdr *) msgb_put(msg, sizeof(*gh));
	gh->proto_discr = GSM48_PDISC_SMS;
	gh->msg_type = GSM411_MT_CP_DATA;

	rp = (struct gsm411_rp_hdr *)msgb_put(msg, sizeof(*rp));
	rp->len = sizeof(tpdu_test) + 10;
	rp->msg_type = GSM411_MT_RP_DATA_MT;
	rp->msg_ref = 42; /* FIXME: Choose randomly */
	/* Hardcode OA for now */
	data = (u_int8_t *)msgb_put(msg, 8);
	data[0] = 0x07;
	data[1] = 0x91;
	data[2] = 0x44;
	data[3] = 0x77;
	data[4] = 0x58;
	data[5] = 0x10;
	data[6] = 0x06;
	data[7] = 0x50;
	data = (u_int8_t *)msgb_put(msg, 1);
	data[0] = 0;

	/* FIXME: Hardcoded for now */
	//smslen = gsm0411_tpdu_from_sms(tpdu, sms);

	/* RPDU length */
	data = (u_int8_t *)msgb_put(msg, 1);
	data[0] = sizeof(tpdu_test);

	data = (u_int8_t *)msgb_put(msg, sizeof(tpdu_test));

	//memcpy(data, tpdu, smslen);
	memcpy(data, tpdu_test, sizeof(tpdu_test));

	DEBUGP(DSMS, "TX: SMS SUBMIT\n");

	return gsm0411_sendmsg(msg);
}
