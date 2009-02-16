/* Point-to-Point (PP) Short Message Service (SMS)
 * Support on Mobile Radio Interface
 * 3GPP TS 04.11 version 7.1.0 Release 1998 / ETSI TS 100 942 V7.1.0 */

/* (C) 2008 by Daniel Willmann <daniel@totalueberwachung.de>
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
#include <openbsc/debug.h>
#include <openbsc/gsm_data.h>
#include <openbsc/gsm_subscriber.h>
#include <openbsc/gsm_04_11.h>
#include <openbsc/gsm_04_08.h>
#include <openbsc/abis_rsl.h>
#include <openbsc/signal.h>

#define GSM411_ALLOC_SIZE	1024
#define GSM411_ALLOC_HEADROOM	128

struct msgb *gsm411_msgb_alloc(void)
{
	return msgb_alloc_headroom(GSM411_ALLOC_SIZE, GSM411_ALLOC_HEADROOM);
}

int gsm0411_sendmsg(struct msgb *msg)
{
	if (msg->lchan)
		msg->trx = msg->lchan->ts->trx;

	msg->l3h = msg->data;

	return rsl_data_request(msg, 0);
}

static char *gsm411_7bit_decode(u_int8_t *user_data, u_int8_t length)
{
	u_int8_t d_off = 0, b_off = 0;
	u_int8_t i;
	char *text = malloc(length+1);

	for (i=0;i<length;i++) {
		text[i] = ((user_data[d_off] + (user_data[d_off+1]<<8)) & (0x7f<<b_off))>>b_off;
		b_off += 7;
		if (b_off >= 8) {
			d_off += 1;
			b_off -= 8;
		}
	}
	text[i] = 0;
	return text;
}

#if 0
static u_int8_t gsm0411_tpdu_from_sms(u_int8_t *tpdu, struct sms_deliver *sms)
{
}
#endif

static int gsm411_sms_submit_from_msgb(struct msgb *msg)
{
	u_int8_t *smsp = msgb_sms(msg);
	struct sms_submit *sms;

	sms = malloc(sizeof(*sms));
	sms->mti = *smsp & 0x03;
	sms->mms = !!(*smsp & 0x04);
	sms->vpf = (*smsp & 0x18) >> 3;
	sms->sri = !!(*smsp & 0x20);
	sms->udhi= !!(*smsp & 0x40);
	sms->rp  = !!(*smsp & 0x80);

	smsp++;
	sms->msg_ref = *smsp++;

	/* Skip destination address for now */
	smsp += 2 + *smsp/2 + *smsp%2;

	sms->pid = *smsp++;
	sms->dcs = *smsp++;
	switch (sms->vpf)
	{
	case 2: /* relative */
		sms->vp = *smsp++;
		break;
	default:
		DEBUGP(DSMS, "SMS Validity period not implemented: 0x%02x\n",
				sms->vpf);
	}
	sms->ud_len = *smsp++;

	sms->user_data = (u_int8_t *)gsm411_7bit_decode(smsp, sms->ud_len);

	DEBUGP(DSMS, "SMS:\nMTI: 0x%02x, VPF: 0x%02x, MR: 0x%02x\n"
			"PID: 0x%02x, DCS: 0x%02x, UserDataLength: 0x%02x\n"
			"UserData: \"%s\"\n", sms->mti, sms->vpf, sms->msg_ref,
			sms->pid, sms->dcs, sms->ud_len, sms->user_data);

	dispatch_signal(SS_SMS, 0, sms);

	free(sms);

	return 0;
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

#if 0
static int gsm411_send_rp_error(struct gsm_lchan *lchan, u_int8_t trans_id,
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
	rp->msg_type = GSM411_MT_RP_ERROR_MT;
	rp->msg_ref = msg_ref;

	DEBUGP(DSMS, "TX: SMS RP ERROR\n");

	return gsm0411_sendmsg(msg);
}
#endif

static int gsm411_cp_data(struct msgb *msg)
{
	struct gsm48_hdr *gh = msgb_l3(msg);
	int rc = 0;

	struct gsm411_rp_hdr *rp_data = (struct gsm411_rp_hdr*)&gh->data;
	u_int8_t msg_type =  rp_data->msg_type & 0x07;

	switch (msg_type) {
	case GSM411_MT_RP_DATA_MO:
		DEBUGP(DSMS, "SMS RP-DATA (MO)\n");
		/* Skip SMSC no and RP-UD length */
		msg->smsh = &rp_data->data[1] + rp_data->data[1] + 2;
		gsm411_sms_submit_from_msgb(msg);
		gsm411_send_rp_ack(msg->lchan, (gh->proto_discr & 0xf0)>>4, rp_data->msg_ref);
		break;
	default:
		DEBUGP(DSMS, "Unimplemented RP type 0x%02x\n", msg_type);
		break;
	}

	return rc;
}

int gsm0411_rcv_sms(struct msgb *msg)
{
	struct gsm48_hdr *gh = msgb_l3(msg);
	u_int8_t msg_type = gh->msg_type;
	int rc = 0;

	DEBUGP(DSMS, "SMS Message\n");

	switch(msg_type) {
	case GSM411_MT_CP_DATA:
		DEBUGP(DSMS, "SMS CP-DATA\n");
		rc = gsm411_cp_data(msg);
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

