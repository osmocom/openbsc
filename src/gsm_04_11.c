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

#define GSM411_ALLOC_SIZE	1024
#define GSM411_ALLOC_HEADROOM	128

static struct msgb *gsm411_msgb_alloc(void)
{
	return msgb_alloc_headroom(GSM411_ALLOC_SIZE, GSM411_ALLOC_HEADROOM);
}

static int gsm0411_sendmsg(struct msgb *msg)
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

static u_int8_t gsm0411_tpdu_from_sms(u_int8_t *tpdu, struct sms_deliver *sms)
{
	u_int8_t len = 0;

}

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

	sms->user_data = gsm411_7bit_decode(smsp, sms->ud_len);

	DEBUGP(DSMS, "SMS:\nMTI: 0x%02x, VPF: 0x%02x, MR: 0x%02x\n"
			"PID: 0x%02x, DCS: 0x%02x, UserDataLength: 0x%02x\n"
			"UserData: \"%s\"\n", sms->mti, sms->vpf, sms->msg_ref,
			sms->pid, sms->dcs, sms->ud_len, sms->user_data);

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

/* Test TPDU */
static u_int8_t tpdu_test[] = {
	0x00, 0x01, 0x00, 0x04, 0x81, 0x32, 0x24, 0x00, 0x00, 0x24, 0xD7, 0x32, 0x7B, 0xFC, 0x6E, 0x97, 0x41, 0xF4, 0x37, 0x88, 0x8E, 0x2E, 0x83, 0x64, 0xB5, 0xE1, 0x0C, 0x74, 0x9C, 0x36, 0x41, 0xF4, 0xF2, 0x9C, 0x0E, 0x72, 0x97, 0xE9, 0xF7, 0xB7, 0x7C, 0x0D
};

int gsm0411_send_sms(struct gsm_lchan *lchan, struct sms_deliver *sms)
{
	struct msgb *msg = gsm411_msgb_alloc();
	struct gsm48_hdr *gh;
	struct gsm411_rp_hdr *rp;
	u_int8_t *data, *tpdu, smslen;

	msg->lchan = lchan;

	gh = (struct gsm48_hdr *) msgb_put(msg, sizeof(*gh));
	gh->proto_discr = GSM48_PDISC_SMS;
	gh->msg_type = GSM411_MT_CP_DATA;

	rp = (struct gsm411_rp_hdr *)msgb_put(msg, sizeof(*rp));
	rp->msg_type = GSM411_MT_RP_DATA_MT;
	rp->msg_ref = 42; /* FIXME: Choose randomly */
	/* No OA or DA for now */
	data = (u_int8_t *)msgb_put(msg, 1);
	data[0] = 0;
	data = (u_int8_t *)msgb_put(msg, 1);
	data[0] = 0;

	/* FIXME: Hardcoded for now */
	smslen = gsm0411_tpdu_from_sms(tpdu, sms);

	data = (u_int8_t *)msgb_put(msg, sizeof(tpdu_test));

	//memcpy(data, tpdu, smslen);
	memcpy(data, tpdu_test, sizeof(tpdu_test));

	free(tpdu);

	DEBUGP(DSMS, "TX: SMS SUBMIT\n");

	return gsm0411_sendmsg(msg);
}

