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
	gh->proto_discr = GSM48_PDISC_SMS | trans_id<<4;
	gh->msg_type = GSM411_MT_CP_ACK;

	rp = (struct gsm411_rp_hdr *)msgb_put(msg, sizeof(*rp));
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
	gh->proto_discr = GSM48_PDISC_SMS | trans_id<<4;
	gh->msg_type = GSM411_MT_CP_ERROR;

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
	case GSM411_MT_CP_ERROR:
	default:
		DEBUGP(DSMS, "Unimplemented CP msg_type: 0x%02x\n", msg_type);
		break;
	}


	return rc;
}

