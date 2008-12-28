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
#include <openbsc/gsm_04_11.h>
#include <openbsc/gsm_04_08.h>
#include <openbsc/abis_rsl.h>

static int gsm411_cp_data(struct msgb *msg)
{
	struct gsm48_hdr *gh = msgb_l3(msg);
	int rc = 0;

	struct gsm411_rp_data_hdr *rp_data = (struct gsm411_rp_data_hdr*)&gh->data;
	u_int8_t msg_type =  rp_data->msg_type & 0x07;

	switch (msg_type) {
	case GSM411_MT_RP_DATA_MO:
    DEBUGP(DSMS, "SMS RP-DATA (MO)\n");

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

