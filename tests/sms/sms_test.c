/*
 * (C) 2008 by Daniel Willmann <daniel@totalueberwachung.de>
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
#include <sys/types.h>
#include <openbsc/debug.h>
#include <openbsc/msgb.h>
#include <openbsc/gsm_04_11.h>
#include <openbsc/gsm_04_08.h>

/* SMS data from MS starting with layer 3 header */
static u_int8_t sms_data[] = {
  0x39,	0x01, 0x1a, 0x00, 0x01, 0x00, 0x07, 0x91, 0x55, 0x11,
  0x18, 0x31, 0x28, 0x00, 0x0e, 0x31, 0x20, 0x04, 0x81, 0x21,
  0x43, 0x00, 0x00, 0xff, 0x04, 0xd4, 0xf2, 0x9c, 0x0e
};

int main(int argc, char** argv)
{
	DEBUGP(DSMS, "SMS testing\n");
	struct msgb *msg;
	u_int8_t *sms;

	/* Setup SMS msgb */
	msg = msgb_alloc(sizeof(sms_data));
	sms = msgb_put(msg, sizeof(sms_data));

	memcpy(sms, sms_data, sizeof(sms_data));
	msg->l3h = sms;

	gsm0411_rcv_sms(msg);
}
