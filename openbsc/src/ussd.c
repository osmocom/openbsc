/* Network-specific handling of mobile-originated USSDs. */

/* (C) 2008-2009 by Harald Welte <laforge@gnumonks.org>
 * (C) 2008, 2009 by Holger Hans Peter Freyther <zecke@selfish.org>
 * (C) 2009 by Mike Haben <michael.haben@btinternet.com>
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

/* This module defines the network-specific handling of mobile-originated
   USSD messages. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include <openbsc/gsm_04_80.h>
#include <openbsc/gsm_subscriber.h>
#include <openbsc/debug.h>

/* Declarations of USSD strings to be recognised */
const char USSD_TEXT_OWN_NUMBER[] = "*#100#";

/* A network-specific handler function */
static int send_own_number(const struct msgb *msg, const struct ussd_request *req)
{
	char *own_number = msg->lchan->conn.subscr->extension;
	char response_string[GSM_EXTENSION_LENGTH + 20];

	/* Need trailing CR as EOT character */
	snprintf(response_string, sizeof(response_string), "Your extension is %s\r", own_number);
	return gsm0480_send_ussd_response(msg, response_string, req);
}

static int handle_rcv_uss_req(struct msgb *msg, struct ussd_request *req)
{
	if (req->unstructured.text[0] == 0xFF)  /* Release-Complete */
		return 0;

	if (strstr(USSD_TEXT_OWN_NUMBER, req->unstructured.text) != NULL) {
		LOGP(DMM, LOGL_INFO, "USSD: Own number requested\n");
		return send_own_number(msg, req);
	} else {
		LOGP(DMM, LOGL_NOTICE, "Unhandled USSD %s\n", req->unstructured.text);
		return gsm0480_send_ussd_reject(msg, req);
	}
}

static int handle_rcv_interrogate(struct msgb *msg, struct ussd_request *req)
{
	uint8_t ss_status;

	switch (req->interrogate.ss_code) {
	case MAP_SS_CODE_CLIP:
	case MAP_SS_CODE_COLP:
		ss_status = SS_STATUS_P_BIT | SS_STATUS_R_BIT | SS_STATUS_A_BIT;
		break;
	case MAP_SS_CODE_CLIR:
	case MAP_SS_CODE_COLR:
		ss_status = SS_STATUS_P_BIT | SS_STATUS_R_BIT;
		break;
	default:
		ss_status = 0;
		break;
	}

	return gsm0480_send_ss_interr_resp(msg, ss_status, req);
}

/* Entrypoint - handler function common to all mobile-originated USSDs */
int handle_rcv_ussd(struct msgb *msg)
{
	struct ussd_request req;

	gsm0480_decode_ussd_request(msg, &req);

	switch (req.opcode) {
	case GSM0480_OP_CODE_INTERROGATE_SS:
		return handle_rcv_interrogate(msg, &req);
	case GSM0480_OP_CODE_USS_REQUEST:
		return handle_rcv_uss_req(msg, &req);
	default:
		LOGP(DMM, LOGL_NOTICE, "Unknown SS opcode 0x%02x\n", req.opcode);
		break;
	}
	return 0;
}


