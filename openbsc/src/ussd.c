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
#include <openbsc/osmo_msc.h>

/* Declarations of USSD strings to be recognised */
const char USSD_TEXT_OWN_NUMBER[] = "*#100#";

/* Forward declarations of network-specific handler functions */
static int send_own_number(struct gsm_subscriber_connection *conn, const struct msgb *msg, const struct ussd_request *req);


/* Entrypoint - handler function common to all mobile-originated USSDs */
int handle_rcv_ussd(struct gsm_subscriber_connection *conn, struct msgb *msg)
{
	int rc;
	struct ussd_request req;

	memset(&req, 0, sizeof(req));
	rc = gsm0480_decode_ussd_request(msg, &req);
	if (req.text[0] == 0xFF)  /* Release-Complete */
		return 0;

	if (strstr(USSD_TEXT_OWN_NUMBER, req.text) != NULL) {
		DEBUGP(DMM, "USSD: Own number requested\n");
		rc = send_own_number(conn, msg, &req);
	} else {
		DEBUGP(DMM, "Unhandled USSD %s\n", req.text);
		rc = gsm0480_send_ussd_reject(conn, msg, &req);
	}

	/* check if we can release it */
	msc_release_connection(conn);
	return rc;
}

/* A network-specific handler function */
static int send_own_number(struct gsm_subscriber_connection *conn, const struct msgb *msg, const struct ussd_request *req)
{
	char *own_number = conn->subscr->extension;
	char response_string[GSM_EXTENSION_LENGTH + 20];

	/* Need trailing CR as EOT character */
	snprintf(response_string, sizeof(response_string), "Your extension is %s\r", own_number);
	return gsm0480_send_ussd_response(conn, msg, response_string, req);
}
