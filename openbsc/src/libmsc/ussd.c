/* Network-specific handling of mobile-originated USSDs. */

/* (C) 2008-2009 by Harald Welte <laforge@gnumonks.org>
 * (C) 2008, 2009 by Holger Hans Peter Freyther <zecke@selfish.org>
 * (C) 2009 by Mike Haben <michael.haben@btinternet.com>
 *
 * All Rights Reserved
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
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

/* A network-specific handler function */
static int send_own_number(struct gsm_subscriber_connection *conn, const struct msgb *msg, const struct ussd_request *req)
{
	char *own_number = conn->subscr->extension;
	char response_string[GSM_EXTENSION_LENGTH + 20];

	DEBUGP(DMM, "USSD: Own number requested\n");

	/* Need trailing CR as EOT character */
	snprintf(response_string, sizeof(response_string), "Your extension is %s", own_number);
	return gsm0480_send_ussd_response(conn, msg, response_string, req);
}

/* A network-specific handler function */
static int send_own_imsi(struct gsm_subscriber_connection *conn, const struct msgb *msg, const struct ussd_request *req)
{
	char *own_imsi = conn->subscr->imsi;
	char response_string[GSM_IMSI_LENGTH + 20];

	DEBUGP(DMM, "USSD: Own IMSI requested\n");

	/* Need trailing CR as EOT character */
	snprintf(response_string, sizeof(response_string), "Your IMSI is %s", own_imsi);
	return gsm0480_send_ussd_response(conn, msg, response_string, req);
}

static struct ussd_function {
	char *request;
	int (*response)(struct gsm_subscriber_connection *conn, const struct msgb *msg, const struct ussd_request *req);
} ussd_function[] = {
	{ "*#100#", send_own_number },
	{ "*#101#", send_own_imsi },
	{ NULL, NULL }
};

/* Entrypoint - handler function common to all mobile-originated USSDs */
int handle_rcv_ussd(struct gsm_subscriber_connection *conn, struct msgb *msg)
{
	int rc, i;
	struct ussd_request req;
	struct gsm48_hdr *gh;

	memset(&req, 0, sizeof(req));
	gh = msgb_l3(msg);
	rc = gsm0480_decode_ussd_request(gh, msgb_l3len(msg), &req);
	if (req.text[0] == 0xFF)  /* Release-Complete */
		return 0;

	for (i = 0; ussd_function[i].request; i++) {
		if (!strcmp(ussd_function[i].request, (const char *)req.text)) {
			rc = ussd_function[i].response(conn, msg, &req);
			break;
		}
	}

	if (!ussd_function[i].request) {
		DEBUGP(DMM, "Unhandled USSD %s\n", req.text);
		rc = gsm0480_send_ussd_reject(conn, msg, &req);
	}

	/* check if we can release it */
	msc_release_connection(conn);
	return rc;
}

