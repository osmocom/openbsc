/* Network-specific handling of mobile-originated USSDs. */

/* (C) 2008-2009 by Harald Welte <laforge@gnumonks.org>
 * (C) 2008, 2009, 2010 by Holger Hans Peter Freyther <zecke@selfish.org>
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


#include <osmocore/talloc.h>

#include <osmocom/vty/vty.h>

struct ussd_mapping {
	struct llist_head entry;
	const char *ussd_number;

	uint8_t **l3_frames;
	uint8_t *l3_sizes;
	int frame_sizes;
};

LLIST_HEAD(mapping_list);

/* Declarations of USSD strings to be recognised */
const char USSD_TEXT_OWN_NUMBER[] = "*#100#";

/* Forward declarations of network-specific handler functions */
static int send_own_number(struct gsm_subscriber_connection *conn, const struct msgb *msg, const struct ussd_request *req);
static int ussd_send_custom(struct gsm_subscriber_connection *, struct msgb *, struct ussd_request *);


/* Entrypoint - handler function common to all mobile-originated USSDs */
int handle_rcv_ussd(struct gsm_subscriber_connection *conn, struct msgb *msg)
{
	int rc;
	struct ussd_request req;
	struct gsm48_hdr *gh;

	memset(&req, 0, sizeof(req));
	gh = msgb_l3(msg);
	rc = gsm0480_decode_ussd_request(gh, msgb_l3len(msg), &req);
	if (req.text[0] == 0xFF)  /* Release-Complete */
		return 0;

	if (strstr(USSD_TEXT_OWN_NUMBER, req.text) != NULL) {
		DEBUGP(DMM, "USSD: Own number requested\n");
		rc = send_own_number(conn, msg, &req);
	} else if (ussd_send_custom(conn, msg, &req)) {
		LOGP(DMM, LOGL_NOTICE, "Sending custom L3 message for USSD.\n");
		rc = 1;
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


static int ussd_send_custom(struct gsm_subscriber_connection *conn,
			    struct msgb *msg, struct ussd_request *req)
{
	struct msgb *out;
	uint8_t* data;
	struct ussd_mapping *map;

	llist_for_each_entry(map, &mapping_list, entry) {
		if (strstr(map->ussd_number, req->text) == NULL)
			continue;

		/* if we have more than one msg */
		if (map->frame_sizes > 1) {
			conn->ussd_sequence = 1;
			conn->ussd_number = map->ussd_number;
		}

		out = gsm48_msgb_alloc();
		if (!out)
			return -1;


		out->lchan = msg->lchan;
		data = msgb_put(out, map->l3_sizes[0]);
		memcpy(data, map->l3_frames[0], map->l3_sizes[0]);
		gsm0808_submit_dtap(conn, out, 0, 0);
		return 1;
	}

	return 0;
}

extern struct gsm_network *bsc_gsmnet;
int ussd_parse_mapping(const char *number, const uint8_t *msg, int len)
{
	struct ussd_mapping *map;

	llist_for_each_entry(map, &mapping_list, entry) {
		if (strcmp(map->ussd_number, number) != 0)
			continue;

		LOGP(DINP, LOGL_ERROR, "NOT IMPLTELEMEND\n");	
#if 0
		map->l3_frames = talloc_realloc(map, map->l3_sizes, uint8_t, 
		map->l3_sizes = talloc_realloc;	

		map->l3_frames[map->frame_sizes] = talloc_array(map, uint8_t, len);
		memcpy(map->l3_frames[map->frame_sizes], msg, len);

		map->l3_sizes[map->frame_sizes] = len;
		map->frame_sizes += 1;
#endif
		return 0;
	}


	map = talloc_zero(bsc_gsmnet, struct ussd_mapping);
	if (!map)
		return -1;

	llist_add(&map->entry, &mapping_list);
	map->ussd_number = talloc_strdup(map, number);
	map->l3_frames = talloc_array(map, uint8_t*, 1);
	map->l3_sizes = talloc_array(map, uint8_t, 1);

	map->l3_frames[0] = talloc_array(map, uint8_t, len);
	memcpy(map->l3_frames[0], msg, len);
	map->l3_sizes[0] = len;
	map->frame_sizes += 1;

	return 0;
}

int ussd_clear_mapping(const char *number)
{
	struct ussd_mapping *map;

	llist_for_each_entry(map, &mapping_list, entry) {
		if (strcmp(map->ussd_number, number) == 0) {
			llist_del(&map->entry);
			talloc_free(map);
			return 0;
		}
	}

	return 0;
}


int ussd_call_reroute(struct gsm_subscriber_connection *conn, struct msgb *msg)
{
	struct ussd_mapping *map;

	if (!conn->ussd_sequence)
		return 0;

	/* check if the rule is still there, compare number */
	llist_for_each_entry(map, &mapping_list, entry) {
		if (conn->ussd_number == map->ussd_number) {
			return 1;
		}
	}

	return -0;
}

int ussd_dump_mapping(struct vty *vty)
{
	int i = 0;
	struct ussd_mapping *map;

	llist_for_each_entry(map, &mapping_list, entry) {
		vty_out(vty, "USSD Nr: %s nr_frames: %d%s",
			map->ussd_number, map->frame_sizes, VTY_NEWLINE);
		for (i = 0; i < map->frame_sizes; ++i)
			vty_out(vty, " %d: '%s'%s",
				i, hexdump(map->l3_frames[i], map->l3_sizes[i]), VTY_NEWLINE);
	}

	return 0;
}

int ussd_call_rx(struct gsm_subscriber_connection *conn, struct msgb *msg)
{
	LOGP(DINP, LOGL_ERROR, "NOT IMPLTELEMEND\n");	
	return -1;
}
