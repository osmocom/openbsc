/* GTP Hub Implementation */

/* (C) 2015 by sysmocom s.f.m.c. GmbH <info@sysmocom.de>
 * All Rights Reserved
 *
 * gtphub_ext.c -- ext means extern. This file is kept separate so that these
 * functions can be wrapped for gtphub_test.c. When a function and its callers
 * are in the same compilational unit, the wrappability may be optimized away.
 *
 * Author: Neels Hofmeyr
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
 */

#include <string.h>
#include <unistd.h>

#include <openbsc/gtphub.h>
#include <openbsc/debug.h>

#include <osmocom/core/utils.h>
#include <osmocom/gsm/apn.h>

/* TODO split GRX ares from sgsn into a separate struct and allow use without
 * globals. */
#include <openbsc/sgsn.h>
extern struct sgsn_instance *sgsn;

struct sgsn_instance sgsn_inst = { 0 };
struct sgsn_instance *sgsn = &sgsn_inst;

extern void *osmo_gtphub_ctx;

int gtphub_ares_init(struct gtphub *hub)
{
	return sgsn_ares_init(sgsn);
}

struct ggsn_lookup {
	struct llist_head entry;
	struct expiring_item expiry_entry;

	struct gtphub *hub;

	char imsi_str[GSM_IMSI_LENGTH];
	char apn_ni_str[GSM_APN_LENGTH];
	char apn_oi_str[GSM_APN_LENGTH];
	int have_3dig_mnc;
};

static int start_ares_query(struct ggsn_lookup *lookup);

static void ggsn_lookup_cb(void *arg, int status, int timeouts, struct hostent *hostent)
{
	struct ggsn_lookup *lookup = arg;

	if (status != ARES_SUCCESS) {
		LOGP(DGTPHUB, LOGL_ERROR, "DNS query failed.\n");

		/* Need to try with three digits now */
		if (!lookup->have_3dig_mnc) {
			lookup->have_3dig_mnc = 1;
			if (start_ares_query(lookup) == 0)
				return;
		}

		LOGP(DGTPHUB, LOGL_ERROR, "Failed to resolve GGSN.\n");
		goto remove_from_queue;
	}

	struct gsn_addr resolved_addr;
	if (hostent->h_length > sizeof(resolved_addr.buf)) {
		LOGP(DGTPHUB, LOGL_ERROR, "Addr size too large: %d > %d\n",
		     (int)hostent->h_length, (int)sizeof(resolved_addr.buf));
		goto remove_from_queue;
	}

	/* Get the first addr from the list */
	char *addr0 = hostent->h_addr_list[0];
	if (!addr0) {
		LOGP(DGTPHUB, LOGL_ERROR, "No host address.\n");
		goto remove_from_queue;
	}

	memcpy(&resolved_addr.buf, addr0, hostent->h_length);
	resolved_addr.len = hostent->h_length;

	gtphub_resolved_ggsn(lookup->hub, lookup->apn_oi_str, &resolved_addr,
			     gtphub_now());

remove_from_queue:
	expiring_item_del(&lookup->expiry_entry);
}

static void make_addr_str(struct ggsn_lookup *lookup)
{
	char *apn_oi_str;
	apn_oi_str = osmo_apn_qualify_from_imsi(lookup->imsi_str,
						lookup->apn_ni_str,
						lookup->have_3dig_mnc);
	strncpy(lookup->apn_oi_str, apn_oi_str, sizeof(lookup->apn_oi_str));
	lookup->apn_oi_str[sizeof(lookup->apn_oi_str)-1] = '\0';
}

static int start_ares_query(struct ggsn_lookup *lookup)
{
	LOGP(DGTPHUB, LOGL_DEBUG, "Going to query %s\n", lookup->apn_oi_str);

	int rc = sgsn_ares_query(sgsn, lookup->apn_oi_str, ggsn_lookup_cb, &lookup);
	if (rc != 0)
		LOGP(DGTPHUB, LOGL_ERROR, "Failed to start ares query.\n");
	return rc;
}

static void ggsn_lookup_del_cb(struct expiring_item *expi)
{
	struct ggsn_lookup *ggsn;
	ggsn = container_of(expi, struct ggsn_lookup, expiry_entry);

	ggsn->expiry_entry.del_cb = 0;
	expiring_item_del(expi);

	llist_del(&ggsn->entry);
	talloc_free(ggsn);
}

struct gtphub_peer_port *gtphub_resolve_ggsn_addr(struct gtphub *hub,
						  const char *imsi_str,
						  const char *apn_ni_str)
{
	struct ggsn_lookup *lookup = talloc_zero(osmo_gtphub_ctx, struct ggsn_lookup);

	lookup->hub = hub;

	strncpy(lookup->imsi_str, imsi_str, sizeof(lookup->imsi_str));
	lookup->imsi_str[sizeof(lookup->imsi_str)-1] = '\0';

	strncpy(lookup->apn_ni_str, apn_ni_str, sizeof(lookup->apn_ni_str));
	lookup->apn_ni_str[sizeof(lookup->apn_ni_str)-1] = '\0';

	make_addr_str(lookup);

	struct ggsn_lookup *active;
	llist_for_each_entry(active, &hub->ggsn_lookups, entry) {
		if (strncmp(active->apn_oi_str, lookup->apn_oi_str,
			    sizeof(lookup->apn_oi_str)) == 0) {
			/* A query already pending. Just tip our hat. */
			return NULL;
		}
	}

	struct gtphub_resolved_ggsn *resolved;
	llist_for_each_entry(resolved, &hub->resolved_ggsns, entry) {
		if (strncmp(resolved->apn_oi_str, lookup->apn_oi_str,
			    sizeof(lookup->apn_oi_str)) == 0) {
			/* Already resolved. */
			return resolved->peer;
		}
	}

	/* Kick off a resolution, but so far return nothing. The hope is that
	 * the peer will resend the request (a couple of times), and by then
	 * the GGSN will be resolved. */

	llist_add(&lookup->entry, &hub->ggsn_lookups);

	lookup->expiry_entry.del_cb = ggsn_lookup_del_cb;
	expiry_add(&hub->expire_seq_maps, &lookup->expiry_entry, gtphub_now());

	start_ares_query(lookup);

	return NULL;
}
