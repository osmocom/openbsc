/* SCCP patching and handling routines */
/*
 * (C) 2010 by Holger Hans Peter Freyther <zecke@selfish.org>
 * (C) 2010 by On-Waves
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

#include <openbsc/debug.h>
#include <openbsc/bsc_nat.h>
#include <openbsc/bsc_nat_sccp.h>

#include <osmocom/sccp/sccp.h>

#include <osmocom/core/talloc.h>

#include <string.h>
#include <time.h>

static int equal(struct sccp_source_reference *ref1, struct sccp_source_reference *ref2)
{
	return memcmp(ref1, ref2, sizeof(*ref1)) == 0;
}

/*
 * SCCP patching below
 */

/* check if we are using this ref for patched already */
static int sccp_ref_is_free(struct sccp_source_reference *ref, struct bsc_nat *nat)
{
	struct nat_sccp_connection *conn;

	llist_for_each_entry(conn, &nat->sccp_connections, list_entry) {
		if (equal(ref, &conn->patched_ref))
			return -1;
	}

	return 0;
}

/* copied from sccp.c */
static int assign_src_local_reference(struct sccp_source_reference *ref, struct bsc_nat *nat)
{
	static uint32_t last_ref = 0x50000;
	int wrapped = 0;

	do {
		struct sccp_source_reference reference;
		reference.octet1 = (last_ref >>  0) & 0xff;
		reference.octet2 = (last_ref >>  8) & 0xff;
		reference.octet3 = (last_ref >> 16) & 0xff;

		++last_ref;
		/* do not use the reversed word and wrap around */
		if ((last_ref & 0x00FFFFFF) == 0x00FFFFFF) {
			LOGP(DNAT, LOGL_NOTICE, "Wrapped searching for a free code\n");
			last_ref = 0;
			++wrapped;
		}

		if (sccp_ref_is_free(&reference, nat) == 0) {
			*ref = reference;
			return 0;
		}
	} while (wrapped != 2);

	LOGP(DNAT, LOGL_ERROR, "Finding a free reference failed\n");
	return -1;
}

struct nat_sccp_connection *create_sccp_src_ref(struct bsc_connection *bsc,
					     struct bsc_nat_parsed *parsed)
{
	struct nat_sccp_connection *conn;

	/* Some commercial BSCs like to reassign there SRC ref */
	llist_for_each_entry(conn, &bsc->nat->sccp_connections, list_entry) {
		if (conn->bsc != bsc)
			continue;
		if (!equal(parsed->src_local_ref, &conn->real_ref))
			continue;

		/* the BSC has reassigned the SRC ref and we failed to keep track */
		memset(&conn->remote_ref, 0, sizeof(conn->remote_ref));
		if (assign_src_local_reference(&conn->patched_ref, bsc->nat) != 0) {
			LOGP(DNAT, LOGL_ERROR, "BSC %d reused src ref: %d and we failed to generate a new id.\n",
			     bsc->cfg->nr, sccp_src_ref_to_int(parsed->src_local_ref));
			bsc_mgcp_dlcx(conn);
			llist_del(&conn->list_entry);
			talloc_free(conn);
			return NULL;
		} else {
			clock_gettime(CLOCK_MONOTONIC, &conn->creation_time);
			bsc_mgcp_dlcx(conn);
			return conn;
		}
	}


	conn = talloc_zero(bsc->nat, struct nat_sccp_connection);
	if (!conn) {
		LOGP(DNAT, LOGL_ERROR, "Memory allocation failure.\n");
		return NULL;
	}

	conn->bsc = bsc;
	clock_gettime(CLOCK_MONOTONIC, &conn->creation_time);
	conn->real_ref = *parsed->src_local_ref;
	if (assign_src_local_reference(&conn->patched_ref, bsc->nat) != 0) {
		LOGP(DNAT, LOGL_ERROR, "Failed to assign a ref.\n");
		talloc_free(conn);
		return NULL;
	}

	bsc_mgcp_init(conn);
	llist_add_tail(&conn->list_entry, &bsc->nat->sccp_connections);
	rate_ctr_inc(&bsc->cfg->stats.ctrg->ctr[BCFG_CTR_SCCP_CONN]);
	osmo_counter_inc(bsc->cfg->nat->stats.sccp.conn);

	LOGP(DNAT, LOGL_DEBUG, "Created 0x%x <-> 0x%x mapping for con %p\n",
	     sccp_src_ref_to_int(&conn->real_ref),
	     sccp_src_ref_to_int(&conn->patched_ref), bsc);

	return conn;
}

int update_sccp_src_ref(struct nat_sccp_connection *sccp, struct bsc_nat_parsed *parsed)
{
	if (!parsed->dest_local_ref || !parsed->src_local_ref) {
		LOGP(DNAT, LOGL_ERROR, "CC MSG should contain both local and dest address.\n");
		return -1;
	}

	sccp->remote_ref = *parsed->src_local_ref;
	sccp->has_remote_ref = 1;
	LOGP(DNAT, LOGL_DEBUG, "Updating 0x%x to remote 0x%x on %p\n",
	     sccp_src_ref_to_int(&sccp->patched_ref),
	     sccp_src_ref_to_int(&sccp->remote_ref), sccp->bsc);

	return 0;
}

void remove_sccp_src_ref(struct bsc_connection *bsc, struct msgb *msg, struct bsc_nat_parsed *parsed)
{
	struct nat_sccp_connection *conn;

	llist_for_each_entry(conn, &bsc->nat->sccp_connections, list_entry) {
		if (equal(parsed->src_local_ref, &conn->patched_ref)) {
			sccp_connection_destroy(conn);
			return;
		}
	}

	LOGP(DNAT, LOGL_ERROR, "Can not remove connection: 0x%x\n",
	     sccp_src_ref_to_int(parsed->src_local_ref));
}

/*
 * We have a message from the MSC to the BSC. The MSC is using
 * an address that was assigned by the MUX, we need to update the
 * dest reference to the real network.
 */
struct nat_sccp_connection *patch_sccp_src_ref_to_bsc(struct msgb *msg,
						   struct bsc_nat_parsed *parsed,
						   struct bsc_nat *nat)
{
	struct nat_sccp_connection *conn;

	if (!parsed->dest_local_ref) {
		LOGP(DNAT, LOGL_ERROR, "MSG should contain dest_local_ref.\n");
		return NULL;
	}


	llist_for_each_entry(conn, &nat->sccp_connections, list_entry) {
		if (!equal(parsed->dest_local_ref, &conn->patched_ref))
			continue;

		/* Change the dest address to the real one */
		*parsed->dest_local_ref = conn->real_ref;
		return conn;
	}

	return NULL;
}

/*
 * These are message to the MSC. We will need to find the BSC
 * Connection by either the SRC or the DST local reference.
 *
 * In case of a CR we need to work by the SRC local reference
 * in all other cases we need to work by the destination local
 * reference..
 */
struct nat_sccp_connection *patch_sccp_src_ref_to_msc(struct msgb *msg,
						   struct bsc_nat_parsed *parsed,
						   struct bsc_connection *bsc)
{
	struct nat_sccp_connection *conn;

	llist_for_each_entry(conn, &bsc->nat->sccp_connections, list_entry) {
		if (conn->bsc != bsc)
			continue;

		if (parsed->src_local_ref) {
			if (equal(parsed->src_local_ref, &conn->real_ref)) {
				*parsed->src_local_ref = conn->patched_ref;
				return conn;
			}
		} else if (parsed->dest_local_ref) {
			if (equal(parsed->dest_local_ref, &conn->remote_ref))
				return conn;
		} else {
			LOGP(DNAT, LOGL_ERROR, "Header has neither loc/dst ref.\n");
			return NULL;
		}
	}

	return NULL;
}

struct nat_sccp_connection *bsc_nat_find_con_by_bsc(struct bsc_nat *nat,
						 struct sccp_source_reference *ref)
{
	struct nat_sccp_connection *conn;

	llist_for_each_entry(conn, &nat->sccp_connections, list_entry) {
		if (equal(ref, &conn->real_ref))
			return conn;
	}

	return NULL;
}
