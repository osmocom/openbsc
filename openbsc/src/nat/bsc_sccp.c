/* SCCP patching and handling routines */
/*
 * (C) 2010 by Holger Hans Peter Freyther <zecke@selfish.org>
 * (C) 2010 by On-Waves
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

#include <openbsc/debug.h>
#include <openbsc/bsc_nat.h>

#include <osmocore/talloc.h>

#include <string.h>

/*
 * SCCP patching below
 */

/* check if we are using this ref for patched already */
static int sccp_ref_is_free(struct sccp_source_reference *ref, struct bsc_nat *nat)
{
	struct sccp_connections *conn;

	llist_for_each_entry(conn, &nat->sccp_connections, list_entry) {
		if (memcmp(ref, &conn->patched_ref, sizeof(*ref)) == 0)
			return -1;
	}

	return 0;
}

/* copied from sccp.c */
static int assign_src_local_reference(struct sccp_source_reference *ref, struct bsc_nat *nat)
{
	static u_int32_t last_ref = 0x50000;
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

int create_sccp_src_ref(struct bsc_connection *bsc, struct msgb *msg, struct bsc_nat_parsed *parsed)
{
	struct sccp_connections *conn;

	conn = talloc_zero(bsc->nat, struct sccp_connections);
	if (!conn) {
		LOGP(DNAT, LOGL_ERROR, "Memory allocation failure.\n");
		return -1;
	}

	conn->real_ref = *parsed->src_local_ref;
	if (assign_src_local_reference(&conn->patched_ref, bsc->nat) != 0) {
		LOGP(DNAT, LOGL_ERROR, "Failed to assign a ref.\n");
		talloc_free(conn);
		return -1;
	}

	return 0;
}

void remove_sccp_src_ref(struct bsc_connection *bsc, struct msgb *msg, struct bsc_nat_parsed *parsed)
{
	struct sccp_connections *conn;

	llist_for_each_entry(conn, &bsc->nat->sccp_connections, list_entry) {
		if (memcmp(parsed->src_local_ref,
			   &conn->real_ref, sizeof(conn->real_ref)) == 0) {
			if (bsc != conn->bsc) {
				LOGP(DNAT, LOGL_ERROR, "Someone else...\n");
				continue;
			}


			llist_del(&conn->list_entry);
			talloc_free(conn);
			return;
		}
	}

	LOGP(DNAT, LOGL_ERROR, "Unknown connection.\n");
}

struct bsc_connection *patch_sccp_src_ref_to_bsc(struct msgb *msg,
						 struct bsc_nat_parsed *parsed,
						 struct bsc_nat *nat)
{
	struct sccp_connections *conn;
	llist_for_each_entry(conn, &nat->sccp_connections, list_entry) {
		if (memcmp(parsed->dest_local_ref,
			   &conn->real_ref, sizeof(*parsed->dest_local_ref)) == 0) {
			memcpy(parsed->dest_local_ref,
			       &conn->patched_ref, sizeof(*parsed->dest_local_ref));
			return conn->bsc;
		}
	}

	return NULL;
}

struct bsc_connection *patch_sccp_src_ref_to_msc(struct msgb *msg,
						 struct bsc_nat_parsed *parsed,
						 struct bsc_nat *nat)
{
	struct sccp_connections *conn;
	llist_for_each_entry(conn, &nat->sccp_connections, list_entry) {
		if (memcmp(parsed->src_local_ref,
			   &conn->real_ref, sizeof(*parsed->src_local_ref)) == 0) {
			memcpy(parsed->src_local_ref,
			       &conn->patched_ref, sizeof(*parsed->src_local_ref));
			return conn->bsc;
		}
	}

	return NULL;
}
