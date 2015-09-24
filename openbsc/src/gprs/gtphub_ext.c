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

#include <openbsc/gtphub.h>
#include <osmocom/core/utils.h>

#define __llist_first(head) (((head)->next == (head)) ? NULL : (head)->next)
#define llist_first(head, type, entry) llist_entry(__llist_first(head), type, entry)

int gtphub_resolve_ggsn_addr(struct gtphub *hub,
			     struct osmo_sockaddr *result,
			     struct gtp_packet_desc *p)
{
	/* TODO  This is just hardcodedly returning the first known address.
	 * Should resolve from actual subscriber data. */
	struct gtphub_peer *peer = llist_first(&hub->to_ggsns[GTPH_PLANE_CTRL].peers,
					       struct gtphub_peer, entry);
	if (!peer)
		return -1;

	struct gtphub_peer_addr *pa = llist_first(&peer->addresses,
						  struct gtphub_peer_addr, entry);
	if (!pa)
		return -1;

	struct gtphub_peer_port *pp = llist_first(&pa->ports,
						  struct gtphub_peer_port, entry);
	if (!pp)
		return -1;

	*result = pp->sa;
	return 0;
}

