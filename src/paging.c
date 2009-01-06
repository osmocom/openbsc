/* Paging helper and manager.... */
/* (C) 2009 by Holger Hans Peter Freyther <zecke@selfish.org>
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

/*
 * Relevant specs:
 *     12.21:
 *       - 9.4.12 for CCCH Local Threshold
 *
 *     05.58:
 *       - 8.5.2 CCCH Load indication
 *       - 9.3.15 Paging Load
 *
 * Approach:
 *       - Send paging command to subscriber
 *       - On Channel Request we will remember the reason
 *       - After the ACK we will request the identity
 *	 - Then we will send assign the gsm_subscriber and
 *	 - and call a callback
 */

#include <openbsc/paging.h>
#include <openbsc/debug.h>

static LLIST_HEAD(managed_bts);

static int page_pending_request(struct paging_bts *bts,
				struct gsm_subscriber *subscr) {
	struct paging_request *req;

	llist_for_each_entry(req, &bts->pending_requests, entry) {
		if (subscr == req->subscr)
			return 1;
	}

	return 0;	
}

struct paging_bts* page_allocate(struct gsm_bts *bts) {
	struct paging_bts *page;

	page = (struct paging_bts *)malloc(sizeof(*page));
	memset(page, 0, sizeof(*page));
	llist_add_tail(&page->bts_list, &managed_bts);

	return page;
}

void page_request(struct gsm_bts *bts, struct gsm_subscriber *subscr) {
	struct paging_bts *bts_entry;
	struct paging_request *req;

	req = (struct paging_request *)malloc(sizeof(*req));
	req->subscr = subscr_get(subscr);
	req->bts = bts;

	llist_for_each_entry(bts_entry, &managed_bts, bts_list) {
		if (bts == bts_entry->bts && !page_pending_request(bts_entry, subscr)) {
			llist_add_tail(&req->entry, &bts_entry->pending_requests);
			return;
		}
	}

	DEBUGP(DPAG, "Paging request for not mnaged BTS\n");
	free(req);
	return;
}
