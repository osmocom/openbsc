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

#define PAGING_TIMEOUT 0, 5000

static LLIST_HEAD(managed_bts);

/*
 * Kill one paging request update the internal list...
 */
static void page_remove_request(struct paging_bts *paging_bts) {
	struct paging_request *to_be_deleted = paging_bts->last_request;
	paging_bts->last_request =
		(struct paging_request *)paging_bts->last_request->entry.next;
	if (&to_be_deleted->entry == &paging_bts->pending_requests)
		paging_bts->last_request = NULL;
	llist_del(&to_be_deleted->entry);
	free(to_be_deleted);
}


static void page_handle_pending_requests(void *data) {
	struct paging_bts *paging_bts = (struct paging_bts *)data;

	if (!paging_bts->last_request)
		paging_bts->last_request =
			(struct paging_request *)paging_bts->pending_requests.next; 
	if (&paging_bts->last_request->entry == &paging_bts->pending_requests) {
		paging_bts->last_request = NULL;
		return;
	}

	DEBUGP(DPAG, "Going to send paging commands: '%s'\n",
		paging_bts->last_request->subscr->imsi);
	schedule_timer(&paging_bts->page_timer, PAGING_TIMEOUT);
}

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
	page->bts = bts;
	INIT_LLIST_HEAD(&page->pending_requests);
	page->page_timer.cb = page_handle_pending_requests;
	page->page_timer.data = page;

	llist_add_tail(&page->bts_list, &managed_bts);

	return page;
}

void page_request(struct gsm_bts *bts, struct gsm_subscriber *subscr, int type) {
	struct paging_bts *bts_entry;
	struct paging_request *req;

	req = (struct paging_request *)malloc(sizeof(*req));
	req->subscr = subscr_get(subscr);
	req->bts = bts;
	req->chan_type = type;

	llist_for_each_entry(bts_entry, &managed_bts, bts_list) {
		if (bts == bts_entry->bts && !page_pending_request(bts_entry, subscr)) {
			llist_add_tail(&req->entry, &bts_entry->pending_requests);
			if (!timer_pending(&bts_entry->page_timer))
				schedule_timer(&bts_entry->page_timer, PAGING_TIMEOUT);
			return;
		}
	}

	DEBUGP(DPAG, "Paging request for not mnaged BTS\n");
	free(req);
	return;
}
