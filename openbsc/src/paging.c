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

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

#include <openbsc/paging.h>
#include <openbsc/talloc.h>
#include <openbsc/debug.h>
#include <openbsc/signal.h>
#include <openbsc/abis_rsl.h>
#include <openbsc/gsm_data.h>

#define PAGING_TIMEOUT 1, 75000
#define MAX_PAGING_REQUEST 750

static void *tall_paging_ctx;

static unsigned int calculate_group(struct gsm_bts *bts, struct gsm_subscriber *subscr)
{
	int ccch_conf;
	int bs_cc_chans;
	int blocks;
	unsigned int group;
	
	ccch_conf = bts->chan_desc.ccch_conf;
	bs_cc_chans = rsl_ccch_conf_to_bs_cc_chans(ccch_conf);
	/* code word + 2, as 2 channels equals 0x0 */
	blocks = rsl_number_of_paging_subchannels(bts);
	group = get_paging_group(str_to_imsi(subscr->imsi),
					bs_cc_chans, blocks);
	return group;
}

/*
 * Kill one paging request update the internal list...
 */
static void paging_remove_request(struct gsm_bts_paging_state *paging_bts,
				struct gsm_paging_request *to_be_deleted)
{
	/* Update the last_request if that is necessary */
	if (to_be_deleted == paging_bts->last_request) {
		paging_bts->last_request =
			(struct gsm_paging_request *)paging_bts->last_request->entry.next;
		if (&to_be_deleted->entry == &paging_bts->pending_requests)
			paging_bts->last_request = NULL;
	}

	bsc_del_timer(&to_be_deleted->T3113);
	llist_del(&to_be_deleted->entry);
	subscr_put(to_be_deleted->subscr);
	talloc_free(to_be_deleted);
}

static void page_ms(struct gsm_paging_request *request)
{
	u_int8_t mi[128];
	unsigned long int tmsi;
	unsigned int mi_len;
	unsigned int page_group;

	DEBUGP(DPAG, "Going to send paging commands: '%s'\n",
		request->subscr->imsi);

	page_group = calculate_group(request->bts, request->subscr);
	tmsi = strtoul(request->subscr->tmsi, NULL, 10);
	mi_len = generate_mid_from_tmsi(mi, tmsi);
	rsl_paging_cmd(request->bts, page_group, mi_len, mi,
			request->chan_type);
}

static void paging_move_to_next(struct gsm_bts_paging_state *paging_bts)
{
	paging_bts->last_request =
		(struct gsm_paging_request *)paging_bts->last_request->entry.next;
	if (&paging_bts->last_request->entry == &paging_bts->pending_requests)
		paging_bts->last_request = NULL;
}

/*
 * This is kicked by the periodic PAGING LOAD Indicator
 * coming from abis_rsl.c
 *
 * We attempt to iterate once over the list of items but
 * only upto available_slots.
 */
static void paging_handle_pending_requests(struct gsm_bts_paging_state *paging_bts)
{
	struct gsm_paging_request *initial_request = NULL;
	struct gsm_paging_request *current_request = NULL;

	/*
	 * Determine if the pending_requests list is empty and
	 * return then.
	 */
	if (llist_empty(&paging_bts->pending_requests)) {
		paging_bts->last_request = NULL;
		/* since the list is empty, no need to reschedule the timer */
		return;
	}

	if (!paging_bts->last_request)
		paging_bts->last_request =
			(struct gsm_paging_request *)paging_bts->pending_requests.next;

	assert(paging_bts->last_request);
	initial_request = paging_bts->last_request;
	current_request = initial_request;

	do {
		/* handle the paging request now */
		page_ms(current_request);
		paging_bts->available_slots--;

		/*
		 * move to the next item. We might wrap around
		 * this means last_request will be NULL and we just
		 * call paging_page_to_next again. It it guranteed
		 * that the list is not empty.
		 */
		paging_move_to_next(paging_bts);
		if (!paging_bts->last_request)
			paging_bts->last_request =
				(struct gsm_paging_request *)paging_bts->pending_requests.next;
		current_request = paging_bts->last_request;
	} while (paging_bts->available_slots > 0
		    &&  initial_request != current_request);

	bsc_schedule_timer(&paging_bts->work_timer, 1, 0);
}

static void paging_worker(void *data)
{
	struct gsm_bts_paging_state *paging_bts = data;

	paging_handle_pending_requests(paging_bts);
}

void paging_init(struct gsm_bts *bts)
{
	bts->paging.bts = bts;
	INIT_LLIST_HEAD(&bts->paging.pending_requests);
	bts->paging.work_timer.cb = paging_worker;
	bts->paging.work_timer.data = &bts->paging;

	/* Large number, until we get a proper message */
	bts->paging.available_slots = 100;
}

static int paging_pending_request(struct gsm_bts_paging_state *bts,
				struct gsm_subscriber *subscr) {
	struct gsm_paging_request *req;

	llist_for_each_entry(req, &bts->pending_requests, entry) {
		if (subscr == req->subscr)
			return 1;
	}

	return 0;	
}

static void paging_T3113_expired(void *data)
{
	struct gsm_paging_request *req = (struct gsm_paging_request *)data;
	struct paging_signal_data sig_data;

	DEBUGP(DPAG, "T3113 expired for request %p (%s)\n",
		req, req->subscr->imsi);
	
	sig_data.subscr = req->subscr,
	sig_data.bts	= req->bts,
	sig_data.lchan	= NULL,

	dispatch_signal(SS_PAGING, S_PAGING_COMPLETED, &sig_data);
	if (req->cbfn)
		req->cbfn(GSM_HOOK_RR_PAGING, GSM_PAGING_EXPIRED, NULL, NULL,
			  req->cbfn_param);
	paging_remove_request(&req->bts->paging, req);
}

static int _paging_request(struct gsm_bts *bts, struct gsm_subscriber *subscr,
			    int type, gsm_cbfn *cbfn, void *data)
{
	struct gsm_bts_paging_state *bts_entry = &bts->paging;
	struct gsm_paging_request *req;

	if (paging_pending_request(bts_entry, subscr)) {
		DEBUGP(DPAG, "Paging request already pending\n");
		return -EEXIST;
	}

	DEBUGP(DPAG, "Start paging of subscriber %llu on bts %d.\n",
		subscr->id, bts->nr);
	req = talloc_zero(tall_paging_ctx, struct gsm_paging_request);
	req->subscr = subscr_get(subscr);
	req->bts = bts;
	req->chan_type = type;
	req->cbfn = cbfn;
	req->cbfn_param = data;
	req->T3113.cb = paging_T3113_expired;
	req->T3113.data = req;
	bsc_schedule_timer(&req->T3113, T3113_VALUE);
	llist_add_tail(&req->entry, &bts_entry->pending_requests);

	if (!bsc_timer_pending(&bts_entry->work_timer))
		bsc_schedule_timer(&bts_entry->work_timer, 1, 0);

	return 0;
}

int paging_request(struct gsm_network *network, struct gsm_subscriber *subscr,
		   int type, gsm_cbfn *cbfn, void *data)
{
	struct gsm_bts *bts = NULL;
	int rc;

	/* start paging subscriber on all BTS within Location Area */
	do {
		bts = gsm_bts_by_lac(network, subscr->lac, bts);
		if (!bts)
			break;

		/* Trigger paging, pass any error to caller */
		rc = _paging_request(bts, subscr, type, cbfn, data);
		if (rc < 0)
			return rc;
	} while (1);

	return 0;
}


/* we consciously ignore the type of the request here */
static void _paging_request_stop(struct gsm_bts *bts, struct gsm_subscriber *subscr,
				 struct gsm_lchan *lchan)
{
	struct gsm_bts_paging_state *bts_entry = &bts->paging;
	struct gsm_paging_request *req, *req2;

	llist_for_each_entry_safe(req, req2, &bts_entry->pending_requests,
				 entry) {
		if (req->subscr == subscr) {
			if (lchan && req->cbfn) {
				DEBUGP(DPAG, "Stop paging on bts %d, calling cbfn.\n", bts->nr);
				req->cbfn(GSM_HOOK_RR_PAGING, GSM_PAGING_SUCCEEDED,
					  NULL, lchan, req->cbfn_param);
			} else
				DEBUGP(DPAG, "Stop paging on bts %d silently.\n", bts->nr);
			paging_remove_request(&bts->paging, req);
			break;
		}
	}
}

/* Stop paging on all other bts' */
void paging_request_stop(struct gsm_bts *_bts, struct gsm_subscriber *subscr,
			 struct gsm_lchan *lchan)
{
	struct gsm_bts *bts = NULL;

	_paging_request_stop(_bts, subscr, lchan);

	do {
		/*
		 * FIXME: Don't use the lac of the subscriber...
		 * as it might have magically changed the lac.. use the
		 * location area of the _bts as reconfiguration of the
		 * network is probably happening less often.
		 */
		bts = gsm_bts_by_lac(_bts->network, subscr->lac, bts);
		if (!bts)
			break;

		/* Stop paging */
                if (bts != _bts)
			_paging_request_stop(bts, subscr, NULL);
	} while (1);
}

void paging_update_buffer_space(struct gsm_bts *bts, u_int16_t free_slots)
{
	bts->paging.available_slots = free_slots;
}

static __attribute__((constructor)) void on_dso_load_paging(void)
{
	tall_paging_ctx = talloc_named_const(NULL, 1, "paging_request");
}
