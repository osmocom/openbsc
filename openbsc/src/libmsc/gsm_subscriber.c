/* The concept of a subscriber for the MSC, roughly HLR/VLR functionality */

/* (C) 2008 by Harald Welte <laforge@gnumonks.org>
 * (C) 2009,2013 by Holger Hans Peter Freyther <zecke@selfish.org>
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

#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <time.h>
#include <stdbool.h>

#include <osmocom/core/talloc.h>

#include <osmocom/vty/vty.h>

#include <openbsc/gsm_subscriber.h>
#include <openbsc/gsm_04_08.h>
#include <openbsc/debug.h>
#include <openbsc/paging.h>
#include <openbsc/signal.h>
#include <openbsc/db.h>
#include <openbsc/chan_alloc.h>
#include <openbsc/vlr.h>
#include <openbsc/iu.h>
#include <openbsc/osmo_msc.h>
#include <openbsc/msc_ifaces.h>

void *tall_sub_req_ctx;

int gsm48_secure_channel(struct gsm_subscriber_connection *conn, int key_seq,
                         gsm_cbfn *cb, void *cb_data);

/* A connection is established and the paging callbacks may run now. */
int subscr_paging_dispatch(unsigned int hooknum, unsigned int event,
			   struct msgb *msg, void *data, void *param)
{
	struct subscr_request *request, *tmp;
	struct gsm_subscriber_connection *conn = data;
	struct vlr_subscr *vsub = param;
	struct paging_signal_data sig_data;

	OSMO_ASSERT(vsub);
	OSMO_ASSERT(hooknum == GSM_HOOK_RR_PAGING);
	OSMO_ASSERT(!(conn && (conn->vsub != vsub)));
	OSMO_ASSERT(!((event == GSM_PAGING_SUCCEEDED) && !conn));

	LOGP(DPAG, LOGL_DEBUG, "Paging %s for %s (event=%d)\n",
	     event == GSM_PAGING_SUCCEEDED ? "success" : "failure",
	     vlr_subscr_name(vsub), event);

	if (!vsub->cs.is_paging) {
		LOGP(DPAG, LOGL_ERROR,
		     "Paging Response received for subscriber"
		     " that is not paging.\n");
		return -EINVAL;
	}

	if (event == GSM_PAGING_SUCCEEDED)
		msc_stop_paging(vsub);

	/* Inform parts of the system we don't know */
	sig_data.vsub = vsub;
	sig_data.conn = conn;
	sig_data.paging_result = event;
	osmo_signal_dispatch(SS_PAGING,
			     event == GSM_PAGING_SUCCEEDED ?
				S_PAGING_SUCCEEDED : S_PAGING_EXPIRED,
			     &sig_data);

	llist_for_each_entry_safe(request, tmp, &vsub->cs.requests, entry) {
		llist_del(&request->entry);
		if (request->cbfn) {
			LOGP(DPAG, LOGL_DEBUG, "Calling paging cbfn.\n");
			request->cbfn(hooknum, event, msg, data, request->param);
		} else
			LOGP(DPAG, LOGL_DEBUG, "Paging without action.\n");
		talloc_free(request);
	}

	/* balanced with the moment we start paging */
	vsub->cs.is_paging = false;
	vlr_subscr_put(vsub);
	return 0;
}

int msc_paging_request(struct vlr_subscr *vsub)
{
	/* The subscriber was last seen in subscr->lac. Find out which
	 * BSCs/RNCs are responsible and send them a paging request via open
	 * SCCP connections (if any). */
	/* TODO Implementing only RNC paging, since this is code on the iu branch.
	 * Need to add BSC paging at some point. */
	switch (vsub->cs.attached_via_ran) {
	case RAN_GERAN_A:
		return a_page(vsub->imsi, vsub->tmsi, vsub->lac);
	case RAN_UTRAN_IU:
		return iu_page_cs(vsub->imsi,
				  vsub->tmsi == GSM_RESERVED_TMSI?
				  NULL : &vsub->tmsi,
				  vsub->lac);
	default:
		break;
	}

	LOGP(DPAG, LOGL_ERROR, "%s: Cannot page, subscriber not attached\n",
	     vlr_subscr_name(vsub));
	return -EINVAL;
}

struct subscr_request *subscr_request_conn(struct vlr_subscr *vsub,
					   gsm_cbfn *cbfn, void *param)
{
	int rc;
	struct subscr_request *request;

	/* Start paging.. we know it is async so we can do it before */
	if (!vsub->cs.is_paging) {
		LOGP(DMM, LOGL_DEBUG, "Subscriber %s not paged yet, start paging.\n",
		     vlr_subscr_name(vsub));
		rc = msc_paging_request(vsub);
		if (rc <= 0) {
			LOGP(DMM, LOGL_ERROR, "Subscriber %s paging failed: %d\n",
			     vlr_subscr_name(vsub), rc);
			return NULL;
		}
		/* reduced on the first paging callback */
		vlr_subscr_get(vsub);
		vsub->cs.is_paging = true;
	} else {
		LOGP(DMM, LOGL_DEBUG, "Subscriber %s already paged.\n",
			vlr_subscr_name(vsub));
	}

	/* TODO: Stop paging in case of memory allocation failure */
	request = talloc_zero(vsub, struct subscr_request);
	if (!request)
		return NULL;

	request->cbfn = cbfn;
	request->param = param;
	llist_add_tail(&request->entry, &vsub->cs.requests);
	return request;
}

void subscr_remove_request(struct subscr_request *request)
{
	llist_del(&request->entry);
	talloc_free(request);
}

struct gsm_subscriber_connection *connection_for_subscr(struct vlr_subscr *vsub)
{
	struct gsm_network *net = vsub->vlr->user_ctx;
	struct gsm_subscriber_connection *conn;

	llist_for_each_entry(conn, &net->subscr_conns, entry) {
		if (conn->vsub == vsub)
			return conn;
	}

	return NULL;
}
