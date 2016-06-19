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

void *tall_sub_req_ctx;

int gsm48_secure_channel(struct gsm_subscriber_connection *conn, int key_seq,
                         gsm_cbfn *cb, void *cb_data);


/*
 * Struct for pending channel requests. This is managed in the
 * llist_head requests of each subscriber. The reference counting
 * should work in such a way that a subscriber with a pending request
 * remains in memory.
 */
struct subscr_request {
	struct llist_head entry;

	/* the callback data */
	gsm_cbfn *cbfn;
	void *param;
};

static struct bsc_subscr *vlr_subscr_to_bsc_sub(struct llist_head *bsc_subscribers,
						struct vlr_subscr *vsub)
{
	struct bsc_subscr *sub;
	/* TODO MSC split -- creating a BSC subscriber directly from MSC data
	 * structures in RAM. At some point the MSC will send a message to the
	 * BSC instead. */
	sub = bsc_subscr_find_or_create_by_imsi(bsc_subscribers, vsub->imsi);
	sub->tmsi = vsub->tmsi;
	sub->lac = vsub->lac;
	return sub;
}

/*
 * We got the channel assigned and can now hand this channel
 * over to one of our callbacks.
 */
int subscr_paging_dispatch(unsigned int hooknum, unsigned int event,
			   struct msgb *msg, void *data, void *param)
{
	struct subscr_request *request, *tmp;
	struct gsm_subscriber_connection *conn = data;
	struct vlr_subscr *vsub = param;
	struct paging_signal_data sig_data;
	struct bsc_subscr *bsub;
	struct gsm_network *net;

	OSMO_ASSERT(vsub && vsub->cs.is_paging);
	net = vsub->vlr->user_ctx;

	/*
	 * Stop paging on all other BTS. E.g. if this is
	 * the first timeout on a BTS then the others will
	 * timeout soon as well. Let's just stop everything
	 * and forget we wanted to page.
	 */

	bsub = vlr_subscr_to_bsc_sub(conn->network->bsc_subscribers, vsub);
	paging_request_stop(&net->bts_list, NULL, bsub, NULL, NULL);
	bsc_subscr_put(bsub);

	/* Inform parts of the system we don't know */
	sig_data.vsub	= vsub;
	sig_data.bts	= conn ? conn->bts : NULL;
	sig_data.conn	= conn;
	sig_data.paging_result = event;
	osmo_signal_dispatch(
		SS_PAGING,
		event == GSM_PAGING_SUCCEEDED ?
			S_PAGING_SUCCEEDED : S_PAGING_EXPIRED,
		&sig_data
	);

	llist_for_each_entry_safe(request, tmp, &vsub->cs.requests, entry) {
		llist_del(&request->entry);
		request->cbfn(hooknum, event, msg, data, request->param);
		talloc_free(request);
	}

	/* balanced with the moment we start paging */
	vsub->cs.is_paging = false;
	vlr_subscr_put(vsub);
	return 0;
}

struct subscr_request *subscr_request_channel(struct vlr_subscr *vsub,
					      int channel_type,
					      gsm_cbfn *cbfn, void *param)
{
	int rc;
	struct subscr_request *request;
	struct bsc_subscr *bsub;
	struct gsm_network *net = vsub->vlr->user_ctx;

	/* Start paging.. we know it is async so we can do it before */
	if (!vsub->cs.is_paging) {
		LOGP(DMM, LOGL_DEBUG, "Subscriber %s not paged yet.\n",
		     vlr_subscr_name(vsub));
		bsub = vlr_subscr_to_bsc_sub(net->bsc_subscribers, vsub);
		rc = paging_request(net, bsub, channel_type, NULL, NULL);
		bsc_subscr_put(bsub);
		if (rc <= 0) {
			LOGP(DMM, LOGL_ERROR, "Subscriber %s paging failed: %d\n",
			     vlr_subscr_name(vsub), rc);
			return NULL;
		}
		/* reduced on the first paging callback */
		vlr_subscr_get(vsub);
		vsub->cs.is_paging = true;
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
