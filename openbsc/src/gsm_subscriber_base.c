/* The concept of a subscriber as seen by the BSC */

/* (C) 2008 by Harald Welte <laforge@gnumonks.org>
 * (C) 2009-2010 by Holger Hans Peter Freyther <zecke@selfish.org>
 * (C) 2010 by On Waves
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

#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>

#include <osmocore/talloc.h>
#include <openbsc/gsm_subscriber.h>
#include <openbsc/paging.h>
#include <openbsc/debug.h>

LLIST_HEAD(active_subscribers);
void *tall_subscr_ctx;
void *tall_sub_req_ctx;

/* for the gsm_subscriber.c */
struct llist_head *subscr_bsc_active_subscriber(void)
{
	return &active_subscribers;
}

/*
 * Struct for pending channel requests. This is managed in the
 * llist_head requests of each subscriber. The reference counting
 * should work in such a way that a subscriber with a pending request
 * remains in memory.
 */
struct subscr_request {
	struct llist_head entry;

	/* back reference */
	struct gsm_subscriber *subscr;

	/* the requested channel type */
	int channel_type;

	/* the callback data */
	gsm_cbfn *cbfn;
	void *param;
};

/*
 * We got the channel assigned and can now hand this channel
 * over to one of our callbacks.
 */
static int subscr_paging_cb(unsigned int hooknum, unsigned int event,
			     struct msgb *msg, void *data, void *param)
{
	struct subscr_request *request;
	struct gsm_subscriber *subscr = (struct gsm_subscriber *)param;

	/* There is no request anymore... */
	if (llist_empty(&subscr->requests))
		return -1;

	/*
	 * FIXME: What to do with paging requests coming during
	 * this callback? We must be sure to not start paging when
	 * we have an active connection to a subscriber and to make
	 * the subscr_put_channel work as required...
	 */
	request = (struct subscr_request *)subscr->requests.next;
	llist_del(&request->entry);
	subscr->in_callback = 1;
	request->cbfn(hooknum, event, msg, data, request->param);
	subscr->in_callback = 0;

	subscr_put(subscr);
	talloc_free(request);
	return 0;
}

static void subscr_send_paging_request(struct gsm_subscriber *subscr)
{
	struct subscr_request *request;
	int rc;

	assert(!llist_empty(&subscr->requests));

	request = (struct subscr_request *)subscr->requests.next;
	rc = paging_request(subscr->net, subscr, request->channel_type,
			    subscr_paging_cb, subscr);

	/* paging failed, quit now */
	if (rc <= 0) {
		subscr_paging_cb(GSM_HOOK_RR_PAGING, GSM_PAGING_EXPIRED,
				 NULL, NULL, subscr);
	}
}

char *subscr_name(struct gsm_subscriber *subscr)
{
	if (strlen(subscr->name))
		return subscr->name;

	return subscr->imsi;
}

struct gsm_subscriber *subscr_alloc(void)
{
	struct gsm_subscriber *s;

	s = talloc_zero(tall_subscr_ctx, struct gsm_subscriber);
	if (!s)
		return NULL;

	llist_add_tail(&s->entry, &active_subscribers);
	s->use_count = 1;
	s->tmsi = GSM_RESERVED_TMSI;

	INIT_LLIST_HEAD(&s->requests);

	return s;
}

static void subscr_free(struct gsm_subscriber *subscr)
{
	llist_del(&subscr->entry);
	talloc_free(subscr);
}

struct gsm_subscriber *subscr_get(struct gsm_subscriber *subscr)
{
	subscr->use_count++;
	DEBUGP(DREF, "subscr %s usage increases usage to: %d\n",
			subscr->extension, subscr->use_count);
	return subscr;
}

struct gsm_subscriber *subscr_put(struct gsm_subscriber *subscr)
{
	subscr->use_count--;
	DEBUGP(DREF, "subscr %s usage decreased usage to: %d\n",
			subscr->extension, subscr->use_count);
	if (subscr->use_count <= 0)
		subscr_free(subscr);
	return NULL;
}

void subscr_get_channel(struct gsm_subscriber *subscr,
			int type, gsm_cbfn *cbfn, void *param)
{
	struct subscr_request *request;

	request = talloc(tall_sub_req_ctx, struct subscr_request);
	if (!request) {
		if (cbfn)
			cbfn(GSM_HOOK_RR_PAGING, GSM_PAGING_OOM,
				NULL, NULL, param);
		return;
	}

	memset(request, 0, sizeof(*request));
	request->subscr = subscr_get(subscr);
	request->channel_type = type;
	request->cbfn = cbfn;
	request->param = param;

	/*
	 * FIXME: We might be able to assign more than one
	 * channel, e.g. voice and SMS submit at the same
	 * time.
	 */
	if (!subscr->in_callback && llist_empty(&subscr->requests)) {
		/* add to the list, send a request */
		llist_add_tail(&request->entry, &subscr->requests);
		subscr_send_paging_request(subscr);
	} else {
		/* this will be picked up later, from subscr_put_channel */
		llist_add_tail(&request->entry, &subscr->requests);
	}
}

void subscr_put_channel(struct gsm_subscriber_connection *conn)
{
	/*
	 * FIXME: Continue with other requests now... by checking
	 * the gsm_subscriber inside the gsm_lchan. Drop the ref count
	 * of the lchan after having asked the next requestee to handle
	 * the channel.
	 */
	/*
	 * FIXME: is the lchan is of a different type we could still
	 * issue an immediate assignment for another channel and then
	 * close this one.
	 */
	/*
	 * Currently we will drop the last ref of the lchan which
	 * will result in a channel release on RSL and we will start
	 * the paging. This should work most of the time as the MS
	 * will listen to the paging requests before we timeout
	 */

	if (conn->subscr && !llist_empty(&conn->subscr->requests))
		subscr_send_paging_request(conn->subscr);
}

