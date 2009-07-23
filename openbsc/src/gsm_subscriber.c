/* Dummy implementation of a subscriber database, roghly HLR/VLR functionality */

/* (C) 2008 by Harald Welte <laforge@gnumonks.org>
 * (C) 2009 by Holger Hans Peter Freyther <zecke@selfish.org>
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

#include <openbsc/talloc.h>
#include <openbsc/gsm_subscriber.h>
#include <openbsc/paging.h>
#include <openbsc/debug.h>
#include <openbsc/paging.h>
#include <openbsc/db.h>

LLIST_HEAD(active_subscribers);
static void *tall_subscr_ctx;
static void *tall_sub_req_ctx;

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

	/* the bts we have decided to use */
	struct gsm_network *network;

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

	assert(!llist_empty(&subscr->requests));

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

	talloc_free(request);
	return 0;
}

static void subscr_send_paging_request(struct gsm_subscriber *subscr)
{
	struct subscr_request *request;
	assert(!llist_empty(&subscr->requests));

	request = (struct subscr_request *)subscr->requests.next;
	paging_request(request->network, subscr, request->channel_type,
		       subscr_paging_cb, subscr);
}

struct gsm_subscriber *subscr_alloc(void)
{
	struct gsm_subscriber *s;

	if (!tall_subscr_ctx)
		tall_subscr_ctx = talloc_named_const(tall_bsc_ctx, 1,
						     "subscriber");

	s = talloc(tall_subscr_ctx, struct gsm_subscriber);
	if (!s)
		return NULL;

	memset(s, 0, sizeof(*s));
	llist_add_tail(&s->entry, &active_subscribers);
	s->use_count = 1;

	INIT_LLIST_HEAD(&s->requests);

	return s;
}

static void subscr_free(struct gsm_subscriber *subscr)
{
	llist_del(&subscr->entry);
	talloc_free(subscr);
}

struct gsm_subscriber *subscr_get_by_tmsi(const char *tmsi)
{
	struct gsm_subscriber *subscr;

	/* we might have a record in memory already */
	llist_for_each_entry(subscr, &active_subscribers, entry) {
		if (strcmp(subscr->tmsi, tmsi) == 0)
			return subscr_get(subscr);
	}

	return db_get_subscriber(GSM_SUBSCRIBER_TMSI, tmsi);
}

struct gsm_subscriber *subscr_get_by_imsi(const char *imsi)
{
	struct gsm_subscriber *subscr;

	llist_for_each_entry(subscr, &active_subscribers, entry) {
		if (strcmp(subscr->imsi, imsi) == 0)
			return subscr_get(subscr);
	}

	return db_get_subscriber(GSM_SUBSCRIBER_IMSI, imsi);
}

struct gsm_subscriber *subscr_get_by_extension(const char *ext)
{
	struct gsm_subscriber *subscr;

	llist_for_each_entry(subscr, &active_subscribers, entry) {
		if (strcmp(subscr->extension, ext) == 0)
			return subscr_get(subscr);
	}

	return db_get_subscriber(GSM_SUBSCRIBER_EXTENSION, ext);
}

int subscr_update(struct gsm_subscriber *s, struct gsm_bts *bts, int reason)
{
	/* FIXME: Migrate pending requests from one BSC to another */
	switch (reason) {
	case GSM_SUBSCRIBER_UPDATE_ATTACHED:
		s->net = bts->network;
		/* Indicate "attached to LAC" */
		s->lac = bts->location_area_code;
		break;
	case GSM_SUBSCRIBER_UPDATE_DETACHED:
		/* Only detach if we are currently in this area */
		if (bts->location_area_code == s->lac)
			s->lac = 0;

		break;
	default:
		fprintf(stderr, "subscr_update with unknown reason: %d\n",
			reason);
		break;
	};
	return db_sync_subscriber(s);
}

struct gsm_subscriber *subscr_get(struct gsm_subscriber *subscr)
{
	subscr->use_count++;
	DEBUGP(DCC, "subscr %s usage increases usage to: %d\n",
			subscr->extension, subscr->use_count);
	return subscr;
}

struct gsm_subscriber *subscr_put(struct gsm_subscriber *subscr)
{
	subscr->use_count--;
	DEBUGP(DCC, "subscr %s usage decreased usage to: %d\n",
			subscr->extension, subscr->use_count);
	if (subscr->use_count <= 0)
		subscr_free(subscr);
	return NULL;
}

void subscr_get_channel(struct gsm_subscriber *subscr,
			struct gsm_network *network, int type,
			gsm_cbfn *cbfn, void *param)
{
	struct subscr_request *request;

	if (!tall_sub_req_ctx)
		tall_sub_req_ctx = talloc_named_const(tall_bsc_ctx, 1,
						      "subscr_request");

	request = talloc(tall_sub_req_ctx, struct subscr_request);
	if (!request) {
		if (cbfn)
			cbfn(GSM_HOOK_RR_PAGING, GSM_PAGING_OOM,
				NULL, NULL, param);
		return;
	}

	memset(request, 0, sizeof(*request));
	request->network = network;
	request->subscr = subscr;
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

void subscr_put_channel(struct gsm_lchan *lchan)
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

	put_lchan(lchan);

	if (lchan->subscr && !llist_empty(&lchan->subscr->requests))
		subscr_send_paging_request(lchan->subscr);
}

