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

#include <osmocom/core/talloc.h>

#include <osmocom/vty/vty.h>

#include <openbsc/gsm_subscriber.h>
#include <openbsc/gsm_04_08.h>
#include <openbsc/debug.h>
#include <openbsc/paging.h>
#include <openbsc/signal.h>
#include <openbsc/db.h>
#include <openbsc/chan_alloc.h>

void *tall_sub_req_ctx;

extern struct llist_head *subscr_bsc_active_subscribers(void);

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

	/* back reference */
	struct gsm_subscriber *subscr;

	/* the requested channel type */
	int channel_type;

	/* what did we do */
	int state;

	/* the callback data */
	gsm_cbfn *cbfn;
	void *param;
};

enum {
	REQ_STATE_INITIAL,
	REQ_STATE_QUEUED,
	REQ_STATE_PAGED,
	REQ_STATE_FAILED_START,
	REQ_STATE_DISPATCHED,
};

static struct gsm_subscriber *get_subscriber(struct gsm_network *net,
						int type, const char *ident)
{
	struct gsm_subscriber *subscr = db_get_subscriber(type, ident);
	if (subscr)
		subscr->net = net;
	return subscr;
}

/*
 * We got the channel assigned and can now hand this channel
 * over to one of our callbacks.
 */
static int subscr_paging_dispatch(unsigned int hooknum, unsigned int event,
                                  struct msgb *msg, void *data, void *param)
{
	struct subscr_request *request;
	struct gsm_subscriber_connection *conn = data;
	struct gsm_subscriber *subscr = param;
	struct paging_signal_data sig_data;

	/* There is no request anymore... */
	if (llist_empty(&subscr->requests))
		return -1;

	/* Dispatch signal */
	sig_data.subscr = subscr;
	sig_data.bts	= conn ? conn->bts : NULL;
	sig_data.conn	= conn;
	sig_data.paging_result = event;
	osmo_signal_dispatch(
		SS_PAGING,
		event == GSM_PAGING_SUCCEEDED ?
			S_PAGING_SUCCEEDED : S_PAGING_EXPIRED,
		&sig_data
	);

	/*
	 * FIXME: What to do with paging requests coming during
	 * this callback? We must be sure to not start paging when
	 * we have an active connection to a subscriber and to make
	 * the subscr_put_channel work as required...
	 */
	request = (struct subscr_request *)subscr->requests.next;
	request->state = REQ_STATE_DISPATCHED;
	llist_del(&request->entry);
	subscr->in_callback = 1;
	request->cbfn(hooknum, event, msg, data, request->param);
	subscr->in_callback = 0;

	if (event != GSM_PAGING_SUCCEEDED) {
		/*
		 *  This is a workaround for a bigger issue. We have
		 *  issued paging that might involve multiple BTSes
		 *  and one of them have failed now. We will stop the
		 *  other paging requests as well as the next timeout
		 *  would work on the next paging request and the queue
		 *  will do bad things. This should be fixed by counting
		 *  the outstanding results.
		 */
		paging_request_stop(NULL, subscr, NULL, NULL);
		subscr_put_channel(subscr);
	}

	subscr_put(subscr);
	talloc_free(request);
	return 0;
}

static int subscr_paging_sec_cb(unsigned int hooknum, unsigned int event,
                                struct msgb *msg, void *data, void *param)
{
	int rc;

	switch (event) {
		case GSM_SECURITY_AUTH_FAILED:
			/* Dispatch as paging failure */
			rc = subscr_paging_dispatch(
				GSM_HOOK_RR_PAGING, GSM_PAGING_EXPIRED,
				msg, data, param);
			break;

		case GSM_SECURITY_NOAVAIL:
		case GSM_SECURITY_SUCCEEDED:
			/* Dispatch as paging failure */
			rc = subscr_paging_dispatch(
				GSM_HOOK_RR_PAGING, GSM_PAGING_SUCCEEDED,
				msg, data, param);
			break;

		default:
			rc = -EINVAL;
	}

	return rc;
}

static int subscr_paging_cb(unsigned int hooknum, unsigned int event,
                            struct msgb *msg, void *data, void *param)
{
	struct gsm_subscriber_connection *conn = data;
	struct gsm48_hdr *gh;
	struct gsm48_pag_resp *pr;

	/* Other cases mean problem, dispatch direclty */
	if (event != GSM_PAGING_SUCCEEDED)
		return subscr_paging_dispatch(hooknum, event, msg, data, param);

	/* Get paging response */
	gh = msgb_l3(msg);
	pr = (struct gsm48_pag_resp *)gh->data;

	/* We _really_ have a channel, secure it now ! */
	return gsm48_secure_channel(conn, pr->key_seq, subscr_paging_sec_cb, param);
}


static void subscr_send_paging_request(struct gsm_subscriber *subscr)
{
	struct subscr_request *request;
	int rc;

	assert(!llist_empty(&subscr->requests));

	request = (struct subscr_request *)subscr->requests.next;
	request->state = REQ_STATE_PAGED;
	rc = paging_request(subscr->net, subscr, request->channel_type,
			    subscr_paging_cb, subscr);

	/* paging failed, quit now */
	if (rc <= 0) {
		request->state = REQ_STATE_FAILED_START;
		subscr_paging_cb(GSM_HOOK_RR_PAGING, GSM_PAGING_BUSY,
				 NULL, NULL, subscr);
	}
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
	request->state = REQ_STATE_INITIAL;

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
		request->state = REQ_STATE_QUEUED;
	}
}

void subscr_put_channel(struct gsm_subscriber *subscr)
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

	if (subscr && !llist_empty(&subscr->requests))
		subscr_send_paging_request(subscr);
}

struct gsm_subscriber *subscr_create_subscriber(struct gsm_network *net,
					const char *imsi)
{
	struct gsm_subscriber *subscr = db_create_subscriber(imsi);
	if (subscr)
		subscr->net = net;
	return subscr;
}

struct gsm_subscriber *subscr_get_by_tmsi(struct gsm_network *net,
					  uint32_t tmsi)
{
	char tmsi_string[14];
	struct gsm_subscriber *subscr;

	/* we might have a record in memory already */
	llist_for_each_entry(subscr, subscr_bsc_active_subscribers(), entry) {
		if (tmsi == subscr->tmsi)
			return subscr_get(subscr);
	}

	sprintf(tmsi_string, "%u", tmsi);
	return get_subscriber(net, GSM_SUBSCRIBER_TMSI, tmsi_string);
}

struct gsm_subscriber *subscr_get_by_imsi(struct gsm_network *net,
					  const char *imsi)
{
	struct gsm_subscriber *subscr;

	llist_for_each_entry(subscr, subscr_bsc_active_subscribers(), entry) {
		if (strcmp(subscr->imsi, imsi) == 0)
			return subscr_get(subscr);
	}

	return get_subscriber(net, GSM_SUBSCRIBER_IMSI, imsi);
}

struct gsm_subscriber *subscr_get_by_extension(struct gsm_network *net,
					       const char *ext)
{
	struct gsm_subscriber *subscr;

	llist_for_each_entry(subscr, subscr_bsc_active_subscribers(), entry) {
		if (strcmp(subscr->extension, ext) == 0)
			return subscr_get(subscr);
	}

	return get_subscriber(net, GSM_SUBSCRIBER_EXTENSION, ext);
}

struct gsm_subscriber *subscr_get_by_id(struct gsm_network *net,
					unsigned long long id)
{
	struct gsm_subscriber *subscr;
	char buf[32];
	sprintf(buf, "%llu", id);

	llist_for_each_entry(subscr, subscr_bsc_active_subscribers(), entry) {
		if (subscr->id == id)
			return subscr_get(subscr);
	}

	return get_subscriber(net, GSM_SUBSCRIBER_ID, buf);
}

int subscr_update_expire_lu(struct gsm_subscriber *s, struct gsm_bts *bts)
{
	int rc;

	/* Table 10.5.33: The T3212 timeout value field is coded as the
	 * binary representation of the timeout value for
	 * periodic updating in decihours. Mark the subscriber as
	 * inactive if it missed two consecutive location updates.
	 * Timeout is twice the t3212 value plus one minute */

	/* Is expiration handling enabled? */
	if (bts->si_common.chan_desc.t3212 == 0)
		s->expire_lu = GSM_SUBSCRIBER_NO_EXPIRATION;
	else
		s->expire_lu = time(NULL) +
			(bts->si_common.chan_desc.t3212 * 60 * 6 * 2) + 60;

	rc = db_sync_subscriber(s);
	db_subscriber_update(s);
	return rc;
}

int subscr_update(struct gsm_subscriber *s, struct gsm_bts *bts, int reason)
{
	int rc;

	/* FIXME: Migrate pending requests from one BSC to another */
	switch (reason) {
	case GSM_SUBSCRIBER_UPDATE_ATTACHED:
		s->net = bts->network;
		/* Indicate "attached to LAC" */
		s->lac = bts->location_area_code;

		LOGP(DMM, LOGL_INFO, "Subscriber %s ATTACHED LAC=%u\n",
			subscr_name(s), s->lac);

		/*
		 * The below will set a new expire_lu but as a side-effect
		 * the new lac will be saved in the database.
		 */
		rc = subscr_update_expire_lu(s, bts);
		osmo_signal_dispatch(SS_SUBSCR, S_SUBSCR_ATTACHED, s);
		break;
	case GSM_SUBSCRIBER_UPDATE_DETACHED:
		/* Only detach if we are currently in this area */
		if (bts->location_area_code == s->lac)
			s->lac = GSM_LAC_RESERVED_DETACHED;
		LOGP(DMM, LOGL_INFO, "Subscriber %s DETACHED\n", subscr_name(s));
		rc = db_sync_subscriber(s);
		db_subscriber_update(s);
		osmo_signal_dispatch(SS_SUBSCR, S_SUBSCR_DETACHED, s);
		break;
	default:
		fprintf(stderr, "subscr_update with unknown reason: %d\n",
			reason);
		rc = db_sync_subscriber(s);
		db_subscriber_update(s);
		break;
	};

	return rc;
}

void subscr_update_from_db(struct gsm_subscriber *sub)
{
	db_subscriber_update(sub);
}

static void subscr_expire_callback(void *data, long long unsigned int id)
{
	struct gsm_network *net = data;
	struct gsm_subscriber *s = subscr_get_by_id(net, id);
	struct gsm_subscriber_connection *conn = connection_for_subscr(s);

	/*
	 * The subscriber is active and the phone stopped the timer. As
	 * we don't want to periodically update the database for active
	 * subscribers we will just do it when the subscriber was selected
	 * for expiration. This way on the next around another subscriber
	 * will be selected.
	 */
	if (conn && conn->expire_timer_stopped) {
		LOGP(DMM, LOGL_DEBUG, "Not expiring subscriber %s (ID %llu)\n",
			subscr_name(s), id);
		subscr_update_expire_lu(s, conn->bts);
		return;
	}


	LOGP(DMM, LOGL_NOTICE, "Expiring inactive subscriber %s (ID %llu)\n",
			subscr_name(s), id);
	s->lac = GSM_LAC_RESERVED_DETACHED;
	db_sync_subscriber(s);

	subscr_put(s);
}

void subscr_expire(struct gsm_network *net)
{
	db_subscriber_expire(net, subscr_expire_callback);
}

int subscr_pending_requests(struct gsm_subscriber *sub)
{
	struct subscr_request *req;
	int pending = 0;

	llist_for_each_entry(req, &sub->requests, entry)
		pending += 1;

	return pending;
}

int subscr_pending_clear(struct gsm_subscriber *sub)
{
	int deleted = 0;
	struct subscr_request *req, *tmp;

	llist_for_each_entry_safe(req, tmp, &sub->requests, entry) {
		subscr_put(req->subscr);
		llist_del(&req->entry);
		talloc_free(req);
		deleted += 1;
	}

	return deleted;
}

int subscr_pending_dump(struct gsm_subscriber *sub, struct vty *vty)
{
	struct subscr_request *req;

	vty_out(vty, "Pending Requests for Subscriber %llu.%s", sub->id, VTY_NEWLINE);
	llist_for_each_entry(req, &sub->requests, entry) {
		vty_out(vty, "Channel type: %d State: %d Sub: %llu.%s",
			req->channel_type, req->state, req->subscr->id, VTY_NEWLINE);
	}

	return 0;
}

int subscr_pending_kick(struct gsm_subscriber *sub)
{
	subscr_put_channel(sub);
	return 0;
}
