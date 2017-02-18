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

	/* the callback data */
	gsm_cbfn *cbfn;
	void *param;
};

static struct gsm_subscriber *get_subscriber(struct gsm_subscriber_group *sgrp,
						int type, const char *ident)
{
	struct gsm_subscriber *subscr = db_get_subscriber(type, ident);
	if (subscr)
		subscr->group = sgrp;
	return subscr;
}

/*
 * We got the channel assigned and can now hand this channel
 * over to one of our callbacks.
 */
static int subscr_paging_dispatch(unsigned int hooknum, unsigned int event,
                                  struct msgb *msg, void *data, void *param)
{
	struct subscr_request *request, *tmp;
	struct gsm_subscriber_connection *conn = data;
	struct gsm_subscriber *subscr = param;
	struct paging_signal_data sig_data;
	struct bsc_subscr *bsub;
	struct gsm_network *net;

	OSMO_ASSERT(subscr && subscr->is_paging);
	net = subscr->group->net;

	/*
	 * Stop paging on all other BTS. E.g. if this is
	 * the first timeout on a BTS then the others will
	 * timeout soon as well. Let's just stop everything
	 * and forget we wanted to page.
	 */

	/* TODO MSC split -- creating a BSC subscriber directly from MSC data
	 * structures in RAM. At some point the MSC will send a message to the
	 * BSC instead. */
	bsub = bsc_subscr_find_or_create_by_imsi(net->bsc_subscribers,
						 subscr->imsi);
	bsub->tmsi = subscr->tmsi;
	bsub->lac = subscr->lac;
	paging_request_stop(&net->bts_list, NULL, bsub, NULL, NULL);
	bsc_subscr_put(bsub);

	/* Inform parts of the system we don't know */
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

	llist_for_each_entry_safe(request, tmp, &subscr->requests, entry) {
		llist_del(&request->entry);
		request->cbfn(hooknum, event, msg, data, request->param);
		talloc_free(request);
	}

	/* balanced with the moment we start paging */
	subscr->is_paging = 0;
	subscr_put(subscr);
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

struct subscr_request *subscr_request_channel(struct gsm_subscriber *subscr,
			int channel_type, gsm_cbfn *cbfn, void *param)
{
	int rc;
	struct subscr_request *request;
	struct bsc_subscr *bsub;
	struct gsm_network *net = subscr->group->net;

	/* Start paging.. we know it is async so we can do it before */
	if (!subscr->is_paging) {
		LOGP(DMM, LOGL_DEBUG, "Subscriber %s not paged yet.\n",
			subscr_name(subscr));
		/* TODO MSC split -- creating a BSC subscriber directly from
		 * MSC data structures in RAM. At some point the MSC will send
		 * a message to the BSC instead. */
		bsub = bsc_subscr_find_or_create_by_imsi(net->bsc_subscribers,
							 subscr->imsi);
		bsub->tmsi = subscr->tmsi;
		bsub->lac = subscr->lac;
		rc = paging_request(net, bsub, channel_type, subscr_paging_cb,
				    subscr);
		bsc_subscr_put(bsub);
		if (rc <= 0) {
			LOGP(DMM, LOGL_ERROR, "Subscriber %s paging failed: %d\n",
				subscr_name(subscr), rc);
			return NULL;
		}
		/* reduced on the first paging callback */
		subscr_get(subscr);
		subscr->is_paging = 1;
	}

	/* TODO: Stop paging in case of memory allocation failure */
	request = talloc_zero(subscr, struct subscr_request);
	if (!request)
		return NULL;

	request->cbfn = cbfn;
	request->param = param;
	llist_add_tail(&request->entry, &subscr->requests);
	return request;
}

void subscr_remove_request(struct subscr_request *request)
{
	llist_del(&request->entry);
	talloc_free(request);
}

struct gsm_subscriber *subscr_create_subscriber(struct gsm_subscriber_group *sgrp,
						const char *imsi)
{
	struct gsm_subscriber *subscr = db_create_subscriber(imsi,
							     sgrp->net->ext_min,
							     sgrp->net->ext_max,
							     sgrp->net->auto_assign_exten);
	if (subscr)
		subscr->group = sgrp;
	return subscr;
}

struct gsm_subscriber *subscr_get_by_tmsi(struct gsm_subscriber_group *sgrp,
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
	return get_subscriber(sgrp, GSM_SUBSCRIBER_TMSI, tmsi_string);
}

struct gsm_subscriber *subscr_get_by_imsi(struct gsm_subscriber_group *sgrp,
					  const char *imsi)
{
	struct gsm_subscriber *subscr;

	llist_for_each_entry(subscr, subscr_bsc_active_subscribers(), entry) {
		if (strcmp(subscr->imsi, imsi) == 0)
			return subscr_get(subscr);
	}

	return get_subscriber(sgrp, GSM_SUBSCRIBER_IMSI, imsi);
}

struct gsm_subscriber *subscr_get_by_extension(struct gsm_subscriber_group *sgrp,
					       const char *ext)
{
	struct gsm_subscriber *subscr;

	llist_for_each_entry(subscr, subscr_bsc_active_subscribers(), entry) {
		if (strcmp(subscr->extension, ext) == 0)
			return subscr_get(subscr);
	}

	return get_subscriber(sgrp, GSM_SUBSCRIBER_EXTENSION, ext);
}

struct gsm_subscriber *subscr_get_by_id(struct gsm_subscriber_group *sgrp,
					unsigned long long id)
{
	struct gsm_subscriber *subscr;
	char buf[32];
	sprintf(buf, "%llu", id);

	llist_for_each_entry(subscr, subscr_bsc_active_subscribers(), entry) {
		if (subscr->id == id)
			return subscr_get(subscr);
	}

	return get_subscriber(sgrp, GSM_SUBSCRIBER_ID, buf);
}

int subscr_update_expire_lu(struct gsm_subscriber *s, struct gsm_bts *bts)
{
	int rc;

	if (!s) {
		LOGP(DMM, LOGL_ERROR, "LU Expiration but NULL subscriber\n");
		return -1;
	}
	if (!bts) {
		LOGP(DMM, LOGL_ERROR, "%s: LU Expiration but NULL bts\n",
		     subscr_name(s));
		return -1;
	}

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
		s->group = bts->network->subscr_group;
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
	struct gsm_subscriber *s = subscr_get_by_id(net->subscr_group, id);
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
		subscr_put(s);
		return;
	}


	LOGP(DMM, LOGL_NOTICE, "Expiring inactive subscriber %s (ID %llu)\n",
			subscr_name(s), id);
	s->lac = GSM_LAC_RESERVED_DETACHED;
	db_sync_subscriber(s);

	subscr_put(s);
}

void subscr_expire(struct gsm_subscriber_group *sgrp)
{
	db_subscriber_expire(sgrp->net, subscr_expire_callback);
}

struct gsm_subscriber_connection *connection_for_subscr(struct gsm_subscriber *subscr)
{
	/* FIXME: replace this with a backpointer in gsm_subscriber? */
	struct gsm_network *net = subscr->group->net;
	struct gsm_subscriber_connection *conn;

	llist_for_each_entry(conn, &net->subscr_conns, entry) {
		if (conn->subscr == subscr)
			return conn;
	}

	return NULL;
}
