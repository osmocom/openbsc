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
#include <regex.h>
#include <sys/types.h>

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


static struct gsm_subscriber *get_subscriber(struct gsm_subscriber_group *sgrp,
						int type, const char *ident)
{
	struct gsm_subscriber *subscr = db_get_subscriber(type, ident);
	if (subscr)
		subscr->group = sgrp;
	return subscr;
}

/* A connection is established and the paging callbacks may run now. */
static int subscr_paging_dispatch(unsigned int hooknum, unsigned int event,
				  struct msgb *msg, void *data, void *param)
{
	struct subscr_request *request, *tmp;
	struct gsm_subscriber_connection *conn = data;
	struct gsm_subscriber *subscr = param;
	struct paging_signal_data sig_data;

	OSMO_ASSERT(hooknum == GSM_HOOK_RR_PAGING);
	OSMO_ASSERT(subscr);
	OSMO_ASSERT(!(conn && (conn->subscr != subscr)));
	OSMO_ASSERT(!((event == GSM_PAGING_SUCCEEDED) && !conn));

	LOGP(DPAG, LOGL_DEBUG, "Paging %s for %s (event=%d)\n",
	     event == GSM_PAGING_SUCCEEDED ? "success" : "failure",
	     subscr_name(subscr), event);

	if (!subscr->is_paging) {
		LOGP(DPAG, LOGL_ERROR,
		     "Paging Response received for subscriber"
		     " that is not paging.\n");
		return -EINVAL;
	}

	/* Inform parts of the system we don't know */
	sig_data.subscr = subscr;
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
		if (request->cbfn) {
			LOGP(DPAG, LOGL_DEBUG, "Calling paging cbfn.\n");
			request->cbfn(hooknum, event, msg, data, request->param);
		} else
			LOGP(DPAG, LOGL_DEBUG, "Paging without action.\n");
		talloc_free(request);
	}

	/* balanced with the moment we start paging */
	subscr->is_paging = 0;

	/* balanced with the moment we receive a paging response */
	subscr_put(subscr);
	return 0;
}

static void paging_timeout_release(struct gsm_subscriber *subscr)
{
	DEBUGP(DPAG, "Paging timeout released for %s\n", subscr_name(subscr));
	osmo_timer_del(&subscr->paging_timeout);
}

static void paging_timeout(void *data)
{
	struct gsm_subscriber *subscr = data;
	DEBUGP(DPAG, "Paging timeout reached for %s\n", subscr_name(subscr));
	paging_timeout_release(subscr);
	subscr_paging_dispatch(GSM_HOOK_RR_PAGING, GSM_PAGING_EXPIRED,
			       NULL, NULL, subscr);
}

static void paging_timeout_start(struct gsm_subscriber *subscr)
{
	DEBUGP(DPAG, "Starting paging timeout for %s\n", subscr_name(subscr));
	subscr->paging_timeout.data = subscr;
	subscr->paging_timeout.cb = paging_timeout;
	osmo_timer_schedule(&subscr->paging_timeout, 10, 0);
	/* TODO: configurable timeout duration? */
}


static int subscr_paging_sec_cb(unsigned int hooknum, unsigned int event,
                                struct msgb *msg, void *data, void *param)
{
	int rc;
	struct gsm_subscriber_connection *conn = data;
	OSMO_ASSERT(conn);

	switch (event) {
		case GSM_SECURITY_AUTH_FAILED:
			LOGP(DPAG, LOGL_ERROR,
			     "Dropping Paging Response:"
			     " authorization failed for subscriber %s\n",
			     subscr_name(conn->subscr));
			rc = subscr_paging_dispatch(
				GSM_HOOK_RR_PAGING, GSM_PAGING_EXPIRED,
				msg, conn, conn->subscr);
			break;

		case GSM_SECURITY_NOAVAIL:
		case GSM_SECURITY_SUCCEEDED:
			rc = subscr_paging_dispatch(
				GSM_HOOK_RR_PAGING, GSM_PAGING_SUCCEEDED,
				msg, conn, conn->subscr);
			break;

		default:
			LOGP(DPAG, LOGL_FATAL,
			     "Invalid authorization event: %d\n", event);
			rc = -EINVAL;
	}

	return rc;
}

int subscr_rx_paging_response(struct msgb *msg,
			      struct gsm_subscriber_connection *conn)
{
	struct gsm48_hdr *gh;
	struct gsm48_pag_resp *pr;

	/* Get key_seq from Paging Response headers */
	gh = msgb_l3(msg);
	pr = (struct gsm48_pag_resp *)gh->data;

	paging_timeout_release(conn->subscr);

	/* Secure the connection */
	if (subscr_authorized(conn->subscr))
		return gsm48_secure_channel(conn, pr->key_seq,
					    subscr_paging_sec_cb, NULL);

	/* Not authorized. Failure. */
	subscr_paging_sec_cb(GSM_HOOK_RR_SECURITY, GSM_SECURITY_AUTH_FAILED,
			     msg, conn, NULL);
	return -1;
}

static int msc_paging_request(struct gsm_subscriber *subscr)
{
	/* The subscriber was last seen in subscr->lac. Find out which
	 * BSCs/RNCs are responsible and send them a paging request via open
	 * SCCP connections (if any). */
	/* TODO Implementing only RNC paging, since this is code on the iu branch.
	 * Need to add BSC paging at some point. */
	return iu_page_cs(subscr->imsi,
			  subscr->tmsi == GSM_RESERVED_TMSI?
				NULL : &subscr->tmsi,
			  subscr->lac);
}

struct subscr_request *subscr_request_conn(struct gsm_subscriber *subscr,
					   gsm_cbfn *cbfn, void *param)
{
	int rc;
	struct subscr_request *request;

	/* Start paging.. we know it is async so we can do it before */
	if (!subscr->is_paging) {
		LOGP(DMM, LOGL_DEBUG, "Subscriber %s not paged yet, start paging.\n",
			subscr_name(subscr));
		rc = msc_paging_request(subscr);
		if (rc <= 0) {
			LOGP(DMM, LOGL_ERROR, "Subscriber %s paging failed: %d\n",
				subscr_name(subscr), rc);
			return NULL;
		}
		/* reduced in subscr_rx_paging_response() */
		subscr_get(subscr);
		subscr->is_paging = 1;
		LOGP(DMM, LOGL_DEBUG, "Paged subscriber %s.\n",
		     subscr_name(subscr));
		paging_timeout_start(subscr);
	}
	else {
		LOGP(DMM, LOGL_DEBUG, "Subscriber %s already paged.\n",
			subscr_name(subscr));
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

int subscr_update_expire_lu(struct gsm_subscriber *s)
{
	int rc;
	struct gsm_network *network = s->group->net;

	/* Table 10.5.33: The T3212 timeout value field is coded as the
	 * binary representation of the timeout value for
	 * periodic updating in decihours. Mark the subscriber as
	 * inactive if it missed two consecutive location updates.
	 * Timeout is twice the t3212 value plus one minute */

	/* Is expiration handling enabled? */
	if (network->t3212 == 0)
		s->expire_lu = GSM_SUBSCRIBER_NO_EXPIRATION;
	else
		s->expire_lu = time(NULL) + (network->t3212 * 60 * 6 * 2) + 60;

	rc = db_sync_subscriber(s);
	db_subscriber_update(s);
	return rc;
}

int subscr_update(struct gsm_subscriber *s, uint16_t lac, int reason)
{
	int rc;
	struct gsm_network *network = s->group->net;

	/* FIXME: Migrate pending requests from one BSC to another */
	switch (reason) {
	case GSM_SUBSCRIBER_UPDATE_ATTACHED:
		s->group = network->subscr_group;
		/* Indicate "attached to LAC" */
		s->lac = lac;

		LOGP(DMM, LOGL_INFO, "Subscriber %s ATTACHED LAC=%u\n",
			subscr_name(s), s->lac);

		/*
		 * The below will set a new expire_lu but as a side-effect
		 * the new lac will be saved in the database.
		 */
		rc = subscr_update_expire_lu(s);
		osmo_signal_dispatch(SS_SUBSCR, S_SUBSCR_ATTACHED, s);
		break;
	case GSM_SUBSCRIBER_UPDATE_DETACHED:
		/* Only detach if we are currently in this area */
		if (lac == s->lac)
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
		subscr_update_expire_lu(s);
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

/*! Validate IMSI against the authorized IMSI regexp.
 * \returns true if IMSI matches the configured authorized_regexp.
 */
bool subscr_authorized_imsi(const struct gsm_network *net, const char *imsi)
{
	if (!net->authorized_reg_str)
		return false;

	if (regexec(&net->authorized_regexp, imsi, 0, NULL, 0) != REG_NOMATCH)
		return true;

	return false;
}

bool subscr_authorized(struct gsm_subscriber *subscriber)
{
	switch (subscriber->group->net->auth_policy) {
	case GSM_AUTH_POLICY_CLOSED:
		LOGP(DMM, LOGL_DEBUG, "subscriber %s authorized = %d\n",
		     subscr_name(subscriber), subscriber->authorized);
		return subscriber->authorized ? true : false;
	case GSM_AUTH_POLICY_REGEXP:
		if (subscriber->authorized)
			return true;
		if (subscr_authorized_imsi(subscriber->group->net,
					   subscriber->imsi))
			subscriber->authorized = true;
		return subscriber->authorized;
	case GSM_AUTH_POLICY_TOKEN:
		if (subscriber->authorized) {
			LOGP(DMM, LOGL_DEBUG,
			     "subscriber %s authorized = %d\n",
			     subscr_name(subscriber), subscriber->authorized);
			return subscriber->authorized;
		}
		LOGP(DMM, LOGL_DEBUG, "subscriber %s first contact = %d\n",
		     subscr_name(subscriber),
		     (int)(subscriber->flags & GSM_SUBSCRIBER_FIRST_CONTACT));
		return (subscriber->flags & GSM_SUBSCRIBER_FIRST_CONTACT);
	case GSM_AUTH_POLICY_ACCEPT_ALL:
		return true;
	default:
		LOGP(DMM, LOGL_DEBUG, "unknown auth_policy, rejecting"
		     " subscriber %s\n", subscr_name(subscriber));
		return false;
	}
}
