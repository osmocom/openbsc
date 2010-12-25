/* SMS queue to continously attempt to deliver SMS */
/*
 * (C) 2010 by Holger Hans Peter Freyther <zecke@selfish.org>
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

/**
 * The difficulty of such a queue is to send a lot of SMS without
 * overloading the paging subsystem and the database and other users
 * of the MSC. To make the best use we would need to know the number
 * of pending paging requests, then throttle the number of SMS we
 * want to send and such.
 * We will start with a very simple SMS Queue and then try to speed
 * things up by collecting data from other parts of the system.
 */

#include <openbsc/sms_queue.h>
#include <openbsc/chan_alloc.h>
#include <openbsc/db.h>
#include <openbsc/debug.h>
#include <openbsc/gsm_data.h>
#include <openbsc/gsm_04_11.h>
#include <openbsc/gsm_subscriber.h>
#include <openbsc/signal.h>

#include <osmocore/talloc.h>

#include <osmocom/vty/vty.h>

/*
 * One pending SMS that we wait for.
 */
struct gsm_sms_pending {
	struct llist_head entry;

	struct gsm_subscriber *subscr;
	unsigned long long sms_id;
	int failed_attempts;
	int resend;
};

struct gsm_sms_queue {
	struct timer_list resend_pending;
	struct timer_list push_queue;
	struct gsm_network *network;
	int max_fail;
	int max_pending;
	int pending;

	struct llist_head pending_sms;
	unsigned long long last_subscr_id;
};

static int sms_subscr_cb(unsigned int, unsigned int, void *, void *);
static int sms_sms_cb(unsigned int, unsigned int, void *, void *);

static struct gsm_sms_pending *sms_find_pending(struct gsm_sms_queue *smsq,
						struct gsm_sms *sms)
{
	struct gsm_sms_pending *pending;

	llist_for_each_entry(pending, &smsq->pending_sms, entry) {
		if (pending->sms_id == sms->id)
			return pending;
	}

	return NULL;
}

static int sms_is_in_pending(struct gsm_sms_queue *smsq, struct gsm_sms *sms)
{
	return sms_find_pending(smsq, sms) != NULL;
}

static int sms_subscriber_is_pending(struct gsm_sms_queue *smsq,
				     struct gsm_subscriber *subscr)
{
	struct gsm_sms_pending *pending;

	llist_for_each_entry(pending, &smsq->pending_sms, entry) {
		if (pending->subscr == subscr)
			return 1;
	}

	return 0;
}

static struct gsm_sms_pending *sms_pending_from(struct gsm_sms_queue *smsq,
						struct gsm_sms *sms)
{
	struct gsm_sms_pending *pending;

	pending = talloc_zero(smsq, struct gsm_sms_pending);
	if (!pending)
		return NULL;

	pending->subscr = subscr_get(sms->receiver);
	pending->sms_id = sms->id;
	return pending;
}

static void sms_pending_free(struct gsm_sms_pending *pending)
{
	subscr_put(pending->subscr);
	llist_del(&pending->entry);
	talloc_free(pending);
}

static void sms_pending_resend(struct gsm_sms_pending *pending)
{
	struct gsm_sms_queue *smsq;
	LOGP(DSMS, LOGL_DEBUG,
	     "Scheduling resend of SMS %llu.\n", pending->sms_id);

	pending->resend = 1;

	smsq = pending->subscr->net->sms_queue;
	if (bsc_timer_pending(&smsq->resend_pending))
		return;

	bsc_schedule_timer(&smsq->resend_pending, 1, 0);
}

static void sms_pending_failed(struct gsm_sms_pending *pending, int paging_error)
{
	struct gsm_sms_queue *smsq;

	LOGP(DSMS, LOGL_NOTICE, "Sending SMS %llu failed %d times.\n",
	     pending->sms_id, pending->failed_attempts);

	smsq = pending->subscr->net->sms_queue;
	if (++pending->failed_attempts < smsq->max_fail)
		return sms_pending_resend(pending);

	if (paging_error) {
		LOGP(DSMS, LOGL_NOTICE,
		     "Subscriber %llu is not reachable. Setting LAC=0.\n", pending->subscr->id);
		pending->subscr->lac = GSM_LAC_RESERVED_DETACHED;
		db_sync_subscriber(pending->subscr);

		/* Workaround a failing sync */
		db_subscriber_update(pending->subscr);
	}

	sms_pending_free(pending);
	smsq->pending -= 1;
	sms_queue_trigger(smsq);
}

/*
 * Resend all SMS that are scheduled for a resend. This is done to
 * avoid an immediate failure.
 */
static void sms_resend_pending(void *_data)
{
	struct gsm_sms_pending *pending, *tmp;
	struct gsm_sms_queue *smsq = _data;

	llist_for_each_entry_safe(pending, tmp, &smsq->pending_sms, entry) {
		struct gsm_sms *sms;
		if (!pending->resend)
			continue;

		sms = db_sms_get(smsq->network, pending->sms_id);

		/* the sms is gone? Move to the next */
		if (!sms) {
			sms_pending_free(pending);
			smsq->pending -= 1;
			sms_queue_trigger(smsq);
		} else {
			pending->resend = 0;
			gsm411_send_sms_subscr(sms->receiver, sms);
		}
	}
}

/**
 * I will submit up to max_pending - pending SMS to the
 * subsystem.
 */
static void sms_submit_pending(void *_data)
{
	struct gsm_sms_queue *smsq = _data;
	int attempts = smsq->max_pending - smsq->pending;
	int i;

	LOGP(DSMS, LOGL_NOTICE, "Attempting to send %d SMS\n", attempts);

	for (i = 0; i < attempts; ++i) {
		struct gsm_sms_pending *pending;
		struct gsm_sms *sms;

		sms = db_sms_get_unsent_by_subscr(smsq->network, smsq->last_subscr_id, 10);

		/* handle wrapping around */
		if (!sms) {
			smsq->last_subscr_id = 0;
			sms = db_sms_get_unsent_by_subscr(smsq->network,
							  smsq->last_subscr_id, 10);
		}

		if (!sms)
			break;

		/* no need to send a pending sms */
		if (sms_is_in_pending(smsq, sms)) {
			LOGP(DSMS, LOGL_DEBUG,
			     "SMSqueue with pending sms: %llu\n. Skipping", sms->id);
			sms_free(sms);
			continue;
		}

		/* no need to send a SMS with the same receiver */
		if (sms_subscriber_is_pending(smsq, sms->receiver)) {
			LOGP(DSMS, LOGL_DEBUG,
			     "SMSqueue with pending sub: %llu. Skipping\n", sms->receiver->id);
			sms_free(sms);
			continue;
		}

		pending = sms_pending_from(smsq, sms);
		if (!pending) {
			LOGP(DSMS, LOGL_ERROR,
			     "Failed to create pending SMS entry.\n");
			sms_free(sms);
			continue;
		}

		smsq->last_subscr_id = sms->receiver->id + 1;
		smsq->pending += 1;
		llist_add(&pending->entry, &smsq->pending_sms);
		gsm411_send_sms_subscr(sms->receiver, sms);
	}
}

/*
 * Kick off the queue again.
 */
int sms_queue_trigger(struct gsm_sms_queue *smsq)
{
	if (bsc_timer_pending(&smsq->push_queue))
		return 0;

	bsc_schedule_timer(&smsq->push_queue, 1, 0);
	return 0;
}

int sms_queue_start(struct gsm_network *network, int max_pending)
{
	struct gsm_sms_queue *sms = talloc_zero(network, struct gsm_sms_queue);
	if (!sms) {
		LOGP(DMSC, LOGL_ERROR, "Failed to create the SMS queue.\n");
		return -1;
	}

	register_signal_handler(SS_SUBSCR, sms_subscr_cb, network);
	register_signal_handler(SS_SMS, sms_sms_cb, network);

	network->sms_queue = sms;
	INIT_LLIST_HEAD(&sms->pending_sms);
	sms->max_fail = 3;
	sms->network = network;
	sms->max_pending = max_pending;
	sms->push_queue.data = sms;
	sms->push_queue.cb = sms_submit_pending;
	sms->resend_pending.data = sms;
	sms->resend_pending.cb = sms_resend_pending;

	sms_submit_pending(sms);

	return 0;
}

static int sub_ready_for_sm(struct gsm_subscriber *subscr)
{
	struct gsm_subscriber_connection *conn;
	struct gsm_sms *sms;

	/* A subscriber has attached. Check if there are
	 * any pending SMS for him to be delivered */
	conn = connection_for_subscr(subscr);
	if (!conn)
		return -1;
	sms = db_sms_get_unsent_for_subscr(subscr);
	if (!sms)
		return -1;
	gsm411_send_sms(conn, sms);
	return 0;
}

static int sms_subscr_cb(unsigned int subsys, unsigned int signal,
			 void *handler_data, void *signal_data)
{
	struct gsm_subscriber *subscr = signal_data;

	if (signal != S_SUBSCR_ATTACHED)
		return 0;

	/* this is readyForSM */
	return sub_ready_for_sm(subscr);
}

static int sms_sms_cb(unsigned int subsys, unsigned int signal,
		      void *handler_data, void *signal_data)
{
	struct gsm_network *network = handler_data;
	struct sms_signal_data *sig_sms = signal_data;
	struct gsm_sms_pending *pending;

	/* We got a new SMS and maybe should launch the queue again. */
	if (signal == S_SMS_SUBMITTED || signal == S_SMS_SMMA) {
		sms_queue_trigger(network->sms_queue);
		return 0;
	}

	if (!sig_sms->sms)
		return -1;


	/*
	 * Find the entry of our queue. The SMS subsystem will submit
	 * sms that are not in our control as we just have a channel
	 * open anyway.
	 */
	pending = sms_find_pending(network->sms_queue, sig_sms->sms);
	if (!pending)
		return 0;

	switch (signal) {
	case S_SMS_DELIVERED:
		/*
		 * Create place for a new SMS but keep the pending data
		 * so we will not attempt to send the SMS for this subscriber
		 * as we still have an open channel and will attempt to submit
		 * SMS to it anyway.
		 */
		network->sms_queue->pending -= 1;
		sms_submit_pending(network->sms_queue);
		sms_pending_free(pending);
		break;
	case S_SMS_MEM_EXCEEDED:
		network->sms_queue->pending -= 1;
		sms_pending_free(pending);
		sms_queue_trigger(network->sms_queue);
		break;
	case S_SMS_UNKNOWN_ERROR:
		/*
		 * There can be many reasons for this failure. E.g. the paging
		 * timed out, the subscriber was not paged at all, or there was
		 * a protocol error. The current strategy is to try sending the
		 * next SMS for busy/oom and to retransmit when we have paged.
		 *
		 * When the paging expires three times we will disable the
		 * subscriber. If we have some kind of other transmit error we
		 * should flag the SMS as bad.
		 */
		switch (sig_sms->paging_result) {
		case 0:
			/* BAD SMS? */
			db_sms_inc_deliver_attempts(sig_sms->sms);
			sms_pending_failed(pending, 0);
			break;
		case GSM_PAGING_EXPIRED:
			sms_pending_failed(pending, 1);
			break;

		case GSM_PAGING_OOM:
		case GSM_PAGING_BUSY:
			network->sms_queue->pending -= 1;
			sms_pending_free(pending);
			sms_queue_trigger(network->sms_queue);
			break;
		default:
			LOGP(DSMS, LOGL_ERROR, "Unhandled result: %d\n",
			     sig_sms->paging_result);
		}
		break;
	default:
		LOGP(DSMS, LOGL_ERROR, "Unhandled result: %d\n",
		     sig_sms->paging_result);
	}

	return 0;
}

/* VTY helper functions */
int sms_queue_stats(struct gsm_sms_queue *smsq, struct vty *vty)
{
	struct gsm_sms_pending *pending;

	vty_out(vty, "SMSqueue with max_pending: %d pending: %d%s",
		smsq->max_pending, smsq->pending, VTY_NEWLINE);

	llist_for_each_entry(pending, &smsq->pending_sms, entry)
		vty_out(vty, " SMS Pending for Subscriber: %llu%s",
			pending->subscr->id, VTY_NEWLINE);
	return 0;
}

int sms_queue_set_max_pending(struct gsm_sms_queue *smsq, int max_pending)
{
	LOGP(DSMS, LOGL_NOTICE, "SMSqueue old max: %d new: %d\n",
	     smsq->max_pending, max_pending);
	smsq->max_pending = max_pending;
	return 0;
}

int sms_queue_set_max_failure(struct gsm_sms_queue *smsq, int max_fail)
{
	LOGP(DSMS, LOGL_NOTICE, "SMSqueue max failure old: %d new: %d\n",
	     smsq->max_fail, max_fail);
	smsq->max_fail = max_fail;
	return 0;
}

int sms_queue_clear(struct gsm_sms_queue *smsq)
{
	struct gsm_sms_pending *pending, *tmp;

	llist_for_each_entry_safe(pending, tmp, &smsq->pending_sms, entry) {
		LOGP(DSMS, LOGL_NOTICE,
		     "SMSqueue clearing for sub %llu\n", pending->subscr->id);
		sms_pending_free(pending);
	}

	return 0;
}
