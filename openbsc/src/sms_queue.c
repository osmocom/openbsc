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
#include <openbsc/signal.h>

#include <osmocore/talloc.h>


struct gsm_sms_queue {
	struct gsm_network *network;
	int max_pending;
	int pending;
};


int sms_queue_start(struct gsm_network *network, int max_pending)
{
	struct gsm_sms_queue *sms = talloc_zero(network, struct gsm_sms_queue);
	if (!sms) {
		LOGP(DMSC, LOGL_ERROR, "Failed to create the SMS queue.\n");
		return -1;
	}

	network->sms_queue = sms;
	sms->network = network;
	sms->max_pending = max_pending;

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

static __attribute__((constructor)) void on_dso_load_sms(void)
{
	register_signal_handler(SS_SUBSCR, sms_subscr_cb, NULL);
}
