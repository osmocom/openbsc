/* The concept of a subscriber for the MSC, roughly HLR/VLR functionality */

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

#include <openbsc/gsm_subscriber.h>
#include <openbsc/debug.h>
#include <openbsc/signal.h>
#include <openbsc/db.h>

extern struct llist_head *subscr_bsc_active_subscriber(void);

struct gsm_subscriber *subscr_get_by_tmsi(struct gsm_network *net,
					  u_int32_t tmsi)
{
	char tmsi_string[14];
	struct gsm_subscriber *subscr;

	/* we might have a record in memory already */
	llist_for_each_entry(subscr, subscr_bsc_active_subscriber(), entry) {
		if (tmsi == subscr->tmsi)
			return subscr_get(subscr);
	}

	sprintf(tmsi_string, "%u", tmsi);
	return db_get_subscriber(net, GSM_SUBSCRIBER_TMSI, tmsi_string);
}

struct gsm_subscriber *subscr_get_by_imsi(struct gsm_network *net,
					  const char *imsi)
{
	struct gsm_subscriber *subscr;

	llist_for_each_entry(subscr, subscr_bsc_active_subscriber(), entry) {
		if (strcmp(subscr->imsi, imsi) == 0)
			return subscr_get(subscr);
	}

	return db_get_subscriber(net, GSM_SUBSCRIBER_IMSI, imsi);
}

struct gsm_subscriber *subscr_get_by_extension(struct gsm_network *net,
					       const char *ext)
{
	struct gsm_subscriber *subscr;

	llist_for_each_entry(subscr, subscr_bsc_active_subscriber(), entry) {
		if (strcmp(subscr->extension, ext) == 0)
			return subscr_get(subscr);
	}

	return db_get_subscriber(net, GSM_SUBSCRIBER_EXTENSION, ext);
}

struct gsm_subscriber *subscr_get_by_id(struct gsm_network *net,
					unsigned long long id)
{
	struct gsm_subscriber *subscr;
	char buf[32];
	sprintf(buf, "%llu", id);

	llist_for_each_entry(subscr, subscr_bsc_active_subscriber(), entry) {
		if (subscr->id == id)
			return subscr_get(subscr);
	}

	return db_get_subscriber(net, GSM_SUBSCRIBER_ID, buf);
}


int subscr_update(struct gsm_subscriber *s, struct gsm_bts *bts, int reason)
{
	/* FIXME: Migrate pending requests from one BSC to another */
	switch (reason) {
	case GSM_SUBSCRIBER_UPDATE_ATTACHED:
		s->net = bts->network;
		/* Indicate "attached to LAC" */
		s->lac = bts->location_area_code;
		LOGP(DMM, LOGL_INFO, "Subscriber %s ATTACHED LAC=%u\n",
			s->imsi, s->lac);
		dispatch_signal(SS_SUBSCR, S_SUBSCR_ATTACHED, s);
		break;
	case GSM_SUBSCRIBER_UPDATE_DETACHED:
		/* Only detach if we are currently in this area */
		if (bts->location_area_code == s->lac)
			s->lac = GSM_LAC_RESERVED_DETACHED;
		LOGP(DMM, LOGL_INFO, "Subscriber %s DETACHED\n", s->imsi);
		dispatch_signal(SS_SUBSCR, S_SUBSCR_DETACHED, s);
		break;
	default:
		fprintf(stderr, "subscr_update with unknown reason: %d\n",
			reason);
		break;
	};
	return db_sync_subscriber(s);
}


