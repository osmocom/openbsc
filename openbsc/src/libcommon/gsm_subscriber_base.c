/* The concept of a subscriber as seen by the BSC */

/* (C) 2008 by Harald Welte <laforge@gnumonks.org>
 * (C) 2009-2010 by Holger Hans Peter Freyther <zecke@selfish.org>
 * (C) 2010 by On-Waves
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

#include <osmocom/core/talloc.h>
#include <openbsc/gsm_subscriber.h>
#include <openbsc/debug.h>

LLIST_HEAD(active_subscribers);
void *tall_subscr_ctx;

/* for the gsm_subscriber.c */
struct llist_head *subscr_bsc_active_subscribers(void)
{
	return &active_subscribers;
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

void subscr_direct_free(struct gsm_subscriber *subscr)
{
	OSMO_ASSERT(subscr->use_count == 1);
	subscr_free(subscr);
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
	if (subscr->use_count <= 0 && !subscr->net->keep_subscr)
		subscr_free(subscr);
	return NULL;
}

struct gsm_subscriber *subscr_get_or_create(struct gsm_network *net,
					    const char *imsi)
{
	struct gsm_subscriber *subscr;

	llist_for_each_entry(subscr, subscr_bsc_active_subscribers(), entry) {
		if (strcmp(subscr->imsi, imsi) == 0 && subscr->net == net)
			return subscr_get(subscr);
	}

	subscr = subscr_alloc();
	if (!subscr)
		return NULL;

	strncpy(subscr->imsi, imsi, GSM_IMSI_LENGTH);
	subscr->imsi[GSM_IMSI_LENGTH - 1] = '\0';
	subscr->net = net;
	return subscr;
}

struct gsm_subscriber *subscr_active_by_tmsi(struct gsm_network *net, uint32_t tmsi)
{
	struct gsm_subscriber *subscr;

	llist_for_each_entry(subscr, subscr_bsc_active_subscribers(), entry) {
		if (subscr->tmsi == tmsi && subscr->net == net)
			return subscr_get(subscr);
	}

	return NULL;
}

struct gsm_subscriber *subscr_active_by_imsi(struct gsm_network *net, const char *imsi)
{
	struct gsm_subscriber *subscr;

	llist_for_each_entry(subscr, subscr_bsc_active_subscribers(), entry) {
		if (strcmp(subscr->imsi, imsi) == 0 && subscr->net == net)
			return subscr_get(subscr);
	}

	return NULL;
}

int subscr_purge_inactive(struct gsm_network *net)
{
	struct gsm_subscriber *subscr, *tmp;
	int purged = 0;

	llist_for_each_entry_safe(subscr, tmp, subscr_bsc_active_subscribers(), entry) {
		if (subscr->net == net && subscr->use_count <= 0) {
			subscr_free(subscr);
			purged += 1;
		}
	}

	return purged;
}
