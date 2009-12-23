/* utility routines for keeping some statistics */

/* (C) 2009 by Harald Welte <laforge@gnumonks.org>
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


#include <sys/types.h>

#include <openbsc/gsm_data.h>
#include <openbsc/signal.h>
#include <openbsc/linuxlist.h>
#include <openbsc/talloc.h>
#include <openbsc/statistics.h>
#include <openbsc/db.h>
#include <openbsc/timer.h>

static LLIST_HEAD(counters);

static struct timer_list db_sync_timer;

#define DB_SYNC_INTERVAL	60, 0

struct counter *counter_alloc(const char *name)
{
	struct counter *ctr = talloc_zero(tall_bsc_ctx, struct counter);

	if (!ctr)
		return NULL;

	ctr->name = name;
	llist_add_tail(&ctr->list, &counters);

	return ctr;
}

void counter_free(struct counter *ctr)
{
	llist_del(&ctr->list);
	talloc_free(ctr);
}

static int counters_store_db(void)
{
	struct counter *ctr;
	int rc = 0;

	llist_for_each_entry(ctr, &counters, list) {
		rc = db_store_counter(ctr);
		if (rc < 0)
			return rc;
	}

	return rc;
}

static void db_sync_timer_cb(void *data)
{
	/* store counters to database and re-schedule */
	counters_store_db();
	bsc_schedule_timer(&db_sync_timer, DB_SYNC_INTERVAL);
}

static __attribute__((constructor)) void on_dso_load_stat(void)
{
	db_sync_timer.cb = db_sync_timer_cb;
	db_sync_timer.data = NULL;
	bsc_schedule_timer(&db_sync_timer, DB_SYNC_INTERVAL);
}
