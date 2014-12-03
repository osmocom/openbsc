/* (C) 2008 by Jan Luebbe <jluebbe@debian.org>
 * (C) 2009 by Holger Hans Peter Freyther <zecke@selfish.org>
 * (C) 2014 by Alexander Chemeris <Alexander.Chemeris@fairwaves.co>
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
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include <openbsc/debug.h>
#include <openbsc/db.h>
#include <openbsc/gsm_subscriber.h>
#include <openbsc/gsm_04_11.h>

#include <osmocom/core/application.h>

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <inttypes.h>

static struct gsm_network dummy_net;
static struct gsm_subscriber_group dummy_sgrp;

static void test_subscr(void)
{
	struct gsm_subscriber *subscr;
	const char *imsi = "1234567890";

	printf("Test subscriber allocation and deletion\n");

	/* Don't keep subscr */

	dummy_sgrp.keep_subscr = 0;

	OSMO_ASSERT(llist_empty(&active_subscribers));

	subscr = subscr_get_or_create(&dummy_sgrp, imsi);

	OSMO_ASSERT(!llist_empty(&active_subscribers));
	OSMO_ASSERT(subscr->use_count == 1);

	subscr_put(subscr);

	OSMO_ASSERT(llist_empty(&active_subscribers));

	/* Keep subscr */

	dummy_sgrp.keep_subscr = 1;

	subscr = subscr_get_or_create(&dummy_sgrp, imsi);

	OSMO_ASSERT(!llist_empty(&active_subscribers));
	OSMO_ASSERT(subscr->use_count == 1);

	subscr_put(subscr);
	OSMO_ASSERT(!llist_empty(&active_subscribers));
	OSMO_ASSERT(subscr->use_count == 0);

	subscr_get(subscr);
	OSMO_ASSERT(subscr->use_count == 1);

	subscr_purge_inactive(&dummy_sgrp);

	OSMO_ASSERT(!llist_empty(&active_subscribers));
	OSMO_ASSERT(subscr->use_count == 1);

	subscr_put(subscr);
	OSMO_ASSERT(!llist_empty(&active_subscribers));
	OSMO_ASSERT(subscr->use_count == 0);

	subscr_purge_inactive(&dummy_sgrp);

	OSMO_ASSERT(llist_empty(&active_subscribers));

	/* Test force_no_keep */

	dummy_sgrp.keep_subscr = 0;

	subscr = subscr_get_or_create(&dummy_sgrp, imsi);
	OSMO_ASSERT(subscr);
	subscr->keep_in_ram = 1;

	OSMO_ASSERT(!llist_empty(&active_subscribers));
	OSMO_ASSERT(subscr->use_count == 1);

	subscr->keep_in_ram = 0;

	subscr_put(subscr);
	OSMO_ASSERT(llist_empty(&active_subscribers));
}

int main()
{
	printf("Testing subscriber core code.\n");
	osmo_init_logging(&log_info);
	log_set_print_filename(osmo_stderr_target, 0);

	dummy_net.subscr_group = &dummy_sgrp;
	dummy_sgrp.net         = &dummy_net;

	test_subscr();

	printf("Done\n");
	return 0;
}
