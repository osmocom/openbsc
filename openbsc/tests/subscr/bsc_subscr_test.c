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
#include <openbsc/bsc_subscriber.h>

#include <osmocom/core/application.h>
#include <osmocom/core/utils.h>

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <inttypes.h>

struct llist_head *bsc_subscribers;

#define VERBOSE_ASSERT(val, expect_op, fmt) \
	do { \
		printf(#val " == " fmt "\n", (val)); \
		OSMO_ASSERT((val) expect_op); \
	} while (0);

static void assert_bsc_subscr(const struct bsc_subscr *bsub, const char *imsi)
{
	struct bsc_subscr *sfound;
	OSMO_ASSERT(bsub);
	OSMO_ASSERT(strcmp(bsub->imsi, imsi) == 0);

	sfound = bsc_subscr_find_by_imsi(bsc_subscribers, imsi);
	OSMO_ASSERT(sfound == bsub);

	bsc_subscr_put(sfound);
}

static void test_bsc_subscr(void)
{
	struct bsc_subscr *s1, *s2, *s3;
	const char *imsi1 = "1234567890";
	const char *imsi2 = "9876543210";
	const char *imsi3 = "5656565656";

	printf("Test BSC subscriber allocation and deletion\n");

	/* Check for emptiness */
	VERBOSE_ASSERT(llist_count(bsc_subscribers), == 0, "%d");
	OSMO_ASSERT(bsc_subscr_find_by_imsi(bsc_subscribers, imsi1) == NULL);
	OSMO_ASSERT(bsc_subscr_find_by_imsi(bsc_subscribers, imsi2) == NULL);
	OSMO_ASSERT(bsc_subscr_find_by_imsi(bsc_subscribers, imsi3) == NULL);

	/* Allocate entry 1 */
	s1 = bsc_subscr_find_or_create_by_imsi(bsc_subscribers, imsi1);
	VERBOSE_ASSERT(llist_count(bsc_subscribers), == 1, "%d");
	assert_bsc_subscr(s1, imsi1);
	VERBOSE_ASSERT(llist_count(bsc_subscribers), == 1, "%d");
	OSMO_ASSERT(bsc_subscr_find_by_imsi(bsc_subscribers, imsi2) == NULL);

	/* Allocate entry 2 */
	s2 = bsc_subscr_find_or_create_by_imsi(bsc_subscribers, imsi2);
	VERBOSE_ASSERT(llist_count(bsc_subscribers), == 2, "%d");

	/* Allocate entry 3 */
	s3 = bsc_subscr_find_or_create_by_imsi(bsc_subscribers, imsi3);
	VERBOSE_ASSERT(llist_count(bsc_subscribers), == 3, "%d");

	/* Check entries */
	assert_bsc_subscr(s1, imsi1);
	assert_bsc_subscr(s2, imsi2);
	assert_bsc_subscr(s3, imsi3);

	/* Free entry 1 */
	bsc_subscr_put(s1);
	s1 = NULL;
	VERBOSE_ASSERT(llist_count(bsc_subscribers), == 2, "%d");
	OSMO_ASSERT(bsc_subscr_find_by_imsi(bsc_subscribers, imsi1) == NULL);

	assert_bsc_subscr(s2, imsi2);
	assert_bsc_subscr(s3, imsi3);

	/* Free entry 2 */
	bsc_subscr_put(s2);
	s2 = NULL;
	VERBOSE_ASSERT(llist_count(bsc_subscribers), == 1, "%d");
	OSMO_ASSERT(bsc_subscr_find_by_imsi(bsc_subscribers, imsi1) == NULL);
	OSMO_ASSERT(bsc_subscr_find_by_imsi(bsc_subscribers, imsi2) == NULL);
	assert_bsc_subscr(s3, imsi3);

	/* Free entry 3 */
	bsc_subscr_put(s3);
	s3 = NULL;
	VERBOSE_ASSERT(llist_count(bsc_subscribers), == 0, "%d");
	OSMO_ASSERT(bsc_subscr_find_by_imsi(bsc_subscribers, imsi3) == NULL);

	OSMO_ASSERT(llist_empty(bsc_subscribers));
}

int main()
{
	printf("Testing BSC subscriber core code.\n");
	osmo_init_logging(&log_info);
	log_set_print_filename(osmo_stderr_target, 0);
	log_set_print_timestamp(osmo_stderr_target, 0);
	log_set_use_color(osmo_stderr_target, 0);
	log_set_print_category(osmo_stderr_target, 1);
	log_set_category_filter(osmo_stderr_target, DREF, 1, LOGL_DEBUG);

	bsc_subscribers = talloc_zero(NULL, struct llist_head);
	INIT_LLIST_HEAD(bsc_subscribers);

	test_bsc_subscr();

	printf("Done\n");
	return 0;
}
