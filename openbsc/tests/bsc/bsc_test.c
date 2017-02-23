/*
 * BSC Message filtering
 *
 * (C) 2013 by sysmocom s.f.m.c. GmbH
 * Written by Jacob Erlbeck <jerlbeck@sysmocom.de>
 * (C) 2010-2013 by Holger Hans Peter Freyther <zecke@selfish.org>
 * (C) 2010-2013 by On-Waves
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
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */


#include <openbsc/debug.h>
#include <openbsc/gsm_data.h>

#include <openbsc/osmo_bsc.h>
#include <openbsc/bsc_msc_data.h>
#include <openbsc/gsm_04_80.h>
#include <openbsc/gsm_subscriber.h>

#include <osmocom/core/application.h>
#include <osmocom/core/backtrace.h>
#include <osmocom/core/talloc.h>

#include <stdio.h>
#include <search.h>

enum test {
	TEST_SCAN_TO_BTS,
	TEST_SCAN_TO_MSC,
};

/* GSM 04.08 MM INFORMATION test message */
static uint8_t gsm48_mm_info_nn_tzt[] = {
	0x05, 0x32, 0x45, 0x08, 0x80, 0x4f, 0x77, 0xeb,
	0x1a, 0xb6, 0x97, 0xe7, 0x47, 0x31, 0x90, 0x61,
	0x11, 0x02, 0x73, 0x00,
};

static uint8_t gsm48_mm_info_nn_tzt_out[] = {
	0x05, 0x32, 0x45, 0x08, 0x80, 0x4f, 0x77, 0xeb,
	0x1a, 0xb6, 0x97, 0xe7, 0x47, 0x31, 0x90, 0x61,
	0x11, 0x02, 0x73, 0x1a,
};

static uint8_t gsm48_mm_info_nn_tzt_dst[] = {
	0x05, 0x32, 0x45, 0x08, 0x80, 0x4f, 0x77, 0xeb,
	0x1a, 0xb6, 0x97, 0xe7, 0x47, 0x31, 0x90, 0x61,
	0x11, 0x02, 0x73, 0x00, 0x49, 0x01, 0x00,
};

static uint8_t gsm48_mm_info_nn_tzt_dst_out[] = {
	0x05, 0x32, 0x45, 0x08, 0x80, 0x4f, 0x77, 0xeb,
	0x1a, 0xb6, 0x97, 0xe7, 0x47, 0x31, 0x90, 0x61,
	0x11, 0x02, 0x73, 0x1a, 0x49, 0x01, 0x02,
};

struct test_definition {
	const uint8_t *data;
	const uint16_t length;
	const int dir;
	const int result;
	const uint8_t *out_data;
	const uint16_t out_length;
	const char* params;
	const int n_params;
};

static int get_int(const char *params, size_t nmemb, const char *key, int def, int *is_set)
{
	const char *kv = NULL;

	kv = strstr(params, key);
	if (kv) {
		kv += strlen(key) + 1;
		fprintf(stderr, "get_int(%s) -> %d\n", key, atoi(kv));
		if (is_set)
			*is_set = 1;
	}

	return kv ? atoi(kv) : def;
}

static const struct test_definition test_scan_defs[] = {
	{
		.data = gsm48_mm_info_nn_tzt_dst,
		.length = ARRAY_SIZE(gsm48_mm_info_nn_tzt),
		.dir = TEST_SCAN_TO_BTS,
		.result = 0,
		.out_data = gsm48_mm_info_nn_tzt_dst_out,
		.out_length = ARRAY_SIZE(gsm48_mm_info_nn_tzt_out),
		.params = "tz_hr=-5 tz_mn=15 tz_dst=2",
		.n_params = 3,
	},
	{
		.data = gsm48_mm_info_nn_tzt_dst,
		.length = ARRAY_SIZE(gsm48_mm_info_nn_tzt_dst),
		.dir = TEST_SCAN_TO_BTS,
		.result = 0,
		.out_data = gsm48_mm_info_nn_tzt_dst_out,
		.out_length = ARRAY_SIZE(gsm48_mm_info_nn_tzt_dst_out),
		.params = "tz_hr=-5 tz_mn=15 tz_dst=2",
		.n_params = 3,
	},
};

static void test_scan(void)
{
	int i;

	struct gsm_network *net;
	struct gsm_bts *bts;
	struct osmo_bsc_sccp_con *sccp_con;
	struct bsc_msc_data *msc;
	struct gsm_subscriber_connection *conn;

	net = talloc_zero(NULL, struct gsm_network);
	bts = talloc_zero(net, struct gsm_bts);
	sccp_con = talloc_zero(net, struct osmo_bsc_sccp_con);
	msc = talloc_zero(net, struct bsc_msc_data);
	conn = talloc_zero(net, struct gsm_subscriber_connection);

	bts->network = net;
	sccp_con->msc = msc;
	conn->bts = bts;
	conn->sccp_con = sccp_con;

	/* start testing with proper messages */
	printf("Testing BTS<->MSC message scan.\n");
	for (i = 0; i < ARRAY_SIZE(test_scan_defs); ++i) {
		const struct test_definition *test_def = &test_scan_defs[i];
		int result;
		struct msgb *msg = msgb_alloc(4096, "test-message");
		int is_set = 0;

		net->tz.hr = get_int(test_def->params, test_def->n_params, "tz_hr", 0, &is_set);
		net->tz.mn = get_int(test_def->params, test_def->n_params, "tz_mn", 0, &is_set);
		net->tz.dst = get_int(test_def->params, test_def->n_params, "tz_dst", 0, &is_set);
		net->tz.override = 1;

		printf("Going to test item: %d\n", i);
		msg->l3h = msgb_put(msg, test_def->length);
		memcpy(msg->l3h, test_def->data, test_def->length);

		switch (test_def->dir) {
		case TEST_SCAN_TO_BTS:
			/* override timezone of msg coming from the MSC */
			result = bsc_scan_msc_msg(conn, msg);
			break;
		case TEST_SCAN_TO_MSC:
			/* override timezone of msg coming from the BSC */
			/* FIXME: no test for this case is defined in
			 * test_scan_defs[], so this is never used. */
			result = bsc_scan_bts_msg(conn, msg);
			break;
		default:
			abort();
			break;
		}

		if (result != test_def->result) {
			printf("FAIL: Not the expected result, got: %d wanted: %d\n",
				result, test_def->result);
			goto out;
		}

		if (msgb_l3len(msg) != test_def->out_length) {
			printf("FAIL: Not the expected message size, got: %d wanted: %d\n",
				msgb_l3len(msg), test_def->out_length);
			goto out;
		}

		if (memcmp(msgb_l3(msg), test_def->out_data, test_def->out_length) != 0) {
			printf("FAIL: Not the expected message\n");
			goto out;
		}

out:
		msgb_free(msg);
	}

	talloc_free(net);
}


int main(int argc, char **argv)
{
	msgb_talloc_ctx_init(NULL, 0);
	osmo_init_logging(&log_info);

	test_scan();

	printf("Testing execution completed.\n");
	return 0;
}
