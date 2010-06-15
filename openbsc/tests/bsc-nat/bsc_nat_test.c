/*
 * BSC NAT Message filtering
 *
 * (C) 2010 by Holger Hans Peter Freyther <zecke@selfish.org>
 * (C) 2010 by on-waves.com
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


#include <openbsc/debug.h>
#include <openbsc/gsm_data.h>
#include <openbsc/bsc_nat.h>

#include <stdio.h>

/* test messages for ipa */
static u_int8_t ipa_id[] = {
	0x00, 0x01, 0xfe, 0x06,
};

/* SCCP messages are below */
static u_int8_t gsm_reset[] = {
	0x00, 0x12, 0xfd,
	0x09, 0x00, 0x03, 0x05, 0x07, 0x02, 0x42, 0xfe,
	0x02, 0x42, 0xfe, 0x06, 0x00, 0x04, 0x30, 0x04,
	0x01, 0x20,
};

static const u_int8_t gsm_reset_ack[] = {
	0x00, 0x13, 0xfd,
	0x09, 0x00, 0x03, 0x07, 0x0b, 0x04, 0x43, 0x01,
	0x00, 0xfe, 0x04, 0x43, 0x5c, 0x00, 0xfe, 0x03,
	0x00, 0x01, 0x31,
};

static const u_int8_t gsm_paging[] = {
	0x00, 0x20, 0xfd,
	0x09, 0x00, 0x03, 0x07, 0x0b, 0x04, 0x43, 0x01,
	0x00, 0xfe, 0x04, 0x43, 0x5c, 0x00, 0xfe, 0x10,
	0x00, 0x0e, 0x52, 0x08, 0x08, 0x29, 0x47, 0x10,
	0x02, 0x01, 0x31, 0x97, 0x61, 0x1a, 0x01, 0x06,
};

/* BSC -> MSC connection open */
static const u_int8_t bssmap_cr[] = {
	0x00, 0x2c, 0xfd,
	0x01, 0x01, 0x02, 0x03, 0x02, 0x02, 0x04, 0x02,
	0x42, 0xfe, 0x0f, 0x1f, 0x00, 0x1d, 0x57, 0x05,
	0x08, 0x00, 0x72, 0xf4, 0x80, 0x20, 0x12, 0xc3,
	0x50, 0x17, 0x10, 0x05, 0x24, 0x11, 0x03, 0x33,
	0x19, 0xa2, 0x08, 0x29, 0x47, 0x10, 0x02, 0x01,
	0x31, 0x97, 0x61, 0x00
};

/* MSC -> BSC connection confirm */
static const u_int8_t bssmap_cc[] = {
	0x00, 0x0a, 0xfd,
	0x02, 0x01, 0x02, 0x03, 0x00, 0x00, 0x03, 0x02, 0x01, 0x00,
};

/* MSC -> BSC released */
static const u_int8_t bssmap_released[] = {
	0x00, 0x0e, 0xfd,
	0x04, 0x00, 0x00, 0x03, 0x01, 0x02, 0x03, 0x00, 0x01, 0x0f,
	0x02, 0x23, 0x42, 0x00,
};

/* BSC -> MSC released */
static const u_int8_t bssmap_release_complete[] = {
	0x00, 0x07, 0xfd,
	0x05, 0x01, 0x02, 0x03, 0x00, 0x00, 0x03
};

struct filter_result {
	const u_int8_t *data;
	const u_int16_t length;
	const int result;
};

static const struct filter_result results[] = {
	{
		.data = ipa_id,
		.length = ARRAY_SIZE(ipa_id),
		.result = FILTER_TO_MSC,
	},
	{
		.data = gsm_reset,
		.length = ARRAY_SIZE(gsm_reset),
		.result = FILTER_TO_MSC,
	},
	{
		.data = gsm_reset_ack,
		.length = ARRAY_SIZE(gsm_reset_ack),
		.result = FILTER_TO_BSC,
	},
	{
		.data = gsm_paging,
		.length = ARRAY_SIZE(gsm_paging),
		.result = FILTER_NONE,
	},
	{
		.data = bssmap_cr,
		.length = ARRAY_SIZE(bssmap_cr),
		.result = FILTER_NONE,
	},
	{
		.data = bssmap_cc,
		.length = ARRAY_SIZE(bssmap_cc),
		.result = FILTER_NONE,
	},
	{
		.data = bssmap_released,
		.length = ARRAY_SIZE(bssmap_released),
		.result = FILTER_NONE,
	},
	{
		.data = bssmap_release_complete,
		.length = ARRAY_SIZE(bssmap_release_complete),
		.result = FILTER_NONE,
	},
};

int main(int argc, char **argv)
{
	int i;


	/* start testinh with proper messages */
	for (i = 0; i < ARRAY_SIZE(results); ++i) {
		int result;
		struct bsc_nat_parsed *parsed;
		struct msgb *msg = msgb_alloc(4096, "test-message");

		fprintf(stderr, "Going to test item: %d\n", i);
		memcpy(msg->data, results[i].data, results[i].length);
		msg->l2h = msgb_put(msg, results[i].length);

		parsed = bsc_nat_parse(msg);
		if (!parsed) {
			fprintf(stderr, "FAIL: Failed to parse the message\n");
			continue;
		}

		result = bsc_nat_filter_ipa(msg, parsed);
		if (result != results[i].result) {
			fprintf(stderr, "FAIL: Not the expected result got: %d wanted: %d\n",
				result, results[i].result);
		}

		msgb_free(msg);
	}

	return 0;
}
