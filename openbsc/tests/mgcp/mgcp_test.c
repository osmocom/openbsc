/*
 * (C) 2011 by Holger Hans Peter Freyther <zecke@selfish.org>
 * (C) 2011 by On-Waves
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
 */

#include <openbsc/mgcp.h>
#include <openbsc/mgcp_internal.h>

#include <osmocom/core/application.h>
#include <osmocom/core/talloc.h>

#include <limits.h>
#include <string.h>

static struct msgb *create_auep1()
{
	struct msgb *msg;

	msg = msgb_alloc_headroom(4096, 128, "MGCP msg");
	int len = sprintf((char *)msg->data, "AUEP 158663169 ds/e1-1/2@172.16.6.66 MGCP 1.0\r\n");
	msg->l2h = msgb_put(msg, len);
	return msg;
}

static struct msgb *create_auep2()
{
	struct msgb *msg;

	msg = msgb_alloc_headroom(4096, 128, "MGCP msg");
	int len = sprintf((char *)msg->data, "AUEP 18983213 ds/e1-2/1@172.16.6.66 MGCP 1.0\r\n");
	msg->l2h = msgb_put(msg, len);
	return msg;
}

static void test_auep(void)
{
	struct msgb *inp;
	struct msgb *msg;
	struct mgcp_config *cfg = mgcp_config_alloc();
	cfg->trunk.number_endpoints = 64;
	mgcp_endpoints_allocate(&cfg->trunk);

	mgcp_endpoints_allocate(mgcp_trunk_alloc(cfg, 1));

	inp = create_auep1();
	msg = mgcp_handle_message(cfg, inp);
	msgb_free(inp);
	if (strcmp((char *) msg->data, "200 158663169 OK\r\n") != 0)
		printf("Result1 failed '%s'\n", (char *) msg->data);
	/* Verify that the endpoint is fine */
	msgb_free(msg);

	inp = create_auep2();
	msg = mgcp_handle_message(cfg, inp);
	msgb_free(inp);
	/* Verify that the endpoint is not fine */
	if (strcmp((char *) msg->data, "500 18983213 FAIL\r\n") != 0)
		printf("Result2 failed '%s'\n", (char *) msg->data);
	msgb_free(msg);

	talloc_free(cfg);
}

/**
 * Sample RTP data
 */

static const uint8_t packet_1[] = {
	0x80, 0xe2, 0xcb, 0x87, 0xf7, 0xcb, 0xba, 0x48,
	0x6f, 0x0f, 0xb1, 0xda, 0x00, 0x14, 0xb2, 0xb6,
	0xf8, 0x7b, 0x04, 0x81, 0x69, 0xf1, 0xdd, 0x33,
	0xd4, 0xd9, 0x45, 0x5c, 0x54,
};


static const uint8_t packet_2[] = {
	0x80, 0x62, 0xcb, 0x88, 0xf7, 0xcb, 0xba, 0xe8,
	0x6f, 0x0f, 0xb1, 0xda, 0x00, 0x14, 0x3d, 0xb6,
	0xf8, 0x08, 0x77, 0xfd, 0xeb, 0x51, 0xc7, 0x3f,
	0xb3, 0x82, 0x56, 0x56, 0x64,
};

static const uint8_t packet_3[] = {
	0x80, 0x62, 0xcb, 0x89, 0xf7, 0xcb, 0xbb, 0x88,
	0x6f, 0x0f, 0xb1, 0xda, 0x00, 0x14, 0xb2, 0xb6,
	0xf8, 0x7e, 0x01, 0x01, 0x7e, 0x06, 0x63, 0xb5,
	0xc7, 0x41, 0x65, 0xa0, 0x10
};

static const uint8_t packet_4[] = {
	0x80, 0x62, 0xcb, 0x8a, 0xf7, 0xcb, 0xbc, 0x28,
	0x6f, 0x0f, 0xb1, 0xda, 0x00, 0x14, 0x3d, 0xb6,
	0xf8, 0x1c, 0x63, 0xf9, 0xe9, 0x71, 0xc3, 0x3f,
	0x13, 0x0e, 0x5e, 0x56, 0x6c
};

/** test with some silence detection and clock jump */
static const uint8_t packet_short_1[] = {
	0x80, 0x62, 0xcc, 0xc2, 0xf7, 0xcd, 0x4f, 0xe8,
	0x6f, 0x0f, 0xb1, 0xda, 0x00, 0x14, 0xff, 0x52,
	0x38, 0xaf, 0xab, 0xa7, 0xfd, 0xf6, 0x5f, 0xfd,
	0xf4, 0xac, 0x03, 0xe2, 0xec,
};

static const uint8_t packet_short_2[] = {
	0x80, 0x62, 0xcc, 0xc3, 0xf7, 0xcd, 0x50, 0x88,
	0x6f, 0x0f, 0xb1, 0xda, 0x00, 0x14, 0x83, 0x58,
	0x53, 0x5f, 0xfe, 0x65, 0xe3, 0x99, 0x9d, 0xdc,
	0xcb, 0xda, 0x9b, 0xab, 0x7c
};

static const uint8_t packet_short_3[] = {
	0x80, 0x62, 0xcc, 0xc4, 0xf7, 0xcd, 0x51, 0x28,
	0x6f, 0x0f, 0xb1, 0xda, 0x00, 0x44, 0x00, 0x00,
	0x00, 0x00, 0x04,
};

static const uint8_t packet_short_4[] = {
	0x80, 0xe2, 0xcc, 0xc5, 0xf7, 0xcd, 0x52, 0x68,
	0x6f, 0x0f, 0xb1, 0xda, 0x00, 0x14, 0x44, 0x7b,
	0xd5, 0xfd, 0xbd, 0xf5, 0x65, 0x77, 0x9f, 0xb3,
	0xc2, 0x90, 0x83, 0x37, 0x88,
};

static struct msgb *from(const uint8_t *data, uint16_t len)
{
	struct msgb *msg = msgb_alloc_headroom(4096, 128, "from");
	msg->l2h = msgb_put(msg, len);
	memcpy(msg->l2h, data, len);
	return msg;
}

struct pdata {
	const uint8_t *data;
	uint16_t len;
};

static const struct pdata marker_normal[] = {
	{ .data = packet_1, .len = sizeof(packet_1), },
	{ .data = packet_2, .len = sizeof(packet_2), },
	{ .data = packet_3, .len = sizeof(packet_3), },
	{ .data = packet_4, .len = sizeof(packet_4), },
};

static const struct pdata shorter_marker[] = {
	{ .data = packet_short_1, .len = sizeof(packet_short_1) },
	{ .data = packet_short_2, .len = sizeof(packet_short_2) },
	{ .data = packet_short_3, .len = sizeof(packet_short_3) },
	{ .data = packet_short_4, .len = sizeof(packet_short_4) },
};

struct estate {
	const struct pdata *data;
	int plen;

	const struct mgcp_rtp_compr_state state;
	int output_size;
};

static const struct estate test_scenarious[] = {
	{ .data = marker_normal, .plen = ARRAY_SIZE(marker_normal),
	  .output_size = 17 *4 + 3 + 4 *1,
	  .state = {
		.last_ts = UCHAR_MAX,
		.generated_ssrc = 0x6f0fb1da,
		.sequence = 52103,
		.timestamp = 4157323848u,
	  },
	},
	{ .data = &marker_normal[1], .plen = ARRAY_SIZE(marker_normal) - 1,
	  .output_size = 17 * 3 + 3,
	  .state = {
		.last_ts = UCHAR_MAX,
		.generated_ssrc = 0x6f0fb1da,
		.sequence = 52104,
		.timestamp = 4157324008u,
	  },
	},
	/* this is testing the bigger encoding due the marker, and ts adjustment */
	{ .data = shorter_marker, .plen = ARRAY_SIZE(shorter_marker),
	  .output_size = 17 * 3 + 7 * 1 + 3 + 4 * 1 + 3,
	  .state = {
	  	.last_ts = UCHAR_MAX,
		.generated_ssrc = 0x6f0fb1da,
		.sequence = 52418,
		.timestamp = 4157427688u,
	  },
	},
	/* without the marker set, should be slim encoding */
	{ .data = shorter_marker, .plen = ARRAY_SIZE(shorter_marker) -1 ,
	  .output_size = 17 * 2 + 7 * 1 + 3,
	  .state = {
	  	.last_ts = UCHAR_MAX,
		.generated_ssrc = 0x6f0fb1da,
		.sequence = 52418,
		.timestamp = 4157427688u,
	  },
	},
};

static void test_compress_one(const struct estate *edata, char *t)
{
	const struct pdata *data = edata->data;
	const int len = edata->plen;

	int i = 0;
	struct msgb *msg;
	struct msgb *msgs[len];
	struct llist_head list;

	INIT_LLIST_HEAD(&list);

	printf("TESTING: %s\n", t);

	for (i = 0; i < len; ++i) {
		msgs[i] = from(data[i].data, data[i].len);
		msgb_enqueue(&list, msgs[i]);
	}

	struct msgb *out = msgb_alloc_headroom(4096, 128, "out");
	out->l2h = msgb_put(out, 0);

	struct mgcp_rtp_compr_state state = edata->state;
	int rc = rtp_compress(&state, out, 23, &list);
	if (rc != len) {
		fprintf(stderr, "Result is not %d: %d\n", len, rc);
		abort();
	}

	if (msgb_l2len(out) != edata->output_size) {
		fprintf(stderr, "Result is wrong size: %d %d\n",
			edata->output_size, msgb_l2len(out));
		abort();
	}

	printf("output is: %s\n", osmo_hexdump(out->l2h, msgb_l2len(out)));


	INIT_LLIST_HEAD(&list);
	state = edata->state;
	if (rtp_decompress(&state, &list, out) != 0) {
		fprintf(stderr, "Failed to decompress the code.\n");
		abort();
	}

	i = 0;
	llist_for_each_entry(msg, &list, list) {
		const struct pdata *got_data = &data[i];

		if (msgb_l2len(msg) != got_data->len) {
			fprintf(stderr, "Wrong len for %d %d\n", i, msgb_l2len(msg));
			abort();
		}

		if (memcmp(msg->l2h, got_data->data, got_data->len) != 0) {
			fprintf(stderr, "Wrong data for %d, '%s'\n",
				i, osmo_hexdump(msg->l2h, msgb_l2len(msg)));
			abort();
		}
		printf("Matched %s\n", osmo_hexdump(msg->l2h, msgb_l2len(msg)));

		i += 1;
	}

	if (len != i) {
		fprintf(stderr, "Failed to decode all packets: %d vs. %d\n", len, i);
	}

	msgb_free(out);
}

void test_compress()
{
	/**
	 * This tests that we correctly encode/decode a marker bit
	 */
	test_compress_one(&test_scenarious[0], "Test marker");


	/**
	 * This tests the code path that will go through a smaller encoding
	 */
	test_compress_one(&test_scenarious[1], "No marker");


	/**
	 * Test some shorter payloads, also a time jump at the end
	 */
	test_compress_one(&test_scenarious[2], "Shortened and Jump");
	test_compress_one(&test_scenarious[3], "Only shortened for slim");
}

int main(int argc, char **argv)
{
	osmo_init_logging(&log_info);

	test_auep();
	test_compress();
	return 0;
}
