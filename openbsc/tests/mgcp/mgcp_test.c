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

static struct msgb *from(const uint8_t *data, uint16_t len)
{
	struct msgb *msg = msgb_alloc_headroom(4096, 128, "from");
	msg->l2h = msgb_put(msg, len);
	memcpy(msg->l2h, data, len);
	return msg;
}

#define FROM(array) \
	from(array, sizeof(array))

void test_compress()
{
	int i = 0;
	struct msgb *msg;

	struct msgb *msg1 = FROM(packet_1);
	struct msgb *msg2 = FROM(packet_2);
	struct msgb *msg3 = FROM(packet_3);
	struct msgb *msg4 = FROM(packet_4);

	struct llist_head list;
	INIT_LLIST_HEAD(&list);
	msgb_enqueue(&list, msg1);
	msgb_enqueue(&list, msg2);
	msgb_enqueue(&list, msg3);
	msgb_enqueue(&list, msg4);

	struct mgcp_rtp_compr_state state;
	memset(&state, 0, sizeof(state));
	state.last_ts = UCHAR_MAX;
	state.generated_ssrc = 0x6f0fb1da;
	state.sequence = 52103;
	state.timestamp = 4157323848u;

	struct msgb *out = msgb_alloc_headroom(4096, 128, "out");
	out->l2h = msgb_put(out, 0);

	int rc = rtp_compress(&state, out, 23, &list);
	if (rc != 4) {
		fprintf(stderr, "Result is not 4: %d\n", rc);
		abort();
	}

	if (msgb_l2len(out) != (17*4 + 3)) {
		fprintf(stderr, "Result is wrong size: %d\n", msgb_l2len(out));
		abort();
	}

	printf("output is: %s\n", osmo_hexdump(out->l2h, msgb_l2len(out)));


	list = rtp_decompress(&state, out);

	llist_for_each_entry(msg, &list, list) {
		const uint8_t *data;
		int len;

		switch (++i) {
		case 1:
			data = packet_1;
			len = sizeof(packet_1);
			break;
		case 2:
			data = packet_2;
			len = sizeof(packet_2);
			break;
		case 3:
			data = packet_3;
			len = sizeof(packet_3);
			break;
		case 4:
			data = packet_4;
			len = sizeof(packet_4);
			break;
		default:
			fprintf(stderr, "Should not be reached.\n");
			abort();
		}

		if (msgb_l2len(msg) != len) {
			fprintf(stderr, "Wrong len for %d %d\n", i, msgb_l2len(msg));
			abort();
		}

		if (memcmp(msg->l2h, data, len) != 0) {
			fprintf(stderr, "Wrong data for %d, '%s'\n",
				i, osmo_hexdump(msg->l2h, msgb_l2len(msg)));
			abort();
		}
	}

	msgb_free(out);
}

int main(int argc, char **argv)
{
	osmo_init_logging(&log_info);

	test_auep();
	test_compress();
	return 0;
}
