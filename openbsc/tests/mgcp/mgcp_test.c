/*
 * (C) 2011-2012 by Holger Hans Peter Freyther <zecke@selfish.org>
 * (C) 2011-2012 by On-Waves
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
#include <string.h>
#include <limits.h>

#define AUEP1	"AUEP 158663169 ds/e1-1/2@172.16.6.66 MGCP 1.0\r\n"
#define AUEP1_RET "200 158663169 OK\r\n"
#define AUEP2	"AUEP 18983213 ds/e1-2/1@172.16.6.66 MGCP 1.0\r\n"
#define AUEP2_RET "500 18983213 FAIL\r\n"
#define EMPTY	"\r\n"
#define EMPTY_RET NULL
#define SHORT	"CRCX \r\n"
#define SHORT_RET "510 000000 FAIL\r\n"

#define SHORT2	"CRCX 1"
#define SHORT2_RET "510 000000 FAIL\r\n"
#define SHORT3	"CRCX 1 1@mgw"
#define SHORT4	"CRCX 1 1@mgw MGCP"
#define SHORT5	"CRCX 1 1@mgw MGCP 1.0"

#define CRCX	 "CRCX 2 1@mgw MGCP 1.0\r\n"	\
		 "M: sendrecv\r\n"		\
		 "C: 2\r\n"			\
		 "\r\n"				\
		 "v=0\r\n"			\
		 "c=IN IP4 123.12.12.123\r\n"	\
		 "m=audio 5904 RTP/AVP 97\r\n"	\
		 "a=rtpmap:97 GSM-EFR/8000\r\n"

#define CRCX_RET "200 2 OK\r\n"			\
		 "I: 1\n"			\
		 "\n"				\
		 "v=0\r\n"			\
		 "o=- 1 23 IN IP4 0.0.0.0\r\n"	\
		 "c=IN IP4 0.0.0.0\r\n"		\
		 "t=0 0\r\n"			\
		 "m=audio 0 RTP/AVP 126\r\n"	\
		 "a=rtpmap:126 AMR/8000\r\n"


#define CRCX_ZYN "CRCX 2 1@mgw MGCP 1.0\r"	\
		 "M: sendrecv\r"		\
		 "C: 2\r\r"			\
		 "v=0\r"			\
		 "c=IN IP4 123.12.12.123\r"	\
		 "m=audio 5904 RTP/AVP 97\r"	\
		 "a=rtpmap:97 GSM-EFR/8000\r"

#define DLCX	 "DLCX 7 1@mgw MGCP 1.0\r\n"	\
		 "C: 2\r\n"

#define DLCX_RET "250 7 OK\r\n"			\
		 "P: PS=0, OS=0, PR=0, OR=0, PL=0, JI=0\r\n"


struct mgcp_test {
	const char *name;
	const char *req;
	const char *exp_resp;
};

const struct mgcp_test tests[] = {
	{ "AUEP1", AUEP1, AUEP1_RET },
	{ "AUEP2", AUEP2, AUEP2_RET },
	{ "CRCX", CRCX, CRCX_RET },
	{ "CRCX_ZYN", CRCX_ZYN, CRCX_RET },
	{ "EMPTY", EMPTY, EMPTY_RET },
	{ "SHORT1", SHORT, SHORT_RET },
	{ "SHORT2", SHORT2, SHORT2_RET },
	{ "SHORT3", SHORT3, SHORT2_RET },
	{ "SHORT4", SHORT4, SHORT2_RET },
	{ "DLCX", DLCX, DLCX_RET },
};

static struct msgb *create_msg(const char *str)
{
	struct msgb *msg;

	msg = msgb_alloc_headroom(4096, 128, "MGCP msg");
	int len = sprintf((char *)msg->data, str);
	msg->l2h = msgb_put(msg, len);
	return msg;
}

static void test_messages(void)
{
	struct mgcp_config *cfg;
	int i;

	cfg = mgcp_config_alloc();

	cfg->trunk.number_endpoints = 64;
	mgcp_endpoints_allocate(&cfg->trunk);

	mgcp_endpoints_allocate(mgcp_trunk_alloc(cfg, 1));

	for (i = 0; i < ARRAY_SIZE(tests); i++) {
		const struct mgcp_test *t = &tests[i];
		struct msgb *inp;
		struct msgb *msg;

		printf("Testing %s\n", t->name);

		inp = create_msg(t->req);
		msg = mgcp_handle_message(cfg, inp);
		msgb_free(inp);
		if (!t->exp_resp) {
			if (msg)
				printf("%s failed '%s'\n", t->name, (char *) msg->data);
		} else if (strcmp((char *) msg->data, t->exp_resp) != 0)
			printf("%s failed '%s'\n", t->name, (char *) msg->data);
		msgb_free(msg);
	}

	talloc_free(cfg);
}

struct pl_test {
	int		cycles;
	uint16_t	base_seq;
	uint16_t	max_seq;
	uint32_t	packets;

	uint32_t	expected;
	int		loss;
};

static const struct pl_test pl_test_dat[] = {
	/* basic.. just one package */
	{ .cycles = 0, .base_seq = 0, .max_seq = 0, .packets = 1, .expected = 1, .loss = 0},
	/* some packages and a bit of loss */
	{ .cycles = 0, .base_seq = 0, .max_seq = 100, .packets = 100, .expected = 101, .loss = 1},
	/* wrap around */
	{ .cycles = 1<<16, .base_seq = 0xffff, .max_seq = 2, .packets = 4, .expected = 4, .loss = 0},
	/* min loss */
	{ .cycles = 0, .base_seq = 0, .max_seq = 0, .packets = UINT_MAX, .expected = 1, .loss = INT_MIN },
	/* max loss, with wrap around on expected max */
	{ .cycles = INT_MAX, .base_seq = 0, .max_seq = UINT16_MAX, .packets = 0, .expected = ((uint32_t)(INT_MAX) + UINT16_MAX + 1), .loss = INT_MAX }, 
};

static void test_packet_loss_calc(void)
{
	int i;
	printf("Testing packet loss calculation.\n");

	for (i = 0; i < ARRAY_SIZE(pl_test_dat); ++i) {
		uint32_t expected;
		int loss;
		struct mgcp_rtp_state state;
		struct mgcp_rtp_end rtp;
		memset(&state, 0, sizeof(state));
		memset(&rtp, 0, sizeof(rtp));

		state.initialized = 1;
		state.base_seq = pl_test_dat[i].base_seq;
		state.max_seq = pl_test_dat[i].max_seq;
		state.cycles = pl_test_dat[i].cycles;

		rtp.packets = pl_test_dat[i].packets;
		mgcp_state_calc_loss(&state, &rtp, &expected, &loss);

		if (loss != pl_test_dat[i].loss || expected != pl_test_dat[i].expected) {
			printf("FAIL: Wrong exp/loss at idx(%d) Loss(%d vs. %d) Exp(%u vs. %u)\n",
				i, loss, pl_test_dat[i].loss,
				expected, pl_test_dat[i].expected);
		}
	}
}

int main(int argc, char **argv)
{
	osmo_init_logging(&log_info);

	test_messages();
	test_packet_loss_calc();

	printf("Done\n");
	return EXIT_SUCCESS;
}
