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

#define MDCX_WRONG_EP "MDCX 18983213 ds/e1-3/1@172.16.6.66 MGCP 1.0\r\n"
#define MDCX_ERR_RET "510 18983213 FAIL\r\n"
#define MDCX_UNALLOCATED "MDCX 18983214 ds/e1-1/2@172.16.6.66 MGCP 1.0\r\n"
#define MDCX_RET "400 18983214 FAIL\r\n"
#define MDCX3 "MDCX 18983215 1@mgw MGCP 1.0\r\n"
#define MDCX3_RET "200 18983215 OK\r\n"		\
		 "I: 1\n"			\
		 "\n"				\
		 "v=0\r\n"			\
		 "o=- 1 23 IN IP4 0.0.0.0\r\n"	\
		 "c=IN IP4 0.0.0.0\r\n"		\
		 "t=0 0\r\n"			\
		 "m=audio 0 RTP/AVP 126\r\n"	\
		 "a=rtpmap:126 AMR/8000\r\n"

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

#define CRCX_ZYN_RET "200 2 OK\r\n"		\
		 "I: 2\n"			\
		 "\n"				\
		 "v=0\r\n"			\
		 "o=- 2 23 IN IP4 0.0.0.0\r\n"	\
		 "c=IN IP4 0.0.0.0\r\n"		\
		 "t=0 0\r\n"			\
		 "m=audio 0 RTP/AVP 126\r\n"	\
		 "a=rtpmap:126 AMR/8000\r\n"

#define DLCX	 "DLCX 7 1@mgw MGCP 1.0\r\n"	\
		 "C: 2\r\n"

#define DLCX_RET "250 7 OK\r\n"			\
		 "P: PS=0, OS=0, PR=0, OR=0, PL=0, JI=0\r\n"

#define RQNT	 "RQNT 186908780 1@mgw MGCP 1.0\r\n"	\
		 "X: B244F267488\r\n"			\
		 "S: D/9\r\n"

#define RQNT2	 "RQNT 186908781 1@mgw MGCP 1.0\r\n"	\
		 "X: ADD4F26746F\r\n"			\
		 "R: D/[0-9#*](N), G/ft, fxr/t38\r\n"

#define RQNT1_RET "200 186908780 OK\r\n"
#define RQNT2_RET "200 186908781 OK\r\n"

struct mgcp_test {
	const char *name;
	const char *req;
	const char *exp_resp;
};

static const struct mgcp_test tests[] = {
	{ "AUEP1", AUEP1, AUEP1_RET },
	{ "AUEP2", AUEP2, AUEP2_RET },
	{ "MDCX1", MDCX_WRONG_EP, MDCX_ERR_RET },
	{ "MDCX2", MDCX_UNALLOCATED, MDCX_RET },
	{ "CRCX", CRCX, CRCX_RET },
	{ "MDCX3", MDCX3, MDCX3_RET },
	{ "DLCX", DLCX, DLCX_RET },
	{ "CRCX_ZYN", CRCX_ZYN, CRCX_ZYN_RET },
	{ "EMPTY", EMPTY, EMPTY_RET },
	{ "SHORT1", SHORT, SHORT_RET },
	{ "SHORT2", SHORT2, SHORT2_RET },
	{ "SHORT3", SHORT3, SHORT2_RET },
	{ "SHORT4", SHORT4, SHORT2_RET },
	{ "RQNT1", RQNT, RQNT1_RET },
	{ "RQNT2", RQNT2, RQNT2_RET },
	{ "DLCX", DLCX, DLCX_RET },
};

static const struct mgcp_test retransmit[] = {
	{ "CRCX", CRCX, CRCX_RET },
	{ "RQNT1", RQNT, RQNT1_RET },
	{ "RQNT2", RQNT2, RQNT2_RET },
	{ "MDCX3", MDCX3, MDCX3_RET },
	{ "DLCX", DLCX, DLCX_RET },
};

static struct msgb *create_msg(const char *str)
{
	struct msgb *msg;

	msg = msgb_alloc_headroom(4096, 128, "MGCP msg");
	int len = sprintf((char *)msg->data, "%s", str);
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

static void test_retransmission(void)
{
	struct mgcp_config *cfg;
	int i;

	cfg = mgcp_config_alloc();

	cfg->trunk.number_endpoints = 64;
	mgcp_endpoints_allocate(&cfg->trunk);

	mgcp_endpoints_allocate(mgcp_trunk_alloc(cfg, 1));

	for (i = 0; i < ARRAY_SIZE(retransmit); i++) {
		const struct mgcp_test *t = &retransmit[i];
		struct msgb *inp;
		struct msgb *msg;

		printf("Testing %s\n", t->name);

		inp = create_msg(t->req);
		msg = mgcp_handle_message(cfg, inp);
		msgb_free(inp);
		if (strcmp((char *) msg->data, t->exp_resp) != 0)
			printf("%s failed '%s'\n", t->name, (char *) msg->data);
		msgb_free(msg);

		/* Retransmit... */
		printf("Re-transmitting %s\n", t->name);
		inp = create_msg(t->req);
		msg = mgcp_handle_message(cfg, inp);
		msgb_free(inp);
		if (strcmp((char *) msg->data, t->exp_resp) != 0)
			printf("%s failed '%s'\n", t->name, (char *) msg->data);
		msgb_free(msg);
	}

	talloc_free(cfg);
}

static int rqnt_cb(struct mgcp_endpoint *endp, char _tone)
{
	ptrdiff_t tone = _tone;
	endp->cfg->data = (void *) tone;
	return 0;
}

static void test_rqnt_cb(void)
{
	struct mgcp_config *cfg;
	struct msgb *inp, *msg;

	cfg = mgcp_config_alloc();
	cfg->rqnt_cb = rqnt_cb;

	cfg->trunk.number_endpoints = 64;
	mgcp_endpoints_allocate(&cfg->trunk);

	mgcp_endpoints_allocate(mgcp_trunk_alloc(cfg, 1));

	inp = create_msg(CRCX);
	msgb_free(mgcp_handle_message(cfg, inp));
	msgb_free(inp);

	/* send the RQNT and check for the CB */
	inp = create_msg(RQNT);
	msg = mgcp_handle_message(cfg, inp);
	if (strncmp((const char *) msg->l2h, "200", 3) != 0) {
		printf("FAILED: message is not 200. '%s'\n", msg->l2h);
		abort();
	}

	if (cfg->data != (void *) '9') {
		printf("FAILED: callback not called: %p\n", cfg->data);
		abort();
	}

	msgb_free(msg);
	msgb_free(inp);

	inp = create_msg(DLCX);
	msgb_free(mgcp_handle_message(cfg, inp));
	msgb_free(inp);
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

static void test_mgcp_stats(void)
{
	printf("Testing stat parsing\n");

	uint32_t bps, bos, pr, _or, jitter;
	struct msgb *msg;
	int loss;
	int rc;

	msg = create_msg(DLCX_RET);
	rc = mgcp_parse_stats(msg, &bps, &bos, &pr, &_or, &loss, &jitter);
	printf("Parsing result: %d\n", rc);
	if (bps != 0 || bos != 0 || pr != 0 ||  _or != 0 || loss != 0 || jitter != 0)
		printf("FAIL: Parsing failed1.\n");
	msgb_free(msg);

	msg = create_msg("250 7 OK\r\nP: PS=10, OS=20, PR=30, OR=40, PL=-3, JI=40\r\n");
	rc = mgcp_parse_stats(msg, &bps, &bos, &pr, &_or, &loss, &jitter);
	printf("Parsing result: %d\n", rc);
	if (bps != 10 || bos != 20 || pr != 30 || _or != 40 || loss != -3 || jitter != 40)
		printf("FAIL: Parsing failed2.\n");
	msgb_free(msg);
}

int main(int argc, char **argv)
{
	osmo_init_logging(&log_info);

	test_messages();
	test_retransmission();
	test_packet_loss_calc();
	test_rqnt_cb();
	test_mgcp_stats();

	printf("Done\n");
	return EXIT_SUCCESS;
}
