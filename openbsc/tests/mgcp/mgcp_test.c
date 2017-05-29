/*
 * (C) 2011-2012,2014 by Holger Hans Peter Freyther <zecke@selfish.org>
 * (C) 2011-2012,2014 by On-Waves
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
#undef _GNU_SOURCE
#define _GNU_SOURCE

#include <openbsc/mgcp.h>
#include <openbsc/vty.h>
#include <openbsc/mgcp_internal.h>

#include <osmocom/core/application.h>
#include <osmocom/core/talloc.h>
#include <osmocom/core/utils.h>
#include <string.h>
#include <limits.h>
#include <dlfcn.h>
#include <time.h>
#include <math.h>

char *strline_r(char *str, char **saveptr);

const char *strline_test_data =
    "one CR\r"
    "two CR\r"
    "\r"
    "one CRLF\r\n"
    "two CRLF\r\n"
    "\r\n"
    "one LF\n"
    "two LF\n"
    "\n"
    "mixed (4 lines)\r\r\n\n\r\n";

#define EXPECTED_NUMBER_OF_LINES 13

static void test_strline(void)
{
	char *save = NULL;
	char *line;
	char buf[2048];
	int counter = 0;

	osmo_strlcpy(buf, strline_test_data, sizeof(buf));

	for (line = strline_r(buf, &save); line;
	     line = strline_r(NULL, &save)) {
		printf("line: '%s'\n", line);
		counter++;
	}

	OSMO_ASSERT(counter == EXPECTED_NUMBER_OF_LINES);
}

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
		 "s=-\r\n"			\
		 "c=IN IP4 0.0.0.0\r\n"		\
		 "t=0 0\r\n"			\
		 "m=audio 0 RTP/AVP 126\r\n"	\
		 "a=rtpmap:126 AMR/8000\r\n"	\
		 "a=ptime:20\r\n"
#define MDCX3_FMTP_RET "200 18983215 OK\r\n"		\
		 "I: 3\n"			\
		 "\n"				\
		 "v=0\r\n"			\
		 "o=- 3 23 IN IP4 0.0.0.0\r\n"	\
		 "s=-\r\n"			\
		 "c=IN IP4 0.0.0.0\r\n"		\
		 "t=0 0\r\n"			\
		 "m=audio 0 RTP/AVP 126\r\n"	\
		 "a=rtpmap:126 AMR/8000\r\n"	\
		 "a=fmtp:126 0/1/2\r\n"		\
		 "a=ptime:20\r\n"
#define MDCX4 "MDCX 18983216 1@mgw MGCP 1.0\r\n" \
		 "M: sendrecv\r"		\
		 "C: 2\r\n"          \
		 "I: 1\r\n"                    \
		 "L: p:20, a:AMR, nt:IN\r\n"    \
		 "\n"				\
		 "v=0\r\n"			\
		 "o=- 1 23 IN IP4 0.0.0.0\r\n"	\
		 "c=IN IP4 0.0.0.0\r\n"		\
		 "t=0 0\r\n"			\
		 "m=audio 4441 RTP/AVP 99\r\n"	\
		 "a=rtpmap:99 AMR/8000\r\n"	\
		 "a=ptime:40\r\n"
#define MDCX4_RET(Ident) "200 " Ident " OK\r\n"	\
		 "I: 1\n"			\
		 "\n"				\
		 "v=0\r\n"			\
		 "o=- 1 23 IN IP4 0.0.0.0\r\n"	\
		 "s=-\r\n"			\
		 "c=IN IP4 0.0.0.0\r\n"		\
		 "t=0 0\r\n"			\
		 "m=audio 0 RTP/AVP 126\r\n"	\
		 "a=rtpmap:126 AMR/8000\r\n"	\
		 "a=ptime:20\r\n"

#define MDCX4_PT1 "MDCX 18983217 1@mgw MGCP 1.0\r\n" \
		 "M: sendrecv\r"		\
		 "C: 2\r\n"          \
		 "I: 1\r\n"                    \
		 "L: p:20-40, a:AMR, nt:IN\r\n"    \
		 "\n"				\
		 "v=0\r\n"			\
		 "o=- 1 23 IN IP4 0.0.0.0\r\n"	\
		 "c=IN IP4 0.0.0.0\r\n"		\
		 "t=0 0\r\n"			\
		 "m=audio 4441 RTP/AVP 99\r\n"	\
		 "a=rtpmap:99 AMR/8000\r\n"	\
		 "a=ptime:40\r\n"

#define MDCX4_PT2 "MDCX 18983218 1@mgw MGCP 1.0\r\n" \
		 "M: sendrecv\r"		\
		 "C: 2\r\n"          \
		 "I: 1\r\n"                    \
		 "L: p:20-20, a:AMR, nt:IN\r\n"    \
		 "\n"				\
		 "v=0\r\n"			\
		 "o=- 1 23 IN IP4 0.0.0.0\r\n"	\
		 "c=IN IP4 0.0.0.0\r\n"		\
		 "t=0 0\r\n"			\
		 "m=audio 4441 RTP/AVP 99\r\n"	\
		 "a=rtpmap:99 AMR/8000\r\n"	\
		 "a=ptime:40\r\n"

#define MDCX4_PT3 "MDCX 18983219 1@mgw MGCP 1.0\r\n" \
		 "M: sendrecv\r"		\
		 "C: 2\r\n"          \
		 "I: 1\r\n"                    \
		 "L: a:AMR, nt:IN\r\n"    \
		 "\n"				\
		 "v=0\r\n"			\
		 "o=- 1 23 IN IP4 0.0.0.0\r\n"	\
		 "c=IN IP4 0.0.0.0\r\n"		\
		 "t=0 0\r\n"			\
		 "m=audio 4441 RTP/AVP 99\r\n"	\
		 "a=rtpmap:99 AMR/8000\r\n"	\
		 "a=ptime:40\r\n"

#define MDCX4_SO "MDCX 18983220 1@mgw MGCP 1.0\r\n" \
		 "M: sendonly\r"		\
		 "C: 2\r\n"          \
		 "I: 1\r\n"                    \
		 "L: p:20, a:AMR, nt:IN\r\n"    \
		 "\n"				\
		 "v=0\r\n"			\
		 "o=- 1 23 IN IP4 0.0.0.0\r\n"	\
		 "c=IN IP4 0.0.0.0\r\n"		\
		 "t=0 0\r\n"			\
		 "m=audio 4441 RTP/AVP 99\r\n"	\
		 "a=rtpmap:99 AMR/8000\r\n"	\
		 "a=ptime:40\r\n"

#define MDCX4_RO "MDCX 18983221 1@mgw MGCP 1.0\r\n" \
		 "M: recvonly\r"		\
		 "C: 2\r\n"          \
		 "I: 1\r\n"                    \
		 "L: p:20, a:AMR, nt:IN\r\n"

#define SHORT2	"CRCX 1"
#define SHORT2_RET "510 000000 FAIL\r\n"
#define SHORT3	"CRCX 1 1@mgw"
#define SHORT4	"CRCX 1 1@mgw MGCP"
#define SHORT5	"CRCX 1 1@mgw MGCP 1.0"

#define CRCX	 "CRCX 2 1@mgw MGCP 1.0\r\n"	\
		 "M: recvonly\r\n"		\
		 "C: 2\r\n"			\
		 "X\r\n"			\
		 "L: p:20\r\n"		\
		 "\r\n"				\
		 "v=0\r\n"			\
		 "c=IN IP4 123.12.12.123\r\n"	\
		 "m=audio 5904 RTP/AVP 97\r\n"	\
		 "a=rtpmap:97 GSM-EFR/8000\r\n"	\
		 "a=ptime:40\r\n"

#define CRCX_RET "200 2 OK\r\n"			\
		 "I: 1\n"			\
		 "\n"				\
		 "v=0\r\n"			\
		 "o=- 1 23 IN IP4 0.0.0.0\r\n"	\
		 "s=-\r\n"			\
		 "c=IN IP4 0.0.0.0\r\n"		\
		 "t=0 0\r\n"			\
		 "m=audio 0 RTP/AVP 126\r\n"	\
		 "a=rtpmap:126 AMR/8000\r\n"	\
		 "a=ptime:20\r\n"

#define CRCX_RET_NO_RTPMAP "200 2 OK\r\n"	\
		 "I: 1\n"			\
		 "\n"				\
		 "v=0\r\n"			\
		 "o=- 1 23 IN IP4 0.0.0.0\r\n"	\
		 "s=-\r\n"			\
		 "c=IN IP4 0.0.0.0\r\n"		\
		 "t=0 0\r\n"			\
		 "m=audio 0 RTP/AVP 126\r\n"	\
		 "a=ptime:20\r\n"

#define CRCX_FMTP_RET "200 2 OK\r\n"			\
		 "I: 3\n"			\
		 "\n"				\
		 "v=0\r\n"			\
		 "o=- 3 23 IN IP4 0.0.0.0\r\n"	\
		 "s=-\r\n"			\
		 "c=IN IP4 0.0.0.0\r\n"		\
		 "t=0 0\r\n"			\
		 "m=audio 0 RTP/AVP 126\r\n"	\
		 "a=rtpmap:126 AMR/8000\r\n"	\
		 "a=fmtp:126 0/1/2\r\n"		\
		 "a=ptime:20\r\n"

#define CRCX_ZYN "CRCX 2 1@mgw MGCP 1.0\r"	\
		 "M: recvonly\r"		\
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
		 "s=-\r\n"			\
		 "c=IN IP4 0.0.0.0\r\n"		\
		 "t=0 0\r\n"			\
		 "m=audio 0 RTP/AVP 126\r\n"	\
		 "a=rtpmap:126 AMR/8000\r\n"	\
		 "a=ptime:20\r\n"

#define DLCX	 "DLCX 7 1@mgw MGCP 1.0\r\n"	\
		 "C: 2\r\n"

#define DLCX_RET "250 7 OK\r\n"			\
		 "P: PS=0, OS=0, PR=0, OR=0, PL=0, JI=0\r\n" \
		 "X-Osmo-CP: EC TIS=0, TOS=0, TIR=0, TOR=0\r\n"

#define RQNT	 "RQNT 186908780 1@mgw MGCP 1.0\r\n"	\
		 "X: B244F267488\r\n"			\
		 "S: D/9\r\n"

#define RQNT2	 "RQNT 186908781 1@mgw MGCP 1.0\r\n"	\
		 "X: ADD4F26746F\r\n"			\
		 "R: D/[0-9#*](N), G/ft, fxr/t38\r\n"

#define RQNT1_RET "200 186908780 OK\r\n"
#define RQNT2_RET "200 186908781 OK\r\n"

#define PTYPE_IGNORE 0 /* == default initializer */
#define PTYPE_NONE 128
#define PTYPE_NYI  PTYPE_NONE

#define CRCX_MULT_1 "CRCX 2 1@mgw MGCP 1.0\r\n"	\
		 "M: recvonly\r\n"		\
		 "C: 2\r\n"			\
		 "X\r\n"			\
		 "L: p:20\r\n"		\
		 "\r\n"				\
		 "v=0\r\n"			\
		 "c=IN IP4 123.12.12.123\r\n"	\
		 "m=audio 5904 RTP/AVP 18 97\r\n"\
		 "a=rtpmap:18 G729/8000\r\n"	\
		 "a=rtpmap:97 GSM-EFR/8000\r\n"	\
		 "a=ptime:40\r\n"

#define CRCX_MULT_2 "CRCX 2 2@mgw MGCP 1.0\r\n"	\
		 "M: recvonly\r\n"		\
		 "C: 2\r\n"			\
		 "X\r\n"			\
		 "L: p:20\r\n"		\
		 "\r\n"				\
		 "v=0\r\n"			\
		 "c=IN IP4 123.12.12.123\r\n"	\
		 "m=audio 5904 RTP/AVP 18 97 101\r\n"\
		 "a=rtpmap:18 G729/8000\r\n"	\
		 "a=rtpmap:97 GSM-EFR/8000\r\n"	\
		 "a=rtpmap:101 FOO/8000\r\n"	\
		 "a=ptime:40\r\n"

#define CRCX_MULT_3 "CRCX 2 3@mgw MGCP 1.0\r\n"	\
		 "M: recvonly\r\n"		\
		 "C: 2\r\n"			\
		 "X\r\n"			\
		 "L: p:20\r\n"		\
		 "\r\n"				\
		 "v=0\r\n"			\
		 "c=IN IP4 123.12.12.123\r\n"	\
		 "m=audio 5904 RTP/AVP\r\n"	\
		 "a=rtpmap:18 G729/8000\r\n"	\
		 "a=rtpmap:97 GSM-EFR/8000\r\n"	\
		 "a=rtpmap:101 FOO/8000\r\n"	\
		 "a=ptime:40\r\n"

#define CRCX_MULT_4 "CRCX 2 4@mgw MGCP 1.0\r\n"	\
		 "M: recvonly\r\n"		\
		 "C: 2\r\n"			\
		 "X\r\n"			\
		 "L: p:20\r\n"		\
		 "\r\n"				\
		 "v=0\r\n"			\
		 "c=IN IP4 123.12.12.123\r\n"	\
		 "m=audio 5904 RTP/AVP 18\r\n"	\
		 "a=rtpmap:18 G729/8000\r\n"	\
		 "a=rtpmap:97 GSM-EFR/8000\r\n"	\
		 "a=rtpmap:101 FOO/8000\r\n"	\
		 "a=ptime:40\r\n"

#define CRCX_MULT_GSM_EXACT \
		"CRCX 259260421 5@mgw MGCP 1.0\r\n"	\
		"C: 1355c6041e\r\n"			\
		"I: 3\r\n"				\
		"L: p:20, a:GSM, nt:IN\r\n"		\
		"M: recvonly\r\n"			\
		"\r\n"					\
		"v=0\r\n"				\
		"o=- 1439038275 1439038275 IN IP4 192.168.181.247\r\n" \
		"s=-\r\nc=IN IP4 192.168.181.247\r\n"	\
		"t=0 0\r\nm=audio 29084 RTP/AVP 255 0 8 3 18 4 96 97 101\r\n" \
		"a=rtpmap:0 PCMU/8000\r\n"		\
		"a=rtpmap:8 PCMA/8000\r\n"		\
		"a=rtpmap:3 gsm/8000\r\n"		\
		"a=rtpmap:18 G729/8000\r\n"		\
		"a=fmtp:18 annexb=no\r\n"		\
		"a=rtpmap:4 G723/8000\r\n"		\
		"a=rtpmap:96 iLBC/8000\r\n"		\
		"a=fmtp:96 mode=20\r\n"			\
		"a=rtpmap:97 iLBC/8000\r\n"		\
		"a=fmtp:97 mode=30\r\n"			\
		"a=rtpmap:101 telephone-event/8000\r\n"	\
		"a=fmtp:101 0-15\r\n"			\
		"a=recvonly\r\n"
#define MDCX_NAT_DUMMY \
		"MDCX 23 5@mgw MGCP 1.0\r\n"		\
		"C: 1355c6041e\r\n"			\
		"\r\n"					\
		"c=IN IP4 8.8.8.8\r\n"		\
		"m=audio 16434 RTP/AVP 255\r\n"


struct mgcp_test {
	const char *name;
	const char *req;
	const char *exp_resp;
	int exp_net_ptype;
	int exp_bts_ptype;

	const char *extra_fmtp;
};

static const struct mgcp_test tests[] = {
	{ "AUEP1", AUEP1, AUEP1_RET },
	{ "AUEP2", AUEP2, AUEP2_RET },
	{ "MDCX1", MDCX_WRONG_EP, MDCX_ERR_RET },
	{ "MDCX2", MDCX_UNALLOCATED, MDCX_RET },
	{ "CRCX", CRCX, CRCX_RET, 97, 126 },
	{ "MDCX3", MDCX3, MDCX3_RET, PTYPE_NONE, 126 },
	{ "MDCX4", MDCX4, MDCX4_RET("18983216"), 99, 126 },
	{ "MDCX4_PT1", MDCX4_PT1, MDCX4_RET("18983217"), 99, 126 },
	{ "MDCX4_PT2", MDCX4_PT2, MDCX4_RET("18983218"), 99, 126 },
	{ "MDCX4_PT3", MDCX4_PT3, MDCX4_RET("18983219"), 99, 126 },
	{ "MDCX4_SO", MDCX4_SO, MDCX4_RET("18983220"), 99, 126 },
	{ "MDCX4_RO", MDCX4_RO, MDCX4_RET("18983221"), PTYPE_IGNORE, 126 },
	{ "DLCX", DLCX, DLCX_RET, -1, -1 },
	{ "CRCX_ZYN", CRCX_ZYN, CRCX_ZYN_RET, 97, 126 },
	{ "EMPTY", EMPTY, EMPTY_RET },
	{ "SHORT1", SHORT, SHORT_RET },
	{ "SHORT2", SHORT2, SHORT2_RET },
	{ "SHORT3", SHORT3, SHORT2_RET },
	{ "SHORT4", SHORT4, SHORT2_RET },
	{ "RQNT1", RQNT, RQNT1_RET },
	{ "RQNT2", RQNT2, RQNT2_RET },
	{ "DLCX", DLCX, DLCX_RET, -1, -1 },
	{ "CRCX", CRCX, CRCX_FMTP_RET, 97, 126, .extra_fmtp = "a=fmtp:126 0/1/2" },
	{ "MDCX3", MDCX3, MDCX3_FMTP_RET, PTYPE_NONE, 126 , .extra_fmtp = "a=fmtp:126 0/1/2" },
	{ "DLCX", DLCX, DLCX_RET, -1, -1 , .extra_fmtp = "a=fmtp:126 0/1/2" },
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

static int last_endpoint = -1;

static int mgcp_test_policy_cb(struct mgcp_trunk_config *cfg, int endpoint,
			       int state, const char *transactio_id)
{
	fprintf(stderr, "Policy CB got state %d on endpoint %d\n",
		state, endpoint);
	last_endpoint = endpoint;
	return MGCP_POLICY_CONT;
}

#define MGCP_DUMMY_LOAD 0x23
static int dummy_packets = 0;
/* override and forward */
ssize_t sendto(int sockfd, const void *buf, size_t len, int flags,
		const struct sockaddr *dest_addr, socklen_t addrlen)
{
	typedef ssize_t (*sendto_t)(int, const void *, size_t, int,
			const struct sockaddr *, socklen_t);
	static sendto_t real_sendto = NULL;
	uint32_t dest_host = htonl(((struct sockaddr_in *)dest_addr)->sin_addr.s_addr);
	int      dest_port = htons(((struct sockaddr_in *)dest_addr)->sin_port);

	if (!real_sendto)
		real_sendto = dlsym(RTLD_NEXT, "sendto");

	if (len == 1 && ((const char *)buf)[0] == MGCP_DUMMY_LOAD ) {
		fprintf(stderr, "Dummy packet to 0x%08x:%d, msg length %zu\n%s\n\n",
		       dest_host, dest_port,
		       len, osmo_hexdump(buf, len));
		dummy_packets += 1;
	}

	return real_sendto(sockfd, buf, len, flags, dest_addr, addrlen);
}

static int64_t force_monotonic_time_us = -1;
/* override and forward */
int clock_gettime(clockid_t clk_id, struct timespec *tp)
{
	typedef int (*clock_gettime_t)(clockid_t clk_id, struct timespec *tp);
	static clock_gettime_t real_clock_gettime = NULL;

	if (!real_clock_gettime)
		real_clock_gettime = dlsym(RTLD_NEXT, "clock_gettime");

	if (clk_id == CLOCK_MONOTONIC && force_monotonic_time_us >= 0) {
		tp->tv_sec = force_monotonic_time_us / 1000000;
		tp->tv_nsec = (force_monotonic_time_us % 1000000) * 1000;
		return 0;
	}

	return real_clock_gettime(clk_id, tp);
}

#define CONN_UNMODIFIED (0x1000)

static void test_values(void)
{
	/* Check that NONE disables all output */
	OSMO_ASSERT((MGCP_CONN_NONE & MGCP_CONN_RECV_SEND) == 0)

	/* Check that LOOPBACK enables all output */
	OSMO_ASSERT((MGCP_CONN_LOOPBACK & MGCP_CONN_RECV_SEND) ==
		    MGCP_CONN_RECV_SEND)
}


static void test_messages(void)
{
	struct mgcp_config *cfg;
	struct mgcp_endpoint *endp;
	int i;

	cfg = mgcp_config_alloc();

	cfg->trunk.number_endpoints = 64;
	mgcp_endpoints_allocate(&cfg->trunk);

	cfg->policy_cb = mgcp_test_policy_cb;

	mgcp_endpoints_allocate(mgcp_trunk_alloc(cfg, 1));

	/* reset endpoints */
	for (i = 0; i < cfg->trunk.number_endpoints; i++) {
		endp = &cfg->trunk.endpoints[i];
		endp->net_end.codec.payload_type = PTYPE_NONE;
		endp->net_end.packet_duration_ms = -1;

		OSMO_ASSERT(endp->conn_mode == MGCP_CONN_NONE);
		endp->conn_mode |= CONN_UNMODIFIED;
	}

	for (i = 0; i < ARRAY_SIZE(tests); i++) {
		const struct mgcp_test *t = &tests[i];
		struct msgb *inp;
		struct msgb *msg;

		printf("Testing %s\n", t->name);

		last_endpoint = -1;
		dummy_packets = 0;

		osmo_talloc_replace_string(cfg, &cfg->trunk.audio_fmtp_extra, t->extra_fmtp);

		inp = create_msg(t->req);
		msg = mgcp_handle_message(cfg, inp);
		msgb_free(inp);
		if (!t->exp_resp) {
			if (msg)
				printf("%s failed '%s'\n", t->name, (char *) msg->data);
		} else if (strcmp((char *) msg->data, t->exp_resp) != 0)
			printf("%s failed '%s'\n", t->name, (char *) msg->data);
		msgb_free(msg);

		if (dummy_packets)
			printf("Dummy packets: %d\n", dummy_packets);

		if (last_endpoint != -1) {
			endp = &cfg->trunk.endpoints[last_endpoint];

			if (endp->net_end.packet_duration_ms != -1)
				printf("Detected packet duration: %d\n",
				       endp->net_end.packet_duration_ms);
			else
				printf("Packet duration not set\n");
			if (endp->local_options.pkt_period_min ||
			    endp->local_options.pkt_period_max)
				printf("Requested packetetization period: "
				       "%d-%d\n",
				       endp->local_options.pkt_period_min,
				       endp->local_options.pkt_period_max);
			else
				printf("Requested packetization period not set\n");

			if ((endp->conn_mode & CONN_UNMODIFIED) == 0) {
				printf("Connection mode: %d:%s%s%s%s\n",
				       endp->conn_mode,
				       !endp->conn_mode ? " NONE" : "",
				       endp->conn_mode & MGCP_CONN_SEND_ONLY ?
				       " SEND" : "",
				       endp->conn_mode & MGCP_CONN_RECV_ONLY ?
				       " RECV" : "",
				       endp->conn_mode & MGCP_CONN_LOOPBACK &
				       ~MGCP_CONN_RECV_SEND ?
				       " LOOP" : "");
				fprintf(stderr,
					"BTS output %sabled, NET output %sabled\n",
					endp->bts_end.output_enabled ? "en" : "dis",
					endp->net_end.output_enabled ? "en" : "dis");
			} else
				printf("Connection mode not set\n");

			OSMO_ASSERT(endp->net_end.output_enabled ==
				    (endp->conn_mode & MGCP_CONN_SEND_ONLY ? 1 : 0));
			OSMO_ASSERT(endp->bts_end.output_enabled ==
				    (endp->conn_mode & MGCP_CONN_RECV_ONLY ? 1 : 0));

			endp->net_end.packet_duration_ms = -1;
			endp->local_options.pkt_period_min = 0;
			endp->local_options.pkt_period_max = 0;
			endp->conn_mode |= CONN_UNMODIFIED;
		}


		/* Check detected payload type */
		if (t->exp_net_ptype != PTYPE_IGNORE ||
		    t->exp_bts_ptype != PTYPE_IGNORE) {
			OSMO_ASSERT(last_endpoint != -1);
			endp = &cfg->trunk.endpoints[last_endpoint];

			fprintf(stderr, "endpoint %d: "
				"payload type BTS %d (exp %d), NET %d (exp %d)\n",
				last_endpoint,
				endp->bts_end.codec.payload_type, t->exp_bts_ptype,
				endp->net_end.codec.payload_type, t->exp_net_ptype);

			if (t->exp_bts_ptype != PTYPE_IGNORE)
				OSMO_ASSERT(endp->bts_end.codec.payload_type ==
					    t->exp_bts_ptype);
			if (t->exp_net_ptype != PTYPE_IGNORE)
				OSMO_ASSERT(endp->net_end.codec.payload_type ==
					    t->exp_net_ptype);

			/* Reset them again for next test */
			endp->net_end.codec.payload_type = PTYPE_NONE;
		}
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

	/* reset endpoints */
	for (i = 0; i < cfg->trunk.number_endpoints; i++) {
		struct mgcp_endpoint *endp;
		endp = &cfg->trunk.endpoints[i];
		endp->bts_end.packet_duration_ms = 20;
	}

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

		state.stats_initialized = 1;
		state.stats_base_seq = pl_test_dat[i].base_seq;
		state.stats_max_seq = pl_test_dat[i].max_seq;
		state.stats_cycles = pl_test_dat[i].cycles;

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

struct rtp_packet_info {
	float txtime;
	int len;
	char *data;
};

struct rtp_packet_info test_rtp_packets1[] = {
	/* RTP: SeqNo=0, TS=0 */
	{0.000000, 20, "\x80\x62\x00\x00\x00\x00\x00\x00\x11\x22\x33\x44"
		       "\x01\x23\x45\x67\x89\xAB\xCD\xEF"},
	/* RTP: SeqNo=1, TS=160 */
	{0.020000, 20, "\x80\x62\x00\x01\x00\x00\x00\xA0\x11\x22\x33\x44"
		       "\x01\x23\x45\x67\x89\xAB\xCD\xEF"},
	/* RTP: SeqNo=2, TS=320 */
	{0.040000, 20, "\x80\x62\x00\x02\x00\x00\x01\x40\x11\x22\x33\x44"
		       "\x01\x23\x45\x67\x89\xAB\xCD\xEF"},
	/* Repeat RTP timestamp: */
	/* RTP: SeqNo=3, TS=320 */
	{0.060000, 20, "\x80\x62\x00\x03\x00\x00\x01\x40\x11\x22\x33\x44"
		       "\x01\x23\x45\x67\x89\xAB\xCD\xEF"},
	/* RTP: SeqNo=4, TS=480 */
	{0.080000, 20, "\x80\x62\x00\x04\x00\x00\x01\xE0\x11\x22\x33\x44"
		       "\x01\x23\x45\x67\x89\xAB\xCD\xEF"},
	/* RTP: SeqNo=5, TS=640 */
	{0.100000, 20, "\x80\x62\x00\x05\x00\x00\x02\x80\x11\x22\x33\x44"
		       "\x01\x23\x45\x67\x89\xAB\xCD\xEF"},
	/* Double skip RTP timestamp (delta = 2*160): */
	/* RTP: SeqNo=6, TS=960 */
	{0.120000, 20, "\x80\x62\x00\x06\x00\x00\x03\xC0\x11\x22\x33\x44"
		       "\x01\x23\x45\x67\x89\xAB\xCD\xEF"},
	/* RTP: SeqNo=7, TS=1120 */
	{0.140000, 20, "\x80\x62\x00\x07\x00\x00\x04\x60\x11\x22\x33\x44"
		       "\x01\x23\x45\x67\x89\xAB\xCD\xEF"},
	/* RTP: SeqNo=8, TS=1280 */
	{0.160000, 20, "\x80\x62\x00\x08\x00\x00\x05\x00\x11\x22\x33\x44"
		       "\x01\x23\x45\x67\x89\xAB\xCD\xEF"},
	/* Non 20ms RTP timestamp (delta = 120): */
	/* RTP: SeqNo=9, TS=1400 */
	{0.180000, 20, "\x80\x62\x00\x09\x00\x00\x05\x78\x11\x22\x33\x44"
		       "\x01\x23\x45\x67\x89\xAB\xCD\xEF"},
	/* RTP: SeqNo=10, TS=1560 */
	{0.200000, 20, "\x80\x62\x00\x0A\x00\x00\x06\x18\x11\x22\x33\x44"
		       "\x01\x23\x45\x67\x89\xAB\xCD\xEF"},
	/* RTP: SeqNo=11, TS=1720 */
	{0.220000, 20, "\x80\x62\x00\x0B\x00\x00\x06\xB8\x11\x22\x33\x44"
		       "\x01\x23\x45\x67\x89\xAB\xCD\xEF"},
	/* SSRC changed to 0x10203040, RTP timestamp jump */
	/* RTP: SeqNo=12, TS=34688 */
	{0.240000, 20, "\x80\x62\x00\x0C\x00\x00\x87\x80\x10\x20\x30\x40"
		       "\x01\x23\x45\x67\x89\xAB\xCD\xEF"},
	/* RTP: SeqNo=13, TS=34848 */
	{0.260000, 20, "\x80\x62\x00\x0D\x00\x00\x88\x20\x10\x20\x30\x40"
		       "\x01\x23\x45\x67\x89\xAB\xCD\xEF"},
	/* RTP: SeqNo=14, TS=35008 */
	{0.280000, 20, "\x80\x62\x00\x0E\x00\x00\x88\xC0\x10\x20\x30\x40"
		       "\x01\x23\x45\x67\x89\xAB\xCD\xEF"},
	/* Non 20ms RTP timestamp (delta = 120): */
	/* RTP: SeqNo=15, TS=35128 */
	{0.300000, 20, "\x80\x62\x00\x0F\x00\x00\x89\x38\x10\x20\x30\x40"
		       "\x01\x23\x45\x67\x89\xAB\xCD\xEF"},
	/* RTP: SeqNo=16, TS=35288 */
	{0.320000, 20, "\x80\x62\x00\x10\x00\x00\x89\xD8\x10\x20\x30\x40"
		       "\x01\x23\x45\x67\x89\xAB\xCD\xEF"},
	/* RTP: SeqNo=17, TS=35448 */
	{0.340000, 20, "\x80\x62\x00\x11\x00\x00\x8A\x78\x10\x20\x30\x40"
		       "\x01\x23\x45\x67\x8A\xAB\xCD\xEF"},
	/* SeqNo increment by 2, RTP timestamp delta = 320: */
	/* RTP: SeqNo=19, TS=35768 */
	{0.360000, 20, "\x80\x62\x00\x13\x00\x00\x8B\xB8\x10\x20\x30\x40"
		       "\x01\x23\x45\x67\x89\xAB\xCD\xEF"},
	/* RTP: SeqNo=20, TS=35928 */
	{0.380000, 20, "\x80\x62\x00\x14\x00\x00\x8C\x58\x10\x20\x30\x40"
		       "\x01\x23\x45\x67\x89\xAB\xCD\xEF"},
	/* RTP: SeqNo=21, TS=36088 */
	{0.380000, 20, "\x80\x62\x00\x15\x00\x00\x8C\xF8\x10\x20\x30\x40"
		       "\x01\x23\x45\x67\x89\xAB\xCD\xEF"},
	/* Repeat last packet */
	/* RTP: SeqNo=21, TS=36088 */
	{0.400000, 20, "\x80\x62\x00\x15\x00\x00\x8C\xF8\x10\x20\x30\x40"
		       "\x01\x23\x45\x67\x89\xAB\xCD\xEF"},
	/* RTP: SeqNo=22, TS=36248 */
	{0.420000, 20, "\x80\x62\x00\x16\x00\x00\x8D\x98\x10\x20\x30\x40"
		       "\x01\x23\x45\x67\x89\xAB\xCD\xEF"},
	/* RTP: SeqNo=23, TS=36408 */
	{0.440000, 20, "\x80\x62\x00\x17\x00\x00\x8E\x38\x10\x20\x30\x40"
		       "\x01\x23\x45\x67\x89\xAB\xCD\xEF"},
	/* Don't increment SeqNo but increment timestamp by 160 */
	/* RTP: SeqNo=23, TS=36568 */
	{0.460000, 20, "\x80\x62\x00\x17\x00\x00\x8E\xD8\x10\x20\x30\x40"
		       "\x01\x23\x45\x67\x89\xAB\xCD\xEF"},
	/* RTP: SeqNo=24, TS=36728 */
	{0.480000, 20, "\x80\x62\x00\x18\x00\x00\x8F\x78\x10\x20\x30\x40"
		       "\x01\x23\x45\x67\x89\xAB\xCD\xEF"},
	/* RTP: SeqNo=25, TS=36888 */
	{0.500000, 20, "\x80\x62\x00\x19\x00\x00\x90\x18\x10\x20\x30\x40"
		       "\x01\x23\x45\x67\x89\xAB\xCD\xEF"},
	/* SSRC changed to 0x50607080, RTP timestamp jump, Delay of 1.5s,
	 * SeqNo jump */
	/* RTP: SeqNo=1000, TS=160000 */
	{2.000000, 20, "\x80\x62\x03\xE8\x00\x02\x71\x00\x50\x60\x70\x80"
			"\x01\x23\x45\x67\x89\xAB\xCD\xEF"},
	/* RTP: SeqNo=1001, TS=160160 */
	{2.020000, 20, "\x80\x62\x03\xE9\x00\x02\x71\xA0\x50\x60\x70\x80"
			"\x01\x23\x45\x67\x89\xAB\xCD\xEF"},
	/* RTP: SeqNo=1002, TS=160320 */
	{2.040000, 20, "\x80\x62\x03\xEA\x00\x02\x72\x40\x50\x60\x70\x80"
			"\x01\x23\x45\x67\x89\xAB\xCD\xEF"},
};

void mgcp_patch_and_count(struct mgcp_endpoint *endp, struct mgcp_rtp_state *state,
			  struct mgcp_rtp_end *rtp_end, struct sockaddr_in *addr,
			  char *data, int len);

static void test_packet_error_detection(int patch_ssrc, int patch_ts)
{
	int i;

	struct mgcp_trunk_config trunk;
	struct mgcp_endpoint endp;
	struct mgcp_rtp_state state;
	struct mgcp_rtp_end *rtp = &endp.net_end;
	struct sockaddr_in addr = {0};
	char buffer[4096];
	uint32_t last_ssrc = 0;
	uint32_t last_timestamp = 0;
	uint32_t last_seqno = 0;
	int last_in_ts_err_cnt = 0;
	int last_out_ts_err_cnt = 0;

	printf("Testing packet error detection%s%s.\n",
	       patch_ssrc ? ", patch SSRC" : "",
	       patch_ts ? ", patch timestamps" : "");

	memset(&trunk, 0, sizeof(trunk));
	memset(&endp, 0, sizeof(endp));
	memset(&state, 0, sizeof(state));

	trunk.number_endpoints = 1;
	trunk.endpoints = &endp;
	trunk.force_constant_ssrc = patch_ssrc;
	trunk.force_aligned_timing = patch_ts;

	endp.tcfg = &trunk;

	mgcp_initialize_endp(&endp);

	rtp->codec.payload_type = 98;

	for (i = 0; i < ARRAY_SIZE(test_rtp_packets1); ++i) {
		struct rtp_packet_info *info = test_rtp_packets1 + i;

		force_monotonic_time_us = round(1000000.0 * info->txtime);

		OSMO_ASSERT(info->len <= sizeof(buffer));
		OSMO_ASSERT(info->len >= 0);
		memmove(buffer, info->data, info->len);

		mgcp_rtp_end_config(&endp, 1, rtp);

		mgcp_patch_and_count(&endp, &state, rtp, &addr,
				     buffer, info->len);

		if (state.out_stream.ssrc != last_ssrc) {
			printf("Output SSRC changed to %08x\n",
			       state.out_stream.ssrc);
			last_ssrc = state.out_stream.ssrc;
		}

		printf("In TS: %d, dTS: %d, Seq: %d\n",
		       state.in_stream.last_timestamp,
		       state.in_stream.last_tsdelta,
		       state.in_stream.last_seq);

		printf("Out TS change: %d, dTS: %d, Seq change: %d, "
		       "TS Err change: in %+d, out %+d\n",
		       state.out_stream.last_timestamp - last_timestamp,
		       state.out_stream.last_tsdelta,
		       state.out_stream.last_seq - last_seqno,
		       state.in_stream.err_ts_counter - last_in_ts_err_cnt,
		       state.out_stream.err_ts_counter - last_out_ts_err_cnt);

		printf("Stats: Jitter = %u, Transit = %d\n",
		       mgcp_state_calc_jitter(&state), state.stats_transit);

		last_in_ts_err_cnt = state.in_stream.err_ts_counter;
		last_out_ts_err_cnt = state.out_stream.err_ts_counter;
		last_timestamp = state.out_stream.last_timestamp;
		last_seqno = state.out_stream.last_seq;
	}

	force_monotonic_time_us = -1;
}

static void test_multilple_codec(void)
{
	struct mgcp_config *cfg;
	struct mgcp_endpoint *endp;
	struct msgb *inp, *resp;
	struct in_addr addr;

	printf("Testing multiple payload types\n");

	cfg = mgcp_config_alloc();
	cfg->trunk.number_endpoints = 64;
	mgcp_endpoints_allocate(&cfg->trunk);
	cfg->policy_cb = mgcp_test_policy_cb;
	mgcp_endpoints_allocate(mgcp_trunk_alloc(cfg, 1));

	/* Allocate endpoint 1@mgw with two codecs */
	last_endpoint = -1;
	inp = create_msg(CRCX_MULT_1);
	resp = mgcp_handle_message(cfg, inp);
	msgb_free(inp);
	msgb_free(resp);

	OSMO_ASSERT(last_endpoint == 1);
	endp = &cfg->trunk.endpoints[last_endpoint];
	OSMO_ASSERT(endp->net_end.codec.payload_type == 18);
	OSMO_ASSERT(endp->net_end.alt_codec.payload_type == 97);

	/* Allocate 2@mgw with three codecs, last one ignored */
	last_endpoint = -1;
	inp = create_msg(CRCX_MULT_2);
	resp = mgcp_handle_message(cfg, inp);
	msgb_free(inp);
	msgb_free(resp);

	OSMO_ASSERT(last_endpoint == 2);
	endp = &cfg->trunk.endpoints[last_endpoint];
	OSMO_ASSERT(endp->net_end.codec.payload_type == 18);
	OSMO_ASSERT(endp->net_end.alt_codec.payload_type == 97);

	/* Allocate 3@mgw with no codecs, check for PT == -1 */
	last_endpoint = -1;
	inp = create_msg(CRCX_MULT_3);
	resp = mgcp_handle_message(cfg, inp);
	msgb_free(inp);
	msgb_free(resp);

	OSMO_ASSERT(last_endpoint == 3);
	endp = &cfg->trunk.endpoints[last_endpoint];
	OSMO_ASSERT(endp->net_end.codec.payload_type == -1);
	OSMO_ASSERT(endp->net_end.alt_codec.payload_type == -1);

	/* Allocate 4@mgw with a single codec */
	last_endpoint = -1;
	inp = create_msg(CRCX_MULT_4);
	resp = mgcp_handle_message(cfg, inp);
	msgb_free(inp);
	msgb_free(resp);

	OSMO_ASSERT(last_endpoint == 4);
	endp = &cfg->trunk.endpoints[last_endpoint];
	OSMO_ASSERT(endp->net_end.codec.payload_type == 18);
	OSMO_ASSERT(endp->net_end.alt_codec.payload_type == -1);

	/* Allocate 5@mgw at select GSM.. */
	last_endpoint = -1;
	inp = create_msg(CRCX_MULT_GSM_EXACT);
	talloc_free(cfg->trunk.audio_name);
	cfg->trunk.audio_name = "GSM/8000";
	cfg->trunk.no_audio_transcoding = 1;
	resp = mgcp_handle_message(cfg, inp);
	msgb_free(inp);
	msgb_free(resp);

	OSMO_ASSERT(last_endpoint == 5);
	endp = &cfg->trunk.endpoints[last_endpoint];
	OSMO_ASSERT(endp->net_end.codec.payload_type == 3);
	OSMO_ASSERT(endp->net_end.alt_codec.payload_type == -1);

	inp = create_msg(MDCX_NAT_DUMMY);
	last_endpoint = -1;
	resp = mgcp_handle_message(cfg, inp);
	msgb_free(inp);
	msgb_free(resp);
	OSMO_ASSERT(last_endpoint == 5);
	endp = &cfg->trunk.endpoints[last_endpoint];
	OSMO_ASSERT(endp->net_end.codec.payload_type == 3);
	OSMO_ASSERT(endp->net_end.alt_codec.payload_type == -1);
	OSMO_ASSERT(endp->net_end.rtp_port == htons(16434));
	memset(&addr, 0, sizeof(addr));
	inet_aton("8.8.8.8", &addr);
	OSMO_ASSERT(endp->net_end.addr.s_addr == addr.s_addr);

	/* Check what happens without that flag */

	/* Free the previous endpoint and the data ... */
	mgcp_release_endp(endp);
	talloc_free(endp->last_response);
	talloc_free(endp->last_trans);
	endp->last_response = endp->last_trans = NULL;

	last_endpoint = -1;
	inp = create_msg(CRCX_MULT_GSM_EXACT);
	cfg->trunk.no_audio_transcoding = 0;
	resp = mgcp_handle_message(cfg, inp);
	msgb_free(inp);
	msgb_free(resp);

	OSMO_ASSERT(last_endpoint == 5);
	endp = &cfg->trunk.endpoints[last_endpoint];
	OSMO_ASSERT(endp->net_end.codec.payload_type == 255);
	OSMO_ASSERT(endp->net_end.alt_codec.payload_type == 0);

	talloc_free(cfg);
}

static void test_no_cycle(void)
{
	struct mgcp_config *cfg;
	struct mgcp_endpoint *endp;

	printf("Testing no sequence flow on initial packet\n");

	cfg = mgcp_config_alloc();
	cfg->trunk.number_endpoints = 64;
	mgcp_endpoints_allocate(&cfg->trunk);

	endp = &cfg->trunk.endpoints[1];
	OSMO_ASSERT(endp->net_state.stats_initialized == 0);

	mgcp_rtp_annex_count(endp, &endp->net_state, 0, 0, 2342);
	OSMO_ASSERT(endp->net_state.stats_initialized == 1);
	OSMO_ASSERT(endp->net_state.stats_cycles == 0);
	OSMO_ASSERT(endp->net_state.stats_max_seq == 0);

	mgcp_rtp_annex_count(endp, &endp->net_state, 1, 0, 2342);
	OSMO_ASSERT(endp->net_state.stats_initialized == 1);
	OSMO_ASSERT(endp->net_state.stats_cycles == 0);
	OSMO_ASSERT(endp->net_state.stats_max_seq == 1);

	/* now jump.. */
	mgcp_rtp_annex_count(endp, &endp->net_state, UINT16_MAX, 0, 2342);
	OSMO_ASSERT(endp->net_state.stats_initialized == 1);
	OSMO_ASSERT(endp->net_state.stats_cycles == 0);
	OSMO_ASSERT(endp->net_state.stats_max_seq == UINT16_MAX);

	/* and wrap */
	mgcp_rtp_annex_count(endp, &endp->net_state, 0, 0, 2342);
	OSMO_ASSERT(endp->net_state.stats_initialized == 1);
	OSMO_ASSERT(endp->net_state.stats_cycles == UINT16_MAX + 1);
	OSMO_ASSERT(endp->net_state.stats_max_seq == 0);

	talloc_free(cfg);
}

static void test_no_name(void)
{
	struct mgcp_config *cfg;
	struct mgcp_endpoint *endp;
	struct msgb *inp, *msg;
	int i;

	printf("Testing no rtpmap name\n");
	cfg = mgcp_config_alloc();

	cfg->trunk.number_endpoints = 64;
	cfg->trunk.audio_send_name = 0;
	mgcp_endpoints_allocate(&cfg->trunk);

	cfg->policy_cb = mgcp_test_policy_cb;

	mgcp_endpoints_allocate(mgcp_trunk_alloc(cfg, 1));

	/* reset endpoints */
	for (i = 0; i < cfg->trunk.number_endpoints; i++) {
		endp = &cfg->trunk.endpoints[i];
		endp->net_end.codec.payload_type = PTYPE_NONE;
		endp->net_end.packet_duration_ms = -1;

		OSMO_ASSERT(endp->conn_mode == MGCP_CONN_NONE);
		endp->conn_mode |= CONN_UNMODIFIED;
	}

	inp = create_msg(CRCX);
	msg = mgcp_handle_message(cfg, inp);
	if (strcmp((char *) msg->data, CRCX_RET_NO_RTPMAP) != 0)
		printf("FAILED: there should not be a RTPMAP: %s\n",
			(char *) msg->data);
	msgb_free(inp);
	msgb_free(msg);

	mgcp_release_endp(&cfg->trunk.endpoints[1]);
	talloc_free(cfg);
}

static void test_osmux_cid(void)
{
	int id, i;

	OSMO_ASSERT(osmux_used_cid() == 0);
	id = osmux_get_cid();
	OSMO_ASSERT(id == 0);
	OSMO_ASSERT(osmux_used_cid() == 1);
	osmux_put_cid(id);
	OSMO_ASSERT(osmux_used_cid() == 0);

	for (i = 0; i < 256; ++i) {
		id = osmux_get_cid();
		OSMO_ASSERT(id == i);
		OSMO_ASSERT(osmux_used_cid() == i + 1);
	}

	id = osmux_get_cid();
	OSMO_ASSERT(id == -1);

	for (i = 0; i < 256; ++i)
		osmux_put_cid(i);
	OSMO_ASSERT(osmux_used_cid() == 0);
}

int main(int argc, char **argv)
{
	msgb_talloc_ctx_init(NULL, 0);
	osmo_init_logging(&log_info);

	test_strline();
	test_values();
	test_messages();
	test_retransmission();
	test_packet_loss_calc();
	test_rqnt_cb();
	test_mgcp_stats();
	test_packet_error_detection(1, 0);
	test_packet_error_detection(0, 0);
	test_packet_error_detection(0, 1);
	test_packet_error_detection(1, 1);
	test_multilple_codec();
	test_no_cycle();
	test_no_name();
	test_osmux_cid();

	printf("Done\n");
	return EXIT_SUCCESS;
}
