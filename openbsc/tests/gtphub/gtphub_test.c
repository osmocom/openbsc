/* Test the GTP hub */

/* (C) 2015 by sysmocom s.f.m.c. GmbH
 * All Rights Reserved
 *
 * Author: Neels Hofmeyr <nhofmeyr@sysmcom.de>
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
 *
 */

#include <stdio.h>
#include <string.h>
#include <limits.h>
#include <unistd.h>

#include <osmocom/core/utils.h>
#include <osmocom/core/msgb.h>
#include <osmocom/core/application.h>

#include <openbsc/debug.h>

#include <openbsc/gtphub.h>
#include <gtp.h>
#include <gtpie.h>

#define EXPIRE_ALL ((60 * GTPH_TEI_MAPPING_EXPIRY_MINUTES) + 1)

/* Make non-public API accessible */

void gtphub_init(struct gtphub *hub);

void *osmo_gtphub_ctx;

/* TODO copied from libosmo-abis/src/subchan_demux.c, remove dup */
static int llist_len(struct llist_head *head)
{
	struct llist_head *entry;
	int i = 0;

	llist_for_each(entry, head)
		i++;

	return i;
}

static void nr_mapping_free(struct expiring_item *e)
{
	struct nr_mapping *m = container_of(e, struct nr_mapping,
					    expiry_entry);
	nr_mapping_del(m);
	talloc_free(m);
}

static struct nr_mapping *nr_mapping_alloc(void)
{
	struct nr_mapping *m;
	m = talloc(osmo_gtphub_ctx, struct nr_mapping);
	nr_mapping_init(m);
	m->expiry_entry.del_cb = nr_mapping_free;
	return m;
}

static struct nr_mapping *nr_map_have(struct nr_map *map, void *origin, nr_t orig, time_t now)
{
	struct nr_mapping *mapping;

	mapping = nr_map_get(map, origin, orig);
	if (!mapping) {
		mapping = nr_mapping_alloc();
		mapping->origin = origin;
		mapping->orig = orig;
		nr_map_add(map, mapping, now);
	}

	return mapping;
}

static nr_t nr_map_verify(const struct nr_map *map, void *origin, nr_t orig, nr_t expect_repl)
{
	struct nr_mapping *m;
	m = nr_map_get(map, origin, orig);

	if (!m) {
		printf("mapping not found for %p %d\n", origin, orig);
		return 0;
	}

	if (m->repl != expect_repl) {
		printf("mapping found, but nr mismatches: expect %d, got %d\n",
		       (int)expect_repl, (int)m->repl);
		return 0;
	}

	return 1;
}

static int nr_map_verify_inv(const struct nr_map *map, nr_t repl,
			     void *expect_origin, nr_t expect_orig)
{
	struct nr_mapping *m;
	m = nr_map_get_inv(map, repl);
	if (!m) {
		printf("mapping not found for %d\n", (int)repl);
		return 0;
	}

	if (m->origin != expect_origin) {
		printf("mapping found, but origin mismatches: expect %p, got %p\n",
		       expect_origin, m->origin);
		return 0;
	}

	if (m->orig != expect_orig) {
		printf("mapping found, but nr mismatches: expect %d, got %d\n",
		       (int)expect_orig, (int)m->orig);
		return 0;
	}

	return 1;
}


static void test_nr_map_basic(void)
{
	struct nr_pool _pool;
	struct nr_pool *pool = &_pool;
	struct nr_map _map;
	struct nr_map *map = &_map;

	nr_pool_init(pool);
	nr_map_init(map, pool, NULL);

	OSMO_ASSERT(llist_empty(&map->mappings));

#define TEST_N_HALF 100
#define TEST_N (2*TEST_N_HALF)
#define TEST_I 123
	uint32_t i, check_i;
	uint32_t m[TEST_N];
	struct nr_mapping *mapping;

	/* create half of TEST_N mappings from one origin */
	void *origin1 = (void*)0x1234;
	for (i = 0; i < TEST_N_HALF; i++) {
		nr_t orig = TEST_I + i;
		mapping = nr_map_have(map, origin1, orig, 0);
		m[i] = mapping->repl;
		OSMO_ASSERT(m[i] != 0);
		OSMO_ASSERT(llist_len(&map->mappings) == (i+1));
		for (check_i = 0; check_i < i; check_i++)
			OSMO_ASSERT(m[check_i] != m[i]);
	}
	OSMO_ASSERT(llist_len(&map->mappings) == TEST_N_HALF);

	/* create another TEST_N mappings with the same original numbers, but
	 * from a different origin */
	void *origin2 = (void*)0x5678;
	for (i = 0; i < TEST_N_HALF; i++) {
		int i2 = TEST_N_HALF + i;
		nr_t orig = TEST_I + i;
		mapping = nr_map_have(map, origin2, orig, 0);
		m[i2] = mapping->repl;
		OSMO_ASSERT(m[i2] != 0);
		OSMO_ASSERT(llist_len(&map->mappings) == (i2+1));
		for (check_i = 0; check_i < i2; check_i++)
			OSMO_ASSERT(m[check_i] != m[i2]);
	}
	OSMO_ASSERT(llist_len(&map->mappings) == TEST_N);

	/* verify mappings */
	for (i = 0; i < TEST_N_HALF; i++) {
		nr_t orig = TEST_I + i;
		{
			OSMO_ASSERT(nr_map_verify(map, origin1, orig, m[i]));
			OSMO_ASSERT(nr_map_verify_inv(map, m[i], origin1, orig));
		}
		{
			int i2 = TEST_N_HALF + i;
			OSMO_ASSERT(nr_map_verify(map, origin2, orig, m[i2]));
			OSMO_ASSERT(nr_map_verify_inv(map, m[i2], origin2, orig));
		}
	}

	/* remove all mappings */
	for (i = 0; i < TEST_N_HALF; i++) {
		OSMO_ASSERT(llist_len(&map->mappings) == (TEST_N - 2*i));

		nr_t orig = TEST_I + i;
		nr_mapping_del(nr_map_get(map, origin1, orig));
		nr_mapping_del(nr_map_get(map, origin2, orig));
	}
	OSMO_ASSERT(llist_empty(&map->mappings));
#undef TEST_N
#undef TEST_I
}

static int nr_map_is(struct nr_map *map, const char *str)
{
	static char buf[4096];
	char *pos = buf;
	size_t len = sizeof(buf);
	struct nr_mapping *m;
	llist_for_each_entry(m, &map->mappings, entry) {
		size_t wrote = snprintf(pos, len, "(%d->%d@%d), ",
					(int)m->orig,
					(int)m->repl,
					(int)m->expiry_entry.expiry);
		OSMO_ASSERT(wrote < len);
		pos += wrote;
		len -= wrote;
	}
	*pos = '\0';

	if (strncmp(buf, str, sizeof(buf)) != 0) {
		printf("FAILURE: nr_map_is() mismatches expected value:\n"
		       "expected: \"%s\"\n"
		       "is:       \"%s\"\n",
		       str, buf);
		return 0;
	}
	return 1;
}

static void test_expiry(void)
{
	struct expiry expiry;
	struct nr_pool pool;
	struct nr_map map;
	int i;

	expiry_init(&expiry, 30);
	nr_pool_init(&pool);
	nr_map_init(&map, &pool, &expiry);
	OSMO_ASSERT(nr_map_is(&map, ""));

	/* tick on empty map */
	OSMO_ASSERT(expiry_tick(&expiry, 10000) == 0);
	OSMO_ASSERT(nr_map_is(&map, ""));

#define MAP1 \
	"(10->1@10040), " \
	""

#define MAP2 \
	"(20->2@10050), " \
	"(21->3@10051), " \
	"(22->4@10052), " \
	"(23->5@10053), " \
	"(24->6@10054), " \
	"(25->7@10055), " \
	"(26->8@10056), " \
	"(27->9@10057), " \
	""

#define MAP3 \
	"(420->10@10072), " \
	"(421->11@10072), " \
	"(422->12@10072), " \
	"(423->13@10072), " \
	"(424->14@10072), " \
	"(425->15@10072), " \
	"(426->16@10072), " \
	"(427->17@10072), " \
	""

	/* add mapping at time 10010. */
	nr_map_have(&map, 0, 10, 10010);
	OSMO_ASSERT(nr_map_is(&map, MAP1));

	/* tick on unexpired item. */
	OSMO_ASSERT(expiry_tick(&expiry, 10010) == 0);
	OSMO_ASSERT(expiry_tick(&expiry, 10011) == 0);
	OSMO_ASSERT(nr_map_is(&map, MAP1));

	/* Spread mappings at 10020, 10021, ... 10027. */
	for (i = 0; i < 8; i++)
		nr_map_have(&map, 0, 20 + i, 10020 + i);
	OSMO_ASSERT(nr_map_is(&map, MAP1 MAP2));

	/* tick on unexpired items. */
	OSMO_ASSERT(expiry_tick(&expiry, 10030) == 0);
	OSMO_ASSERT(expiry_tick(&expiry, 10039) == 0);
	OSMO_ASSERT(nr_map_is(&map, MAP1 MAP2));

	/* expire the first item (from 10010). */
	OSMO_ASSERT(expiry_tick(&expiry, 10010 + 30) == 1);
	OSMO_ASSERT(nr_map_is(&map, MAP2));

	/* again nothing to expire */
	OSMO_ASSERT(expiry_tick(&expiry, 10041) == 0);
	OSMO_ASSERT(nr_map_is(&map, MAP2));

	/* Mappings all at the same time. */
	for (i = 0; i < 8; i++)
		nr_map_have(&map, 0, 420 + i, 10042);
	OSMO_ASSERT(nr_map_is(&map, MAP2 MAP3));

	/* Eight to expire, were added further above to be chronologically
	 * correct, at 10020..10027. */
	OSMO_ASSERT(expiry_tick(&expiry, 10027 + 30) == 8);
	OSMO_ASSERT(nr_map_is(&map, MAP3));

	/* again nothing to expire */
	OSMO_ASSERT(expiry_tick(&expiry, 10027 + 30) == 0);
	OSMO_ASSERT(nr_map_is(&map, MAP3));

	/* Eight to expire, from 10042. Now at 10042 + 30: */
	OSMO_ASSERT(expiry_tick(&expiry, 10042 + 30) == 8);
	OSMO_ASSERT(nr_map_is(&map, ""));

#undef MAP1
#undef MAP2
#undef MAP3
}



/* override, requires '-Wl,--wrap=gtphub_resolve_ggsn_addr' */
int __real_gtphub_resolve_ggsn_addr(struct gtphub *hub,
				    struct osmo_sockaddr *result,
				    struct gtp_packet_desc *p);

struct osmo_sockaddr resolved_ggsn_addr = {.l = 0};
int __wrap_gtphub_resolve_ggsn_addr(struct gtphub *hub,
				    struct osmo_sockaddr *result,
				    struct gtp_packet_desc *p)
{
	osmo_sockaddr_copy(result, &resolved_ggsn_addr);
	printf("Wrap: returning GGSN addr: %s\n",
	       osmo_sockaddr_to_str(result));
	return (resolved_ggsn_addr.l != 0)? 0 : -1;
}

#define buf_len 1024
static uint8_t buf[buf_len];

static unsigned int msg(const char *hex)
{
	unsigned int l = osmo_hexparse(hex, buf, buf_len);
	OSMO_ASSERT(l > 0);
	return l;
}

/* Compare static buf to given string constant. The amount of bytes is obtained
 * from parsing the GTP header in buf.  hex must match an osmo_hexdump() of the
 * desired message. Return 1 if size and content match. */
#define msg_is(MSG) _msg_is(MSG, __FILE__, __LINE__)
static int _msg_is(const char *hex, const char *file, int line)
{
	struct gtp1_header_long *h = (void*)buf;
	int len = ntoh16(h->length) + 8;
	const char *dump = osmo_hexdump_nospc(buf, len);
	int cmp = strcmp(dump, hex);

	if (cmp != 0) {
		printf("\n%s:%d: msg_is(): MISMATCH\n"
		       "  expecting:\n'%s'\n"
		       "        got:\n'%s'\n\n",
		       file,
		       line,
		       hex, dump);
		int i;
		int l = strlen(hex);
		int m = strlen(dump);
		if (m < l)
			l = m;
		for (i = 0; i < l; i++) {
			if (hex[i] != dump[i]) {
				printf("First mismatch at position %d:\n"
				       "  %s\n  %s\n", i, hex + i, dump + i);
				break;
			}
		}
	}
	return cmp == 0;
}

#define same_addr(GOT, EXPECTED) _same_addr((GOT),(EXPECTED), __FILE__, __LINE__)
static int _same_addr(const struct osmo_sockaddr *got,
		      const struct osmo_sockaddr *expected,
		      const char *file, int line)
{
	int cmp = osmo_sockaddr_cmp(got, expected);
	if (!cmp)
		return 1;
	char buf[256];
	printf("\n%s:%d: addr_is(): MISMATCH\n"
	       "  expecting: '%s'\n"
	       "        got: '%s'\n\n",
	       file, line,
	       osmo_sockaddr_to_str(expected),
	       osmo_sockaddr_to_strb(got, buf, sizeof(buf)));
	return 0;
}

static void test_echo(void)
{
	struct gtphub _hub;
	struct gtphub *hub = &_hub;
	time_t now = 123;

	gtphub_init(hub);

	const char *gtp_ping_from_sgsn =
		"32"	/* 0b001'1 0010: version 1, protocol GTP, with seq nr. */
		"01"	/* type 01: Echo request */
		"0004"	/* length of 4 after header TEI */
		"00000000" /* header TEI == 0 in Echo */
		"abcd"	/* some 16 octet sequence nr */
		"0000"	/* N-PDU 0, no extension header (why is this here?) */
		;

	/* Same with mapped sequence number */
	const char *gtp_ping_to_ggsn =
		"32" "01" "0004" "00000000"
		"6d31"	/* mapped seq */
		"00" "00";

	const char *gtp_pong_from_ggsn =
		"32"
		"02"	/* type 02: Echo response */
		"0006"	/* len */
		"00000000" /* tei */
		"6d31"	/* mapped seq */
		"0000"	/* ext */
		"0e01"	/* 0e: Recovery, val == 1 */
		;
	/* Same with unmapped sequence number */
	const char *gtp_pong_to_sgsn =
		"32" "02" "0006" "00000000"
		"abcd"	/* unmapped seq */
		"00" "00" "0e01";

	/* Set the GGSN address that gtphub is forced to resolve to. */
	OSMO_ASSERT(osmo_sockaddr_init_udp(&resolved_ggsn_addr,
					   "192.168.43.34", 434)
		    == 0);

	/* according to spec, we'd always send to port 2123 instead...
	struct osmo_sockaddr ggsn_standard_port;
	OSMO_ASSERT(osmo_sockaddr_init_udp(&ggsn_standard_port,
					   "192.168.43.34", 2123)
		    == 0);
	 */

	struct osmo_sockaddr orig_sgsn_addr;
	OSMO_ASSERT(osmo_sockaddr_init(&orig_sgsn_addr,
				       AF_UNSPEC, SOCK_DGRAM, IPPROTO_UDP,
				       "192.168.42.23", 423) == 0);
	struct osmo_fd *ggsn_ofd = NULL;
	struct osmo_sockaddr ggsn_addr;
	int send;
	send = gtphub_from_sgsns_handle_buf(hub, GTPH_PLANE_CTRL, &orig_sgsn_addr,
					    buf, msg(gtp_ping_from_sgsn), now,
					    &ggsn_ofd, &ggsn_addr);
	OSMO_ASSERT(send > 0);
	OSMO_ASSERT(ggsn_addr.l);
	OSMO_ASSERT(same_addr(&ggsn_addr, &resolved_ggsn_addr));
	OSMO_ASSERT(msg_is(gtp_ping_to_ggsn));

	struct osmo_fd *sgsn_ofd;
	struct osmo_sockaddr sgsn_addr;
	send = gtphub_from_ggsns_handle_buf(hub, GTPH_PLANE_CTRL, &ggsn_addr,
					    buf, msg(gtp_pong_from_ggsn), now,
					    &sgsn_ofd, &sgsn_addr);
	OSMO_ASSERT(send > 0);
	OSMO_ASSERT(same_addr(&sgsn_addr, &orig_sgsn_addr));
	OSMO_ASSERT(msg_is(gtp_pong_to_sgsn));

	struct gtphub_peer_port *ggsn_port =
		gtphub_port_find_sa(&hub->to_ggsns[GTPH_PLANE_CTRL],
				    &resolved_ggsn_addr);
	OSMO_ASSERT(ggsn_port);
	struct gtphub_peer *ggsn = ggsn_port->peer_addr->peer;
	/* now == 123; now + 30 == 153. */
	OSMO_ASSERT(nr_map_is(&ggsn->seq_map, "(43981->27953@153), "));

	OSMO_ASSERT(nr_map_is(&hub->tei_map[GTPH_PLANE_CTRL], ""));
	OSMO_ASSERT(nr_map_is(&hub->tei_map[GTPH_PLANE_USER], ""));

	gtphub_gc(hub, now + EXPIRE_ALL);
}

static void test_create_pdp_ctx(void)
{
	struct gtphub _hub;
	struct gtphub *hub = &_hub;
	time_t now = 345;

	gtphub_init(hub);

	/* Tell this mock gtphub its local address for this test. */
	OSMO_ASSERT(gsn_addr_from_str(&hub->to_sgsns[GTPH_PLANE_CTRL].local_addr,
				      "127.0.1.1") == 0);
	OSMO_ASSERT(gsn_addr_from_str(&hub->to_sgsns[GTPH_PLANE_USER].local_addr,
				      "127.0.1.2") == 0);
	OSMO_ASSERT(gsn_addr_from_str(&hub->to_ggsns[GTPH_PLANE_CTRL].local_addr,
				      "127.0.2.1") == 0);
	OSMO_ASSERT(gsn_addr_from_str(&hub->to_ggsns[GTPH_PLANE_USER].local_addr,
				      "127.0.2.2") == 0);

	/* This is copied from a packet that sgsnemu sends. */
	const char *gtp_req_from_sgsn =
		"32" 	/* 0b001'1 0010: version 1, protocol GTP, with seq nr. */
		"10" 	/* type 16: Create PDP Context Request */
		"0067"	/* length = 8 + 103 */
		"00000000" /* No TEI yet */
		"abcd"	/* Sequence nr */
		"00"	/* N-PDU 0 */
		"00"	/* No extensions */
		/* IEs */
		"02"	/* 2 = IMSI */
		  "42000121436587f9"
		"0e" "60" /* 14: Recovery = 96 */
		"0f01"	/* 15: Selection mode = MS provided APN, subscription not verified*/
		"10"	/* 16: TEI Data I */
		  "00000123"
		"11"	/* 17: TEI Control Plane */
		  "00000321"
		"1400"	/* 20: NSAPI = 0*/
		"1a"	/* 26: Charging Characteristics */
		  "0800"
		"80"	/* 128: End User Address */
		  "0002" /* length = 2: empty PDP Address */
		  "f121" /* spare 0xf0, PDP organization 1, PDP type number 0x21 = 33 */
		"83"	/* 131: Access Point Name */
		  "0008" /* length = 8 */
		  "696e7465726e6574" /* "internet" */
		"84"	/* 132: Protocol Configuration Options */
		  "0015" /* length = 21 */
		  "80c0231101010011036d69670868656d6d656c6967"
		"85"	/* 133: GSN Address */
		  "0004" /* length */
		  "abcdef00"
		"85"	/* 133: GSN Address (second entry) */
		  "0004" /* length */
		  "fedcba00"
		"86"	/* 134: MS International PSTN/ISDN Number (MSISDN) */
		  "0007" /* length */
		  "916407123254f6" /* 1946702123456(f) */
		"87"	/* 135: Quality of Service (QoS) Profile */
		  "0004" /* length */
		  "00"	/* priority */
		  "0b921f" /* QoS profile data */
		;

	const char *gtp_req_to_ggsn =
		"32" "10" "0067" "00000000"
		"6d31"	/* mapped seq ("abcd") */
		"00" "00" "02" "42000121436587f9" "0e60" "0f01"
		"10" "00000001" /* mapped TEI Data I ("123") */
		"11" "00000001" /* mapped TEI Control ("321") */
		"1400" "1a" "0800" "80" "0002" "f121" "83"
		"0008" "696e7465726e6574" "84" "0015"
		"80c0231101010011036d69670868656d6d656c6967" "85" "0004"
		"7f000201" /* replaced with gtphub's address ggsn ctrl */
		"85" "0004"
		"7f000202" /* replaced with gtphub's address ggsn user */
		"86" "0007" "916407123254f6"
		"87" "0004" "00" "0b921f"
		;

	const char *gtp_resp_from_ggsn =
		"32"
		"11"	/* Create PDP Context Response */
		"004e"	/* length = 78 + 8 */
		"00000001" /* destination TEI (sent in req above) */
		"6d31"	/* mapped seq */
		"00" "00"
		/* IEs */
		"01"	/* 1: Cause */
		  "80"	/* value = 0b10000000 = response, no rejection. */
		"08"	/* 8: Reordering Required */
		  "00"	/* not required. */
		"0e" "01" /* 14: Recovery = 1 */
		"10"	/* 16: TEI Data I */
		  "00000567"
		"11"	/* 17: TEI Control */
		  "00000765"
		"7f"	/* 127: Charging ID */
		  "00000001"
		"80"	/* 128: End User Address */
		  "0006" /* length = 6 */
		  "f121" /* spare 0xf0, PDP organization 1, PDP type number 0x21 = 33 */
		  "7f000002"
		"84"	/* 132: Protocol Configuration Options */
		  "0014" /* len = 20 */
		  "8080211002000010810608080808830600000000"
		"85"	/* 133: GSN Address (Ctrl) */
		  "0004" /* length */
		  "7f000002"
		"85"	/* 133: GSN Address (User) */
		  "0004" /* length */
		  "7f000002"
		"87"	/* 135: Quality of Service (QoS) Profile */
		  "0004" /* length */
		  "00"	/* priority */
		  "0b921f" /* QoS profile data */
		;

	const char *gtp_resp_to_sgsn =
		"32" "11" "004e"
		"00000321" /* unmapped TEI ("001") */
		"abcd" /* unmapped seq ("6d31") */
		"00" "00" "01" "80" "08" "00" "0e" "01"
		"10" "00000002" /* mapped TEI from GGSN ("567") */
		"11" "00000002" /* mapped TEI from GGSN ("765") */
		"7f" "00000001" "80" "0006" "f121" "7f000002" "84" "0014"
		"8080211002000010810608080808830600000000"
		"85" "0004"
		  "7f000101" /* gtphub's address towards SGSNs (Ctrl) */
		"85" "0004"
		  "7f000102" /* gtphub's address towards SGSNs (User) */
		"87" "0004" "00" "0b921f"
		;

	/* Set the GGSN address that gtphub is forced to resolve to. */
	OSMO_ASSERT(osmo_sockaddr_init_udp(&resolved_ggsn_addr,
					   "192.168.43.34", 434)
		    == 0);

	struct osmo_sockaddr orig_sgsn_addr;
	OSMO_ASSERT(osmo_sockaddr_init(&orig_sgsn_addr,
				       AF_UNSPEC, SOCK_DGRAM, IPPROTO_UDP,
				       "192.168.42.23", 423) == 0);
	struct osmo_fd *ggsn_ofd = NULL;
	struct osmo_sockaddr ggsn_addr;
	int send;
	send = gtphub_from_sgsns_handle_buf(hub, GTPH_PLANE_CTRL, &orig_sgsn_addr,
					    buf, msg(gtp_req_from_sgsn), now,
					    &ggsn_ofd, &ggsn_addr);
	OSMO_ASSERT(send > 0);
	OSMO_ASSERT(same_addr(&ggsn_addr, &resolved_ggsn_addr));
	OSMO_ASSERT(msg_is(gtp_req_to_ggsn));

	struct osmo_fd *sgsn_ofd;
	struct osmo_sockaddr sgsn_addr;
	send = gtphub_from_ggsns_handle_buf(hub, GTPH_PLANE_CTRL, &ggsn_addr,
					    buf, msg(gtp_resp_from_ggsn), now,
					    &sgsn_ofd, &sgsn_addr);
	OSMO_ASSERT(send > 0);
	OSMO_ASSERT(same_addr(&sgsn_addr, &orig_sgsn_addr));
	OSMO_ASSERT(msg_is(gtp_resp_to_sgsn));

	struct gtphub_peer_port *ggsn_port =
		gtphub_port_find_sa(&hub->to_ggsns[GTPH_PLANE_CTRL],
				    &resolved_ggsn_addr);
	OSMO_ASSERT(ggsn_port);
	struct gtphub_peer *ggsn = ggsn_port->peer_addr->peer;
	/* now == 345; now + 30 == 375.
	 * seq mapping from above:
	 *   0xabcd == 43981 (sent in the packet)
	 *   0x6d31 == 27953 (harcoded seq mapping start val) */
	OSMO_ASSERT(nr_map_is(&ggsn->seq_map, "(43981->27953@375), "));

	/* now == 345; now + (6 * 60 * 60) == 21600 + 345 == 21945.
	 * 0x00000321 == 801 (TEI from SGSN Ctrl)
	 * 0x00000123 == 291 (TEI from SGSN User)
	 * 0x00000765 == 1893 (TEI from GGSN Ctrl)
	 * 0x00000567 == 1383 (TEI from GGSN User)
	 * Mapped TEIs should be 1 and 2. */
	OSMO_ASSERT(nr_map_is(&hub->tei_map[GTPH_PLANE_CTRL], "(801->1@21945), (1893->2@21945), "));
	OSMO_ASSERT(nr_map_is(&hub->tei_map[GTPH_PLANE_USER], "(291->1@21945), (1383->2@21945), "));

	gtphub_gc(hub, now + EXPIRE_ALL);
}

static struct log_info_cat gtphub_categories[] = {
	[DGTPHUB] = {
		.name = "DGTPHUB",
		.description = "GTP Hub",
		.color = "\033[1;33m",
		.enabled = 1, .loglevel = LOGL_NOTICE,
	},
};

static struct log_info info = {
	.cat = gtphub_categories,
	.num_cat = ARRAY_SIZE(gtphub_categories),
};

int main(int argc, char **argv)
{
	osmo_init_logging(&info);
	osmo_gtphub_ctx = talloc_named_const(NULL, 0, "osmo_gtphub");

	test_nr_map_basic();
	test_expiry();
	test_echo();
	test_create_pdp_ctx();
	printf("Done\n");

	talloc_report_full(osmo_gtphub_ctx, stderr);
	OSMO_ASSERT(talloc_total_blocks(osmo_gtphub_ctx) == 1);
	return 0;
}

