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
#include <osmocom/core/application.h>

#include <openbsc/debug.h>

#include <openbsc/gtphub.h>
#include <gtp.h>
#include <gtpie.h>

#define ZERO_STRUCT(struct_pointer) memset(struct_pointer, '\0', \
					   sizeof(*(struct_pointer)))

#define LVL2_ASSERT(exp) LVL2_ASSERT_R(exp, return 0)
#define LVL2_ASSERT_R(exp, ret)    \
	if (!(exp)) { \
		fprintf(stderr, "LVL2 Assert failed %s %s:%d\n", #exp, \
			__FILE__, __LINE__); \
		osmo_generate_backtrace(); \
		ret; \
	}

/* Convenience makro, note: only within this C file. */
#define LOG(label) \
	{ fprintf(stderr, "\n" label "\n"); \
	  printf(label "\n"); }

void gtphub_init(struct gtphub *hub);
void gtphub_free(struct gtphub *hub);

void *osmo_gtphub_ctx;

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

static struct nr_mapping *nr_map_have(struct nr_map *map, void *origin,
				      nr_t orig, time_t now)
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

static nr_t nr_map_verify(const struct nr_map *map, void *origin, nr_t orig,
			  nr_t expect_repl)
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
		printf("mapping found, but origin mismatches:"
		       " expect %p, got %p\n",
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

	nr_pool_init(pool, 1, 1000);
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
		OSMO_ASSERT(llist_count(&map->mappings) == (i+1));
		for (check_i = 0; check_i < i; check_i++)
			OSMO_ASSERT(m[check_i] != m[i]);
	}
	OSMO_ASSERT(llist_count(&map->mappings) == TEST_N_HALF);

	/* create another TEST_N mappings with the same original numbers, but
	 * from a different origin */
	void *origin2 = (void*)0x5678;
	for (i = 0; i < TEST_N_HALF; i++) {
		int i2 = TEST_N_HALF + i;
		nr_t orig = TEST_I + i;
		mapping = nr_map_have(map, origin2, orig, 0);
		m[i2] = mapping->repl;
		OSMO_ASSERT(m[i2] != 0);
		OSMO_ASSERT(llist_count(&map->mappings) == (i2+1));
		for (check_i = 0; check_i < i2; check_i++)
			OSMO_ASSERT(m[check_i] != m[i2]);
	}
	OSMO_ASSERT(llist_count(&map->mappings) == TEST_N);

	/* verify mappings */
	for (i = 0; i < TEST_N_HALF; i++) {
		nr_t orig = TEST_I + i;
		{
			OSMO_ASSERT(nr_map_verify(map, origin1, orig, m[i]));
			OSMO_ASSERT(nr_map_verify_inv(map, m[i], origin1,
						      orig));
		}
		{
			int i2 = TEST_N_HALF + i;
			OSMO_ASSERT(nr_map_verify(map, origin2, orig, m[i2]));
			OSMO_ASSERT(nr_map_verify_inv(map, m[i2], origin2,
						      orig));
		}
	}

	/* remove all mappings */
	for (i = 0; i < TEST_N_HALF; i++) {
		OSMO_ASSERT(llist_count(&map->mappings) == (TEST_N - 2*i));

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
		size_t wrote = snprintf(pos, len, "(%u->%u@%d), ",
					m->orig,
					m->repl,
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

static int test_nr_map_wrap_with(nr_t nr_min, nr_t nr_max, nr_t repl_last,
				 nr_t orig_start, int orig_n,
				 const char *expect)
{
	struct nr_pool _pool;
	struct nr_pool *pool = &_pool;
	struct nr_map _map;
	struct nr_map *map = &_map;

	nr_pool_init(pool, nr_min, nr_max);
	nr_map_init(map, pool, NULL);

	pool->last_nr = repl_last;

	void *origin = (void*)0x1234;

	int i;
	for (i = 0; i < orig_n; i++)
		LVL2_ASSERT(nr_map_have(map, origin, orig_start + i, 0));

	LVL2_ASSERT(nr_map_is(map, expect));

	nr_map_clear(map);
	return 1;
}

static void test_nr_map_wrap(void)
{
	OSMO_ASSERT(test_nr_map_wrap_with(
		0, UINT_MAX, UINT_MAX - 2,
		1, 5,
		"(1->4294967294@0), "
		"(2->4294967295@0), "
		"(3->0@0), "
		"(4->1@0), "
		"(5->2@0), "
		));
	OSMO_ASSERT(test_nr_map_wrap_with(
		5, 10, 8,
		1, 5,
		"(1->9@0), (2->10@0), (3->5@0), (4->6@0), (5->7@0), "
		));
}

static void test_expiry(void)
{
	struct expiry expiry;
	struct nr_pool pool;
	struct nr_map map;
	int i;

	expiry_init(&expiry, 30);
	nr_pool_init(&pool, 1, 1000);
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

char resolve_ggsn_got_imsi[GSM23003_IMSI_MAX_DIGITS+1];
char resolve_ggsn_got_ni[GSM_APN_LENGTH];

struct osmo_sockaddr resolved_ggsn_addr;
static int resolve_to_ggsn(const char *addr, uint16_t port)
{
	LVL2_ASSERT(osmo_sockaddr_init_udp(&resolved_ggsn_addr,
					   addr, port)
		    == 0);
	return 1;
}

struct osmo_sockaddr resolved_sgsn_addr;
static int resolve_to_sgsn(const char *addr, uint16_t port)
{
	LVL2_ASSERT(osmo_sockaddr_init_udp(&resolved_sgsn_addr,
					   addr, port)
		    == 0);
	return 1;
}

struct osmo_sockaddr sgsn_sender;
static int send_from_sgsn(const char *addr, uint16_t port)
{
	LVL2_ASSERT(osmo_sockaddr_init_udp(&sgsn_sender,
					   addr, port)
		    == 0);
	return 1;
}

struct osmo_sockaddr ggsn_sender;
static int send_from_ggsn(const char *addr, uint16_t port)
{
	LVL2_ASSERT(osmo_sockaddr_init_udp(&ggsn_sender,
					   addr, port)
		    == 0);
	return 1;
}


/* override, requires '-Wl,--wrap=gtphub_resolve_ggsn_addr' */
struct gtphub_peer_port *__real_gtphub_resolve_ggsn_addr(struct gtphub *hub,
							 const char *imsi_str,
							 const char *apn_ni_str);

struct gtphub_peer_port *__wrap_gtphub_resolve_ggsn_addr(struct gtphub *hub,
							 const char *imsi_str,
							 const char *apn_ni_str)
{
	struct gsn_addr resolved_gsna;
	uint16_t resolved_port;

	OSMO_ASSERT(gsn_addr_from_sockaddr(&resolved_gsna, &resolved_port,
					   &resolved_ggsn_addr) == 0);

	struct gtphub_peer_port *pp;
	pp = gtphub_port_have(hub, &hub->to_gsns[GTPH_SIDE_GGSN][GTPH_PLANE_CTRL],
			      &resolved_gsna, resolved_port);
	printf("- __wrap_gtphub_resolve_ggsn_addr():\n"
	       "  returning GGSN addr from imsi %s ni %s: %s\n",
	       imsi_str, apn_ni_str, gtphub_port_str(pp));

	if (!imsi_str)
		imsi_str = "(null)";
	osmo_strlcpy(resolve_ggsn_got_imsi, imsi_str,
		     sizeof(resolve_ggsn_got_imsi));

	if (!apn_ni_str)
		apn_ni_str = "(null)";
	osmo_strlcpy(resolve_ggsn_got_ni, apn_ni_str,
		     sizeof(resolve_ggsn_got_ni));

	return pp;
}

#define was_resolved_for(IMSI,NI) _was_resolved_for(IMSI, NI, __FILE__, __LINE__)
static int _was_resolved_for(const char *imsi, const char *ni, const char
			     *file, int line)
{
	int cmp0 = strncmp(imsi, resolve_ggsn_got_imsi,
			   sizeof(resolve_ggsn_got_imsi));

	if (cmp0 != 0) {
		printf("\n%s:%d: was_resolved_for(): MISMATCH for IMSI\n"
		       "  expecting: '%s'\n"
		       "        got: '%s'\n\n",
		       file,
		       line,
		       imsi, resolve_ggsn_got_imsi);
	}

	int cmp1 = strncmp(ni, resolve_ggsn_got_ni,
			   sizeof(resolve_ggsn_got_ni));
	if (cmp1 != 0) {
		printf("\n%s:%d: was_resolved_for(): MISMATCH for NI\n"
		       "  expecting: '%s'\n"
		       "        got: '%s'\n\n",
		       file,
		       line,
		       ni, resolve_ggsn_got_ni);
	}

	return (cmp0 == 0) && (cmp1 == 0);
}

/* override, requires '-Wl,--wrap=gtphub_ares_init' */
int __real_gtphub_ares_init(struct gtphub *hub);

int __wrap_gtphub_ares_init(struct gtphub *hub)
{
	/* Do nothing. */
	return 0;
}

/* override, requires '-Wl,--wrap=gtphub_write' */
int __real_gtphub_write(const struct osmo_fd *to,
			const struct osmo_sockaddr *to_addr,
			const uint8_t *buf, size_t buf_len);

int __wrap_gtphub_write(const struct osmo_fd *to,
			const struct osmo_sockaddr *to_addr,
			const uint8_t *buf, size_t buf_len)
{
	printf("Out-of-band gtphub_write(%d):\n"
	       "to %s\n"
	       "%s\n",
	       (int)buf_len,
	       osmo_sockaddr_to_str(to_addr),
	       osmo_hexdump(buf, buf_len));
	return 0;
}

#define buf_len 1024
static uint8_t buf[buf_len];
static uint8_t *reply_buf;

static unsigned int msg(const char *hex)
{
	unsigned int l = osmo_hexparse(hex, buf, buf_len);
	OSMO_ASSERT(l > 0);
	return l;
}

/* Compare static buf to given string constant. The amount of bytes is obtained
 * from parsing the GTP header in buf.  hex must match an osmo_hexdump() of the
 * desired message. Return 1 if size and content match. */
#define reply_is(MSG) _reply_is(MSG, __FILE__, __LINE__)
static int _reply_is(const char *hex, const char *file, int line)
{
	struct gtp1_header_long *h = (void*)reply_buf;
	int len = ntoh16(h->length) + 8;
	const char *dump = osmo_hexdump_nospc(reply_buf, len);
	int cmp = strcmp(dump, hex);

	if (cmp != 0) {
		printf("\n%s:%d: reply_is(): MISMATCH\n"
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


time_t now;
static struct gtphub _hub;
static struct gtphub *hub = &_hub;

static int setup_test_hub()
{
	/* Not really needed, but to make 100% sure... */
	ZERO_STRUCT(hub);

	gtphub_init(hub);

	/* Tell this mock gtphub its local address for this test. */
	LVL2_ASSERT(gsn_addr_from_str(&hub->to_gsns[GTPH_SIDE_SGSN][GTPH_PLANE_CTRL].local_addr,
				      "127.0.1.1") == 0);
	LVL2_ASSERT(gsn_addr_from_str(&hub->to_gsns[GTPH_SIDE_SGSN][GTPH_PLANE_USER].local_addr,
				      "127.0.1.2") == 0);
	LVL2_ASSERT(gsn_addr_from_str(&hub->to_gsns[GTPH_SIDE_GGSN][GTPH_PLANE_CTRL].local_addr,
				      "127.0.2.1") == 0);
	LVL2_ASSERT(gsn_addr_from_str(&hub->to_gsns[GTPH_SIDE_GGSN][GTPH_PLANE_USER].local_addr,
				      "127.0.2.2") == 0);

	hub->restart_counter = 0x23;
	now = 345;
	LVL2_ASSERT(send_from_sgsn("192.168.42.23", 423));
	LVL2_ASSERT(resolve_to_ggsn("192.168.43.34", 2123));
	LVL2_ASSERT(send_from_ggsn("192.168.43.34", 434));
	LVL2_ASSERT(resolve_to_sgsn("192.168.42.23", 2123));

#define GGSNS_CTRL_FD 1
#define GGSNS_USER_FD 2
#define SGSNS_CTRL_FD 3
#define SGSNS_USER_FD 4
	hub->to_gsns[GTPH_SIDE_GGSN][GTPH_PLANE_CTRL].ofd.priv_nr = GGSNS_CTRL_FD;
	hub->to_gsns[GTPH_SIDE_GGSN][GTPH_PLANE_USER].ofd.priv_nr = GGSNS_USER_FD;
	hub->to_gsns[GTPH_SIDE_SGSN][GTPH_PLANE_CTRL].ofd.priv_nr = SGSNS_CTRL_FD;
	hub->to_gsns[GTPH_SIDE_SGSN][GTPH_PLANE_USER].ofd.priv_nr = SGSNS_USER_FD;

	return 1;
}

static int clear_test_hub()
{
	/* expire all */
	gtphub_gc(hub, now + (60 * GTPH_EXPIRE_SLOWLY_MINUTES) + 1);

	int plane_idx;
	plane_idx = GTPH_PLANE_CTRL;
	LVL2_ASSERT(llist_empty(&hub->to_gsns[GTPH_SIDE_GGSN][plane_idx].peers));
	LVL2_ASSERT(llist_empty(&hub->to_gsns[GTPH_SIDE_SGSN][plane_idx].peers));
	plane_idx = GTPH_PLANE_USER;
	LVL2_ASSERT(llist_empty(&hub->to_gsns[GTPH_SIDE_GGSN][plane_idx].peers));
	LVL2_ASSERT(llist_empty(&hub->to_gsns[GTPH_SIDE_SGSN][plane_idx].peers));

	LVL2_ASSERT(llist_empty(&hub->tunnels));
	LVL2_ASSERT(llist_empty(&hub->pending_deletes));
	LVL2_ASSERT(llist_empty(&hub->ggsn_lookups));
	LVL2_ASSERT(llist_empty(&hub->resolved_ggsns));

	gtphub_free(hub);
	return 1;
}

static int tunnels_are(const char *expect)
{
	static char buf[4096];
	char *pos = buf;
	size_t len = sizeof(buf);
	struct gtphub_tunnel *t;
	llist_for_each_entry(t, &hub->tunnels, entry) {
		size_t wrote = snprintf(pos, len, "%s @%d\n",
					gtphub_tunnel_str(t),
					(int)t->expiry_entry.expiry);
		LVL2_ASSERT(wrote < len);
		pos += wrote;
		len -= wrote;
	}
	*pos = '\0';

	if (strncmp(buf, expect, sizeof(buf)) != 0) {
		fprintf(stderr, "FAILURE: tunnels_are() mismatches expected value:\n"
		       "EXPECTED:\n%s\n"
		       "IS:\n%s\n",
		       expect, buf);
		LVL2_ASSERT("tunnels do not match expected listing.");
		return 0;
	}
	return 1;
}

static void test_echo(void)
{
	LOG("test_echo");
	OSMO_ASSERT(setup_test_hub());

	now = 123;

	struct osmo_fd *to_ofd;
	struct osmo_sockaddr to_addr;
	struct gtphub_peer_port *pp;
	int send;

	const char *gtp_ping_from_sgsn =
		"32"	/* 0b001'1 0010: version 1, protocol GTP, with seq nr */
		"01"	/* type 01: Echo request */
		"0004"	/* length of 4 after header TEI */
		"00000000" /* header TEI == 0 in Echo */
		"abcd"	/* some 2 octet sequence nr */
		"0000"	/* N-PDU 0, no extension header (why is this here?) */
		;

	const char *gtp_pong_to_sgsn =
		"32"
		"02"	/* type 02: Echo response */
		"0006"	/* length of 6 after header TEI */
		"00000000" /* header TEI == 0 in Echo */
		"abcd"	/* same sequence nr */
		"0000"
		"0e23"	/* Recovery with restart counter */
		;

	to_ofd = NULL;
	ZERO_STRUCT(&to_addr);
	send = gtphub_handle_buf(hub, GTPH_SIDE_SGSN, GTPH_PLANE_CTRL,
				 &sgsn_sender, buf, msg(gtp_ping_from_sgsn),
				 now, &reply_buf, &to_ofd, &to_addr);
	OSMO_ASSERT(send > 0);
	OSMO_ASSERT(to_addr.l);
	OSMO_ASSERT(same_addr(&to_addr, &sgsn_sender));
	OSMO_ASSERT(to_ofd && (to_ofd->priv_nr == SGSNS_CTRL_FD));
	OSMO_ASSERT(reply_is(gtp_pong_to_sgsn));

	pp = gtphub_port_find_sa(&hub->to_gsns[GTPH_SIDE_SGSN][GTPH_PLANE_CTRL],
				 &sgsn_sender);
	/* We don't record Echo peers. */
	OSMO_ASSERT(!pp);

	const char *gtp_ping_from_ggsn =
		"32"	/* 0b001'1 0010: version 1, protocol GTP, with seq nr */
		"01"	/* type 01: Echo request */
		"0004"	/* length of 4 after header TEI */
		"00000000" /* header TEI == 0 in Echo */
		"cdef"	/* some 2 octet sequence nr */
		"0000"	/* N-PDU 0, no extension header (why is this here?) */
		;

	const char *gtp_pong_to_ggsn =
		"32"
		"02"	/* type 02: Echo response */
		"0006"	/* length of 6 after header TEI */
		"00000000" /* header TEI == 0 in Echo */
		"cdef"	/* same sequence nr */
		"0000"
		"0e23"	/* Recovery with restart counter */
		;

	to_ofd = NULL;
	ZERO_STRUCT(&to_addr);
	send = gtphub_handle_buf(hub, GTPH_SIDE_GGSN, GTPH_PLANE_CTRL,
				 &ggsn_sender, buf, msg(gtp_ping_from_ggsn),
				 now, &reply_buf, &to_ofd, &to_addr);
	OSMO_ASSERT(send > 0);
	OSMO_ASSERT(same_addr(&to_addr, &ggsn_sender));
	OSMO_ASSERT(to_ofd && (to_ofd->priv_nr == GGSNS_CTRL_FD));
	OSMO_ASSERT(reply_is(gtp_pong_to_ggsn));

	pp = gtphub_port_find_sa(&hub->to_gsns[GTPH_SIDE_GGSN][GTPH_PLANE_CTRL],
				 &sgsn_sender);
	OSMO_ASSERT(!pp);


	/* And all the same on the user plane. */

	to_ofd = NULL;
	ZERO_STRUCT(&to_addr);
	send = gtphub_handle_buf(hub, GTPH_SIDE_SGSN, GTPH_PLANE_USER,
				 &sgsn_sender, buf, msg(gtp_ping_from_sgsn),
				 now, &reply_buf, &to_ofd, &to_addr);
	OSMO_ASSERT(send > 0);
	OSMO_ASSERT(to_addr.l);
	OSMO_ASSERT(same_addr(&to_addr, &sgsn_sender));
	OSMO_ASSERT(to_ofd && (to_ofd->priv_nr == SGSNS_USER_FD));
	OSMO_ASSERT(reply_is(gtp_pong_to_sgsn));

	pp = gtphub_port_find_sa(&hub->to_gsns[GTPH_SIDE_SGSN][GTPH_PLANE_USER],
				 &sgsn_sender);
	OSMO_ASSERT(!pp);

	to_ofd = NULL;
	ZERO_STRUCT(&to_addr);
	send = gtphub_handle_buf(hub, GTPH_SIDE_GGSN, GTPH_PLANE_USER,
				 &ggsn_sender, buf, msg(gtp_ping_from_ggsn),
				 now, &reply_buf, &to_ofd, &to_addr);
	OSMO_ASSERT(send > 0);
	OSMO_ASSERT(same_addr(&to_addr, &ggsn_sender));
	OSMO_ASSERT(to_ofd && (to_ofd->priv_nr == GGSNS_USER_FD));
	OSMO_ASSERT(reply_is(gtp_pong_to_ggsn));

	pp = gtphub_port_find_sa(&hub->to_gsns[GTPH_SIDE_GGSN][GTPH_PLANE_USER],
				 &sgsn_sender);
	OSMO_ASSERT(!pp);


	OSMO_ASSERT(clear_test_hub());
}


#define MSG_PDP_CTX_REQ(len, seq, restart, imsi, tei_u, tei_c, apn, gsn_c, gsn_u) \
		"32" 	/* 0b001'1 0010: version 1, protocol GTP, with seq nr. */ \
		"10" 	/* type 16: Create PDP Context Request */ \
		len	/* msg length = 8 + len (2 octets) */ \
		"00000000" /* No TEI yet */ \
		seq	/* Sequence nr (2 octets) */ \
		"00"	/* N-PDU 0 */ \
		"00"	/* No extensions */ \
		/* IEs */ \
		"0e" restart /* 14: Recovery (restart counter: 1 octet) */ \
		"02"	/* 2 = IMSI */ \
		  imsi	/* (8 octets) */ \
		"0f01"	/* 15: Selection mode = MS provided APN, subscription not verified*/ \
		"10"	/* 16: TEI Data I */ \
		  tei_u	/* (4 octets) */ \
		"11"	/* 17: TEI Control Plane */ \
		  tei_c	/* (4 octets) */ \
		"1400"	/* 20: NSAPI = 0*/ \
		"1a"	/* 26: Charging Characteristics */ \
		  "0800" \
		"80"	/* 128: End User Address */ \
		  "0002" /* length = 2: empty PDP Address */ \
		  "f121" /* spare 0xf0, PDP organization 1, PDP type number 0x21 = 33 */ \
		"83"	/* 131: Access Point Name */ \
                  apn	/* (2 octets length, N octets encoded APN-NI) */ \
		"84"	/* 132: Protocol Configuration Options */ \
		  "0015" /* length = 21 */ \
		  "80c0231101010011036d69670868656d6d656c6967" \
		"85"	/* 133: GSN Address */ \
		  gsn_c /* (2 octets length, N octets addr) */ \
		"85"	/* 133: GSN Address (second entry) */ \
		  gsn_u /* (2 octets length, N octets addr) */ \
		"86"	/* 134: MS International PSTN/ISDN Number (MSISDN) */ \
		  "0007" /* length */ \
		  "916407123254f6" /* 1946702123456(f) */ \
		"87"	/* 135: Quality of Service (QoS) Profile */ \
		  "0004" /* length */ \
		  "00"	/* priority */ \
		  "0b921f" /* QoS profile data */ 

#define MSG_PDP_CTX_RSP(len, tei_h, seq, restart, tei_u, tei_c, gsn_c, gsn_u) \
		"32" \
		"11"	/* Create PDP Context Response */ \
		len	/* msg length = 8 + len (2 octets) */ \
		tei_h	/* destination TEI (sent in req above) */ \
		seq	/* mapped seq */ \
		"00" "00" \
		/* IEs */ \
		"01"	/* 1: Cause */ \
		  "80"	/* value = 0b10000000 = response, no rejection. */ \
		"08"	/* 8: Reordering Required */ \
		  "00"	/* not required. */ \
		"0e" restart /* 14: Recovery */ \
		"10"	/* 16: TEI Data I */ \
		  tei_u \
		"11"	/* 17: TEI Control */ \
		  tei_c \
		"7f"	/* 127: Charging ID */ \
		  "00000001" \
		"80"	/* 128: End User Address */ \
		  "0006" /* length = 6 */ \
		  "f121" /* spare 0xf0, PDP organization 1, PDP type number 0x21 = 33 */ \
		  "7f000002" \
		"84"	/* 132: Protocol Configuration Options */ \
		  "0014" /* len = 20 */ \
		  "8080211002000010810608080808830600000000" \
		"85"	/* 133: GSN Address (Ctrl) */ \
		  gsn_c \
		"85"	/* 133: GSN Address (User) */ \
		  gsn_u \
		"87"	/* 135: Quality of Service (QoS) Profile */ \
		  "0004" /* length */ \
		  "00"	/* priority */ \
		  "0b921f" /* QoS profile data */

#define msg_from_sgsn_c(A,B,C,D) msg_from_sgsn(GTPH_PLANE_CTRL, A,B,C,D)
#define msg_from_sgsn_u(A,B,C,D) msg_from_sgsn(GTPH_PLANE_USER, A,B,C,D)
static int msg_from_sgsn(int plane_idx,
			 struct osmo_sockaddr *_sgsn_sender,
			 struct osmo_sockaddr *ggsn_receiver,
			 const char *hex_from_sgsn,
			 const char *hex_to_ggsn)
{
	struct osmo_fd *ggsn_ofd = NULL;
	struct osmo_sockaddr ggsn_addr;
	int send;
	send = gtphub_handle_buf(hub, GTPH_SIDE_SGSN, plane_idx, _sgsn_sender,
				 buf, msg(hex_from_sgsn), now,
				 &reply_buf, &ggsn_ofd, &ggsn_addr);
	LVL2_ASSERT(send > 0);
	LVL2_ASSERT(same_addr(&ggsn_addr, ggsn_receiver));
	LVL2_ASSERT(reply_is(hex_to_ggsn));
	return 1;
}

#define msg_from_ggsn_c(A,B,C,D) msg_from_ggsn(GTPH_PLANE_CTRL, A,B,C,D)
#define msg_from_ggsn_u(A,B,C,D) msg_from_ggsn(GTPH_PLANE_USER, A,B,C,D)
static int msg_from_ggsn(int plane_idx,
			 struct osmo_sockaddr *ggsn_sender,
			 struct osmo_sockaddr *sgsn_receiver,
			 const char *msg_from_ggsn,
			 const char *msg_to_sgsn)
{
	struct osmo_fd *sgsn_ofd;
	struct osmo_sockaddr sgsn_addr;
	int send;
	send = gtphub_handle_buf(hub, GTPH_SIDE_GGSN, plane_idx, ggsn_sender,
				 buf, msg(msg_from_ggsn), now,
				 &reply_buf, &sgsn_ofd, &sgsn_addr);
	if (*msg_to_sgsn) {
		LVL2_ASSERT(send > 0);
		LVL2_ASSERT(same_addr(&sgsn_addr, sgsn_receiver));
		LVL2_ASSERT(reply_is(msg_to_sgsn));
	}
	else
		LVL2_ASSERT(send == 0);
	return 1;
}

static int create_pdp_ctx()
{
	const char *gtp_req_from_sgsn =
		MSG_PDP_CTX_REQ("0068",
				"abcd",
				"60",
				"42000121436587f9",
				"00000123",
				"00000321",
				"0009""08696e7465726e6574", /* "(8)internet" */
				"0004""c0a82a17", /* same as default sgsn_sender */
				"0004""c0a82a17"
			       );
	const char *gtp_req_to_ggsn =
		MSG_PDP_CTX_REQ("0068",
				"6d31",	/* mapped seq ("abcd") */
				"23",
				"42000121436587f9",
				"00000001", /* Data I: tunnel's TEI */
				"00000001", /* Control: tunnel's TEI */
				"0009""08696e7465726e6574",
				"0004""7f000201", /* replaced with gtphub's ggsn ctrl */
				"0004""7f000202" /* replaced with gtphub's ggsn user */
			       );

	LVL2_ASSERT(msg_from_sgsn_c(&sgsn_sender,
				    &resolved_ggsn_addr,
				    gtp_req_from_sgsn,
				    gtp_req_to_ggsn));
	LVL2_ASSERT(was_resolved_for("240010123456789", "internet"));

	LVL2_ASSERT(tunnels_are(
		"TEI=1:"
		" 192.168.42.23 (TEI C=321 U=123)"
		" <-> 192.168.43.34/(uninitialized) (TEI C=0 U=0)"
		" @21945\n"));

	const char *gtp_resp_from_ggsn =
		MSG_PDP_CTX_RSP("004e",
				"00000001", /* destination TEI (sent in req above) */
				"6d31", /* mapped seq */
				"01", /* restart */
				"00000567", /* TEI U */
				"00000765", /* TEI C */
				"0004""c0a82b22", /* GSN addresses */
				"0004""c0a82b22"  /* (== resolved_ggsn_addr) */
			       );
	const char *gtp_resp_to_sgsn =
		MSG_PDP_CTX_RSP("004e",
				"00000321", /* unmapped TEI ("001") */
				"abcd", /* unmapped seq ("6d31") */
				"23",
				"00000001", /* mapped TEI from GGSN ("567") */
				"00000001", /* mapped TEI from GGSN ("765") */
				"0004""7f000101", /* gtphub's address towards SGSNs (Ctrl) */
				"0004""7f000102" /* gtphub's address towards SGSNs (User) */
			       );
	/* The response should go back to whichever port the request came from
	 * (unmapped by sequence nr) */
	LVL2_ASSERT(msg_from_ggsn_c(&resolved_ggsn_addr,
				    &sgsn_sender,
				    gtp_resp_from_ggsn,
				    gtp_resp_to_sgsn));

	return 1;
}

#define MSG_DEL_PDP_CTX_REQ(tei, seq) \
		"32" 	/* 0b001'1 0010: version 1, protocol GTP, with seq nr. */ \
		"14" 	/* type 20: Delete PDP Context Request */ \
		"0008"	/* msg length = 8 + len (2 octets) */ \
		tei	/* TEI Ctrl */ \
		seq	/* Sequence nr (2 octets) */ \
		"00"	/* N-PDU 0 */ \
		"00"	/* No extensions */ \
		/* IEs */ \
		"13fe"  /* 19: Teardown ind = 0 */ \
		"1400"	/* 20: NSAPI = 0*/ \

#define MSG_DEL_PDP_CTX_RSP(tei, seq) \
		"32" 	/* 0b001'1 0010: version 1, protocol GTP, with seq nr. */ \
		"15" 	/* type 21: Delete PDP Context Response */ \
		"0006"	/* msg length = 8 + len (2 octets) */ \
		tei	/* TEI Ctrl */ \
		seq	/* Sequence nr (2 octets) */ \
		"00"	/* N-PDU 0 */ \
		"00"	/* No extensions */ \
		/* IEs */ \
		"01"	/* 1: Cause */ \
		  "80"	/* value = 0b10000000 = response, no rejection. */ \

static int delete_pdp_ctx_from_sgsn(void)
{
	now += GTPH_EXPIRE_QUICKLY_SECS + 1;
	gtphub_gc(hub, now);

	LVL2_ASSERT(tunnels_are(
		"TEI=1:"
		" 192.168.42.23 (TEI C=321 U=123)"
		" <-> 192.168.43.34 (TEI C=765 U=567)"
		" @21945\n"));

	/* TEI Ctrl from above and next sequence after abcd. */
	const char *gtp_req_from_sgsn = MSG_DEL_PDP_CTX_REQ("00000001", "abce");
	const char *gtp_req_to_ggsn = MSG_DEL_PDP_CTX_REQ("00000765", "6d32");

	LVL2_ASSERT(msg_from_sgsn_c(&sgsn_sender,
				    &resolved_ggsn_addr,
				    gtp_req_from_sgsn,
				    gtp_req_to_ggsn));

	/* 21945 + 31 = 21976 */
	LVL2_ASSERT(tunnels_are(
		"TEI=1:"
		" 192.168.42.23 (TEI C=321 U=123)"
		" <-> 192.168.43.34 (TEI C=765 U=567)"
		" @21976\n"));

	const char *gtp_resp_from_ggsn =
		MSG_DEL_PDP_CTX_RSP("00000001", "6d32");
	const char *gtp_resp_to_sgsn =
		MSG_DEL_PDP_CTX_RSP("00000321", "abce");

	/* The response should go back to whichever port the request came from
	 * (unmapped by sequence nr) */
	LVL2_ASSERT(msg_from_ggsn_c(&resolved_ggsn_addr,
				    &sgsn_sender,
				    gtp_resp_from_ggsn,
				    gtp_resp_to_sgsn));

	LVL2_ASSERT(tunnels_are(""));

	return 1;
}

static int delete_pdp_ctx_from_ggsn(void)
{
	now += GTPH_EXPIRE_QUICKLY_SECS + 1;
	gtphub_gc(hub, now);

	LVL2_ASSERT(tunnels_are(
		"TEI=1:"
		" 192.168.42.23 (TEI C=321 U=123)"
		" <-> 192.168.43.34 (TEI C=765 U=567)"
		" @21945\n"));

	/* TEI Ctrl from above and next sequence after abcd. */
	const char *gtp_req_from_ggsn = MSG_DEL_PDP_CTX_REQ("00000001", "5432");
	const char *gtp_req_to_sgsn = MSG_DEL_PDP_CTX_REQ("00000321", "6d31");

	LVL2_ASSERT(msg_from_ggsn_c(&ggsn_sender,
				    &resolved_sgsn_addr,
				    gtp_req_from_ggsn,
				    gtp_req_to_sgsn));

	/* 21945 + 31 = 21976 */
	LVL2_ASSERT(tunnels_are(
		"TEI=1:"
		" 192.168.42.23 (TEI C=321 U=123)"
		" <-> 192.168.43.34 (TEI C=765 U=567)"
		" @21976\n"));

	const char *gtp_resp_from_sgsn =
		MSG_DEL_PDP_CTX_RSP("00000001", "6d31");
	const char *gtp_resp_to_ggsn =
		MSG_DEL_PDP_CTX_RSP("00000765", "5432");

	/* The response should go back to whichever port the request came from
	 * (unmapped by sequence nr) */
	LVL2_ASSERT(msg_from_sgsn_c(&resolved_sgsn_addr,
				    &ggsn_sender,
				    gtp_resp_from_sgsn,
				    gtp_resp_to_ggsn));

	LVL2_ASSERT(tunnels_are(""));

	return 1;
}

static void test_one_pdp_ctx(int del_from_side)
{
	if (del_from_side == GTPH_SIDE_SGSN)
		LOG("test_one_pdp_ctx (del from SGSN)")
	else	LOG("test_one_pdp_ctx (del from GGSN)");
	OSMO_ASSERT(setup_test_hub());

	OSMO_ASSERT(create_pdp_ctx());

	struct gtphub_peer_port *ggsn_port =
		gtphub_port_find_sa(&hub->to_gsns[GTPH_SIDE_GGSN][GTPH_PLANE_CTRL],
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
	OSMO_ASSERT(tunnels_are(
		"TEI=1:"
		" 192.168.42.23 (TEI C=321 U=123)"
		" <-> 192.168.43.34 (TEI C=765 U=567)"
		" @21945\n"));

	if (del_from_side == GTPH_SIDE_SGSN) {
		OSMO_ASSERT(delete_pdp_ctx_from_sgsn());
	} else {
		OSMO_ASSERT(delete_pdp_ctx_from_ggsn());
	}
	OSMO_ASSERT(tunnels_are(""));

	OSMO_ASSERT(clear_test_hub());
}

static void test_user_data(void)
{
	LOG("test_user_data");

	OSMO_ASSERT(setup_test_hub());

	OSMO_ASSERT(create_pdp_ctx());

	/* now == 345; now + (6 * 60 * 60) == 21600 + 345 == 21945. */
	OSMO_ASSERT(tunnels_are(
		"TEI=1:"
		" 192.168.42.23 (TEI C=321 U=123)"
		" <-> 192.168.43.34 (TEI C=765 U=567)"
		" @21945\n"));

	LOG("- user data starts");
	/* Now expect default port numbers for User plane. */
	resolve_to_ggsn("192.168.43.34", 2152);
	resolve_to_sgsn("192.168.42.23", 2152);

	/* 10 minutes later */
	now += 600;

	const char *u_from_ggsn =
		"32" 	/* 0b001'1 0010: version 1, protocol GTP, with seq nr */
		"ff"	/* type 255: G-PDU */
		"0058"	/* length: 88 + 8 octets == 96 */
		"00000001" /* mapped TEI for SGSN from create_pdp_ctx() */
		"0070"	/* seq */
		"0000"	/* No extensions */
		/* User data (ICMP packet), 96 - 12 = 84 octets  */
		"45000054daee40004001f7890a172a010a172a02080060d23f590071e3f8"
		"4156000000007241010000000000101112131415161718191a1b1c1d1e1f"
		"202122232425262728292a2b2c2d2e2f3031323334353637"
		;
	const char *u_to_sgsn =
		"32" 	/* 0b001'1 0010: version 1, protocol GTP, with seq nr */
		"ff"	/* type 255: G-PDU */
		"0058"	/* length: 88 + 8 octets == 96 */
		"00000123" /* unmapped User TEI */
		"6d31"	/* new mapped seq */
		"0000"
		"45000054daee40004001f7890a172a010a172a02080060d23f590071e3f8"
		"4156000000007241010000000000101112131415161718191a1b1c1d1e1f"
		"202122232425262728292a2b2c2d2e2f3031323334353637"
		;

	/* This depends on create_pdp_ctx() sending resolved_sgsn_addr as GSN
	 * Address IEs in the GGSN's Create PDP Ctx Response. */
	OSMO_ASSERT(msg_from_ggsn_u(&ggsn_sender,
				    &resolved_sgsn_addr,
				    u_from_ggsn,
				    u_to_sgsn));

	/* Make sure the user plane messages have refreshed the TEI mapping
	 * timeouts: 21945 + 600 == 22545. */
	OSMO_ASSERT(tunnels_are(
		"TEI=1:"
		" 192.168.42.23 (TEI C=321 U=123)"
		" <-> 192.168.43.34 (TEI C=765 U=567)"
		" @22545\n"));

	const char *u_from_sgsn =
		"32" 	/* 0b001'1 0010: version 1, protocol GTP, with seq nr */
		"ff"	/* type 255: G-PDU */
		"0058"	/* length: 88 + 8 octets == 96 */
		"00000001" /* mapped User TEI for GGSN from create_pdp_ctx() */
		"1234"	/* unknown seq */
		"0000"	/* No extensions */
		/* User data (ICMP packet), 96 - 12 = 84 octets  */
		"45000054daee40004001f7890a172a010a172a02080060d23f590071e3f8"
		"4156000000007241010000000000101112131415161718191a1b1c1d1e1f"
		"202122232425262728292a2b2c2d2e2f3031323334353637"
		;
	const char *u_to_ggsn =
		"32" 	/* 0b001'1 0010: version 1, protocol GTP, with seq nr */
		"ff"	/* type 255: G-PDU */
		"0058"	/* length: 88 + 8 octets == 96 */
		"00000567" /* unmapped User TEI */
		"6d31"	/* unmapped seq */
		"0000"
		"45000054daee40004001f7890a172a010a172a02080060d23f590071e3f8"
		"4156000000007241010000000000101112131415161718191a1b1c1d1e1f"
		"202122232425262728292a2b2c2d2e2f3031323334353637"
		;

	OSMO_ASSERT(msg_from_sgsn_u(&sgsn_sender,
				    &resolved_ggsn_addr,
				    u_from_sgsn,
				    u_to_ggsn));

	/* Make sure the user plane messages have refreshed the TEI mapping
	 * timeouts: 21945 + 600 == 22545. Both timeouts refreshed: */
	OSMO_ASSERT(tunnels_are(
		"TEI=1:"
		" 192.168.42.23 (TEI C=321 U=123)"
		" <-> 192.168.43.34 (TEI C=765 U=567)"
		" @22545\n"));

	OSMO_ASSERT(clear_test_hub());
}

static void test_reused_tei(void)
{
	LOG("test_reused_tei");

	OSMO_ASSERT(setup_test_hub());

	OSMO_ASSERT(create_pdp_ctx());

	const char *gtp_req_from_sgsn =
		MSG_PDP_CTX_REQ("0068",
				"abce", /* Next seq */
				"60",
				"42000121436587f9",
				"00000123", /* Same TEIs as before */
				"00000321",
				"0009""08696e7465726e6574", /* "(8)internet" */
				"0004""c0a82a17", /* same as default sgsn_sender */
				"0004""c0a82a17"
			       );
	const char *gtp_req_to_ggsn =
		MSG_PDP_CTX_REQ("0068",
				"6d32",	/* mapped seq ("abce") */
				"23",
				"42000121436587f9",
				"00000002", /* mapped TEI Data I ("123") */
				"00000002", /* mapped TEI Control ("321") */
				"0009""08696e7465726e6574",
				"0004""7f000201", /* replaced with gtphub's ggsn ctrl */
				"0004""7f000202" /* replaced with gtphub's ggsn user */
			       );

	OSMO_ASSERT(msg_from_sgsn_c(&sgsn_sender,
				    &resolved_ggsn_addr,
				    gtp_req_from_sgsn,
				    gtp_req_to_ggsn));
	OSMO_ASSERT(was_resolved_for("240010123456789", "internet"));

	OSMO_ASSERT(tunnels_are(
		"TEI=2:"
		" 192.168.42.23 (TEI C=321 U=123)"
		" <-> 192.168.43.34/(uninitialized) (TEI C=0 U=0)"
		" @21945\n"));

	const char *gtp_resp_from_ggsn =
		MSG_PDP_CTX_RSP("004e",
				"00000002", /* destination TEI (sent in req above) */
				"6d32", /* mapped seq */
				"01", /* restart */
				"00000567", /* TEI U */
				"00000765", /* TEI C */
				"0004""c0a82b22", /* GSN addresses */
				"0004""c0a82b22"  /* (== resolved_ggsn_addr) */
			       );
	const char *gtp_resp_to_sgsn =
		MSG_PDP_CTX_RSP("004e",
				"00000321", /* unmapped TEI ("001") */
				"abce", /* unmapped seq ("6d32") */
				"23",
				"00000002", /* mapped TEI from GGSN ("567") */
				"00000002", /* mapped TEI from GGSN ("765") */
				"0004""7f000101", /* gtphub's address towards SGSNs (Ctrl) */
				"0004""7f000102" /* gtphub's address towards SGSNs (User) */
			       );
	/* The response should go back to whichever port the request came from
	 * (unmapped by sequence nr) */
	OSMO_ASSERT(msg_from_ggsn_c(&resolved_ggsn_addr,
				    &sgsn_sender,
				    gtp_resp_from_ggsn,
				    gtp_resp_to_sgsn));

	OSMO_ASSERT(clear_test_hub());
}

static void test_peer_restarted(void)
{
	LOG("test_peer_restarted");

	OSMO_ASSERT(setup_test_hub());

	OSMO_ASSERT(create_pdp_ctx());

	now += 10;

	const char *gtp_req_from_sgsn =
		MSG_PDP_CTX_REQ("0068",
				"1234", /* brand new seq */
				"61",	/* DIFFERING restart counter */
				"42000121436587f9",
				"00000abc",
				"00000cba",
				"0009""08696e7465726e6574", /* "(8)internet" */
				"0004""c0a82a17", /* same as default sgsn_sender */
				"0004""c0a82a17"
			       );
	const char *gtp_req_to_ggsn =
		MSG_PDP_CTX_REQ("0068",
				"6d33",	/* mapped seq ("1234") */
				"23",
				"42000121436587f9",
				"00000002", /* mapped TEI Data I ("123") */
				"00000002", /* mapped TEI Control ("321") */
				"0009""08696e7465726e6574",
				"0004""7f000201", /* replaced with gtphub's ggsn ctrl */
				"0004""7f000202" /* replaced with gtphub's ggsn user */
			       );

	OSMO_ASSERT(msg_from_sgsn_c(&sgsn_sender,
				    &resolved_ggsn_addr,
				    gtp_req_from_sgsn,
				    gtp_req_to_ggsn));
	OSMO_ASSERT(was_resolved_for("240010123456789", "internet"));

	OSMO_ASSERT(tunnels_are(
		"TEI=2:"
		" 192.168.42.23 (TEI C=cba U=abc)"
		" <-> 192.168.43.34/(uninitialized) (TEI C=0 U=0)"
		" @21955\n"
		"TEI=1:"
		" (uninitialized) (TEI C=321 U=123)"
		" <-> 192.168.43.34 (TEI C=765 U=567)"
		" @21945\n"
		));

	const char *gtp_resp_from_ggsn =
		MSG_PDP_CTX_RSP("004e",
				"00000002", /* destination TEI (sent in req above) */
				"6d33", /* mapped seq */
				"01", /* restart */
				"00000def", /* TEI U */
				"00000fde", /* TEI C */
				"0004""c0a82b22", /* GSN addresses */
				"0004""c0a82b22"  /* (== resolved_ggsn_addr) */
			       );
	const char *gtp_resp_to_sgsn =
		MSG_PDP_CTX_RSP("004e",
				"00000cba", /* unmapped TEI ("005") */
				"1234", /* unmapped seq ("6d32") */
				"23",
				"00000002", /* mapped TEI from GGSN ("567") */
				"00000002", /* mapped TEI from GGSN ("765") */
				"0004""7f000101", /* gtphub's address towards SGSNs (Ctrl) */
				"0004""7f000102" /* gtphub's address towards SGSNs (User) */
			       );
	/* The response should go back to whichever port the request came from
	 * (unmapped by sequence nr) */
	OSMO_ASSERT(msg_from_ggsn_c(&resolved_ggsn_addr,
				    &sgsn_sender,
				    gtp_resp_from_ggsn,
				    gtp_resp_to_sgsn));

	OSMO_ASSERT(clear_test_hub());
}

static void test_peer_restarted_reusing_tei(void)
{
	LOG("test_peer_restarted_reusing_tei");

	OSMO_ASSERT(setup_test_hub());

	OSMO_ASSERT(create_pdp_ctx());

	now += 10;

	const char *gtp_req_from_sgsn =
		MSG_PDP_CTX_REQ("0068",
				"1234", /* brand new seq */
				"61",	/* DIFFERING restart counter */
				"42000121436587f9",
				"00000123", /* SAME TEI */
				"00000321",
				"0009""08696e7465726e6574", /* "(8)internet" */
				"0004""c0a82a17", /* same as default sgsn_sender */
				"0004""c0a82a17"
			       );
	const char *gtp_req_to_ggsn =
		MSG_PDP_CTX_REQ("0068",
				"6d33",	/* seq 6d31 + 2, after "out-of-band" Delete PDP Ctx
					   due to differing restart counter. */
				"23",
				"42000121436587f9",
				"00000002", /* mapped TEI Data I ("123") */
				"00000002", /* mapped TEI Control ("321") */
				"0009""08696e7465726e6574",
				"0004""7f000201", /* replaced with gtphub's ggsn ctrl */
				"0004""7f000202" /* replaced with gtphub's ggsn user */
			       );

	OSMO_ASSERT(msg_from_sgsn_c(&sgsn_sender,
				    &resolved_ggsn_addr,
				    gtp_req_from_sgsn,
				    gtp_req_to_ggsn));
	OSMO_ASSERT(was_resolved_for("240010123456789", "internet"));

	OSMO_ASSERT(tunnels_are(
		"TEI=2:" /* being established after restart */
		" 192.168.42.23 (TEI C=321 U=123)"
		" <-> 192.168.43.34/(uninitialized) (TEI C=0 U=0)"
		" @21955\n"
		"TEI=1:" /* invalidated due to restart */
		" (uninitialized) (TEI C=321 U=123)"
		" <-> 192.168.43.34 (TEI C=765 U=567)"
		" @21945\n"
		));

	/* An "out-of-band" delete request should have been sent to the GGSN
	 * (checked by expected log output in gtphub_test.ok), and the GGSN
	 * will (usually) send a Delete Response like this: */
	const char *gtp_del_resp_from_ggsn =
		MSG_DEL_PDP_CTX_RSP("00000001", "6d32");

	/* For this response (due to peer restart) we expect no forwarded
	 * message. */
	OSMO_ASSERT(msg_from_ggsn_c(&resolved_ggsn_addr,
				    &sgsn_sender,
				    gtp_del_resp_from_ggsn,
				    ""));

	OSMO_ASSERT(tunnels_are(
		"TEI=2:" /* still being established after restart */
		" 192.168.42.23 (TEI C=321 U=123)"
		" <-> 192.168.43.34/(uninitialized) (TEI C=0 U=0)"
		" @21955\n"
		));

	const char *gtp_resp_from_ggsn =
		MSG_PDP_CTX_RSP("004e",
				"00000002", /* destination TEI (sent in req above) */
				"6d33", /* mapped seq */
				"01", /* restart */
				"00000def", /* TEI U */
				"00000fde", /* TEI C */
				"0004""c0a82b22", /* GSN addresses */
				"0004""c0a82b22"  /* (== resolved_ggsn_addr) */
			       );
	const char *gtp_resp_to_sgsn =
		MSG_PDP_CTX_RSP("004e",
				"00000321", /* unmapped TEI ("005") */
				"1234", /* unmapped seq ("6d33") */
				"23",
				"00000002", /* mapped TEI from GGSN ("567") */
				"00000002", /* mapped TEI from GGSN ("765") */
				"0004""7f000101", /* gtphub's address towards SGSNs (Ctrl) */
				"0004""7f000102" /* gtphub's address towards SGSNs (User) */
			       );
	/* The response should go back to whichever port the request came from
	 * (unmapped by sequence nr) */
	OSMO_ASSERT(msg_from_ggsn_c(&resolved_ggsn_addr,
				    &sgsn_sender,
				    gtp_resp_from_ggsn,
				    gtp_resp_to_sgsn));

	OSMO_ASSERT(tunnels_are(
		"TEI=2:" /* still being established after restart */
		" 192.168.42.23 (TEI C=321 U=123)"
		" <-> 192.168.43.34 (TEI C=fde U=def)"
		" @21955\n"
		));

	OSMO_ASSERT(clear_test_hub());
}

static void test_sgsn_behind_nat(void)
{
	LOG("test_user_data");

	OSMO_ASSERT(setup_test_hub());
	hub->sgsn_use_sender = 1; /* <-- Main difference to test_user_data() */
	resolve_to_sgsn("192.168.42.23", 423); /* Same as sender */

	OSMO_ASSERT(create_pdp_ctx());

	/* now == 345; now + (6 * 60 * 60) == 21600 + 345 == 21945. */
	OSMO_ASSERT(tunnels_are(
		"TEI=1:"
		" 192.168.42.23 (TEI C=321 U=123)"
		" <-> 192.168.43.34 (TEI C=765 U=567)"
		" @21945\n"));

	LOG("- user data starts");
	/* Now expect default port numbers for User plane -- except SGSN. */
	resolve_to_ggsn("192.168.43.34", 2152);

	/* 10 minutes later */
	now += 600;

	const char *u_from_ggsn =
		"32" 	/* 0b001'1 0010: version 1, protocol GTP, with seq nr */
		"ff"	/* type 255: G-PDU */
		"0058"	/* length: 88 + 8 octets == 96 */
		"00000001" /* mapped User TEI for SGSN from create_pdp_ctx() */
		"0070"	/* seq */
		"0000"	/* No extensions */
		/* User data (ICMP packet), 96 - 12 = 84 octets  */
		"45000054daee40004001f7890a172a010a172a02080060d23f590071e3f8"
		"4156000000007241010000000000101112131415161718191a1b1c1d1e1f"
		"202122232425262728292a2b2c2d2e2f3031323334353637"
		;
	const char *u_to_sgsn =
		"32" 	/* 0b001'1 0010: version 1, protocol GTP, with seq nr */
		"ff"	/* type 255: G-PDU */
		"0058"	/* length: 88 + 8 octets == 96 */
		"00000123" /* unmapped User TEI */
		"6d31"	/* new mapped seq */
		"0000"
		"45000054daee40004001f7890a172a010a172a02080060d23f590071e3f8"
		"4156000000007241010000000000101112131415161718191a1b1c1d1e1f"
		"202122232425262728292a2b2c2d2e2f3031323334353637"
		;

	/* This depends on create_pdp_ctx() sending resolved_sgsn_addr as GSN
	 * Address IEs in the GGSN's Create PDP Ctx Response. */
	OSMO_ASSERT(msg_from_ggsn_u(&ggsn_sender,
				    &resolved_sgsn_addr,
				    u_from_ggsn,
				    u_to_sgsn));

	/* Make sure the user plane messages have refreshed the TEI mapping
	 * timeouts: 21945 + 600 == 22545. */
	OSMO_ASSERT(tunnels_are(
		"TEI=1:"
		" 192.168.42.23 (TEI C=321 U=123)"
		" <-> 192.168.43.34 (TEI C=765 U=567)"
		" @22545\n"));

	const char *u_from_sgsn =
		"32" 	/* 0b001'1 0010: version 1, protocol GTP, with seq nr */
		"ff"	/* type 255: G-PDU */
		"0058"	/* length: 88 + 8 octets == 96 */
		"00000001" /* mapped User TEI for GGSN from create_pdp_ctx() */
		"1234"	/* unknown seq */
		"0000"	/* No extensions */
		/* User data (ICMP packet), 96 - 12 = 84 octets  */
		"45000054daee40004001f7890a172a010a172a02080060d23f590071e3f8"
		"4156000000007241010000000000101112131415161718191a1b1c1d1e1f"
		"202122232425262728292a2b2c2d2e2f3031323334353637"
		;
	const char *u_to_ggsn =
		"32" 	/* 0b001'1 0010: version 1, protocol GTP, with seq nr */
		"ff"	/* type 255: G-PDU */
		"0058"	/* length: 88 + 8 octets == 96 */
		"00000567" /* unmapped User TEI */
		"6d31"	/* unmapped seq */
		"0000"
		"45000054daee40004001f7890a172a010a172a02080060d23f590071e3f8"
		"4156000000007241010000000000101112131415161718191a1b1c1d1e1f"
		"202122232425262728292a2b2c2d2e2f3031323334353637"
		;

	OSMO_ASSERT(msg_from_sgsn_u(&sgsn_sender,
				    &resolved_ggsn_addr,
				    u_from_sgsn,
				    u_to_ggsn));

	/* Make sure the user plane messages have refreshed the TEI mapping
	 * timeouts: 21945 + 600 == 22545. Both timeouts refreshed: */
	OSMO_ASSERT(tunnels_are(
		"TEI=1:"
		" 192.168.42.23 (TEI C=321 U=123)"
		" <-> 192.168.43.34 (TEI C=765 U=567)"
		" @22545\n"));

	OSMO_ASSERT(clear_test_hub());
}

void test_parallel_context_creation(void)
{
	LOG("test_parallel_context_creation");

	OSMO_ASSERT(setup_test_hub());

	const char *gtp_req_from_sgsn1 =
		MSG_PDP_CTX_REQ("0068",
				"abcd",
				"60",
				"42000121436587f9",
				"00000123",
				"00000321",
				"0009""08696e7465726e6574", /* "(8)internet" */
				"0004""c0a82a17", /* same as default sgsn_sender */
				"0004""c0a82a17"
			       );
	const char *gtp_req_to_ggsn1 =
		MSG_PDP_CTX_REQ("0068",
				"6d31",	/* mapped seq ("abcd") */
				"23",
				"42000121436587f9",
				"00000001", /* mapped TEI Data I ("123") */
				"00000001", /* mapped TEI Control ("321") */
				"0009""08696e7465726e6574",
				"0004""7f000201", /* replaced with gtphub's ggsn ctrl */
				"0004""7f000202" /* replaced with gtphub's ggsn user */
			       );

	OSMO_ASSERT(msg_from_sgsn_c(&sgsn_sender,
				    &resolved_ggsn_addr,
				    gtp_req_from_sgsn1,
				    gtp_req_to_ggsn1));

	OSMO_ASSERT(tunnels_are(
		"TEI=1:"
		" 192.168.42.23 (TEI C=321 U=123)"
		" <-> 192.168.43.34/(uninitialized) (TEI C=0 U=0)"
		" @21945\n"));

	now ++;

	const char *gtp_req_from_sgsn2 =
		MSG_PDP_CTX_REQ("0068",
				"abce",
				"60",
				"42000121436588f9",
				"00000124",
				"00000322",
				"0009""08696e7465726e6574", /* "(8)internet" */
				"0004""c0a82a17", /* same as default sgsn_sender */
				"0004""c0a82a17"
			       );
	const char *gtp_req_to_ggsn2 =
		MSG_PDP_CTX_REQ("0068",
				"6d32",	/* mapped seq ("abce") */
				"23",
				"42000121436588f9",
				"00000002", /* mapped TEI Data I ("124") */
				"00000002", /* mapped TEI Control ("322") */
				"0009""08696e7465726e6574",
				"0004""7f000201", /* replaced with gtphub's ggsn ctrl */
				"0004""7f000202" /* replaced with gtphub's ggsn user */
			       );

	OSMO_ASSERT(msg_from_sgsn_c(&sgsn_sender,
				    &resolved_ggsn_addr,
				    gtp_req_from_sgsn2,
				    gtp_req_to_ggsn2));

	OSMO_ASSERT(tunnels_are(
		"TEI=2:"
		" 192.168.42.23 (TEI C=322 U=124)"
		" <-> 192.168.43.34/(uninitialized) (TEI C=0 U=0)"
		" @21946\n"
		"TEI=1:"
		" 192.168.42.23 (TEI C=321 U=123)"
		" <-> 192.168.43.34/(uninitialized) (TEI C=0 U=0)"
		" @21945\n"
		));

	now ++;

	const char *gtp_resp_from_ggsn1 =
		MSG_PDP_CTX_RSP("004e",
				"00000001", /* destination TEI (sent in req above) */
				"6d31", /* mapped seq */
				"01", /* restart */
				"00000567", /* TEI U */
				"00000765", /* TEI C */
				"0004""c0a82b22", /* GSN addresses */
				"0004""c0a82b22"  /* (== resolved_ggsn_addr) */
			       );
	const char *gtp_resp_to_sgsn1 =
		MSG_PDP_CTX_RSP("004e",
				"00000321", /* unmapped TEI ("001") */
				"abcd", /* unmapped seq ("6d31") */
				"23",
				"00000001", /* mapped TEI from GGSN ("567") */
				"00000001", /* mapped TEI from GGSN ("765") */
				"0004""7f000101", /* gtphub's address towards SGSNs (Ctrl) */
				"0004""7f000102" /* gtphub's address towards SGSNs (User) */
			       );

	OSMO_ASSERT(msg_from_ggsn_c(&resolved_ggsn_addr,
				    &sgsn_sender,
				    gtp_resp_from_ggsn1,
				    gtp_resp_to_sgsn1));

	OSMO_ASSERT(tunnels_are(
		"TEI=2:"
		" 192.168.42.23 (TEI C=322 U=124)"
		" <-> 192.168.43.34/(uninitialized) (TEI C=0 U=0)"
		" @21946\n"
		"TEI=1:"
		" 192.168.42.23 (TEI C=321 U=123)"
		" <-> 192.168.43.34 (TEI C=765 U=567)"
		" @21947\n"
		));

	now ++;

	const char *gtp_resp_from_ggsn2 =
		MSG_PDP_CTX_RSP("004e",
				"00000002", /* destination TEI (sent in req above) */
				"6d32", /* mapped seq */
				"01", /* restart */
				"00000568", /* TEI U */
				"00000766", /* TEI C */
				"0004""c0a82b22", /* GSN addresses */
				"0004""c0a82b22"  /* (== resolved_ggsn_addr) */
			       );
	const char *gtp_resp_to_sgsn2 =
		MSG_PDP_CTX_RSP("004e",
				"00000322", /* unmapped TEI ("001") */
				"abce", /* unmapped seq ("6d31") */
				"23",
				"00000002", /* mapped TEI from GGSN ("567") */
				"00000002", /* mapped TEI from GGSN ("765") */
				"0004""7f000101", /* gtphub's address towards SGSNs (Ctrl) */
				"0004""7f000102" /* gtphub's address towards SGSNs (User) */
			       );

	OSMO_ASSERT(msg_from_ggsn_c(&resolved_ggsn_addr,
				    &sgsn_sender,
				    gtp_resp_from_ggsn2,
				    gtp_resp_to_sgsn2));

	OSMO_ASSERT(tunnels_are(
		"TEI=2:"
		" 192.168.42.23 (TEI C=322 U=124)"
		" <-> 192.168.43.34 (TEI C=766 U=568)"
		" @21948\n"
		"TEI=1:"
		" 192.168.42.23 (TEI C=321 U=123)"
		" <-> 192.168.43.34 (TEI C=765 U=567)"
		" @21947\n"
		));

	OSMO_ASSERT(clear_test_hub());
}


static struct log_info_cat gtphub_categories[] = {
	[DGTPHUB] = {
		.name = "DGTPHUB",
		.description = "GTP Hub",
		.color = "\033[1;33m",
		.enabled = 1, .loglevel = LOGL_DEBUG,
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
	test_nr_map_wrap();
	test_expiry();
	test_echo();
	test_one_pdp_ctx(GTPH_SIDE_SGSN);
	test_one_pdp_ctx(GTPH_SIDE_GGSN);
	test_user_data();
	test_reused_tei();
	test_peer_restarted();
	test_peer_restarted_reusing_tei();
	test_sgsn_behind_nat();
	test_parallel_context_creation();
	printf("Done\n");

	talloc_report_full(osmo_gtphub_ctx, stderr);
	OSMO_ASSERT(talloc_total_blocks(osmo_gtphub_ctx) == 1);
	return 0;
}

