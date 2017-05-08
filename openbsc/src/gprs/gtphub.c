/* GTP Hub Implementation */

/* (C) 2015 by sysmocom s.f.m.c. GmbH <info@sysmocom.de>
 * All Rights Reserved
 *
 * Author: Neels Hofmeyr
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

#include <string.h>
#include <errno.h>
#include <inttypes.h>
#include <time.h>
#include <limits.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <gtp.h>
#include <gtpie.h>

#include <openbsc/gtphub.h>
#include <openbsc/debug.h>
#include <openbsc/gprs_utils.h>

#include <osmocom/core/utils.h>
#include <osmocom/core/logging.h>
#include <osmocom/core/socket.h>
#include <osmocom/core/rate_ctr.h>
#include <osmocom/core/stats.h>


static const int GTPH_GC_TICK_SECONDS = 1;

void *osmo_gtphub_ctx;

/* Convenience makro, note: only within this C file. */
#define LOG(level, fmt, args...) \
	LOGP(DGTPHUB, level, fmt, ##args)

#define ZERO_STRUCT(struct_pointer) memset(struct_pointer, '\0', \
					   sizeof(*(struct_pointer)))

/* TODO move this to osmocom/core/select.h ? */
typedef int (*osmo_fd_cb_t)(struct osmo_fd *fd, unsigned int what);

/* TODO move this to osmocom/core/linuxlist.h ? */
#define __llist_first(head) (((head)->next == (head)) ? NULL : (head)->next)
#define llist_first(head, type, entry) \
	llist_entry(__llist_first(head), type, entry)

#define __llist_last(head) (((head)->next == (head)) ? NULL : (head)->prev)
#define llist_last(head, type, entry) \
	llist_entry(__llist_last(head), type, entry)

/* TODO move GTP header stuff to openggsn/gtp/ ? See gtp_decaps*() */

enum gtp_rc {
	GTP_RC_UNKNOWN = 0,
	GTP_RC_TINY = 1,    /* no IEs (like ping/pong) */
	GTP_RC_PDU_C = 2,     /* a real packet with IEs */
	GTP_RC_PDU_U = 3,     /* a real packet with User data */

	GTP_RC_TOOSHORT = -1,
	GTP_RC_UNSUPPORTED_VERSION = -2,
	GTP_RC_INVALID_IE = -3,
};

struct gtp_packet_desc {
	union gtp_packet *data;
	int data_len;
	int header_len;
	int version;
	uint8_t type;
	uint16_t seq;
	uint32_t header_tei_rx;
	uint32_t header_tei;
	int rc; /* enum gtp_rc */
	unsigned int plane_idx;
	unsigned int side_idx;
	struct gtphub_tunnel *tun;
	time_t timestamp;
	union gtpie_member *ie[GTPIE_SIZE];
};

struct pending_delete {
	struct llist_head entry;
	struct expiring_item expiry_entry;

	struct gtphub_tunnel *tun;
	uint8_t teardown_ind;
	uint8_t nsapi;
};


/* counters */

enum gtphub_counters_io {
	GTPH_CTR_PKTS_IN = 0,
	GTPH_CTR_PKTS_OUT,
	GTPH_CTR_BYTES_IN,
	GTPH_CTR_BYTES_OUT
};

static const struct rate_ctr_desc gtphub_counters_io_desc[] = {
	{ "packets.in",  "Packets ( In)" },
	{ "packets.out", "Packets (Out)" },
	{ "bytes.in",    "Bytes   ( In)" },
	{ "bytes.out",   "Bytes   (Out)" },
};

static const struct rate_ctr_group_desc gtphub_ctrg_io_desc = {
	.group_name_prefix = "gtphub.bind",
	.group_description = "I/O Statistics",
	.num_ctr = ARRAY_SIZE(gtphub_counters_io_desc),
	.ctr_desc = gtphub_counters_io_desc,
	.class_id = OSMO_STATS_CLASS_GLOBAL,
};


/* support */

static const char *gtp_type_str(uint8_t type)
{
	switch (type) {
	case 1:
		return " (Echo Request)";
	case 2:
		return " (Echo Response)";
	case 16:
		return " (Create PDP Ctx Request)";
	case 17:
		return " (Create PDP Ctx Response)";
	case 18:
		return " (Update PDP Ctx Request)";
	case 19:
		return " (Update PDP Ctx Response)";
	case 20:
		return " (Delete PDP Ctx Request)";
	case 21:
		return " (Delete PDP Ctx Response)";
	case 255:
		return " (User Data)";
	default:
		return "";
	}
}

void gsn_addr_copy(struct gsn_addr *gsna, const struct gsn_addr *src)
{
	*gsna = *src;
}

int gsn_addr_from_sockaddr(struct gsn_addr *gsna, uint16_t *port,
			   const struct osmo_sockaddr *sa)
{
	char addr_str[256];
	char port_str[6];

	if (osmo_sockaddr_to_strs(addr_str, sizeof(addr_str),
				  port_str, sizeof(port_str),
				  sa, (NI_NUMERICHOST | NI_NUMERICSERV))
	    != 0) {
		return -1;
	}

	if (port)
		*port = atoi(port_str);

	return gsn_addr_from_str(gsna, addr_str);
}

int gsn_addr_from_str(struct gsn_addr *gsna, const char *numeric_addr_str)
{
	if ((!gsna) || (!numeric_addr_str))
		return -1;

	int af = AF_INET;
	gsna->len = 4;
	const char *pos = numeric_addr_str;
	for (; *pos; pos++) {
		if (*pos == ':') {
			af = AF_INET6;
			gsna->len = 16;
			break;
		}
	}

	int rc = inet_pton(af, numeric_addr_str, gsna->buf);
	if (rc != 1) {
		LOG(LOGL_ERROR, "Cannot resolve numeric address: '%s'\n",
		    numeric_addr_str);
		return -1;
	}
	return 0;
}

const char *gsn_addr_to_str(const struct gsn_addr *gsna)
{
	static char buf[INET6_ADDRSTRLEN + 1];
	return gsn_addr_to_strb(gsna, buf, sizeof(buf));
}

const char *gsn_addr_to_strb(const struct gsn_addr *gsna,
			     char *strbuf,
			     int strbuf_len)
{
	int af;
	switch (gsna->len) {
	case 4:
		af = AF_INET;
		break;
	case 16:
		af = AF_INET6;
		break;
	default:
		return NULL;
	}

	const char *r = inet_ntop(af, gsna->buf, strbuf, strbuf_len);
	if (!r) {
		LOG(LOGL_ERROR, "Cannot convert gsn_addr to string:"
		    " %s: len=%d, buf=%s\n",
		    strerror(errno),
		    (int)gsna->len,
		    osmo_hexdump(gsna->buf, sizeof(gsna->buf)));
	}
	return r;
}

int gsn_addr_same(const struct gsn_addr *a, const struct gsn_addr *b)
{
	if (a == b)
		return 1;
	if ((!a) || (!b))
		return 0;
	if (a->len != b->len)
		return 0;
	return (memcmp(a->buf, b->buf, a->len) == 0)? 1 : 0;
}

static int gsn_addr_get(struct gsn_addr *gsna, const struct gtp_packet_desc *p,
			int idx)
{
	if (p->rc != GTP_RC_PDU_C)
		return -1;

	unsigned int len;
	/* gtpie.h fails to declare gtpie_gettlv()'s first arg as const. */
	if (gtpie_gettlv((union gtpie_member**)p->ie, GTPIE_GSN_ADDR, idx,
			 &len, gsna->buf, sizeof(gsna->buf))
	    != 0)
		return -1;
	gsna->len = len;
	return 0;
}

static int gsn_addr_put(const struct gsn_addr *gsna, struct gtp_packet_desc *p,
			int idx)
{
	if (p->rc != GTP_RC_PDU_C)
		return -1;

	int ie_idx;
	ie_idx = gtpie_getie(p->ie, GTPIE_GSN_ADDR, idx);

	if (ie_idx < 0)
		return -1;

	struct gtpie_tlv *ie = &p->ie[ie_idx]->tlv;
	int ie_l = ntoh16(ie->l);
	if (ie_l != gsna->len) {
		LOG(LOGL_ERROR, "Not implemented:"
		    " replace an IE address of different size:"
		    " replace %d with %d\n", (int)ie_l, (int)gsna->len);
		return -1;
	}

	memcpy(ie->v, gsna->buf, (int)ie_l);
	return 0;
}

/* Validate GTP version 0 data; analogous to validate_gtp1_header(), see there.
 */
void validate_gtp0_header(struct gtp_packet_desc *p)
{
	const struct gtp0_header *pheader = &(p->data->gtp0.h);
	p->rc = GTP_RC_UNKNOWN;
	p->header_len = 0;

	OSMO_ASSERT(p->data_len >= 1);
	OSMO_ASSERT(p->version == 0);

	if (p->data_len < GTP0_HEADER_SIZE) {
		LOG(LOGL_ERROR, "GTP0 packet too short: %d\n", p->data_len);
		p->rc = GTP_RC_TOOSHORT;
		return;
	}

	p->type = ntoh8(pheader->type);
	p->seq = ntoh16(pheader->seq);
	p->header_tei_rx = 0; /* TODO */
	p->header_tei = p->header_tei_rx;

	if (p->data_len == GTP0_HEADER_SIZE) {
		p->rc = GTP_RC_TINY;
		p->header_len = GTP0_HEADER_SIZE;
		return;
	}

	/* Check packet length field versus length of packet */
	if (p->data_len != (ntoh16(pheader->length) + GTP0_HEADER_SIZE)) {
		LOG(LOGL_ERROR, "GTP packet length field (%d + %d) does not"
		    " match actual length (%d)\n",
		    GTP0_HEADER_SIZE, (int)ntoh16(pheader->length),
		    p->data_len);
		p->rc = GTP_RC_TOOSHORT;
		return;
	}

	LOG(LOGL_DEBUG, "GTP v0 TID = %" PRIu64 "\n", pheader->tid);
	p->header_len = GTP0_HEADER_SIZE;
	p->rc = GTP_RC_PDU_C;
}

/* Validate GTP version 1 data, and update p->rc with the result, as well as
 * p->header_len in case of a valid header. */
void validate_gtp1_header(struct gtp_packet_desc *p)
{
	const struct gtp1_header_long *pheader = &(p->data->gtp1l.h);
	p->rc = GTP_RC_UNKNOWN;
	p->header_len = 0;

	OSMO_ASSERT(p->data_len >= 1);
	OSMO_ASSERT(p->version == 1);

	if ((p->data_len < GTP1_HEADER_SIZE_LONG)
	    && (p->data_len != GTP1_HEADER_SIZE_SHORT)){
		LOG(LOGL_ERROR, "GTP packet too short: %d\n", p->data_len);
		p->rc = GTP_RC_TOOSHORT;
		return;
	}

	p->type = ntoh8(pheader->type);
	p->header_tei_rx = ntoh32(pheader->tei);
	p->header_tei = p->header_tei_rx;
	p->seq = ntoh16(pheader->seq);

	LOG(LOGL_DEBUG, "| GTPv1\n");
	LOG(LOGL_DEBUG, "| type = %" PRIu8 " 0x%02" PRIx8 "\n", p->type, p->type);
	LOG(LOGL_DEBUG, "| length = %" PRIu16 " 0x%04" PRIx16 "\n", ntoh16(pheader->length), ntoh16(pheader->length));
	LOG(LOGL_DEBUG, "| TEI = %" PRIu32 " 0x%08" PRIx32 "\n", p->header_tei_rx, p->header_tei_rx);
	LOG(LOGL_DEBUG, "| seq = %" PRIu16 " 0x%04" PRIx16 "\n", p->seq, p->seq);
	LOG(LOGL_DEBUG, "| npdu = %" PRIu8 " 0x%02" PRIx8 "\n", pheader->npdu, pheader->npdu);
	LOG(LOGL_DEBUG, "| next = %" PRIu8 " 0x%02" PRIx8 "\n", pheader->next, pheader->next);

	if (p->data_len <= GTP1_HEADER_SIZE_LONG) {
		p->rc = GTP_RC_TINY;
		p->header_len = GTP1_HEADER_SIZE_SHORT;
		return;
	}

	/* Check packet length field versus length of packet */
	int announced_len = ntoh16(pheader->length) + GTP1_HEADER_SIZE_SHORT;
	if (p->data_len != announced_len) {
		LOG(LOGL_ERROR, "GTP packet length field (%d + %d) does not"
		    " match actual length (%d)\n",
		    GTP1_HEADER_SIZE_SHORT, (int)ntoh16(pheader->length),
		    p->data_len);
		p->rc = GTP_RC_TOOSHORT;
		return;
	}

	p->rc = GTP_RC_PDU_C;
	p->header_len = GTP1_HEADER_SIZE_LONG;
}

/* Examine whether p->data of size p->data_len has a valid GTP header. Set
 * p->version, p->rc and p->header_len. On error, p->rc <= 0 (see enum
 * gtp_rc). p->data must point at a buffer with p->data_len set. */
void validate_gtp_header(struct gtp_packet_desc *p)
{
	p->rc = GTP_RC_UNKNOWN;

	/* Need at least 1 byte in order to check version */
	if (p->data_len < 1) {
		LOG(LOGL_ERROR, "Discarding packet - too small: %d\n",
		    p->data_len);
		p->rc = GTP_RC_TOOSHORT;
		return;
	}

	p->version = p->data->flags >> 5;

	switch (p->version) {
	case 0:
		validate_gtp0_header(p);
		break;
	case 1:
		validate_gtp1_header(p);
		break;
	default:
		LOG(LOGL_ERROR, "Unsupported GTP version: %d\n", p->version);
		p->rc = GTP_RC_UNSUPPORTED_VERSION;
		break;
	}
}


/* Return the value of the i'th IMSI IEI by copying to *imsi.
 * The first IEI is reached by passing i = 0.
 * imsi must point at allocated space of (at least) 8 bytes.
 * Return 1 on success, or 0 if not found. */
static int get_ie_imsi(union gtpie_member *ie[], int i, uint8_t *imsi)
{
	return gtpie_gettv0(ie, GTPIE_IMSI, i, imsi, 8) == 0;
}

/* Analogous to get_ie_imsi(). nsapi must point at a single uint8_t. */
static int get_ie_nsapi(union gtpie_member *ie[], int i, uint8_t *nsapi)
{
	return gtpie_gettv1(ie, GTPIE_NSAPI, i, nsapi) == 0;
}

static char imsi_digit_to_char(uint8_t nibble)
{
	nibble &= 0x0f;
	if (nibble > 9)
		return (nibble == 0x0f) ? '\0' : '?';
	return '0' + nibble;
}

/* Return a human readable IMSI string, in a static buffer.
 * imsi must point at 8 octets of IMSI IE encoded IMSI data. */
static int imsi_to_str(uint8_t *imsi, const char **imsi_str)
{
	static char str[17];
	int i;

	for (i = 0; i < 8; i++) {
		char c;
		c = imsi_digit_to_char(imsi[i]);
		if (c == '?')
			return -1;
		str[2*i] = c;

		c = imsi_digit_to_char(imsi[i] >> 4);
		if (c == '?')
			return -1;
		str[2*i + 1] = c;
	}
	str[16] = '\0';
	*imsi_str = str;
	return 1;
}

/* Return 0 if not present, 1 if present and decoded successfully, -1 if
 * present but cannot be decoded. */
static int get_ie_imsi_str(union gtpie_member *ie[], int i,
			   const char **imsi_str)
{
	uint8_t imsi_buf[8];
	if (!get_ie_imsi(ie, i, imsi_buf))
		return 0;
	return imsi_to_str(imsi_buf, imsi_str);
}

/* Return 0 if not present, 1 if present and decoded successfully, -1 if
 * present but cannot be decoded. */
static int get_ie_apn_str(union gtpie_member *ie[], const char **apn_str)
{
	static char apn_buf[GSM_APN_LENGTH];
	unsigned int len;
	if (gtpie_gettlv(ie, GTPIE_APN, 0,
			 &len, apn_buf, sizeof(apn_buf)) != 0)
		return 0;

	if (len < 2) {
		LOG(LOGL_ERROR, "APN IE: invalid length: %d\n",
		    (int)len);
		return -1;
	}

	if (len > (sizeof(apn_buf) - 1))
		len = sizeof(apn_buf) - 1;
	apn_buf[len] = '\0';

	*apn_str = gprs_apn_to_str(apn_buf, (uint8_t*)apn_buf, len);
	if (!(*apn_str)) {
		LOG(LOGL_ERROR, "APN IE: present but cannot be decoded: %s\n",
		    osmo_hexdump((uint8_t*)apn_buf, len));
		return -1;
	}
	return 1;
}


/* Validate header, and index information elements. Write decoded packet
 * information to *res. res->data will point at the given data buffer. On
 * error, p->rc is set <= 0 (see enum gtp_rc). */
static void gtp_decode(const uint8_t *data, int data_len,
		       unsigned int from_side_idx,
		       unsigned int from_plane_idx,
		       struct gtp_packet_desc *res,
		       time_t now)
{
	ZERO_STRUCT(res);
	res->data = (union gtp_packet*)data;
	res->data_len = data_len;
	res->side_idx = from_side_idx;
	res->plane_idx = from_plane_idx;
	res->timestamp = now;

	validate_gtp_header(res);

	if (res->rc <= 0)
		return;

	LOG(LOGL_DEBUG, "Valid GTP header (v%d)\n", res->version);

	if (from_plane_idx == GTPH_PLANE_USER) {
		res->rc = GTP_RC_PDU_U;
		return;
	}

	if (res->rc != GTP_RC_PDU_C) {
		LOG(LOGL_DEBUG, "no IEs in this GTP packet\n");
		return;
	}

	if (gtpie_decaps(res->ie, res->version,
			 (void*)(data + res->header_len),
			 res->data_len - res->header_len) != 0) {
		res->rc = GTP_RC_INVALID_IE;
		LOG(LOGL_ERROR, "INVALID: cannot decode IEs."
		    " Dropping GTP packet%s.\n",
		    gtp_type_str(res->type)
		    );
		return;
	}

#if 1
	/* TODO if (<loglevel is debug>)
	   (waiting for a commit from jerlbeck) */
	int i;

	for (i = 0; i < 10; i++) {
		const char *imsi;
		if (get_ie_imsi_str(res->ie, i, &imsi) < 1)
			break;
		LOG(LOGL_DEBUG, "| IMSI %s\n", imsi);
	}

	for (i = 0; i < 10; i++) {
		uint8_t nsapi;
		if (!get_ie_nsapi(res->ie, i, &nsapi))
			break;
		LOG(LOGL_DEBUG, "| NSAPI %d\n", (int)nsapi);
	}

	for (i = 0; i < 2; i++) {
		struct gsn_addr addr;
		if (gsn_addr_get(&addr, res, i) == 0)
			LOG(LOGL_DEBUG, "| addr %s\n", gsn_addr_to_str(&addr));
	}

	for (i = 0; i < 10; i++) {
		uint32_t tei;
		if (gtpie_gettv4(res->ie, GTPIE_TEI_DI, i, &tei) != 0)
			break;
		LOG(LOGL_DEBUG, "| TEI DI (USER) %" PRIu32 " 0x%08" PRIx32 "\n",
		    tei, tei);
	}

	for (i = 0; i < 10; i++) {
		uint32_t tei;
		if (gtpie_gettv4(res->ie, GTPIE_TEI_C, i, &tei) != 0)
			break;
		LOG(LOGL_DEBUG, "| TEI (CTRL) %" PRIu32 " 0x%08" PRIx32 "\n",
		    tei, tei);
	}
#endif
}


/* expiry */

void expiry_init(struct expiry *exq, int expiry_in_seconds)
{
	ZERO_STRUCT(exq);
	exq->expiry_in_seconds = expiry_in_seconds;
	INIT_LLIST_HEAD(&exq->items);
}

void expiry_add(struct expiry *exq, struct expiring_item *item, time_t now)
{
	item->expiry = now + exq->expiry_in_seconds;

	OSMO_ASSERT(llist_empty(&exq->items)
		    || (item->expiry
			>= llist_last(&exq->items, struct expiring_item, entry)->expiry));

	/* Add/move to the tail to always sort by expiry, ascending. */
	llist_del(&item->entry);
	llist_add_tail(&item->entry, &exq->items);
}

int expiry_tick(struct expiry *exq, time_t now)
{
	int expired = 0;
	struct expiring_item *m, *n;
	llist_for_each_entry_safe(m, n, &exq->items, entry) {
		if (m->expiry <= now) {
			expiring_item_del(m);
			expired ++;
		} else {
			/* The items are added sorted by expiry. So when we hit
			 * an unexpired entry, only more unexpired ones will
			 * follow. */
			break;
		}
	}
	return expired;
}

void expiry_clear(struct expiry *exq)
{
	struct expiring_item *m, *n;
	llist_for_each_entry_safe(m, n, &exq->items, entry) {
		expiring_item_del(m);
	}
}

void expiring_item_init(struct expiring_item *item)
{
	ZERO_STRUCT(item);
	INIT_LLIST_HEAD(&item->entry);
}

void expiring_item_del(struct expiring_item *item)
{
	OSMO_ASSERT(item);
	llist_del(&item->entry);
	INIT_LLIST_HEAD(&item->entry);
	if (item->del_cb) {
		/* avoid loops */
		del_cb_t del_cb = item->del_cb;
		item->del_cb = 0;
		(del_cb)(item);
	}
}


/* nr_map, nr_pool */

void nr_pool_init(struct nr_pool *pool, nr_t nr_min, nr_t nr_max)
{
	*pool = (struct nr_pool){
		.nr_min = nr_min,
		.nr_max = nr_max,
		.last_nr = nr_max
	};
}

nr_t nr_pool_next(struct nr_pool *pool)
{
	if (pool->last_nr >= pool->nr_max)
		pool->last_nr = pool->nr_min;
	else
		pool->last_nr ++;

	return pool->last_nr;
}

void nr_map_init(struct nr_map *map, struct nr_pool *pool,
		 struct expiry *exq)
{
	ZERO_STRUCT(map);
	map->pool = pool;
	map->add_items_to_expiry = exq;
	INIT_LLIST_HEAD(&map->mappings);
}

void nr_mapping_init(struct nr_mapping *m)
{
	ZERO_STRUCT(m);
	INIT_LLIST_HEAD(&m->entry);
	expiring_item_init(&m->expiry_entry);
}

void nr_map_add(struct nr_map *map, struct nr_mapping *mapping, time_t now)
{
	/* Generate a mapped number */
	mapping->repl = nr_pool_next(map->pool);

	/* Add to the tail to always yield a list sorted by expiry, in
	 * ascending order. */
	llist_add_tail(&mapping->entry, &map->mappings);
	nr_map_refresh(map, mapping, now);
}

void nr_map_refresh(struct nr_map *map, struct nr_mapping *mapping, time_t now)
{
	if (!map->add_items_to_expiry)
		return;
	expiry_add(map->add_items_to_expiry,
		   &mapping->expiry_entry,
		   now);
}

void nr_map_clear(struct nr_map *map)
{
	struct nr_mapping *m;
	struct nr_mapping *n;
	llist_for_each_entry_safe(m, n, &map->mappings, entry) {
		nr_mapping_del(m);
	}
}

int nr_map_empty(const struct nr_map *map)
{
	return llist_empty(&map->mappings);
}

struct nr_mapping *nr_map_get(const struct nr_map *map,
			      void *origin, nr_t nr_orig)
{
	struct nr_mapping *mapping;
	llist_for_each_entry(mapping, &map->mappings, entry) {
		if ((mapping->origin == origin)
		    && (mapping->orig == nr_orig))
			return mapping;
	}
	/* Not found. */
	return NULL;
}

struct nr_mapping *nr_map_get_inv(const struct nr_map *map, nr_t nr_repl)
{
	struct nr_mapping *mapping;
	llist_for_each_entry(mapping, &map->mappings, entry) {
		if (mapping->repl == nr_repl) {
			return mapping;
		}
	}
	/* Not found. */
	return NULL;
}

void nr_mapping_del(struct nr_mapping *mapping)
{
	OSMO_ASSERT(mapping);
	llist_del(&mapping->entry);
	INIT_LLIST_HEAD(&mapping->entry);
	expiring_item_del(&mapping->expiry_entry);
}


/* gtphub */

const char* const gtphub_plane_idx_names[GTPH_PLANE_N] = {
	"CTRL",
	"USER",
};

const uint16_t gtphub_plane_idx_default_port[GTPH_PLANE_N] = {
	2123,
	2152,
};

const char* const gtphub_side_idx_names[GTPH_SIDE_N] = {
	"SGSN",
	"GGSN",
};

time_t gtphub_now(void)
{
	struct timespec now_tp;
	OSMO_ASSERT(clock_gettime(CLOCK_MONOTONIC, &now_tp) >= 0);
	return now_tp.tv_sec;
}

/* Remove a gtphub_peer from its list and free it. */
static void gtphub_peer_del(struct gtphub_peer *peer)
{
	OSMO_ASSERT(llist_empty(&peer->addresses));
	nr_map_clear(&peer->seq_map);
	llist_del(&peer->entry);
	talloc_free(peer);
}

static void gtphub_peer_addr_del(struct gtphub_peer_addr *pa)
{
	OSMO_ASSERT(llist_empty(&pa->ports));
	llist_del(&pa->entry);
	talloc_free(pa);
}

static void gtphub_peer_port_del(struct gtphub_peer_port *pp)
{
	OSMO_ASSERT(pp->ref_count == 0);
	llist_del(&pp->entry);
	rate_ctr_group_free(pp->counters_io);
	talloc_free(pp);
}

/* From the information in the gtp_packet_desc, return the address of a GGSN.
 * Return -1 on error. */
static int gtphub_resolve_ggsn(struct gtphub *hub,
			       struct gtp_packet_desc *p,
			       struct gtphub_peer_port **pp);

/* See gtphub_ext.c (wrapped by unit test) */
struct gtphub_peer_port *gtphub_resolve_ggsn_addr(struct gtphub *hub,
						  const char *imsi_str,
						  const char *apn_ni_str);
int gtphub_ares_init(struct gtphub *hub);

static void gtphub_zero(struct gtphub *hub)
{
	ZERO_STRUCT(hub);
	INIT_LLIST_HEAD(&hub->ggsn_lookups);
	INIT_LLIST_HEAD(&hub->resolved_ggsns);
}

static int gtphub_sock_init(struct osmo_fd *ofd,
			    const struct gtphub_cfg_addr *addr,
			    osmo_fd_cb_t cb,
			    void *data,
			    int ofd_id)
{
	if (!addr->addr_str) {
		LOG(LOGL_FATAL, "Cannot bind: empty address.\n");
		return -1;
	}
	if (!addr->port) {
		LOG(LOGL_FATAL, "Cannot bind: zero port not permitted.\n");
		return -1;
	}

	ofd->when = BSC_FD_READ;
	ofd->cb = cb;
	ofd->data = data;
	ofd->priv_nr = ofd_id;

	int rc;
	rc = osmo_sock_init_ofd(ofd,
				AF_UNSPEC, SOCK_DGRAM, IPPROTO_UDP,
				addr->addr_str, addr->port,
				OSMO_SOCK_F_BIND);
	if (rc < 1) {
		LOG(LOGL_FATAL, "Cannot bind to %s port %d (rc %d)\n",
		    addr->addr_str, (int)addr->port, rc);
		return -1;
	}

	return 0;
}

static void gtphub_sock_close(struct osmo_fd *ofd)
{
	close(ofd->fd);
	osmo_fd_unregister(ofd);
	ofd->cb = NULL;
}

static void gtphub_bind_init(struct gtphub_bind *b)
{
	ZERO_STRUCT(b);

	INIT_LLIST_HEAD(&b->peers);

	b->counters_io = rate_ctr_group_alloc(osmo_gtphub_ctx,
					      &gtphub_ctrg_io_desc, 0);
	OSMO_ASSERT(b->counters_io);
}

static int gtphub_bind_start(struct gtphub_bind *b,
			     const struct gtphub_cfg_bind *cfg,
			     osmo_fd_cb_t cb, void *cb_data,
			     unsigned int ofd_id)
{
	LOG(LOGL_DEBUG, "Starting bind %s\n", b->label);
	if (gsn_addr_from_str(&b->local_addr, cfg->bind.addr_str) != 0) {
		LOG(LOGL_FATAL, "Invalid bind address for %s: %s\n",
		    b->label, cfg->bind.addr_str);
		return -1;
	}
	if (gtphub_sock_init(&b->ofd, &cfg->bind, cb, cb_data, ofd_id) != 0) {
		LOG(LOGL_FATAL, "Cannot bind for %s: %s\n",
		    b->label, cfg->bind.addr_str);
		return -1;
	}
	b->local_port = cfg->bind.port;
	return 0;
}

static void gtphub_bind_free(struct gtphub_bind *b)
{
	OSMO_ASSERT(llist_empty(&b->peers));
	rate_ctr_group_free(b->counters_io);
}

static void gtphub_bind_stop(struct gtphub_bind *b) {
	gtphub_sock_close(&b->ofd);
	gtphub_bind_free(b);
}

/* Recv datagram from from->fd, write sender's address to *from_addr.
 * Return the number of bytes read, zero on error. */
static int gtphub_read(const struct osmo_fd *from,
		       struct osmo_sockaddr *from_addr,
		       uint8_t *buf, size_t buf_len)
{
	OSMO_ASSERT(from_addr);

	/* recvfrom requires the available length set in *from_addr_len. */
	from_addr->l = sizeof(from_addr->a);
	errno = 0;
	ssize_t received = recvfrom(from->fd, buf, buf_len, 0,
				    (struct sockaddr*)&from_addr->a,
				    &from_addr->l);
	/* TODO use recvmsg and get a MSG_TRUNC flag to make sure the message
	 * is not truncated. Then maybe reduce buf's size. */

	if (received <= 0) {
		LOG((errno == EAGAIN? LOGL_DEBUG : LOGL_ERROR),
		    "error: %s\n", strerror(errno));
		return 0;
	}

	LOG(LOGL_DEBUG, "Received %d bytes from %s: %s%s\n",
	    (int)received, osmo_sockaddr_to_str(from_addr),
	    osmo_hexdump(buf, received > 1000? 1000 : received),
	    received > 1000 ? "..." : "");

	return received;
}

static inline void gtphub_port_ref_count_inc(struct gtphub_peer_port *pp)
{
	OSMO_ASSERT(pp);
	OSMO_ASSERT(pp->ref_count < UINT_MAX);
	pp->ref_count++;
}

static inline void gtphub_port_ref_count_dec(struct gtphub_peer_port *pp)
{
	OSMO_ASSERT(pp);
	OSMO_ASSERT(pp->ref_count > 0);
	pp->ref_count--;
}

static inline void set_seq(struct gtp_packet_desc *p, uint16_t seq)
{
	OSMO_ASSERT(p->version == 1);
	p->data->gtp1l.h.seq = hton16(seq);
	p->seq = seq;
}

static inline void set_tei(struct gtp_packet_desc *p, uint32_t tei)
{
	OSMO_ASSERT(p->version == 1);
	p->data->gtp1l.h.tei = hton32(tei);
	p->header_tei = tei;
}

static void gtphub_mapping_del_cb(struct expiring_item *expi);

static struct nr_mapping *gtphub_mapping_new()
{
	struct nr_mapping *nrm;
	nrm = talloc_zero(osmo_gtphub_ctx, struct nr_mapping);
	OSMO_ASSERT(nrm);

	nr_mapping_init(nrm);
	nrm->expiry_entry.del_cb = gtphub_mapping_del_cb;
	return nrm;
}


#define APPEND(args...) \
		l = snprintf(pos, left, args); \
		pos += l; \
		left -= l

static const char *gtphub_tunnel_side_str(struct gtphub_tunnel *tun,
					  int side_idx)
{
	static char buf[256];
	char *pos = buf;
	int left = sizeof(buf);
	int l;
	                 
	struct gtphub_tunnel_endpoint *c, *u;
	c = &tun->endpoint[side_idx][GTPH_PLANE_CTRL];
	u = &tun->endpoint[side_idx][GTPH_PLANE_USER];

	/* print both only if they differ. */
	if (!c->peer) {
		APPEND("(uninitialized)");
	} else {
		APPEND("%s", gsn_addr_to_str(&c->peer->peer_addr->addr));
	}

	if (!u->peer) {
		if (c->peer) {
			APPEND("/(uninitialized)");
		}
	} else if ((!c->peer)
		   || (!gsn_addr_same(&u->peer->peer_addr->addr,
				      &c->peer->peer_addr->addr))) {
		APPEND("/%s", gsn_addr_to_str(&u->peer->peer_addr->addr));
	}

	APPEND(" (TEI C=%x U=%x)",
	       c->tei_orig,
	       u->tei_orig);
	return buf;
}

const char *gtphub_tunnel_str(struct gtphub_tunnel *tun)
{
	static char buf[512];
	char *pos = buf;
	int left = sizeof(buf);
	int l;

	if (!tun)
		return "null-tunnel";

	APPEND("TEI=%x: ", tun->tei_repl);
	APPEND("%s", gtphub_tunnel_side_str(tun, GTPH_SIDE_SGSN));
	APPEND(" <-> %s", gtphub_tunnel_side_str(tun, GTPH_SIDE_GGSN));

	return buf;
}

#undef APPEND

void gtphub_tunnel_endpoint_set_peer(struct gtphub_tunnel_endpoint *te,
				     struct gtphub_peer_port *pp)
{
	if (te->peer)
		gtphub_port_ref_count_dec(te->peer);
	te->peer = pp;
	if (te->peer)
		gtphub_port_ref_count_inc(te->peer);
}

int gtphub_tunnel_complete(struct gtphub_tunnel *tun)
{
	if (!tun)
		return 0;
	if (!tun->tei_repl)
		return 0;
	int side_idx;
	int plane_idx;
	for_each_side_and_plane(side_idx, plane_idx) {
		struct gtphub_tunnel_endpoint *te =
			&tun->endpoint[side_idx][plane_idx];
		if (!(te->peer && te->tei_orig))
			return 0;
	}
	return 1;
}

static void gtphub_tunnel_del_cb(struct expiring_item *expi)
{
	struct gtphub_tunnel *tun = container_of(expi,
						 struct gtphub_tunnel,
						 expiry_entry);
	LOG(LOGL_DEBUG, "expired: %s\n", gtphub_tunnel_str(tun));

	llist_del(&tun->entry);
	INIT_LLIST_HEAD(&tun->entry); /* mark unused */

	expi->del_cb = 0; /* avoid recursion loops */
	expiring_item_del(&tun->expiry_entry); /* usually already done, but make sure. */

	int side_idx;
	int plane_idx;
	for_each_side_and_plane(side_idx, plane_idx) {
		struct gtphub_tunnel_endpoint *te = &tun->endpoint[side_idx][plane_idx];

		/* clear ref count */
		gtphub_tunnel_endpoint_set_peer(te, NULL);

		rate_ctr_group_free(te->counters_io);
	}

	talloc_free(tun);
}

static struct gtphub_tunnel *gtphub_tunnel_new()
{
	struct gtphub_tunnel *tun;
	tun = talloc_zero(osmo_gtphub_ctx, struct gtphub_tunnel);
	OSMO_ASSERT(tun);

	INIT_LLIST_HEAD(&tun->entry);
	expiring_item_init(&tun->expiry_entry);

	int side_idx, plane_idx;
	for_each_side_and_plane(side_idx, plane_idx) {
		struct gtphub_tunnel_endpoint *te = &tun->endpoint[side_idx][plane_idx];
		te->counters_io = rate_ctr_group_alloc(osmo_gtphub_ctx,
						       &gtphub_ctrg_io_desc,
						       0);
		OSMO_ASSERT(te->counters_io);
	}

	tun->expiry_entry.del_cb = gtphub_tunnel_del_cb;
	return tun;
}

static const char *gtphub_peer_strb(struct gtphub_peer *peer, char *buf,
				    int buflen)
{
	if (llist_empty(&peer->addresses))
		return "(addressless)";

	struct gtphub_peer_addr *a = llist_first(&peer->addresses,
						 struct gtphub_peer_addr,
						 entry);
	return gsn_addr_to_strb(&a->addr, buf, buflen);
}

static const char *gtphub_port_strb(struct gtphub_peer_port *port, char *buf,
				    int buflen)
{
	if (!port)
		return "(null port)";

	snprintf(buf, buflen, "%s port %d",
		 gsn_addr_to_str(&port->peer_addr->addr),
		 (int)port->port);
	return buf;
}

const char *gtphub_peer_str(struct gtphub_peer *peer)
{
	static char buf[256];
	return gtphub_peer_strb(peer, buf, sizeof(buf));
}

const char *gtphub_port_str(struct gtphub_peer_port *port)
{
	static char buf[256];
	return gtphub_port_strb(port, buf, sizeof(buf));
}

static const char *gtphub_port_str2(struct gtphub_peer_port *port)
{
	static char buf[256];
	return gtphub_port_strb(port, buf, sizeof(buf));
}

static void gtphub_mapping_del_cb(struct expiring_item *expi)
{
	expi->del_cb = 0; /* avoid recursion loops */
	expiring_item_del(expi); /* usually already done, but make sure. */

	struct nr_mapping *nrm = container_of(expi,
					      struct nr_mapping,
					      expiry_entry);
	llist_del(&nrm->entry);
	INIT_LLIST_HEAD(&nrm->entry); /* mark unused */

	/* Just for log */
	struct gtphub_peer_port *from = nrm->origin;
	OSMO_ASSERT(from);
	LOG(LOGL_DEBUG, "expired: %d: nr mapping from %s: %u->%u\n",
	    (int)nrm->expiry_entry.expiry,
	    gtphub_port_str(from),
	    (unsigned int)nrm->orig, (unsigned int)nrm->repl);

	gtphub_port_ref_count_dec(from);

	talloc_free(nrm);
}

static struct nr_mapping *gtphub_mapping_have(struct nr_map *map,
					      struct gtphub_peer_port *from,
					      nr_t orig_nr,
					      time_t now)
{
	struct nr_mapping *nrm;

	nrm = nr_map_get(map, from, orig_nr);

	if (!nrm) {
		nrm = gtphub_mapping_new();
		nrm->orig = orig_nr;
		nrm->origin = from;
		nr_map_add(map, nrm, now);
		gtphub_port_ref_count_inc(from);
		LOG(LOGL_DEBUG, "peer %s: sequence map %d --> %d\n",
		    gtphub_port_str(from),
		    (int)(nrm->orig), (int)(nrm->repl));
	} else {
		nr_map_refresh(map, nrm, now);
	}

	OSMO_ASSERT(nrm);
	return nrm;
}

static void gtphub_map_seq(struct gtp_packet_desc *p,
			   struct gtphub_peer_port *from_port,
			   struct gtphub_peer_port *to_port)
{
	/* Store a mapping in to_peer's map, so when we later receive a GTP
	 * packet back from to_peer, the seq nr can be unmapped back to its
	 * origin (from_peer here). */
	struct nr_mapping *nrm;
	nrm = gtphub_mapping_have(&to_port->peer_addr->peer->seq_map,
				  from_port, p->seq, p->timestamp);

	/* Change the GTP packet to yield the new, mapped seq nr */
	set_seq(p, nrm->repl);
}

static struct gtphub_peer_port *gtphub_unmap_seq(struct gtp_packet_desc *p,
						 struct gtphub_peer_port *responding_port)
{
	OSMO_ASSERT(p->version == 1);
	struct nr_mapping *nrm =
		nr_map_get_inv(&responding_port->peer_addr->peer->seq_map,
			       p->seq);
	if (!nrm)
		return NULL;
	LOG(LOGL_DEBUG, "peer %p: sequence unmap %d <-- %d\n",
	    nrm->origin, (int)(nrm->orig), (int)(nrm->repl));
	set_seq(p, nrm->orig);
	return nrm->origin;
}

static int gtphub_check_mapped_tei(struct gtphub_tunnel *new_tun,
				   struct gtphub_tunnel *iterated_tun,
				   uint32_t *tei_min,
				   uint32_t *tei_max)
{
	if (!new_tun->tei_repl || !iterated_tun->tei_repl)
		return 1;

	*tei_min = (*tei_min < iterated_tun->tei_repl)? *tei_min : iterated_tun->tei_repl;
	*tei_max = (*tei_max > iterated_tun->tei_repl)? *tei_max : iterated_tun->tei_repl;

	if (new_tun->tei_repl != iterated_tun->tei_repl)
		return 1;

	/* new_tun->tei_repl is already taken. Try to find one out of the known
	 * range. */
	LOG(LOGL_DEBUG, "TEI replacement %d already taken.\n", new_tun->tei_repl);

	if ((*tei_max) < 0xffffffff) {
		(*tei_max)++;
		new_tun->tei_repl = *tei_max;
		LOG(LOGL_DEBUG, "Using TEI %d instead.\n", new_tun->tei_repl);
		return 1;
	} else if ((*tei_min) > 1) {
		(*tei_min)--;
		new_tun->tei_repl = *tei_min;
		LOG(LOGL_DEBUG, "Using TEI %d instead.\n", new_tun->tei_repl);
		return 1;
	}

	/* None seems to be available. */
	return 0;
}

static int gtphub_check_reused_teis(struct gtphub *hub,
				    struct gtphub_tunnel *new_tun)
{
	uint32_t tei_min = 0xffffffff;
	uint32_t tei_max = 0;
	int side_idx;
	int plane_idx;
	struct gtphub_tunnel_endpoint *te;
	struct gtphub_tunnel_endpoint *te2;

	struct gtphub_tunnel *tun, *ntun;

	llist_for_each_entry_safe(tun, ntun, &hub->tunnels, entry) {
		if (tun == new_tun)
			continue;

		/* Check whether the GSN sent a TEI that it is reusing from a
		 * previous tunnel. */
		int tun_continue = 0;
		for_each_side(side_idx) {
			for_each_plane(plane_idx) {
				te = &tun->endpoint[side_idx][plane_idx];
				te2 = &new_tun->endpoint[side_idx][plane_idx];
				if ((te->tei_orig == 0)
				    || (te->tei_orig != te2->tei_orig)
				    || (!te->peer)
				    || (!te2->peer)
				    || !gsn_addr_same(&te->peer->peer_addr->addr,
						      &te2->peer->peer_addr->addr))
					continue;

				/* The peer is reusing a TEI that I believe to
				 * be part of another tunnel. The other tunnel
				 * must be stale, then. */
				LOG(LOGL_NOTICE,
				    "Expiring tunnel due to reused TEI:"
				    " %s peer %s sent %s TEI %x,"
				    " previously used by tunnel %s...\n",
				    gtphub_side_idx_names[side_idx],
				    gtphub_port_str(te->peer),
				    gtphub_plane_idx_names[plane_idx],
				    te->tei_orig,
				    gtphub_tunnel_str(tun));
				LOG(LOGL_NOTICE, "...while establishing tunnel %s\n",
				    gtphub_tunnel_str(new_tun));

				expiring_item_del(&tun->expiry_entry);
				/* continue to find more matches. There shouldn't be
				 * any, but let's make sure. However, tun is deleted,
				 * so we need to skip to the next tunnel. */
				tun_continue = 1;
				break;
			}
			if (tun_continue)
				break;
		}
		if (tun_continue)
			continue;

		/* Check whether the mapped TEI is already used by another
		 * tunnel. */
		if (!gtphub_check_mapped_tei(new_tun, tun, &tei_min, &tei_max)) {
			LOG(LOGL_ERROR,
			    "No mapped TEI is readily available."
			    " Searching for holes between occupied"
			    " TEIs not implemented.");
			return 0;
		}

	}

	return 1;
}

static void gtphub_tunnel_refresh(struct gtphub *hub,
				  struct gtphub_tunnel *tun,
				  time_t now)
{
	expiry_add(&hub->expire_slowly,
		   &tun->expiry_entry,
		   now);
}

static struct gtphub_tunnel_endpoint *gtphub_unmap_tei(struct gtphub *hub,
						       struct gtp_packet_desc *p,
						       struct gtphub_peer_port *from,
						       struct gtphub_tunnel **unmapped_from_tun)
{
	OSMO_ASSERT(from);
	int other_side = other_side_idx(p->side_idx);

	struct gtphub_tunnel *tun;
	llist_for_each_entry(tun, &hub->tunnels, entry) {
		struct gtphub_tunnel_endpoint *te_from =
			&tun->endpoint[p->side_idx][p->plane_idx];
		struct gtphub_tunnel_endpoint *te_to =
			&tun->endpoint[other_side][p->plane_idx];
		if ((tun->tei_repl == p->header_tei_rx)
		    && te_from->peer
		    && gsn_addr_same(&te_from->peer->peer_addr->addr,
				     &from->peer_addr->addr)) {
			gtphub_tunnel_refresh(hub, tun, p->timestamp);
			if (unmapped_from_tun)
				*unmapped_from_tun = tun;
			return te_to;
		}
	}

	if (unmapped_from_tun)
		*unmapped_from_tun = NULL;
	return NULL;
}

static void gtphub_map_restart_counter(struct gtphub *hub,
				       struct gtp_packet_desc *p)
{
	if (p->rc != GTP_RC_PDU_C)
		return;

	int ie_idx;
	ie_idx = gtpie_getie(p->ie, GTPIE_RECOVERY, 0);
	if (ie_idx < 0)
		return;

	/* Always send gtphub's own restart counter */
	p->ie[ie_idx]->tv1.v = hton8(hub->restart_counter);
}

static int gtphub_unmap_header_tei(struct gtphub_peer_port **to_port_p,
				   struct gtphub_tunnel **unmapped_from_tun,
				   struct gtphub *hub,
				   struct gtp_packet_desc *p,
				   struct gtphub_peer_port *from_port)
{
	OSMO_ASSERT(p->version == 1);
	*to_port_p = NULL;
	if (unmapped_from_tun)
		*unmapped_from_tun = NULL;

	/* If the header's TEI is zero, no PDP context has been established
	 * yet. If nonzero, a mapping should actually already exist for this
	 * TEI, since it must have been announced in a PDP context creation. */
	if (!p->header_tei_rx)
		return 0;

	/* to_peer has previously announced a TEI, which was stored and
	 * mapped in a tunnel struct. */
	struct gtphub_tunnel_endpoint *to;
	to = gtphub_unmap_tei(hub, p, from_port, unmapped_from_tun);
	if (!to) {
		LOG(LOGL_ERROR, "Received unknown TEI %" PRIx32 " from %s\n",
		    p->header_tei_rx, gtphub_port_str(from_port));
		return -1;
	}

	if (unmapped_from_tun) {
		OSMO_ASSERT(*unmapped_from_tun);
		LOG(LOGL_DEBUG, "Unmapped TEI coming from: %s\n",
		    gtphub_tunnel_str(*unmapped_from_tun));
	}

	uint32_t unmapped_tei = to->tei_orig;
	set_tei(p, unmapped_tei);

	/* May be NULL for an invalidated tunnel. */
	*to_port_p = to->peer;

	return 0;
}

static int gtphub_handle_create_pdp_ctx(struct gtphub *hub,
					struct gtp_packet_desc *p,
					struct gtphub_peer_port *from_ctrl,
					struct gtphub_peer_port *to_ctrl)
{
	int plane_idx;

	osmo_static_assert((GTPH_PLANE_CTRL == 0) && (GTPH_PLANE_USER == 1),
			   plane_nrs_match_GSN_addr_IE_indices);

	struct gtphub_tunnel *tun = p->tun;

	if (p->type == GTP_CREATE_PDP_REQ) {
		if (p->side_idx != GTPH_SIDE_SGSN) {
			LOG(LOGL_ERROR, "Wrong side: Create PDP Context"
			    " Request from the GGSN side: %s",
			    gtphub_port_str(from_ctrl));
			return -1;
		}

		if (tun) {
			LOG(LOGL_ERROR, "Not implemented: Received"
			    " Create PDP Context Request for an already"
			    " established tunnel:"
			    " from %s, tunnel %s\n",
			    gtphub_port_str(from_ctrl),
			    gtphub_tunnel_str(p->tun));
			return -1;
		}

		/* A new tunnel. */
		p->tun = tun = gtphub_tunnel_new();

		/* Create TEI mapping */
		tun->tei_repl = nr_pool_next(&hub->tei_pool);

		llist_add(&tun->entry, &hub->tunnels);
		gtphub_tunnel_refresh(hub, tun, p->timestamp);
		/* The endpoint peers on this side (SGSN) will be set from IEs
		 * below. Also set the GGSN Ctrl endpoint, for logging. */
		gtphub_tunnel_endpoint_set_peer(&tun->endpoint[GTPH_SIDE_GGSN][GTPH_PLANE_CTRL],
						to_ctrl);
	} else if (p->type == GTP_CREATE_PDP_RSP) {
		if (p->side_idx != GTPH_SIDE_GGSN) {
			LOG(LOGL_ERROR, "Wrong side: Create PDP Context"
			    " Response from the SGSN side: %s",
			    gtphub_port_str(from_ctrl));
			return -1;
		}

		/* The tunnel should already have been resolved from the header
		 * TEI and be available in tun (== p->tun). Just fill in the
		 * GSN Addresses below.*/
		OSMO_ASSERT(tun);
		OSMO_ASSERT(tun->tei_repl == p->header_tei_rx);
		OSMO_ASSERT(to_ctrl);
	}

	uint8_t ie_type[] = { GTPIE_TEI_C, GTPIE_TEI_DI };
	int ie_mandatory = (p->type == GTP_CREATE_PDP_REQ);
	unsigned int side_idx = p->side_idx;

	for (plane_idx = 0; plane_idx < 2; plane_idx++) {
		int rc;
		struct gsn_addr use_addr;
		uint16_t use_port;
		uint32_t tei_from_ie;
		int ie_idx;

		/* Fetch GSN Address and TEI from IEs. As ensured by above
		 * static asserts, plane_idx corresponds to the GSN Address IE
		 * index (the first one = 0 = ctrl, second one = 1 = user). */
		rc = gsn_addr_get(&use_addr, p, plane_idx);
		if (rc) {
			LOG(LOGL_ERROR, "Cannot read %s GSN Address IE\n",
			    gtphub_plane_idx_names[plane_idx]);
			return -1;
		}
		LOG(LOGL_DEBUG, "Read %s GSN addr %s (%d)\n",
		    gtphub_plane_idx_names[plane_idx],
		    gsn_addr_to_str(&use_addr),
		    use_addr.len);

		ie_idx = gtpie_getie(p->ie, ie_type[plane_idx], 0);
		if (ie_idx < 0) {
			if (ie_mandatory) {
				LOG(LOGL_ERROR,
				    "Create PDP Context message invalid:"
				    " missing IE %d\n",
				    (int)ie_type[plane_idx]);
				return -1;
			}
			tei_from_ie = 0;
		}
		else
			tei_from_ie = ntoh32(p->ie[ie_idx]->tv4.v);

		/* Make sure an entry for this peer address with default port
		 * exists.
		 *
		 * Exception: if sgsn_use_sender is set, instead use the
		 * sender's address and port for Ctrl -- the User port is not
		 * known until the first User packet arrives.
		 *
		 * Note: doing this here is just an optimization, because
		 * gtphub_handle_buf() has code to replace the tunnel
		 * endpoints' addresses with the sender (needed for User
		 * plane). We could just ignore sgsn_use_sender here. But if we
		 * set up a default port here and replace it in
		 * gtphub_handle_buf(), we'd be creating a peer port just to
		 * expire it right away. */
		if (hub->sgsn_use_sender && (side_idx == GTPH_SIDE_SGSN)) {
			gsn_addr_from_sockaddr(&use_addr, &use_port, &from_ctrl->sa);
		} else {
			use_port = gtphub_plane_idx_default_port[plane_idx];

		}

		struct gtphub_peer_port *peer_from_ie;
		peer_from_ie = gtphub_port_have(hub,
						&hub->to_gsns[side_idx][plane_idx],
						&use_addr, use_port);

		gtphub_tunnel_endpoint_set_peer(&tun->endpoint[side_idx][plane_idx],
						peer_from_ie);

		if (!tei_from_ie &&
		    !tun->endpoint[side_idx][plane_idx].tei_orig) {
			LOG(LOGL_ERROR,
			    "Create PDP Context message omits %s TEI, but"
			    " no TEI has been announced for this tunnel: %s\n",
			    gtphub_plane_idx_names[plane_idx],
			    gtphub_tunnel_str(tun));
			return -1;
		}

		if (tei_from_ie) {
			/* Replace TEI in GTP packet IE */
			tun->endpoint[side_idx][plane_idx].tei_orig = tei_from_ie;
			p->ie[ie_idx]->tv4.v = hton32(tun->tei_repl);

			if (!gtphub_check_reused_teis(hub, tun)) {
				/* It's highly unlikely that all TEIs are
				 * taken. But the code looking for an unused
				 * TEI is, at the time of writing this comment,
				 * not able to find gaps in the TEI space. To
				 * explicitly alert the user of this problem,
				 * rather abort than carry on. */
				LOG(LOGL_FATAL, "TEI range exhausted. Cannot create TEI mapping, aborting.\n");
				abort();
			}
		}

		/* Replace the GSN address to reflect gtphub. */
		rc = gsn_addr_put(&hub->to_gsns[other_side_idx(side_idx)][plane_idx].local_addr,
				  p, plane_idx);
		if (rc) {
			LOG(LOGL_ERROR, "Cannot write %s GSN Address IE\n",
			    gtphub_plane_idx_names[plane_idx]);
			return -1;
		}
	}

	if (p->type == GTP_CREATE_PDP_REQ) {
		LOG(LOGL_DEBUG, "New tunnel, first half: %s\n",
		    gtphub_tunnel_str(tun));
	} else if (p->type == GTP_CREATE_PDP_RSP) {
		LOG(LOGL_DEBUG, "New tunnel: %s\n",
		    gtphub_tunnel_str(tun));
	}

	return 0;
}

static void pending_delete_del_cb(struct expiring_item *expi)
{
	struct pending_delete *pd;
	pd = container_of(expi, struct pending_delete, expiry_entry);

	llist_del(&pd->entry);
	INIT_LLIST_HEAD(&pd->entry);

	pd->expiry_entry.del_cb = 0;
	expiring_item_del(&pd->expiry_entry);

	talloc_free(pd);
}

static struct pending_delete *pending_delete_new(void)
{
	struct pending_delete *pd = talloc_zero(osmo_gtphub_ctx, struct pending_delete);
	INIT_LLIST_HEAD(&pd->entry);
	expiring_item_init(&pd->expiry_entry);
	pd->expiry_entry.del_cb = pending_delete_del_cb;
	return pd;
}

static int gtphub_handle_delete_pdp_ctx(struct gtphub *hub,
					struct gtp_packet_desc *p,
					struct gtphub_peer_port *from_ctrl,
					struct gtphub_peer_port *to_ctrl)
{
	struct gtphub_tunnel *known_tun = p->tun;

	if (p->type == GTP_DELETE_PDP_REQ) {
		if (!known_tun) {
			LOG(LOGL_ERROR, "Cannot find tunnel for Delete PDP Context Request.\n");
			return -1;
		}

		/* Store the Delete Request until a successful Response is seen. */
		uint8_t teardown_ind;
		uint8_t nsapi;

		if (gtpie_gettv1(p->ie, GTPIE_TEARDOWN, 0, &teardown_ind) != 0) {
			LOG(LOGL_ERROR, "Missing Teardown Ind IE in Delete PDP Context Request.\n");
			return -1;
		}

		if (gtpie_gettv1(p->ie, GTPIE_NSAPI, 0, &nsapi) != 0) {
			LOG(LOGL_ERROR, "Missing NSAPI IE in Delete PDP Context Request.\n");
			return -1;
		}

		struct pending_delete *pd = NULL;

		struct pending_delete *pdi = NULL;
		llist_for_each_entry(pdi, &hub->pending_deletes, entry) {
			if ((pdi->tun == known_tun)
			    && (pdi->teardown_ind == teardown_ind)
			    && (pdi->nsapi == nsapi)) {
				pd = pdi;
				break;
			}
		}

		if (!pd) {
			pd = pending_delete_new();
			pd->tun = known_tun;
			pd->teardown_ind = teardown_ind;
			pd->nsapi = nsapi;

			LOG(LOGL_DEBUG, "Tunnel delete pending: %s\n",
			    gtphub_tunnel_str(known_tun));
			llist_add(&pd->entry, &hub->pending_deletes);
		}

		/* Add or refresh timeout. */
		expiry_add(&hub->expire_quickly, &pd->expiry_entry, p->timestamp);

		/* If a pending_delete should expire before the response to
		 * indicate success comes in, the responding peer will have the
		 * tunnel deactivated, while the requesting peer gets no reply
		 * and keeps the tunnel. The hope is that the requesting peer
		 * will try again and get a useful response. */
	} else if (p->type == GTP_DELETE_PDP_RSP) {
		/* Find the Delete Request for this Response. */
		struct pending_delete *pd = NULL;

		struct pending_delete *pdi;
		llist_for_each_entry(pdi, &hub->pending_deletes, entry) {
			if (known_tun == pdi->tun) {
				pd = pdi;
				break;
			}
		}

		if (!pd) {
			LOG(LOGL_ERROR, "Delete PDP Context Response:"
			    " Cannot find matching request.");
			/* If we delete the tunnel now, anyone can send a
			 * Delete response to kill tunnels at will. */
			return -1;
		}

		/* TODO handle teardown_ind and nsapi */

		expiring_item_del(&pd->expiry_entry);

		uint8_t cause;
		if (gtpie_gettv1(p->ie, GTPIE_CAUSE, 0, &cause) != 0) {
			LOG(LOGL_ERROR, "Delete PDP Context Response:"
			    " Missing Cause IE.");
			/* If we delete the tunnel now, at least one of the
			 * peers may still think it is active. */
			return -1;
		}

		if (cause != GTPCAUSE_ACC_REQ) {
			LOG(LOGL_NOTICE,
			    "Delete PDP Context Response indicates failure;"
			    "for %s\n",
			    gtphub_tunnel_str(known_tun));
			return -1;
		}

		LOG(LOGL_DEBUG, "Delete PDP Context: removing tunnel %s\n",
		    gtphub_tunnel_str(known_tun));
		p->tun = NULL;
		expiring_item_del(&known_tun->expiry_entry);
	}

	return 0;
}

static int gtphub_handle_update_pdp_ctx(struct gtphub *hub,
					struct gtp_packet_desc *p,
					struct gtphub_peer_port *from_ctrl,
					struct gtphub_peer_port *to_ctrl)
{
	/* TODO */
	return 0;
}

/* Read GSN address IEs from p, and make sure these peer addresses exist in
 * bind[plane_idx] with default ports, in their respective planes (both Ctrl
 * and User). Map TEIs announced in IEs, and write mapped TEIs in-place into
 * the packet p. */
static int gtphub_handle_pdp_ctx(struct gtphub *hub,
				 struct gtp_packet_desc *p,
				 struct gtphub_peer_port *from_ctrl,
				 struct gtphub_peer_port *to_ctrl)
{
	OSMO_ASSERT(p->plane_idx == GTPH_PLANE_CTRL);

	switch (p->type) {
	case GTP_CREATE_PDP_REQ:
	case GTP_CREATE_PDP_RSP:
		return gtphub_handle_create_pdp_ctx(hub, p,
						    from_ctrl, to_ctrl);

	case GTP_DELETE_PDP_REQ:
	case GTP_DELETE_PDP_RSP:
		return gtphub_handle_delete_pdp_ctx(hub, p,
						    from_ctrl, to_ctrl);

	case GTP_UPDATE_PDP_REQ:
	case GTP_UPDATE_PDP_RSP:
		return gtphub_handle_update_pdp_ctx(hub, p,
						    from_ctrl, to_ctrl);

	default:
		/* Nothing to do for this message type. */
		return 0;
	}

}

static int gtphub_send_del_pdp_ctx(struct gtphub *hub,
				   struct gtphub_tunnel *tun,
				   int to_side)
{
	static uint8_t del_ctx_msg[16] = {
		0x32,	/* GTP v1 flags */
		GTP_DELETE_PDP_REQ,
		0x00, 0x08, /* Length in network byte order */
		0x00, 0x00, 0x00, 0x00,	/* TEI to be replaced */
		0, 0,	/* Seq, to be replaced */
		0, 0,	/* no extensions */
		0x13, 0xff,  /* 19: Teardown ind = 1 */
		0x14, 0	/* 20: NSAPI = 0 */
	};

	uint32_t *tei = (uint32_t*)&del_ctx_msg[4];
	uint16_t *seq = (uint16_t*)&del_ctx_msg[8];

	struct gtphub_tunnel_endpoint *te =
		&tun->endpoint[to_side][GTPH_PLANE_CTRL];

	if (! te->peer)
		return 0;

	*tei = hton32(te->tei_orig);
	*seq = hton16(nr_pool_next(&te->peer->peer_addr->peer->seq_pool));

	struct gtphub_bind *to_bind = &hub->to_gsns[to_side][GTPH_PLANE_CTRL];
	int rc = gtphub_write(&to_bind->ofd, &te->peer->sa,
			      del_ctx_msg, sizeof(del_ctx_msg));
	if (rc != 0) {
		LOG(LOGL_ERROR,
		    "Failed to send out-of-band Delete PDP Context Request to %s\n",
		    gtphub_port_str(te->peer));
	}
	return rc;
}

/* Tell all peers on the other end of tunnels that PDP contexts are void. */
static void gtphub_restarted(struct gtphub *hub,
			     struct gtp_packet_desc *p,
			     struct gtphub_peer_port *pp)
{
	LOG(LOGL_NOTICE, "Peer has restarted: %s\n",
	    gtphub_port_str(pp));

	int deleted_count = 0;
	struct gtphub_tunnel *tun;
	llist_for_each_entry(tun, &hub->tunnels, entry) {
		int side_idx;
		for_each_side(side_idx) {
			struct gtphub_tunnel_endpoint *te = &tun->endpoint[side_idx][GTPH_PLANE_CTRL];
			struct gtphub_tunnel_endpoint *te2 = &tun->endpoint[other_side_idx(side_idx)][GTPH_PLANE_CTRL];
			if ((!te->peer)
			    || (!te2->tei_orig)
			    || (pp->peer_addr->peer != te->peer->peer_addr->peer))
				continue;

			LOG(LOGL_DEBUG, "Deleting tunnel due to peer restart: %s\n",
			    gtphub_tunnel_str(tun));
			deleted_count ++;

			/* Send a Delete PDP Context Request to the
			 * peer on the other side, remember the pending
			 * delete and wait for the response to delete
			 * the tunnel. Clear this side of the tunnel to
			 * make sure it isn't used.
			 *
			 * Should the delete message send fail, or if no
			 * response is received, this tunnel will expire. If
			 * its TEIs come up in a new PDP Context Request, it
			 * will be removed. If messages for this tunnel should
			 * come in (from the not restarted side), they will be
			 * dropped because the tunnel is rendered unusable. */
			gtphub_send_del_pdp_ctx(hub, tun, other_side_idx(side_idx));

			gtphub_tunnel_endpoint_set_peer(&tun->endpoint[side_idx][GTPH_PLANE_CTRL],
							NULL);
			gtphub_tunnel_endpoint_set_peer(&tun->endpoint[side_idx][GTPH_PLANE_USER],
							NULL);
		}
	}

	if (deleted_count)
		LOG(LOGL_NOTICE, "Deleting %d tunnels due to restart of: %s\n",
		    deleted_count,
		    gtphub_port_str(pp));
}

static int get_restart_count(struct gtp_packet_desc *p)
{
	int ie_idx;
	ie_idx = gtpie_getie(p->ie, GTPIE_RECOVERY, 0);
	if (ie_idx < 0)
		return -1;
	return ntoh8(p->ie[ie_idx]->tv1.v);
}

static void gtphub_check_restart_counter(struct gtphub *hub,
					 struct gtp_packet_desc *p,
					 struct gtphub_peer_port *from)
{
	/* If the peer is sending a Recovery IE (7.7.11) with a restart counter
	 * that doesn't match the peer's previously sent restart counter, clear
	 * that peer and cancel PDP contexts. */

	int restart = get_restart_count(p);

	if ((restart < 0) || (restart > 255))
		return;

	if ((from->last_restart_count >= 0) && (from->last_restart_count <= 255)) {
		if (from->last_restart_count != restart) {
			gtphub_restarted(hub, p, from);
		}
	}

	from->last_restart_count = restart;
}

static int from_sgsns_read_cb(struct osmo_fd *from_sgsns_ofd, unsigned int what)
{
	unsigned int plane_idx = from_sgsns_ofd->priv_nr;
	OSMO_ASSERT(plane_idx < GTPH_PLANE_N);
	LOG(LOGL_DEBUG, "=== reading from SGSN (%s)\n",
	    gtphub_plane_idx_names[plane_idx]);

	if (!(what & BSC_FD_READ))
		return 0;

	struct gtphub *hub = from_sgsns_ofd->data;

	static uint8_t buf[4096];
	struct osmo_sockaddr from_addr;
	struct osmo_sockaddr to_addr;
	struct osmo_fd *to_ofd;
	int len;
	uint8_t *reply_buf;

	len = gtphub_read(from_sgsns_ofd, &from_addr, buf, sizeof(buf));
	if (len < 1)
		return 0;

	len = gtphub_handle_buf(hub, GTPH_SIDE_SGSN, plane_idx, &from_addr,
				buf, len, gtphub_now(),
				&reply_buf, &to_ofd, &to_addr);
	if (len < 1)
		return 0;

	return gtphub_write(to_ofd, &to_addr, reply_buf, len);
}

static int from_ggsns_read_cb(struct osmo_fd *from_ggsns_ofd, unsigned int what)
{
	unsigned int plane_idx = from_ggsns_ofd->priv_nr;
	OSMO_ASSERT(plane_idx < GTPH_PLANE_N);
	LOG(LOGL_DEBUG, "=== reading from GGSN (%s)\n",
	    gtphub_plane_idx_names[plane_idx]);
	if (!(what & BSC_FD_READ))
		return 0;

	struct gtphub *hub = from_ggsns_ofd->data;

	static uint8_t buf[4096];
	struct osmo_sockaddr from_addr;
	struct osmo_sockaddr to_addr;
	struct osmo_fd *to_ofd;
	int len;
	uint8_t *reply_buf;

	len = gtphub_read(from_ggsns_ofd, &from_addr, buf, sizeof(buf));
	if (len < 1)
		return 0;

	len = gtphub_handle_buf(hub, GTPH_SIDE_GGSN, plane_idx, &from_addr,
				buf, len, gtphub_now(),
				&reply_buf, &to_ofd, &to_addr);
	if (len < 1)
		return 0;

	return gtphub_write(to_ofd, &to_addr, reply_buf, len);
}

static int gtphub_unmap(struct gtphub *hub,
			struct gtp_packet_desc *p,
			struct gtphub_peer_port *from,
			struct gtphub_peer_port *to_proxy,
			struct gtphub_peer_port **final_unmapped,
			struct gtphub_peer_port **unmapped_from_seq)
{
	/* Always (try to) unmap sequence and TEI numbers, which need to be
	 * replaced in the packet. Either way, give precedence to the proxy, if
	 * configured. */

	if (unmapped_from_seq)
		*unmapped_from_seq = NULL;
	if (final_unmapped)
		*final_unmapped = NULL;
	p->tun = NULL;

	struct gtphub_peer_port *from_seq = NULL;
	struct gtphub_peer_port *from_tei = NULL;
	struct gtphub_peer_port *unmapped = NULL;

	from_seq = gtphub_unmap_seq(p, from);

	if (gtphub_unmap_header_tei(&from_tei, &p->tun, hub, p, from) < 0)
		return -1;

	struct gtphub_peer *from_peer = from->peer_addr->peer;
	if (from_seq && from_tei && (from_seq != from_tei)) {
		LOG(LOGL_DEBUG,
		    "Seq unmap and TEI unmap yield two different peers."
		    " Using seq unmap."
		    " (from %s %s: seq %d yields %s, tei %u yields %s)\n",
		    gtphub_plane_idx_names[p->plane_idx],
		    gtphub_peer_str(from_peer),
		    (int)p->seq,
		    gtphub_port_str(from_seq),
		    (unsigned int)p->header_tei_rx,
		    gtphub_port_str2(from_tei)
		   );
	}
	unmapped = (from_seq? from_seq : from_tei);

	if (unmapped && to_proxy && (unmapped != to_proxy)) {
		LOG(LOGL_NOTICE,
		    "Unmap yields a different peer than the configured proxy."
		    " Using proxy."
		    " unmapped: %s  proxy: %s\n",
		    gtphub_port_str(unmapped),
		    gtphub_port_str2(to_proxy)
		   );
	}
	unmapped = (to_proxy? to_proxy : unmapped);

	if (!unmapped) {
		/* Return no error, but returned pointers are all NULL. */
		return 0;
	}

	if (unmapped_from_seq)
		*unmapped_from_seq = from_seq;
	if (final_unmapped)
		*final_unmapped = unmapped;
	return 0;
}

static int gsn_addr_to_sockaddr(struct gsn_addr *src,
				uint16_t port,
				struct osmo_sockaddr *dst)
{
	return osmo_sockaddr_init_udp(dst, gsn_addr_to_str(src), port);
}

/* If p is an Echo request, replace p's data with the matching response and
 * return 1. If p is no Echo request, return 0, or -1 if an invalid packet is
 * detected. */
static int gtphub_handle_echo_req(struct gtphub *hub, struct gtp_packet_desc *p,
				  uint8_t **reply_buf)
{
	if (p->type != GTP_ECHO_REQ)
		return 0;

	static uint8_t echo_response_data[14] = {
		0x32,	/* GTP v1 flags */
		GTP_ECHO_RSP,
		0x00, 14 - 8, /* Length in network byte order */
		0x00, 0x00, 0x00, 0x00,	/* Zero TEI */
		0, 0,	/* Seq, to be replaced */
		0, 0,	/* no extensions */
		0x0e,	/* Recovery IE */
		0	/* Restart counter, to be replaced */
	};
	uint16_t *seq = (uint16_t*)&echo_response_data[8];
	uint8_t *recovery = &echo_response_data[13];

	*seq = hton16(p->seq);
	*recovery = hub->restart_counter;

	*reply_buf = echo_response_data;

	return sizeof(echo_response_data);
}

struct gtphub_peer_port *gtphub_known_addr_have_port(const struct gtphub_bind *bind,
						     const struct osmo_sockaddr *addr);

/* Parse buffer as GTP packet, replace elements in-place and return the ofd and
 * address to forward to. Return a pointer to the osmo_fd, but copy the
 * sockaddr to *to_addr. The reason for this is that the sockaddr may expire at
 * any moment, while the osmo_fd is guaranteed to persist. Return the number of
 * bytes to forward, 0 or less on failure. */
int gtphub_handle_buf(struct gtphub *hub,
		      unsigned int side_idx,
		      unsigned int plane_idx,
		      const struct osmo_sockaddr *from_addr,
		      uint8_t *buf,
		      size_t received,
		      time_t now,
		      uint8_t **reply_buf,
		      struct osmo_fd **to_ofd,
		      struct osmo_sockaddr *to_addr)
{
	struct gtphub_bind *from_bind = &hub->to_gsns[side_idx][plane_idx];
	struct gtphub_bind *to_bind = &hub->to_gsns[other_side_idx(side_idx)][plane_idx];

	rate_ctr_add(&from_bind->counters_io->ctr[GTPH_CTR_BYTES_IN],
		     received);

	struct gtp_packet_desc p;
	gtp_decode(buf, received, side_idx, plane_idx, &p, now);

	LOG(LOGL_DEBUG, "%s rx %s from %s %s%s\n",
	    (side_idx == GTPH_SIDE_GGSN)? "<-" : "->",
	    gtphub_plane_idx_names[plane_idx],
	    gtphub_side_idx_names[side_idx],
	    osmo_sockaddr_to_str(from_addr),
	    gtp_type_str(p.type));

	if (p.rc <= 0) {
		LOG(LOGL_ERROR, "INVALID: dropping GTP packet%s from %s %s %s\n",
		    gtp_type_str(p.type),
		    gtphub_side_idx_names[side_idx],
		    gtphub_plane_idx_names[plane_idx],
		    osmo_sockaddr_to_str(from_addr));
		return -1;
	}

	rate_ctr_inc(&from_bind->counters_io->ctr[GTPH_CTR_PKTS_IN]);

	int reply_len;
	reply_len = gtphub_handle_echo_req(hub, &p, reply_buf);
	if (reply_len > 0) {
		/* It was an echo. Nothing left to do. */
		osmo_sockaddr_copy(to_addr, from_addr);
		*to_ofd = &from_bind->ofd;

		rate_ctr_inc(&from_bind->counters_io->ctr[GTPH_CTR_PKTS_OUT]);
		rate_ctr_add(&from_bind->counters_io->ctr[GTPH_CTR_BYTES_OUT],
			     reply_len);
		LOG(LOGL_DEBUG, "%s Echo response to %s: %d bytes to %s\n",
		    (side_idx == GTPH_SIDE_GGSN)? "-->" : "<--",
		    gtphub_side_idx_names[side_idx],
		    (int)reply_len, osmo_sockaddr_to_str(to_addr));
		return reply_len;
	}
	if (reply_len < 0)
		return -1;

	*to_ofd = &to_bind->ofd;

	/* If a proxy is configured, check that it's indeed that proxy talking
	 * to us. A proxy is a forced 1:1 connection, e.g. to another gtphub,
	 * so no-one else is allowed to talk to us from that side. */
	struct gtphub_peer_port *from_peer = hub->proxy[side_idx][plane_idx];
	if (from_peer) {
		if (osmo_sockaddr_cmp(&from_peer->sa, from_addr) != 0) {
			LOG(LOGL_ERROR,
			    "Rejecting: %s proxy configured, but GTP packet"
			    " received on %s bind is from another sender:"
			    " proxy: %s  sender: %s\n",
			    gtphub_side_idx_names[side_idx],
			    gtphub_side_idx_names[side_idx],
			    gtphub_port_str(from_peer),
			    osmo_sockaddr_to_str(from_addr));
			return -1;
		}
	}

	if (!from_peer) {
		/* Find or create a peer with a matching address. The sender's
		 * port may in fact differ. */
		from_peer = gtphub_known_addr_have_port(from_bind, from_addr);
	}

	/* If any PDP context has been created, we already have an entry for
	 * this GSN. If we don't have an entry, a GGSN has nothing to tell us
	 * about, while an SGSN may initiate a PDP context. */
	if (!from_peer) {
		if (side_idx == GTPH_SIDE_GGSN) {
			LOG(LOGL_ERROR, "Dropping packet%s: unknown GGSN peer: %s\n",
			    gtp_type_str(p.type),
			    osmo_sockaddr_to_str(from_addr));
			return -1;
		} else {
			/* SGSN */
			/* A new peer. If this is on the Ctrl plane, an SGSN
			 * may make first contact without being known yet, so
			 * create the peer struct for the current sender. */
			if (plane_idx != GTPH_PLANE_CTRL) {
				LOG(LOGL_ERROR,
				    "Dropping packet%s: User plane peer was not"
				    "announced by PDP Context: %s\n",
				    gtp_type_str(p.type),
				    osmo_sockaddr_to_str(from_addr));
				return -1;
			}

			struct gsn_addr from_gsna;
			uint16_t from_port;
			if (gsn_addr_from_sockaddr(&from_gsna, &from_port, from_addr) != 0)
				return -1;

			from_peer = gtphub_port_have(hub, from_bind, &from_gsna, from_port);
		}
	}

	if (!from_peer) {
		/* This could theoretically happen for invalid address data or
		 * somesuch. */
		LOG(LOGL_ERROR, "Dropping packet%s: invalid %s peer: %s\n",
		    gtp_type_str(p.type),
		    gtphub_side_idx_names[side_idx],
		    osmo_sockaddr_to_str(from_addr));
		return -1;
	}

	rate_ctr_add(&from_peer->counters_io->ctr[GTPH_CTR_BYTES_IN],
		     received);
	rate_ctr_inc(&from_peer->counters_io->ctr[GTPH_CTR_PKTS_IN]);

	LOG(LOGL_DEBUG, "from %s peer: %s\n", gtphub_side_idx_names[side_idx],
	    gtphub_port_str(from_peer));

	gtphub_check_restart_counter(hub, &p, from_peer);
	gtphub_map_restart_counter(hub, &p);

	struct gtphub_peer_port *to_peer_from_seq;
	struct gtphub_peer_port *to_peer;
	if (gtphub_unmap(hub, &p, from_peer,
			 hub->proxy[other_side_idx(side_idx)][plane_idx],
			 &to_peer, &to_peer_from_seq)
	    != 0) {
		return -1;
	}

	if (p.tun) {
		struct gtphub_tunnel_endpoint *te = &p.tun->endpoint[p.side_idx][p.plane_idx];
		rate_ctr_add(&te->counters_io->ctr[GTPH_CTR_BYTES_IN],
			     received);
		rate_ctr_inc(&te->counters_io->ctr[GTPH_CTR_PKTS_IN]);
	}

	if ((!to_peer) && (side_idx == GTPH_SIDE_SGSN)) {
		if (gtphub_resolve_ggsn(hub, &p, &to_peer) < 0)
			return -1;
	}

	if (!to_peer && p.tun && p.type == GTP_DELETE_PDP_RSP) {
		/* It's a delete confirmation for a tunnel that is partly
		 * invalid, probably marked unsuable due to a restarted peer.
		 * Remove the tunnel and be happy without forwarding. */
		expiring_item_del(&p.tun->expiry_entry);
		p.tun = NULL;
		return 0;
	}

	if (!to_peer) {
		LOG(LOGL_ERROR, "No %s to send to. Dropping packet%s"
		    " (type=%" PRIu8 ", header-TEI=%" PRIx32 ", seq=%" PRIx16 ").\n",
		    gtphub_side_idx_names[other_side_idx(side_idx)],
		    gtp_type_str(p.type),
		    p.type, p.header_tei_rx, p.seq
		    );
		return -1;
	}

	if (plane_idx == GTPH_PLANE_CTRL) {
		/* This may be a Create PDP Context response. If it is, there
		 * are other addresses in the GTP message to set up apart from
		 * the sender. */
		if (gtphub_handle_pdp_ctx(hub, &p, from_peer, to_peer)
		    != 0)
			return -1;
	}
	
	/* Either to_peer was resolved from an existing tunnel,
	 * or a PDP Ctx and thus a tunnel has just been created,
	 * or the tunnel has been deleted due to this message. */
	OSMO_ASSERT(p.tun || (p.type == GTP_DELETE_PDP_RSP));

	/* If the GGSN is replying to an SGSN request, the sequence nr has
	 * already been unmapped above (to_peer_from_seq != NULL), and we need not
	 * create a new mapping. */
	if (!to_peer_from_seq)
		gtphub_map_seq(&p, from_peer, to_peer);

	osmo_sockaddr_copy(to_addr, &to_peer->sa);

	*reply_buf = (uint8_t*)p.data;

	if (received) {
		rate_ctr_inc(&to_bind->counters_io->ctr[GTPH_CTR_PKTS_OUT]);
		rate_ctr_add(&to_bind->counters_io->ctr[GTPH_CTR_BYTES_OUT],
			     received);

		rate_ctr_inc(&to_peer->counters_io->ctr[GTPH_CTR_PKTS_OUT]);
		rate_ctr_add(&to_peer->counters_io->ctr[GTPH_CTR_BYTES_OUT],
			     received);
	}

	if (p.tun) {
		struct gtphub_tunnel_endpoint *te = &p.tun->endpoint[other_side_idx(p.side_idx)][p.plane_idx];
		rate_ctr_inc(&te->counters_io->ctr[GTPH_CTR_PKTS_OUT]);
		rate_ctr_add(&te->counters_io->ctr[GTPH_CTR_BYTES_OUT],
			     received);
	}

	LOG(LOGL_DEBUG, "%s Forward to %s:"
	    " header-TEI %" PRIx32", seq %" PRIx16", %d bytes to %s\n",
	    (side_idx == GTPH_SIDE_SGSN)? "-->" : "<--",
	    gtphub_side_idx_names[other_side_idx(side_idx)],
	    p.header_tei, p.seq,
	    (int)received, osmo_sockaddr_to_str(to_addr));
	return received;
}

static void resolved_gssn_del_cb(struct expiring_item *expi)
{
	struct gtphub_resolved_ggsn *ggsn;
	ggsn = container_of(expi, struct gtphub_resolved_ggsn, expiry_entry);

	gtphub_port_ref_count_dec(ggsn->peer);
	llist_del(&ggsn->entry);

	ggsn->expiry_entry.del_cb = 0;
	expiring_item_del(&ggsn->expiry_entry);

	talloc_free(ggsn);
}

void gtphub_resolved_ggsn(struct gtphub *hub, const char *apn_oi_str,
			  struct gsn_addr *resolved_addr,
			  time_t now)
{
	struct gtphub_peer_port *pp;
	struct gtphub_resolved_ggsn *ggsn;

	LOG(LOGL_DEBUG, "Resolved GGSN callback: %s %s\n",
	    apn_oi_str, osmo_hexdump((unsigned char*)resolved_addr,
				     sizeof(*resolved_addr)));

	pp = gtphub_port_have(hub, &hub->to_gsns[GTPH_SIDE_GGSN][GTPH_PLANE_CTRL],
			      resolved_addr, 2123);
	if (!pp) {
		LOG(LOGL_ERROR, "Internal: Cannot create/find peer '%s'\n",
		    gsn_addr_to_str(resolved_addr));
		return;
	}

	ggsn = talloc_zero(osmo_gtphub_ctx, struct gtphub_resolved_ggsn);
	OSMO_ASSERT(ggsn);
	INIT_LLIST_HEAD(&ggsn->entry);
	expiring_item_init(&ggsn->expiry_entry);

	ggsn->peer = pp;
	gtphub_port_ref_count_inc(pp);

	osmo_strlcpy(ggsn->apn_oi_str, apn_oi_str, sizeof(ggsn->apn_oi_str));

	ggsn->expiry_entry.del_cb = resolved_gssn_del_cb;
	expiry_add(&hub->expire_slowly, &ggsn->expiry_entry, now);

	llist_add(&ggsn->entry, &hub->resolved_ggsns);
}

static int gtphub_gc_peer_port(struct gtphub_peer_port *pp)
{
	return pp->ref_count == 0;
}

static int gtphub_gc_peer_addr(struct gtphub_peer_addr *pa)
{
	struct gtphub_peer_port *pp, *npp;
	llist_for_each_entry_safe(pp, npp, &pa->ports, entry) {
		if (gtphub_gc_peer_port(pp)) {
			LOG(LOGL_DEBUG, "expired: peer %s\n",
			    gtphub_port_str(pp));
			gtphub_peer_port_del(pp);
		}
	}
	return llist_empty(&pa->ports);
}

static int gtphub_gc_peer(struct gtphub_peer *p)
{
	struct gtphub_peer_addr *pa, *npa;
	llist_for_each_entry_safe(pa, npa, &p->addresses, entry) {
		if (gtphub_gc_peer_addr(pa)) {
			gtphub_peer_addr_del(pa);
		}
	}

	/* Note that there's a ref_count in each gtphub_peer_port instance
	 * listed within p->addresses, referenced by TEI mappings from
	 * hub->tei_map. As long as those don't expire, this peer will stay. */

	return llist_empty(&p->addresses)
		&& nr_map_empty(&p->seq_map);
}

static void gtphub_gc_bind(struct gtphub_bind *b)
{
	struct gtphub_peer *p, *n;
	llist_for_each_entry_safe(p, n, &b->peers, entry) {
		if (gtphub_gc_peer(p)) {
			gtphub_peer_del(p);
		}
	}
}

void gtphub_gc(struct gtphub *hub, time_t now)
{
	int expired;
	expired = expiry_tick(&hub->expire_quickly, now);
	expired += expiry_tick(&hub->expire_slowly, now);

	/* ... */

	if (expired) {
		int s, p;
		for_each_side_and_plane(s, p) {
			gtphub_gc_bind(&hub->to_gsns[s][p]);
		}
	}
}

static void gtphub_gc_cb(void *data)
{
	struct gtphub *hub = data;
	gtphub_gc(hub, gtphub_now());
	osmo_timer_schedule(&hub->gc_timer, GTPH_GC_TICK_SECONDS, 0);
}

static void gtphub_gc_start(struct gtphub *hub)
{
	osmo_timer_setup(&hub->gc_timer, gtphub_gc_cb, hub);
	osmo_timer_schedule(&hub->gc_timer, GTPH_GC_TICK_SECONDS, 0);
}

/* called by unit tests */
void gtphub_init(struct gtphub *hub)
{
	gtphub_zero(hub);

	INIT_LLIST_HEAD(&hub->tunnels);
	INIT_LLIST_HEAD(&hub->pending_deletes);

	expiry_init(&hub->expire_quickly, GTPH_EXPIRE_QUICKLY_SECS);
	expiry_init(&hub->expire_slowly, GTPH_EXPIRE_SLOWLY_MINUTES * 60);

	nr_pool_init(&hub->tei_pool, 1, 0xffffffff);

	int side_idx;
	int plane_idx;
	for_each_side_and_plane(side_idx, plane_idx) {
		gtphub_bind_init(&hub->to_gsns[side_idx][plane_idx]);
	}

	hub->to_gsns[GTPH_SIDE_SGSN][GTPH_PLANE_CTRL].label = "SGSN Ctrl";
	hub->to_gsns[GTPH_SIDE_GGSN][GTPH_PLANE_CTRL].label = "GGSN Ctrl";
	hub->to_gsns[GTPH_SIDE_SGSN][GTPH_PLANE_USER].label = "SGSN User";
	hub->to_gsns[GTPH_SIDE_GGSN][GTPH_PLANE_USER].label = "GGSN User";
}

/* For the test suite, this is kept separate from gtphub_stop(), which also
 * closes sockets. The test suite avoids using sockets and would cause
 * segfaults when trying to close uninitialized ofds. */
void gtphub_free(struct gtphub *hub)
{
	/* By expiring all mappings, a garbage collection should free
	 * everything else. A gtphub_bind_free() will assert that everything is
	 * indeed empty. */
	expiry_clear(&hub->expire_quickly);
	expiry_clear(&hub->expire_slowly);

	int side_idx;
	int plane_idx;
	for_each_side_and_plane(side_idx, plane_idx) {
		gtphub_gc_bind(&hub->to_gsns[side_idx][plane_idx]);
		gtphub_bind_free(&hub->to_gsns[side_idx][plane_idx]);
	}
}

void gtphub_stop(struct gtphub *hub)
{
	int side_idx;
	int plane_idx;
	for_each_side_and_plane(side_idx, plane_idx) {
		gtphub_bind_stop(&hub->to_gsns[side_idx][plane_idx]);
	}
	gtphub_free(hub);
}

static int gtphub_make_proxy(struct gtphub *hub,
			     struct gtphub_peer_port **pp,
			     struct gtphub_bind *bind,
			     const struct gtphub_cfg_addr *addr)
{
	if (!addr->addr_str)
		return 0;

	struct gsn_addr gsna;
	if (gsn_addr_from_str(&gsna, addr->addr_str) != 0)
		return -1;

	*pp = gtphub_port_have(hub, bind, &gsna, addr->port);

	/* This is *the* proxy. Make sure it is never expired. */
	gtphub_port_ref_count_inc(*pp);
	return 0;
}

int gtphub_start(struct gtphub *hub, struct gtphub_cfg *cfg,
		 uint8_t restart_counter)
{
	gtphub_init(hub);

	hub->restart_counter = restart_counter;
	hub->sgsn_use_sender = cfg->sgsn_use_sender? 1 : 0;

	/* If a Ctrl plane proxy is configured, ares will never be used. */
	if (!cfg->proxy[GTPH_SIDE_GGSN][GTPH_PLANE_CTRL].addr_str) {
		if (gtphub_ares_init(hub) != 0) {
			LOG(LOGL_FATAL, "Failed to initialize ares\n");
			return -1;
		}
	}

	int side_idx;
	int plane_idx;
	for_each_side_and_plane(side_idx, plane_idx) {
		int rc;
		rc = gtphub_bind_start(&hub->to_gsns[side_idx][plane_idx],
				       &cfg->to_gsns[side_idx][plane_idx],
				       (side_idx == GTPH_SIDE_SGSN)
					       ? from_sgsns_read_cb
					       : from_ggsns_read_cb,
				       hub, plane_idx);
		if (rc) {
			LOG(LOGL_FATAL, "Failed to bind for %ss (%s)\n",
			    gtphub_side_idx_names[side_idx],
			    gtphub_plane_idx_names[plane_idx]);
			return rc;
		}
	}

	for_each_side_and_plane(side_idx, plane_idx) {
		if (gtphub_make_proxy(hub,
				      &hub->proxy[side_idx][plane_idx],
				      &hub->to_gsns[side_idx][plane_idx],
				      &cfg->proxy[side_idx][plane_idx])
		    != 0) {
			LOG(LOGL_FATAL, "Cannot configure %s proxy"
			    " %s port %d.\n",
			    gtphub_side_idx_names[side_idx],
			    cfg->proxy[side_idx][plane_idx].addr_str,
			    (int)cfg->proxy[side_idx][plane_idx].port);
			return -1;
		}
	}

	for_each_side_and_plane(side_idx, plane_idx) {
		if (hub->proxy[side_idx][plane_idx])
			LOG(LOGL_NOTICE, "Using %s %s proxy %s\n",
			    gtphub_side_idx_names[side_idx],
			    gtphub_plane_idx_names[plane_idx],
			    gtphub_port_str(hub->proxy[side_idx][plane_idx]));
	}

	if (hub->sgsn_use_sender)
		LOG(LOGL_NOTICE, "Using sender address and port for SGSN instead of GSN Addr IE and default ports.\n");

	gtphub_gc_start(hub);
	return 0;
}

static struct gtphub_peer_addr *gtphub_peer_find_addr(const struct gtphub_peer *peer,
						      const struct gsn_addr *addr)
{
	struct gtphub_peer_addr *a;
	llist_for_each_entry(a, &peer->addresses, entry) {
		if (gsn_addr_same(&a->addr, addr))
			return a;
	}
	return NULL;
}

static struct gtphub_peer_port *gtphub_addr_find_port(const struct gtphub_peer_addr *a,
						      uint16_t port)
{
	OSMO_ASSERT(port);
	struct gtphub_peer_port *pp;
	llist_for_each_entry(pp, &a->ports, entry) {
		if (pp->port == port)
			return pp;
	}
	return NULL;
}

static struct gtphub_peer_addr *gtphub_addr_find(const struct gtphub_bind *bind,
						 const struct gsn_addr *addr)
{
	struct gtphub_peer *peer;
	llist_for_each_entry(peer, &bind->peers, entry) {
		struct gtphub_peer_addr *a = gtphub_peer_find_addr(peer, addr);
		if (a)
			return a;
	}
	return NULL;
}

static struct gtphub_peer_port *gtphub_port_find(const struct gtphub_bind *bind,
						 const struct gsn_addr *addr,
						 uint16_t port)
{
	struct gtphub_peer_addr *a = gtphub_addr_find(bind, addr);
	if (!a)
		return NULL;
	return gtphub_addr_find_port(a, port);
}

struct gtphub_peer_port *gtphub_port_find_sa(const struct gtphub_bind *bind,
					     const struct osmo_sockaddr *addr)
{
	struct gsn_addr gsna;
	uint16_t port;
	gsn_addr_from_sockaddr(&gsna, &port, addr);
	return gtphub_port_find(bind, &gsna, port);
}

static struct gtphub_peer *gtphub_peer_new(struct gtphub *hub,
					   struct gtphub_bind *bind)
{
	struct gtphub_peer *peer = talloc_zero(osmo_gtphub_ctx,
					       struct gtphub_peer);
	OSMO_ASSERT(peer);

	INIT_LLIST_HEAD(&peer->addresses);

	nr_pool_init(&peer->seq_pool, 0, 0xffff);
	nr_map_init(&peer->seq_map, &peer->seq_pool, &hub->expire_quickly);

	/* TODO use something random to pick the initial sequence nr.
	   0x6d31 produces the ASCII character sequence 'm1', currently used in
	   gtphub_nc_test.sh. */
	peer->seq_pool.last_nr = 0x6d31 - 1;

	llist_add(&peer->entry, &bind->peers);
	return peer;
}

static struct gtphub_peer_addr *gtphub_peer_add_addr(struct gtphub_peer *peer,
						     const struct gsn_addr *addr)
{
	struct gtphub_peer_addr *a;
	a = talloc_zero(osmo_gtphub_ctx, struct gtphub_peer_addr);
	OSMO_ASSERT(a);
	a->peer = peer;
	gsn_addr_copy(&a->addr, addr);
	INIT_LLIST_HEAD(&a->ports);
	llist_add(&a->entry, &peer->addresses);

	return a;
}

static struct gtphub_peer_addr *gtphub_addr_have(struct gtphub *hub,
						 struct gtphub_bind *bind,
						 const struct gsn_addr *addr)
{
	struct gtphub_peer_addr *a = gtphub_addr_find(bind, addr);
	if (a)
		return a;

	/* If we haven't found an address, that means we need to create an
	 * entirely new peer for the new address. More addresses may be added
	 * to this peer later, but not via this function. */
	struct gtphub_peer *peer = gtphub_peer_new(hub, bind);

	a = gtphub_peer_add_addr(peer, addr);
	
	LOG(LOGL_DEBUG, "New peer address: %s %s\n",
	    bind->label,
	    gsn_addr_to_str(&a->addr));

	return a;
}

static struct gtphub_peer_port *gtphub_addr_add_port(struct gtphub_peer_addr *a,
						     uint16_t port)
{
	struct gtphub_peer_port *pp;

	pp = talloc_zero(osmo_gtphub_ctx, struct gtphub_peer_port);
	OSMO_ASSERT(pp);
	pp->peer_addr = a;
	pp->port = port;
	pp->last_restart_count = -1;

	if (gsn_addr_to_sockaddr(&a->addr, port, &pp->sa) != 0) {
		talloc_free(pp);
		return NULL;
	}

	pp->counters_io = rate_ctr_group_alloc(osmo_gtphub_ctx,
					       &gtphub_ctrg_io_desc, 0);

	llist_add(&pp->entry, &a->ports);

	LOG(LOGL_DEBUG, "New peer port: %s port %d\n",
	    gsn_addr_to_str(&a->addr),
	    (int)port);

	return pp;
}

struct gtphub_peer_port *gtphub_port_have(struct gtphub *hub,
					  struct gtphub_bind *bind,
					  const struct gsn_addr *addr,
					  uint16_t port)
{
	struct gtphub_peer_addr *a = gtphub_addr_have(hub, bind, addr);

	struct gtphub_peer_port *pp = gtphub_addr_find_port(a, port);
	if (pp)
		return pp;

	return gtphub_addr_add_port(a, port);
}

/* Find a GGSN peer with a matching address. If the address is known but the
 * port not, create a new port for that peer address. */
struct gtphub_peer_port *gtphub_known_addr_have_port(const struct gtphub_bind *bind,
						     const struct osmo_sockaddr *addr)
{
	struct gtphub_peer_addr *pa;
	struct gtphub_peer_port *pp;

	struct gsn_addr gsna;
	uint16_t port;
	gsn_addr_from_sockaddr(&gsna, &port, addr);

	pa = gtphub_addr_find(bind, &gsna);
	if (!pa)
		return NULL;

	pp = gtphub_addr_find_port(pa, port);

	if (!pp)
		pp = gtphub_addr_add_port(pa, port);

	return pp;
}


/* Return 0 if the message in p is not applicable for GGSN resolution, -1 if
 * resolution should be possible but failed, and 1 if resolution was
 * successful. *pp will be set to NULL if <1 is returned. */
static int gtphub_resolve_ggsn(struct gtphub *hub,
			       struct gtp_packet_desc *p,
			       struct gtphub_peer_port **pp)
{
	*pp = NULL;

	/* TODO determine from message type whether IEs should be present? */

	int rc;
	const char *imsi_str;
	rc = get_ie_imsi_str(p->ie, 0, &imsi_str);
	if (rc < 1)
		return rc;
	OSMO_ASSERT(imsi_str);

	const char *apn_str;
	rc = get_ie_apn_str(p->ie, &apn_str);
	if (rc < 1)
		return rc;
	OSMO_ASSERT(apn_str);

	*pp = gtphub_resolve_ggsn_addr(hub, imsi_str, apn_str);
	return (*pp)? 1 : -1;
}


/* TODO move to osmocom/core/socket.c ? */
/* use this in osmo_sock_init() to remove dup. */
/* Internal: call getaddrinfo for osmo_sockaddr_init(). The caller is required
   to call freeaddrinfo(*result), iff zero is returned. */
static int _osmo_getaddrinfo(struct addrinfo **result,
			     uint16_t family, uint16_t type, uint8_t proto,
			     const char *host, uint16_t port)
{
	struct addrinfo hints;
	char portbuf[16];

	sprintf(portbuf, "%u", port);
	memset(&hints, '\0', sizeof(struct addrinfo));
	hints.ai_family = family;
	if (type == SOCK_RAW) {
		/* Workaround for glibc, that returns EAI_SERVICE (-8) if
		 * SOCK_RAW and IPPROTO_GRE is used.
		 */
		hints.ai_socktype = SOCK_DGRAM;
		hints.ai_protocol = IPPROTO_UDP;
	} else {
		hints.ai_socktype = type;
		hints.ai_protocol = proto;
	}

	return getaddrinfo(host, portbuf, &hints, result);
}

/* TODO move to osmocom/core/socket.c ? */
int osmo_sockaddr_init(struct osmo_sockaddr *addr,
		       uint16_t family, uint16_t type, uint8_t proto,
		       const char *host, uint16_t port)
{
	struct addrinfo *res;
	int rc;
	rc = _osmo_getaddrinfo(&res, family, type, proto, host, port);

	if (rc != 0) {
		LOG(LOGL_ERROR, "getaddrinfo returned error %d\n", (int)rc);
		return -EINVAL;
	}

	OSMO_ASSERT(res->ai_addrlen <= sizeof(addr->a));
	memcpy(&addr->a, res->ai_addr, res->ai_addrlen);
	addr->l = res->ai_addrlen;
	freeaddrinfo(res);

	return 0;
}

int osmo_sockaddr_to_strs(char *addr_str, size_t addr_str_len,
			  char *port_str, size_t port_str_len,
			  const struct osmo_sockaddr *addr,
			  int flags)
{
       int rc;

       if ((addr->l < 1) || (addr->l > sizeof(addr->a))) {
	       LOGP(DGTPHUB, LOGL_ERROR, "Invalid address size: %d\n", addr->l);
	       return -1;
       }

       if (addr->l > sizeof(addr->a)) {
	       LOGP(DGTPHUB, LOGL_ERROR, "Invalid address: too long: %d\n",
		    addr->l);
	       return -1;
       }

       rc = getnameinfo((struct sockaddr*)&addr->a, addr->l,
			addr_str, addr_str_len,
			port_str, port_str_len,
			flags);

       if (rc)
	       LOGP(DGTPHUB, LOGL_ERROR, "Invalid address: %s: %s\n",
		    gai_strerror(rc), osmo_hexdump((uint8_t*)&addr->a,
						   addr->l));

       return rc;
}

const char *osmo_sockaddr_to_strb(const struct osmo_sockaddr *addr,
				  char *buf, size_t buf_len)
{
	const int portbuf_len = 6;
	OSMO_ASSERT(buf_len > portbuf_len);
	char *portbuf = buf + buf_len - portbuf_len;
	buf_len -= portbuf_len;
	if (osmo_sockaddr_to_strs(buf, buf_len,
				  portbuf, portbuf_len,
				  addr,
				  NI_NUMERICHOST | NI_NUMERICSERV))
		return NULL;

	char *pos = buf + strnlen(buf, buf_len-1);
	size_t len = buf_len - (pos - buf);

	snprintf(pos, len, " port %s", portbuf);
	buf[buf_len-1] = '\0';

	return buf;
}

const char *osmo_sockaddr_to_str(const struct osmo_sockaddr *addr)
{
	static char buf[256];
	const char *result = osmo_sockaddr_to_strb(addr, buf, sizeof(buf));
	if (! result)
		return "(invalid)";
	return result;
}

int osmo_sockaddr_cmp(const struct osmo_sockaddr *a,
		      const struct osmo_sockaddr *b)
{
	if (a == b)
		return 0;
	if (!a)
		return -1;
	if (!b)
		return 1;
	if (a->l != b->l) {
		/* Lengths are not the same, but determine the order. Will
		 * anyone ever sort a list by osmo_sockaddr though...? */
		int cmp = memcmp(&a->a, &b->a, (a->l < b->l)? a->l : b->l);
		if (cmp == 0) {
			if (a->l < b->l)
				return -1;
			else
				return 1;
		}
		return cmp;
	}
	return memcmp(&a->a, &b->a, a->l);
}

void osmo_sockaddr_copy(struct osmo_sockaddr *dst,
			const struct osmo_sockaddr *src)
{
	OSMO_ASSERT(src->l <= sizeof(dst->a));
	memcpy(&dst->a, &src->a, src->l);
	dst->l = src->l;
}
