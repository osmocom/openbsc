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

#pragma once

#include <stdint.h>
#include <sys/socket.h>

#include <osmocom/core/select.h>
#include <osmocom/core/timer.h>
#include <osmocom/core/rate_ctr.h>

#include <openbsc/gprs_sgsn.h>


/* support */

/* TODO move to osmocom/core/socket.c ? */
#include <netdb.h> /* for IPPROTO_* etc */
struct osmo_sockaddr {
	struct sockaddr_storage a;
	socklen_t l;
};

/* TODO move to osmocom/core/socket.c ? */
/*! \brief Initialize a sockaddr
 * \param[out] addr  Valid osmo_sockaddr pointer to write result to
 * \param[in] family  Address Family like AF_INET, AF_INET6, AF_UNSPEC
 * \param[in] type  Socket type like SOCK_DGRAM, SOCK_STREAM
 * \param[in] proto  Protocol like IPPROTO_TCP, IPPROTO_UDP
 * \param[in] host Remote host name or IP address in string form
 * \param[in] port Remote port number in host byte order
 * \returns 0 on success, otherwise an error code (from getaddrinfo()).
 *
 * Copy the first result from a getaddrinfo() call with the given parameters to
 * *addr and *addr_len. On error, do not change *addr and return nonzero.
 */
int osmo_sockaddr_init(struct osmo_sockaddr *addr,
		       uint16_t family, uint16_t type, uint8_t proto,
		       const char *host, uint16_t port);

/* Conveniently pass AF_UNSPEC, SOCK_DGRAM and IPPROTO_UDP to
 * osmo_sockaddr_init(). */
static inline int osmo_sockaddr_init_udp(struct osmo_sockaddr *addr,
					 const char *host, uint16_t port)
{
	return osmo_sockaddr_init(addr, AF_UNSPEC, SOCK_DGRAM, IPPROTO_UDP,
				  host, port);
}

/*! \brief convert sockaddr to human readable string.
 * \param[out] addr_str  Valid pointer to a buffer of length addr_str_len.
 * \param[in] addr_str_len  Size of buffer addr_str points at.
 * \param[out] port_str  Valid pointer to a buffer of length port_str_len.
 * \param[in] port_str_len  Size of buffer port_str points at.
 * \param[in] addr  Binary representation as returned by osmo_sockaddr_init().
 * \param[in] flags  flags as passed to getnameinfo().
 * \returns  0 on success, an error code on error.
 *
 * Return the IPv4 or IPv6 address string and the port (a.k.a. service) string
 * representations of the given struct osmo_sockaddr in two caller provided
 * char buffers. Flags of (NI_NUMERICHOST | NI_NUMERICSERV) return numeric
 * address and port. Either one of addr_str or port_str may be NULL, in which
 * case nothing is returned there.
 *
 * See also osmo_sockaddr_to_str() (less flexible, but much more convenient). */
int osmo_sockaddr_to_strs(char *addr_str, size_t addr_str_len,
			  char *port_str, size_t port_str_len,
			  const struct osmo_sockaddr *addr,
			  int flags);


/*! \brief concatenate the parts returned by osmo_sockaddr_to_strs().
 * \param[in] addr  Binary representation as returned by osmo_sockaddr_init().
 * \param[in] buf  A buffer to use for string operations.
 * \param[in] buf_len  Length of the buffer.
 * \returns  Address string (in buffer).
 *
 * Compose a string of the numeric IP-address and port represented by *addr of
 * the form "<ip-addr> port <port>". The returned string is valid until the
 * next invocation of this function.
 */
const char *osmo_sockaddr_to_strb(const struct osmo_sockaddr *addr,
				  char *buf, size_t buf_len);

/*! \brief conveniently return osmo_sockaddr_to_strb() in a static buffer.
 * \param[in] addr  Binary representation as returned by osmo_sockaddr_init().
 * \returns  Address string in static buffer.
 *
 * See osmo_sockaddr_to_strb().
 *
 * Note: only one osmo_sockaddr_to_str() call will work per print/log
 * statement. For two or more, use osmo_sockaddr_to_strb() with a separate
 * buffer each.
 */
const char *osmo_sockaddr_to_str(const struct osmo_sockaddr *addr);

/*! \brief compare two osmo_sockaddr.
 * \param[in] a  The first address to compare.
 * \param[in] b  The other address to compare.
 * \returns 0 if equal, otherwise -1 or 1.
 */
int osmo_sockaddr_cmp(const struct osmo_sockaddr *a,
		      const struct osmo_sockaddr *b);

/*! \brief Overwrite *dst with *src.
 * Like memcpy(), but copy only the valid bytes. */
void osmo_sockaddr_copy(struct osmo_sockaddr *dst,
			const struct osmo_sockaddr *src);


/* general */

enum gtphub_plane_idx {
	GTPH_PLANE_CTRL = 0,
	GTPH_PLANE_USER = 1,
	GTPH_PLANE_N
};

enum gtphub_side_idx {
	GTPH_SIDE_SGSN = 0,
	GTPH_SIDE_GGSN = 1,
	GTPH_SIDE_N
};

#define for_each_side(I)	for (I = 0; I < GTPH_SIDE_N; I++)
#define for_each_plane(I)	for (I = 0; I < GTPH_PLANE_N; I++)
#define for_each_side_and_plane(I,J)	for_each_side(I) for_each_plane(J)

static inline int other_side_idx(int side_idx)
{
	return (side_idx + 1) & 1;
}

extern const char* const gtphub_plane_idx_names[GTPH_PLANE_N];
extern const uint16_t gtphub_plane_idx_default_port[GTPH_PLANE_N];

extern const char* const gtphub_side_idx_names[GTPH_SIDE_N];

/* A host address in the form that is expected in the 7.7.32 GSN Address IE.
 * len is either 4 (IPv4) or 16 (IPv6), any other value is invalid. If no
 * address is set, len shall be 0. */
struct gsn_addr {
	uint16_t len;
	uint8_t buf[16];
};

void gsn_addr_copy(struct gsn_addr *gsna, const struct gsn_addr *src);
int gsn_addr_from_str(struct gsn_addr *gsna, const char *numeric_addr_str);

/* Return gsna in numeric string form, in a static buffer. */
const char *gsn_addr_to_str(const struct gsn_addr *gsna);

/* note: strbuf_len doesn't need to be larger than INET6_ADDRSTRLEN + 1. */
const char *gsn_addr_to_strb(const struct gsn_addr *gsna,
			     char *strbuf, int strbuf_len);

/* Return 1 on match, zero otherwise. */
int gsn_addr_same(const struct gsn_addr *a, const struct gsn_addr *b);

/* Decode sa to gsna. Return 0 on success. If port is non-NULL, the port number
 * from sa is also returned. */
int gsn_addr_from_sockaddr(struct gsn_addr *gsna, uint16_t *port,
			   const struct osmo_sockaddr *sa);

/* expiry */

struct expiring_item;
typedef void (*del_cb_t)(struct expiring_item *);

struct expiring_item {
	struct llist_head entry;
	time_t expiry;
	del_cb_t del_cb;
};

struct expiry {
	int expiry_in_seconds;
	struct llist_head items;
};

/* Initialize an expiry queue. */
void expiry_init(struct expiry *exq, int expiry_in_seconds);

/* Add a new mapping, or restart the expiry timeout for an already listed
 * mapping. */
void expiry_add(struct expiry *exq, struct expiring_item *item, time_t now);

/* Initialize to all-empty; must be called before using the item in any way. */
void expiring_item_init(struct expiring_item *item);

/* Remove the given item from its expiry queue, and call item->del_cb, if set.
 * This sets item->del_cb to NULL and is harmless when run a second time on the
 * same item, so the del_cb may choose to call this function, too, to allow
 * deleting items from several code paths. */
void expiring_item_del(struct expiring_item *item);

/* Carry out due expiry of mappings. Must be invoked regularly.
 * 'now' is the current clock count in seconds and must correspond to the clock
 * count passed to nr_map_add(). A monotonous clock counter should be used. */
int expiry_tick(struct expiry *exq, time_t now);

/* Expire all items. */
void expiry_clear(struct expiry *exq);


/* number map */

/* A number map assigns a "random" mapped number to each user provided number.
 * If the same number is requested multiple times, the same mapped number is
 * returned.
 *
 * Number maps plug into possibly shared pools and expiry queues, for example:
 *
 *     mapA -----------+-> pool1           <-+-- mapB
 *     {10->1, 11->5}  |   {1, 2, 3, ...}    |   {10->2, 11->3}
 *                     |                     |
 *                     |                     |
 *                 /-> \-> expiry1         <-/
 *                 |       (30 seconds)
 *                 |
 *     mapC -------+-----> pool2           <-+-- mapD
 *     {10->1, 11->3}      {1, 2, 3, ...}    |   {10->2, 11->5}
 *                                           |
 *                         expiry2         <-/
 *                         (60 seconds)
 *
 * A map contains mappings ("10->1"). Each map needs a number pool, which can
 * be shared with other maps. Each new mapping receives a number from the pool,
 * which is then unavailable to any other map using the same pool.
 *
 * A map may point at an expiry queue, in which case all mappings added to it
 * are also appended to the expiry queue (using a separate llist entry in the
 * mapping). Any number of maps may submit to the same expiry queue, if they
 * desire the same expiry timeout. An expiry queue stores the mappings in
 * chronological order, so that expiry checking is needed only from the start
 * of the queue; hence only mappings with identical expiry timeout can be added
 * to the same expiry queue. Upon expiry, a mapping is dropped from the map it
 * was submitted at. expiry_tick() needs to be called regularly for each expiry
 * queue.
 *
 * A nr_mapping can be embedded in a larger struct: each mapping can have a
 * distinct destructor (del_cb), and each del_cb can figure out the container
 * struct's address and free that upon expiry or manual deletion. So in expiry
 * queues (and even maps), mappings of different container types can be mixed.
 * This can help to drastically reduce the amount of unnecessary visits during
 * expiry checking, for the case that no expiry is pending. An expiry queue
 * always knows which mappings to expire next, because they are right at the
 * start of its list.
 *
 * Mapping allocation and a del_cb are provided by the caller. If del_cb is
 * NULL, no deallocation will be done (allowing statically allocated entries).
 */

typedef unsigned int nr_t;

/* Generator for unused numbers. So far this counts upwards from zero, but the
 * implementation may change in the future. Treat this like an opaque struct.
 * If this becomes random, the tests need to be fixed. */
struct nr_pool {
	nr_t last_nr;
	nr_t nr_min;
	nr_t nr_max;
};

struct nr_mapping {
	struct llist_head entry;
	struct expiring_item expiry_entry;

	void *origin;
	nr_t orig;
	nr_t repl;
};

struct nr_map {
	struct nr_pool *pool; /* multiple nr_maps can share a nr_pool. */
	struct expiry *add_items_to_expiry;
	struct llist_head mappings;
};


void nr_pool_init(struct nr_pool *pool, nr_t nr_min, nr_t nr_max);

/* Return the next unused number from the nr_pool. */
nr_t nr_pool_next(struct nr_pool *pool);

/* Initialize the nr_mapping to zero/empty values. */
void nr_mapping_init(struct nr_mapping *mapping);

/* Remove the given mapping from its parent map and expiry queue, and call
 * mapping->del_cb, if set. */
void nr_mapping_del(struct nr_mapping *mapping);

/* Initialize an (already allocated) nr_map, and set the map's number pool.
 * Multiple nr_map instances may use the same nr_pool. Set the nr_map's expiry
 * queue to exq, so that all added mappings are automatically expired after the
 * time configured in exq. exq may be NULL to disable automatic expiry. */
void nr_map_init(struct nr_map *map, struct nr_pool *pool,
		 struct expiry *exq);

/* Add a new entry to the map. mapping->orig, mapping->origin and
 * mapping->del_cb must be set before calling this function. The remaining
 * fields of *mapping will be overwritten. mapping->repl is set to the next
 * available mapped number from map->pool. 'now' is the current clock count in
 * seconds; if no map->expiry is used, just pass 0 for 'now'. */
void nr_map_add(struct nr_map *map, struct nr_mapping *mapping,
		time_t now);

/* Restart the timeout for the given mapping. mapping must be a member of map.
 */
void nr_map_refresh(struct nr_map *map, struct nr_mapping *mapping,
		    time_t now);

/* Return a known mapping from nr_orig and the given origin. If nr_orig is
 * unknown, return NULL. */
struct nr_mapping *nr_map_get(const struct nr_map *map,
			      void *origin, nr_t nr_orig);

/* Return a known mapping to nr_repl. If nr_repl is unknown, return NULL. */
struct nr_mapping *nr_map_get_inv(const struct nr_map *map, nr_t nr_repl);

/* Remove all mappings from map. */
void nr_map_clear(struct nr_map *map);

/* Return 1 if map has no entries, 0 otherwise. */
int nr_map_empty(const struct nr_map *map);


/* config */

static const int GTPH_EXPIRE_QUICKLY_SECS = 30; /* TODO is there a spec for this? */
static const int GTPH_EXPIRE_SLOWLY_MINUTES = 6 * 60; /* TODO is there a spec for this? */

struct gtphub_cfg_addr {
	const char *addr_str;
	uint16_t port;
};

struct gtphub_cfg_bind {
	struct gtphub_cfg_addr bind;
};

struct gtphub_cfg {
	struct gtphub_cfg_bind to_gsns[GTPH_SIDE_N][GTPH_PLANE_N];
	struct gtphub_cfg_addr proxy[GTPH_SIDE_N][GTPH_PLANE_N];
	int sgsn_use_sender; /* Use sender, not GSN addr IE with std ports */
};


/* state */

struct gtphub_peer {
	struct llist_head entry;

	struct llist_head addresses; /* Alternatives, not load balancing. */
	struct nr_pool seq_pool;
	struct nr_map seq_map;
};

struct gtphub_peer_addr {
	struct llist_head entry;

	struct gtphub_peer *peer;
	struct gsn_addr addr;
	struct llist_head ports;
};

struct gtphub_peer_port {
	struct llist_head entry;

	struct gtphub_peer_addr *peer_addr;
	uint16_t port;
	unsigned int ref_count; /* references from other peers' seq_maps */
	struct osmo_sockaddr sa; /* a "cache" for (peer_addr->addr, port) */
	int last_restart_count; /* 0..255 = valid, all else means unknown */

	struct rate_ctr_group *counters_io;
};

struct gtphub_tunnel_endpoint {
	struct gtphub_peer_port *peer;
	uint32_t tei_orig; /* from/to peer */

	struct rate_ctr_group *counters_io;
};

struct gtphub_tunnel {
	struct llist_head entry;
	struct expiring_item expiry_entry;

	uint32_t tei_repl; /* unique TEI to replace peers' TEIs */
	struct gtphub_tunnel_endpoint endpoint[GTPH_SIDE_N][GTPH_PLANE_N];
};

struct gtphub_bind {
	struct gsn_addr local_addr;
	uint16_t local_port;
	struct osmo_fd ofd;

	/* list of struct gtphub_peer */
	struct llist_head peers;

	const char *label; /* For logging */
	struct rate_ctr_group *counters_io;
};

struct gtphub_resolved_ggsn {
	struct llist_head entry;
	struct expiring_item expiry_entry;

	/* The APN OI, the Operator Identifier, is the combined address,
	 * including parts of the IMSI and APN NI, and ending with ".gprs". */
	char apn_oi_str[GSM_APN_LENGTH];

	/* Which address and port we resolved that to. */
	struct gtphub_peer_port *peer;
};

struct gtphub {
	struct gtphub_bind to_gsns[GTPH_SIDE_N][GTPH_PLANE_N];

	/* pointers to an entry of to_gsns[s][p].peers */
	struct gtphub_peer_port *proxy[GTPH_SIDE_N][GTPH_PLANE_N];

	/* The TEI numbers will simply wrap and be reused, which will work out
	 * in practice. Problems would arise if one given peer maintained the
	 * same TEI for a time long enough for the TEI nr map to wrap an entire
	 * uint32_t; if a new TEI were mapped every second, this would take
	 * more than 100 years (in which a single given TEI must not time out)
	 * to cause a problem. */
	struct nr_pool tei_pool;

	struct llist_head tunnels; /* struct gtphub_tunnel */
	struct llist_head pending_deletes; /* opaque (gtphub.c) */

	struct llist_head ggsn_lookups; /* opaque (gtphub_ares.c) */
	struct llist_head resolved_ggsns; /* struct gtphub_resolved_ggsn */

	struct osmo_timer_list gc_timer;
	struct expiry expire_quickly;
	struct expiry expire_slowly;

	uint8_t restart_counter;

	int sgsn_use_sender;
};

struct gtp_packet_desc;


/* api */

int gtphub_vty_init(struct gtphub *global_hub, struct gtphub_cfg *global_cfg);
int gtphub_cfg_read(struct gtphub_cfg *cfg, const char *config_file);

/* Initialize and start gtphub: bind to ports, run expiry timers. */
int gtphub_start(struct gtphub *hub, struct gtphub_cfg *cfg,
		 uint8_t restart_counter);

/* Close all sockets, expire all maps and peers and free all allocations. The
 * struct is then unusable, unless gtphub_start() is run on it again. */
void gtphub_stop(struct gtphub *hub);

time_t gtphub_now(void);

/* Remove expired items, empty peers, ... */
void gtphub_gc(struct gtphub *hub, time_t now);

/* Return the string of the first address for this peer. */
const char *gtphub_peer_str(struct gtphub_peer *peer);

/* Return a human readable description of tun in a static buffer. */
const char *gtphub_tunnel_str(struct gtphub_tunnel *tun);

/* Return 1 if all of tun's endpoints are fully established, 0 otherwise. */
int gtphub_tunnel_complete(struct gtphub_tunnel *tun);

int gtphub_handle_buf(struct gtphub *hub,
		      unsigned int side_idx,
		      unsigned int port_idx,
		      const struct osmo_sockaddr *from_addr,
		      uint8_t *buf,
		      size_t received,
		      time_t now,
		      uint8_t **reply_buf,
		      struct osmo_fd **to_ofd,
		      struct osmo_sockaddr *to_addr);

struct gtphub_peer_port *gtphub_port_have(struct gtphub *hub,
					  struct gtphub_bind *bind,
					  const struct gsn_addr *addr,
					  uint16_t port);

struct gtphub_peer_port *gtphub_port_find_sa(const struct gtphub_bind *bind,
					     const struct osmo_sockaddr *addr);

void gtphub_resolved_ggsn(struct gtphub *hub, const char *apn_oi_str,
			  struct gsn_addr *resolved_addr,
			  time_t now);

const char *gtphub_port_str(struct gtphub_peer_port *port);

int gtphub_write(const struct osmo_fd *to,
		 const struct osmo_sockaddr *to_addr,
		 const uint8_t *buf, size_t buf_len);
