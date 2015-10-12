/* A Media Gateway Control Protocol Media Gateway: RFC 3435 */

/*
 * (C) 2009-2012 by Holger Hans Peter Freyther <zecke@selfish.org>
 * (C) 2009-2012 by On-Waves
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
 *
 */

#ifndef OPENBSC_MGCP_H
#define OPENBSC_MGCP_H

#include <osmocom/core/msgb.h>
#include <osmocom/core/write_queue.h>
#include <osmocom/core/timer.h>

#include "debug.h"

#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

#define RTP_PORT_DEFAULT 4000
#define RTP_PORT_NET_DEFAULT 16000

/**
 * Calculate the RTP audio port for the given multiplex
 * and the direction. This allows a semi static endpoint
 * to port calculation removing the need for the BSC
 * and the MediaGateway to communicate.
 *
 * Port usage explained:
 *       base + (multiplex * 2) + 0 == local port to wait for network packets
 *       base + (multiplex * 2) + 1 == local port for rtcp
 *
 * The above port will receive packets from the BTS that need
 * to be patched and forwarded to the network.
 * The above port will receive packets from the network that
 * need to be patched and forwarded to the BTS.
 *
 * We assume to have a static BTS IP address so we can differentiate
 * network and BTS.
 *
 */
static inline int rtp_calculate_port(int multiplex, int base)
{
	return base + (multiplex * 2);
}


/*
 * Handling of MGCP Endpoints and the MGCP Config
 */
struct mgcp_endpoint;
struct mgcp_config;
struct mgcp_trunk_config;
struct mgcp_rtp_end;

#define MGCP_ENDP_CRCX 1
#define MGCP_ENDP_DLCX 2
#define MGCP_ENDP_MDCX 3

/*
 * what to do with the msg?
 *	- continue as usual?
 *	- reject and send a failure code?
 *	- defer? do not send anything
 */
#define MGCP_POLICY_CONT	4
#define MGCP_POLICY_REJECT	5
#define MGCP_POLICY_DEFER	6

typedef int (*mgcp_realloc)(struct mgcp_trunk_config *cfg, int endpoint);
typedef int (*mgcp_change)(struct mgcp_trunk_config *cfg, int endpoint, int state);
typedef int (*mgcp_policy)(struct mgcp_trunk_config *cfg, int endpoint, int state, const char *transactio_id);
typedef int (*mgcp_reset)(struct mgcp_trunk_config *cfg);
typedef int (*mgcp_rqnt)(struct mgcp_endpoint *endp, char tone);

/**
 * Return:
 *   <  0 in case no audio was processed
 *   >= 0 in case audio was processed. The remaining payload
 *   length will be returned.
 */
typedef int (*mgcp_processing)(struct mgcp_endpoint *endp,
			       struct mgcp_rtp_end *dst_end,
			       char *data, int *len, int buf_size);
typedef int (*mgcp_processing_setup)(struct mgcp_endpoint *endp,
				     struct mgcp_rtp_end *dst_end,
				     struct mgcp_rtp_end *src_end);

typedef void (*mgcp_get_format)(struct mgcp_endpoint *endp,
				int *payload_type,
				const char**subtype_name,
				const char**fmtp_extra);

#define PORT_ALLOC_STATIC	0
#define PORT_ALLOC_DYNAMIC	1

/**
 * This holds information on how to allocate ports
 */
struct mgcp_port_range {
	int mode;

	/* addr or NULL to fall-back to default */
	char *bind_addr;

	/* pre-allocated from a base? */
	int base_port;

	/* dynamically allocated */
	int range_start;
	int range_end;
	int last_port;
};

#define MGCP_KEEPALIVE_ONCE (-1)

struct mgcp_trunk_config {
	struct llist_head entry;

	struct mgcp_config *cfg;

	int trunk_nr;
	int trunk_type;

	char *audio_fmtp_extra;
	char *audio_name;
	int audio_payload;
	int audio_send_ptime;
	int audio_send_name;
	int audio_loop;

	int no_audio_transcoding;

	int omit_rtcp;
	int keepalive_interval;

	/* RTP patching */
	int force_constant_ssrc; /* 0: don't, 1: once */
	int force_aligned_timing;

	/* spec handling */
	int force_realloc;

	/* timer */
	struct osmo_timer_list keepalive_timer;

	unsigned int number_endpoints;
	struct mgcp_endpoint *endpoints;
};

enum mgcp_role {
	MGCP_BSC = 0,
	MGCP_BSC_NAT,
};

struct mgcp_config {
	int source_port;
	char *local_ip;
	char *source_addr;
	char *bts_ip;
	char *call_agent_addr;

	struct in_addr bts_in;

	/* transcoder handling */
	char *transcoder_ip;
	struct in_addr transcoder_in;
	int transcoder_remote_base;

	/* RTP processing */
	mgcp_processing rtp_processing_cb;
	mgcp_processing_setup setup_rtp_processing_cb;

	mgcp_get_format get_net_downlink_format_cb;

	struct osmo_wqueue gw_fd;

	struct mgcp_port_range bts_ports;
	struct mgcp_port_range net_ports;
	struct mgcp_port_range transcoder_ports;
	int endp_dscp;

	int bts_force_ptime;

	mgcp_change change_cb;
	mgcp_policy policy_cb;
	mgcp_reset reset_cb;
	mgcp_realloc realloc_cb;
	mgcp_rqnt rqnt_cb;
	void *data;

	uint32_t last_call_id;

	/* trunk handling */
	struct mgcp_trunk_config trunk;
	struct llist_head trunks;

	/* only used for start with a static configuration */
	int last_net_port;
	int last_bts_port;

	enum mgcp_role role;

	/* osmux translator: 0 means disabled, 1 means enabled */
	int osmux;
	/* addr to bind the server to */
	char *osmux_addr;
	/* The BSC-NAT may ask for enabling osmux on demand. This tells us if
	 * the osmux socket is already initialized.
	 */
	int osmux_init;
	/* osmux batch factor: from 1 to 4 maximum */
	int osmux_batch;
	/* osmux batch size (in bytes) */
	int osmux_batch_size;
	/* osmux port */
	uint16_t osmux_port;
	/* Pad circuit with dummy messages until we see the first voice
	 * message.
	 */
	uint16_t osmux_dummy;
};

/* config management */
struct mgcp_config *mgcp_config_alloc(void);
int mgcp_parse_config(const char *config_file, struct mgcp_config *cfg,
		      enum mgcp_role role);
int mgcp_vty_init(void);
int mgcp_endpoints_allocate(struct mgcp_trunk_config *cfg);
void mgcp_release_endp(struct mgcp_endpoint *endp);
void mgcp_initialize_endp(struct mgcp_endpoint *endp);
int mgcp_reset_transcoder(struct mgcp_config *cfg);
void mgcp_format_stats(struct mgcp_endpoint *endp, char *stats, size_t size);
int mgcp_parse_stats(struct msgb *msg, uint32_t *ps, uint32_t *os, uint32_t *pr, uint32_t *_or, int *loss, uint32_t *jitter);

void mgcp_trunk_set_keepalive(struct mgcp_trunk_config *tcfg, int interval);

/*
 * format helper functions
 */
struct msgb *mgcp_handle_message(struct mgcp_config *cfg, struct msgb *msg);

/* adc helper */
static inline int mgcp_timeslot_to_endpoint(int multiplex, int timeslot)
{
	if (timeslot == 0) {
		LOGP(DMGCP, LOGL_ERROR, "Timeslot should not be 0\n");
		timeslot = 255;
	}

	return timeslot + (32 * multiplex);
}

static inline void mgcp_endpoint_to_timeslot(int endpoint, int *multiplex, int *timeslot)
{
	*multiplex = endpoint / 32;
	*timeslot = endpoint % 32;
}

int mgcp_send_reset_ep(struct mgcp_endpoint *endp, int endpoint);
int mgcp_send_reset_all(struct mgcp_config *cfg);


int mgcp_create_bind(const char *source_addr, struct osmo_fd *fd, int port);
int mgcp_send(struct mgcp_endpoint *endp, int dest, int is_rtp, struct sockaddr_in *addr, char *buf, int rc);
int mgcp_udp_send(int fd, struct in_addr *addr, int port, char *buf, int len);

#endif
