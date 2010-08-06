/* A Media Gateway Control Protocol Media Gateway: RFC 3435 */

/*
 * (C) 2009-2010 by Holger Hans Peter Freyther <zecke@selfish.org>
 * (C) 2009-2010 by On-Waves
 * All Rights Reserved
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 */

#ifndef OPENBSC_MGCP_H
#define OPENBSC_MGCP_H

#include <osmocore/msgb.h>

#include <arpa/inet.h>

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

typedef int (*mgcp_change)(struct mgcp_config *cfg, int endpoint, int state);
typedef int (*mgcp_policy)(struct mgcp_config *cfg, int endpoint, int state, const char *transactio_id);
typedef int (*mgcp_reset)(struct mgcp_config *cfg);

#define PORT_ALLOC_STATIC	0
#define PORT_ALLOC_DYNAMIC	1

/**
 * This holds information on how to allocate ports
 */
struct mgcp_port_range {
	int mode;

	/* pre-allocated from a base? */
	int base_port;

	/* dynamically allocated */
	int range_start;
	int range_end;
	int last_port;
};

struct mgcp_config {
	int source_port;
	char *local_ip;
	char *source_addr;
	unsigned int number_endpoints;
	char *bts_ip;
	char *call_agent_addr;

	struct in_addr bts_in;
	char *audio_name;
	int audio_payload;
	int audio_loop;

	struct mgcp_port_range bts_ports;
	struct mgcp_port_range net_ports;
	int endp_dscp;

	/* spec handling */
	int force_realloc;

	mgcp_change change_cb;
	mgcp_policy policy_cb;
	mgcp_reset reset_cb;
	void *data;

	struct mgcp_endpoint *endpoints;
	uint32_t last_call_id;
};

/* config management */
struct mgcp_config *mgcp_config_alloc(void);
int mgcp_parse_config(const char *config_file, struct mgcp_config *cfg);
int mgcp_vty_init(void);
int mgcp_endpoints_allocate(struct mgcp_config *cfg);
void mgcp_free_endp(struct mgcp_endpoint *endp);

/*
 * format helper functions
 */
struct msgb *mgcp_handle_message(struct mgcp_config *cfg, struct msgb *msg);
struct msgb *mgcp_create_response_with_data(int code, const char *msg, const char *trans, const char *data);

/* adc helper */
static inline int mgcp_timeslot_to_endpoint(int multiplex, int timeslot)
{
	if (timeslot == 0)
		timeslot = 1;
	return timeslot + (31 * multiplex);
}


#endif
