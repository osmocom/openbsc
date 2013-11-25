/* MGCP Private Data */

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

#ifndef OPENBSC_MGCP_DATA_H
#define OPENBSC_MGCP_DATA_H

#include <osmocom/core/select.h>

#define CI_UNUSED 0

enum mgcp_connection_mode {
	MGCP_CONN_NONE = 0,
	MGCP_CONN_RECV_ONLY = 1,
	MGCP_CONN_SEND_ONLY = 2,
	MGCP_CONN_RECV_SEND = MGCP_CONN_RECV_ONLY | MGCP_CONN_SEND_ONLY,
	MGCP_CONN_LOOPBACK  = 4,
};

enum mgcp_trunk_type {
	MGCP_TRUNK_VIRTUAL,
	MGCP_TRUNK_E1,
};

struct mgcp_rtp_stream_state {
	uint32_t ssrc;
	uint16_t last_seq;
	uint32_t last_timestamp;
	uint32_t err_ts_counter;
	int32_t last_tsdelta;
};

struct mgcp_rtp_state {
	int initialized;
	int patch;

	uint32_t orig_ssrc;

	uint16_t base_seq;
	int seq_offset;
	int cycles;

	int32_t  timestamp_offset;
	uint32_t jitter;
	int32_t transit;

	struct mgcp_rtp_stream_state in_stream;
	struct mgcp_rtp_stream_state out_stream;
};

struct mgcp_rtp_end {
	/* statistics */
	unsigned int packets;
	unsigned int octets;
	struct in_addr addr;

	/* in network byte order */
	int rtp_port, rtcp_port;

	/* per endpoint data */
	int payload_type;
	char *fmtp_extra;

	/*
	 * Each end has a socket...
	 */
	struct osmo_fd rtp;
	struct osmo_fd rtcp;

	int local_port;
	int local_alloc;
};

enum {
	MGCP_TAP_BTS_IN,
	MGCP_TAP_BTS_OUT,
	MGCP_TAP_NET_IN,
	MGCP_TAP_NET_OUT,

	/* last element */
	MGCP_TAP_COUNT
};

struct mgcp_rtp_tap {
	int enabled;
	struct sockaddr_in forward;
};

enum mgcp_type {
	MGCP_RTP_DEFAULT	= 0,
	MGCP_RTP_TRANSCODED,
};

struct mgcp_endpoint {
	int allocated;
	uint32_t ci;
	char *callid;
	char *local_options;
	int conn_mode;
	int orig_mode;

	/* backpointer */
	struct mgcp_config *cfg;
	struct mgcp_trunk_config *tcfg;

	/* port status for bts/net */
	struct mgcp_rtp_end bts_end;
	struct mgcp_rtp_end net_end;

	/*
	 * For transcoding we will send from the local_port
	 * of trans_bts and it will arrive at trans_net from
	 * where we will forward it to the network.
	 */
	struct mgcp_rtp_end trans_bts;
	struct mgcp_rtp_end trans_net;
	enum mgcp_type type;

	/* sequence bits */
	struct mgcp_rtp_state net_state;
	struct mgcp_rtp_state bts_state;

	/* SSRC/seq/ts patching for loop */
	int allow_patch;

	/* fields for re-transmission */
	char *last_trans;
	char *last_response;

	/* tap for the endpoint */
	struct mgcp_rtp_tap taps[MGCP_TAP_COUNT];
};

#define ENDPOINT_NUMBER(endp) abs(endp - endp->tcfg->endpoints)

struct mgcp_msg_ptr {
	unsigned int start;
	unsigned int length;
};

int mgcp_send_dummy(struct mgcp_endpoint *endp);
int mgcp_bind_bts_rtp_port(struct mgcp_endpoint *endp, int rtp_port);
int mgcp_bind_net_rtp_port(struct mgcp_endpoint *endp, int rtp_port);
int mgcp_bind_trans_bts_rtp_port(struct mgcp_endpoint *enp, int rtp_port);
int mgcp_bind_trans_net_rtp_port(struct mgcp_endpoint *enp, int rtp_port);
int mgcp_free_rtp_port(struct mgcp_rtp_end *end);

/* For transcoding we need to manage an in and an output that are connected */
static inline int endp_back_channel(int endpoint)
{
	return endpoint + 60;
}

struct mgcp_trunk_config *mgcp_trunk_alloc(struct mgcp_config *cfg, int index);
struct mgcp_trunk_config *mgcp_trunk_num(struct mgcp_config *cfg, int index);

void mgcp_state_calc_loss(struct mgcp_rtp_state *s, struct mgcp_rtp_end *,
			uint32_t *expected, int *loss);
uint32_t mgcp_state_calc_jitter(struct mgcp_rtp_state *);


#endif
