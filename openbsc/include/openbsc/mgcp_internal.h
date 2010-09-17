/* MGCP Private Data */

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

#ifndef OPENBSC_MGCP_DATA_H
#define OPENBSC_MGCP_DATA_H

#include <osmocore/select.h>

#define CI_UNUSED 0

enum mgcp_connection_mode {
	MGCP_CONN_NONE = 0,
	MGCP_CONN_RECV_ONLY = 1,
	MGCP_CONN_SEND_ONLY = 2,
	MGCP_CONN_RECV_SEND = MGCP_CONN_RECV_ONLY | MGCP_CONN_SEND_ONLY,
	MGCP_CONN_LOOPBACK  = 4,
};

struct mgcp_rtp_state {
	int initialized;
	int patch;

	uint32_t orig_ssrc;
	uint32_t ssrc;
	uint16_t seq_no;
	int lost_no;
	int seq_offset;
	uint32_t last_timestamp;
	int32_t  timestamp_offset;
};

struct mgcp_rtp_end {
	/* statistics */
	unsigned int packets;
	struct in_addr addr;

	/* in network byte order */
	int rtp_port, rtcp_port;

	int payload_type;

	/*
	 * Each end has a socket...
	 */
	struct bsc_fd rtp;
	struct bsc_fd rtcp;

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

struct mgcp_endpoint {
	int allocated;
	uint32_t ci;
	char *callid;
	char *local_options;
	int conn_mode;
	int orig_mode;

	/* backpointer */
	struct mgcp_config *cfg;

	/* port status for bts/net */
	struct mgcp_rtp_end bts_end;
	struct mgcp_rtp_end net_end;
	struct mgcp_rtp_end transcoder_end;

	/* sequence bits */
	struct mgcp_rtp_state net_state;
	struct mgcp_rtp_state bts_state;

	/* SSRC/seq/ts patching for loop */
	int allow_patch;

	/* tap for the endpoint */
	struct mgcp_rtp_tap taps[MGCP_TAP_COUNT];
};

#define ENDPOINT_NUMBER(endp) abs(endp - endp->cfg->endpoints)

struct mgcp_msg_ptr {
	unsigned int start;
	unsigned int length;
};

int mgcp_analyze_header(struct mgcp_config *cfg, struct msgb *msg,
			struct mgcp_msg_ptr *ptr, int size,
			const char **transaction_id, struct mgcp_endpoint **endp);
int mgcp_send_dummy(struct mgcp_endpoint *endp);
int mgcp_bind_bts_rtp_port(struct mgcp_endpoint *endp, int rtp_port);
int mgcp_bind_net_rtp_port(struct mgcp_endpoint *endp, int rtp_port);
int mgcp_bind_transcoder_rtp_port(struct mgcp_endpoint *enp, int rtp_port);
int mgcp_free_rtp_port(struct mgcp_rtp_end *end);

#endif
