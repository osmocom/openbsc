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

	int local_port;
};

struct mgcp_endpoint {
	int ci;
	char *callid;
	char *local_options;
	int conn_mode;
	int orig_mode;

	/*
	 * RTP mangling:
	 *  - we get RTP and RTCP to us and need to forward to the BTS
	 *  - we get RTP and RTCP from the BTS and forward to the network
	 */
	struct bsc_fd local_rtp;
	struct bsc_fd local_rtcp;

	/* backpointer */
	struct mgcp_config *cfg;

	/* port status for bts/net */
	struct mgcp_rtp_end bts_end;
	struct mgcp_rtp_end net_end;

	/* sequence bits */
	struct mgcp_rtp_state net_state;
	struct mgcp_rtp_state bts_state;
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

#endif
