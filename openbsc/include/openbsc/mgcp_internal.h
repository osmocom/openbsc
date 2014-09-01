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

#pragma once

#include <osmocom/core/select.h>

#define CI_UNUSED 0

enum mgcp_connection_mode {
	MGCP_CONN_NONE = 0,
	MGCP_CONN_RECV_ONLY = 1,
	MGCP_CONN_SEND_ONLY = 2,
	MGCP_CONN_RECV_SEND = MGCP_CONN_RECV_ONLY | MGCP_CONN_SEND_ONLY,
	MGCP_CONN_LOOPBACK  = 4 | MGCP_CONN_RECV_SEND,
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
	uint32_t last_arrival_time;
};

struct mgcp_rtp_state {
	int initialized;
	int patch_ssrc;

	uint32_t orig_ssrc;

	uint16_t base_seq;
	int seq_offset;
	int cycles;

	int32_t  timestamp_offset;
	uint32_t packet_duration;
	uint32_t jitter;
	int32_t transit;

	struct mgcp_rtp_stream_state in_stream;
	struct mgcp_rtp_stream_state out_stream;
};

struct mgcp_rtp_codec {
	uint32_t rate;
	int channels;
	uint32_t frame_duration_num;
	uint32_t frame_duration_den;

	int payload_type;
	char *audio_name;
	char *subtype_name;
};

struct mgcp_rtp_end {
	/* statistics */
	unsigned int packets;
	unsigned int octets;
	unsigned int dropped_packets;
	struct in_addr addr;

	/* in network byte order */
	int rtp_port, rtcp_port;

	/* audio codec information */
	struct mgcp_rtp_codec codec;
	struct mgcp_rtp_codec alt_codec; /* TODO/XXX: make it generic */

	/* per endpoint data */
	int  frames_per_packet;
	uint32_t packet_duration_ms;
	char *fmtp_extra;
	int output_enabled;
	int force_output_ptime;

	/* RTP patching */
	int force_constant_ssrc; /* -1: always, 0: don't, 1: once */
	int force_aligned_timing;
	void *rtp_process_data;

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

struct mgcp_lco {
	char *string;
	char *codec;
	int pkt_period_min; /* time in ms */
	int pkt_period_max; /* time in ms */
};

enum mgcp_type {
	MGCP_RTP_DEFAULT	= 0,
	MGCP_RTP_TRANSCODED,
	MGCP_OSMUX_BSC,
	MGCP_OSMUX_BSC_NAT,
};

#include <openbsc/osmux.h>

struct mgcp_endpoint {
	int allocated;
	uint32_t ci;
	char *callid;
	struct mgcp_lco local_options;
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

	/* fields for re-transmission */
	char *last_trans;
	char *last_response;

	/* tap for the endpoint */
	struct mgcp_rtp_tap taps[MGCP_TAP_COUNT];

	struct {
		/* Osmux state: disabled, activating, active */
		enum osmux_state state;
		/* Allocated Osmux circuit ID for this endpoint */
		uint8_t cid;
		/* handle to batch messages */
		struct osmux_in_handle *in;
		/* handle to unbatch messages */
		struct osmux_out_handle out;
	} osmux;
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

void mgcp_rtp_end_config(struct mgcp_endpoint *endp, int expect_ssrc_change,
			 struct mgcp_rtp_end *rtp);
uint32_t mgcp_rtp_packet_duration(struct mgcp_endpoint *endp,
				  struct mgcp_rtp_end *rtp);

void mgcp_state_calc_loss(struct mgcp_rtp_state *s, struct mgcp_rtp_end *,
			uint32_t *expected, int *loss);
uint32_t mgcp_state_calc_jitter(struct mgcp_rtp_state *);

/* payload processing default functions */
int mgcp_rtp_processing_default(struct mgcp_endpoint *endp, struct mgcp_rtp_end *dst_end,
				char *data, int *len, int buf_size);

int mgcp_setup_rtp_processing_default(struct mgcp_endpoint *endp,
				      struct mgcp_rtp_end *dst_end,
				      struct mgcp_rtp_end *src_end);

void mgcp_get_net_downlink_format_default(struct mgcp_endpoint *endp,
					  int *payload_type,
					  const char**subtype_name,
					  const char**fmtp_extra);

enum {
	MGCP_DEST_NET = 0,
	MGCP_DEST_BTS,
};

#define MGCP_DUMMY_LOAD 0x23

