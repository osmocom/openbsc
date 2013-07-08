/* A Media Gateway Control Protocol Media Gateway: RFC 3435 */
/* The protocol implementation */

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

#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>

#include <sys/socket.h>
#include <arpa/inet.h>

#include <osmocom/core/msgb.h>
#include <osmocom/core/select.h>

#include <openbsc/mgcp.h>
#include <openbsc/mgcp_internal.h>

#warning "Make use of the rtp proxy code"

/* attempt to determine byte order */
#include <sys/param.h>
#include <limits.h>
#include <time.h>

#ifndef __BYTE_ORDER
# ifdef __APPLE__
#  define __BYTE_ORDER __DARWIN_BYTE_ORDER
#  define __LITTLE_ENDIAN __DARWIN_LITTLE_ENDIAN
#  define __BIG_ENDIAN __DARWIN_BIG_ENDIAN
# else
#  error "__BYTE_ORDER should be defined by someone"
# endif
#endif

/* according to rtp_proxy.c RFC 3550 */
struct rtp_hdr {
#if __BYTE_ORDER == __LITTLE_ENDIAN
	uint8_t  csrc_count:4,
		  extension:1,
		  padding:1,
		  version:2;
	uint8_t  payload_type:7,
		  marker:1;
#elif __BYTE_ORDER == __BIG_ENDIAN
	uint8_t  version:2,
		  padding:1,
		  extension:1,
		  csrc_count:4;
	uint8_t  marker:1,
		  payload_type:7;
#endif
	uint16_t sequence;
	uint32_t timestamp;
	uint32_t ssrc;
} __attribute__((packed));

#define RTP_SEQ_MOD		(1 << 16)
#define RTP_MAX_DROPOUT		3000
#define RTP_MAX_MISORDER	100


enum {
	DEST_NETWORK = 0,
	DEST_BTS = 1,
};

enum {
	PROTO_RTP,
	PROTO_RTCP,
};

#define DUMMY_LOAD 0x23


/**
 * This does not need to be a precision timestamp and
 * is allowed to wrap quite fast. The returned value is
 * milli seconds now.
 */
uint32_t get_current_ts(void)
{
	struct timespec tp;
	uint64_t ret;

	memset(&tp, 0, sizeof(tp));
	if (clock_gettime(CLOCK_MONOTONIC, &tp) != 0)
		LOGP(DMGCP, LOGL_NOTICE,
			"Getting the clock failed.\n");

	/* convert it to useconds */
	ret = tp.tv_sec;
	ret *= 1000;
	ret += tp.tv_nsec / 1000 / 1000;

	return ret;
}

static int udp_send(int fd, struct in_addr *addr, int port, char *buf, int len)
{
	struct sockaddr_in out;
	out.sin_family = AF_INET;
	out.sin_port = port;
	memcpy(&out.sin_addr, addr, sizeof(*addr));

	return sendto(fd, buf, len, 0, (struct sockaddr *)&out, sizeof(out));
}

int mgcp_send_dummy(struct mgcp_endpoint *endp)
{
	static char buf[] = { DUMMY_LOAD };

	return udp_send(endp->net_end.rtp.fd, &endp->net_end.addr,
			endp->net_end.rtp_port, buf, 1);
}

/**
 * The RFC 3550 Appendix A assumes there are multiple sources but
 * some of the supported endpoints (e.g. the nanoBTS) can only handle
 * one source and this code will patch packages to appear as if there
 * is only one source.
 * There is also no probation period for new sources. Every package
 * we receive will be seen as a switch in streams.
 */
static void patch_and_count(struct mgcp_endpoint *endp, struct mgcp_rtp_state *state,
			    int payload, struct sockaddr_in *addr, char *data, int len)
{
	uint32_t arrival_time;
	int32_t transit, d;
	uint16_t seq, udelta;
	uint32_t timestamp;
	struct rtp_hdr *rtp_hdr;

	if (len < sizeof(*rtp_hdr))
		return;

	rtp_hdr = (struct rtp_hdr *) data;
	seq = ntohs(rtp_hdr->sequence);
	timestamp = ntohl(rtp_hdr->timestamp);
	arrival_time = get_current_ts();

	if (!state->initialized) {
		state->base_seq = seq;
		state->max_seq = seq - 1;
		state->ssrc = state->orig_ssrc = rtp_hdr->ssrc;
		state->initialized = 1;
		state->last_timestamp = timestamp;
		state->jitter = 0;
		state->transit = arrival_time - timestamp;
	} else if (state->ssrc != rtp_hdr->ssrc) {
		state->ssrc = rtp_hdr->ssrc;
		state->seq_offset = (state->max_seq + 1) - seq;
		state->timestamp_offset = state->last_timestamp - timestamp;
		state->patch = endp->allow_patch;
		LOGP(DMGCP, LOGL_NOTICE,
			"The SSRC changed on 0x%x SSRC: %u offset: %d from %s:%d in %d\n",
			ENDPOINT_NUMBER(endp), state->ssrc, state->seq_offset,
			inet_ntoa(addr->sin_addr), ntohs(addr->sin_port), endp->conn_mode);
	}

	/* apply the offset and store it back to the packet */
	if (state->patch) {
		seq += state->seq_offset;
		rtp_hdr->sequence = htons(seq);
		rtp_hdr->ssrc = state->orig_ssrc;

		timestamp += state->timestamp_offset;
		rtp_hdr->timestamp = htonl(timestamp);
	}

	/*
	 * The below takes the shape of the validation from Appendix A. Check
	 * if there is something weird with the sequence number, otherwise check
	 * for a wrap around in the sequence number.
	 */
	udelta = seq - state->max_seq;
	if (udelta < RTP_MAX_DROPOUT) {
		if (seq < state->max_seq)
			state->cycles += RTP_SEQ_MOD;
	} else if (udelta <= RTP_SEQ_MOD - RTP_MAX_MISORDER) {
		LOGP(DMGCP, LOGL_NOTICE,
			"RTP seqno made a very large jump on 0x%x delta: %u\n",
			ENDPOINT_NUMBER(endp), udelta);
	}

	/*
	 * calculate the jitter between the two packages. The TS should be
	 * taken closer to the read function. This was taken from the
	 * Appendix A of RFC 3550. The local timestamp has a usec resolution.
	 */
	transit = arrival_time - timestamp;
	d = transit - state->transit;
	state->transit = transit;
	if (d < 0)
		d = -d;
	state->jitter += d - ((state->jitter + 8) >> 4);


	state->max_seq = seq;
	state->last_timestamp = timestamp;

	if (payload < 0)
		return;

	rtp_hdr->payload_type = payload;
}

/*
 * The below code is for dispatching. We have a dedicated port for
 * the data coming from the net and one to discover the BTS.
 */
static int forward_data(int fd, struct mgcp_rtp_tap *tap, const char *buf, int len)
{
	if (!tap->enabled)
		return 0;

	return sendto(fd, buf, len, 0,
		      (struct sockaddr *)&tap->forward, sizeof(tap->forward));
}

static int send_transcoder(struct mgcp_rtp_end *end, struct mgcp_config *cfg,
			   int is_rtp, const char *buf, int len)
{
	int rc;
	int port;
	struct sockaddr_in addr;

	port = is_rtp ? end->rtp_port : end->rtcp_port;

	addr.sin_family = AF_INET;
	addr.sin_addr = cfg->transcoder_in;
	addr.sin_port = port;

	rc = sendto(is_rtp ?
		end->rtp.fd :
		end->rtcp.fd, buf, len, 0,
		(struct sockaddr *) &addr, sizeof(addr));

	if (rc != len)
		LOGP(DMGCP, LOGL_ERROR,
			"Failed to send data to the transcoder: %s\n",
			strerror(errno));

	return rc;
}

static int send_to(struct mgcp_endpoint *endp, int dest, int is_rtp,
		   struct sockaddr_in *addr, char *buf, int rc)
{
	struct mgcp_trunk_config *tcfg = endp->tcfg;
	/* For loop toggle the destination and then dispatch. */
	if (tcfg->audio_loop)
		dest = !dest;

	/* Loop based on the conn_mode, maybe undoing the above */
	if (endp->conn_mode == MGCP_CONN_LOOPBACK)
		dest = !dest;

	if (dest == DEST_NETWORK) {
		if (is_rtp) {
			patch_and_count(endp, &endp->bts_state,
					endp->net_end.payload_type,
					addr, buf, rc);
			forward_data(endp->net_end.rtp.fd,
				     &endp->taps[MGCP_TAP_NET_OUT], buf, rc);
			return udp_send(endp->net_end.rtp.fd, &endp->net_end.addr,
					endp->net_end.rtp_port, buf, rc);
		} else if (!tcfg->omit_rtcp) {
			return udp_send(endp->net_end.rtcp.fd, &endp->net_end.addr,
					endp->net_end.rtcp_port, buf, rc);
		}
	} else {
		if (is_rtp) {
			patch_and_count(endp, &endp->net_state,
					endp->bts_end.payload_type,
					addr, buf, rc);
			forward_data(endp->bts_end.rtp.fd,
				     &endp->taps[MGCP_TAP_BTS_OUT], buf, rc);
			return udp_send(endp->bts_end.rtp.fd, &endp->bts_end.addr,
					endp->bts_end.rtp_port, buf, rc);
		} else if (!tcfg->omit_rtcp) {
			return udp_send(endp->bts_end.rtcp.fd, &endp->bts_end.addr,
					endp->bts_end.rtcp_port, buf, rc);
		}
	}

	return 0;
}

static int receive_from(struct mgcp_endpoint *endp, int fd, struct sockaddr_in *addr,
			char *buf, int bufsize)
{
	int rc;
	socklen_t slen = sizeof(*addr);

	rc = recvfrom(fd, buf, bufsize, 0,
			    (struct sockaddr *) addr, &slen);
	if (rc < 0) {
		LOGP(DMGCP, LOGL_ERROR, "Failed to receive message on: 0x%x errno: %d/%s\n",
			ENDPOINT_NUMBER(endp), errno, strerror(errno));
		return -1;
	}

	/* do not forward aynthing... maybe there is a packet from the bts */
	if (!endp->allocated)
		return -1;

	#warning "Slight spec violation. With connection mode recvonly we should attempt to forward."

	return rc;
}

static int rtp_data_net(struct osmo_fd *fd, unsigned int what)
{
	char buf[4096];
	struct sockaddr_in addr;
	struct mgcp_endpoint *endp;
	int rc, proto;

	endp = (struct mgcp_endpoint *) fd->data;

	rc = receive_from(endp, fd->fd, &addr, buf, sizeof(buf));
	if (rc <= 0)
		return -1;

	if (memcmp(&addr.sin_addr, &endp->net_end.addr, sizeof(addr.sin_addr)) != 0) {
		LOGP(DMGCP, LOGL_ERROR,
			"Endpoint 0x%x data from wrong address %s vs. ",
			ENDPOINT_NUMBER(endp), inet_ntoa(addr.sin_addr));
		LOGPC(DMGCP, LOGL_ERROR,
			"%s\n", inet_ntoa(endp->net_end.addr));
		return -1;
	}

	if (endp->net_end.rtp_port != addr.sin_port &&
	    endp->net_end.rtcp_port != addr.sin_port) {
		LOGP(DMGCP, LOGL_ERROR,
			"Data from wrong source port %d on 0x%x\n",
			ntohs(addr.sin_port), ENDPOINT_NUMBER(endp));
		return -1;
	}

	/* throw away the dummy message */
	if (rc == 1 && buf[0] == DUMMY_LOAD) {
		LOGP(DMGCP, LOGL_NOTICE, "Filtered dummy from network on 0x%x\n",
			ENDPOINT_NUMBER(endp));
		return 0;
	}

	proto = fd == &endp->net_end.rtp ? PROTO_RTP : PROTO_RTCP;
	endp->net_end.packets += 1;
	endp->net_end.octets += rc;

	forward_data(fd->fd, &endp->taps[MGCP_TAP_NET_IN], buf, rc);

	switch (endp->type) {
	case MGCP_RTP_DEFAULT:
		return send_to(endp, DEST_BTS, proto == PROTO_RTP, &addr,
			       buf, rc);
	case MGCP_RTP_TRANSCODED:
		return send_transcoder(&endp->trans_net, endp->cfg,
				       proto == PROTO_RTP, buf, rc);
	}

	LOGP(DMGCP, LOGL_ERROR, "Bad MGCP type %u on endpoint %u\n",
	     endp->type, ENDPOINT_NUMBER(endp));
	return 0;
}

static void discover_bts(struct mgcp_endpoint *endp, int proto, struct sockaddr_in *addr)
{
	struct mgcp_config *cfg = endp->cfg;

	if (proto == PROTO_RTP && endp->bts_end.rtp_port == 0) {
		if (!cfg->bts_ip ||
		    memcmp(&addr->sin_addr,
			   &cfg->bts_in, sizeof(cfg->bts_in)) == 0 ||
		    memcmp(&addr->sin_addr,
			   &endp->bts_end.addr, sizeof(endp->bts_end.addr)) == 0) {

			endp->bts_end.rtp_port = addr->sin_port;
			endp->bts_end.addr = addr->sin_addr;

			LOGP(DMGCP, LOGL_NOTICE,
				"Found BTS for endpoint: 0x%x on port: %d/%d of %s\n",
				ENDPOINT_NUMBER(endp), ntohs(endp->bts_end.rtp_port),
				ntohs(endp->bts_end.rtcp_port), inet_ntoa(addr->sin_addr));
		}
	} else if (proto == PROTO_RTCP && endp->bts_end.rtcp_port == 0) {
		if (memcmp(&endp->bts_end.addr, &addr->sin_addr,
				sizeof(endp->bts_end.addr)) == 0) {
			endp->bts_end.rtcp_port = addr->sin_port;
		}
	}
}

static int rtp_data_bts(struct osmo_fd *fd, unsigned int what)
{
	char buf[4096];
	struct sockaddr_in addr;
	struct mgcp_endpoint *endp;
	int rc, proto;

	endp = (struct mgcp_endpoint *) fd->data;

	rc = receive_from(endp, fd->fd, &addr, buf, sizeof(buf));
	if (rc <= 0)
		return -1;

	proto = fd == &endp->bts_end.rtp ? PROTO_RTP : PROTO_RTCP;

	/* We have no idea who called us, maybe it is the BTS. */
	/* it was the BTS... */
	discover_bts(endp, proto, &addr);

	if (memcmp(&endp->bts_end.addr, &addr.sin_addr, sizeof(addr.sin_addr)) != 0) {
		LOGP(DMGCP, LOGL_ERROR,
			"Data from wrong bts %s on 0x%x\n",
			inet_ntoa(addr.sin_addr), ENDPOINT_NUMBER(endp));
		return -1;
	}

	if (endp->bts_end.rtp_port != addr.sin_port &&
	    endp->bts_end.rtcp_port != addr.sin_port) {
		LOGP(DMGCP, LOGL_ERROR,
			"Data from wrong bts source port %d on 0x%x\n",
			ntohs(addr.sin_port), ENDPOINT_NUMBER(endp));
		return -1;
	}

	/* throw away the dummy message */
	if (rc == 1 && buf[0] == DUMMY_LOAD) {
		LOGP(DMGCP, LOGL_NOTICE, "Filtered dummy from bts on 0x%x\n",
			ENDPOINT_NUMBER(endp));
		return 0;
	}

	/* do this before the loop handling */
	endp->bts_end.packets += 1;
	endp->bts_end.octets += rc;

	forward_data(fd->fd, &endp->taps[MGCP_TAP_BTS_IN], buf, rc);

	switch (endp->type) {
	case MGCP_RTP_DEFAULT:
		return send_to(endp, DEST_NETWORK, proto == PROTO_RTP, &addr,
			       buf, rc);
	case MGCP_RTP_TRANSCODED:
		return send_transcoder(&endp->trans_bts, endp->cfg,
				       proto == PROTO_RTP, buf, rc);
	}

	LOGP(DMGCP, LOGL_ERROR, "Bad MGCP type %u on endpoint %u\n",
	     endp->type, ENDPOINT_NUMBER(endp));
	return 0;
}

static int rtp_data_transcoder(struct mgcp_rtp_end *end, struct mgcp_endpoint *_endp,
			      int dest, struct osmo_fd *fd)
{
	char buf[4096];
	struct sockaddr_in addr;
	struct mgcp_config *cfg;
	int rc, proto;

	cfg = _endp->cfg;
	rc = receive_from(_endp, fd->fd, &addr, buf, sizeof(buf));
	if (rc <= 0)
		return -1;

	proto = fd == &end->rtp ? PROTO_RTP : PROTO_RTCP;

	if (memcmp(&addr.sin_addr, &cfg->transcoder_in, sizeof(addr.sin_addr)) != 0) {
		LOGP(DMGCP, LOGL_ERROR,
			"Data not coming from transcoder dest: %d %s on 0x%x\n",
			dest, inet_ntoa(addr.sin_addr), ENDPOINT_NUMBER(_endp));
		return -1;
	}

	if (end->rtp_port != addr.sin_port &&
	    end->rtcp_port != addr.sin_port) {
		LOGP(DMGCP, LOGL_ERROR,
			"Data from wrong transcoder dest %d source port %d on 0x%x\n",
			dest, ntohs(addr.sin_port), ENDPOINT_NUMBER(_endp));
		return -1;
	}

	/* throw away the dummy message */
	if (rc == 1 && buf[0] == DUMMY_LOAD) {
		LOGP(DMGCP, LOGL_NOTICE, "Filtered dummy from transcoder dest %d on 0x%x\n",
			dest, ENDPOINT_NUMBER(_endp));
		return 0;
	}

	end->packets += 1;
	return send_to(_endp, dest, proto == PROTO_RTP, &addr, &buf[0], rc);
}

static int rtp_data_trans_net(struct osmo_fd *fd, unsigned int what)
{
	struct mgcp_endpoint *endp;
	endp = (struct mgcp_endpoint *) fd->data;

	return rtp_data_transcoder(&endp->trans_net, endp, DEST_NETWORK, fd);
}

static int rtp_data_trans_bts(struct osmo_fd *fd, unsigned int what)
{
	struct mgcp_endpoint *endp;
	endp = (struct mgcp_endpoint *) fd->data;

	return rtp_data_transcoder(&endp->trans_bts, endp, DEST_BTS, fd);
}

static int create_bind(const char *source_addr, struct osmo_fd *fd, int port)
{
	struct sockaddr_in addr;
	int on = 1;

	fd->fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd->fd < 0) {
		LOGP(DMGCP, LOGL_ERROR, "Failed to create UDP port.\n");
		return -1;
	}

	setsockopt(fd->fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);
	inet_aton(source_addr, &addr.sin_addr);

	if (bind(fd->fd, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
		close(fd->fd);
		fd->fd = -1;
		return -1;
	}

	return 0;
}

static int set_ip_tos(int fd, int tos)
{
	int ret;
	ret = setsockopt(fd, IPPROTO_IP, IP_TOS,
			 &tos, sizeof(tos));
	return ret != 0;
}

static int bind_rtp(struct mgcp_config *cfg, struct mgcp_rtp_end *rtp_end, int endpno)
{
	if (create_bind(cfg->source_addr, &rtp_end->rtp, rtp_end->local_port) != 0) {
		LOGP(DMGCP, LOGL_ERROR, "Failed to create RTP port: %s:%d on 0x%x\n",
		       cfg->source_addr, rtp_end->local_port, endpno);
		goto cleanup0;
	}

	if (create_bind(cfg->source_addr, &rtp_end->rtcp, rtp_end->local_port + 1) != 0) {
		LOGP(DMGCP, LOGL_ERROR, "Failed to create RTCP port: %s:%d on 0x%x\n",
		       cfg->source_addr, rtp_end->local_port + 1, endpno);
		goto cleanup1;
	}

	set_ip_tos(rtp_end->rtp.fd, cfg->endp_dscp);
	set_ip_tos(rtp_end->rtcp.fd, cfg->endp_dscp);

	rtp_end->rtp.when = BSC_FD_READ;
	if (osmo_fd_register(&rtp_end->rtp) != 0) {
		LOGP(DMGCP, LOGL_ERROR, "Failed to register RTP port %d on 0x%x\n",
			rtp_end->local_port, endpno);
		goto cleanup2;
	}

	rtp_end->rtcp.when = BSC_FD_READ;
	if (osmo_fd_register(&rtp_end->rtcp) != 0) {
		LOGP(DMGCP, LOGL_ERROR, "Failed to register RTCP port %d on 0x%x\n",
			rtp_end->local_port + 1, endpno);
		goto cleanup3;
	}

	return 0;

cleanup3:
	osmo_fd_unregister(&rtp_end->rtp);
cleanup2:
	close(rtp_end->rtcp.fd);
	rtp_end->rtcp.fd = -1;
cleanup1:
	close(rtp_end->rtp.fd);
	rtp_end->rtp.fd = -1;
cleanup0:
	return -1;
}

static int int_bind(const char *port,
		    struct mgcp_rtp_end *end, int (*cb)(struct osmo_fd *, unsigned),
		    struct mgcp_endpoint *_endp, int rtp_port)
{
	if (end->rtp.fd != -1 || end->rtcp.fd != -1) {
		LOGP(DMGCP, LOGL_ERROR, "Previous %s was still bound on %d\n",
			port, ENDPOINT_NUMBER(_endp));
		mgcp_free_rtp_port(end);
	}

	end->local_port = rtp_port;
	end->rtp.cb = cb;
	end->rtp.data = _endp;
	end->rtcp.data = _endp;
	end->rtcp.cb = cb;
	return bind_rtp(_endp->cfg, end, ENDPOINT_NUMBER(_endp));
}


int mgcp_bind_bts_rtp_port(struct mgcp_endpoint *endp, int rtp_port)
{
	return int_bind("bts-port", &endp->bts_end,
			rtp_data_bts, endp, rtp_port);
}

int mgcp_bind_net_rtp_port(struct mgcp_endpoint *endp, int rtp_port)
{
	return int_bind("net-port", &endp->net_end,
			rtp_data_net, endp, rtp_port);
}

int mgcp_bind_trans_net_rtp_port(struct mgcp_endpoint *endp, int rtp_port)
{
	return int_bind("trans-net", &endp->trans_net,
			rtp_data_trans_net, endp, rtp_port);
}

int mgcp_bind_trans_bts_rtp_port(struct mgcp_endpoint *endp, int rtp_port)
{
	return int_bind("trans-bts", &endp->trans_bts,
			rtp_data_trans_bts, endp, rtp_port);
}

int mgcp_free_rtp_port(struct mgcp_rtp_end *end)
{
	if (end->rtp.fd != -1) {
		close(end->rtp.fd);
		end->rtp.fd = -1;
		osmo_fd_unregister(&end->rtp);
	}

	if (end->rtcp.fd != -1) {
		close(end->rtcp.fd);
		end->rtcp.fd = -1;
		osmo_fd_unregister(&end->rtcp);
	}

	return 0;
}


void mgcp_state_calc_loss(struct mgcp_rtp_state *state,
			struct mgcp_rtp_end *end, uint32_t *expected,
			int *loss)
{
	*expected = state->cycles + state->max_seq;
	*expected = *expected - state->base_seq + 1;

	if (!state->initialized) {
		*expected = 0;
		*loss = 0;
		return;
	}

	/*
	 * Make sure the sign is correct and use the biggest
	 * positive/negative number that fits.
	 */
	*loss = *expected - end->packets;
	if (*expected < end->packets) {
		if (*loss > 0)
			*loss = INT_MIN;
	} else {
		if (*loss < 0)
			*loss = INT_MAX;
	}
}

uint32_t mgcp_state_calc_jitter(struct mgcp_rtp_state *state)
{
	if (!state->initialized)
		return 0;
	return state->jitter >> 4;
}
