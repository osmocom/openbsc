/* A Media Gateway Control Protocol Media Gateway: RFC 3435 */
/* The protocol implementation */

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

#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <endian.h>
#include <errno.h>

#include <sys/socket.h>
#include <arpa/inet.h>

#include <osmocore/msgb.h>
#include <osmocore/select.h>

#include <openbsc/debug.h>
#include <openbsc/mgcp.h>
#include <openbsc/mgcp_internal.h>

#warning "Make use of the rtp proxy code"

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


enum {
	DEST_NETWORK = 0,
	DEST_BTS = 1,
};

enum {
	PROTO_RTP,
	PROTO_RTCP,
};

#define DUMMY_LOAD 0x23


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

	return udp_send(endp->local_rtp.fd, &endp->remote,
			endp->net_rtp, buf, 1);
}

static void patch_and_count(struct mgcp_rtp_state *state, int endp_no, int conn_mode,
			    struct sockaddr_in *addr, int payload, char *data, int len)
{
	uint16_t seq;
	uint32_t timestamp;
	struct rtp_hdr *rtp_hdr;

	if (len < sizeof(*rtp_hdr))
		return;

	rtp_hdr = (struct rtp_hdr *) data;
	seq = ntohs(rtp_hdr->sequence);
	timestamp = ntohl(rtp_hdr->timestamp);

	if (!state->initialized) {
		state->seq_no = seq - 1;
		state->ssrc = state->orig_ssrc = rtp_hdr->ssrc;
		state->initialized = 1;
		state->last_timestamp = timestamp;
	} else if (state->ssrc != rtp_hdr->ssrc) {
		state->ssrc = rtp_hdr->ssrc;
		state->seq_offset = (state->seq_no + 1) - seq;
		state->timestamp_offset = state->last_timestamp - timestamp;
		//state->patch = 1;
		LOGP(DMGCP, LOGL_NOTICE,
			"The SSRC changed on %d SSRC: %u offset: %d from %s:%d in %d\n",
			endp_no, state->ssrc, state->seq_offset,
			inet_ntoa(addr->sin_addr), ntohs(addr->sin_port), conn_mode);
	}

	/* apply the offset and store it back to the packet */
	if (state->patch) {
		seq += state->seq_offset;
		rtp_hdr->sequence = htons(seq);
		rtp_hdr->ssrc = state->orig_ssrc;

		timestamp += state->timestamp_offset;
		rtp_hdr->timestamp = htonl(timestamp);
	}

	/* seq changed, now compare if we have lost something */
	if (state->seq_no + 1u != seq)
		state->lost_no = abs(seq - (state->seq_no + 1));
	state->seq_no = seq;

	state->last_timestamp = timestamp;

	if (payload < 0)
		return;

	rtp_hdr->payload_type = payload;
}

/*
 * There is data coming. We will have to figure out if it
 * came from the BTS or the MediaGateway of the MSC. On top
 * of that we need to figure out if it was RTP or RTCP.
 *
 * Currently we do not communicate with the BSC so we have
 * no idea where the BTS is listening for RTP and need to
 * do the classic routing trick. Wait for the first packet
 * from the BTS and then go ahead.
 */
static int rtp_data_cb(struct bsc_fd *fd, unsigned int what)
{
	char buf[4096];
	struct sockaddr_in addr;
	socklen_t slen = sizeof(addr);
	struct mgcp_endpoint *endp;
	struct mgcp_config *cfg;
	int rc, dest, proto;

	endp = (struct mgcp_endpoint *) fd->data;
	cfg = endp->cfg;

	rc = recvfrom(fd->fd, &buf, sizeof(buf), 0,
			    (struct sockaddr *) &addr, &slen);
	if (rc < 0) {
		LOGP(DMGCP, LOGL_ERROR, "Failed to receive message on: 0x%x errno: %d/%s\n",
			ENDPOINT_NUMBER(endp), errno, strerror(errno));
		return -1;
	}

	/* do not forward aynthing... maybe there is a packet from the bts */
	if (endp->ci == CI_UNUSED)
		return -1;

	/*
	 * Figure out where to forward it to. This code assumes that we
	 * have received the Connection Modify and know who is a legitimate
	 * partner. According to the spec we could attempt to forward even
	 * after the Create Connection but we will not as we are not really
	 * able to tell if this is legitimate.
	 */
	#warning "Slight spec violation. With connection mode recvonly we should attempt to forward."
	dest = memcmp(&addr.sin_addr, &endp->remote, sizeof(addr.sin_addr)) == 0 &&
		    (endp->net_rtp == addr.sin_port || endp->net_rtcp == addr.sin_port)
			? DEST_BTS : DEST_NETWORK;
	proto = fd == &endp->local_rtp ? PROTO_RTP : PROTO_RTCP;

	/* We have no idea who called us, maybe it is the BTS. */
	if (dest == DEST_NETWORK && (endp->bts_rtp == 0 || cfg->forward_ip)) {
		/* it was the BTS... */
		if (!cfg->bts_ip
		    || memcmp(&addr.sin_addr, &cfg->bts_in, sizeof(cfg->bts_in)) == 0
		    || memcmp(&addr.sin_addr, &endp->bts, sizeof(endp->bts)) == 0) {
			if (fd == &endp->local_rtp) {
				endp->bts_rtp = addr.sin_port;
			} else {
				endp->bts_rtcp = addr.sin_port;
			}

			endp->bts = addr.sin_addr;
			LOGP(DMGCP, LOGL_NOTICE, "Found BTS for endpoint: 0x%x on port: %d/%d of %s\n",
				ENDPOINT_NUMBER(endp), ntohs(endp->bts_rtp), ntohs(endp->bts_rtcp),
				inet_ntoa(addr.sin_addr));

		}
	}

	/* throw away the dummy message */
	if (rc == 1 && buf[0] == DUMMY_LOAD) {
		LOGP(DMGCP, LOGL_NOTICE, "Filtered dummy on 0x%x\n",
			ENDPOINT_NUMBER(endp));
		return 0;
	}

	/* do this before the loop handling */
	if (dest == DEST_NETWORK)
		++endp->in_bts;
	else
		++endp->in_remote;

	/* For loop toggle the destination and then dispatch. */
	if (cfg->audio_loop)
		dest = !dest;

	/* Loop based on the conn_mode, maybe undoing the above */
	if (endp->conn_mode == MGCP_CONN_LOOPBACK)
		dest = !dest;

	if (dest == DEST_NETWORK) {
		if (proto == PROTO_RTP)
			patch_and_count(&endp->bts_state,
					endp->net_payload_type, endp->conn_mode,
					&addr,
					ENDPOINT_NUMBER(endp), buf, rc);
		return udp_send(fd->fd, &endp->remote,
			     proto == PROTO_RTP ? endp->net_rtp : endp->net_rtcp,
			     buf, rc);
	} else {
		if (proto == PROTO_RTP)
			patch_and_count(&endp->net_state,
					endp->bts_payload_type, endp->conn_mode,
					&addr,
					ENDPOINT_NUMBER(endp), buf, rc);
		return udp_send(fd->fd, &endp->bts,
			     proto == PROTO_RTP ? endp->bts_rtp : endp->bts_rtcp,
			     buf, rc);
	}
}

static int create_bind(const char *source_addr, struct bsc_fd *fd, int port)
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

static int bind_rtp(struct mgcp_endpoint *endp)
{
	struct mgcp_config *cfg = endp->cfg;

	if (create_bind(cfg->source_addr, &endp->local_rtp, endp->rtp_port) != 0) {
		LOGP(DMGCP, LOGL_ERROR, "Failed to create RTP port: %s:%d on 0x%x\n",
		       cfg->source_addr, endp->rtp_port, ENDPOINT_NUMBER(endp));
		goto cleanup0;
	}

	if (create_bind(cfg->source_addr, &endp->local_rtcp, endp->rtp_port + 1) != 0) {
		LOGP(DMGCP, LOGL_ERROR, "Failed to create RTCP port: %s:%d on 0x%x\n",
		       cfg->source_addr, endp->rtp_port + 1, ENDPOINT_NUMBER(endp));
		goto cleanup1;
	}

	set_ip_tos(endp->local_rtp.fd, cfg->endp_dscp);
	set_ip_tos(endp->local_rtcp.fd, cfg->endp_dscp);

	endp->local_rtp.cb = rtp_data_cb;
	endp->local_rtp.data = endp;
	endp->local_rtp.when = BSC_FD_READ;
	if (bsc_register_fd(&endp->local_rtp) != 0) {
		LOGP(DMGCP, LOGL_ERROR, "Failed to register RTP port %d on 0x%x\n",
			endp->rtp_port, ENDPOINT_NUMBER(endp));
		goto cleanup2;
	}

	endp->local_rtcp.cb = rtp_data_cb;
	endp->local_rtcp.data = endp;
	endp->local_rtcp.when = BSC_FD_READ;
	if (bsc_register_fd(&endp->local_rtcp) != 0) {
		LOGP(DMGCP, LOGL_ERROR, "Failed to register RTCP port %d on 0x%x\n",
			endp->rtp_port + 1, ENDPOINT_NUMBER(endp));
		goto cleanup3;
	}

	return 0;

cleanup3:
	bsc_unregister_fd(&endp->local_rtp);
cleanup2:
	close(endp->local_rtcp.fd);
	endp->local_rtcp.fd = -1;
cleanup1:
	close(endp->local_rtp.fd);
	endp->local_rtp.fd = -1;
cleanup0:
	return -1;
}

int mgcp_bind_rtp_port(struct mgcp_endpoint *endp, int rtp_port)
{
	endp->rtp_port = rtp_port;
	return bind_rtp(endp);
}
