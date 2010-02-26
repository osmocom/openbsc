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
#include <unistd.h>
#include <endian.h>

#include <sys/socket.h>
#include <arpa/inet.h>

#include <openbsc/debug.h>
#include <openbsc/mgcp.h>
#include <openbsc/mgcp_internal.h>
#include <openbsc/msgb.h>
#include <openbsc/talloc.h>
#include <openbsc/select.h>

#warning "Make use of the rtp proxy code"

/* according to rtp_proxy.c RFC 3550 */
struct rtp_hdr {
#if __BYTE_ORDER == __LITTLE_ENDIAN
	u_int8_t  csrc_count:4,
		  extension:1,
		  padding:1,
		  version:2;
	u_int8_t  payload_type:7,
		  marker:1;
#elif __BYTE_ORDER == __BIG_ENDIAN
	u_int8_t  version:2,
		  padding:1,
		  extension:1,
		  csrc_count:4;
	u_int8_t  marker:1,
		  payload_type:7;
#endif
	u_int16_t sequence;
	u_int32_t timestamp;
	u_int32_t ssrc;
} __attribute__((packed));


enum {
	DEST_NETWORK = 0,
	DEST_BTS = 1,
};

enum {
	PROTO_RTP,
	PROTO_RTCP,
};


static int udp_send(int fd, struct in_addr *addr, int port, char *buf, int len)
{
	struct sockaddr_in out;
	out.sin_family = AF_INET;
	out.sin_port = port;
	memcpy(&out.sin_addr, addr, sizeof(*addr));

	return sendto(fd, buf, len, 0, (struct sockaddr *)&out, sizeof(out));
}

static void patch_payload(int payload, char *data, int len)
{
	struct rtp_hdr *rtp_hdr;

	if (len < sizeof(*rtp_hdr))
		return;

	rtp_hdr = (struct rtp_hdr *) data;
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
		LOGP(DMGCP, LOGL_ERROR, "Failed to receive message on: 0x%x\n",
			ENDPOINT_NUMBER(endp));
		return -1;
	}

	/* do not forward aynthing... maybe there is a packet from the bts */
	if (endp->ci == CI_UNUSED) {
		LOGP(DMGCP, LOGL_ERROR, "Unknown message on endpoint: 0x%x\n", ENDPOINT_NUMBER(endp));
		return -1;
	}

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
		if (!cfg->bts_ip || memcmp(&addr.sin_addr, &cfg->bts_in, sizeof(cfg->bts_in)) == 0) {
			if (fd == &endp->local_rtp) {
				endp->bts_rtp = addr.sin_port;
			} else {
				endp->bts_rtcp = addr.sin_port;
			}

			endp->bts = addr.sin_addr;
			LOGP(DMGCP, LOGL_NOTICE, "Found BTS for endpoint: 0x%x on port: %d/%d\n",
				ENDPOINT_NUMBER(endp), ntohs(endp->bts_rtp), ntohs(endp->bts_rtcp));
		}
	}

	/* dispatch */
	if (cfg->audio_loop)
		dest = !dest;

	if (dest == DEST_NETWORK) {
		patch_payload(endp->net_payload_type, buf, rc);
		return udp_send(fd->fd, &endp->remote,
			     proto == PROTO_RTP ? endp->net_rtp : endp->net_rtcp,
			     buf, rc);
	} else {
		patch_payload(endp->bts_payload_type, buf, rc);
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
