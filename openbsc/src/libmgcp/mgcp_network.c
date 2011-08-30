/* A Media Gateway Control Protocol Media Gateway: RFC 3435 */
/* The protocol implementation */

/*
 * (C) 2009-2011 by Holger Hans Peter Freyther <zecke@selfish.org>
 * (C) 2009-2011 by On-Waves
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
#include <assert.h>

#include <sys/socket.h>
#include <arpa/inet.h>

#include <osmocom/core/msgb.h>
#include <osmocom/core/select.h>

#include <openbsc/mgcp.h>
#include <openbsc/mgcp_internal.h>
#include <openbsc/rtp_rfc.h>

#warning "Make use of the rtp proxy code"

/* attempt to determine byte order */
#include <sys/param.h>
#include <limits.h>


enum {
	DEST_NETWORK = 0,
	DEST_BTS = 1,
};

enum {
	PROTO_RTP,
	PROTO_RTCP,
};

#define DUMMY_LOAD 0x23

static int send_to(struct mgcp_endpoint *endp, int dest, int is_rtp,
		   struct sockaddr_in *addr, char *buf, int rc);

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

void mgcp_msgb_clear_queue(struct llist_head *head)
{
	struct msgb *msg;

	while (!llist_empty(head)) {
		msg = msgb_dequeue(head);
		msgb_free(msg);
	}
}

static void patch_and_count(struct mgcp_endpoint *endp, struct mgcp_rtp_state *state,
			    int payload, struct sockaddr_in *addr, char *data, int len)
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

static struct msgb *from_data(char *buf, int rc)
{
	struct msgb *msg = mgcp_msgb_alloc();
	if (!msg) {
		LOGP(DMGCP, LOGL_ERROR, "Failed to allocate.\n");
		return NULL;
	}

	msg->l2h = msgb_put(msg, rc);
	memcpy(msg->l2h, buf, rc);
	return msg;
}

static int maybe_send_queue(struct mgcp_endpoint *endp,
			    struct mgcp_rtp_end *rtp_end)
{
	struct msgb *out;
	int rc;

	/* Queue up to four messages per endpoint */
	if (++endp->compr_queue_size != 4)
		return 0;

	/* Allocate the outgoing data */
	out = mgcp_msgb_alloc();
	if (!out) {
		LOGP(DMGCP, LOGL_ERROR, "Failed to allocate.\n");
		goto cleanup;
	}

	out->l2h = msgb_put(out, 0);

	/* Attempt to compress the samples */
	rc = rtp_compress(&endp->compr_loc_state, out,
			  ENDPOINT_NUMBER(endp), &endp->compr_queue);
	if (rc == 0) {
		LOGP(DMGCP, LOGL_ERROR, "Failed to compress. %d\n", rc);
		goto cleanup;
	}

	/* send them out */
	rc = udp_send(rtp_end->rtp.fd, &rtp_end->addr, rtp_end->rtp_port,
		      (char *) out->l2h, msgb_l2len(out));

	/* cleanup */
	msgb_free(out);
	assert(llist_empty(&endp->compr_queue));
	endp->compr_queue_size = 0;
	return 1;

cleanup:
	mgcp_msgb_clear_queue(&endp->compr_queue);
	endp->compr_queue_size = 0;
	return 0;
}

static int queue_for_compr_net(struct mgcp_endpoint *endp, char *buf, int rc)
{
	struct msgb *msg = from_data(buf, rc);
	if (!msg)
		return -1;

	msgb_enqueue(&endp->compr_queue, msg);
	return maybe_send_queue(endp, &endp->net_end);
}

static int queue_for_compr_bts(struct mgcp_endpoint *endp, char *buf, int rc)
{
	struct msgb *msg = from_data(buf, rc);
	if (!msg)
		return -1;

	msgb_enqueue(&endp->compr_queue, msg);
	return maybe_send_queue(endp, &endp->net_end);
}

static int dispatch_from_net(struct osmo_fd *fd, int proto,
			     struct sockaddr_in *addr,
			     struct mgcp_endpoint *endp,
			     char *buf, int rc)
{
	endp->net_end.packets += 1;

	forward_data(fd->fd, &endp->taps[MGCP_TAP_NET_IN], buf, rc);
	if (endp->is_transcoded)
		return send_transcoder(&endp->trans_net, endp->cfg, proto == PROTO_RTP, &buf[0], rc);
	else {
		return send_to(endp, DEST_BTS, proto == PROTO_RTP, addr, &buf[0], rc);
	}
}

static int handle_compr_net(struct osmo_fd *fd, int proto,
			    struct sockaddr_in *addr,
			    struct mgcp_endpoint *endp,
			    char *buf, int rc)
{
	struct msgb *msg, *tmp;
	struct llist_head out_list;
	INIT_LLIST_HEAD(&out_list);

	msg = from_data(buf, rc);
	if (!msg) {
		LOGP(DMGCP, LOGL_ERROR,
		     "Failed to allocate buffer for decode on %d/0x%x\n",
		     ENDPOINT_NUMBER(endp), ENDPOINT_NUMBER(endp));
		return -1;
	}

	rc = rtp_decompress(&endp->compr_rem_state, &out_list, msg);
	msgb_free(msg);

	if (rc != 0) {
		LOGP(DMGCP, LOGL_ERROR,
		     "Failed to decode RTP stream %d/0x%x\n",
		     ENDPOINT_NUMBER(endp), ENDPOINT_NUMBER(endp));
		return -1;
	}

	llist_for_each_entry_safe(msg, tmp, &out_list, list) {
		dispatch_from_net(fd, proto, addr, endp, (char *) msg->l2h, msgb_l2len(msg));
		llist_del(&msg->list);
		msgb_free(msg);
	}

	return 0;
}

static int dispatch_from_bts(struct osmo_fd *fd, int proto,
			     struct sockaddr_in *addr,
			     struct mgcp_endpoint *endp,
			     char *buf, int rc)
{
	/* do this before the loop handling */
	endp->bts_end.packets += 1;

	forward_data(fd->fd, &endp->taps[MGCP_TAP_BTS_IN], buf, rc);
	if (endp->is_transcoded)
		return send_transcoder(&endp->trans_bts, endp->cfg, proto == PROTO_RTP, &buf[0], rc);
	else
		return send_to(endp, DEST_NETWORK, proto == PROTO_RTP, addr, &buf[0], rc);
}

static int handle_compr_bts(struct osmo_fd *fd, int proto,
			    struct sockaddr_in *addr,
			    struct mgcp_endpoint *endp,
			    char *buf, int rc)
{
	struct msgb *msg, *tmp;
	struct llist_head out_list;
	INIT_LLIST_HEAD(&out_list);

#warning "REMOVE code duplication here..."

	msg = from_data(buf, rc);
	if (!msg) {
		LOGP(DMGCP, LOGL_ERROR,
		     "Failed to allocate buffer for decode on %d/0x%x\n",
		     ENDPOINT_NUMBER(endp), ENDPOINT_NUMBER(endp));
		return -1;
	}

	rc = rtp_decompress(&endp->compr_rem_state, &out_list, msg);
	msgb_free(msg);

	if (rc != 0) {
		LOGP(DMGCP, LOGL_ERROR,
		     "Failed to decode RTP stream %d/0x%x\n",
		     ENDPOINT_NUMBER(endp), ENDPOINT_NUMBER(endp));
		return -1;
	}

	llist_for_each_entry_safe(msg, tmp, &out_list, list) {
		dispatch_from_bts(fd, proto, addr, endp, (char *) msg->l2h, msgb_l2len(msg));
		llist_del(&msg->list);
		msgb_free(msg);
	}

	return 0;
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
			if (tcfg->compress_dir == COMPR_NET && endp->compr_enabled)
				return queue_for_compr_net(endp, buf, rc);
			return udp_send(endp->net_end.rtp.fd, &endp->net_end.addr,
					endp->net_end.rtp_port, buf, rc);
		} else if (!endp->compr_enabled) {
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
			if (tcfg->compress_dir == COMPR_BTS && endp->compr_enabled)
				return queue_for_compr_bts(endp, buf, rc);
			return udp_send(endp->bts_end.rtp.fd, &endp->bts_end.addr,
					endp->bts_end.rtp_port, buf, rc);
		} else if (!endp->compr_enabled) {
			return udp_send(endp->bts_end.rtcp.fd, &endp->bts_end.addr,
					endp->bts_end.rtcp_port, buf, rc);
		}
	}

	return -1;
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
			"Data from wrong address %s on 0x%x\n",
			inet_ntoa(addr.sin_addr), ENDPOINT_NUMBER(endp));
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

	if (endp->compr_enabled && endp->tcfg->compress_dir == COMPR_NET)
		return handle_compr_net(fd, proto, &addr, endp, buf, rc);

	return dispatch_from_net(fd, proto, &addr, endp, buf, rc);
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
	struct mgcp_config *cfg;
	int rc, proto;

	endp = (struct mgcp_endpoint *) fd->data;
	cfg = endp->cfg;

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

	if (endp->compr_enabled && endp->tcfg->compress_dir == COMPR_BTS)
		return handle_compr_bts(fd, proto, &addr, endp, buf, rc);

	return dispatch_from_bts(fd, proto, &addr, endp, buf, rc);
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
