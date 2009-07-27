/* RTP proxy handling for ip.access nanoBTS */

/* (C) 2009 by Harald Welte <laforge@gnumonks.org>
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

#include <errno.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include <openbsc/talloc.h>
#include <openbsc/gsm_data.h>
#include <openbsc/msgb.h>
#include <openbsc/select.h>
#include <openbsc/rtp_proxy.h>

static LLIST_HEAD(rtp_sockets);

enum rtp_bfd_priv {
	RTP_PRIV_NONE,
	RTP_PRIV_RTP,
	RTP_PRIV_RTCP
};

#define RTP_ALLOC_SIZE	1500

/* read from incoming RTP/RTCP socket */
static int rtp_socket_read(struct rtp_socket *rs, struct rtp_sub_socket *rss)
{
	int rc;
	struct msgb *msg = msgb_alloc(RTP_ALLOC_SIZE, "RTP/RTCP");
	struct rtp_sub_socket *other_rss;

	if (!msg)
		return -ENOMEM;

	rc = read(rss->bfd.fd, msg->data, RTP_ALLOC_SIZE);
	if (rc <= 0) {
		rss->bfd.when &= ~BSC_FD_READ;
		return rc;
	}

	msgb_put(msg, rc);

	switch (rs->rx_action) {
	case RTP_PROXY:
		if (rss->bfd.priv_nr == RTP_PRIV_RTP)
			other_rss = &rs->proxy.other_sock->rtp;
		else if (rss->bfd.priv_nr == RTP_PRIV_RTCP)
			other_rss = &rs->proxy.other_sock->rtcp;
		else {
			msgb_free(msg);
			return -EINVAL;
		}
		msgb_enqueue(&other_rss->tx_queue, msg);
		other_rss->bfd.when |= BSC_FD_WRITE;
		break;
	/* FIXME: other cases */
	}

	return rc;
}

/* write from tx_queue to RTP/RTCP socket */
static int rtp_socket_write(struct rtp_socket *rs, struct rtp_sub_socket *rss)
{
	struct msgb *msg;
	int written;

	msg = msgb_dequeue(&rss->tx_queue);
	if (!msg) {
		rss->bfd.when &= ~BSC_FD_WRITE;
		return 0;
	}

	written = write(rss->bfd.fd, msg->data, msg->len);
	if (written < msg->len) {
		perror("short write");
		msgb_free(msg);
		return -EIO;
	}

	msgb_free(msg);

	return 0;
}


/* callback for the select.c:bfd_* layer */
static int rtp_bfd_cb(struct bsc_fd *bfd, unsigned int flags)
{
	struct rtp_socket *rs = bfd->data;
	struct rtp_sub_socket *rss;

	switch (bfd->priv_nr) {
	case RTP_PRIV_RTP:
		rss = &rs->rtp;
		break;
	case RTP_PRIV_RTCP:
		rss = &rs->rtcp;
		break;
	default:
		return -EINVAL;
	}

	if (flags & BSC_FD_READ)
		rtp_socket_read(rs, rss);

	if (flags & BSC_FD_WRITE)
		rtp_socket_write(rs, rss);

	return 0;
}

static void init_rss(struct rtp_sub_socket *rss, 
		     struct rtp_socket *rs, int fd, int priv_nr)
{
	/* initialize bfd */
	rss->bfd.fd = fd;
	rss->bfd.data = rs;
	rss->bfd.priv_nr = priv_nr;
	rss->bfd.cb = rtp_bfd_cb;
}

struct rtp_socket *rtp_socket_create(void)
{
	int rc;
	struct rtp_socket *rs;

	rs = talloc_zero(tall_bsc_ctx, struct rtp_socket);
	if (!rs)
		return NULL;

	INIT_LLIST_HEAD(&rs->rtp.tx_queue);
	INIT_LLIST_HEAD(&rs->rtcp.tx_queue);

	rc = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (rc < 0)
		goto out_free;

	init_rss(&rs->rtp, rs, rc, RTP_PRIV_RTP);
	rc = bsc_register_fd(&rs->rtp.bfd);
	if (rc < 0)
		goto out_rtp_socket;

	rc = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (rc < 0)
		goto out_rtp_bfd;

	init_rss(&rs->rtcp, rs, rc, RTP_PRIV_RTCP);
	rc = bsc_register_fd(&rs->rtcp.bfd);
	if (rc < 0)
		goto out_rtcp_socket;

	return rs;

out_rtcp_socket:
	close(rs->rtcp.bfd.fd);
out_rtp_bfd:
	bsc_unregister_fd(&rs->rtp.bfd);
out_rtp_socket:
	close(rs->rtp.bfd.fd);
out_free:
	talloc_free(rs);
	return NULL;
}

static int rtp_sub_socket_bind(struct rtp_sub_socket *rss, u_int32_t ip,
				u_int16_t port)
{
	rss->sin_local.sin_family = AF_INET;
	rss->sin_local.sin_addr.s_addr = htonl(ip);
	rss->sin_local.sin_port = htons(port);
	rss->bfd.when |= BSC_FD_READ;

	return bind(rss->bfd.fd, (struct sockaddr *)&rss->sin_local,
		    sizeof(rss->sin_local));
}

#define RTP_PORT_BASE	30000
static u_int16_t next_udp_port = RTP_PORT_BASE;

/* bind a RTP socket to a local address */
int rtp_socket_bind(struct rtp_socket *rs, u_int32_t ip)
{
	int rc;

	/* try to bind to a consecutive pair of ports */
	for (next_udp_port; next_udp_port < 0xffff; next_udp_port += 2) {
		rc = rtp_sub_socket_bind(&rs->rtp, ip, next_udp_port);
		if (rc != 0)
			continue;

		rc = rtp_sub_socket_bind(&rs->rtcp, ip, next_udp_port+1);
		if (rc == 0)
			break;
	}
	if (rc < 0)
		return rc;

	return ntohs(rs->rtp.sin_local.sin_port);
}

static int rtp_sub_socket_connect(struct rtp_sub_socket *rss,
				  u_int32_t ip, u_int16_t port)
{
	rss->sin_remote.sin_family = AF_INET;
	rss->sin_remote.sin_addr.s_addr = htonl(ip);
	rss->sin_remote.sin_port = htons(port);

	return connect(rss->bfd.fd, (struct sockaddr *) &rss->sin_remote,
			sizeof(rss->sin_remote));
}

/* 'connect' a RTP socket to a remote peer */
int rtp_socket_connect(struct rtp_socket *rs, u_int32_t ip, u_int16_t port)
{
	int rc;

	rc = rtp_sub_socket_connect(&rs->rtp, ip, port);
	if (rc < 0)
		return rc;

	return rtp_sub_socket_connect(&rs->rtcp, ip, port+1);
}

/* bind two RTP/RTCP sockets together */
int rtp_socket_proxy(struct rtp_socket *this, struct rtp_socket *other)
{
	this->rx_action = RTP_PROXY;
	this->proxy.other_sock = other;

	other->rx_action = RTP_PROXY;
	other->proxy.other_sock = this;

	return 0;
}

static void free_tx_queue(struct rtp_sub_socket *rss)
{
	struct msgb *msg;
	
	while ((msg = msgb_dequeue(&rss->tx_queue)))
		msgb_free(msg);
}

int rtp_socket_free(struct rtp_socket *rs)
{

	/* make sure we don't leave references dangling to us */
	if (rs->rx_action == RTP_PROXY &&
	    rs->proxy.other_sock)
		rs->proxy.other_sock->proxy.other_sock = NULL;

	bsc_unregister_fd(&rs->rtp.bfd);
	close(rs->rtp.bfd.fd);
	free_tx_queue(&rs->rtp);

	bsc_unregister_fd(&rs->rtcp.bfd);
	close(rs->rtcp.bfd.fd);
	free_tx_queue(&rs->rtcp);

	talloc_free(rs);

	return 0;
}
