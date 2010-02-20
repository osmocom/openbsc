#ifndef _RTP_PROXY_H
#define _RTP_PROXY_H

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


#include <netinet/in.h>

#include <osmocore/linuxlist.h>
#include <osmocore/select.h>

enum rtp_rx_action {
	RTP_NONE,
	RTP_PROXY,
	RTP_RECV_UPSTREAM,
};

enum rtp_tx_action {
	RTP_SEND_NONE,
	RTP_SEND_DOWNSTREAM,
};

struct rtp_sub_socket {
	struct sockaddr_in sin_local;
	struct sockaddr_in sin_remote;

	struct bsc_fd bfd;
	/* linked list of to-be-transmitted msgb's */
	struct llist_head tx_queue;
};

struct rtp_socket {
	struct llist_head list;

	struct rtp_sub_socket rtp;
	struct rtp_sub_socket rtcp;

	/* what should we do on receive? */
	enum rtp_rx_action rx_action;
	union {
		struct {
			struct rtp_socket *other_sock;
		} proxy;
		struct {
			struct gsm_network *net;
			u_int32_t callref;
		} receive;
	};
	enum rtp_tx_action tx_action;
	struct {
		u_int16_t sequence;
		u_int32_t timestamp;
		u_int32_t ssrc;
		struct timeval last_tv;
	} transmit;
};

struct rtp_socket *rtp_socket_create(void);
int rtp_socket_bind(struct rtp_socket *rs, u_int32_t ip);
int rtp_socket_connect(struct rtp_socket *rs, u_int32_t ip, u_int16_t port);
int rtp_socket_proxy(struct rtp_socket *this, struct rtp_socket *other);
int rtp_socket_upstream(struct rtp_socket *this, struct gsm_network *net, u_int32_t callref);
int rtp_socket_free(struct rtp_socket *rs);
int rtp_send_frame(struct rtp_socket *rs, struct gsm_data_frame *frame);

#endif /* _RTP_PROXY_H */
