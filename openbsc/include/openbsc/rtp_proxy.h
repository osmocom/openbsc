#ifndef _RTP_PROXY_H
#define _RTP_PROXY_H

/* RTP proxy handling for ip.access nanoBTS */

/* (C) 2009 by Harald Welte <laforge@gnumonks.org>
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


#include <netinet/in.h>

#include <osmocom/core/linuxlist.h>
#include <osmocom/core/select.h>

#include <openbsc/mncc.h>

#define RTP_PT_GSM_FULL 3
#define RTP_PT_GSM_HALF 96
#define RTP_PT_GSM_EFR 97
#define RTP_PT_AMR 98
#define RTP_LEN_GSM_FULL 33
#define RTP_LEN_GSM_HALF 15
#define RTP_LEN_GSM_EFR 31
#define RTP_GSM_DURATION 160

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

	struct osmo_fd bfd;
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
			uint32_t callref;
		} receive;
	};
	enum rtp_tx_action tx_action;
	struct {
		uint16_t sequence;
		uint32_t timestamp;
		uint32_t ssrc;
		struct timeval last_tv;
	} transmit;
};

struct rtp_socket *rtp_socket_create(void);
int rtp_socket_bind(struct rtp_socket *rs, uint32_t ip);
int rtp_socket_connect(struct rtp_socket *rs, uint32_t ip, uint16_t port);
int rtp_socket_proxy(struct rtp_socket *this, struct rtp_socket *other);
int rtp_socket_upstream(struct rtp_socket *this, struct gsm_network *net, uint32_t callref);
int rtp_socket_free(struct rtp_socket *rs);
int rtp_send_frame(struct rtp_socket *rs, struct gsm_data_frame *frame);

#endif /* _RTP_PROXY_H */
