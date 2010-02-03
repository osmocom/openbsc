/* A Media Gateway Control Protocol Media Gateway: RFC 3435 */

/*
 * (C) 2009 by Holger Hans Peter Freyther <zecke@selfish.org>
 * (C) 2009 by on-waves.com
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

#define RTP_PORT_DEFAULT 4000
extern unsigned int rtp_base_port;

/**
 * Calculate the RTP audio port for the given multiplex
 * and the direction. This allows a semi static endpoint
 * to port calculation removing the need for the BSC
 * and the MediaGateway to communicate.
 *
 * Port usage explained:
 *       base + (multiplex * 2) + 0 == local port to wait for network packets
 *       base + (multiplex * 2) + 1 == local port for rtcp
 *
 * The above port will receive packets from the BTS that need
 * to be patched and forwarded to the network.
 * The above port will receive packets from the network that
 * need to be patched and forwarded to the BTS.
 *
 * We assume to have a static BTS IP address so we can differentiate
 * network and BTS.
 *
 */
static inline int rtp_calculate_port(int multiplex, int base)
{
	return base + (multiplex * 2);
}

int mgcp_parse_config(const char *config_file, struct gsm_network *dummy_network);
int mgcp_handle_message(int fd, struct msgb *msg, struct sockaddr_in *source);
int mgcp_send_rsip(int fd, struct sockaddr_in *source);
int mgcp_vty_init(void);

/* endpoint managed */
#define MGCP_ENDP_CRCX 1
#define MGCP_ENDP_DLCX 2
#define MGCP_ENDP_MDCX 3

typedef int (*mgcp_change)(int endpoint, int state, int local_rtp, void *);
void mgcp_set_change_cb(mgcp_change cb, void *data);
