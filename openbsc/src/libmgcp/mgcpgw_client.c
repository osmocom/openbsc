/* mgcp_utils - common functions to setup an MGCP connection
 */
/* (C) 2016 by sysmocom s.f.m.c. GmbH <info@sysmocom.de>
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

#include <osmocom/core/select.h>
#include <osmocom/core/write_queue.h>
#include <osmocom/core/msgb.h>
#include <osmocom/core/logging.h>

#include <openbsc/mgcpgw_client.h>
#include <openbsc/mgcp.h>
#include <openbsc/debug.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#include <errno.h>
#include <unistd.h>
#include <string.h>

struct mgcpgw_client {
	struct mgcpgw_client_conf actual;
	uint32_t remote_addr;
	struct osmo_wqueue wq;
	mgcp_rx_cb_t rx_cb;
	void *rx_cb_priv;
	unsigned int next_trans_id;
	uint16_t next_endpoint;
};

void mgcpgw_client_conf_init(struct mgcpgw_client_conf *conf)
{
	/* NULL and -1 default to MGCPGW_CLIENT_*_DEFAULT values */
	*conf = (struct mgcpgw_client_conf){
		.local_addr = NULL,
		.local_port = -1,
		.remote_addr = NULL,
		.remote_port = -1,
	};
}

unsigned int mgcpgw_client_next_endpoint(struct mgcpgw_client *client)
{
	return client->next_endpoint ++;
}

static int mgcp_do_read(struct osmo_fd *fd)
{
	struct mgcpgw_client *mgcp = fd->data;
	struct msgb *msg;
	int ret;

	msg = msgb_alloc_headroom(4096, 128, "mgcp_from_gw");
	if (!msg) {
		LOGP(DMGCP, LOGL_ERROR, "Failed to allocate MGCP message.\n");
		return -1;
	}

	ret = read(fd->fd, msg->data, 4096 - 128);
	if (ret <= 0) {
		LOGP(DMGCP, LOGL_ERROR, "Failed to read: %d/%s\n", errno, strerror(errno));
		msgb_free(msg);
		return -1;
	} else if (ret > 4096 - 128) {
		LOGP(DMGCP, LOGL_ERROR, "Too much data: %d\n", ret);
		msgb_free(msg);
		return -1;
        }

	msg->l2h = msgb_put(msg, ret);
	if (mgcp->rx_cb)
		mgcp->rx_cb(msg, mgcp->rx_cb_priv);
	return 0;
}

static int mgcp_do_write(struct osmo_fd *fd, struct msgb *msg)
{
	int ret;
	static char strbuf[4096];
	unsigned int l = msg->len < sizeof(strbuf)-1 ? msg->len : sizeof(strbuf)-1;
	strncpy(strbuf, (const char*)msg->data, l);
	strbuf[l] = '\0';
	DEBUGP(DMGCP, "Tx MGCP msg to MGCP GW: '%s'\n", strbuf);

	LOGP(DMGCP, LOGL_DEBUG, "Sending msg to MGCP GW size: %u\n", msg->len);

	ret = write(fd->fd, msg->data, msg->len);
	if (ret != msg->len)
		LOGP(DMGCP, LOGL_ERROR, "Failed to forward message to MGCP"
		     " GW: %s\n", strerror(errno));

	return ret;
}

struct mgcpgw_client *mgcpgw_client_init(void *ctx,
					 struct mgcpgw_client_conf *conf,
					 mgcp_rx_cb_t rx_cb, void *rx_cb_priv)
{
	int on;
	struct sockaddr_in addr;
	struct mgcpgw_client *mgcp;
	struct osmo_wqueue *wq;

	mgcp = talloc_zero(ctx, struct mgcpgw_client);

	mgcp->next_trans_id = 1;
	mgcp->next_endpoint = 1;

	mgcp->actual.local_addr = conf->local_addr ? conf->local_addr :
		MGCPGW_CLIENT_LOCAL_ADDR_DEFAULT;
	mgcp->actual.local_port = conf->local_port >= 0 ? (uint16_t)conf->local_port :
		MGCPGW_CLIENT_LOCAL_PORT_DEFAULT;

	mgcp->actual.remote_addr = conf->remote_addr ? conf->remote_addr :
		MGCPGW_CLIENT_REMOTE_ADDR_DEFAULT;
	mgcp->actual.remote_port = conf->remote_port >= 0 ? (uint16_t)conf->remote_port :
		MGCPGW_CLIENT_REMOTE_PORT_DEFAULT;

	mgcp->rx_cb = rx_cb;
	mgcp->rx_cb_priv = rx_cb_priv;
	wq = &mgcp->wq;

	wq->bfd.fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (wq->bfd.fd < 0) {
		LOGP(DMGCP, LOGL_FATAL, "Failed to create UDP socket errno: %d\n", errno);
		goto error_free;
	}

	on = 1;
	if (setsockopt(wq->bfd.fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) < 0) {
		LOGP(DMGCP, LOGL_FATAL,
		     "Failed to initialize socket for MGCP GW: %s\n",
		     strerror(errno));
		goto error_close_fd;
	}

	/* bind socket */
	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	inet_aton(mgcp->actual.local_addr, &addr.sin_addr);
	addr.sin_port = htons(mgcp->actual.local_port);
	if (bind(wq->bfd.fd, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
		LOGP(DMGCP, LOGL_FATAL,
		     "Failed to bind for MGCP GW to %s %u\n",
		     mgcp->actual.local_addr, mgcp->actual.local_port);
		goto error_close_fd;
	}

	/* connect to the remote */
	inet_aton(mgcp->actual.remote_addr, &addr.sin_addr);
	addr.sin_port = htons(mgcp->actual.remote_port);
	if (connect(wq->bfd.fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		LOGP(DMGCP, LOGL_FATAL,
		     "Failed to connect to MGCP GW at %s %u: %s\n",
		     mgcp->actual.remote_addr, mgcp->actual.remote_port,
		     strerror(errno));
		goto error_close_fd;
	}

	mgcp->remote_addr = htonl(addr.sin_addr.s_addr);

	osmo_wqueue_init(wq, 10);
	wq->bfd.when = BSC_FD_READ;
	wq->bfd.data = mgcp;
	wq->read_cb = mgcp_do_read;
	wq->write_cb = mgcp_do_write;

	if (osmo_fd_register(&wq->bfd) != 0) {
		LOGP(DMGCP, LOGL_FATAL, "Failed to register BFD\n");
		goto error_close_fd;
	}
	LOGP(DMGCP, LOGL_INFO, "MGCP GW connection: %s:%u -> %s:%u\n",
	     mgcp->actual.local_addr, mgcp->actual.local_port,
	     mgcp->actual.remote_addr, mgcp->actual.remote_port);

	return mgcp;
error_close_fd:
	close(wq->bfd.fd);
	wq->bfd.fd = -1;
error_free:
	talloc_free(mgcp);
	return NULL;
}

const char *mgcpgw_client_remote_addr_str(struct mgcpgw_client *mgcp)
{
	return mgcp->actual.remote_addr;
}

uint16_t mgcpgw_client_remote_port(struct mgcpgw_client *mgcp)
{
	return mgcp->actual.remote_port;
}

/* Return the MGCP GW binary IPv4 address in network byte order. */
uint32_t mgcpgw_client_remote_addr_n(struct mgcpgw_client *mgcp)
{
	return mgcp->remote_addr;
}

int mgcpgw_client_tx(struct mgcpgw_client *mgcp, struct msgb *msg)
{
	int rc;

	if (msgb_l2len(msg) > 4096) {
		LOGP(DMGCP, LOGL_ERROR,
		     "Cannot send, MGCP message too large: %u\n",
		     msgb_l2len(msg));
		msgb_free(msg);
		return -EINVAL;
	}

	rc = osmo_wqueue_enqueue(&mgcp->wq, msg);
	if (rc) {
		LOGP(DMGCP, LOGL_FATAL, "Could not queue message to MGCP GW\n");
		msgb_free(msg);
		return rc;
	} else
		LOGP(DMGCP, LOGL_INFO, "Queued %u bytes for MGCP GW\n",
		     msgb_l2len(msg));
	return 0;
}

int mgcpgw_client_tx_buf(struct mgcpgw_client *mgcp, const char *buf, int len)
{
	struct msgb *msg;

	if (len > (4096 - 128)) {
		LOGP(DMGCP, LOGL_ERROR, "Cannot send to MGCP GW:"
		     " message too large: %d\n", len);
		return -ENOTSUP;
	}

	msg = msgb_alloc_headroom(4096, 128, "MGCP Tx");
	OSMO_ASSERT(msg);

	char *dst = (char*)msgb_put(msg, len);
	memcpy(dst, buf, len);
	msg->l2h = msg->data;

	return mgcpgw_client_tx(mgcp, msg);
}

int mgcpgw_client_tx_str(struct mgcpgw_client *mgcp, const char *fmt, ...)
{
	char compose[4096 - 128];
	va_list ap;
	int len;
	OSMO_ASSERT(fmt);

	va_start(ap, fmt);
	len = vsnprintf(compose, sizeof(compose), fmt, ap);
	va_end(ap);
	if (len >= sizeof(compose))
		return -EMSGSIZE;
	if (len < 1)
		return -EIO;
	return mgcpgw_client_tx_buf(mgcp, compose, len);
}

int mgcpgw_client_tx_crcx(struct mgcpgw_client *client,
			  uint16_t rtp_endpoint, unsigned int call_id,
			  enum mgcp_connection_mode mode)
{
	return mgcpgw_client_tx_str(client,
		 "CRCX %u %x@mgw MGCP 1.0\r\n"
		 "C: %x\r\n"
		 "L: p:20, a:AMR, nt:IN\r\n"
		 "M: %s\r\n"
		 ,
		 client->next_trans_id ++,
		 rtp_endpoint,
		 call_id,
		 mgcp_cmode_name(mode));
}

int mgcpgw_client_tx_mdcx(struct mgcpgw_client *client, uint16_t rtp_endpoint,
			  const char *rtp_conn_addr, uint16_t rtp_port,
			  enum mgcp_connection_mode mode)
{
	return mgcpgw_client_tx_str(client,
		 "MDCX %u %x@mgw MGCP 1.0\r\n"
		 "M: %s\r\n"
		 "\r\n"
		 "c=IN IP4 %s\r\n"
		 "m=audio %u RTP/AVP 255\r\n"
		 ,
		 client->next_trans_id ++,
		 rtp_endpoint,
		 mgcp_cmode_name(mode),
		 rtp_conn_addr,
		 rtp_port);
}
