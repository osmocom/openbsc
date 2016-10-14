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
#include <openbsc/mgcp_internal.h>
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
	unsigned int next_trans_id;
	uint16_t next_endpoint;
	struct llist_head responses_pending;
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

static void mgcpgw_client_handle_response(struct mgcpgw_client *mgcp,
					  struct mgcp_response_pending *pending,
					  struct mgcp_response *response)
{
	if (!pending)
		return;
	if (pending->response_cb)
		pending->response_cb(response, pending->priv);
	else
		LOGP(DMGCP, LOGL_INFO, "MGCP response ignored (NULL cb)\n");
	talloc_free(pending);
}

static int mgcp_response_parse_head(struct mgcp_response *r, struct msgb *msg)
{
	int comment_pos;

	if (mgcp_msg_terminate_nul(msg))
		goto response_parse_failure;

	r->data = (char *)msg->data;

        if (sscanf(r->data, "%3d %u %n",
		   &r->head.response_code, &r->head.trans_id,
		   &comment_pos) != 2)
		goto response_parse_failure;

	r->head.comment = r->data + comment_pos;
	return 0;

response_parse_failure:
	LOGP(DMGCP, LOGL_ERROR,
	     "Failed to parse MGCP response header\n");
	return -EINVAL;
}

/* TODO undup against mgcp_protocol.c:mgcp_check_param() */
static bool mgcp_line_is_valid(const char *line)
{
	const size_t line_len = strlen(line);
	if (line[0] == '\0')
		return true;

	if (line_len < 2
	    || line[1] != '=') {
		LOGP(DMGCP, LOGL_ERROR,
		     "Wrong MGCP option format: '%s'\n",
		     line);
		return false;
	}

	return true;
}

/* Parse a line like "m=audio 16002 RTP/AVP 98" */
static int mgcp_parse_audio(struct mgcp_response *r, const char *line)
{
        if (sscanf(line, "m=audio %hu",
		   &r->audio_port) != 1)
		goto response_parse_failure;

	return 0;

response_parse_failure:
	LOGP(DMGCP, LOGL_ERROR,
	     "Failed to parse MGCP response header\n");
	return -EINVAL;
}

int mgcp_response_parse_params(struct mgcp_response *r)
{
	char *line;
	char *data = r->data;
	int rc;
	for_each_line(line, data) {
		if (!mgcp_line_is_valid(line))
			return -EINVAL;

		switch (line[0]) {
		case 'm':
			rc = mgcp_parse_audio(r, line);
			if (rc)
				return rc;
			break;
		default:
			/* skip unhandled parameters */
			break;
		}
	}
	return 0;
}

static struct mgcp_response_pending *mgcpgw_client_response_pending_get(
					 struct mgcpgw_client *mgcp,
					 struct mgcp_response *r)
{
	struct mgcp_response_pending *pending;
	if (!r)
		return NULL;
	llist_for_each_entry(pending, &mgcp->responses_pending, entry) {
		if (pending->trans_id == r->head.trans_id) {
			llist_del(&pending->entry);
			return pending;
		}
	}
	return NULL;
}

static int mgcpgw_client_read(struct mgcpgw_client *mgcp, struct msgb *msg)
{
	struct mgcp_response r;
	struct mgcp_response_pending *pending;
	int rc;

	rc = mgcp_response_parse_head(&r, msg);
	if (rc) {
		LOGP(DMGCP, LOGL_ERROR, "Cannot parse MGCP response\n");
		return -1;
	}
	
	pending = mgcpgw_client_response_pending_get(mgcp, &r);
	if (!pending) {
		LOGP(DMGCP, LOGL_ERROR,
		     "Cannot find matching MGCP transaction for trans_id %d\n",
		     r.head.trans_id);
		return -1;
	}

	mgcpgw_client_handle_response(mgcp, pending, &r);
	return 0;
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
	ret = mgcpgw_client_read(mgcp, msg);
	talloc_free(msg);
	return ret;
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
					 struct mgcpgw_client_conf *conf)
{
	int on;
	struct sockaddr_in addr;
	struct mgcpgw_client *mgcp;
	struct osmo_wqueue *wq;

	mgcp = talloc_zero(ctx, struct mgcpgw_client);

	INIT_LLIST_HEAD(&mgcp->responses_pending);

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

int mgcpgw_client_tx(struct mgcpgw_client *mgcp,
		     mgcp_response_cb_t response_cb, void *priv,
		     struct msgb *msg, unsigned int trans_id)
{
	struct mgcp_response_pending *pending;
	int rc;

	pending = talloc_zero(mgcp, struct mgcp_response_pending);
	pending->trans_id = trans_id;
	pending->response_cb = response_cb;
	pending->priv = priv;
	llist_add_tail(&pending->entry, &mgcp->responses_pending);

	if (msgb_l2len(msg) > 4096) {
		LOGP(DMGCP, LOGL_ERROR,
		     "Cannot send, MGCP message too large: %u\n",
		     msgb_l2len(msg));
		msgb_free(msg);
		rc = -EINVAL;
		goto mgcp_tx_error;
	}

	rc = osmo_wqueue_enqueue(&mgcp->wq, msg);
	if (rc) {
		LOGP(DMGCP, LOGL_FATAL, "Could not queue message to MGCP GW\n");
		msgb_free(msg);
		goto mgcp_tx_error;
	} else
		LOGP(DMGCP, LOGL_INFO, "Queued %u bytes for MGCP GW\n",
		     msgb_l2len(msg));
	return 0;

mgcp_tx_error:
	/* Pass NULL to response cb to indicate an error */
	mgcpgw_client_handle_response(mgcp, pending, NULL);
	return -1;
}

int mgcpgw_client_tx_buf(struct mgcpgw_client *mgcp,
			 mgcp_response_cb_t response_cb, void *priv,
			 const char *buf, int len,
			 unsigned int trans_id)
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

	return mgcpgw_client_tx(mgcp, response_cb, priv, msg, trans_id);
}

int mgcpgw_client_tx_str(struct mgcpgw_client *mgcp,
			 mgcp_response_cb_t response_cb, void *priv,
			 unsigned int trans_id,
			 const char *fmt, ...)
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
	return mgcpgw_client_tx_buf(mgcp, response_cb, priv, compose, len, trans_id);
}

int mgcpgw_client_tx_crcx(struct mgcpgw_client *mgcp,
			  mgcp_response_cb_t response_cb, void *priv,
			  uint16_t rtp_endpoint, unsigned int call_id,
			  enum mgcp_connection_mode mode)
{
	unsigned int trans_id = mgcp->next_trans_id ++;
	return mgcpgw_client_tx_str(mgcp,
		 response_cb, priv, trans_id,
		 "CRCX %u %x@mgw MGCP 1.0\r\n"
		 "C: %x\r\n"
		 "L: p:20, a:AMR, nt:IN\r\n"
		 "M: %s\r\n"
		 ,
		 trans_id,
		 rtp_endpoint,
		 call_id,
		 mgcp_cmode_name(mode));
}

int mgcpgw_client_tx_mdcx(struct mgcpgw_client *mgcp,
			  mgcp_response_cb_t response_cb, void *priv,
			  uint16_t rtp_endpoint, const char *rtp_conn_addr,
			  uint16_t rtp_port, enum mgcp_connection_mode mode)

{
	unsigned int trans_id = mgcp->next_trans_id ++;
	return mgcpgw_client_tx_str(mgcp,
		 response_cb, priv, trans_id,
		 "MDCX %u %x@mgw MGCP 1.0\r\n"
		 "M: %s\r\n"
		 "\r\n"
		 "c=IN IP4 %s\r\n"
		 "m=audio %u RTP/AVP 255\r\n"
		 ,
		 trans_id,
		 rtp_endpoint,
		 mgcp_cmode_name(mode),
		 rtp_conn_addr,
		 rtp_port);
}
