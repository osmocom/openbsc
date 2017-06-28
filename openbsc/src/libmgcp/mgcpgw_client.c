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

void mgcpgw_client_conf_init(struct mgcpgw_client_conf *conf)
{
	/* NULL and -1 default to MGCPGW_CLIENT_*_DEFAULT values */
	*conf = (struct mgcpgw_client_conf){
		.local_addr = NULL,
		.local_port = -1,
		.remote_addr = NULL,
		.remote_port = -1,
		.first_endpoint = 0,
		.last_endpoint = 0,
		.bts_base = 0,
	};
}

/* Test if a given endpoint id is currently in use */
static bool endpoint_in_use(uint16_t id, struct mgcpgw_client *client)
{
	struct mgcp_inuse_endpoint *endpoint;
	llist_for_each_entry(endpoint, &client->inuse_endpoints, entry) {
		if (endpoint->id == id)
			return true;
	}

	return false;
}

/* Find and seize an unsused endpoint id */
int mgcpgw_client_next_endpoint(struct mgcpgw_client *client)
{
	int i;
	uint16_t first_endpoint = client->actual.first_endpoint;
	uint16_t last_endpoint = client->actual.last_endpoint;
	struct mgcp_inuse_endpoint *endpoint;

	/* Use the maximum permitted range if the VTY
	 * configuration does not specify a range */
	if (client->actual.last_endpoint == 0) {
		first_endpoint = 1;
		last_endpoint = 65534;
	}

	/* Test the permitted endpoint range for an endpoint
	 * number that is not in use. When a suitable endpoint
	 * number can be found, seize it by adding it to the
	 * inuse list. */
	for (i=first_endpoint;i<last_endpoint;i++)
	{
		if (endpoint_in_use(i,client) == false) {
			endpoint = talloc_zero(client, struct mgcp_inuse_endpoint);
			endpoint->id = i;
			llist_add_tail(&endpoint->entry, &client->inuse_endpoints);
			return endpoint->id;
		}
	}

	/* All endpoints are busy! */
	return -EINVAL;
}

/* Release a seized endpoint id to make it available again for other calls */
void mgcpgw_client_release_endpoint(uint16_t id, struct mgcpgw_client *client)
{
	struct mgcp_inuse_endpoint *endpoint;
	struct mgcp_inuse_endpoint *endpoint_tmp;
	llist_for_each_entry_safe(endpoint, endpoint_tmp, &client->inuse_endpoints, entry) {
		if (endpoint->id == id) {
			llist_del(&endpoint->entry);
			talloc_free(endpoint);
		}
	}
}

static void mgcpgw_client_handle_response(struct mgcpgw_client *mgcp,
					  struct mgcp_response_pending *pending,
					  struct mgcp_response *response)
{
	if (!pending) {
		LOGP(DMGCP, LOGL_ERROR,
		     "Cannot handle NULL response\n");
		return;
	}
	if (pending->response_cb)
		pending->response_cb(response, pending->priv);
	else
		LOGP(DMGCP, LOGL_INFO, "MGCP response ignored (NULL cb)\n");
	talloc_free(pending);
}

static int mgcp_response_parse_head(struct mgcp_response *r, struct msgb *msg)
{
	int comment_pos;
	char *end;

	if (mgcp_msg_terminate_nul(msg))
		goto response_parse_failure;

	r->body = (char *)msg->data;

        if (sscanf(r->body, "%3d %u %n",
		   &r->head.response_code, &r->head.trans_id,
		   &comment_pos) != 2)
		goto response_parse_failure;

	r->head.comment = r->body + comment_pos;
	end = strchr(r->head.comment, '\r');
	if (!end)
		goto response_parse_failure;
	/* Mark the end of the comment */
	*end = '\0';
	r->body = end + 1;
	if (r->body[0] == '\n')
		r->body ++;
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
	int rc;
	OSMO_ASSERT(r->body);
	char *data = strstr(r->body, "\n\n");

	if (!data) {
		LOGP(DMGCP, LOGL_ERROR,
		     "MGCP response: cannot find start of parameters\n");
		return -EINVAL;
	}

	/* Advance to after the \n\n, replace the second \n with \0. That's
	 * where the parameters start. */
	data ++;
	*data = '\0';
	data ++;

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

/* Feed an MGCP message into the receive processing.
 * Parse the head and call any callback registered for the transaction id found
 * in the MGCP message. This is normally called directly from the internal
 * mgcp_do_read that reads from the socket connected to the MGCP gateway. This
 * function is published mainly to be able to feed data from the test suite.
 */
int mgcpgw_client_rx(struct mgcpgw_client *mgcp, struct msgb *msg)
{
	struct mgcp_response r = { 0 };
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
	ret = mgcpgw_client_rx(mgcp, msg);
	talloc_free(msg);
	return ret;
}

static int mgcp_do_write(struct osmo_fd *fd, struct msgb *msg)
{
	int ret;
	static char strbuf[4096];
	unsigned int l = msg->len < sizeof(strbuf) ? msg->len : sizeof(strbuf);
	unsigned int i;

	strncpy(strbuf, (const char*)msg->data, l);
	for (i = 0; i < sizeof(strbuf); i++) {
		if (strbuf[i] == '\n' || strbuf[i] == '\r') {
			strbuf[i] = '\0';
			break;
		}
	}
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
	struct mgcpgw_client *mgcp;

	mgcp = talloc_zero(ctx, struct mgcpgw_client);

	INIT_LLIST_HEAD(&mgcp->responses_pending);
	INIT_LLIST_HEAD(&mgcp->inuse_endpoints);

	mgcp->next_trans_id = 1;

	mgcp->actual.local_addr = conf->local_addr ? conf->local_addr :
		MGCPGW_CLIENT_LOCAL_ADDR_DEFAULT;
	mgcp->actual.local_port = conf->local_port >= 0 ? (uint16_t)conf->local_port :
		MGCPGW_CLIENT_LOCAL_PORT_DEFAULT;

	mgcp->actual.remote_addr = conf->remote_addr ? conf->remote_addr :
		MGCPGW_CLIENT_REMOTE_ADDR_DEFAULT;
	mgcp->actual.remote_port = conf->remote_port >= 0 ? (uint16_t)conf->remote_port :
		MGCPGW_CLIENT_REMOTE_PORT_DEFAULT;

	mgcp->actual.first_endpoint = conf->first_endpoint > 0 ? (uint16_t)conf->first_endpoint : 0;
	mgcp->actual.last_endpoint = conf->last_endpoint > 0 ? (uint16_t)conf->last_endpoint : 0;
	mgcp->actual.bts_base = conf->bts_base > 0 ? (uint16_t)conf->bts_base : 4000;

	return mgcp;
}

int mgcpgw_client_connect(struct mgcpgw_client *mgcp)
{
	int on;
	struct sockaddr_in addr;
	struct osmo_wqueue *wq;
	int rc;

	if (!mgcp) {
		LOGP(DMGCP, LOGL_FATAL, "MGCPGW client not initialized properly\n");
		return -EINVAL;
	}

	wq = &mgcp->wq;

	wq->bfd.fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (wq->bfd.fd < 0) {
		LOGP(DMGCP, LOGL_FATAL, "Failed to create UDP socket errno: %d\n", errno);
		return -errno;
	}

	on = 1;
	if (setsockopt(wq->bfd.fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) < 0) {
		LOGP(DMGCP, LOGL_FATAL,
		     "Failed to initialize socket for MGCP GW: %s\n",
		     strerror(errno));
		rc = -errno;
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
		rc = -errno;
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
		rc = -errno;
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
		rc = -EIO;
		goto error_close_fd;
	}
	LOGP(DMGCP, LOGL_INFO, "MGCP GW connection: %s:%u -> %s:%u\n",
	     mgcp->actual.local_addr, mgcp->actual.local_port,
	     mgcp->actual.remote_addr, mgcp->actual.remote_port);

	return 0;
error_close_fd:
	close(wq->bfd.fd);
	wq->bfd.fd = -1;
	return rc;
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

struct mgcp_response_pending * mgcpgw_client_pending_add(
					struct mgcpgw_client *mgcp,
					mgcp_trans_id_t trans_id,
					mgcp_response_cb_t response_cb,
					void *priv)
{
	struct mgcp_response_pending *pending;

	pending = talloc_zero(mgcp, struct mgcp_response_pending);
	pending->trans_id = trans_id;
	pending->response_cb = response_cb;
	pending->priv = priv;
	llist_add_tail(&pending->entry, &mgcp->responses_pending);

	return pending;
}

/* Send the MGCP message in msg to the MGCP GW and handle a response with
 * response_cb. NOTE: the response_cb still needs to call
 * mgcp_response_parse_params(response) to get the parsed parameters -- to
 * potentially save some CPU cycles, only the head line has been parsed when
 * the response_cb is invoked. */
int mgcpgw_client_tx(struct mgcpgw_client *mgcp, struct msgb *msg,
		     mgcp_response_cb_t response_cb, void *priv)
{
	struct mgcp_response_pending *pending;
	mgcp_trans_id_t trans_id;
	int rc;

	trans_id = msg->cb[MSGB_CB_MGCP_TRANS_ID];
	if (!trans_id) {
		LOGP(DMGCP, LOGL_ERROR,
		     "Unset transaction id in mgcp send request\n");
		talloc_free(msg);
		return -EINVAL;
	}

	pending = mgcpgw_client_pending_add(mgcp, trans_id, response_cb, priv);

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

static struct msgb *mgcp_msg_from_buf(mgcp_trans_id_t trans_id,
				      const char *buf, int len)
{
	struct msgb *msg;

	if (len > (4096 - 128)) {
		LOGP(DMGCP, LOGL_ERROR, "Cannot send to MGCP GW:"
		     " message too large: %d\n", len);
		return NULL;
	}

	msg = msgb_alloc_headroom(4096, 128, "MGCP tx");
	OSMO_ASSERT(msg);

	char *dst = (char*)msgb_put(msg, len);
	memcpy(dst, buf, len);
	msg->l2h = msg->data;
	msg->cb[MSGB_CB_MGCP_TRANS_ID] = trans_id;

	return msg;
}

static struct msgb *mgcp_msg_from_str(mgcp_trans_id_t trans_id,
				      const char *fmt, ...)
{
	static char compose[4096 - 128];
	va_list ap;
	int len;
	OSMO_ASSERT(fmt);

	va_start(ap, fmt);
	len = vsnprintf(compose, sizeof(compose), fmt, ap);
	va_end(ap);
	if (len >= sizeof(compose)) {
		LOGP(DMGCP, LOGL_ERROR,
		     "Message too large: trans_id=%u len=%d\n",
		     trans_id, len);
		return NULL;
	}
	if (len < 1) {
		LOGP(DMGCP, LOGL_ERROR,
		     "Failed to compose message: trans_id=%u len=%d\n",
		     trans_id, len);
		return NULL;
	}
	return mgcp_msg_from_buf(trans_id, compose, len);
}

static mgcp_trans_id_t mgcpgw_client_next_trans_id(struct mgcpgw_client *mgcp)
{
	/* avoid zero trans_id to distinguish from unset trans_id */
	if (!mgcp->next_trans_id)
		mgcp->next_trans_id ++;
	return mgcp->next_trans_id ++;
}

struct msgb *mgcp_msg_crcx(struct mgcpgw_client *mgcp,
			   uint16_t rtp_endpoint, unsigned int call_id,
			   enum mgcp_connection_mode mode)
{
	mgcp_trans_id_t trans_id = mgcpgw_client_next_trans_id(mgcp);
	return mgcp_msg_from_str(trans_id,
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

struct msgb *mgcp_msg_mdcx(struct mgcpgw_client *mgcp,
			   uint16_t rtp_endpoint, const char *rtp_conn_addr,
			   uint16_t rtp_port, enum mgcp_connection_mode mode)

{
	mgcp_trans_id_t trans_id = mgcpgw_client_next_trans_id(mgcp);
	return mgcp_msg_from_str(trans_id,
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

struct msgb *mgcp_msg_dlcx(struct mgcpgw_client *mgcp, uint16_t rtp_endpoint,
			   unsigned int call_id)
{
	mgcp_trans_id_t trans_id = mgcpgw_client_next_trans_id(mgcp);
	return mgcp_msg_from_str(trans_id,
				 "DLCX %u %x@mgw MGCP 1.0\r\n"
				 "C: %x\r\n", trans_id, rtp_endpoint, call_id);
}
