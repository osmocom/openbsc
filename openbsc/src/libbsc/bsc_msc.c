/* Routines to talk to the MSC using the IPA Protocol */
/*
 * (C) 2010 by Holger Hans Peter Freyther <zecke@selfish.org>
 * (C) 2010 by On-Waves
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

#include <openbsc/bsc_msc.h>
#include <openbsc/debug.h>
#include <osmocom/abis/ipaccess.h>

#include <osmocom/core/write_queue.h>
#include <osmocom/core/talloc.h>

#include <osmocom/gsm/tlv.h>

#include <arpa/inet.h>
#include <sys/socket.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static void connection_loss(struct bsc_msc_connection *con)
{
	struct osmo_fd *fd;

	fd = &con->write_queue.bfd;

	if (con->pending_msg) {
		LOGP(DMSC, LOGL_ERROR,
		     "MSC(%s) dropping incomplete message.\n", con->name);
		msgb_free(con->pending_msg);
		con->pending_msg = NULL;
	}

	close(fd->fd);
	fd->fd = -1;
	fd->cb = osmo_wqueue_bfd_cb;
	fd->when = 0;

	con->is_connected = 0;
	con->first_contact = 0;
	con->connection_loss(con);
}

static void msc_con_timeout(void *_con)
{
	struct bsc_msc_connection *con = _con;

	LOGP(DMSC, LOGL_ERROR,
		"MSC(%s) Connection timeout.\n", con->name);
	bsc_msc_lost(con);
}

/* called in the case of a non blocking connect */
static int msc_connection_connect(struct osmo_fd *fd, unsigned int what)
{
	int rc;
	int val;
	struct bsc_msc_connection *con;
	struct osmo_wqueue *queue;

	socklen_t len = sizeof(val);

	queue = container_of(fd, struct osmo_wqueue, bfd);
	con = container_of(queue, struct bsc_msc_connection, write_queue);

	if ((what & BSC_FD_WRITE) == 0) {
		LOGP(DMSC, LOGL_ERROR,
			"MSC(%s) Callback but not writable.\n", con->name);
		return -1;
	}

	/* From here on we will either be connected or reconnect */
	osmo_timer_del(&con->timeout_timer);

	/* check the socket state */
	rc = getsockopt(fd->fd, SOL_SOCKET, SO_ERROR, &val, &len);
	if (rc != 0) {
		LOGP(DMSC, LOGL_ERROR,
			"getsockopt for the MSC(%s) socket failed.\n", con->name);
		goto error;
	}
	if (val != 0) {
		LOGP(DMSC, LOGL_ERROR,
			"Not connected to the MSC(%s): %d\n",
			con->name, val);
		goto error;
	}


	/* go to full operation */
	fd->cb = osmo_wqueue_bfd_cb;
	fd->when = BSC_FD_READ | BSC_FD_EXCEPT;

	con->is_connected = 1;
	LOGP(DMSC, LOGL_NOTICE,
		"(Re)Connected to the MSC(%s).\n", con->name);
	if (con->connected)
		con->connected(con);
	return 0;

error:
	osmo_fd_unregister(fd);
	connection_loss(con);
	return -1;
}
static void setnonblocking(struct osmo_fd *fd)
{
	int flags;

	flags = fcntl(fd->fd, F_GETFL);
	if (flags < 0) {
		perror("fcntl get failed");
		close(fd->fd);
		fd->fd = -1;
		return;
	}

	flags |= O_NONBLOCK;
	flags = fcntl(fd->fd, F_SETFL, flags);
	if (flags < 0) {
		perror("fcntl get failed");
		close(fd->fd);
		fd->fd = -1;
		return;
	}
}

int bsc_msc_connect(struct bsc_msc_connection *con)
{
	struct bsc_msc_dest *dest;
	struct osmo_fd *fd;
	struct sockaddr_in sin;
	int on = 1, ret;

	if (llist_empty(con->dests)) {
		LOGP(DMSC, LOGL_ERROR,
			"No MSC(%s) connections configured.\n",
			con->name);
		connection_loss(con);
		return -1;
	}

	/* TODO: Why are we not using the libosmocore soecket
	 * abstraction, or libosmo-netif? */

	/* move to the next connection */
	dest = (struct bsc_msc_dest *) con->dests->next;
	llist_del(&dest->list);
	llist_add_tail(&dest->list, con->dests);

	LOGP(DMSC, LOGL_NOTICE,
		"Attempting to connect MSC(%s) at %s:%d\n",
		con->name, dest->ip, dest->port);

	con->is_connected = 0;

	msgb_free(con->pending_msg);
	con->pending_msg = NULL;

	fd = &con->write_queue.bfd;
	fd->fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	fd->priv_nr = 1;

	if (fd->fd < 0) {
		perror("Creating TCP socket failed");
		return fd->fd;
	}

	/* make it non blocking */
	setnonblocking(fd);

	/* set the socket priority */
	ret = setsockopt(fd->fd, IPPROTO_IP, IP_TOS,
			 &dest->dscp, sizeof(dest->dscp));
	if (ret != 0)
		LOGP(DMSC, LOGL_ERROR,
			"Failed to set DSCP to %d on MSC(%s). %s\n",
			dest->dscp, con->name, strerror(errno));

	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_port = htons(dest->port);
	inet_aton(dest->ip, &sin.sin_addr);

	ret = setsockopt(fd->fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
	if (ret != 0)
		LOGP(DMSC, LOGL_ERROR,
		     "Failed to set SO_REUSEADDR socket option\n");
	ret = connect(fd->fd, (struct sockaddr *) &sin, sizeof(sin));

	if (ret == -1 && errno == EINPROGRESS) {
		LOGP(DMSC, LOGL_ERROR,
			"MSC(%s) Connection in progress\n", con->name);
		fd->when = BSC_FD_WRITE;
		fd->cb = msc_connection_connect;
		osmo_timer_setup(&con->timeout_timer, msc_con_timeout, con);
		osmo_timer_schedule(&con->timeout_timer, 20, 0);
	} else if (ret < 0) {
		perror("Connection failed");
		connection_loss(con);
		return ret;
	} else {
		fd->when = BSC_FD_READ | BSC_FD_EXCEPT;
		fd->cb = osmo_wqueue_bfd_cb;
		con->is_connected = 1;
		if (con->connected)
			con->connected(con);
	}

	ret = osmo_fd_register(fd);
	if (ret < 0) {
		perror("Registering the fd failed");
		close(fd->fd);
		return ret;
	}

	return ret;
}

struct bsc_msc_connection *bsc_msc_create(void *ctx, struct llist_head *dests)
{
	struct bsc_msc_connection *con;

	con = talloc_zero(NULL, struct bsc_msc_connection);
	if (!con) {
		LOGP(DMSC, LOGL_FATAL, "Failed to create the MSC connection.\n");
		return NULL;
	}

	con->dests = dests;
	con->write_queue.bfd.fd = -1;
	con->name = "";
	osmo_wqueue_init(&con->write_queue, 100);
	return con;
}

void bsc_msc_lost(struct bsc_msc_connection *con)
{
	osmo_wqueue_clear(&con->write_queue);
	osmo_timer_del(&con->timeout_timer);
	osmo_timer_del(&con->reconnect_timer);

	if (con->write_queue.bfd.fd >= 0)
		osmo_fd_unregister(&con->write_queue.bfd);
	connection_loss(con);
}

static void reconnect_msc(void *_msc)
{
	struct bsc_msc_connection *con = _msc;

	LOGP(DMSC, LOGL_NOTICE,
		"Attempting to reconnect to the MSC(%s).\n", con->name);
	bsc_msc_connect(con);
}

void bsc_msc_schedule_connect(struct bsc_msc_connection *con)
{
	LOGP(DMSC, LOGL_NOTICE,
		"Attempting to reconnect to the MSC(%s)\n", con->name);
	osmo_timer_setup(&con->reconnect_timer, reconnect_msc, con);
	osmo_timer_schedule(&con->reconnect_timer, 5, 0);
}

struct msgb *bsc_msc_id_get_resp(int fixed, const char *token, const uint8_t *res, int len)
{
	struct msgb *msg;

	if (!token) {
		LOGP(DMSC, LOGL_ERROR, "No token specified.\n");
		return NULL;
	}

	msg = msgb_alloc_headroom(4096, 128, "id resp");
	if (!msg) {
		LOGP(DMSC, LOGL_ERROR, "Failed to create the message.\n");
		return NULL;
	}

	/*
	 * The situation is bizarre. The encoding doesn't follow the
	 * TLV structure. It is more like a LV and old versions had
	 * it wrong but we want new versions to old servers so we
	 * introduce the quirk here.
	 */
	msg->l2h = msgb_v_put(msg, IPAC_MSGT_ID_RESP);
	if (fixed) {
		msgb_put_u8(msg, 0);
		msgb_put_u8(msg, strlen(token) + 2);
		msgb_tv_fixed_put(msg, IPAC_IDTAG_UNITNAME, strlen(token) + 1, (uint8_t *) token);
		if (len > 0) {
			msgb_put_u8(msg, 0);
			msgb_put_u8(msg, len + 1);
			msgb_tv_fixed_put(msg, 0x24, len, res);
		}
	} else {
		msgb_l16tv_put(msg, strlen(token) + 1,
			IPAC_IDTAG_UNITNAME, (uint8_t *) token);
	}

	return msg;
}
