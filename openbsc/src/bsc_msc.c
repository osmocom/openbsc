/* Routines to talk to the MSC using the IPA Protocol */
/*
 * (C) 2010 by Holger Hans Peter Freyther <zecke@selfish.org>
 * (C) 2010 by On-Waves
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

#include <openbsc/bsc_msc.h>
#include <openbsc/debug.h>

#include <osmocore/write_queue.h>
#include <osmocore/talloc.h>

#include <arpa/inet.h>
#include <sys/socket.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static void connection_loss(struct bsc_msc_connection *con)
{
	struct bsc_fd *fd;

	fd = &con->write_queue.bfd;

	close(fd->fd);
	fd->fd = -1;
	fd->cb = write_queue_bfd_cb;
	fd->when = 0;

	con->is_connected = 0;
	con->connection_loss(con);
}

static int bsc_msc_except(struct bsc_fd *bfd)
{
	struct write_queue *wrt;
	struct bsc_msc_connection *con;

	LOGP(DMSC, LOGL_ERROR, "Exception on the BFD. Closing down.\n");

	wrt = container_of(bfd, struct write_queue, bfd);
	con = container_of(wrt, struct bsc_msc_connection, write_queue);

	connection_loss(con);
	return 0;
}

/* called in the case of a non blocking connect */
static int msc_connection_connect(struct bsc_fd *fd, unsigned int what)
{
	int rc;
	int val;
	struct bsc_msc_connection *con;
	struct write_queue *queue;

	socklen_t len = sizeof(val);

	if ((what & BSC_FD_WRITE) == 0) {
		LOGP(DMSC, LOGL_ERROR, "Callback but not readable.\n");
		return -1;
	}

	queue = container_of(fd, struct write_queue, bfd);
	con = container_of(queue, struct bsc_msc_connection, write_queue);

	/* check the socket state */
	rc = getsockopt(fd->fd, SOL_SOCKET, SO_ERROR, &val, &len);
	if (rc != 0) {
		LOGP(DMSC, LOGL_ERROR, "getsockopt for the MSC socket failed.\n");
		goto error;
	}
	if (val != 0) {
		LOGP(DMSC, LOGL_ERROR, "Not connected to the MSC: %d\n", val);
		goto error;
	}


	/* go to full operation */
	fd->cb = write_queue_bfd_cb;
	fd->when = BSC_FD_READ | BSC_FD_EXCEPT;

	con->is_connected = 1;
	LOGP(DMSC, LOGL_NOTICE, "(Re)Connected to the MSC.\n");
	if (con->connected)
		con->connected(con);
	return 0;

error:
	bsc_unregister_fd(fd);
	connection_loss(con);
	return -1;
}
static void setnonblocking(struct bsc_fd *fd)
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
	struct bsc_fd *fd;
	struct sockaddr_in sin;
	int on = 1, ret;

	LOGP(DMSC, LOGL_NOTICE, "Attempting to connect MSC at %s:%d\n", con->ip, con->port);

	con->is_connected = 0;

	fd = &con->write_queue.bfd;
	fd->fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	fd->data = NULL;
	fd->priv_nr = 1;

	if (fd->fd < 0) {
		perror("Creating TCP socket failed");
		return fd->fd;
	}

	/* make it non blocking */
	setnonblocking(fd);

	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_port = htons(con->port);
	inet_aton(con->ip, &sin.sin_addr);

	setsockopt(fd->fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
	ret = connect(fd->fd, (struct sockaddr *) &sin, sizeof(sin));

	if (ret == -1 && errno == EINPROGRESS) {
		LOGP(DMSC, LOGL_ERROR, "MSC Connection in progress\n");
		fd->when = BSC_FD_WRITE;
		fd->cb = msc_connection_connect;
	} else if (ret < 0) {
		perror("Connection failed");
		connection_loss(con);
		return ret;
	} else {
		fd->when = BSC_FD_READ | BSC_FD_EXCEPT;
		fd->cb = write_queue_bfd_cb;
		con->is_connected = 1;
		if (con->connected)
			con->connected(con);
	}

	ret = bsc_register_fd(fd);
	if (ret < 0) {
		perror("Registering the fd failed");
		close(fd->fd);
		return ret;
	}

	return ret;
}

struct bsc_msc_connection *bsc_msc_create(const char *ip, int port)
{
	struct bsc_msc_connection *con;

	con = talloc_zero(NULL, struct bsc_msc_connection);
	if (!con) {
		LOGP(DMSC, LOGL_FATAL, "Failed to create the MSC connection.\n");
		return NULL;
	}

	con->ip = ip;
	con->port = port;
	write_queue_init(&con->write_queue, 100);
	con->write_queue.except_cb = bsc_msc_except;
	return con;
}

void bsc_msc_lost(struct bsc_msc_connection *con)
{
	write_queue_clear(&con->write_queue);
	bsc_unregister_fd(&con->write_queue.bfd);
	connection_loss(con);
}

static void reconnect_msc(void *_msc)
{
	struct bsc_msc_connection *con = _msc;

	LOGP(DMSC, LOGL_NOTICE, "Attempting to reconnect to the MSC.\n");
	bsc_msc_connect(con);
}

void bsc_msc_schedule_connect(struct bsc_msc_connection *con)
{
	LOGP(DMSC, LOGL_NOTICE, "Attempting to reconnect to the MSC.\n");
	con->reconnect_timer.cb = reconnect_msc;
	con->reconnect_timer.data = con;
	bsc_schedule_timer(&con->reconnect_timer, 5, 0);
}