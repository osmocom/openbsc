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

#include <arpa/inet.h>
#include <sys/socket.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

/* called in the case of a non blocking connect */
static int msc_connection_connect(struct bsc_fd *fd, unsigned int what)
{
	int rc;
	int val;
	struct write_queue *queue;

	socklen_t len = sizeof(val);

	if ((what & BSC_FD_WRITE) == 0) {
		LOGP(DMSC, LOGL_ERROR, "Callback but not readable.\n");
		return -1;
	}

	/* check the socket state */
	rc = getsockopt(fd->fd, SOL_SOCKET, SO_ERROR, &val, &len);
	if (rc != 0) {
		LOGP(DMSC, LOGL_ERROR, "getsockopt for the MSC socket failed.\n");
		goto error;
	}
	if (val != 0) {
		LOGP(DMSC, LOGL_ERROR, "Not connected to the MSC.\n");
		goto error;
	}


	/* go to full operation */
	queue = container_of(fd, struct write_queue, bfd);
	fd->cb = write_queue_bfd_cb;
	fd->when = BSC_FD_READ;
	if (!llist_empty(&queue->msg_queue))
		fd->when |= BSC_FD_WRITE;
	return 0;

error:
	bsc_unregister_fd(fd);
	close(fd->fd);
	fd->fd = -1;
	fd->cb = write_queue_bfd_cb;
	fd->when = 0;
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

int connect_to_msc(struct bsc_fd *fd, const char *ip, int port)
{
	struct sockaddr_in sin;
	int on = 1, ret;

	printf("Attempting to connect MSC at %s:%d\n", ip, port);

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
	sin.sin_port = htons(port);
        inet_aton(ip, &sin.sin_addr);

	setsockopt(fd->fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
	ret = connect(fd->fd, (struct sockaddr *) &sin, sizeof(sin));

	if (ret == -1 && errno == EINPROGRESS) {
		LOGP(DMSC, LOGL_ERROR, "MSC Connection in progress\n");
		fd->when = BSC_FD_WRITE;
		fd->cb = msc_connection_connect;
	} else if (ret < 0) {
		perror("Connection failed");
		close(fd->fd);
		fd->fd = -1;
		return ret;
	} else {
		fd->when = BSC_FD_READ;
		fd->cb = write_queue_bfd_cb;
	}

	ret = bsc_register_fd(fd);
	if (ret < 0) {
		perror("Registering the fd failed");
		close(fd->fd);
		return ret;
	}

	return ret;
}
