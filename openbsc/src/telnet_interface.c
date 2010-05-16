/* minimalistic telnet/network interface it might turn into a wire interface */
/* (C) 2009 by Holger Hans Peter Freyther <zecke@selfish.org>
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

#include <sys/socket.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <openbsc/telnet_interface.h>
#include <openbsc/gsm_subscriber.h>
#include <openbsc/chan_alloc.h>
#include <openbsc/gsm_04_08.h>
#include <openbsc/gsm_04_11.h>
#include <osmocore/msgb.h>
#include <openbsc/abis_rsl.h>
#include <openbsc/paging.h>
#include <openbsc/signal.h>
#include <osmocore/talloc.h>
#include <openbsc/debug.h>

#include <vty/buffer.h>

/* per connection data */
LLIST_HEAD(active_connections);

static void *tall_telnet_ctx;

/* per network data */
static int telnet_new_connection(struct bsc_fd *fd, unsigned int what);

static struct bsc_fd server_socket = {
	.when	    = BSC_FD_READ,
	.cb	    = telnet_new_connection,
	.priv_nr    = 0,
};

void telnet_init(struct gsm_network *network, int port) {
	struct sockaddr_in sock_addr;
	int fd, on = 1;

	tall_telnet_ctx = talloc_named_const(tall_bsc_ctx, 1,
					     "telnet_connection");

	bsc_vty_init(network);

	fd = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);

	if (fd < 0) {
		LOGP(DNM, LOGL_ERROR, "Telnet interface socket creation failed\n");
		return;
	}

	setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));

	memset(&sock_addr, 0, sizeof(sock_addr));
	sock_addr.sin_family = AF_INET;
	sock_addr.sin_port = htons(port);
	sock_addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

	if (bind(fd, (struct sockaddr*)&sock_addr, sizeof(sock_addr)) < 0) {
		LOGP(DNM, LOGL_ERROR, "Telnet interface failed to bind\n");
		return;
	}

	if (listen(fd, 0) < 0) {
		LOGP(DNM, LOGL_ERROR, "Telnet interface failed to listen\n");
		return;
	}

	server_socket.data = network;
	server_socket.fd = fd;
	bsc_register_fd(&server_socket);
}

extern const char *openbsc_copyright;

static void print_welcome(int fd) {
	int ret;
	static char *msg =
		"Welcome to the OpenBSC Control interface\n";

	ret = write(fd, msg, strlen(msg));
	ret = write(fd, openbsc_copyright, strlen(openbsc_copyright));
}

int telnet_close_client(struct bsc_fd *fd) {
	struct telnet_connection *conn = (struct telnet_connection*)fd->data;

	close(fd->fd);
	bsc_unregister_fd(fd);

	if (conn->dbg) {
		log_del_target(conn->dbg);
		talloc_free(conn->dbg);
	}

	llist_del(&conn->entry);
	talloc_free(conn);
	return 0;
}

static int client_data(struct bsc_fd *fd, unsigned int what)
{
	struct telnet_connection *conn = fd->data;
	int rc = 0;

	if (what & BSC_FD_READ) {
		conn->fd.when &= ~BSC_FD_READ;
		rc = vty_read(conn->vty);
	}

	/* vty might have been closed from vithin vty_read() */
	if (!conn->vty)
		return rc;

	if (what & BSC_FD_WRITE) {
		rc = buffer_flush_all(conn->vty->obuf, fd->fd);
		if (rc == BUFFER_EMPTY)
			conn->fd.when &= ~BSC_FD_WRITE;
	}

	return rc;
}

static int telnet_new_connection(struct bsc_fd *fd, unsigned int what) {
	struct telnet_connection *connection;
	struct sockaddr_in sockaddr;
	socklen_t len = sizeof(sockaddr);
	int new_connection = accept(fd->fd, (struct sockaddr*)&sockaddr, &len);

	if (new_connection < 0) {
		LOGP(DNM, LOGL_ERROR, "telnet accept failed\n");
		return -1;
	}


	connection = talloc_zero(tall_telnet_ctx, struct telnet_connection);
	connection->network = (struct gsm_network*)fd->data;
	connection->fd.data = connection;
	connection->fd.fd = new_connection;
	connection->fd.when = BSC_FD_READ;
	connection->fd.cb = client_data;
	bsc_register_fd(&connection->fd);
	llist_add_tail(&connection->entry, &active_connections);

	print_welcome(new_connection);

	connection->vty = vty_create(new_connection, connection);
	if (!connection->vty) {
		LOGP(DNM, LOGL_ERROR, "couldn't create VTY\n");
		return -1;
	}

	return 0;
}

/* callback from VTY code */
void vty_event(enum event event, int sock, struct vty *vty)
{
	struct telnet_connection *connection = vty->priv;
	struct bsc_fd *bfd = &connection->fd;

	if (vty->type != VTY_TERM)
		return;

	switch (event) {
	case VTY_READ:
		bfd->when |= BSC_FD_READ;
		break;
	case VTY_WRITE:
		bfd->when |= BSC_FD_WRITE;
		break;
	case VTY_CLOSED:
		/* vty layer is about to free() vty */
		connection->vty = NULL;
		telnet_close_client(bfd);
		break;
	default:
		break;
	}
}

