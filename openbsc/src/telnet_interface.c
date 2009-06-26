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
#include <openbsc/msgb.h>
#include <openbsc/abis_rsl.h>
#include <openbsc/paging.h>
#include <openbsc/signal.h>
#include <openbsc/talloc.h>

#include <vty/buffer.h>

#define WRITE_CONNECTION(fd, msg...) \
	int ret; \
	char buf[4096]; \
	snprintf(buf, sizeof(buf), msg); \
	ret = write(fd, buf, strlen(buf));


/* per connection data */
LLIST_HEAD(active_connections);

static void *tall_telnet_ctx;

/* per network data */
static int telnet_new_connection(struct bsc_fd *fd, unsigned int what);
#if 0
static int telnet_paging_callback(unsigned int subsys, unsigned int signal,
				  void *handler_data, void *signal_data);
static int telnet_sms_callback(unsigned int subsys, unsigned int signal,
				void *handler_data, void *signal_data);
#endif

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
		perror("Telnet interface socket creation failed");
		return;
	}

	setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));

	memset(&sock_addr, 0, sizeof(sock_addr));
	sock_addr.sin_family = AF_INET;
	sock_addr.sin_port = htons(port);
	sock_addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

	if (bind(fd, (struct sockaddr*)&sock_addr, sizeof(sock_addr)) < 0) {
		perror("Telnet interface failed to bind");
		return;
	}

	if (listen(fd, 0) < 0) {
		perror("Telnet interface failed to listen");
		return;
	}

	server_socket.data = network;
	server_socket.fd = fd;
	bsc_register_fd(&server_socket);

	/* register callbacks */
#if 0
	register_signal_handler(SS_PAGING, telnet_paging_callback, network);
	register_signal_handler(SS_SMS, telnet_sms_callback, network);
#endif
}

static void print_welcome(int fd) {
	int ret;
	static char *msg =
		"Welcome to the OpenBSC Control interface\n"
		"Copyright (C) 2008, 2009 Harald Welte\n"
		"Contributions by Daniel Willmann, Jan Lübbe, "
		"Stefan Schmidt, Holger Freyther\n\n"
		"License GPLv2+: GNU GPL version 2 or later "
		"<http://gnu.org/licenses/gpl.html>\n"
		"This is free software: you are free to change "
		"and redistribute it.\n"
		"There is NO WARRANTY, to the extent permitted "
		"by law.\nType \"help\" to get a short introduction.\n";

	ret = write(fd, msg, strlen(msg));
}

int telnet_close_client(struct bsc_fd *fd) {
	struct telnet_connection *conn = (struct telnet_connection*)fd->data;

	close(fd->fd);
	bsc_unregister_fd(fd);
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
		perror("telnet accept failed");
		return -1;
	}


	connection = talloc_zero(tall_telnet_ctx, struct telnet_connection);
	connection->network = (struct gsm_network*)fd->data;
	connection->fd.data = connection;
	connection->fd.fd = new_connection;
	connection->fd.when = BSC_FD_READ;
	connection->fd.cb = client_data;
	connection->bts = 0;
	bsc_register_fd(&connection->fd);
	llist_add_tail(&connection->entry, &active_connections);

	print_welcome(new_connection);

	connection->vty = vty_create(new_connection, connection);
	if (!connection->vty)
		return -1;

	return 0;
}

/* callback from VTY code */
void vty_event(enum event event, int sock, struct vty *vty)
{
	struct telnet_connection *connection = vty->priv;
	struct bsc_fd *bfd = &connection->fd;

	switch (event) {
	case VTY_READ:
		bfd->when |= BSC_FD_READ;
		break;
	case VTY_WRITE:
		bfd->when |= BSC_FD_WRITE;
		break;
	default:
		break;
	}
}

#if 0
static int telnet_paging_callback(unsigned int subsys, unsigned int singal,
				  void *handler_data, void *signal_data)
{
	struct paging_signal_data *paging = signal_data;
	struct telnet_connection *con;

	llist_for_each_entry(con, &active_connections, entry) {
		if (paging->lchan) {
			WRITE_CONNECTION(con->fd.fd, "Paging succeeded\n");
			show_lchan(con->fd.fd, paging->lchan);
		} else {
			WRITE_CONNECTION(con->fd.fd, "Paging failed for subscriber: %s/%s/%s\n",
				paging->subscr->imsi,
				paging->subscr->tmsi,
				paging->subscr->name);
		}
	}

	return 0;
}

static int telnet_sms_callback(unsigned int subsys, unsigned int signal,
				void *handler_data, void *signal_data)
{
	struct sms_submit *sms = signal_data;
	struct telnet_connection *con;

	llist_for_each_entry(con, &active_connections, entry) {
		WRITE_CONNECTION(con->fd.fd, "Incoming SMS: %s\n", sms->user_data);
	}

	return 0;
}
#endif
