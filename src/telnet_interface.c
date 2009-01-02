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
#include <malloc.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <openbsc/telnet_interface.h>

extern void telnet_parse(struct telnet_connection *connection, char *line);

/* per connection data */
LLIST_HEAD(active_connections);

/* per network data */
static int telnet_new_connection(struct bsc_fd *fd, unsigned int what);
static struct bsc_fd server_socket = {
	.when	    = BSC_FD_READ,
	.cb	    = telnet_new_connection,
	.priv_nr    = 0,
};

void telnet_init(struct gsm_network *network, int port) {
	struct sockaddr_in sock_addr;
	int fd;

	fd = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);

	if (fd < 0) {
		perror("Telnet interface socket creation failed");
		return;
	}

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
}

void telnet_write_help(int fd) {
	int ret;
	static char *msg =
		"Help for the ad-hoc telnet command line interface\n"
		"The generic pattern is CMD LEN DATA\\n or just CMD\n"
		"where CMD is one of the following:\n"
		"help\n"
		"page IMSI (type)\n"
		"call IMSI (number)\n"
		"get_channel IMSI Add use count on an active channel\n"
		"put_channel IMSI Remove use count on an active channel\n"
		"48 IMSI 0xAB 0xEF...Send GSM 04.08\n"
		"11 IMSI 0xAB 0xEF...Send GSM 04.11\n";

	ret = write(fd, msg, strlen(msg));
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
	free(conn);
	return 0;
}

void telnet_error_client(int fd) {
	int ret;
	static char *msg = "Something went wrong. Please try again.\n";

	printf("Error\n");
	ret = write(fd, msg, strlen(msg));
}

void telnet_page(struct telnet_connection *connection, const char *imsi, int page) {
	printf("going to page: '%s' %d\n", imsi, page);
}

void telnet_put_channel(struct telnet_connection *connection, const char *imsi) {
	printf("put_channel: '%s'\n", imsi);
}

void telnet_get_channel(struct telnet_connection *connection, const char *imsi) {
	printf("get_channel: '%s'\n", imsi);
}

void telnet_call(struct telnet_connection *connection, const char* imsi,
		const char *origin) {
	printf("calling: '%s' from: '%s'\n", imsi, origin);
}

void telnet_send_gsm_48(struct telnet_connection *connection) {
	printf("sending gsm04.08 message\n");
}

void telnet_send_gsm_11(struct telnet_connection *connection) {
	printf("sending gsm04.11 message\n");
}

static int client_data(struct bsc_fd *fd, unsigned int what) {
	char buf[4096];
	int ret;

	ret = read(fd->fd, buf, sizeof(buf)-1);
	buf[ret] = '\0';

	/* connection is gone */
	if (ret <= 0)
		return telnet_close_client(fd);

	/* time to parse. This code assumes that the input is line based */
	telnet_parse((struct telnet_connection*)fd->data, buf);

	return 0;
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


	connection = (struct telnet_connection*)malloc(sizeof(*connection));
	memset(connection, 0, sizeof(*connection));
	connection->network = (struct gsm_network*)fd->data;
	connection->fd.data = connection;
	connection->fd.fd = new_connection;
	connection->fd.when = BSC_FD_READ;
	connection->fd.cb = client_data;
	bsc_register_fd(&connection->fd);
	llist_add_tail(&connection->entry, &active_connections);

	print_welcome(new_connection);

	return 0;
}
