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
#include <openbsc/gsm_subscriber.h>
#include <openbsc/chan_alloc.h>
#include <openbsc/gsm_04_08.h>
#include <openbsc/msgb.h>
#include <openbsc/abis_rsl.h>
#include <openbsc/paging.h>

extern void telnet_parse(struct telnet_connection *connection, char *line);

#define WRITE_CONNECTION(fd, msg...) \
	int ret; \
	char buf[4096]; \
	snprintf(buf, sizeof(buf), msg); \
	ret = write(fd, buf, strlen(buf));


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
		"show  This will show the channel allocation\n"
		"48 IMSI 0xAB 0xEF...Send GSM 04.08. proto and msg byte then data\n"
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

static struct gsm_lchan* find_channel(struct gsm_bts *bts, const char *imsi,
			    const char **error, int fd) {
	int ret;
	struct gsm_lchan *lchan;
	struct gsm_subscriber *subscr;

	subscr = subscr_get_by_imsi(imsi);
	if (!subscr) {
		ret = write(fd, error[0], strlen(error[0]));
		return NULL;
	}

	lchan = lchan_find(bts, subscr);
	if (!lchan)
		ret = write(fd, error[1], strlen(error[1]));

	subscr_put(subscr);
	return lchan;
}

void telnet_page(struct telnet_connection *connection, const char *imsi, int type) {
	int ret;
	static const char* error[] = {
		"paging: IMSI not found\n",
		"paging: No channel allocated for IMSI -> will allocate\n" };
	struct gsm_bts *bts = &connection->network->bts[connection->bts];
	struct gsm_lchan *lchan = find_channel(bts, imsi, error, connection->fd.fd);

	if (lchan) {
		static const char *msg = "paging: A Channel is already allocated.\n";
		ret = write(connection->fd.fd, msg, strlen(msg));
		return;
	}

	struct gsm_subscriber *subscr = subscr_get_by_imsi(imsi);
	if (!subscr)
		return;

	page_request(bts, subscr, type);	
}

void telnet_put_channel(struct telnet_connection *connection, const char *imsi) {
	static const char* error[] = {
		"put_channel: IMSI not found\n",
		"put_channel: No channel allocated for IMSI\n" };
	struct gsm_bts *bts = &connection->network->bts[connection->bts];
	struct gsm_lchan *lchan = find_channel(bts, imsi, error, connection->fd.fd);

	if (!lchan)
		return;

	put_lchan(lchan);
}

void telnet_get_channel(struct telnet_connection *connection, const char *imsi) {
	static const char* error[] = {
		"get_channel: IMSI not found\n",
		"get_channel: No channel allocated for IMSI\n" };
	struct gsm_bts *bts = &connection->network->bts[connection->bts];
	struct gsm_lchan *lchan = find_channel(bts, imsi, error, connection->fd.fd);

	if (!lchan)
		return;

	use_lchan(lchan);
}

void telnet_call(struct telnet_connection *connection, const char* imsi,
		const char *origin) {
	static const char* error[] = {
		"call: IMSI not found\n",
		"call: No channel allocated for IMSI\n" };
	struct gsm_bts *bts = &connection->network->bts[connection->bts];
	struct gsm_lchan *lchan = find_channel(bts, imsi, error, connection->fd.fd);

	if (!lchan)
		return;

	/* TODO: add the origin */
	gsm48_cc_tx_setup(lchan);
}

void telnet_send_gsm_48(struct telnet_connection *connection) {
	static const char* error[] = {
		"48: IMSI not found\n",
		"48: No channel allocated for IMSI\n" };
	int ret;
	struct gsm_bts *bts = &connection->network->bts[connection->bts];
	struct gsm_lchan *lchan = find_channel(bts, connection->imsi, error, connection->fd.fd);

	if (!lchan)
		return;

	if (connection->read < 2) {
		static const char *msg = "48: Need at least two bytes";
		ret = write(connection->fd.fd, msg, strlen(msg));
		return;
	}

	struct msgb *msg = gsm48_msgb_alloc();
	struct gsm48_hdr *gh;
	int i;

	gh = (struct gsm48_hdr *) msgb_put(msg, sizeof(*gh) + connection->read-2);
	msg->lchan = lchan;

	gh->proto_discr = connection->commands[0];
	gh->msg_type = connection->commands[1];
	for (i = 2; i < connection->read; ++i)
	    gh->data[i-2] = connection->commands[i];

	gsm48_sendmsg(msg);
}

void telnet_send_gsm_11(struct telnet_connection *connection) {
	printf("sending gsm04.11 message\n");
}

static void show_bts(int fd, struct gsm_bts *bts) {
	WRITE_CONNECTION(fd,
		 "BTS #%u on link %u  LOC: %u TRX: %d CCCH0: arfcn:%u,#%u\n",
		 bts->nr, bts->bts_nr, bts->location_area_code,
		 bts->num_trx, bts->c0->arfcn, bts->c0->nr)
}

static void show_trx(int fd, struct gsm_bts_trx *trx) {
	WRITE_CONNECTION(fd,
		 "  TRX: %u ARFCN: %u\n",
		trx->nr, trx->arfcn)
}

static void show_ts(int fd, struct gsm_bts_trx_ts *ts) {
	WRITE_CONNECTION(fd,
		"     TS: #%u pchan: %12s flags: %u\n",
		ts->nr, gsm_pchan_name(ts->pchan), ts->flags);
}

static void show_lchan(int fd, struct gsm_lchan *lchan) {
	struct gsm_subscriber *subscr = lchan->subscr;
	WRITE_CONNECTION(fd,
		"       LCHAN: #%u type: %7s  count: %d subscriber: %s/%s/%s use: %d loc: %p\n",
		lchan->nr, gsm_lchan_name(lchan->type),
		lchan->use_count,
		subscr ? subscr->imsi : "na",
		subscr ? subscr->tmsi : "na",
		subscr ? subscr->name : "na",
		lchan->use_count, lchan->loc_operation);
}

void telnet_list_channels(struct telnet_connection *connection) {
	int bts_no, trx, lchan_no, ts_no;
	struct gsm_network *network = connection->network;

	for (bts_no = 0; bts_no < network->num_bts; ++bts_no) {
		struct gsm_bts *bts = &network->bts[bts_no];
		show_bts(connection->fd.fd, bts);

		for (trx = 0; trx < bts->num_trx; ++trx) {
			show_trx(connection->fd.fd, &bts->trx[trx]);
			for (ts_no = 0; ts_no < 8; ++ts_no) {
				show_ts(connection->fd.fd, &bts->trx[trx].ts[ts_no]);
				for (lchan_no = 0; lchan_no < TS_MAX_LCHAN; ++lchan_no) {
					struct gsm_lchan *lchan =
						&bts->trx[trx].ts[ts_no].lchan[lchan_no];
					show_lchan(connection->fd.fd, lchan);
				}
			}
		}
	}
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
	connection->bts = 0;
	bsc_register_fd(&connection->fd);
	llist_add_tail(&connection->entry, &active_connections);

	print_welcome(new_connection);

	return 0;
}
