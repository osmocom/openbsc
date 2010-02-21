/* A Media Gateway Control Protocol Media Gateway: RFC 3435 */
/* The main method to drive it as a standalone process      */

/*
 * (C) 2009 by Holger Hans Peter Freyther <zecke@selfish.org>
 * (C) 2009 by On-Waves
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

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <limits.h>
#include <unistd.h>

#include <sys/socket.h>
#include <arpa/inet.h>

#include <openbsc/debug.h>
#include <osmocore/msgb.h>
#include <osmocore/talloc.h>
#include <openbsc/gsm_data.h>
#include <osmocore/select.h>
#include <openbsc/mgcp.h>
#include <openbsc/telnet_interface.h>

#include <vty/command.h>
#include <vty/vty.h>

/* this is here for the vty... it will never be called */
void subscr_put() { abort(); }

#define _GNU_SOURCE
#include <getopt.h>

#warning "Make use of the rtp proxy code"

static int source_port = 2427;
static const char *source_addr = "0.0.0.0";
static struct bsc_fd bfd;
static int first_request = 1;

static char *config_file = "mgcp.cfg";

/* used by msgb and mgcp */
void *tall_bsc_ctx = NULL;

unsigned int rtp_base_port = RTP_PORT_DEFAULT;

static void print_help()
{
	printf("Some useful help...\n");
	printf(" -h --help is printing this text.\n");
	printf(" -c --config-file filename The config file to use.\n");
}

static void handle_options(int argc, char** argv)
{
	while (1) {
		int option_index = 0, c;
		static struct option long_options[] = {
			{"help", 0, 0, 'h'},
			{"config-file", 1, 0, 'c'},
			{0, 0, 0, 0},
		};

		c = getopt_long(argc, argv, "hc:", long_options, &option_index);

		if (c == -1)
			break;

		switch(c) {
		case 'h':
			print_help();
			exit(0);
			break;
		case 'c':
			config_file = talloc_strdup(tall_bsc_ctx, optarg);
			break;
		default:
			/* ignore */
			break;
		};
	}
}

static int read_call_agent(struct bsc_fd *fd, unsigned int what)
{
	struct sockaddr_in addr;
	socklen_t slen = sizeof(addr);
	struct msgb *msg;
	struct msgb *resp;

	msg = (struct msgb *) fd->data;

	/* read one less so we can use it as a \0 */
	int rc = recvfrom(bfd.fd, msg->data, msg->data_len - 1, 0,
		(struct sockaddr *) &addr, &slen);
	if (rc < 0) {
		perror("Gateway failed to read");
		return -1;
	} else if (slen > sizeof(addr)) {
		fprintf(stderr, "Gateway received message from outerspace: %d %d\n",
			slen, sizeof(addr));
		return -1;
	}

	if (first_request) {
		first_request = 0;
		resp = mgcp_create_rsip();

		if (resp) {
			sendto(bfd.fd, resp->l2h, msgb_l2len(resp), 0,
				(struct sockaddr *) &addr, sizeof(addr));
			msgb_free(resp);
		}
		return 0;
        }

	/* handle message now */
	msg->l2h = msgb_put(msg, rc);
	resp = mgcp_handle_message(msg);
	msgb_reset(msg);

	if (resp) {
		sendto(bfd.fd, resp->l2h, msgb_l2len(resp), 0, (struct sockaddr *) &addr, sizeof(addr));
		msgb_free(resp);
	}
	return 0;
}


int bsc_vty_init(struct gsm_network *dummy)
{
	cmd_init(1);
	vty_init();

        mgcp_vty_init();
	return 0;
}

int main(int argc, char** argv)
{
	struct gsm_network dummy_network;
	struct sockaddr_in addr;
	int on = 1, rc;
	struct debug_target *stderr_target;

	tall_bsc_ctx = talloc_named_const(NULL, 1, "mgcp-callagent");

	debug_init();
	stderr_target = debug_target_create_stderr();
	debug_add_target(stderr_target);
	debug_set_all_filter(stderr_target, 1);

	handle_options(argc, argv);

	telnet_init(&dummy_network, 4243);
        rc = mgcp_parse_config(config_file, &dummy_network);
	if (rc < 0)
		return rc;


        /* we need to bind a socket */
        if (rc == 0) {
		bfd.when = BSC_FD_READ;
		bfd.cb = read_call_agent;
		bfd.fd = socket(AF_INET, SOCK_DGRAM, 0);
		if (bfd.fd < 0) {
			perror("Gateway failed to listen");
			return -1;
		}

		setsockopt(bfd.fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));

		memset(&addr, 0, sizeof(addr));
		addr.sin_family = AF_INET;
		addr.sin_port = htons(source_port);
		inet_aton(source_addr, &addr.sin_addr);

		if (bind(bfd.fd, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
			perror("Gateway failed to bind");
			return -1;
		}

		bfd.data = msgb_alloc(4096, "mgcp-msg");
		if (!bfd.data) {
			fprintf(stderr, "Gateway memory error.\n");
			return -1;
		}


		if (bsc_register_fd(&bfd) != 0) {
			DEBUGP(DMGCP, "Failed to register the fd\n");
			return -1;
		}

		DEBUGP(DMGCP, "Configured for MGCP.\n");
	}

	/* initialisation */
	srand(time(NULL));

	/* main loop */
	while (1) {
		bsc_select_main(0);
	}


	return 0;
}
