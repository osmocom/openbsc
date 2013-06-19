/* A hackish minimal TRAU and RTP multiplexing */

/* (C) 2013 by Harald Welte <laforge@gnumonks.org>
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

#include <unistd.h>
#include <time.h>
#include <errno.h>
#include <signal.h>
#include <fcntl.h>
#include <sys/stat.h>

#define _GNU_SOURCE
#include <getopt.h>

#include <arpa/inet.h>
#include <netinet/in.h>

#include <osmocom/core/application.h>
#include <osmocom/core/select.h>
#include <osmocom/core/talloc.h>
#include <osmocom/abis/abis.h>
#include <osmocom/abis/e1_input.h>
#include <osmocom/vty/telnet_interface.h>
#include <osmocom/vty/logging.h>

#include <openbsc/debug.h>
#include <openbsc/signal.h>
#include <openbsc/vty.h>
#include <openbsc/rtp_proxy.h>
#include <openbsc/mgcp.h>

#include "../../bscconfig.h"

static const char *config_file = "osmo-rtp_proxy.cfg";
extern const char *openbsc_copyright;
static int daemonize = 0;

static void print_usage()
{
	printf("Usage: osmo-rtp_proxy\n");
}

static void print_help()
{
	printf("  Some useful help...\n");
	printf("  -h --help this text\n");
	printf("  -D --daemonize Fork the process into a background daemon\n");
	printf("  -c --config-file filename The config file to use.\n");
	printf("  -V --version. Print the version of OpenBSC.\n");
}

static void handle_options(int argc, char **argv)
{
	while (1) {
		int option_index = 0, c;
		static struct option long_options[] = {
			{"help", 0, 0, 'h'},
			{"debug", 1, 0, 'd'},
			{"daemonize", 0, 0, 'D'},
			{"config-file", 1, 0, 'c'},
			{"version", 0, 0, 'V' },
			{0, 0, 0, 0}
		};

		c = getopt_long(argc, argv, "hd:DVc:",
				long_options, &option_index);
		if (c == -1)
			break;

		switch (c) {
		case 'h':
			print_usage();
			print_help();
			exit(0);
		case 'd':
			log_parse_category_mask(osmo_stderr_target, optarg);
			break;
		case 'D':
			daemonize = 1;
			break;
		case 'c':
			config_file = strdup(optarg);
			break;
		case 'V':
			print_version(1);
			exit(0);
			break;
		default:
			/* ignore */
			break;
		}
	}
}

static void signal_handler(int signal)
{
	fprintf(stdout, "signal %u received\n", signal);

	switch (signal) {
	case SIGINT:
		osmo_signal_dispatch(SS_L_GLOBAL, S_L_GLOBAL_SHUTDOWN, NULL);
		sleep(3);
		exit(0);
		break;
	case SIGABRT:
		/* in case of abort, we want to obtain a talloc report
		 * and then return to the caller, who will abort the process */
	case SIGUSR1:
		talloc_report_full(tall_bsc_ctx, stderr);
		break;
	case SIGUSR2:
		break;
	default:
		break;
	}
}

void gsm_net_update_ctype(struct gsm_network *network)
{
}

extern enum node_type bsc_vty_go_parent(struct vty *vty);

static struct vty_app_info vty_info = {
	.name 		= "OsmoRTP",
	.version	= PACKAGE_VERSION,
	.go_parent_cb	= bsc_vty_go_parent,
	.is_config_node	= bsc_vty_is_config_node,
};

static int create_socket_loop(uint16_t port)
{
	struct rtp_socket *s;
	int rc;

	s = rtp_socket_create();
	if (!s)
		return -EIO;

	rc = rtp_socket_bind_port(s, INADDR_ANY, port);
	if (rc < 0)
		goto err_free_s;

	rc = rtp_socket_loopback(s);
	if (rc < 0)
		goto err_free_s;

	return 0;
err_free_s:
	rtp_socket_free(s);
	return -EIO;
}

static int create_socket_pair(uint16_t port1, uint16_t port2)
{
	struct rtp_socket *a, *b;
	uint32_t localhost = 0x7f000001;
	int rc;

	a = rtp_socket_create();
	if (!a)
		return -EIO;

	b = rtp_socket_create();
	if (!a)
		goto err_free_a;

	rc = rtp_socket_bind_port(a, INADDR_ANY, port1);
	if (rc < 0)
		goto err_free;

	rc = rtp_socket_bind_port(b, INADDR_ANY, port2);
	if (rc < 0)
		goto err_free;

	rc = rtp_socket_connect(a, localhost, port2);
	if (rc < 0)
		goto err_free;

	rtp_socket_connect(b, localhost, port1);
	if (rc < 0)
		goto err_free;

	rc = rtp_socket_proxy(a, b);
	if (rc < 0)
		goto err_free;

	return 0;

err_free:
	rtp_socket_free(b);
err_free_a:
	rtp_socket_free(a);

	return -EIO;
}


#define PORT_BY_CIC(mux, x) rtp_calculate_port((mux)*32+(x), 4000)

int main(int argc, char **argv)
{
	int rc, i;
	struct gsm_network dummy_network;

	vty_info.copyright = openbsc_copyright;

	tall_bsc_ctx = talloc_named_const(NULL, 1, "osmortp");

	libosmo_abis_init(tall_bsc_ctx);
	osmo_init_logging(&log_info);

	/* This needs to precede handle_options() */
	vty_init(&vty_info);
	logging_vty_add_cmds(&log_info);

	/* parse options */
	handle_options(argc, argv);

	/* FIXME: parse config file */

	rc = telnet_init(tall_bsc_ctx, &dummy_network, 4239);
	if (rc < 0)
		return rc;

	/* seed the PRNG */
	srand(time(NULL));

	signal(SIGINT, &signal_handler);
	signal(SIGABRT, &signal_handler);
	signal(SIGUSR1, &signal_handler);
	signal(SIGUSR2, &signal_handler);
	osmo_init_ignore_signals();

	/* hard-wire map CIC 1->33, 2->33, ... */
	for (i = 1; i <= 8; i++) {
		uint16_t port1, port2;
		port1 = PORT_BY_CIC(0, i);
		port2 = PORT_BY_CIC(1, i);
		printf("Creating UDP port mapping (%u,%u:%u) -> (%u,%u:%u)\n",
			0,i,1,i,port1, port2);
		rc = create_socket_pair(port1, port2);
		if (rc < 0)
			exit(1);
	}
	printf("Creating loopback CIC (%u,%u:%u)\n",
		0, 16, PORT_BY_CIC(0, 16));
	rc = create_socket_loop(PORT_BY_CIC(0,16));
	if (rc < 0)
		exit(1);

	if (daemonize) {
		rc = osmo_daemonize();
		if (rc < 0) {
			perror("Error during daemonize");
			exit(1);
		}
	}

	while (1) {
		log_reset_context();
		osmo_select_main(0);
	}
}
