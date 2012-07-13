/* OsmoGANC - Osmocom GAN/UMA Controller */

/* (C) 2012 by Harald Welte <laforge@gnumonks.org>
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

#define _GNU_SOURCE
#include <getopt.h>

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <time.h>
#include <unistd.h>

#include "../../bscconfig.h"

#include <osmocom/core/application.h>
#include <osmocom/core/linuxlist.h>
#include <osmocom/core/talloc.h>
#include <osmocom/vty/vty.h>
#include <osmocom/vty/telnet_interface.h>

#include <osmocom/sccp/sccp.h>

#include <openbsc/debug.h>
#include <openbsc/signal.h>
#include <openbsc/vty.h>

#include "ganc_data.h"


static const char *config_file = "osmo-ganc.cfg";
static const char *rf_ctrl = NULL;
extern const char *openbsc_copyright;
static int daemonize = 0;

static void print_usage()
{
	printf("Usage: osmo-ganc\n");
}

static void print_help()
{
	printf("  Some useful help...\n");
	printf("  -h --help this text\n");
	printf("  -D --daemonize Fork the process into a background daemon\n");
	printf("  -d option --debug=DRLL:DCC:DMM:DRR:DRSL:DNM enable debugging\n");
	printf("  -s --disable-color\n");
	printf("  -T --timestamp. Print a timestamp in the debug output.\n");
	printf("  -c --config-file filename The config file to use.\n");
	printf("  -l --local=IP. The local address of the MGCP.\n");
	printf("  -e --log-level number. Set a global loglevel.\n");
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
			{"disable-color", 0, 0, 's'},
			{"timestamp", 0, 0, 'T'},
			{"local", 1, 0, 'l'},
			{"log-level", 1, 0, 'e'},
			{0, 0, 0, 0}
		};

		c = getopt_long(argc, argv, "hd:DsTc:e:",
				long_options, &option_index);
		if (c == -1)
			break;

		switch (c) {
		case 'h':
			print_usage();
			print_help();
			exit(0);
		case 's':
			log_set_use_color(osmo_stderr_target, 0);
			break;
		case 'd':
			log_parse_category_mask(osmo_stderr_target, optarg);
			break;
		case 'D':
			daemonize = 1;
			break;
		case 'c':
			config_file = strdup(optarg);
			break;
		case 'T':
			log_set_print_timestamp(osmo_stderr_target, 1);
			break;
		case 'e':
			log_set_log_level(osmo_stderr_target, atoi(optarg));
			break;
			break;
		default:
			/* ignore */
			break;
		}
	}
}

extern enum node_type bsc_vty_go_parent(struct vty *vty);

static struct vty_app_info vty_info = {
	.name 		= "OsmoGANC",
	.version	= PACKAGE_VERSION,
	.go_parent_cb	= bsc_vty_go_parent,
	.is_config_node	= bsc_vty_is_config_node,
};

extern int bsc_shutdown_net(struct gsm_network *net);
static void signal_handler(int signal)
{
	struct osmo_msc_data *msc;

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
		talloc_report(tall_vty_ctx, stderr);
		talloc_report_full(tall_bsc_ctx, stderr);
		break;
	case SIGUSR2:
#if 0
		if (!bsc_gsmnet->bsc_data)
			return;
		llist_for_each_entry(msc, &bsc_gsmnet->bsc_data->mscs, entry)
			bsc_msc_lost(msc->msc_con);
#endif
		break;
	default:
		break;
	}
}


void gsm_net_update_ctype(struct gsm_network *network)
{
}

struct ganc_bts *g_ganc_bts;
struct ganc_net *g_ganc_net;

int main(int argc, char **argv)
{
	struct osmo_msc_data *msc;
	struct osmo_bsc_data *data;
	int rc;

	tall_bsc_ctx = talloc_named_const(NULL, 1, "openbsc");

	g_ganc_net = talloc_zero(tall_bsc_ctx, struct ganc_net);
	ganc_net_init(g_ganc_net);
	g_ganc_bts = talloc_zero(g_ganc_net, struct ganc_bts);
	ganc_bts_init(g_ganc_bts, g_ganc_net);

	osmo_init_logging(&log_info);

	/* enable filters */

	/* This needs to precede handle_options() */
	vty_info.copyright = openbsc_copyright;
	vty_init(&vty_info);
	//bsc_vty_init(&log_info);
	ganc_vty_init_extra();

	/* parse options */
	handle_options(argc, argv);

	/* seed the PRNG */
	srand(time(NULL));

	/* initialize SCCP */
	sccp_set_log_area(DSCCP);

	struct telnet_connection dummy_conn;
	rc = vty_read_config_file(config_file, &dummy_conn);
	if (rc < 0) {
		fprintf(stderr, "Failed to parse the config file: '%s'\n", config_file);
		return rc;
	}

	ganc_server_start(NULL, 14001);

	rc = telnet_init(tall_bsc_ctx, g_ganc_net, 4251);
	if (rc < 0)
		exit(23);

#if 0
	llist_for_each_entry(msc, &bsc_gsmnet->bsc_data->mscs, entry) {
		if (osmo_bsc_msc_init(msc) != 0) {
			LOGP(DNAT, LOGL_ERROR, "Failed to start up. Exiting.\n");
			exit(1);
		}
	}


	if (osmo_bsc_sccp_init(bsc_gsmnet) != 0) {
		LOGP(DNM, LOGL_ERROR, "Failed to register SCCP.\n");
		exit(1);
	}

	if (osmo_bsc_audio_init(bsc_gsmnet) != 0) {
		LOGP(DMSC, LOGL_ERROR, "Failed to register audio support.\n");
		exit(1);
	}
#endif
	signal(SIGINT, &signal_handler);
	signal(SIGABRT, &signal_handler);
	signal(SIGUSR1, &signal_handler);
	signal(SIGUSR2, &signal_handler);
	osmo_init_ignore_signals();

	if (daemonize) {
		rc = osmo_daemonize();
		if (rc < 0) {
			perror("Error during daemonize");
			exit(1);
		}
	}

	while (1) {
		osmo_select_main(0);
	}

	return 0;
}
