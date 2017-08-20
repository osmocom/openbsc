/* (C) 2008-2009 by Harald Welte <laforge@gnumonks.org>
 * (C) 2009-2011 by Holger Hans Peter Freyther <zecke@selfish.org>
 * (C) 2009-2011 by On-Waves
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

#include <openbsc/bss.h>
#include <openbsc/debug.h>
#include <openbsc/gsm_data.h>
#include <openbsc/osmo_bsc.h>
#include <openbsc/osmo_bsc_rf.h>
#include <openbsc/bsc_msc_data.h>
#include <openbsc/signal.h>
#include <openbsc/vty.h>
#include <openbsc/ipaccess.h>
#include <openbsc/ctrl.h>

#include <osmocom/ctrl/control_cmd.h>
#include <osmocom/ctrl/control_if.h>
#include <osmocom/ctrl/ports.h>
#include <osmocom/ctrl/control_vty.h>

#include <osmocom/core/application.h>
#include <osmocom/core/linuxlist.h>
#include <osmocom/core/talloc.h>
#include <osmocom/core/stats.h>
#include <osmocom/gsm/protocol/gsm_12_21.h>

#include <osmocom/abis/abis.h>

#include <osmocom/sccp/sccp.h>

#define _GNU_SOURCE
#include <getopt.h>

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>


#include "../../bscconfig.h"

struct gsm_network *bsc_gsmnet = 0;
static const char *config_file = "openbsc.cfg";
static const char *rf_ctrl = NULL;
extern const char *openbsc_copyright;
static int daemonize = 0;
static struct llist_head access_lists;

struct llist_head *bsc_access_lists(void)
{
	return &access_lists;
}

static void print_usage()
{
	printf("Usage: osmo-bsc\n");
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
	printf("  -r --rf-ctl NAME. A unix domain socket to listen for cmds.\n");
	printf("  -t --testmode. A special mode to provoke failures at the MSC.\n");
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
			{"rf-ctl", 1, 0, 'r'},
			{"testmode", 0, 0, 't'},
			{0, 0, 0, 0}
		};

		c = getopt_long(argc, argv, "hd:DsTc:e:r:t",
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
			config_file = optarg;
			break;
		case 'T':
			log_set_print_timestamp(osmo_stderr_target, 1);
			break;
		case 'e':
			log_set_log_level(osmo_stderr_target, atoi(optarg));
			break;
		case 'r':
			rf_ctrl = optarg;
			break;
		default:
			/* ignore */
			break;
		}
	}
}

extern int bsc_vty_go_parent(struct vty *vty);

static struct vty_app_info vty_info = {
	.name 		= "OsmoBSC",
	.version	= PACKAGE_VERSION,
	.go_parent_cb	= bsc_vty_go_parent,
	.is_config_node	= bsc_vty_is_config_node,
};

extern int bsc_shutdown_net(struct gsm_network *net);
static void signal_handler(int signal)
{
	struct bsc_msc_data *msc;

	fprintf(stdout, "signal %u received\n", signal);

	switch (signal) {
	case SIGINT:
	case SIGTERM:
		bsc_shutdown_net(bsc_gsmnet);
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
		if (!bsc_gsmnet->bsc_data)
			return;
		llist_for_each_entry(msc, &bsc_gsmnet->bsc_data->mscs, entry)
			bsc_msc_lost(msc->msc_con);
		break;
	default:
		break;
	}
}

int main(int argc, char **argv)
{
	struct bsc_msc_data *msc;
	struct osmo_bsc_data *data;
	int rc;

	tall_bsc_ctx = talloc_named_const(NULL, 1, "openbsc");
	msgb_talloc_ctx_init(tall_bsc_ctx, 0);

	/* Allocate global gsm_network struct */
	rc = bsc_network_alloc(NULL);
	if (rc) {
		fprintf(stderr, "Allocation failed. exiting.\n");
		exit(1);
	}

	osmo_init_logging(&log_info);
	osmo_stats_init(tall_bsc_ctx);

	bts_init();
	libosmo_abis_init(tall_bsc_ctx);

	/* enable filters */

	/* This needs to precede handle_options() */
	vty_info.copyright = openbsc_copyright;
	vty_init(&vty_info);
	bsc_vty_init(bsc_gsmnet);
	bsc_msg_lst_vty_init(tall_bsc_ctx, &access_lists, BSC_NODE);
	ctrl_vty_init(tall_bsc_ctx);

	INIT_LLIST_HEAD(&access_lists);

	/* parse options */
	handle_options(argc, argv);

	/* seed the PRNG */
	srand(time(NULL));

	/* initialize SCCP */
	sccp_set_log_area(DSCCP);

	/* Read the config */
	rc = bsc_network_configure(config_file);
	if (rc < 0) {
		fprintf(stderr, "Bootstrapping the network failed. exiting.\n");
		exit(1);
	}
	bsc_api_init(bsc_gsmnet, osmo_bsc_api());

	/* start control interface after reading config for
	 * ctrl_vty_get_bind_addr() */
	bsc_gsmnet->ctrl = bsc_controlif_setup(bsc_gsmnet,
					       ctrl_vty_get_bind_addr(),
					       OSMO_CTRL_PORT_NITB_BSC);
	if (!bsc_gsmnet->ctrl) {
		fprintf(stderr, "Failed to init the control interface. Exiting.\n");
		exit(1);
	}

	rc = bsc_ctrl_cmds_install(bsc_gsmnet);
	if (rc < 0) {
		fprintf(stderr, "Failed to install control commands. Exiting.\n");
		exit(1);
	}

	data = bsc_gsmnet->bsc_data;
	if (rf_ctrl)
		osmo_talloc_replace_string(data, &data->rf_ctrl_name, rf_ctrl);

	data->rf_ctrl = osmo_bsc_rf_create(data->rf_ctrl_name, bsc_gsmnet);
	if (!data->rf_ctrl) {
		fprintf(stderr, "Failed to create the RF service.\n");
		exit(1);
	}

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

	signal(SIGINT, &signal_handler);
	signal(SIGTERM, &signal_handler);
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
