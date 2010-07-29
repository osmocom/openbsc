/* (C) 2008-2009 by Harald Welte <laforge@gnumonks.org>
 * (C) 2009-2010 by Holger Hans Peter Freyther <zecke@selfish.org>
 * (C) 2009-2010 by On-Waves
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

#include <openbsc/debug.h>
#include <openbsc/gsm_data.h>
#include <openbsc/osmo_bsc_rf.h>

#include <osmocom/vty/command.h>
#include <osmocore/talloc.h>

#include <sccp/sccp.h>

#define _GNU_SOURCE
#include <getopt.h>

#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#include "bscconfig.h"

static struct log_target *stderr_target;
struct gsm_network *bsc_gsmnet = 0;
static const char *config_file = "openbsc.cfg";
static const char *rf_ctl = NULL;

extern void bsc_vty_init(void);
extern int bsc_bootstrap_network(int (*layer4)(struct gsm_network *, int, void *), const char *cfg_file);

static void print_usage()
{
	printf("Usage: bsc_msc_ip\n");
}

static void print_help()
{
	printf("  Some useful help...\n");
	printf("  -h --help this text\n");
	printf("  -d option --debug=DRLL:DCC:DMM:DRR:DRSL:DNM enable debugging\n");
	printf("  -s --disable-color\n");
	printf("  -T --timestamp. Print a timestamp in the debug output.\n");
	printf("  -c --config-file filename The config file to use.\n");
	printf("  -l --local=IP. The local address of the MGCP.\n");
	printf("  -e --log-level number. Set a global loglevel.\n");
	printf("  -r --rf-ctl NAME. A unix domain socket to listen for cmds.\n");
	printf("  -t --testmode. A special mode to provoke failures at the MSC.\n");
}

static void handle_options(int argc, char** argv)
{
	while (1) {
		int option_index = 0, c;
		static struct option long_options[] = {
			{"help", 0, 0, 'h'},
			{"debug", 1, 0, 'd'},
			{"config-file", 1, 0, 'c'},
			{"disable-color", 0, 0, 's'},
			{"timestamp", 0, 0, 'T'},
			{"msc", 1, 0, 'm'},
			{"local", 1, 0, 'l'},
			{"log-level", 1, 0, 'e'},
			{"rf-ctl", 1, 0, 'r'},
			{"testmode", 0, 0, 't'},
			{0, 0, 0, 0}
		};

		c = getopt_long(argc, argv, "hd:sTc:e:r:t",
				long_options, &option_index);
		if (c == -1)
			break;

		switch (c) {
		case 'h':
			print_usage();
			print_help();
			exit(0);
		case 's':
			log_set_use_color(stderr_target, 0);
			break;
		case 'd':
			log_parse_category_mask(stderr_target, optarg);
			break;
		case 'c':
			config_file = strdup(optarg);
			break;
		case 'T':
			log_set_print_timestamp(stderr_target, 1);
			break;
		case 'P':
			ipacc_rtp_direct = 0;
			break;
		case 'e':
			log_set_log_level(stderr_target, atoi(optarg));
			break;
		case 'r':
			rf_ctl = optarg;
			break;
		default:
			/* ignore */
			break;
		}
	}
}

extern int bts_model_unknown_init(void);
extern int bts_model_bs11_init(void);
extern int bts_model_nanobts_init(void);

extern enum node_type bsc_vty_go_parent(struct vty *vty);

static struct vty_app_info vty_info = {
	.name 		= "OpenBSC Osmo BSC",
	.version	= PACKAGE_VERSION,
	.go_parent_cb	= bsc_vty_go_parent,
};


int main(int argc, char **argv)
{
	char *msc;
	int rc;

	log_init(&log_info);
	tall_bsc_ctx = talloc_named_const(NULL, 1, "openbsc");
	stderr_target = log_target_create_stderr();
	log_add_target(stderr_target);

	bts_model_unknown_init();
	bts_model_bs11_init();
	bts_model_nanobts_init();

	/* enable filters */
	log_set_all_filter(stderr_target, 1);

	/* This needs to precede handle_options() */
	vty_init(&vty_info);
	bsc_vty_init();

	/* parse options */
	handle_options(argc, argv);

	/* seed the PRNG */
	srand(time(NULL));

	/* initialize SCCP */
	sccp_set_log_area(DSCCP);


	rc = bsc_bootstrap_network(NULL, config_file);
	if (rc < 0) {
		fprintf(stderr, "Bootstrapping the network failed. exiting.\n");
		exit(1);
	}

	if (rf_ctl) {
		struct osmo_bsc_rf *rf;
		rf = osmo_bsc_rf_create(rf_ctl, bsc_gsmnet);
		if (!rf) {
			fprintf(stderr, "Failed to create the RF service.\n");
			exit(1);
		}
	}


	while (1) {
		bsc_select_main(0);
	}

	return 0;
}
