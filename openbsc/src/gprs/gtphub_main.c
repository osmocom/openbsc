/* GTP Hub main program */

/* (C) 2015 by sysmocom s.f.m.c. GmbH <info@sysmocom.de>
 * All Rights Reserved
 *
 * Author: Neels Hofmeyr
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
 */

#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <errno.h>

#define _GNU_SOURCE
#include <getopt.h>

#include <osmocom/core/signal.h>
#include <osmocom/core/application.h>
#include <osmocom/core/logging.h>
#include <osmocom/core/utils.h>
#include <osmocom/core/rate_ctr.h>

#include <osmocom/vty/logging.h>
#include <osmocom/vty/telnet_interface.h>

#include <openbsc/debug.h>
#include <openbsc/gtphub.h>
#include <openbsc/vty.h>

#include "../../bscconfig.h"

#ifndef OSMO_VTY_PORT_GTPHUB
/* should come from libosmocore */
#define OSMO_VTY_PORT_GTPHUB	4253
#endif

extern void *osmo_gtphub_ctx;


const char *gtphub_copyright =
	"Copyright (C) 2015 sysmocom s.f.m.c GmbH <info@sysmocom.de>\r\n"
	"License AGPLv3+: GNU AGPL version 2 or later <http://gnu.org/licenses/agpl-3.0.html>\r\n"
	"This is free software: you are free to change and redistribute it.\r\n"
	"There is NO WARRANTY, to the extent permitted by law.\r\n";

static struct log_info_cat gtphub_categories[] = {
	[DGTPHUB] = {
		.name = "DGTPHUB",
		.description = "GTP Hub",
		.color = "\033[1;33m",
		.enabled = 1,
		.loglevel = LOGL_NOTICE,
	},
};

int gtphub_log_filter_fn(const struct log_context *ctx,
			 struct log_target *tar)
{
	return 0;
}

static const struct log_info gtphub_log_info = {
	.filter_fn = gtphub_log_filter_fn,
	.cat = gtphub_categories,
	.num_cat = ARRAY_SIZE(gtphub_categories),
};

void log_cfg(struct gtphub_cfg *cfg)
{
	struct gtphub_cfg_addr *a;
	a = &cfg->to_sgsns[GTPH_PLANE_CTRL].bind;
	LOGP(DGTPHUB, LOGL_NOTICE,
	     "to-SGSNs bind, Control: %s port %d\n",
	     a->addr_str, a->port);
	a = &cfg->to_sgsns[GTPH_PLANE_USER].bind;
	LOGP(DGTPHUB, LOGL_NOTICE,
	     "to-SGSNs bind, User:    %s port %d\n",
	     a->addr_str, a->port);
	a = &cfg->to_ggsns[GTPH_PLANE_CTRL].bind;
	LOGP(DGTPHUB, LOGL_NOTICE,
	     "to-GGSNs bind, Control: %s port %d\n",
	     a->addr_str, a->port);
	a = &cfg->to_ggsns[GTPH_PLANE_USER].bind;
	LOGP(DGTPHUB, LOGL_NOTICE,
	     "to-GGSNs bind, User:    %s port %d\n",
	     a->addr_str, a->port);
}

static void signal_handler(int signal)
{
	fprintf(stdout, "signal %u received\n", signal);

	switch (signal) {
	case SIGINT:
		osmo_signal_dispatch(SS_L_GLOBAL, S_L_GLOBAL_SHUTDOWN, NULL);
		sleep(1);
		exit(0);
		break;
	case SIGABRT:
		/* in case of abort, we want to obtain a talloc report
		 * and then return to the caller, who will abort the process */
	case SIGUSR1:
	case SIGUSR2:
		talloc_report_full(osmo_gtphub_ctx, stderr);
		break;
	default:
		break;
	}
}

extern int bsc_vty_go_parent(struct vty *vty);

static struct vty_app_info vty_info = {
	.name 		= "OsmoGTPhub",
	.version	= PACKAGE_VERSION,
	.go_parent_cb	= bsc_vty_go_parent,
	.is_config_node	= bsc_vty_is_config_node,
};

struct cmdline_cfg {
	const char *config_file;
	int daemonize;
};

static void print_help(struct cmdline_cfg *ccfg)
{
	printf("gtphub commandline options\n");
	printf("  -h --help            This text.\n");
	printf("  -D --daemonize       Fork the process into a background daemon.\n");
	printf("  -d,--debug <cat>     Enable Debugging for this category.\n");
	printf("                       Pass '-d list' to get a category listing.\n");
	printf("  -s --disable-color");
	printf("  -c --config-file     The config file to use [%s].\n", ccfg->config_file);
	printf("  -e,--log-level <nr>  Set a global log level.\n");
}

static void list_categories(void)
{
	printf("Avaliable debug categories:\n");
	int i;
	for (i = 0; i < gtphub_log_info.num_cat; ++i) {
		if (!gtphub_log_info.cat[i].name)
			continue;

		printf("%s\n", gtphub_log_info.cat[i].name);
	}
}

static void handle_options(struct cmdline_cfg *ccfg, int argc, char **argv)
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
			{"log-level", 1, 0, 'e'},
			{NULL, 0, 0, 0}
		};

		c = getopt_long(argc, argv, "hd:Dc:sTe:",
				long_options, &option_index);
		if (c == -1)
			break;

		switch (c) {
		case 'h':
			//print_usage();
			print_help(ccfg);
			exit(0);
		case 's':
			log_set_use_color(osmo_stderr_target, 0);
			break;
		case 'd':
			if (strcmp("list", optarg) == 0) {
				list_categories();
				exit(0);
			} else
				log_parse_category_mask(osmo_stderr_target, optarg);
			break;
		case 'D':
			ccfg->daemonize = 1;
			break;
		case 'c':
			ccfg->config_file = optarg;
			break;
		case 'T':
			log_set_print_timestamp(osmo_stderr_target, 1);
			break;
		case 'e':
			log_set_log_level(osmo_stderr_target, atoi(optarg));
			break;
		default:
			/* ignore */
			break;
		}
	}
}

int main(int argc, char **argv)
{
	int rc;

	struct cmdline_cfg _ccfg;
	struct cmdline_cfg *ccfg = &_ccfg;
	memset(ccfg, '\0', sizeof(*ccfg));
	ccfg->config_file = "./gtphub.conf";

	struct gtphub_cfg _cfg;
	struct gtphub_cfg *cfg = &_cfg;
	memset(cfg, '\0', sizeof(*cfg));

	struct gtphub _hub;
	struct gtphub *hub = &_hub;

	osmo_gtphub_ctx = talloc_named_const(NULL, 0, "osmo_gtphub");

	signal(SIGINT, &signal_handler);
	signal(SIGABRT, &signal_handler);
	signal(SIGUSR1, &signal_handler);
	signal(SIGUSR2, &signal_handler);
	osmo_init_ignore_signals();

	osmo_init_logging(&gtphub_log_info);

	vty_info.copyright = gtphub_copyright;
	vty_init(&vty_info);
	logging_vty_add_cmds(&gtphub_log_info);
        gtphub_vty_init(hub, cfg);

	rate_ctr_init(osmo_gtphub_ctx);
	rc = telnet_init(osmo_gtphub_ctx, 0, OSMO_VTY_PORT_GTPHUB);
	if (rc < 0)
		exit(1);

	handle_options(ccfg, argc, argv);

	rc = gtphub_cfg_read(cfg, ccfg->config_file);
	if (rc < 0) {
		LOGP(DGTPHUB, LOGL_FATAL, "Cannot parse config file '%s'\n",
		     ccfg->config_file);
		exit(2);
	}

	if (gtphub_start(hub, cfg) != 0)
		return -1;

	log_cfg(cfg);

	if (ccfg->daemonize) {
		rc = osmo_daemonize();
		if (rc < 0) {
			LOGP(DGTPHUB, LOGL_FATAL, "Error during daemonize");
			exit(1);
		}
	}

	while (1) {
		rc = osmo_select_main(0);
		if (rc < 0)
			exit(3);
	}

	/* not reached */
	exit(0);
}
