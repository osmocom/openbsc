/* NS-over-IP proxy */

/* (C) 2010 by Harald Welte <laforge@gnumonks.org>
 * (C) 2010 by On-Waves
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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <errno.h>
#include <signal.h>
#include <sys/fcntl.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <osmocom/core/application.h>
#include <osmocom/core/talloc.h>
#include <osmocom/core/select.h>
#include <osmocom/core/rate_ctr.h>
#include <osmocom/core/stats.h>

#include <osmocom/gprs/gprs_ns.h>
#include <osmocom/gprs/gprs_bssgp.h>

#include <openbsc/signal.h>
#include <openbsc/debug.h>
#include <openbsc/vty.h>
#include <openbsc/gb_proxy.h>

#include <osmocom/vty/command.h>
#include <osmocom/vty/telnet_interface.h>
#include <osmocom/vty/logging.h>
#include <osmocom/vty/stats.h>
#include <osmocom/vty/ports.h>

#include "../../bscconfig.h"

#define _GNU_SOURCE
#include <getopt.h>

void *tall_bsc_ctx;

const char *openbsc_copyright =
	"Copyright (C) 2010 Harald Welte and On-Waves\r\n"
	"License AGPLv3+: GNU AGPL version 3 or later <http://gnu.org/licenses/agpl-3.0.html>\r\n"
	"This is free software: you are free to change and redistribute it.\r\n"
	"There is NO WARRANTY, to the extent permitted by law.\r\n";

static char *config_file = "osmo_gbproxy.cfg";
struct gbproxy_config gbcfg = {0};
static int daemonize = 0;

/* Pointer to the SGSN peer */
extern struct gbprox_peer *gbprox_peer_sgsn;

/* call-back function for the NS protocol */
static int proxy_ns_cb(enum gprs_ns_evt event, struct gprs_nsvc *nsvc,
		      struct msgb *msg, uint16_t bvci)
{
	int rc = 0;

	switch (event) {
	case GPRS_NS_EVT_UNIT_DATA:
		rc = gbprox_rcvmsg(&gbcfg, msg, nsvc->nsei, bvci, nsvc->nsvci);
		break;
	default:
		LOGP(DGPRS, LOGL_ERROR, "SGSN: Unknown event %u from NS\n", event);
		if (msg)
			msgb_free(msg);
		rc = -EIO;
		break;
	}
	return rc;
}

static void signal_handler(int signal)
{
	fprintf(stdout, "signal %u received\n", signal);

	switch (signal) {
	case SIGINT:
	case SIGTERM:
		osmo_signal_dispatch(SS_L_GLOBAL, S_L_GLOBAL_SHUTDOWN, NULL);
		sleep(1);
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
		talloc_report_full(tall_vty_ctx, stderr);
		break;
	default:
		break;
	}
}

static void print_usage()
{
	printf("Usage: bsc_hack\n");
}

static void print_help()
{
	printf("  Some useful help...\n");
	printf("  -h --help this text\n");
	printf("  -d option --debug=DNS:DGPRS,0:0 enable debugging\n");
	printf("  -D --daemonize Fork the process into a background daemon\n");
	printf("  -c --config-file filename The config file to use.\n");
	printf("  -s --disable-color\n");
	printf("  -T --timestamp Prefix every log line with a timestamp\n");
	printf("  -V --version. Print the version of OpenBSC.\n");
	printf("  -e --log-level number. Set a global loglevel.\n");
}

static void handle_options(int argc, char **argv)
{
	while (1) {
		int option_index = 0, c;
		static struct option long_options[] = {
			{ "help", 0, 0, 'h' },
			{ "debug", 1, 0, 'd' },
			{ "daemonize", 0, 0, 'D' },
			{ "config-file", 1, 0, 'c' },
			{ "disable-color", 0, 0, 's' },
			{ "timestamp", 0, 0, 'T' },
			{ "version", 0, 0, 'V' },
			{ "log-level", 1, 0, 'e' },
			{ 0, 0, 0, 0 }
		};

		c = getopt_long(argc, argv, "hd:Dc:sTVe:",
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
		case 'V':
			print_version(1);
			exit(0);
			break;
		default:
			break;
		}
	}
}

extern int bsc_vty_go_parent(struct vty *vty);

static struct vty_app_info vty_info = {
	.name 		= "OsmoGbProxy",
	.version	= PACKAGE_VERSION,
	.go_parent_cb	= bsc_vty_go_parent,
	.is_config_node	= bsc_vty_is_config_node,
};

/* default categories */
static struct log_info_cat gprs_categories[] = {
	[DGPRS] = {
		.name = "DGPRS",
		.description = "GPRS Packet Service",
		.enabled = 1, .loglevel = LOGL_DEBUG,
	},
	[DNS] = {
		.name = "DNS",
		.description = "GPRS Network Service (NS)",
		.enabled = 1, .loglevel = LOGL_INFO,
	},
	[DBSSGP] = {
		.name = "DBSSGP",
		.description = "GPRS BSS Gateway Protocol (BSSGP)",
		.enabled = 1, .loglevel = LOGL_DEBUG,
	},
};

static const struct log_info gprs_log_info = {
	.filter_fn = gprs_log_filter_fn,
	.cat = gprs_categories,
	.num_cat = ARRAY_SIZE(gprs_categories),
};

int main(int argc, char **argv)
{
	struct gsm_network dummy_network;
	int rc;

	tall_bsc_ctx = talloc_named_const(NULL, 0, "nsip_proxy");
	msgb_talloc_ctx_init(tall_bsc_ctx, 0);

	signal(SIGINT, &signal_handler);
	signal(SIGTERM, &signal_handler);
	signal(SIGABRT, &signal_handler);
	signal(SIGUSR1, &signal_handler);
	signal(SIGUSR2, &signal_handler);
	osmo_init_ignore_signals();

	osmo_init_logging(&gprs_log_info);

	vty_info.copyright = openbsc_copyright;
	vty_init(&vty_info);
	logging_vty_add_cmds(NULL);
	osmo_stats_vty_add_cmds(&gprs_log_info);
	gbproxy_vty_init();

	handle_options(argc, argv);

	rate_ctr_init(tall_bsc_ctx);
	osmo_stats_init(tall_bsc_ctx);

	bssgp_nsi = gprs_ns_instantiate(&proxy_ns_cb, tall_bsc_ctx);
	if (!bssgp_nsi) {
		LOGP(DGPRS, LOGL_ERROR, "Unable to instantiate NS\n");
		exit(1);
	}
	gbproxy_init_config(&gbcfg);
	gbcfg.nsi = bssgp_nsi;
	gprs_ns_vty_init(bssgp_nsi);
	gprs_ns_set_log_ss(DNS);
	bssgp_set_log_ss(DBSSGP);
	osmo_signal_register_handler(SS_L_NS, &gbprox_signal, &gbcfg);

	rc = gbproxy_parse_config(config_file, &gbcfg);
	if (rc < 0) {
		LOGP(DGPRS, LOGL_FATAL, "Cannot parse config file\n");
		exit(2);
	}

	/* start telnet after reading config for vty_get_bind_addr() */
	rc = telnet_init_dynif(tall_bsc_ctx, &dummy_network,
			       vty_get_bind_addr(), OSMO_VTY_PORT_GBPROXY);
	if (rc < 0)
		exit(1);

	if (!gprs_nsvc_by_nsei(gbcfg.nsi, gbcfg.nsip_sgsn_nsei)) {
		LOGP(DGPRS, LOGL_FATAL, "You cannot proxy to NSEI %u "
			"without creating that NSEI before\n",
			gbcfg.nsip_sgsn_nsei);
		exit(2);
	}

	rc = gprs_ns_nsip_listen(bssgp_nsi);
	if (rc < 0) {
		LOGP(DGPRS, LOGL_FATAL, "Cannot bind/listen on NSIP socket\n");
		exit(2);
	}

	rc = gprs_ns_frgre_listen(bssgp_nsi);
	if (rc < 0) {
		LOGP(DGPRS, LOGL_FATAL, "Cannot bind/listen GRE "
			"socket. Do you have CAP_NET_RAW?\n");
		exit(2);
	}

	if (daemonize) {
		rc = osmo_daemonize();
		if (rc < 0) {
			perror("Error during daemonize");
			exit(1);
		}
	}

	/* Reset all the persistent NS-VCs that we've read from the config */
	gbprox_reset_persistent_nsvcs(bssgp_nsi);

	while (1) {
		rc = osmo_select_main(0);
		if (rc < 0)
			exit(3);
	}

	exit(0);
}
