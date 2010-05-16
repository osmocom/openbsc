/* NS-over-IP proxy */

/* (C) 2010 by Harald Welte <laforge@gnumonks.org>
 * (C) 2010 by On Waves
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

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <errno.h>
#include <signal.h>
#include <sys/fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <osmocore/talloc.h>
#include <osmocore/select.h>
#include <osmocore/rate_ctr.h>

#include <openbsc/signal.h>
#include <openbsc/debug.h>
#include <openbsc/gprs_ns.h>
#include <openbsc/gprs_bssgp.h>
#include <openbsc/telnet_interface.h>
#include <openbsc/vty.h>
#include <openbsc/gb_proxy.h>

#include <vty/command.h>

#include "../../bscconfig.h"

/* this is here for the vty... it will never be called */
void subscr_put() { abort(); }

#define _GNU_SOURCE
#include <getopt.h>

void *tall_bsc_ctx;

const char *openbsc_copyright =
	"Copyright (C) 2010 Harald Welte and On-Waves\n"
	"License GPLv2+: GNU GPL version 2 or later <http://gnu.org/licenses/gpl.html>\n"
	"This is free software: you are free to change and redistribute it.\n"
	"There is NO WARRANTY, to the extent permitted by law.\n";

static struct log_target *stderr_target;
static char *config_file = "osmo_gbproxy.cfg";
struct gbproxy_config gbcfg;

/* Pointer to the SGSN peer */
extern struct gbprox_peer *gbprox_peer_sgsn;

/* call-back function for the NS protocol */
static int proxy_ns_cb(enum gprs_ns_evt event, struct gprs_nsvc *nsvc,
		      struct msgb *msg, u_int16_t bvci)
{
	int rc = 0;

	switch (event) {
	case GPRS_NS_EVT_UNIT_DATA:
		rc = gbprox_rcvmsg(msg, nsvc, bvci);
		break;
	default:
		LOGP(DGPRS, LOGL_ERROR, "SGSN: Unknown event %u from NS\n", event);
		if (msg)
			talloc_free(msg);
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
		dispatch_signal(SS_GLOBAL, S_GLOBAL_SHUTDOWN, NULL);
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
			{ "config-file", 1, 0, 'c' },
			{ "disable-color", 0, 0, 's' },
			{ "timestamp", 0, 0, 'T' },
			{ "version", 0, 0, 'V' },
			{ "log-level", 1, 0, 'e' },
			{ 0, 0, 0, 0 }
		};

		c = getopt_long(argc, argv, "hd:c:sTVe:",
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
		case 'e':
			log_set_log_level(stderr_target, atoi(optarg));
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

extern void *tall_msgb_ctx;

int main(int argc, char **argv)
{
	struct gsm_network dummy_network;
	struct sockaddr_in sin;
	int rc;

	tall_bsc_ctx = talloc_named_const(NULL, 0, "nsip_proxy");
	tall_msgb_ctx = talloc_named_const(tall_bsc_ctx, 0, "msgb");

	signal(SIGINT, &signal_handler);
	signal(SIGABRT, &signal_handler);
	signal(SIGUSR1, &signal_handler);
	signal(SIGUSR2, &signal_handler);
	signal(SIGPIPE, SIG_IGN);

	log_init(&log_info);
	stderr_target = log_target_create_stderr();
	log_add_target(stderr_target);
	log_set_all_filter(stderr_target, 1);

	vty_init("Osmocom Gb Proxy", PACKAGE_VERSION, openbsc_copyright);
	openbsc_vty_add_cmds();
        gbproxy_vty_init();

	handle_options(argc, argv);

	rate_ctr_init(tall_bsc_ctx);

	rc = telnet_init(tall_bsc_ctx, &dummy_network, 4246);
	if (rc < 0)
		exit(1);

	bssgp_nsi = gprs_ns_instantiate(&proxy_ns_cb);
	if (!bssgp_nsi) {
		LOGP(DGPRS, LOGL_ERROR, "Unable to instantiate NS\n");
		exit(1);
	}
	gbcfg.nsi = bssgp_nsi;
	gprs_ns_vty_init(bssgp_nsi);
	register_signal_handler(SS_NS, &gbprox_signal, NULL);

	rc = gbproxy_parse_config(config_file, &gbcfg);
	if (rc < 0) {
		LOGP(DGPRS, LOGL_FATAL, "Cannot parse config file\n");
		exit(2);
	}

	nsip_listen(bssgp_nsi, gbcfg.nsip_listen_port);

	/* 'establish' the outgoing connection to the SGSN */
	sin.sin_family = AF_INET;
	sin.sin_port = htons(gbcfg.nsip_sgsn_port);
	sin.sin_addr.s_addr = htonl(gbcfg.nsip_sgsn_ip);
	nsip_connect(bssgp_nsi, &sin, gbcfg.nsip_sgsn_nsei,
			gbcfg.nsip_sgsn_nsvci);


	/* Reset all the persistent NS-VCs that we've read from the config */
	gbprox_reset_persistent_nsvcs(bssgp_nsi);

	while (1) {
		rc = bsc_select_main(0);
		if (rc < 0)
			exit(3);
	}

	exit(0);
}
