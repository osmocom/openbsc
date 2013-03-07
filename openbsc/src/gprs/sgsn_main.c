/* GPRS SGSN Implementation */

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
#include <osmocom/core/logging.h>

#include <osmocom/gprs/gprs_ns.h>
#include <osmocom/gprs/gprs_bssgp.h>

#include <osmocom/vty/telnet_interface.h>
#include <osmocom/vty/logging.h>

#include <openbsc/signal.h>
#include <openbsc/debug.h>
#include <openbsc/vty.h>
#include <openbsc/sgsn.h>
#include <openbsc/gprs_llc.h>
#include <openbsc/gprs_gmm.h>

#include <gtp.h>

#include "../../bscconfig.h"

/* FIXME: put into seperate header file */
int gprs_sndcp_vty_init(void);
int sgsn_gtp_init(struct sgsn_instance *sgi);

/* this is here for the vty... it will never be called */
void subscr_put() { abort(); }

#define _GNU_SOURCE
#include <getopt.h>

void *tall_bsc_ctx;

struct gprs_ns_inst *sgsn_nsi;
static int daemonize = 0;
const char *openbsc_copyright =
	"Copyright (C) 2010 Harald Welte and On-Waves\r\n"
	"License AGPLv3+: GNU AGPL version 2 or later <http://gnu.org/licenses/agpl-3.0.html>\r\n"
	"This is free software: you are free to change and redistribute it.\r\n"
	"There is NO WARRANTY, to the extent permitted by law.\r\n";

static struct sgsn_instance sgsn_inst = {
	.config_file = "osmo_sgsn.cfg",
	.cfg = {
		.gtp_statedir = "./",
		.acl_enabled = 1,
	},
};
struct sgsn_instance *sgsn = &sgsn_inst;

/* call-back function for the NS protocol */
static int sgsn_ns_cb(enum gprs_ns_evt event, struct gprs_nsvc *nsvc,
		      struct msgb *msg, uint16_t bvci)
{
	int rc = 0;

	switch (event) {
	case GPRS_NS_EVT_UNIT_DATA:
		/* hand the message into the BSSGP implementation */
		rc = bssgp_rcvmsg(msg);
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

/* call-back function for the BSSGP protocol */
int bssgp_prim_cb(struct osmo_prim_hdr *oph, void *ctx)
{
	struct osmo_bssgp_prim *bp;
	bp = container_of(oph, struct osmo_bssgp_prim, oph);

	switch (oph->sap) {
	case SAP_BSSGP_LL:
		switch (oph->primitive) {
		case PRIM_BSSGP_UL_UD:
			return gprs_llc_rcvmsg(oph->msg, bp->tp);
		}
		break;
	case SAP_BSSGP_GMM:
		switch (oph->primitive) {
		case PRIM_BSSGP_GMM_SUSPEND:
			return gprs_gmm_rx_suspend(bp->ra_id, bp->tlli);
		case PRIM_BSSGP_GMM_RESUME:
			return gprs_gmm_rx_resume(bp->ra_id, bp->tlli,
						  bp->u.resume.suspend_ref);
		}
		break;
	case SAP_BSSGP_NM:
		break;
	}
	return 0;
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

/* NSI that BSSGP uses when transmitting on NS */
extern struct gprs_ns_inst *bssgp_nsi;
extern void *tall_msgb_ctx;

extern enum node_type bsc_vty_go_parent(struct vty *vty);

static struct vty_app_info vty_info = {
	.name 		= "OsmoSGSN",
	.version	= PACKAGE_VERSION,
	.go_parent_cb	= bsc_vty_go_parent,
	.is_config_node	= bsc_vty_is_config_node,
};

static void print_help(void)
{
	printf("Some useful help...\n");
	printf("  -h --help\tthis text\n");
	printf("  -D --daemonize\tFork the process into a background daemon\n");
	printf("  -d option --debug\tenable Debugging\n");
	printf("  -s --disable-color\n");
	printf("  -c --config-file\tThe config file to use\n");
	printf("  -e --log-level number\tSet a global log level\n");
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
			sgsn_inst.config_file = strdup(optarg);
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

/* default categories */
static struct log_info_cat gprs_categories[] = {
	[DMM] = {
		.name = "DMM",
		.description = "Layer3 Mobility Management (MM)",
		.color = "\033[1;33m",
		.enabled = 1, .loglevel = LOGL_NOTICE,
	},
	[DPAG]	= {
		.name = "DPAG",
		.description = "Paging Subsystem",
		.color = "\033[1;38m",
		.enabled = 1, .loglevel = LOGL_NOTICE,
	},
	[DMEAS] = {
		.name = "DMEAS",
		.description = "Radio Measurement Processing",
		.enabled = 0, .loglevel = LOGL_NOTICE,
	},
	[DREF] = {
		.name = "DREF",
		.description = "Reference Counting",
		.enabled = 0, .loglevel = LOGL_NOTICE,
	},
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
	[DLLC] = {
		.name = "DLLC",
		.description = "GPRS Logical Link Control Protocol (LLC)",
		.enabled = 1, .loglevel = LOGL_DEBUG,
	},
	[DSNDCP] = {
		.name = "DSNDCP",
		.description = "GPRS Sub-Network Dependent Control Protocol (SNDCP)",
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

	tall_bsc_ctx = talloc_named_const(NULL, 0, "osmo_sgsn");
	tall_msgb_ctx = talloc_named_const(tall_bsc_ctx, 0, "msgb");

	signal(SIGINT, &signal_handler);
	signal(SIGABRT, &signal_handler);
	signal(SIGUSR1, &signal_handler);
	signal(SIGUSR2, &signal_handler);

	osmo_init_ignore_signals();
	osmo_init_logging(&gprs_log_info);

	vty_info.copyright = openbsc_copyright;
	vty_init(&vty_info);
	logging_vty_add_cmds(&gprs_log_info);
        sgsn_vty_init();

	handle_options(argc, argv);

	rate_ctr_init(tall_bsc_ctx);
	rc = telnet_init(tall_bsc_ctx, &dummy_network, 4245);
	if (rc < 0)
		exit(1);

	gprs_ns_set_log_ss(DNS);
	bssgp_set_log_ss(DBSSGP);

	sgsn_nsi = gprs_ns_instantiate(&sgsn_ns_cb, tall_bsc_ctx);
	if (!sgsn_nsi) {
		LOGP(DGPRS, LOGL_ERROR, "Unable to instantiate NS\n");
		exit(1);
	}
	bssgp_nsi = sgsn_inst.cfg.nsi = sgsn_nsi;

	gprs_llc_init("/usr/local/lib/osmocom/crypt/");

	gprs_ns_vty_init(bssgp_nsi);
	bssgp_vty_init();
	gprs_llc_vty_init();
	gprs_sndcp_vty_init();
	/* FIXME: register signal handler for SS_L_NS */

	rc = sgsn_parse_config(sgsn_inst.config_file, &sgsn_inst.cfg);
	if (rc < 0) {
		LOGP(DGPRS, LOGL_FATAL, "Cannot parse config file\n");
		exit(2);
	}

	rc = sgsn_gtp_init(&sgsn_inst);
	if (rc) {
		LOGP(DGPRS, LOGL_FATAL, "Cannot bind/listen on GTP socket\n");
		exit(2);
	}

	rc = gprs_ns_nsip_listen(sgsn_nsi);
	if (rc < 0) {
		LOGP(DGPRS, LOGL_FATAL, "Cannot bind/listen on NSIP socket\n");
		exit(2);
	}

	rc = gprs_ns_frgre_listen(sgsn_nsi);
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

	while (1) {
		rc = osmo_select_main(0);
		if (rc < 0)
			exit(3);
	}

	/* not reached */
	exit(0);
}
