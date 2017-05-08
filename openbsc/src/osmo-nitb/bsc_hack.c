/* A hackish minimal BSC (+MSC +HLR) implementation */

/* (C) 2008-2010 by Harald Welte <laforge@gnumonks.org>
 * (C) 2009-2012 by Holger Hans Peter Freyther <zecke@selfish.org>
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

#include <openbsc/db.h>
#include <osmocom/core/application.h>
#include <osmocom/core/select.h>
#include <osmocom/core/stats.h>
#include <openbsc/debug.h>
#include <osmocom/abis/abis.h>
#include <osmocom/abis/e1_input.h>
#include <osmocom/core/talloc.h>
#include <openbsc/signal.h>
#include <openbsc/osmo_msc.h>
#include <openbsc/bsc_msc_data.h>
#include <openbsc/sms_queue.h>
#include <openbsc/vty.h>
#include <openbsc/bss.h>
#include <openbsc/mncc.h>
#include <openbsc/token_auth.h>
#include <openbsc/handover_decision.h>
#include <openbsc/rrlp.h>
#include <osmocom/ctrl/control_if.h>
#include <osmocom/ctrl/ports.h>
#include <osmocom/ctrl/control_vty.h>
#include <openbsc/ctrl.h>
#include <openbsc/osmo_bsc_rf.h>
#include <openbsc/smpp.h>

#include "../../bscconfig.h"

/* MCC and MNC for the Location Area Identifier */
struct gsm_network *bsc_gsmnet = 0;
static const char *database_name = "hlr.sqlite3";
static const char *config_file = "openbsc.cfg";
static const char *rf_ctrl_path = NULL;
extern const char *openbsc_copyright;
static int daemonize = 0;
static const char *mncc_sock_path = NULL;
static int use_db_counter = 1;

/* timer to store statistics */
#define DB_SYNC_INTERVAL	60, 0
#define EXPIRE_INTERVAL		10, 0

static struct osmo_timer_list db_sync_timer;

static void create_pcap_file(char *file)
{
	mode_t mode = S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH;
	int fd = open(file, O_WRONLY|O_TRUNC|O_CREAT, mode);

	if (fd < 0) {
		perror("Failed to open file for pcap");
		return;
	}

	e1_set_pcap_fd(fd);
}

static void print_usage()
{
	printf("Usage: osmo-nitb\n");
}

static void print_help()
{
	printf("  Some useful help...\n");
	printf("  -h --help                  This text.\n");
	printf("  -d option --debug=DRLL:DCC:DMM:DRR:DRSL:DNM  Enable debugging.\n");
	printf("  -D --daemonize             Fork the process into a background daemon.\n");
	printf("  -c --config-file filename  The config file to use.\n");
	printf("  -s --disable-color\n");
	printf("  -l --database db-name      The database to use.\n");
	printf("  -a --authorize-everyone    Authorize every new subscriber. Dangerous!\n");
	printf("  -T --timestamp             Prefix every log line with a timestamp.\n");
	printf("  -V --version               Print the version of OpenBSC.\n");
	printf("  -P --rtp-proxy             Enable the RTP Proxy code inside OpenBSC.\n");
	printf("  -e --log-level number      Set a global loglevel.\n");
	printf("  -M --mncc-sock-path PATH   Disable built-in MNCC handler and offer socket.\n");
	printf("  -m --mncc-sock 	     Same as `-M /tmp/bsc_mncc' (deprecated).\n");
	printf("  -C --no-dbcounter          Disable regular syncing of counters to database.\n");
	printf("  -r --rf-ctl PATH           A unix domain socket to listen for cmds.\n");
	printf("  -p --pcap PATH             Write abis communication to pcap trace file.\n");
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
			{"database", 1, 0, 'l'},
			{"authorize-everyone", 0, 0, 'a'},
			{"pcap", 1, 0, 'p'},
			{"timestamp", 0, 0, 'T'},
			{"version", 0, 0, 'V' },
			{"rtp-proxy", 0, 0, 'P'},
			{"log-level", 1, 0, 'e'},
			{"mncc-sock", 0, 0, 'm'},
			{"mncc-sock-path", 1, 0, 'M'},
			{"no-dbcounter", 0, 0, 'C'},
			{"rf-ctl", 1, 0, 'r'},
			{0, 0, 0, 0}
		};

		c = getopt_long(argc, argv, "hd:Dsl:ar:p:TPVc:e:mCr:M:",
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
		case 'l':
			database_name = optarg;
			break;
		case 'c':
			config_file = optarg;
			break;
		case 'p':
			create_pcap_file(optarg);
			break;
		case 'T':
			log_set_print_timestamp(osmo_stderr_target, 1);
			break;
		case 'P':
			ipacc_rtp_direct = 0;
			break;
		case 'e':
			log_set_log_level(osmo_stderr_target, atoi(optarg));
			break;
		case 'M':
			mncc_sock_path = optarg;
			break;
		case 'm':
			mncc_sock_path = "/tmp/bsc_mncc";
			break;
		case 'C':
			use_db_counter = 0;
			break;
		case 'V':
			print_version(1);
			exit(0);
			break;
		case 'r':
			rf_ctrl_path = optarg;
			break;
		default:
			/* catch unknown options *as well as* missing arguments. */
			fprintf(stderr, "Error in command line options. Exiting.\n");
			exit(-1);
			break;
		}
	}
}

extern void *tall_vty_ctx;
static void signal_handler(int signal)
{
	fprintf(stdout, "signal %u received\n", signal);

	switch (signal) {
	case SIGINT:
		bsc_shutdown_net(bsc_gsmnet);
		osmo_signal_dispatch(SS_L_GLOBAL, S_L_GLOBAL_SHUTDOWN, NULL);
		sleep(3);
		exit(0);
		break;
	case SIGABRT:
		osmo_generate_backtrace();
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

/* timer handling */
static int _db_store_counter(struct osmo_counter *counter, void *data)
{
	return db_store_counter(counter);
}

static void db_sync_timer_cb(void *data)
{
	/* store counters to database and re-schedule */
	osmo_counters_for_each(_db_store_counter, NULL);
	osmo_timer_schedule(&db_sync_timer, DB_SYNC_INTERVAL);
}

static void subscr_expire_cb(void *data)
{
	subscr_expire(bsc_gsmnet->subscr_group);
	osmo_timer_schedule(&bsc_gsmnet->subscr_expire_timer, EXPIRE_INTERVAL);
}

extern int bsc_vty_go_parent(struct vty *vty);

static struct vty_app_info vty_info = {
	.name 		= "OpenBSC",
	.version	= PACKAGE_VERSION,
	.go_parent_cb	= bsc_vty_go_parent,
	.is_config_node	= bsc_vty_is_config_node,
};

int main(int argc, char **argv)
{
	int rc;

	vty_info.copyright = openbsc_copyright;

	tall_bsc_ctx = talloc_named_const(NULL, 1, "openbsc");
	talloc_ctx_init(tall_bsc_ctx);
	on_dso_load_token();
	on_dso_load_rrlp();
	on_dso_load_ho_dec();

	libosmo_abis_init(tall_bsc_ctx);
	osmo_init_logging(&log_info);
	osmo_stats_init(tall_bsc_ctx);
	bts_init();
	vty_init(&vty_info);

	/* Parse options */
	handle_options(argc, argv);

	/* Allocate global gsm_network struct; choose socket/internal MNCC */
	rc = bsc_network_alloc(mncc_sock_path?
			       mncc_sock_from_cc : int_mncc_recv);
	if (rc) {
		fprintf(stderr, "Allocation failed. Exiting.\n");
		exit(1);
	}

	/* Initialize VTY */
	bsc_vty_init(bsc_gsmnet);
	ctrl_vty_init(tall_bsc_ctx);

#ifdef BUILD_SMPP
	if (smpp_openbsc_alloc_init(tall_bsc_ctx) < 0)
		return -1;
#endif

	/* Initialize MNCC socket if appropriate */
	if (mncc_sock_path) {
		rc = mncc_sock_init(bsc_gsmnet, mncc_sock_path);
		if (rc) {
			fprintf(stderr, "MNCC socket initialization failed. exiting.\n");
			exit(1);
		}
	} else
		DEBUGP(DMNCC, "Using internal MNCC handler.\n");

	/*
	 * For osmo-nitb, skip TCH/F for now, because otherwise dyn TS
	 * always imply the possibility to have a mix of TCH/F and
	 * TCH/H channels; if two phones request a TCH/F and a TCH/H,
	 * respectively, they cannot call each other. If we deny TCH/F,
	 * they will both fall back to TCH/H, and dynamic channels are
	 * usable. See OS#1778.
	 *
	 * A third-party MSC may well be able to handle a TCH/H TCH/F
	 * mismatch. Moreover, this option may be overwritten in the
	 * config file or in VTY.
	 */
	bsc_gsmnet->dyn_ts_allow_tch_f = false;

	/* Read the config */
	rc = bsc_network_configure(config_file);
	if (rc < 0) {
		fprintf(stderr, "Reading config failed. Exiting.\n");
		exit(1);
	}

#ifdef BUILD_SMPP
	smpp_openbsc_start(bsc_gsmnet);
#endif
	bsc_api_init(bsc_gsmnet, msc_bsc_api());

	/* start control interface after reading config for
	 * ctrl_vty_get_bind_addr() */
	bsc_gsmnet->ctrl = bsc_controlif_setup(bsc_gsmnet,
					       ctrl_vty_get_bind_addr(),
					       OSMO_CTRL_PORT_NITB_BSC);
	if (!bsc_gsmnet->ctrl) {
		printf("Failed to initialize control interface. Exiting.\n");
		return -1;
	}

	if (bsc_base_ctrl_cmds_install() != 0) {
		printf("Failed to initialize the BSC control commands.\n");
		return -1;
	}

	if (msc_ctrl_cmds_install() != 0) {
		printf("Failed to initialize the MSC control commands.\n");
		return -1;
	}

	/* seed the PRNG */
	srand(time(NULL));

	bsc_gsmnet->bsc_data->rf_ctrl = osmo_bsc_rf_create(rf_ctrl_path, bsc_gsmnet);
	if (!bsc_gsmnet->bsc_data->rf_ctrl) {
		fprintf(stderr, "Failed to create the RF service.\n");
		exit(1);
	}

	if (db_init(database_name)) {
		printf("DB: Failed to init database. Please check the option settings.\n");
		return -1;
	}
	printf("DB: Database initialized.\n");

	if (db_prepare()) {
		printf("DB: Failed to prepare database.\n");
		return -1;
	}
	printf("DB: Database prepared.\n");

	/* setup the timer */
	osmo_timer_setup(&db_sync_timer, db_sync_timer_cb, NULL);
	if (use_db_counter)
		osmo_timer_schedule(&db_sync_timer, DB_SYNC_INTERVAL);

	osmo_timer_setup(&bsc_gsmnet->subscr_expire_timer, subscr_expire_cb,
			 NULL);
	osmo_timer_schedule(&bsc_gsmnet->subscr_expire_timer, EXPIRE_INTERVAL);

	signal(SIGINT, &signal_handler);
	signal(SIGABRT, &signal_handler);
	signal(SIGUSR1, &signal_handler);
	signal(SIGUSR2, &signal_handler);
	osmo_init_ignore_signals();

	/* start the SMS queue */
	if (sms_queue_start(bsc_gsmnet, 20) != 0)
		return -1;

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
