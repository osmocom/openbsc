/* OsmoCSCN - Circuit-Switched Core Network (MSC+VLR+HLR+SMSC) implementation
 */

/* (C) 2016 by sysmocom s.f.m.c. GmbH <info@sysmocom.de>
 * All Rights Reserved
 *
 * Based on OsmoNITB:
 * (C) 2008-2010 by Harald Welte <laforge@gnumonks.org>
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

/* build switches from the configure script */
#include "../../bscconfig.h"

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
#include <openbsc/osmo_msc_data.h>
#include <openbsc/sms_queue.h>
#include <osmocom/vty/telnet_interface.h>
#include <osmocom/vty/ports.h>
#include <osmocom/vty/logging.h>
#include <openbsc/vty.h>
#include <openbsc/bss.h>
#include <openbsc/mncc.h>
#include <openbsc/token_auth.h>
#include <openbsc/handover_decision.h>
#include <openbsc/rrlp.h>
#include <osmocom/ctrl/control_if.h>
#include <osmocom/ctrl/control_vty.h>
#include <osmocom/ctrl/ports.h>
#include <openbsc/ctrl.h>
#include <openbsc/osmo_bsc_rf.h>
#include <openbsc/smpp.h>
#include <osmocom/sigtran/sccp_sap.h>
#include <osmocom/sigtran/sua.h>

#include <openbsc/msc_ifaces.h>
#include <openbsc/iu.h>
#include <openbsc/iucs.h>

#include "iucs_ranap.h"

static const char * const osmocscn_copyright =
	"OsmoCSCN - Osmocom Circuit-Switched Core Network implementation\r\n"
	"Copyright (C) 2016 by sysmocom s.f.m.c. GmbH <info@sysmocom.de>\r\n"
	"Based on OsmoNITB:\r\n"
	"  (C) 2008-2010 by Harald Welte <laforge@gnumonks.org>\r\n"
	"  (C) 2009-2012 by Holger Hans Peter Freyther <zecke@selfish.org>\r\n"
	"Contributions by Daniel Willmann, Jan Lübbe, Stefan Schmidt\r\n"
	"Dieter Spaar, Andreas Eversberg, Sylvain Munaut, Neels Hofmeyr\r\n\r\n"
	"License AGPLv3+: GNU AGPL version 3 or later <http://gnu.org/licenses/agpl-3.0.html>\r\n"
	"This is free software: you are free to change and redistribute it.\r\n"
	"There is NO WARRANTY, to the extent permitted by law.\r\n";

void *tall_cscn_ctx = NULL;

/* satisfy deps from libbsc legacy.
   TODO double check these */
void *tall_fle_ctx = NULL;
void *tall_paging_ctx = NULL;
void *tall_map_ctx = NULL;
void *tall_upq_ctx = NULL;
/* end deps from libbsc legacy. */

static struct {
	const char *database_name;
	const char *config_file;
	int daemonize;
	const char *mncc_sock_path;
	int use_db_counter;
} cscn_cmdline_config = {
	"hlr.sqlite3",
	"osmo-cscn.cfg",
	0,
	0,
	1
};

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
	printf("  -m --mncc-sock             Same as `-M /tmp/bsc_mncc' (deprecated).\n");
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
			{0, 0, 0, 0}
		};

		c = getopt_long(argc, argv, "hd:Dsl:ap:TPVc:e:mCM:",
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
			cscn_cmdline_config.daemonize = 1;
			break;
		case 'l':
			cscn_cmdline_config.database_name = optarg;
			break;
		case 'c':
			cscn_cmdline_config.config_file = optarg;
			break;
		case 'p':
			create_pcap_file(optarg);
			break;
		case 'T':
			log_set_print_timestamp(osmo_stderr_target, 1);
			break;
#if BEFORE_MSCSPLIT
		case 'P':
			ipacc_rtp_direct = 0;
			break;
#endif
		case 'e':
			log_set_log_level(osmo_stderr_target, atoi(optarg));
			break;
		case 'M':
			cscn_cmdline_config.mncc_sock_path = optarg;
			break;
		case 'm':
			cscn_cmdline_config.mncc_sock_path = "/tmp/bsc_mncc";
			break;
		case 'C':
			cscn_cmdline_config.use_db_counter = 0;
			break;
		case 'V':
			print_version(1);
			exit(0);
			break;
		default:
			/* catch unknown options *as well as* missing arguments. */
			fprintf(stderr, "Error in command line options. Exiting.\n");
			exit(-1);
		}
	}
}

struct gsm_network *cscn_network_alloc(void *ctx,
				       mncc_recv_cb_t mncc_recv)
{
	struct gsm_network *net = gsm_network_init(ctx, 1, 1, mncc_recv);
	if (!net)
		return NULL;

	net->name_long = talloc_strdup(net, "OsmoCSCN");
	net->name_short = talloc_strdup(net, "OsmoCSCN");

	return net;
}

void cscn_network_shutdown(struct gsm_network *net)
{
	/* nothing here yet */
}

static struct gsm_network *cscn_network = NULL;

/* TODO this is here to satisfy linking during intermediate development. Once
 * libbsc is not linked to osmo-cscn, this should go away. */
struct gsm_network *bsc_gsmnet = NULL;

extern void *tall_vty_ctx;
static void signal_handler(int signal)
{
	fprintf(stdout, "signal %u received\n", signal);

	switch (signal) {
	case SIGINT:
		cscn_network_shutdown(cscn_network);
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
		talloc_report_full(tall_cscn_ctx, stderr);
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
	subscr_expire(cscn_network->subscr_group);
	osmo_timer_schedule(&cscn_network->subscr_expire_timer, EXPIRE_INTERVAL);
}

extern int bsc_vty_go_parent(struct vty *vty);

static struct vty_app_info cscn_vty_info = {
	.name		= "OsmoCSCN",
	.version	= PACKAGE_VERSION,
	.go_parent_cb	= bsc_vty_go_parent,
	.is_config_node	= bsc_vty_is_config_node,
};

static int rcvmsg_iu_cs(struct msgb *msg, struct gprs_ra_id *ra_id, /* FIXME gprs_ in CS code */
			uint16_t *sai)
{
	DEBUGP(DIUCS, "got IuCS message"
	       " %d bytes: %s\n",
	       msg->len, osmo_hexdump(msg->data, msg->len));
	if (ra_id) {
		DEBUGP(DIUCS, "got IuCS message on"
		       " MNC %d MCC %d LAC %d RAC %d\n",
		       ra_id->mnc, ra_id->mcc, ra_id->lac, ra_id->rac);
	}

	return gsm0408_rcvmsg_iucs(cscn_network, msg, ra_id? &ra_id->lac : NULL);
}

static int rx_iu_event(struct ue_conn_ctx *ctx, enum iu_event_type type,
		       void *data)
{
	DEBUGP(DIUCS, "got IuCS event %u: %s\n", type,
	       iu_event_type_str(type));

	return iucs_rx_ranap_event(cscn_network, ctx, type, data);
}

int main(int argc, char **argv)
{
	int rc;

	cscn_vty_info.copyright	= osmocscn_copyright;

	tall_cscn_ctx = talloc_named_const(NULL, 1, "osmo_cscn");
	talloc_ctx_init(tall_cscn_ctx);

	osmo_init_logging(&log_info);
	osmo_stats_init(tall_cscn_ctx);

	/* For --version, vty_init() must be called before handling options */
	vty_init(&cscn_vty_info);

	/* Parse options */
	handle_options(argc, argv);

	/* Allocate global gsm_network struct; choose socket/internal MNCC */
	cscn_network = cscn_network_alloc(tall_cscn_ctx,
					  cscn_cmdline_config.mncc_sock_path?
						  mncc_sock_from_cc
						  : int_mncc_recv);
	if (!cscn_network)
		return -ENOMEM;

	ctrl_vty_init(tall_cscn_ctx);
	logging_vty_add_cmds(&log_info);
	cscn_vty_init(cscn_network);
	bsc_vty_init_extra();

#ifdef BUILD_SMPP
	if (smpp_openbsc_alloc_init(tall_cscn_ctx) < 0)
		return -1;
#endif

	rc = vty_read_config_file(cscn_cmdline_config.config_file, NULL);
	if (rc < 0) {
		LOGP(DNM, LOGL_FATAL, "Failed to parse the config file: '%s'\n",
		     cscn_cmdline_config.config_file);
		return 1;
	}

	/* Initialize MNCC socket if appropriate */
	if (cscn_cmdline_config.mncc_sock_path) {
		rc = mncc_sock_init(cscn_network,
				    cscn_cmdline_config.mncc_sock_path);
		if (rc) {
			fprintf(stderr, "MNCC socket initialization failed. exiting.\n");
			exit(1);
		}
	} else
		DEBUGP(DMNCC, "Using internal MNCC handler.\n");

	/* start telnet after reading config for vty_get_bind_addr() */
	rc = telnet_init_dynif(tall_cscn_ctx, &cscn_network,
			       vty_get_bind_addr(), OSMO_VTY_PORT_CSCN);
	if (rc < 0)
		return 2;

	/* BSC stuff is to be split behind an A-interface to be used with
	 * OsmoBSC, but there is no need to remove it yet. Most of the
	 * following code until iu_init() is legacy. */

#ifdef BUILD_SMPP
	smpp_openbsc_start(cscn_network);
#endif

#if 0
	the bsc_ctrl_node_lookup() only returns BSC specific ctrl nodes

	/*
	 * For osmo-nitb, skip TCH/F for now, because otherwise dyn TS
	 * always imply the possibility to have a mix of TCH/F and
	 * TCH/H channels; if two phones request a TCH/F and a TCH/H,
	 * respectively, they cannot call each other. If we deny TCH/F,
	 * they will both fall back to TCH/H, and dynamic channels are
	 * usable. See http://osmocom.org/issues/1778.
	 *
	 * A third-party MSC may well be able to handle a TCH/H TCH/F
	 * mismatch.
	 */
	bsc_gsmnet->dyn_ts_allow_tch_f = false;

	/* start control interface after reading config for
	 * ctrl_vty_get_bind_addr() */
	cscn_network->ctrl = bsc_controlif_setup(cscn_network,
						 ctrl_vty_get_bind_addr(),
						 OSMO_CTRL_PORT_CSCN);
	if (!cscn_network->ctrl) {
		printf("Failed to initialize control interface. Exiting.\n");
		return -1;
	}
#endif

#if 0
TODO: we probably want some of the _net_ ctrl commands from bsc_base_ctrl_cmds_install().
	if (bsc_base_ctrl_cmds_install() != 0) {
		printf("Failed to initialize the BSC control commands.\n");
		return -1;
	}
#endif

#if 0
	if (msc_ctrl_cmds_install() != 0) {
		printf("Failed to initialize the MSC control commands.\n");
		return -1;
	}
#endif

	/* seed the PRNG */
	srand(time(NULL));
	/* TODO: is this used for crypto?? Improve randomness, at least we
	 * should try to use the nanoseconds part of the current time. */

	if (db_init(cscn_cmdline_config.database_name)) {
		printf("DB: Failed to init database: %s\n",
		       cscn_cmdline_config.database_name);
		return 4;
	}

	if (db_prepare()) {
		printf("DB: Failed to prepare database.\n");
		return 5;
	}

	db_sync_timer.cb = db_sync_timer_cb;
	db_sync_timer.data = NULL;
	if (cscn_cmdline_config.use_db_counter)
		osmo_timer_schedule(&db_sync_timer, DB_SYNC_INTERVAL);

	cscn_network->subscr_expire_timer.cb = subscr_expire_cb;
	cscn_network->subscr_expire_timer.data = NULL;
	osmo_timer_schedule(&cscn_network->subscr_expire_timer, EXPIRE_INTERVAL);

	signal(SIGINT, &signal_handler);
	signal(SIGABRT, &signal_handler);
	signal(SIGUSR1, &signal_handler);
	signal(SIGUSR2, &signal_handler);
	osmo_init_ignore_signals();

	/* start the SMS queue */
	if (sms_queue_start(cscn_network, 20) != 0)
		return -1;

	/* Set up A-Interface */
	/* TODO: implement A-Interface and remove above legacy stuff. */

	/* Set up IuCS */
	iu_init(tall_cscn_ctx, "127.0.0.1", 14001, rcvmsg_iu_cs, rx_iu_event);

	if (cscn_cmdline_config.daemonize) {
		rc = osmo_daemonize();
		if (rc < 0) {
			perror("Error during daemonize");
			return 6;
		}
	}

	while (1) {
		log_reset_context();
		osmo_select_main(0);
	}
}
