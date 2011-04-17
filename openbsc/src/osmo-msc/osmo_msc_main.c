/* A MSC (+HLR +VLR) in a box without MAP */

/* (C) 2011 by Holger Hans Peter Freyther <zecke@selfish.org>
 * (C) 2011 by On-Waves
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

#include <osmocom/core/select.h>
#include <osmocom/core/process.h>
#include <osmocom/core/talloc.h>

#include <openbsc/db.h>
#include <openbsc/debug.h>
#include <openbsc/signal.h>
#include <openbsc/osmo_msc.h>
#include <openbsc/sms_queue.h>
#include <openbsc/vty.h>

#include "../../bscconfig.h"

extern enum node_type bsc_vty_go_parent(struct vty *vty);

static const char *database_name = "hlr.sqlite3";
static const char *config_file = "openbsc.cfg";
extern const char *openbsc_copyright;

static struct vty_app_info vty_info = {
	.name 		= "OsmoMSC",
	.version	= PACKAGE_VERSION,
	.go_parent_cb	= bsc_vty_go_parent,
	.is_config_node	= bsc_vty_is_config_node,
};

/* timer to store statistics */
#define DB_SYNC_INTERVAL	60, 0
static struct timer_list db_sync_timer;

static struct log_target *stderr_target;
struct gsm_network *bsc_gsmnet = 0;

static int daemonize = 0;
static int use_mncc_sock = 0;

/* timer handling */
static int _db_store_counter(struct counter *counter, void *data)
{
	return db_store_counter(counter);
}

static void db_sync_timer_cb(void *data)
{
	/* store counters to database and re-schedule */
	counters_for_each(_db_store_counter, NULL);
	bsc_schedule_timer(&db_sync_timer, DB_SYNC_INTERVAL);
}

extern void *tall_vty_ctx;
static void signal_handler(int signal)
{
	fprintf(stdout, "signal %u received\n", signal);

	switch (signal) {
	case SIGINT:
		bsc_shutdown_net(bsc_gsmnet);
		dispatch_signal(SS_GLOBAL, S_GLOBAL_SHUTDOWN, NULL);
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
		talloc_report_full(tall_vty_ctx, stderr);
		break;
	default:
		break;
	}
}

static void handle_options(char **argv, int argc)
{
}

int main(int argc, char **argv)
{
	int rc;

	vty_info.copyright = openbsc_copyright;

	log_init(&log_info);
	tall_bsc_ctx = talloc_named_const(NULL, 1, "osmomsc");
	talloc_ctx_init();
	on_dso_load_token();
	on_dso_load_rrlp();
	on_dso_load_ho_dec();
	stderr_target = log_target_create_stderr();
	log_add_target(stderr_target);


	/* enable filters */
	log_set_all_filter(stderr_target, 1);

	/* This needs to precede handle_options() */
	vty_init(&vty_info);
	bsc_vty_init(&log_info);

	/* parse options */
	handle_options(argc, argv);

	/* internal MNCC handler or MNCC socket? */
	if (use_mncc_sock) {
		rc = bsc_bootstrap_network(mncc_sock_from_cc, config_file);
		if (rc >= 0)
			mncc_sock_init(bsc_gsmnet);
	} else
		rc = bsc_bootstrap_network(int_mncc_recv, config_file);
	if (rc < 0)
		exit(1);
	bsc_api_init(bsc_gsmnet, msc_bsc_api());

	/* seed the PRNG */
	srand(time(NULL));

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
	db_sync_timer.cb = db_sync_timer_cb;
	db_sync_timer.data = NULL;
	bsc_schedule_timer(&db_sync_timer, DB_SYNC_INTERVAL);

	signal(SIGINT, &signal_handler);
	signal(SIGABRT, &signal_handler);
	signal(SIGUSR1, &signal_handler);
	signal(SIGUSR2, &signal_handler);
	signal(SIGPIPE, SIG_IGN);

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
		bsc_select_main(0);
	}
}
