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
#include <openbsc/osmo_msc_data.h>
#include <openbsc/signal.h>
#include <openbsc/vty.h>
#include <openbsc/ipaccess.h>

#include <openbsc/control_cmd.h>
#include <openbsc/control_if.h>

#include <osmocom/core/application.h>
#include <osmocom/core/linuxlist.h>
#include <osmocom/core/talloc.h>
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
			config_file = strdup(optarg);
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

extern enum node_type bsc_vty_go_parent(struct vty *vty);

static struct vty_app_info vty_info = {
	.name 		= "OsmoBSC",
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

struct location {
	struct llist_head list;
	unsigned long age;
	int valid;
	double lat;
	double lon;
	double height;
};

static LLIST_HEAD(locations);

static void cleanup_locations()
{
	struct location *myloc, *tmp;
	int invalpos = 0, i = 0;

	LOGP(DCTRL, LOGL_DEBUG, "Checking position list.\n");
	llist_for_each_entry_safe(myloc, tmp, &locations, list) {
		i++;
		if (i > 3) {
			LOGP(DCTRL, LOGL_DEBUG, "Deleting old position.\n");
			llist_del(&myloc->list);
			talloc_free(myloc);
		} else if (!myloc->valid) { /* Only capture the newest of subsequent invalid positions */
			invalpos++;
			if (invalpos > 1) {
				LOGP(DCTRL, LOGL_DEBUG, "Deleting subsequent invalid position.\n");
				invalpos--;
				i--;
				llist_del(&myloc->list);
				talloc_free(myloc);
			}
		} else {
			invalpos = 0;
		}
	}
	LOGP(DCTRL, LOGL_DEBUG, "Found %i positions.\n", i);
}

CTRL_CMD_DEFINE(net_loc, "location");
static int get_net_loc(struct ctrl_cmd *cmd, void *data)
{
	struct location *myloc;

	if (llist_empty(&locations)) {
		cmd->reply = talloc_asprintf(cmd, "0,0,0,0,0");
		return CTRL_CMD_REPLY;
	} else {
		myloc = llist_entry(locations.next, struct location, list);
	}

	cmd->reply = talloc_asprintf(cmd, "%lu,%i,%f,%f,%f", myloc->age, myloc->valid, myloc->lat, myloc->lon, myloc->height);
	if (!cmd->reply) {
		cmd->reply = "OOM";
		return CTRL_CMD_ERROR;
	}

	return CTRL_CMD_REPLY;
}

static int set_net_loc(struct ctrl_cmd *cmd, void *data)
{
	char *saveptr, *lat, *lon, *height, *age, *valid, *tmp;
	struct location *myloc;

	tmp = talloc_strdup(cmd, cmd->value);
	if (!tmp)
		goto oom;

	myloc = talloc_zero(tall_bsc_ctx, struct location);
	if (!myloc) {
		talloc_free(tmp);
		goto oom;
	}
	INIT_LLIST_HEAD(&myloc->list);


	age = strtok_r(tmp, ",", &saveptr);
	valid = strtok_r(NULL, ",", &saveptr);
	lat = strtok_r(NULL, ",", &saveptr);
	lon = strtok_r(NULL, ",", &saveptr);
	height = strtok_r(NULL, "\0", &saveptr);

	myloc->age = atol(age);
	myloc->valid = atoi(valid);
	myloc->lat = atof(lat);
	myloc->lon = atof(lon);
	myloc->height = atof(height);
	talloc_free(tmp);

	/* Add location to the end of the list */
	llist_add(&myloc->list, &locations);
	cleanup_locations();

	return get_net_loc(cmd, data);
oom:
	cmd->reply = "OOM";
	return CTRL_CMD_ERROR;
}

static int verify_net_loc(struct ctrl_cmd *cmd, const char *value, void *data)
{
	char *saveptr, *latstr, *lonstr, *heightstr, *agestr, *validstr, *tmp;
	unsigned long age;
	int valid;
	double lat, lon, height;

	tmp = talloc_strdup(cmd, value);
	if (!tmp)
		return 1;

	agestr = strtok_r(tmp, ",", &saveptr);
	validstr = strtok_r(NULL, ",", &saveptr);
	latstr = strtok_r(NULL, ",", &saveptr);
	lonstr = strtok_r(NULL, ",", &saveptr);
	heightstr = strtok_r(NULL, "\0", &saveptr);

	if ((agestr == NULL) || (validstr == NULL) || (latstr == NULL) ||
			(lonstr == NULL) || (heightstr == NULL))
		return 1;

	age = atol(agestr);
	valid = atoi(validstr);
	lat = atof(latstr);
	lon = atof(lonstr);
	height = atof(heightstr);
	talloc_free(tmp);

	if (((age == 0) && (valid !=0)) || (lat < -90) || (lat > 90) ||
			(lon < -180) || (lon > 180) || (valid < 0) || (valid > 2))
		return 1;

	return 0;
}

CTRL_CMD_DEFINE(trx_rf_lock, "rf_locked");
static int get_trx_rf_lock(struct ctrl_cmd *cmd, void *data)
{
	struct gsm_bts_trx *trx = cmd->node;
	if (!trx) {
		cmd->reply = "trx not found.";
		return CTRL_CMD_ERROR;
	}

	cmd->reply = talloc_asprintf(cmd, "%u", trx->mo.nm_state.administrative == NM_STATE_LOCKED ? 1 : 0);
	return CTRL_CMD_REPLY;
}

static int set_trx_rf_lock(struct ctrl_cmd *cmd, void *data)
{
	int locked = atoi(cmd->value);
	struct gsm_bts_trx *trx = cmd->node;
	if (!trx) {
		cmd->reply = "trx not found.";
		return CTRL_CMD_ERROR;
	}

	gsm_trx_lock_rf(trx, locked);

	return get_trx_rf_lock(cmd, data);
}

static int verify_trx_rf_lock(struct ctrl_cmd *cmd, const char *value, void *data)
{
	int locked = atoi(cmd->value);

	if ((locked != 0) && (locked != 1))
		return 1;

	return 0;
}

CTRL_CMD_DEFINE(net_rf_lock, "rf_locked");
static int get_net_rf_lock(struct ctrl_cmd *cmd, void *data)
{
	cmd->reply = "get only works for the individual trx properties.";
	return CTRL_CMD_ERROR;
}

static int set_net_rf_lock(struct ctrl_cmd *cmd, void *data)
{
	int locked = atoi(cmd->value);
	struct gsm_network *net = cmd->node;
	struct gsm_bts *bts;
	if (!net) {
		cmd->reply = "net not found.";
		return CTRL_CMD_ERROR;
	}

	llist_for_each_entry(bts, &net->bts_list, list) {
		struct gsm_bts_trx *trx;
		llist_for_each_entry(trx, &bts->trx_list, list) {
			gsm_trx_lock_rf(trx, locked);
		}
	}

	cmd->reply = talloc_asprintf(cmd, "%u", locked);
	if (!cmd->reply) {
		cmd->reply = "OOM.";
		return CTRL_CMD_ERROR;
	}

	return CTRL_CMD_REPLY;
}

static int verify_net_rf_lock(struct ctrl_cmd *cmd, const char *value, void *data)
{
	int locked = atoi(cmd->value);

	if ((locked != 0) && (locked != 1))
		return 1;

	return 0;
}

int main(int argc, char **argv)
{
	struct osmo_msc_data *msc;
	struct osmo_bsc_data *data;
	int rc;

	tall_bsc_ctx = talloc_named_const(NULL, 1, "openbsc");

	osmo_init_logging(&log_info);

	bts_init();
	libosmo_abis_init(tall_bsc_ctx);

	/* enable filters */

	/* This needs to precede handle_options() */
	vty_info.copyright = openbsc_copyright;
	vty_init(&vty_info);
	bsc_vty_init(&log_info);

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
	bsc_api_init(bsc_gsmnet, osmo_bsc_api());

	bsc_gsmnet->ctrl = controlif_setup(bsc_gsmnet, 4249);

	ctrl_cmd_install(CTRL_NODE_NET, &cmd_net_loc);
	ctrl_cmd_install(CTRL_NODE_NET, &cmd_net_rf_lock);
	ctrl_cmd_install(CTRL_NODE_TRX, &cmd_trx_rf_lock);

	data = bsc_gsmnet->bsc_data;
	if (rf_ctrl)
		bsc_replace_string(data, &data->rf_ctrl_name, rf_ctrl);

	if (data->rf_ctrl_name) {
		data->rf_ctrl = osmo_bsc_rf_create(data->rf_ctrl_name,
						  bsc_gsmnet);
		if (!data->rf_ctrl) {
			fprintf(stderr, "Failed to create the RF service.\n");
			exit(1);
		}
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
