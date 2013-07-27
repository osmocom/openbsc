/* (C) 2011 by Daniel Willmann <daniel@totalueberwachung.de>
 * (C) 2011 by Holger Hans Peter Freyther
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

#include <openbsc/control_cmd.h>
#include <openbsc/debug.h>
#include <openbsc/gsm_data.h>
#include <openbsc/osmo_bsc.h>
#include <openbsc/osmo_bsc_rf.h>
#include <openbsc/osmo_msc_data.h>
#include <openbsc/signal.h>

#include <osmocom/core/linuxlist.h>
#include <osmocom/core/signal.h>
#include <osmocom/core/talloc.h>

#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>

void osmo_bsc_send_trap(struct ctrl_cmd *cmd, struct bsc_msc_connection *msc_con)
{
	struct ctrl_cmd *trap;
	struct ctrl_handle *ctrl;
	struct osmo_msc_data *msc_data;

	msc_data = (struct osmo_msc_data *) msc_con->write_queue.bfd.data;
	ctrl = msc_data->network->ctrl;

	trap = ctrl_cmd_trap(cmd);
	if (!trap) {
		LOGP(DCTRL, LOGL_ERROR, "Failed to create trap.\n");
		return;
	}

	ctrl_cmd_send_to_all(ctrl, trap);
	ctrl_cmd_send(&msc_con->write_queue, trap);

	talloc_free(trap);
}

CTRL_CMD_DEFINE(msc_connection_status, "msc_connection_status");
static int msc_connection_status = 0;

static int get_msc_connection_status(struct ctrl_cmd *cmd, void *data)
{
	if (msc_connection_status)
		cmd->reply = "connected";
	else
		cmd->reply = "disconnected";
	return CTRL_CMD_REPLY;
}

static int set_msc_connection_status(struct ctrl_cmd *cmd, void *data)
{
	return CTRL_CMD_ERROR;
}

static int verify_msc_connection_status(struct ctrl_cmd *cmd, const char *value, void *data)
{
	cmd->reply = "Read-only property";
	return 1;
}

static int msc_connection_status_trap_cb(unsigned int subsys, unsigned int signal, void *handler_data, void *signal_data)
{
	struct ctrl_cmd *cmd;
	struct gsm_network *gsmnet = (struct gsm_network *)handler_data;

	if (signal == S_MSC_LOST && msc_connection_status == 1) {
		LOGP(DCTRL, LOGL_DEBUG, "MSC connection lost, sending TRAP.\n");
		msc_connection_status = 0;
	} else if (signal == S_MSC_CONNECTED && msc_connection_status == 0) {
		LOGP(DCTRL, LOGL_DEBUG, "MSC connection (re)established, sending TRAP.\n");
		msc_connection_status = 1;
	} else {
		return 0;
	}

	cmd = ctrl_cmd_create(tall_bsc_ctx, CTRL_TYPE_TRAP);
	if (!cmd) {
		LOGP(DCTRL, LOGL_ERROR, "Trap creation failed.\n");
		return 0;
	}

	cmd->id = "0";
	cmd->variable = "msc_connection_status";

	get_msc_connection_status(cmd, NULL);

	ctrl_cmd_send_to_all(gsmnet->ctrl, cmd);

	talloc_free(cmd);

	return 0;
}

CTRL_CMD_DEFINE(bts_connection_status, "bts_connection_status");
static int bts_connection_status = 0;

static int get_bts_connection_status(struct ctrl_cmd *cmd, void *data)
{
	if (bts_connection_status)
		cmd->reply = "connected";
	else
		cmd->reply = "disconnected";
	return CTRL_CMD_REPLY;
}

static int set_bts_connection_status(struct ctrl_cmd *cmd, void *data)
{
	return CTRL_CMD_ERROR;
}

static int verify_bts_connection_status(struct ctrl_cmd *cmd, const char *value, void *data)
{
	cmd->reply = "Read-only property";
	return 1;
}

static int bts_connection_status_trap_cb(unsigned int subsys, unsigned int signal, void *handler_data, void *signal_data)
{
	struct ctrl_cmd *cmd;
	struct gsm_network *gsmnet = (struct gsm_network *)handler_data;
	struct gsm_bts *bts;
	int bts_current_status;

	if (signal != S_L_INP_TEI_DN && signal != S_L_INP_TEI_UP) {
		return 0;
	}

	bts_current_status = 0;
	/* Check if OML on at least one BTS is up */
	llist_for_each_entry(bts, &gsmnet->bts_list, list) {
		if (bts->oml_link) {
			bts_current_status = 1;
			break;
		}
	}
	if (bts_connection_status == 0 && bts_current_status == 1) {
		LOGP(DCTRL, LOGL_DEBUG, "BTS connection (re)established, sending TRAP.\n");
	} else if (bts_connection_status == 1 && bts_current_status == 0) {
		LOGP(DCTRL, LOGL_DEBUG, "No more BTS connected, sending TRAP.\n");
	} else {
		return 0;
	}

	cmd = ctrl_cmd_create(tall_bsc_ctx, CTRL_TYPE_TRAP);
	if (!cmd) {
		LOGP(DCTRL, LOGL_ERROR, "Trap creation failed.\n");
		return 0;
	}

	bts_connection_status = bts_current_status;

	cmd->id = "0";
	cmd->variable = "bts_connection_status";

	get_bts_connection_status(cmd, NULL);

	ctrl_cmd_send_to_all(gsmnet->ctrl, cmd);

	talloc_free(cmd);

	return 0;
}

static int get_bts_loc(struct ctrl_cmd *cmd, void *data);

static void generate_location_state_trap(struct gsm_bts *bts, struct bsc_msc_connection *msc_con)
{
	struct ctrl_cmd *cmd;
	const char *oper, *admin, *policy;

	cmd = ctrl_cmd_create(msc_con, CTRL_TYPE_TRAP);
	if (!cmd) {
		LOGP(DCTRL, LOGL_ERROR, "Failed to create TRAP command.\n");
		return;
	}

	cmd->id = "0";
	cmd->variable = talloc_asprintf(cmd, "bts.%i.location-state", bts->nr);

	/* Prepare the location reply */
	cmd->node = bts;
	get_bts_loc(cmd, NULL);

	oper = osmo_bsc_rf_get_opstate_name(osmo_bsc_rf_get_opstate_by_bts(bts));
	admin = osmo_bsc_rf_get_adminstate_name(osmo_bsc_rf_get_adminstate_by_bts(bts));
	policy = osmo_bsc_rf_get_policy_name(osmo_bsc_rf_get_policy_by_bts(bts));

	cmd->reply = talloc_asprintf_append(cmd->reply, ",%s,%s,%s", oper, admin, policy);

	osmo_bsc_send_trap(cmd, msc_con);
	talloc_free(cmd);
}

static int location_equal(struct bts_location *a, struct bts_location *b)
{
	return ((a->tstamp == b->tstamp) && (a->valid == b->valid) && (a->lat == b->lat) &&
		(a->lon == b->lon) && (a->height == b->height));
}

static void cleanup_locations(struct llist_head *locations)
{
	struct bts_location *myloc, *tmp;
	int invalpos = 0, i = 0;

	LOGP(DCTRL, LOGL_DEBUG, "Checking position list.\n");
	llist_for_each_entry_safe(myloc, tmp, locations, list) {
		i++;
		if (i > 3) {
			LOGP(DCTRL, LOGL_DEBUG, "Deleting old position.\n");
			llist_del(&myloc->list);
			talloc_free(myloc);
		} else if (myloc->valid == BTS_LOC_FIX_INVALID) {
			/* Only capture the newest of subsequent invalid positions */
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

CTRL_CMD_DEFINE(bts_loc, "location");
static int get_bts_loc(struct ctrl_cmd *cmd, void *data)
{
	struct bts_location *curloc;
	struct gsm_bts *bts = (struct gsm_bts *) cmd->node;
	if (!bts) {
		cmd->reply = "bts not found.";
		return CTRL_CMD_ERROR;
	}

	if (llist_empty(&bts->loc_list)) {
		cmd->reply = talloc_asprintf(cmd, "0,invalid,0,0,0");
		return CTRL_CMD_REPLY;
	} else {
		curloc = llist_entry(bts->loc_list.next, struct bts_location, list);
	}

	cmd->reply = talloc_asprintf(cmd, "%lu,%s,%f,%f,%f", curloc->tstamp,
			get_value_string(bts_loc_fix_names, curloc->valid), curloc->lat, curloc->lon, curloc->height);
	if (!cmd->reply) {
		cmd->reply = "OOM";
		return CTRL_CMD_ERROR;
	}

	return CTRL_CMD_REPLY;
}

static int set_bts_loc(struct ctrl_cmd *cmd, void *data)
{
	char *saveptr, *lat, *lon, *height, *tstamp, *valid, *tmp;
	struct osmo_msc_data *msc;
	struct bts_location *curloc, *lastloc;
	int ret;
	struct gsm_network *gsmnet = (struct gsm_network *)data;
	struct gsm_bts *bts = (struct gsm_bts *) cmd->node;
	if (!bts) {
		cmd->reply = "bts not found.";
		return CTRL_CMD_ERROR;
	}

	tmp = talloc_strdup(cmd, cmd->value);
	if (!tmp)
		goto oom;

	curloc = talloc_zero(tall_bsc_ctx, struct bts_location);
	if (!curloc) {
		talloc_free(tmp);
		goto oom;
	}
	INIT_LLIST_HEAD(&curloc->list);


	tstamp = strtok_r(tmp, ",", &saveptr);
	valid = strtok_r(NULL, ",", &saveptr);
	lat = strtok_r(NULL, ",", &saveptr);
	lon = strtok_r(NULL, ",", &saveptr);
	height = strtok_r(NULL, "\0", &saveptr);

	curloc->tstamp = atol(tstamp);
	curloc->valid = get_string_value(bts_loc_fix_names, valid);
	curloc->lat = atof(lat);
	curloc->lon = atof(lon);
	curloc->height = atof(height);
	talloc_free(tmp);

	lastloc = llist_entry(bts->loc_list.next, struct bts_location, list);

	/* Add location to the end of the list */
	llist_add(&curloc->list, &bts->loc_list);

	ret = get_bts_loc(cmd, data);

	if (!location_equal(curloc, lastloc))
		llist_for_each_entry(msc, &gsmnet->bsc_data->mscs, entry)
			generate_location_state_trap(bts, msc->msc_con);

	cleanup_locations(&bts->loc_list);

	return ret;

oom:
	cmd->reply = "OOM";
	return CTRL_CMD_ERROR;
}

static int verify_bts_loc(struct ctrl_cmd *cmd, const char *value, void *data)
{
	char *saveptr, *latstr, *lonstr, *heightstr, *tstampstr, *validstr, *tmp;
	time_t tstamp;
	int valid;
	double lat, lon, height __attribute__((unused));

	tmp = talloc_strdup(cmd, value);
	if (!tmp)
		return 1;

	tstampstr = strtok_r(tmp, ",", &saveptr);
	validstr = strtok_r(NULL, ",", &saveptr);
	latstr = strtok_r(NULL, ",", &saveptr);
	lonstr = strtok_r(NULL, ",", &saveptr);
	heightstr = strtok_r(NULL, "\0", &saveptr);

	if ((tstampstr == NULL) || (validstr == NULL) || (latstr == NULL) ||
			(lonstr == NULL) || (heightstr == NULL))
		goto err;

	tstamp = atol(tstampstr);
	valid = get_string_value(bts_loc_fix_names, validstr);
	lat = atof(latstr);
	lon = atof(lonstr);
	height = atof(heightstr);
	talloc_free(tmp);
	tmp = NULL;

	if (((tstamp == 0) && (valid != BTS_LOC_FIX_INVALID)) || (lat < -90) || (lat > 90) ||
			(lon < -180) || (lon > 180) || (valid < 0)) {
		goto err;
	}

	return 0;

err:
	talloc_free(tmp);
	cmd->reply = talloc_strdup(cmd, "The format is <unixtime>,(invalid|fix2d|fix3d),<lat>,<lon>,<height>");
	return 1;
}

CTRL_CMD_DEFINE(bts_rf_state, "rf_state");
static int get_bts_rf_state(struct ctrl_cmd *cmd, void *data)
{
	const char *oper, *admin, *policy;
	struct gsm_bts *bts = cmd->node;

	if (!bts) {
		cmd->reply = "bts not found.";
		return CTRL_CMD_ERROR;
	}

	oper = osmo_bsc_rf_get_opstate_name(osmo_bsc_rf_get_opstate_by_bts(bts));
	admin = osmo_bsc_rf_get_adminstate_name(osmo_bsc_rf_get_adminstate_by_bts(bts));
	policy = osmo_bsc_rf_get_policy_name(osmo_bsc_rf_get_policy_by_bts(bts));

	cmd->reply = talloc_asprintf(cmd, "%s,%s,%s", oper, admin, policy);
	if (!cmd->reply) {
		cmd->reply = "OOM.";
		return CTRL_CMD_ERROR;
	}

	return CTRL_CMD_REPLY;
}

static int set_bts_rf_state(struct ctrl_cmd *cmd, void *data)
{
	cmd->reply = "set is unimplemented";
	return CTRL_CMD_ERROR;
}

static int verify_bts_rf_state(struct ctrl_cmd *cmd, const char *value, void *data)
{
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
	if (!net) {
		cmd->reply = "net not found.";
		return CTRL_CMD_ERROR;
	}

	if (!net->bsc_data->rf_ctrl) {
		cmd->reply = "RF Ctrl is not enabled in the BSC Configuration";
		return CTRL_CMD_ERROR;
	}

	osmo_bsc_rf_schedule_lock(net->bsc_data->rf_ctrl,
			locked == 1 ? '0' : '1');

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

static int msc_signal_handler(unsigned int subsys, unsigned int signal,
			void *handler_data, void *signal_data)
{
	struct msc_signal_data *msc;
	struct gsm_network *net;
	struct gsm_bts *bts;

	if (subsys != SS_MSC)
		return 0;
	if (signal != S_MSC_AUTHENTICATED)
		return 0;

	msc = signal_data;

	net = msc->data->network;
	llist_for_each_entry(bts, &net->bts_list, list)
		generate_location_state_trap(bts, msc->data->msc_con);	

	return 0;
}

int bsc_ctrl_cmds_install(struct gsm_network *net)
{
	int rc;

	rc = ctrl_cmd_install(CTRL_NODE_BTS, &cmd_bts_rf_state);
	if (rc)
		goto end;
	rc = ctrl_cmd_install(CTRL_NODE_BTS, &cmd_bts_loc);
	if (rc)
		goto end;
	rc = ctrl_cmd_install(CTRL_NODE_ROOT, &cmd_net_rf_lock);
	if (rc)
		goto end;
	rc = ctrl_cmd_install(CTRL_NODE_ROOT, &cmd_msc_connection_status);
	if (rc)
		goto end;
	rc = osmo_signal_register_handler(SS_MSC, &msc_connection_status_trap_cb, net);
	if (rc)
		goto end;
	rc = osmo_signal_register_handler(SS_MSC, msc_signal_handler, NULL);
	if (rc)
		goto end;
	rc = ctrl_cmd_install(CTRL_NODE_ROOT, &cmd_bts_connection_status);
	if (rc)
		goto end;
	rc = osmo_signal_register_handler(SS_L_INPUT, &bts_connection_status_trap_cb, net);

end:
	return rc;
}
