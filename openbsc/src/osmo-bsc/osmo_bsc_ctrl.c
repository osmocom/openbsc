/* (C) 2011 by Daniel Willmann <daniel@totalueberwachung.de>
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

#include <osmocom/core/linuxlist.h>
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

#define LOC_FIX_INVALID 0
#define LOC_FIX_2D	1
#define LOC_FIX_3D	2

static const struct value_string valid_names[] = {
	{ LOC_FIX_INVALID,	"invalid" },
	{ LOC_FIX_2D,		"fix2d" },
	{ LOC_FIX_3D,		"fix3d" },
	{ 0, NULL }
};

struct location {
	struct llist_head list;
	time_t tstamp;
	int valid;
	double lat;
	double lon;
	double height;
};

static int location_equal(struct location *a, struct location *b)
{
	return ((a->tstamp == b->tstamp) && (a->valid == b->valid) && (a->lat == b->lat) &&
		(a->lon == b->lon) && (a->height == b->height));
}

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
		} else if (myloc->valid == LOC_FIX_INVALID) {
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

CTRL_CMD_DEFINE(net_loc, "location");
static int get_net_loc(struct ctrl_cmd *cmd, void *data)
{
	struct location *myloc;

	if (llist_empty(&locations)) {
		cmd->reply = talloc_asprintf(cmd, "0,invalid,0,0,0");
		return CTRL_CMD_REPLY;
	} else {
		myloc = llist_entry(locations.next, struct location, list);
	}

	cmd->reply = talloc_asprintf(cmd, "%lu,%s,%f,%f,%f", myloc->tstamp,
			get_value_string(valid_names, myloc->valid), myloc->lat, myloc->lon, myloc->height);
	if (!cmd->reply) {
		cmd->reply = "OOM";
		return CTRL_CMD_ERROR;
	}

	return CTRL_CMD_REPLY;
}

static int set_net_loc(struct ctrl_cmd *cmd, void *data)
{
	char *saveptr, *lat, *lon, *height, *tstamp, *valid, *tmp;
	struct osmo_msc_data *msc;
	struct location *myloc, *lastloc;
	int ret;
	struct gsm_network *gsmnet = (struct gsm_network *)data;

	tmp = talloc_strdup(cmd, cmd->value);
	if (!tmp)
		goto oom;

	myloc = talloc_zero(tall_bsc_ctx, struct location);
	if (!myloc) {
		talloc_free(tmp);
		goto oom;
	}
	INIT_LLIST_HEAD(&myloc->list);


	tstamp = strtok_r(tmp, ",", &saveptr);
	valid = strtok_r(NULL, ",", &saveptr);
	lat = strtok_r(NULL, ",", &saveptr);
	lon = strtok_r(NULL, ",", &saveptr);
	height = strtok_r(NULL, "\0", &saveptr);

	myloc->tstamp = atol(tstamp);
	myloc->valid = get_string_value(valid_names, valid);
	myloc->lat = atof(lat);
	myloc->lon = atof(lon);
	myloc->height = atof(height);
	talloc_free(tmp);

	lastloc = llist_entry(locations.next, struct location, list);

	/* Add location to the end of the list */
	llist_add(&myloc->list, &locations);

	ret = get_net_loc(cmd, data);

	if (!location_equal(myloc, lastloc))
		llist_for_each_entry(msc, &gsmnet->bsc_data->mscs, entry)
			osmo_bsc_send_trap(cmd, msc->msc_con);

	cleanup_locations();

	return ret;

oom:
	cmd->reply = "OOM";
	return CTRL_CMD_ERROR;
}

static int verify_net_loc(struct ctrl_cmd *cmd, const char *value, void *data)
{
	char *saveptr, *latstr, *lonstr, *heightstr, *tstampstr, *validstr, *tmp;
	time_t tstamp;
	int valid;
	double lat, lon, height;

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
	valid = get_string_value(valid_names, validstr);
	lat = atof(latstr);
	lon = atof(lonstr);
	height = atof(heightstr);
	talloc_free(tmp);

	if (((tstamp == 0) && (valid != LOC_FIX_INVALID)) || (lat < -90) || (lat > 90) ||
			(lon < -180) || (lon > 180) || (valid < 0)) {
		goto err;
	}

	return 0;
err:
		cmd->reply = talloc_strdup(cmd, "The format is <unixtime>,(invalid|fix2d|fix3d),<lat>,<lon>,<height>");
		return 1;
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

int bsc_ctrl_cmds_install()
{
	int rc;

	rc = ctrl_cmd_install(CTRL_NODE_NET, &cmd_net_loc);
	if (rc)
		goto end;
	rc = ctrl_cmd_install(CTRL_NODE_NET, &cmd_net_rf_lock);
	if (rc)
		goto end;
	rc = ctrl_cmd_install(CTRL_NODE_TRX, &cmd_trx_rf_lock);
end:
	return rc;
}
