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

static const struct value_string valid_names[] = {
	{ BTS_LOC_FIX_INVALID,	"invalid" },
	{ BTS_LOC_FIX_2D,	"fix2d" },
	{ BTS_LOC_FIX_3D,	"fix3d" },
	{ 0, NULL }
};

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
			get_value_string(valid_names, curloc->valid), curloc->lat, curloc->lon, curloc->height);
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
	curloc->valid = get_string_value(valid_names, valid);
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
			osmo_bsc_send_trap(cmd, msc->msc_con);

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

	if (((tstamp == 0) && (valid != BTS_LOC_FIX_INVALID)) || (lat < -90) || (lat > 90) ||
			(lon < -180) || (lon > 180) || (valid < 0)) {
		goto err;
	}

	return 0;
err:
		cmd->reply = talloc_strdup(cmd, "The format is <unixtime>,(invalid|fix2d|fix3d),<lat>,<lon>,<height>");
		return 1;
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

	rc = ctrl_cmd_install(CTRL_NODE_BTS, &cmd_bts_loc);
	if (rc)
		goto end;
	rc = ctrl_cmd_install(CTRL_NODE_NET, &cmd_net_rf_lock);
end:
	return rc;
}
