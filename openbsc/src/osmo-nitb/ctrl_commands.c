/*
 * (C) 2013 by Holger Hans Peter Freyther
 * (C) 2013 by sysmocom s.f.m.c. GmbH
 *
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
#include <openbsc/ipaccess.h>
#include <openbsc/gsm_data.h>

#include <osmocom/vty/misc.h>

#define CTRL_CMD_VTY_STRING(cmdname, cmdstr, dtype, element) \
	CTRL_HELPER_GET_STRING(cmdname, dtype, element) \
	CTRL_HELPER_SET_STRING(cmdname, dtype, element) \
static struct ctrl_cmd_element cmd_##cmdname = { \
	.name = cmdstr, \
	.param = NULL, \
	.get = get_##cmdname, \
	.set = set_##cmdname, \
	.verify = verify_vty_description_string, \
}

CTRL_HELPER_VERIFY_RANGE(net_timer, 0, 65535);
#define CTRL_CMD_TIMER(timer) \
		CTRL_HELPER_GET_INT(net_timer_t##timer, struct gsm_network, T##timer); \
		CTRL_HELPER_SET_INT(net_timer_t##timer, struct gsm_network, T##timer); \
		CTRL_CMD_RAW(net_timer_t##timer, "t"#timer, \
			get_net_timer_t##timer, set_net_timer_t##timer, \
			verify_net_timer);

/**
 * Check that there are no newlines or comments or other things
 * that could make the VTY configuration unparsable.
 */
static int verify_vty_description_string(struct ctrl_cmd *cmd,
			const char *value, void *data)
{
	int i;
	const size_t len = strlen(value);

	for (i = 0; i < len; ++i) {
		switch(value[i]) {
		case '#':
		case '\n':
		case '\r':
			cmd->reply = "String includes illegal character";
			return -1;
		default:
			break;
		}
	}

	return 0;
}

CTRL_CMD_DEFINE_RANGE(net_mnc, "mnc", struct gsm_network, network_code, 0, 999);
CTRL_CMD_DEFINE_RANGE(net_mcc, "mcc", struct gsm_network, country_code, 1, 999);
CTRL_CMD_VTY_STRING(net_short_name, "short-name", struct gsm_network, name_short);
CTRL_CMD_VTY_STRING(net_long_name, "long-name", struct gsm_network, name_long);
CTRL_CMD_TIMER(3101);
CTRL_CMD_TIMER(3103);
CTRL_CMD_TIMER(3105);
CTRL_CMD_TIMER(3107);
CTRL_CMD_TIMER(3109);
CTRL_CMD_TIMER(3111);
CTRL_CMD_TIMER(3113);
CTRL_CMD_TIMER(3115);
CTRL_CMD_TIMER(3117);
CTRL_CMD_TIMER(3119);
CTRL_CMD_TIMER(3122);
CTRL_CMD_TIMER(3141);

static int verify_net_save_config(struct ctrl_cmd *cmd, const char *v, void *d)
{
	return 0;
}

static int set_net_save_config(struct ctrl_cmd *cmd, void *data)
{
	int rc = osmo_vty_save_config_file();
	cmd->reply = talloc_asprintf(cmd, "%d", rc);
	if (!cmd->reply) {
		cmd->reply = "OOM";
		return CTRL_CMD_ERROR;
	}

	return CTRL_CMD_REPLY;
}

static int get_net_save_config(struct ctrl_cmd *cmd, void *data)
{
	cmd->reply = "Write only attribute";
	return CTRL_CMD_ERROR;
}

CTRL_CMD_DEFINE(net_save_config, "save-configuration");

static int verify_net_apply_config(struct ctrl_cmd *cmd, const char *v, void *d)
{
	return 0;
}

static int get_net_apply_config(struct ctrl_cmd *cmd, void *data)
{
	cmd->reply = "Write only attribute";
	return CTRL_CMD_ERROR;
}

static int set_net_apply_config(struct ctrl_cmd *cmd, void *data)
{
	struct gsm_network *net = cmd->node;
	struct gsm_bts *bts;

	llist_for_each_entry(bts, &net->bts_list, list) {
		if (!is_ipaccess_bts(bts))
			continue;

		ipaccess_drop_oml(bts);
	}

	cmd->reply = "Tried to drop the BTS";
	return CTRL_CMD_REPLY;
}

CTRL_CMD_DEFINE(net_apply_config, "apply-configuration");

/* BTS related commands below here */
CTRL_CMD_VTY_STRING(bts_description, "description", struct gsm_bts, description);
CTRL_CMD_DEFINE_RANGE(bts_unit_id, "unit-id", struct gsm_bts,
		ip_access.site_id, 0, 65534);
CTRL_CMD_DEFINE_RANGE(bts_lac, "location-area-code", struct gsm_bts,
		location_area_code, 0, 65535);
CTRL_CMD_DEFINE_RANGE(bts_ci, "cell-identity", struct gsm_bts,
		cell_identity, 0, 65535);


int bsc_ctrl_cmds_install(void)
{
	int rc = 0;
	rc |= ctrl_cmd_install(CTRL_NODE_ROOT, &cmd_net_mnc);
	rc |= ctrl_cmd_install(CTRL_NODE_ROOT, &cmd_net_mcc);
	rc |= ctrl_cmd_install(CTRL_NODE_ROOT, &cmd_net_short_name);
	rc |= ctrl_cmd_install(CTRL_NODE_ROOT, &cmd_net_long_name);
	rc |= ctrl_cmd_install(CTRL_NODE_ROOT, &cmd_net_apply_config);
	rc |= ctrl_cmd_install(CTRL_NODE_ROOT, &cmd_net_save_config);
	rc |= ctrl_cmd_install(CTRL_NODE_ROOT, &cmd_net_timer_t3101);
	rc |= ctrl_cmd_install(CTRL_NODE_ROOT, &cmd_net_timer_t3103);
	rc |= ctrl_cmd_install(CTRL_NODE_ROOT, &cmd_net_timer_t3105);
	rc |= ctrl_cmd_install(CTRL_NODE_ROOT, &cmd_net_timer_t3107);
	rc |= ctrl_cmd_install(CTRL_NODE_ROOT, &cmd_net_timer_t3109);
	rc |= ctrl_cmd_install(CTRL_NODE_ROOT, &cmd_net_timer_t3111);
	rc |= ctrl_cmd_install(CTRL_NODE_ROOT, &cmd_net_timer_t3113);
	rc |= ctrl_cmd_install(CTRL_NODE_ROOT, &cmd_net_timer_t3115);
	rc |= ctrl_cmd_install(CTRL_NODE_ROOT, &cmd_net_timer_t3117);
	rc |= ctrl_cmd_install(CTRL_NODE_ROOT, &cmd_net_timer_t3119);
	rc |= ctrl_cmd_install(CTRL_NODE_ROOT, &cmd_net_timer_t3122);
	rc |= ctrl_cmd_install(CTRL_NODE_ROOT, &cmd_net_timer_t3141);

	rc |= ctrl_cmd_install(CTRL_NODE_BTS, &cmd_bts_description);
	rc |= ctrl_cmd_install(CTRL_NODE_BTS, &cmd_bts_unit_id);
	rc |= ctrl_cmd_install(CTRL_NODE_BTS, &cmd_bts_lac);
	rc |= ctrl_cmd_install(CTRL_NODE_BTS, &cmd_bts_ci);

	return rc;
}
