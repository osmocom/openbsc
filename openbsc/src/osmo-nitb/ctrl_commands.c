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
CTRL_CMD_DEFINE_RANGE(bts_ms_max_power, "ms-max-power", struct gsm_bts,
		ms_max_power, 0, 40);

static int verify_bts_neighbor_mode(struct ctrl_cmd *cmd, const char *v, void *d)
{
	if (bts_neigh_mode_value(v) >= 0)
		return 0;
	cmd->reply = "Illegal neighbor mode";
	return -1;
}

static int get_bts_neighbor_mode(struct ctrl_cmd *cmd, void *data)
{
	struct gsm_bts *bts = cmd->node;
	cmd->reply = talloc_strdup(cmd, bts_neigh_mode_string(bts->neigh_list_manual_mode));
	return CTRL_CMD_REPLY;
}

static int set_bts_neighbor_mode(struct ctrl_cmd *cmd, void *data)
{
	struct gsm_bts *bts = cmd->node;
	enum neigh_list_manual_mode mode;

	mode = bts_neigh_mode_value(cmd->value);
	bts_set_neigh_mode(bts, mode);

	return get_bts_neighbor_mode(cmd, data);
}
CTRL_CMD_DEFINE(bts_neighbor_mode, "neighbor-mode");

static int set_bts_neighbor_add(struct ctrl_cmd *cmd, void *data)
{
	int arfcn;
	struct gsm_bts *bts = cmd->node;

	if (bts->neigh_list_manual_mode != NL_MODE_MANUAL) {
		cmd->reply = "neighbor-mode must be manual";
		return CTRL_CMD_ERROR;
	}

	arfcn = atoi(cmd->value);
	bitvec_set_bit_pos(&bts->si_common.neigh_list, arfcn, 1);
	cmd->reply = "Added";
	return CTRL_CMD_REPLY;
}

static int set_bts_neighbor_del(struct ctrl_cmd *cmd, void *data)
{
	int arfcn;
	struct gsm_bts *bts = cmd->node;

	if (bts->neigh_list_manual_mode != NL_MODE_MANUAL) {
		cmd->reply = "neighbor-mode must be manual";
		return CTRL_CMD_ERROR;
	}

	arfcn = atoi(cmd->value);
	bitvec_set_bit_pos(&bts->si_common.neigh_list, arfcn, 0);
	cmd->reply = "Removed";
	return CTRL_CMD_REPLY;
}

CTRL_HELPER_VERIFY_RANGE(bts_neighbor_add, 0, 1023);
CTRL_HELPER_VERIFY_RANGE(bts_neighbor_del, 0, 1023);
CTRL_CMD_RAW(bts_neighbor_add, "neighbor-add", NULL,
		set_bts_neighbor_add, verify_bts_neighbor_add);
CTRL_CMD_RAW(bts_neighbor_del, "neighbor-del", NULL,
		set_bts_neighbor_del, verify_bts_neighbor_del);

static int bts_t200_get(struct ctrl_cmd *cmd, void *data)
{
	struct gsm_bts *bts = cmd->node;

	cmd->reply = talloc_asprintf(cmd,
			"%u,%u,%u,%u,%u,%u,%u",
			bts->t200.sdcch,
			bts->t200.facch_fullrate,
			bts->t200.facch_halfrate,
			bts->t200.sacch_with_tch_sapi0,
			bts->t200.sacch_with_sdcch,
			bts->t200.sdcch_with_sapi3,
			bts->t200.sacch_with_tch_sapi3);

	if (!cmd->reply) {
		cmd->reply = "OOM";
		return CTRL_CMD_ERROR;
	}

	return CTRL_CMD_REPLY;
}

static int bts_t200_set(struct ctrl_cmd *cmd, void *data)
{
	char *saveptr, *tmp, *item;
	struct gsm_bts *bts = cmd->node;

	tmp = talloc_strdup(cmd, cmd->value);
	if (!tmp)
		goto out;

	item = strtok_r(tmp, ",", &saveptr);
	bts->t200.sdcch = atoi(item);

	item = strtok_r(NULL, ",", &saveptr);
	bts->t200.facch_fullrate = atoi(item);

	item = strtok_r(NULL, ",", &saveptr);
	bts->t200.facch_halfrate = atoi(item);

	item = strtok_r(NULL, ",", &saveptr);
	bts->t200.sacch_with_tch_sapi0 = atoi(item);

	item = strtok_r(NULL, ",", &saveptr);
	bts->t200.sacch_with_sdcch = atoi(item);

	item = strtok_r(NULL, ",", &saveptr);
	bts->t200.sdcch_with_sapi3 = atoi(item);

	item = strtok_r(NULL, "\0", &saveptr);
	bts->t200.sacch_with_tch_sapi3 = atoi(item);

	talloc_free(tmp);
out:
	return bts_t200_get(cmd, data);
}

static int bts_t200_verify(struct ctrl_cmd *cmd, const char *value, void *data)
{
	char *saveptr, *tmpstr, *tmp;

	tmp = talloc_strdup(cmd, value);
	if (!tmp)
		return 1;

#define CHECK(str) \
		if (!str || atoi(str) == 0) \
			goto error;

	tmpstr = strtok_r(tmp, ",", &saveptr);
	CHECK(tmpstr)
	tmpstr = strtok_r(NULL, ",", &saveptr);
	CHECK(tmpstr);
	tmpstr = strtok_r(NULL, ",", &saveptr);
	CHECK(tmpstr);
	tmpstr = strtok_r(NULL, ",", &saveptr);
	CHECK(tmpstr);
	tmpstr = strtok_r(NULL, ",", &saveptr);
	CHECK(tmpstr);
	tmpstr = strtok_r(NULL, ",", &saveptr);
	CHECK(tmpstr);
	tmpstr = strtok_r(NULL, "\0", &saveptr);
	CHECK(tmpstr);
#undef CHECK

	talloc_free(tmp);
	return 0;

error:
	cmd->reply = "Number of arguments are wrong. Range is 1-255.\n";
	talloc_free(tmp);
	return 1;
}

CTRL_CMD_RAW(bts_t200, "t200", bts_t200_get, bts_t200_set, bts_t200_verify);


/* TRX related commands below here */
CTRL_HELPER_GET_INT(trx_max_power, struct gsm_bts_trx, max_power_red);
CTRL_HELPER_SET_INT(trx_max_power, struct gsm_bts_trx, max_power_red);
static int verify_trx_max_power(struct ctrl_cmd *cmd, const char *value, void *_data)
{
	int tmp = atoi(value);

	if (tmp < 0 || tmp > 22) {
		cmd->reply = "Value must be between 0 and 22";
		return -1;
	}

	if (tmp & 1) {
		cmd->reply = "Value must be even";
		return -1;
	}

	return 0;
}
CTRL_CMD_DEFINE(trx_max_power, "bs-power-reduction");
CTRL_CMD_DEFINE_RANGE(trx_arfcn, "arfcn", struct gsm_bts_trx, arfcn, 0, 1023);



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
	rc |= ctrl_cmd_install(CTRL_NODE_BTS, &cmd_bts_ms_max_power);
	rc |= ctrl_cmd_install(CTRL_NODE_BTS, &cmd_bts_neighbor_mode);
	rc |= ctrl_cmd_install(CTRL_NODE_BTS, &cmd_bts_neighbor_add);
	rc |= ctrl_cmd_install(CTRL_NODE_BTS, &cmd_bts_neighbor_del);
	rc |= ctrl_cmd_install(CTRL_NODE_BTS, &cmd_bts_t200);

	rc |= ctrl_cmd_install(CTRL_NODE_TRX, &cmd_trx_max_power);
	rc |= ctrl_cmd_install(CTRL_NODE_TRX, &cmd_trx_arfcn);

	return rc;
}
