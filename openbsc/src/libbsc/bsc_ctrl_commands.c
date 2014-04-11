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
#include <openbsc/abis_nm.h>
#include <openbsc/debug.h>

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

static int verify_net_auth_policy(struct ctrl_cmd *cmd, const char *value, void *data)
{

	if ((int)gsm_auth_policy_parse(value) < 0) {
		return -1;
	}

	return 0;
}

static int get_net_auth_policy(struct ctrl_cmd *cmd, void *data)
{
	struct gsm_network *net = cmd->node;
	cmd->reply = talloc_asprintf(cmd, "%s", gsm_auth_policy_name(net->auth_policy));
	if (!cmd->reply) {
		cmd->reply = "OOM";
		return CTRL_CMD_ERROR;
	}
	return CTRL_CMD_REPLY;
}

static int set_net_auth_policy(struct ctrl_cmd *cmd, void *data)
{
	struct gsm_network *net = cmd->node;
	net->auth_policy = gsm_auth_policy_parse(cmd->value);
	return get_net_auth_policy(cmd, data);
}

CTRL_CMD_DEFINE(net_auth_policy, "auth-policy");

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

static int verify_net_mcc_mnc_apply(struct ctrl_cmd *cmd, const char *value, void *d)
{
	char *tmp, *saveptr, *mcc, *mnc;

	tmp = talloc_strdup(cmd, value);
	if (!tmp)
		return 1;

	mcc = strtok_r(tmp, ",", &saveptr);
	mnc = strtok_r(NULL, ",", &saveptr);
	talloc_free(tmp);

	if (!mcc || !mnc)
		return 1;
	return 0;
}

static int get_net_mcc_mnc_apply(struct ctrl_cmd *cmd, void *data)
{
	cmd->reply = "Write only attribute";
	return CTRL_CMD_ERROR;
}

static int set_net_mcc_mnc_apply(struct ctrl_cmd *cmd, void *data)
{
	struct gsm_network *net = cmd->node;
	char *tmp, *saveptr, *mcc_str, *mnc_str;
	int mcc, mnc;

	tmp = talloc_strdup(cmd, cmd->value);
	if (!tmp)
		goto oom;


	mcc_str = strtok_r(tmp, ",", &saveptr);
	mnc_str = strtok_r(NULL, ",", &saveptr);

	mcc = atoi(mcc_str);
	mnc = atoi(mnc_str);

	talloc_free(tmp);

	if (net->network_code == mnc && net->country_code == mcc) {
		cmd->reply = "Nothing changed";
		return CTRL_CMD_REPLY;
	}

	net->network_code = mnc;
	net->country_code = mcc;

	return set_net_apply_config(cmd, data);

oom:
	cmd->reply = "OOM";
	return CTRL_CMD_ERROR;
}
CTRL_CMD_DEFINE(net_mcc_mnc_apply, "mcc-mnc-apply");

/* BTS related commands below here */
static int verify_bts_band(struct ctrl_cmd *cmd, const char *value, void *data)
{

	if ((int)gsm_band_parse(value) < 0) {
		return -1;
	}

	return 0;
}

static int get_bts_band(struct ctrl_cmd *cmd, void *data)
{
	struct gsm_bts *bts = cmd->node;
	cmd->reply = talloc_asprintf(cmd, "%s", gsm_band_name(bts->band));
	if (!cmd->reply) {
		cmd->reply = "OOM";
		return CTRL_CMD_ERROR;
	}
	return CTRL_CMD_REPLY;
}

static int set_bts_band(struct ctrl_cmd *cmd, void *data)
{
	struct gsm_bts *bts = cmd->node;
	bts->band = gsm_band_parse(cmd->value);
	return get_bts_band(cmd, data);
}

CTRL_CMD_DEFINE(bts_band, "band");

/* TRX related commands below here */
CTRL_HELPER_GET_INT(trx_max_power, struct gsm_bts_trx, max_power_red);
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

static int set_trx_max_power(struct ctrl_cmd *cmd, void *_data)
{
	struct gsm_bts_trx *trx = cmd->node;
	int old_power;

	/* remember the old value, set the new one */
	old_power = trx->max_power_red;
	trx->max_power_red = atoi(cmd->value);

	/* Maybe update the value */
	if (old_power != trx->max_power_red) {
		LOGP(DCTRL, LOGL_NOTICE,
			"%s updating max_pwr_red(%d)\n",
			gsm_trx_name(trx), trx->max_power_red);
		abis_nm_update_max_power_red(trx);
	}

	return get_trx_max_power(cmd, _data);
}
CTRL_CMD_DEFINE(trx_max_power, "max-power-reduction");
CTRL_CMD_DEFINE_RANGE(trx_arfcn, "arfcn", struct gsm_bts_trx, arfcn, 0, 1023);

int bsc_base_ctrl_cmds_install(void)
{
	int rc = 0;
	rc |= ctrl_cmd_install(CTRL_NODE_ROOT, &cmd_net_mnc);
	rc |= ctrl_cmd_install(CTRL_NODE_ROOT, &cmd_net_mcc);
	rc |= ctrl_cmd_install(CTRL_NODE_ROOT, &cmd_net_short_name);
	rc |= ctrl_cmd_install(CTRL_NODE_ROOT, &cmd_net_long_name);
	rc |= ctrl_cmd_install(CTRL_NODE_ROOT, &cmd_net_auth_policy);
	rc |= ctrl_cmd_install(CTRL_NODE_ROOT, &cmd_net_apply_config);
	rc |= ctrl_cmd_install(CTRL_NODE_ROOT, &cmd_net_mcc_mnc_apply);

	rc |= ctrl_cmd_install(CTRL_NODE_BTS, &cmd_bts_band);

	rc |= ctrl_cmd_install(CTRL_NODE_TRX, &cmd_trx_max_power);
	rc |= ctrl_cmd_install(CTRL_NODE_TRX, &cmd_trx_arfcn);
	return rc;
}
