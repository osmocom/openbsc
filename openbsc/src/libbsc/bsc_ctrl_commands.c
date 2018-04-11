/*
 * (C) 2013-2015 by Holger Hans Peter Freyther
 * (C) 2013-2015 by sysmocom s.f.m.c. GmbH
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
#include <errno.h>
#include <time.h>

#include <osmocom/ctrl/control_cmd.h>
#include <osmocom/gsm/gsm48.h>
#include <openbsc/ipaccess.h>
#include <openbsc/gsm_data.h>
#include <openbsc/abis_nm.h>
#include <openbsc/debug.h>
#include <openbsc/chan_alloc.h>
#include <openbsc/osmo_bsc_rf.h>
#include <openbsc/bsc_msc_data.h>

#define CTRL_CMD_VTY_STRING(cmdname, cmdstr, dtype, element) \
	CTRL_HELPER_GET_STRING(cmdname, dtype, element) \
	CTRL_HELPER_SET_STRING(cmdname, dtype, element) \
static struct ctrl_cmd_element cmd_##cmdname = { \
	.name = cmdstr, \
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

CTRL_CMD_DEFINE(net_mcc, "mcc");
static int get_net_mcc(struct ctrl_cmd *cmd, void *_data)
{
       struct gsm_network *net = cmd->node;
       cmd->reply = talloc_asprintf(cmd, "%s", osmo_mcc_name(net->plmn.mcc));
       if (!cmd->reply) {
               cmd->reply = "OOM";
               return CTRL_CMD_ERROR;
       }
       return CTRL_CMD_REPLY;
}
static int set_net_mcc(struct ctrl_cmd *cmd, void *_data)
{
       struct gsm_network *net = cmd->node;
       uint16_t mcc;
       if (osmo_mcc_from_str(cmd->value, &mcc))
               return -1;
       net->plmn.mcc = mcc;
       return get_net_mcc(cmd, _data);
}
static int verify_net_mcc(struct ctrl_cmd *cmd, const char *value, void *_data)
{
       if (osmo_mcc_from_str(value, NULL))
               return -1;
       return 0;
}

CTRL_CMD_DEFINE(net_mnc, "mnc");
static int get_net_mnc(struct ctrl_cmd *cmd, void *_data)
{
       struct gsm_network *net = cmd->node;
       cmd->reply = talloc_asprintf(cmd, "%s", osmo_mnc_name(net->plmn.mnc, net->plmn.mnc_3_digits));
       if (!cmd->reply) {
               cmd->reply = "OOM";
               return CTRL_CMD_ERROR;
       }
       return CTRL_CMD_REPLY;
}
static int set_net_mnc(struct ctrl_cmd *cmd, void *_data)
{
       struct gsm_network *net = cmd->node;
       struct osmo_plmn_id plmn = net->plmn;
       if (osmo_mnc_from_str(cmd->value, &plmn.mnc, &plmn.mnc_3_digits)) {
               cmd->reply = "Error while decoding MNC";
               return CTRL_CMD_ERROR;
       }
       net->plmn = plmn;
       return get_net_mnc(cmd, _data);
}
static int verify_net_mnc(struct ctrl_cmd *cmd, const char *value, void *_data)
{
       if (osmo_mnc_from_str(value, NULL, NULL))
               return -1;
       return 0;
}

CTRL_CMD_VTY_STRING(net_short_name, "short-name", struct gsm_network, name_short);
CTRL_CMD_VTY_STRING(net_long_name, "long-name", struct gsm_network, name_long);

static int set_net_apply_config(struct ctrl_cmd *cmd, void *data)
{
	struct gsm_network *net = cmd->node;
	struct gsm_bts *bts;

	llist_for_each_entry(bts, &net->bts_list, list) {
		if (!is_ipaccess_bts(bts))
			continue;

		/*
		 * The ip.access nanoBTS seems to be unrelaible on BSSGP
		 * so let's us just reboot it. For the sysmoBTS we can just
		 * restart the process as all state is gone.
		 */
		if (!is_sysmobts_v2(bts) && strcmp(cmd->value, "restart") == 0) {
			struct gsm_bts_trx *trx;
			llist_for_each_entry_reverse(trx, &bts->trx_list, list)
				abis_nm_ipaccess_restart(trx);
		} else
			ipaccess_drop_oml(bts);
	}

	cmd->reply = "Tried to drop the BTS";
	return CTRL_CMD_REPLY;
}

CTRL_CMD_DEFINE_WO_NOVRF(net_apply_config, "apply-configuration");

static int verify_net_mcc_mnc_apply(struct ctrl_cmd *cmd, const char *value, void *d)
{
	char *tmp, *saveptr, *mcc, *mnc;
	int rc = 0;

	tmp = talloc_strdup(cmd, value);
	if (!tmp)
		return 1;

	mcc = strtok_r(tmp, ",", &saveptr);
	mnc = strtok_r(NULL, ",", &saveptr);

	if (osmo_mcc_from_str(mcc, NULL) || osmo_mnc_from_str(mnc, NULL, NULL))
		rc = -1;

	talloc_free(tmp);
	return rc;
}

static int set_net_mcc_mnc_apply(struct ctrl_cmd *cmd, void *data)
{
	struct gsm_network *net = cmd->node;
	char *tmp, *saveptr, *mcc_str, *mnc_str;
	struct osmo_plmn_id plmn;

	tmp = talloc_strdup(cmd, cmd->value);
	if (!tmp)
		goto oom;

	mcc_str = strtok_r(tmp, ",", &saveptr);
	mnc_str = strtok_r(NULL, ",", &saveptr);

	if (osmo_mcc_from_str(mcc_str, &plmn.mcc)) {
		cmd->reply = "Error while decoding MCC";
		talloc_free(tmp);
		return CTRL_CMD_ERROR;
	}

	if (osmo_mnc_from_str(mnc_str, &plmn.mnc, &plmn.mnc_3_digits)) {
		cmd->reply = "Error while decoding MNC";
		talloc_free(tmp);
		return CTRL_CMD_ERROR;
	}

	talloc_free(tmp);

	if (!osmo_plmn_cmp(&net->plmn, &plmn)) {
		cmd->reply = "Nothing changed";
		return CTRL_CMD_REPLY;
	}

	net->plmn = plmn;

	return set_net_apply_config(cmd, data);

oom:
	cmd->reply = "OOM";
	return CTRL_CMD_ERROR;
}
CTRL_CMD_DEFINE_WO(net_mcc_mnc_apply, "mcc-mnc-apply");

/* BTS related commands below */
CTRL_CMD_DEFINE_RANGE(bts_lac, "location-area-code", struct gsm_bts, location_area_code, 0, 65535);
CTRL_CMD_DEFINE_RANGE(bts_ci, "cell-identity", struct gsm_bts, cell_identity, 0, 65535);

static int set_bts_apply_config(struct ctrl_cmd *cmd, void *data)
{
	struct gsm_bts *bts = cmd->node;

	if (!is_ipaccess_bts(bts)) {
		cmd->reply = "BTS is not IP based";
		return CTRL_CMD_ERROR;
	}

	ipaccess_drop_oml(bts);
	cmd->reply = "Tried to drop the BTS";
	return CTRL_CMD_REPLY;
}

CTRL_CMD_DEFINE_WO_NOVRF(bts_apply_config, "apply-configuration");

static int set_bts_si(struct ctrl_cmd *cmd, void *data)
{
	struct gsm_bts *bts = cmd->node;
	int rc;

	rc = gsm_bts_set_system_infos(bts);
	if (rc != 0) {
		cmd->reply = "Failed to generate SI";
		return CTRL_CMD_ERROR;
	}

	cmd->reply = "Generated new System Information";
	return CTRL_CMD_REPLY;
}
CTRL_CMD_DEFINE_WO_NOVRF(bts_si, "send-new-system-informations");

static int get_bts_chan_load(struct ctrl_cmd *cmd, void *data)
{
	int i;
	struct pchan_load pl;
	struct gsm_bts *bts;
	const char *space = "";

	bts = cmd->node;
	memset(&pl, 0, sizeof(pl));
	bts_chan_load(&pl, bts);

	cmd->reply = talloc_strdup(cmd, "");

	for (i = 0; i < ARRAY_SIZE(pl.pchan); ++i) {
		const struct load_counter *lc = &pl.pchan[i];

		/* These can never have user load */
		if (i == GSM_PCHAN_NONE)
			continue;
		if (i == GSM_PCHAN_CCCH)
			continue;
		if (i == GSM_PCHAN_PDCH)
			continue;
		if (i == GSM_PCHAN_UNKNOWN)
			continue;

		cmd->reply = talloc_asprintf_append(cmd->reply,
					"%s%s,%u,%u",
					space, gsm_pchan_name(i), lc->used, lc->total);
		if (!cmd->reply)
			goto error;
		space = " ";
	}

	return CTRL_CMD_REPLY;

error:
	cmd->reply = "Memory allocation failure";
	return CTRL_CMD_ERROR;
}

CTRL_CMD_DEFINE_RO(bts_chan_load, "channel-load");

static int get_bts_oml_conn(struct ctrl_cmd *cmd, void *data)
{
	struct gsm_bts *bts = cmd->node;

	cmd->reply = bts->oml_link ? "connected" : "disconnected";
	return CTRL_CMD_REPLY;
}

CTRL_CMD_DEFINE_RO(bts_oml_conn, "oml-connection-state");

static int verify_bts_gprs_mode(struct ctrl_cmd *cmd, const char *value, void *_data)
{
	int valid;
	enum bts_gprs_mode mode;
	struct gsm_bts *bts = cmd->node;

	mode = bts_gprs_mode_parse(value, &valid);
	if (!valid) {
		cmd->reply = "Mode is not known";
		return 1;
	}

	if (!bts_gprs_mode_is_compat(bts, mode)) {
		cmd->reply = "bts does not support this mode";
		return 1;
	}

	return 0;
}

static int get_bts_gprs_mode(struct ctrl_cmd *cmd, void *data)
{
	struct gsm_bts *bts = cmd->node;

	cmd->reply = talloc_strdup(cmd, bts_gprs_mode_name(bts->gprs.mode));
	return CTRL_CMD_REPLY;
}

static int set_bts_gprs_mode(struct ctrl_cmd *cmd, void *data)
{
	struct gsm_bts *bts = cmd->node;

	bts->gprs.mode = bts_gprs_mode_parse(cmd->value, NULL);
	return get_bts_gprs_mode(cmd, data);
}

CTRL_CMD_DEFINE(bts_gprs_mode, "gprs-mode");

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
CTRL_CMD_DEFINE_RO(bts_rf_state, "rf_state");

static int get_net_rf_lock(struct ctrl_cmd *cmd, void *data)
{
	struct gsm_network *net = cmd->node;
	struct gsm_bts *bts;
	const char *policy_name;

	policy_name = osmo_bsc_rf_get_policy_name(net->bsc_data->rf_ctrl->policy);

	llist_for_each_entry(bts, &net->bts_list, list) {
		struct gsm_bts_trx *trx;

		/* Exclude the BTS from the global lock */
		if (bts->excl_from_rf_lock)
			continue;

		llist_for_each_entry(trx, &bts->trx_list, list) {
			if (trx->mo.nm_state.availability == NM_AVSTATE_OK &&
			    trx->mo.nm_state.operational != NM_OPSTATE_DISABLED) {
				cmd->reply = talloc_asprintf(cmd,
						"state=on,policy=%s,bts=%u,trx=%u",
						policy_name, bts->nr, trx->nr);
				return CTRL_CMD_REPLY;
			}
		}
	}

	cmd->reply = talloc_asprintf(cmd, "state=off,policy=%s",
			policy_name);
	return CTRL_CMD_REPLY;
}

#define TIME_FORMAT_RFC2822 "%a, %d %b %Y %T %z"

static int set_net_rf_lock(struct ctrl_cmd *cmd, void *data)
{
	int locked = atoi(cmd->value);
	struct gsm_network *net = cmd->node;
	time_t now = time(NULL);
	char now_buf[64];
	struct osmo_bsc_rf *rf;

	if (!net) {
		cmd->reply = "net not found.";
		return CTRL_CMD_ERROR;
	}

	rf = net->bsc_data->rf_ctrl;

	if (!rf) {
		cmd->reply = "RF Ctrl is not enabled in the BSC Configuration";
		return CTRL_CMD_ERROR;
	}

	talloc_free(rf->last_rf_lock_ctrl_command);
	strftime(now_buf, sizeof(now_buf), TIME_FORMAT_RFC2822, gmtime(&now));
	rf->last_rf_lock_ctrl_command =
		talloc_asprintf(rf, "rf_locked %u (%s)", locked, now_buf);

	osmo_bsc_rf_schedule_lock(rf, locked == 1 ? '0' : '1');

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
CTRL_CMD_DEFINE(net_rf_lock, "rf_locked");

static int get_net_bts_num(struct ctrl_cmd *cmd, void *data)
{
	struct gsm_network *net = cmd->node;

	cmd->reply = talloc_asprintf(cmd, "%u", net->num_bts);
	return CTRL_CMD_REPLY;
}
CTRL_CMD_DEFINE_RO(net_bts_num, "number-of-bts");

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
CTRL_CMD_DEFINE_RANGE(trx_arfcn, "arfcn", struct gsm_bts_trx, arfcn, 0, 1023);

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

int bsc_base_ctrl_cmds_install(void)
{
	int rc = 0;
	rc |= ctrl_cmd_install(CTRL_NODE_ROOT, &cmd_net_mnc);
	rc |= ctrl_cmd_install(CTRL_NODE_ROOT, &cmd_net_mcc);
	rc |= ctrl_cmd_install(CTRL_NODE_ROOT, &cmd_net_short_name);
	rc |= ctrl_cmd_install(CTRL_NODE_ROOT, &cmd_net_long_name);
	rc |= ctrl_cmd_install(CTRL_NODE_ROOT, &cmd_net_apply_config);
	rc |= ctrl_cmd_install(CTRL_NODE_ROOT, &cmd_net_mcc_mnc_apply);
	rc |= ctrl_cmd_install(CTRL_NODE_ROOT, &cmd_net_rf_lock);
	rc |= ctrl_cmd_install(CTRL_NODE_ROOT, &cmd_net_bts_num);

	rc |= ctrl_cmd_install(CTRL_NODE_BTS, &cmd_bts_lac);
	rc |= ctrl_cmd_install(CTRL_NODE_BTS, &cmd_bts_ci);
	rc |= ctrl_cmd_install(CTRL_NODE_BTS, &cmd_bts_apply_config);
	rc |= ctrl_cmd_install(CTRL_NODE_BTS, &cmd_bts_si);
	rc |= ctrl_cmd_install(CTRL_NODE_BTS, &cmd_bts_chan_load);
	rc |= ctrl_cmd_install(CTRL_NODE_BTS, &cmd_bts_oml_conn);
	rc |= ctrl_cmd_install(CTRL_NODE_BTS, &cmd_bts_gprs_mode);
	rc |= ctrl_cmd_install(CTRL_NODE_BTS, &cmd_bts_rf_state);

	rc |= ctrl_cmd_install(CTRL_NODE_TRX, &cmd_trx_max_power);
	rc |= ctrl_cmd_install(CTRL_NODE_TRX, &cmd_trx_arfcn);

	return rc;
}
