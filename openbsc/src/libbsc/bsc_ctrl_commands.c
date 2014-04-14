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
#include <openbsc/chan_alloc.h>
#include <openbsc/sms_queue.h>
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

#define PRINT_LCHAN_INT_INFO(name, element) \
cmd->reply = talloc_asprintf_append(cmd->reply, \
"lchan_status.bts.%u.trx.%u.ts.%u.lchan.%u."#name, \
lchan->ts->trx->bts->nr, lchan->ts->trx->nr, lchan->ts->nr, lchan->nr); \
if (sizeof(element) == sizeof(int)) \
	cmd->reply = talloc_asprintf_append(cmd->reply, ",%d\n", element); \
else \
	cmd->reply = talloc_asprintf_append(cmd->reply, ",%u\n", element);

#define PRINT_LCHAN_LLUINT_INFO(name, element) \
cmd->reply = talloc_asprintf_append(cmd->reply, \
"lchan_status.bts.%u.trx.%u.ts.%u.lchan.%u."#name, \
lchan->ts->trx->bts->nr, lchan->ts->trx->nr, lchan->ts->nr, lchan->nr); \
cmd->reply = talloc_asprintf_append(cmd->reply, ",%llu\n", element);

#define PRINT_LCHAN_STR_INFO(name, element) \
cmd->reply = talloc_asprintf_append(cmd->reply, \
"lchan_status.bts.%u.trx.%u.ts.%u.lchan.%u."#name, \
lchan->ts->trx->bts->nr, lchan->ts->trx->nr, lchan->ts->nr, lchan->nr); \
cmd->reply = talloc_asprintf_append(cmd->reply, ",%s\n", element);

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

CTRL_HELPER_VERIFY_STATUS(net_channels_load);
CTRL_HELPER_SET_STATUS(net_channels_load);

static int get_net_channels_load(struct ctrl_cmd *cmd, void *data)
{
	struct gsm_network *net = cmd->node;
	struct pchan_load pl;
	network_chan_load(&pl, net);
	struct pchan_load* pl_ptr = &pl;

	int i;

	if (!strcmp(cmd->variable,"channels-load"))
		cmd->reply = talloc_strdup(cmd, "\n");

	for (i = 0; i < ARRAY_SIZE(pl_ptr->pchan); i++) {
		const struct load_counter *lc = &pl_ptr->pchan[i];
		unsigned int percent;

		if (lc->total == 0)
			continue;

		percent = (lc->used * 100) / lc->total;
		cmd->reply = talloc_asprintf_append(cmd->reply,
			"channel_load.percent.%s,%u\n", gsm_pchan_name(i), percent);
		cmd->reply = talloc_asprintf_append(cmd->reply,
			"channel_load.lc_used.%s,%u\n", gsm_pchan_name(i), lc->used);
		cmd->reply = talloc_asprintf_append(cmd->reply,
			"channel_load.lc_total.%s,%u\n", gsm_pchan_name(i), lc->total);
	}

	if (!cmd->reply) {
		cmd->reply = "OOM";
		return CTRL_CMD_ERROR;
	}

	return CTRL_CMD_REPLY;
}

CTRL_CMD_DEFINE(net_channels_load, "channels-load");

static int print_lchan_trx_ts(struct ctrl_cmd *cmd, struct gsm_bts_trx_ts *ts)
{
	int lchan_nr;

	for (lchan_nr = 0; lchan_nr < TS_MAX_LCHAN; lchan_nr++) {

		struct gsm_lchan * lchan = &ts->lchan[lchan_nr];

		if ((lchan->type == GSM_LCHAN_NONE) &&
			(lchan->state == LCHAN_S_NONE))
			continue;

		PRINT_LCHAN_STR_INFO(type, gsm_lchant_name(lchan->type));
		PRINT_LCHAN_INT_INFO(conn, lchan->conn ? 1: 0);
		PRINT_LCHAN_STR_INFO(state, gsm_lchans_name(lchan->state));

		if (lchan->conn && lchan->conn->subscr) {
			struct gsm_subscriber *subscr = lchan->conn->subscr;
			PRINT_LCHAN_LLUINT_INFO(subscr_id, subscr->id);
			PRINT_LCHAN_INT_INFO(subscr_auth, subscr->authorized);
			if (strlen(subscr->name)) {
				PRINT_LCHAN_STR_INFO(subscr_name, subscr->name);
			}
			if (subscr->extension) {
				PRINT_LCHAN_STR_INFO(subscr_ext, subscr->extension);
			}
			PRINT_LCHAN_STR_INFO(subscr_imsi, subscr->imsi);
			if (subscr->tmsi != GSM_RESERVED_TMSI) {
				PRINT_LCHAN_INT_INFO(subscr_tmsi, subscr->tmsi);
			}
			PRINT_LCHAN_INT_INFO(subscr_use_count, subscr->use_count);
		}

		if (is_ipaccess_bts(lchan->ts->trx->bts)) {
			struct in_addr ia;
			ia.s_addr = htonl(lchan->abis_ip.bound_ip);
			PRINT_LCHAN_STR_INFO(bound_ip, inet_ntoa(ia));
			PRINT_LCHAN_INT_INFO(bound_port, lchan->abis_ip.bound_port);
			PRINT_LCHAN_INT_INFO(rtp_type2, lchan->abis_ip.rtp_payload2);
			PRINT_LCHAN_INT_INFO(conn_id, lchan->abis_ip.conn_id);
		}

		PRINT_LCHAN_INT_INFO(bs_power, lchan->ts->trx->nominal_power
				 - lchan->ts->trx->max_power_red- lchan->bs_power*2);
		PRINT_LCHAN_INT_INFO(ms_power,
						ms_pwr_dbm(lchan->ts->trx->bts->band,
						lchan->ms_power));

		/* we want to report the last measurement report */
		int idx = calc_initial_idx(ARRAY_SIZE(lchan->meas_rep),
									lchan->meas_rep_idx, 1);
		struct gsm_meas_rep *mr = &lchan->meas_rep[idx];

		if (mr->flags & MEAS_REP_F_MS_TO) {
			PRINT_LCHAN_INT_INFO(ms_timing_offset,
								mr->ms_timing_offset);
		}

		if (mr->flags & MEAS_REP_F_MS_L1) {
			PRINT_LCHAN_INT_INFO(l1_ms_power, mr->ms_l1.pwr);
			PRINT_LCHAN_INT_INFO(timing_advance, mr->ms_l1.ta);
		}

		struct gsm_meas_rep_unidir *mru_dl = &mr->dl;
		struct gsm_meas_rep_unidir *mru_ul = &mr->ul;
		if (mr->flags & MEAS_REP_F_DL_VALID) {
			PRINT_LCHAN_INT_INFO(rxl_full.dl, rxlev2dbm(mru_dl->full.rx_lev));
			PRINT_LCHAN_INT_INFO(rxl_sub.dl, rxlev2dbm(mru_dl->sub.rx_lev));
			PRINT_LCHAN_INT_INFO(rxq_full.dl, mru_dl->full.rx_qual);
			PRINT_LCHAN_INT_INFO(rxq_sub.dl, mru_dl->sub.rx_qual);
		}
		PRINT_LCHAN_INT_INFO(rxl_full.ul, rxlev2dbm(mru_ul->full.rx_lev));
		PRINT_LCHAN_INT_INFO(rxl_sub.ul, rxlev2dbm(mru_ul->sub.rx_lev));
		PRINT_LCHAN_INT_INFO(rxq_full.ul, mru_ul->full.rx_qual);
		PRINT_LCHAN_INT_INFO(rxq_sub.ul, mru_ul->sub.rx_qual);
	}

	return CMD_SUCCESS;
}

static int print_lchan_trx(struct ctrl_cmd *cmd, struct gsm_bts_trx *trx)
{
	int ts_nr;

	for (ts_nr = 0; ts_nr < TRX_NR_TS; ts_nr++) {
		struct gsm_bts_trx_ts *ts = &trx->ts[ts_nr];
		print_lchan_trx_ts(cmd, ts);
	}

	return CMD_SUCCESS;
}

static int print_lchan_bts(struct ctrl_cmd *cmd, struct gsm_bts *bts)
{
	int trx_nr;

	for (trx_nr = 0; trx_nr < bts->num_trx; trx_nr++) {
		struct gsm_bts_trx *trx = gsm_bts_trx_num(bts, trx_nr);
		print_lchan_trx(cmd, trx);
	}

	return CMD_SUCCESS;
}

CTRL_HELPER_VERIFY_STATUS(net_lchan);
CTRL_HELPER_SET_STATUS(net_lchan);

static int get_net_lchan(struct ctrl_cmd *cmd, void *data)
{
	struct gsm_network *net = cmd->node;
	int bts_nr;

	if (!strcmp(cmd->variable,"lchan"))
		cmd->reply = talloc_strdup(cmd, "\n");

	for (bts_nr = 0; bts_nr < net->num_bts; bts_nr++) {
		struct gsm_bts *bts = gsm_bts_num(net, bts_nr);
		print_lchan_bts(cmd, bts);
	}

	if (!cmd->reply) {
		cmd->reply = "OOM";
		return CTRL_CMD_ERROR;
	}

	return CTRL_CMD_REPLY;
}

CTRL_CMD_DEFINE(net_lchan, "lchan");

CTRL_HELPER_VERIFY_STATUS(net_paging);
CTRL_HELPER_SET_STATUS(net_paging);

static int get_net_paging(struct ctrl_cmd *cmd, void *data)
{
	struct gsm_network *net = cmd->node;
	struct gsm_bts *bts;
	int bts_nr;

	if (!strcmp(cmd->variable,"paging"))
		cmd->reply = talloc_strdup(cmd, "\n");

	for (bts_nr = 0; bts_nr < net->num_bts; bts_nr++) {
		bts = gsm_bts_num(net, bts_nr);
		cmd->reply = talloc_asprintf_append(cmd->reply,
			"paging.pending_requests.bts.%u,%u\n", bts_nr,
			paging_pending_requests_nr(bts));
		cmd->reply = talloc_asprintf_append(cmd->reply,
			"paging.available_slots.bts.%u,%u\n", bts_nr,
			bts->paging.available_slots);
	}

	if (!cmd->reply) {
		cmd->reply = "OOM";
		return CTRL_CMD_ERROR;
	}

	return CTRL_CMD_REPLY;
}

CTRL_CMD_DEFINE(net_paging, "paging");


CTRL_HELPER_VERIFY_STATUS(net_oml_link);
CTRL_HELPER_SET_STATUS(net_oml_link);

static int get_net_oml_link(struct ctrl_cmd *cmd, void *data)
{
	struct gsm_network *net = cmd->node;
	struct gsm_bts *bts;
	int bts_nr;

	if (!strcmp(cmd->variable,"oml_link"))
		cmd->reply = talloc_strdup(cmd, "\n");

	for (bts_nr = 0; bts_nr < net->num_bts; bts_nr++) {
		bts = gsm_bts_num(net, bts_nr);
		cmd->reply = talloc_asprintf_append(cmd->reply,
			"oml_link.bts.%u,%u\n", bts_nr, bts->oml_link ? 1 : 0);
	}

	if (!cmd->reply) {
		cmd->reply = "OOM";
		return CTRL_CMD_ERROR;
	}

	return CTRL_CMD_REPLY;
}

CTRL_CMD_DEFINE(net_oml_link, "oml_link");

CTRL_HELPER_VERIFY_STATUS(net_smsqueue);
CTRL_HELPER_SET_STATUS(net_smsqueue);

static int get_net_smsqueue(struct ctrl_cmd *cmd, void *data)
{
	struct gsm_network *net = cmd->node;

	if (!strcmp(cmd->variable,"smsqueue"))
		cmd->reply = talloc_strdup(cmd, "\n");

	sms_queue_pending_stat(net, cmd);

	if (!cmd->reply) {
		cmd->reply = "OOM";
		return CTRL_CMD_ERROR;
	}

	return CTRL_CMD_REPLY;
}

CTRL_CMD_DEFINE(net_smsqueue, "smsqueue");

static int print_counter(struct osmo_counter *counter, struct ctrl_cmd *cmd)
{
	cmd->reply = talloc_asprintf_append(cmd->reply, "%s,%lu\n", counter->name,
																counter->value);
	if (!cmd->reply) {
		cmd->reply = "OOM";
		return CTRL_CMD_ERROR;
	}
	return CTRL_CMD_REPLY;
}

CTRL_HELPER_VERIFY_STATUS(net_counters);
CTRL_HELPER_SET_STATUS(net_counters);

static int get_net_counters(struct ctrl_cmd *cmd, void *data)
{
	struct gsm_network *net = cmd->node;

	if (!strcmp(cmd->variable,"counters")) {
		cmd->reply = talloc_strdup(cmd, "\n");
		osmo_counters_for_each(print_counter, cmd);
	}

	if (!cmd->reply) {
		cmd->reply = "OOM";
		return CTRL_CMD_ERROR;
	}

	return CTRL_CMD_REPLY;
}

CTRL_CMD_DEFINE(net_counters, "counters");

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
	rc |= ctrl_cmd_install(CTRL_NODE_ROOT, &cmd_net_channels_load);
	rc |= ctrl_cmd_install(CTRL_NODE_ROOT, &cmd_net_lchan);
	rc |= ctrl_cmd_install(CTRL_NODE_ROOT, &cmd_net_paging);
	rc |= ctrl_cmd_install(CTRL_NODE_ROOT, &cmd_net_oml_link);
	rc |= ctrl_cmd_install(CTRL_NODE_ROOT, &cmd_net_smsqueue);
	rc |= ctrl_cmd_install(CTRL_NODE_ROOT, &cmd_net_counters);

	rc |= ctrl_cmd_install(CTRL_NODE_BTS, &cmd_bts_band);

	rc |= ctrl_cmd_install(CTRL_NODE_TRX, &cmd_trx_max_power);
	rc |= ctrl_cmd_install(CTRL_NODE_TRX, &cmd_trx_arfcn);
	return rc;
}
