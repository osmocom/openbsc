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
#include <time.h>
#include <arpa/inet.h>
#include <openbsc/paging.h>
#include <openbsc/control_cmd.h>
#include <openbsc/ipaccess.h>
#include <openbsc/gsm_data.h>
#include <openbsc/chan_alloc.h>
#include <openbsc/sms_queue.h>
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

#define CTRL_CMD_VTY_COUNTER(cmdname, cmdstr, dtype, element) \
	CTRL_HELPER_GET_COUNTER(cmdname, dtype, element) \
	CTRL_HELPER_SET_COUNTER(cmdname, dtype, element) \
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

CTRL_HELPER_VERIFY_STATUS(net_lchan);
CTRL_HELPER_SET_STATUS(net_lchan);

static int get_net_lchan(struct ctrl_cmd *cmd, void *data)
{
	struct gsm_network *net = cmd->node;
	struct gsm_bts *bts;
	struct gsm_bts_trx *trx;
	struct gsm_bts_trx_ts *ts;
	struct gsm_lchan *lchan;
	struct gsm_subscriber *subscr;
	struct gsm_meas_rep *mr;
	struct gsm_meas_rep_unidir *mru_dl;
	struct gsm_meas_rep_unidir *mru_ul;
	int bts_nr, trx_nr, ts_nr, lchan_nr, idx;

	if (!strcmp(cmd->variable,"lchan"))
		cmd->reply = talloc_strdup(cmd, "\n");

	for (bts_nr = 0; bts_nr < net->num_bts; bts_nr++) {

		bts = gsm_bts_num(net, bts_nr);

		for (trx_nr = 0; trx_nr < bts->num_trx; trx_nr++) {

			trx = gsm_bts_trx_num(bts, trx_nr);

			for (ts_nr = 0; ts_nr < TRX_NR_TS; ts_nr++) {

				ts = &trx->ts[ts_nr];

				for (lchan_nr = 0; lchan_nr < TS_MAX_LCHAN; lchan_nr++) {

					lchan = &ts->lchan[lchan_nr];

					if ((lchan->type == GSM_LCHAN_NONE) &&
							(lchan->state == LCHAN_S_NONE))
						continue;

					PRINT_LCHAN_STR_INFO(type, gsm_lchant_name(lchan->type));
					PRINT_LCHAN_INT_INFO(conn, lchan->conn ? 1: 0);
					PRINT_LCHAN_STR_INFO(state, gsm_lchans_name(lchan->state));

					if (lchan->conn && lchan->conn->subscr) {
						subscr = lchan->conn->subscr;
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
					idx = calc_initial_idx(ARRAY_SIZE(lchan->meas_rep),
							lchan->meas_rep_idx, 1);
					mr = &lchan->meas_rep[idx];

					if (mr->flags & MEAS_REP_F_MS_TO) {
						PRINT_LCHAN_INT_INFO(ms_timing_offset,
								mr->ms_timing_offset);
					}

					if (mr->flags & MEAS_REP_F_MS_L1) {
						PRINT_LCHAN_INT_INFO(l1_ms_power, mr->ms_l1.pwr);
						PRINT_LCHAN_INT_INFO(timing_advance, mr->ms_l1.ta);
					}

					mru_dl = &mr->dl;
					mru_ul = &mr->ul;
					if (mr->flags & MEAS_REP_F_DL_VALID) {
						PRINT_LCHAN_INT_INFO(rxl_full.dl,
							rxlev2dbm(mru_dl->full.rx_lev));
						PRINT_LCHAN_INT_INFO(rxl_sub.dl,
							rxlev2dbm(mru_dl->sub.rx_lev));
						PRINT_LCHAN_INT_INFO(rxq_full.dl, mru_dl->full.rx_qual);
						PRINT_LCHAN_INT_INFO(rxq_sub.dl, mru_dl->sub.rx_qual);
					}
					PRINT_LCHAN_INT_INFO(rxl_full.ul,
						rxlev2dbm(mru_ul->full.rx_lev));
					PRINT_LCHAN_INT_INFO(rxl_sub.ul,
						rxlev2dbm(mru_ul->sub.rx_lev));
					PRINT_LCHAN_INT_INFO(rxq_full.ul, mru_ul->full.rx_qual);
					PRINT_LCHAN_INT_INFO(rxq_sub.ul, mru_ul->sub.rx_qual);
				}
			}
		}
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

/* Network related counters */
CTRL_CMD_VTY_COUNTER(net_chreq_total, "chreq.total",
		struct gsm_network, stats.chreq.total);
CTRL_CMD_VTY_COUNTER(net_chreq_no_channel, "chreq.no_channel",
		struct gsm_network, stats.chreq.no_channel);
CTRL_CMD_VTY_COUNTER(net_chan_rf_fail, "chan.rf_fail",
		struct gsm_network, stats.chan.rf_fail);
CTRL_CMD_VTY_COUNTER(net_chan_rll_err, "chan.rll_err",
		struct gsm_network, stats.chan.rll_err);
CTRL_CMD_VTY_COUNTER(net_paging_attempted, "paging.attempted",
		struct gsm_network, stats.paging.attempted);
CTRL_CMD_VTY_COUNTER(net_paging_detached, "paging.detached",
		struct gsm_network, stats.paging.detached);
CTRL_CMD_VTY_COUNTER(net_paging_completed, "paging.completed",
		struct gsm_network, stats.paging.completed);
CTRL_CMD_VTY_COUNTER(net_paging_expired, "paging.expired",
		struct gsm_network, stats.paging.expired);
CTRL_CMD_VTY_COUNTER(net_bts_oml_fail, "bts.oml_fail",
		struct gsm_network, stats.bts.oml_fail);
CTRL_CMD_VTY_COUNTER(net_bts_rsl_fail, "bts.rsl_fail",
		struct gsm_network, stats.bts.rsl_fail);
CTRL_CMD_VTY_COUNTER(net_loc_upd_type_attach, "loc_upd_type.attach",
		struct gsm_network, stats.loc_upd_type.attach);
CTRL_CMD_VTY_COUNTER(net_loc_upd_type_normal, "loc_upd_type.normal",
		struct gsm_network, stats.loc_upd_type.normal);
CTRL_CMD_VTY_COUNTER(net_loc_upd_type_periodic, "loc_upd_type.periodic",
		struct gsm_network, stats.loc_upd_type.periodic);
CTRL_CMD_VTY_COUNTER(net_loc_upd_type_detach, "loc_upd_type.detach",
		struct gsm_network, stats.loc_upd_type.detach);
CTRL_CMD_VTY_COUNTER(net_loc_upd_type_accept, "loc_upd_type.accept",
		struct gsm_network, stats.loc_upd_resp.accept);
CTRL_CMD_VTY_COUNTER(net_loc_upd_type_reject, "loc_upd_type.reject",
		struct gsm_network, stats.loc_upd_resp.reject);
CTRL_CMD_VTY_COUNTER(net_handover_attempted, "handover.attempted",
		struct gsm_network, stats.handover.attempted);
CTRL_CMD_VTY_COUNTER(net_handover_no_channel, "handover.no_channel",
		struct gsm_network, stats.handover.no_channel);
CTRL_CMD_VTY_COUNTER(net_handover_timeout, "handover.timeout",
		struct gsm_network, stats.handover.timeout);
CTRL_CMD_VTY_COUNTER(net_handover_completed, "handover.completed",
		struct gsm_network, stats.handover.completed);
CTRL_CMD_VTY_COUNTER(net_handover_failed, "handover.failed",
		struct gsm_network, stats.handover.failed);
CTRL_CMD_VTY_COUNTER(net_sms_submitted, "sms.submitted",
		struct gsm_network, stats.sms.submitted);
CTRL_CMD_VTY_COUNTER(net_sms_no_receiver, "sms.no_receiver",
		struct gsm_network, stats.sms.no_receiver);
CTRL_CMD_VTY_COUNTER(net_sms_delivered, "sms.delivered",
		struct gsm_network, stats.sms.delivered);
CTRL_CMD_VTY_COUNTER(net_sms_rp_err_mem, "sms.rp_err_mem",
		struct gsm_network, stats.sms.rp_err_mem);
CTRL_CMD_VTY_COUNTER(net_sms_rp_err_other,"sms.rp_err_other",
		struct gsm_network, stats.sms.rp_err_other);
CTRL_CMD_VTY_COUNTER(net_call_mo_setup, "call.mo_setup",
		struct gsm_network, stats.call.mo_setup);
CTRL_CMD_VTY_COUNTER(net_call_mo_connect_ack, "call.mo_connect_ack",
		struct gsm_network, stats.call.mo_connect_ack);
CTRL_CMD_VTY_COUNTER(net_call_mt_setup, "call.mt_setup",
		struct gsm_network, stats.call.mt_setup);
CTRL_CMD_VTY_COUNTER(net_call_mt_connect, "call.mt_connect",
		struct gsm_network, stats.call.mt_connect);

CTRL_HELPER_VERIFY_STATUS(net_status);
CTRL_HELPER_SET_STATUS(net_status);

static int get_net_status(struct ctrl_cmd *cmd, void *data)
{
	struct gsm_network *net = cmd->node;
	cmd->reply = talloc_strdup(cmd, "\n");
	cmd->reply = talloc_asprintf_append(cmd->reply,"time,%u",
		(unsigned)time(NULL));
	cmd->reply = talloc_strdup_append(cmd->reply, "\nchreq.total,");
	get_net_chreq_total(cmd, net);
	cmd->reply = talloc_strdup_append(cmd->reply, "\nchreq.no_channel,");
	get_net_chreq_no_channel(cmd, net);
	cmd->reply = talloc_strdup_append(cmd->reply, "\nchan.rf_fail,");
	get_net_chan_rf_fail(cmd, net);
	cmd->reply = talloc_strdup_append(cmd->reply, "\nchan.rll_err,");
	get_net_chan_rll_err(cmd, net);
	cmd->reply = talloc_strdup_append(cmd->reply, "\npaging.attempted,");
	get_net_paging_attempted(cmd, net);
	cmd->reply = talloc_strdup_append(cmd->reply, "\npaging.completed,");
	get_net_paging_completed(cmd, net);
	cmd->reply = talloc_strdup_append(cmd->reply, "\npaging.expired,");
	get_net_paging_expired(cmd, net);
	cmd->reply = talloc_strdup_append(cmd->reply, "\nbts.oml_fail,");
	get_net_bts_oml_fail(cmd, net);
	cmd->reply = talloc_strdup_append(cmd->reply, "\nbts.rsl_fail,");
	get_net_bts_rsl_fail(cmd, net);
	cmd->reply = talloc_strdup_append(cmd->reply, "\nloc_upd_type.attach,");
	get_net_loc_upd_type_attach(cmd, net);
	cmd->reply = talloc_strdup_append(cmd->reply, "\nloc_upd_type.normal,");
	get_net_loc_upd_type_normal(cmd, net);
	cmd->reply = talloc_strdup_append(cmd->reply, "\nloc_upd_type.periodic,");
	get_net_loc_upd_type_periodic(cmd, net);
	cmd->reply = talloc_strdup_append(cmd->reply, "\nloc_upd_type.detach,");
	get_net_loc_upd_type_detach(cmd, net);
	cmd->reply = talloc_strdup_append(cmd->reply, "\nloc_upd_type.accept,");
	get_net_loc_upd_type_accept(cmd, net);
	cmd->reply = talloc_strdup_append(cmd->reply, "\nloc_upd_type.reject,");
	get_net_loc_upd_type_reject(cmd, net);
	cmd->reply = talloc_strdup_append(cmd->reply, "\nhandover.attempted,");
	get_net_handover_attempted(cmd, net);
	cmd->reply = talloc_strdup_append(cmd->reply, "\nhandover.no_channel,");
	get_net_handover_no_channel(cmd, net);
	cmd->reply = talloc_strdup_append(cmd->reply, "\nhandover.timeout,");
	get_net_handover_timeout(cmd, net);
	cmd->reply = talloc_strdup_append(cmd->reply, "\nhandover.completed,");
	get_net_handover_completed(cmd, net);
	cmd->reply = talloc_strdup_append(cmd->reply, "\nhandover.failed,");
	get_net_handover_failed(cmd, net);
	cmd->reply = talloc_strdup_append(cmd->reply, "\nsms.submitted,");
	get_net_sms_submitted(cmd, net);
	cmd->reply = talloc_strdup_append(cmd->reply, "\nsms.no_receiver,");
	get_net_sms_no_receiver(cmd, net);
	cmd->reply = talloc_strdup_append(cmd->reply, "\nsms.delivered,");
	get_net_sms_delivered(cmd, net);
	cmd->reply = talloc_strdup_append(cmd->reply, "\nsms.rp_err_mem,");
	get_net_sms_rp_err_mem(cmd, net);
	cmd->reply = talloc_strdup_append(cmd->reply, "\nsms.rp_err_other,");
	get_net_sms_rp_err_other(cmd, net);
	cmd->reply = talloc_strdup_append(cmd->reply, "\ncall.mo_setup,");
	get_net_call_mo_setup(cmd, net);
	cmd->reply = talloc_strdup_append(cmd->reply, "\ncall.mo_connect_ack,");
	get_net_call_mo_connect_ack(cmd, net);
	cmd->reply = talloc_strdup_append(cmd->reply, "\ncall.mt_setup,");
	get_net_call_mt_setup(cmd, net);
	cmd->reply = talloc_strdup_append(cmd->reply, "\ncall.mt_connect,");
	get_net_call_mt_connect(cmd, net);
	cmd->reply = talloc_strdup_append(cmd->reply, "\n");
	get_net_channels_load(cmd, net);
	get_net_paging(cmd, net);
	get_net_oml_link(cmd, net);
	get_net_smsqueue(cmd, net);
	get_net_lchan(cmd, net);

	return CTRL_CMD_REPLY;
}

CTRL_CMD_DEFINE(net_status, "network-status");


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
	rc |= ctrl_cmd_install(CTRL_NODE_ROOT, &cmd_net_channels_load);
	rc |= ctrl_cmd_install(CTRL_NODE_ROOT, &cmd_net_lchan);
	rc |= ctrl_cmd_install(CTRL_NODE_ROOT, &cmd_net_paging);
	rc |= ctrl_cmd_install(CTRL_NODE_ROOT, &cmd_net_oml_link);
	rc |= ctrl_cmd_install(CTRL_NODE_ROOT, &cmd_net_smsqueue);
	rc |= ctrl_cmd_install(CTRL_NODE_ROOT, &cmd_net_chreq_total);
	rc |= ctrl_cmd_install(CTRL_NODE_ROOT, &cmd_net_chreq_no_channel);
	rc |= ctrl_cmd_install(CTRL_NODE_ROOT, &cmd_net_chan_rf_fail);
	rc |= ctrl_cmd_install(CTRL_NODE_ROOT, &cmd_net_chan_rll_err);
	rc |= ctrl_cmd_install(CTRL_NODE_ROOT, &cmd_net_paging_attempted);
	rc |= ctrl_cmd_install(CTRL_NODE_ROOT, &cmd_net_paging_detached);
	rc |= ctrl_cmd_install(CTRL_NODE_ROOT, &cmd_net_paging_completed);
	rc |= ctrl_cmd_install(CTRL_NODE_ROOT, &cmd_net_paging_expired);
	rc |= ctrl_cmd_install(CTRL_NODE_ROOT, &cmd_net_bts_oml_fail);
	rc |= ctrl_cmd_install(CTRL_NODE_ROOT, &cmd_net_bts_rsl_fail);
	rc |= ctrl_cmd_install(CTRL_NODE_ROOT, &cmd_net_loc_upd_type_attach);
	rc |= ctrl_cmd_install(CTRL_NODE_ROOT, &cmd_net_loc_upd_type_normal);
	rc |= ctrl_cmd_install(CTRL_NODE_ROOT, &cmd_net_loc_upd_type_periodic);
	rc |= ctrl_cmd_install(CTRL_NODE_ROOT, &cmd_net_loc_upd_type_detach);
	rc |= ctrl_cmd_install(CTRL_NODE_ROOT, &cmd_net_loc_upd_type_accept);
	rc |= ctrl_cmd_install(CTRL_NODE_ROOT, &cmd_net_loc_upd_type_reject);
	rc |= ctrl_cmd_install(CTRL_NODE_ROOT, &cmd_net_handover_attempted);
	rc |= ctrl_cmd_install(CTRL_NODE_ROOT, &cmd_net_handover_no_channel);
	rc |= ctrl_cmd_install(CTRL_NODE_ROOT, &cmd_net_handover_timeout);
	rc |= ctrl_cmd_install(CTRL_NODE_ROOT, &cmd_net_handover_completed);
	rc |= ctrl_cmd_install(CTRL_NODE_ROOT, &cmd_net_handover_failed);
	rc |= ctrl_cmd_install(CTRL_NODE_ROOT, &cmd_net_sms_submitted);
	rc |= ctrl_cmd_install(CTRL_NODE_ROOT, &cmd_net_sms_no_receiver);
	rc |= ctrl_cmd_install(CTRL_NODE_ROOT, &cmd_net_sms_delivered);
	rc |= ctrl_cmd_install(CTRL_NODE_ROOT, &cmd_net_sms_rp_err_mem);
	rc |= ctrl_cmd_install(CTRL_NODE_ROOT, &cmd_net_sms_rp_err_other);
	rc |= ctrl_cmd_install(CTRL_NODE_ROOT, &cmd_net_call_mo_setup);
	rc |= ctrl_cmd_install(CTRL_NODE_ROOT, &cmd_net_call_mo_connect_ack);
	rc |= ctrl_cmd_install(CTRL_NODE_ROOT, &cmd_net_call_mt_setup);
	rc |= ctrl_cmd_install(CTRL_NODE_ROOT, &cmd_net_call_mt_connect);
	rc |= ctrl_cmd_install(CTRL_NODE_ROOT, &cmd_net_status);
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

	rc |= ctrl_cmd_install(CTRL_NODE_TRX, &cmd_trx_max_power);
	rc |= ctrl_cmd_install(CTRL_NODE_TRX, &cmd_trx_arfcn);

	return rc;
}
