/* (C) 2008-2010 by Harald Welte <laforge@gnumonks.org>
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


#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <ctype.h>

#include <netinet/in.h>

#include <osmocom/core/linuxlist.h>
#include <osmocom/core/talloc.h>
#include <osmocom/gsm/gsm_utils.h>
#include <osmocom/gsm/abis_nm.h>
#include <osmocom/core/statistics.h>

#include <openbsc/gsm_data.h>
#include <openbsc/osmo_msc_data.h>
#include <openbsc/abis_nm.h>

void *tall_bsc_ctx;

static LLIST_HEAD(bts_models);

void set_ts_e1link(struct gsm_bts_trx_ts *ts, uint8_t e1_nr,
		   uint8_t e1_ts, uint8_t e1_ts_ss)
{
	ts->e1_link.e1_nr = e1_nr;
	ts->e1_link.e1_ts = e1_ts;
	ts->e1_link.e1_ts_ss = e1_ts_ss;
}

static struct gsm_bts_model *bts_model_find(enum gsm_bts_type type)
{
	struct gsm_bts_model *model;

	llist_for_each_entry(model, &bts_models, list) {
		if (model->type == type)
			return model;
	}

	return NULL;
}

int gsm_bts_model_register(struct gsm_bts_model *model)
{
	if (bts_model_find(model->type))
		return -EEXIST;

	tlv_def_patch(&model->nm_att_tlvdef, &abis_nm_att_tlvdef);
	llist_add_tail(&model->list, &bts_models);
	return 0;
}

struct gsm_network *gsm_network_init(uint16_t country_code, uint16_t network_code,
				     int (*mncc_recv)(struct gsm_network *, struct msgb *))
{
	struct gsm_network *net;

	net = talloc_zero(tall_bsc_ctx, struct gsm_network);
	if (!net)
		return NULL;

	net->bsc_data = talloc_zero(net, struct osmo_bsc_data);
	if (!net->bsc_data) {
		talloc_free(net);
		return NULL;
	}

	/* Init back pointer */
	net->bsc_data->auto_off_timeout = -1;
	net->bsc_data->network = net;
	INIT_LLIST_HEAD(&net->bsc_data->mscs);

	net->country_code = country_code;
	net->network_code = network_code;
	net->num_bts = 0;
	net->reject_cause = GSM48_REJECT_ROAMING_NOT_ALLOWED;
	net->T3101 = GSM_T3101_DEFAULT;
	net->T3105 = GSM_T3105_DEFAULT;
	net->T3113 = GSM_T3113_DEFAULT;
	net->T3122 = GSM_T3122_DEFAULT;
	/* FIXME: initialize all other timers! */

	/* default set of handover parameters */
	net->handover.win_rxlev_avg = 10;
	net->handover.win_rxqual_avg = 1;
	net->handover.win_rxlev_avg_neigh = 10;
	net->handover.pwr_interval = 6;
	net->handover.pwr_hysteresis = 3;
	net->handover.max_distance = 9999;

	INIT_LLIST_HEAD(&net->trans_list);
	INIT_LLIST_HEAD(&net->upqueue);
	INIT_LLIST_HEAD(&net->bts_list);

	net->stats.chreq.total = osmo_counter_alloc("net.chreq.total");
	net->stats.chreq.no_channel = osmo_counter_alloc("net.chreq.no_channel");
	net->stats.handover.attempted = osmo_counter_alloc("net.handover.attempted");
	net->stats.handover.no_channel = osmo_counter_alloc("net.handover.no_channel");
	net->stats.handover.timeout = osmo_counter_alloc("net.handover.timeout");
	net->stats.handover.completed = osmo_counter_alloc("net.handover.completed");
	net->stats.handover.failed = osmo_counter_alloc("net.handover.failed");
	net->stats.loc_upd_type.attach = osmo_counter_alloc("net.loc_upd_type.attach");
	net->stats.loc_upd_type.normal = osmo_counter_alloc("net.loc_upd_type.normal");
	net->stats.loc_upd_type.periodic = osmo_counter_alloc("net.loc_upd_type.periodic");
	net->stats.loc_upd_type.detach = osmo_counter_alloc("net.imsi_detach.count");
	net->stats.loc_upd_resp.reject = osmo_counter_alloc("net.loc_upd_resp.reject");
	net->stats.loc_upd_resp.accept = osmo_counter_alloc("net.loc_upd_resp.accept");
	net->stats.paging.attempted = osmo_counter_alloc("net.paging.attempted");
	net->stats.paging.detached = osmo_counter_alloc("net.paging.detached");
	net->stats.paging.completed = osmo_counter_alloc("net.paging.completed");
	net->stats.paging.expired = osmo_counter_alloc("net.paging.expired");
	net->stats.sms.submitted = osmo_counter_alloc("net.sms.submitted");
	net->stats.sms.no_receiver = osmo_counter_alloc("net.sms.no_receiver");
	net->stats.sms.delivered = osmo_counter_alloc("net.sms.delivered");
	net->stats.sms.rp_err_mem = osmo_counter_alloc("net.sms.rp_err_mem");
	net->stats.sms.rp_err_other = osmo_counter_alloc("net.sms.rp_err_other");
	net->stats.call.mo_setup = osmo_counter_alloc("net.call.mo_setup");
	net->stats.call.mo_connect_ack = osmo_counter_alloc("net.call.mo_connect_ack");
	net->stats.call.mt_setup = osmo_counter_alloc("net.call.mt_setup");
	net->stats.call.mt_connect = osmo_counter_alloc("net.call.mt_connect");
	net->stats.chan.rf_fail = osmo_counter_alloc("net.chan.rf_fail");
	net->stats.chan.rll_err = osmo_counter_alloc("net.chan.rll_err");
	net->stats.bts.oml_fail = osmo_counter_alloc("net.bts.oml_fail");
	net->stats.bts.rsl_fail = osmo_counter_alloc("net.bts.rsl_fail");

	net->mncc_recv = mncc_recv;

	gsm_net_update_ctype(net);

	return net;
}

/* Get reference to a neighbor cell on a given BCCH ARFCN */
struct gsm_bts *gsm_bts_neighbor(const struct gsm_bts *bts,
				 uint16_t arfcn, uint8_t bsic)
{
	struct gsm_bts *neigh;
	/* FIXME: use some better heuristics here to determine which cell
	 * using this ARFCN really is closest to the target cell.  For
	 * now we simply assume that each ARFCN will only be used by one
	 * cell */

	llist_for_each_entry(neigh, &bts->network->bts_list, list) {
		if (neigh->c0->arfcn == arfcn &&
		    neigh->bsic == bsic)
			return neigh;
	}

	return NULL;
}

const struct value_string bts_type_names[_NUM_GSM_BTS_TYPE+1] = {
	{ GSM_BTS_TYPE_UNKNOWN,	"unknown" },
	{ GSM_BTS_TYPE_BS11,	"bs11" },
	{ GSM_BTS_TYPE_NANOBTS,	"nanobts" },
	{ GSM_BTS_TYPE_RBS2000,	"rbs2000" },
	{ GSM_BTS_TYPE_NOKIA_SITE, "nokia_site" },
	{ GSM_BTS_TYPE_OSMO_SYSMO, "sysmobts" },
	{ 0,			NULL }
};

const struct value_string bts_type_descs[_NUM_GSM_BTS_TYPE+1] = {
	{ GSM_BTS_TYPE_UNKNOWN,		"Unknown BTS Type" },
	{ GSM_BTS_TYPE_BS11,		"Siemens BTS (BS-11 or compatible)" },
	{ GSM_BTS_TYPE_NANOBTS,		"ip.access nanoBTS or compatible" },
	{ GSM_BTS_TYPE_RBS2000,		"Ericsson RBS2000 Series" },
	{ GSM_BTS_TYPE_NOKIA_SITE,	"Nokia {Metro,Ultra,In}Site" },
	{ GSM_BTS_TYPE_OSMO_SYSMO,	"sysmocom sysmoBTS" },
	{ 0,				NULL }
};

enum gsm_bts_type parse_btstype(const char *arg)
{
	return get_string_value(bts_type_names, arg);
}

const char *btstype2str(enum gsm_bts_type type)
{
	return get_value_string(bts_type_names, type);
}

struct gsm_bts_trx *gsm_bts_trx_by_nr(struct gsm_bts *bts, int nr)
{
	struct gsm_bts_trx *trx;

	llist_for_each_entry(trx, &bts->trx_list, list) {
		if (trx->nr == nr)
			return trx;
	}
	return NULL;
}

/* Search for a BTS in the given Location Area; optionally start searching
 * with start_bts (for continuing to search after the first result) */
struct gsm_bts *gsm_bts_by_lac(struct gsm_network *net, unsigned int lac,
				struct gsm_bts *start_bts)
{
	int i;
	struct gsm_bts *bts;
	int skip = 0;

	if (start_bts)
		skip = 1;

	for (i = 0; i < net->num_bts; i++) {
		bts = gsm_bts_num(net, i);

		if (skip) {
			if (start_bts == bts)
				skip = 0;
			continue;
		}

		if (lac == GSM_LAC_RESERVED_ALL_BTS || bts->location_area_code == lac)
			return bts;
	}
	return NULL;
}

static const struct value_string auth_policy_names[] = {
	{ GSM_AUTH_POLICY_CLOSED,	"closed" },
	{ GSM_AUTH_POLICY_ACCEPT_ALL,	"accept-all" },
	{ GSM_AUTH_POLICY_TOKEN,	"token" },
	{ 0,				NULL }
};

enum gsm_auth_policy gsm_auth_policy_parse(const char *arg)
{
	return get_string_value(auth_policy_names, arg);
}

const char *gsm_auth_policy_name(enum gsm_auth_policy policy)
{
	return get_value_string(auth_policy_names, policy);
}

static const struct value_string rrlp_mode_names[] = {
	{ RRLP_MODE_NONE,	"none" },
	{ RRLP_MODE_MS_BASED,	"ms-based" },
	{ RRLP_MODE_MS_PREF,	"ms-preferred" },
	{ RRLP_MODE_ASS_PREF,	"ass-preferred" },
	{ 0,			NULL }
};

enum rrlp_mode rrlp_mode_parse(const char *arg)
{
	return get_string_value(rrlp_mode_names, arg);
}

const char *rrlp_mode_name(enum rrlp_mode mode)
{
	return get_value_string(rrlp_mode_names, mode);
}

static const struct value_string bts_gprs_mode_names[] = {
	{ BTS_GPRS_NONE,	"none" },
	{ BTS_GPRS_GPRS,	"gprs" },
	{ BTS_GPRS_EGPRS,	"egprs" },
	{ 0,			NULL }
};

enum bts_gprs_mode bts_gprs_mode_parse(const char *arg)
{
	return get_string_value(bts_gprs_mode_names, arg);
}

const char *bts_gprs_mode_name(enum bts_gprs_mode mode)
{
	return get_value_string(bts_gprs_mode_names, mode);
}

struct gsm_meas_rep *lchan_next_meas_rep(struct gsm_lchan *lchan)
{
	struct gsm_meas_rep *meas_rep;

	meas_rep = &lchan->meas_rep[lchan->meas_rep_idx];
	memset(meas_rep, 0, sizeof(*meas_rep));
	meas_rep->lchan = lchan;
	lchan->meas_rep_idx = (lchan->meas_rep_idx + 1)
					% ARRAY_SIZE(lchan->meas_rep);

	return meas_rep;
}

int gsm_btsmodel_set_feature(struct gsm_bts_model *bts, enum gsm_bts_features feat)
{
	return bitvec_set_bit_pos(&bts->features, feat, 1);
}

int gsm_bts_has_feature(struct gsm_bts *bts, enum gsm_bts_features feat)
{
	return bitvec_get_bit_pos(&bts->model->features, feat);
}

int gsm_set_bts_type(struct gsm_bts *bts, enum gsm_bts_type type)
{
	struct gsm_bts_model *model;

	model = bts_model_find(type);
	if (!model)
		return -EINVAL;

	bts->type = type;
	bts->model = model;

	if (model->start && !model->started) {
		int ret = model->start(bts->network);
		if (ret < 0)
			return ret;

		model->started = true;
	}

	switch (bts->type) {
	case GSM_BTS_TYPE_NANOBTS:
	case GSM_BTS_TYPE_OSMO_SYSMO:
		/* Set the default OML Stream ID to 0xff */
		bts->oml_tei = 0xff;
		bts->c0->nominal_power = 23;
		break;
	case GSM_BTS_TYPE_RBS2000:
		INIT_LLIST_HEAD(&bts->rbs2000.is.conn_groups);
		INIT_LLIST_HEAD(&bts->rbs2000.con.conn_groups);
		break;
	case GSM_BTS_TYPE_BS11:
	case GSM_BTS_TYPE_UNKNOWN:
	case GSM_BTS_TYPE_NOKIA_SITE:
	case _NUM_GSM_BTS_TYPE:
		break;
	}

	return 0;
}

struct gsm_bts *gsm_bts_alloc_register(struct gsm_network *net, enum gsm_bts_type type,
					uint8_t tsc, uint8_t bsic)
{
	struct gsm_bts_model *model = bts_model_find(type);
	struct gsm_bts *bts;

	if (!model && type != GSM_BTS_TYPE_UNKNOWN)
		return NULL;

	bts = gsm_bts_alloc(net);
	if (!bts)
		return NULL;

	bts->network = net;
	bts->nr = net->num_bts++;
	bts->type = type;
	bts->model = model;
	bts->tsc = tsc;
	bts->bsic = bsic;

	bts->neigh_list_manual_mode = 0;
	bts->si_common.cell_sel_par.cell_resel_hyst = 2; /* 4 dB */
	bts->si_common.cell_sel_par.rxlev_acc_min = 0;
	bts->si_common.neigh_list.data = bts->si_common.data.neigh_list;
	bts->si_common.neigh_list.data_len =
				sizeof(bts->si_common.data.neigh_list);
	bts->si_common.si5_neigh_list.data = bts->si_common.data.si5_neigh_list;
	bts->si_common.si5_neigh_list.data_len =
				sizeof(bts->si_common.data.si5_neigh_list);
	bts->si_common.cell_alloc.data = bts->si_common.data.cell_alloc;
	bts->si_common.cell_alloc.data_len =
				sizeof(bts->si_common.data.cell_alloc);
	bts->si_common.rach_control.re = 1; /* no re-establishment */
	bts->si_common.rach_control.tx_integer = 9;  /* 12 slots spread - 217/115 slots delay */
	bts->si_common.rach_control.max_trans = 3; /* 7 retransmissions */
	bts->si_common.rach_control.t2 = 4; /* no emergency calls */
	bts->si_common.chan_desc.att = 1; /* attachment required */
	bts->si_common.chan_desc.bs_pa_mfrms = RSL_BS_PA_MFRMS_5; /* paging frames */
	bts->si_common.chan_desc.bs_ag_blks_res = 1; /* reserved AGCH blocks */
	bts->si_common.chan_desc.t3212 = 5; /* Use 30 min periodic update interval as sane default */

	llist_add_tail(&bts->list, &net->bts_list);

	INIT_LLIST_HEAD(&bts->abis_queue);

	INIT_LLIST_HEAD(&bts->loc_list);

	return bts;
}

void gprs_ra_id_by_bts(struct gprs_ra_id *raid, struct gsm_bts *bts)
{
	raid->mcc = bts->network->country_code;
	raid->mnc = bts->network->network_code;
	raid->lac = bts->location_area_code;
	raid->rac = bts->gprs.rac;
}

int gsm48_ra_id_by_bts(uint8_t *buf, struct gsm_bts *bts)
{
	struct gprs_ra_id raid;

	gprs_ra_id_by_bts(&raid, bts);

	return gsm48_construct_ra(buf, &raid);
}

int gsm_parse_reg(void *ctx, regex_t *reg, char **str, int argc, const char **argv)
{
	int ret;

	ret = 0;
	if (*str) {
		talloc_free(*str);
		*str = NULL;
	}
	regfree(reg);

	if (argc > 0) {
		*str = talloc_strdup(ctx, argv[0]);
		ret = regcomp(reg, argv[0], 0);

		/* handle compilation failures */
		if (ret != 0) {
			talloc_free(*str);
			*str = NULL;
		}
	}

	return ret;
}

