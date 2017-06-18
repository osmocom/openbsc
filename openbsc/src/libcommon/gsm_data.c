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
#include <stdbool.h>
#include <netinet/in.h>

#include <osmocom/core/linuxlist.h>
#include <osmocom/core/talloc.h>
#include <osmocom/gsm/gsm_utils.h>
#include <osmocom/gsm/abis_nm.h>
#include <osmocom/core/statistics.h>
#include <osmocom/gsm/protocol/gsm_04_08.h>

#include <openbsc/gsm_data.h>
#include <openbsc/bsc_msc_data.h>
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

const struct value_string bts_type_descs[_NUM_GSM_BTS_TYPE+1] = {
	{ GSM_BTS_TYPE_UNKNOWN,		"Unknown BTS Type" },
	{ GSM_BTS_TYPE_BS11,		"Siemens BTS (BS-11 or compatible)" },
	{ GSM_BTS_TYPE_NANOBTS,		"ip.access nanoBTS or compatible" },
	{ GSM_BTS_TYPE_RBS2000,		"Ericsson RBS2000 Series" },
	{ GSM_BTS_TYPE_NOKIA_SITE,	"Nokia {Metro,Ultra,In}Site" },
	{ GSM_BTS_TYPE_OSMOBTS,		"sysmocom sysmoBTS" },
	{ 0,				NULL }
};

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
	{ GSM_AUTH_POLICY_REGEXP,	"regexp" },
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

enum bts_gprs_mode bts_gprs_mode_parse(const char *arg, int *valid)
{
	int rc;

	rc = get_string_value(bts_gprs_mode_names, arg);
	if (valid)
		*valid = rc != -EINVAL;
	return rc;
}

const char *bts_gprs_mode_name(enum bts_gprs_mode mode)
{
	return get_value_string(bts_gprs_mode_names, mode);
}

int bts_gprs_mode_is_compat(struct gsm_bts *bts, enum bts_gprs_mode mode)
{
	if (mode != BTS_GPRS_NONE &&
	    !gsm_btsmodel_has_feature(bts->model, BTS_FEAT_GPRS)) {
		return 0;
	}
	if (mode == BTS_GPRS_EGPRS &&
	    !gsm_btsmodel_has_feature(bts->model, BTS_FEAT_EGPRS)) {
		return 0;
	}

	return 1;
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

int gsm_btsmodel_set_feature(struct gsm_bts_model *model, enum gsm_bts_features feat)
{
	OSMO_ASSERT(_NUM_BTS_FEAT < MAX_BTS_FEATURES);
	return bitvec_set_bit_pos(&model->features, feat, 1);
}

bool gsm_btsmodel_has_feature(struct gsm_bts_model *model, enum gsm_bts_features feat)
{
	OSMO_ASSERT(_NUM_BTS_FEAT < MAX_BTS_FEATURES);
	return bitvec_get_bit_pos(&model->features, feat);
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
	case GSM_BTS_TYPE_OSMOBTS:
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
		/* Set default BTS reset timer */
		bts->nokia.bts_reset_timer_cnf = 15;
	case _NUM_GSM_BTS_TYPE:
		break;
	}

	return 0;
}

struct gsm_bts *gsm_bts_alloc_register(struct gsm_network *net, enum gsm_bts_type type,
					uint8_t bsic)
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
	bts->bsic = bsic;
	bts->dtxu = GSM48_DTX_SHALL_NOT_BE_USED;
	bts->dtxd = false;
	bts->gprs.ctrl_ack_type_use_block = true; /* use RLC/MAC control block */
	bts->neigh_list_manual_mode = 0;
	bts->si_common.cell_sel_par.cell_resel_hyst = 2; /* 4 dB */
	bts->si_common.cell_sel_par.rxlev_acc_min = 0;
	bts->si_common.si2quater_neigh_list.arfcn = bts->si_common.data.earfcn_list;
	bts->si_common.si2quater_neigh_list.meas_bw = bts->si_common.data.meas_bw_list;
	bts->si_common.si2quater_neigh_list.length = MAX_EARFCN_LIST;
	bts->si_common.si2quater_neigh_list.thresh_hi = 0;
	osmo_earfcn_init(&bts->si_common.si2quater_neigh_list);
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
	gsm_bts_set_radio_link_timeout(bts, 32); /* Use RADIO LINK TIMEOUT of 32 */

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

/* Assume there are only 256 possible bts */
osmo_static_assert(sizeof(((struct gsm_bts *) 0)->nr) == 1, _bts_nr_is_256);
static void depends_calc_index_bit(int bts_nr, int *idx, int *bit)
{
	*idx = bts_nr / (8 * 4);
	*bit = bts_nr % (8 * 4);
}

void bts_depend_mark(struct gsm_bts *bts, int dep)
{
	int idx, bit;
	depends_calc_index_bit(dep, &idx, &bit);

	bts->depends_on[idx] |= 1 << bit;
}

void bts_depend_clear(struct gsm_bts *bts, int dep)
{
	int idx, bit;
	depends_calc_index_bit(dep, &idx, &bit);

	bts->depends_on[idx] &= ~(1 << bit);
}

int bts_depend_is_depedency(struct gsm_bts *base, struct gsm_bts *other)
{
	int idx, bit;
	depends_calc_index_bit(other->nr, &idx, &bit);

	/* Check if there is a depends bit */
	return (base->depends_on[idx] & (1 << bit)) > 0;
}

static int bts_is_online(struct gsm_bts *bts)
{
	/* TODO: support E1 BTS too */
	if (!is_ipaccess_bts(bts))
		return 1;

	if (!bts->oml_link)
		return 0;

	return bts->mo.nm_state.operational == NM_OPSTATE_ENABLED;
}

int bts_depend_check(struct gsm_bts *bts)
{
	struct gsm_bts *other_bts;

	llist_for_each_entry(other_bts, &bts->network->bts_list, list) {
		if (!bts_depend_is_depedency(bts, other_bts))
			continue;
		if (bts_is_online(other_bts))
			continue;
		return 0;
	}
	return 1;
}

/* get the radio link timeout (based on SACCH decode errors, according
 * to algorithm specified in TS 05.08 section 5.2.  A value of -1
 * indicates we should use an infinitely long timeout, which only works
 * with OsmoBTS as the BTS implementation */
int gsm_bts_get_radio_link_timeout(const struct gsm_bts *bts)
{
	const struct gsm48_cell_options *cell_options = &bts->si_common.cell_options;

	if (bts->infinite_radio_link_timeout)
		return -1;
	else {
		/* Encoding as per Table 10.5.21 of TS 04.08 */
		return (cell_options->radio_link_timeout + 1) << 2;
	}
}

/* set the radio link timeout (based on SACCH decode errors, according
 * to algorithm specified in TS 05.08 Section 5.2.  A value of -1
 * indicates we should use an infinitely long timeout, which only works
 * with OsmoBTS as the BTS implementation */
void gsm_bts_set_radio_link_timeout(struct gsm_bts *bts, int value)
{
	struct gsm48_cell_options *cell_options = &bts->si_common.cell_options;

	if (value < 0)
		bts->infinite_radio_link_timeout = true;
	else {
		bts->infinite_radio_link_timeout = false;
		/* Encoding as per Table 10.5.21 of TS 04.08 */
		if (value < 4)
			value = 4;
		if (value > 64)
			value = 64;
		cell_options->radio_link_timeout = (value >> 2) - 1;
	}
}
