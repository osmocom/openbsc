/* OpenBSC E1 Input code */

/* (C) 2008-2010 by Harald Welte <laforge@gnumonks.org>
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

#include <string.h>
#include <errno.h>

#include <netinet/in.h>

#include <openbsc/gsm_data.h>
#include <osmocom/abis/e1_input.h>
#include <osmocom/abis/trau_frame.h>
#include <openbsc/trau_mux.h>
#include <openbsc/misdn.h>
#include <osmocom/abis/ipaccess.h>
#include <osmocom/core/talloc.h>
#include <openbsc/debug.h>
#include <openbsc/abis_rsl.h>

#define SAPI_L2ML	0
#define SAPI_OML	62
#define SAPI_RSL	0	/* 63 ? */

/* The e1_reconfig_*() functions below take the configuration present in the
 * bts/trx/ts data structures and ensure the E1 configuration reflects the
 * timeslot/subslot/TEI configuration */

int e1_reconfig_ts(struct gsm_bts_trx_ts *ts)
{
	struct gsm_e1_subslot *e1_link = &ts->e1_link;
	struct e1inp_line *line;
	struct e1inp_ts *e1_ts;

	DEBUGP(DLMI, "e1_reconfig_ts(%u,%u,%u)\n", ts->trx->bts->nr, ts->trx->nr, ts->nr);

	if (!e1_link->e1_ts) {
		LOGP(DLINP, LOGL_ERROR, "TS (%u/%u/%u) without E1 timeslot?\n",
		     ts->nr, ts->trx->nr, ts->trx->bts->nr);
		return 0;
	}

	line = e1inp_line_find(e1_link->e1_nr);
	if (!line) {
		LOGP(DLINP, LOGL_ERROR, "TS (%u/%u/%u) referring to "
		     "non-existing E1 line %u\n", ts->nr, ts->trx->nr,
		     ts->trx->bts->nr, e1_link->e1_nr);
		return -ENOMEM;
	}

	if (ts_is_tch(ts)) {
		e1_ts = &line->ts[e1_link->e1_ts-1];
		e1inp_ts_config_trau(e1_ts, line, subch_cb);
		subch_demux_activate(&e1_ts->trau.demux, e1_link->e1_ts_ss);
	}

	return 0;
}

int e1_reconfig_trx(struct gsm_bts_trx *trx)
{
	struct gsm_e1_subslot *e1_link = &trx->rsl_e1_link;
	struct e1inp_ts *sign_ts;
	struct e1inp_line *line;
	struct e1inp_sign_link *rsl_link;
	int i;

	if (!e1_link->e1_ts) {
		LOGP(DLINP, LOGL_ERROR, "TRX (%u/%u) RSL link without "
		     "timeslot?\n", trx->bts->nr, trx->nr);
		return -EINVAL;
	}

	/* RSL Link */
	line = e1inp_line_find(e1_link->e1_nr);
	if (!line) {
		LOGP(DLINP, LOGL_ERROR, "TRX (%u/%u) RSL link referring "
		     "to non-existing E1 line %u\n", trx->bts->nr,
		     trx->nr, e1_link->e1_nr);
		return -ENOMEM;
	}
	sign_ts = &line->ts[e1_link->e1_ts-1];
	e1inp_ts_config_sign(sign_ts, line);
	/* Ericsson RBS have a per-TRX OML link in parallel to RSL */
	if (trx->bts->type == GSM_BTS_TYPE_RBS2000) {
		struct e1inp_sign_link *oml_link;
		oml_link = e1inp_sign_link_create(sign_ts, E1INP_SIGN_OML, trx,
						  trx->rsl_tei, SAPI_OML);
		if (!oml_link) {
			LOGP(DLINP, LOGL_ERROR, "TRX (%u/%u) OML link creation "
				"failed\n", trx->bts->nr, trx->nr);
			return -ENOMEM;
		}
		if (trx->oml_link)
			e1inp_sign_link_destroy(trx->oml_link);
		trx->oml_link = oml_link;
	}
	rsl_link = e1inp_sign_link_create(sign_ts, E1INP_SIGN_RSL,
					  trx, trx->rsl_tei, SAPI_RSL);
	if (!rsl_link) {
		LOGP(DLINP, LOGL_ERROR, "TRX (%u/%u) RSL link creation "
		     "failed\n", trx->bts->nr, trx->nr);
		return -ENOMEM;
	}
	if (trx->rsl_link)
		e1inp_sign_link_destroy(trx->rsl_link);
	trx->rsl_link = rsl_link;

	for (i = 0; i < TRX_NR_TS; i++)
		e1_reconfig_ts(&trx->ts[i]);

	return 0;
}

/* this is the generic callback for all ISDN-based BTS. */
static int bts_isdn_sign_link(struct msgb *msg)
{
	int ret = -EINVAL;
	struct e1inp_sign_link *link = msg->dst;
	struct gsm_bts *bts;

	switch (link->type) {
	case E1INP_SIGN_OML:
		bts = link->trx->bts;
		ret = bts->model->oml_rcvmsg(msg);
		break;
	case E1INP_SIGN_RSL:
		ret = abis_rsl_rcvmsg(msg);
		break;
	default:
		LOGP(DLMI, LOGL_ERROR, "unknown link type %u\n", link->type);
		break;
	}
	return ret;
}

struct e1inp_line_ops bts_isdn_e1inp_line_ops = {
	.sign_link	= bts_isdn_sign_link,
};

int e1_reconfig_bts(struct gsm_bts *bts)
{
	struct gsm_e1_subslot *e1_link = &bts->oml_e1_link;
	struct e1inp_ts *sign_ts;
	struct e1inp_line *line;
	struct e1inp_sign_link *oml_link;
	struct gsm_bts_trx *trx;

	DEBUGP(DLMI, "e1_reconfig_bts(%u)\n", bts->nr);

	line = e1inp_line_find(e1_link->e1_nr);
	if (!line) {
		LOGP(DLINP, LOGL_ERROR, "BTS %u OML link referring to "
		     "non-existing E1 line %u\n", bts->nr, e1_link->e1_nr);
		return -ENOMEM;
	}

	if (!bts->model->e1line_bind_ops) {
		LOGP(DLINP, LOGL_ERROR, "no callback to bind E1 line operations\n");
		return -EINVAL;
	}
	if (!line->ops)
		bts->model->e1line_bind_ops(line);

	/* skip signal link initialization, this is done later for these BTS. */
	if (bts->type == GSM_BTS_TYPE_NANOBTS ||
	    bts->type == GSM_BTS_TYPE_OSMOBTS)
		return e1inp_line_update(line);

	/* OML link */
	if (!e1_link->e1_ts) {
		LOGP(DLINP, LOGL_ERROR, "BTS %u OML link without timeslot?\n",
		     bts->nr);
		return -EINVAL;
	}

	sign_ts = &line->ts[e1_link->e1_ts-1];
	e1inp_ts_config_sign(sign_ts, line);
	oml_link = e1inp_sign_link_create(sign_ts, E1INP_SIGN_OML,
					  bts->c0, bts->oml_tei, SAPI_OML);
	if (!oml_link) {
		LOGP(DLINP, LOGL_ERROR, "BTS %u OML link creation failed\n",
		     bts->nr);
		return -ENOMEM;
	}
	if (bts->oml_link)
		e1inp_sign_link_destroy(bts->oml_link);
	bts->oml_link = oml_link;

	llist_for_each_entry(trx, &bts->trx_list, list)
		e1_reconfig_trx(trx);

	/* notify E1 input something has changed */
	return e1inp_line_update(line);
}

#if 0
/* do some compiled-in configuration for our BTS/E1 setup */
int e1_config(struct gsm_bts *bts, int cardnr, int release_l2)
{
	struct e1inp_line *line;
	struct e1inp_ts *sign_ts;
	struct e1inp_sign_link *oml_link, *rsl_link;
	struct gsm_bts_trx *trx = bts->c0;
	int base_ts;

	switch (bts->nr) {
	case 0:
		/* First BTS uses E1 TS 01,02,03,04,05 */
		base_ts = HARDCODED_BTS0_TS - 1;
		break;
	case 1:
		/* Second BTS uses E1 TS 06,07,08,09,10 */
		base_ts = HARDCODED_BTS1_TS - 1;
		break;
	case 2:
		/* Third BTS uses E1 TS 11,12,13,14,15 */
		base_ts = HARDCODED_BTS2_TS - 1;
	default:
		return -EINVAL;
	}

	line = talloc_zero(tall_bsc_ctx, struct e1inp_line);
	if (!line)
		return -ENOMEM;

	/* create E1 timeslots for signalling and TRAU frames */
	e1inp_ts_config(&line->ts[base_ts+1-1], line, E1INP_TS_TYPE_SIGN);
	e1inp_ts_config(&line->ts[base_ts+2-1], line, E1INP_TS_TYPE_TRAU);
	e1inp_ts_config(&line->ts[base_ts+3-1], line, E1INP_TS_TYPE_TRAU);

	/* create signalling links for TS1 */
	sign_ts = &line->ts[base_ts+1-1];
	oml_link = e1inp_sign_link_create(sign_ts, E1INP_SIGN_OML,
					  trx, TEI_OML, SAPI_OML);
	rsl_link = e1inp_sign_link_create(sign_ts, E1INP_SIGN_RSL,
					  trx, TEI_RSL, SAPI_RSL);

	/* create back-links from bts/trx */
	bts->oml_link = oml_link;
	trx->rsl_link = rsl_link;

	/* enable subchannel demuxer on TS2 */
	subch_demux_activate(&line->ts[base_ts+2-1].trau.demux, 1);
	subch_demux_activate(&line->ts[base_ts+2-1].trau.demux, 2);
	subch_demux_activate(&line->ts[base_ts+2-1].trau.demux, 3);

	/* enable subchannel demuxer on TS3 */
	subch_demux_activate(&line->ts[base_ts+3-1].trau.demux, 0);
	subch_demux_activate(&line->ts[base_ts+3-1].trau.demux, 1);
	subch_demux_activate(&line->ts[base_ts+3-1].trau.demux, 2);
	subch_demux_activate(&line->ts[base_ts+3-1].trau.demux, 3);

	trx = gsm_bts_trx_num(bts, 1);
	if (trx) {
		/* create E1 timeslots for TRAU frames of TRX1 */
		e1inp_ts_config(&line->ts[base_ts+4-1], line, E1INP_TS_TYPE_TRAU);
		e1inp_ts_config(&line->ts[base_ts+5-1], line, E1INP_TS_TYPE_TRAU);

		/* create RSL signalling link for TRX1 */
		sign_ts = &line->ts[base_ts+1-1];
		rsl_link = e1inp_sign_link_create(sign_ts, E1INP_SIGN_RSL,
					  trx, TEI_RSL+1, SAPI_RSL);
		/* create back-links from trx */
		trx->rsl_link = rsl_link;

		/* enable subchannel demuxer on TS2 */
		subch_demux_activate(&line->ts[base_ts+4-1].trau.demux, 0);
		subch_demux_activate(&line->ts[base_ts+4-1].trau.demux, 1);
		subch_demux_activate(&line->ts[base_ts+4-1].trau.demux, 2);
		subch_demux_activate(&line->ts[base_ts+4-1].trau.demux, 3);

		/* enable subchannel demuxer on TS3 */
		subch_demux_activate(&line->ts[base_ts+5-1].trau.demux, 0);
		subch_demux_activate(&line->ts[base_ts+5-1].trau.demux, 1);
		subch_demux_activate(&line->ts[base_ts+5-1].trau.demux, 2);
		subch_demux_activate(&line->ts[base_ts+5-1].trau.demux, 3);
	}

	return mi_setup(cardnr, line, release_l2);
}
#endif
