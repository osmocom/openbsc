/* Handover Decision making for Inter-BTS (Intra-BSC) Handover.  This
 * only implements the handover algorithm/decision, but not execution
 * of it */

/* (C) 2009 by Harald Welte <laforge@gnumonks.org>
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
#include <errno.h>

#include <osmocom/core/msgb.h>
#include <openbsc/debug.h>
#include <openbsc/gsm_data.h>
#include <openbsc/meas_rep.h>
#include <openbsc/signal.h>
#include <osmocom/core/talloc.h>
#include <openbsc/handover.h>
#include <osmocom/gsm/gsm_utils.h>

/* Get reference to a neighbor cell on a given BCCH ARFCN */
static struct gsm_bts *gsm_bts_neighbor(const struct gsm_bts *bts,
					uint16_t arfcn, uint8_t bsic)
{
	struct gsm_bts *neigh;
	/* FIXME: use some better heuristics here to determine which cell
	 * using this ARFCN really is closest to the target cell.  For
	 * now we simply assume that each ARFCN will only be used by one
	 * cell */

	llist_for_each_entry(neigh, &bts->network->bts_list, list) {
		/* FIXME: this is probably returning the same bts again!? */
		if (neigh->c0->arfcn == arfcn &&
		    neigh->bsic == bsic)
			return neigh;
	}

	return NULL;
}


/* issue handover to a cell identified by ARFCN and BSIC */
static int handover_to_arfcn_bsic(struct gsm_lchan *lchan,
				  uint16_t arfcn, uint8_t bsic)
{
	struct gsm_bts *new_bts;

	/* resolve the gsm_bts structure for the best neighbor */
	new_bts = gsm_bts_neighbor(lchan->ts->trx->bts, arfcn, bsic);
	if (!new_bts) {
		LOGP(DHO, LOGL_NOTICE, "unable to determine neighbor BTS "
		     "for ARFCN %u BSIC %u ?!?\n", arfcn, bsic);
		return -EINVAL;
	}

	/* and actually try to handover to that cell */
	return bsc_handover_start(lchan, new_bts);
}

/* did we get a RXLEV for a given cell in the given report? */
static int rxlev_for_cell_in_rep(struct gsm_meas_rep *mr,
				 uint16_t arfcn, uint8_t bsic)
{
	int i;

	for (i = 0; i < mr->num_cell; i++) {
		struct gsm_meas_rep_cell *mrc = &mr->cell[i];

		/* search for matching report */
		if (!(mrc->arfcn == arfcn && mrc->bsic == bsic))
			continue;

		mrc->flags |= MRC_F_PROCESSED;
		return mrc->rxlev;
	}
	return -ENODEV;
}

/* obtain averaged rxlev for given neighbor */
static int neigh_meas_avg(struct neigh_meas_proc *nmp, int window)
{
	unsigned int i, idx;
	int avg = 0;

	idx = calc_initial_idx(ARRAY_SIZE(nmp->rxlev),
				nmp->rxlev_cnt % ARRAY_SIZE(nmp->rxlev),
				window);

	for (i = 0; i < window; i++) {
		int j = (idx+i) % ARRAY_SIZE(nmp->rxlev);

		avg += nmp->rxlev[j];
	}

	return avg / window;
}

/* find empty or evict bad neighbor */
static struct neigh_meas_proc *find_evict_neigh(struct gsm_lchan *lchan)
{
	int j, worst = 999999;
	struct neigh_meas_proc *nmp_worst = NULL;

	/* first try to find an empty/unused slot */
	for (j = 0; j < ARRAY_SIZE(lchan->neigh_meas); j++) {
		struct neigh_meas_proc *nmp = &lchan->neigh_meas[j];
		if (!nmp->arfcn)
			return nmp;
	}

	/* no empty slot found. evict worst neighbor from list */
	for (j = 0; j < ARRAY_SIZE(lchan->neigh_meas); j++) {
		struct neigh_meas_proc *nmp = &lchan->neigh_meas[j];
		int avg = neigh_meas_avg(nmp, MAX_WIN_NEIGH_AVG);
		if (!nmp_worst || avg < worst) {
			worst = avg;
			nmp_worst = nmp;
		}
	}

	return nmp_worst;
}

/* process neighbor cell measurement reports */
static void process_meas_neigh(struct gsm_meas_rep *mr)
{
	int i, j, idx;

	/* for each reported cell, try to update global state */
	for (j = 0; j < ARRAY_SIZE(mr->lchan->neigh_meas); j++) {
		struct neigh_meas_proc *nmp = &mr->lchan->neigh_meas[j];
		unsigned int idx;
		int rxlev;

		/* skip unused entries */
		if (!nmp->arfcn)
			continue;

		rxlev = rxlev_for_cell_in_rep(mr, nmp->arfcn, nmp->bsic);
		idx = nmp->rxlev_cnt % ARRAY_SIZE(nmp->rxlev);
		if (rxlev >= 0) {
			nmp->rxlev[idx] = rxlev;
			nmp->last_seen_nr = mr->nr;
		} else
			nmp->rxlev[idx] = 0;
		nmp->rxlev_cnt++;
	}

	/* iterate over list of reported cells, check if we did not
	 * process all of them */
	for (i = 0; i < mr->num_cell; i++) {
		struct gsm_meas_rep_cell *mrc = &mr->cell[i];
		struct neigh_meas_proc *nmp;

		if (mrc->flags & MRC_F_PROCESSED)
			continue;

		nmp = find_evict_neigh(mr->lchan);

		nmp->arfcn = mrc->arfcn;
		nmp->bsic = mrc->bsic;

		idx = nmp->rxlev_cnt % ARRAY_SIZE(nmp->rxlev);
		nmp->rxlev[idx] = mrc->rxlev;
		nmp->rxlev_cnt++;
		nmp->last_seen_nr = mr->nr;

		mrc->flags |= MRC_F_PROCESSED;
	}
}

/* attempt to do a handover */
static int attempt_handover(struct gsm_meas_rep *mr)
{
	struct gsm_network *net = mr->lchan->ts->trx->bts->network;
	struct neigh_meas_proc *best_cell = NULL;
	unsigned int best_better_db = 0;
	int i, rc;

	/* find the best cell in this report that is at least RXLEV_HYST
	 * better than the current serving cell */

	for (i = 0; i < ARRAY_SIZE(mr->lchan->neigh_meas); i++) {
		struct neigh_meas_proc *nmp = &mr->lchan->neigh_meas[i];
		int avg, better;

		/* skip empty slots */
		if (nmp->arfcn == 0)
			continue;

		/* caculate average rxlev for this cell over the window */
		avg = neigh_meas_avg(nmp, net->handover.win_rxlev_avg_neigh);

		/* check if hysteresis is fulfilled */
		if (avg < mr->dl.full.rx_lev + net->handover.pwr_hysteresis)
			continue;

		better = avg - mr->dl.full.rx_lev;
		if (better > best_better_db) {
			best_cell = nmp;
			best_better_db = better;
		}
	}

	if (!best_cell)
		return 0;

	LOGP(DHO, LOGL_INFO, "%s: Cell on ARFCN %u is better: ",
		gsm_ts_name(mr->lchan->ts), best_cell->arfcn);
	if (!net->handover.active) {
		LOGPC(DHO, LOGL_INFO, "Skipping, Handover disabled\n");
		return 0;
	}

	rc = handover_to_arfcn_bsic(mr->lchan, best_cell->arfcn, best_cell->bsic);
	switch (rc) {
	case 0:
		LOGPC(DHO, LOGL_INFO, "Starting handover\n");
		break;
	case -ENOSPC:
		LOGPC(DHO, LOGL_INFO, "No channel available\n");
		break;
	case -EBUSY:
		LOGPC(DHO, LOGL_INFO, "Handover already active\n");
		break;
	default:
		LOGPC(DHO, LOGL_ERROR, "Unknown error\n");
	}
	return rc;
}

/* process an already parsed measurement report and decide if we want to
 * attempt a handover */
static int process_meas_rep(struct gsm_meas_rep *mr)
{
	struct gsm_network *net = mr->lchan->ts->trx->bts->network;
	enum meas_rep_field dlev, dqual;
	int av_rxlev;

	/* we currently only do handover for TCH channels */
	switch (mr->lchan->type) {
	case GSM_LCHAN_TCH_F:
	case GSM_LCHAN_TCH_H:
		break;
	default:
		return 0;
	}

	if (mr->flags & MEAS_REP_F_DL_DTX) {
		dlev = MEAS_REP_DL_RXLEV_SUB;
		dqual = MEAS_REP_DL_RXQUAL_SUB;
	} else {
		dlev = MEAS_REP_DL_RXLEV_FULL;
		dqual = MEAS_REP_DL_RXQUAL_FULL;
	}

	/* parse actual neighbor cell info */
	if (mr->num_cell > 0 && mr->num_cell < 7)
		process_meas_neigh(mr);

	av_rxlev = get_meas_rep_avg(mr->lchan, dlev,
				    net->handover.win_rxlev_avg);

	/* Interference HO */
	if (rxlev2dbm(av_rxlev) > -85 &&
	    meas_rep_n_out_of_m_be(mr->lchan, dqual, 3, 4, 5))
		return attempt_handover(mr);

	/* Bad Quality */
	if (meas_rep_n_out_of_m_be(mr->lchan, dqual, 3, 4, 5))
		return attempt_handover(mr);

	/* Low Level */
	if (rxlev2dbm(av_rxlev) <= -110)
		return attempt_handover(mr);

	/* Distance */
	if (mr->ms_l1.ta > net->handover.max_distance)
		return attempt_handover(mr);

	/* Power Budget AKA Better Cell */
	if ((mr->nr % net->handover.pwr_interval) == 0)
		return attempt_handover(mr);

	return 0;

}

static int ho_dec_sig_cb(unsigned int subsys, unsigned int signal,
			   void *handler_data, void *signal_data)
{
	struct lchan_signal_data *lchan_data;

	if (subsys != SS_LCHAN)
		return 0;

	lchan_data = signal_data;
	switch (signal) {
	case S_LCHAN_MEAS_REP:
		process_meas_rep(lchan_data->mr);
		break;
	}

	return 0;
}

void on_dso_load_ho_dec(void)
{
	osmo_signal_register_handler(SS_LCHAN, ho_dec_sig_cb, NULL);
}
