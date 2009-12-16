/* Handover Decision making for Inter-BTS (Intra-BSC) Handover.  This
 * only implements the handover algorithm/decision, but not execution
 * of it */

/* (C) 2009 by Harald Welte <laforge@gnumonks.org>
 *
 * All Rights Reserved
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 */

#include <stdlib.h>
#include <errno.h>

#include <openbsc/msgb.h>
#include <openbsc/debug.h>
#include <openbsc/gsm_data.h>
#include <openbsc/meas_rep.h>
#include <openbsc/signal.h>
#include <openbsc/talloc.h>
#include <openbsc/handover.h>

static int handover_to_arfcn_bsic(struct gsm_lchan *lchan,
				  u_int16_t arfcn, u_int8_t bsic)
{
	struct gsm_bts *new_bts;

	/* resolve the gsm_bts structure for the best neighbor */
	new_bts = gsm_bts_neighbor(lchan->ts->trx->bts, arfcn, bsic);
	if (!new_bts) {
		DEBUGP(DHO, "unable to determine neighbor BTS for ARFCN %u BSIC %u ?!?\n", arfcn, bsic);
		return -EINVAL;
	}

	/* and actually try to handover to that cell */
	return bsc_handover_start(lchan, new_bts);
}

#define RXLEV_HYST 3

/* process an already parsed measurement report */
static int process_meas_rep(struct gsm_meas_rep *mr)
{
	struct gsm_meas_rep_cell *mr_cell = NULL;
	unsigned int best_better_db;
	int i;

	DEBUGP(DHO, "process meas res: ");

	/* FIXME: implement actual averaging over multiple measurement
	 * reports */

	/* find the best cell in this report that is at least RXLEV_HYST
	 * better than the current serving cell */
	for (i = 0; i < mr->num_cell; i++) {
		unsigned int better;
		if (mr->cell[i].rxlev < mr->dl.full.rx_lev + RXLEV_HYST)
			continue;

		better = mr->cell[i].rxlev - mr->dl.full.rx_lev;
		if (better > best_better_db) {
			mr_cell = &mr->cell[i];
			best_better_db = better;
		}
	}

	if (mr_cell) {
		DEBUGPC(DHO, "Cell on ARFCN %u is better, starting handover\n", mr_cell->arfcn);
		return handover_to_arfcn_bsic(mr->lchan, mr_cell->arfcn,
						mr_cell->bsic);
	}

	DEBUGPC(DHO, "No better cell\n");
	return 0;
}

static int ho_dec_sig_cb(unsigned int subsys, unsigned int signal,
			   void *handler_data, void *signal_data)
{
	struct gsm_meas_rep *mr;

	if (subsys != SS_LCHAN)
		return 0;

	switch (signal) {
	case S_LCHAN_MEAS_REP:
		mr = signal_data;
		process_meas_rep(mr);
		break;
	}

	return 0;
}

void on_dso_load_ho_dec(void)
{
	register_signal_handler(SS_LCHAN, ho_dec_sig_cb, NULL);
}
