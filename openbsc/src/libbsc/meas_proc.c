/* Measurement Processing */

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

#include <osmocom/core/talloc.h>
#include <osmocom/core/msgb.h>
#include <openbsc/debug.h>
#include <openbsc/gsm_data.h>
#include <openbsc/meas_rep.h>
#include <openbsc/signal.h>

/* process an already parsed measurement report */
static int process_meas_rep(struct gsm_meas_rep *mr)
{
	struct gsm_meas_rep_cell *mr_cell = NULL;
	unsigned int best_better_db;
	int i;

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

	if (mr_cell)
		return handover_to_arfcn_bsic(mr->lchan, mr_cell->arfcn,
						mr_cell->bsic);
	return 0;
}

static int meas_proc_sig_cb(unsigned int subsys, unsigned int signal,
			   void *handler_data, void *signal_data)
{
	struct gsm_lchan *lchan;
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

static __attribute__((constructor)) void on_dso_load_meas(void)
{
	osmo_signal_register_handler(SS_LCHAN, meas_proc_sig_cb, NULL);
}
