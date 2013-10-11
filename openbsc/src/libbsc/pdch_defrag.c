/* (C) 2013 by Andreas Eversberg <andreas@eversberg.eu>
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
#include <stdbool.h>
#include <errno.h>

#include <openbsc/debug.h>
#include <openbsc/gsm_data.h>
#include <openbsc/handover.h>
#include <openbsc/pdch_defrag.h>
#include <openbsc/chan_alloc.h>

static struct gsm_lchan *find_lchan(struct gsm_bts *bts,
				    enum gsm_phys_chan_config type,
				    bool forward)
{
	struct gsm_bts_trx *trx;
	struct gsm_lchan *lc;
	int i, start, stop, dir;

	if (forward) {
		/* check TS 0..7 */
		start = 0;
		stop = 8;
		dir = 1;
	} else {
		/* check TS 7..0 */
		start = 7;
		stop = -1;
		dir = -1;
	}

	llist_for_each_entry(trx, &bts->trx_list, list) {
		for (i = start; i != stop; i += dir) {
			if (trx->ts[i].pchan == type) {
				lc = &trx->ts[i].lchan[0];
				if (lc->state == LCHAN_S_ACTIVE)
					return lc;
			}
		}
	}

	return NULL;
}

#define LOGTSP(ss, ll, ts, fmt, args...) \
	LOGP(ss, ll, "(BTS %u, TRX %u, TS %u) " fmt, \
	     ts->trx->bts->nr, ts->trx->nr, ts->nr, \
	     ##args)

/* Defragment TCH/F+PDCH channels to remove gaps between active
 * GSM_PCHAN_TCH_F_PDCH slots. Assign active connections to standard TCH/F or
 * to consecutive TCH/F+PDCH channels.
 *
 * This function depends on being re-triggered whenever a channel has been
 * released: each reassignment for defragmentation includes a channel release,
 * which should trigger another invocation, and defragmentation will continue.
 *
 * Look up the last active TCH/F+PDCH (highest TRX/TS number). If there
 * is a TCH/F or a free TCH/F+PDCH on a lower TRX/TS number, re-assign it.
 * If allocation order is reversed, re-assign in reverse direction instead.
 */
void do_pdch_defrag(struct gsm_bts *bts)
{
	struct gsm_lchan *old_lchan = NULL, *new_lchan;
	int rc;
	int want_dir;
	int is_dir;

	/* Find the "last" lchan in use, according to chan_alloc_reverse: if
	 * reversed, find the highest-numbered lchan == start looking from the
	 * back. */
	old_lchan = find_lchan(bts, GSM_PCHAN_TCH_F_PDCH,
			       bts->chan_alloc_reverse? true : false);

	/* if there is no candidate on GSM_PCHAN_TCH_F_PDCH, we are done */
	/* FIXME: for multi-TRX, if the first TRX's last lchan doesn't need
	 * re-assignment, the other TRXes are not going to be checked. */
	if (!old_lchan)
		return;

	LOGTSP(DHODEC, LOGL_DEBUG, old_lchan->ts,
	       "A shared TCH/F+PDCH is in use, check for reassignment.\n");

	/* allocate new lchan */
	new_lchan = lchan_alloc(bts, GSM_LCHAN_TCH_F, 0);
	/* no free destination for candidate */
	if (!new_lchan) {
		LOGTSP(DHODEC, LOGL_DEBUG, old_lchan->ts,
		       "-> Cannot move, no other TCH/F available.\n");
		return;
	}

	/* if new TS is also a GSM_PCHAN_TCH_F_PDCH */
	if (new_lchan->ts->pchan == GSM_PCHAN_TCH_F_PDCH) {
		LOGTSP(DHODEC, LOGL_DEBUG, new_lchan->ts,
		       "<- New channel for candidate is also a TCH/F+PDCH.\n");
		/* be sure to move to lower number (or to higher number in case
		 * of reverse allocation) */
		want_dir = bts->chan_alloc_reverse ? 1 : -1;
		is_dir = new_lchan->ts->trx->nr - old_lchan->ts->trx->nr;

		if (is_dir == 0) {
			/* TRX number stays the same, check TS numbers. */
			is_dir = new_lchan->ts->nr - old_lchan->ts->nr;
		}

		/* If is_dir were 0 here, new_lchan == old_lchan, which should
		 * never happen. Even if it does, that would mean no decrease
		 * in fragmentation... */

		if ((is_dir > 0) != (want_dir > 0)) {
			LOGP(DHODEC, LOGL_DEBUG,
			     "-> Move does not lower fragmentation:"
			     " TRX %u TS %u to TRX %u TS %u%s\n",
			     old_lchan->ts->trx->nr, old_lchan->ts->nr,
			     new_lchan->ts->trx->nr, new_lchan->ts->nr,
			     bts->chan_alloc_reverse ? " (reverse allocation)" : "");
			lchan_free(new_lchan);
			return;
		}
	} else {
		LOGTSP(DHODEC, LOGL_DEBUG, new_lchan->ts,
		       "<- New channel for candidate is a TCH/F.\n");
	}

	rc = bsc_handover_start(old_lchan, new_lchan, new_lchan->ts->trx->bts);
	if (rc) {
		LOGP(DHODEC, LOGL_NOTICE,
		     "Cannot trigger assignment to defragment TCH/F+PDCH slots.\n");
	} else {
		LOGP(DHODEC, LOGL_NOTICE,
		     "Triggered assignment to defragment TCH/F+PDCH slots.\n");
	}

	/* We do not need to take further action here regardless of
	 * re-assignment success or failure, because in both cases a channel is
	 * freed, and this defragmentation should be triggered again.
	 */
	/* FIXME: does re-assignment failure mean infinite looping/recursion!? */
}

