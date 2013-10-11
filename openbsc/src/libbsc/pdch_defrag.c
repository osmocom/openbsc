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
#include <errno.h>

#include <openbsc/debug.h>
#include <openbsc/gsm_data.h>
#include <openbsc/handover.h>
#include <openbsc/pdch_defrag.h>
#include <openbsc/chan_alloc.h>

static struct gsm_lchan *find_shared_forward(struct gsm_bts *bts)
{
	struct gsm_bts_trx *trx;
	struct gsm_lchan *lc;
	int j;

	llist_for_each_entry(trx, &bts->trx_list, list) {
		for (j = 0; j < 8; j++) {
			/* find first TCH/F+PDCH */
			if (trx->ts[j].pchan == GSM_PCHAN_TCH_F_PDCH) {
				lc = &trx->ts[j].lchan[0];
				if (lc->state == LCHAN_S_ACTIVE)
					return lc;
			}
		}
	}

	return NULL;
}

static struct gsm_lchan *find_shared_reverse(struct gsm_bts *bts)
{
	struct gsm_bts_trx *trx;
	struct gsm_lchan *lc;
	int j;

	llist_for_each_entry_reverse(trx, &bts->trx_list, list) {
		for (j = 7; j >= 0; j--) {
			/* find last TCH/F+PDCH */
			if (trx->ts[j].pchan == GSM_PCHAN_TCH_F_PDCH) {
				lc = &trx->ts[j].lchan[0];
				if (lc->state == LCHAN_S_ACTIVE)
					return lc;
			}
		}
	}

	return NULL;
}

static void debug_bts_trx_ts(struct gsm_bts_trx_ts *ts)
{
	LOGPC(DHODEC, LOGL_DEBUG, " (BTS %u, TRX %u, TS %u)\n",
		ts->trx->bts->nr, ts->trx->nr, ts->nr);
}

/* Try to move a TCH/F+PDCH candidate to maintain as much free and consecutive
 * GSM_PCHAN_TCH_F_PDCH slots as possible.
 *
 * This algorithm is triggered whenever a channel has been released.
 *
 * The last (highest TRX/TS number) and active TCH/F+PDCH is searched. If there
 * is a TCH/F or a free TCH/F+PDCH on a lower TRX/TS number, assignment is
 * triggered. (When allocation order is reversed, this algorithm handles TRX/TS
 * numbers in reversed order also.
 *
 * This algorithm ensures that gaps between active TCH/F+PDCH channels are
 * removed, by assigning active connections to standard TCH/F or by assigning
 * them to consecutive TCH/F+PDCH channels.
 */
void do_pdch_defrag(struct gsm_bts *bts)
{
	struct gsm_lchan *old_lchan = NULL, *new_lchan;
	int rc;

	/* search TCH/F+PDCH in reverse order of allocation */
	if (bts->chan_alloc_reverse) {
		/* search from first to last TRX/TS */
		old_lchan = find_shared_forward(bts);
	} else {
		/* search from last to first TRX/TS */
		old_lchan = find_shared_reverse(bts);
	}

	/* if there is no candidate on GSM_PCHAN_TCH_F_PDCH, we are done */
	if (!old_lchan)
		return;

	LOGP(DHODEC, LOGL_DEBUG, "A shared TCH/F+PDCH is in use, check if we "
		"can move connection.");
	debug_bts_trx_ts(old_lchan->ts);

	/* allocate new lchan */
	new_lchan = lchan_alloc(bts, GSM_LCHAN_TCH_F, 0);
	/* no free destination for candidate */
	if (!new_lchan) {
		LOGP(DHODEC, LOGL_DEBUG, "-> Cannot move, no other TCH/F "
			"available.\n");
		return;
	}

	/* if new TS is also a GSM_PCHAN_TCH_F_PDCH */
	if (new_lchan->ts->pchan == GSM_PCHAN_TCH_F_PDCH) {
		LOGP(DHODEC, LOGL_DEBUG, "-> New channel for candidate is also "
			"a TCH/F+PDCH.");
		debug_bts_trx_ts(new_lchan->ts);
		/* be sure to move down (or up at reverse allocation) */
		if (bts->chan_alloc_reverse) {
			/* new TS is lower */
			if (new_lchan->ts->trx->nr < old_lchan->ts->trx->nr) {
				LOGP(DHODEC, LOGL_DEBUG, "-> Move does not "
					"lower fragmentation, new TRX has "
					"lower number.\n");
				goto free_lchan;
			}
			if (new_lchan->ts->trx->nr == old_lchan->ts->trx->nr
			 && new_lchan->ts->nr < old_lchan->ts->nr) {
				LOGP(DHODEC, LOGL_DEBUG, "-> Move does not "
					"lower fragmentation, new TS has "
					"lower number.\n");
				goto free_lchan;
			}
		} else {
			/* new TS is higher */
			if (new_lchan->ts->trx->nr > old_lchan->ts->trx->nr) {
				goto free_lchan;
				LOGP(DHODEC, LOGL_DEBUG, "-> Move does not "
					"lower fragmentation, new TRX has "
					"higher number.\n");
			}
			if (new_lchan->ts->trx->nr == old_lchan->ts->trx->nr
			 && new_lchan->ts->nr > old_lchan->ts->nr) {
				LOGP(DHODEC, LOGL_DEBUG, "-> Move does not "
					"lower fragmentation, new TS has "
					"higher number.\n");
				goto free_lchan;
			}
		}
	} else {
		LOGP(DHODEC, LOGL_DEBUG, "-> New channel for candidate is a "
			"TCH/F.");
		debug_bts_trx_ts(new_lchan->ts);
	}

	rc = bsc_handover_start(old_lchan, new_lchan, new_lchan->ts->trx->bts,
		1);
	if (rc) {
		LOGP(DHODEC, LOGL_NOTICE, "Cannot trigger assignment to "
			"defragment TCH/F+PDCH slots.\n");
	} else {
		LOGP(DHODEC, LOGL_NOTICE, "Triggered assignment to defragment "
			"TCH/F+PDCH slots.\n");
	}

	/* We do not need to check, if assignment is ongoing or if it fails,
	 * because in both cases a channel is freed, so this defragmentation
	 * is triggered again.
	 */

	return;

free_lchan:
	lchan_free(new_lchan);
}

