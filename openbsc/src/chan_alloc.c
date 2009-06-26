/* GSM Channel allocation routines
 *
 * (C) 2008 by Harald Welte <laforge@gnumonks.org>
 * (C) 2008, 2009 by Holger Hans Peter Freyther <zecke@selfish.org>
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include <openbsc/gsm_data.h>
#include <openbsc/chan_alloc.h>
#include <openbsc/abis_nm.h>
#include <openbsc/abis_rsl.h>
#include <openbsc/debug.h>
#include <openbsc/signal.h>

static void auto_release_channel(void *_lchan);

struct gsm_bts_trx_ts *ts_c0_alloc(struct gsm_bts *bts,
				   enum gsm_phys_chan_config pchan)
{
	struct gsm_bts_trx *trx = &bts->trx[0];	
	struct gsm_bts_trx_ts *ts = &trx->ts[0];

	if (pchan != GSM_PCHAN_CCCH &&
	    pchan != GSM_PCHAN_CCCH_SDCCH4)
		return NULL;

	if (ts->pchan != GSM_PCHAN_NONE)
		return NULL;

	ts->pchan = pchan;

	return ts;
}

static const enum abis_nm_chan_comb chcomb4pchan[] = {
	[GSM_PCHAN_CCCH]	= NM_CHANC_mainBCCH,
	[GSM_PCHAN_CCCH_SDCCH4]	= NM_CHANC_BCCHComb,
	[GSM_PCHAN_TCH_F]	= NM_CHANC_TCHFull,
	[GSM_PCHAN_TCH_H]	= NM_CHANC_TCHHalf,
	[GSM_PCHAN_SDCCH8_SACCH8C] = NM_CHANC_SDCCH,
	/* FIXME: bounds check */
};

/* Allocate a physical channel (TS) */
struct gsm_bts_trx_ts *ts_alloc(struct gsm_bts *bts,
				enum gsm_phys_chan_config pchan)
{
	int i, j;
	for (i = 0; i < bts->num_trx; i++) {
		struct gsm_bts_trx *trx = &bts->trx[i];
		int from, to;

		/* the following constraints are pure policy,
		 * no requirement to put this restriction in place */
		switch (pchan) {
		case GSM_PCHAN_CCCH:
		case GSM_PCHAN_CCCH_SDCCH4:
			from = 0; to = 0;
			break;
		case GSM_PCHAN_SDCCH8_SACCH8C:
			from = 1; to = 1;
			break;
		case GSM_PCHAN_TCH_F:
		case GSM_PCHAN_TCH_H:
			from = 2; to = 7;
			break;
		default:
			return NULL;
		}

		for (j = from; j <= to; j++) {
			struct gsm_bts_trx_ts *ts = &trx->ts[j];
			if (ts->pchan == GSM_PCHAN_NONE) {
				ts->pchan = pchan;
				/* set channel attribute on OML */
				abis_nm_set_channel_attr(ts, chcomb4pchan[pchan]);
				return ts;
			}
		}
	}
	return NULL;
}

/* Free a physical channel (TS) */
void ts_free(struct gsm_bts_trx_ts *ts)
{
	ts->pchan = GSM_PCHAN_NONE;
}

static const u_int8_t subslots_per_pchan[] = {
	[GSM_PCHAN_NONE] = 0,
	[GSM_PCHAN_CCCH] = 0,
	[GSM_PCHAN_CCCH_SDCCH4] = 4,
	[GSM_PCHAN_TCH_F] = 1,
	[GSM_PCHAN_TCH_H] = 2,
	[GSM_PCHAN_SDCCH8_SACCH8C] = 8,
};

static struct gsm_lchan *
_lc_find(struct gsm_bts *bts, enum gsm_phys_chan_config pchan)
{
	struct gsm_bts_trx *trx;
	struct gsm_bts_trx_ts *ts;
	int i, j, ss;
	for (i = 0; i < bts->num_trx; i++) {
		trx = &bts->trx[i];
		for (j = 0; j < 8; j++) {
			ts = &trx->ts[j];
			if (ts->pchan != pchan)
				continue;
			/* check if all sub-slots are allocated yet */
			for (ss = 0; ss < subslots_per_pchan[pchan]; ss++) {
				struct gsm_lchan *lc = &ts->lchan[ss];
				if (lc->type == GSM_LCHAN_NONE)
					return lc;
			}
		}
	}
	/* we cannot allocate more of these */
	if (pchan == GSM_PCHAN_CCCH_SDCCH4)
		return NULL;

	/* if we've reached here, we need to allocate a new physical
	 * channel for the logical channel type requested */
	ts = ts_alloc(bts, pchan);
	if (!ts) {
		/* no more radio resources */
		return NULL;
	}
	return &ts->lchan[0];
}

/* Allocate a logical channel */
struct gsm_lchan *lchan_alloc(struct gsm_bts *bts, enum gsm_chan_t type)
{
	struct gsm_lchan *lchan = NULL;

	switch (type) {
	case GSM_LCHAN_SDCCH:
		lchan = _lc_find(bts, GSM_PCHAN_CCCH_SDCCH4);
		if (lchan == NULL)
			lchan = _lc_find(bts, GSM_PCHAN_SDCCH8_SACCH8C);
		break;
	case GSM_LCHAN_TCH_F:
		lchan = _lc_find(bts, GSM_PCHAN_TCH_F);
		break;
	case GSM_LCHAN_TCH_H:
		lchan =_lc_find(bts, GSM_PCHAN_TCH_H);
		break;
	default:
		fprintf(stderr, "Unknown gsm_chan_t %u\n", type);
	}

	if (lchan) {
		lchan->type = type;
		lchan->use_count = 0;

		/* Configure the time and start it so it will be closed */
		lchan->release_timer.cb = auto_release_channel;
		lchan->release_timer.data = lchan;
		bsc_schedule_timer(&lchan->release_timer, LCHAN_RELEASE_TIMEOUT);
	}

	return lchan;
}

/* Free a logical channel */
void lchan_free(struct gsm_lchan *lchan)
{
	lchan->type = GSM_LCHAN_NONE;
	if (lchan->subscr) {
		subscr_put(lchan->subscr);
		lchan->subscr = 0;
	}

	/* We might kill an active channel... */
	if (lchan->use_count != 0) {
		dispatch_signal(SS_LCHAN, S_LCHAN_UNEXPECTED_RELEASE, lchan);
		lchan->use_count = 0;
	}

	/* stop the timer */
	bsc_del_timer(&lchan->release_timer);

	/* FIXME: ts_free() the timeslot, if we're the last logical
	 * channel using it */
}

/* Consider releasing the channel now */
int lchan_auto_release(struct gsm_lchan *lchan)
{
	if (lchan->use_count > 0) {
		return 0;
	}

	/* Assume we have GSM04.08 running and send a release */
	if (lchan->subscr) {
		gsm48_send_rr_release(lchan);
	}

	/* spoofed? message */
	if (lchan->use_count < 0) {
		DEBUGP(DRLL, "Channel count is negative: %d\n", lchan->use_count);
	}

	DEBUGP(DRLL, "Recycling the channel with: %d (%x)\n", lchan->nr, lchan->nr);
	rsl_chan_release(lchan);
	return 1;
}

/* Auto release the channel when the use count is zero */
static void auto_release_channel(void *_lchan)
{
	struct gsm_lchan *lchan = _lchan;

	if (!lchan_auto_release(lchan))
		bsc_schedule_timer(&lchan->release_timer, LCHAN_RELEASE_TIMEOUT);
}

struct gsm_lchan* lchan_find(struct gsm_bts *bts, struct gsm_subscriber *subscr) {
	int trx, ts_no, lchan_no; 

	for (trx = 0; trx < bts->num_trx; ++trx) {
		for (ts_no = 0; ts_no < 8; ++ts_no) {
			for (lchan_no = 0; lchan_no < TS_MAX_LCHAN; ++lchan_no) {
				struct gsm_lchan *lchan =
					&bts->trx[trx].ts[ts_no].lchan[lchan_no];
				if (subscr == lchan->subscr)
					return lchan;
			}
		}
	}

	return NULL;
}
