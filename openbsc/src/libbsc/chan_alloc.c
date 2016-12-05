/* GSM Channel allocation routines
 *
 * (C) 2008 by Harald Welte <laforge@gnumonks.org>
 * (C) 2008, 2009 by Holger Hans Peter Freyther <zecke@selfish.org>
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include <openbsc/gsm_subscriber.h>
#include <openbsc/chan_alloc.h>
#include <openbsc/abis_nm.h>
#include <openbsc/abis_rsl.h>
#include <openbsc/debug.h>
#include <openbsc/rtp_proxy.h>
#include <openbsc/signal.h>

#include <osmocom/core/talloc.h>

static int ts_is_usable(struct gsm_bts_trx_ts *ts)
{
	/* FIXME: How does this behave for BS-11 ? */
	if (is_ipaccess_bts(ts->trx->bts)) {
		if (!nm_is_running(&ts->mo.nm_state))
			return 0;
	}

	/* If a TCH/F_PDCH TS is busy changing, it is already taken or not
	 * yet available. */
	if (ts->pchan == GSM_PCHAN_TCH_F_PDCH) {
		if (ts->flags & TS_F_PDCH_PENDING_MASK)
			return 0;
	}

	/* If a dynamic channel is busy changing, it is already taken or not
	 * yet available. */
	if (ts->pchan == GSM_PCHAN_TCH_F_TCH_H_PDCH) {
		if (ts->dyn.pchan_is != ts->dyn.pchan_want)
			return 0;
	}

	return 1;
}

int trx_is_usable(struct gsm_bts_trx *trx)
{
	/* FIXME: How does this behave for BS-11 ? */
	if (is_ipaccess_bts(trx->bts)) {
		if (!nm_is_running(&trx->mo.nm_state) ||
		    !nm_is_running(&trx->bb_transc.mo.nm_state))
			return 0;
	}

	return 1;
}

static struct gsm_lchan *
_lc_find_trx(struct gsm_bts_trx *trx, enum gsm_phys_chan_config pchan,
	     enum gsm_phys_chan_config dyn_as_pchan)
{
	struct gsm_bts_trx_ts *ts;
	int j, start, stop, dir, ss;
	int check_subslots;

	if (!trx_is_usable(trx))
		return NULL;

	if (trx->bts->chan_alloc_reverse) {
		/* check TS 7..0 */
		start = 7;
		stop = -1;
		dir = -1;
	} else {
		/* check TS 0..7 */
		start = 0;
		stop = 8;
		dir = 1;
	}

	for (j = start; j != stop; j += dir) {
		ts = &trx->ts[j];
		if (!ts_is_usable(ts))
			continue;
		if (ts->pchan != pchan)
			continue;

		/*
		 * Allocation for fully dynamic timeslots
		 * (does not apply for ip.access style GSM_PCHAN_TCH_F_PDCH)
		 *
		 * Note the special nature of a dynamic timeslot in PDCH mode:
		 * in PDCH mode, typically, lchan->type is GSM_LCHAN_NONE and
		 * lchan->state is LCHAN_S_NONE -- an otherwise unused slot
		 * becomes PDCH implicitly. In the same sense, this channel
		 * allocator will never be asked to find an available PDCH
		 * slot; only TCH/F or TCH/H will be requested, and PDCH mode
		 * means that it is available for switchover.
		 *
		 * A dynamic timeslot in PDCH mode may be switched to TCH/F or
		 * TCH/H. If a dyn TS is already in TCH/F or TCH/H mode, it
		 * means that it is in use and its mode can't be switched.
		 *
		 * The logic concerning channels for TCH/F is trivial: there is
		 * only one channel, so a dynamic TS in TCH/F mode is already
		 * taken and not available for allocation. For TCH/H, we need
		 * to check whether a dynamic timeslot is already in TCH/H mode
		 * and whether one of the two channels is still available.
		 */
		switch (pchan) {
		case GSM_PCHAN_TCH_F_TCH_H_PDCH:
			if (ts->dyn.pchan_is != ts->dyn.pchan_want) {
				/* The TS's mode is being switched. Not
				 * available anymore/yet. */
				DEBUGP(DRLL, "%s already in switchover\n",
				       gsm_ts_and_pchan_name(ts));
				continue;
			}
			if (ts->dyn.pchan_is == GSM_PCHAN_PDCH) {
				/* This slot is available. Still check for
				 * error states to be sure; in all cases the
				 * first lchan will be used. */
				if (ts->lchan->state != LCHAN_S_NONE
				    && ts->lchan->state != LCHAN_S_ACTIVE)
					continue;
				return ts->lchan;
			}
			if (ts->dyn.pchan_is != dyn_as_pchan)
				/* not applicable. */
				continue;
			/* The requested type matches the dynamic timeslot's
			 * current mode. A channel may still be available
			 * (think TCH/H). */
			check_subslots = ts_subslots(ts);
			break;

		case GSM_PCHAN_TCH_F_PDCH:
			/* Available for voice when in PDCH mode */
			if (ts_pchan(ts) != GSM_PCHAN_PDCH)
				continue;
			/* Subslots of a PDCH ts don't need to be checked. */
			return ts->lchan;

		default:
			/* Not a dynamic channel, there is only one pchan kind: */
			check_subslots = ts_subslots(ts);
			break;
		}

		/* Is a sub-slot still available? */
		for (ss = 0; ss < check_subslots; ss++) {
			struct gsm_lchan *lc = &ts->lchan[ss];
			if (lc->type == GSM_LCHAN_NONE &&
			    lc->state == LCHAN_S_NONE)
				return lc;
		}
	}

	return NULL;
}

static struct gsm_lchan *
_lc_dyn_find_bts(struct gsm_bts *bts, enum gsm_phys_chan_config pchan,
		 enum gsm_phys_chan_config dyn_as_pchan)
{
	struct gsm_bts_trx *trx;
	struct gsm_lchan *lc;

	if (bts->chan_alloc_reverse) {
		llist_for_each_entry_reverse(trx, &bts->trx_list, list) {
			lc = _lc_find_trx(trx, pchan, dyn_as_pchan);
			if (lc)
				return lc;
		}
	} else {
		llist_for_each_entry(trx, &bts->trx_list, list) {
			lc = _lc_find_trx(trx, pchan, dyn_as_pchan);
			if (lc)
				return lc;
		}
	}

	return NULL;
}

static struct gsm_lchan *
_lc_find_bts(struct gsm_bts *bts, enum gsm_phys_chan_config pchan)
{
	return _lc_dyn_find_bts(bts, pchan, GSM_PCHAN_NONE);
}

/* Allocate a logical channel.
 *
 * Dynamic channel types: we always prefer a dedicated TS, and only pick +
 * switch a dynamic TS if no pure TS of the requested PCHAN is available.
 *
 * TCH_F/PDCH: if we pick a PDCH ACT style dynamic TS as TCH/F channel, PDCH
 * will be disabled in rsl_chan_activate_lchan(); there is no need to check
 * whether PDCH mode is currently active, here.
 */
struct gsm_lchan *lchan_alloc(struct gsm_bts *bts, enum gsm_chan_t type,
			      int allow_bigger)
{
	struct gsm_lchan *lchan = NULL;
	enum gsm_phys_chan_config first, first_cbch, second, second_cbch;

	switch (type) {
	case GSM_LCHAN_SDCCH:
		if (bts->chan_alloc_reverse) {
			first = GSM_PCHAN_SDCCH8_SACCH8C;
			first_cbch = GSM_PCHAN_SDCCH8_SACCH8C_CBCH;
			second = GSM_PCHAN_CCCH_SDCCH4;
			second_cbch = GSM_PCHAN_CCCH_SDCCH4_CBCH;
		} else {
			first = GSM_PCHAN_CCCH_SDCCH4;
			first_cbch = GSM_PCHAN_CCCH_SDCCH4_CBCH;
			second = GSM_PCHAN_SDCCH8_SACCH8C;
			second_cbch = GSM_PCHAN_SDCCH8_SACCH8C_CBCH;
		}

		lchan = _lc_find_bts(bts, first);
		if (lchan == NULL)
			lchan = _lc_find_bts(bts, first_cbch);
		if (lchan == NULL)
			lchan = _lc_find_bts(bts, second);
		if (lchan == NULL)
			lchan = _lc_find_bts(bts, second_cbch);

		/* allow to assign bigger channels */
		if (allow_bigger) {
			if (lchan == NULL) {
				lchan = _lc_find_bts(bts, GSM_PCHAN_TCH_H);
				if (lchan)
					type = GSM_LCHAN_TCH_H;
			}

			if (lchan == NULL) {
				lchan = _lc_find_bts(bts, GSM_PCHAN_TCH_F);
				if (lchan)
					type = GSM_LCHAN_TCH_F;
			}

			/* try dynamic TCH/F_PDCH */
			if (lchan == NULL) {
				lchan = _lc_find_bts(bts, GSM_PCHAN_TCH_F_PDCH);
				/* TCH/F_PDCH will be used as TCH/F */
				if (lchan)
					type = GSM_LCHAN_TCH_F;
			}

			/* try fully dynamic TCH/F_TCH/H_PDCH */
			if (lchan == NULL) {
				lchan = _lc_dyn_find_bts(bts, GSM_PCHAN_TCH_F_TCH_H_PDCH,
							 GSM_PCHAN_TCH_H);
				if (lchan)
					type = GSM_LCHAN_TCH_H;
			}
			/*
			 * No need to check fully dynamic channels for TCH/F:
			 * if no TCH/H was available, neither will be TCH/F.
			 */
		}
		break;
	case GSM_LCHAN_TCH_F:
		lchan = _lc_find_bts(bts, GSM_PCHAN_TCH_F);
		/* If we don't have TCH/F available, fall-back to TCH/H */
		if (!lchan) {
			lchan = _lc_find_bts(bts, GSM_PCHAN_TCH_H);
			if (lchan)
				type = GSM_LCHAN_TCH_H;
		}
		/* If we don't have TCH/H either, try dynamic TCH/F_PDCH */
		if (!lchan) {
			lchan = _lc_find_bts(bts, GSM_PCHAN_TCH_F_PDCH);
			/* TCH/F_PDCH used as TCH/F -- here, type is already
			 * set to GSM_LCHAN_TCH_F, but for clarity's sake... */
			if (lchan)
				type = GSM_LCHAN_TCH_F;
		}

		/* Try fully dynamic TCH/F_TCH/H_PDCH as TCH/F... */
		if (!lchan && bts->network->dyn_ts_allow_tch_f) {
			lchan = _lc_dyn_find_bts(bts,
						 GSM_PCHAN_TCH_F_TCH_H_PDCH,
						 GSM_PCHAN_TCH_F);
			if (lchan)
				type = GSM_LCHAN_TCH_F;
		}
		/* ...and as TCH/H. */
		if (!lchan) {
			lchan = _lc_dyn_find_bts(bts,
						 GSM_PCHAN_TCH_F_TCH_H_PDCH,
						 GSM_PCHAN_TCH_H);
			if (lchan)
				type = GSM_LCHAN_TCH_H;
		}
		break;
	case GSM_LCHAN_TCH_H:
		lchan = _lc_find_bts(bts, GSM_PCHAN_TCH_H);
		/* If we don't have TCH/H available, fall-back to TCH/F */
		if (!lchan) {
			lchan = _lc_find_bts(bts, GSM_PCHAN_TCH_F);
			if (lchan)
				type = GSM_LCHAN_TCH_F;
		}
		/* No dedicated TCH/x available -- try fully dynamic
		 * TCH/F_TCH/H_PDCH */
		if (!lchan) {
			lchan = _lc_dyn_find_bts(bts,
						 GSM_PCHAN_TCH_F_TCH_H_PDCH,
						 GSM_PCHAN_TCH_H);
			if (lchan)
				type = GSM_LCHAN_TCH_H;
		}
		/*
		 * No need to check TCH/F_TCH/H_PDCH channels for TCH/F:
		 * if no TCH/H was available, neither will be TCH/F.
		 */
		/* If we don't have TCH/F either, try dynamic TCH/F_PDCH */
		if (!lchan) {
			lchan = _lc_find_bts(bts, GSM_PCHAN_TCH_F_PDCH);
			if (lchan)
				type = GSM_LCHAN_TCH_F;
		}
		break;
	default:
		LOGP(DRLL, LOGL_ERROR, "Unknown gsm_chan_t %u\n", type);
	}

	if (lchan) {
		lchan->type = type;

		LOGP(DRLL, LOGL_INFO, "%s Allocating lchan=%u as %s\n",
		     gsm_ts_and_pchan_name(lchan->ts),
		     lchan->nr, gsm_lchant_name(lchan->type));

		/* clear sapis */
		memset(lchan->sapis, 0, ARRAY_SIZE(lchan->sapis));

		/* clear multi rate config */
		memset(&lchan->mr_ms_lv, 0, sizeof(lchan->mr_ms_lv));
		memset(&lchan->mr_bts_lv, 0, sizeof(lchan->mr_bts_lv));
		lchan->broken_reason = "";
	} else {
		struct challoc_signal_data sig;

		LOGP(DRLL, LOGL_ERROR, "Failed to allocate %s channel\n",
		     gsm_lchant_name(type));

		sig.bts = bts;
		sig.type = type;
		osmo_signal_dispatch(SS_CHALLOC, S_CHALLOC_ALLOC_FAIL, &sig);
	}

	return lchan;
}

/* Free a logical channel */
void lchan_free(struct gsm_lchan *lchan)
{
	struct challoc_signal_data sig;
	int i;

	sig.type = lchan->type;
	lchan->type = GSM_LCHAN_NONE;


	if (lchan->conn) {
		struct lchan_signal_data sig;

		/* We might kill an active channel... */
		sig.lchan = lchan;
		sig.mr = NULL;
		osmo_signal_dispatch(SS_LCHAN, S_LCHAN_UNEXPECTED_RELEASE, &sig);
	}

	if (lchan->abis_ip.rtp_socket) {
		LOGP(DRLL, LOGL_ERROR, "%s RTP Proxy Socket remained open.\n",
			gsm_lchan_name(lchan));
		rtp_socket_free(lchan->abis_ip.rtp_socket);
		lchan->abis_ip.rtp_socket = NULL;
	}

	/* stop the timer */
	osmo_timer_del(&lchan->T3101);

	/* clear cached measuement reports */
	lchan->meas_rep_idx = 0;
	for (i = 0; i < ARRAY_SIZE(lchan->meas_rep); i++) {
		lchan->meas_rep[i].flags = 0;
		lchan->meas_rep[i].nr = 0;
	}
	for (i = 0; i < ARRAY_SIZE(lchan->neigh_meas); i++)
		lchan->neigh_meas[i].arfcn = 0;

	if (lchan->rqd_ref) {
		talloc_free(lchan->rqd_ref);
		lchan->rqd_ref = NULL;
		lchan->rqd_ta = 0;
	}

	sig.lchan = lchan;
	sig.bts = lchan->ts->trx->bts;
	osmo_signal_dispatch(SS_CHALLOC, S_CHALLOC_FREED, &sig);

	if (lchan->conn) {
		LOGP(DRLL, LOGL_ERROR, "the subscriber connection should be gone.\n");
		lchan->conn = NULL;
	}

	/* FIXME: ts_free() the timeslot, if we're the last logical
	 * channel using it */
}

/*
 * There was an error with the TRX and we need to forget
 * any state so that a lchan can be allocated again after
 * the trx is fully usable.
 *
 * This should be called after lchan_free to force a channel
 * be available for allocation again. This means that this
 * method will stop the "delay after error"-timer and set the
 * state to LCHAN_S_NONE.
 */
void lchan_reset(struct gsm_lchan *lchan)
{
	osmo_timer_del(&lchan->T3101);
	osmo_timer_del(&lchan->T3109);
	osmo_timer_del(&lchan->T3111);
	osmo_timer_del(&lchan->error_timer);

	lchan->type = GSM_LCHAN_NONE;
	lchan->state = LCHAN_S_NONE;

	if (lchan->abis_ip.rtp_socket) {
		rtp_socket_free(lchan->abis_ip.rtp_socket);
		lchan->abis_ip.rtp_socket = NULL;
	}
}

/* Drive the release process of the lchan */
static void _lchan_handle_release(struct gsm_lchan *lchan,
				  int sacch_deact, int mode)
{
	/* Release all SAPIs on the local end and continue */
	rsl_release_sapis_from(lchan, 1, RSL_REL_LOCAL_END);

	/*
	 * Shall we send a RR Release, start T3109 and wait for the
	 * release indication from the BTS or just take it down (e.g.
	 * on assignment requests)
	 */
	if (sacch_deact) {
		gsm48_send_rr_release(lchan);

		/* Deactivate the SACCH on the BTS side */
		rsl_deact_sacch(lchan);
		rsl_start_t3109(lchan);
	} else if (lchan->sapis[0] == LCHAN_SAPI_UNUSED) {
		rsl_direct_rf_release(lchan);
	} else {
		rsl_release_request(lchan, 0, mode);
	}
}

/* Consider releasing the channel now */
int lchan_release(struct gsm_lchan *lchan, int sacch_deact, enum rsl_rel_mode mode)
{
	DEBUGP(DRLL, "%s starting release sequence\n", gsm_lchan_name(lchan));
	rsl_lchan_set_state(lchan, LCHAN_S_REL_REQ);

	lchan->conn = NULL;
	_lchan_handle_release(lchan, sacch_deact, mode);
	return 1;
}

void bts_chan_load(struct pchan_load *cl, const struct gsm_bts *bts)
{
	struct gsm_bts_trx *trx;

	llist_for_each_entry(trx, &bts->trx_list, list) {
		int i;

		/* skip administratively deactivated tranxsceivers */
		if (!nm_is_running(&trx->mo.nm_state) ||
		    !nm_is_running(&trx->bb_transc.mo.nm_state))
			continue;

		for (i = 0; i < ARRAY_SIZE(trx->ts); i++) {
			struct gsm_bts_trx_ts *ts = &trx->ts[i];
			struct load_counter *pl = &cl->pchan[ts->pchan];
			int j;
			int subslots;

			/* skip administratively deactivated timeslots */
			if (!nm_is_running(&ts->mo.nm_state))
				continue;

			subslots = ts_subslots(ts);
			for (j = 0; j < subslots; j++) {
				struct gsm_lchan *lchan = &ts->lchan[j];

				pl->total++;

				switch (lchan->state) {
				case LCHAN_S_NONE:
					break;
				default:
					pl->used++;
					break;
				}
			}
		}
	}
}

void network_chan_load(struct pchan_load *pl, struct gsm_network *net)
{
	struct gsm_bts *bts;

	memset(pl, 0, sizeof(*pl));

	llist_for_each_entry(bts, &net->bts_list, list)
		bts_chan_load(pl, bts);
}

