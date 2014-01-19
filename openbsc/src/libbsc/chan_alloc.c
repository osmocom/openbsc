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

static const uint8_t subslots_per_pchan[] = {
	[GSM_PCHAN_NONE] = 0,
	[GSM_PCHAN_CCCH] = 0,
	[GSM_PCHAN_CCCH_SDCCH4] = 4,
	[GSM_PCHAN_TCH_F] = 1,
	[GSM_PCHAN_TCH_H] = 2,
	[GSM_PCHAN_SDCCH8_SACCH8C] = 8,
	/* FIXME: what about dynamic TCH_F_TCH_H ? */
	[GSM_PCHAN_TCH_F_PDCH] = 1,
	[GSM_PCHAN_CCCH_SDCCH4_CBCH] = 4,
	[GSM_PCHAN_SDCCH8_SACCH8C_CBCH] = 8,
};

static struct gsm_lchan *
_lc_find_trx(struct gsm_bts_trx *trx, enum gsm_phys_chan_config pchan)
{
	struct gsm_bts_trx_ts *ts;
	int j, ss;

	if (!trx_is_usable(trx))
		return NULL;

	for (j = 0; j < 8; j++) {
		ts = &trx->ts[j];
		if (!ts_is_usable(ts))
			continue;
		/* ip.access dynamic TCH/F + PDCH combination */
		if (ts->pchan == GSM_PCHAN_TCH_F_PDCH &&
		    pchan == GSM_PCHAN_TCH_F) {
			/* we can only consider such a dynamic channel
			 * if the PDCH is currently inactive */
			if (ts->flags & TS_F_PDCH_MODE)
				continue;
		} else if (ts->pchan != pchan)
			continue;
		/* check if all sub-slots are allocated yet */
		for (ss = 0; ss < subslots_per_pchan[pchan]; ss++) {
			struct gsm_lchan *lc = &ts->lchan[ss];
			if (lc->type == GSM_LCHAN_NONE &&
			    lc->state == LCHAN_S_NONE)
				return lc;
		}
	}

	return NULL;
}

static struct gsm_lchan *
_lc_find_bts(struct gsm_bts *bts, enum gsm_phys_chan_config pchan)
{
	struct gsm_bts_trx *trx;
	struct gsm_lchan *lc;

	if (bts->chan_alloc_reverse) {
		llist_for_each_entry_reverse(trx, &bts->trx_list, list) {
			lc = _lc_find_trx(trx, pchan);
			if (lc)
				return lc;
		}
	} else {
		llist_for_each_entry(trx, &bts->trx_list, list) {
			lc = _lc_find_trx(trx, pchan);
			if (lc)
				return lc;
		}
	}

	return NULL;
}

/* Allocate a logical channel */
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
				type = GSM_LCHAN_TCH_H;
			}

			if (lchan == NULL) {
				lchan = _lc_find_bts(bts, GSM_PCHAN_TCH_F);
				type = GSM_LCHAN_TCH_F;
			}
		}
		break;
	case GSM_LCHAN_TCH_F:
		lchan = _lc_find_bts(bts, GSM_PCHAN_TCH_F);
		/* If we don't have TCH/F available, fall-back to TCH/H */
		if (!lchan) {
			lchan = _lc_find_bts(bts, GSM_PCHAN_TCH_H);
			type = GSM_LCHAN_TCH_H;
		}
		break;
	case GSM_LCHAN_TCH_H:
		lchan =_lc_find_bts(bts, GSM_PCHAN_TCH_H);
		/* If we don't have TCH/H available, fall-back to TCH/F */
		if (!lchan) {
			lchan = _lc_find_bts(bts, GSM_PCHAN_TCH_F);
			type = GSM_LCHAN_TCH_F;
		}
		break;
	default:
		LOGP(DRLL, LOGL_ERROR, "Unknown gsm_chan_t %u\n", type);
	}

	if (lchan) {
		lchan->type = type;

		/* clear sapis */
		memset(lchan->sapis, 0, ARRAY_SIZE(lchan->sapis));

		/* clear multi rate config */
		memset(&lchan->mr_ms_lv, 0, sizeof(lchan->mr_ms_lv));
		memset(&lchan->mr_bts_lv, 0, sizeof(lchan->mr_bts_lv));
		lchan->broken_reason = "";
	} else {
		struct challoc_signal_data sig;
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

static struct gsm_lchan* lchan_find(struct gsm_bts *bts, struct gsm_subscriber *subscr) {
	struct gsm_bts_trx *trx;
	int ts_no, lchan_no;

	llist_for_each_entry(trx, &bts->trx_list, list) {
		for (ts_no = 0; ts_no < 8; ++ts_no) {
			for (lchan_no = 0; lchan_no < TS_MAX_LCHAN; ++lchan_no) {
				struct gsm_lchan *lchan =
					&trx->ts[ts_no].lchan[lchan_no];
				if (lchan->conn && subscr == lchan->conn->subscr)
					return lchan;
			}
		}
	}

	return NULL;
}

struct gsm_subscriber_connection *connection_for_subscr(struct gsm_subscriber *subscr)
{
	struct gsm_bts *bts;
	struct gsm_network *net = subscr->group->net;
	struct gsm_lchan *lchan;

	llist_for_each_entry(bts, &net->bts_list, list) {
		lchan = lchan_find(bts, subscr);
		if (lchan)
			return lchan->conn;
	}

	return NULL;
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

			/* skip administratively deactivated timeslots */
			if (!nm_is_running(&ts->mo.nm_state))
				continue;

			for (j = 0; j < subslots_per_pchan[ts->pchan]; j++) {
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

