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
#include <time.h>

#include <osmocom/core/msgb.h>
#include <openbsc/debug.h>
#include <openbsc/gsm_data.h>
#include <openbsc/meas_rep.h>
#include <openbsc/signal.h>
#include <osmocom/core/talloc.h>
#include <openbsc/handover.h>
#include <openbsc/bsc_api.h>
#include <osmocom/gsm/gsm_utils.h>
#include <openbsc/chan_alloc.h>
#include <openbsc/gsm_subscriber.h>

extern struct gsm_network *bsc_gsmnet;

#define REQUIREMENT_A_TCHF	0x01
#define REQUIREMENT_B_TCHF	0x02
#define REQUIREMENT_C_TCHF	0x04
#define REQUIREMENT_A_TCHH	0x10
#define REQUIREMENT_B_TCHH	0x20
#define REQUIREMENT_C_TCHH	0x40
#define REQUIREMENT_TCHF_MASK	0x0f
#define REQUIREMENT_TCHH_MASK	0xf0
#define REQUIREMENT_A_MASK	0x11
#define REQUIREMENT_B_MASK	0x22
#define REQUIREMENT_C_MASK	0x44

struct ho_candidate {
	struct gsm_lchan *lchan;	/* candidate for whom */
	struct gsm_bts *bts;		/* target BTS */
	uint8_t requirements;		/* what is fulfilled */
	int avg;			/* average RX level */
};

enum ho_reason {
	HO_REASON_INTERFERENCE,
	HO_REASON_BAD_QUALITY,
	HO_REASON_LOW_RXLEVEL,
	HO_REASON_MAX_DISTANCE,
	HO_REASON_BETTER_CELL,
	HO_REASON_CONGESTION,
};

static enum ho_reason ho_reason;

static const struct value_string ho_reason_names[] = {
	{ HO_REASON_INTERFERENCE,	"interference (bad quality)" },
	{ HO_REASON_BAD_QUALITY,	"bad quality" },
	{ HO_REASON_LOW_RXLEVEL,	"low rxlevel" },
	{ HO_REASON_MAX_DISTANCE,	"maximum allowed distance" },
	{ HO_REASON_BETTER_CELL,	"better cell" },
	{ HO_REASON_CONGESTION,		"congestion" },
	{ 0,				NULL }
};

static const char *get_ho_reason_name(int value)
{
        return get_value_string(ho_reason_names, value);
}

void log_bts_subscr(int subsys, int level, struct gsm_lchan *lchan)
{
	LOGP(subsys, level, "(BTS %d subscr %s) ", lchan->ts->trx->bts->nr,
		subscr_name(lchan->conn->subscr));
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

	/* reduce window to the actual number of existing measurements */
	if (window > nmp->rxlev_cnt)
		window = nmp->rxlev_cnt;
	/* this should never happen */
	if (window == 0)
		return 0;

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
			nmp->last_seen_nr = mr->lchan->meas_rep_cnt - 1;
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

		nmp->rxlev_cnt = 0;
		idx = nmp->rxlev_cnt % ARRAY_SIZE(nmp->rxlev);
		nmp->rxlev[idx] = mrc->rxlev;
		nmp->rxlev_cnt++;
		nmp->last_seen_nr = mr->lchan->meas_rep_cnt - 1;

		mrc->flags |= MRC_F_PROCESSED;
	}
}

/*
 * Check what requirements the given cell fulfills.
 * A bit mask of fulfilled requirements is returned.
 *
 * Target cell requirement A
 *
 * In order to successfully handover/assign to a better cell, the target cell
 * must be able to continue the current call. Therefore the cell must fulfill
 * the following criteria:
 *
 *  * The handover must be enabled for the target cell, if it differs from the
 *    originating cell.
 *  * The assignment must be enabled for the cell, if it equals the current
 *    cell.
 *  * The handover penalty timer must not run for the cell.
 *  * If FR, EFR or HR codec is used, the cell must support this codec.
 *  * If FR or EFR codec is used, the cell must have a TCH/F slot type
 *    available.
 *  * If HR codec is used, the cell must have a TCH/H slot type available.
 *  * If AMR codec is used, the cell must have a TCH/F slot available, if AFS
 *    is supported by mobile and BTS.
 *  * If AMR codec is used, the cell must have a TCH/H slot available, if AHS
 *    is supported by mobile and BTS.
 *  * osmo-nitb with built-in MNCC application:
 *     o If AMR codec is used, the cell must support AMR codec with equal codec
 *       rate or rates. (not meaning TCH types)
 *  * If defined, the number of maximum unsynchronized handovers to this cell
 *    may not be exceeded. (This limits processing load for random access
 *    bursts.)
 *
 *
 * Target cell requirement B
 *
 * In order to prevent congestion of a target cell, the cell must fulfill the
 * requirement A, but also:
 *
 *  * The minimum free channels, that are defined for that cell must be
 *    maintained after handover/assignment.
 *  * The minimum free channels are defined for TCH/F and TCH/H slot types
 *    individually.
 *
 *
 * Target cell requirement C
 *
 * In order to balance congested cells, the target cell must fulfill the
 * requirement A, but also:
 *
 *  * The target cell (which is congested also) must have more or equal free
 *    slots after handover/assignment.
 *  * The number of free slots are checked for TCH/F and TCH/H slot types
 *    individually.
 */
static uint8_t check_requirements(struct gsm_lchan *lchan, struct gsm_bts *bts,
	int tchf_count, int tchh_count)
{
	time_t now;
	int count;
	uint8_t requirement = 0;
	struct ho_penalty_timer *timer;
	struct gsm_bts *current_bts = lchan->ts->trx->bts;
	struct gsm_mncc_bearer_cap *bcap;
	int i;

	/* Requirement A */

	/* the handover/assignment must not be disabled */
	if (current_bts == bts) {
		if (!bts->handover.as_active) {
			LOGP(DHODEC, LOGL_DEBUG, " - BTS %d is not a "
				"candidate, because assignment is not "
				"enabled\n", bts->nr);
			return 0;
		}
	} else {
		if (!bts->handover.ho_active) {
			LOGP(DHODEC, LOGL_DEBUG, " - BTS %d is not a "
				"candidate, because handover is not enabled "
				"there\n",
				bts->nr);
			return 0;
		}
	}

	/* the handover penalty timer must not run for this bts */
	time(&now);
	llist_for_each_entry(timer, &lchan->conn->ho_penalty_timers, entry) {
		if (timer->bts != bts->nr)
			continue;
		if (now < timer->timeout) {
			LOGP(DHODEC, LOGL_DEBUG, " - BTS %d is not a "
				"candidate, because penalty timer is running "
				"(%ld seconds left)\n", bts->nr,
				timer->timeout - now);
			return 0;
		}
	}

	/* compatibility check for codecs.
	 * if so, the candidates for full rate and half rate are selected */
	switch (lchan->tch_mode) {
	case GSM48_CMODE_SPEECH_V1:
		switch (lchan->type) {
		case GSM_LCHAN_TCH_F: /* mandatory */
			requirement |= REQUIREMENT_A_TCHF;
			break;
		case GSM_LCHAN_TCH_H:
			if (bts->codec.hr)
				requirement |= REQUIREMENT_A_TCHH;
			break;
		default:
			LOGP(DHODEC, LOGL_DEBUG, " - BTS %d is not a "
				"candidate, because channel type is not TCH\n",
				bts->nr);
			return 0;
		}
		break;
	case GSM48_CMODE_SPEECH_EFR:
		if (bts->codec.efr)
			requirement |= REQUIREMENT_A_TCHF;
		break;
	case GSM48_CMODE_SPEECH_AMR:
		/* only select AFS/AHS, if supported by the MS */
		bcap = &lchan->conn->bcap;
		for (i = 0; bcap->speech_ver[i] >= 0; i++) {
			if (bcap->speech_ver[i] == 4 && bts->codec.afs)
				requirement |= REQUIREMENT_A_TCHF;
			if (bcap->speech_ver[i] == 5 && bts->codec.ahs)
				requirement |= REQUIREMENT_A_TCHH;
		}
		break;
	default:
		LOGP(DHODEC, LOGL_DEBUG, " - BTS %d is not a candidate, "
			"because current channel mode is not SPEECH\n",
			bts->nr);
		return 0;
	}

	/* no candidate, because new cell is incompatible */
	if (!requirement) {
		LOGP(DHODEC, LOGL_DEBUG, " - BTS %d is not a candidate, "
			"because codec of MS and BTS are incompatible\n",
			bts->nr);
		return 0;
	}

	/* count available slots and remove slot types that are not available */
	if ((requirement & REQUIREMENT_A_TCHF) && !tchf_count)
		requirement &= ~(REQUIREMENT_A_TCHF);
	if ((requirement & REQUIREMENT_A_TCHH) && !tchh_count)
		requirement &= ~(REQUIREMENT_A_TCHH);

	/* no candidate, because new cell has not free slots */
	if (!requirement) {
		LOGP(DHODEC, LOGL_DEBUG, " - BTS %d is not a candidate, "
			"because there is no (suitable) slot free\n",
			bts->nr);
		return 0;
	}

	/* omit same channel type on same BTS (will not change anything) */
	if (bts == current_bts) {
		switch (lchan->type) {
		case GSM_LCHAN_TCH_F:
			requirement &= ~(REQUIREMENT_A_TCHF);
			break;
		case GSM_LCHAN_TCH_H:
			requirement &= ~(REQUIREMENT_A_TCHH);
			break;
		default:
			break;
		}
	}

	/* no candidate, because no different slot for improvement */
	if (!requirement) {
		LOGP(DHODEC, LOGL_DEBUG, " - BTS %d is not a candidate, "
			"because no diffrent slot for improvement available\n",
			bts->nr);
		return 0;
	}

	/* built-in call control requires equal codec rates.
	 * remove rates that are not equal. */
	if (lchan->tch_mode == GSM48_CMODE_SPEECH_AMR
	 && current_bts->network->mncc_recv != mncc_sock_from_cc) {
		switch (lchan->type) {
		case GSM_LCHAN_TCH_F:
			if ((requirement & REQUIREMENT_A_TCHF)
			 && !!memcmp(&current_bts->mr_full, &bts->mr_full,
					sizeof(struct amr_multirate_conf)))
				requirement &= ~(REQUIREMENT_A_TCHF);
			if ((requirement & REQUIREMENT_A_TCHH)
			 && !!memcmp(&current_bts->mr_full, &bts->mr_half,
					sizeof(struct amr_multirate_conf)))
				requirement &= ~(REQUIREMENT_A_TCHH);
			break;
		case GSM_LCHAN_TCH_H:
			if ((requirement & REQUIREMENT_A_TCHF)
			 && !!memcmp(&current_bts->mr_half, &bts->mr_full,
					sizeof(struct amr_multirate_conf)))
				requirement &= ~(REQUIREMENT_A_TCHF);
			if ((requirement & REQUIREMENT_A_TCHH)
			 && !!memcmp(&current_bts->mr_half, &bts->mr_half,
					sizeof(struct amr_multirate_conf)))
				requirement &= ~(REQUIREMENT_A_TCHH);
			break;
		default:
			break;
		}
	}

	/* no candidate, because new cell's AMR rates are incompatible */
	if (!requirement) {
		LOGP(DHODEC, LOGL_DEBUG, " - BTS %d is not a candidate, "
			"because built-in MNCC doesn't privide equal AMR "
			"rates\n", bts->nr);
		return 0;
	}

	/* the maximum number of unsynchonized handovers must no be exceeded */
	if (current_bts != bts
	 && bsc_ho_count(bts) >= bts->handover.max_unsync_ho) {
		LOGP(DHODEC, LOGL_DEBUG, " - BTS %d is not a candidate, "
			"because maximum number of allowed handovers would be "
			"exceeded\n",
			bts->nr);
		return 0;
	}

	/* Requirement B */

	/* the minimum free timeslots that are defined for this cell must
	 * be maintained _after_ handover/assignment */
	if ((requirement & REQUIREMENT_A_TCHF)
	 && tchf_count - 1 >= bts->handover.min_free_tchf)
		requirement |= REQUIREMENT_B_TCHF;
	if ((requirement & REQUIREMENT_A_TCHH)
	 && tchh_count - 1 >= bts->handover.min_free_tchh)
		requirement |= REQUIREMENT_B_TCHH;

	/* Requirement C */

	/* the free timeslots of the target cell must be more or qual to the
	 * free slots of the current cell _after_ handover/assignment */
	count = lc_count_bts(current_bts, (lchan->type == GSM_LCHAN_TCH_H) ?
					GSM_PCHAN_TCH_H : GSM_PCHAN_TCH_F);
	if ((requirement & REQUIREMENT_A_TCHF) && tchf_count - 1 >= count + 1)
		requirement |= REQUIREMENT_C_TCHF;
	if ((requirement & REQUIREMENT_A_TCHH) && tchh_count - 1 >= count + 1)
		requirement |= REQUIREMENT_C_TCHH;

	/* return mask of fulfilled requirements */
	return requirement;
}

/* Trigger handover or assignment depending on the target BTS */
static int trigger_handover_or_assignment(struct gsm_lchan *lchan,
	struct gsm_bts *new_bts, uint8_t requirements)
{
	struct gsm_bts *current_bts = lchan->ts->trx->bts;
	int improve_afs = 0;
	int full_rate = 0;

	log_bts_subscr(DHODEC, LOGL_NOTICE, lchan);

	/* improve_afs becomes > 0, if AFS is used and is improved */
	if (lchan->tch_mode == GSM48_CMODE_SPEECH_AMR)
		improve_afs = new_bts->handover.afs_rxlev_improve;

	/* select TCH rate, prefer TCH/F if AFS is improved */
	switch (lchan->type) {
	case GSM_LCHAN_TCH_F:
		/* keep on full rate, if a candidate */
		if ((requirements & REQUIREMENT_TCHF_MASK)) {
			if (current_bts == new_bts) {
				LOGPC(DHODEC, LOGL_INFO, "Not performing "
					"assignment: Already on target type\n");
				return 0;
			}
			full_rate = 1;
			break;
		}
		/* change to half rate */
		if (!(requirements & REQUIREMENT_TCHH_MASK)) {
			LOGPC(DHODEC, LOGL_ERROR, "Not performing assignment: "
				"No requirement given, please fix!\n");
			return -EINVAL;
		}
		break;
	case GSM_LCHAN_TCH_H:
		/* change to full rate if AFS is improved and a candidate */
		if (improve_afs > 0 && (requirements & REQUIREMENT_TCHF_MASK)) {
			full_rate = 1;
			LOGPC(DHODEC, LOGL_INFO, "[Improve AHS->AFS] ");
			break;
		}
		/* change to full rate if the only candidate */
		if ((requirements & REQUIREMENT_TCHF_MASK)
		 && !(requirements & REQUIREMENT_TCHH_MASK)) {
			full_rate = 1;
			break;
		}
		/* keep on half rate */
		if (!(requirements & REQUIREMENT_TCHH_MASK)) {
			LOGPC(DHODEC, LOGL_ERROR, "Not performing assignment: "
				"No requirement given, please fix!\n");
			return -EINVAL;
		}
		if (current_bts == new_bts) {
			LOGPC(DHODEC, LOGL_INFO, "Not performing assignment: "
				"Already on target type\n");
			return 0;
		}
		break;
	default:
		LOGPC(DHODEC, LOGL_ERROR, "Not performing handover nor "
			"assignment: lchan type no TCH, please fix!\n");
		return -EINVAL;
	}

	/* trigger handover or asignment */
	if  (current_bts == new_bts) {
		LOGPC(DHODEC, LOGL_NOTICE, "Trigger assignment due to %s to "
			"%s.\n", get_ho_reason_name(ho_reason),
			(full_rate) ? "TCH/F" : "TCH/H");
		return bsc_handover_start(lchan, NULL, full_rate);
	} else {
		LOGPC(DHODEC, LOGL_NOTICE, "Trigger handover to BTS %d due to "
			"%s to %s.\n", new_bts->nr,
			get_ho_reason_name(ho_reason),
			(full_rate) ? "TCH/F" : "TCH/H");
		return bsc_handover_start(lchan, new_bts, full_rate);
	}

	return 0;
}

/* debug collected candidates */
static inline void debug_candidate(struct ho_candidate *candidate,
	int neighbor, int8_t rxlev, int tchf_count, int tchh_count)
{
	if (!candidate->requirements)
		return;

	if (neighbor)
		LOGP(DHODEC, LOGL_DEBUG, " - neighbor BTS %d, RX level "
			"%d -> %d\n", candidate->bts->nr, rxlev2dbm(rxlev),
			rxlev2dbm(candidate->avg));
	else
		LOGP(DHODEC, LOGL_DEBUG, " - current BTS %d, RX level %d\n",
			candidate->bts->nr, rxlev2dbm(candidate->avg));

	LOGP(DHODEC, LOGL_DEBUG, "   o free TCH/F slots %d, minimum required "
		"%d\n", tchf_count, candidate->bts->handover.min_free_tchf);
	LOGP(DHODEC, LOGL_DEBUG, "   o free TCH/H slots %d, minimum required "
		"%d\n", tchh_count, candidate->bts->handover.min_free_tchh);

	if ((candidate->requirements & REQUIREMENT_TCHF_MASK))
		LOGP(DHODEC, LOGL_DEBUG, "   o requirement ");
	else
		LOGP(DHODEC, LOGL_DEBUG, "   o no requirement ");
	if ((candidate->requirements & REQUIREMENT_A_TCHF))
		LOGPC(DHODEC, LOGL_DEBUG, "A ");
	if ((candidate->requirements & REQUIREMENT_B_TCHF))
		LOGPC(DHODEC, LOGL_DEBUG, "B ");
	if ((candidate->requirements & REQUIREMENT_C_TCHF))
		LOGPC(DHODEC, LOGL_DEBUG, "C ");
	LOGPC(DHODEC, LOGL_DEBUG, "fulfilled for TCHF");
	if (!(candidate->requirements & REQUIREMENT_TCHF_MASK)) /* nothing */
		LOGPC(DHODEC, LOGL_DEBUG, " (no %s possible)\n",
			(neighbor) ? "handover" : "assignment");
	else if ((candidate->requirements & REQUIREMENT_TCHF_MASK)
					== REQUIREMENT_A_TCHF) /* only A */
		LOGPC(DHODEC, LOGL_DEBUG, " (more congestion after %s)\n",
			(neighbor) ? "handover" : "assignment");
	else if ((candidate->requirements & REQUIREMENT_B_TCHF)) /* B incl. */
		LOGPC(DHODEC, LOGL_DEBUG, " (not congested after %s)\n",
			(neighbor) ? "handover" : "assignment");
	else /* so it must include C */
		LOGPC(DHODEC, LOGL_DEBUG, " (less or equally congested after "
			"%s)\n", (neighbor) ? "handover" : "assignment");

	if ((candidate->requirements & REQUIREMENT_TCHH_MASK))
		LOGP(DHODEC, LOGL_DEBUG, "   o requirement ");
	else
		LOGP(DHODEC, LOGL_DEBUG, "   o no requirement ");
	if ((candidate->requirements & REQUIREMENT_A_TCHH))
		LOGPC(DHODEC, LOGL_DEBUG, "A ");
	if ((candidate->requirements & REQUIREMENT_B_TCHH))
		LOGPC(DHODEC, LOGL_DEBUG, "B ");
	if ((candidate->requirements & REQUIREMENT_C_TCHH))
		LOGPC(DHODEC, LOGL_DEBUG, "C ");
	LOGPC(DHODEC, LOGL_DEBUG, "fulfilled for TCHH");
	if (!(candidate->requirements & REQUIREMENT_TCHH_MASK)) /* nothing */
		LOGPC(DHODEC, LOGL_DEBUG, " (no %s possible)\n",
			(neighbor) ? "handover" : "assignment");
	else if ((candidate->requirements & REQUIREMENT_TCHH_MASK)
					== REQUIREMENT_A_TCHH) /* only A */
		LOGPC(DHODEC, LOGL_DEBUG, " (more congestion after %s)\n",
			(neighbor) ? "handover" : "assignment");
	else if ((candidate->requirements & REQUIREMENT_B_TCHH)) /* B incl. */
		LOGPC(DHODEC, LOGL_DEBUG, " (not congested after %s)\n",
			(neighbor) ? "handover" : "assignment");
	else /* so it must include C */
		LOGPC(DHODEC, LOGL_DEBUG, " (less or equally congested after "
			"%s)\n", (neighbor) ? "handover" : "assignment");
}

/* subroutine for collecting candidates of one lchan */
static int collect_candidates_for_lchan(struct gsm_lchan *lchan,
	struct ho_candidate *clist, int *_av_rxlev, int check_hyst,
	int ign_level)
{
	struct gsm_bts *current_bts = lchan->ts->trx->bts;
	int candidates = 0, i;
	int av_rxlev;
	int tchf_count, tchh_count;

	/* caculate average rxlev for this cell over the window */
	av_rxlev = get_meas_rep_avg(lchan, (current_bts->handover.full) ?
			MEAS_REP_DL_RXLEV_FULL : MEAS_REP_DL_RXLEV_SUB,
			current_bts->handover.win_rxlev_avg);
	if (_av_rxlev)
		*_av_rxlev = av_rxlev;

	LOGP(DHODEC, LOGL_DEBUG, "Collecting candidates (for subscr. %s):\n",
		subscr_name(lchan->conn->subscr));

	/* in case there is no measurment report (yet) */
	if (av_rxlev < 0) {
		LOGP(DHODEC, LOGL_DEBUG, "- Omitting, because not enough "
			"measurements yet\n");
		return 0;
	}

	/* check requirements for current cell */
	if (current_bts->handover.as_active) {
		tchf_count = lc_count_bts(current_bts, GSM_PCHAN_TCH_F);
		tchh_count = lc_count_bts(current_bts, GSM_PCHAN_TCH_H);
		clist[candidates].lchan = lchan;
		clist[candidates].bts = current_bts;
		clist[candidates].requirements = check_requirements(lchan,
			current_bts, tchf_count, tchh_count);
		clist[candidates].avg = av_rxlev;
		debug_candidate(&clist[candidates], 0, 0, tchf_count,
			tchh_count);
		candidates++;
	} else {
		LOGP(DHODEC, LOGL_DEBUG, " - Assignment for BTS %u disabled\n",
			current_bts->nr);
	}

	/* check requirements for all neighbor cells */
	if (current_bts->handover.ho_active) {
		int n = 0;
		for (i = 0; i < ARRAY_SIZE(lchan->neigh_meas); i++) {
			struct neigh_meas_proc *nmp = &lchan->neigh_meas[i];
			struct gsm_bts *neighbor_bts;
			int avg;

			/* skip empty slots */
			if (nmp->arfcn == 0)
				continue;

			/* skip if measurement report is old */
			if (nmp->last_seen_nr != lchan->meas_rep_cnt - 1)
				continue;

			neighbor_bts = gsm_bts_neighbor(current_bts, nmp->arfcn,
								nmp->bsic);
			if (!neighbor_bts)
				continue;

			/* in case we have measurements of our bts, due to
			 * missconfiguration */
			if (neighbor_bts == current_bts)
				continue;

			n++;

			/* caculate average rxlev for this cell over the
			 * window */
			avg = neigh_meas_avg(nmp,
				current_bts->handover.win_rxlev_avg_neigh);

			/* check if rx level is better level */
			if (!ign_level && check_hyst
			 && avg <= av_rxlev
				       + current_bts->handover.pwr_hysteresis) {
				LOGP(DHODEC, LOGL_DEBUG, " - BTS %d is not a "
					"candidate, because RX level (%d) is "
					"lower or equal than current RX level "
					"(%d) + hysteresis (%d)\n",
					neighbor_bts->nr, rxlev2dbm(avg),
					rxlev2dbm(av_rxlev),
					current_bts->handover.pwr_hysteresis);
				continue;
			} else
			if (!ign_level && avg <= av_rxlev) {
				LOGP(DHODEC, LOGL_DEBUG, " - BTS %d is not a "
					"candidate, because RX level (%d) is "
					"lower or equal than current RX level "
					"(%d)\n", neighbor_bts->nr,
					rxlev2dbm(avg), rxlev2dbm(av_rxlev));
				continue;
			}

			/* if the minimum level is not reached */
			if (rxlev2dbm(avg)
					< neighbor_bts->handover.min_rxlev) {
				LOGP(DHODEC, LOGL_DEBUG, " - BTS %d is not a "
					"candidate, because RX level (%d) is "
					"below minimum required RX level "
					"(%d)\n", neighbor_bts->nr,
					rxlev2dbm(avg),
					neighbor_bts->handover.min_rxlev);
				continue;
			}

			tchf_count = lc_count_bts(neighbor_bts, GSM_PCHAN_TCH_F);
			tchh_count = lc_count_bts(neighbor_bts, GSM_PCHAN_TCH_H);
			clist[candidates].lchan = lchan;
			clist[candidates].bts = neighbor_bts;
			clist[candidates].requirements = check_requirements(
				lchan, neighbor_bts, tchf_count, tchh_count);
			clist[candidates].avg = avg;
			debug_candidate(&clist[candidates], 1, av_rxlev,
				tchf_count, tchh_count);
			candidates++;
		}
		if (!n) {
			LOGP(DHODEC, LOGL_DEBUG, " - No neighbor cells at "
				"measurement report\n");
		}
	} else {
		LOGP(DHODEC, LOGL_DEBUG, " - No neighbor cells, because "
			"handover is disabled in this cell\n");
	}

	return candidates;
}

/*
 * Search for a better cell
 *
 * Do not trigger handover/assignment on slots which have already ongoing
 * handover/assignment processes. If no AFS improvement offset is given, try to
 * maintain the same TCH rate, if available.
 * Do not perform this process, if handover and assignment are disabled for
 * the current cell.
 * Do not perform handover, if the minimum acceptable RX level
 * is not reched for this cell.
 *
 * If one or more 'better cells' are available, check the current and neighbor
 * cell measurements in descending order of their RX levels (down-link):
 *
 *  * Select the best candidate that fulfills requirement B (no congestion
 *    after handover/assignment) and trigger handover or assignment.
 *  * If no candidate fulfills requirement B, select the best candidate that
 *    fulfills requirement C (less or equally congested cells after handover)
 *    and trigger handover or assignment.
 *  * If no candidate fulfills requirement C, do not perform handover nor
 *    assignment.
 *
 * If the RX level (down-link) or RX quality (down-link) of the current cell is
 * below minimum acceptable level, or if the maximum allowed timing advance is
 * reached or exceeded, check the RX levels (down-link) of the current and
 * neighbor cells in descending order of their levels: (bad BTS case)
 *
 *  * Select the best candidate that fulfills requirement B (no congestion after
 *    handover/assignment) and trigger handover or assignment.
 *  * If no candidate fulfills requirement B, select the best candidate that
 *    fulfills requirement C (less or equally congested cells after handover)
 *    and trigger handover or assignment.
 *  * If no candidate fulfills requirement C, select the best candidate that
 *    fulfills requirement A (ignore congestion after handover or assignment)
 *    and trigger handover or assignment.
 *  * If no candidate fulfills requirement A, do not perform handover nor
 *    assignment.
 *
 * RX levels (down-link) of current and neighbor cells:
 *
 *  * The RX levels of the current cell and neighbor cells are improved by a
 *    given offset, if AFS (AMR on TCH/F) is used or is a candidate for
 *    handover/assignment.
 *  * If AMR is used, the requirement for handover is checked for TCH/F and
 *    TCH/H. Both results (if any) are used as a candidate.
 *  * If AMR is used, the requirement for assignment to a different TCH slot
 *    rate is checked. The result (if available) is used as a candidate.
 */
static int better_cell(struct gsm_lchan *lchan, int better_cell_search,
	int ign_level)
{
	struct gsm_bts *current_bts = lchan->ts->trx->bts;
	int ahs = (lchan->tch_mode == GSM48_CMODE_SPEECH_AMR
	        && lchan->type == GSM_LCHAN_TCH_H);
	int av_rxlev;
	struct ho_candidate clist[1 + ARRAY_SIZE(lchan->neigh_meas)];
	int candidates, i;
	struct ho_candidate *best_cand = NULL;
	unsigned int best_better_db;
	int better;
	int is_improved = 0;

	/* check for disabled handover/assignment at the current cell */
	if (!current_bts->handover.as_active
	 && !current_bts->handover.ho_active) {
		LOGP(DHODEC, LOGL_INFO, "Skipping, Handover and Assignment is "
			"disabled in this cell\n");
		return 0;
	}

	/* collect candidates */
	candidates = collect_candidates_for_lchan(lchan, clist, &av_rxlev,
		better_cell_search, ign_level);

	/* if no candiate (may happen if assignment is disabled and no
	 * neighbor cell report exists) */
	if (candidates == 0)
		goto no_cand;

	/* select best candidate that fulfills requirement B */
	best_better_db = 0;
	for (i = 0; i < candidates; i++) {
		if (!(clist[i].requirements & REQUIREMENT_B_MASK))
			continue;

		better = clist[i].avg - av_rxlev;
		/* improve AHS */
		if (ahs && (clist[i].requirements & REQUIREMENT_B_TCHF)) {
			better += clist[i].bts->handover.afs_rxlev_improve;
			is_improved = 1;
		} else
			is_improved = 0;
		if (better > best_better_db) {
			best_cand = &clist[i];
			best_better_db = better;
		}
	}

	/* perform handover, if there is a candidate */
	if (best_cand) {
		LOGP(DHODEC, LOGL_INFO, "Best candidate BTS %d (RX level %d) "
			"without congestion after handover found.\n",
			best_cand->bts->nr, rxlev2dbm(best_cand->avg));
		if (is_improved)
			LOGP(DHODEC, LOGL_INFO, "(is improved due to "
				"AHS -> AFS)\n");
		return trigger_handover_or_assignment(lchan, best_cand->bts,
			best_cand->requirements & REQUIREMENT_B_MASK);
	}

	/* select best candidate that fulfills requirement C */
	best_better_db = 0;
	for (i = 0; i < candidates; i++) {
		if (!(clist[i].requirements & REQUIREMENT_C_MASK))
			continue;

		better = clist[i].avg - av_rxlev;
		/* improve AHS */
		if (ahs && (clist[i].requirements & REQUIREMENT_C_TCHF)) {
			better += clist[i].bts->handover.afs_rxlev_improve;
			is_improved = 1;
		} else
			is_improved = 0;
		if (better > best_better_db) {
			best_cand = &clist[i];
			best_better_db = better;
		}
	}

	/* perform handover, if there is a candidate */
	if (best_cand) {
		LOGP(DHODEC, LOGL_INFO, "Best candidate BTS %d (RX level %d) "
			"with less or equal congestion after handover found.\n",
			best_cand->bts->nr, rxlev2dbm(best_cand->avg));
		if (is_improved)
			LOGP(DHODEC, LOGL_INFO, "(is improved due to "
				"AHS -> AFS)\n");
		return trigger_handover_or_assignment(lchan, best_cand->bts,
			best_cand->requirements & REQUIREMENT_C_MASK);
	}

	/* we are done in case of searching a better cell */
	if (better_cell_search)
		goto no_cand;

	/* select best candidate that fulfills requirement A */
	best_better_db = 0;
	for (i = 0; i < candidates; i++) {
		if (!(clist[i].requirements & REQUIREMENT_A_MASK))
			continue;

		better = clist[i].avg - av_rxlev;
		/* improve AHS */
		if (ahs && (clist[i].requirements & REQUIREMENT_A_TCHF)) {
			better += clist[i].bts->handover.afs_rxlev_improve;
			is_improved = 1;
		} else
			is_improved = 0;
		if (better > best_better_db) {
			best_cand = &clist[i];
			best_better_db = better;
		}
	}

	/* perform handover, if there is a candidate */
	if (best_cand) {
		LOGP(DHODEC, LOGL_INFO, "Best candidate BTS %d (RX level %d) "
			"with greater congestion found.\n", best_cand->bts->nr,
			rxlev2dbm(best_cand->avg));
		if (is_improved)
			LOGP(DHODEC, LOGL_INFO, "(is improved due to "
				"AHS -> AFS)\n");
		return trigger_handover_or_assignment(lchan, best_cand->bts,
			best_cand->requirements & REQUIREMENT_A_MASK);
	}

no_cand:
	if (better_cell_search)
		LOGP(DHODEC, LOGL_INFO, "No better candidate found\n");
	else
		LOGP(DHODEC, LOGL_INFO, "No suitable candidate found\n");

	return 0;
}

/*
 * Handover/assignment check, if measurement report is received
 *
 * Do not trigger handover/assignment on slots which have already ongoing
 * handover/assignment processes.
 *
 * In case of handover triggered because maximum allowed timing advance is
 * exceeded, the handover penalty timer is started for the originating cell.
 *
 */
static int attempt_handover_after_mr(struct gsm_meas_rep *mr)
{
	struct gsm_lchan *lchan = mr->lchan;
	struct gsm_bts *bts = lchan->ts->trx->bts;
	int av_rxlev = -EINVAL, av_rxqual = -EINVAL;
	int rc;

	/* we currently only do handover for TCH channels */
	switch (mr->lchan->type) {
	case GSM_LCHAN_TCH_F:
	case GSM_LCHAN_TCH_H:
		break;
	default:
		return 0;
	}

	/* parse actual neighbor cell info */
	if (mr->num_cell > 0 && mr->num_cell < 7)
		process_meas_neigh(mr);

	/* check for ongoing handover/assignment */
	if (!lchan->conn) {
		log_bts_subscr(DHODEC, LOGL_ERROR, lchan);
		LOGPC(DHODEC, LOGL_ERROR, "Skipping, No subscriber "
			"connection???\n");
		return 0;
	}
	if (lchan->conn->secondary_lchan) {
		log_bts_subscr(DHODEC, LOGL_INFO, lchan);
		LOGPC(DHODEC, LOGL_INFO, "Skipping, Initial Assignment is "
			"still ongoing\n");
		return 0;
	}
	if (lchan->conn->ho_lchan) {
		log_bts_subscr(DHODEC, LOGL_INFO, lchan);
		LOGPC(DHODEC, LOGL_INFO, "Skipping, Handover already "
			"triggered\n");
		return 0;
	}

	/* get average levels. if not enought measurements yet, value is < 0 */
	av_rxlev = get_meas_rep_avg(lchan, (bts->handover.full) ?
			MEAS_REP_DL_RXLEV_FULL : MEAS_REP_DL_RXLEV_SUB,
			bts->handover.win_rxlev_avg);
	av_rxqual = get_meas_rep_avg(lchan, (bts->handover.full) ?
			MEAS_REP_DL_RXQUAL_FULL : MEAS_REP_DL_RXQUAL_SUB,
			bts->handover.win_rxqual_avg);
	if (av_rxlev < 0 && av_rxqual < 0) {
		log_bts_subscr(DHODEC, LOGL_INFO, lchan);
		LOGPC(DHODEC, LOGL_INFO, "Skipping, Not enough recent "
			"measuements\n");
		return 0;
	}
	if (av_rxlev >= 0) {
		log_bts_subscr(DHODEC, LOGL_DEBUG, lchan);
		LOGPC(DHODEC, LOGL_DEBUG, "Measurement report: average "
			"RX level = %d\n", rxlev2dbm(av_rxlev));
	}
	if (av_rxqual >= 0) {
		log_bts_subscr(DHODEC, LOGL_DEBUG, lchan);
		LOGPC(DHODEC, LOGL_DEBUG, "Measurement report: average "
			"RX quality = %d\n", av_rxqual);
	}

	/* improve levels in case of AFS, if defined */
	if (lchan->type == GSM_LCHAN_TCH_F
	 && lchan->tch_mode == GSM48_CMODE_SPEECH_AMR) {
		if (av_rxlev >= 0 && bts->handover.afs_rxlev_improve) {
			int imp = av_rxlev + bts->handover.afs_rxlev_improve;
			log_bts_subscr(DHODEC, LOGL_INFO, lchan);
			LOGPC(DHODEC, LOGL_INFO, "Virtually improving RX "
				"level from %d to %d, due to AFS improvement "
				"setting\n", rxlev2dbm(av_rxlev),
				rxlev2dbm(imp));
			av_rxlev = imp;
		}
		if (av_rxqual >= 0 && bts->handover.afs_rxqual_improve) {
			int imp = av_rxqual - bts->handover.afs_rxqual_improve;
			if (imp < 0)
				imp = 0;
			log_bts_subscr(DHODEC, LOGL_INFO, lchan);
			LOGPC(DHODEC, LOGL_INFO, "Virtually improving RX "
				"quality from %d to %d, due to AFS improvement "
				"setting\n", rxlev2dbm(av_rxqual),
				rxlev2dbm(imp));
			av_rxqual = imp;
		}
	}

	/* Bad Quality */
	if (av_rxqual >= 0 && av_rxqual > bts->handover.min_rxqual) {
		if (rxlev2dbm(av_rxlev) > -85) {
			ho_reason = HO_REASON_INTERFERENCE;
			log_bts_subscr(DHODEC, LOGL_INFO, lchan);
			LOGPC(DHODEC, LOGL_INFO, "Trying handover/assignment "
				"due to interference (bad quality)\n");
		} else {
			ho_reason = HO_REASON_BAD_QUALITY;
			log_bts_subscr(DHODEC, LOGL_INFO, lchan);
			LOGPC(DHODEC, LOGL_INFO, "Trying handover/assignment "
				"due to bad quality\n");
		}
		rc = better_cell(lchan, 0, 1);
		if (lchan->conn->ho_lchan || lchan->conn->secondary_lchan)
			return rc;
		return 0;
	}

	/* Low Level */
	if (av_rxlev >= 0 && rxlev2dbm(av_rxlev) < bts->handover.min_rxlev) {
		ho_reason = HO_REASON_LOW_RXLEVEL;
		log_bts_subscr(DHODEC, LOGL_INFO, lchan);
		LOGPC(DHODEC, LOGL_INFO, "Trying handover/assignment due to "
			"low level\n");
		rc = better_cell(lchan, 0, 1);
		if (lchan->conn->ho_lchan || lchan->conn->secondary_lchan)
			return rc;
		return 0;
	}

	/* Max Distance */
	if (lchan->meas_rep_cnt > 0
	 && lchan->rqd_ta > bts->handover.max_distance) {
		ho_reason = HO_REASON_MAX_DISTANCE;
		log_bts_subscr(DHODEC, LOGL_INFO, lchan);
		LOGPC(DHODEC, LOGL_INFO, "Trying handover due high TA\n");
		/* start penalty timer to prevent comming back too
		 * early. it must be started before selecting a better cell,
		 * so there is no assignment selected, due to running
		 * penalty timer. */
		add_penalty_timer(lchan->conn, bts,
			bts->handover.penalty_max_dist);
		rc = better_cell(lchan, 0, 1);
		if (lchan->conn->ho_lchan || lchan->conn->secondary_lchan)
			return rc;
		return 0;
	}

	/* try handover to a better cell */
	if (av_rxlev >= 0 && (mr->nr % bts->handover.pwr_interval) == 0) {
		log_bts_subscr(DHODEC, LOGL_INFO, lchan);
		LOGPC(DHODEC, LOGL_INFO, "Looking for better cell (with no, "
			"less or equal congestion hafter handover)\n");
		ho_reason = HO_REASON_BETTER_CELL;
		rc = better_cell(lchan, 1, 0);
		if (lchan->conn->ho_lchan || lchan->conn->secondary_lchan)
			return rc;
		return 0;
	}

	return 0;
}

/*
 * Handover/assignment check after timer timeout:
 *
 * Even if handover process tries to prevent a congestion, a cell might get
 * congested due to new call setups or handovers to prevent loss of radio link.
 * A cell is congested, if not the minimum number of free slots are available.
 * The minimum number can be defined for TCH/F and TCH/H individually.
 *
 * Do not perform congestion check, if no minimum free slots are defined for
 * a cell.
 * Do not trigger handover/assignment on slots which have already ongoing
 * handover/assignment processes. If no AFS improvement offset is given, try to
 * maintain the same TCH rate, if available.
 * Do not perform this process, if handover and assignment are disabled for
 * the current cell.
 * Do not perform handover, if the minimum acceptable RX level
 * is not reched for this cell.
 * Only check candidates that will solve/reduce congestion.
 *
 * If a cell is congested, all slots are checked for all their RX levels
 * (down-link) of the current and neighbor cell measurements in descending
 * order of their RX levels:
 *
 *  * Select the best candidate that fulfills requirement B (no congestion after
 *    handover/assignment), trigger handover or assignment. Candidates that will
 *    cause an assignment from AHS (AMR on TCH/H) to AFS (AMR on TCH/F) are
 *    omitted.
 *     o This process repeated until the minimum required number of free slots
 *       are restored or if all cell measurements are checked. The process ends
 *       then, otherwise:
 *  * Select the worst candidate that fulfills requirement B, trigger
 *    assignment. Note that only assignment candidates for changing from AHS to
 *    AFS are left.
 *     o This process repeated until the minimum required number of free slots
 *       are restored or if all cell measurements are checked. The process ends
 *       then, otherwise:
 *  * Select the best candidates that fulfill requirement C (less or equally
 *    congested cells after handover/assignment), trigger handover or
 *    assignment. Candidates that will cause an assignment from AHS (AMR on
 *    TCH/H) to AFS (AMR on TCH/F) are omitted.
 *     o This process repeated until the minimum required number of free slots
 *       are restored or if all cell measurements are checked. The process ends
 *       then, otherwise:
 *  * Select the worst candidate that fulfills requirement C, trigger
 *    assignment. Note that only assignment candidates for changing from AHS to
 *    AFS are left.
 *     o This process repeated until the minimum required number of free slots
 *       are restored or if all cell measurements are checked.
 */
static int congestion_check_bts(struct gsm_bts *bts, int tchf_congestion,
	int tchh_congestion)
{
	struct gsm_lchan *lc;
	struct gsm_bts_trx *trx;
	struct gsm_bts_trx_ts *ts;
	int i, j;
	struct ho_candidate *clist;
	int candidates = 0;
	struct ho_candidate *best_cand = NULL, *worst_cand = NULL;
	struct gsm_lchan *delete_lchan = NULL;
	unsigned int best_avg_db, worst_avg_db;
	int avg;
	int rc = 0;
	int any_ho = 0;
	int is_improved = 0;

	if (tchf_congestion < 0)
		tchf_congestion = 0;
	if (tchh_congestion < 0)
		tchh_congestion = 0;

	LOGP(DHODEC, LOGL_INFO, "BTS %d is congested: %d TCH/F and %d TCH/H "
		"must be moved\n", bts->nr, tchf_congestion, tchh_congestion);

	/* allocate array of all bts */
	clist = talloc_zero_array(tall_bsc_ctx, struct ho_candidate,
		bts->num_trx * 8 * 2 * (1 + ARRAY_SIZE(lc->neigh_meas)));
	if (!clist)
		return 0;

	/* loop through all active lchan and collect candidates */
	llist_for_each_entry(trx, &bts->trx_list, list) {
		if (!trx_is_usable(trx))
			continue;

		for (i = 0; i < 8; i++) {
			ts = &trx->ts[i];
			if (!ts_is_usable(ts))
				continue;
			switch (ts->pchan) {
			case GSM_PCHAN_TCH_F_PDCH:
			/* we can only consider such a dynamic channel
			 * if the PDCH is currently inactive */
			if (ts->flags & TS_F_PDCH_MODE)
				break;
			// fall through
			case GSM_PCHAN_TCH_F:
				lc = &ts->lchan[0];
				/* omit if channel not active */
				if (lc->type != GSM_LCHAN_TCH_F
				 || lc->state != LCHAN_S_ACTIVE)
					break;
				/* omit of there is an ongoing ho/as */
				if (!lc->conn || lc->conn->secondary_lchan
				 || lc->conn->ho_lchan)
					break;
				/* collect candidates */
				candidates += collect_candidates_for_lchan(lc,
					&clist[candidates], NULL, 0, 1);
				break;
			case GSM_PCHAN_TCH_H:
				for (j = 0; j < 2; j++) {
					lc = &ts->lchan[j];
					/* omit if channel not active */
					if (lc->type != GSM_LCHAN_TCH_H
					 || lc->state != LCHAN_S_ACTIVE)
						continue;
					/* omit of there is an ongoing ho/as */
					if (!lc->conn
					 || lc->conn->secondary_lchan
					 || lc->conn->ho_lchan)
						continue;
					candidates +=
						collect_candidates_for_lchan(lc,
						&clist[candidates], NULL, 0, 1);
					}
				break;
			default:
				break;
			}
		}
	}

	/* if no candiate */
	if (candidates == 0) {
		LOGP(DHODEC, LOGL_DEBUG, "No candidates at BTS %d to solve "
			"congestion.\n", bts->nr);
		goto exit;
	}

#if 0
next_b1:
#endif
	/* select best candidate that fulfills requirement B,
	 * omit change from AHS to AFS */
	best_avg_db = 0;
	for (i = 0; i < candidates; i++) {
		/* delete subscriber that just have handovered */
		if (clist[i].lchan == delete_lchan)
			clist[i].lchan = NULL;
		/* omit all subscribers that are handovered */
		if (!clist[i].lchan)
			continue;

		if (!(clist[i].requirements & REQUIREMENT_B_MASK))
			continue;
		/* omit assignment from AHS to AFS */
		if (clist[i].lchan->ts->trx->bts == clist[i].bts
		 && clist[i].lchan->type == GSM_LCHAN_TCH_H
		 && (clist[i].requirements & REQUIREMENT_B_TCHF))
			continue;
		/* omit candidates that will not solve/reduce congestion */
		if (clist[i].lchan->type == GSM_LCHAN_TCH_F
		 && tchf_congestion <= 0)
			continue;
		if (clist[i].lchan->type == GSM_LCHAN_TCH_H
		 && tchh_congestion <= 0)
			continue;

		avg = clist[i].avg;
		/* improve AHS */
		if (clist[i].lchan->tch_mode == GSM48_CMODE_SPEECH_AMR
		 && clist[i].lchan->type == GSM_LCHAN_TCH_H
		 && (clist[i].requirements & REQUIREMENT_B_TCHF)) {
			avg += clist[i].bts->handover.afs_rxlev_improve;
			is_improved = 1;
		} else
			is_improved = 0;
		if (avg > best_avg_db) {
			best_cand = &clist[i];
			best_avg_db = avg;
		}
	}

	/* perform handover, if there is a candidate */
	if (best_cand) {
		any_ho = 1;
		log_bts_subscr(DHODEC, LOGL_INFO, best_cand->lchan);
		LOGPC(DHODEC, LOGL_INFO, "Best candidate BTS %d (RX level %d) "
			"without congestion found.\n", best_cand->bts->nr,
			rxlev2dbm(best_cand->avg));
		if (is_improved)
			LOGP(DHODEC, LOGL_INFO, "(is improved due to "
				"AHS -> AFS)\n");
		trigger_handover_or_assignment(best_cand->lchan, best_cand->bts,
			best_cand->requirements & REQUIREMENT_B_MASK);
#if 0
		/* if there is still congestion, mark lchan as deleted
		 * and redo this process */
		if (best_cand->lchan->type == GSM_LCHAN_TCH_H)
			tchh_congestion--;
		else
			tchf_congestion--;
		if (tchf_congestion > 0 || tchh_congestion > 0) {
			delete_lchan = best_cand->lchan;
			best_cand = NULL;
			goto next_b1;
		}
#else
		/* must exit here, because triggering handover/assignment
		 * will cause change in requirements. more check for this
		 * bts is performed in the next iteration.
		 */
#endif
		goto exit;
	}

#if 0
next_b2:
#endif
	/* select worst candidate that fulfills requirement B,
	 * select candidates that change from AHS to AFS only */
	if (tchh_congestion > 0) {
		/* since this will only check half rate channels, it will
		 * only need to be checked, if tchh is congested */
		worst_avg_db = 999;
		for (i = 0; i < candidates; i++) {
			/* delete subscriber that just have handovered */
			if (clist[i].lchan == delete_lchan)
				clist[i].lchan = NULL;
			/* omit all subscribers that are handovered */
			if (!clist[i].lchan)
				continue;

			if (!(clist[i].requirements & REQUIREMENT_B_MASK))
				continue;
			/* omit all but assignment from AHS to AFS */
			if (clist[i].lchan->ts->trx->bts != clist[i].bts
			 || clist[i].lchan->type != GSM_LCHAN_TCH_H
			 || !(clist[i].requirements & REQUIREMENT_B_TCHF))
				continue;

			avg = clist[i].avg;
			/* improve AHS */
			if (clist[i].lchan->tch_mode == GSM48_CMODE_SPEECH_AMR
			 && clist[i].lchan->type == GSM_LCHAN_TCH_H) {
				avg += clist[i].bts->handover.afs_rxlev_improve;
				is_improved = 1;
			} else
				is_improved = 0;
			if (avg < worst_avg_db) {
				worst_cand = &clist[i];
				worst_avg_db = avg;
			}
		}
	}

	/* perform handover, if there is a candidate */
	if (worst_cand) {
		any_ho = 1;
		LOGP(DHODEC, LOGL_INFO, "Worst candidate for assignment "
			"(RX level %d) from TCH/H -> TCH/F without congestion "
			"found.\n", rxlev2dbm(worst_cand->avg));
		if (is_improved)
			LOGP(DHODEC, LOGL_INFO, "(is improved due to "
				"AHS -> AFS)\n");
		trigger_handover_or_assignment(worst_cand->lchan,
			worst_cand->bts,
			worst_cand->requirements & REQUIREMENT_B_MASK);
#if 0
		/* if there is still congestion, mark lchan as deleted
		 * and redo this process */
		tchh_congestion--;
		if (tchh_congestion > 0) {
			delete_lchan = worst_cand->lchan;
			best_cand = NULL;
			goto next_b2;
		}
#else
		/* must exit here, because triggering handover/assignment
		 * will cause change in requirements. more check for this
		 * bts is performed in the next iteration.
		 */
#endif
		goto exit;
	}

#if 0
next_c1:
#endif
	/* select best candidate that fulfills requirement C,
	 * omit change from AHS to AFS */
	best_avg_db = 0;
	for (i = 0; i < candidates; i++) {
		/* delete subscriber that just have handovered */
		if (clist[i].lchan == delete_lchan)
			clist[i].lchan = NULL;
		/* omit all subscribers that are handovered */
		if (!clist[i].lchan)
			continue;

		if (!(clist[i].requirements & REQUIREMENT_C_MASK))
			continue;
		/* omit assignment from AHS to AFS */
		if (clist[i].lchan->ts->trx->bts == clist[i].bts
		 && clist[i].lchan->type == GSM_LCHAN_TCH_H
		 && (clist[i].requirements & REQUIREMENT_C_TCHF))
			continue;
		/* omit candidates that will not solve/reduce congestion */
		if (clist[i].lchan->type == GSM_LCHAN_TCH_F
		 && tchf_congestion <= 0)
			continue;
		if (clist[i].lchan->type == GSM_LCHAN_TCH_H
		 && tchh_congestion <= 0)
			continue;

		avg = clist[i].avg;
		/* improve AHS */
		if (clist[i].lchan->tch_mode == GSM48_CMODE_SPEECH_AMR
		 && clist[i].lchan->type == GSM_LCHAN_TCH_H
		 && (clist[i].requirements & REQUIREMENT_C_TCHF)) {
			avg += clist[i].bts->handover.afs_rxlev_improve;
			is_improved = 1;
		} else
			is_improved = 0;
		if (avg > best_avg_db) {
			best_cand = &clist[i];
			best_avg_db = avg;
		}
	}

	/* perform handover, if there is a candidate */
	if (best_cand) {
		any_ho = 1;
		LOGP(DHODEC, LOGL_INFO, "Best candidate BTS %d (RX level %d) "
			"with less or equal congestion found.\n",
			best_cand->bts->nr, rxlev2dbm(best_cand->avg));
		if (is_improved)
			LOGP(DHODEC, LOGL_INFO, "(is improved due to "
				"AHS -> AFS)\n");
		trigger_handover_or_assignment(best_cand->lchan, best_cand->bts,
			best_cand->requirements & REQUIREMENT_C_MASK);
#if 0
		/* if there is still congestion, mark lchan as deleted
		 * and redo this process */
		if (best_cand->lchan->type == GSM_LCHAN_TCH_H)
			tchh_congestion--;
		else
			tchf_congestion--;
		if (tchf_congestion > 0 || tchh_congestion > 0) {
			delete_lchan = best_cand->lchan;
			best_cand = NULL;
			goto next_c1;
		}
#else
		/* must exit here, because triggering handover/assignment
		 * will cause change in requirements. more check for this
		 * bts is performed in the next iteration.
		 */
#endif
		goto exit;
	}

#if 0
next_c2:
#endif
	/* select worst candidate that fulfills requirement C,
	 * select candidates that change from AHS to AFS only */
	if (tchh_congestion > 0) {
		/* since this will only check half rate channels, it will
		 * only need to be checked, if tchh is congested */
		worst_avg_db = 999;
		for (i = 0; i < candidates; i++) {
			/* delete subscriber that just have handovered */
			if (clist[i].lchan == delete_lchan)
				clist[i].lchan = NULL;
			/* omit all subscribers that are handovered */
			if (!clist[i].lchan)
				continue;

			if (!(clist[i].requirements & REQUIREMENT_C_MASK))
				continue;
			/* omit all but assignment from AHS to AFS */
			if (clist[i].lchan->ts->trx->bts != clist[i].bts
			 || clist[i].lchan->type != GSM_LCHAN_TCH_H
			 || !(clist[i].requirements & REQUIREMENT_C_TCHF))
				continue;

			avg = clist[i].avg;
			/* improve AHS */
			if (clist[i].lchan->tch_mode == GSM48_CMODE_SPEECH_AMR
			 && clist[i].lchan->type == GSM_LCHAN_TCH_H) {
				avg += clist[i].bts->handover.afs_rxlev_improve;
				avg += clist[i].bts->handover.afs_rxlev_improve;
				is_improved = 1;
			} else
				is_improved = 0;
			if (avg < worst_avg_db) {
				worst_cand = &clist[i];
				worst_avg_db = avg;
			}
		}
	}

	/* perform handover, if there is a candidate */
	if (worst_cand) {
		any_ho = 1;
		LOGP(DHODEC, LOGL_INFO, "Worst candidate for assignment "
			"(RX level %d) from TCH/H -> TCH/F with less or equal "
			"congestion found.\n", rxlev2dbm(worst_cand->avg));
		if (is_improved)
			LOGP(DHODEC, LOGL_INFO, "(is improved due to "
				"AHS -> AFS)\n");
		trigger_handover_or_assignment(worst_cand->lchan,
			worst_cand->bts,
			worst_cand->requirements & REQUIREMENT_C_MASK);
#if 0
		/* if there is still congestion, mark lchan as deleted
		 * and redo this process */
		tchh_congestion--;
		if (tchh_congestion > 0) {
			delete_lchan = worst_cand->lchan;
			worst_cand = NULL;
			goto next_c2;
		}
#else
		/* must exit here, because triggering handover/assignment
		 * will cause change in requirements. more check for this
		 * bts is performed in the next iteration.
		 */
#endif
		goto exit;
	}

exit:
	/* free array */
	talloc_free(clist);

	if (tchf_congestion <= 0 && tchh_congestion <= 0)
		LOGP(DHODEC, LOGL_INFO, "Congestion at BTS %d solved!\n",
			bts->nr);
	else if (any_ho)
		LOGP(DHODEC, LOGL_INFO, "Congestion at BTS %d reduced!\n",
			bts->nr);
	else
		LOGP(DHODEC, LOGL_INFO, "Congestion at BTS %d can't be "
			"reduced/solved!\n", bts->nr);

	return rc;
}
void congestion_check_2(void *data)
{
	int min_free_tchf, min_free_tchh;
	int tchf_count, tchh_count;
	struct gsm_bts *bts;
	int n = 0;

	LOGP(DHODEC, LOGL_DEBUG, "Checking for congestion of all BTS\n");

	ho_reason = HO_REASON_CONGESTION;

	/* loop through all bts */
	llist_for_each_entry(bts, &bsc_gsmnet->bts_list, list) {
		/* only check BTS if TRX 0 is usable */
		if (!trx_is_usable(bts->c0))
			continue;

		/* only check BTS if handover or assignment is enabled */
		if (!bts->handover.as_active
		 && !bts->handover.ho_active)
			continue;

		min_free_tchf = bts->handover.min_free_tchf;
		min_free_tchh = bts->handover.min_free_tchh;

		/* only check BTS with congestion level set */
		if (!min_free_tchf && !min_free_tchh)
			continue;

		tchf_count = lc_count_bts(bts, GSM_PCHAN_TCH_F);
		tchh_count = lc_count_bts(bts, GSM_PCHAN_TCH_H);

		/* only check BTS if congested */
		if (tchf_count >= min_free_tchf && tchh_count >= min_free_tchh)
			continue;

		/* try resolving congestion of bts */
		congestion_check_bts(bts, min_free_tchf - tchf_count,
				min_free_tchh - tchh_count);
		n++;
	}

	if (!n)
		LOGP(DHODEC, LOGL_DEBUG, "No congested BTS\n");

	/* schedule next event */
	osmo_timer_schedule(&bsc_gsmnet->ho_congest_timer,
		bsc_gsmnet->ho_congest_timeout, 0);
}

void init_ho_timer_2(void)
{
	if (!bsc_gsmnet->ho_congest_timeout)
		return;
	bsc_gsmnet->ho_congest_timer.cb = congestion_check_2;
	bsc_gsmnet->ho_congest_timer.data = NULL;
	osmo_timer_schedule(&bsc_gsmnet->ho_congest_timer,
		bsc_gsmnet->ho_congest_timeout, 0);
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
		attempt_handover_after_mr(lchan_data->mr);
		break;
	}

	return 0;
}

void init_ho_2(void)
{
	osmo_signal_register_handler(SS_LCHAN, ho_dec_sig_cb, NULL);
}

