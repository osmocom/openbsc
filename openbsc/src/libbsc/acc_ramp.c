/* (C) 2018 by sysmocom s.f.m.c. GmbH <info@sysmocom.de>
 *
 * Author: Stefan Sperling <ssperling@sysmocom.de>
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

#include <strings.h>
#include <errno.h>
#include <stdbool.h>

#include <openbsc/debug.h>
#include <openbsc/acc_ramp.h>
#include <openbsc/gsm_data.h>
#include <openbsc/chan_alloc.h>
#include <openbsc/signal.h>
#include <openbsc/abis_nm.h>

/*
 * Check if an ACC has been permanently barred for a BTS,
 * e.g. with the 'rach access-control-class' VTY command.
 */
static bool acc_is_permanently_barred(struct gsm_bts *bts, unsigned int acc)
{
	OSMO_ASSERT(acc >= 0 && acc <= 9);
	if (acc == 8 || acc == 9)
		return (bts->si_common.rach_control.t2 & (1 << (acc - 8)));
	return (bts->si_common.rach_control.t3 & (1 << (acc)));
}

static void allow_one_acc(struct acc_ramp *acc_ramp, unsigned int acc)
{
	OSMO_ASSERT(acc >= 0 && acc <= 9);
	if (acc_ramp->barred_accs & (1 << acc))
		LOGP(DRSL, LOGL_DEBUG, "(bts=%d) ACC RAMP: allowing Access Control Class %u\n", acc_ramp->bts->nr, acc);
	acc_ramp->barred_accs &= ~(1 << acc);
}

static void barr_one_acc(struct acc_ramp *acc_ramp, unsigned int acc)
{
	OSMO_ASSERT(acc >= 0 && acc <= 9);
	if ((acc_ramp->barred_accs & (1 << acc)) == 0)
		LOGP(DRSL, LOGL_DEBUG, "(bts=%d) ACC RAMP: barring Access Control Class %u\n", acc_ramp->bts->nr, acc);
	acc_ramp->barred_accs |= (1 << acc);
}

static void barr_all_accs(struct acc_ramp *acc_ramp)
{
	unsigned int acc;
	for (acc = 0; acc < 10; acc++) {
		if (!acc_is_permanently_barred(acc_ramp->bts, acc))
			barr_one_acc(acc_ramp, acc);
	}
}

static void allow_all_accs(struct acc_ramp *acc_ramp)
{
	unsigned int acc;
	for (acc = 0; acc < 10; acc++) {
		if (!acc_is_permanently_barred(acc_ramp->bts, acc))
			allow_one_acc(acc_ramp, acc);
	}
}

static unsigned int get_next_step_interval(struct acc_ramp *acc_ramp)
{
	struct gsm_bts *bts = acc_ramp->bts;
	uint64_t load;

	if (acc_ramp->step_interval_is_fixed)
		return acc_ramp->step_interval_sec;

	/* Scale the step interval to current channel load average. */
	load = (bts->chan_load_avg << 8); /* convert to fixed-point */
	acc_ramp->step_interval_sec = ((load * ACC_RAMP_STEP_INTERVAL_MAX) / 100) >> 8;
	if (acc_ramp->step_interval_sec < ACC_RAMP_STEP_SIZE_MIN)
		acc_ramp->step_interval_sec = ACC_RAMP_STEP_INTERVAL_MIN;
	else if (acc_ramp->step_interval_sec > ACC_RAMP_STEP_INTERVAL_MAX)
		acc_ramp->step_interval_sec = ACC_RAMP_STEP_INTERVAL_MAX;

	LOGP(DRSL, LOGL_DEBUG, "(bts=%d) ACC RAMP: step interval set to %u seconds based on %u%% channel load average\n",
	     bts->nr, acc_ramp->step_interval_sec, bts->chan_load_avg);
	return acc_ramp->step_interval_sec;
}

static void do_acc_ramping_step(void *data)
{
	struct acc_ramp *acc_ramp = data;
	int i;

	/* Shortcut in case we only do one ramping step. */
	if (acc_ramp->step_size == ACC_RAMP_STEP_SIZE_MAX) {
		allow_all_accs(acc_ramp);
		gsm_bts_set_system_infos(acc_ramp->bts);
		return;
	}

	/* Allow 'step_size' ACCs, starting from ACC0. ACC9 will be allowed last. */
	for (i = 0; i < acc_ramp->step_size; i++) {
		int idx = ffs(acc_ramp_get_barred_t3(acc_ramp));
		if (idx > 0) {
			/* One of ACC0-ACC7 is still bared. */
			unsigned int acc = idx - 1;
			if (!acc_is_permanently_barred(acc_ramp->bts, acc))
				allow_one_acc(acc_ramp, acc);
		} else {
			idx = ffs(acc_ramp_get_barred_t2(acc_ramp));
			if (idx == 1 || idx == 2) {
				/* ACC8 or ACC9 is still barred. */
				unsigned int acc = idx - 1 + 8;
				if (!acc_is_permanently_barred(acc_ramp->bts, acc))
					allow_one_acc(acc_ramp, acc);
			} else {
				/* All ACCs are now allowed. */
				break;
			}
		}
	}

	gsm_bts_set_system_infos(acc_ramp->bts);

	/* If we have not allowed all ACCs yet, schedule another ramping step. */
	if (acc_ramp_get_barred_t2(acc_ramp) != 0x00 ||
	    acc_ramp_get_barred_t3(acc_ramp) != 0x00)
		osmo_timer_schedule(&acc_ramp->step_timer, get_next_step_interval(acc_ramp), 0);
}

/* Implements osmo_signal_cbfn() -- trigger or abort ACC ramping upon changes RF lock state. */
static int acc_ramp_nm_sig_cb(unsigned int subsys, unsigned int signal, void *handler_data, void *signal_data)
{
	struct nm_statechg_signal_data *nsd = signal_data;
	struct acc_ramp *acc_ramp = handler_data;
	struct gsm_bts_trx *trx = NULL;
	bool trigger_ramping = false, abort_ramping = false;

	/* Handled signals map to an Administrative State Change ACK, or a State Changed Event Report. */
	if (signal != S_NM_STATECHG_ADM && signal != S_NM_STATECHG_OPER)
		return 0;

	if (nsd->obj_class != NM_OC_RADIO_CARRIER)
		return 0;

	trx = nsd->obj;

	LOGP(DRSL, LOGL_DEBUG, "(bts=%d,trx=%d) ACC RAMP: administrative state %s -> %s\n",
	    acc_ramp->bts->nr, trx->nr,
	    get_value_string(abis_nm_adm_state_names, nsd->old_state->administrative),
	    get_value_string(abis_nm_adm_state_names, nsd->new_state->administrative));
	LOGP(DRSL, LOGL_DEBUG, "(bts=%d,trx=%d) ACC RAMP: operational state %s -> %s\n",
	    acc_ramp->bts->nr, trx->nr,
	    abis_nm_opstate_name(nsd->old_state->operational),
	    abis_nm_opstate_name(nsd->new_state->operational));

	/* We only care about state changes of the first TRX. */
	if (trx->nr != 0)
		return 0;

	/* RSL must already be up. We cannot send RACH system information to the BTS otherwise. */
	if (trx->rsl_link == NULL) {
		LOGP(DRSL, LOGL_DEBUG, "(bts=%d,trx=%d) ACC RAMP: ignoring state change because RSL link is down\n",
		     acc_ramp->bts->nr, trx->nr);
		return 0;
	}

	/* Trigger or abort ACC ramping based on the new state of this TRX. */
	if (nsd->old_state->administrative != nsd->new_state->administrative) {
		switch (nsd->new_state->administrative) {
		case NM_STATE_UNLOCKED:
			if (nsd->old_state->operational != nsd->new_state->operational) {
				/*
				 * Administrative and operational state have both changed.
				 * Trigger ramping only if TRX 0 will be both enabled and unlocked.
				 */
				if (nsd->new_state->operational == NM_OPSTATE_ENABLED)
					trigger_ramping = true;
				else
					LOGP(DRSL, LOGL_DEBUG, "(bts=%d,trx=%d) ACC RAMP: ignoring state change "
					     "because TRX is transitioning into operational state '%s'\n",
					     acc_ramp->bts->nr, trx->nr,
					     abis_nm_opstate_name(nsd->new_state->operational));
			} else {
				/*
				 * Operational state has not changed.
				 * Trigger ramping only if TRX 0 is already usable.
				 */
				if (trx_is_usable(trx))
					trigger_ramping = true;
				else
					LOGP(DRSL, LOGL_DEBUG, "(bts=%d,trx=%d) ACC RAMP: ignoring state change "
					     "because TRX is not usable\n", acc_ramp->bts->nr, trx->nr);
			}
			break;
		case NM_STATE_LOCKED:
		case NM_STATE_SHUTDOWN:
			abort_ramping = true;
			break;
		case NM_STATE_NULL:
		default:
			LOGP(DRSL, LOGL_NOTICE, "(bts=%d) ACC RAMP: unrecognized administrative state '0x%x' "
			    "reported for TRX 0\n", acc_ramp->bts->nr, nsd->new_state->administrative);
			break;
		}
	}
	if (nsd->old_state->operational != nsd->new_state->operational) {
		switch (nsd->new_state->operational) {
		case NM_OPSTATE_ENABLED:
			if (nsd->old_state->administrative != nsd->new_state->administrative) {
				/*
				 * Administrative and operational state have both changed.
				 * Trigger ramping only if TRX 0 will be both enabled and unlocked.
				 */
				if (nsd->new_state->administrative == NM_STATE_UNLOCKED)
					trigger_ramping = true;
				else
					LOGP(DRSL, LOGL_DEBUG, "(bts=%d,trx=%d) ACC RAMP: ignoring state change "
					     "because TRX is transitioning into administrative state '%s'\n",
					     acc_ramp->bts->nr, trx->nr,
					     get_value_string(abis_nm_adm_state_names, nsd->new_state->administrative));
			} else {
				/*
				 * Administrative state has not changed.
				 * Trigger ramping only if TRX 0 is already unlocked.
				 */
				if (trx->mo.nm_state.administrative == NM_STATE_UNLOCKED)
					trigger_ramping = true;
				else
					LOGP(DRSL, LOGL_DEBUG, "(bts=%d,trx=%d) ACC RAMP: ignoring state change "
					     "because TRX is in administrative state '%s'\n",
					     acc_ramp->bts->nr, trx->nr,
					     get_value_string(abis_nm_adm_state_names, trx->mo.nm_state.administrative));
			}
			break;
		case NM_OPSTATE_DISABLED:
			abort_ramping = true;
			break;
		case NM_OPSTATE_NULL:
		default:
			LOGP(DRSL, LOGL_NOTICE, "(bts=%d) ACC RAMP: unrecognized operational state '0x%x' "
			     "reported for TRX 0\n", acc_ramp->bts->nr, nsd->new_state->administrative);
			break;
		}
	}

	if (trigger_ramping)
		acc_ramp_trigger(acc_ramp);
	else if (abort_ramping)
		acc_ramp_abort(acc_ramp);

	return 0;
}

/*!
 * Initialize an acc_ramp data structure.
 * Storage for this structure must be provided by the caller.
 *
 * By default, ACC ramping is disabled and all ACCs are allowed.
 *
 * \param[in] acc_ramp Pointer to acc_ramp structure to be initialized.
 * \param[in] bts BTS which uses this ACC ramp data structure.
 */
void acc_ramp_init(struct acc_ramp *acc_ramp, struct gsm_bts *bts)
{
	acc_ramp->bts = bts;
	acc_ramp_set_enabled(acc_ramp, false);
	acc_ramp->step_size = ACC_RAMP_STEP_SIZE_DEFAULT;
	acc_ramp->step_interval_sec = ACC_RAMP_STEP_INTERVAL_MIN;
	acc_ramp->step_interval_is_fixed = false;
	allow_all_accs(acc_ramp);
	osmo_timer_setup(&acc_ramp->step_timer, do_acc_ramping_step, acc_ramp);
	osmo_signal_register_handler(SS_NM, acc_ramp_nm_sig_cb, acc_ramp);
}

/*!
 * Change the ramping step size which controls how many ACCs will be allowed per ramping step.
 * Returns negative on error (step_size out of range), else zero.
 * \param[in] acc_ramp Pointer to acc_ramp structure.
 * \param[in] step_size The new step size value.
 */
int acc_ramp_set_step_size(struct acc_ramp *acc_ramp, unsigned int step_size)
{
	if (step_size < ACC_RAMP_STEP_SIZE_MIN || step_size > ACC_RAMP_STEP_SIZE_MAX)
		return -ERANGE;

	acc_ramp->step_size = step_size;
	LOGP(DRSL, LOGL_DEBUG, "(bts=%d) ACC RAMP: ramping step size set to %u\n", acc_ramp->bts->nr, step_size);
	return 0;
}

/*!
 * Change the ramping step interval to a fixed value. Unless this function is called,
 * the interval is automatically scaled to the BTS channel load average.
 * \param[in] acc_ramp Pointer to acc_ramp structure.
 * \param[in] step_interval The new fixed step interval in seconds.
 */
int acc_ramp_set_step_interval(struct acc_ramp *acc_ramp, unsigned int step_interval)
{
	if (step_interval < ACC_RAMP_STEP_INTERVAL_MIN || step_interval > ACC_RAMP_STEP_INTERVAL_MAX)
		return -ERANGE;

	acc_ramp->step_interval_sec = step_interval;
	acc_ramp->step_interval_is_fixed = true;
	LOGP(DRSL, LOGL_DEBUG, "(bts=%d) ACC RAMP: ramping step interval set to %u seconds\n",
	     acc_ramp->bts->nr, step_interval);
	return 0;
}

/*!
 * Clear a previously set fixed ramping step interval, so that the interval
 * is again automatically scaled to the BTS channel load average.
 * \param[in] acc_ramp Pointer to acc_ramp structure.
 */
void acc_ramp_set_step_interval_dynamic(struct acc_ramp *acc_ramp)
{
	acc_ramp->step_interval_is_fixed = false;
	LOGP(DRSL, LOGL_DEBUG, "(bts=%d) ACC RAMP: ramping step interval set to 'dynamic'\n",
	     acc_ramp->bts->nr);
}

/*!
 * Determine if ACC ramping should be started according to configuration, and
 * begin the ramping process if the necessary conditions are present.
 * Perform at least one ramping step to allow 'step_size' ACCs.
 * If 'step_size' is ACC_RAMP_STEP_SIZE_MAX, or if ACC ramping is disabled,
 * all ACCs will be allowed immediately.
 * \param[in] acc_ramp Pointer to acc_ramp structure.
 */
void acc_ramp_trigger(struct acc_ramp *acc_ramp)
{
	/* Abort any previously running ramping process and allow all available ACCs. */
	acc_ramp_abort(acc_ramp);

	if (acc_ramp_is_enabled(acc_ramp)) {
		/* Set all available ACCs to barred and start ramping up. */
		barr_all_accs(acc_ramp);
		do_acc_ramping_step(acc_ramp);
	}
}

/*!
 * Abort the ramping process and allow all available ACCs immediately.
 * \param[in] acc_ramp Pointer to acc_ramp structure.
 */
void acc_ramp_abort(struct acc_ramp *acc_ramp)
{
	if (osmo_timer_pending(&acc_ramp->step_timer))
		osmo_timer_del(&acc_ramp->step_timer);

	allow_all_accs(acc_ramp);
}

