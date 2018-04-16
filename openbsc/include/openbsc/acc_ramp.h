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

#pragma once

#include <stdbool.h>
#include <stdint.h>

#include <osmocom/core/timer.h>
#include <osmocom/gsm/protocol/gsm_04_08.h>

/*!
 * Access control class (ACC) ramping is used to slowly make the cell available to
 * an increasing number of MS. This avoids overload at startup time in cases where
 * a lot of MS would discover the new cell and try to connect to it all at once.
 */

#define ACC_RAMP_STEP_SIZE_MIN 1 /* allow at most 1 new ACC per ramp step */
#define ACC_RAMP_STEP_SIZE_DEFAULT ACC_RAMP_STEP_SIZE_MIN
#define ACC_RAMP_STEP_SIZE_MAX 10 /* allow all ACC in one step (effectively disables ramping) */

#define ACC_RAMP_STEP_INTERVAL_MIN 30	/* 30 seconds */
#define ACC_RAMP_STEP_INTERVAL_MAX 600	/* 10 minutes */

/*!
 * Data structure used to manage ACC ramping. Please avoid setting or reading fields
 * in this structure directly. Use the accessor functions below instead.
 */
struct acc_ramp {
	struct gsm_bts *bts; /*!< backpointer to BTS using this ACC ramp */

	bool acc_ramping_enabled; /*!< whether ACC ramping is enabled */

	/*!
	 * Bitmask which keeps track of access control classes that are currently denied
	 * access. The function acc_ramp_apply() uses this mask to modulate bits from
	 * octets 2 and 3 in RACH Control Parameters (see 3GPP 44.018 10.5.2.29).
	 * Ramping is only concerned with ACCs 0-9. While any of the bits 0-9 is set,
	 * the corresponding ACC is barred.
	 * ACCs 11-15 should always be allowed, and ACC 10 denies emergency calls for
	 * all ACCs from 0-9 inclusive; these ACCs are ignored in this implementation.
	 */
	uint16_t barred_accs;

	/*!
	 * This controls the maximum number of ACCs to allow per ramping step (1 - 10).
	 * The compile-time default value is ACC_RAMP_STEP_SIZE_DEFAULT.
	 * This value can be changed by VTY configuration.
	 * A value of ACC_RAMP_STEP_SIZE_MAX effectively disables ramping.
	 */
	unsigned int step_size;

	/*!
	 * Ramping step interval in seconds.
	 * This value depends on the current BTS channel load average, unless
	 * it has been overriden by VTY configuration.
	 */
	unsigned int step_interval_sec;
	bool step_interval_is_fixed;
	struct osmo_timer_list step_timer;
};

/*!
 * Enable or disable ACC ramping.
 * When enabled, ramping begins once acc_ramp_start() is called.
 * When disabled, an ACC ramping process in progress will continue
 * unless acc_ramp_abort() is called as well.
 * \param[in] acc_ramp Pointer to acc_ramp structure.
 */
static inline void acc_ramp_set_enabled(struct acc_ramp *acc_ramp, bool enable)
{
	acc_ramp->acc_ramping_enabled = enable;
}

/*!
 * Return true if ACC ramping is currently enabled, else false.
 * \param[in] acc_ramp Pointer to acc_ramp structure.
 */
static inline bool acc_ramp_is_enabled(struct acc_ramp *acc_ramp)
{
	return acc_ramp->acc_ramping_enabled;
}

/*!
 * Return the current ACC ramp step size.
 * \param[in] acc_ramp Pointer to acc_ramp structure.
 */
static inline unsigned int acc_ramp_get_step_size(struct acc_ramp *acc_ramp)
{
	return acc_ramp->step_size;
}

/*!
 * Return the current ACC ramp step interval (in seconds)
 * \param[in] acc_ramp Pointer to acc_ramp structure.
 */
static inline unsigned int acc_ramp_get_step_interval(struct acc_ramp *acc_ramp)
{
	return acc_ramp->step_interval_sec;
}

/*!
 * If the step interval is dynamic, return true, else return false.
 * \param[in] acc_ramp Pointer to acc_ramp structure.
 */
static inline bool acc_ramp_step_interval_is_dynamic(struct acc_ramp *acc_ramp)
{
	return !(acc_ramp->step_interval_is_fixed);
}

/*!
 * Return bitmasks which correspond to access control classes that are currently
 * denied access. Ramping is only concerned with those bits which control access
 * for ACCs 0-9, and any of the other bits will always be set to zero in these masks, i.e.
 * it is safe to OR these bitmasks with the corresponding fields in struct gsm48_rach_control.
 * \param[in] acc_ramp Pointer to acc_ramp structure.
 */
static inline uint8_t acc_ramp_get_barred_t2(struct acc_ramp *acc_ramp)
{
	return ((acc_ramp->barred_accs >> 8) & 0x03);
};
static inline uint8_t acc_ramp_get_barred_t3(struct acc_ramp *acc_ramp)
{
	return (acc_ramp->barred_accs & 0xff);
}

/*!
 * Potentially mark certain Access Control Classes (ACCs) as barred in accordance to ACC ramping.
 * \param[in] rach_control RACH control parameters in which barred ACCs will be configured.
 * \param[in] acc_ramp Pointer to acc_ramp structure.
 */
static inline void acc_ramp_apply(struct gsm48_rach_control *rach_control, struct acc_ramp *acc_ramp)
{
	rach_control->t2 |= acc_ramp_get_barred_t2(acc_ramp);
	rach_control->t3 |= acc_ramp_get_barred_t3(acc_ramp);
}

void acc_ramp_init(struct acc_ramp *acc_ramp, struct gsm_bts *bts);
int acc_ramp_set_step_size(struct acc_ramp *acc_ramp, unsigned int step_size);
int acc_ramp_set_step_interval(struct acc_ramp *acc_ramp, unsigned int step_interval);
void acc_ramp_set_step_interval_dynamic(struct acc_ramp *acc_ramp);
void acc_ramp_trigger(struct acc_ramp *acc_ramp);
void acc_ramp_abort(struct acc_ramp *acc_ramp);
