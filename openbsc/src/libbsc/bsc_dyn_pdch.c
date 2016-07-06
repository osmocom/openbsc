/* Dynamic PDCH initialisation implementation shared across NM and RSL */

/* (C) 2016 by sysmocom s.f.m.c. GmbH <info@sysmocom.de>
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

#include <osmocom/core/logging.h>
#include <openbsc/debug.h>
#include <openbsc/gsm_data.h>
#include <openbsc/abis_rsl.h>

void dyn_pdch_init(struct gsm_bts_trx_ts *ts)
{
	int rc;

	/* Clear all dyn PDCH flags */
	ts->flags &= ~(TS_F_PDCH_PENDING_MASK | TS_F_PDCH_ACTIVE);

	/* Nothing to do if not a dynamic channel. */
	if (ts->pchan != GSM_PCHAN_TCH_F_PDCH)
		return;

	if (ts->trx->bts->gprs.mode == BTS_GPRS_NONE) {
		LOGP(DRSL, LOGL_NOTICE, "%s %s: GPRS mode is 'none':"
		     " not activating PDCH.\n",
		     gsm_ts_name(ts), gsm_pchan_name(ts->pchan));
		return;
	}

	LOGP(DRSL, LOGL_DEBUG, "%s %s: trying to PDCH ACT\n",
	     gsm_ts_name(ts), gsm_pchan_name(ts->pchan));

	rc = rsl_ipacc_pdch_activate(ts, 1);
	if (rc != 0)
		LOGP(DRSL, LOGL_ERROR, "%s %s: PDCH ACT failed\n",
		     gsm_ts_name(ts), gsm_pchan_name(ts->pchan));
}
