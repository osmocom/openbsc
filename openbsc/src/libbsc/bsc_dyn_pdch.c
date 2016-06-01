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

	if (ts->pchan == GSM_PCHAN_TCH_F_PDCH) {
		LOGP(DRSL, LOGL_DEBUG, "trying to PDCH ACT on"
		     " BTS %u TRX %u TS %u\n",
		     ts->trx->bts->nr, ts->trx->nr, ts->nr);
		rc = rsl_ipacc_pdch_activate(ts, 1);
		if (rc != 0) {
			LOGP(DRSL, LOGL_ERROR,
			     "Failed to activate PDCH on"
			     " BTS %u TRX %u TS %u: %d\n",
			     ts->trx->bts->nr, ts->trx->nr, ts->nr, rc);
		}
	}
}
