/* GPRS SNDCP protocol implementation as per 3GPP TS 04.65 */

/* (C) 2010 by Harald Welte <laforge@gnumonks.org>
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

#include <errno.h>
#include <stdint.h>

#include <osmocore/msgb.h>
#include <osmocore/linuxlist.h>
#include <osmocore/timer.h>
#include <osmocore/talloc.h>

#include <openbsc/gsm_data.h>
#include <openbsc/debug.h>
#include <openbsc/gprs_bssgp.h>
#include <openbsc/gprs_llc.h>

/* Chapter 7.2: SN-PDU Formats */
struct sndcp_common_hdr {
	/* octet 1 */
	uint8_t nsapi:4;
	uint8_t more:1;
	uint8_t type:1;
	uint8_t first:1;
	uint8_t spare:1;
	/* octet 2 */
	uint8_t pcomp;
	uint8_t dcomp;
};

struct sndcp_udata_hdr {
	/* octet 3 */
	uint8_t npdu_high:4;
	uint8_t seg_nr:4;
	/* octet 4 */
	uint8_t npdu_low;
};

/* Entry point for the LL-UNITDATA.indication */
int sndcp_unitdata_ind(struct msgb *msg, uint8_t sapi, uint8_t *hdr, uint8_t len)
{
	struct sndcp_udata_hdr *suh;
	uint16_t npdu;

	if (suh->type == 0) {
		LOGP(DGPRS, LOGL_ERROR, "SN-DATA PDU at unitdata_ind() function\n");
		return -EINVAL;
	}

	npdu = (suh->npdu_high << 8) | suh->npdu_low;
}

