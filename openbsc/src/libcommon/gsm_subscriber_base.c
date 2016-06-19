/* The concept of a subscriber as seen by the BSC */

/* (C) 2008 by Harald Welte <laforge@gnumonks.org>
 * (C) 2009-2010 by Holger Hans Peter Freyther <zecke@selfish.org>
 * (C) 2010 by On-Waves
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

#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>

#include <osmocom/core/talloc.h>
#include <osmocom/core/utils.h>
#include <openbsc/gsm_subscriber.h>
#include <openbsc/debug.h>
#include <openbsc/vlr.h>

LLIST_HEAD(active_subscribers);
void *tall_subscr_ctx;

/* return static buffer with printable name of VLR subscriber */
const char *vlr_subscr_name(struct vlr_subscr *vsub)
{
	static char buf[32];
	if (!vsub)
		return "unknown";
	if (vsub->msisdn[0])
		snprintf(buf, sizeof(buf), "MSISDN:%s", vsub->msisdn);
	else if (vsub->imsi[0])
		snprintf(buf, sizeof(buf), "IMSI:%s", vsub->imsi);
	else if (vsub->tmsi != GSM_RESERVED_TMSI)
		snprintf(buf, sizeof(buf), "TMSI:0x%08x", vsub->tmsi);
	else if (vsub->tmsi_new != GSM_RESERVED_TMSI)
		snprintf(buf, sizeof(buf), "TMSI(new):0x%08x", vsub->tmsi_new);
	else
		return "unknown";
	buf[sizeof(buf)-1] = '\0';
	return buf;
}

const char *vlr_subscr_msisdn_or_name(struct vlr_subscr *vsub)
{
	if (!vsub || !vsub->msisdn[0])
		return vlr_subscr_name(vsub);
	return vsub->msisdn;
}
