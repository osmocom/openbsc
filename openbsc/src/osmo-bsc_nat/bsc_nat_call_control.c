/* Local Call-Control Filter Code */
/*
 * (C) 2013 by Holger Hans Peter Freyther <zecke@selfish.org>
 * (C) 2013 by On-Waves
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

#include <openbsc/bsc_nat.h>
#include <openbsc/bsc_msc.h>
#include <openbsc/vty.h>

#include <osmocom/core/talloc.h>

void bsc_cc_update_msc_ip(struct bsc_nat *nat, const char *ip)
{
	if (ip) {
		bsc_replace_string(nat, &nat->local_dest->ip, ip);
	} else {
		talloc_free(nat->local_dest->ip);
		nat->local_dest->ip = NULL;
	}
}

