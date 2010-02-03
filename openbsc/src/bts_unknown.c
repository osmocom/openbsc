/* Generic BTS - VTY code tries to allocate this BTS before type is known */

/* (C) 2010 by Daniel Willmann <daniel@totalueberwachung.de>
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

#include <sys/types.h>

#include <openbsc/gsm_data.h>
#include <openbsc/tlv.h>
#include <openbsc/abis_nm.h>

static struct gsm_bts_model model_unknown = {
	.type = GSM_BTS_TYPE_UNKNOWN,
	.nm_att_tlvdef = {
		.def = {
		},
	},
};

int bts_model_unknown_init(void)
{
	return gsm_bts_model_register(&model_unknown);
}
