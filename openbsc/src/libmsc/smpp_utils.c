
/* (C) 2012-2013 by Harald Welte <laforge@gnumonks.org>
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
 */


#include "smpp_smsc.h"
#include <openbsc/debug.h>


int smpp_determine_scheme(uint8_t dcs, uint8_t *data_coding, int *mode)
{
	if ((dcs & 0xF0) == 0xF0) {
		if (dcs & 0x04) {
			/* bit 2 == 1: 8bit data */
			*data_coding = 0x02;
			*mode = MODE_8BIT;
		} else {
			/* bit 2 == 0: default alphabet */
			*data_coding = 0x01;
			*mode = MODE_7BIT;
		}
	} else if ((dcs & 0xE0) == 0) {
		switch (dcs & 0xC) {
		case 0:
			*data_coding = 0x01;
			*mode = MODE_7BIT;
			break;
		case 4:
			*data_coding = 0x02;
			*mode = MODE_8BIT;
			break;
		case 8:
			*data_coding = 0x08;     /* UCS-2 */
			*mode = MODE_8BIT;
			break;
		default:
			goto unknown_mo;
		}
	} else {
unknown_mo:
		LOGP(DLSMS, LOGL_ERROR, "SMPP MO Unknown Data Coding 0x%02x\n", dcs);
		return -1;
	}

	return 0;

}
