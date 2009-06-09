/*
 * (C) 2008 by Daniel Willmann <daniel@totalueberwachung.de>
 * (C) 2009 by Holger Hans Peter Freyther <zecke@selfish.org>
 * (C) 2009 by Harald Welte <laforge@gnumonks.org>
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

#include <openbsc/gsm_utils.h>
#include <stdlib.h>
#include <string.h>

/* GSM 03.38 6.2.1 Charachter packing */
int gsm_7bit_decode(char *text, const u_int8_t *user_data, u_int8_t length)
{
	u_int8_t d_off = 0, b_off = 0;
	u_int8_t i;

	for (i=0;i<length;i++) {
		text[i] = ((user_data[d_off] + (user_data[d_off+1]<<8)) & (0x7f<<b_off))>>b_off;
		b_off += 7;
		if (b_off >= 8) {
			d_off += 1;
			b_off -= 8;
		}
	}
	text[i] = '\0';
	return 0;
}

/* GSM 03.38 6.2.1 Charachter packing */
int gsm_7bit_encode(u_int8_t *result, const char *data)
{
	int i;
	u_int8_t d_off = 0, b_off = 0;
	const int length = strlen(data);
	int out_length = (length * 8)/7;

	memset(result, 0, out_length);

	for (i = 0; i < length; ++i) {
		u_int8_t first  = (data[i] & 0x7f) << b_off;
		u_int8_t second = (data[i] & 0x7f) >> (8 - b_off);
    
		result[d_off] |= first;
		if (second != 0)
			result[d_off + 1] = second;

		b_off += 7;

		if (b_off >= 8) {
			d_off += 1;
			b_off -= 8;
		}
	}

	return out_length;
}
