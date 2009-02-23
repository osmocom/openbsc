/*
 * (C) 2008 by Daniel Willmann <daniel@totalueberwachung.de>
 * (C) 2009 by Holger Hans Peter Freyther <zecke@selfish.org>
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
#include <malloc.h>
#include <string.h>

/* GSM 03.38 6.2.1 Charachter packing */
char *gsm_7bit_decode(u_int8_t *user_data, u_int8_t length)
{
	u_int8_t d_off = 0, b_off = 0;
	u_int8_t i;
	char *text = malloc(length+1);

	for (i=0;i<length;i++) {
		text[i] = ((user_data[d_off] + (user_data[d_off+1]<<8)) & (0x7f<<b_off))>>b_off;
		b_off += 7;
		if (b_off >= 8) {
			d_off += 1;
			b_off -= 8;
		}
	}
	text[i] = '\0';
	return text;
}

/* GSM 03.38 6.2.1 Charachter packing */
u_int8_t *gsm_7bit_encode(const char *data, u_int8_t *out_length)
{
	int i;
	u_int8_t d_off = 0, b_off = 0;
	const int length = strlen(data);
	char *result = malloc(length + 1);
	memset(result, 0, length + 1);

	for (i = 0; i < length; ++i) {
		u_int8_t first  = (data[i] & 0x7f) << b_off;
		u_int8_t second = (data[i] & 0x7f) >> (7 - b_off);

		result[d_off] |= first;
		if (second != 0)
			result[d_off + 1] = second;

		b_off += 7;

		if (b_off >= 8) {
			d_off += 1;
			b_off -= 8;
		}
	}

	*out_length = d_off;

	return result;
}
