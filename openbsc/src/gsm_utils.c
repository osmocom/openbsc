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

#include <openbsc/gsm_data.h>
#include <openbsc/gsm_utils.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

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

/* determine power control level for given dBm value, as indicated
 * by the tables in chapter 4.1.1 of GSM TS 05.05 */
int ms_pwr_ctl_lvl(enum gsm_band band, unsigned int dbm)
{
	switch (band) {
	case GSM_BAND_400:
	case GSM_BAND_900:
	case GSM_BAND_850:
		if (dbm >= 39)
			return 0;
		else if (dbm < 5)
			return 19;
		else
			return 2 + ((39 - dbm) / 2);
		break;
	case GSM_BAND_1800:
		if (dbm >= 36)
			return 29;
		else if (dbm >= 34)	
			return 30;
		else if (dbm >= 32)
			return 31;
		else
			return (30 - dbm) / 2;
		break;
	case GSM_BAND_1900:
		if (dbm >= 33)
			return 30;
		else if (dbm >= 32)
			return 31;
		else
			return (30 - dbm) / 2;
		break;
	}
	return -EINVAL;
}

int ms_pwr_dbm(enum gsm_band band, u_int8_t lvl)
{
	lvl &= 0x1f;

	switch (band) {
	case GSM_BAND_400:
	case GSM_BAND_900:
	case GSM_BAND_850:
		if (lvl < 2)
			return 39;
		else if (lvl < 20)
			return 39 - ((lvl - 2) * 2) ;
		else
			return 5;
		break;
	case GSM_BAND_1800:
		if (lvl < 16)
			return 30 - (lvl * 2);
		else if (lvl < 29)
			return 0;
		else
			return 36 - ((lvl - 29) * 2);
		break;
	case GSM_BAND_1900:
		if (lvl < 16)
			return 30 - (lvl * 2);
		else if (lvl < 30)
			return -EINVAL;
		else
			return 33 - (lvl - 30);
		break;
	}
	return -EINVAL;
}


