/* TRAU frame handling according to GSM TS 08.60 */

/* (C) 2009 by Harald Welte <laforge@gnumonks.org>
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

#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>

#include <openbsc/trau_frame.h>

static u_int32_t get_bits(u_int8_t *bitbuf, int offset, int num)
{
	int i;
	u_int32_t ret = 0;

	for (i = offset; i < offset + num; i++) {
		ret = ret << 1;
		if (bitbuf[i])
			ret |= 1;
	}
	return ret;
}

/* Decode according to 3.1.1 */
static void decode_fr(struct decoded_trau_frame *fr, u_int8_t *trau_bits)
{
	int i;
	int d_idx = 0;

	/* C1 .. C15 */
	memcpy(fr->c_bits+0, trau_bits+17, 15);
	/* C16 .. C21 */
	memcpy(fr->c_bits+15, trau_bits+310, 6);
	/* T1 .. T4 */
	memcpy(fr->t_bits+0, trau_bits+316, 4);
	/* D1 .. D255 */
	for (i = 32; i < 304; i+= 16) {
		memcpy(fr->d_bits + d_idx, trau_bits+i+1, 15);
		d_idx += 15;
	}
	/* D256 .. D260 */
	memcpy(fr->d_bits + d_idx, trau_bits + 305, 5);
}

static void decode_amr(struct decoded_trau_frame *fr, u_int8_t *trau_bits)
{
	int i;
	int d_idx = 0;

	/* C1 .. C15 */
	memcpy(fr->c_bits+0, trau_bits+17, 15);
	/* C16 .. C25 */
	memcpy(fr->c_bits+15, trau_bits+33, 10);
	/* T1 .. T4 */
	memcpy(fr->t_bits+0, trau_bits+316, 4);
	/* D1 .. D5 */
	memcpy(fr->d_bits, trau_bits+43, 5);
	/* D6 .. D245 */
	for (i = 48; i < 304; i += 16) {
		memcpy(fr->d_bits + d_idx, trau_bits+i+1, 15);
		d_idx += 15;
	}
	/* D246 .. D256 */
	memcpy(fr->d_bits + d_idx, trau_bits + 305, 11);
}

int decode_trau_frame(struct decoded_trau_frame *fr, u_int8_t *trau_bits)
{
	u_int8_t cbits5 = get_bits(trau_bits, 17, 5);

	switch (cbits5) {
	case TRAU_FT_FR_UP:
	case TRAU_FT_FR_DOWN:
	case TRAU_FT_EFR:
		decode_fr(fr, trau_bits);
		break;
	case TRAU_FT_AMR:
		decode_amr(fr, trau_bits);
		break;
	case TRAU_FT_OM_UP:
	case TRAU_FT_OM_DOWN:
	case TRAU_FT_DATA_UP:
	case TRAU_FT_DATA_DOWN:
	case TRAU_FT_D145_SYNC:
	case TRAU_FT_EDATA:
		fprintf(stderr, "unimplemented TRAU Frame Type 0x%02x\n", cbits5);
		return -1;
		break;
	default:
		fprintf(stderr, "unknown TRAU Frame Type 0x%02x\n", cbits5);
		return -1;
		break;
	}

	return 0;
}
