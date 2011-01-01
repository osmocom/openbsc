/* TRAU frame handling according to GSM TS 08.60 */

/* (C) 2009 by Harald Welte <laforge@gnumonks.org>
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
#include <errno.h>

#include <openbsc/trau_frame.h>
#include <openbsc/subchan_demux.h>
#include <openbsc/debug.h>

static u_int32_t get_bits(const u_int8_t *bitbuf, int offset, int num)
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
static void decode_fr(struct decoded_trau_frame *fr, const u_int8_t *trau_bits)
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

/* Decode according to 3.1.2 */
static void decode_amr(struct decoded_trau_frame *fr, const u_int8_t *trau_bits)
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

int decode_trau_frame(struct decoded_trau_frame *fr, const u_int8_t *trau_bits)
{
	u_int8_t cbits5 = get_bits(trau_bits, 17, 5);

	switch (cbits5) {
	case TRAU_FT_FR_UP:
	case TRAU_FT_FR_DOWN:
	case TRAU_FT_IDLE_UP:
	case TRAU_FT_IDLE_DOWN:
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
		LOGP(DMUX, LOGL_NOTICE, "can't decode unimplemented TRAU "
			"Frame Type 0x%02x\n", cbits5);
		return -1;
		break;
	default:
		LOGP(DMUX, LOGL_NOTICE, "can't decode unknown TRAU "
			"Frame Type 0x%02x\n", cbits5);
		return -1;
		break;
	}

	return 0;
}

const u_int8_t ft_fr_down_bits[] = { 1, 1, 1, 0, 0 };
const u_int8_t ft_idle_down_bits[] = { 0, 1, 1, 1, 0 };

/* modify an uplink TRAU frame so we can send it downlink */
int trau_frame_up2down(struct decoded_trau_frame *fr)
{
	u_int8_t cbits5 = get_bits(fr->c_bits, 0, 5);

	switch (cbits5) {
	case TRAU_FT_FR_UP:
		memcpy(fr->c_bits, ft_fr_down_bits, 5);
		/* clear time alignment */
		memset(fr->c_bits+5, 0, 6);
		/* FIXME: SP / BFI in case of DTx */
		/* C12 .. C21 are spare and coded as '1' */
		memset(fr->c_bits+11, 0x01, 10);
		break;
	case TRAU_FT_EFR:
		/* clear time alignment */
		memset(fr->c_bits+5, 0, 6);
		/* FIXME: set UFE appropriately */
		/* FIXME: SP / BFI in case of DTx */
		break;
	case TRAU_FT_IDLE_UP:
		memcpy(fr->c_bits, ft_idle_down_bits, 5);
		/* clear time alignment */
		memset(fr->c_bits+5, 0, 6);
		/* FIXME: SP / BFI in case of DTx */
		/* C12 .. C21 are spare and coded as '1' */
		memset(fr->c_bits+11, 0x01, 10);
		break;
	case TRAU_FT_FR_DOWN:
	case TRAU_FT_IDLE_DOWN:
	case TRAU_FT_OM_DOWN:
	case TRAU_FT_DATA_DOWN:
		/* we cannot convert a downlink to a downlink frame */
		return -EINVAL;
		break;
	case TRAU_FT_AMR:
	case TRAU_FT_OM_UP:
	case TRAU_FT_DATA_UP:
	case TRAU_FT_D145_SYNC:
	case TRAU_FT_EDATA:
		LOGP(DMUX, LOGL_NOTICE, "unimplemented TRAU Frame Type "
			"0x%02x\n", cbits5);
		return -1;
		break;
	default:
		LOGP(DMUX, LOGL_NOTICE, "unknown TRAU Frame Type "
			"0x%02x\n", cbits5);
		return -1;
		break;
	}

	return 0;

}

static void encode_fr(u_int8_t *trau_bits, const struct decoded_trau_frame *fr)
{
	int i;
	int d_idx = 0;

	trau_bits[16] = 1;
	/* C1 .. C15 */
	memcpy(trau_bits+17, fr->c_bits+0, 15);
	/* D1 .. D255 */
	for (i = 32; i < 304; i+= 16) {
		trau_bits[i] = 1;
		memcpy(trau_bits+i+1, fr->d_bits + d_idx, 15);
		d_idx += 15;
	}
	/* D256 .. D260 */
	trau_bits[304] = 1;
	memcpy(trau_bits + 305, fr->d_bits + d_idx, 5);
	/* C16 .. C21 */
	memcpy(trau_bits+310, fr->c_bits+15, 6);

	/* FIXME: handle timing adjustment */

	/* T1 .. T4 */
	memcpy(trau_bits+316, fr->t_bits+0, 4);
}


int encode_trau_frame(u_int8_t *trau_bits, const struct decoded_trau_frame *fr)
{
	u_int8_t cbits5 = get_bits(fr->c_bits, 0, 5);
	
	/* 16 bits of sync header */
	memset(trau_bits, 0, 16);

	switch (cbits5) {
	case TRAU_FT_FR_UP:
	case TRAU_FT_FR_DOWN:
	case TRAU_FT_IDLE_UP:
	case TRAU_FT_IDLE_DOWN:
	case TRAU_FT_EFR:
		encode_fr(trau_bits, fr);
		break;
	case TRAU_FT_AMR:
	case TRAU_FT_OM_UP:
	case TRAU_FT_OM_DOWN:
	case TRAU_FT_DATA_UP:
	case TRAU_FT_DATA_DOWN:
	case TRAU_FT_D145_SYNC:
	case TRAU_FT_EDATA:
		LOGP(DMUX, LOGL_NOTICE, "unimplemented TRAU Frame Type "
			"0x%02x\n", cbits5);
		return -1;
		break;
	default:
		LOGP(DMUX, LOGL_NOTICE, "unknown TRAU Frame Type "
			"0x%02x\n", cbits5);
		return -1;
		break;
	}

	return 0;
}

static struct decoded_trau_frame fr_idle_frame = {
	.c_bits = { 0, 1, 1, 1, 0 },	/* IDLE DOWNLINK 3.5.5 */
	.t_bits = { 1, 1, 1, 1 },
};
static u_int8_t encoded_idle_frame[TRAU_FRAME_BITS];
static int dbits_initted;

u_int8_t *trau_idle_frame(void)
{
	/* only initialize during the first call */
	if (!dbits_initted) {
		/* set all D-bits to 1 */
		memset(&fr_idle_frame.d_bits, 0x01, 260);
		encode_fr(encoded_idle_frame, &fr_idle_frame);
	}
	return encoded_idle_frame;
}
