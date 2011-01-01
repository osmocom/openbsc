#ifndef _TRAU_FRAME_H
#define _TRAU_FRAME_H
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

#include <sys/types.h>

/* 21 for FR/EFR, 25 for AMR, 15 for OM, 15 for data, 13 for E-data, 21 idle */
#define MAX_C_BITS	25
/* 260 for FR/EFR, 256 for AMR, 264 for OM, 288 for E-data */
#define MAX_D_BITS	288
/* for all speech frames */
#define MAX_T_BITS	4
/* for OM */
#define MAX_S_BITS	6
/* for E-data */
#define MAX_M_BITS	2

struct decoded_trau_frame {
	u_int8_t c_bits[MAX_C_BITS];
	u_int8_t d_bits[MAX_D_BITS];
	u_int8_t t_bits[MAX_T_BITS];
	u_int8_t s_bits[MAX_S_BITS];
	u_int8_t m_bits[MAX_M_BITS];
};

#define TRAU_FT_FR_UP		0x02	/* 0 0 0 1 0 - 3.5.1.1.1 */
#define TRAU_FT_FR_DOWN		0x1c	/* 1 1 1 0 0 - 3.5.1.1.1 */
#define TRAU_FT_EFR		0x1a	/* 1 1 0 1 0 - 3.5.1.1.1 */
#define TRAU_FT_AMR		0x06	/* 0 0 1 1 0 - 3.5.1.2 */
#define TRAU_FT_OM_UP		0x07	/* 0 0 1 0 1 - 3.5.2 */
#define TRAU_FT_OM_DOWN		0x1b	/* 1 1 0 1 1 - 3.5.2 */
#define TRAU_FT_DATA_UP		0x08	/* 0 1 0 0 0 - 3.5.3 */
#define TRAU_FT_DATA_DOWN	0x16	/* 1 0 1 1 0 - 3.5.3 */
#define TRAU_FT_D145_SYNC	0x14	/* 1 0 1 0 0 - 3.5.3 */
#define TRAU_FT_EDATA		0x1f	/* 1 1 1 1 1 - 3.5.4 */
#define TRAU_FT_IDLE_UP		0x10	/* 1 0 0 0 0 - 3.5.5 */
#define TRAU_FT_IDLE_DOWN	0x0e	/* 0 1 1 1 0 - 3.5.5 */


int decode_trau_frame(struct decoded_trau_frame *fr, const u_int8_t *trau_bits);
int encode_trau_frame(u_int8_t *trau_bits, const struct decoded_trau_frame *fr);
int trau_frame_up2down(struct decoded_trau_frame *fr);
u_int8_t *trau_idle_frame(void);


#endif /* _TRAU_FRAME_H */
