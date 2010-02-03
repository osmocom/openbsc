/*
 * gps.c
 *
 * A few utility functions to deal with low level GPS data
 *
 *
 * Copyright (C) 2009  Sylvain Munaut <tnt@246tNt.com>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "gps.h"


#define GET_FIELD_U(w, nb, pos) (((w) >> (pos)) & ((1<<(nb))-1))
#define GET_FIELD_S(w, nb, pos) (((int)((w) << (32-(nb)-(pos)))) >> (32-(nb)))

/*
 * Unpacks GPS Subframe 1,2,3 payloads (3 * 8 words)
 *
 * Note: eph->sv_id is not filled here since not present in those subframes
 *
 * (no parity bit checking is done, only the lower 24 bits of each word
 *  are used)
 */
int
gps_unpack_sf123(uint32_t *sf, struct gps_ephemeris_sv *eph)
{
	uint32_t *sf1 = &sf[0];
	uint32_t *sf2 = &sf[8];
	uint32_t *sf3 = &sf[16];

	int iode1, iode2;

	eph->week_no	= GET_FIELD_U(sf1[0], 10, 14);
	eph->code_on_l2	= GET_FIELD_U(sf1[0],  2, 12);
	eph->sv_ura	= GET_FIELD_U(sf1[0],  4,  8);
	eph->sv_health	= GET_FIELD_U(sf1[0],  6,  2);
	eph->l2_p_flag	= GET_FIELD_U(sf1[1],  1, 23);
	eph->t_gd	= GET_FIELD_S(sf1[4],  8,  0);
	eph->iodc	= (GET_FIELD_U(sf1[0],  2,  0) << 8) | \
	                   GET_FIELD_U(sf1[5],  8, 16);
	eph->t_oc	= GET_FIELD_U(sf1[5], 16,  0);
	eph->a_f2	= GET_FIELD_S(sf1[6],  8, 16);
	eph->a_f1	= GET_FIELD_S(sf1[6], 16,  0);
	eph->a_f0	= GET_FIELD_S(sf1[7], 22,  2);

	iode1		= GET_FIELD_U(sf2[0],  8, 16);
	eph->c_rs	= GET_FIELD_S(sf2[0], 16,  0);
	eph->delta_n	= GET_FIELD_S(sf2[1], 16,  8);
	eph->m_0	= (GET_FIELD_S(sf2[1],  8,  0) << 24) | \
	                   GET_FIELD_U(sf2[2], 24,  0);
	eph->c_uc	= GET_FIELD_S(sf2[3], 16,  8);
	eph->e		= (GET_FIELD_U(sf2[3],  8,  0) << 24) | \
	                   GET_FIELD_U(sf2[4], 24,  0);
	eph->c_us	= GET_FIELD_S(sf2[5], 16,  8);
	eph->a_powhalf	= (GET_FIELD_U(sf2[5],  8,  0) << 24) | \
	                   GET_FIELD_U(sf2[6], 24,  0);
	eph->t_oe	= GET_FIELD_U(sf2[7], 16,  8);
	eph->fit_flag	= GET_FIELD_U(sf2[7],  1,  7);

	eph->c_ic	= GET_FIELD_S(sf3[0], 16,  8);
	eph->omega_0	= (GET_FIELD_S(sf3[0],  8,  0) << 24) | \
	                   GET_FIELD_U(sf3[1], 24,  0);
	eph->c_is	= GET_FIELD_S(sf3[2], 16,  8);
	eph->i_0	= (GET_FIELD_S(sf3[2],  8,  0) << 24) | \
	                   GET_FIELD_U(sf3[3], 24,  0);
	eph->c_rc	= GET_FIELD_S(sf3[4], 16,  8);
	eph->w		= (GET_FIELD_S(sf3[4],  8,  0) << 24) | \
	                   GET_FIELD_U(sf3[5], 24,  0);
	eph->omega_dot	= GET_FIELD_S(sf3[6], 24,  0);
	iode2		= GET_FIELD_U(sf3[7],  8, 16);
	eph->idot	= GET_FIELD_S(sf3[7], 14,  2);

	eph->_rsvd1	= GET_FIELD_U(sf1[1], 23,  0);
	eph->_rsvd2	= GET_FIELD_U(sf1[2], 24,  0);
	eph->_rsvd3	= GET_FIELD_U(sf1[3], 24,  0);
	eph->_rsvd4	= GET_FIELD_U(sf1[4], 16,  8);
	eph->aodo	= GET_FIELD_U(sf2[7],  5,  2);

	/* Check & cross-validate iodc[7:0], iode1, iode2 */
	if ((iode1 != iode2) || (iode1 != (eph->iodc & 0xff)))
		return -1;

	return 0;
}


/*
 * Unpacks GPS Subframe 4 or 5 Almanac pages payload (8 words)
 *
 * (no parity bit checking is done, only the lower 24 bits of each word
 *  are used)
 */
int
gps_unpack_sf45_almanac(uint32_t *sf, struct gps_almanac_sv *alm)
{
	alm->sv_id      = GET_FIELD_U(sf[0],  6, 16);

	alm->e		= GET_FIELD_U(sf[0], 16,  0);
	alm->t_oa	= GET_FIELD_U(sf[1],  8, 16);
	alm->ksii	= GET_FIELD_S(sf[1], 16,  0);
	alm->omega_dot	= GET_FIELD_S(sf[2], 16,  8);
	alm->sv_health	= GET_FIELD_U(sf[2],  8,  0);
	alm->a_powhalf	= GET_FIELD_U(sf[3], 24,  0);
	alm->omega_0	= GET_FIELD_S(sf[4], 24,  0);
	alm->w		= GET_FIELD_S(sf[5], 24,  0);
	alm->m_0	= GET_FIELD_S(sf[6], 24,  0);
	alm->a_f0	= (GET_FIELD_S(sf[7], 8, 16) << 3) | \
	                   GET_FIELD_U(sf[7], 3,  2);
	alm->a_f1	= GET_FIELD_S(sf[7], 11,  5);

	return 0;
}

