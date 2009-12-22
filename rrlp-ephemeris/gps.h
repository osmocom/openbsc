/*
 * gps.h
 *
 * Header to deal with low level GPS data
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

#ifndef __GPS_H__
#define __GPS_H__

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>


#define MAX_SV	64


/* Ionosperic model data */
struct gps_ionosphere_model {
			/* #bits  Scale factor  Effective  Units            */
			/*           (LSB)       range                      */

	int alpha_0;	/* s 8       2^-30                 seconds          */
	int alpha_1;	/* s 8       2^-27                 s / semi-circles */
	int alpha_2;	/* s 8       2^-24                 s / (semi-circles)^2 */
	int alpha_3;	/* s 8       2^-24                 s / (semi-circles)^3 */
	int beta_0;	/* s 8       2^11                  seconds          */
	int beta_1;	/* s 8       2^14                  s / semi-circles */
	int beta_2;	/* s 8       2^16                  s / (semi-circles)^2 */
	int beta_3;	/* s 8       2^16                  s / (semi-circles)^3 */
};


/* UTC model data */
struct gps_utc_model {
			/* #bits  Scale factor  Effective  Units            */
			/*           (LSB)       range                      */

	int a0;		/* s 32      2^-30                 seconds          */
	int a1;		/* s 24      2^-50                 seconds / seconds */
	int delta_t_ls;	/* s  8      1                     seconds          */
	int t_ot;	/* u  8      2^12       602,112    seconds          */
	int wn_t;	/* u  8      1                     weeks            */
	int wn_lsf;	/* u  8      1                     weeks            */
	int dn;		/* u  8      1                7    days             */
	int delta_t_lsf;/* s  8      1                     seconds          */
};


/* Almanach data */
struct gps_almanac_sv {
	int sv_id;
	int sv_health;

			/* #bits  Scale factor  Effective  Units            */
			/*           (LSB)       range                      */

	int e;		/* u 16      2^-21                                  */
	int t_oa;	/* u  8      2^12       602,112    seconds          */
	int ksii;	/* s 16      2^-19                 semi-circles     */
	int omega_dot;	/* s 16      2^-38                 semi-circles / s */
	int a_powhalf;	/* u 24      2^-11                 meters           */
	int omega_0;	/* s 24      2^-23                 semi-circles     */
	int w;		/* s 24      2^-23                 semi-circles     */
	int m_0;	/* s 24      2^-23                 semi-circles     */
	int a_f0;	/* s 11      2^-20                 seconds          */
	int a_f1;	/* s 11      2^-38                 seconds / seconds */
};

struct gps_almanac {
	int wna;
	int n_sv;
	struct gps_almanac_sv svs[MAX_SV];
};


/* Ephemeris data */
struct gps_ephemeris_sv {
	int sv_id;

			/* #bits  Scale factor  Effective  Units            */
			/*           (LSB)       range                      */

	int code_on_l2;	/* u  2      1                     /                */
	int week_no;	/* u 10      1                     week             */
	int l2_p_flag;	/* u  1      1                     /                */
	int sv_ura;	/* u  4      /                     /                */
	int sv_health;	/* u  6      /                     /                */
	int t_gd;	/* s  8      2^-31                 seconds          */
	int iodc;	/* u 10      /                     /                */
	int t_oc;	/* u 16      2^4        604,784    seconds          */
	int a_f2;	/* s  8      2^-55                 sec / sec^2      */
	int a_f1;	/* s 16      2^-43                 sec / sec        */
	int a_f0;	/* s 22      2^-31                 seconds          */

	int c_rs;	/* s 16      2^-5                  meters           */
	int delta_n;	/* s 16      2^-43                 semi-circles / s */
	int m_0;		/* s 32      2^-31                 semi-circles     */
	int c_uc;	/* s 16      2^-29                 radians          */
	unsigned int e;	/* u 32      2^-33      0.03       /                */
	int c_us;	/* s 16      2^-29                 radians          */
	unsigned int a_powhalf; /* u 32  2^-19             meters^(1/2)     */
	int t_oe;	/* u 16      2^4        604,784    seconds          */
	int fit_flag;	/* u  1      /                     /                */

	int c_ic;	/* s 16      2^-29                 radians          */
	int omega_0;	/* s 32      2^-31                 semi-circles     */
	int c_is;	/* s 16      2^-29                 radians          */
	int i_0;	/* s 32      2^-31                 semi-circles     */
	int c_rc;	/* s 16      2^-5                  meters           */
	int w;		/* s 32      2^-31                 semi-circles     */
	int omega_dot;	/* s 24      2^-43                 semi-circles / s */
	int idot;	/* s 14      2^-43                 semi-circles / s */

	int _rsvd1;	/* 23 bits */
	int _rsvd2;	/* 24 bits */
	int _rsvd3;	/* 24 bits */
	int _rsvd4;	/* 16 bits */
	int aodo;	/* 8 bits  Not sure it needs to be here ... */
};

struct gps_ephemeris {
	int n_sv;
	struct gps_ephemeris_sv svs[MAX_SV];
};


/* All assist data */
#define GPS_FIELD_IONOSPHERE	(1<<0)
#define GPS_FIELD_UTC		(1<<1)
#define GPS_FIELD_ALMANAC	(1<<2)
#define GPS_FIELD_EPHEMERIS	(1<<3)

struct gps_assist_data {
	int fields;
	struct gps_ionosphere_model	ionosphere;
	struct gps_utc_model		utc;
	struct gps_almanac		almanac;
	struct gps_ephemeris		ephemeris;
};


/* GPS Subframe utility methods (see gps.c for details) */
int gps_unpack_sf123(uint32_t *sf, struct gps_ephemeris_sv *eph);
int gps_unpack_sf45_almanac(uint32_t *sf, struct gps_almanac_sv *alm);


#ifdef __cplusplus
}
#endif

#endif /* __GPS_H__ */

