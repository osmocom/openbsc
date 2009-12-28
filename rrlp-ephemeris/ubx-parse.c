/*
 * ubx-parse.c
 *
 * Implementation of parsing code converting UBX messages to GPS assist
 * data
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

#include <stdio.h>

#include "gps.h"
#include "ubx.h"
#include "ubx-parse.h"


/* Helpers */

static int
float_to_fixedpoint(float f, int sf)
{
	if (sf < 0) {
		while (sf++ < 0)
			f *= 2.0f;
	} else {
		while (sf-- > 0)
			f *= 0.5f;
	}

	return (int)f;
}

static inline int
double_to_fixedpoint(double d, int sf)
{
	if (sf < 0) {
		while (sf++ < 0)
			d *= 2.0;
	} else {
		while (sf-- > 0)
			d *= 0.5;
	}

	return (int)d;
}


/* UBX message parsing to fill gps assist data */

static void
_ubx_msg_parse_nav_posllh(struct ubx_hdr *hdr, void *pl, int pl_len, void *ud)
{
	struct ubx_nav_posllh *nav_posllh = pl;
	struct gps_assist_data *gps = ud;

	//printf("[.] NAV_POSLLH\n");

	gps->fields |= GPS_FIELD_REFPOS;

	gps->ref_pos.latitude  = (double)(nav_posllh->lat) * 1e-7;
	gps->ref_pos.longitude = (double)(nav_posllh->lon) * 1e-7;
	gps->ref_pos.altitude  = (double)(nav_posllh->height) * 1e-3;
}

static void
_ubx_msg_parse_aid_ini(struct ubx_hdr *hdr, void *pl, int pl_len, void *ud)
{
	struct ubx_aid_ini *aid_ini = pl;
	struct gps_assist_data *gps = ud;

	//printf("[.] AID_INI\n");

	// FIXME: Extract info for "Reference Time"
}

static void
_ubx_msg_parse_aid_hui(struct ubx_hdr *hdr, void *pl, int pl_len, void *ud)
{
	struct ubx_aid_hui *aid_hui = pl;
	struct gps_assist_data *gps = ud;

	//printf("[.] AID_HUI\n");

	if (aid_hui->flags & 0x2) { /* UTC parameters valid */
		struct gps_utc_model *utc = &gps->utc;

		gps->fields |= GPS_FIELD_UTC;

		utc->a0          = double_to_fixedpoint(aid_hui->utc_a0, -30);
		utc->a1          = double_to_fixedpoint(aid_hui->utc_a1, -50);
		utc->delta_t_ls  = aid_hui->utc_ls;
		utc->t_ot        = aid_hui->utc_tot >> 12;
		utc->wn_t        = aid_hui->utc_wnt;
		utc->wn_lsf      = aid_hui->utc_wnf;
		utc->dn          = aid_hui->utc_dn;
		utc->delta_t_lsf = aid_hui->utc_lsf;
	}

	if (aid_hui->flags & 0x04) { /* Klobuchar parameters valid */
		struct gps_ionosphere_model *iono = &gps->ionosphere;

		gps->fields |= GPS_FIELD_IONOSPHERE;

		iono->alpha_0 = float_to_fixedpoint(aid_hui->klob_a0, -30);
		iono->alpha_1 = float_to_fixedpoint(aid_hui->klob_a1, -27);
		iono->alpha_2 = float_to_fixedpoint(aid_hui->klob_a2, -24);
		iono->alpha_3 = float_to_fixedpoint(aid_hui->klob_a3, -24);
		iono->beta_0 = float_to_fixedpoint(aid_hui->klob_b0, 11);
		iono->beta_1 = float_to_fixedpoint(aid_hui->klob_b1, 14);
		iono->beta_2 = float_to_fixedpoint(aid_hui->klob_b2, 16);
		iono->beta_3 = float_to_fixedpoint(aid_hui->klob_b3, 16);
	}
}

static void
_ubx_msg_parse_aid_alm(struct ubx_hdr *hdr, void *pl, int pl_len, void *ud)
{
	struct ubx_aid_alm *aid_alm = pl;
	struct gps_assist_data *gps = ud;

	//printf("[.] AID_ALM %d - %d\n", aid_alm->sv_id, aid_alm->gps_week);

	if (aid_alm->gps_week) {
		gps->fields |= GPS_FIELD_ALMANAC;
		gps->almanac.wna = aid_alm->gps_week & 0xff;
		gps_unpack_sf45_almanac(aid_alm->alm_words, &gps->almanac.svs[gps->almanac.n_sv++]);
	}
}

static void
_ubx_msg_parse_aid_eph(struct ubx_hdr *hdr, void *pl, int pl_len, void *ud)
{
	struct ubx_aid_eph *aid_eph = pl;
	struct gps_assist_data *gps = ud;

	//printf("[.] AID_EPH %d - %s\n", aid_eph->sv_id, aid_eph->present ? "present" : "not present");

	if (aid_eph->present) {
		int i = gps->ephemeris.n_sv++;
		gps->fields |= GPS_FIELD_EPHEMERIS;
		gps->ephemeris.svs[i].sv_id = aid_eph->sv_id;
		gps_unpack_sf123(aid_eph->eph_words, &gps->ephemeris.svs[i]);
	}
}


/* Dispatch table */
struct ubx_dispatch_entry ubx_parse_dt[] = {
	UBX_DISPATCH(NAV, POSLLH, _ubx_msg_parse_nav_posllh),
	UBX_DISPATCH(AID, INI, _ubx_msg_parse_aid_ini),
	UBX_DISPATCH(AID, HUI, _ubx_msg_parse_aid_hui),
	UBX_DISPATCH(AID, ALM, _ubx_msg_parse_aid_alm),
	UBX_DISPATCH(AID, EPH, _ubx_msg_parse_aid_eph),
};

