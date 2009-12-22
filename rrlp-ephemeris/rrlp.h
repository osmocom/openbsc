/*
 * rrlp.h
 *
 * RRLP Header
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

#ifndef __RRLP_H__
#define __RRLP_H__

#include <stdint.h>

#include "gps.h"

#ifdef __cplusplus
extern "C" {
#endif


/* Our internal simplified structure for requests */

#define RRLP_AR_REF_LOC		(1<<0)
#define RRLP_AR_REF_TIME	(1<<1)
#define RRLP_AR_UTC_MODEL	(1<<2)
#define RRLP_AR_IONO_MODEL	(1<<3)
#define RRLP_AR_ALMANAC		(1<<4)
#define RRLP_AR_EPHEMERIS	(1<<5)

struct rrlp_assist_req {
	uint32_t req_elems;
	uint64_t eph_svs;
};


/* Methods */
int rrlp_decode_assistance_request(struct rrlp_assist_req *ar,
	void *req, int req_len);

int rrlp_gps_assist_pdus(
	struct gps_assist_data *gps_ad, struct rrlp_assist_req *req,
	void **o_pdu, int *o_len, int o_max_pdus);


#ifdef __cplusplus
}
#endif

#endif /* __RRLP_H__ */

