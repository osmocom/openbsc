/* GPRS SNDCP data compression handler */

/* (C) 2016 by sysmocom s.f.m.c. GmbH <info@sysmocom.de>
 * All Rights Reserved
 *
 * Author: Philipp Maier
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
 */

#pragma once

#include <stdint.h>
#include <osmocom/core/linuxlist.h>
#include <openbsc/gprs_sndcp_comp.h>

/* Note: The decompressed packet may have a maximum size of:
 * Return value * MAX_DATADECOMPR_FAC */
#define MAX_DATADECOMPR_FAC 10

/* Note: In unacknowledged mode (SN_UNITDATA), the comression state is reset
 * for every NPDU. The compressor needs a reasonably large payload to operate
 * effectively (yield positive compression gain). For packets shorter than 100
 * byte, no positive compression gain can be expected so we will skip the
 * compression for short packets. */
#define MIN_COMPR_PAYLOAD 100

/* Initalize data compression */
int gprs_sndcp_dcomp_init(const void *ctx, struct gprs_sndcp_comp *comp_entity,
			  const struct gprs_sndcp_comp_field *comp_field);

/* Terminate data compression */
void gprs_sndcp_dcomp_term(struct gprs_sndcp_comp *comp_entity);

/* Expand packet */
int gprs_sndcp_dcomp_expand(uint8_t *data, unsigned int len, uint8_t pcomp,
			    const struct llist_head *comp_entities);

/* Compress packet */
int gprs_sndcp_dcomp_compress(uint8_t *data, unsigned int len, uint8_t *pcomp,
			      const struct llist_head *comp_entities,
			      uint8_t nsapi);
