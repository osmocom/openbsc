/* GPRS SNDCP header compression handler */

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
 * Return value + MAX_DECOMPR_INCR */
#define MAX_HDRDECOMPR_INCR 64

/* Initalize header compression */
int gprs_sndcp_pcomp_init(const void *ctx, struct gprs_sndcp_comp *comp_entity,
			  const struct gprs_sndcp_comp_field *comp_field);

/* Terminate header compression */
void gprs_sndcp_pcomp_term(struct gprs_sndcp_comp *comp_entity);

/* Expand packet header */
int gprs_sndcp_pcomp_expand(uint8_t *data, unsigned int len, uint8_t pcomp,
			    const struct llist_head *comp_entities);

/* Compress packet header */
int gprs_sndcp_pcomp_compress(uint8_t *data, unsigned int len, uint8_t *pcomp,
			      const struct llist_head *comp_entities,
			      uint8_t nsapi);
