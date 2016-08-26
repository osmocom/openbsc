/* GPRS SNDCP header compression entity management tools */

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
#include <openbsc/gprs_sndcp_xid.h>

/* Header / Data compression entity */
struct gprs_sndcp_comp {
	struct llist_head list;

	/* Serves as an ID in case we want to delete this entity later */
	unsigned int entity;	/* see also: 6.5.1.1.3 and 6.6.1.1.3 */

	/* Specifies to which NSAPIs the compression entity is assigned */
	uint8_t nsapi_len;	/* Number of applicable NSAPIs (default 0) */
	uint8_t nsapi[MAX_NSAPI];	/* Applicable NSAPIs (default 0) */

	/* Assigned pcomp values */
	uint8_t comp_len;	/* Number of contained PCOMP / DCOMP values */
	uint8_t comp[MAX_COMP];	/* see also: 6.5.1.1.5 and 6.6.1.1.5 */

	/* Algorithm parameters */
	int algo;		/* Algorithm type (see gprs_sndcp_xid.h) */
	int compclass;		/* See gprs_sndcp_xid.h/c */
	void *state;		/* Algorithm status and parameters */
};

#define MAX_COMP 16	/* Maximum number of possible pcomp/dcomp values */
#define MAX_NSAPI 11	/* Maximum number usable NSAPIs */

/* Allocate a compression enitiy list */
struct llist_head *gprs_sndcp_comp_alloc(const void *ctx);

/* Free a compression entitiy list */
void gprs_sndcp_comp_free(struct llist_head *comp_entities);

/* Delete a compression entity */
void gprs_sndcp_comp_delete(struct llist_head *comp_entities, unsigned int entity);

/* Create and Add a new compression entity
 * (returns a pointer to the compression entity that has just been created) */
struct gprs_sndcp_comp *gprs_sndcp_comp_add(const void *ctx,
					    struct llist_head *comp_entities,
					    const struct gprs_sndcp_comp_field
					    *comp_field);

/* Find which compression entity handles the specified pcomp/dcomp */
struct gprs_sndcp_comp *gprs_sndcp_comp_by_comp(const struct llist_head
						*comp_entities, uint8_t comp);

/* Find which compression entity handles the specified nsapi */
struct gprs_sndcp_comp *gprs_sndcp_comp_by_nsapi(const struct llist_head
						 *comp_entities, uint8_t nsapi);

/* Find a comp_index for a given pcomp/dcomp value */
uint8_t gprs_sndcp_comp_get_idx(const struct gprs_sndcp_comp *comp_entity,
				uint8_t comp);

/* Find a pcomp/dcomp value for a given comp_index */
uint8_t gprs_sndcp_comp_get_comp(const struct gprs_sndcp_comp *comp_entity,
			         uint8_t comp_index);
