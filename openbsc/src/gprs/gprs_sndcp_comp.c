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

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <math.h>
#include <errno.h>
#include <stdbool.h>

#include <osmocom/core/linuxlist.h>
#include <osmocom/core/talloc.h>
#include <osmocom/core/utils.h>

#include <openbsc/debug.h>
#include <openbsc/gprs_sndcp_xid.h>
#include <openbsc/gprs_sndcp_comp.h>
#include <openbsc/gprs_sndcp_pcomp.h>
#include <openbsc/gprs_sndcp_dcomp.h>

/* Create a new compression entity from a XID-Field */
static struct gprs_sndcp_comp *gprs_sndcp_comp_create(const void *ctx,
						      const struct
						      gprs_sndcp_comp_field
						      *comp_field)
{
	struct gprs_sndcp_comp *comp_entity;
	comp_entity = talloc_zero(ctx, struct gprs_sndcp_comp);

	/* Copy relevant information from the SNDCP-XID field */
	comp_entity->entity = comp_field->entity;
	comp_entity->comp_len = comp_field->comp_len;
	memcpy(comp_entity->comp, comp_field->comp, sizeof(comp_entity->comp));

	if (comp_field->rfc1144_params) {
		comp_entity->nsapi_len = comp_field->rfc1144_params->nsapi_len;
		memcpy(comp_entity->nsapi,
		       comp_field->rfc1144_params->nsapi,
		       sizeof(comp_entity->nsapi));
	} else if (comp_field->rfc2507_params) {
		comp_entity->nsapi_len = comp_field->rfc2507_params->nsapi_len;
		memcpy(comp_entity->nsapi,
		       comp_field->rfc2507_params->nsapi,
		       sizeof(comp_entity->nsapi));
	} else if (comp_field->rohc_params) {
		comp_entity->nsapi_len = comp_field->rohc_params->nsapi_len;
		memcpy(comp_entity->nsapi, comp_field->rohc_params->nsapi,
		       sizeof(comp_entity->nsapi));
	} else if (comp_field->v42bis_params) {
		comp_entity->nsapi_len = comp_field->v42bis_params->nsapi_len;
		memcpy(comp_entity->nsapi,
		       comp_field->v42bis_params->nsapi,
		       sizeof(comp_entity->nsapi));
	} else if (comp_field->v44_params) {
		comp_entity->nsapi_len = comp_field->v44_params->nsapi_len;
		memcpy(comp_entity->nsapi,
		       comp_field->v44_params->nsapi,
		       sizeof(comp_entity->nsapi));
	} else {
		/* The caller is expected to check carefully if the all
		 * data fields required for compression entity creation
		 * are present. Otherwise we blow an assertion here */
		OSMO_ASSERT(false);
	}
	comp_entity->algo = comp_field->algo;

	/* Check if an NSAPI is selected, if not, it does not make sense
	 * to create the compression entity, since the caller should
	 * have checked the presence of the NSAPI, we blow an assertion
	 * in case of missing NSAPIs */
	OSMO_ASSERT(comp_entity->nsapi_len > 0);

	/* Determine of which class our compression entity will be
	 * (Protocol or Data compresson ?) */
	comp_entity->compclass = gprs_sndcp_get_compression_class(comp_field);

	OSMO_ASSERT(comp_entity->compclass != -1);

	/* Create an algorithm specific compression context */
	if (comp_entity->compclass == SNDCP_XID_PROTOCOL_COMPRESSION) {
		if (gprs_sndcp_pcomp_init(ctx, comp_entity, comp_field) != 0) {
			talloc_free(comp_entity);
			comp_entity = NULL;
		}
	} else {
		if (gprs_sndcp_dcomp_init(ctx, comp_entity, comp_field) != 0) {
			talloc_free(comp_entity);
			comp_entity = NULL;
		}
	}

	/* Bail on failure */
	if (comp_entity == NULL) {
		LOGP(DSNDCP, LOGL_ERROR,
		     "Compression entity creation failed!\n");
		return NULL;
	}

	/* Display info message */
	if (comp_entity->compclass == SNDCP_XID_PROTOCOL_COMPRESSION) {
		LOGP(DSNDCP, LOGL_INFO,
		     "New header compression entity (%d) created.\n",
		     comp_entity->entity);
	} else {
		LOGP(DSNDCP, LOGL_INFO,
		     "New data compression entity (%d) created.\n",
		     comp_entity->entity);
	}

	return comp_entity;
}

/* Allocate a compression enitiy list */
struct llist_head *gprs_sndcp_comp_alloc(const void *ctx)
{
	struct llist_head *lh;

	lh = talloc_zero(ctx, struct llist_head);
	INIT_LLIST_HEAD(lh);

	return lh;
}

/* Free a compression entitiy list */
void gprs_sndcp_comp_free(struct llist_head *comp_entities)
{
	struct gprs_sndcp_comp *comp_entity;

	/* We expect the caller to take care of allocating a
	 * compression entity list properly. Attempting to
	 * free a non existing list clearly points out
	 * a malfunction. */
	OSMO_ASSERT(comp_entities);

	llist_for_each_entry(comp_entity, comp_entities, list) {
		/* Free compression entity */
		if (comp_entity->compclass == SNDCP_XID_PROTOCOL_COMPRESSION) {
			LOGP(DSNDCP, LOGL_INFO,
			     "Deleting header compression entity %d ...\n",
			     comp_entity->entity);
			gprs_sndcp_pcomp_term(comp_entity);
		} else {
			LOGP(DSNDCP, LOGL_INFO,
			     "Deleting data compression entity %d ...\n",
			     comp_entity->entity);
			gprs_sndcp_dcomp_term(comp_entity);
		}
	}

	talloc_free(comp_entities);
}

/* Delete a compression entity */
void gprs_sndcp_comp_delete(struct llist_head *comp_entities,
			    unsigned int entity)
{
	struct gprs_sndcp_comp *comp_entity;
	struct gprs_sndcp_comp *comp_entity_to_delete = NULL;

	OSMO_ASSERT(comp_entities);

	llist_for_each_entry(comp_entity, comp_entities, list) {
		if (comp_entity->entity == entity) {
			comp_entity_to_delete = comp_entity;
			break;
		}
	}

	if (!comp_entity_to_delete)
		return;

	if (comp_entity_to_delete->compclass == SNDCP_XID_PROTOCOL_COMPRESSION) {
		LOGP(DSNDCP, LOGL_INFO,
		     "Deleting header compression entity %d ...\n",
		     comp_entity_to_delete->entity);
		gprs_sndcp_pcomp_term(comp_entity_to_delete);
	} else {
		LOGP(DSNDCP, LOGL_INFO,
		     "Deleting data compression entity %d ...\n",
		     comp_entity_to_delete->entity);
	}

	/* Delete compression entity */
	llist_del(&comp_entity_to_delete->list);
	talloc_free(comp_entity_to_delete);
}

/* Create and Add a new compression entity
 * (returns a pointer to the compression entity that has just been created) */
struct gprs_sndcp_comp *gprs_sndcp_comp_add(const void *ctx,
					    struct llist_head *comp_entities,
					    const struct gprs_sndcp_comp_field
					    *comp_field)
{
	struct gprs_sndcp_comp *comp_entity;

	OSMO_ASSERT(comp_entities);
	OSMO_ASSERT(comp_field);

	/* Just to be sure, if the entity is already in
	 * the list it will be deleted now */
	gprs_sndcp_comp_delete(comp_entities, comp_field->entity);

	/* Create and add a new entity to the list */
	comp_entity = gprs_sndcp_comp_create(ctx, comp_field);

	if (!comp_entity)
		return NULL;

	llist_add(&comp_entity->list, comp_entities);
	return comp_entity;
}

/* Find which compression entity handles the specified pcomp/dcomp */
struct gprs_sndcp_comp *gprs_sndcp_comp_by_comp(const struct llist_head
						*comp_entities, uint8_t comp)
{
	struct gprs_sndcp_comp *comp_entity;
	int i;

	OSMO_ASSERT(comp_entities);

	llist_for_each_entry(comp_entity, comp_entities, list) {
		for (i = 0; i < comp_entity->comp_len; i++) {
			if (comp_entity->comp[i] == comp)
				return comp_entity;
		}
	}

	LOGP(DSNDCP, LOGL_ERROR,
	     "Could not find a matching compression entity for given pcomp/dcomp value %d.\n",
	     comp);
	return NULL;
}

/* Find which compression entity handles the specified nsapi */
struct gprs_sndcp_comp *gprs_sndcp_comp_by_nsapi(const struct llist_head
						 *comp_entities, uint8_t nsapi)
{
	struct gprs_sndcp_comp *comp_entity;
	int i;

	OSMO_ASSERT(comp_entities);

	llist_for_each_entry(comp_entity, comp_entities, list) {
		for (i = 0; i < comp_entity->nsapi_len; i++) {
			if (comp_entity->nsapi[i] == nsapi)
				return comp_entity;
		}
	}

	return NULL;
}

/* Find a comp_index for a given pcomp/dcomp value */
uint8_t gprs_sndcp_comp_get_idx(const struct gprs_sndcp_comp *comp_entity,
				uint8_t comp)
{
	/* Note: This function returns a normalized version of the comp value,
	 * which matches up with the position of the comp field. Since comp=0
	 * is reserved for "no compression", the index value starts counting
	 * at one. The return value is the PCOMPn/DCOMPn value one can find
	 * in the Specification (see e.g. 3GPP TS 44.065, 6.5.3.2, Table 7) */

	int i;
	OSMO_ASSERT(comp_entity);

	/* A pcomp/dcomp value of zero is reserved for "no comproession",
	 * So we just bail and return zero in this case */
	if (comp == 0)
		return 0;

	/* Look in the pcomp/dcomp list for the index */
	for (i = 0; i < comp_entity->comp_len; i++) {
		if (comp_entity->comp[i] == comp)
			return i + 1;
	}

	LOGP(DSNDCP, LOGL_ERROR,
	     "Could not find a matching comp_index for given pcomp/dcomp value %d\n",
	     comp);
	return 0;
}

/* Find a pcomp/dcomp value for a given comp_index */
uint8_t gprs_sndcp_comp_get_comp(const struct gprs_sndcp_comp *comp_entity,
			         uint8_t comp_index)
{
	OSMO_ASSERT(comp_entity);

	/* A comp_index of zero translates to zero right away. */
	if (comp_index == 0)
		return 0;

	if (comp_index > comp_entity->comp_len) {
		LOGP(DSNDCP, LOGL_ERROR,
		     "Could not find a matching pcomp/dcomp value for given comp_index value %d.\n",
		     comp_index);
		return 0;
	}

	/* Look in the pcomp/dcomp list for the comp_index, see
	 * note in gprs_sndcp_comp_get_idx() */
	return comp_entity->comp[comp_index - 1];
}
