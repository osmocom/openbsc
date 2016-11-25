/* GPRS SNDCP header compression handler */

/* (C) 2016 by Sysmocom s.f.m.c. GmbH
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
 *
 */

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <math.h>
#include <errno.h>
#include <stdbool.h>

#include <osmocom/core/utils.h>
#include <osmocom/core/msgb.h>
#include <osmocom/core/linuxlist.h>
#include <osmocom/core/talloc.h>
#include <osmocom/gsm/tlv.h>

#include <openbsc/gprs_llc.h>
#include <openbsc/sgsn.h>
#include <openbsc/gprs_sndcp_xid.h>
#include <openbsc/slhc.h>
#include <openbsc/debug.h>
#include <openbsc/gprs_sndcp_comp.h>
#include <openbsc/gprs_sndcp_pcomp.h>

/* Initalize header compression */
int gprs_sndcp_pcomp_init(const void *ctx, struct gprs_sndcp_comp *comp_entity,
			  const struct gprs_sndcp_comp_field *comp_field)
{
	/* Note: This function is automatically called from
	 * gprs_sndcp_comp.c when a new header compression
	 * entity is created by gprs_sndcp.c */

	OSMO_ASSERT(comp_entity);
	OSMO_ASSERT(comp_field);

	if (comp_entity->compclass == SNDCP_XID_PROTOCOL_COMPRESSION
	    && comp_entity->algo == RFC_1144) {
		OSMO_ASSERT(comp_field->rfc1144_params);
		comp_entity->state =
		    slhc_init(ctx, comp_field->rfc1144_params->s01 + 1,
			      comp_field->rfc1144_params->s01 + 1);
		LOGP(DSNDCP, LOGL_INFO,
		     "RFC1144 header compression initalized.\n");
		return 0;
	}

	/* Just in case someone tries to initalize an unknown or unsupported
	 * header compresson. Since everything is checked during the SNDCP
	 * negotiation process, this should never happen! */
	OSMO_ASSERT(false);
}

/* Terminate header compression */
void gprs_sndcp_pcomp_term(struct gprs_sndcp_comp *comp_entity)
{
	/* Note: This function is automatically called from
	 * gprs_sndcp_comp.c when a header compression
	 * entity is deleted by gprs_sndcp.c */

	OSMO_ASSERT(comp_entity);

	if (comp_entity->compclass == SNDCP_XID_PROTOCOL_COMPRESSION
	    && comp_entity->algo == RFC_1144) {
		if (comp_entity->state) {
			slhc_free((struct slcompress *)comp_entity->state);
			comp_entity->state = NULL;
		}
		LOGP(DSNDCP, LOGL_INFO,
		     "RFC1144 header compression terminated.\n");
		return;
	}

	/* Just in case someone tries to terminate an unknown or unsupported
	 * data compresson. Since everything is checked during the SNDCP
	 * negotiation process, this should never happen! */
	OSMO_ASSERT(false);
}

/* Compress a packet using Van Jacobson RFC1144 header compression */
static int rfc1144_compress(uint8_t *pcomp_index, uint8_t *data,
			    unsigned int len, struct slcompress *comp)
{
	uint8_t *comp_ptr;
	int compr_len;
	uint8_t *data_o;

	/* Create a working copy of the incoming data */
	data_o = talloc_zero_size(comp, len);
	memcpy(data_o, data, len);

	/* Run compressor */
	compr_len = slhc_compress(comp, data, len, data_o, &comp_ptr, 0);

	/* Generate pcomp_index */
	if (data_o[0] & SL_TYPE_COMPRESSED_TCP) {
		*pcomp_index = 2;
		data_o[0] &= ~SL_TYPE_COMPRESSED_TCP;
		memcpy(data, data_o, compr_len);
	} else if ((data_o[0] & SL_TYPE_UNCOMPRESSED_TCP) ==
		   SL_TYPE_UNCOMPRESSED_TCP) {
		*pcomp_index = 1;
		data_o[0] &= 0x4F;
		memcpy(data, data_o, compr_len);
	} else
		*pcomp_index = 0;

	talloc_free(data_o);
	return compr_len;
}

/* Expand a packet using Van Jacobson RFC1144 header compression */
static int rfc1144_expand(uint8_t *data, unsigned int len, uint8_t pcomp_index,
			  struct slcompress *comp)
{
	int data_decompressed_len;
	int type;

	/* Note: this function should never be called with pcomp_index=0,
	 * since this condition is already filtered
	 * out by gprs_sndcp_pcomp_expand() */

	/* Determine the data type by the PCOMP index */
	switch (pcomp_index) {
	case 0:
		type = SL_TYPE_IP;
		break;
	case 1:
		type = SL_TYPE_UNCOMPRESSED_TCP;
		break;
	case 2:
		type = SL_TYPE_COMPRESSED_TCP;
		break;
	default:
		LOGP(DSNDCP, LOGL_ERROR,
		     "rfc1144_expand() Invalid pcomp_index value (%d) detected, assuming no compression!\n",
		     pcomp_index);
		type = SL_TYPE_IP;
		break;
	}

	/* Restore the original version nibble on
	 * marked uncompressed packets */
	if (type == SL_TYPE_UNCOMPRESSED_TCP) {
		/* Just in case the phone tags uncompressed tcp-data
		 * (normally this is handled by pcomp so there is
		 * no need for tagging the data) */
		data[0] &= 0x4F;
		data_decompressed_len = slhc_remember(comp, data, len);
		return data_decompressed_len;
	}

	/* Uncompress compressed packets */
	else if (type == SL_TYPE_COMPRESSED_TCP) {
		data_decompressed_len = slhc_uncompress(comp, data, len);
		return data_decompressed_len;
	}

	/* Regular or unknown packets will not be touched */
	return len;
}

/* Expand packet header */
int gprs_sndcp_pcomp_expand(uint8_t *data, unsigned int len, uint8_t pcomp,
			    const struct llist_head *comp_entities)
{
	int rc;
	uint8_t pcomp_index = 0;
	struct gprs_sndcp_comp *comp_entity;

	OSMO_ASSERT(data);
	OSMO_ASSERT(comp_entities);

	LOGP(DSNDCP, LOGL_DEBUG,
	     "Header compression entity list: comp_entities=%p\n",
	     comp_entities);

	LOGP(DSNDCP, LOGL_DEBUG, "Header compression mode: pcomp=%d\n", pcomp);

	/* Skip on pcomp=0 */
	if (pcomp == 0) {
		return len;
	}

	/* Find out which compression entity handles the data */
	comp_entity = gprs_sndcp_comp_by_comp(comp_entities, pcomp);

	/* Skip compression if no suitable compression entity can be found */
	if (!comp_entity) {
		return len;
	}

	/* Note: Only protocol compression entities may appear in
	 * protocol compression context */
	OSMO_ASSERT(comp_entity->compclass == SNDCP_XID_PROTOCOL_COMPRESSION);

	/* Note: Currently RFC1144 is the only compression method we
	 * support, so the only allowed algorithm is RFC1144 */
	OSMO_ASSERT(comp_entity->algo == RFC_1144);

	/* Find pcomp_index */
	pcomp_index = gprs_sndcp_comp_get_idx(comp_entity, pcomp);

	/* Run decompression algo */
	rc = rfc1144_expand(data, len, pcomp_index, comp_entity->state);
	slhc_i_status(comp_entity->state);
	slhc_o_status(comp_entity->state);

	LOGP(DSNDCP, LOGL_DEBUG,
	     "Header expansion done, old length=%d, new length=%d, entity=%p\n",
	     len, rc, comp_entity);

	return rc;
}

/* Compress packet header */
int gprs_sndcp_pcomp_compress(uint8_t *data, unsigned int len, uint8_t *pcomp,
			      const struct llist_head *comp_entities,
			      uint8_t nsapi)
{
	int rc;
	uint8_t pcomp_index = 0;
	struct gprs_sndcp_comp *comp_entity;

	OSMO_ASSERT(data);
	OSMO_ASSERT(pcomp);
	OSMO_ASSERT(comp_entities);

	LOGP(DSNDCP, LOGL_DEBUG,
	     "Header compression entity list: comp_entities=%p\n",
	     comp_entities);

	/* Find out which compression entity handles the data */
	comp_entity = gprs_sndcp_comp_by_nsapi(comp_entities, nsapi);

	/* Skip compression if no suitable compression entity can be found */
	if (!comp_entity) {
		*pcomp = 0;
		return len;
	}

	/* Note: Only protocol compression entities may appear in
	 * protocol compression context */
	OSMO_ASSERT(comp_entity->compclass == SNDCP_XID_PROTOCOL_COMPRESSION);

	/* Note: Currently RFC1144 is the only compression method we
	 * support, so the only allowed algorithm is RFC1144 */
	OSMO_ASSERT(comp_entity->algo == RFC_1144);

	/* Run compression algo */
	rc = rfc1144_compress(&pcomp_index, data, len, comp_entity->state);
	slhc_i_status(comp_entity->state);
	slhc_o_status(comp_entity->state);

	/* Find pcomp value */
	*pcomp = gprs_sndcp_comp_get_comp(comp_entity, pcomp_index);

	LOGP(DSNDCP, LOGL_DEBUG, "Header compression mode: pcomp=%d\n", *pcomp);

	LOGP(DSNDCP, LOGL_DEBUG,
	     "Header compression done, old length=%d, new length=%d, entity=%p\n",
	     len, rc, comp_entity);
	return rc;
}
