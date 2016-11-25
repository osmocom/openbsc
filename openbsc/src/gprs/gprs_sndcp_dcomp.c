/* GPRS SNDCP data compression handler */

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
#include <openbsc/v42bis.h>
#include <openbsc/v42bis_private.h>
#include <openbsc/debug.h>
#include <openbsc/gprs_sndcp_comp.h>
#include <openbsc/gprs_sndcp_dcomp.h>

/* A struct to capture the output data of compressor and decompressor */
struct v42bis_output_buffer {
	uint8_t *buf;
	uint8_t *buf_pointer;
	int len;
};

/* Handler to capture the output data from the compressor */
void tx_v42bis_frame_handler(void *user_data, const uint8_t *pkt, int len)
{
	struct v42bis_output_buffer *output_buffer =
	    (struct v42bis_output_buffer *)user_data;
	memcpy(output_buffer->buf_pointer, pkt, len);
	output_buffer->buf_pointer += len;
	output_buffer->len += len;
	return;
}

/* Handler to capture the output data from the decompressor */
void rx_v42bis_data_handler(void *user_data, const uint8_t *buf, int len)
{
	struct v42bis_output_buffer *output_buffer =
	    (struct v42bis_output_buffer *)user_data;
	memcpy(output_buffer->buf_pointer, buf, len);
	output_buffer->buf_pointer += len;
	output_buffer->len += len;
	return;
}

/* Initalize data compression */
int gprs_sndcp_dcomp_init(const void *ctx, struct gprs_sndcp_comp *comp_entity,
			  const struct gprs_sndcp_comp_field *comp_field)
{
	/* Note: This function is automatically called from
	 * gprs_sndcp_comp.c when a new data compression
	 * entity is created by gprs_sndcp.c */

	OSMO_ASSERT(comp_entity);
	OSMO_ASSERT(comp_field);

	if (comp_entity->compclass == SNDCP_XID_DATA_COMPRESSION
	    && comp_entity->algo == V42BIS) {
		OSMO_ASSERT(comp_field->v42bis_params);
		comp_entity->state =
		    v42bis_init(ctx, NULL, comp_field->v42bis_params->p0,
				comp_field->v42bis_params->p1,
				comp_field->v42bis_params->p2,
				&tx_v42bis_frame_handler, NULL,
				V42BIS_MAX_OUTPUT_LENGTH,
				&rx_v42bis_data_handler, NULL,
				V42BIS_MAX_OUTPUT_LENGTH);
		LOGP(DSNDCP, LOGL_INFO,
		     "V.42bis data compression initalized.\n");
		return 0;
	}

	/* Just in case someone tries to initalize an unknown or unsupported
	 * data compresson. Since everything is checked during the SNDCP
	 * negotiation process, this should never happen! */
	OSMO_ASSERT(false);
}

/* Terminate data compression */
void gprs_sndcp_dcomp_term(struct gprs_sndcp_comp *comp_entity)
{
	/* Note: This function is automatically called from
	 * gprs_sndcp_comp.c when a data compression
	 * entity is deleted by gprs_sndcp.c */

	OSMO_ASSERT(comp_entity);

	if (comp_entity->compclass == SNDCP_XID_DATA_COMPRESSION
	    && comp_entity->algo == V42BIS) {
		if (comp_entity->state) {
			v42bis_free((v42bis_state_t *) comp_entity->state);
			comp_entity->state = NULL;
		}
		LOGP(DSNDCP, LOGL_INFO,
		     "V.42bis data compression terminated.\n");
		return;
	}

	/* Just in case someone tries to terminate an unknown or unsupported
	 * data compresson. Since everything is checked during the SNDCP
	 * negotiation process, this should never happen! */
	OSMO_ASSERT(false);
}

/* Perform a full reset of the V.42bis compression state */
static void v42bis_reset(v42bis_state_t *comp)
{
	/* This function performs a complete reset of the V.42bis compression
	 * state by reinitalizing the state withe the previously negotiated
	 * parameters. */

	int p0, p1, p2;
	p0 = comp->decompress.v42bis_parm_p0 | comp->compress.v42bis_parm_p0;
	p1 = comp->decompress.v42bis_parm_n2;
	p2 = comp->decompress.v42bis_parm_n7;

	DEBUGP(DSNDCP, "Resetting compression state: %p, p0=%d, p1=%d, p2=%d\n",
	       comp, p0, p1, p2);

	v42bis_init(NULL, comp, p0, p1, p2, &tx_v42bis_frame_handler, NULL,
		    V42BIS_MAX_OUTPUT_LENGTH, &rx_v42bis_data_handler, NULL,
		    V42BIS_MAX_OUTPUT_LENGTH);
}

/* Compress a packet using V.42bis data compression */
static int v42bis_compress_unitdata(uint8_t *pcomp_index, uint8_t *data,
				    unsigned int len, v42bis_state_t *comp)
{
	/* Note: This implementation may only be used to compress SN_UNITDATA
	 * packets, since it resets the compression state for each NPDU. */

	uint8_t *data_o;
	int rc;
	int skip = 0;
	struct v42bis_output_buffer compressed_data;

	/* Don't bother with short packets */
	if (len < MIN_COMPR_PAYLOAD)
		skip = 1;

	/* Skip if compression is not enabled for TX direction */
	if (!comp->compress.v42bis_parm_p0)
		skip = 1;

	/* Skip compression */
	if (skip) {
		*pcomp_index = 0;
		return len;
	}

	/* Reset V.42bis compression state */
	v42bis_reset(comp);

	/* Run compressor */
	data_o = talloc_zero_size(comp, len * MAX_DATADECOMPR_FAC);
	compressed_data.buf = data_o;
	compressed_data.buf_pointer = data_o;
	compressed_data.len = 0;
	comp->compress.user_data = (&compressed_data);
	rc = v42bis_compress(comp, data, len);
	if (rc < 0) {
		LOGP(DSNDCP, LOGL_ERROR,
		     "Data compression failed, skipping...\n");
		skip = 1;
	}
	rc = v42bis_compress_flush(comp);
	if (rc < 0) {
		LOGP(DSNDCP, LOGL_ERROR,
		     "Data compression failed, skipping...\n");
		skip = 1;
	}

	/* The compressor might yield negative compression gain, in
	 * this case, we just decide to send the packat as normal,
	 * uncompressed payload => skip compresssion */
	if (compressed_data.len >= len) {
		LOGP(DSNDCP, LOGL_ERROR,
		     "Data compression ineffective, skipping...\n");
		skip = 1;
	}

	/* Skip compression */
	if (skip) {
		*pcomp_index = 0;
		talloc_free(data_o);
		return len;
	}

	*pcomp_index = 1;
	memcpy(data, data_o, compressed_data.len);
	talloc_free(data_o);

	return compressed_data.len;
}

/* Expand a packet using V.42bis data compression */
static int v42bis_expand_unitdata(uint8_t *data, unsigned int len,
				  uint8_t pcomp_index, v42bis_state_t *comp)
{
	/* Note: This implementation may only be used to compress SN_UNITDATA
	 * packets, since it resets the compression state for each NPDU. */

	int rc;
	struct v42bis_output_buffer uncompressed_data;
	uint8_t *data_i;

	/* Skip when the packet is marked as uncompressed */
	if (pcomp_index == 0) {
		return len;
	}

	/* Reset V.42bis compression state */
	v42bis_reset(comp);

	/* Decompress packet */
	data_i = talloc_zero_size(comp, len);
	memcpy(data_i, data, len);
	uncompressed_data.buf = data;
	uncompressed_data.buf_pointer = data;
	uncompressed_data.len = 0;
	comp->decompress.user_data = (&uncompressed_data);
	rc = v42bis_decompress(comp, data_i, len);
	talloc_free(data_i);
	if (rc < 0)
		return -EINVAL;
	rc = v42bis_decompress_flush(comp);
	if (rc < 0)
		return -EINVAL;

	return uncompressed_data.len;
}

/* Expand packet */
int gprs_sndcp_dcomp_expand(uint8_t *data, unsigned int len, uint8_t pcomp,
			    const struct llist_head *comp_entities)
{
	int rc;
	uint8_t pcomp_index = 0;
	struct gprs_sndcp_comp *comp_entity;

	OSMO_ASSERT(data);
	OSMO_ASSERT(comp_entities);

	LOGP(DSNDCP, LOGL_DEBUG,
	     "Data compression entity list: comp_entities=%p\n", comp_entities);

	LOGP(DSNDCP, LOGL_DEBUG, "Data compression mode: dcomp=%d\n", pcomp);

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

	/* Note: Only data compression entities may appear in
	 * data compression context */
	OSMO_ASSERT(comp_entity->compclass == SNDCP_XID_DATA_COMPRESSION);

	/* Note: Currently V42BIS is the only compression method we
	 * support, so the only allowed algorithm is V42BIS */
	OSMO_ASSERT(comp_entity->algo == V42BIS);

	/* Find pcomp_index */
	pcomp_index = gprs_sndcp_comp_get_idx(comp_entity, pcomp);

	/* Run decompression algo */
	rc = v42bis_expand_unitdata(data, len, pcomp_index, comp_entity->state);

	LOGP(DSNDCP, LOGL_DEBUG,
	     "Data expansion done, old length=%d, new length=%d, entity=%p\n",
	     len, rc, comp_entity);

	return rc;
}

/* Compress packet */
int gprs_sndcp_dcomp_compress(uint8_t *data, unsigned int len, uint8_t *pcomp,
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
	     "Data compression entity list: comp_entities=%p\n", comp_entities);

	/* Find out which compression entity handles the data */
	comp_entity = gprs_sndcp_comp_by_nsapi(comp_entities, nsapi);

	/* Skip compression if no suitable compression entity can be found */
	if (!comp_entity) {
		*pcomp = 0;
		return len;
	}

	/* Note: Only data compression entities may appear in
	 * data compression context */
	OSMO_ASSERT(comp_entity->compclass == SNDCP_XID_DATA_COMPRESSION);

	/* Note: Currently V42BIS is the only compression method we
	 * support, so the only allowed algorithm is V42BIS */
	OSMO_ASSERT(comp_entity->algo == V42BIS);

	/* Run compression algo */
	rc = v42bis_compress_unitdata(&pcomp_index, data, len,
				      comp_entity->state);

	/* Find pcomp value */
	*pcomp = gprs_sndcp_comp_get_comp(comp_entity, pcomp_index);

	LOGP(DSNDCP, LOGL_DEBUG, "Data compression mode: dcomp=%d\n", *pcomp);

	LOGP(DSNDCP, LOGL_DEBUG,
	     "Data compression done, old length=%d, new length=%d, entity=%p\n",
	     len, rc, comp_entity);

	return rc;
}
