/* GPRS SNDCP XID field encoding/decoding as per 3GPP TS 44.065 */

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

#include <osmocom/core/utils.h>
#include <osmocom/core/msgb.h>
#include <osmocom/core/linuxlist.h>
#include <osmocom/core/talloc.h>
#include <osmocom/gsm/tlv.h>

#include <openbsc/debug.h>
#include <openbsc/gprs_llc.h>
#include <openbsc/sgsn.h>
#include <openbsc/gprs_sndcp_xid.h>

/* When the propose bit in an SNDCP-XID compression field is set to zero,
 * the algorithm identifier is stripped. The algoritm parameters are specific
 * for each algorithms. The following struct is used to pass the information
 * about the referenced algorithm to the parser. */
struct entity_algo_table {
	unsigned int entity;	/* see also: 6.5.1.1.3 and 6.6.1.1.3 */
	unsigned int algo;	/* see also: 6.5.1.1.4 and 6.6.1.1.4 */
	unsigned int compclass;	/* Can be either SNDCP_XID_DATA_COMPRESSION or
				   SNDCP_XID_PROTOCOL_COMPRESSION */
};

/* FUNCTIONS RELATED TO SNDCP-XID ENCODING */

/* Encode applicable sapis (works the same in all three compression schemes) */
static int encode_pcomp_applicable_sapis(uint8_t *dst,
					 const uint8_t *nsapis,
					 uint8_t nsapis_len)
{
	/* NOTE: Buffer *dst needs offer at 2 bytes
	 * of space to store the generation results */

	uint16_t blob;
	uint8_t nsapi;
	int i;

	/* Bail if number of possible nsapis exceeds valid range
	 * (Only 11 nsapis possible for PDP-Contexts) */
	OSMO_ASSERT(nsapis_len <= 11);

	/* Encode applicable SAPIs */
	blob = 0;
	for (i = 0; i < nsapis_len; i++) {
		nsapi = nsapis[i];
		/* Only NSAPI 5 to 15 are applicable for user traffic (PDP-
		 * contexts). Only for these NSAPIs SNDCP-XID parameters
		 * can apply. See also 3GPP TS 44.065, 5.1 Service primitives */
		OSMO_ASSERT(nsapi >= 5 && nsapi <= 15);
		blob |= (1 << nsapi);
	}

	/* Store result */
	*dst = (blob >> 8) & 0xFF;
	dst++;
	*dst = blob & 0xFF;

	return 2;
}

/* Encode rfc1144 parameter field
 * (see also: 3GPP TS 44.065, 6.5.2.1, Table 5) */
static int encode_pcomp_rfc1144_params(uint8_t *dst, unsigned int dst_maxlen,
				       const struct
				       gprs_sndcp_pcomp_rfc1144_params *params)
{
	/* NOTE: Buffer *dst should offer at least 3 bytes
	 * of space to store the generation results */

	int dst_counter = 0;
	int rc;

	OSMO_ASSERT(dst_maxlen >= 3);

	/* Zero out buffer */
	memset(dst, 0, dst_maxlen);

	/* Encode applicable SAPIs */
	rc = encode_pcomp_applicable_sapis(dst, params->nsapi,
					   params->nsapi_len);
	dst += rc;
	dst_counter += rc;

	/* Encode s01 (see also: 3GPP TS 44.065, 6.5.2.1, Table 5) */
	OSMO_ASSERT(params->s01 >= 0);
	OSMO_ASSERT(params->s01 <= 255);
	*dst = params->s01;
	dst++;
	dst_counter++;

	/* Return generated length */
	return dst_counter;
}

/*
 * Encode rfc2507 parameter field
 * (see also: 3GPP TS 44.065, 6.5.3.1, Table 6)
 */
static int encode_pcomp_rfc2507_params(uint8_t *dst, unsigned int dst_maxlen,
				       const struct
				       gprs_sndcp_pcomp_rfc2507_params *params)
{
	/* NOTE: Buffer *dst should offer at least 3 bytes
	 * of space to store the generation results */

	int dst_counter = 0;
	int rc;

	OSMO_ASSERT(dst_maxlen >= 9);

	/* Zero out buffer */
	memset(dst, 0, dst_maxlen);

	/* Encode applicable SAPIs */
	rc = encode_pcomp_applicable_sapis(dst, params->nsapi,
					   params->nsapi_len);
	dst += rc;
	dst_counter += rc;

	/* Encode F_MAX_PERIOD (see also: 3GPP TS 44.065, 6.5.3.1, Table 6) */
	OSMO_ASSERT(params->f_max_period >= 1);
	OSMO_ASSERT(params->f_max_period <= 65535);
	*dst = (params->f_max_period >> 8) & 0xFF;
	dst++;
	dst_counter++;
	*dst = (params->f_max_period) & 0xFF;
	dst++;
	dst_counter++;

	/* Encode F_MAX_TIME (see also: 3GPP TS 44.065, 6.5.3.1, Table 6) */
	OSMO_ASSERT(params->f_max_time >= 1);
	OSMO_ASSERT(params->f_max_time <= 255);
	*dst = params->f_max_time;
	dst++;
	dst_counter++;

	/* Encode MAX_HEADER (see also: 3GPP TS 44.065, 6.5.3.1, Table 6) */
	OSMO_ASSERT(params->max_header >= 60);
	OSMO_ASSERT(params->max_header <= 255);
	*dst = params->max_header;
	dst++;
	dst_counter++;

	/* Encode TCP_SPACE (see also: 3GPP TS 44.065, 6.5.3.1, Table 6) */
	OSMO_ASSERT(params->tcp_space >= 3);
	OSMO_ASSERT(params->tcp_space <= 255);
	*dst = params->tcp_space;
	dst++;
	dst_counter++;

	/* Encode NON_TCP_SPACE (see also: 3GPP TS 44.065, 6.5.3.1, Table 6) */
	OSMO_ASSERT(params->non_tcp_space >= 3);
	OSMO_ASSERT(params->non_tcp_space <= 65535);
	*dst = (params->non_tcp_space >> 8) & 0xFF;
	dst++;
	dst_counter++;
	*dst = (params->non_tcp_space) & 0xFF;
	dst++;
	dst_counter++;

	/* Return generated length */
	return dst_counter;
}

/* Encode ROHC parameter field
 * (see also: 3GPP TS 44.065, 6.5.4.1, Table 10) */
static int encode_pcomp_rohc_params(uint8_t *dst, unsigned int dst_maxlen,
				    const struct gprs_sndcp_pcomp_rohc_params
				    *params)
{
	/* NOTE: Buffer *dst should offer at least 36
	 * (2 * 16 Profiles + 2 * 3 Parameter) bytes
	 * of memory space to store generation results */

	int i;
	int dst_counter = 0;
	int rc;

	OSMO_ASSERT(dst_maxlen >= 38);

	/* Bail if number of ROHC profiles exceeds limit
	 * (ROHC supports only a maximum of 16 different profiles) */
	OSMO_ASSERT(params->profile_len <= 16);

	/* Zero out buffer */
	memset(dst, 0, dst_maxlen);

	/* Encode applicable SAPIs */
	rc = encode_pcomp_applicable_sapis(dst, params->nsapi,
					   params->nsapi_len);
	dst += rc;
	dst_counter += rc;

	/* Encode MAX_CID (see also: 3GPP TS 44.065, 6.5.4.1, Table 10) */
	OSMO_ASSERT(params->max_cid >= 0);
	OSMO_ASSERT(params->max_cid <= 16383);
	*dst = (params->max_cid >> 8) & 0xFF;
	dst++;
	*dst = params->max_cid & 0xFF;
	dst++;
	dst_counter += 2;

	/* Encode MAX_HEADER (see also: 3GPP TS 44.065, 6.5.4.1, Table 10) */
	OSMO_ASSERT(params->max_header >= 60);
	OSMO_ASSERT(params->max_header <= 255);
	*dst = (params->max_header >> 8) & 0xFF;
	dst++;
	*dst = params->max_header & 0xFF;
	dst++;
	dst_counter += 2;

	/* Encode ROHC Profiles (see also: 3GPP TS 44.065, 6.5.4.1, Table 10) */
	for (i = 0; i < params->profile_len; i++) {
		*dst = (params->profile[i] >> 8) & 0xFF;
		dst++;
		*dst = params->profile[i] & 0xFF;
		dst++;
		dst_counter += 2;
	}

	/* Return generated length */
	return dst_counter;
}

/* Encode V.42bis parameter field
 * (see also: 3GPP TS 44.065, 6.6.2.1, Table 7a) */
static int encode_dcomp_v42bis_params(uint8_t *dst, unsigned int dst_maxlen,
				      const struct
				      gprs_sndcp_dcomp_v42bis_params *params)
{
	/* NOTE: Buffer *dst should offer at least 6 bytes
	 * of space to store the generation results */

	int dst_counter = 0;
	int rc;

	OSMO_ASSERT(dst_maxlen >= 6);

	/* Zero out buffer */
	memset(dst, 0, dst_maxlen);

	/* Encode applicable SAPIs */
	rc = encode_pcomp_applicable_sapis(dst, params->nsapi,
					   params->nsapi_len);
	dst += rc;
	dst_counter += rc;

	/* Encode P0 (see also: 3GPP TS 44.065, 6.6.2.1, Table 7a) */
	OSMO_ASSERT(params->p0 >= 0);
	OSMO_ASSERT(params->p0 <= 3);
	*dst = params->p0 & 0x03;
	dst++;
	dst_counter++;

	/* Encode P1 (see also: 3GPP TS 44.065, 6.6.2.1, Table 7a) */
	OSMO_ASSERT(params->p1 >= 512);
	OSMO_ASSERT(params->p1 <= 65535);
	*dst = (params->p1 >> 8) & 0xFF;
	dst++;
	*dst = params->p1 & 0xFF;
	dst++;
	dst_counter += 2;

	/* Encode P2 (see also: 3GPP TS 44.065, 6.6.2.1, Table 7a) */
	OSMO_ASSERT(params->p2 >= 6);
	OSMO_ASSERT(params->p2 <= 250);
	*dst = params->p2;
	dst++;
	dst_counter++;

	/* Return generated length */
	return dst_counter;
}

/* Encode V44 parameter field
 * (see also: 3GPP TS 44.065, 6.6.3.1, Table 7c) */
static int encode_dcomp_v44_params(uint8_t *dst, unsigned int dst_maxlen,
				   const struct gprs_sndcp_dcomp_v44_params
				   *params)
{
	/* NOTE: Buffer *dst should offer at least 12 bytes
	 * of space to store the generation results */

	int dst_counter = 0;
	int rc;

	OSMO_ASSERT(dst_maxlen >= 12);

	/* Zero out buffer */
	memset(dst, 0, dst_maxlen);

	/* Encode applicable SAPIs */
	rc = encode_pcomp_applicable_sapis(dst, params->nsapi,
					   params->nsapi_len);
	dst += rc;
	dst_counter += rc;

	/* Encode C0 (see also: 3GPP TS 44.065, 6.6.3.1, Table 7c) */
	OSMO_ASSERT(params->c0 == 0x80 || params->c0 == 0xC0);
	*dst = params->c0 & 0xC0;
	dst++;
	dst_counter++;

	/* Encode P0 (see also: 3GPP TS 44.065, 6.6.3.1, Table 7c) */
	OSMO_ASSERT(params->p0 >= 0);
	OSMO_ASSERT(params->p0 <= 3);
	*dst = params->p0 & 0x03;
	dst++;
	dst_counter++;

	/* Encode P1T (see also: 3GPP TS 44.065, 6.6.3.1, Table 7c) */
	OSMO_ASSERT(params->p1t >= 256);
	OSMO_ASSERT(params->p1t <= 65535);
	*dst = (params->p1t >> 8) & 0xFF;
	dst++;
	*dst = params->p1t & 0xFF;
	dst++;
	dst_counter += 2;

	/* Encode P1R (see also: 3GPP TS 44.065, 6.6.3.1, Table 7c) */
	OSMO_ASSERT(params->p1r >= 256);
	OSMO_ASSERT(params->p1r <= 65535);
	*dst = (params->p1r >> 8) & 0xFF;
	dst++;
	*dst = params->p1r & 0xFF;
	dst++;
	dst_counter += 2;

	/* Encode P3T (see also: 3GPP TS 44.065, 6.6.3.1, Table 7c) */
	OSMO_ASSERT(params->p3t >= 0);
	OSMO_ASSERT(params->p3t <= 65535);
	OSMO_ASSERT(params->p3t >= 2 * params->p1t);
	*dst = (params->p3t >> 8) & 0xFF;
	dst++;
	*dst = params->p3t & 0xFF;
	dst++;
	dst_counter += 2;

	/* Encode P3R (see also: 3GPP TS 44.065, 6.6.3.1, Table 7c) */
	OSMO_ASSERT(params->p3r >= 0);
	OSMO_ASSERT(params->p3r <= 65535);
	OSMO_ASSERT(params->p3r >= 2 * params->p1r);
	*dst = (params->p3r >> 8) & 0xFF;
	dst++;
	*dst = params->p3r & 0xFF;
	dst++;
	dst_counter += 2;

	/* Return generated length */
	return dst_counter;
}

/* Encode data or protocol control information compression field
 * (see also: 3GPP TS 44.065, 6.6.1.1, Figure 9 and
 *            3GPP TS 44.065, 6.5.1.1, Figure 7) */
static int encode_comp_field(uint8_t *dst, unsigned int dst_maxlen,
			     const struct gprs_sndcp_comp_field *comp_field)
{
	int dst_counter = 0;
	int len;
	int expected_length;
	int i;

	uint8_t payload_bytes[256];
	int payload_bytes_len = -1;

	/* If possible, try do encode payload bytes first */
	if (comp_field->rfc1144_params) {
		payload_bytes_len =
		    encode_pcomp_rfc1144_params(payload_bytes,
						sizeof(payload_bytes),
						comp_field->rfc1144_params);
	} else if (comp_field->rfc2507_params) {
		payload_bytes_len =
		    encode_pcomp_rfc2507_params(payload_bytes,
						sizeof(payload_bytes),
						comp_field->rfc2507_params);
	} else if (comp_field->rohc_params) {
		payload_bytes_len =
		    encode_pcomp_rohc_params(payload_bytes,
					     sizeof(payload_bytes),
					     comp_field->rohc_params);
	} else if (comp_field->v42bis_params) {
		payload_bytes_len =
		    encode_dcomp_v42bis_params(payload_bytes,
					       sizeof(payload_bytes),
					       comp_field->v42bis_params);
	} else if (comp_field->v44_params) {
		payload_bytes_len =
		    encode_dcomp_v44_params(payload_bytes,
					    sizeof(payload_bytes),
					    comp_field->v44_params);
	} else
		OSMO_ASSERT(false);

	/* Bail immediately if payload byte generation failed */
	OSMO_ASSERT(payload_bytes_len >= 0);

	/* Bail if comp_len is out of bounds */
	OSMO_ASSERT(comp_field->comp_len <= sizeof(comp_field->comp));

	/* Calculate length field of the data block */
	if (comp_field->p) {
		len =
		    payload_bytes_len +
		    ceil((double)(comp_field->comp_len) / 2.0);
		expected_length = len + 3;
	} else {
		len = payload_bytes_len;
		expected_length = len + 2;
	}

	/* Bail immediately if no sufficient memory space is supplied */
	OSMO_ASSERT(dst_maxlen >= expected_length);

	/* Check if the entity number is within bounds */
	OSMO_ASSERT(comp_field->entity <= 0x1f);

	/* Check if the algorithm number is within bounds */
	OSMO_ASSERT(comp_field->algo >= 0 || comp_field->algo <= 0x1f);

	/* Zero out buffer */
	memset(dst, 0, dst_maxlen);

	/* Encode Propose bit */
	if (comp_field->p)
		*dst |= (1 << 7);

	/* Encode entity number */
	*dst |= comp_field->entity & 0x1F;
	dst++;
	dst_counter++;

	/* Encode algorithm number */
	if (comp_field->p) {
		*dst |= comp_field->algo & 0x1F;
		dst++;
		dst_counter++;
	}

	/* Encode length field */
	*dst |= len & 0xFF;
	dst++;
	dst_counter++;

	/* Encode PCOMP/DCOMP values */
	if (comp_field->p) {
		for (i = 0; i < comp_field->comp_len; i++) {
			/* Check if submitted PCOMP/DCOMP
			   values are within bounds */
			if (comp_field->comp[i] > 0x0F)
				return -EINVAL;

			if (i & 1) {
				*dst |= comp_field->comp[i] & 0x0F;
				dst++;
				dst_counter++;
			} else
				*dst |= (comp_field->comp[i] << 4) & 0xF0;
		}

		if (i & 1) {
			dst++;
			dst_counter++;
		}
	}

	/* Append payload bytes */
	memcpy(dst, payload_bytes, payload_bytes_len);
	dst_counter += payload_bytes_len;

	/* Return generated length */
	return dst_counter;
}

/* Find out to which compression class the specified comp-field belongs
 * (header compression or data compression?) */
int gprs_sndcp_get_compression_class(const struct gprs_sndcp_comp_field
				     *comp_field)
{
	OSMO_ASSERT(comp_field);

	if (comp_field->rfc1144_params)
		return SNDCP_XID_PROTOCOL_COMPRESSION;
	else if (comp_field->rfc2507_params)
		return SNDCP_XID_PROTOCOL_COMPRESSION;
	else if (comp_field->rohc_params)
		return SNDCP_XID_PROTOCOL_COMPRESSION;
	else if (comp_field->v42bis_params)
		return SNDCP_XID_DATA_COMPRESSION;
	else if (comp_field->v44_params)
		return SNDCP_XID_DATA_COMPRESSION;
	else
		return -EINVAL;
}

/* Convert all compression fields to bytstreams */
static int gprs_sndcp_pack_fields(const struct llist_head *comp_fields,
				  uint8_t *dst,
				  unsigned int dst_maxlen, int class)
{
	struct gprs_sndcp_comp_field *comp_field;
	int byte_counter = 0;
	int rc;

	llist_for_each_entry_reverse(comp_field, comp_fields, list) {
		if (class == gprs_sndcp_get_compression_class(comp_field)) {
			rc = encode_comp_field(dst + byte_counter,
					       dst_maxlen - byte_counter,
					       comp_field);

			/* When input data is correct, there is
			 * no reason for the encoder to fail! */
			OSMO_ASSERT(rc >= 0);

			byte_counter += rc;
		}
	}

	/* Return generated length */
	return byte_counter;
}

/* Transform a list with compression fields into an SNDCP-XID message (dst) */
int gprs_sndcp_compile_xid(uint8_t *dst, unsigned int dst_maxlen,
			   const struct llist_head *comp_fields, int version)
{
	int rc;
	int byte_counter = 0;
	uint8_t comp_bytes[512];
	uint8_t xid_version_number[1];

	OSMO_ASSERT(comp_fields);
	OSMO_ASSERT(dst);
	OSMO_ASSERT(dst_maxlen >= 2 + sizeof(xid_version_number));

	/* Prepend header with version number */
	if (version >= 0) {
		xid_version_number[0] = (uint8_t) (version & 0xff);
		dst =
		    tlv_put(dst, SNDCP_XID_VERSION_NUMBER,
			    sizeof(xid_version_number), xid_version_number);
		byte_counter += (sizeof(xid_version_number) + 2);
	}

	/* Stop if there is no compression fields supplied */
	if (llist_empty(comp_fields))
		return byte_counter;

	/* Add data compression fields */
	rc = gprs_sndcp_pack_fields(comp_fields, comp_bytes,
				    sizeof(comp_bytes),
				    SNDCP_XID_DATA_COMPRESSION);
	OSMO_ASSERT(rc >= 0);

	if (rc > 0) {
		dst = tlv_put(dst, SNDCP_XID_DATA_COMPRESSION, rc, comp_bytes);
		byte_counter += rc + 2;
	}

	/* Add header compression fields */
	rc = gprs_sndcp_pack_fields(comp_fields, comp_bytes,
				    sizeof(comp_bytes),
				    SNDCP_XID_PROTOCOL_COMPRESSION);
	OSMO_ASSERT(rc >= 0);

	if (rc > 0) {
		dst = tlv_put(dst, SNDCP_XID_PROTOCOL_COMPRESSION, rc,
			      comp_bytes);
		byte_counter += rc + 2;
	}

	/* Return generated length */
	return byte_counter;
}

/* FUNCTIONS RELATED TO SNDCP-XID DECODING */

/* Decode applicable sapis (works the same in all three compression schemes) */
static int decode_pcomp_applicable_sapis(uint8_t *nsapis,
					 uint8_t *nsapis_len,
					 const uint8_t *src,
					 unsigned int src_len)
{
	uint16_t blob;
	int i;
	int nsapi_len = 0;

	/* Exit immediately if no result can be stored */
	if (!nsapis)
		return -EINVAL;

	/* Exit immediately if not enough input data is available */
	if (src_len < 2)
		return -EINVAL;

	/* Read bitmask */
	blob = *src;
	blob = (blob << 8) & 0xFF00;
	src++;
	blob |= (*src) & 0xFF;
	blob = (blob >> 5);

	/* Decode applicable SAPIs */
	for (i = 0; i < 15; i++) {
		if ((blob >> i) & 1) {
			nsapis[nsapi_len] = i + 5;
			nsapi_len++;
		}
	}

	/* Return consumed length */
	*nsapis_len = nsapi_len;
	return 2;
}

/* Decode 16 bit field */
static int decode_pcomp_16_bit_field(int *value_int, uint16_t * value_uint16,
				     const uint8_t *src,
				     unsigned int src_len,
				     int value_min, int value_max)
{
	uint16_t blob;

	/* Reset values to zero (just to be sure) */
	if (value_int)
		*value_int = -1;
	if (value_uint16)
		*value_uint16 = 0;

	/* Exit if not enough src are available */
	if (src_len < 2)
		return -EINVAL;

	/* Decode bit value */
	blob = *src;
	blob = (blob << 8) & 0xFF00;
	src++;
	blob |= *src;

	/* Check if parsed value is within bounds */
	if (blob < value_min)
		return -EINVAL;
	if (blob > value_max)
		return -EINVAL;

	/* Hand back results to the caller */
	if (value_int)
		*value_int = blob;
	if (value_uint16)
		*value_uint16 = blob;

	/* Return consumed length */
	return 2;
}

/* Decode 8 bit field */
static int decode_pcomp_8_bit_field(int *value_int, uint8_t *value_uint8,
				    const uint8_t *src,
				    unsigned int src_len,
				    int value_min, int value_max)
{
	uint8_t blob;

	/* Reset values to invalid (just to be sure) */
	if (value_int)
		*value_int = -1;
	if (value_uint8)
		*value_uint8 = 0;

	/* Exit if not enough src are available */
	if (src_len < 1)
		return -EINVAL;

	/* Decode bit value */
	blob = *src;

	/* Check if parsed value is within bounds */
	if (blob < value_min)
		return -EINVAL;
	if (blob > value_max)
		return -EINVAL;

	/* Hand back results to the caller */
	if (value_int)
		*value_int = blob;
	if (value_uint8)
		*value_uint8 = blob;

	/* Return consumed length */
	return 1;
}

/* Decode rfc1144 parameter field see also: 3GPP TS 44.065, 6.5.2.1, Table 5) */
static int decode_pcomp_rfc1144_params(struct gprs_sndcp_pcomp_rfc1144_params
				       *params, const uint8_t *src,
				       unsigned int src_len)
{
	int rc;
	int byte_counter = 0;

	/* Mark all optional parameters invalid by default */
	params->s01 = -1;

	/* Decode applicable SAPIs */
	rc = decode_pcomp_applicable_sapis(params->nsapi, &params->nsapi_len,
					   src, src_len);
	if (rc > 0) {
		byte_counter += rc;
		src += rc;
	} else
		return byte_counter;

	/* Decode parameter S0 -1
	 * (see also: 3GPP TS 44.065, 6.5.2.1, Table 5) */
	rc = decode_pcomp_8_bit_field(&params->s01, NULL, src,
				      src_len - byte_counter, 0, 255);
	if (rc <= 0)
		return byte_counter;
	byte_counter += rc;
	src += rc;

	/* Return consumed length */
	return byte_counter;
}

/* Decode rfc2507 parameter field
 * (see also: 3GPP TS 44.065, 6.5.3.1, Table 6) */
static int decode_pcomp_rfc2507_params(struct gprs_sndcp_pcomp_rfc2507_params
				       *params, const uint8_t *src,
				       unsigned int src_len)
{
	int rc;
	int byte_counter = 0;

	/* Mark all optional parameters invalid by default */
	params->f_max_period = -1;
	params->f_max_time = -1;
	params->max_header = -1;
	params->tcp_space = -1;
	params->non_tcp_space = -1;

	/* Decode applicable SAPIs */
	rc = decode_pcomp_applicable_sapis(params->nsapi, &params->nsapi_len,
					   src, src_len);
	if (rc > 0) {
		byte_counter += rc;
		src += rc;
	} else
		return byte_counter;

	/* Decode F_MAX_PERIOD (see also: 3GPP TS 44.065, 6.5.3.1, Table 6) */
	rc = decode_pcomp_16_bit_field(&params->f_max_period, NULL, src,
				       src_len - byte_counter, 1, 65535);
	if (rc <= 0)
		return byte_counter;
	byte_counter += rc;
	src += rc;

	/* Decode F_MAX_TIME (see also: 3GPP TS 44.065, 6.5.3.1, Table 6) */
	rc = decode_pcomp_8_bit_field(&params->f_max_time, NULL, src,
				      src_len - byte_counter, 1, 255);
	if (rc <= 0)
		return byte_counter;
	byte_counter += rc;
	src += rc;

	/* Decode MAX_HEADER (see also: 3GPP TS 44.065, 6.5.3.1, Table 6) */
	rc = decode_pcomp_8_bit_field(&params->max_header, NULL, src,
				      src_len - byte_counter, 60, 255);
	if (rc <= 0)
		return byte_counter;
	byte_counter += rc;
	src += rc;

	/* Decode TCP_SPACE (see also: 3GPP TS 44.065, 6.5.3.1, Table 6) */
	rc = decode_pcomp_8_bit_field(&params->tcp_space, NULL, src,
				      src_len - byte_counter, 3, 255);
	if (rc <= 0)
		return byte_counter;
	byte_counter += rc;
	src += rc;

	/* Decode NON_TCP_SPACE (see also: 3GPP TS 44.065, 6.5.3.1, Table 6) */
	rc = decode_pcomp_16_bit_field(&params->non_tcp_space, NULL, src,
				       src_len - byte_counter, 3, 65535);
	if (rc <= 0)
		return byte_counter;
	byte_counter += rc;
	src += rc;

	/* Return consumed length */
	return byte_counter;
}

/* Decode ROHC parameter field (see also: 3GPP TS 44.065, 6.5.4.1, Table 10) */
static int decode_pcomp_rohc_params(struct gprs_sndcp_pcomp_rohc_params *params,
				    const uint8_t *src, unsigned int src_len)
{
	int rc;
	int byte_counter = 0;
	int i;

	/* Mark all optional parameters invalid by default */
	params->max_cid = -1;
	params->max_header = -1;

	/* Decode applicable SAPIs */
	rc = decode_pcomp_applicable_sapis(params->nsapi, &params->nsapi_len,
					   src, src_len);
	if (rc <= 0)
		return byte_counter;
	byte_counter += rc;
	src += rc;

	/* Decode MAX_CID (see also: 3GPP TS 44.065, 6.5.4.1, Table 10) */
	rc = decode_pcomp_16_bit_field(&params->max_cid, NULL, src,
				       src_len - byte_counter, 0, 16383);
	if (rc <= 0)
		return byte_counter;
	byte_counter += rc;
	src += rc;

	/* Decode MAX_HEADER (see also: 3GPP TS 44.065, 6.5.4.1, Table 10) */
	rc = decode_pcomp_16_bit_field(&params->max_header, NULL, src,
				       src_len - byte_counter, 60, 255);
	if (rc <= 0)
		return byte_counter;
	byte_counter += rc;
	src += rc;

	/* Decode Profiles (see also: 3GPP TS 44.065, 6.5.4.1, Table 10) */
	for (i = 0; i < 16; i++) {
		params->profile_len = 0;
		rc = decode_pcomp_16_bit_field(NULL, &params->profile[i], src,
					       src_len - byte_counter, 0,
					       65535);
		if (rc <= 0)
			return byte_counter;
		byte_counter += rc;
		src += rc;
		params->profile_len = i + 1;
	}

	/* Return consumed length */
	return byte_counter;
}

/* Decode V.42bis parameter field
 * (see also: 3GPP TS 44.065, 6.6.2.1, Table 7a) */
static int decode_dcomp_v42bis_params(struct gprs_sndcp_dcomp_v42bis_params
				      *params, const uint8_t *src,
				      unsigned int src_len)
{
	int rc;
	int byte_counter = 0;

	/* Mark all optional parameters invalid by default */
	params->p0 = -1;
	params->p1 = -1;
	params->p2 = -1;

	/* Decode applicable SAPIs */
	rc = decode_pcomp_applicable_sapis(params->nsapi, &params->nsapi_len,
					   src, src_len);
	if (rc > 0) {
		byte_counter += rc;
		src += rc;
	} else
		return byte_counter;

	/* Decode P0 (see also: 3GPP TS 44.065, 6.6.2.1, Table 7a) */
	rc = decode_pcomp_8_bit_field(&params->p0, NULL, src,
				      src_len - byte_counter, 0, 3);
	if (rc <= 0)
		return byte_counter;
	byte_counter += rc;
	src += rc;

	/* Decode P1 (see also: 3GPP TS 44.065, 6.6.2.1, Table 7a) */
	rc = decode_pcomp_16_bit_field(&params->p1, NULL, src,
				       src_len - byte_counter, 512, 65535);
	if (rc <= 0)
		return byte_counter;
	byte_counter += rc;
	src += rc;

	/* Decode P2 (see also: 3GPP TS 44.065, 6.6.2.1, Table 7a) */
	rc = decode_pcomp_8_bit_field(&params->p2, NULL, src,
				      src_len - byte_counter, 6, 250);
	if (rc <= 0)
		return byte_counter;
	byte_counter += rc;
	src += rc;

	/* Return consumed length */
	return byte_counter;
}

/* Decode V44 parameter field (see also: 3GPP TS 44.065, 6.6.3.1, Table 7c) */
static int decode_dcomp_v44_params(struct gprs_sndcp_dcomp_v44_params *params,
				   const uint8_t *src, unsigned int src_len)
{
	int rc;
	int byte_counter = 0;

	/* Mark all optional parameters invalid by default */
	params->c0 = -1;
	params->p0 = -1;
	params->p1t = -1;
	params->p1r = -1;
	params->p3t = -1;
	params->p3r = -1;

	/* Decode applicable SAPIs */
	rc = decode_pcomp_applicable_sapis(params->nsapi, &params->nsapi_len,
					   src, src_len);
	if (rc > 0) {
		byte_counter += rc;
		src += rc;
	} else
		return byte_counter;

	/* Decode C0 (see also: 3GPP TS 44.065, 6.6.3.1, Table 7c) */
	rc = decode_pcomp_8_bit_field(&params->c0, NULL, src,
				      src_len - byte_counter, 0, 255);
	if (rc <= 0)
		return byte_counter;
	if ((params->c0 != 0x80) && (params->c0 != 0xC0))
		return -EINVAL;
	byte_counter += rc;
	src += rc;

	/* Decode P0 (see also: 3GPP TS 44.065, 6.6.3.1, Table 7c) */
	rc = decode_pcomp_8_bit_field(&params->p0, NULL, src,
				      src_len - byte_counter, 0, 3);
	if (rc <= 0)
		return byte_counter;
	byte_counter += rc;
	src += rc;

	/* Decode P1T (see also: 3GPP TS 44.065, 6.6.3.1, Table 7c) */
	rc = decode_pcomp_16_bit_field(&params->p1t, NULL, src,
				       src_len - byte_counter, 265, 65535);
	if (rc <= 0)
		return byte_counter;
	byte_counter += rc;
	src += rc;

	/* Decode P1R (see also: 3GPP TS 44.065, 6.6.3.1, Table 7c) */
	rc = decode_pcomp_16_bit_field(&params->p1r, NULL, src,
				       src_len - byte_counter, 265, 65535);
	if (rc <= 0)
		return byte_counter;
	byte_counter += rc;
	src += rc;

	/* Decode P3T (see also: 3GPP TS 44.065, 6.6.3.1, Table 7c) */
	rc = decode_pcomp_16_bit_field(&params->p3t, NULL, src,
				       src_len - byte_counter, 265, 65535);
	if (rc <= 0)
		return byte_counter;
	if (params->p3t < 2 * params->p1t)
		return -EINVAL;
	byte_counter += rc;
	src += rc;

	/* Decode P3R (see also: 3GPP TS 44.065, 6.6.3.1, Table 7c) */
	rc = decode_pcomp_16_bit_field(&params->p3r, NULL, src,
				       src_len - byte_counter, 265, 65535);
	if (rc <= 0)
		return byte_counter;
	if (params->p3r < 2 * params->p1r)
		return -EINVAL;
	byte_counter += rc;
	src += rc;

	/* Return consumed length */
	return byte_counter;
}

/* Lookup algorithm identfier by entity ID */
static int lookup_algorithm_identifier(int entity, const struct
				       entity_algo_table
				       *lt, unsigned int lt_len, int compclass)
{
	int i;

	if (!lt)
		return -1;

	for (i = 0; i < lt_len; i++) {
		if ((lt[i].entity == entity)
		    && (lt[i].compclass == compclass))
			return lt[i].algo;
	}

	return -1;
}

/* Helper function for decode_comp_field(), decodes
 * numeric pcomp/dcomp values */
static int decode_comp_values(struct gprs_sndcp_comp_field *comp_field,
			      const uint8_t *src, int compclass)
{
	int src_counter = 0;
	int i;

	if (comp_field->p) {
		/* Determine the number of expected PCOMP/DCOMP values */
		if (compclass == SNDCP_XID_PROTOCOL_COMPRESSION) {
			/* For protocol compression */
			switch (comp_field->algo) {
			case RFC_1144:
				comp_field->comp_len = RFC1144_PCOMP_NUM;
				break;
			case RFC_2507:
				comp_field->comp_len = RFC2507_PCOMP_NUM;
				break;
			case ROHC:
				comp_field->comp_len = ROHC_PCOMP_NUM;
				break;

				/* Exit if the algorithem type encodes
				   something unknown / unspecified */
			default:
				return -EINVAL;
			}
		} else {
			/* For data compression */
			switch (comp_field->algo) {
			case V42BIS:
				comp_field->comp_len = V42BIS_DCOMP_NUM;
				break;
			case V44:
				comp_field->comp_len = V44_DCOMP_NUM;
				break;

				/* Exit if the algorithem type encodes
				   something unknown / unspecified */
			default:
				return -EINVAL;
			}
		}

		for (i = 0; i < comp_field->comp_len; i++) {
			if (i & 1) {
				comp_field->comp[i] = (*src) & 0x0F;
				src++;
				src_counter++;
			} else
				comp_field->comp[i] = ((*src) >> 4) & 0x0F;
		}

		if (i & 1) {
			src++;
			src_counter++;
		}
	}

	return src_counter;
}

/* Helper function for decode_comp_field(), decodes the parameters
 * which are protocol compression specific */
static int decode_pcomp_params(struct gprs_sndcp_comp_field *comp_field,
			       const uint8_t *src, int src_len)
{
	int rc;

	switch (comp_field->algo) {
	case RFC_1144:
		comp_field->rfc1144_params = talloc_zero(comp_field, struct
					gprs_sndcp_pcomp_rfc1144_params);
		rc = decode_pcomp_rfc1144_params(comp_field->rfc1144_params,
						 src, src_len);
		if (rc < 0)
			talloc_free(comp_field->rfc1144_params);
		break;
	case RFC_2507:
		comp_field->rfc2507_params = talloc_zero(comp_field, struct
					gprs_sndcp_pcomp_rfc2507_params);
		rc = decode_pcomp_rfc2507_params(comp_field->rfc2507_params,
						 src, src_len);
		if (rc < 0)
			talloc_free(comp_field->rfc1144_params);
		break;
	case ROHC:
		comp_field->rohc_params = talloc_zero(comp_field, struct
					gprs_sndcp_pcomp_rohc_params);
		rc = decode_pcomp_rohc_params(comp_field->rohc_params, src,
					      src_len);
		if (rc < 0)
			talloc_free(comp_field->rohc_params);
		break;

		/* If no suitable decoder is detected,
		   leave the remaining bytes undecoded */
	default:
		rc = src_len;
	}

	if (rc < 0) {
		comp_field->rfc1144_params = NULL;
		comp_field->rfc2507_params = NULL;
		comp_field->rohc_params = NULL;
	}

	return rc;
}

/* Helper function for decode_comp_field(), decodes the parameters
 * which are data compression specific */
static int decode_dcomp_params(struct gprs_sndcp_comp_field *comp_field,
			       const uint8_t *src, int src_len)
{
	int rc;

	switch (comp_field->algo) {
	case V42BIS:
		comp_field->v42bis_params = talloc_zero(comp_field, struct
					gprs_sndcp_dcomp_v42bis_params);
		rc = decode_dcomp_v42bis_params(comp_field->v42bis_params, src,
						src_len);
		if (rc < 0)
			talloc_free(comp_field->v42bis_params);
		break;
	case V44:
		comp_field->v44_params = talloc_zero(comp_field, struct
					gprs_sndcp_dcomp_v44_params);
		rc = decode_dcomp_v44_params(comp_field->v44_params, src,
					     src_len);
		if (rc < 0)
			talloc_free(comp_field->v44_params);
		break;

		/* If no suitable decoder is detected,
		 * leave the remaining bytes undecoded */
	default:
		rc = src_len;
	}

	if (rc < 0) {
		comp_field->v42bis_params = NULL;
		comp_field->v44_params = NULL;
	}

	return rc;
}

/* Decode data or protocol control information compression field
 * (see also: 3GPP TS 44.065, 6.6.1.1, Figure 9 and
 *            3GPP TS 44.065, 6.5.1.1, Figure 7) */
static int decode_comp_field(struct gprs_sndcp_comp_field *comp_field,
			     const uint8_t *src, unsigned int src_len,
			     const struct entity_algo_table *lt,
			     unsigned int lt_len, int compclass)
{
	int src_counter = 0;
	unsigned int len;
	int rc;

	OSMO_ASSERT(comp_field);

	/* Exit immediately if it is clear that no
	   parseable data is present */
	if (src_len < 1 || !src)
		return -EINVAL;

	/* Zero out target struct */
	memset(comp_field, 0, sizeof(struct gprs_sndcp_comp_field));

	/* Decode Propose bit and Entity number */
	if ((*src) & 0x80)
		comp_field->p = 1;
	comp_field->entity = (*src) & 0x1F;
	src_counter++;
	src++;

	/* Decode algorithm number (if present) */
	if (comp_field->p) {
		comp_field->algo = (*src) & 0x1F;
		src_counter++;
		src++;
	}
	/* Alternatively take the information from the lookup table */
	else
		comp_field->algo =
		    lookup_algorithm_identifier(comp_field->entity, lt,
						lt_len, compclass);

	/* Decode length field */
	len = *src;
	src_counter++;
	src++;

	/* Decode PCOMP/DCOMP values */
	rc = decode_comp_values(comp_field, src, compclass);
	if (rc < 0)
		return -EINVAL;
	src_counter += rc;
	src += rc;
	len -= rc;

	/* Decode algorithm specific payload data */
	if (compclass == SNDCP_XID_PROTOCOL_COMPRESSION)
		rc = decode_pcomp_params(comp_field, src, len);
	else if (compclass == SNDCP_XID_DATA_COMPRESSION)
		rc = decode_dcomp_params(comp_field, src, len);
	else
		return -EINVAL;

	if (rc >= 0)
		src_counter += rc;
	else
		return -EINVAL;

	/* Return consumed length */
	return src_counter;
}

/* Helper function for gprs_sndcp_decode_xid() to decode XID blocks */
static int decode_xid_block(struct llist_head *comp_fields, uint8_t tag,
			    uint16_t tag_len, const uint8_t *val,
			    const struct entity_algo_table *lt,
			    unsigned int lt_len)
{
	struct gprs_sndcp_comp_field *comp_field;
	int byte_counter = 0;
	int comp_field_count = 0;
	int rc;

	byte_counter = 0;
	do {
		/* Bail if more than the maximum number of
		   comp_fields is generated */
		if (comp_field_count > MAX_ENTITIES * 2) {
			return -EINVAL;
		}

		/* Parse and add comp_field */
		comp_field =
		    talloc_zero(comp_fields, struct gprs_sndcp_comp_field);

		rc = decode_comp_field(comp_field, val + byte_counter,
				       tag_len - byte_counter, lt, lt_len, tag);

		if (rc < 0) {
			talloc_free(comp_field);
			return -EINVAL;
		}

		byte_counter += rc;
		llist_add(&comp_field->list, comp_fields);
		comp_field_count++;
	}
	while (tag_len - byte_counter > 0);

	return byte_counter;
}

/* Transform an SNDCP-XID message (src) into a list of SNDCP-XID fields */
static int gprs_sndcp_decode_xid(int *version, struct llist_head *comp_fields,
				 const uint8_t *src, unsigned int src_len,
				 const struct entity_algo_table *lt,
				 unsigned int lt_len)
{
	int src_pos = 0;
	uint8_t tag;
	uint16_t tag_len;
	const uint8_t *val;
	int byte_counter = 0;
	int rc;
	int tlv_count = 0;

	/* Preset version value as invalid */
	if (version)
		*version = -1;

	/* Valid TLV-Tag and types */
	static const struct tlv_definition sndcp_xid_def = {
		.def = {
			[SNDCP_XID_VERSION_NUMBER] = {TLV_TYPE_TLV,},
			[SNDCP_XID_DATA_COMPRESSION] = {TLV_TYPE_TLV,},
			[SNDCP_XID_PROTOCOL_COMPRESSION] = {TLV_TYPE_TLV,},
			},
	};

	/* Parse TLV-Encoded SNDCP-XID message and defer payload
	   to the apporpiate sub-parser functions */
	while (1) {

		/* Bail if an the maximum number of TLV fields
		 * have been parsed */
		if (tlv_count >= 3) {
			talloc_free(comp_fields);
			return -EINVAL;
		}

		/* Parse TLV field */
		rc = tlv_parse_one(&tag, &tag_len, &val, &sndcp_xid_def,
				   src + src_pos, src_len - src_pos);
		if (rc > 0)
			src_pos += rc;
		else {
			talloc_free(comp_fields);
			return -EINVAL;
		}

		/* Decode sndcp xid version number */
		if (version && tag == SNDCP_XID_VERSION_NUMBER)
			*version = val[0];

		/* Decode compression parameters */
		if ((tag == SNDCP_XID_PROTOCOL_COMPRESSION)
		    || (tag == SNDCP_XID_DATA_COMPRESSION)) {
			rc = decode_xid_block(comp_fields, tag, tag_len, val,
					      lt, lt_len);

			if (rc < 0) {
				talloc_free(comp_fields);
				return -EINVAL;
			} else
				byte_counter += rc;
		}

		/* Stop when no further TLV elements can be expected */
		if (src_len - src_pos <= 2)
			break;

		tlv_count++;
	}

	return 0;
}

/* Fill up lookutable from a list with comression entitiy fields */
static int gprs_sndcp_fill_table(struct
				 entity_algo_table *lt,
				 unsigned int lt_len,
				 const struct llist_head *comp_fields)
{
	struct gprs_sndcp_comp_field *comp_field;
	int i = 0;
	int rc;

	if (!comp_fields)
		return -EINVAL;
	if (!lt)
		return -EINVAL;

	memset(lt, 0, sizeof(*lt));

	llist_for_each_entry(comp_field, comp_fields, list) {
		if (comp_field->algo >= 0) {
			lt[i].entity = comp_field->entity;
			lt[i].algo = comp_field->algo;
			rc = gprs_sndcp_get_compression_class(comp_field);

			if (rc < 0) {
				memset(lt, 0, sizeof(*lt));
				return -EINVAL;
			}

			lt[i].compclass = rc;
			i++;
		}
	}

	return i;
}

/* Complete comp field params
 * (if a param (dst) is not valid, it will be copied from source (src) */
static int complete_comp_field_params(struct gprs_sndcp_comp_field
				      *comp_field_dst, const struct
				      gprs_sndcp_comp_field *comp_field_src)
{
	if (comp_field_dst->algo < 0)
		return -EINVAL;

	if (comp_field_dst->rfc1144_params && comp_field_src->rfc1144_params) {
		if (comp_field_dst->rfc1144_params->s01 < 0) {
			comp_field_dst->rfc1144_params->s01 =
			    comp_field_src->rfc1144_params->s01;
		}
		return 0;
	}

	if (comp_field_dst->rfc2507_params && comp_field_src->rfc2507_params) {

		if (comp_field_dst->rfc2507_params->f_max_period < 0) {
			comp_field_dst->rfc2507_params->f_max_period =
			    comp_field_src->rfc2507_params->f_max_period;
		}
		if (comp_field_dst->rfc2507_params->f_max_time < 0) {
			comp_field_dst->rfc2507_params->f_max_time =
			    comp_field_src->rfc2507_params->f_max_time;
		}
		if (comp_field_dst->rfc2507_params->max_header < 0) {
			comp_field_dst->rfc2507_params->max_header =
			    comp_field_src->rfc2507_params->max_header;
		}
		if (comp_field_dst->rfc2507_params->tcp_space < 0) {
			comp_field_dst->rfc2507_params->tcp_space =
			    comp_field_src->rfc2507_params->tcp_space;
		}
		if (comp_field_dst->rfc2507_params->non_tcp_space < 0) {
			comp_field_dst->rfc2507_params->non_tcp_space =
			    comp_field_src->rfc2507_params->non_tcp_space;
		}
		return 0;
	}

	if (comp_field_dst->rohc_params && comp_field_src->rohc_params) {
		if (comp_field_dst->rohc_params->max_cid < 0) {
			comp_field_dst->rohc_params->max_cid =
			    comp_field_src->rohc_params->max_cid;
		}
		if (comp_field_dst->rohc_params->max_header < 0) {
			comp_field_dst->rohc_params->max_header =
			    comp_field_src->rohc_params->max_header;
		}
		if (comp_field_dst->rohc_params->profile_len > 0) {
			memcpy(comp_field_dst->rohc_params->profile,
			       comp_field_src->rohc_params->profile,
			       sizeof(comp_field_dst->rohc_params->profile));
			comp_field_dst->rohc_params->profile_len =
			    comp_field_src->rohc_params->profile_len;
		}

		return 0;
	}

	if (comp_field_dst->v42bis_params && comp_field_src->v42bis_params) {
		if (comp_field_dst->v42bis_params->p0 < 0) {
			comp_field_dst->v42bis_params->p0 =
			    comp_field_src->v42bis_params->p0;
		}
		if (comp_field_dst->v42bis_params->p1 < 0) {
			comp_field_dst->v42bis_params->p1 =
			    comp_field_src->v42bis_params->p1;
		}
		if (comp_field_dst->v42bis_params->p2 < 0) {
			comp_field_dst->v42bis_params->p2 =
			    comp_field_src->v42bis_params->p2;
		}
		return 0;
	}

	if (comp_field_dst->v44_params && comp_field_src->v44_params) {
		if (comp_field_dst->v44_params->c0 < 0) {
			comp_field_dst->v44_params->c0 =
			    comp_field_src->v44_params->c0;
		}
		if (comp_field_dst->v44_params->p0 < 0) {
			comp_field_dst->v44_params->p0 =
			    comp_field_src->v44_params->p0;
		}
		if (comp_field_dst->v44_params->p1t < 0) {
			comp_field_dst->v44_params->p1t =
			    comp_field_src->v44_params->p1t;
		}
		if (comp_field_dst->v44_params->p1r < 0) {
			comp_field_dst->v44_params->p1r =
			    comp_field_src->v44_params->p1r;
		}
		if (comp_field_dst->v44_params->p3t < 0) {
			comp_field_dst->v44_params->p3t =
			    comp_field_src->v44_params->p3t;
		}
		if (comp_field_dst->v44_params->p3r < 0) {
			comp_field_dst->v44_params->p3r =
			    comp_field_src->v44_params->p3r;
		}
		return 0;
	}

	/* There should be at least exist one param set
	 * in the destination struct, otherwise something
	 * must be wrong! */
	return -EINVAL;
}

/* Complete missing parameters in a comp_field */
static int gprs_sndcp_complete_comp_field(struct gprs_sndcp_comp_field
					  *comp_field, const struct llist_head
					  *comp_fields)
{
	struct gprs_sndcp_comp_field *comp_field_src;
	int rc = 0;

	llist_for_each_entry(comp_field_src, comp_fields, list) {
		if (comp_field_src->entity == comp_field->entity) {

			/* Complete header fields */
			if (comp_field_src->comp_len > 0) {
				memcpy(comp_field->comp,
				       comp_field_src->comp,
				       sizeof(comp_field_src->comp));
				comp_field->comp_len = comp_field_src->comp_len;
			}

			/* Complete parameter fields */
			rc = complete_comp_field_params(comp_field,
							comp_field_src);
		}
	}

	return rc;
}

/* Complete missing parameters of all comp_field in a list */
static int gprs_sndcp_complete_comp_fields(struct llist_head
					   *comp_fields_incomplete,
					   const struct llist_head *comp_fields)
{
	struct gprs_sndcp_comp_field *comp_field_incomplete;
	int rc;

	llist_for_each_entry(comp_field_incomplete, comp_fields_incomplete,
			     list) {

		rc = gprs_sndcp_complete_comp_field(comp_field_incomplete,
						    comp_fields);
		if (rc < 0)
			return -EINVAL;

	}

	return 0;
}

/* Transform an SNDCP-XID message (src) into a list of SNDCP-XID fields */
struct llist_head *gprs_sndcp_parse_xid(int *version,
					const void *ctx,
					const uint8_t *src,
					unsigned int src_len,
					const struct llist_head
					*comp_fields_req)
{
	int rc;
	int lt_len;
	struct llist_head *comp_fields;
	struct entity_algo_table lt[MAX_ENTITIES * 2];

	/* In case of a zero length field, just exit */
	if (src_len == 0)
		return NULL;

	/* We should go any further if we have a field length greater
	 * zero and a null pointer as buffer! */
	OSMO_ASSERT(src);

	comp_fields = talloc_zero(ctx, struct llist_head);
	INIT_LLIST_HEAD(comp_fields);

	if (comp_fields_req) {
		/* Generate lookup table */
		lt_len =
		    gprs_sndcp_fill_table(lt, MAX_ENTITIES * 2,
					  comp_fields_req);
		if (lt_len < 0) {
			talloc_free(comp_fields);
			return NULL;
		}

		/* Parse SNDCP-CID XID-Field */
		rc = gprs_sndcp_decode_xid(version, comp_fields, src, src_len,
					   lt, lt_len);
		if (rc < 0) {
			talloc_free(comp_fields);
			return NULL;
		}

		rc = gprs_sndcp_complete_comp_fields(comp_fields,
						     comp_fields_req);
		if (rc < 0) {
			talloc_free(comp_fields);
			return NULL;
		}

	} else {
		/* Parse SNDCP-CID XID-Field */
		rc = gprs_sndcp_decode_xid(version, comp_fields, src, src_len,
					   NULL, 0);
		if (rc < 0) {
			talloc_free(comp_fields);
			return NULL;
		}
	}

	return comp_fields;
}

/* Helper for gprs_sndcp_dump_comp_fields(),
 * dumps protocol compression parameters */
static void dump_pcomp_params(const struct gprs_sndcp_comp_field
			      *comp_field, unsigned int logl)
{
	int i;

	switch (comp_field->algo) {
	case RFC_1144:
		if (comp_field->rfc1144_params == NULL) {
			LOGP(DSNDCP, logl,
			     "   gprs_sndcp_pcomp_rfc1144_params=NULL\n");
			break;
		}
		LOGP(DSNDCP, logl, "   gprs_sndcp_pcomp_rfc1144_params {\n");
		LOGP(DSNDCP, logl,
		     "      nsapi_len=%d;\n",
		     comp_field->rfc1144_params->nsapi_len);
		if (comp_field->rfc1144_params->nsapi_len == 0)
			LOGP(DSNDCP, logl, "      nsapi[] = NULL;\n");
		for (i = 0; i < comp_field->rfc1144_params->nsapi_len; i++) {
			LOGP(DSNDCP, logl,
			     "      nsapi[%d]=%d;\n", i,
			     comp_field->rfc1144_params->nsapi[i]);
		}
		LOGP(DSNDCP, logl, "      s01=%d;\n",
		     comp_field->rfc1144_params->s01);
		LOGP(DSNDCP, logl, "   }\n");
		break;
	case RFC_2507:
		if (comp_field->rfc2507_params == NULL) {
			LOGP(DSNDCP, logl,
			     "   gprs_sndcp_pcomp_rfc2507_params=NULL\n");
			break;
		}
		LOGP(DSNDCP, logl, "   gprs_sndcp_pcomp_rfc2507_params {\n");
		LOGP(DSNDCP, logl,
		     "      nsapi_len=%d;\n",
		     comp_field->rfc2507_params->nsapi_len);
		if (comp_field->rfc2507_params->nsapi_len == 0)
			LOGP(DSNDCP, logl, "      nsapi[] = NULL;\n");
		for (i = 0; i < comp_field->rfc2507_params->nsapi_len; i++) {
			LOGP(DSNDCP, logl,
			     "      nsapi[%d]=%d;\n", i,
			     comp_field->rfc2507_params->nsapi[i]);
		}
		LOGP(DSNDCP, logl,
		     "      f_max_period=%d;\n",
		     comp_field->rfc2507_params->f_max_period);
		LOGP(DSNDCP, logl,
		     "      f_max_time=%d;\n",
		     comp_field->rfc2507_params->f_max_time);
		LOGP(DSNDCP, logl,
		     "      max_header=%d;\n",
		     comp_field->rfc2507_params->max_header);
		LOGP(DSNDCP, logl,
		     "      tcp_space=%d;\n",
		     comp_field->rfc2507_params->tcp_space);
		LOGP(DSNDCP, logl,
		     "      non_tcp_space=%d;\n",
		     comp_field->rfc2507_params->non_tcp_space);
		LOGP(DSNDCP, logl, "   }\n");
		break;
	case ROHC:
		if (comp_field->rohc_params == NULL) {
			LOGP(DSNDCP, logl,
			     "   gprs_sndcp_pcomp_rohc_params=NULL\n");
			break;
		}
		LOGP(DSNDCP, logl, "   gprs_sndcp_pcomp_rohc_params {\n");
		LOGP(DSNDCP, logl,
		     "      nsapi_len=%d;\n",
		     comp_field->rohc_params->nsapi_len);
		if (comp_field->rohc_params->nsapi_len == 0)
			LOGP(DSNDCP, logl, "      nsapi[] = NULL;\n");
		for (i = 0; i < comp_field->rohc_params->nsapi_len; i++) {
			LOGP(DSNDCP, logl,
			     "      nsapi[%d]=%d;\n", i,
			     comp_field->rohc_params->nsapi[i]);
		}
		LOGP(DSNDCP, logl,
		     "      max_cid=%d;\n", comp_field->rohc_params->max_cid);
		LOGP(DSNDCP, logl,
		     "      max_header=%d;\n",
		     comp_field->rohc_params->max_header);
		LOGP(DSNDCP, logl,
		     "      profile_len=%d;\n",
		     comp_field->rohc_params->profile_len);
		if (comp_field->rohc_params->profile_len == 0)
			LOGP(DSNDCP, logl, "      profile[] = NULL;\n");
		for (i = 0; i < comp_field->rohc_params->profile_len; i++)
			LOGP(DSNDCP, logl,
			     "      profile[%d]=%04x;\n",
			     i, comp_field->rohc_params->profile[i]);
		LOGP(DSNDCP, logl, "   }\n");
		break;
	}

}

/* Helper for gprs_sndcp_dump_comp_fields(),
 * data protocol compression parameters */
static void dump_dcomp_params(const struct gprs_sndcp_comp_field
			      *comp_field, unsigned int logl)
{
	int i;

	switch (comp_field->algo) {
	case V42BIS:
		if (comp_field->v42bis_params == NULL) {
			LOGP(DSNDCP, logl,
			     "   gprs_sndcp_dcomp_v42bis_params=NULL\n");
			break;
		}
		LOGP(DSNDCP, logl, "   gprs_sndcp_dcomp_v42bis_params {\n");
		LOGP(DSNDCP, logl,
		     "      nsapi_len=%d;\n",
		     comp_field->v42bis_params->nsapi_len);
		if (comp_field->v42bis_params->nsapi_len == 0)
			LOGP(DSNDCP, logl, "      nsapi[] = NULL;\n");
		for (i = 0; i < comp_field->v42bis_params->nsapi_len; i++)
			LOGP(DSNDCP, logl,
			     "      nsapi[%d]=%d;\n", i,
			     comp_field->v42bis_params->nsapi[i]);
		LOGP(DSNDCP, logl, "      p0=%d;\n",
		     comp_field->v42bis_params->p0);
		LOGP(DSNDCP, logl, "      p1=%d;\n",
		     comp_field->v42bis_params->p1);
		LOGP(DSNDCP, logl, "      p2=%d;\n",
		     comp_field->v42bis_params->p2);
		LOGP(DSNDCP, logl, "   }\n");
		break;
	case V44:
		if (comp_field->v44_params == NULL) {
			LOGP(DSNDCP, logl,
			     "   gprs_sndcp_dcomp_v44_params=NULL\n");
			break;
		}
		LOGP(DSNDCP, logl, "   gprs_sndcp_dcomp_v44_params {\n");
		LOGP(DSNDCP, logl,
		     "      nsapi_len=%d;\n",
		     comp_field->v44_params->nsapi_len);
		if (comp_field->v44_params->nsapi_len == 0)
			LOGP(DSNDCP, logl, "      nsapi[] = NULL;\n");
		for (i = 0; i < comp_field->v44_params->nsapi_len; i++) {
			LOGP(DSNDCP, logl,
			     "      nsapi[%d]=%d;\n", i,
			     comp_field->v44_params->nsapi[i]);
		}
		LOGP(DSNDCP, logl, "      c0=%d;\n",
		     comp_field->v44_params->c0);
		LOGP(DSNDCP, logl, "      p0=%d;\n",
		     comp_field->v44_params->p0);
		LOGP(DSNDCP, logl, "      p1t=%d;\n",
		     comp_field->v44_params->p1t);
		LOGP(DSNDCP, logl, "      p1r=%d;\n",
		     comp_field->v44_params->p1r);
		LOGP(DSNDCP, logl, "      p3t=%d;\n",
		     comp_field->v44_params->p3t);
		LOGP(DSNDCP, logl, "      p3r=%d;\n",
		     comp_field->v44_params->p3r);
		LOGP(DSNDCP, logl, "   }\n");
		break;
	}
}

/* Dump a list with SNDCP-XID fields (Debug) */
void gprs_sndcp_dump_comp_fields(const struct llist_head *comp_fields,
				 unsigned int logl)
{
	struct gprs_sndcp_comp_field *comp_field;
	int i;
	int compclass;

	OSMO_ASSERT(comp_fields);

	llist_for_each_entry(comp_field, comp_fields, list) {
		LOGP(DSNDCP, logl, "SNDCP-XID:\n");
		LOGP(DSNDCP, logl, "struct gprs_sndcp_comp_field {\n");
		LOGP(DSNDCP, logl, "   entity=%d;\n", comp_field->entity);
		LOGP(DSNDCP, logl, "   algo=%d;\n", comp_field->algo);
		LOGP(DSNDCP, logl, "   comp_len=%d;\n", comp_field->comp_len);
		if (comp_field->comp_len == 0)
			LOGP(DSNDCP, logl, "   comp[] = NULL;\n");
		for (i = 0; i < comp_field->comp_len; i++) {
			LOGP(DSNDCP, logl, "   comp[%d]=%d;\n", i,
			     comp_field->comp[i]);
		}

		compclass = gprs_sndcp_get_compression_class(comp_field);

		if (compclass == SNDCP_XID_PROTOCOL_COMPRESSION) {
			dump_pcomp_params(comp_field, logl);
		} else if (compclass == SNDCP_XID_DATA_COMPRESSION) {
			dump_dcomp_params(comp_field, logl);
		}

		LOGP(DSNDCP, logl, "}\n");
	}

}
