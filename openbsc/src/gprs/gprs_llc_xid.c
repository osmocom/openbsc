/* GPRS LLC XID field encoding/decoding as per 3GPP TS 44.064 */

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
#include <errno.h>

#include <osmocom/core/utils.h>
#include <osmocom/core/linuxlist.h>
#include <osmocom/core/talloc.h>
#include <osmocom/core/msgb.h>
#include <osmocom/core/talloc.h>

#include <openbsc/debug.h>
#include <openbsc/gprs_llc.h>
#include <openbsc/sgsn.h>
#include <openbsc/gprs_llc_xid.h>

const struct value_string gprs_llc_xid_type_names[] = {
	{ GPRS_LLC_XID_T_VERSION,	"VERSION"},
	{ GPRS_LLC_XID_T_IOV_UI,	"IOV_UI"},
	{ GPRS_LLC_XID_T_IOV_I,		"IOV_I"},
	{ GPRS_LLC_XID_T_T200,		"T200"},
	{ GPRS_LLC_XID_T_N200,		"N200"},
	{ GPRS_LLC_XID_T_N201_U,	"N201_"},
	{ GPRS_LLC_XID_T_N201_I,	"N201_I"},
	{ GPRS_LLC_XID_T_mD,		"mD"},
	{ GPRS_LLC_XID_T_mU,		"mU"},
	{ GPRS_LLC_XID_T_kD,		"kD"},
	{ GPRS_LLC_XID_T_kU,		"kU"},
	{ GPRS_LLC_XID_T_L3_PAR,	"L3_PAR"},
	{ GPRS_LLC_XID_T_RESET,		"RESET"},
	{ 0, NULL },
};

/* Parse XID parameter field */
static int decode_xid_field(struct gprs_llc_xid_field *xid_field,
			    const uint8_t *src, uint8_t src_len)
{
	uint8_t xl;
	uint8_t type;
	uint8_t len;
	int src_counter = 0;

	/* Exit immediately if it is clear that no
	 * parseable data is present */
	if (src_len < 1 || !src)
		return -EINVAL;

	/* Extract header info */
	xl = (*src >> 7) & 1;
	type = (*src >> 2) & 0x1F;

	/* Extract length field */
	len = (*src) & 0x3;
	src++;
	src_counter++;
	if (xl) {
		if (src_len < 2)
			return -EINVAL;
		len = (len << 6) & 0xC0;
		len |= ((*src) >> 2) & 0x3F;
		src++;
		src_counter++;
	}

	/* Fill out struct */
	xid_field->type = type;
	xid_field->data_len = len;
	if (len > 0) {
		if (src_len < src_counter + len)
			return -EINVAL;
		xid_field->data =
			talloc_memdup(xid_field,src,xid_field->data_len);
	} else
		xid_field->data = NULL;

	/* Return consumed length */
	return src_counter + len;
}

/* Encode XID parameter field */
static int encode_xid_field(uint8_t *dst, int dst_maxlen,
			    const struct gprs_llc_xid_field *xid_field)
{
	int xl = 0;

	/* When the length does not fit into 2 bits,
	 * we need extended length fields */
	if (xid_field->data_len > 3)
		xl = 1;

	/* Exit immediately if it is clear that no
	 * encoding result can be stored */
	if (dst_maxlen < xid_field->data_len + 1 + xl)
		return -EINVAL;

	/* There are only 5 bits reserved for the type, exit on exceed */
	if (xid_field->type > 31)
		return -EINVAL;

	/* Encode header */
	memset(dst, 0, dst_maxlen);
	if (xl)
		dst[0] |= 0x80;
	dst[0] |= (((xid_field->type) & 0x1F) << 2);

	if (xl) {
		dst[0] |= (((xid_field->data_len) >> 6) & 0x03);
		dst[1] = ((xid_field->data_len) << 2) & 0xFC;
	} else
		dst[0] |= ((xid_field->data_len) & 0x03);

	/* Append payload data */
	if (xid_field->data && xid_field->data_len)
		memcpy(dst + 1 + xl, xid_field->data, xid_field->data_len);

	/* Return generated length */
	return xid_field->data_len + 1 + xl;
}

/* Transform a list with XID fields into a XID message (dst) */
int gprs_llc_compile_xid(uint8_t *dst, int dst_maxlen,
			 const struct llist_head *xid_fields)
{
	struct gprs_llc_xid_field *xid_field;
	int rc;
	int byte_counter = 0;

	OSMO_ASSERT(xid_fields);
	OSMO_ASSERT(dst);

	llist_for_each_entry_reverse(xid_field, xid_fields, list) {
		/* Encode XID-Field */
		rc = encode_xid_field(dst, dst_maxlen, xid_field);
		if (rc < 0)
			return -EINVAL;

		/* Advance pointer and lower maxlen for the
		 * next encoding round */
		dst += rc;
		byte_counter += rc;
		dst_maxlen -= rc;
	}

	/* Return generated length */
	return byte_counter;
}

/* Transform a XID message (dst) into a list of XID fields */
struct llist_head *gprs_llc_parse_xid(const void *ctx, const uint8_t *src,
				      int src_len)
{
	struct gprs_llc_xid_field *xid_field;
	struct llist_head *xid_fields;

	int rc;
	int max_loops = src_len;

	OSMO_ASSERT(src);

	xid_fields = talloc_zero(ctx, struct llist_head);
	INIT_LLIST_HEAD(xid_fields);

	while (1) {
		/* Bail in case decode_xid_field() constantly returns zero */
		if (max_loops <= 0) {
			talloc_free(xid_fields);
			return NULL;
		}

		/* Decode XID field */
		xid_field = talloc_zero(xid_fields, struct gprs_llc_xid_field);
		rc = decode_xid_field(xid_field, src, src_len);

		/* Immediately stop on error */
		if (rc < 0) {
			talloc_free(xid_fields);
			return NULL;
		}

		/* Add parsed XID field to list */
		llist_add(&xid_field->list, xid_fields);

		/* Advance pointer and lower dst_len for the next
		 * decoding round */
		src += rc;
		src_len -= rc;

		/* We are (scuccessfully) done when no further byes are left */
		if (src_len == 0)
			return xid_fields;

		max_loops--;
	}
}

/* Create a duplicate of an XID-Field */
struct gprs_llc_xid_field *gprs_llc_dup_xid_field(const void *ctx, const struct
						  gprs_llc_xid_field
						  *xid_field)
{
	struct gprs_llc_xid_field *dup;

	OSMO_ASSERT(xid_field);

	/* Create a copy of the XID field in memory */
	dup = talloc_memdup(ctx, xid_field, sizeof(*xid_field));
	dup->data = talloc_memdup(ctx, xid_field->data, xid_field->data_len);

	/* Unlink duplicate from source list */
	INIT_LLIST_HEAD(&dup->list);

	return dup;
}

/* Copy an llist with xid fields */
struct llist_head *gprs_llc_copy_xid(const void *ctx,
				     const struct llist_head *xid_fields)
{
	struct gprs_llc_xid_field *xid_field;
	struct llist_head *xid_fields_copy;

	OSMO_ASSERT(xid_fields);

	xid_fields_copy = talloc_zero(ctx, struct llist_head);
	INIT_LLIST_HEAD(xid_fields_copy);

	/* Create duplicates and add them to the target list */
	llist_for_each_entry(xid_field, xid_fields, list) {
		llist_add(&gprs_llc_dup_xid_field(ctx, xid_field)->list,
			  xid_fields_copy);
	}

	return xid_fields_copy;
}

/* Dump a list with XID fields (Debug) */
void gprs_llc_dump_xid_fields(const struct llist_head *xid_fields,
			      unsigned int logl)
{
	struct gprs_llc_xid_field *xid_field;

	OSMO_ASSERT(xid_fields);

	llist_for_each_entry(xid_field, xid_fields, list) {
		if (xid_field->data_len) {
			OSMO_ASSERT(xid_field->data);
			LOGP(DLLC, logl,
			     "XID: type %s, data_len=%d, data=%s\n",
			     get_value_string(gprs_llc_xid_type_names,
					      xid_field->type),
			     xid_field->data_len,
			     osmo_hexdump_nospc(xid_field->data,
						xid_field->data_len));
		} else {
			LOGP(DLLC, logl,
			     "XID: type=%d, data_len=%d, data=NULL\n",
			     xid_field->type, xid_field->data_len);
		}
	}
}
