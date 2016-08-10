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

#pragma once

#include <stdint.h>
#include <osmocom/core/linuxlist.h>

/* 3GPP TS 44.064 6.4.1.6 Exchange Identification (XID)
   command/response parameter field */
struct gprs_llc_xid_field {
	struct llist_head list;
	uint8_t type;		/* See also Table 6: LLC layer parameter
				   negotiation */
	uint8_t *data;		/* Payload data (memory is owned by the
				 * creator of the struct) */
	unsigned int data_len;	/* Payload length */
};

/* Transform a list with XID fields into a XID message (dst) */
int gprs_llc_compile_xid(uint8_t *dst, int dst_maxlen,
			 const struct llist_head *xid_fields);

/* Transform a XID message (dst) into a list of XID fields */
struct llist_head *gprs_llc_parse_xid(const void *ctx, const uint8_t *src,
				      int src_len);

/* Create a duplicate of an XID-Field */
struct gprs_llc_xid_field *gprs_llc_dup_xid_field(const void *ctx,
				const struct gprs_llc_xid_field *xid_field);

/* Copy an llist with xid fields */
struct llist_head *gprs_llc_copy_xid(const void *ctx,
				     const struct llist_head *xid_fields);

/* Dump a list with XID fields (Debug) */
void gprs_llc_dump_xid_fields(const struct llist_head *xid_fields,
			      unsigned int logl);

