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

#pragma once

#include <stdint.h>
#include <osmocom/core/linuxlist.h>

#define DEFAULT_SNDCP_VERSION 0	/* See 3GPP TS 44.065, clause 8 */
#define MAX_ENTITIES 32		/* 3GPP TS 44.065 reserves 5 bit
				 * for compression enitity number */

#define MAX_COMP 16	/* Maximum number of possible pcomp/dcomp values */
#define MAX_NSAPI 11	/* Maximum number usable NSAPIs */
#define MAX_ROHC 16	/* Maximum number of ROHC compression profiles */

/* According to: 3GPP TS 44.065, 6.5.1.1 Format of the protocol control
 * information compression field (Figure 7) and 3GPP TS 44.065, 
 * 6.6.1.1 Format of the data compression field (Figure 9) */
struct gprs_sndcp_comp_field {
	struct llist_head list;

	/* Propose bit (P), see also: 6.5.1.1.2 and 6.6.1.1.2 */
	unsigned int p;

	/* Entity number, see also: 6.5.1.1.3 and 6.6.1.1.3 */
	unsigned int entity;

	/* Algorithm identifier, see also: 6.5.1.1.4 and 6.6.1.1.4 */
	int algo;

	/* Number of contained PCOMP / DCOMP values */
	uint8_t comp_len;

	/* PCOMP / DCOMP values, see also: 6.5.1.1.5 and 6.6.1.1.5 */
	uint8_t comp[MAX_COMP];

	/* Note: Only one of the following struct pointers may,
	   be used. Unused pointers must be set to NULL! */
	struct gprs_sndcp_pcomp_rfc1144_params *rfc1144_params;
	struct gprs_sndcp_pcomp_rfc2507_params *rfc2507_params;
	struct gprs_sndcp_pcomp_rohc_params *rohc_params;
	struct gprs_sndcp_dcomp_v42bis_params *v42bis_params;
	struct gprs_sndcp_dcomp_v44_params *v44_params;
};

/* According to: 3GPP TS 44.065, 6.5.1.1.4 Algorithm identifier */
enum gprs_sndcp_hdr_comp_algo {
	RFC_1144,		/* TCP/IP header compression, see also 6.5.2 */
	RFC_2507,		/* TCP/UDP/IP header compression, see also: 6.5.3 */
	ROHC			/* Robust Header Compression, see also 6.5.4 */
};

/* According to: 3GPP TS 44.065, 6.5.1.1.4 Algorithm identifier */
enum gprs_sndcp_data_comp_algo {
	V42BIS,			/* V.42bis data compression, see also 6.6.2 */
	V44			/* V44 data compression, see also: 6.6.3 */
};

/* According to: 3GPP TS 44.065, 8 SNDCP XID parameters */
enum gprs_sndcp_xid_param_types {
	SNDCP_XID_VERSION_NUMBER,
	SNDCP_XID_DATA_COMPRESSION,	/* See also: subclause 6.6.1 */
	SNDCP_XID_PROTOCOL_COMPRESSION,	/* See also: subclause 6.5.1 */
};

/* According to: 3GPP TS 44.065, 6.5.2.1 Parameters (Table 5) */
struct gprs_sndcp_pcomp_rfc1144_params {
	uint8_t nsapi_len;		/* Number of applicable NSAPIs
					 * (default 0) */
	uint8_t nsapi[MAX_NSAPI];	/* Applicable NSAPIs (default 0) */
	int s01;			/* (default 15) */
};

/* According to: 3GPP TS 44.065, 6.5.2.2 Assignment of PCOMP values */
enum gprs_sndcp_pcomp_rfc1144_pcomp {
	RFC1144_PCOMP1,			/* Uncompressed TCP */
	RFC1144_PCOMP2,			/* Compressed TCP */
	RFC1144_PCOMP_NUM		/* Number of pcomp values */
};

/* According to: 3GPP TS 44.065, 6.5.3.1 Parameters (Table 6) */
struct gprs_sndcp_pcomp_rfc2507_params {
	uint8_t nsapi_len;		/* Number of applicable NSAPIs
					 * (default 0) */
	uint8_t nsapi[MAX_NSAPI];	/* Applicable NSAPIs (default 0) */
	int f_max_period;		/* (default 256) */
	int f_max_time;			/* (default 5) */
	int max_header;			/* (default 168) */
	int tcp_space;			/* (default 15) */
	int non_tcp_space;		/* (default 15) */
};

/* According to: 3GPP TS 44.065, 6.5.3.2 Assignment of PCOMP values for RFC2507 */
enum gprs_sndcp_pcomp_rfc2507_pcomp {
	RFC2507_PCOMP1,			/* Full Header */
	RFC2507_PCOMP2,			/* Compressed TCP */
	RFC2507_PCOMP3,			/* Compressed TCP non delta */
	RFC2507_PCOMP4,			/* Compressed non TCP */
	RFC2507_PCOMP5,			/* Context state */
	RFC2507_PCOMP_NUM		/* Number of pcomp values */
};

/* According to: 3GPP TS 44.065, 6.5.4.1 Parameter (Table 10) */
struct gprs_sndcp_pcomp_rohc_params {
	uint8_t nsapi_len;		/* Number of applicable NSAPIs
					 * (default 0) */
	uint8_t nsapi[MAX_NSAPI];	/* Applicable NSAPIs (default 0) */
	int max_cid;			/* (default 15) */
	int max_header;			/* (default 168) */
	uint8_t profile_len;		/* (default 1) */
	uint16_t profile[MAX_ROHC];	/* (default 0, ROHC uncompressed) */
};

/* According to: 3GPP TS 44.065, 6.5.4.2 Assignment of PCOMP values for ROHC */
enum gprs_sndcp_pcomp_rohc_pcomp {
	ROHC_PCOMP1,			/* ROHC small CIDs */
	ROHC_PCOMP2,			/* ROHC large CIDs */
	ROHC_PCOMP_NUM			/* Number of pcomp values */
};

/* ROHC compression profiles, see also:
   http://www.iana.org/assignments/rohc-pro-ids/rohc-pro-ids.xhtml */
enum gprs_sndcp_xid_rohc_profiles {
	ROHC_UNCOMPRESSED = 0x0000,	/* ROHC uncompressed    [RFC5795] */
	ROHC_RTP = 0x0001,		/* ROHC RTP             [RFC3095] */
	ROHCV2_RTP = 0x0101,		/* ROHCv2 RTP           [RFC5225] */
	ROHC_UDP = 0x0002,		/* ROHC UDP             [RFC3095] */
	ROHCv2_UDP = 0x0102,		/* ROHCv2 UDP           [RFC5225] */
	ROHC_ESP = 0x0003,		/* ROHC ESP             [RFC3095] */
	ROHCV2_ESP = 0x0103,		/* ROHCv2 ESP           [RFC5225] */
	ROHC_IP = 0x0004,		/* ROHC IP              [RFC3843] */
	ROHCV2_IP = 0x0104,		/* ROHCv2 IP            [RFC5225] */
	ROHC_LLA = 0x0005,		/* ROHC LLA             [RFC4362] */
	ROHC_LLA_WITH_R_MODE = 0x0105,	/* ROHC LLA with R-mode [RFC3408] */
	ROHC_TCP = 0x0006,		/* ROHC TCP             [RFC6846] */
	ROHC_RTP_UDP_LITE = 0x0007,	/* ROHC RTP/UDP-Lite    [RFC4019] */
	ROHCV2_RTP_UDP_LITE = 0x0107,	/* ROHCv2 RTP/UDP-Lite  [RFC5225] */
	ROHC_UDP_LITE = 0x0008,		/* ROHC UDP-Lite        [RFC4019] */
	ROHCV2_UDP_LITE = 0x0108,	/* ROHCv2 UDP-Lite      [RFC5225] */
};

/* According to: 3GPP TS 44.065, 6.6.2.1 Parameters (Table 7a) */
struct gprs_sndcp_dcomp_v42bis_params {
	uint8_t nsapi_len;		/* Number of applicable NSAPIs
					 * (default 0) */
	uint8_t nsapi[MAX_NSAPI];	/* Applicable NSAPIs (default 0) */
	int p0;				/* (default 3) */
	int p1;				/* (default 2048) */
	int p2;				/* (default 20) */

};

/* According to: 3GPP TS 44.065, 6.6.2.2 Assignment of DCOMP values */
enum gprs_sndcp_dcomp_v42bis_dcomp {
	V42BIS_DCOMP1,			/* V.42bis enabled */
	V42BIS_DCOMP_NUM		/* Number of dcomp values */
};

/* According to: 3GPP TS 44.065, 6.6.3.1 Parameters (Table 7c) */
struct gprs_sndcp_dcomp_v44_params {
	uint8_t nsapi_len;		/* Number of applicable NSAPIs
					 * (default 0) */
	uint8_t nsapi[MAX_NSAPI];	/* Applicable NSAPIs (default 0) */
	int c0;				/* (default 10000000) */
	int p0;				/* (default 3) */
	int p1t;			/* Refer to subclause 6.6.3.1.4 */
	int p1r;			/* Refer to subclause 6.6.3.1.5 */
	int p3t;			/* (default 3 x p1t) */
	int p3r;			/* (default 3 x p1r) */
};

/* According to: 3GPP TS 44.065, 6.6.3.2 Assignment of DCOMP values */
enum gprs_sndcp_dcomp_v44_dcomp {
	V44_DCOMP1,			/* Packet method compressed */
	V44_DCOMP2,			/* Multi packet method compressed */
	V44_DCOMP_NUM			/* Number of dcomp values */
};

/* Transform a list with compression fields into an SNDCP-XID message (dst) */
int gprs_sndcp_compile_xid(uint8_t *dst, unsigned int dst_maxlen,
			   const struct llist_head *comp_fields, int version);

/* Transform an SNDCP-XID message (src) into a list of SNDCP-XID fields */
struct llist_head *gprs_sndcp_parse_xid(int *version,
					const void *ctx,
					const uint8_t *src,
					unsigned int src_len,
					const struct llist_head
					*comp_fields_req);

/* Find out to which compression class the specified comp-field belongs
 * (header compression or data compression?) */
int gprs_sndcp_get_compression_class(
				const struct gprs_sndcp_comp_field *comp_field);

/* Dump a list with SNDCP-XID fields (Debug) */
void gprs_sndcp_dump_comp_fields(const struct llist_head *comp_fields,
				 unsigned int logl);

