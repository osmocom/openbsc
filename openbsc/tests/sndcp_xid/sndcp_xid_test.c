/* Test SNDCP-XID Encoding/Decoding */

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

#include <openbsc/gprs_sndcp_xid.h>
#include <openbsc/debug.h>

#include <osmocom/core/talloc.h>
#include <osmocom/core/utils.h>

#include <osmocom/core/application.h>

#include <stdio.h>
#include <string.h>

/* Test SNDCP-XID decoding with a real world sample */
static void test_xid_decode_realworld(const void *ctx)
{
	struct llist_head *comp_fields;
	int rc;
	printf("Testing SNDCP XID-Decoder/Encoder (real world data)\n");

	/* Example of a real world SNDCP-XID message */
	uint8_t xid[] =
	    { 0x00, 0x01, 0x00, 0x02, 0x31, 0x82, 0x02, 0x27, 0x89, 0xff, 0xe0,
	0x00, 0x0f, 0x00, 0xa8, 0x00, 0x00, 0x00, 0x01, 0x01, 0x01, 0x00, 0x02,
	0x01, 0x02, 0x00, 0x03, 0x01, 0x03, 0x00, 0x04, 0x01, 0x04, 0x00, 0x05,
	0x01, 0x05, 0x00, 0x06, 0x00, 0x07, 0x01, 0x07, 0x00, 0x08, 0x01, 0x08,
	0x80, 0x00, 0x04, 0x12, 0x00, 0x40, 0x07 };
	uint8_t xid_r[512];

	/* Parse and show contained comp fields */
	comp_fields = gprs_sndcp_parse_xid(NULL, ctx, xid, sizeof(xid), NULL);
	OSMO_ASSERT(comp_fields);
	printf("Decoded:\n");
	gprs_sndcp_dump_comp_fields(comp_fields, DSNDCP);

	/* Encode comp-fields again */
	rc = gprs_sndcp_compile_xid(xid_r,sizeof(xid_r), comp_fields,
				    DEFAULT_SNDCP_VERSION);
	printf("Result length=%i\n",rc);
	printf("Encoded:  %s\n", osmo_hexdump_nospc(xid, sizeof(xid)));
	printf("Rencoded: %s\n", osmo_hexdump_nospc(xid_r, rc));

	OSMO_ASSERT(rc == 54);
	OSMO_ASSERT(memcmp(xid, xid_r, sizeof(xid)) == 0);

	/* Free comp fields */
	talloc_free(comp_fields);

	printf("\n");
}

/* Encode and decode test with artificial test data */
static void test_xid_encode_decode(const void *ctx)
{
	printf("Testing SNDCP XID-Encoder/Decoder\n");

	LLIST_HEAD(comp_fields);
	struct gprs_sndcp_pcomp_rfc1144_params rfc1144_params;
	struct gprs_sndcp_comp_field rfc1144_comp_field;
	struct gprs_sndcp_pcomp_rfc2507_params rfc2507_params;
	struct gprs_sndcp_comp_field rfc2507_comp_field;
	struct gprs_sndcp_pcomp_rohc_params rohc_params;
	struct gprs_sndcp_comp_field rohc_comp_field;
	struct gprs_sndcp_dcomp_v42bis_params v42bis_params;
	struct gprs_sndcp_comp_field v42bis_comp_field;
	struct gprs_sndcp_dcomp_v44_params v44_params;
	struct gprs_sndcp_comp_field v44_comp_field;
	struct llist_head *comp_fields_dec;

	uint8_t xid[512];
	unsigned int xid_len = sizeof(xid);
	int rc;

	memset(&rfc1144_comp_field, 0, sizeof(struct gprs_sndcp_comp_field));
	memset(&rfc2507_comp_field, 0, sizeof(struct gprs_sndcp_comp_field));
	memset(&rohc_comp_field, 0, sizeof(struct gprs_sndcp_comp_field));
	memset(&v42bis_comp_field, 0, sizeof(struct gprs_sndcp_comp_field));
	memset(&v44_comp_field, 0, sizeof(struct gprs_sndcp_comp_field));

	/* Setup which NSAPIs shall make use of rfc1144 */
	rfc1144_params.nsapi[0] = 5;
	rfc1144_params.nsapi_len = 1;

	/* Setup rfc1144 operating parameters */
	rfc1144_params.s01 = 7;

	/* Setup rfc1144 compression field */
	rfc1144_comp_field.p = 1;
	rfc1144_comp_field.entity = 0;
	rfc1144_comp_field.algo = RFC_1144;
	rfc1144_comp_field.comp[RFC1144_PCOMP1] = 1;
	rfc1144_comp_field.comp[RFC1144_PCOMP2] = 2;
	rfc1144_comp_field.comp_len = RFC1144_PCOMP_NUM;
	rfc1144_comp_field.rfc1144_params = &rfc1144_params;

	/* Setup which NSAPIs shall make use of rfc1144 */
	rfc2507_params.nsapi[0] = 6;
	rfc2507_params.nsapi_len = 1;

	/* Setup rfc2507 operating parameters */
	rfc2507_params.f_max_period = 256;
	rfc2507_params.f_max_time = 5;
	rfc2507_params.max_header = 168;
	rfc2507_params.tcp_space = 15;
	rfc2507_params.non_tcp_space = 15;

	/* Setup rfc2507 compression field */
	rfc2507_comp_field.p = 1;
	rfc2507_comp_field.entity = 1;
	rfc2507_comp_field.algo = RFC_2507;
	rfc2507_comp_field.comp[RFC2507_PCOMP1] = 3;
	rfc2507_comp_field.comp[RFC2507_PCOMP2] = 4;
	rfc2507_comp_field.comp[RFC2507_PCOMP3] = 5;
	rfc2507_comp_field.comp[RFC2507_PCOMP4] = 6;
	rfc2507_comp_field.comp[RFC2507_PCOMP5] = 7;
	rfc2507_comp_field.comp_len = RFC2507_PCOMP_NUM;
	rfc2507_comp_field.rfc2507_params = &rfc2507_params;

	/* Setup which NSAPIs shall make use of ROHC */
	rohc_params.nsapi[0] = 5;
	rohc_params.nsapi[1] = 6;
	rohc_params.nsapi[2] = 7;
	rohc_params.nsapi[3] = 8;
	rohc_params.nsapi[4] = 9;
	rohc_params.nsapi[5] = 10;
	rohc_params.nsapi[6] = 11;
	rohc_params.nsapi[7] = 12;
	rohc_params.nsapi[8] = 13;
	rohc_params.nsapi[9] = 14;
	rohc_params.nsapi[10] = 15;
	rohc_params.nsapi_len = 11;

	/* Setup ROHC operating parameters */
	rohc_params.max_cid = 15;	/* default */
	rohc_params.max_header = 168;	/* default */
	rohc_params.profile[0] = ROHC_UNCOMPRESSED;
	rohc_params.profile[1] = ROHC_RTP;
	rohc_params.profile[2] = ROHCV2_RTP;
	rohc_params.profile[3] = ROHC_UDP;
	rohc_params.profile[4] = ROHCv2_UDP;
	rohc_params.profile[5] = ROHC_ESP;
	rohc_params.profile[6] = ROHCV2_ESP;
	rohc_params.profile[7] = ROHC_IP;
	rohc_params.profile[8] = ROHCV2_IP;
	rohc_params.profile[9] = ROHC_LLA;
	rohc_params.profile[10] = ROHC_LLA_WITH_R_MODE;
	rohc_params.profile[11] = ROHC_TCP;
	rohc_params.profile[12] = ROHC_RTP_UDP_LITE;
	rohc_params.profile[13] = ROHCV2_RTP_UDP_LITE;
	rohc_params.profile[14] = ROHC_UDP_LITE;
	rohc_params.profile[15] = ROHCV2_UDP_LITE;
	rohc_params.profile_len = 16;

	/* Setup ROHC compression field */
	rohc_comp_field.p = 1;
	rohc_comp_field.entity = 2;
	rohc_comp_field.algo = ROHC;
	rohc_comp_field.comp[ROHC_PCOMP1] = 8;
	rohc_comp_field.comp[ROHC_PCOMP2] = 9;
	rohc_comp_field.comp_len = ROHC_PCOMP_NUM;
	rohc_comp_field.rohc_params = &rohc_params;

	/* Setup which NSAPIs shall make use of v42bis */
	v42bis_params.nsapi[0] = 5;
	v42bis_params.nsapi_len = 1;

	/* Setup v42bis operating parameters */
	v42bis_params.p0 = 3;
	v42bis_params.p1 = 2048;
	v42bis_params.p2 = 20;

	/* Setup v42bis compression field */
	v42bis_comp_field.p = 1;
	v42bis_comp_field.entity = 3;
	v42bis_comp_field.algo = V42BIS;
	v42bis_comp_field.comp[V42BIS_DCOMP1] = 10;
	v42bis_comp_field.comp_len = V42BIS_DCOMP_NUM;
	v42bis_comp_field.v42bis_params = &v42bis_params;

	/* Setup which NSAPIs shall make use of v44 */
	v44_params.nsapi[0] = 5;
	v44_params.nsapi_len = 1;

	/* Setup v44 operating parameters */
	v44_params.c0 = 0x80;
	v44_params.p0 = 3;
	v44_params.p1t = 300;
	v44_params.p1r = 300;
	v44_params.p3t = 600;
	v44_params.p3r = 600;

	/* Setup v44 compression field */
	v44_comp_field.p = 1;
	v44_comp_field.entity = 3;
	v44_comp_field.algo = V44;
	v44_comp_field.comp[V44_DCOMP1] = 10;
	v44_comp_field.comp[V44_DCOMP2] = 11;
	v44_comp_field.comp_len = V44_DCOMP_NUM;
	v44_comp_field.v44_params = &v44_params;

	/* Add compression field(s) to list */
	llist_add(&v44_comp_field.list, &comp_fields);
	llist_add(&v42bis_comp_field.list, &comp_fields);
	llist_add(&rfc1144_comp_field.list, &comp_fields);
	llist_add(&rfc2507_comp_field.list, &comp_fields);
	llist_add(&rohc_comp_field.list, &comp_fields);
	printf("Test input data:\n");
	gprs_sndcp_dump_comp_fields(&comp_fields, DSNDCP);

	/* Encode SNDCP-XID fields */
	rc = gprs_sndcp_compile_xid(xid, xid_len, &comp_fields,
				    DEFAULT_SNDCP_VERSION);
	OSMO_ASSERT(rc > 0);

	printf("Encoded:  %s (%i bytes)\n", osmo_hexdump_nospc(xid, rc), rc);

	/* Parse and show contained comp fields */
	comp_fields_dec = gprs_sndcp_parse_xid(NULL, ctx, xid, rc, NULL);
	OSMO_ASSERT(comp_fields_dec);

	printf("Decoded:\n");
	gprs_sndcp_dump_comp_fields(comp_fields_dec, DSNDCP);

	/* Free comp fields */
	talloc_free(comp_fields_dec);
}

static struct log_info_cat gprs_categories[] = {
	[DSNDCP] = {
		    .name = "DSNDCP",
		    .description =
		    "GPRS Sub-Network Dependent Control Protocol (SNDCP)",
		    .enabled = 1,.loglevel = LOGL_DEBUG,
		    }
};

static struct log_info info = {
	.cat = gprs_categories,
	.num_cat = ARRAY_SIZE(gprs_categories),
};

int main(int argc, char **argv)
{
	void *xid_ctx;

	osmo_init_logging(&info);

	xid_ctx = talloc_named_const(NULL, 0, "xid_ctx");

	test_xid_decode_realworld(xid_ctx);
	test_xid_encode_decode(xid_ctx);

	printf("Done\n");

	talloc_report_full(xid_ctx, stderr);
	OSMO_ASSERT(talloc_total_blocks(xid_ctx) == 1);
	return 0;
}

/* stubs */
struct osmo_prim_hdr;
int bssgp_prim_cb(struct osmo_prim_hdr *oph, void *ctx)
{
        abort();
}
