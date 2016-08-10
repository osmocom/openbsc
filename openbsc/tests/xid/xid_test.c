/* Test LLC-XID Encoding/Decoding */

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

#include <openbsc/gprs_llc_xid.h>
#include <openbsc/debug.h>

#include <osmocom/core/talloc.h>
#include <osmocom/core/utils.h>

#include <osmocom/core/application.h>

#include <stdio.h>
#include <string.h>

/* Test XID encoding */
static void test_xid_encode(const void *ctx)
{
	struct gprs_llc_xid_field xid_field_1;
	struct gprs_llc_xid_field xid_field_2;
	struct gprs_llc_xid_field xid_field_3;
	struct gprs_llc_xid_field xid_field_4;
	LLIST_HEAD(xid_fields);
	uint8_t xid[255];
	uint8_t xid_expected[] =
	    { 0x10, 0x8c, 0x14, 0x43, 0x43, 0x43, 0x43, 0x43, 0x0b, 0x42, 0x42,
	0x42, 0x05, 0x41 };
	int rc;

	printf("Testing LLC XID-Encoder\n");

	/* Setup some simple XID data */
	xid_field_1.type = 1;
	xid_field_2.type = 2;
	xid_field_3.type = 3;
	xid_field_4.type = 4;

	xid_field_1.data = (uint8_t *) "A";
	xid_field_2.data = (uint8_t *) "BBB";
	xid_field_3.data = (uint8_t *) "CCCCC";
	xid_field_4.data = NULL;

	xid_field_1.data_len = 1;
	xid_field_2.data_len = 3;
	xid_field_3.data_len = 5;
	xid_field_4.data_len = 0;

	llist_add(&xid_field_4.list, &xid_fields);
	llist_add(&xid_field_3.list, &xid_fields);
	llist_add(&xid_field_2.list, &xid_fields);
	llist_add(&xid_field_1.list, &xid_fields);

	printf("Data to encode:\n");
	gprs_llc_dump_xid_fields(&xid_fields, DSNDCP);

	/* Encode data */
	rc = gprs_llc_compile_xid(xid, sizeof(xid), &xid_fields);
	OSMO_ASSERT(rc == 14);
	printf("Encoded:  %s (%i bytes)\n", osmo_hexdump_nospc(xid, rc), rc);
	printf("Expected: %s (%i bytes)\n",
	       osmo_hexdump_nospc(xid_expected, sizeof(xid_expected)),
	       (int)sizeof(xid_expected));

	OSMO_ASSERT(memcmp(xid_expected, xid, sizeof(xid_expected)) == 0);

	printf("\n");
}

/* Test XID decoding */
static void test_xid_decode(const void *ctx)
{
	struct llist_head *xid_fields;
	int rc;

	printf("Testing LLC XID-Decoder/Encoder\n");

	/* Example of a real world LLC-XID message */
	uint8_t xid[] =
	    { 0x01, 0x00, 0x16, 0x05, 0xf0, 0x1a, 0x05, 0xf0, 0xac, 0xd8, 0x00,
	0x01, 0x00, 0x02, 0x31, 0x82, 0x02, 0x27, 0x89, 0xff, 0xe0, 0x00, 0x0f,
	0x00, 0xa8, 0x00, 0x00, 0x00, 0x01, 0x01, 0x01, 0x00, 0x02, 0x01, 0x02,
	0x00, 0x03, 0x01, 0x03, 0x00, 0x04, 0x01, 0x04, 0x00, 0x05, 0x01, 0x05,
	0x00, 0x06, 0x00, 0x07, 0x01, 0x07, 0x00, 0x08, 0x01, 0x08, 0x80, 0x00,
	0x04, 0x12, 0x00, 0x40, 0x07 };

	uint8_t xid_r[512];

	/* Decode and display XID fields */
	xid_fields = gprs_llc_parse_xid(ctx, xid, sizeof(xid));
	OSMO_ASSERT(xid_fields);

	printf("Decoded:\n");
	gprs_llc_dump_xid_fields(xid_fields, DSNDCP);


	/* Encode xid-fields again */
	rc = gprs_llc_compile_xid(xid_r, sizeof(xid_r), xid_fields);
	printf("Result length=%i\n",rc);
	printf("Encoded:  %s\n", osmo_hexdump_nospc(xid, sizeof(xid)));
	printf("Rencoded: %s\n", osmo_hexdump_nospc(xid_r, rc));

	OSMO_ASSERT(rc == 64);
	OSMO_ASSERT(memcmp(xid, xid_r, sizeof(xid)) == 0);

	/* Free xid fields */
	talloc_free(xid_fields);

	printf("\n");
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

	test_xid_decode(xid_ctx);
	test_xid_encode(xid_ctx);
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
