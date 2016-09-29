/* Test OML attribute generator */

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
#include <openbsc/gsm_data.h>
#include <openbsc/bts_ipaccess_nanobts_omlattr.h>

#include <osmocom/core/talloc.h>
#include <osmocom/core/utils.h>
#include <osmocom/core/application.h>

#include <stdio.h>
#include <string.h>

struct gsm_bts_model bts_model_nanobts = {
	.type = GSM_BTS_TYPE_NANOBTS,
	.name = "nanobts",
	.start = NULL,
	.oml_rcvmsg = NULL,
	.e1line_bind_ops = NULL,
	.nm_att_tlvdef = {
			  .def = {
				  /* ip.access specifics */
				  [NM_ATT_IPACC_DST_IP] = {TLV_TYPE_FIXED, 4},
				  [NM_ATT_IPACC_DST_IP_PORT] =
				  {TLV_TYPE_FIXED, 2},
				  [NM_ATT_IPACC_STREAM_ID] = {TLV_TYPE_TV,},
				  [NM_ATT_IPACC_SEC_OML_CFG] =
				  {TLV_TYPE_FIXED, 6},
				  [NM_ATT_IPACC_IP_IF_CFG] =
				  {TLV_TYPE_FIXED, 8},
				  [NM_ATT_IPACC_IP_GW_CFG] =
				  {TLV_TYPE_FIXED, 12},
				  [NM_ATT_IPACC_IN_SERV_TIME] =
				  {TLV_TYPE_FIXED, 4},
				  [NM_ATT_IPACC_LOCATION] = {TLV_TYPE_TL16V},
				  [NM_ATT_IPACC_PAGING_CFG] =
				  {TLV_TYPE_FIXED, 2},
				  [NM_ATT_IPACC_UNIT_ID] = {TLV_TYPE_TL16V},
				  [NM_ATT_IPACC_UNIT_NAME] = {TLV_TYPE_TL16V},
				  [NM_ATT_IPACC_SNMP_CFG] = {TLV_TYPE_TL16V},
				  [NM_ATT_IPACC_PRIM_OML_CFG_LIST] =
				  {TLV_TYPE_TL16V},
				  [NM_ATT_IPACC_NV_FLAGS] = {TLV_TYPE_TL16V},
				  [NM_ATT_IPACC_FREQ_CTRL] =
				  {TLV_TYPE_FIXED, 2},
				  [NM_ATT_IPACC_PRIM_OML_FB_TOUT] =
				  {TLV_TYPE_TL16V},
				  [NM_ATT_IPACC_CUR_SW_CFG] = {TLV_TYPE_TL16V},
				  [NM_ATT_IPACC_TIMING_BUS] = {TLV_TYPE_TL16V},
				  [NM_ATT_IPACC_CGI] = {TLV_TYPE_TL16V},
				  [NM_ATT_IPACC_RAC] = {TLV_TYPE_TL16V},
				  [NM_ATT_IPACC_OBJ_VERSION] = {TLV_TYPE_TL16V},
				  [NM_ATT_IPACC_GPRS_PAGING_CFG] =
				  {TLV_TYPE_TL16V},
				  [NM_ATT_IPACC_NSEI] = {TLV_TYPE_TL16V},
				  [NM_ATT_IPACC_BVCI] = {TLV_TYPE_TL16V},
				  [NM_ATT_IPACC_NSVCI] = {TLV_TYPE_TL16V},
				  [NM_ATT_IPACC_NS_CFG] = {TLV_TYPE_TL16V},
				  [NM_ATT_IPACC_BSSGP_CFG] = {TLV_TYPE_TL16V},
				  [NM_ATT_IPACC_NS_LINK_CFG] = {TLV_TYPE_TL16V},
				  [NM_ATT_IPACC_RLC_CFG] = {TLV_TYPE_TL16V},
				  [NM_ATT_IPACC_ALM_THRESH_LIST] =
				  {TLV_TYPE_TL16V},
				  [NM_ATT_IPACC_MONIT_VAL_LIST] =
				  {TLV_TYPE_TL16V},
				  [NM_ATT_IPACC_TIB_CONTROL] = {TLV_TYPE_TL16V},
				  [NM_ATT_IPACC_SUPP_FEATURES] =
				  {TLV_TYPE_TL16V},
				  [NM_ATT_IPACC_CODING_SCHEMES] =
				  {TLV_TYPE_TL16V},
				  [NM_ATT_IPACC_RLC_CFG_2] = {TLV_TYPE_TL16V},
				  [NM_ATT_IPACC_HEARTB_TOUT] = {TLV_TYPE_TL16V},
				  [NM_ATT_IPACC_UPTIME] = {TLV_TYPE_TL16V},
				  [NM_ATT_IPACC_RLC_CFG_3] = {TLV_TYPE_TL16V},
				  [NM_ATT_IPACC_SSL_CFG] = {TLV_TYPE_TL16V},
				  [NM_ATT_IPACC_SEC_POSSIBLE] =
				  {TLV_TYPE_TL16V},
				  [NM_ATT_IPACC_IML_SSL_STATE] =
				  {TLV_TYPE_TL16V},
				  [NM_ATT_IPACC_REVOC_DATE] = {TLV_TYPE_TL16V},
				  },
			  },
};

static void test_nanobts_attr_bts_get(struct gsm_bts *bts, uint8_t *expected)
{
	struct msgb *msgb;

	printf("Testing nanobts_attr_bts_get()...\n");

	msgb = nanobts_attr_bts_get(bts);
	printf("result=  %s\n", osmo_hexdump_nospc(msgb->data, msgb->len));
	printf("expected=%s\n", osmo_hexdump_nospc(expected, msgb->len));
	OSMO_ASSERT(memcmp(msgb->data, expected, msgb->len) == 0);
	msgb_free(msgb);

	printf("ok.\n");
	printf("\n");
}

static void test_nanobts_attr_nse_get(struct gsm_bts *bts, uint8_t *expected)
{
	struct msgb *msgb;

	printf("Testing nanobts_attr_nse_get()...\n");

	msgb = nanobts_attr_nse_get(bts);
	printf("result=  %s\n", osmo_hexdump_nospc(msgb->data, msgb->len));
	printf("expected=%s\n", osmo_hexdump_nospc(expected, msgb->len));
	OSMO_ASSERT(memcmp(msgb->data, expected, msgb->len) == 0);
	msgb_free(msgb);

	printf("ok.\n");
	printf("\n");
}

static void test_nanobts_attr_cell_get(struct gsm_bts *bts, uint8_t *expected)
{
	struct msgb *msgb;

	printf("Testing nanobts_attr_cell_get()...\n");

	msgb = nanobts_attr_cell_get(bts);
	printf("result=  %s\n", osmo_hexdump_nospc(msgb->data, msgb->len));
	printf("expected=%s\n", osmo_hexdump_nospc(expected, msgb->len));
	OSMO_ASSERT(memcmp(msgb->data, expected, msgb->len) == 0);
	msgb_free(msgb);

	printf("ok.\n");
	printf("\n");
}

static void test_nanobts_attr_nscv_get(struct gsm_bts *bts, uint8_t *expected)
{
	struct msgb *msgb;

	printf("Testing nanobts_attr_nscv_get()...\n");

	msgb = nanobts_attr_nscv_get(bts);
	printf("result=  %s\n", osmo_hexdump_nospc(msgb->data, msgb->len));
	printf("expected=%s\n", osmo_hexdump_nospc(expected, msgb->len));
	OSMO_ASSERT(memcmp(msgb->data, expected, msgb->len) == 0);
	msgb_free(msgb);

	printf("ok.\n");
	printf("\n");
}

static void test_nanobts_attr_radio_get(struct gsm_bts *bts,
					struct gsm_bts_trx *trx,
					uint8_t *expected)
{
	struct msgb *msgb;

	printf("Testing nanobts_attr_nscv_get()...\n");

	msgb = nanobts_attr_radio_get(bts, trx);
	printf("result=  %s\n", osmo_hexdump_nospc(msgb->data, msgb->len));
	printf("expected=%s\n", osmo_hexdump_nospc(expected, msgb->len));
	OSMO_ASSERT(memcmp(msgb->data, expected, msgb->len) == 0);
	msgb_free(msgb);

	printf("ok.\n");
	printf("\n");
}

int main(int argc, char **argv)
{
	void *ctx;

	struct gsm_bts *bts;
	struct gsm_network *net;
	struct gsm_bts_trx *trx;

	ctx = talloc_named_const(NULL, 0, "ctx");

	/* Allocate environmental structs (bts, net, trx) */
	net = talloc_zero(ctx, struct gsm_network);
	INIT_LLIST_HEAD(&net->bts_list);
	gsm_bts_model_register(&bts_model_nanobts);
	bts = gsm_bts_alloc_register(net, GSM_BTS_TYPE_NANOBTS, 63);
	OSMO_ASSERT(bts);
	trx = talloc_zero(ctx, struct gsm_bts_trx);

	/* Parameters needed by nanobts_attr_bts_get() */
	bts->rach_b_thresh = -1;
	bts->rach_ldavg_slots = -1;
	bts->c0->arfcn = 866;
	bts->cell_identity = 1337;
	bts->network->country_code = 1;
	bts->network->network_code = 1;
	bts->location_area_code = 1;
	bts->gprs.rac = 0;
	uint8_t attr_bts_expected[] =
	    { 0x19, 0x55, 0x5b, 0x61, 0x67, 0x6d, 0x73, 0x18, 0x06, 0x0e, 0x00,
		0x02, 0x01, 0x20, 0x33, 0x1e, 0x24, 0x24, 0xa8, 0x34, 0x21,
		0xa8, 0x1f, 0x3f, 0x25,
		0x00, 0x01, 0x0a, 0x0c, 0x0a, 0x0b, 0x01, 0x2a, 0x0a, 0x2b,
		0x03, 0xe8, 0x0a, 0x80,
		0x23, 0x0a, 0x08, 0x03, 0x62, 0x09, 0x3f, 0x99, 0x00, 0x07,
		0x00, 0xf1, 0x10, 0x00,
		0x01, 0x05, 0x39
	};

	/* Parameters needed to test nanobts_attr_nse_get() */
	bts->gprs.nse.nsei = 101;
	uint8_t attr_nse_expected[] =
	    { 0x9d, 0x00, 0x02, 0x00, 0x65, 0xa0, 0x00, 0x07, 0x03, 0x03, 0x03,
		0x03, 0x1e, 0x03, 0x0a, 0xa1, 0x00, 0x0b, 0x03, 0x03, 0x03,
		0x03, 0x03, 0x0a, 0x03,
		0x0a, 0x03, 0x0a, 0x03
	};

	/* Parameters needed to test nanobts_attr_cell_get() */
	bts->gprs.rac = 0x00;
	bts->gprs.cell.bvci = 2;
	bts->gprs.mode = BTS_GPRS_GPRS;
	uint8_t attr_cell_expected[] =
	    { 0x9a, 0x00, 0x01, 0x00, 0x9c, 0x00, 0x02, 0x05, 0x03, 0x9e, 0x00,
		0x02, 0x00, 0x02, 0xa3, 0x00, 0x09, 0x14, 0x05, 0x05, 0xa0,
		0x05, 0x0a, 0x04, 0x08,
		0x0f, 0xa8, 0x00, 0x02, 0x0f, 0x00, 0xa9, 0x00, 0x05, 0x00,
		0xfa, 0x00, 0xfa, 0x02
	};

	/* Parameters needed to test nanobts_attr_nscv_get() */
	bts->gprs.nsvc[0].nsvci = 0x65;
	bts->gprs.nsvc[0].remote_port = 0x59d8;
	bts->gprs.nsvc[0].remote_ip = 0x0a090165;
	bts->gprs.nsvc[0].local_port = 0x5a3c;
	uint8_t attr_nscv_expected[] =
	    { 0x9f, 0x00, 0x02, 0x00, 0x65, 0xa2, 0x00, 0x08, 0x59, 0xd8, 0x0a,
		0x09, 0x01, 0x65, 0x5a, 0x3c
	};

	/* Parameters needed to test nanobts_attr_radio_get() */
	trx->arfcn = 866;
	trx->max_power_red = 22;
	bts->c0->max_power_red = 22;
	uint8_t attr_radio_expected[] =
	    { 0x2d, 0x0b, 0x05, 0x00, 0x02, 0x03, 0x62 };

	/* Run tests */
	test_nanobts_attr_bts_get(bts, attr_bts_expected);
	test_nanobts_attr_nse_get(bts, attr_nse_expected);
	test_nanobts_attr_cell_get(bts, attr_cell_expected);
	test_nanobts_attr_nscv_get(bts, attr_nscv_expected);
	test_nanobts_attr_radio_get(bts, trx, attr_radio_expected);

	printf("Done\n");
	talloc_free(bts);
	talloc_free(net);
	talloc_free(trx);
	talloc_report_full(ctx, stderr);
	OSMO_ASSERT(talloc_total_blocks(ctx) == 1);
	return 0;
}

/* stubs */
struct osmo_prim_hdr;
int bssgp_prim_cb(struct osmo_prim_hdr *oph, void *ctx)
{
	abort();
}
