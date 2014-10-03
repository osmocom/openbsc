/* Test the SGSN */
/*
 * (C) 2014 by Holger Hans Peter Freyther
 * (C) 2014 by sysmocom s.f.m.c. GmbH
 * All Rights Reserved
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

#include <openbsc/gprs_llc.h>
#include <openbsc/sgsn.h>
#include <openbsc/gprs_gmm.h>
#include <openbsc/debug.h>

#include <osmocom/gsm/gsm_utils.h>

#include <osmocom/core/application.h>
#include <osmocom/core/msgb.h>

#include <stdio.h>

extern void *tall_msgb_ctx;

void *tall_bsc_ctx;
static struct sgsn_instance sgsn_inst = {
	.config_file = "osmo_sgsn.cfg",
	.cfg = {
		.gtp_statedir = "./",
		.acl_enabled = 1,
	},
};
struct sgsn_instance *sgsn = &sgsn_inst;

static int count(struct llist_head *head)
{
	struct llist_head *cur;
	int count = 0;

	llist_for_each(cur, head)
		count += 1;

	return count;		
}

static struct msgb *create_msg(const uint8_t *data, size_t len)
{
	struct msgb *msg = msgb_alloc(len + 8, "test message");
	msg->l1h = msgb_put(msg, 8);
	msg->l2h = msgb_put(msg, len);
	memcpy(msg->l2h, data, len);

	msgb_bcid(msg) = msg->l1h;
	msgb_gmmh(msg) = msg->l2h;
	return msg;
}

static void test_llme(void)
{
	struct gprs_llc_lle *lle, *lle_copy;
	uint32_t local_tlli;
	uint32_t foreign_tlli;

	printf("Testing LLME allocations\n");
	local_tlli = gprs_tmsi2tlli(0x234, TLLI_LOCAL);
	foreign_tlli = gprs_tmsi2tlli(0x234, TLLI_FOREIGN);

	/* initial state */
	OSMO_ASSERT(count(gprs_llme_list()) == 0);

	/* Create a new entry */
	lle = gprs_lle_get_or_create(local_tlli, 3);
	OSMO_ASSERT(lle);
	OSMO_ASSERT(count(gprs_llme_list()) == 1);

	/* No new entry is created */
	lle_copy = gprs_lle_get_or_create(local_tlli, 3);
	OSMO_ASSERT(lle == lle_copy);
	OSMO_ASSERT(count(gprs_llme_list()) == 1);
	lle_copy = gprs_lle_get_or_create(foreign_tlli, 3);
	OSMO_ASSERT(lle == lle_copy);
	OSMO_ASSERT(count(gprs_llme_list()) == 1);

	/* unassign which should delete it*/
	gprs_llgmm_assign(lle->llme, lle->llme->tlli, 0xffffffff, GPRS_ALGO_GEA0, NULL);

	/* Check that everything was cleaned up */
	OSMO_ASSERT(count(gprs_llme_list()) == 0);
}

/*
 * Test that a GMM Detach will remove the MMCTX and the
 * associated LLME.
 */
static void test_gmm_detach(void)
{
	struct gprs_ra_id raid = { 0, };
	struct sgsn_mm_ctx *ctx, *ictx;
	struct gprs_llc_lle *lle;
	uint32_t local_tlli;
	struct msgb *msg;

	printf("Testing GMM detach\n");

	/* DTAP - Detach Request (MO) */
	/* normal detach, power_off = 0 */
	static const unsigned char detach_req[] = {
		0x08, 0x05, 0x01, 0x18, 0x05, 0xf4, 0xef, 0xe2,
		0xb7, 0x00, 0x19, 0x03, 0xb9, 0x97, 0xcb
	};

	/* Create a conext and search for it */
	OSMO_ASSERT(count(gprs_llme_list()) == 0);
	local_tlli = gprs_tmsi2tlli(0x23, TLLI_LOCAL);
	lle = gprs_lle_get_or_create(local_tlli, 3);
	ctx = sgsn_mm_ctx_alloc(local_tlli, &raid);
	ctx->mm_state = GMM_REGISTERED_NORMAL;
	ctx->llme = lle->llme;

	ictx = sgsn_mm_ctx_by_tlli(local_tlli, &raid);
	OSMO_ASSERT(ictx == ctx);
	OSMO_ASSERT(count(gprs_llme_list()) == 1);

	/* inject the detach */
	msg = create_msg(detach_req, ARRAY_SIZE(detach_req));
	msgb_tlli(msg) = local_tlli;
	gsm0408_gprs_rcvmsg(msg, ctx->llme);
	msgb_free(msg);

	/* verify that things are gone */
	OSMO_ASSERT(count(gprs_llme_list()) == 0);
	ictx = sgsn_mm_ctx_by_tlli(local_tlli, &raid);
	OSMO_ASSERT(!ictx);

	/* and inject it again, e.g. the response was lost */
	lle = gprs_lle_get_or_create(local_tlli, 3);
	msg = create_msg(detach_req, ARRAY_SIZE(detach_req));
	msgb_tlli(msg) = local_tlli;
	gsm0408_gprs_rcvmsg(msg, lle->llme);
	msgb_free(msg);

	/* No context */
	ictx = sgsn_mm_ctx_by_tlli(local_tlli, &raid);
	OSMO_ASSERT(!ictx);

	/* TODO: Expected failure on re-transmission */
	OSMO_ASSERT(count(gprs_llme_list()) == 1);
	/* TODO: check the output we get */
}

static struct log_info_cat gprs_categories[] = {
	[DMM] = {
		.name = "DMM",
		.description = "Layer3 Mobility Management (MM)",
		.color = "\033[1;33m",
		.enabled = 1, .loglevel = LOGL_NOTICE,
	},
	[DPAG]	= {
		.name = "DPAG",
		.description = "Paging Subsystem",
		.color = "\033[1;38m",
		.enabled = 1, .loglevel = LOGL_NOTICE,
	},
	[DMEAS] = {
		.name = "DMEAS",
		.description = "Radio Measurement Processing",
		.enabled = 0, .loglevel = LOGL_NOTICE,
	},
	[DREF] = {
		.name = "DREF",
		.description = "Reference Counting",
		.enabled = 0, .loglevel = LOGL_NOTICE,
	},
	[DGPRS] = {
		.name = "DGPRS",
		.description = "GPRS Packet Service",
		.enabled = 1, .loglevel = LOGL_DEBUG,
	},
	[DNS] = {
		.name = "DNS",
		.description = "GPRS Network Service (NS)",
		.enabled = 1, .loglevel = LOGL_INFO,
	},
	[DBSSGP] = {
		.name = "DBSSGP",
		.description = "GPRS BSS Gateway Protocol (BSSGP)",
		.enabled = 1, .loglevel = LOGL_DEBUG,
	},
	[DLLC] = {
		.name = "DLLC",
		.description = "GPRS Logical Link Control Protocol (LLC)",
		.enabled = 1, .loglevel = LOGL_DEBUG,
	},
	[DSNDCP] = {
		.name = "DSNDCP",
		.description = "GPRS Sub-Network Dependent Control Protocol (SNDCP)",
		.enabled = 1, .loglevel = LOGL_DEBUG,
	},
};

static struct log_info info = {
	.cat = gprs_categories,
	.num_cat = ARRAY_SIZE(gprs_categories),
};

int main(int argc, char **argv)
{
	osmo_init_logging(&info);
	tall_bsc_ctx = talloc_named_const(NULL, 0, "osmo_sgsn");
	tall_msgb_ctx = talloc_named_const(tall_bsc_ctx, 0, "msgb");

	test_llme();
	test_gmm_detach();
	printf("Done\n");
	return 0;
}


/* stubs */
struct osmo_prim_hdr;
int bssgp_prim_cb(struct osmo_prim_hdr *oph, void *ctx)
{
	abort();
}
