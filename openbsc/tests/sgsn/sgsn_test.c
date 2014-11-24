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

#include <osmocom/gprs/gprs_bssgp.h>

#include <osmocom/gsm/gsm_utils.h>

#include <osmocom/core/application.h>
#include <osmocom/core/msgb.h>
#include <osmocom/core/rate_ctr.h>

#include <stdio.h>

extern void *tall_msgb_ctx;

void *tall_bsc_ctx;
static struct sgsn_instance sgsn_inst = {
	.config_file = "osmo_sgsn.cfg",
	.cfg = {
		.gtp_statedir = "./",
		.auth_policy = SGSN_AUTH_POLICY_CLOSED,
	},
};
struct sgsn_instance *sgsn = &sgsn_inst;
unsigned sgsn_tx_counter = 0;

/* override */
int bssgp_tx_dl_ud(struct msgb *msg, uint16_t pdu_lifetime,
		   struct bssgp_dl_ud_par *dup)
{
	sgsn_tx_counter += 1;
	return 0;
}

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

/*
 * Create a context and search for it
 */
static struct sgsn_mm_ctx *alloc_mm_ctx(uint32_t tlli, struct gprs_ra_id *raid)
{
	struct sgsn_mm_ctx *ctx, *ictx;
	struct gprs_llc_lle *lle;
	int old_count = count(gprs_llme_list());

	lle = gprs_lle_get_or_create(tlli, 3);
	ctx = sgsn_mm_ctx_alloc(tlli, raid);
	ctx->mm_state = GMM_REGISTERED_NORMAL;
	ctx->llme = lle->llme;

	ictx = sgsn_mm_ctx_by_tlli(tlli, raid);
	OSMO_ASSERT(ictx == ctx);

	OSMO_ASSERT(count(gprs_llme_list()) == old_count + 1);

	return ctx;
}

static void send_0408_message(struct gprs_llc_llme *llme, uint32_t tlli,
			      const uint8_t *data, size_t data_len)
{
	struct msgb *msg;

	sgsn_tx_counter = 0;

	msg = create_msg(data, data_len);
	msgb_tlli(msg) = tlli;
	gsm0408_gprs_rcvmsg(msg, llme);
	msgb_free(msg);
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
	uint32_t local_tlli;

	printf("Testing GMM detach\n");

	/* DTAP - Detach Request (MO) */
	/* normal detach, power_off = 0 */
	static const unsigned char detach_req[] = {
		0x08, 0x05, 0x01, 0x18, 0x05, 0xf4, 0xef, 0xe2,
		0xb7, 0x00, 0x19, 0x03, 0xb9, 0x97, 0xcb
	};

	local_tlli = gprs_tmsi2tlli(0x23, TLLI_LOCAL);

	/* Create a context */
	OSMO_ASSERT(count(gprs_llme_list()) == 0);
	ctx = alloc_mm_ctx(local_tlli, &raid);

	/* inject the detach */
	send_0408_message(ctx->llme, local_tlli,
			  detach_req, ARRAY_SIZE(detach_req));

	/* verify that a single message (hopefully the Detach Accept) has been
	 * sent by the SGSN */
	OSMO_ASSERT(sgsn_tx_counter == 1);

	/* verify that things are gone */
	OSMO_ASSERT(count(gprs_llme_list()) == 0);
	ictx = sgsn_mm_ctx_by_tlli(local_tlli, &raid);
	OSMO_ASSERT(!ictx);
}

/*
 * Test that a GMM Detach will remove the MMCTX and the associated LLME but
 * will not sent a Detach Accept message (power_off = 1)
 */
static void test_gmm_detach_power_off(void)
{
	struct gprs_ra_id raid = { 0, };
	struct sgsn_mm_ctx *ctx, *ictx;
	uint32_t local_tlli;

	printf("Testing GMM detach (power off)\n");

	/* DTAP - Detach Request (MO) */
	/* normal detach, power_off = 1 */
	static const unsigned char detach_req[] = {
		0x08, 0x05, 0x09, 0x18, 0x05, 0xf4, 0xef, 0xe2,
		0xb7, 0x00, 0x19, 0x03, 0xb9, 0x97, 0xcb
	};

	local_tlli = gprs_tmsi2tlli(0x23, TLLI_LOCAL);

	/* Create a context */
	OSMO_ASSERT(count(gprs_llme_list()) == 0);
	ctx = alloc_mm_ctx(local_tlli, &raid);

	/* inject the detach */
	send_0408_message(ctx->llme, local_tlli,
			  detach_req, ARRAY_SIZE(detach_req));

	/* verify that no message (and therefore no Detach Accept) has been
	 * sent by the SGSN */
	OSMO_ASSERT(sgsn_tx_counter == 0);

	/* verify that things are gone */
	OSMO_ASSERT(count(gprs_llme_list()) == 0);
	ictx = sgsn_mm_ctx_by_tlli(local_tlli, &raid);
	OSMO_ASSERT(!ictx);
}

/*
 * Test that a GMM Detach will remove the associated LLME if there is no MMCTX.
 */
static void test_gmm_detach_no_mmctx(void)
{
	struct gprs_llc_lle *lle;
	uint32_t local_tlli;

	printf("Testing GMM detach (no MMCTX)\n");

	/* DTAP - Detach Request (MO) */
	/* normal detach, power_off = 0 */
	static const unsigned char detach_req[] = {
		0x08, 0x05, 0x01, 0x18, 0x05, 0xf4, 0xef, 0xe2,
		0xb7, 0x00, 0x19, 0x03, 0xb9, 0x97, 0xcb
	};

	/* Create an LLME  */
	OSMO_ASSERT(count(gprs_llme_list()) == 0);
	local_tlli = gprs_tmsi2tlli(0x23, TLLI_LOCAL);
	lle = gprs_lle_get_or_create(local_tlli, 3);

	OSMO_ASSERT(count(gprs_llme_list()) == 1);

	/* inject the detach */
	send_0408_message(lle->llme, local_tlli,
			  detach_req, ARRAY_SIZE(detach_req));

	/* verify that the LLME is gone */
	OSMO_ASSERT(count(gprs_llme_list()) == 0);
}

/*
 * Test that a single GMM Detach Accept message will not cause the SGSN to send
 * any message or leave an MM context at the SGSN.
 */
static void test_gmm_detach_accept_unexpected(void)
{
	struct gprs_llc_lle *lle;
	uint32_t local_tlli;

	printf("Testing GMM detach accept (unexpected)\n");

	/* DTAP - Detach Accept (MT) */
	/* normal detach */
	static const unsigned char detach_acc[] = {
		0x08, 0x06
	};

	/* Create an LLME  */
	OSMO_ASSERT(count(gprs_llme_list()) == 0);
	local_tlli = gprs_tmsi2tlli(0x23, TLLI_LOCAL);
	lle = gprs_lle_get_or_create(local_tlli, 3);

	/* inject the detach */
	send_0408_message(lle->llme, local_tlli,
			  detach_acc, ARRAY_SIZE(detach_acc));

	/* verify that no message (and therefore no Status or XID reset) has been
	 * sent by the SGSN */
	OSMO_ASSERT(sgsn_tx_counter == 0);

	/* verify that things are gone */
	OSMO_ASSERT(count(gprs_llme_list()) == 0);
}

/*
 * Test that a GMM Status will remove the associated LLME if there is no MMCTX.
 */
static void test_gmm_status_no_mmctx(void)
{
	struct gprs_llc_lle *lle;
	uint32_t local_tlli;

	printf("Testing GMM Status (no MMCTX)\n");

	/* DTAP - GMM Status, protocol error */
	static const unsigned char gmm_status[] = {
		0x08, 0x20, 0x6f
	};

	/* Create an LLME  */
	OSMO_ASSERT(count(gprs_llme_list()) == 0);
	local_tlli = gprs_tmsi2tlli(0x23, TLLI_LOCAL);
	lle = gprs_lle_get_or_create(local_tlli, 3);

	OSMO_ASSERT(count(gprs_llme_list()) == 1);

	/* inject the detach */
	send_0408_message(lle->llme, local_tlli,
			  gmm_status, ARRAY_SIZE(gmm_status));

	/* verify that no message has been sent by the SGSN */
	OSMO_ASSERT(sgsn_tx_counter == 0);

	/* verify that the LLME is gone */
	OSMO_ASSERT(count(gprs_llme_list()) == 0);
}

/*
 * Test the GMM Attach procedure
 */
static void test_gmm_attach(void)
{
	struct gprs_ra_id raid = { 0, };
	struct sgsn_mm_ctx *ctx = NULL;
	struct sgsn_mm_ctx *ictx;
	uint32_t ptmsi1;
	uint32_t foreign_tlli;
	uint32_t local_tlli = 0;
	struct gprs_llc_lle *lle;

	/* DTAP - Attach Request */
	/* The P-TMSI is not known by the SGSN */
	static const unsigned char attach_req[] = {
		0x08, 0x01, 0x02, 0xf5, 0xe0, 0x21, 0x08, 0x02, 0x05, 0xf4,
		0xfb, 0xc5, 0x46, 0x79, 0x11, 0x22, 0x33, 0x40, 0x50, 0x60,
		0x19, 0x18, 0xb3, 0x43, 0x2b, 0x25, 0x96, 0x62, 0x00, 0x60,
		0x80, 0x9a, 0xc2, 0xc6, 0x62, 0x00, 0x60, 0x80, 0xba, 0xc8,
		0xc6, 0x62, 0x00, 0x60, 0x80, 0x00
	};

	/* DTAP - Identity Response IMEI */
	static const unsigned char ident_resp_imei[] = {
		0x08, 0x16, 0x08, 0x9a, 0x78, 0x56, 0x34, 0x12, 0x90, 0x78,
		0x56
	};

	/* DTAP - Identity Response IMSI */
	static const unsigned char ident_resp_imsi[] = {
		0x08, 0x16, 0x08, 0x19, 0x32, 0x54, 0x76, 0x98, 0x10, 0x32,
		0x54
	};

	/* DTAP - Attach Complete */
	static const unsigned char attach_compl[] = {
		0x08, 0x03
	};

	/* DTAP - Detach Request (MO) */
	/* normal detach, power_off = 0 */
	static const unsigned char detach_req[] = {
		0x08, 0x05, 0x01, 0x18, 0x05, 0xf4, 0xeb, 0x8b,
		0x45, 0x67, 0x19, 0x03, 0xb9, 0x97, 0xcb
	};

	printf("Testing GMM attach\n");

	/* reset the PRNG used by sgsn_alloc_ptmsi */
	srand(1);

	ptmsi1 = sgsn_alloc_ptmsi();
	OSMO_ASSERT(ptmsi1 != GSM_RESERVED_TMSI);

	/* reset the PRNG, so that the same P-TMSI sequence will be generated
	 * again */
	srand(1);

	sgsn_acl_add("123456789012345", &sgsn->cfg);

	foreign_tlli = gprs_tmsi2tlli(0xc0000023, TLLI_FOREIGN);

	/* Create a LLE/LLME */
	OSMO_ASSERT(count(gprs_llme_list()) == 0);
	lle = gprs_lle_get_or_create(foreign_tlli, 3);
	OSMO_ASSERT(count(gprs_llme_list()) == 1);

	/* inject the attach request */
	send_0408_message(lle->llme, foreign_tlli,
			  attach_req, ARRAY_SIZE(attach_req));

	ctx = sgsn_mm_ctx_by_tlli(foreign_tlli, &raid);
	OSMO_ASSERT(ctx != NULL);
	OSMO_ASSERT(ctx->mm_state == GMM_COMMON_PROC_INIT);

	/* we expect an identity request (IMEI) */
	OSMO_ASSERT(sgsn_tx_counter == 1);

	/* inject the identity response (IMEI) */
	send_0408_message(ctx->llme, foreign_tlli,
			  ident_resp_imei, ARRAY_SIZE(ident_resp_imei));

	/* we expect an identity request (IMSI) */
	OSMO_ASSERT(sgsn_tx_counter == 1);

	/* inject the identity response (IMSI) */
	send_0408_message(ctx->llme, foreign_tlli,
			  ident_resp_imsi, ARRAY_SIZE(ident_resp_imsi));

	/* check that the MM context has not been removed due to a failed
	 * authorization */
	OSMO_ASSERT(ctx == sgsn_mm_ctx_by_tlli(foreign_tlli, &raid));

	OSMO_ASSERT(ctx->mm_state == GMM_COMMON_PROC_INIT);

	/* we expect an attach accept/reject */
	OSMO_ASSERT(sgsn_tx_counter == 1);

	/* this has been randomly assigned by the SGSN */
	local_tlli = gprs_tmsi2tlli(ptmsi1, TLLI_LOCAL);

	/* inject the attach complete */
	send_0408_message(ctx->llme, local_tlli,
			  attach_compl, ARRAY_SIZE(attach_compl));

	OSMO_ASSERT(ctx->mm_state == GMM_REGISTERED_NORMAL);

	/* we don't expect a response */
	OSMO_ASSERT(sgsn_tx_counter == 0);

	/* inject the detach */
	send_0408_message(ctx->llme, local_tlli,
			  detach_req, ARRAY_SIZE(detach_req));

	/* verify that things are gone */
	OSMO_ASSERT(count(gprs_llme_list()) == 0);
	ictx = sgsn_mm_ctx_by_tlli(local_tlli, &raid);
	OSMO_ASSERT(!ictx);

	sgsn_acl_del("123456789012345", &sgsn->cfg);
}

/*
 * Test the GMM Rejects
 */
static void test_gmm_reject(void)
{
	struct gprs_ra_id raid = { 0, };
	struct sgsn_mm_ctx *ctx = NULL;
	uint32_t foreign_tlli;
	struct gprs_llc_lle *lle;
	int idx;

	/* DTAP - Attach Request */
	/* Invalid MI length */
	static const unsigned char attach_req_inv_mi_len[] = {
		0x08, 0x01, 0x02, 0xf5, 0xe0, 0x21, 0x08, 0x02, 0x09, 0xf4,
		0xfb, 0xc5, 0x46, 0x79, 0xff, 0xff, 0xff, 0xff, 0x11, 0x22,
		0x33, 0x40, 0x50, 0x60, 0x19, 0x18, 0xb3, 0x43, 0x2b, 0x25,
		0x96, 0x62, 0x00, 0x60, 0x80, 0x9a, 0xc2, 0xc6, 0x62, 0x00,
		0x60, 0x80, 0xba, 0xc8, 0xc6, 0x62, 0x00, 0x60, 0x80, 0x00
	};

	/* DTAP - Attach Request */
	/* Invalid MI type (IMEI) */
	static const unsigned char attach_req_inv_mi_type[] = {
		0x08, 0x01, 0x02, 0xf5, 0xe0, 0x21, 0x08, 0x02, 0x05, 0xf2,
		0xfb, 0xc5, 0x46, 0x79, 0x11, 0x22, 0x33, 0x40, 0x50, 0x60,
		0x19, 0x18, 0xb3, 0x43, 0x2b, 0x25, 0x96, 0x62, 0x00, 0x60,
		0x80, 0x9a, 0xc2, 0xc6, 0x62, 0x00, 0x60, 0x80, 0xba, 0xc8,
		0xc6, 0x62, 0x00, 0x60, 0x80, 0x00
	};

	/* DTAP - Routing Area Update Request */
	static const unsigned char dtap_ra_upd_req[] = {
		0x08, 0x08, 0x10, 0x11, 0x22, 0x33, 0x40, 0x50,
		0x60, 0x1d, 0x19, 0x13, 0x42, 0x33, 0x57, 0x2b,
		0xf7, 0xc8, 0x48, 0x02, 0x13, 0x48, 0x50, 0xc8,
		0x48, 0x02, 0x14, 0x48, 0x50, 0xc8, 0x48, 0x02,
		0x17, 0x49, 0x10, 0xc8, 0x48, 0x02, 0x00, 0x19,
		0x8b, 0xb2, 0x92, 0x17, 0x16, 0x27, 0x07, 0x04,
		0x31, 0x02, 0xe5, 0xe0, 0x32, 0x02, 0x20, 0x00
	};

	/* DTAP - Routing Area Update Request */
	/* Invalid type: GPRS_UPD_T_RA_LA_IMSI_ATT */
	static const unsigned char dtap_ra_upd_req_inv_type[] = {
		0x08, 0x08, 0x12, 0x11, 0x22, 0x33, 0x40, 0x50,
		0x60, 0x1d, 0x19, 0x13, 0x42, 0x33, 0x57, 0x2b,
		0xf7, 0xc8, 0x48, 0x02, 0x13, 0x48, 0x50, 0xc8,
		0x48, 0x02, 0x14, 0x48, 0x50, 0xc8, 0x48, 0x02,
		0x17, 0x49, 0x10, 0xc8, 0x48, 0x02, 0x00, 0x19,
		0x8b, 0xb2, 0x92, 0x17, 0x16, 0x27, 0x07, 0x04,
		0x31, 0x02, 0xe5, 0xe0, 0x32, 0x02, 0x20, 0x00
	};

	/* DTAP - Routing Area Update Request */
	/* Invalid cap length */
	static const unsigned char dtap_ra_upd_req_inv_cap_len[] = {
		0x08, 0x08, 0x10, 0x11, 0x22, 0x33, 0x40, 0x50,
		0x60, 0x3d, 0x19, 0x13, 0x42, 0x33, 0x57, 0x2b,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xf7, 0xc8, 0x48, 0x02, 0x13, 0x48, 0x50, 0xc8,
		0x48, 0x02, 0x14, 0x48, 0x50, 0xc8, 0x48, 0x02,
		0x17, 0x49, 0x10, 0xc8, 0x48, 0x02, 0x00, 0x19,
		0x8b, 0xb2, 0x92, 0x17, 0x16, 0x27, 0x07, 0x04,
		0x31, 0x02, 0xe5, 0xe0, 0x32, 0x02, 0x20, 0x00
	};

	struct test {
		const char *title;
		const unsigned char *msg;
		unsigned msg_len;
		unsigned num_resp;

	};
	static struct test tests[] = {
		{
			.title    = "Attach Request (invalid MI length)",
			.msg      = attach_req_inv_mi_len,
			.msg_len  = sizeof(attach_req_inv_mi_len),
			.num_resp = 1 /* Reject */

		},
		{
			.title   = "Attach Request (invalid MI type)",
			.msg     = attach_req_inv_mi_type,
			.msg_len = sizeof(attach_req_inv_mi_type),
			.num_resp = 1 /* Reject */
		},
		{
			.title   = "Routing Area Update Request (valid)",
			.msg     = dtap_ra_upd_req,
			.msg_len = sizeof(dtap_ra_upd_req),
			.num_resp = 2 /* XID Reset + Reject */
		},
		{
			.title   = "Routing Area Update Request (invalid type)",
			.msg     = dtap_ra_upd_req_inv_type,
			.msg_len = sizeof(dtap_ra_upd_req_inv_type),
			.num_resp = 1 /* Reject */
		},
		{
			.title   = "Routing Area Update Request (invalid CAP length)",
			.msg     = dtap_ra_upd_req_inv_cap_len,
			.msg_len = sizeof(dtap_ra_upd_req_inv_cap_len),
			.num_resp = 1 /* Reject */
		},
	};

	printf("Testing GMM reject\n");

	/* reset the PRNG used by sgsn_alloc_ptmsi */
	srand(1);

	foreign_tlli = gprs_tmsi2tlli(0xc0000023, TLLI_FOREIGN);

	OSMO_ASSERT(count(gprs_llme_list()) == 0);

	for (idx = 0; idx < ARRAY_SIZE(tests); idx++) {
		const struct test *test = &tests[idx];
		printf("  - %s\n", test->title);

		/* Create a LLE/LLME */
		lle = gprs_lle_get_or_create(foreign_tlli, 3);
		OSMO_ASSERT(count(gprs_llme_list()) == 1);

		/* Inject the Request message */
		send_0408_message(lle->llme, foreign_tlli,
				  test->msg, test->msg_len);

		/* We expect a Reject message */
		fprintf(stderr, "sgsn_tx_counter = %d (expected %d)\n",
			sgsn_tx_counter, test->num_resp);
		OSMO_ASSERT(sgsn_tx_counter == test->num_resp);

		/* verify that LLME/MM are removed */
		ctx = sgsn_mm_ctx_by_tlli(foreign_tlli, &raid);
		OSMO_ASSERT(ctx == NULL);
		OSMO_ASSERT(count(gprs_llme_list()) == 0);
	}
}

/*
 * Test the dynamic allocation of P-TMSIs
 */
static void test_gmm_ptmsi_allocation(void)
{
	struct gprs_ra_id raid = { 0, };
	struct sgsn_mm_ctx *ctx = NULL;
	struct sgsn_mm_ctx *ictx;
	uint32_t foreign_tlli;
	uint32_t ptmsi1;
	uint32_t ptmsi2;
	uint32_t old_ptmsi;
	uint32_t local_tlli = 0;
	struct gprs_llc_lle *lle;
	const enum sgsn_auth_policy saved_auth_policy = sgsn->cfg.auth_policy;

	/* DTAP - Attach Request (IMSI 12131415161718) */
	static const unsigned char attach_req[] = {
		0x08, 0x01, 0x02, 0xf5, 0xe0, 0x21, 0x08, 0x02,
		0x08, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
		0x18, 0x11, 0x22, 0x33, 0x40, 0x50, 0x60, 0x19,
		0x18, 0xb3, 0x43, 0x2b, 0x25, 0x96, 0x62, 0x00,
		0x60, 0x80, 0x9a, 0xc2, 0xc6, 0x62, 0x00, 0x60,
		0x80, 0xba, 0xc8, 0xc6, 0x62, 0x00, 0x60, 0x80,
		0x00,
	};

	/* DTAP - Identity Response IMEI */
	static const unsigned char ident_resp_imei[] = {
		0x08, 0x16, 0x08, 0x9a, 0x78, 0x56, 0x34, 0x12, 0x90, 0x78,
		0x56
	};

	/* DTAP - Attach Complete */
	static const unsigned char attach_compl[] = {
		0x08, 0x03
	};

	/* DTAP - Routing Area Update Request */
	static const unsigned char ra_upd_req[] = {
		0x08, 0x08, 0x10, 0x11, 0x22, 0x33, 0x40, 0x50,
		0x60, 0x1d, 0x19, 0x13, 0x42, 0x33, 0x57, 0x2b,
		0xf7, 0xc8, 0x48, 0x02, 0x13, 0x48, 0x50, 0xc8,
		0x48, 0x02, 0x14, 0x48, 0x50, 0xc8, 0x48, 0x02,
		0x17, 0x49, 0x10, 0xc8, 0x48, 0x02, 0x00, 0x19,
		0x8b, 0xb2, 0x92, 0x17, 0x16, 0x27, 0x07, 0x04,
		0x31, 0x02, 0xe5, 0xe0, 0x32, 0x02, 0x20, 0x00
	};

	/* DTAP - Routing Area Update Complete */
	static const unsigned char ra_upd_complete[] = {
		0x08, 0x0a
	};

	/* DTAP - Detach Request (MO) */
	/* normal detach, power_off = 1 */
	static const unsigned char detach_req[] = {
		0x08, 0x05, 0x09, 0x18, 0x05, 0xf4, 0xef, 0xe2,
		0xb7, 0x00, 0x19, 0x03, 0xb9, 0x97, 0xcb
	};

	sgsn->cfg.auth_policy = SGSN_AUTH_POLICY_OPEN;

	printf("Testing P-TMSI allocation\n");

	printf("  - sgsn_alloc_ptmsi\n");

	/* reset the PRNG used by sgsn_alloc_ptmsi */
	srand(1);

	ptmsi1 = sgsn_alloc_ptmsi();
	OSMO_ASSERT(ptmsi1 != GSM_RESERVED_TMSI);

	ptmsi2 = sgsn_alloc_ptmsi();
	OSMO_ASSERT(ptmsi2 != GSM_RESERVED_TMSI);

	OSMO_ASSERT(ptmsi1 != ptmsi2);

	printf("  - Repeated Attach Request\n");

	/* reset the PRNG, so that the same P-TMSI will be generated
	 * again */
	srand(1);

	foreign_tlli = gprs_tmsi2tlli(0xc0000023, TLLI_FOREIGN);

	/* Create a LLE/LLME */
	OSMO_ASSERT(count(gprs_llme_list()) == 0);
	lle = gprs_lle_get_or_create(foreign_tlli, 3);
	OSMO_ASSERT(count(gprs_llme_list()) == 1);

	/* inject the attach request */
	send_0408_message(lle->llme, foreign_tlli,
			  attach_req, ARRAY_SIZE(attach_req));

	ctx = sgsn_mm_ctx_by_tlli(foreign_tlli, &raid);
	OSMO_ASSERT(ctx != NULL);
	OSMO_ASSERT(ctx->mm_state == GMM_COMMON_PROC_INIT);
	OSMO_ASSERT(ctx->p_tmsi == ptmsi1);

	old_ptmsi = ctx->p_tmsi_old;

	/* we expect an identity request (IMEI) */
	OSMO_ASSERT(sgsn_tx_counter == 1);

	/* inject the identity response (IMEI) */
	send_0408_message(ctx->llme, foreign_tlli,
			  ident_resp_imei, ARRAY_SIZE(ident_resp_imei));

	/* check that the MM context has not been removed due to a failed
	 * authorization */
	OSMO_ASSERT(ctx == sgsn_mm_ctx_by_tlli(foreign_tlli, &raid));

	OSMO_ASSERT(ctx->mm_state == GMM_COMMON_PROC_INIT);
	OSMO_ASSERT(ctx->p_tmsi == ptmsi1);

	/* we expect an attach accept */
	OSMO_ASSERT(sgsn_tx_counter == 1);

	/* we ignore this and send the attach again */
	send_0408_message(lle->llme, foreign_tlli,
			  attach_req, ARRAY_SIZE(attach_req));

	/* the allocated P-TMSI should be the same */
	ctx = sgsn_mm_ctx_by_tlli(foreign_tlli, &raid);
	OSMO_ASSERT(ctx != NULL);
	OSMO_ASSERT(ctx->mm_state == GMM_COMMON_PROC_INIT);
	OSMO_ASSERT(ctx->p_tmsi_old == old_ptmsi);
	OSMO_ASSERT(ctx->p_tmsi == ptmsi1);

	/* inject the attach complete */
	local_tlli = gprs_tmsi2tlli(ptmsi1, TLLI_LOCAL);
	send_0408_message(ctx->llme, local_tlli,
			  attach_compl, ARRAY_SIZE(attach_compl));

	/* we don't expect a response */
	OSMO_ASSERT(sgsn_tx_counter == 0);

	OSMO_ASSERT(ctx->mm_state == GMM_REGISTERED_NORMAL);
	OSMO_ASSERT(ctx->p_tmsi_old == 0);
	OSMO_ASSERT(ctx->p_tmsi == ptmsi1);

	printf("  - Repeated RA Update Request\n");

	/* inject the RA update request */
	send_0408_message(ctx->llme, local_tlli,
			  ra_upd_req, ARRAY_SIZE(ra_upd_req));

	/* we expect an RA update accept */
	OSMO_ASSERT(sgsn_tx_counter == 1);

	OSMO_ASSERT(ctx->mm_state == GMM_COMMON_PROC_INIT);
	OSMO_ASSERT(ctx->p_tmsi_old == ptmsi1);
	OSMO_ASSERT(ctx->p_tmsi == ptmsi2);

	/* repeat the RA update request */
	send_0408_message(ctx->llme, local_tlli,
			  ra_upd_req, ARRAY_SIZE(ra_upd_req));

	/* we expect an RA update accept */
	OSMO_ASSERT(sgsn_tx_counter == 1);

	OSMO_ASSERT(ctx->mm_state == GMM_COMMON_PROC_INIT);
	OSMO_ASSERT(ctx->p_tmsi_old == ptmsi1);
	OSMO_ASSERT(ctx->p_tmsi == ptmsi2);

	/* inject the RA update complete */
	local_tlli = gprs_tmsi2tlli(ptmsi2, TLLI_LOCAL);
	send_0408_message(ctx->llme, local_tlli,
			  ra_upd_complete, ARRAY_SIZE(ra_upd_complete));

	/* we don't expect a response */
	OSMO_ASSERT(sgsn_tx_counter == 0);

	OSMO_ASSERT(ctx->mm_state == GMM_REGISTERED_NORMAL);
	OSMO_ASSERT(ctx->p_tmsi_old == 0);
	OSMO_ASSERT(ctx->p_tmsi == ptmsi2);

	/* inject the detach */
	send_0408_message(ctx->llme, local_tlli,
			  detach_req, ARRAY_SIZE(detach_req));

	/* verify that things are gone */
	OSMO_ASSERT(count(gprs_llme_list()) == 0);
	ictx = sgsn_mm_ctx_by_tlli(local_tlli, &raid);
	OSMO_ASSERT(!ictx);

	sgsn->cfg.auth_policy = saved_auth_policy;
}


static struct log_info_cat gprs_categories[] = {
	[DMM] = {
		.name = "DMM",
		.description = "Layer3 Mobility Management (MM)",
		.color = "\033[1;33m",
		.enabled = 1, .loglevel = LOGL_DEBUG,
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

	sgsn_auth_init();

	test_llme();
	test_gmm_detach();
	test_gmm_detach_power_off();
	test_gmm_detach_no_mmctx();
	test_gmm_detach_accept_unexpected();
	test_gmm_status_no_mmctx();
	test_gmm_attach();
	test_gmm_reject();
	test_gmm_ptmsi_allocation();
	printf("Done\n");
	return 0;
}


/* stubs */
struct osmo_prim_hdr;
int bssgp_prim_cb(struct osmo_prim_hdr *oph, void *ctx)
{
	abort();
}
