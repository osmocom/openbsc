/* GPRS SGSN functionality */

/* (C) 2009 by Harald Welte <laforge@gnumonks.org>
 *
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

#include <stdint.h>

#include <osmocom/core/linuxlist.h>
#include <osmocom/core/talloc.h>
#include <osmocom/core/timer.h>
#include <osmocom/core/rate_ctr.h>
#include <osmocom/core/stats.h>
#include <osmocom/core/backtrace.h>
#include <osmocom/gprs/gprs_ns.h>
#include <osmocom/gprs/gprs_bssgp.h>
#include <osmocom/gsm/protocol/gsm_04_08_gprs.h>

#include <openbsc/gprs_subscriber.h>
#include <openbsc/debug.h>
#include <openbsc/gprs_sgsn.h>
#include <openbsc/sgsn.h>
#include <openbsc/gprs_gmm.h>
#include <openbsc/gprs_utils.h>
#include <openbsc/signal.h>
#include "openbsc/gprs_llc.h"
#include <openbsc/iu.h>

#include <pdp.h>

#include <time.h>

#include <openssl/rand.h>

#define GPRS_LLME_CHECK_TICK 30

extern struct sgsn_instance *sgsn;

LLIST_HEAD(sgsn_mm_ctxts);
LLIST_HEAD(sgsn_ggsn_ctxts);
LLIST_HEAD(sgsn_apn_ctxts);
LLIST_HEAD(sgsn_pdp_ctxts);

static const struct rate_ctr_desc mmctx_ctr_description[] = {
	{ "sign.packets.in",	"Signalling Messages ( In)" },
	{ "sign.packets.out",	"Signalling Messages (Out)" },
	{ "udata.packets.in",	"User Data  Messages ( In)" },
	{ "udata.packets.out",	"User Data  Messages (Out)" },
	{ "udata.bytes.in",	"User Data  Bytes    ( In)" },
	{ "udata.bytes.out",	"User Data  Bytes    (Out)" },
	{ "pdp_ctx_act",	"PDP Context Activations  " },
	{ "suspend",		"SUSPEND Count            " },
	{ "paging.ps",		"Paging Packet Switched   " },
	{ "paging.cs",		"Paging Circuit Switched  " },
	{ "ra_update",		"Routing Area Update      " },
};

static const struct rate_ctr_group_desc mmctx_ctrg_desc = {
	.group_name_prefix = "sgsn.mmctx",
	.group_description = "SGSN MM Context Statistics",
	.num_ctr = ARRAY_SIZE(mmctx_ctr_description),
	.ctr_desc = mmctx_ctr_description,
	.class_id = OSMO_STATS_CLASS_SUBSCRIBER,
};

static const struct rate_ctr_desc pdpctx_ctr_description[] = {
	{ "udata.packets.in",	"User Data  Messages ( In)" },
	{ "udata.packets.out",	"User Data  Messages (Out)" },
	{ "udata.bytes.in",	"User Data  Bytes    ( In)" },
	{ "udata.bytes.out",	"User Data  Bytes    (Out)" },
};

static const struct rate_ctr_group_desc pdpctx_ctrg_desc = {
	.group_name_prefix = "sgsn.pdpctx",
	.group_description = "SGSN PDP Context Statistics",
	.num_ctr = ARRAY_SIZE(pdpctx_ctr_description),
	.ctr_desc = pdpctx_ctr_description,
	.class_id = OSMO_STATS_CLASS_SUBSCRIBER,
};

static const struct rate_ctr_desc sgsn_ctr_description[] = {
	{ "llc.dl_bytes", "Count sent LLC bytes before giving it to the bssgp layer" },
	{ "llc.ul_bytes", "Count sucessful received LLC bytes (encrypt & fcs correct)" },
	{ "llc.dl_packets", "Count sucessful sent LLC packets before giving it to the bssgp layer" },
	{ "llc.ul_packets", "Count sucessful received LLC packets (encrypt & fcs correct)" },
	{ "gprs.attach_requested", "Received attach requests" },
	{ "gprs.attach_accepted", "Sent attach accepts" },
	{ "gprs.attach_rejected", "Sent attach rejects" },
	{ "gprs.detach_requested", "Received detach requests" },
	{ "gprs.detach_acked", "Sent detach acks" },
	{ "gprs.routing_area_requested", "Received routing area requests" },
	{ "gprs.routing_area_requested", "Sent routing area acks" },
	{ "gprs.routing_area_requested", "Sent routing area rejects" },
	{ "pdp.activate_requested", "Received activate requests" },
	{ "pdp.activate_rejected", "Sent activate rejects" },
	{ "pdp.activate_accepted", "Sent activate accepts" },
	{ "pdp.request_activated", "unused" },
	{ "pdp.request_activate_rejected", "unused" },
	{ "pdp.modify_requested", "unused" },
	{ "pdp.modify_accepted", "unused" },
	{ "pdp.dl_deactivate_requested", "Sent deactivate requests" },
	{ "pdp.dl_deactivate_accepted", "Sent deactivate accepted" },
	{ "pdp.ul_deactivate_requested", "Received deactivate requests" },
	{ "pdp.ul_deactivate_accepted", "Received deactivate accepts" },
};

static const struct rate_ctr_group_desc sgsn_ctrg_desc = {
	"sgsn",
	"SGSN Overall Statistics",
	OSMO_STATS_CLASS_GLOBAL,
	ARRAY_SIZE(sgsn_ctr_description),
	sgsn_ctr_description,
};

void sgsn_rate_ctr_init() {
	sgsn->rate_ctrs = rate_ctr_group_alloc(tall_bsc_ctx, &sgsn_ctrg_desc, 0);
}

/* look-up an SGSN MM context based on Iu UE context (struct ue_conn_ctx)*/
struct sgsn_mm_ctx *sgsn_mm_ctx_by_ue_ctx(const void *uectx)
{
	struct sgsn_mm_ctx *ctx;

	llist_for_each_entry(ctx, &sgsn_mm_ctxts, list) {
		if (ctx->ran_type == MM_CTX_T_UTRAN_Iu
		    && uectx == ctx->iu.ue_ctx)
			return ctx;
	}

	return NULL;
}

/* look-up a SGSN MM context based on TLLI + RAI */
struct sgsn_mm_ctx *sgsn_mm_ctx_by_tlli(uint32_t tlli,
					const struct gprs_ra_id *raid)
{
	struct sgsn_mm_ctx *ctx;

	llist_for_each_entry(ctx, &sgsn_mm_ctxts, list) {
		if ((tlli == ctx->gb.tlli || tlli == ctx->gb.tlli_new) &&
		    gprs_ra_id_equals(raid, &ctx->ra))
			return ctx;
	}

	return NULL;
}

struct sgsn_mm_ctx *sgsn_mm_ctx_by_tlli_and_ptmsi(uint32_t tlli,
					const struct gprs_ra_id *raid)
{
	struct sgsn_mm_ctx *ctx;
	int tlli_type;

	/* TODO: Also check the P_TMSI signature to be safe. That signature
	 * should be different (at least with a sufficiently high probability)
	 * after SGSN restarts and for multiple SGSN instances.
	 */

	tlli_type = gprs_tlli_type(tlli);
	if (tlli_type != TLLI_FOREIGN && tlli_type != TLLI_LOCAL)
		return NULL;

	llist_for_each_entry(ctx, &sgsn_mm_ctxts, list) {
		if ((gprs_tmsi2tlli(ctx->p_tmsi, tlli_type) == tlli ||
		     gprs_tmsi2tlli(ctx->p_tmsi_old, tlli_type) == tlli) &&
		    gprs_ra_id_equals(raid, &ctx->ra))
			return ctx;
	}

	return NULL;
}

struct sgsn_mm_ctx *sgsn_mm_ctx_by_ptmsi(uint32_t p_tmsi)
{
	struct sgsn_mm_ctx *ctx;

	llist_for_each_entry(ctx, &sgsn_mm_ctxts, list) {
		if (p_tmsi == ctx->p_tmsi ||
		    (ctx->p_tmsi_old && ctx->p_tmsi_old == p_tmsi))
			return ctx;
	}
	return NULL;
}

struct sgsn_mm_ctx *sgsn_mm_ctx_by_imsi(const char *imsi)
{
	struct sgsn_mm_ctx *ctx;

	llist_for_each_entry(ctx, &sgsn_mm_ctxts, list) {
		if (!strcmp(imsi, ctx->imsi))
			return ctx;
	}
	return NULL;

}

/* Allocate a new SGSN MM context for GERAN_Gb */
struct sgsn_mm_ctx *sgsn_mm_ctx_alloc_gb(uint32_t tlli,
					const struct gprs_ra_id *raid)
{
	struct sgsn_mm_ctx *ctx;

	ctx = talloc_zero(tall_bsc_ctx, struct sgsn_mm_ctx);
	if (!ctx)
		return NULL;

	memcpy(&ctx->ra, raid, sizeof(ctx->ra));
	ctx->ran_type = MM_CTX_T_GERAN_Gb;
	ctx->gb.tlli = tlli;
	ctx->gmm_state = GMM_DEREGISTERED;
	ctx->pmm_state = MM_IDLE;
	ctx->auth_triplet.key_seq = GSM_KEY_SEQ_INVAL;
	ctx->ciph_algo = sgsn->cfg.cipher;
	LOGMMCTXP(LOGL_DEBUG, ctx, "Allocated with %s cipher.\n",
		  get_value_string(gprs_cipher_names, ctx->ciph_algo));
	ctx->ctrg = rate_ctr_group_alloc(ctx, &mmctx_ctrg_desc, tlli);
	INIT_LLIST_HEAD(&ctx->pdp_list);

	llist_add(&ctx->list, &sgsn_mm_ctxts);

	return ctx;
}

/* Allocate a new SGSN MM context */
struct sgsn_mm_ctx *sgsn_mm_ctx_alloc_iu(void *uectx)
{
	struct sgsn_mm_ctx *ctx;

	ctx = talloc_zero(tall_bsc_ctx, struct sgsn_mm_ctx);
	if (!ctx)
		return NULL;

	ctx->ran_type = MM_CTX_T_UTRAN_Iu;
	ctx->iu.ue_ctx = uectx;
	ctx->iu.ue_ctx->rab_assign_addr_enc = sgsn->cfg.iu.rab_assign_addr_enc;
	ctx->iu.new_key = 1;
	ctx->gmm_state = GMM_DEREGISTERED;
	ctx->pmm_state = PMM_DETACHED;
	ctx->auth_triplet.key_seq = GSM_KEY_SEQ_INVAL;
	ctx->ctrg = rate_ctr_group_alloc(ctx, &mmctx_ctrg_desc, 0);

	/* Need to get RAID from IU conn */
	ctx->ra = ctx->iu.ue_ctx->ra_id;

	INIT_LLIST_HEAD(&ctx->pdp_list);

	llist_add(&ctx->list, &sgsn_mm_ctxts);

	return ctx;
}


/* this is a hard _free_ function, it doesn't clean up the PDP contexts
 * in libgtp! */
static void sgsn_mm_ctx_free(struct sgsn_mm_ctx *mm)
{
	struct sgsn_pdp_ctx *pdp, *pdp2;

	/* Unlink from global list of MM contexts */
	llist_del(&mm->list);

	/* Free all PDP contexts */
	llist_for_each_entry_safe(pdp, pdp2, &mm->pdp_list, list)
		sgsn_pdp_ctx_free(pdp);

	rate_ctr_group_free(mm->ctrg);

	talloc_free(mm);
}

void sgsn_mm_ctx_cleanup_free(struct sgsn_mm_ctx *mm)
{
	struct gprs_llc_llme *llme = NULL;
	uint32_t tlli = mm->gb.tlli;
	struct sgsn_pdp_ctx *pdp, *pdp2;
	struct sgsn_signal_data sig_data;

	if (mm->ran_type == MM_CTX_T_GERAN_Gb)
		llme = mm->gb.llme;
	else
		OSMO_ASSERT(mm->gb.llme == NULL);

	/* Forget about ongoing look-ups */
	if (mm->ggsn_lookup) {
		LOGMMCTXP(LOGL_NOTICE, mm,
			"Cleaning mmctx with on-going query.\n");
		mm->ggsn_lookup->mmctx = NULL;
		mm->ggsn_lookup = NULL;
	}

	/* delete all existing PDP contexts for this MS */
	llist_for_each_entry_safe(pdp, pdp2, &mm->pdp_list, list) {
		LOGMMCTXP(LOGL_NOTICE, mm,
			  "Dropping PDP context for NSAPI=%u\n", pdp->nsapi);
		sgsn_pdp_ctx_terminate(pdp);
	}

	if (osmo_timer_pending(&mm->timer)) {
		LOGMMCTXP(LOGL_INFO, mm, "Cancelling MM timer %u\n", mm->T);
		osmo_timer_del(&mm->timer);
	}

	memset(&sig_data, 0, sizeof(sig_data));
	sig_data.mm = mm;
	osmo_signal_dispatch(SS_SGSN, S_SGSN_MM_FREE, &sig_data);


	/* Detach from subscriber which is possibly freed then */
	if (mm->subscr) {
		struct gprs_subscr *subscr = gprs_subscr_get(mm->subscr);
		gprs_subscr_cleanup(subscr);
		gprs_subscr_put(subscr);
	}

	sgsn_mm_ctx_free(mm);
	mm = NULL;

	if (llme) {
		/* TLLI unassignment, must be called after sgsn_mm_ctx_free */
		gprs_llgmm_assign(llme, tlli, 0xffffffff);
	}
}


/* look up PDP context by MM context and NSAPI */
struct sgsn_pdp_ctx *sgsn_pdp_ctx_by_nsapi(const struct sgsn_mm_ctx *mm,
					   uint8_t nsapi)
{
	struct sgsn_pdp_ctx *pdp;

	llist_for_each_entry(pdp, &mm->pdp_list, list) {
		if (pdp->nsapi == nsapi)
			return pdp;
	}
	return NULL;
}

/* look up PDP context by MM context and transaction ID */
struct sgsn_pdp_ctx *sgsn_pdp_ctx_by_tid(const struct sgsn_mm_ctx *mm,
					 uint8_t tid)
{
	struct sgsn_pdp_ctx *pdp;

	llist_for_each_entry(pdp, &mm->pdp_list, list) {
		if (pdp->ti == tid)
			return pdp;
	}
	return NULL;
}

/* you don't want to use this directly, call sgsn_create_pdp_ctx() */
struct sgsn_pdp_ctx *sgsn_pdp_ctx_alloc(struct sgsn_mm_ctx *mm,
					uint8_t nsapi)
{
	struct sgsn_pdp_ctx *pdp;

	pdp = sgsn_pdp_ctx_by_nsapi(mm, nsapi);
	if (pdp)
		return NULL;

	pdp = talloc_zero(tall_bsc_ctx, struct sgsn_pdp_ctx);
	if (!pdp)
		return NULL;

	pdp->mm = mm;
	pdp->nsapi = nsapi;
	pdp->ctrg = rate_ctr_group_alloc(pdp, &pdpctx_ctrg_desc, nsapi);
	llist_add(&pdp->list, &mm->pdp_list);
	llist_add(&pdp->g_list, &sgsn_pdp_ctxts);

	return pdp;
}

/*
 * This function will not trigger any GSM DEACT PDP ACK messages, so you
 * probably want to call sgsn_delete_pdp_ctx() instead if the connection
 * isn't detached already.
 */
void sgsn_pdp_ctx_terminate(struct sgsn_pdp_ctx *pdp)
{
	struct sgsn_signal_data sig_data;

	OSMO_ASSERT(pdp->mm != NULL);

	/* There might still be pending callbacks in libgtp. So the parts of
	 * this object relevant to GTP need to remain intact in this case. */

	LOGPDPCTXP(LOGL_INFO, pdp, "Forcing release of PDP context\n");

	if (pdp->mm->ran_type == MM_CTX_T_GERAN_Gb) {
		/* Force the deactivation of the SNDCP layer */
		sndcp_sm_deactivate_ind(&pdp->mm->gb.llme->lle[pdp->sapi], pdp->nsapi);
	}

	memset(&sig_data, 0, sizeof(sig_data));
	sig_data.pdp = pdp;
	osmo_signal_dispatch(SS_SGSN, S_SGSN_PDP_TERMINATE, &sig_data);

	/* Detach from MM context */
	llist_del(&pdp->list);
	pdp->mm = NULL;

	sgsn_delete_pdp_ctx(pdp);
}

/*
 * Don't call this function directly unless you know what you are doing.
 * In normal conditions use sgsn_delete_pdp_ctx and in unspecified or
 * implementation dependent abnormal ones sgsn_pdp_ctx_terminate.
 */
void sgsn_pdp_ctx_free(struct sgsn_pdp_ctx *pdp)
{
	struct sgsn_signal_data sig_data;

	memset(&sig_data, 0, sizeof(sig_data));
	sig_data.pdp = pdp;
	osmo_signal_dispatch(SS_SGSN, S_SGSN_PDP_FREE, &sig_data);

	rate_ctr_group_free(pdp->ctrg);
	if (pdp->mm)
		llist_del(&pdp->list);
	llist_del(&pdp->g_list);

	/* _if_ we still have a library handle, at least set it to NULL
	 * to avoid any dereferences of the now-deleted PDP context from
	 * sgsn_libgtp:cb_data_ind() */
	if (pdp->lib) {
		struct pdp_t *lib = pdp->lib;
		LOGPDPCTXP(LOGL_NOTICE, pdp, "freeing PDP context that still "
		     "has a libgtp handle attached to it, this shouldn't "
		     "happen!\n");
		osmo_generate_backtrace();
		lib->priv = NULL;
	}

	if (pdp->destroy_ggsn)
		sgsn_ggsn_ctx_free(pdp->ggsn);
	talloc_free(pdp);
}

/* GGSN contexts */

struct sgsn_ggsn_ctx *sgsn_ggsn_ctx_alloc(uint32_t id)
{
	struct sgsn_ggsn_ctx *ggc;

	ggc = talloc_zero(tall_bsc_ctx, struct sgsn_ggsn_ctx);
	if (!ggc)
		return NULL;

	ggc->id = id;
	ggc->gtp_version = 1;
	ggc->remote_restart_ctr = -1;
	/* if we are called from config file parse, this gsn doesn't exist yet */
	ggc->gsn = sgsn->gsn;
	llist_add(&ggc->list, &sgsn_ggsn_ctxts);

	return ggc;
}

void sgsn_ggsn_ctx_free(struct sgsn_ggsn_ctx *ggc)
{
	llist_del(&ggc->list);
	talloc_free(ggc);
}

struct sgsn_ggsn_ctx *sgsn_ggsn_ctx_by_id(uint32_t id)
{
	struct sgsn_ggsn_ctx *ggc;

	llist_for_each_entry(ggc, &sgsn_ggsn_ctxts, list) {
		if (id == ggc->id)
			return ggc;
	}
	return NULL;
}

struct sgsn_ggsn_ctx *sgsn_ggsn_ctx_by_addr(struct in_addr *addr)
{
	struct sgsn_ggsn_ctx *ggc;

	llist_for_each_entry(ggc, &sgsn_ggsn_ctxts, list) {
		if (!memcmp(addr, &ggc->remote_addr, sizeof(*addr)))
			return ggc;
	}
	return NULL;
}


struct sgsn_ggsn_ctx *sgsn_ggsn_ctx_find_alloc(uint32_t id)
{
	struct sgsn_ggsn_ctx *ggc;

	ggc = sgsn_ggsn_ctx_by_id(id);
	if (!ggc)
		ggc = sgsn_ggsn_ctx_alloc(id);
	return ggc;
}

/* APN contexts */

static struct apn_ctx *sgsn_apn_ctx_alloc(const char *ap_name, const char *imsi_prefix)
{
	struct apn_ctx *actx;

	actx = talloc_zero(tall_bsc_ctx, struct apn_ctx);
	if (!actx)
		return NULL;
	actx->name = talloc_strdup(actx, ap_name);
	actx->imsi_prefix = talloc_strdup(actx, imsi_prefix);

	llist_add_tail(&actx->list, &sgsn_apn_ctxts);

	return actx;
}

void sgsn_apn_ctx_free(struct apn_ctx *actx)
{
	llist_del(&actx->list);
	talloc_free(actx);
}

struct apn_ctx *sgsn_apn_ctx_match(const char *name, const char *imsi)
{
	struct apn_ctx *actx;
	struct apn_ctx *found_actx = NULL;
	size_t imsi_prio = 0;
	size_t name_prio = 0;
	size_t name_req_len = strlen(name);

	llist_for_each_entry(actx, &sgsn_apn_ctxts, list) {
		size_t name_ref_len, imsi_ref_len;
		const char *name_ref_start, *name_match_start;

		imsi_ref_len = strlen(actx->imsi_prefix);
		if (strncmp(actx->imsi_prefix, imsi, imsi_ref_len) != 0)
			continue;

		if (imsi_ref_len < imsi_prio)
			continue;

		/* IMSI matches */

		name_ref_start = &actx->name[0];
		if (name_ref_start[0] == '*') {
			/* Suffix match */
			name_ref_start += 1;
			name_ref_len = strlen(name_ref_start);
			if (name_ref_len > name_req_len)
				continue;
		} else {
			name_ref_len = strlen(name_ref_start);
			if (name_ref_len != name_req_len)
				continue;
		}

		name_match_start = name + (name_req_len - name_ref_len);
		if (strcasecmp(name_match_start, name_ref_start) != 0)
			continue;

		/* IMSI and name match */

		if (imsi_ref_len == imsi_prio && name_ref_len < name_prio)
			/* Lower priority, skip */
			continue;

		imsi_prio = imsi_ref_len;
		name_prio = name_ref_len;
		found_actx = actx;
	}
	return found_actx;
}

struct apn_ctx *sgsn_apn_ctx_by_name(const char *name, const char *imsi_prefix)
{
	struct apn_ctx *actx;

	llist_for_each_entry(actx, &sgsn_apn_ctxts, list) {
		if (strcasecmp(name, actx->name) == 0 &&
		    strcasecmp(imsi_prefix, actx->imsi_prefix) == 0)
			return actx;
	}
	return NULL;
}

struct apn_ctx *sgsn_apn_ctx_find_alloc(const char *name, const char *imsi_prefix)
{
	struct apn_ctx *actx;

	actx = sgsn_apn_ctx_by_name(name, imsi_prefix);
	if (!actx)
		actx = sgsn_apn_ctx_alloc(name, imsi_prefix);

	return actx;
}

uint32_t sgsn_alloc_ptmsi(void)
{
	struct sgsn_mm_ctx *mm;
	uint32_t ptmsi = 0xdeadbeef;
	int max_retries = 100;

restart:
	if (RAND_bytes((uint8_t *) &ptmsi, sizeof(ptmsi)) != 1)
		goto failed;

	/* Enforce that the 2 MSB are set without loosing the distance between
	 * identical values. Since rand() has no duplicate values within a
	 * period (because the size of the state is the same like the size of
	 * the random value), this leads to a distance of period/4 when the
	 * distribution of the 2 MSB is uniform. This approach fails with a
	 * probability of (3/4)^max_retries, only 1% of the approaches will
	 * need more than 16 numbers (even distribution assumed).
	 *
	 * Alternatively, a freeze list could be used if another PRNG is used
	 * or when this approach proves to be not sufficient.
	 */
	if (ptmsi >= 0xC0000000) {
		if (!max_retries--)
			goto failed;
		goto restart;
	}
	ptmsi |= 0xC0000000;

	if (ptmsi == GSM_RESERVED_TMSI) {
		if (!max_retries--)
			goto failed;
		goto restart;
	}

	llist_for_each_entry(mm, &sgsn_mm_ctxts, list) {
		if (mm->p_tmsi == ptmsi) {
			if (!max_retries--)
				goto failed;
			goto restart;
		}
	}

	return ptmsi;

failed:
	LOGP(DGPRS, LOGL_ERROR, "Failed to allocate a P-TMSI\n");
	return GSM_RESERVED_TMSI;
}

static void drop_one_pdp(struct sgsn_pdp_ctx *pdp)
{
	if (pdp->mm->gmm_state == GMM_REGISTERED_NORMAL)
		gsm48_tx_gsm_deact_pdp_req(pdp, GSM_CAUSE_NET_FAIL);
	else  {
		/* FIXME: GPRS paging in case MS is SUSPENDED */
		LOGPDPCTXP(LOGL_NOTICE, pdp, "Hard-dropping PDP ctx due to GGSN "
			"recovery\n");
		/* FIXME: how to tell this to libgtp? */
		sgsn_pdp_ctx_free(pdp);
	}
}

/* High-level function to be called in case a GGSN has disappeared or
 * otherwise lost state (recovery procedure) */
int drop_all_pdp_for_ggsn(struct sgsn_ggsn_ctx *ggsn)
{
	struct sgsn_mm_ctx *mm;
	int num = 0;

	llist_for_each_entry(mm, &sgsn_mm_ctxts, list) {
		struct sgsn_pdp_ctx *pdp;
		llist_for_each_entry(pdp, &mm->pdp_list, list) {
			if (pdp->ggsn == ggsn) {
				drop_one_pdp(pdp);
				num++;
			}
		}
	}

	return num;
}

void sgsn_update_subscriber_data(struct sgsn_mm_ctx *mmctx)
{
	OSMO_ASSERT(mmctx != NULL);
	LOGMMCTXP(LOGL_INFO, mmctx, "Subscriber data update\n");

	sgsn_auth_update(mmctx);
}

static void insert_qos(struct tlv_parsed *tp, struct sgsn_subscriber_pdp_data *pdp)
{
	tp->lv[OSMO_IE_GSM_SUB_QOS].len = pdp->qos_subscribed_len;
	tp->lv[OSMO_IE_GSM_SUB_QOS].val = pdp->qos_subscribed;
}

/**
 * The tlv_parsed tp parameter will be modified to insert a
 * OSMO_IE_GSM_SUB_QOS in case the data is available in the
 * PDP context handling.
 */
struct sgsn_ggsn_ctx *sgsn_mm_ctx_find_ggsn_ctx(struct sgsn_mm_ctx *mmctx,
						struct tlv_parsed *tp,
						enum gsm48_gsm_cause *gsm_cause,
						char *out_apn_str)
{
	char req_apn_str[GSM_APN_LENGTH] = {0};
	const struct apn_ctx *apn_ctx = NULL;
	const char *selected_apn_str = NULL;
	struct sgsn_subscriber_pdp_data *pdp;
	struct sgsn_ggsn_ctx *ggsn = NULL;
	int allow_any_apn = 0;

	out_apn_str[0] = '\0';

	if (TLVP_PRESENT(tp, GSM48_IE_GSM_APN)) {
		if (TLVP_LEN(tp, GSM48_IE_GSM_APN) >= GSM_APN_LENGTH - 1) {
			LOGMMCTXP(LOGL_ERROR, mmctx, "APN IE too long\n");
			*gsm_cause = GSM_CAUSE_INV_MAND_INFO;
			return NULL;
		}

		gprs_apn_to_str(req_apn_str,
				TLVP_VAL(tp, GSM48_IE_GSM_APN),
				TLVP_LEN(tp, GSM48_IE_GSM_APN));

		if (strcmp(req_apn_str, "*") == 0)
			req_apn_str[0] = 0;
	}

	if (mmctx->subscr == NULL)
		allow_any_apn = 1;

	if (strlen(req_apn_str) == 0 && !allow_any_apn) {
		/* No specific APN requested, check for an APN that is both
		 * granted and configured */

		llist_for_each_entry(pdp, &mmctx->subscr->sgsn_data->pdp_list, list) {
			if (strcmp(pdp->apn_str, "*") == 0)
			{
				allow_any_apn = 1;
				selected_apn_str = "";
				insert_qos(tp, pdp);
				continue;
			}
			if (!llist_empty(&sgsn_apn_ctxts)) {
				apn_ctx = sgsn_apn_ctx_match(req_apn_str, mmctx->imsi);
				/* Not configured */
				if (apn_ctx == NULL)
					continue;
			}
			insert_qos(tp, pdp);
			selected_apn_str = pdp->apn_str;
			break;
		}
	} else if (!allow_any_apn) {
		/* Check whether the given APN is granted */
		llist_for_each_entry(pdp, &mmctx->subscr->sgsn_data->pdp_list, list) {
			if (strcmp(pdp->apn_str, "*") == 0) {
				insert_qos(tp, pdp);
				selected_apn_str = req_apn_str;
				allow_any_apn = 1;
				continue;
			}
			if (strcasecmp(pdp->apn_str, req_apn_str) == 0) {
				insert_qos(tp, pdp);
				selected_apn_str = req_apn_str;
				break;
			}
		}
	} else if (strlen(req_apn_str) != 0) {
		/* Any APN is allowed */
		selected_apn_str = req_apn_str;
	} else {
		/* Prefer the GGSN associated with the wildcard APN */
		selected_apn_str = "";
	}

	if (!allow_any_apn && selected_apn_str == NULL) {
		/* Access not granted */
		LOGMMCTXP(LOGL_NOTICE, mmctx,
			  "The requested APN '%s' is not allowed\n",
			  req_apn_str);
		*gsm_cause = GSM_CAUSE_REQ_SERV_OPT_NOTSUB;
		return NULL;
	}

	/* copy the selected apn_str */
	if (selected_apn_str)
		strcpy(out_apn_str, selected_apn_str);
	else
		out_apn_str[0] = '\0';

	if (apn_ctx == NULL && selected_apn_str)
		apn_ctx = sgsn_apn_ctx_match(selected_apn_str, mmctx->imsi);

	if (apn_ctx != NULL) {
		ggsn = apn_ctx->ggsn;
	} else if (llist_empty(&sgsn_apn_ctxts)) {
		/* No configuration -> use GGSN 0 */
		ggsn = sgsn_ggsn_ctx_by_id(0);
	} else if (allow_any_apn &&
		   (selected_apn_str == NULL || strlen(selected_apn_str) == 0)) {
		/* No APN given and no default configuration -> Use GGSN 0 */
		ggsn = sgsn_ggsn_ctx_by_id(0);
	} else {
		/* No matching configuration found */
		LOGMMCTXP(LOGL_NOTICE, mmctx,
			  "The selected APN '%s' has not been configured\n",
			  selected_apn_str);
		*gsm_cause = GSM_CAUSE_MISSING_APN;
		return NULL;
	}

	if (!ggsn) {
		LOGMMCTXP(LOGL_NOTICE, mmctx,
			"No static GGSN configured. Selected APN '%s'\n",
			selected_apn_str);
			return NULL;
	}

	LOGMMCTXP(LOGL_INFO, mmctx,
		  "Found GGSN %d for APN '%s' (requested '%s')\n",
		  ggsn->id, selected_apn_str ? selected_apn_str : "---",
		  req_apn_str);

	return ggsn;
}

static void sgsn_llme_cleanup_free(struct gprs_llc_llme *llme)
{
	struct sgsn_mm_ctx *mmctx = NULL;

	llist_for_each_entry(mmctx, &sgsn_mm_ctxts, list) {
		if (llme == mmctx->gb.llme) {
			gsm0408_gprs_access_cancelled(mmctx, SGSN_ERROR_CAUSE_NONE);
			return;
		}
	}

	/* No MM context found */
	LOGP(DGPRS, LOGL_INFO, "Deleting orphaned LLME, TLLI 0x%08x\n",
	     llme->tlli);
	gprs_llgmm_unassign(llme);
}

static void sgsn_llme_check_cb(void *data_)
{
	struct gprs_llc_llme *llme, *llme_tmp;
	struct timespec now_tp;
	time_t now, age;
	time_t max_age = gprs_max_time_to_idle();

	int rc;

	rc = clock_gettime(CLOCK_MONOTONIC, &now_tp);
	OSMO_ASSERT(rc >= 0);
	now = now_tp.tv_sec;

	LOGP(DGPRS, LOGL_DEBUG,
	     "Checking for inactive LLMEs, time = %u\n", (unsigned)now);

	llist_for_each_entry_safe(llme, llme_tmp, &gprs_llc_llmes, list) {
		if (llme->age_timestamp == GPRS_LLME_RESET_AGE)
			llme->age_timestamp = now;

		age = now - llme->age_timestamp;

		if (age > max_age || age < 0) {
			LOGP(DGPRS, LOGL_INFO,
			     "Inactivity timeout for TLLI 0x%08x, age %d\n",
			     llme->tlli, (int)age);
			sgsn_llme_cleanup_free(llme);
		}
	}

	osmo_timer_schedule(&sgsn->llme_timer, GPRS_LLME_CHECK_TICK, 0);
}

void sgsn_inst_init()
{
	osmo_timer_setup(&sgsn->llme_timer, sgsn_llme_check_cb, NULL);
	osmo_timer_schedule(&sgsn->llme_timer, GPRS_LLME_CHECK_TICK, 0);
}

