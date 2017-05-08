/* GSM Mobile Radio Interface Layer 3 messages on the A-bis interface
 * 3GPP TS 04.08 version 7.21.0 Release 1998 / ETSI TS 100 940 V7.21.0 */

/* (C) 2009-2015 by Harald Welte <laforge@gnumonks.org>
 * (C) 2010 by On-Waves
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <stdbool.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#include <openssl/rand.h>

#include "bscconfig.h"

#include <openbsc/db.h>
#include <osmocom/core/msgb.h>
#include <osmocom/gsm/tlv.h>
#include <osmocom/gsm/gsm_utils.h>
#include <osmocom/core/signal.h>
#include <osmocom/core/talloc.h>
#include <osmocom/core/rate_ctr.h>
#include <osmocom/core/utils.h>
#include <osmocom/crypt/auth.h>
#include <osmocom/gsm/apn.h>
#include <osmocom/gsm/protocol/gsm_04_08_gprs.h>

#include <osmocom/gprs/gprs_bssgp.h>

#ifdef BUILD_IU
#include <osmocom/ranap/ranap_ies_defs.h>
#include <osmocom/ranap/ranap_msg_factory.h>
#endif

#include <openbsc/debug.h>
#include <openbsc/gsm_data.h>
#include <openbsc/gsm_subscriber.h>
#include <openbsc/gsm_04_08.h>
#include <openbsc/paging.h>
#include <openbsc/transaction.h>
#include <openbsc/gprs_llc.h>
#include <openbsc/gprs_sgsn.h>
#include <openbsc/gprs_gmm.h>
#include <openbsc/gprs_utils.h>
#include <openbsc/gprs_subscriber.h>
#include <openbsc/sgsn.h>
#include <openbsc/signal.h>
#include <openbsc/iu.h>
#include <openbsc/gprs_sndcp.h>

#include <pdp.h>

#define PTMSI_ALLOC

extern struct sgsn_instance *sgsn;

static const struct tlv_definition gsm48_gmm_att_tlvdef = {
	.def = {
		[GSM48_IE_GMM_CIPH_CKSN]	= { TLV_TYPE_FIXED, 1 },
		[GSM48_IE_GMM_TIMER_READY]	= { TLV_TYPE_TV, 1 },
		[GSM48_IE_GMM_ALLOC_PTMSI]	= { TLV_TYPE_TLV, 0 },
		[GSM48_IE_GMM_PTMSI_SIG]	= { TLV_TYPE_FIXED, 3 },
		[GSM48_IE_GMM_AUTH_RAND]	= { TLV_TYPE_FIXED, 16 },
		[GSM48_IE_GMM_AUTH_SRES]	= { TLV_TYPE_FIXED, 4 },
		[GSM48_IE_GMM_AUTH_RES_EXT]	= { TLV_TYPE_TLV, 0 },
		[GSM48_IE_GMM_AUTH_FAIL_PAR]	= { TLV_TYPE_TLV, 0 },
		[GSM48_IE_GMM_IMEISV]		= { TLV_TYPE_TLV, 0 },
		[GSM48_IE_GMM_DRX_PARAM]	= { TLV_TYPE_FIXED, 2 },
		[GSM48_IE_GMM_MS_NET_CAPA]	= { TLV_TYPE_TLV, 0 },
		[GSM48_IE_GMM_PDP_CTX_STATUS]	= { TLV_TYPE_TLV, 0 },
		[GSM48_IE_GMM_PS_LCS_CAPA]	= { TLV_TYPE_TLV, 0 },
		[GSM48_IE_GMM_GMM_MBMS_CTX_ST]	= { TLV_TYPE_TLV, 0 },
	},
};

static const struct tlv_definition gsm48_sm_att_tlvdef = {
	.def = {
		[GSM48_IE_GSM_APN]		= { TLV_TYPE_TLV, 0 },
		[GSM48_IE_GSM_PROTO_CONF_OPT]	= { TLV_TYPE_TLV, 0 },
		[GSM48_IE_GSM_PDP_ADDR]		= { TLV_TYPE_TLV, 0 },
		[GSM48_IE_GSM_AA_TMR]		= { TLV_TYPE_TV, 1 },
		[GSM48_IE_GSM_NAME_FULL]	= { TLV_TYPE_TLV, 0 },
		[GSM48_IE_GSM_NAME_SHORT]	= { TLV_TYPE_TLV, 0 },
		[GSM48_IE_GSM_TIMEZONE]		= { TLV_TYPE_FIXED, 1 },
		[GSM48_IE_GSM_UTC_AND_TZ]	= { TLV_TYPE_FIXED, 7 },
		[GSM48_IE_GSM_LSA_ID]		= { TLV_TYPE_TLV, 0 },
	},
};

static const struct value_string gprs_pmm_state_names[] = {
	{ PMM_DETACHED,		"PMM DETACH" },
	{ PMM_CONNECTED,	"PMM CONNECTED" },
	{ PMM_IDLE,		"PMM IDLE" },
	{ MM_IDLE,		"MM IDLE" },
	{ MM_READY,		"MM READY" },
	{ MM_STANDBY,		"MM STANDBY" },
	{ 0, NULL }
};

static int gsm48_gmm_authorize(struct sgsn_mm_ctx *ctx);

static void mmctx_change_gtpu_endpoints_to_sgsn(struct sgsn_mm_ctx *mm_ctx)
{
	struct sgsn_pdp_ctx *pdp;
	llist_for_each_entry(pdp, &mm_ctx->pdp_list, list) {
		sgsn_pdp_upd_gtp_u(pdp,
				   &sgsn->cfg.gtp_listenaddr.sin_addr,
				   sizeof(sgsn->cfg.gtp_listenaddr.sin_addr));
	}
}

void mmctx_set_pmm_state(struct sgsn_mm_ctx *ctx, enum gprs_pmm_state state)
{
	if (ctx->ran_type != MM_CTX_T_UTRAN_Iu)
		return;

	if (ctx->pmm_state == state)
		return;

	LOGMMCTXP(LOGL_INFO, ctx, "Changing PMM state from %s to %s\n",
		  get_value_string(gprs_pmm_state_names, ctx->pmm_state),
		  get_value_string(gprs_pmm_state_names, state));

	switch (state) {
	case PMM_IDLE:
		/* TODO: start RA Upd timer */
		mmctx_change_gtpu_endpoints_to_sgsn(ctx);
		break;
	case PMM_CONNECTED:
		break;
	default:
		break;
	}

	ctx->pmm_state = state;
}

void mmctx_set_mm_state(struct sgsn_mm_ctx *ctx, enum gprs_pmm_state state)
{
	if (ctx->ran_type != MM_CTX_T_GERAN_Gb)
		return;

	if (ctx->pmm_state == state)
		return;

	LOGMMCTXP(LOGL_INFO, ctx, "Changing MM state from %s to %s\n",
		  get_value_string(gprs_pmm_state_names, ctx->pmm_state),
		  get_value_string(gprs_pmm_state_names, state));

	ctx->pmm_state = state;
}

#ifdef BUILD_IU
int sgsn_ranap_rab_ass_resp(struct sgsn_mm_ctx *ctx, RANAP_RAB_SetupOrModifiedItemIEs_t *setup_ies);
int sgsn_ranap_iu_event(struct ue_conn_ctx *ctx, enum iu_event_type type, void *data)
{
	struct sgsn_mm_ctx *mm;
	int rc = -1;

	mm = sgsn_mm_ctx_by_ue_ctx(ctx);
	if (!mm) {
		LOGP(DRANAP, LOGL_NOTICE, "Cannot find mm ctx for IU event %i!\n", type);
		return rc;
	}

	switch (type) {
	case IU_EVENT_RAB_ASSIGN:
		rc = sgsn_ranap_rab_ass_resp(mm, (RANAP_RAB_SetupOrModifiedItemIEs_t *)data);
		break;
	case IU_EVENT_IU_RELEASE:
		/* fall thru */
	case IU_EVENT_LINK_INVALIDATED:
		/* Clean up ue_conn_ctx here */
		LOGMMCTXP(LOGL_INFO, mm, "IU release for imsi %s\n", mm->imsi);
		if (mm->pmm_state == PMM_CONNECTED)
			mmctx_set_pmm_state(mm, PMM_IDLE);
		rc = 0;
		break;
	case IU_EVENT_SECURITY_MODE_COMPLETE:
		/* Continue authentication here */
		mm->iu.ue_ctx->integrity_active = 1;
		rc = gsm48_gmm_authorize(mm);
		break;
	default:
		LOGP(DRANAP, LOGL_NOTICE, "Unknown event received: %i\n", type);
		rc = -1;
		break;
	}
	return rc;
}
#endif


/* Our implementation, should be kept in SGSN */

static void mmctx_timer_cb(void *_mm);

static void mmctx_timer_start(struct sgsn_mm_ctx *mm, unsigned int T,
				unsigned int seconds)
{
	if (osmo_timer_pending(&mm->timer))
		LOGMMCTXP(LOGL_ERROR, mm, "Starting MM timer %u while old "
			"timer %u pending\n", T, mm->T);
	mm->T = T;
	mm->num_T_exp = 0;

	/* FIXME: we should do this only once ? */
	osmo_timer_setup(&mm->timer, mmctx_timer_cb, mm);
	osmo_timer_schedule(&mm->timer, seconds, 0);
}

static void mmctx_timer_stop(struct sgsn_mm_ctx *mm, unsigned int T)
{
	if (mm->T != T)
		LOGMMCTXP(LOGL_ERROR, mm, "Stopping MM timer %u but "
			"%u is running\n", T, mm->T);
	osmo_timer_del(&mm->timer);
}

time_t gprs_max_time_to_idle(void)
{
	return sgsn->cfg.timers.T3314 + (sgsn->cfg.timers.T3312 + 4 * 60);
}

/* Send a message through the underlying layer.
 * For param encryptable, see 3GPP TS 24.008 § 4.7.1.2 and
 * gsm48_hdr_gmm_cipherable(). Pass false for not cipherable messages. */
static int gsm48_gmm_sendmsg(struct msgb *msg, int command,
			     struct sgsn_mm_ctx *mm, bool encryptable)
{
	if (mm) {
		rate_ctr_inc(&mm->ctrg->ctr[GMM_CTR_PKTS_SIG_OUT]);
#ifdef BUILD_IU
		if (mm->ran_type == MM_CTX_T_UTRAN_Iu)
			return iu_tx(msg, GPRS_SAPI_GMM);
#endif
	}

#ifdef BUILD_IU
	/* In Iu mode, msg->dst contains the ue_conn_ctx pointer, in Gb mode
	 * dst is empty. */
	/* FIXME: have a more explicit indicator for Iu messages */
	if (msg->dst)
		return iu_tx(msg, GPRS_SAPI_GMM);
#endif

	/* caller needs to provide TLLI, BVCI and NSEI */
	return gprs_llc_tx_ui(msg, GPRS_SAPI_GMM, command, mm, encryptable);
}

/* copy identifiers from old message to new message, this
 * is required so lower layers can route it correctly */
static void gmm_copy_id(struct msgb *msg, const struct msgb *old)
{
	msgb_tlli(msg) = msgb_tlli(old);
	msgb_bvci(msg) = msgb_bvci(old);
	msgb_nsei(msg) = msgb_nsei(old);
	msg->dst = old->dst;
}

/* Store BVCI/NSEI in MM context */
static void msgid2mmctx(struct sgsn_mm_ctx *mm, const struct msgb *msg)
{
	mm->gb.bvci = msgb_bvci(msg);
	mm->gb.nsei = msgb_nsei(msg);
	/* In case a Iu connection is reconnected we need to update the ue ctx */
	mm->iu.ue_ctx = msg->dst;
}

/* Store BVCI/NSEI in MM context */
static void mmctx2msgid(struct msgb *msg, const struct sgsn_mm_ctx *mm)
{
	msgb_tlli(msg) = mm->gb.tlli;
	msgb_bvci(msg) = mm->gb.bvci;
	msgb_nsei(msg) = mm->gb.nsei;
	msg->dst = mm->iu.ue_ctx;
}

static void mm_ctx_cleanup_free(struct sgsn_mm_ctx *ctx, const char *log_text)
{
	LOGMMCTXP(LOGL_INFO, ctx, "Cleaning MM context due to %s\n", log_text);

	/* Mark MM state as deregistered */
	ctx->gmm_state = GMM_DEREGISTERED;
	mmctx_set_pmm_state(ctx, PMM_DETACHED);
	mmctx_set_pmm_state(ctx, MM_IDLE);

	sgsn_mm_ctx_cleanup_free(ctx);
}

/* Chapter 9.4.18 */
static int _tx_status(struct msgb *msg, uint8_t cause,
		      struct sgsn_mm_ctx *mmctx, int sm)
{
	struct gsm48_hdr *gh;

	/* MMCTX might be NULL! */

	DEBUGP(DMM, "<- GPRS MM STATUS (cause: %s)\n",
		get_value_string(gsm48_gmm_cause_names, cause));

	gh = (struct gsm48_hdr *) msgb_put(msg, sizeof(*gh) + 1);
	if (sm) {
		gh->proto_discr = GSM48_PDISC_SM_GPRS;
		gh->msg_type = GSM48_MT_GSM_STATUS;
	} else {
		gh->proto_discr = GSM48_PDISC_MM_GPRS;
		gh->msg_type = GSM48_MT_GMM_STATUS;
	}
	gh->data[0] = cause;

	return gsm48_gmm_sendmsg(msg, 0, mmctx, true);
}

static int gsm48_tx_gmm_status(struct sgsn_mm_ctx *mmctx, uint8_t cause)
{
	struct msgb *msg = gsm48_msgb_alloc_name("GSM 04.08 GMM STATUS");

	mmctx2msgid(msg, mmctx);
	return _tx_status(msg, cause, mmctx, 0);
}

static int gsm48_tx_sm_status(struct sgsn_mm_ctx *mmctx, uint8_t cause)
{
	struct msgb *msg = gsm48_msgb_alloc_name("GSM 04.08 SM STATUS");

	mmctx2msgid(msg, mmctx);
	return _tx_status(msg, cause, mmctx, 1);
}

static int _tx_detach_req(struct msgb *msg, uint8_t detach_type, uint8_t cause,
			  struct sgsn_mm_ctx *mmctx)
{
	struct gsm48_hdr *gh;

	/* MMCTX might be NULL! */

	DEBUGP(DMM, "<- GPRS MM DETACH REQ (type: %s, cause: %s)\n",
		get_value_string(gprs_det_t_mt_strs, detach_type),
		get_value_string(gsm48_gmm_cause_names, cause));

	gh = (struct gsm48_hdr *) msgb_put(msg, sizeof(*gh) + 1);

	gh->proto_discr = GSM48_PDISC_MM_GPRS;
	gh->msg_type = GSM48_MT_GMM_DETACH_REQ;
	gh->data[0] = detach_type & 0x07;

	msgb_tv_put(msg, GSM48_IE_GMM_CAUSE, cause);

	return gsm48_gmm_sendmsg(msg, 0, mmctx, true);
}

static int gsm48_tx_gmm_detach_req(struct sgsn_mm_ctx *mmctx,
				   uint8_t detach_type, uint8_t cause)
{
	struct msgb *msg = gsm48_msgb_alloc_name("GSM 04.08 DET REQ");

	mmctx2msgid(msg, mmctx);
	return _tx_detach_req(msg, detach_type, cause, mmctx);
}

static int gsm48_tx_gmm_detach_req_oldmsg(struct msgb *oldmsg,
					  uint8_t detach_type, uint8_t cause)
{
	struct msgb *msg = gsm48_msgb_alloc_name("GSM 04.08 DET OLD");

	gmm_copy_id(msg, oldmsg);
	return _tx_detach_req(msg, detach_type, cause, NULL);
}

static struct gsm48_qos default_qos = {
	.delay_class = 4,	/* best effort */
	.reliab_class = GSM48_QOS_RC_LLC_UN_RLC_ACK_DATA_PROT,
	.peak_tput = GSM48_QOS_PEAK_TPUT_32000bps,
	.preced_class = GSM48_QOS_PC_NORMAL,
	.mean_tput = GSM48_QOS_MEAN_TPUT_BEST_EFFORT,
	.traf_class = GSM48_QOS_TC_INTERACTIVE,
	.deliv_order = GSM48_QOS_DO_UNORDERED,
	.deliv_err_sdu = GSM48_QOS_ERRSDU_YES,
	.max_sdu_size = GSM48_QOS_MAXSDU_1520,
	.max_bitrate_up = GSM48_QOS_MBRATE_63k,
	.max_bitrate_down = GSM48_QOS_MBRATE_63k,
	.resid_ber = GSM48_QOS_RBER_5e_2,
	.sdu_err_ratio = GSM48_QOS_SERR_1e_2,
	.handling_prio = 3,
	.xfer_delay = 0x10,	/* 200ms */
	.guar_bitrate_up = GSM48_QOS_MBRATE_0k,
	.guar_bitrate_down = GSM48_QOS_MBRATE_0k,
	.sig_ind = 0,	/* not optimised for signalling */
	.max_bitrate_down_ext = 0,	/* use octet 9 */
	.guar_bitrate_down_ext = 0,	/* use octet 13 */
};

/* Chapter 9.4.2: Attach accept */
static int gsm48_tx_gmm_att_ack(struct sgsn_mm_ctx *mm)
{
	struct msgb *msg = gsm48_msgb_alloc_name("GSM 04.08 ATT ACK");
	struct gsm48_hdr *gh;
	struct gsm48_attach_ack *aa;
	uint8_t *mid;
#if 0
	uint8_t *ptsig;
#endif

	LOGMMCTXP(LOGL_INFO, mm, "<- GPRS ATTACH ACCEPT (new P-TMSI=0x%08x)\n", mm->p_tmsi);
	rate_ctr_inc(&sgsn->rate_ctrs->ctr[CTR_GPRS_ATTACH_ACKED]);

	mmctx2msgid(msg, mm);

	gh = (struct gsm48_hdr *) msgb_put(msg, sizeof(*gh));
	gh->proto_discr = GSM48_PDISC_MM_GPRS;
	gh->msg_type = GSM48_MT_GMM_ATTACH_ACK;

	aa = (struct gsm48_attach_ack *) msgb_put(msg, sizeof(*aa));
	aa->force_stby = 0;	/* not indicated */
	aa->att_result = 1;	/* GPRS only */
	aa->ra_upd_timer = gprs_secs_to_tmr_floor(sgsn->cfg.timers.T3312);
	aa->radio_prio = 4;	/* lowest */
	gsm48_construct_ra(aa->ra_id.digits, &mm->ra);

#if 0
	/* Optional: P-TMSI signature */
	msgb_v_put(msg, GSM48_IE_GMM_PTMSI_SIG);
	ptsig = msgb_put(msg, 3);
	ptsig[0] = mm->p_tmsi_sig >> 16;
	ptsig[1] = mm->p_tmsi_sig >> 8;
	ptsig[2] = mm->p_tmsi_sig & 0xff;

#endif
	/* Optional: Negotiated Ready timer value
	 * (fixed 44s, default value, GSM 04.08, table 11.4a) to safely limit
	 * the inactivity time READY->STANDBY.
	 */
	msgb_tv_put(msg, GSM48_IE_GMM_TIMER_READY,
		    gprs_secs_to_tmr_floor(sgsn->cfg.timers.T3314));

#ifdef PTMSI_ALLOC
	/* Optional: Allocated P-TMSI */
	mid = msgb_put(msg, GSM48_MID_TMSI_LEN);
	gsm48_generate_mid_from_tmsi(mid, mm->p_tmsi);
	mid[0] = GSM48_IE_GMM_ALLOC_PTMSI;
#endif

	/* Optional: MS-identity (combined attach) */
	/* Optional: GMM cause (partial attach result for combined attach) */

	return gsm48_gmm_sendmsg(msg, 0, mm, true);
}

/* Chapter 9.4.5: Attach reject */
static int _tx_gmm_att_rej(struct msgb *msg, uint8_t gmm_cause,
			   const struct sgsn_mm_ctx *mm)
{
	struct gsm48_hdr *gh;

	LOGMMCTXP(LOGL_NOTICE, mm, "<- GPRS ATTACH REJECT: %s\n",
		  get_value_string(gsm48_gmm_cause_names, gmm_cause));
	rate_ctr_inc(&sgsn->rate_ctrs->ctr[CTR_GPRS_ATTACH_REJECTED]);

	gh = (struct gsm48_hdr *) msgb_put(msg, sizeof(*gh) + 1);
	gh->proto_discr = GSM48_PDISC_MM_GPRS;
	gh->msg_type = GSM48_MT_GMM_ATTACH_REJ;
	gh->data[0] = gmm_cause;

	return gsm48_gmm_sendmsg(msg, 0, NULL, false);
}
static int gsm48_tx_gmm_att_rej_oldmsg(const struct msgb *old_msg,
					uint8_t gmm_cause)
{
	struct msgb *msg = gsm48_msgb_alloc_name("GSM 04.08 ATT REJ OLD");
	gmm_copy_id(msg, old_msg);
	return _tx_gmm_att_rej(msg, gmm_cause, NULL);
}
static int gsm48_tx_gmm_att_rej(struct sgsn_mm_ctx *mm,
				uint8_t gmm_cause)
{
	struct msgb *msg = gsm48_msgb_alloc_name("GSM 04.08 ATT REJ");
	mmctx2msgid(msg, mm);
	return _tx_gmm_att_rej(msg, gmm_cause, mm);
}

/* Chapter 9.4.6.2 Detach accept */
static int _tx_detach_ack(struct msgb *msg, uint8_t force_stby,
			  struct sgsn_mm_ctx *mm)
{
	struct gsm48_hdr *gh;

	/* MMCTX might be NULL! */

	DEBUGP(DMM, "<- GPRS MM DETACH ACC (force-standby: %d)\n", force_stby);
	rate_ctr_inc(&sgsn->rate_ctrs->ctr[CTR_GPRS_DETACH_ACKED]);

	gh = (struct gsm48_hdr *) msgb_put(msg, sizeof(*gh) + 1);
	gh->proto_discr = GSM48_PDISC_MM_GPRS;
	gh->msg_type = GSM48_MT_GMM_DETACH_ACK;
	gh->data[0] = force_stby;

	return gsm48_gmm_sendmsg(msg, 0, mm, true);
}

static int gsm48_tx_gmm_det_ack(struct sgsn_mm_ctx *mm, uint8_t force_stby)
{
	struct msgb *msg = gsm48_msgb_alloc_name("GSM 04.08 DET ACK");

	mmctx2msgid(msg, mm);
	return _tx_detach_ack(msg, force_stby, mm);
}

static int gsm48_tx_gmm_det_ack_oldmsg(struct msgb *oldmsg, uint8_t force_stby)
{
	struct msgb *msg = gsm48_msgb_alloc_name("GSM 04.08 DET ACK OLD");

	gmm_copy_id(msg, oldmsg);
	return _tx_detach_ack(msg, force_stby, NULL);
}

/* Transmit Chapter 9.4.12 Identity Request */
static int gsm48_tx_gmm_id_req(struct sgsn_mm_ctx *mm, uint8_t id_type)
{
	struct msgb *msg = gsm48_msgb_alloc_name("GSM 04.08 ID REQ");
	struct gsm48_hdr *gh;

	LOGMMCTXP(LOGL_DEBUG, mm, "<- GPRS IDENTITY REQUEST: mi_type=%s\n",
		  gsm48_mi_type_name(id_type));

	mmctx2msgid(msg, mm);

	gh = (struct gsm48_hdr *) msgb_put(msg, sizeof(*gh) + 1);
	gh->proto_discr = GSM48_PDISC_MM_GPRS;
	gh->msg_type = GSM48_MT_GMM_ID_REQ;
	/* 10.5.5.9 ID type 2 + identity type and 10.5.5.7 'force to standby' IE */
	gh->data[0] = id_type & 0xf;

	return gsm48_gmm_sendmsg(msg, 1, mm, false);
}

/* determine if the MS/UE supports R99 or later */
static bool mmctx_is_r99(const struct sgsn_mm_ctx *mm)
{
	if (mm->ms_network_capa.len < 1)
		return false;
	if (mm->ms_network_capa.buf[0] & 0x01)
		return true;
	return false;
}

/* 3GPP TS 24.008 Section 9.4.9: Authentication and Ciphering Request */
static int gsm48_tx_gmm_auth_ciph_req(struct sgsn_mm_ctx *mm,
				      const struct osmo_auth_vector *vec,
				      uint8_t key_seq, bool force_standby)
{
	struct msgb *msg = gsm48_msgb_alloc_name("GSM 04.08 AUTH CIPH REQ");
	struct gsm48_hdr *gh;
	struct gsm48_auth_ciph_req *acreq;
	uint8_t *m_rand, *m_cksn, rbyte;

	LOGMMCTXP(LOGL_INFO, mm, "<- GPRS AUTH AND CIPHERING REQ (rand = %s",
		  osmo_hexdump(vec->rand, sizeof(vec->rand)));
	if (mmctx_is_r99(mm) && vec
	    && (vec->auth_types & OSMO_AUTH_TYPE_UMTS)) {
		LOGPC(DMM, LOGL_INFO, ", autn = %s)\n",
		      osmo_hexdump(vec->autn, sizeof(vec->autn)));
	} else
		LOGPC(DMM, LOGL_INFO, ")\n");

	mmctx2msgid(msg, mm);

	gh = (struct gsm48_hdr *) msgb_put(msg, sizeof(*gh));
	gh->proto_discr = GSM48_PDISC_MM_GPRS;
	gh->msg_type = GSM48_MT_GMM_AUTH_CIPH_REQ;

	acreq = (struct gsm48_auth_ciph_req *) msgb_put(msg, sizeof(*acreq));
	acreq->ciph_alg = mm->ciph_algo & 0xf;
	/* § 10.5.5.10: */
	acreq->imeisv_req = 0x1;
	/* § 10.5.5.7: */
	acreq->force_stby = force_standby;
	/* 3GPP TS 24.008 § 10.5.5.19: */
	if (RAND_bytes(&rbyte, 1) != 1) {
		LOGP(DMM, LOGL_NOTICE, "RAND_bytes failed for A&C ref, falling "
		     "back to rand()\n");
		acreq->ac_ref_nr = rand();
	} else
		acreq->ac_ref_nr = rbyte;
	mm->ac_ref_nr_used = acreq->ac_ref_nr;

	/* Only if authentication is requested we need to set RAND + CKSN */
	if (vec) {
		m_rand = msgb_put(msg, sizeof(vec->rand) + 1);
		m_rand[0] = GSM48_IE_GMM_AUTH_RAND;
		memcpy(m_rand + 1, vec->rand, sizeof(vec->rand));

		/* § 10.5.1.2: */
		m_cksn = msgb_put(msg, 1);
		m_cksn[0] = (GSM48_IE_GMM_CIPH_CKSN << 4) | (key_seq & 0x07);

		/* A Release99 or higher MS/UE must be able to handle
		 * the optional AUTN IE.  If a classic GSM SIM is
		 * inserted, it will simply ignore AUTN and just use
		 * RAND */
		if (mmctx_is_r99(mm) &&
		    (vec->auth_types & OSMO_AUTH_TYPE_UMTS)) {
			msgb_tlv_put(msg, GSM48_IE_GMM_AUTN,
				     sizeof(vec->autn), vec->autn);
		}
	}

	return gsm48_gmm_sendmsg(msg, 1, mm, false);
}

/* Section 9.4.11: Authentication and Ciphering Reject */
static int gsm48_tx_gmm_auth_ciph_rej(struct sgsn_mm_ctx *mm)
{
	struct msgb *msg = gsm48_msgb_alloc_name("GSM 04.08 AUTH CIPH REJ");
	struct gsm48_hdr *gh;

	LOGMMCTXP(LOGL_NOTICE, mm, "<- GPRS AUTH AND CIPH REJECT\n");

	mmctx2msgid(msg, mm);

	gh = (struct gsm48_hdr *) msgb_put(msg, sizeof(*gh));
	gh->proto_discr = GSM48_PDISC_MM_GPRS;
	gh->msg_type = GSM48_MT_GMM_AUTH_CIPH_REJ;

	return gsm48_gmm_sendmsg(msg, 0, mm, false);
}

/* check if the received authentication response matches */
static bool check_auth_resp(struct sgsn_mm_ctx *ctx,
			    bool is_utran,
			    const struct osmo_auth_vector *vec,
			    const uint8_t *res, uint8_t res_len)
{
	const uint8_t *expect_res;
	uint8_t expect_res_len;
	enum osmo_sub_auth_type expect_type;
	const char *expect_str;

	if (!vec)
		return true; /* really!? */

	/* On UTRAN (3G) we always expect UMTS AKA. On GERAN (2G) we sent AUTN
	 * and expect UMTS AKA if there is R99 capability and our vector
	 * supports UMTS AKA, otherwise we expect GSM AKA. */
	if (is_utran
	    || (mmctx_is_r99(ctx) && (vec->auth_types & OSMO_AUTH_TYPE_UMTS))) {
		expect_type = OSMO_AUTH_TYPE_UMTS;
		expect_str = "UMTS RES";
		expect_res = vec->res;
		expect_res_len = vec->res_len;
	} else {
		expect_type = OSMO_AUTH_TYPE_GSM;
		expect_str = "GSM SRES";
		expect_res = vec->sres;
		expect_res_len = sizeof(vec->sres);
	}
	
	if (!(vec->auth_types & expect_type)) {
		LOGMMCTXP(LOGL_ERROR, ctx, "Auth error: auth vector does"
			  " not provide the expected auth type:"
			  " expected %s = 0x%x, auth_types are 0x%x\n",
			  expect_str, expect_type, vec->auth_types);
		return false;
	}

	if (!res)
		goto auth_mismatch;

	if (res_len != expect_res_len)
		goto auth_mismatch;

	if (memcmp(res, expect_res, res_len) != 0)
		goto auth_mismatch;

	/* Authorized! */
	return true;

auth_mismatch:
	LOGMMCTXP(LOGL_ERROR, ctx, "Auth mismatch: expected %s = %s\n",
		  expect_str, osmo_hexdump_nospc(expect_res, expect_res_len));
	return false;
}

/* Section 9.4.10: Authentication and Ciphering Response */
static int gsm48_rx_gmm_auth_ciph_resp(struct sgsn_mm_ctx *ctx,
					struct msgb *msg)
{
	struct gsm48_hdr *gh = (struct gsm48_hdr *) msgb_gmmh(msg);
	struct gsm48_auth_ciph_resp *acr = (struct gsm48_auth_ciph_resp *)gh->data;
	struct tlv_parsed tp;
	struct gsm_auth_tuple *at;
	const char *res_name = "(no response)";
	uint8_t res[16];
	uint8_t res_len;
	int rc;

	LOGMMCTXP(LOGL_INFO, ctx, "-> GPRS AUTH AND CIPH RESPONSE\n");

	if (ctx->auth_triplet.key_seq == GSM_KEY_SEQ_INVAL) {
		LOGMMCTXP(LOGL_NOTICE, ctx,
			  "Unexpected Auth & Ciph Response (ignored)\n");
		return 0;
	}

	if (acr->ac_ref_nr != ctx->ac_ref_nr_used) {
		LOGMMCTXP(LOGL_NOTICE, ctx, "Reference mismatch for Auth & Ciph"
			  " Response: %u received, %u expected\n",
			  acr->ac_ref_nr, ctx->ac_ref_nr_used);
		return 0;
	}

	/* Stop T3360 */
	mmctx_timer_stop(ctx, 3360);

	tlv_parse(&tp, &gsm48_gmm_att_tlvdef, acr->data,
			(msg->data + msg->len) - acr->data, 0, 0);

	if (!TLVP_PRESENT(&tp, GSM48_IE_GMM_AUTH_SRES) ||
	    !TLVP_PRESENT(&tp, GSM48_IE_GMM_IMEISV) ||
	    TLVP_LEN(&tp,GSM48_IE_GMM_AUTH_SRES) != 4) {
		/* TODO: missing mandatory IE, return STATUS or REJ? */
		LOGMMCTXP(LOGL_ERROR, ctx, "Missing mandantory IE\n");
		return -EINVAL;
	}

	/* Start with the good old 4-byte SRES */
	memcpy(res, TLVP_VAL(&tp, GSM48_IE_GMM_AUTH_SRES), 4);
	res_len = 4;
	res_name = "GSM SRES";

	/* Append extended RES as part of UMTS AKA, if any */
	if (TLVP_PRESENT(&tp, GSM48_IE_GMM_AUTH_RES_EXT)) {
		unsigned int l = TLVP_LEN(&tp, GSM48_IE_GMM_AUTH_RES_EXT);
		if (l > sizeof(res)-4)
			l = sizeof(res)-4;
		memcpy(res+4, TLVP_VAL(&tp, GSM48_IE_GMM_AUTH_RES_EXT), l);
		res_len += l;
		res_name = "UMTS RES";
	}

	at = &ctx->auth_triplet;

	LOGMMCTXP(LOGL_DEBUG, ctx, "checking auth: received %s = %s\n",
		  res_name, osmo_hexdump(res, res_len));
	rc = check_auth_resp(ctx, false, &at->vec, res, res_len);
	if (!rc) {
		rc = gsm48_tx_gmm_auth_ciph_rej(ctx);
		mm_ctx_cleanup_free(ctx, "GPRS AUTH AND CIPH REJECT");
		return rc;
	}

	ctx->is_authenticated = 1;

	if (ctx->ran_type == MM_CTX_T_UTRAN_Iu)
		ctx->iu.new_key = 1;

	/* FIXME: enable LLC cipheirng */

	/* Check if we can let the mobile station enter */
	return gsm48_gmm_authorize(ctx);
}

/* Section 9.4.10: Authentication and Ciphering Failure */
static int gsm48_rx_gmm_auth_ciph_fail(struct sgsn_mm_ctx *ctx,
					struct msgb *msg)
{
	struct gsm48_hdr *gh = (struct gsm48_hdr *) msgb_gmmh(msg);
	struct tlv_parsed tp;
	const uint8_t gmm_cause = gh->data[0];
	const uint8_t *auts;
	int rc;

	LOGMMCTXP(LOGL_INFO, ctx, "-> GPRS AUTH AND CIPH FAILURE (cause = %s)\n",
		  get_value_string(gsm48_gmm_cause_names, gmm_cause));

	tlv_parse(&tp, &gsm48_gmm_att_tlvdef, gh->data+1, msg->len - 1, 0, 0);

	/* Only if GMM cause is present and the AUTS is provided, we can
	 * start re-sync procedure */
	if (gmm_cause == GMM_CAUSE_SYNC_FAIL &&
	    TLVP_PRESENT(&tp, GSM48_IE_GMM_AUTH_FAIL_PAR)) {
		if (TLVP_LEN(&tp, GSM48_IE_GMM_AUTH_FAIL_PAR) != 14) {
			LOGMMCTXP(LOGL_ERROR, ctx, "AUTS IE has wrong size:"
				  " expected %d, got %u\n", 14,
				  TLVP_LEN(&tp, GSM48_IE_GMM_AUTH_FAIL_PAR));
			return -EINVAL;
		}
		auts = TLVP_VAL(&tp, GSM48_IE_GMM_AUTH_FAIL_PAR);

		LOGMMCTXP(LOGL_INFO, ctx,
			  "R99 AUTHENTICATION SYNCH (AUTS = %s)\n",
			  osmo_hexdump_nospc(auts, 14));

		/* make sure we'll refresh the auth_triplet in
		 * sgsn_auth_update() */
		ctx->auth_triplet.key_seq = GSM_KEY_SEQ_INVAL;

		/* make sure we'll retry authentication after the resync */
		ctx->auth_state = SGSN_AUTH_UMTS_RESYNC;

		/* Send AUTS to HLR and wait for new Auth Info Result */
		rc = gprs_subscr_request_auth_info(ctx, auts,
						   ctx->auth_triplet.vec.rand);
		if (!rc)
			return 0;
		/* on error, fall through to send a reject */
		LOGMMCTXP(LOGL_ERROR, ctx,
			  "Sending AUTS to HLR failed (rc = %d)\n", rc);
	}

	LOGMMCTXP(LOGL_NOTICE, ctx, "Authentication failed\n");
	rc = gsm48_tx_gmm_auth_ciph_rej(ctx);
	mm_ctx_cleanup_free(ctx, "GPRS AUTH FAILURE");
	return rc;
}

static void extract_subscr_msisdn(struct sgsn_mm_ctx *ctx)
{
	struct gsm_mncc_number called;
	uint8_t msisdn[sizeof(ctx->subscr->sgsn_data->msisdn) + 1];

	/* Convert MSISDN from encoded to string.. */
	if (!ctx->subscr)
		return;

	if (ctx->subscr->sgsn_data->msisdn_len < 1)
		return;

	/* prepare the data for the decoder */
	memset(&called, 0, sizeof(called));
	msisdn[0] = ctx->subscr->sgsn_data->msisdn_len;
	memcpy(&msisdn[1], ctx->subscr->sgsn_data->msisdn,
		ctx->subscr->sgsn_data->msisdn_len);

	/* decode the string now */
	gsm48_decode_called(&called, msisdn);

	/* Prepend a '+' for international numbers */
	if (called.plan == 1 && called.type == 1) {
		ctx->msisdn[0] = '+';
		osmo_strlcpy(&ctx->msisdn[1], called.number,
			     sizeof(ctx->msisdn));
	} else {
		osmo_strlcpy(ctx->msisdn, called.number, sizeof(ctx->msisdn));
	}
}

static void extract_subscr_hlr(struct sgsn_mm_ctx *ctx)
{
	struct gsm_mncc_number called;
	uint8_t hlr_number[sizeof(ctx->subscr->sgsn_data->hlr) + 1];

	if (!ctx->subscr)
		return;

	if (ctx->subscr->sgsn_data->hlr_len < 1)
		return;

	/* prepare the data for the decoder */
	memset(&called, 0, sizeof(called));
	hlr_number[0] = ctx->subscr->sgsn_data->hlr_len;
	memcpy(&hlr_number[1], ctx->subscr->sgsn_data->hlr,
		ctx->subscr->sgsn_data->hlr_len);

	/* decode the string now */
	gsm48_decode_called(&called, hlr_number);

	if (called.plan != 1) {
		LOGMMCTXP(LOGL_ERROR, ctx,
				"Numbering plan(%d) not allowed\n",
				called.plan);
		return;
	}

	if (called.type != 1) {
		LOGMMCTXP(LOGL_ERROR, ctx,
				"Numbering type(%d) not allowed\n",
				called.type);
		return;
	}

	osmo_strlcpy(ctx->hlr, called.number, sizeof(ctx->hlr));
}

#ifdef BUILD_IU
/* Chapter 9.4.21: Service accept */
static int gsm48_tx_gmm_service_ack(struct sgsn_mm_ctx *mm)
{
	struct msgb *msg = gsm48_msgb_alloc_name("GSM 04.08 SERVICE ACK");
	struct gsm48_hdr *gh;

	LOGMMCTXP(LOGL_INFO, mm, "<- GPRS SERVICE ACCEPT (P-TMSI=0x%08x)\n", mm->p_tmsi);

	mmctx2msgid(msg, mm);

	gh = (struct gsm48_hdr *) msgb_put(msg, sizeof(*gh));
	gh->proto_discr = GSM48_PDISC_MM_GPRS;
	gh->msg_type = GSM48_MT_GMM_SERVICE_ACK;

	/* Optional: PDP context status */
	/* Optional: MBMS context status */

	return gsm48_gmm_sendmsg(msg, 0, mm, false);
}
#endif

/* Chapter 9.4.22: Service reject */
static int _tx_gmm_service_rej(struct msgb *msg, uint8_t gmm_cause,
			   const struct sgsn_mm_ctx *mm)
{
	struct gsm48_hdr *gh;

	LOGMMCTXP(LOGL_NOTICE, mm, "<- GPRS SERVICE REJECT: %s\n",
		  get_value_string(gsm48_gmm_cause_names, gmm_cause));

	gh = (struct gsm48_hdr *) msgb_put(msg, sizeof(*gh) + 1);
	gh->proto_discr = GSM48_PDISC_MM_GPRS;
	gh->msg_type = GSM48_MT_GMM_SERVICE_REJ;
	gh->data[0] = gmm_cause;

	return gsm48_gmm_sendmsg(msg, 0, NULL, true);
}
static int gsm48_tx_gmm_service_rej_oldmsg(const struct msgb *old_msg,
					uint8_t gmm_cause)
{
	struct msgb *msg = gsm48_msgb_alloc_name("GSM 04.08 SERVICE REJ OLD");
	gmm_copy_id(msg, old_msg);
	return _tx_gmm_service_rej(msg, gmm_cause, NULL);
}
#if 0
-- currently unused --
static int gsm48_tx_gmm_service_rej(struct sgsn_mm_ctx *mm,
				uint8_t gmm_cause)
{
	struct msgb *msg = gsm48_msgb_alloc_name("GSM 04.08 SERVICE REJ");
	mmctx2msgid(msg, mm);
	return _tx_gmm_service_rej(msg, gmm_cause, mm);
}
#endif

static int gsm48_tx_gmm_ra_upd_ack(struct sgsn_mm_ctx *mm);

#ifdef BUILD_IU
void activate_pdp_rabs(struct sgsn_mm_ctx *ctx)
{
	/* Send RAB activation requests for all PDP contexts */
	struct sgsn_pdp_ctx *pdp;
	llist_for_each_entry(pdp, &ctx->pdp_list, list) {
		iu_rab_act_ps(pdp->nsapi, pdp, 1);
	}
}
#endif

/* Check if we can already authorize a subscriber */
static int gsm48_gmm_authorize(struct sgsn_mm_ctx *ctx)
{
#ifdef BUILD_IU
	int rc;
#endif
#ifndef PTMSI_ALLOC
	struct sgsn_signal_data sig_data;
#endif

	/* Request IMSI and IMEI from the MS if they are unknown */
	if (!strlen(ctx->imei)) {
		ctx->t3370_id_type = GSM_MI_TYPE_IMEI;
		mmctx_timer_start(ctx, 3370, sgsn->cfg.timers.T3370);
		return gsm48_tx_gmm_id_req(ctx, GSM_MI_TYPE_IMEI);
	}
	if (!strlen(ctx->imsi)) {
		ctx->t3370_id_type = GSM_MI_TYPE_IMSI;
		mmctx_timer_start(ctx, 3370, sgsn->cfg.timers.T3370);
		return gsm48_tx_gmm_id_req(ctx, GSM_MI_TYPE_IMSI);
	}

	/* All information required for authentication is available */
	ctx->t3370_id_type = GSM_MI_TYPE_NONE;

	if (ctx->auth_state == SGSN_AUTH_UNKNOWN) {
		/* Request authorization, this leads to a call to
		 * sgsn_auth_update which in turn calls
		 * gsm0408_gprs_access_granted or gsm0408_gprs_access_denied */

		sgsn_auth_request(ctx);
		/* Note that gsm48_gmm_authorize can be called recursively via
		 * sgsn_auth_request iff ctx->auth_info changes to AUTH_ACCEPTED
		 */
		return 0;
	}

	if (ctx->auth_state == SGSN_AUTH_AUTHENTICATE && !ctx->is_authenticated) {
		struct gsm_auth_tuple *at = &ctx->auth_triplet;

		mmctx_timer_start(ctx, 3360, sgsn->cfg.timers.T3360);
		return gsm48_tx_gmm_auth_ciph_req(ctx, &at->vec, at->key_seq,
						  false);
	}

	if (ctx->auth_state == SGSN_AUTH_AUTHENTICATE && ctx->is_authenticated &&
	    ctx->auth_triplet.key_seq != GSM_KEY_SEQ_INVAL) {
		/* Check again for authorization */
		sgsn_auth_request(ctx);
		return 0;
	}

	if (ctx->auth_state != SGSN_AUTH_ACCEPTED) {
		LOGMMCTXP(LOGL_NOTICE, ctx,
			  "authorization is denied, aborting procedure\n");
		return -EACCES;
	}

	/* The MS is authorized */
#ifdef BUILD_IU
	if (ctx->ran_type == MM_CTX_T_UTRAN_Iu && !ctx->iu.ue_ctx->integrity_active) {
		rc = iu_tx_sec_mode_cmd(ctx->iu.ue_ctx, &ctx->auth_triplet, 0, ctx->iu.new_key);
		ctx->iu.new_key = 0;
		return rc;
	}
#endif

	switch (ctx->pending_req) {
	case 0:
		LOGMMCTXP(LOGL_INFO, ctx,
			  "no pending request, authorization completed\n");
		break;
	case GSM48_MT_GMM_ATTACH_REQ:
		ctx->pending_req = 0;

		extract_subscr_msisdn(ctx);
		extract_subscr_hlr(ctx);
#ifdef PTMSI_ALLOC
		/* Start T3350 and re-transmit up to 5 times until ATTACH COMPLETE */
		mmctx_timer_start(ctx, 3350, sgsn->cfg.timers.T3350);
		ctx->t3350_mode = GMM_T3350_MODE_ATT;
#else
		memset(&sig_data, 0, sizeof(sig_data));
		sig_data.mm = mmctx;
		osmo_signal_dispatch(SS_SGSN, S_SGSN_ATTACH, &sig_data);
		ctx->gmm_state = GMM_REGISTERED_NORMAL;
#endif

		return gsm48_tx_gmm_att_ack(ctx);
#ifdef BUILD_IU
	case GSM48_MT_GMM_SERVICE_REQ:
		ctx->pending_req = 0;
		mmctx_set_pmm_state(ctx, PMM_CONNECTED);
		rc = gsm48_tx_gmm_service_ack(ctx);

		if (ctx->iu.service.type != GPRS_SERVICE_T_SIGNALLING)
			activate_pdp_rabs(ctx);

		return rc;
#endif
	case GSM48_MT_GMM_RA_UPD_REQ:
		ctx->pending_req = 0;
		/* Send RA UPDATE ACCEPT */
		return gsm48_tx_gmm_ra_upd_ack(ctx);

	default:
		LOGMMCTXP(LOGL_ERROR, ctx,
			  "only Attach Request is supported yet, "
			  "got request type %u\n", ctx->pending_req);
		break;
	}

	return 0;
}

void gsm0408_gprs_authenticate(struct sgsn_mm_ctx *ctx)
{
	ctx->is_authenticated = 0;

	gsm48_gmm_authorize(ctx);
}

void gsm0408_gprs_access_granted(struct sgsn_mm_ctx *ctx)
{
	switch (ctx->gmm_state) {
	case GMM_COMMON_PROC_INIT:
		LOGMMCTXP(LOGL_NOTICE, ctx,
		     "Authorized, continuing procedure, IMSI=%s\n",
		     ctx->imsi);
		/* Continue with the authorization */
		gsm48_gmm_authorize(ctx);
		break;
	default:
		LOGMMCTXP(LOGL_INFO, ctx,
		     "Authorized, ignored, IMSI=%s\n",
		     ctx->imsi);
	}
}

void gsm0408_gprs_access_denied(struct sgsn_mm_ctx *ctx, int gmm_cause)
{
	if (gmm_cause == SGSN_ERROR_CAUSE_NONE)
		gmm_cause = GMM_CAUSE_GPRS_NOTALLOWED;

	switch (ctx->gmm_state) {
	case GMM_COMMON_PROC_INIT:
		LOGMMCTXP(LOGL_NOTICE, ctx,
			  "Not authorized, rejecting ATTACH REQUEST "
			  "with cause '%s' (%d)\n",
			  get_value_string(gsm48_gmm_cause_names, gmm_cause),
			  gmm_cause);
		gsm48_tx_gmm_att_rej(ctx, gmm_cause);
		mm_ctx_cleanup_free(ctx, "GPRS ATTACH REJECT");
		break;
	case GMM_REGISTERED_NORMAL:
	case GMM_REGISTERED_SUSPENDED:
		LOGMMCTXP(LOGL_NOTICE, ctx,
			  "Authorization lost, detaching "
			  "with cause '%s' (%d)\n",
			  get_value_string(gsm48_gmm_cause_names, gmm_cause),
			  gmm_cause);
		gsm48_tx_gmm_detach_req(
			ctx, GPRS_DET_T_MT_REATT_NOTREQ, gmm_cause);

		mm_ctx_cleanup_free(ctx, "auth lost");
		break;
	default:
		LOGMMCTXP(LOGL_INFO, ctx,
			  "Authorization lost, cause is '%s' (%d)\n",
			  get_value_string(gsm48_gmm_cause_names, gmm_cause),
			  gmm_cause);
		mm_ctx_cleanup_free(ctx, "auth lost");
	}
}

void gsm0408_gprs_access_cancelled(struct sgsn_mm_ctx *ctx, int gmm_cause)
{
	if (gmm_cause != SGSN_ERROR_CAUSE_NONE) {
		LOGMMCTXP(LOGL_INFO, ctx,
			  "Cancelled with cause '%s' (%d), deleting context\n",
			  get_value_string(gsm48_gmm_cause_names, gmm_cause),
			  gmm_cause);
		gsm0408_gprs_access_denied(ctx, gmm_cause);
		return;
	}

	LOGMMCTXP(LOGL_INFO, ctx, "Cancelled, deleting context silently\n");
	mm_ctx_cleanup_free(ctx, "access cancelled");
}

/* Parse Chapter 9.4.13 Identity Response */
static int gsm48_rx_gmm_id_resp(struct sgsn_mm_ctx *ctx, struct msgb *msg)
{
	struct gsm48_hdr *gh = (struct gsm48_hdr *) msgb_gmmh(msg);
	uint8_t mi_type = gh->data[1] & GSM_MI_TYPE_MASK;
	char mi_string[GSM48_MI_SIZE];

	gsm48_mi_to_string(mi_string, sizeof(mi_string), &gh->data[1], gh->data[0]);
	if (!ctx) {
		DEBUGP(DMM, "from unknown TLLI 0x%08x?!? This should not happen\n", msgb_tlli(msg));
		return -EINVAL;
	}

	LOGMMCTXP(LOGL_DEBUG, ctx, "-> GMM IDENTITY RESPONSE: MI(%s)=%s\n",
		gsm48_mi_type_name(mi_type), mi_string);

	if (ctx->t3370_id_type == GSM_MI_TYPE_NONE) {
		LOGMMCTXP(LOGL_NOTICE, ctx,
			  "Got unexpected IDENTITY RESPONSE: MI(%s)=%s, "
			  "ignoring message\n",
			  gsm48_mi_type_name(mi_type), mi_string);
		return -EINVAL;
	}

	if (mi_type == ctx->t3370_id_type)
		mmctx_timer_stop(ctx, 3370);

	switch (mi_type) {
	case GSM_MI_TYPE_IMSI:
		/* we already have a mm context with current TLLI, but no
		 * P-TMSI / IMSI yet.  What we now need to do is to fill
		 * this initial context with data from the HLR */
		if (strlen(ctx->imsi) == 0) {
			/* Check if we already have a MM context for this IMSI */
			struct sgsn_mm_ctx *ictx;
			ictx = sgsn_mm_ctx_by_imsi(mi_string);
			if (ictx) {
				/* Handle it like in gsm48_rx_gmm_det_req,
				 * except that no messages are sent to the BSS */

				LOGMMCTXP(LOGL_NOTICE, ctx, "Deleting old MM Context for same IMSI "
				       "p_tmsi_old=0x%08x\n",
					ictx->p_tmsi);

				mm_ctx_cleanup_free(ictx, "GPRS IMSI re-use");
			}
		}
		osmo_strlcpy(ctx->imsi, mi_string, sizeof(ctx->imsi));
		break;
	case GSM_MI_TYPE_IMEI:
		osmo_strlcpy(ctx->imei, mi_string, sizeof(ctx->imei));
		break;
	case GSM_MI_TYPE_IMEISV:
		break;
	}

	/* Check if we can let the mobile station enter */
	return gsm48_gmm_authorize(ctx);
}

/* Section 9.4.1 Attach request */
static int gsm48_rx_gmm_att_req(struct sgsn_mm_ctx *ctx, struct msgb *msg,
				struct gprs_llc_llme *llme)
{
	struct gsm48_hdr *gh = (struct gsm48_hdr *) msgb_gmmh(msg);
	uint8_t *cur = gh->data, *msnc, *mi, *ms_ra_acc_cap;
	uint8_t msnc_len, att_type, mi_len, mi_type, ms_ra_acc_cap_len;
	uint16_t drx_par;
	uint32_t tmsi;
	char mi_string[GSM48_MI_SIZE];
	struct gprs_ra_id ra_id;
	uint16_t cid = 0;
	enum gsm48_gmm_cause reject_cause;
	int rc;

	LOGMMCTXP(LOGL_INFO, ctx, "-> GMM ATTACH REQUEST ");
	rate_ctr_inc(&sgsn->rate_ctrs->ctr[CTR_GPRS_ATTACH_REQUEST]);

	/* As per TS 04.08 Chapter 4.7.1.4, the attach request arrives either
	 * with a foreign TLLI (P-TMSI that was allocated to the MS before),
	 * or with random TLLI. */

	/* In Iu mode, msg->dst contains the ue_conn_ctx pointer, in Gb mode
	 * dst is empty. */
	/* FIXME: have a more explicit indicator for Iu messages */
	if (!msg->dst) {
		/* Gb mode */
		cid = bssgp_parse_cell_id(&ra_id, msgb_bcid(msg));
	} else
		ra_id = ((struct ue_conn_ctx*)msg->dst)->ra_id;

	/* MS network capability 10.5.5.12 */
	msnc_len = *cur++;
	msnc = cur;
	if (msnc_len > sizeof(ctx->ms_network_capa.buf))
		goto err_inval;
	cur += msnc_len;

	/* TODO: In iu mode - handle follow-on request */

	/* aTTACH Type 10.5.5.2 */
	att_type = *cur++ & 0x07;

	/* DRX parameter 10.5.5.6 */
	drx_par = *cur++ << 8;
	drx_par |= *cur++;

	/* Mobile Identity (P-TMSI or IMSI) 10.5.1.4 */
	mi_len = *cur++;
	mi = cur;
	if (mi_len > 8)
		goto err_inval;
	mi_type = *mi & GSM_MI_TYPE_MASK;
	cur += mi_len;

	gsm48_mi_to_string(mi_string, sizeof(mi_string), mi, mi_len);

	DEBUGPC(DMM, "MI(%s) type=\"%s\" ", mi_string,
		get_value_string(gprs_att_t_strs, att_type));

	/* Old routing area identification 10.5.5.15. Skip it */
	cur += 6;

	/* MS Radio Access Capability 10.5.5.12a */
	ms_ra_acc_cap_len = *cur++;
	ms_ra_acc_cap = cur;
	if (ms_ra_acc_cap_len > sizeof(ctx->ms_radio_access_capa.buf))
		goto err_inval;
	cur += ms_ra_acc_cap_len;

	LOGPC(DMM, LOGL_INFO, "\n");

	/* Optional: Old P-TMSI Signature, Requested READY timer, TMSI Status */

	switch (mi_type) {
	case GSM_MI_TYPE_IMSI:
		/* Try to find MM context based on IMSI */
		if (!ctx)
			ctx = sgsn_mm_ctx_by_imsi(mi_string);
		if (!ctx) {
#if 0
			return gsm48_tx_gmm_att_rej(msg, GMM_CAUSE_IMSI_UNKNOWN);
#else
			if (msg->dst)
				ctx = sgsn_mm_ctx_alloc_iu(msg->dst);
			else
				ctx = sgsn_mm_ctx_alloc_gb(0, &ra_id);
			if (!ctx) {
				reject_cause = GMM_CAUSE_NET_FAIL;
				goto rejected;
			}
			osmo_strlcpy(ctx->imsi, mi_string, sizeof(ctx->imsi));
#endif
		}
		if (ctx->ran_type == MM_CTX_T_GERAN_Gb) {
			ctx->gb.tlli = msgb_tlli(msg);
			ctx->gb.llme = llme;
		}
		msgid2mmctx(ctx, msg);
		break;
	case GSM_MI_TYPE_TMSI:
		memcpy(&tmsi, mi+1, 4);
		tmsi = ntohl(tmsi);
		/* Try to find MM context based on P-TMSI */
		if (!ctx)
			ctx = sgsn_mm_ctx_by_ptmsi(tmsi);
		if (!ctx) {
			/* Allocate a context as most of our code expects one.
			 * Context will not have an IMSI ultil ID RESP is received */
			if (msg->dst)
				ctx = sgsn_mm_ctx_alloc_iu(msg->dst);
			else
				ctx = sgsn_mm_ctx_alloc_gb(msgb_tlli(msg), &ra_id);
			ctx->p_tmsi = tmsi;
		}
		if (ctx->ran_type == MM_CTX_T_GERAN_Gb) {
			ctx->gb.tlli = msgb_tlli(msg);
			ctx->gb.llme = llme;
		}
		msgid2mmctx(ctx, msg);
		break;
	default:
		LOGMMCTXP(LOGL_NOTICE, ctx, "Rejecting ATTACH REQUEST with "
			"MI type %s\n", gsm48_mi_type_name(mi_type));
		reject_cause = GMM_CAUSE_MS_ID_NOT_DERIVED;
		goto rejected;
	}
	/* Update MM Context with currient RA and Cell ID */
	ctx->ra = ra_id;
	if (ctx->ran_type == MM_CTX_T_GERAN_Gb)
		ctx->gb.cell_id = cid;
	else if (ctx->ran_type == MM_CTX_T_UTRAN_Iu) {
		/* DEVELOPMENT HACK: Our current HLR does not support 3G
		 * authentication tokens. A new HLR/VLR implementation is being
		 * developed. Until it is ready and actual milenage
		 * authentication is properly supported, we are hardcoding a
		 * fixed Ki and use 2G auth. */
		unsigned char tmp_rand[16];
		/* Ki 000102030405060708090a0b0c0d0e0f */
		struct osmo_sub_auth_data auth = {
			.type	= OSMO_AUTH_TYPE_GSM,
			.algo	= OSMO_AUTH_ALG_COMP128v1,
			.u.gsm.ki = {
				0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
				0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
				0x0e, 0x0f
			},
		};
		/* XXX: Hack to make 3G auth work with special SIM card */
		ctx->auth_state = SGSN_AUTH_AUTHENTICATE;

		RAND_bytes(tmp_rand, 16);

		memset(&ctx->auth_triplet.vec, 0, sizeof(ctx->auth_triplet.vec));
		osmo_auth_gen_vec(&ctx->auth_triplet.vec, &auth, tmp_rand);

		ctx->auth_triplet.key_seq = 0;
	}

	/* Update MM Context with other data */
	ctx->drx_parms = drx_par;
	ctx->ms_radio_access_capa.len = ms_ra_acc_cap_len;
	memcpy(ctx->ms_radio_access_capa.buf, ms_ra_acc_cap,
		ctx->ms_radio_access_capa.len);
	ctx->ms_network_capa.len = msnc_len;
	memcpy(ctx->ms_network_capa.buf, msnc, msnc_len);
	if (!gprs_ms_net_cap_gea_supported(ctx->ms_network_capa.buf, msnc_len,
					   ctx->ciph_algo)) {
		reject_cause = GMM_CAUSE_PROTO_ERR_UNSPEC;
		LOGMMCTXP(LOGL_NOTICE, ctx, "Rejecting ATTACH REQUEST with MI "
			  "type %s because MS do not support required %s "
			  "encryption\n", gsm48_mi_type_name(mi_type),
			  get_value_string(gprs_cipher_names,ctx->ciph_algo));
		goto rejected;
	}
#ifdef PTMSI_ALLOC
	/* Allocate a new P-TMSI (+ P-TMSI signature) and update TLLI */
	/* Don't change the P-TMSI if a P-TMSI re-assignment is under way */
	if (ctx->gmm_state != GMM_COMMON_PROC_INIT) {
		ctx->p_tmsi_old = ctx->p_tmsi;
		ctx->p_tmsi = sgsn_alloc_ptmsi();
	}
	ctx->gmm_state = GMM_COMMON_PROC_INIT;
#endif

	if (ctx->ran_type == MM_CTX_T_GERAN_Gb) {
		/* Even if there is no P-TMSI allocated, the MS will
		 * switch from foreign TLLI to local TLLI */
		ctx->gb.tlli_new = gprs_tmsi2tlli(ctx->p_tmsi, TLLI_LOCAL);

		/* Inform LLC layer about new TLLI but keep old active */
		if (ctx->is_authenticated)
			gprs_llme_copy_key(ctx, ctx->gb.llme);

		gprs_llgmm_assign(ctx->gb.llme, ctx->gb.tlli, ctx->gb.tlli_new);
	}

	ctx->pending_req = GSM48_MT_GMM_ATTACH_REQ;
	return gsm48_gmm_authorize(ctx);

err_inval:
	LOGPC(DMM, LOGL_INFO, "\n");
	reject_cause = GMM_CAUSE_SEM_INCORR_MSG;

rejected:
	/* Send ATTACH REJECT */
	LOGMMCTXP(LOGL_NOTICE, ctx,
		  "Rejecting Attach Request with cause '%s' (%d)\n",
		  get_value_string(gsm48_gmm_cause_names, reject_cause), reject_cause);
	rc = gsm48_tx_gmm_att_rej_oldmsg(msg, reject_cause);
	if (ctx)
		mm_ctx_cleanup_free(ctx, "GPRS ATTACH REJ");
	else
		gprs_llgmm_unassign(llme);

	return rc;

}

/* Section 4.7.4.1 / 9.4.5.2 MO Detach request */
static int gsm48_rx_gmm_det_req(struct sgsn_mm_ctx *ctx, struct msgb *msg)
{
	struct gsm48_hdr *gh = (struct gsm48_hdr *) msgb_gmmh(msg);
	uint8_t detach_type, power_off;
	int rc = 0;

	detach_type = gh->data[0] & 0x7;
	power_off = gh->data[0] & 0x8;

	/* FIXME: In 24.008 there is an optional P-TMSI and P-TMSI signature IE */
	rate_ctr_inc(&sgsn->rate_ctrs->ctr[CTR_GPRS_DETACH_REQUEST]);
	LOGMMCTXP(LOGL_INFO, ctx, "-> GMM DETACH REQUEST TLLI=0x%08x type=%s %s\n",
		msgb_tlli(msg), get_value_string(gprs_det_t_mo_strs, detach_type),
		power_off ? "Power-off" : "");

	/* Only send the Detach Accept (MO) if power off isn't indicated,
	 * see 04.08, 4.7.4.1.2/3 for details */
	if (!power_off) {
		/* force_stby = 0 */
		if (ctx)
			rc = gsm48_tx_gmm_det_ack(ctx, 0);
		else
			rc = gsm48_tx_gmm_det_ack_oldmsg(msg, 0);
	}

	if (ctx) {
		struct sgsn_signal_data sig_data;
		memset(&sig_data, 0, sizeof(sig_data));
		sig_data.mm = ctx;
		osmo_signal_dispatch(SS_SGSN, S_SGSN_DETACH, &sig_data);
		mm_ctx_cleanup_free(ctx, "GPRS DETACH REQUEST");
	}

	return rc;
}

/* Chapter 9.4.15: Routing area update accept */
static int gsm48_tx_gmm_ra_upd_ack(struct sgsn_mm_ctx *mm)
{
	struct msgb *msg = gsm48_msgb_alloc_name("GSM 04.08 UPD ACK");
	struct gsm48_hdr *gh;
	struct gsm48_ra_upd_ack *rua;
	uint8_t *mid;

	rate_ctr_inc(&sgsn->rate_ctrs->ctr[CTR_GPRS_ROUTING_AREA_ACKED]);
	LOGMMCTXP(LOGL_INFO, mm, "<- ROUTING AREA UPDATE ACCEPT\n");

	mmctx2msgid(msg, mm);

	gh = (struct gsm48_hdr *) msgb_put(msg, sizeof(*gh));
	gh->proto_discr = GSM48_PDISC_MM_GPRS;
	gh->msg_type = GSM48_MT_GMM_RA_UPD_ACK;

	rua = (struct gsm48_ra_upd_ack *) msgb_put(msg, sizeof(*rua));
	rua->force_stby = 0;	/* not indicated */
	rua->upd_result = 0;	/* RA updated */
	rua->ra_upd_timer = gprs_secs_to_tmr_floor(sgsn->cfg.timers.T3312);

	gsm48_construct_ra(rua->ra_id.digits, &mm->ra);

#if 0
	/* Optional: P-TMSI signature */
	msgb_v_put(msg, GSM48_IE_GMM_PTMSI_SIG);
	ptsig = msgb_put(msg, 3);
	ptsig[0] = mm->p_tmsi_sig >> 16;
	ptsig[1] = mm->p_tmsi_sig >> 8;
	ptsig[2] = mm->p_tmsi_sig & 0xff;
#endif

#ifdef PTMSI_ALLOC
	/* Optional: Allocated P-TMSI */
	mid = msgb_put(msg, GSM48_MID_TMSI_LEN);
	gsm48_generate_mid_from_tmsi(mid, mm->p_tmsi);
	mid[0] = GSM48_IE_GMM_ALLOC_PTMSI;
#endif

	/* Optional: Negotiated READY timer value */
	msgb_tv_put(msg, GSM48_IE_GMM_TIMER_READY,
		    gprs_secs_to_tmr_floor(sgsn->cfg.timers.T3314));

	/* Option: MS ID, ... */
	return gsm48_gmm_sendmsg(msg, 0, mm, true);
}

/* Chapter 9.4.17: Routing area update reject */
static int gsm48_tx_gmm_ra_upd_rej(struct msgb *old_msg, uint8_t cause)
{
	struct msgb *msg = gsm48_msgb_alloc_name("GSM 04.08 RA UPD REJ");
	struct gsm48_hdr *gh;

	LOGP(DMM, LOGL_NOTICE, "<- ROUTING AREA UPDATE REJECT\n");
	rate_ctr_inc(&sgsn->rate_ctrs->ctr[CTR_GPRS_ROUTING_AREA_REJECT]);

	gmm_copy_id(msg, old_msg);

	gh = (struct gsm48_hdr *) msgb_put(msg, sizeof(*gh) + 2);
	gh->proto_discr = GSM48_PDISC_MM_GPRS;
	gh->msg_type = GSM48_MT_GMM_RA_UPD_REJ;
	gh->data[0] = cause;
	gh->data[1] = 0; /* ? */

	/* Option: P-TMSI signature, allocated P-TMSI, MS ID, ... */
	return gsm48_gmm_sendmsg(msg, 0, NULL, false);
}

static void process_ms_ctx_status(struct sgsn_mm_ctx *mmctx,
				  const uint8_t *pdp_status)
{
	struct sgsn_pdp_ctx *pdp, *pdp2;
	/* 24.008 4.7.5.1.3: If the PDP context status information element is
	 * included in ROUTING AREA UPDATE REQUEST message, then the network
	 * shall deactivate all those PDP contexts locally (without peer to
	 * peer signalling between the MS and the network), which are not in SM
	 * state PDP-INACTIVE on network side but are indicated by the MS as
	 * being in state PDP-INACTIVE. */

	llist_for_each_entry_safe(pdp, pdp2, &mmctx->pdp_list, list) {
		if (pdp->nsapi < 8) {
			if (!(pdp_status[0] & (1 << pdp->nsapi))) {
				LOGMMCTXP(LOGL_NOTICE, mmctx, "Dropping PDP context for NSAPI=%u "
					"due to PDP CTX STATUS IE= 0x%02x%02x\n",
					pdp->nsapi, pdp_status[1], pdp_status[0]);
				sgsn_delete_pdp_ctx(pdp);
			}
		} else {
			if (!(pdp_status[1] & (1 << (pdp->nsapi - 8)))) {
				LOGMMCTXP(LOGL_NOTICE, mmctx, "Dropping PDP context for NSAPI=%u "
					"due to PDP CTX STATUS IE= 0x%02x%02x\n",
					pdp->nsapi, pdp_status[1], pdp_status[0]);
				sgsn_delete_pdp_ctx(pdp);
			}
		}
	}
}

/* Chapter 9.4.14: Routing area update request */
static int gsm48_rx_gmm_ra_upd_req(struct sgsn_mm_ctx *mmctx, struct msgb *msg,
				   struct gprs_llc_llme *llme)
{
#ifndef PTMSI_ALLOC
	struct sgsn_signal_data sig_data;
#endif
	struct gsm48_hdr *gh = (struct gsm48_hdr *) msgb_gmmh(msg);
	uint8_t *cur = gh->data;
	uint8_t ms_ra_acc_cap_len;
	struct gprs_ra_id old_ra_id;
	struct tlv_parsed tp;
	uint8_t upd_type;
	enum gsm48_gmm_cause reject_cause = GMM_CAUSE_PROTO_ERR_UNSPEC;
	int rc;

	/* TODO: In iu mode - handle follow-on request */

	/* Update Type 10.5.5.18 */
	upd_type = *cur++ & 0x07;

	rate_ctr_inc(&sgsn->rate_ctrs->ctr[CTR_GPRS_ROUTING_AREA_REQUEST]);
	LOGP(DMM, LOGL_INFO, "-> GMM RA UPDATE REQUEST type=\"%s\"\n",
		get_value_string(gprs_upd_t_strs, upd_type));

	/* Old routing area identification 10.5.5.15 */
	gsm48_parse_ra(&old_ra_id, cur);
	cur += 6;

	/* MS Radio Access Capability 10.5.5.12a */
	ms_ra_acc_cap_len = *cur++;
	if (ms_ra_acc_cap_len > 52) {
		reject_cause = GMM_CAUSE_PROTO_ERR_UNSPEC;
		goto rejected;
	}
	cur += ms_ra_acc_cap_len;

	/* Optional: Old P-TMSI Signature, Requested READY timer, TMSI Status,
	 * DRX parameter, MS network capability */
	tlv_parse(&tp, &gsm48_gmm_att_tlvdef, cur,
			(msg->data + msg->len) - cur, 0, 0);

	switch (upd_type) {
	case GPRS_UPD_T_RA_LA:
	case GPRS_UPD_T_RA_LA_IMSI_ATT:
		LOGP(DMM, LOGL_NOTICE, "Update type %i unsupported in Mode III, is your SI13 corrupt?\n", upd_type);
		reject_cause = GMM_CAUSE_PROTO_ERR_UNSPEC;
		goto rejected;
	case GPRS_UPD_T_RA:
	case GPRS_UPD_T_PERIODIC:
		break;
	}

	if (!mmctx) {
		/* BSSGP doesn't give us an mmctx */

		/* TODO: Check if there is an MM CTX with old_ra_id and
		 * the P-TMSI (if given, reguired for UMTS) or as last resort
		 * if the TLLI matches foreign_tlli (P-TMSI). Note that this
		 * is an optimization to avoid the RA reject (impl detached)
		 * below, which will cause a new attach cycle. */
		/* Look-up the MM context based on old RA-ID and TLLI */
		/* In Iu mode, msg->dst contains the ue_conn_ctx pointer, in Gb
		 * mode dst is empty. */
		/* FIXME: have a more explicit indicator for Iu messages */
		if (!msg->dst) {
			mmctx = sgsn_mm_ctx_by_tlli_and_ptmsi(msgb_tlli(msg), &old_ra_id);
		} else if (TLVP_PRESENT(&tp, GSM48_IE_GMM_ALLOC_PTMSI)) {
#ifdef BUILD_IU
			/* In Iu mode search only for ptmsi */
			char mi_string[GSM48_MI_SIZE];
			uint8_t mi_len = TLVP_LEN(&tp, GSM48_IE_GMM_ALLOC_PTMSI);
			uint8_t *mi = TLVP_VAL(&tp, GSM48_IE_GMM_ALLOC_PTMSI);
			uint8_t mi_type = *mi & GSM_MI_TYPE_MASK;
			uint32_t tmsi;

			gsm48_mi_to_string(mi_string, sizeof(mi_string), mi, mi_len);

			if (mi_type == GSM_MI_TYPE_TMSI) {
				memcpy(&tmsi, mi+1, 4);
				tmsi = ntohl(tmsi);
				mmctx = sgsn_mm_ctx_by_ptmsi(tmsi);
			}
#else
			goto rejected;
#endif
		}
		if (mmctx) {
			LOGMMCTXP(LOGL_INFO, mmctx,
				"Looked up by matching TLLI and P_TMSI. "
				"BSSGP TLLI: %08x, P-TMSI: %08x (%08x), "
				"TLLI: %08x (%08x), RA: %d-%d-%d-%d\n",
				msgb_tlli(msg),
				mmctx->p_tmsi, mmctx->p_tmsi_old,
				mmctx->gb.tlli, mmctx->gb.tlli_new,
				mmctx->ra.mcc, mmctx->ra.mnc,
				mmctx->ra.lac, mmctx->ra.rac);

			mmctx->gmm_state = GMM_COMMON_PROC_INIT;
		}
	} else if (!gprs_ra_id_equals(&mmctx->ra, &old_ra_id) ||
		mmctx->gmm_state == GMM_DEREGISTERED)
	{
		/* We cannot use the mmctx */
		LOGMMCTXP(LOGL_INFO, mmctx,
			"The MM context cannot be used, RA: %d-%d-%d-%d\n",
			mmctx->ra.mcc, mmctx->ra.mnc,
			mmctx->ra.lac, mmctx->ra.rac);
		mmctx = NULL;
	}

	if (!mmctx) {
		if (llme) {
			/* send a XID reset to re-set all LLC sequence numbers
			 * in the MS */
			LOGMMCTXP(LOGL_NOTICE, mmctx, "LLC XID RESET\n");
			gprs_llgmm_reset(llme);
		}
		/* The MS has to perform GPRS attach */
		/* Device is still IMSI attached for CS but initiate GPRS ATTACH,
		 * see GSM 04.08, 4.7.5.1.4 and G.6 */
		reject_cause = GMM_CAUSE_IMPL_DETACHED;
		goto rejected;
	}

	/* Store new BVCI/NSEI in MM context (FIXME: delay until we ack?) */
	msgid2mmctx(mmctx, msg);
	/* Bump the statistics of received signalling msgs for this MM context */
	rate_ctr_inc(&mmctx->ctrg->ctr[GMM_CTR_PKTS_SIG_IN]);

	/* Update the MM context with the new RA-ID */
	if (mmctx->ran_type == MM_CTX_T_GERAN_Gb) {
		bssgp_parse_cell_id(&mmctx->ra, msgb_bcid(msg));
		/* Update the MM context with the new (i.e. foreign) TLLI */
		mmctx->gb.tlli = msgb_tlli(msg);
	}
	/* FIXME: Update the MM context with the MS radio acc capabilities */
	/* FIXME: Update the MM context with the MS network capabilities */

	rate_ctr_inc(&mmctx->ctrg->ctr[GMM_CTR_RA_UPDATE]);

#ifdef PTMSI_ALLOC
	/* Don't change the P-TMSI if a P-TMSI re-assignment is under way */
	if (mmctx->gmm_state != GMM_COMMON_PROC_INIT) {
		mmctx->p_tmsi_old = mmctx->p_tmsi;
		mmctx->p_tmsi = sgsn_alloc_ptmsi();
	}
	/* Start T3350 and re-transmit up to 5 times until ATTACH COMPLETE */
	mmctx->t3350_mode = GMM_T3350_MODE_RAU;
	mmctx_timer_start(mmctx, 3350, sgsn->cfg.timers.T3350);

	mmctx->gmm_state = GMM_COMMON_PROC_INIT;
#else
	/* Make sure we are NORMAL (i.e. not SUSPENDED anymore) */
	mmctx->gmm_state = GMM_REGISTERED_NORMAL;

	memset(&sig_data, 0, sizeof(sig_data));
	sig_data.mm = mmctx;
	osmo_signal_dispatch(SS_SGSN, S_SGSN_UPDATE, &sig_data);
#endif
	if (mmctx->ran_type == MM_CTX_T_GERAN_Gb) {
		/* Even if there is no P-TMSI allocated, the MS will switch from
	 	* foreign TLLI to local TLLI */
		mmctx->gb.tlli_new = gprs_tmsi2tlli(mmctx->p_tmsi, TLLI_LOCAL);

		/* Inform LLC layer about new TLLI but keep old active */
		gprs_llgmm_assign(mmctx->gb.llme, mmctx->gb.tlli,
				  mmctx->gb.tlli_new);
	}

	/* Look at PDP Context Status IE and see if MS's view of
	 * activated/deactivated NSAPIs agrees with our view */
	if (TLVP_PRESENT(&tp, GSM48_IE_GMM_PDP_CTX_STATUS)) {
		const uint8_t *pdp_status = TLVP_VAL(&tp, GSM48_IE_GMM_PDP_CTX_STATUS);
		process_ms_ctx_status(mmctx, pdp_status);
	}

	/* Send RA UPDATE ACCEPT. In Iu, the RA upd request can be called from
	 * a new Iu connection, so we might need to re-authenticate the
	 * connection as well as turn on integrity protection. */
	mmctx->pending_req = GSM48_MT_GMM_RA_UPD_REQ;
	return gsm48_gmm_authorize(mmctx);

rejected:
	/* Send RA UPDATE REJECT */
	LOGMMCTXP(LOGL_NOTICE, mmctx,
		  "Rejecting RA Update Request with cause '%s' (%d)\n",
		  get_value_string(gsm48_gmm_cause_names, reject_cause), reject_cause);
	rc = gsm48_tx_gmm_ra_upd_rej(msg, reject_cause);
	if (mmctx)
		mm_ctx_cleanup_free(mmctx, "GPRS RA UPDATE REJ");
	else {
		if (llme)
			gprs_llgmm_unassign(llme);
	}

	return rc;
}

/* 3GPP TS 24.008 Section 9.4.20 Service request.
 * In Iu, a UE in PMM-IDLE mode can use GSM48_MT_GMM_SERVICE_REQ to switch back
 * to PMM-CONNECTED mode. */
static int gsm48_rx_gmm_service_req(struct sgsn_mm_ctx *ctx, struct msgb *msg)
{
	struct gsm48_hdr *gh = (struct gsm48_hdr *) msgb_gmmh(msg);
	uint8_t *cur = gh->data, *mi;
	uint8_t ciph_seq_nr, service_type, mi_len, mi_type;
	uint32_t tmsi;
	struct tlv_parsed tp;
	char mi_string[GSM48_MI_SIZE];
	enum gsm48_gmm_cause reject_cause;
	int rc;

	LOGMMCTXP(LOGL_INFO, ctx, "-> GMM SERVICE REQUEST ");

	/* This message is only valid in Iu mode */
	if (!msg->dst) {
		LOGPC(DMM, LOGL_INFO, "Invalid if not in Iu mode\n");
		return -1;
	}

	/* Skip Ciphering key sequence number 10.5.1.2 */
	ciph_seq_nr = *cur & 0x07;

	/* Service type 10.5.5.20 */
	service_type = (*cur++ >> 4) & 0x07;

	/* Mobile Identity (P-TMSI or IMSI) 10.5.1.4 */
	mi_len = *cur++;
	mi = cur;
	if (mi_len > 8)
		goto err_inval;
	mi_type = *mi & GSM_MI_TYPE_MASK;
	cur += mi_len;

	gsm48_mi_to_string(mi_string, sizeof(mi_string), mi, mi_len);

	DEBUGPC(DMM, "MI(%s) type=\"%s\" ", mi_string,
		get_value_string(gprs_service_t_strs, service_type));

	LOGPC(DMM, LOGL_INFO, "\n");

	/* Optional: PDP context status, MBMS context status, Uplink data status, Device properties */
	tlv_parse(&tp, &gsm48_gmm_att_tlvdef, cur, (msg->data + msg->len) - cur, 0, 0);

	switch (mi_type) {
	case GSM_MI_TYPE_IMSI:
		/* Try to find MM context based on IMSI */
		if (!ctx)
			ctx = sgsn_mm_ctx_by_imsi(mi_string);
		if (!ctx) {
			/* FIXME: We need to have a context for service request? */
			reject_cause = GMM_CAUSE_NET_FAIL;
			goto rejected;
		}
		msgid2mmctx(ctx, msg);
		break;
	case GSM_MI_TYPE_TMSI:
		memcpy(&tmsi, mi+1, 4);
		tmsi = ntohl(tmsi);
		/* Try to find MM context based on P-TMSI */
		if (!ctx)
			ctx = sgsn_mm_ctx_by_ptmsi(tmsi);
		if (!ctx) {
			/* FIXME: We need to have a context for service request? */
			reject_cause = GMM_CAUSE_NET_FAIL;
			goto rejected;
		}
		msgid2mmctx(ctx, msg);
		break;
	default:
		LOGMMCTXP(LOGL_NOTICE, ctx, "Rejecting SERVICE REQUEST with "
			"MI type %s\n", gsm48_mi_type_name(mi_type));
		reject_cause = GMM_CAUSE_MS_ID_NOT_DERIVED;
		goto rejected;
	}

	ctx->gmm_state = GMM_COMMON_PROC_INIT;

	ctx->iu.service.type = service_type;

	/* TODO: Handle those only in case of accept? */
	/* Look at PDP Context Status IE and see if MS's view of
	 * activated/deactivated NSAPIs agrees with our view */
	if (TLVP_PRESENT(&tp, GSM48_IE_GMM_PDP_CTX_STATUS)) {
		const uint8_t *pdp_status = TLVP_VAL(&tp, GSM48_IE_GMM_PDP_CTX_STATUS);
		process_ms_ctx_status(ctx, pdp_status);
	}


	ctx->pending_req = GSM48_MT_GMM_SERVICE_REQ;
	return gsm48_gmm_authorize(ctx);

err_inval:
	LOGPC(DMM, LOGL_INFO, "\n");
	reject_cause = GMM_CAUSE_SEM_INCORR_MSG;

rejected:
	/* Send SERVICE REJECT */
	LOGMMCTXP(LOGL_NOTICE, ctx,
		  "Rejecting Service Request with cause '%s' (%d)\n",
		  get_value_string(gsm48_gmm_cause_names, reject_cause), reject_cause);
	rc = gsm48_tx_gmm_service_rej_oldmsg(msg, reject_cause);

	return rc;

}


static int gsm48_rx_gmm_status(struct sgsn_mm_ctx *mmctx, struct msgb *msg)
{
	struct gsm48_hdr *gh = msgb_l3(msg);

	LOGMMCTXP(LOGL_INFO, mmctx, "-> GPRS MM STATUS (cause: %s)\n",
		get_value_string(gsm48_gmm_cause_names, gh->data[0]));

	return 0;
}

/* GPRS Mobility Management */
static int gsm0408_rcv_gmm(struct sgsn_mm_ctx *mmctx, struct msgb *msg,
			   struct gprs_llc_llme *llme, bool drop_cipherable)
{
	struct sgsn_signal_data sig_data;
	struct gsm48_hdr *gh = (struct gsm48_hdr *) msgb_gmmh(msg);
	int rc;

	/* MMCTX can be NULL when called */
	if (drop_cipherable && gsm48_hdr_gmm_cipherable(gh)) {
		LOGMMCTXP(LOGL_NOTICE, mmctx, "Dropping cleartext GMM %s which "
			  "is expected to be encrypted for TLLI 0x%08x\n",
			  get_value_string(gprs_msgt_gmm_names, gh->msg_type),
			  llme->tlli);
		return -EBADMSG;
	}

	if (llme && !mmctx &&
	    gh->msg_type != GSM48_MT_GMM_ATTACH_REQ &&
	    gh->msg_type != GSM48_MT_GMM_RA_UPD_REQ) {
		LOGP(DMM, LOGL_NOTICE, "Cannot handle GMM for unknown MM CTX\n");
		/* 4.7.10 */
		if (gh->msg_type == GSM48_MT_GMM_STATUS) {
			/* TLLI unassignment */
			gprs_llgmm_unassign(llme);
			return 0;
		}

		/* Don't reply or establish a LLME on DETACH_ACK */
		if (gh->msg_type == GSM48_MT_GMM_DETACH_ACK)
			return gprs_llgmm_unassign(llme);

		gprs_llgmm_reset(llme);

		/* Don't force it into re-attachment */
		if (gh->msg_type == GSM48_MT_GMM_DETACH_REQ) {
			/* Handle Detach Request */
			rc = gsm48_rx_gmm_det_req(NULL, msg);

			/* TLLI unassignment */
			gprs_llgmm_unassign(llme);
			return rc;
		}

		/* Force the MS to re-attach */
		rc = gsm0408_gprs_force_reattach_oldmsg(msg, llme);

		/* TLLI unassignment */
		gprs_llgmm_unassign(llme);
		return rc;
	}

	/*
	 * For a few messages, mmctx may be NULL. For most, we want to ensure a
	 * non-NULL mmctx. At the same time, we want to keep the message
	 * validity check intact, so that all message types appear in the
	 * switch statement and the default case thus means "unknown message".
	 * If we split the switch in two parts to check non-NULL halfway, the
	 * unknown-message check breaks, or we'd need to duplicate the switch
	 * cases in both parts. Just keep one large switch and add some gotos.
	 */
	switch (gh->msg_type) {
	case GSM48_MT_GMM_RA_UPD_REQ:
		rc = gsm48_rx_gmm_ra_upd_req(mmctx, msg, llme);
		break;
	case GSM48_MT_GMM_ATTACH_REQ:
		rc = gsm48_rx_gmm_att_req(mmctx, msg, llme);
		break;
	case GSM48_MT_GMM_SERVICE_REQ:
		rc = gsm48_rx_gmm_service_req(mmctx, msg);
		break;
	/* For all the following types mmctx can not be NULL */
	case GSM48_MT_GMM_ID_RESP:
		if (!mmctx)
			goto null_mmctx;
		rc = gsm48_rx_gmm_id_resp(mmctx, msg);
		break;
	case GSM48_MT_GMM_STATUS:
		if (!mmctx)
			goto null_mmctx;
		rc = gsm48_rx_gmm_status(mmctx, msg);
		break;
	case GSM48_MT_GMM_DETACH_REQ:
		if (!mmctx)
			goto null_mmctx;
		rc = gsm48_rx_gmm_det_req(mmctx, msg);
		break;
	case GSM48_MT_GMM_DETACH_ACK:
		if (!mmctx)
			goto null_mmctx;
		LOGMMCTXP(LOGL_INFO, mmctx, "-> DETACH ACK\n");
		mm_ctx_cleanup_free(mmctx, "GPRS DETACH ACK");
		rc = 0;
		break;
	case GSM48_MT_GMM_ATTACH_COMPL:
		if (!mmctx)
			goto null_mmctx;
		/* only in case SGSN offered new P-TMSI */
		LOGMMCTXP(LOGL_INFO, mmctx, "-> ATTACH COMPLETE\n");
		mmctx_timer_stop(mmctx, 3350);
		mmctx->t3350_mode = GMM_T3350_MODE_NONE;
		mmctx->p_tmsi_old = 0;
		mmctx->pending_req = 0;
		if (mmctx->ran_type == MM_CTX_T_GERAN_Gb) {
			/* Unassign the old TLLI */
			mmctx->gb.tlli = mmctx->gb.tlli_new;
			gprs_llme_copy_key(mmctx, mmctx->gb.llme);
			gprs_llgmm_assign(mmctx->gb.llme, 0xffffffff,
					  mmctx->gb.tlli_new);
		}
		mmctx->gmm_state = GMM_REGISTERED_NORMAL;
		mmctx_set_pmm_state(mmctx, PMM_CONNECTED);
		mmctx_set_mm_state(mmctx, MM_READY);
		rc = 0;

		memset(&sig_data, 0, sizeof(sig_data));
		sig_data.mm = mmctx;
		osmo_signal_dispatch(SS_SGSN, S_SGSN_ATTACH, &sig_data);
		break;
	case GSM48_MT_GMM_RA_UPD_COMPL:
		if (!mmctx)
			goto null_mmctx;
		/* only in case SGSN offered new P-TMSI */
		LOGMMCTXP(LOGL_INFO, mmctx, "-> ROUTING AREA UPDATE COMPLETE\n");
		mmctx_timer_stop(mmctx, 3350);
		mmctx->t3350_mode = GMM_T3350_MODE_NONE;
		mmctx->p_tmsi_old = 0;
		mmctx->pending_req = 0;
		if (mmctx->ran_type == MM_CTX_T_GERAN_Gb) {
			/* Unassign the old TLLI */
			mmctx->gb.tlli = mmctx->gb.tlli_new;
			gprs_llgmm_assign(mmctx->gb.llme, 0xffffffff,
					  mmctx->gb.tlli_new);
		}
		mmctx->gmm_state = GMM_REGISTERED_NORMAL;
		mmctx_set_pmm_state(mmctx, PMM_CONNECTED);
		mmctx_set_mm_state(mmctx, MM_READY);
		rc = 0;

		memset(&sig_data, 0, sizeof(sig_data));
		sig_data.mm = mmctx;
		osmo_signal_dispatch(SS_SGSN, S_SGSN_UPDATE, &sig_data);
		break;
	case GSM48_MT_GMM_PTMSI_REALL_COMPL:
		if (!mmctx)
			goto null_mmctx;
		LOGMMCTXP(LOGL_INFO, mmctx, "-> PTMSI REALLLICATION COMPLETE\n");
		mmctx_timer_stop(mmctx, 3350);
		mmctx->t3350_mode = GMM_T3350_MODE_NONE;
		mmctx->p_tmsi_old = 0;
		mmctx->pending_req = 0;
		if (mmctx->ran_type == MM_CTX_T_GERAN_Gb) {
			/* Unassign the old TLLI */
			mmctx->gb.tlli = mmctx->gb.tlli_new;
			//gprs_llgmm_assign(mmctx->gb.llme, 0xffffffff, mmctx->gb.tlli_new, GPRS_ALGO_GEA0, NULL);
		}
		rc = 0;
		break;
	case GSM48_MT_GMM_AUTH_CIPH_RESP:
		if (!mmctx)
			goto null_mmctx;
		rc = gsm48_rx_gmm_auth_ciph_resp(mmctx, msg);
		break;
	case GSM48_MT_GMM_AUTH_CIPH_FAIL:
		rc = gsm48_rx_gmm_auth_ciph_fail(mmctx, msg);
		break;
	default:
		LOGMMCTXP(LOGL_NOTICE, mmctx, "Unknown GSM 04.08 GMM msg type 0x%02x\n",
			gh->msg_type);
		if (mmctx)
			rc = gsm48_tx_gmm_status(mmctx, GMM_CAUSE_MSGT_NOTEXIST_NOTIMPL);
		else
			rc = -EINVAL;
		break;
	}

	return rc;

null_mmctx:
	LOGP(DMM, LOGL_ERROR,
	     "Received GSM 04.08 message type 0x%02x,"
	     " but no MM context available\n",
	     gh->msg_type);
	return -EINVAL;
}

static void mmctx_timer_cb(void *_mm)
{
	struct sgsn_mm_ctx *mm = _mm;
	struct gsm_auth_tuple *at;

	mm->num_T_exp++;

	switch (mm->T) {
	case 3350:	/* waiting for ATTACH COMPLETE */
		if (mm->num_T_exp >= 5) {
			LOGMMCTXP(LOGL_NOTICE, mm, "T3350 expired >= 5 times\n");
			mm_ctx_cleanup_free(mm, "T3350");
			/* FIXME: should we return some error? */
			break;
		}
		/* re-transmit the respective msg and re-start timer */
		switch (mm->t3350_mode) {
		case GMM_T3350_MODE_ATT:
			gsm48_tx_gmm_att_ack(mm);
			break;
		case GMM_T3350_MODE_RAU:
			gsm48_tx_gmm_ra_upd_ack(mm);
			break;
		case GMM_T3350_MODE_PTMSI_REALL:
			/* FIXME */
			break;
		case GMM_T3350_MODE_NONE:
			LOGMMCTXP(LOGL_NOTICE, mm,
				  "T3350 mode wasn't set, ignoring timeout\n");
			break;
		}
		osmo_timer_schedule(&mm->timer, sgsn->cfg.timers.T3350, 0);
		break;
	case 3360:	/* waiting for AUTH AND CIPH RESP */
		if (mm->num_T_exp >= 5) {
			LOGMMCTXP(LOGL_NOTICE, mm, "T3360 expired >= 5 times\n");
			mm_ctx_cleanup_free(mm, "T3360");
			break;
		}
		/* Re-transmit the respective msg and re-start timer */
		if (mm->auth_triplet.key_seq == GSM_KEY_SEQ_INVAL) {
			LOGMMCTXP(LOGL_ERROR, mm,
				  "timeout: invalid auth triplet reference\n");
			mm_ctx_cleanup_free(mm, "T3360");
			break;
		}
		at = &mm->auth_triplet;

		gsm48_tx_gmm_auth_ciph_req(mm, &at->vec, at->key_seq, false);
		osmo_timer_schedule(&mm->timer, sgsn->cfg.timers.T3360, 0);
		break;
	case 3370:	/* waiting for IDENTITY RESPONSE */
		if (mm->num_T_exp >= 5) {
			LOGMMCTXP(LOGL_NOTICE, mm, "T3370 expired >= 5 times\n");
			gsm48_tx_gmm_att_rej(mm, GMM_CAUSE_MS_ID_NOT_DERIVED);
			mm_ctx_cleanup_free(mm, "GPRS ATTACH REJECT (T3370)");
			break;
		}
		/* re-tranmit IDENTITY REQUEST and re-start timer */
		gsm48_tx_gmm_id_req(mm, mm->t3370_id_type);
		osmo_timer_schedule(&mm->timer, sgsn->cfg.timers.T3370, 0);
		break;
	default:
		LOGMMCTXP(LOGL_ERROR, mm, "timer expired in unknown mode %u\n",
			mm->T);
	}
}

/* GPRS SESSION MANAGEMENT */

static void pdpctx_timer_cb(void *_mm);

static void pdpctx_timer_start(struct sgsn_pdp_ctx *pdp, unsigned int T,
				unsigned int seconds)
{
	if (osmo_timer_pending(&pdp->timer))
		LOGPDPCTXP(LOGL_ERROR, pdp, "Starting PDP timer %u while old "
			"timer %u pending\n", T, pdp->T);
	pdp->T = T;
	pdp->num_T_exp = 0;

	/* FIXME: we should do this only once ? */
	osmo_timer_setup(&pdp->timer, pdpctx_timer_cb, pdp);
	osmo_timer_schedule(&pdp->timer, seconds, 0);
}

static void pdpctx_timer_stop(struct sgsn_pdp_ctx *pdp, unsigned int T)
{
	if (pdp->T != T)
		LOGPDPCTXP(LOGL_ERROR, pdp, "Stopping PDP timer %u but "
			"%u is running\n", T, pdp->T);
	osmo_timer_del(&pdp->timer);
}

#if 0
static void msgb_put_pdp_addr_ipv4(struct msgb *msg, uint32_t ipaddr)
{
	uint8_t v[6];

	v[0] = PDP_TYPE_ORG_IETF;
	v[1] = PDP_TYPE_N_IETF_IPv4;
	*(uint32_t *)(v+2) = htonl(ipaddr);

	msgb_tlv_put(msg, GSM48_IE_GSM_PDP_ADDR, sizeof(v), v);
}

static void msgb_put_pdp_addr_ppp(struct msgb *msg)
{
	uint8_t v[2];

	v[0] = PDP_TYPE_ORG_ETSI;
	v[1] = PDP_TYPE_N_ETSI_PPP;

	msgb_tlv_put(msg, GSM48_IE_GSM_PDP_ADDR, sizeof(v), v);
}
#endif

/* Section 9.5.2: Activate PDP Context Accept */
int gsm48_tx_gsm_act_pdp_acc(struct sgsn_pdp_ctx *pdp)
{
	struct msgb *msg = gsm48_msgb_alloc_name("GSM 04.08 PDP ACC");
	struct gsm48_hdr *gh;
	uint8_t transaction_id = pdp->ti ^ 0x8; /* flip */

	LOGPDPCTXP(LOGL_INFO, pdp, "<- ACTIVATE PDP CONTEXT ACK\n");
	rate_ctr_inc(&sgsn->rate_ctrs->ctr[CTR_PDP_ACTIVATE_ACCEPT]);

	mmctx2msgid(msg, pdp->mm);

	gh = (struct gsm48_hdr *) msgb_put(msg, sizeof(*gh));
	gh->proto_discr = GSM48_PDISC_SM_GPRS | (transaction_id << 4);
	gh->msg_type = GSM48_MT_GSM_ACT_PDP_ACK;

	/* Negotiated LLC SAPI */
	msgb_v_put(msg, pdp->sapi);

	/* FIXME: copy QoS parameters from original request */
	//msgb_lv_put(msg, pdp->lib->qos_neg.l, pdp->lib->qos_neg.v);
	msgb_lv_put(msg, sizeof(default_qos), (uint8_t *)&default_qos);

	/* Radio priority 10.5.7.2 */
	msgb_v_put(msg, pdp->lib->radio_pri);

	/* PDP address */
	/* Highest 4 bits of first byte need to be set to 1, otherwise
	 * the IE is identical with the 04.08 PDP Address IE */
	pdp->lib->eua.v[0] &= ~0xf0;
	msgb_tlv_put(msg, GSM48_IE_GSM_PDP_ADDR,
		     pdp->lib->eua.l, pdp->lib->eua.v);
	pdp->lib->eua.v[0] |= 0xf0;

	/* Optional: Protocol configuration options (FIXME: why 'req') */
	if (pdp->lib->pco_req.l)
		msgb_tlv_put(msg, GSM48_IE_GSM_PROTO_CONF_OPT,
			     pdp->lib->pco_req.l, pdp->lib->pco_req.v);

	/* Optional: Packet Flow Identifier */

	return gsm48_gmm_sendmsg(msg, 0, pdp->mm, true);
}

/* Section 9.5.3: Activate PDP Context reject */
int gsm48_tx_gsm_act_pdp_rej(struct sgsn_mm_ctx *mm, uint8_t tid,
			     uint8_t cause, uint8_t pco_len, uint8_t *pco_v)
{
	struct msgb *msg = gsm48_msgb_alloc_name("GSM 04.08 PDP REJ");
	struct gsm48_hdr *gh;
	uint8_t transaction_id = tid ^ 0x8; /* flip */

	LOGMMCTXP(LOGL_NOTICE, mm, "<- ACTIVATE PDP CONTEXT REJ(cause=%u)\n", cause);
	rate_ctr_inc(&sgsn->rate_ctrs->ctr[CTR_PDP_ACTIVATE_REJECT]);

	mmctx2msgid(msg, mm);

	gh = (struct gsm48_hdr *) msgb_put(msg, sizeof(*gh));
	gh->proto_discr = GSM48_PDISC_SM_GPRS | (transaction_id << 4);
	gh->msg_type = GSM48_MT_GSM_ACT_PDP_REJ;

	msgb_v_put(msg, cause);
	if (pco_len && pco_v)
		msgb_tlv_put(msg, GSM48_IE_GSM_PROTO_CONF_OPT, pco_len, pco_v);

	return gsm48_gmm_sendmsg(msg, 0, mm, true);
}

/* Section 9.5.8: Deactivate PDP Context Request */
static int _gsm48_tx_gsm_deact_pdp_req(struct sgsn_mm_ctx *mm, uint8_t tid,
					uint8_t sm_cause)
{
	struct msgb *msg = gsm48_msgb_alloc_name("GSM 04.08 PDP DET REQ");
	struct gsm48_hdr *gh;
	uint8_t transaction_id = tid ^ 0x8; /* flip */

	LOGMMCTXP(LOGL_INFO, mm, "<- DEACTIVATE PDP CONTEXT REQ\n");
	rate_ctr_inc(&sgsn->rate_ctrs->ctr[CTR_PDP_DL_DEACTIVATE_REQUEST]);

	mmctx2msgid(msg, mm);

	gh = (struct gsm48_hdr *) msgb_put(msg, sizeof(*gh));
	gh->proto_discr = GSM48_PDISC_SM_GPRS | (transaction_id << 4);
	gh->msg_type = GSM48_MT_GSM_DEACT_PDP_REQ;

	msgb_v_put(msg, sm_cause);

	return gsm48_gmm_sendmsg(msg, 0, mm, true);
}
int gsm48_tx_gsm_deact_pdp_req(struct sgsn_pdp_ctx *pdp, uint8_t sm_cause)
{
	pdpctx_timer_start(pdp, 3395, sgsn->cfg.timers.T3395);

	return _gsm48_tx_gsm_deact_pdp_req(pdp->mm, pdp->ti, sm_cause);
}

/* Section 9.5.9: Deactivate PDP Context Accept */
static int _gsm48_tx_gsm_deact_pdp_acc(struct sgsn_mm_ctx *mm, uint8_t tid)
{
	struct msgb *msg = gsm48_msgb_alloc_name("GSM 04.08 PDP DET ACC");
	struct gsm48_hdr *gh;
	uint8_t transaction_id = tid ^ 0x8; /* flip */

	LOGMMCTXP(LOGL_INFO, mm, "<- DEACTIVATE PDP CONTEXT ACK\n");
	rate_ctr_inc(&sgsn->rate_ctrs->ctr[CTR_PDP_DL_DEACTIVATE_ACCEPT]);

	mmctx2msgid(msg, mm);

	gh = (struct gsm48_hdr *) msgb_put(msg, sizeof(*gh));
	gh->proto_discr = GSM48_PDISC_SM_GPRS | (transaction_id << 4);
	gh->msg_type = GSM48_MT_GSM_DEACT_PDP_ACK;

	return gsm48_gmm_sendmsg(msg, 0, mm, true);
}
int gsm48_tx_gsm_deact_pdp_acc(struct sgsn_pdp_ctx *pdp)
{
	return _gsm48_tx_gsm_deact_pdp_acc(pdp->mm, pdp->ti);
}

static int activate_ggsn(struct sgsn_mm_ctx *mmctx,
		struct sgsn_ggsn_ctx *ggsn, const uint8_t transaction_id,
		const uint8_t req_nsapi, const uint8_t req_llc_sapi,
		struct tlv_parsed *tp, int destroy_ggsn)
{
	struct sgsn_pdp_ctx *pdp;

	LOGMMCTXP(LOGL_DEBUG, mmctx, "Using GGSN %u\n", ggsn->id);
	ggsn->gsn = sgsn->gsn;
	pdp = sgsn_create_pdp_ctx(ggsn, mmctx, req_nsapi, tp);
	if (!pdp)
		return -1;

	/* Store SAPI and Transaction Identifier */
	pdp->sapi = req_llc_sapi;
	pdp->ti = transaction_id;
	pdp->destroy_ggsn = destroy_ggsn;

	return 0;
}

static void ggsn_lookup_cb(void *arg, int status, int timeouts, struct hostent *hostent)
{
	struct sgsn_ggsn_ctx *ggsn;
	struct sgsn_ggsn_lookup *lookup = arg;
	struct in_addr *addr = NULL;

	/* The context is gone while we made a request */
	if (!lookup->mmctx) {
		talloc_free(lookup->orig_msg);
		talloc_free(lookup);
		return;
	}

	if (status != ARES_SUCCESS) {
		struct sgsn_mm_ctx *mmctx = lookup->mmctx;

		LOGMMCTXP(LOGL_ERROR, mmctx, "DNS query failed.\n");

		/* Need to try with three digits now */
		if (lookup->state == SGSN_GGSN_2DIGIT) {
			char *hostname;
			int rc;

			lookup->state = SGSN_GGSN_3DIGIT;
			hostname = osmo_apn_qualify_from_imsi(mmctx->imsi,
					lookup->apn_str, 1);
			LOGMMCTXP(LOGL_DEBUG, mmctx,
				"Going to query %s\n", hostname);
			rc = sgsn_ares_query(sgsn, hostname,
					ggsn_lookup_cb, lookup);
			if (rc != 0) {
				LOGMMCTXP(LOGL_ERROR, mmctx, "Couldn't start GGSN\n");
				goto reject_due_failure;
			}
			return;
		}

		LOGMMCTXP(LOGL_ERROR, mmctx, "Couldn't resolve GGSN\n");
		goto reject_due_failure;
	}

	if (hostent->h_length != sizeof(struct in_addr)) {
		LOGMMCTXP(LOGL_ERROR, lookup->mmctx,
			"Wrong addr size(%zu)\n", sizeof(struct in_addr));
		goto reject_due_failure;
	}

	/* Get the first addr from the list */
	addr = (struct in_addr *) hostent->h_addr_list[0];
	if (!addr) {
		LOGMMCTXP(LOGL_ERROR, lookup->mmctx, "No host address.\n");
		goto reject_due_failure;
	}

	ggsn = sgsn_ggsn_ctx_alloc(UINT32_MAX);
	if (!ggsn) {
		LOGMMCTXP(LOGL_ERROR, lookup->mmctx, "Failed to create ggsn.\n");
		goto reject_due_failure;
	}
	ggsn->remote_addr = *addr;
	LOGMMCTXP(LOGL_NOTICE, lookup->mmctx,
		"Selected %s as GGSN.\n", inet_ntoa(*addr));

	/* forget about the ggsn look-up */
	lookup->mmctx->ggsn_lookup = NULL;

	activate_ggsn(lookup->mmctx, ggsn, lookup->ti, lookup->nsapi,
			lookup->sapi, &lookup->tp, 1);

	/* Now free it */
	talloc_free(lookup->orig_msg);
	talloc_free(lookup);
	return;

reject_due_failure:
	gsm48_tx_gsm_act_pdp_rej(lookup->mmctx, lookup->ti,
				GMM_CAUSE_NET_FAIL, 0, NULL);
	lookup->mmctx->ggsn_lookup = NULL;
	talloc_free(lookup->orig_msg);
	talloc_free(lookup);
}

static int do_act_pdp_req(struct sgsn_mm_ctx *mmctx, struct msgb *msg, bool *delete)
{
	struct gsm48_hdr *gh = (struct gsm48_hdr *) msgb_gmmh(msg);
	struct gsm48_act_pdp_ctx_req *act_req = (struct gsm48_act_pdp_ctx_req *) gh->data;
	uint8_t req_qos_len, req_pdpa_len;
	uint8_t *req_qos, *req_pdpa;
	struct tlv_parsed tp;
	uint8_t transaction_id = gsm48_hdr_trans_id(gh);
	struct sgsn_ggsn_ctx *ggsn;
	struct sgsn_pdp_ctx *pdp;
	enum gsm48_gsm_cause gsm_cause;
	char apn_str[GSM_APN_LENGTH] = { 0, };
	char *hostname;
	int rc;
	struct gprs_llc_lle *lle;

	LOGMMCTXP(LOGL_INFO, mmctx, "-> ACTIVATE PDP CONTEXT REQ: SAPI=%u NSAPI=%u ",
		act_req->req_llc_sapi, act_req->req_nsapi);

	/* FIXME: length checks! */
	req_qos_len = act_req->data[0];
	req_qos = act_req->data + 1;	/* 10.5.6.5 */
	req_pdpa_len = act_req->data[1 + req_qos_len];
	req_pdpa = act_req->data + 1 + req_qos_len + 1;	/* 10.5.6.4 */

	switch (req_pdpa[0] & 0xf) {
	case 0x0:
		DEBUGPC(DMM, "ETSI ");
		break;
	case 0x1:
		DEBUGPC(DMM, "IETF ");
		break;
	case 0xf:
		DEBUGPC(DMM, "Empty ");
		break;
	}

	switch (req_pdpa[1]) {
	case 0x21:
		DEBUGPC(DMM, "IPv4 ");
		if (req_pdpa_len >= 6) {
			struct in_addr ia;
			ia.s_addr = ntohl(*((uint32_t *) (req_pdpa+2)));
			DEBUGPC(DMM, "%s ", inet_ntoa(ia));
		}
		break;
	case 0x57:
		DEBUGPC(DMM, "IPv6 ");
		if (req_pdpa_len >= 18) {
			/* FIXME: print IPv6 address */
		}
		break;
	default:	
		DEBUGPC(DMM, "0x%02x ", req_pdpa[1]);
		break;
	}

	LOGPC(DMM, LOGL_INFO, "\n");

	/* Check if NSAPI is out of range (TS 04.65 / 7.2) */
	if (act_req->req_nsapi < 5 || act_req->req_nsapi > 15) {
		/* Send reject with GSM_CAUSE_INV_MAND_INFO */
		return gsm48_tx_gsm_act_pdp_rej(mmctx, transaction_id,
						GSM_CAUSE_INV_MAND_INFO,
						0, NULL);
	}

	/* Optional: Access Point Name, Protocol Config Options */
	if (req_pdpa + req_pdpa_len < msg->data + msg->len)
		tlv_parse(&tp, &gsm48_sm_att_tlvdef, req_pdpa + req_pdpa_len,
			  (msg->data + msg->len) - (req_pdpa + req_pdpa_len), 0, 0);
	else
		memset(&tp, 0, sizeof(tp));


	/* put the non-TLV elements in the TLV parser structure to
	 * pass them on to the SGSN / GTP code */
	tp.lv[OSMO_IE_GSM_REQ_QOS].len = req_qos_len;
	tp.lv[OSMO_IE_GSM_REQ_QOS].val = req_qos;
	tp.lv[OSMO_IE_GSM_REQ_PDP_ADDR].len = req_pdpa_len;
	tp.lv[OSMO_IE_GSM_REQ_PDP_ADDR].val = req_pdpa;

	/* Check if NSAPI is already in use */
	pdp = sgsn_pdp_ctx_by_nsapi(mmctx, act_req->req_nsapi);
	if (pdp) {
		/* We already have a PDP context for this TLLI + NSAPI tuple */
		if (pdp->sapi == act_req->req_llc_sapi &&
		    pdp->ti == transaction_id) {
			/* This apparently is a re-transmission of a PDP CTX
			 * ACT REQ (our ACT ACK must have got dropped) */
			rc = gsm48_tx_gsm_act_pdp_acc(pdp);
			if (rc < 0)
				return rc;

			if (pdp->mm->ran_type == MM_CTX_T_GERAN_Gb) {
				/* Also re-transmit the SNDCP XID message */
				lle = &pdp->mm->gb.llme->lle[pdp->sapi];
				rc = sndcp_sn_xid_req(lle,pdp->nsapi);
				if (rc < 0)
					return rc;
			}

			return 0;
		}

		/* Send reject with GSM_CAUSE_NSAPI_IN_USE */
		return gsm48_tx_gsm_act_pdp_rej(mmctx, transaction_id,
						GSM_CAUSE_NSAPI_IN_USE,
						0, NULL);
	}

	if (mmctx->ggsn_lookup) {
		if (mmctx->ggsn_lookup->sapi == act_req->req_llc_sapi &&
			mmctx->ggsn_lookup->ti == transaction_id) {
			LOGMMCTXP(LOGL_NOTICE, mmctx,
				"Re-transmission while doing look-up. Ignoring.\n");
			return 0;
		}
	}

	/* Only increment counter for a real activation, after we checked
	 * for re-transmissions */
	rate_ctr_inc(&mmctx->ctrg->ctr[GMM_CTR_PDP_CTX_ACT]);

	/* Determine GGSN based on APN and subscription options */
	ggsn = sgsn_mm_ctx_find_ggsn_ctx(mmctx, &tp, &gsm_cause, apn_str);
	if (ggsn)
		return activate_ggsn(mmctx, ggsn, transaction_id,
				act_req->req_nsapi, act_req->req_llc_sapi,
				&tp, 0);

	if (strlen(apn_str) == 0)
		goto no_context;
	if (!sgsn->cfg.dynamic_lookup)
		goto no_context;

	/* schedule a dynamic look-up */
	mmctx->ggsn_lookup = talloc_zero(tall_bsc_ctx, struct sgsn_ggsn_lookup);
	if (!mmctx->ggsn_lookup)
		goto no_context;

	mmctx->ggsn_lookup->state = SGSN_GGSN_2DIGIT;
	mmctx->ggsn_lookup->mmctx = mmctx;
	strcpy(mmctx->ggsn_lookup->apn_str, apn_str);

	mmctx->ggsn_lookup->orig_msg = msg;
	mmctx->ggsn_lookup->tp = tp;

	mmctx->ggsn_lookup->ti = transaction_id;
	mmctx->ggsn_lookup->nsapi = act_req->req_nsapi;
	mmctx->ggsn_lookup->sapi = act_req->req_llc_sapi;

	hostname = osmo_apn_qualify_from_imsi(mmctx->imsi,
				mmctx->ggsn_lookup->apn_str, 0);

	LOGMMCTXP(LOGL_DEBUG, mmctx, "Going to query %s\n", hostname);
	rc = sgsn_ares_query(sgsn, hostname,
				ggsn_lookup_cb, mmctx->ggsn_lookup);
	if (rc != 0) {
		LOGMMCTXP(LOGL_ERROR, mmctx, "Failed to start ares query.\n");
		goto no_context;
	}
	*delete = 0;

	return 0;

no_context:
	LOGMMCTXP(LOGL_ERROR, mmctx, "No GGSN context found!\n");
	return gsm48_tx_gsm_act_pdp_rej(mmctx, transaction_id,
					gsm_cause, 0, NULL);
}

/* Section 9.5.1: Activate PDP Context Request */
static int gsm48_rx_gsm_act_pdp_req(struct sgsn_mm_ctx *mmctx,
				    struct msgb *_msg)
{
	bool delete = 1;
	struct msgb *msg;
	int rc;

	rate_ctr_inc(&sgsn->rate_ctrs->ctr[CTR_PDP_ACTIVATE_REQUEST]);

	/*
	 * This is painful. We might not have a static GGSN
	 * configuration and then would need to copy the msg
	 * and re-do most of this routine (or call it again
	 * and make sure it only goes through the dynamic
	 * resolving. The question is what to optimize for
	 * and the dynamic resolution will be the right thing
	 * in the long run.
	 */
	msg = gprs_msgb_copy(_msg, __func__);
	if (!msg) {
		struct gsm48_hdr *gh = (struct gsm48_hdr *) msgb_gmmh(_msg);
		uint8_t transaction_id = gsm48_hdr_trans_id(gh);

		LOGMMCTXP(LOGL_ERROR, mmctx, "-> ACTIVATE PDP CONTEXT REQ failed copy.\n");
		/* Send reject with GSM_CAUSE_INV_MAND_INFO */
		return gsm48_tx_gsm_act_pdp_rej(mmctx, transaction_id,
						GSM_CAUSE_NET_FAIL,
						0, NULL);
	}

	rc = do_act_pdp_req(mmctx, msg, &delete);
	if (delete)
		msgb_free(msg);
	return rc;
}

/* Section 9.5.8: Deactivate PDP Context Request */
static int gsm48_rx_gsm_deact_pdp_req(struct sgsn_mm_ctx *mm, struct msgb *msg)
{
	struct gsm48_hdr *gh = (struct gsm48_hdr *) msgb_gmmh(msg);
	uint8_t transaction_id = gsm48_hdr_trans_id(gh);
	struct sgsn_pdp_ctx *pdp;

	LOGMMCTXP(LOGL_INFO, mm, "-> DEACTIVATE PDP CONTEXT REQ (cause: %s)\n",
		get_value_string(gsm48_gsm_cause_names, gh->data[0]));
	rate_ctr_inc(&sgsn->rate_ctrs->ctr[CTR_PDP_UL_DEACTIVATE_REQUEST]);

	pdp = sgsn_pdp_ctx_by_tid(mm, transaction_id);
	if (!pdp) {
		LOGMMCTXP(LOGL_NOTICE, mm, "Deactivate PDP Context Request for "
			"non-existing PDP Context (IMSI=%s, TI=%u)\n",
			mm->imsi, transaction_id);
		return _gsm48_tx_gsm_deact_pdp_acc(mm, transaction_id);
	}

	return sgsn_delete_pdp_ctx(pdp);
}

/* Section 9.5.9: Deactivate PDP Context Accept */
static int gsm48_rx_gsm_deact_pdp_ack(struct sgsn_mm_ctx *mm, struct msgb *msg)
{
	struct gsm48_hdr *gh = (struct gsm48_hdr *) msgb_gmmh(msg);
	uint8_t transaction_id = gsm48_hdr_trans_id(gh);
	struct sgsn_pdp_ctx *pdp;

	LOGMMCTXP(LOGL_INFO, mm, "-> DEACTIVATE PDP CONTEXT ACK\n");
	rate_ctr_inc(&sgsn->rate_ctrs->ctr[CTR_PDP_UL_DEACTIVATE_ACCEPT]);

	pdp = sgsn_pdp_ctx_by_tid(mm, transaction_id);
	if (!pdp) {
		LOGMMCTXP(LOGL_NOTICE, mm, "Deactivate PDP Context Accept for "
			"non-existing PDP Context (IMSI=%s, TI=%u)\n",
			mm->imsi, transaction_id);
		return 0;
	}
	/* stop timer 3395 */
	pdpctx_timer_stop(pdp, 3395);
	return sgsn_delete_pdp_ctx(pdp);
}

static int gsm48_rx_gsm_status(struct sgsn_mm_ctx *ctx, struct msgb *msg)
{
	struct gsm48_hdr *gh = msgb_l3(msg);

	LOGMMCTXP(LOGL_INFO, ctx, "-> GPRS SM STATUS (cause: %s)\n",
		get_value_string(gsm48_gsm_cause_names, gh->data[0]));

	return 0;
}

static void pdpctx_timer_cb(void *_pdp)
{
	struct sgsn_pdp_ctx *pdp = _pdp;

	pdp->num_T_exp++;

	switch (pdp->T) {
	case 3395:	/* waiting for PDP CTX DEACT ACK */
		if (pdp->num_T_exp >= 4) {
			LOGPDPCTXP(LOGL_NOTICE, pdp, "T3395 expired >= 5 times\n");
			pdp->state = PDP_STATE_INACTIVE;
			sgsn_delete_pdp_ctx(pdp);
			break;
		}
		gsm48_tx_gsm_deact_pdp_req(pdp, GSM_CAUSE_NET_FAIL);
		break;
	default:
		LOGPDPCTXP(LOGL_ERROR, pdp, "timer expired in unknown mode %u\n",
			pdp->T);
	}
}


/* GPRS Session Management */
static int gsm0408_rcv_gsm(struct sgsn_mm_ctx *mmctx, struct msgb *msg,
			   struct gprs_llc_llme *llme)
{
	struct gsm48_hdr *gh = (struct gsm48_hdr *) msgb_gmmh(msg);
	int rc;

	/* MMCTX can be NULL when called */

	if (!mmctx) {
		LOGP(DMM, LOGL_NOTICE, "Cannot handle SM for unknown MM CTX\n");
		/* 6.1.3.6 */
		if (gh->msg_type == GSM48_MT_GSM_STATUS)
			return 0;

		return gsm0408_gprs_force_reattach_oldmsg(msg, llme);
	}

	switch (gh->msg_type) {
	case GSM48_MT_GSM_ACT_PDP_REQ:
		rc = gsm48_rx_gsm_act_pdp_req(mmctx, msg);
		break;
	case GSM48_MT_GSM_DEACT_PDP_REQ:
		rc = gsm48_rx_gsm_deact_pdp_req(mmctx, msg);
		break;
	case GSM48_MT_GSM_DEACT_PDP_ACK:
		rc = gsm48_rx_gsm_deact_pdp_ack(mmctx, msg);
		break;
	case GSM48_MT_GSM_STATUS:
		rc = gsm48_rx_gsm_status(mmctx, msg);
		break;
	case GSM48_MT_GSM_REQ_PDP_ACT_REJ:
	case GSM48_MT_GSM_ACT_AA_PDP_REQ:
	case GSM48_MT_GSM_DEACT_AA_PDP_REQ:
		LOGMMCTXP(LOGL_NOTICE, mmctx, "Unimplemented GSM 04.08 GSM msg type 0x%02x: %s\n",
			gh->msg_type, osmo_hexdump((uint8_t *)gh, msgb_l3len(msg)));
		rc = gsm48_tx_sm_status(mmctx, GSM_CAUSE_MSGT_NOTEXIST_NOTIMPL);
		break;
	default:
		LOGMMCTXP(LOGL_NOTICE, mmctx, "Unknown GSM 04.08 GSM msg type 0x%02x: %s\n",
			gh->msg_type, osmo_hexdump((uint8_t *)gh, msgb_l3len(msg)));
		rc = gsm48_tx_sm_status(mmctx, GSM_CAUSE_MSGT_NOTEXIST_NOTIMPL);
		break;

	}

	return rc;
}

int gsm0408_gprs_force_reattach_oldmsg(struct msgb *msg,
				       struct gprs_llc_llme *llme)
{
	int rc;
	if (llme)
		gprs_llgmm_reset_oldmsg(msg, GPRS_SAPI_GMM, llme);

	rc = gsm48_tx_gmm_detach_req_oldmsg(
		msg, GPRS_DET_T_MT_REATT_REQ, GMM_CAUSE_IMPL_DETACHED);

	return rc;
}

int gsm0408_gprs_force_reattach(struct sgsn_mm_ctx *mmctx)
{
	int rc;
	if (mmctx->ran_type == MM_CTX_T_GERAN_Gb)
		gprs_llgmm_reset(mmctx->gb.llme);

	rc = gsm48_tx_gmm_detach_req(
		mmctx, GPRS_DET_T_MT_REATT_REQ, GMM_CAUSE_IMPL_DETACHED);

	mm_ctx_cleanup_free(mmctx, "forced reattach");

	return rc;
}

/* Main entry point for incoming 04.08 GPRS messages from Iu */
int gsm0408_gprs_rcvmsg_iu(struct msgb *msg, struct gprs_ra_id *ra_id,
			   uint16_t *sai)
{
	struct gsm48_hdr *gh = (struct gsm48_hdr *) msgb_gmmh(msg);
	uint8_t pdisc = gsm48_hdr_pdisc(gh);
	struct sgsn_mm_ctx *mmctx;
	int rc = -EINVAL;

	mmctx = sgsn_mm_ctx_by_ue_ctx(msg->dst);
	if (mmctx) {
		rate_ctr_inc(&mmctx->ctrg->ctr[GMM_CTR_PKTS_SIG_IN]);
		if (ra_id)
			memcpy(&mmctx->ra, ra_id, sizeof(mmctx->ra));
	}

	/* MMCTX can be NULL */

	switch (pdisc) {
	case GSM48_PDISC_MM_GPRS:
		rc = gsm0408_rcv_gmm(mmctx, msg, NULL, false);
#warning "set drop_cipherable arg for gsm0408_rcv_gmm() from IuPS?"
		break;
	case GSM48_PDISC_SM_GPRS:
		rc = gsm0408_rcv_gsm(mmctx, msg, NULL);
		break;
	default:
		LOGMMCTXP(LOGL_NOTICE, mmctx,
			"Unknown GSM 04.08 discriminator 0x%02x: %s\n",
			pdisc, osmo_hexdump((uint8_t *)gh, msgb_l3len(msg)));
		/* FIXME: return status message */
		break;
	}

	/* MMCTX can be invalid */

	return rc;
}

/* Main entry point for incoming 04.08 GPRS messages from Gb */
int gsm0408_gprs_rcvmsg_gb(struct msgb *msg, struct gprs_llc_llme *llme,
			   bool drop_cipherable)
{
	struct gsm48_hdr *gh = (struct gsm48_hdr *) msgb_gmmh(msg);
	uint8_t pdisc = gsm48_hdr_pdisc(gh);
	struct sgsn_mm_ctx *mmctx;
	struct gprs_ra_id ra_id;
	int rc = -EINVAL;

	bssgp_parse_cell_id(&ra_id, msgb_bcid(msg));
	mmctx = sgsn_mm_ctx_by_tlli(msgb_tlli(msg), &ra_id);
	if (mmctx) {
		msgid2mmctx(mmctx, msg);
		rate_ctr_inc(&mmctx->ctrg->ctr[GMM_CTR_PKTS_SIG_IN]);
		mmctx->gb.llme = llme;
	}

	/* MMCTX can be NULL */

	switch (pdisc) {
	case GSM48_PDISC_MM_GPRS:
		rc = gsm0408_rcv_gmm(mmctx, msg, llme, drop_cipherable);
		break;
	case GSM48_PDISC_SM_GPRS:
		rc = gsm0408_rcv_gsm(mmctx, msg, llme);
		break;
	default:
		LOGMMCTXP(LOGL_NOTICE, mmctx,
			"Unknown GSM 04.08 discriminator 0x%02x: %s\n",
			pdisc, osmo_hexdump((uint8_t *)gh, msgb_l3len(msg)));
		/* FIXME: return status message */
		break;
	}

	/* MMCTX can be invalid */

	return rc;
}

int gprs_gmm_rx_suspend(struct gprs_ra_id *raid, uint32_t tlli)
{
	struct sgsn_mm_ctx *mmctx;

	mmctx = sgsn_mm_ctx_by_tlli(tlli, raid);
	if (!mmctx) {
		LOGP(DMM, LOGL_NOTICE, "SUSPEND request for unknown "
			"TLLI=%08x\n", tlli);
		return -EINVAL;
	}

	if (mmctx->gmm_state != GMM_REGISTERED_NORMAL &&
	    mmctx->gmm_state != GMM_REGISTERED_SUSPENDED) {
		LOGMMCTXP(LOGL_NOTICE, mmctx, "SUSPEND request while state "
			"!= REGISTERED (TLLI=%08x)\n", tlli);
		return -EINVAL;
	}

	/* Transition from REGISTERED_NORMAL to REGISTERED_SUSPENDED */
	mmctx->gmm_state = GMM_REGISTERED_SUSPENDED;
	return 0;
}

int gprs_gmm_rx_resume(struct gprs_ra_id *raid, uint32_t tlli,
		       uint8_t suspend_ref)
{
	struct sgsn_mm_ctx *mmctx;

	/* FIXME: make use of suspend reference? */

	mmctx = sgsn_mm_ctx_by_tlli(tlli, raid);
	if (!mmctx) {
		LOGP(DMM, LOGL_NOTICE, "RESUME request for unknown "
			"TLLI=%08x\n", tlli);
		return -EINVAL;
	}

	if (mmctx->gmm_state != GMM_REGISTERED_NORMAL &&
	    mmctx->gmm_state != GMM_REGISTERED_SUSPENDED) {
		LOGMMCTXP(LOGL_NOTICE, mmctx, "RESUME request while state "
			"!= SUSPENDED (TLLI=%08x)\n", tlli);
		/* FIXME: should we not simply ignore it? */
		return -EINVAL;
	}

	/* Transition from SUSPENDED to NORMAL */
	mmctx->gmm_state = GMM_REGISTERED_NORMAL;
	return 0;
}

#ifdef BUILD_IU
int iu_rab_act_ps(uint8_t rab_id, struct sgsn_pdp_ctx *pdp, bool use_x213_nsap)
{
	struct msgb *msg;
	struct sgsn_mm_ctx *mm = pdp->mm;
	struct ue_conn_ctx *uectx;
	uint32_t ggsn_ip;

	uectx = mm->iu.ue_ctx;

	/* Get the IP address for ggsn user plane */
	memcpy(&ggsn_ip, pdp->lib->gsnru.v, pdp->lib->gsnru.l);
	ggsn_ip = htonl(ggsn_ip);

	LOGP(DRANAP, LOGL_DEBUG, "Assigning RAB: rab_id=%d, ggsn_ip=%x,"
	     " teid_gn=%x, use_x213_nsap=%d\n",
	     rab_id, ggsn_ip, pdp->lib->teid_gn, use_x213_nsap);

	msg = ranap_new_msg_rab_assign_data(rab_id, ggsn_ip,
					    pdp->lib->teid_gn, use_x213_nsap);
	msg->l2h = msg->data;
	return iu_rab_act(uectx, msg);
}
#endif
