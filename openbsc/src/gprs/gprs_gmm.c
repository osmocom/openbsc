/* GSM Mobile Radio Interface Layer 3 messages on the A-bis interface
 * 3GPP TS 04.08 version 7.21.0 Release 1998 / ETSI TS 100 940 V7.21.0 */

/* (C) 2009-2010 by Harald Welte <laforge@gnumonks.org>
 *
 * All Rights Reserved
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#include <openbsc/db.h>
#include <osmocore/msgb.h>
#include <osmocore/tlv.h>
#include <osmocore/gsm_utils.h>
#include <osmocore/signal.h>
#include <osmocore/talloc.h>
#include <osmocore/rate_ctr.h>

#include <openbsc/debug.h>
#include <openbsc/gsm_data.h>
#include <openbsc/gsm_subscriber.h>
#include <openbsc/gsm_04_08.h>
#include <openbsc/gsm_04_08_gprs.h>
#include <openbsc/paging.h>
#include <openbsc/transaction.h>
#include <openbsc/gprs_bssgp.h>
#include <openbsc/gprs_llc.h>
#include <openbsc/gprs_sgsn.h>
#include <openbsc/gprs_gmm.h>
#include <openbsc/sgsn.h>

#include <pdp.h>

extern struct sgsn_instance *sgsn;
extern struct sgsn_ggsn_ctx *dummy_ggsn;

/* Protocol related stuff, should go into libosmocore */

/* 10.5.5.14 GPRS MM Cause / Table 10.5.147 */
const struct value_string gmm_cause_names[] = {
	/* FIXME */
	{ GMM_CAUSE_SEM_INCORR_MSG, "Semantically incorrect message" },
	{ GMM_CAUSE_INV_MAND_INFO, "Invalid mandatory information" },
	{ GMM_CAUSE_MSGT_NOTEXIST_NOTIMPL,
			"Message type non-existant or not implemented" },
	{ GMM_CAUSE_MSGT_INCOMP_P_STATE,
			"Message type not compatible with protocol state" },
	{ GMM_CAUSE_IE_NOTEXIST_NOTIMPL,
			"Information element non-existent or not implemented" },
	{ GMM_CAUSE_COND_IE_ERR, "Conditional IE error" },
	{ GMM_CAUSE_MSG_INCOMP_P_STATE,
				"Message not compatible with protocol state " },
	{ GMM_CAUSE_PROTO_ERR_UNSPEC, "Protocol error, unspecified" },
	{ 0, NULL }
};

/* 10.5.6.6 SM Cause / Table 10.5.157 */
const struct value_string gsm_cause_names[] = {
	{ GSM_CAUSE_INSUFF_RSRC, "Insufficient resources" },
	{ GSM_CAUSE_MISSING_APN, "Missing or unknown APN" },
	{ GSM_CAUSE_UNKNOWN_PDP, "Unknown PDP address or PDP type" },
	{ GSM_CAUSE_AUTH_FAILED, "User Authentication failed" },
	{ GSM_CAUSE_ACT_REJ_GGSN, "Activation rejected by GGSN" },
	{ GSM_CAUSE_ACT_REJ_UNSPEC, "Activation rejected, unspecified" },
	{ GSM_CAUSE_SERV_OPT_NOTSUPP, "Service option not supported" },
	{ GSM_CAUSE_REQ_SERV_OPT_NOTSUB,
				"Requested service option not subscribed" },
	{ GSM_CAUSE_SERV_OPT_TEMP_OOO,
				"Service option temporarily out of order" },
	{ GSM_CAUSE_NSAPI_IN_USE, "NSAPI already used" },
	{ GSM_CAUSE_DEACT_REGULAR, "Regular deactivation" },
	{ GSM_CAUSE_QOS_NOT_ACCEPTED, "QoS not accepted" },
	{ GSM_CAUSE_NET_FAIL, "Network Failure" },
	{ GSM_CAUSE_REACT_RQD, "Reactivation required" },
	{ GSM_CAUSE_FEATURE_NOTSUPP, "Feature not supported " },
	{ GSM_CAUSE_INVALID_TRANS_ID, "Invalid transaction identifier" },
	{ GSM_CAUSE_SEM_INCORR_MSG, "Semantically incorrect message" },
	{ GSM_CAUSE_INV_MAND_INFO, "Invalid mandatory information" },
	{ GSM_CAUSE_MSGT_NOTEXIST_NOTIMPL,
			"Message type non-existant or not implemented" },
	{ GSM_CAUSE_MSGT_INCOMP_P_STATE,
			"Message type not compatible with protocol state" },
	{ GSM_CAUSE_IE_NOTEXIST_NOTIMPL,
			"Information element non-existent or not implemented" },
	{ GSM_CAUSE_COND_IE_ERR, "Conditional IE error" },
	{ GSM_CAUSE_MSG_INCOMP_P_STATE,
				"Message not compatible with protocol state " },
	{ GSM_CAUSE_PROTO_ERR_UNSPEC, "Protocol error, unspecified" },
	{ 0, NULL }
};

/* 10.5.5.2 */
const struct value_string gprs_att_t_strs[] = {
	{ GPRS_ATT_T_ATTACH, 		"GPRS attach" },
	{ GPRS_ATT_T_ATT_WHILE_IMSI, 	"GPRS attach while IMSI attached" },
	{ GPRS_ATT_T_COMBINED, 		"Combined GPRS/IMSI attach" },
	{ 0, NULL }
};

const struct value_string gprs_upd_t_strs[] = {
	{ GPRS_UPD_T_RA,		"RA updating" },
	{ GPRS_UPD_T_RA_LA,		"combined RA/LA updating" },
	{ GPRS_UPD_T_RA_LA_IMSI_ATT,	"combined RA/LA updating + IMSI attach" },
	{ GPRS_UPD_T_PERIODIC,		"periodic updating" },
	{ 0, NULL }
};

/* 10.5.5.5 */
const struct value_string gprs_det_t_mo_strs[] = {
	{ GPRS_DET_T_MO_GPRS,		"GPRS detach" },
	{ GPRS_DET_T_MO_IMSI,		"IMSI detach" },
	{ GPRS_DET_T_MO_COMBINED,	"Combined GPRS/IMSI detach" },
	{ 0, NULL }
};

/* Our implementation, should be kept in SGSN */

/* Send a message through the underlying layer */
static int gsm48_gmm_sendmsg(struct msgb *msg, int command,
			     const struct sgsn_mm_ctx *mm)
{
	if (mm)
		rate_ctr_inc(&mm->ctrg->ctr[GMM_CTR_PKTS_SIG_OUT]);

	/* caller needs to provide TLLI, BVCI and NSEI */
	return gprs_llc_tx_ui(msg, GPRS_SAPI_GMM, command);
}

/* copy identifiers from old message to new message, this
 * is required so lower layers can route it correctly */
static void gmm_copy_id(struct msgb *msg, const struct msgb *old)
{
	msgb_tlli(msg) = msgb_tlli(old);
	msgb_bvci(msg) = msgb_bvci(old);
	msgb_nsei(msg) = msgb_nsei(old);
}

/* Store BVCI/NSEI in MM context */
static void msgid2mmctx(struct sgsn_mm_ctx *mm, const struct msgb *msg)
{
	mm->bvci = msgb_bvci(msg);
	mm->nsei = msgb_nsei(msg);
}

/* Store BVCI/NSEI in MM context */
static void mmctx2msgid(struct msgb *msg, const struct sgsn_mm_ctx *mm)
{
	msgb_tlli(msg) = mm->tlli;
	msgb_bvci(msg) = mm->bvci;
	msgb_nsei(msg) = mm->nsei;
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
	struct msgb *msg = gsm48_msgb_alloc();
	struct gsm48_hdr *gh;
	struct gsm48_attach_ack *aa;
	uint8_t *ptsig, *mid;

	DEBUGP(DMM, "<- GPRS ATTACH ACCEPT\n");

	mmctx2msgid(msg, mm);

	gh = (struct gsm48_hdr *) msgb_put(msg, sizeof(*gh));
	gh->proto_discr = GSM48_PDISC_MM_GPRS;
	gh->msg_type = GSM48_MT_GMM_ATTACH_ACK;

	aa = (struct gsm48_attach_ack *) msgb_put(msg, sizeof(*aa));
	aa->force_stby = 0;	/* not indicated */
	aa->att_result = 1;	/* GPRS only */
	aa->ra_upd_timer = GPRS_TMR_MINUTE | 10;
	aa->radio_prio = 4;	/* lowest */
	gsm48_construct_ra(aa->ra_id.digits, &mm->ra);

	/* Optional: P-TMSI signature */
	msgb_v_put(msg, GSM48_IE_GMM_PTMSI_SIG);
	ptsig = msgb_put(msg, 3);
	ptsig[0] = mm->p_tmsi_sig >> 16;
	ptsig[1] = mm->p_tmsi_sig >> 8;
	ptsig[2] = mm->p_tmsi_sig & 0xff;

	/* Optional: Negotiated Ready timer value */

	/* Optional: Allocated P-TMSI */
	msgb_v_put(msg, GSM48_IE_GMM_ALLOC_PTMSI);
	mid = msgb_put(msg, GSM48_MID_TMSI_LEN);
	gsm48_generate_mid_from_tmsi(mid, mm->p_tmsi);

	/* Optional: MS-identity (combined attach) */
	/* Optional: GMM cause (partial attach result for combined attach) */

	return gsm48_gmm_sendmsg(msg, 0, NULL);
}

/* Chapter 9.4.5: Attach reject */
static int _tx_gmm_att_rej(struct msgb *msg, uint8_t gmm_cause)
{
	struct gsm48_hdr *gh;

	DEBUGP(DMM, "<- GPRS ATTACH REJECT\n");

	gh = (struct gsm48_hdr *) msgb_put(msg, sizeof(*gh) + 1);
	gh->proto_discr = GSM48_PDISC_MM_GPRS;
	gh->msg_type = GSM48_MT_GMM_ATTACH_REJ;
	gh->data[0] = gmm_cause;

	return gsm48_gmm_sendmsg(msg, 0, NULL);
}
static int gsm48_tx_gmm_att_rej_oldmsg(const struct msgb *old_msg,
					uint8_t gmm_cause)
{
	struct msgb *msg = gsm48_msgb_alloc();
	gmm_copy_id(msg, old_msg);
	return _tx_gmm_att_rej(msg, gmm_cause);
}
static int gsm48_tx_gmm_att_rej(struct sgsn_mm_ctx *mm,
				uint8_t gmm_cause)
{
	struct msgb *msg = gsm48_msgb_alloc();
	mmctx2msgid(msg, mm);
	return _tx_gmm_att_rej(msg, gmm_cause);
}

/* Chapter 9.4.6.2 Detach accept */
static int gsm48_tx_gmm_det_ack(struct sgsn_mm_ctx *mm, uint8_t force_stby)
{
	struct msgb *msg = gsm48_msgb_alloc();
	struct gsm48_hdr *gh;

	DEBUGP(DMM, "<- GPRS DETACH ACCEPT\n");

	mmctx2msgid(msg, mm);

	gh = (struct gsm48_hdr *) msgb_put(msg, sizeof(*gh) + 1);
	gh->proto_discr = GSM48_PDISC_MM_GPRS;
	gh->msg_type = GSM48_MT_GMM_DETACH_ACK;
	gh->data[0] = force_stby;

	return gsm48_gmm_sendmsg(msg, 0, NULL);
}

/* Transmit Chapter 9.4.12 Identity Request */
static int gsm48_tx_gmm_id_req(struct sgsn_mm_ctx *mm, uint8_t id_type)
{
	struct msgb *msg = gsm48_msgb_alloc();
	struct gsm48_hdr *gh;

	DEBUGP(DMM, "-> GPRS IDENTITY REQUEST: mi_type=%02x\n", id_type);

	mmctx2msgid(msg, mm);

	gh = (struct gsm48_hdr *) msgb_put(msg, sizeof(*gh) + 1);
	gh->proto_discr = GSM48_PDISC_MM_GPRS;
	gh->msg_type = GSM48_MT_GMM_ID_REQ;
	/* 10.5.5.9 ID type 2 + identity type and 10.5.5.7 'force to standby' IE */
	gh->data[0] = id_type & 0xf;

	return gsm48_gmm_sendmsg(msg, 0, NULL);
}

/* Check if we can already authorize a subscriber */
static int gsm48_gmm_authorize(struct sgsn_mm_ctx *ctx)
{
	if (strlen(ctx->imei) && strlen(ctx->imsi)) {
		ctx->mm_state = GMM_REGISTERED_NORMAL;
		return gsm48_tx_gmm_att_ack(ctx);
	} 
	if (!strlen(ctx->imei))
		return gsm48_tx_gmm_id_req(ctx, GSM_MI_TYPE_IMEI);

	if (!strlen(ctx->imsi))
		return gsm48_tx_gmm_id_req(ctx, GSM_MI_TYPE_IMSI);

	return 0;
}

/* Parse Chapter 9.4.13 Identity Response */
static int gsm48_rx_gmm_id_resp(struct sgsn_mm_ctx *ctx, struct msgb *msg)
{
	struct gsm48_hdr *gh = (struct gsm48_hdr *) msgb_gmmh(msg);
	uint8_t mi_type = gh->data[1] & GSM_MI_TYPE_MASK;
	char mi_string[GSM48_MI_SIZE];

	gsm48_mi_to_string(mi_string, sizeof(mi_string), &gh->data[1], gh->data[0]);
	DEBUGP(DMM, "-> GMM IDENTITY RESPONSE: mi_type=0x%02x MI(%s) ",
		mi_type, mi_string);

	if (!ctx) {
		DEBUGP(DMM, "from unknown TLLI 0x%08x?!?\n", msgb_tlli(msg));
		return -EINVAL;
	}

	switch (mi_type) {
	case GSM_MI_TYPE_IMSI:
		/* we already have a mm context with current TLLI, but no
		 * P-TMSI / IMSI yet.  What we now need to do is to fill
		 * this initial context with data from the HLR */
		strncpy(ctx->imsi, mi_string, sizeof(ctx->imei));
		break;
	case GSM_MI_TYPE_IMEI:
		strncpy(ctx->imei, mi_string, sizeof(ctx->imei));
		break;
	case GSM_MI_TYPE_IMEISV:
		break;
	}

	DEBUGPC(DMM, "\n");
	/* Check if we can let the mobile station enter */
	return gsm48_gmm_authorize(ctx);
}

static void attach_rej_cb(void *data)
{
	struct sgsn_mm_ctx *ctx = data;

	gsm48_tx_gmm_att_rej(ctx, GMM_CAUSE_MS_ID_NOT_DERIVED);
	ctx->mm_state = GMM_DEREGISTERED;
	/* FIXME: release the context */
}

static void schedule_reject(struct sgsn_mm_ctx *ctx)
{
	ctx->T = 3370;
	ctx->timer.cb = attach_rej_cb;
	ctx->timer.data = ctx;
	bsc_schedule_timer(&ctx->timer, 6, 0);
}

/* Section 9.4.1 Attach request */
static int gsm48_rx_gmm_att_req(struct sgsn_mm_ctx *mmctx, struct msgb *msg)
{
	struct gsm48_hdr *gh = (struct gsm48_hdr *) msgb_gmmh(msg);
	uint8_t *cur = gh->data, *msnc, *mi, *old_ra_info;
	uint8_t msnc_len, att_type, mi_len, mi_type;
	uint16_t drx_par;
	uint32_t tmsi;
	char mi_string[GSM48_MI_SIZE];
	struct gprs_ra_id ra_id;
	uint16_t cid;
	struct sgsn_mm_ctx *ctx;

	DEBUGP(DMM, "-> GMM ATTACH REQUEST ");

	/* As per TS 04.08 Chapter 4.7.1.4, the attach request arrives either
	 * with a foreign TLLI (P-TMSI that was allocated to the MS before),
	 * or with random TLLI. */

	cid = bssgp_parse_cell_id(&ra_id, msgb_bcid(msg));

	/* MS network capability 10.5.5.12 */
	msnc_len = *cur++;
	msnc = cur;
	if (msnc_len > 2)
		goto err_inval;
	cur += msnc_len;

	/* aTTACH Type 10.5.5.2 */
	att_type = *cur++ & 0x0f;

	/* DRX parameter 10.5.5.6 */
	drx_par = *cur++;
	drx_par |= *cur++ << 8;

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

	/* Old routing area identification 10.5.5.15 */
	old_ra_info = cur;
	cur += 6;

	/* MS Radio Access Capability 10.5.5.12a */

	/* Optional: Old P-TMSI Signature, Requested READY timer, TMSI Status */

	switch (mi_type) {
	case GSM_MI_TYPE_IMSI:
		/* Try to find MM context based on IMSI */
		ctx = sgsn_mm_ctx_by_imsi(mi_string);
		if (!ctx) {
#if 0
			return gsm48_tx_gmm_att_rej(msg, GMM_CAUSE_IMSI_UNKNOWN);
#else
			/* As a temorary hack, we simply assume that the IMSI exists */
			ctx = sgsn_mm_ctx_alloc(0, &ra_id);
			if (!ctx)
				return gsm48_tx_gmm_att_rej_oldmsg(msg, GMM_CAUSE_NET_FAIL);
			strncpy(ctx->imsi, mi_string, sizeof(ctx->imsi));
#endif
		}
		/* FIXME: Start some timer */
		ctx->mm_state = GMM_COMMON_PROC_INIT;
		ctx->tlli = msgb_tlli(msg);
		msgid2mmctx(ctx, msg);
		break;
	case GSM_MI_TYPE_TMSI:
		tmsi = strtoul(mi_string, NULL, 10);
		/* Try to find MM context based on P-TMSI */
		ctx = sgsn_mm_ctx_by_ptmsi(tmsi);
		if (!ctx) {
			ctx = sgsn_mm_ctx_alloc(msgb_tlli(msg), &ra_id);
			/* FIXME: Start some timer */
			ctx->mm_state = GMM_COMMON_PROC_INIT;
			ctx->tlli = msgb_tlli(msg);
			msgid2mmctx(ctx, msg);
		}
		ctx->p_tmsi = tmsi;
		break;
	default:
		return 0;
	}
	/* Update MM Context with currient RA and Cell ID */
	ctx->ra = ra_id;
	ctx->cell_id = cid;

	/* Allocate a new P-TMSI (+ P-TMSI signature) */
	ctx->p_tmsi = sgsn_alloc_ptmsi();

	/* FIXME: update the TLLI with the new local TLLI based on the P-TMSI */

	DEBUGPC(DMM, "\n");

	return ctx ? gsm48_gmm_authorize(ctx) : 0;

err_inval:
	DEBUGPC(DMM, "\n");
	return gsm48_tx_gmm_att_rej_oldmsg(msg, GMM_CAUSE_SEM_INCORR_MSG);
}

/* Section 4.7.4.1 / 9.4.5.2 MO Detach request */
static int gsm48_rx_gmm_det_req(struct sgsn_mm_ctx *ctx, struct msgb *msg)
{
	struct gsm48_hdr *gh = (struct gsm48_hdr *) msgb_gmmh(msg);
	uint8_t detach_type, power_off;

	detach_type = gh->data[0] & 0x7;
	power_off = gh->data[0] & 0x8;

	/* FIXME: In 24.008 there is an optional P-TMSI and P-TMSI signature IE */

	DEBUGP(DMM, "-> GMM DETACH REQUEST TLLI=0x%08x type=%s %s\n",
		msgb_tlli(msg), get_value_string(gprs_det_t_mo_strs, detach_type),
		power_off ? "Power-off" : "");

	/* Mark MM state as deregistered */
	ctx->mm_state = GMM_DEREGISTERED;

	/* force_stby = 0 */
	return gsm48_tx_gmm_det_ack(ctx, 0);
}

/* Chapter 9.4.15: Routing area update accept */
static int gsm48_tx_gmm_ra_upd_ack(struct sgsn_mm_ctx *mm)
{
	struct msgb *msg = gsm48_msgb_alloc();
	struct gsm48_hdr *gh;
	struct gsm48_ra_upd_ack *rua;

	DEBUGP(DMM, "<- ROUTING AREA UPDATE ACCEPT\n");

	mmctx2msgid(msg, mm);

	gh = (struct gsm48_hdr *) msgb_put(msg, sizeof(*gh));
	gh->proto_discr = GSM48_PDISC_MM_GPRS;
	gh->msg_type = GSM48_MT_GMM_RA_UPD_ACK;

	rua = (struct gsm48_ra_upd_ack *) msgb_put(msg, sizeof(*rua));
	rua->force_stby = 0;	/* not indicated */
	rua->upd_result = 0;	/* RA updated */
	rua->ra_upd_timer = GPRS_TMR_MINUTE | 10;

	gsm48_construct_ra(rua->ra_id.digits, &mm->ra);

	/* Option: P-TMSI signature, allocated P-TMSI, MS ID, ... */
	return gsm48_gmm_sendmsg(msg, 0, NULL);
}

/* Chapter 9.4.17: Routing area update reject */
static int gsm48_tx_gmm_ra_upd_rej(struct msgb *old_msg, uint8_t cause)
{
	struct msgb *msg = gsm48_msgb_alloc();
	struct gsm48_hdr *gh;

	DEBUGP(DMM, "<- ROUTING AREA UPDATE REJECT\n");

	gmm_copy_id(msg, old_msg);

	gh = (struct gsm48_hdr *) msgb_put(msg, sizeof(*gh) + 2);
	gh->proto_discr = GSM48_PDISC_MM_GPRS;
	gh->msg_type = GSM48_MT_GMM_RA_UPD_REJ;
	gh->data[0] = cause;
	gh->data[1] = 0; /* ? */

	/* Option: P-TMSI signature, allocated P-TMSI, MS ID, ... */
	return gsm48_gmm_sendmsg(msg, 0, NULL);
}

/* Chapter 9.4.14: Routing area update request */
static int gsm48_rx_gmm_ra_upd_req(struct sgsn_mm_ctx *mmctx, struct msgb *msg)
{
	struct gsm48_hdr *gh = (struct gsm48_hdr *) msgb_gmmh(msg);
	uint8_t *cur = gh->data;
	struct gprs_ra_id old_ra_id;
	uint8_t upd_type;

	/* Update Type 10.5.5.18 */
	upd_type = *cur++ & 0x0f;

	DEBUGP(DMM, "-> GMM RA UPDATE REQUEST type=\"%s\" ",
		get_value_string(gprs_upd_t_strs, upd_type));

	/* Old routing area identification 10.5.5.15 */
	gsm48_parse_ra(&old_ra_id, cur);
	cur += 6;

	/* MS Radio Access Capability 10.5.5.12a */

	/* Optional: Old P-TMSI Signature, Requested READY timer, TMSI Status,
	 * DRX parameter, MS network capability */

	switch (upd_type) {
	case GPRS_UPD_T_RA_LA:
	case GPRS_UPD_T_RA_LA_IMSI_ATT:
		DEBUGPC(DMM, " unsupported in Mode III, is your SI13 corrupt?\n");
		return gsm48_tx_gmm_ra_upd_rej(msg, GMM_CAUSE_PROTO_ERR_UNSPEC);
		break;
	case GPRS_UPD_T_RA:
	case GPRS_UPD_T_PERIODIC:
		break;
	}

	/* Look-up the MM context based on old RA-ID and TLLI */
	if (!mmctx || mmctx->mm_state == GMM_DEREGISTERED) {
		/* The MS has to perform GPRS attach */
		DEBUGPC(DMM, " REJECT\n");
		return gsm48_tx_gmm_ra_upd_rej(msg, GMM_CAUSE_IMPL_DETACHED);
	}

	/* Update the MM context with the new RA-ID */
	bssgp_parse_cell_id(&mmctx->ra, msgb_bcid(msg));
	/* Update the MM context with the new TLLI */
	mmctx->tlli = msgb_tlli(msg);
	/* FIXME: Update the MM context with the MS radio acc capabilities */
	/* FIXME: Update the MM context with the MS network capabilities */

	rate_ctr_inc(&mmctx->ctrg->ctr[GMM_CTR_RA_UPDATE]);

	DEBUGPC(DMM, " ACCEPT\n");
	return gsm48_tx_gmm_ra_upd_ack(mmctx);
}

static int gsm48_rx_gmm_status(struct sgsn_mm_ctx *mmctx, struct msgb *msg)
{
	struct gsm48_hdr *gh = msgb_l3(msg);

	DEBUGP(DMM, "-> GPRS MM STATUS (cause: %s)\n",
		get_value_string(gmm_cause_names, gh->data[0]));

	return 0;
}

/* GPRS Mobility Management */
static int gsm0408_rcv_gmm(struct sgsn_mm_ctx *mmctx, struct msgb *msg)
{
	struct gsm48_hdr *gh = (struct gsm48_hdr *) msgb_gmmh(msg);
	int rc;

	if (!mmctx &&
	    gh->msg_type != GSM48_MT_GMM_ATTACH_REQ &&
	    gh->msg_type != GSM48_MT_GMM_RA_UPD_REQ) {
		LOGP(DMM, LOGL_NOTICE, "Cannot handle GMM for unknown MM CTX\n");
		/* FIXME: Send GMM_CAUSE_IMPL_DETACHED */
		return -EINVAL;
	}


	switch (gh->msg_type) {
	case GSM48_MT_GMM_RA_UPD_REQ:
		rc = gsm48_rx_gmm_ra_upd_req(mmctx, msg);
		break;
	case GSM48_MT_GMM_ATTACH_REQ:
		rc = gsm48_rx_gmm_att_req(mmctx, msg);
		break;
	case GSM48_MT_GMM_ID_RESP:
		rc = gsm48_rx_gmm_id_resp(mmctx, msg);
		break;
	case GSM48_MT_GMM_STATUS:
		rc = gsm48_rx_gmm_status(mmctx, msg);
		break;
	case GSM48_MT_GMM_DETACH_REQ:
		rc = gsm48_rx_gmm_det_req(mmctx, msg);
		break;
	case GSM48_MT_GMM_RA_UPD_COMPL:
		/* only in case SGSN offered new P-TMSI */
	case GSM48_MT_GMM_ATTACH_COMPL:
		/* only in case SGSN offered new P-TMSI */
	case GSM48_MT_GMM_PTMSI_REALL_COMPL:
	case GSM48_MT_GMM_AUTH_CIPH_RESP:
		DEBUGP(DMM, "Unimplemented GSM 04.08 GMM msg type 0x%02x\n",
			gh->msg_type);
		/* FIXME: Send GMM_CAUSE_MSGT_NOTEXIST_NOTIMPL */
		break;
	default:
		DEBUGP(DMM, "Unknown GSM 04.08 GMM msg type 0x%02x\n",
			gh->msg_type);
		/* FIXME: Send GMM_CAUSE_MSGT_NOTEXIST_NOTIMPL */
		break;
	}

	return rc;
}

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

/* Section 9.5.2: Ativate PDP Context Accept */
int gsm48_tx_gsm_act_pdp_acc(struct sgsn_pdp_ctx *pdp)
{
	struct msgb *msg = gsm48_msgb_alloc();
	struct gsm48_hdr *gh;
	uint8_t transaction_id = pdp->ti ^ 0x8; /* flip */

	DEBUGP(DMM, "<- ACTIVATE PDP CONTEXT ACK\n");

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
	if (pdp->lib->pco_req.l && pdp->lib->pco_req.v)
		msgb_tlv_put(msg, GSM48_IE_GSM_PROTO_CONF_OPT,
			     pdp->lib->pco_req.l, pdp->lib->pco_req.v);

	/* Optional: Packet Flow Identifier */

	return gsm48_gmm_sendmsg(msg, 0, pdp->mm);
}

/* Section 9.5.3: Activate PDP Context reject */
int gsm48_tx_gsm_act_pdp_rej(struct sgsn_mm_ctx *mm, uint8_t tid,
			     uint8_t cause, uint8_t pco_len, uint8_t *pco_v)
{
	struct msgb *msg = gsm48_msgb_alloc();
	struct gsm48_hdr *gh;
	uint8_t transaction_id = tid ^ 0x8; /* flip */

	DEBUGP(DMM, "<- ACTIVATE PDP CONTEXT REJ(cause=%u)\n", cause);

	mmctx2msgid(msg, mm);

	gh = (struct gsm48_hdr *) msgb_put(msg, sizeof(*gh));
	gh->proto_discr = GSM48_PDISC_SM_GPRS | (transaction_id << 4);
	gh->msg_type = GSM48_MT_GSM_ACT_PDP_REJ;

	msgb_v_put(msg, cause);
	if (pco_len && pco_v)
		msgb_tlv_put(msg, GSM48_IE_GSM_PROTO_CONF_OPT, pco_len, pco_v);

	return gsm48_gmm_sendmsg(msg, 0, mm);
}

/* Section 9.5.9: Deactivate PDP Context Accept */
int gsm48_tx_gsm_deact_pdp_acc(struct sgsn_pdp_ctx *pdp)
{
	struct msgb *msg = gsm48_msgb_alloc();
	struct gsm48_hdr *gh;
	uint8_t transaction_id = pdp->ti ^ 0x8; /* flip */

	DEBUGP(DMM, "<- DEACTIVATE PDP CONTEXT ACK\n");

	mmctx2msgid(msg, pdp->mm);

	gh = (struct gsm48_hdr *) msgb_put(msg, sizeof(*gh));
	gh->proto_discr = GSM48_PDISC_SM_GPRS | (transaction_id << 4);
	gh->msg_type = GSM48_MT_GSM_DEACT_PDP_ACK;

	return gsm48_gmm_sendmsg(msg, 0, pdp->mm);
}

/* Section 9.5.1: Activate PDP Context Request */
static int gsm48_rx_gsm_act_pdp_req(struct sgsn_mm_ctx *mmctx,
				    struct msgb *msg)
{
	struct gsm48_hdr *gh = (struct gsm48_hdr *) msgb_gmmh(msg);
	struct gsm48_act_pdp_ctx_req *act_req = (struct gsm48_act_pdp_ctx_req *) gh->data;
	uint8_t req_qos_len, req_pdpa_len;
	uint8_t *req_qos, *req_pdpa;
	struct tlv_parsed tp;
	uint8_t transaction_id = (gh->proto_discr >> 4);
	struct sgsn_pdp_ctx *pdp;

	DEBUGP(DMM, "-> ACTIVATE PDP CONTEXT REQ: SAPI=%u NSAPI=%u ",
		act_req->req_llc_sapi, act_req->req_nsapi);

	rate_ctr_inc(&mmctx->ctrg->ctr[GMM_CTR_PDP_CTX_ACT]);

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

	DEBUGPC(DMM, "\n");

	/* put the non-TLV elements in the TLV parser structure to
	 * pass them on to the SGSN / GTP code */
	tp.lv[OSMO_IE_GSM_REQ_QOS].len = req_qos_len;
	tp.lv[OSMO_IE_GSM_REQ_QOS].val = req_qos;
	tp.lv[OSMO_IE_GSM_REQ_PDP_ADDR].len = req_pdpa_len;
	tp.lv[OSMO_IE_GSM_REQ_PDP_ADDR].val = req_pdpa;

	/* FIXME:  determine GGSN based on APN and subscription options */
	if (TLVP_PRESENT(&tp, GSM48_IE_GSM_APN)) {}

	/* Check if NSAPI is out of range (TS 04.65 / 7.2) */
	if (act_req->req_nsapi < 5 || act_req->req_nsapi > 15) {
		/* Send reject with GSM_CAUSE_INV_MAND_INFO */
		return gsm48_tx_gsm_act_pdp_rej(mmctx, transaction_id,
						GSM_CAUSE_INV_MAND_INFO,
						0, NULL);
	}

	/* Check if NSAPI is already in use */
	if (sgsn_pdp_ctx_by_nsapi(mmctx, act_req->req_nsapi)) {
		/* FIXME: send reject with GSM_CAUSE_NSAPI_IN_USE */
		return gsm48_tx_gsm_act_pdp_rej(mmctx, transaction_id,
						GSM_CAUSE_NSAPI_IN_USE,
						0, NULL);
	}

#if 1
	{
		pdp = sgsn_create_pdp_ctx(dummy_ggsn, mmctx, act_req->req_nsapi, &tp);
		if (!pdp)
			return -1;
		pdp->sapi = act_req->req_llc_sapi;
		pdp->ti = transaction_id;
		
	}
	return 0;
#else
	return gsm48_tx_gsm_act_pdp_acc(mmctx, transaction_id, act_req);
#endif
}

/* Section 9.5.8: Deactivate PDP Context Request */
static int gsm48_rx_gsm_deact_pdp_req(struct sgsn_mm_ctx *mm, struct msgb *msg)
{
	struct gsm48_hdr *gh = (struct gsm48_hdr *) msgb_gmmh(msg);
	uint8_t transaction_id = (gh->proto_discr >> 4);
	struct sgsn_pdp_ctx *pdp;

	DEBUGP(DMM, "-> DEACTIVATE PDP CONTEXT REQ (cause: %s)\n",
		get_value_string(gsm_cause_names, gh->data[0]));

	pdp = sgsn_pdp_ctx_by_tid(mm, transaction_id);
	if (!pdp) {
		LOGP(DMM, LOGL_NOTICE, "Deactivate PDP Context Request for "
			"non-existing PDP Context (IMSI=%s, TI=%u)\n",
			mm->imsi, transaction_id);
		return -EINVAL;
	}

	return sgsn_delete_pdp_ctx(pdp);
}

static int gsm48_rx_gsm_status(struct sgsn_mm_ctx *ctx, struct msgb *msg)
{
	struct gsm48_hdr *gh = msgb_l3(msg);

	DEBUGP(DMM, "-> GPRS SM STATUS (cause: %s)\n",
		get_value_string(gsm_cause_names, gh->data[0]));

	return 0;
}

/* GPRS Session Management */
static int gsm0408_rcv_gsm(struct sgsn_mm_ctx *mmctx, struct msgb *msg)
{
	struct gsm48_hdr *gh = (struct gsm48_hdr *) msgb_gmmh(msg);
	int rc;

	if (!mmctx) {
		LOGP(DMM, LOGL_NOTICE, "Cannot handle SM for unknown MM CTX\n");
		return -EINVAL;
	}

	switch (gh->msg_type) {
	case GSM48_MT_GSM_ACT_PDP_REQ:
		rc = gsm48_rx_gsm_act_pdp_req(mmctx, msg);
		break;
	case GSM48_MT_GSM_DEACT_PDP_REQ:
		rc = gsm48_rx_gsm_deact_pdp_req(mmctx, msg);
		break;
	case GSM48_MT_GSM_STATUS:
		rc = gsm48_rx_gsm_status(mmctx, msg);
		break;
	case GSM48_MT_GSM_REQ_PDP_ACT_REJ:
	case GSM48_MT_GSM_ACT_AA_PDP_REQ:
	case GSM48_MT_GSM_DEACT_AA_PDP_REQ:
		DEBUGP(DMM, "Unimplemented GSM 04.08 GSM msg type 0x%02x\n",
			gh->msg_type);
		break;
	default:
		DEBUGP(DMM, "Unknown GSM 04.08 GSM msg type 0x%02x\n",
			gh->msg_type);
		break;

	}

	return rc;
}

/* Main entry point for incoming 04.08 GPRS messages */
int gsm0408_gprs_rcvmsg(struct msgb *msg)
{
	struct gsm48_hdr *gh = (struct gsm48_hdr *) msgb_gmmh(msg);
	uint8_t pdisc = gh->proto_discr & 0x0f;
	struct sgsn_mm_ctx *mmctx;
	struct gprs_ra_id ra_id;
	int rc = -EINVAL;

	bssgp_parse_cell_id(&ra_id, msgb_bcid(msg));
	mmctx = sgsn_mm_ctx_by_tlli(msgb_tlli(msg), &ra_id);
	if (mmctx) {
		msgid2mmctx(mmctx, msg);
		rate_ctr_inc(&mmctx->ctrg->ctr[GMM_CTR_PKTS_SIG_IN]);
	}

	/* MMCTX can be NULL */

	switch (pdisc) {
	case GSM48_PDISC_MM_GPRS:
		rc = gsm0408_rcv_gmm(mmctx, msg);
		break;
	case GSM48_PDISC_SM_GPRS:
		rc = gsm0408_rcv_gsm(mmctx, msg);
		break;
	default:
		DEBUGP(DMM, "Unknown GSM 04.08 discriminator 0x%02x\n",
			pdisc);
		/* FIXME: return status message */
		break;
	}

	return rc;
}
