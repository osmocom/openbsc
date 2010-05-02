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

#include <openbsc/db.h>
#include <osmocore/msgb.h>
#include <osmocore/tlv.h>
#include <openbsc/debug.h>
#include <openbsc/gsm_data.h>
#include <osmocore/gsm_utils.h>
#include <openbsc/gsm_subscriber.h>
#include <openbsc/gsm_04_08.h>
#include <openbsc/gsm_04_08_gprs.h>
#include <openbsc/paging.h>
#include <osmocore/signal.h>
#include <osmocore/talloc.h>
#include <openbsc/transaction.h>
#include <openbsc/gprs_bssgp.h>
#include <openbsc/gprs_llc.h>
#include <openbsc/gprs_sgsn.h>

/* 10.5.5.14 GPRS MM Cause / Table 10.5.147 */
struct value_string gmm_cause_names[] = {
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
struct value_string gsm_cause_names[] = {
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

static const char *att_name(uint8_t type)
{
	switch (type) {
	case GPRS_ATT_T_ATTACH:
		return "GPRS attach";
	case GPRS_ATT_T_ATT_WHILE_IMSI:
		return "GPRS attach while IMSI attached";
	case GPRS_ATT_T_COMBINED:
		return "Combined GPRS/IMSI attach";
	default:
		return "unknown";
	}
}

static const char *upd_name(uint8_t type)
{
	switch (type) {
	case GPRS_UPD_T_RA:
		return "RA updating";
	case GPRS_UPD_T_RA_LA:
		return "combined RA/LA updating";
	case GPRS_UPD_T_RA_LA_IMSI_ATT:
		return "combined RA/LA updating + IMSI attach";
	case GPRS_UPD_T_PERIODIC:
		return "periodic updating";
	}
	return "unknown";
}

/* Send a message through the underlying layer */
static int gsm48_gmm_sendmsg(struct msgb *msg, int command)
{
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

/* Chapter 9.4.2: Attach accept */
static int gsm48_tx_gmm_att_ack(struct msgb *old_msg)
{
	struct msgb *msg = gsm48_msgb_alloc();
	struct gsm48_hdr *gh;
	struct gsm48_attach_ack *aa;
	struct gprs_ra_id ra_id;

	DEBUGP(DMM, "<- GPRS ATTACH ACCEPT\n");

	gmm_copy_id(msg, old_msg);

	gh = (struct gsm48_hdr *) msgb_put(msg, sizeof(*gh));
	gh->proto_discr = GSM48_PDISC_MM_GPRS;
	gh->msg_type = GSM48_MT_GMM_ATTACH_ACK;

	aa = (struct gsm48_attach_ack *) msgb_put(msg, sizeof(*aa));
	aa->force_stby = 0;	/* not indicated */
	aa->att_result = 1;	/* GPRS only */
	aa->ra_upd_timer = GPRS_TMR_MINUTE | 10;
	aa->radio_prio = 4;	/* lowest */
	bssgp_parse_cell_id(&ra_id, msgb_bcid(msg));
	gsm48_construct_ra(aa->ra_id.digits, &ra_id);

	/* Option: P-TMSI signature, allocated P-TMSI, MS ID, ... */
	return gsm48_gmm_sendmsg(msg, 0);
}

/* Chapter 9.4.5: Attach reject */
static int gsm48_tx_gmm_att_rej(struct msgb *old_msg, uint8_t gmm_cause)
{
	struct msgb *msg = gsm48_msgb_alloc();
	struct gsm48_hdr *gh;

	DEBUGP(DMM, "<- GPRS ATTACH REJECT\n");

	gmm_copy_id(msg, old_msg);

	gh = (struct gsm48_hdr *) msgb_put(msg, sizeof(*gh) + 1);
	gh->proto_discr = GSM48_PDISC_MM_GPRS;
	gh->msg_type = GSM48_MT_GMM_ATTACH_REJ;
	gh->data[0] = gmm_cause;

	return gsm48_gmm_sendmsg(msg, 0);
}

/* Transmit Chapter 9.4.12 Identity Request */
static int gsm48_tx_gmm_id_req(struct msgb *old_msg, uint8_t id_type)
{
	struct msgb *msg = gsm48_msgb_alloc();
	struct gsm48_hdr *gh;

	DEBUGP(DMM, "-> GPRS IDENTITY REQUEST: mi_type=%02x\n", id_type);

	gmm_copy_id(msg, old_msg);

	gh = (struct gsm48_hdr *) msgb_put(msg, sizeof(*gh) + 1);
	gh->proto_discr = GSM48_PDISC_MM_GPRS;
	gh->msg_type = GSM48_MT_GMM_ID_REQ;
	/* 10.5.5.9 ID type 2 + identity type and 10.5.5.7 'force to standby' IE */
	gh->data[0] = id_type & 0xf;

	return gsm48_gmm_sendmsg(msg, 0);
}

/* Check if we can already authorize a subscriber */
static int gsm48_gmm_authorize(struct sgsn_mm_ctx *ctx, struct msgb *msg)
{
	if (strlen(ctx->imei) && strlen(ctx->imsi)) {
		ctx->mm_state = GMM_REGISTERED_NORMAL;
		return gsm48_tx_gmm_att_ack(msg);
	} 
	if (!strlen(ctx->imei))
		return gsm48_tx_gmm_id_req(msg, GSM_MI_TYPE_IMEI);

	if (!strlen(ctx->imsi))
		return gsm48_tx_gmm_id_req(msg, GSM_MI_TYPE_IMSI);

	return 0;
}

/* Parse Chapter 9.4.13 Identity Response */
static int gsm48_rx_gmm_id_resp(struct msgb *msg)
{
	struct gsm48_hdr *gh = (struct gsm48_hdr *) msgb_gmmh(msg);
	uint8_t mi_type = gh->data[1] & GSM_MI_TYPE_MASK;
	char mi_string[GSM48_MI_SIZE];
	struct gprs_ra_id ra_id;
	struct sgsn_mm_ctx *ctx;

	gsm48_mi_to_string(mi_string, sizeof(mi_string), &gh->data[1], gh->data[0]);
	DEBUGP(DMM, "GMM IDENTITY RESPONSE: mi_type=0x%02x MI(%s) ",
		mi_type, mi_string);

	bssgp_parse_cell_id(&ra_id, msgb_bcid(msg));
	ctx = sgsn_mm_ctx_by_tlli(msgb_tlli(msg), &ra_id);
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
	return gsm48_gmm_authorize(ctx, msg);
}

static void attach_rej_cb(void *data)
{
	struct sgsn_mm_ctx *ctx = data;

	/* FIXME: determine through which BTS/TRX to send this */
	//gsm48_tx_gmm_att_rej(ctx->tlli, GMM_CAUSE_MS_ID_NOT_DERIVED);
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
static int gsm48_rx_gmm_att_req(struct msgb *msg)
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

	DEBUGP(DMM, "GMM ATTACH REQUEST ");

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

	DEBUGPC(DMM, "MI(%s) type=\"%s\" ", mi_string, att_name(att_type));

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
				return gsm48_tx_gmm_att_rej(msg, GMM_CAUSE_NET_FAIL);
			strncpy(ctx->imsi, mi_string, sizeof(ctx->imsi));
#endif
		}
		/* FIXME: Start some timer */
		ctx->mm_state = GMM_COMMON_PROC_INIT;
		ctx->tlli = msgb_tlli(msg);
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
		}
		break;
	default:
		return 0;
	}
	/* Update MM Context with currient RA and Cell ID */
	ctx->ra = ra_id;
	ctx->cell_id = cid;

	/* FIXME: allocate a new P-TMSI (+ P-TMSI signature) */
	/* FIXME: update the TLLI with the new local TLLI based on the P-TMSI */

	DEBUGPC(DMM, "\n");

	return ctx ? gsm48_gmm_authorize(ctx, msg) : 0;

err_inval:
	DEBUGPC(DMM, "\n");
	return gsm48_tx_gmm_att_rej(msg, GMM_CAUSE_SEM_INCORR_MSG);
}

/* Chapter 9.4.15: Routing area update accept */
static int gsm48_tx_gmm_ra_upd_ack(struct msgb *old_msg)
{
	struct msgb *msg = gsm48_msgb_alloc();
	struct gsm48_hdr *gh;
	struct gsm48_ra_upd_ack *rua;
	struct gprs_ra_id ra_id;

	DEBUGP(DMM, "<- ROUTING AREA UPDATE ACCEPT\n");

	gmm_copy_id(msg, old_msg);

	gh = (struct gsm48_hdr *) msgb_put(msg, sizeof(*gh));
	gh->proto_discr = GSM48_PDISC_MM_GPRS;
	gh->msg_type = GSM48_MT_GMM_RA_UPD_ACK;

	rua = (struct gsm48_ra_upd_ack *) msgb_put(msg, sizeof(*rua));
	rua->force_stby = 0;	/* not indicated */
	rua->upd_result = 0;	/* RA updated */
	rua->ra_upd_timer = GPRS_TMR_MINUTE | 10;

	bssgp_parse_cell_id(&ra_id, msgb_bcid(msg));
	gsm48_construct_ra(rua->ra_id.digits, &ra_id);

	/* Option: P-TMSI signature, allocated P-TMSI, MS ID, ... */
	return gsm48_gmm_sendmsg(msg, 0);
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
	return gsm48_gmm_sendmsg(msg, 0);
}

/* Chapter 9.4.14: Routing area update request */
static int gsm48_rx_gmm_ra_upd_req(struct msgb *msg)
{
	struct gsm48_hdr *gh = (struct gsm48_hdr *) msgb_gmmh(msg);
	struct sgsn_mm_ctx *mmctx;
	uint8_t *cur = gh->data;
	struct gprs_ra_id old_ra_id;
	uint8_t upd_type;

	/* Update Type 10.5.5.18 */
	upd_type = *cur++ & 0x0f;

	DEBUGP(DMM, "GMM RA UPDATE REQUEST type=\"%s\" ", upd_name(upd_type));

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
	mmctx = sgsn_mm_ctx_by_tlli(msgb_tlli(msg), &old_ra_id);
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

	DEBUGPC(DMM, " ACCEPT\n");
	return gsm48_tx_gmm_ra_upd_ack(msg);
}

static int gsm48_rx_gmm_status(struct msgb *msg)
{
	struct gsm48_hdr *gh = msgb_l3(msg);

	DEBUGP(DMM, "GPRS MM STATUS (cause: %s)\n",
		get_value_string(gmm_cause_names, gh->data[0]));

	return 0;
}

/* GPRS Mobility Management */
static int gsm0408_rcv_gmm(struct msgb *msg)
{
	struct gsm48_hdr *gh = (struct gsm48_hdr *) msgb_gmmh(msg);
	int rc;

	switch (gh->msg_type) {
	case GSM48_MT_GMM_RA_UPD_REQ:
		rc = gsm48_rx_gmm_ra_upd_req(msg);
		break;
	case GSM48_MT_GMM_ATTACH_REQ:
		rc = gsm48_rx_gmm_att_req(msg);
		break;
	case GSM48_MT_GMM_ID_RESP:
		rc = gsm48_rx_gmm_id_resp(msg);
		break;
	case GSM48_MT_GMM_STATUS:
		rc = gsm48_rx_gmm_status(msg);
		break;
	case GSM48_MT_GMM_RA_UPD_COMPL:
		/* only in case SGSN offered new P-TMSI */
	case GSM48_MT_GMM_ATTACH_COMPL:
		/* only in case SGSN offered new P-TMSI */
	case GSM48_MT_GMM_DETACH_REQ:
	case GSM48_MT_GMM_PTMSI_REALL_COMPL:
	case GSM48_MT_GMM_AUTH_CIPH_RESP:
		DEBUGP(DMM, "Unimplemented GSM 04.08 GMM msg type 0x%02x\n",
			gh->msg_type);
		break;
	default:
		DEBUGP(DMM, "Unknown GSM 04.08 GMM msg type 0x%02x\n",
			gh->msg_type);
		break;
	}

	return rc;
}

/* Section 9.5.2: Ativate PDP Context Accept */
static int gsm48_tx_gsm_act_pdp_acc(struct msgb *old_msg, struct gsm48_act_pdp_ctx_req *req)
{
	struct gsm48_hdr *old_gh = (struct gsm48_hdr *) msgb_gmmh(old_msg);
	struct msgb *msg = gsm48_msgb_alloc();
	struct gsm48_act_pdp_ctx_ack *act_ack;
	struct gsm48_hdr *gh;
	uint8_t transaction_id = ((old_gh->proto_discr >> 4) ^ 0x8); /* flip */

	DEBUGP(DMM, "<- ACTIVATE PDP CONTEXT ACK\n");

	gmm_copy_id(msg, old_msg);

	gh = (struct gsm48_hdr *) msgb_put(msg, sizeof(*gh));
	gh->proto_discr = GSM48_PDISC_SM_GPRS | (transaction_id << 4);
	gh->msg_type = GSM48_MT_GSM_ACT_PDP_ACK;
	act_ack = (struct gsm48_act_pdp_ctx_ack *)
					msgb_put(msg, sizeof(*act_ack));
	act_ack->llc_sapi = req->req_llc_sapi;
	memcpy(act_ack->qos_lv, req->req_qos_lv, sizeof(act_ack->qos_lv));
	//act_ack->radio_prio = 4;

	return gsm48_gmm_sendmsg(msg, 0);
}

/* Section 9.5.9: Deactivate PDP Context Accept */
static int gsm48_tx_gsm_deact_pdp_acc(struct msgb *old_msg)
{
	struct gsm48_hdr *old_gh = (struct gsm48_hdr *) msgb_gmmh(old_msg);
	struct msgb *msg = gsm48_msgb_alloc();
	struct gsm48_hdr *gh;
	uint8_t transaction_id = ((old_gh->proto_discr >> 4) ^ 0x8); /* flip */

	DEBUGP(DMM, "<- DEACTIVATE PDP CONTEXT ACK\n");

	gmm_copy_id(msg, old_msg);

	gh = (struct gsm48_hdr *) msgb_put(msg, sizeof(*gh));
	gh->proto_discr = GSM48_PDISC_SM_GPRS | (transaction_id << 4);
	gh->msg_type = GSM48_MT_GSM_DEACT_PDP_ACK;

	return gsm48_gmm_sendmsg(msg, 0);
}

/* Section 9.5.1: Activate PDP Context Request */
static int gsm48_rx_gsm_act_pdp_req(struct msgb *msg)
{
	struct gsm48_hdr *gh = (struct gsm48_hdr *) msgb_gmmh(msg);
	struct gsm48_act_pdp_ctx_req *act_req = (struct gsm48_act_pdp_ctx_req *) gh->data;
	uint8_t *pdp_addr_lv = act_req->data;

	DEBUGP(DMM, "ACTIVATE PDP CONTEXT REQ\n");

	/* FIXME: parse access point name + IPCP config options */

	return gsm48_tx_gsm_act_pdp_acc(msg, act_req);
}

/* Section 9.5.8: Deactivate PDP Context Request */
static int gsm48_rx_gsm_deact_pdp_req(struct msgb *msg)
{
	struct gsm48_hdr *gh = (struct gsm48_hdr *) msgb_gmmh(msg);

	DEBUGP(DMM, "DEACTIVATE PDP CONTEXT REQ (cause: %s)\n",
		get_value_string(gsm_cause_names, gh->data[0]));

	return gsm48_tx_gsm_deact_pdp_acc(msg);
}

static int gsm48_rx_gsm_status(struct msgb *msg)
{
	struct gsm48_hdr *gh = msgb_l3(msg);

	DEBUGP(DMM, "GPRS SM STATUS (cause: %s)\n",
		get_value_string(gsm_cause_names, gh->data[0]));

	return 0;
}

/* GPRS Session Management */
static int gsm0408_rcv_gsm(struct msgb *msg)
{
	struct gsm48_hdr *gh = (struct gsm48_hdr *) msgb_gmmh(msg);
	int rc;

	switch (gh->msg_type) {
	case GSM48_MT_GSM_ACT_PDP_REQ:
		rc = gsm48_rx_gsm_act_pdp_req(msg);
		break;
	case GSM48_MT_GSM_DEACT_PDP_REQ:
		rc = gsm48_rx_gsm_deact_pdp_req(msg);
	case GSM48_MT_GSM_STATUS:
		rc = gsm48_rx_gsm_status(msg);
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
	int rc = -EINVAL;

	switch (pdisc) {
	case GSM48_PDISC_MM_GPRS:
		rc = gsm0408_rcv_gmm(msg);
		break;
	case GSM48_PDISC_SM_GPRS:
		rc = gsm0408_rcv_gsm(msg);
		break;
	default:
		DEBUGP(DMM, "Unknown GSM 04.08 discriminator 0x%02x\n",
			pdisc);
		break;
	}

	return rc;
}
