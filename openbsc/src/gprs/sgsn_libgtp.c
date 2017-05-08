/* GPRS SGSN integration with libgtp of OpenGGSN */
/* libgtp implements the GPRS Tunelling Protocol GTP per TS 09.60 / 29.060 */

/* (C) 2010 by Harald Welte <laforge@gnumonks.org>
 * (C) 2010 by On-Waves
 * (C) 2015 by Holger Hans Peter Freyther
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

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <errno.h>
#include <signal.h>
#include <sys/fcntl.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "bscconfig.h"

#include <osmocom/core/talloc.h>
#include <osmocom/core/select.h>
#include <osmocom/core/rate_ctr.h>
#include <osmocom/gprs/gprs_bssgp.h>
#include <osmocom/gsm/protocol/gsm_04_08_gprs.h>

#include <openbsc/signal.h>
#include <openbsc/debug.h>
#include <openbsc/sgsn.h>
#include <openbsc/gprs_llc.h>
#include <openbsc/gprs_sgsn.h>
#include <openbsc/gprs_gmm.h>
#include <openbsc/gprs_subscriber.h>
#include <openbsc/gprs_sndcp.h>

#ifdef BUILD_IU
#include <openbsc/iu.h>
#include <osmocom/ranap/ranap_ies_defs.h>
#endif

#include <gtp.h>
#include <pdp.h>

/* TS 23.003: The MSISDN shall take the dummy MSISDN value composed of
 * 15 digits set to 0 (encoded as an E.164 international number) when
 * the MSISDN is not available in messages in which the presence of the
 * MSISDN parameter */
static const uint8_t dummy_msisdn[] =
	{ 0x91, /* No extension, international, E.164 */
	  0, 0, 0, 0, 0, 0, 0, /* 14 digits of zeroes */
	  0xF0 /* 15th digit of zero + padding */ };

const struct value_string gtp_cause_strs[] = {
	{ GTPCAUSE_REQ_IMSI, "Request IMSI" },
	{ GTPCAUSE_REQ_IMEI, "Request IMEI" },
	{ GTPCAUSE_REQ_IMSI_IMEI, "Request IMSI and IMEI" },
	{ GTPCAUSE_NO_ID_NEEDED, "No identity needed" },
	{ GTPCAUSE_MS_REFUSES_X, "MS refuses" },
	{ GTPCAUSE_MS_NOT_RESP_X, "MS is not GPRS responding" },
	{ GTPCAUSE_ACC_REQ, "Request accepted" },
	{ GTPCAUSE_NON_EXIST, "Non-existent" },
	{ GTPCAUSE_INVALID_MESSAGE, "Invalid message format" },
	{ GTPCAUSE_IMSI_NOT_KNOWN, "IMSI not known" },
	{ GTPCAUSE_MS_DETACHED, "MS is GPRS detached" },
	{ GTPCAUSE_MS_NOT_RESP, "MS is not GPRS responding" },
	{ GTPCAUSE_MS_REFUSES, "MS refuses" },
	{ GTPCAUSE_NO_RESOURCES, "No resources available" },
	{ GTPCAUSE_NOT_SUPPORTED, "Service not supported" },
	{ GTPCAUSE_MAN_IE_INCORRECT, "Mandatory IE incorrect" },
	{ GTPCAUSE_MAN_IE_MISSING, "Mandatory IE missing" },
	{ GTPCAUSE_OPT_IE_INCORRECT, "Optional IE incorrect" },
	{ GTPCAUSE_SYS_FAIL, "System failure" },
	{ GTPCAUSE_ROAMING_REST, "Roaming restrictions" },
	{ GTPCAUSE_PTIMSI_MISMATCH, "P-TMSI Signature mismatch" },
	{ GTPCAUSE_CONN_SUSP, "GPRS connection suspended" },
	{ GTPCAUSE_AUTH_FAIL, "Authentication failure" },
	{ GTPCAUSE_USER_AUTH_FAIL, "User authentication failed" },
	{ GTPCAUSE_CONTEXT_NOT_FOUND, "Context not found" },
	{ GTPCAUSE_ADDR_OCCUPIED, "All dynamic PDP addresses occupied" },
	{ GTPCAUSE_NO_MEMORY, "No memory is available" },
	{ GTPCAUSE_RELOC_FAIL, "Relocation failure" },
	{ GTPCAUSE_UNKNOWN_MAN_EXTHEADER, "Unknown mandatory ext. header" },
	{ GTPCAUSE_SEM_ERR_TFT, "Semantic error in TFT operation" },
	{ GTPCAUSE_SYN_ERR_TFT, "Syntactic error in TFT operation" },
	{ GTPCAUSE_SEM_ERR_FILTER, "Semantic errors in packet filter" },
	{ GTPCAUSE_SYN_ERR_FILTER, "Syntactic errors in packet filter" },
	{ GTPCAUSE_MISSING_APN, "Missing or unknown APN" },
	{ GTPCAUSE_UNKNOWN_PDP, "Unknown PDP address or PDP type" },
	{ 0, NULL }
};

/* Generate the GTP IMSI IE according to 09.60 Section 7.9.2 */
static uint64_t imsi_str2gtp(char *str)
{
	uint64_t imsi64 = 0;
	unsigned int n;
	unsigned int imsi_len = strlen(str);

	if (imsi_len > 16) {
		LOGP(DGPRS, LOGL_NOTICE, "IMSI length > 16 not supported!\n");
		return 0;
	}

	for (n = 0; n < 16; n++) {
		uint64_t val;
		if (n < imsi_len)
			val = (str[n]-'0') & 0xf;
		else
			val = 0xf;
		imsi64 |= (val << (n*4));
	}
	return imsi64;
}

/* generate a PDP context based on the IE's from the 04.08 message,
 * and send the GTP create pdp context request to the GGSN */
struct sgsn_pdp_ctx *sgsn_create_pdp_ctx(struct sgsn_ggsn_ctx *ggsn,
					 struct sgsn_mm_ctx *mmctx,
					 uint16_t nsapi,
					 struct tlv_parsed *tp)
{
	struct gprs_ra_id raid;
	struct sgsn_pdp_ctx *pctx;
	struct pdp_t *pdp;
	uint64_t imsi_ui64;
	size_t qos_len;
	const uint8_t *qos;
	int rc;

	LOGP(DGPRS, LOGL_ERROR, "Create PDP Context\n");
	pctx = sgsn_pdp_ctx_alloc(mmctx, nsapi);
	if (!pctx) {
		LOGP(DGPRS, LOGL_ERROR, "Couldn't allocate PDP Ctx\n");
		return NULL;
	}

	imsi_ui64 = imsi_str2gtp(mmctx->imsi);

	rc = pdp_newpdp(&pdp, imsi_ui64, nsapi, NULL);
	if (rc) {
		LOGP(DGPRS, LOGL_ERROR, "Out of libgtp PDP Contexts\n");
		return NULL;
	}
	pdp->priv = pctx;
	pctx->lib = pdp;
	pctx->ggsn = ggsn;

	//pdp->peer =	/* sockaddr_in of GGSN (receive) */
	//pdp->ipif =	/* not used by library */
	pdp->version = ggsn->gtp_version;
	pdp->hisaddr0 =	ggsn->remote_addr;
	pdp->hisaddr1 = ggsn->remote_addr;
	//pdp->cch_pdp = 512;	/* Charging Flat Rate */

	/* MS provided APN, subscription was verified by the caller */
	pdp->selmode = 0xFC | 0x00;

	/* IMSI, TEID/TEIC, FLLU/FLLC, TID, NSAPI set in pdp_newpdp */

	/* Put the MSISDN in case we have it */
	if (mmctx->subscr && mmctx->subscr->sgsn_data->msisdn_len) {
		pdp->msisdn.l = mmctx->subscr->sgsn_data->msisdn_len;
		if (pdp->msisdn.l > sizeof(pdp->msisdn.v))
			pdp->msisdn.l = sizeof(pdp->msisdn.v);
		memcpy(pdp->msisdn.v, mmctx->subscr->sgsn_data->msisdn,
			pdp->msisdn.l);
	} else {
		/* use the dummy 15-digits-zero MSISDN value */
		pdp->msisdn.l = sizeof(dummy_msisdn);
		memcpy(pdp->msisdn.v, dummy_msisdn, pdp->msisdn.l);
	}

	/* End User Address from GMM requested PDP address */
	pdp->eua.l = TLVP_LEN(tp, OSMO_IE_GSM_REQ_PDP_ADDR);
	if (pdp->eua.l > sizeof(pdp->eua.v))
		pdp->eua.l = sizeof(pdp->eua.v);
	memcpy(pdp->eua.v, TLVP_VAL(tp, OSMO_IE_GSM_REQ_PDP_ADDR),
		pdp->eua.l);
	/* Highest 4 bits of first byte need to be set to 1, otherwise
	 * the IE is identical with the 04.08 PDP Address IE */
	pdp->eua.v[0] |= 0xf0;

	/* APN name from GMM */
	pdp->apn_use.l = TLVP_LEN(tp, GSM48_IE_GSM_APN);
	if (pdp->apn_use.l > sizeof(pdp->apn_use.v))
		pdp->apn_use.l = sizeof(pdp->apn_use.v);
	memcpy(pdp->apn_use.v, TLVP_VAL(tp, GSM48_IE_GSM_APN),
		pdp->apn_use.l);

	/* Protocol Configuration Options from GMM */
	pdp->pco_req.l = TLVP_LEN(tp, GSM48_IE_GSM_PROTO_CONF_OPT);
	if (pdp->pco_req.l > sizeof(pdp->pco_req.v))
		pdp->pco_req.l = sizeof(pdp->pco_req.v);
	memcpy(pdp->pco_req.v, TLVP_VAL(tp, GSM48_IE_GSM_PROTO_CONF_OPT),
		pdp->pco_req.l);

	/* QoS options from GMM or remote */
	if (TLVP_LEN(tp, OSMO_IE_GSM_SUB_QOS) > 0) {
		qos_len = TLVP_LEN(tp, OSMO_IE_GSM_SUB_QOS);
		qos = TLVP_VAL(tp, OSMO_IE_GSM_SUB_QOS);
	} else {
		qos_len = TLVP_LEN(tp, OSMO_IE_GSM_REQ_QOS);
		qos = TLVP_VAL(tp, OSMO_IE_GSM_REQ_QOS);
	}

	if (qos_len <= 3) {
		pdp->qos_req.l = qos_len + 1;
		if (pdp->qos_req.l > sizeof(pdp->qos_req.v))
			pdp->qos_req.l = sizeof(pdp->qos_req.v);
		pdp->qos_req.v[0] = 0; /* Allocation/Retention policy */
		memcpy(&pdp->qos_req.v[1], qos, pdp->qos_req.l - 1);
	} else {
		pdp->qos_req.l = qos_len;
		if (pdp->qos_req.l > sizeof(pdp->qos_req.v))
			pdp->qos_req.l = sizeof(pdp->qos_req.v);
		memcpy(pdp->qos_req.v, qos, pdp->qos_req.l);
	}

	/* SGSN address for control plane */
	pdp->gsnlc.l = sizeof(sgsn->cfg.gtp_listenaddr.sin_addr);
	memcpy(pdp->gsnlc.v, &sgsn->cfg.gtp_listenaddr.sin_addr,
		sizeof(sgsn->cfg.gtp_listenaddr.sin_addr));

	/* SGSN address for user plane
	 * Default to the control plane addr for now. If we are connected to a
	 * hnbgw via IuPS we'll need to send a PDP context update with the
	 * correct IP address after the RAB Assignment is complete */
	pdp->gsnlu.l = sizeof(sgsn->cfg.gtp_listenaddr.sin_addr);
	memcpy(pdp->gsnlu.v, &sgsn->cfg.gtp_listenaddr.sin_addr,
		sizeof(sgsn->cfg.gtp_listenaddr.sin_addr));

	/* Assume we are a GERAN system */
	pdp->rattype.l = 1;
	pdp->rattype.v[0] = 2;
	pdp->rattype_given = 1;

	/* Include RAI and ULI all the time */
	pdp->rai_given = 1;
	pdp->rai.l = 6;
	raid = mmctx->ra;
	raid.lac = 0xFFFE;
	raid.rac = 0xFF;
	gsm48_construct_ra(pdp->rai.v, &raid);

	pdp->userloc_given = 1;
	pdp->userloc.l = 8;
	pdp->userloc.v[0] = 0; /* CGI for GERAN */
	bssgp_create_cell_id(&pdp->userloc.v[1], &mmctx->ra, mmctx->gb.cell_id);

	/* include the IMEI(SV) */
	pdp->imeisv_given = 1;
	gsm48_encode_bcd_number(&pdp->imeisv.v[0], 8, 0, mmctx->imei);
	pdp->imeisv.l = pdp->imeisv.v[0];
	memmove(&pdp->imeisv.v[0], &pdp->imeisv.v[1], 8);

	/* change pdp state to 'requested' */
	pctx->state = PDP_STATE_CR_REQ;

	rc = gtp_create_context_req(ggsn->gsn, pdp, pctx);
	/* FIXME */

	return pctx;
}

/* SGSN wants to delete a PDP context */
int sgsn_delete_pdp_ctx(struct sgsn_pdp_ctx *pctx)
{
	LOGPDPCTXP(LOGL_ERROR, pctx, "Delete PDP Context\n");

	/* FIXME: decide if we need teardown or not ! */
	return gtp_delete_context_req(pctx->ggsn->gsn, pctx->lib, pctx, 1);
}

struct cause_map {
	uint8_t cause_in;
	uint8_t cause_out;
};

static uint8_t cause_map(const struct cause_map *map, uint8_t in, uint8_t deflt)
{
	const struct cause_map *m;

	for (m = map; m->cause_in && m->cause_out; m++) {
		if (m->cause_in == in)
			return m->cause_out;
	}
	return deflt;
}

/* how do we map from gtp cause to SM cause */
static const struct cause_map gtp2sm_cause_map[] = {
	{ GTPCAUSE_NO_RESOURCES, 	GSM_CAUSE_INSUFF_RSRC },
	{ GTPCAUSE_NOT_SUPPORTED,	GSM_CAUSE_SERV_OPT_NOTSUPP },
	{ GTPCAUSE_MAN_IE_INCORRECT,	GSM_CAUSE_INV_MAND_INFO },
	{ GTPCAUSE_MAN_IE_MISSING,	GSM_CAUSE_INV_MAND_INFO },
	{ GTPCAUSE_OPT_IE_INCORRECT,	GSM_CAUSE_PROTO_ERR_UNSPEC },
	{ GTPCAUSE_SYS_FAIL,		GSM_CAUSE_NET_FAIL },
	{ GTPCAUSE_ROAMING_REST,	GSM_CAUSE_REQ_SERV_OPT_NOTSUB },
	{ GTPCAUSE_PTIMSI_MISMATCH,	GSM_CAUSE_PROTO_ERR_UNSPEC },
	{ GTPCAUSE_CONN_SUSP,		GSM_CAUSE_PROTO_ERR_UNSPEC },
	{ GTPCAUSE_AUTH_FAIL,		GSM_CAUSE_AUTH_FAILED },
	{ GTPCAUSE_USER_AUTH_FAIL,	GSM_CAUSE_ACT_REJ_GGSN },
	{ GTPCAUSE_CONTEXT_NOT_FOUND,	GSM_CAUSE_PROTO_ERR_UNSPEC },
	{ GTPCAUSE_ADDR_OCCUPIED,	GSM_CAUSE_INSUFF_RSRC },
	{ GTPCAUSE_NO_MEMORY,		GSM_CAUSE_INSUFF_RSRC },
	{ GTPCAUSE_RELOC_FAIL,		GSM_CAUSE_PROTO_ERR_UNSPEC },
	{ GTPCAUSE_UNKNOWN_MAN_EXTHEADER, GSM_CAUSE_PROTO_ERR_UNSPEC },
	{ GTPCAUSE_MISSING_APN,		GSM_CAUSE_MISSING_APN },
	{ GTPCAUSE_UNKNOWN_PDP,		GSM_CAUSE_UNKNOWN_PDP },
	{ 0, 0 }
};

static int send_act_pdp_cont_acc(struct sgsn_pdp_ctx *pctx)
{
	struct sgsn_signal_data sig_data;
	int rc;
	struct gprs_llc_lle *lle;

	/* Inform others about it */
	memset(&sig_data, 0, sizeof(sig_data));
	sig_data.pdp = pctx;
	osmo_signal_dispatch(SS_SGSN, S_SGSN_PDP_ACT, &sig_data);

	/* Send PDP CTX ACT to MS */
	rc = gsm48_tx_gsm_act_pdp_acc(pctx);
	if (rc < 0)
		return rc;

	if (pctx->mm->ran_type == MM_CTX_T_GERAN_Gb) {
		/* Send SNDCP XID to MS */
		lle = &pctx->mm->gb.llme->lle[pctx->sapi];
		rc = sndcp_sn_xid_req(lle,pctx->nsapi);
		if (rc < 0)
			return rc;
	}

	return 0;
}

/* The GGSN has confirmed the creation of a PDP Context */
static int create_pdp_conf(struct pdp_t *pdp, void *cbp, int cause)
{
	struct sgsn_pdp_ctx *pctx = cbp;
	uint8_t reject_cause;

	LOGPDPCTXP(LOGL_INFO, pctx, "Received CREATE PDP CTX CONF, cause=%d(%s)\n",
		cause, get_value_string(gtp_cause_strs, cause));

	if (!pctx->mm) {
		LOGP(DGPRS, LOGL_INFO,
		     "No MM context, aborting CREATE PDP CTX CONF\n");
		return -EIO;
	}

	/* Check for cause value if it was really successful */
	if (cause < 0) {
		LOGP(DGPRS, LOGL_NOTICE, "Create PDP ctx req timed out\n");
		if (pdp && pdp->version == 1) {
			pdp->version = 0;
			gtp_create_context_req(sgsn->gsn, pdp, cbp);
			return 0;
		} else {
			reject_cause = GSM_CAUSE_NET_FAIL;
			goto reject;
		}
	}

	/* Check for cause value if it was really successful */
	if (cause != GTPCAUSE_ACC_REQ) {
		reject_cause = cause_map(gtp2sm_cause_map, cause,
					 GSM_CAUSE_ACT_REJ_GGSN);
		goto reject;
	}

	if (pctx->mm->ran_type == MM_CTX_T_GERAN_Gb) {
		/* Activate the SNDCP layer */
		sndcp_sm_activate_ind(&pctx->mm->gb.llme->lle[pctx->sapi], pctx->nsapi);
		return send_act_pdp_cont_acc(pctx);
	} else if (pctx->mm->ran_type == MM_CTX_T_UTRAN_Iu) {
#ifdef BUILD_IU
		/* Activate a radio bearer */
		iu_rab_act_ps(pdp->nsapi, pctx, 1);
		return 0;
#else
		return -ENOTSUP;
#endif
	}

	LOGP(DGPRS, LOGL_ERROR, "Unknown ran_type %d\n",
	     pctx->mm->ran_type);
	reject_cause = GSM_CAUSE_PROTO_ERR_UNSPEC;

reject:
	/*
	 * In case of a timeout pdp will be NULL but we have a valid pointer
	 * in pctx->lib. For other rejects pctx->lib and pdp might be the
	 * same.
	 */
	pctx->state = PDP_STATE_NONE;
	if (pctx->lib && pctx->lib != pdp)
		pdp_freepdp(pctx->lib);
	pctx->lib = NULL;

	if (pdp)
		pdp_freepdp(pdp);
	/* Send PDP CTX ACT REJ to MS */
	gsm48_tx_gsm_act_pdp_rej(pctx->mm, pctx->ti, reject_cause,
					0, NULL);
	sgsn_pdp_ctx_free(pctx);

	return EOF;
}

void sgsn_pdp_upd_gtp_u(struct sgsn_pdp_ctx *pdp, void *addr, size_t alen)
{
	pdp->lib->gsnlu.l = alen;
	memcpy(pdp->lib->gsnlu.v, addr, alen);
	gtp_update_context(pdp->ggsn->gsn, pdp->lib, pdp, &pdp->lib->hisaddr0);
}

#ifdef BUILD_IU
/* Callback for RAB assignment response */
int sgsn_ranap_rab_ass_resp(struct sgsn_mm_ctx *ctx, RANAP_RAB_SetupOrModifiedItemIEs_t *setup_ies)
{
	uint8_t rab_id;
	bool require_pdp_update = false;
	struct sgsn_pdp_ctx *pdp = NULL;
	RANAP_RAB_SetupOrModifiedItem_t *item = &setup_ies->raB_SetupOrModifiedItem;

	rab_id = item->rAB_ID.buf[0];

	pdp = sgsn_pdp_ctx_by_nsapi(ctx, rab_id);
	if (!pdp) {
		LOGP(DRANAP, LOGL_ERROR, "RAB Assignment Response for unknown RAB/NSAPI=%u\n", rab_id);
		return -1;
	}

	if (item->transportLayerAddress) {
		LOGPC(DRANAP, LOGL_INFO, " Setup: (%u/%s)", rab_id, osmo_hexdump(item->transportLayerAddress->buf,
								     item->transportLayerAddress->size));
		switch (item->transportLayerAddress->size) {
		case 7:
			/* It must be IPv4 inside a X213 NSAP */
			memcpy(pdp->lib->gsnlu.v, &item->transportLayerAddress->buf[3], 4);
			break;
		case 4:
			/* It must be a raw IPv4 address */
			memcpy(pdp->lib->gsnlu.v, item->transportLayerAddress->buf, 4);
			break;
		case 16:
			/* TODO: It must be a raw IPv6 address */
		case 19:
			/* TODO: It must be IPv6 inside a X213 NSAP */
		default:
			LOGP(DRANAP, LOGL_ERROR, "RAB Assignment Resp: Unknown "
				"transport layer address size %u\n",
				item->transportLayerAddress->size);
			return -1;
		}
		require_pdp_update = true;
	}

	/* The TEI on the RNC side might have changed, too */
	if (item->iuTransportAssociation &&
	    item->iuTransportAssociation->present == RANAP_IuTransportAssociation_PR_gTP_TEI &&
	    item->iuTransportAssociation->choice.gTP_TEI.buf &&
	    item->iuTransportAssociation->choice.gTP_TEI.size >= 4) {
		uint32_t tei = osmo_load32be(item->iuTransportAssociation->choice.gTP_TEI.buf);
		LOGP(DRANAP, LOGL_DEBUG, "Updating TEID on RNC side from 0x%08x to 0x%08x\n",
			pdp->lib->teid_own, tei);
		pdp->lib->teid_own = tei;
		require_pdp_update = true;
	}

	if (require_pdp_update)
		gtp_update_context(pdp->ggsn->gsn, pdp->lib, pdp, &pdp->lib->hisaddr0);

	if (pdp->state != PDP_STATE_CR_CONF) {
		send_act_pdp_cont_acc(pdp);
		pdp->state = PDP_STATE_CR_CONF;
	}
	return 0;

}
#endif

/* Confirmation of a PDP Context Delete */
static int delete_pdp_conf(struct pdp_t *pdp, void *cbp, int cause)
{
	struct sgsn_signal_data sig_data;
	struct sgsn_pdp_ctx *pctx = cbp;
	int rc = 0;

	LOGPDPCTXP(LOGL_INFO, pctx, "Received DELETE PDP CTX CONF, cause=%d(%s)\n",
		cause, get_value_string(gtp_cause_strs, cause));

	memset(&sig_data, 0, sizeof(sig_data));
	sig_data.pdp = pctx;
	osmo_signal_dispatch(SS_SGSN, S_SGSN_PDP_DEACT, &sig_data);

	if (pctx->mm) {
		if (pctx->mm->ran_type == MM_CTX_T_GERAN_Gb) {
			/* Deactivate the SNDCP layer */
			sndcp_sm_deactivate_ind(&pctx->mm->gb.llme->lle[pctx->sapi], pctx->nsapi);
		} else {
#ifdef BUILD_IU
			/* Deactivate radio bearer */
			iu_rab_deact(pctx->mm->iu.ue_ctx, 1);
#else
			return -ENOTSUP;
#endif
		}

		/* Confirm deactivation of PDP context to MS */
		rc = gsm48_tx_gsm_deact_pdp_acc(pctx);
	} else {
		LOGPDPCTXP(LOGL_NOTICE, pctx,
			   "Not deactivating SNDCP layer since the MM context "
			   "is not available\n");
	}

	/* unlink the now non-existing library handle from the pdp
	 * context */
	pctx->lib = NULL;

	sgsn_pdp_ctx_free(pctx);

	return rc;
}

/* Confirmation of an GTP ECHO request */
static int echo_conf(struct pdp_t *pdp, void *cbp, int recovery)
{
	if (recovery < 0) {
		LOGP(DGPRS, LOGL_NOTICE, "GTP Echo Request timed out\n");
		/* FIXME: if version == 1, retry with version 0 */
	} else {
		DEBUGP(DGPRS, "GTP Rx Echo Response\n");
	}
	return 0;
}

/* Any message received by GGSN contains a recovery IE */
static int cb_recovery(struct sockaddr_in *peer, uint8_t recovery)
{
	struct sgsn_ggsn_ctx *ggsn;
	
	ggsn = sgsn_ggsn_ctx_by_addr(&peer->sin_addr);
	if (!ggsn) {
		LOGP(DGPRS, LOGL_NOTICE, "Received Recovery IE for unknown GGSN\n");
		return -EINVAL;
	}

	if (ggsn->remote_restart_ctr == -1) {
		/* First received ECHO RESPONSE, note the restart ctr */
		ggsn->remote_restart_ctr = recovery;
	} else if (ggsn->remote_restart_ctr != recovery) {
		/* counter has changed (GGSN restart): release all PDP */
		LOGP(DGPRS, LOGL_NOTICE, "GGSN recovery (%u->%u), "
		     "releasing all PDP contexts\n",
		     ggsn->remote_restart_ctr, recovery);
		ggsn->remote_restart_ctr = recovery;
		drop_all_pdp_for_ggsn(ggsn);
	}
	return 0;
}

/* libgtp callback for confirmations */
static int cb_conf(int type, int cause, struct pdp_t *pdp, void *cbp)
{
	DEBUGP(DGPRS, "libgtp cb_conf(type=%d, cause=%d, pdp=%p, cbp=%p)\n",
		type, cause, pdp, cbp);

	if (cause == EOF)
		LOGP(DGPRS, LOGL_ERROR, "libgtp EOF (type=%u, pdp=%p, cbp=%p)\n",
			type, pdp, cbp);

	switch (type) {
	case GTP_ECHO_REQ:
		/* libgtp hands us the RECOVERY number instead of a cause */
		return echo_conf(pdp, cbp, cause);
	case GTP_CREATE_PDP_REQ:
		return create_pdp_conf(pdp, cbp, cause);
	case GTP_DELETE_PDP_REQ:
		return delete_pdp_conf(pdp, cbp, cause);
	default:
		break;
	}
	return 0;
}

/* Called whenever a PDP context is deleted for any reason */
static int cb_delete_context(struct pdp_t *pdp)
{
	LOGP(DGPRS, LOGL_INFO, "PDP Context was deleted\n");
	return 0;
}

/* Called when we receive a Version Not Supported message */
static int cb_unsup_ind(struct sockaddr_in *peer)
{
	LOGP(DGPRS, LOGL_INFO, "GTP Version not supported Indication "
		"from %s:%u\n", inet_ntoa(peer->sin_addr),
		ntohs(peer->sin_port));
	return 0;
}

/* Called when we receive a Supported Ext Headers Notification */
static int cb_extheader_ind(struct sockaddr_in *peer)
{
	LOGP(DGPRS, LOGL_INFO, "GTP Supported Ext Headers Noficiation "
		"from %s:%u\n", inet_ntoa(peer->sin_addr),
		ntohs(peer->sin_port));
	return 0;
}

/* Called whenever we recive a DATA packet */
static int cb_data_ind(struct pdp_t *lib, void *packet, unsigned int len)
{
	struct bssgp_paging_info pinfo;
	struct sgsn_pdp_ctx *pdp;
	struct sgsn_mm_ctx *mm;
	struct msgb *msg;
	uint8_t *ud;

	pdp = lib->priv;
	if (!pdp) {
		LOGP(DGPRS, LOGL_NOTICE,
		     "GTP DATA IND from GGSN for unknown PDP\n");
		return -EIO;
	}
	mm = pdp->mm;
	if (!mm) {
		LOGP(DGPRS, LOGL_ERROR,
		     "PDP context (address=%u) without MM context!\n",
		     pdp->address);
		return -EIO;
	}

	DEBUGP(DGPRS, "GTP DATA IND from GGSN for %s, length=%u\n", mm->imsi,
	       len);

	if (mm->ran_type == MM_CTX_T_UTRAN_Iu) {
#ifdef BUILD_IU
		/* Ignore the packet for now and page the UE to get the RAB
		 * reestablished */
		iu_page_ps(mm->imsi, &mm->p_tmsi, mm->ra.lac, mm->ra.rac);

		return 0;
#else
		return -ENOTSUP;
#endif
	}

	msg = msgb_alloc_headroom(len+256, 128, "GTP->SNDCP");
	ud = msgb_put(msg, len);
	memcpy(ud, packet, len);

	msgb_tlli(msg) = mm->gb.tlli;
	msgb_bvci(msg) = mm->gb.bvci;
	msgb_nsei(msg) = mm->gb.nsei;

	switch (mm->gmm_state) {
	case GMM_REGISTERED_SUSPENDED:
		/* initiate PS PAGING procedure */
		memset(&pinfo, 0, sizeof(pinfo));
		pinfo.mode = BSSGP_PAGING_PS;
		pinfo.scope = BSSGP_PAGING_BVCI;
		pinfo.bvci = mm->gb.bvci;
		pinfo.imsi = mm->imsi;
		pinfo.ptmsi = &mm->p_tmsi;
		pinfo.drx_params = mm->drx_parms;
		pinfo.qos[0] = 0; // FIXME
		bssgp_tx_paging(mm->gb.nsei, 0, &pinfo);
		rate_ctr_inc(&mm->ctrg->ctr[GMM_CTR_PAGING_PS]);
		/* FIXME: queue the packet we received from GTP */
		break;
	case GMM_REGISTERED_NORMAL:
		break;
	default:
		LOGP(DGPRS, LOGL_ERROR, "GTP DATA IND for TLLI %08X in state "
			"%u\n", mm->gb.tlli, mm->gmm_state);
		msgb_free(msg);
		return -1;
	}

	rate_ctr_inc(&pdp->ctrg->ctr[PDP_CTR_PKTS_UDATA_OUT]);
	rate_ctr_add(&pdp->ctrg->ctr[PDP_CTR_BYTES_UDATA_OUT], len);
	rate_ctr_inc(&mm->ctrg->ctr[GMM_CTR_PKTS_UDATA_OUT]);
	rate_ctr_add(&mm->ctrg->ctr[GMM_CTR_BYTES_UDATA_OUT], len);

	/* It is easier to have a global count */
	pdp->cdr_bytes_out += len;

	return sndcp_unitdata_req(msg, &mm->gb.llme->lle[pdp->sapi],
				  pdp->nsapi, mm);
}

/* Called by SNDCP when it has received/re-assembled a N-PDU */
int sgsn_rx_sndcp_ud_ind(struct gprs_ra_id *ra_id, int32_t tlli, uint8_t nsapi,
			 struct msgb *msg, uint32_t npdu_len, uint8_t *npdu)
{
	struct sgsn_mm_ctx *mmctx;
	struct sgsn_pdp_ctx *pdp;

	/* look-up the MM context for this message */
	mmctx = sgsn_mm_ctx_by_tlli(tlli, ra_id);
	if (!mmctx) {
		LOGP(DGPRS, LOGL_ERROR,
			"Cannot find MM CTX for TLLI %08x\n", tlli);
		return -EIO;
	}
	/* look-up the PDP context for this message */
	pdp = sgsn_pdp_ctx_by_nsapi(mmctx, nsapi);
	if (!pdp) {
		LOGP(DGPRS, LOGL_ERROR, "Cannot find PDP CTX for "
			"TLLI=%08x, NSAPI=%u\n", tlli, nsapi);
		return -EIO;
	}
	if (!pdp->lib) {
		LOGP(DGPRS, LOGL_ERROR, "PDP CTX without libgtp\n");
		return -EIO;
	}

	rate_ctr_inc(&pdp->ctrg->ctr[PDP_CTR_PKTS_UDATA_IN]);
	rate_ctr_add(&pdp->ctrg->ctr[PDP_CTR_BYTES_UDATA_IN], npdu_len);
	rate_ctr_inc(&mmctx->ctrg->ctr[GMM_CTR_PKTS_UDATA_IN]);
	rate_ctr_add(&mmctx->ctrg->ctr[GMM_CTR_BYTES_UDATA_IN], npdu_len);

	/* It is easier to have a global count */
	pdp->cdr_bytes_in += npdu_len;

	return gtp_data_req(pdp->ggsn->gsn, pdp->lib, npdu, npdu_len);
}

/* libgtp select loop integration */
static int sgsn_gtp_fd_cb(struct osmo_fd *fd, unsigned int what)
{
	struct sgsn_instance *sgi = fd->data;
	int rc;

	if (!(what & BSC_FD_READ))
		return 0;

	switch (fd->priv_nr) {
	case 0:
		rc = gtp_decaps0(sgi->gsn);
		break;
	case 1:
		rc = gtp_decaps1c(sgi->gsn);
		break;
	case 2:
		rc = gtp_decaps1u(sgi->gsn);
		break;
	default:
		rc = -EINVAL;
		break;
	}
	return rc;
}

static void sgsn_gtp_tmr_start(struct sgsn_instance *sgi)
{
	struct timeval next;

	/* Retrieve next retransmission as struct timeval */
	gtp_retranstimeout(sgi->gsn, &next);

	/* re-schedule the timer */
	osmo_timer_schedule(&sgi->gtp_timer, next.tv_sec, next.tv_usec/1000);
}

/* timer callback for libgtp retransmissions and ping */
static void sgsn_gtp_tmr_cb(void *data)
{
	struct sgsn_instance *sgi = data;

	/* Do all the retransmissions as needed */
	gtp_retrans(sgi->gsn);

	sgsn_gtp_tmr_start(sgi);
}

int sgsn_gtp_init(struct sgsn_instance *sgi)
{
	int rc;
	struct gsn_t *gsn;

	rc = gtp_new(&sgi->gsn, sgi->cfg.gtp_statedir,
		     &sgi->cfg.gtp_listenaddr.sin_addr, GTP_MODE_SGSN);
	if (rc) {
		LOGP(DGPRS, LOGL_ERROR, "Failed to create GTP: %d\n", rc);
		return rc;
	}
	gsn = sgi->gsn;

	sgi->gtp_fd0.fd = gsn->fd0;
	sgi->gtp_fd0.priv_nr = 0;
	sgi->gtp_fd0.data = sgi;
	sgi->gtp_fd0.when = BSC_FD_READ;
	sgi->gtp_fd0.cb = sgsn_gtp_fd_cb;
	rc = osmo_fd_register(&sgi->gtp_fd0);
	if (rc < 0)
		return rc;

	sgi->gtp_fd1c.fd = gsn->fd1c;
	sgi->gtp_fd1c.priv_nr = 1;
	sgi->gtp_fd1c.data = sgi;
	sgi->gtp_fd1c.when = BSC_FD_READ;
	sgi->gtp_fd1c.cb = sgsn_gtp_fd_cb;
	rc = osmo_fd_register(&sgi->gtp_fd1c);
	if (rc < 0) {
		osmo_fd_unregister(&sgi->gtp_fd0);
		return rc;
	}

	sgi->gtp_fd1u.fd = gsn->fd1u;
	sgi->gtp_fd1u.priv_nr = 2;
	sgi->gtp_fd1u.data = sgi;
	sgi->gtp_fd1u.when = BSC_FD_READ;
	sgi->gtp_fd1u.cb = sgsn_gtp_fd_cb;
	rc = osmo_fd_register(&sgi->gtp_fd1u);
	if (rc < 0) {
		osmo_fd_unregister(&sgi->gtp_fd0);
		osmo_fd_unregister(&sgi->gtp_fd1c);
		return rc;
	}

	/* Start GTP re-transmission timer */
	osmo_timer_setup(&sgi->gtp_timer, sgsn_gtp_tmr_cb, sgi);
	sgsn_gtp_tmr_start(sgi);

	/* Register callbackcs with libgtp */
	gtp_set_cb_delete_context(gsn, cb_delete_context);
	gtp_set_cb_conf(gsn, cb_conf);
	gtp_set_cb_recovery(gsn, cb_recovery);
	gtp_set_cb_data_ind(gsn, cb_data_ind);
	gtp_set_cb_unsup_ind(gsn, cb_unsup_ind);
	gtp_set_cb_extheader_ind(gsn, cb_extheader_ind);

	return 0;
}
