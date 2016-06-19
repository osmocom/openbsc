/* Point-to-Point (PP) Short Message Service (SMS)
 * Support on Mobile Radio Interface
 * 3GPP TS 04.11 version 7.1.0 Release 1998 / ETSI TS 100 942 V7.1.0 */

/* (C) 2008 by Daniel Willmann <daniel@totalueberwachung.de>
 * (C) 2009 by Harald Welte <laforge@gnumonks.org>
 * (C) 2010-2012 by Holger Hans Peter Freyther <zecke@selfish.org>
 * (C) 2010 by On-Waves
 * (C) 2011 by Andreas Eversberg <jolly@eversberg.eu>
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
#include <errno.h>
#include <time.h>
#include <netinet/in.h>

#include "bscconfig.h"

#include <osmocom/core/msgb.h>
#include <osmocom/core/talloc.h>
#include <osmocom/core/utils.h>

#include <osmocom/gsm/gsm_utils.h>
#include <osmocom/gsm/gsm0411_utils.h>
#include <osmocom/gsm/protocol/gsm_04_11.h>

#include <openbsc/debug.h>
#include <openbsc/gsm_data.h>
#include <openbsc/db.h>
#include <openbsc/gsm_subscriber.h>
#include <openbsc/gsm_04_08.h>
#include <openbsc/abis_rsl.h>
#include <openbsc/signal.h>
#include <openbsc/db.h>
#include <openbsc/transaction.h>
#include <openbsc/paging.h>
#include <openbsc/bsc_rll.h>
#include <openbsc/chan_alloc.h>
#include <openbsc/bsc_api.h>
#include <openbsc/osmo_msc.h>
#include <openbsc/vlr.h>

#ifdef BUILD_SMPP
#include "smpp_smsc.h"
#endif

void *tall_gsms_ctx;
static uint32_t new_callref = 0x40000001;


struct gsm_sms *sms_alloc(void)
{
	return talloc_zero(tall_gsms_ctx, struct gsm_sms);
}

void sms_free(struct gsm_sms *sms)
{
	/* drop references to subscriber structure */
	if (sms->receiver)
		vlr_subscr_put(sms->receiver);
#ifdef BUILD_SMPP
	if (sms->smpp.esme)
		smpp_esme_put(sms->smpp.esme);
#endif

	talloc_free(sms);
}

struct gsm_sms *sms_from_text(struct vlr_subscr *receiver,
			      struct vlr_subscr *sender,
                              int dcs, const char *text)
{
	struct gsm_sms *sms = sms_alloc();

	if (!sms)
		return NULL;

	sms->receiver = vlr_subscr_get(receiver);
	osmo_strlcpy(sms->text, text, sizeof(sms->text));

	osmo_strlcpy(sms->src.addr, sender->msisdn, sizeof(sms->src.addr));
	sms->reply_path_req = 0;
	sms->status_rep_req = 0;
	sms->ud_hdr_ind = 0;
	sms->protocol_id = 0; /* implicit */
	sms->data_coding_scheme = dcs;
	osmo_strlcpy(sms->dst.addr, receiver->msisdn, sizeof(sms->dst.addr));
	/* Generate user_data */
	sms->user_data_len = gsm_7bit_encode_n(sms->user_data, sizeof(sms->user_data),
						sms->text, NULL);

	return sms;
}


static void send_signal(int sig_no,
			struct gsm_trans *trans,
			struct gsm_sms *sms,
			int paging_result)
{
	struct sms_signal_data sig;
	sig.trans = trans;
	sig.sms = sms;
	sig.paging_result = paging_result;
	osmo_signal_dispatch(SS_SMS, sig_no, &sig);
}

static int gsm411_sendmsg(struct gsm_subscriber_connection *conn, struct msgb *msg)
{
	DEBUGP(DLSMS, "GSM4.11 TX %s\n", osmo_hexdump(msg->data, msg->len));
	msg->l3h = msg->data;
	return gsm0808_submit_dtap(conn, msg, UM_SAPI_SMS, 1);
}

/* Prefix msg with a 04.08/04.11 CP header */
static int gsm411_cp_sendmsg(struct msgb *msg, struct gsm_trans *trans,
			     uint8_t msg_type)
{
	struct gsm48_hdr *gh;

	gh = (struct gsm48_hdr *) msgb_push(msg, sizeof(*gh));
	/* Outgoing needs the highest bit set */
	gh->proto_discr = trans->protocol | (trans->transaction_id<<4);
	gh->msg_type = msg_type;

	DEBUGP(DLSMS, "sending CP message (trans=%x)\n", trans->transaction_id);

	return gsm411_sendmsg(trans->conn, msg);
}

/* mm_send: receive MMCCSMS sap message from SMC */
static int gsm411_mm_send(struct gsm411_smc_inst *inst, int msg_type,
			struct msgb *msg, int cp_msg_type)
{
	struct gsm_trans *trans =
		container_of(inst, struct gsm_trans, sms.smc_inst);
	int rc = 0;

	switch (msg_type) {
	case GSM411_MMSMS_EST_REQ:
		/* recycle msg */
		rc = gsm411_smc_recv(inst, GSM411_MMSMS_EST_CNF, msg, 0);
		msgb_free(msg); /* upper layer does not free msg */
		break;
	case GSM411_MMSMS_DATA_REQ:
		rc = gsm411_cp_sendmsg(msg, trans, cp_msg_type);
		break;
	case GSM411_MMSMS_REL_REQ:
		DEBUGP(DLSMS, "Got MMSMS_REL_REQ, destroying transaction.\n");
		msgb_free(msg);
		trans_free(trans);
		break;
	default:
		LOGP(DLSMS, LOGL_NOTICE, "Unhandled MMCCSMS msg 0x%x\n", msg_type);
		msgb_free(msg);
		rc = -EINVAL;
	}

	return rc;
}

/* mm_send: receive MNCCSMS sap message from SMR */
int gsm411_mn_send(struct gsm411_smr_inst *inst, int msg_type,
			struct msgb *msg)
{
	struct gsm_trans *trans =
		container_of(inst, struct gsm_trans, sms.smr_inst);

	/* forward to SMC */
	return gsm411_smc_send(&trans->sms.smc_inst, msg_type, msg);
}

static int gsm340_rx_sms_submit(struct msgb *msg, struct gsm_sms *gsms)
{
	if (db_sms_store(gsms) != 0) {
		LOGP(DLSMS, LOGL_ERROR, "Failed to store SMS in Database\n");
		return GSM411_RP_CAUSE_MO_NET_OUT_OF_ORDER;
	}
	/* dispatch a signal to tell higher level about it */
	send_signal(S_SMS_SUBMITTED, NULL, gsms, 0);

	return 0;
}

/* generate a TPDU address field compliant with 03.40 sec. 9.1.2.5 */
static int gsm340_gen_oa_sub(uint8_t *oa, unsigned int oa_len,
			 const struct gsm_sms_addr *src)
{
	/* network specific, private numbering plan */
	return gsm340_gen_oa(oa, oa_len, src->ton, src->npi, src->addr);
}

/* generate a msgb containing an 03.40 9.2.2.1 SMS-DELIVER TPDU derived from
 * struct gsm_sms, returns total size of TPDU */
static int gsm340_gen_sms_deliver_tpdu(struct msgb *msg, struct gsm_sms *sms)
{
	uint8_t *smsp;
	uint8_t oa[12];	/* max len per 03.40 */
	uint8_t oa_len = 0;
	uint8_t octet_len;
	unsigned int old_msg_len = msg->len;

	/* generate first octet with masked bits */
	smsp = msgb_put(msg, 1);
	/* TP-MTI (message type indicator) */
	*smsp = GSM340_SMS_DELIVER_SC2MS;
	/* TP-MMS (more messages to send) */
	if (0 /* FIXME */)
		*smsp |= 0x04;
	/* TP-SRI(deliver)/SRR(submit) */
	if (sms->status_rep_req)
		*smsp |= 0x20;
	/* TP-UDHI (indicating TP-UD contains a header) */
	if (sms->ud_hdr_ind)
		*smsp |= 0x40;

	/* generate originator address */
	oa_len = gsm340_gen_oa_sub(oa, sizeof(oa), &sms->src);
	smsp = msgb_put(msg, oa_len);
	memcpy(smsp, oa, oa_len);

	/* generate TP-PID */
	smsp = msgb_put(msg, 1);
	*smsp = sms->protocol_id;

	/* generate TP-DCS */
	smsp = msgb_put(msg, 1);
	*smsp = sms->data_coding_scheme;

	/* generate TP-SCTS */
	smsp = msgb_put(msg, 7);
	gsm340_gen_scts(smsp, time(NULL));

	/* generate TP-UDL */
	smsp = msgb_put(msg, 1);
	*smsp = sms->user_data_len;

	/* generate TP-UD */
	switch (gsm338_get_sms_alphabet(sms->data_coding_scheme)) {
	case DCS_7BIT_DEFAULT:
		octet_len = sms->user_data_len*7/8;
		if (sms->user_data_len*7%8 != 0)
			octet_len++;
		/* Warning, user_data_len indicates the amount of septets
		 * (characters), we need amount of octets occupied */
		smsp = msgb_put(msg, octet_len);
		memcpy(smsp, sms->user_data, octet_len);
		break;
	case DCS_UCS2:
	case DCS_8BIT_DATA:
		smsp = msgb_put(msg, sms->user_data_len);
		memcpy(smsp, sms->user_data, sms->user_data_len);
		break;
	default:
		LOGP(DLSMS, LOGL_NOTICE, "Unhandled Data Coding Scheme: 0x%02X\n",
		     sms->data_coding_scheme);
		break;
	}

	return msg->len - old_msg_len;
}

int sms_route_mt_sms(struct gsm_subscriber_connection *conn, struct msgb *msg,
		     struct gsm_sms *gsms, uint8_t sms_mti, bool *deferred)
{
	int rc;

#ifdef BUILD_SMPP
	int smpp_first = smpp_route_smpp_first(gsms, conn);

	/*
	 * Route through SMPP first before going to the local database. In case
	 * of a unroutable message and no local subscriber, SMPP will be tried
	 * twice. In case of an unknown subscriber continue with the normal
	 * delivery of the SMS.
	 */
	if (smpp_first) {
		rc = smpp_try_deliver(gsms, conn, deferred);
		if (rc == GSM411_RP_CAUSE_MO_NUM_UNASSIGNED)
			goto try_local;
		if (rc < 0) {
	 		LOGP(DLSMS, LOGL_ERROR, "%s: SMS delivery error: %d.",
			     vlr_subscr_name(conn->vsub), rc);
	 		rc = GSM411_RP_CAUSE_MO_TEMP_FAIL;
			/* rc will be logged by gsm411_send_rp_error() */
	 		rate_ctr_inc(&conn->bts->network->msc_ctrs->ctr[
					MSC_CTR_SMS_DELIVER_UNKNOWN_ERROR]);
		}
		return rc;
	}

try_local:
#endif

	/* determine gsms->receiver based on dialled number */
	gsms->receiver = vlr_subscr_find_by_msisdn(conn->network->vlr,
						   gsms->dst.addr);
	if (!gsms->receiver) {
#ifdef BUILD_SMPP
		/* Avoid a second look-up */
		if (smpp_first) {
			rate_ctr_inc(&conn->network->msc_ctrs->ctr[MSC_CTR_SMS_NO_RECEIVER]);
			return GSM411_RP_CAUSE_MO_NUM_UNASSIGNED;
		}

		rc = smpp_try_deliver(gsms, conn, deferred);
		if (rc == GSM411_RP_CAUSE_MO_NUM_UNASSIGNED) {
			rate_ctr_inc(&conn->network->msc_ctrs->ctr[MSC_CTR_SMS_NO_RECEIVER]);
		} else if (rc < 0) {
	 		LOGP(DLSMS, LOGL_ERROR, "%s: SMS delivery error: %d.",
			     vlr_subscr_name(conn->vsub), rc);
	 		rc = GSM411_RP_CAUSE_MO_TEMP_FAIL;
			/* rc will be logged by gsm411_send_rp_error() */
	 		rate_ctr_inc(&conn->bts->network->msc_ctrs->ctr[
					MSC_CTR_SMS_DELIVER_UNKNOWN_ERROR]);
		}
#else
		rc = GSM411_RP_CAUSE_MO_NUM_UNASSIGNED;
		rate_ctr_inc(&conn->network->msc_ctrs->ctr[MSC_CTR_SMS_NO_RECEIVER]);
#endif
		return rc;
	}

	switch (sms_mti) {
	case GSM340_SMS_SUBMIT_MS2SC:
		/* MS is submitting a SMS */
		rc = gsm340_rx_sms_submit(msg, gsms);
		break;
	case GSM340_SMS_COMMAND_MS2SC:
	case GSM340_SMS_DELIVER_REP_MS2SC:
		LOGP(DLSMS, LOGL_NOTICE, "Unimplemented MTI 0x%02x\n", sms_mti);
		rc = GSM411_RP_CAUSE_IE_NOTEXIST;
		break;
	default:
		LOGP(DLSMS, LOGL_NOTICE, "Undefined MTI 0x%02x\n", sms_mti);
		rc = GSM411_RP_CAUSE_IE_NOTEXIST;
		break;
	}

	if (!rc && !gsms->receiver)
		rc = GSM411_RP_CAUSE_MO_NUM_UNASSIGNED;

	return rc;
}


/* process an incoming TPDU (called from RP-DATA)
 * return value > 0: RP CAUSE for ERROR; < 0: silent error; 0 = success */
static int gsm340_rx_tpdu(struct gsm_trans *trans, struct msgb *msg,
			  uint32_t gsm411_msg_ref, bool *deferred)
{
	struct gsm_subscriber_connection *conn = trans->conn;
	uint8_t *smsp = msgb_sms(msg);
	struct gsm_sms *gsms;
	unsigned int sms_alphabet;
	uint8_t sms_mti, sms_vpf;
	uint8_t *sms_vp;
	uint8_t da_len_bytes;
	uint8_t address_lv[12]; /* according to 03.40 / 9.1.2.5 */
	int rc = 0;

	rate_ctr_inc(&conn->network->msc_ctrs->ctr[MSC_CTR_SMS_SUBMITTED]);

	gsms = sms_alloc();
	if (!gsms)
		return GSM411_RP_CAUSE_MO_NET_OUT_OF_ORDER;

	/* invert those fields where 0 means active/present */
	sms_mti = *smsp & 0x03;
	sms_vpf = (*smsp & 0x18) >> 3;
	gsms->status_rep_req = (*smsp & 0x20);
	gsms->ud_hdr_ind = (*smsp & 0x40);
	/*
	 * Not evaluating MMS (More Messages to Send) because the
	 * lchan stays open anyway.
	 * Not evaluating RP (Reply Path) because we're not aware of its
	 * benefits.
	 */

	smsp++;
	gsms->msg_ref = *smsp++;

	gsms->gsm411.transaction_id = trans->transaction_id;
	gsms->gsm411.msg_ref = gsm411_msg_ref;

	/* length in bytes of the destination address */
	da_len_bytes = 2 + *smsp/2 + *smsp%2;
	if (da_len_bytes > 12) {
		LOGP(DLSMS, LOGL_ERROR, "Destination Address > 12 bytes ?!?\n");
		rc = GSM411_RP_CAUSE_SEMANT_INC_MSG;
		goto out;
	} else if (da_len_bytes < 4) {
		LOGP(DLSMS, LOGL_ERROR, "Destination Address < 4 bytes ?!?\n");
		rc = GSM411_RP_CAUSE_SEMANT_INC_MSG;
		goto out;
	}
	memset(address_lv, 0, sizeof(address_lv));
	memcpy(address_lv, smsp, da_len_bytes);
	/* mangle first byte to reflect length in bytes, not digits */
	address_lv[0] = da_len_bytes - 1;

	gsms->dst.ton = (address_lv[1] >> 4) & 7;
	gsms->dst.npi = address_lv[1] & 0xF;
	/* convert to real number */
	gsm48_decode_bcd_number(gsms->dst.addr,
				sizeof(gsms->dst.addr), address_lv, 1);
	smsp += da_len_bytes;

	gsms->protocol_id = *smsp++;
	gsms->data_coding_scheme = *smsp++;

	sms_alphabet = gsm338_get_sms_alphabet(gsms->data_coding_scheme);
	if (sms_alphabet == 0xffffffff) {
		rc = GSM411_RP_CAUSE_MO_NET_OUT_OF_ORDER;
		goto out;
	}

	switch (sms_vpf) {
	case GSM340_TP_VPF_RELATIVE:
		sms_vp = smsp++;
		break;
	case GSM340_TP_VPF_ABSOLUTE:
	case GSM340_TP_VPF_ENHANCED:
		sms_vp = smsp;
		/* the additional functionality indicator... */
		if (sms_vpf == GSM340_TP_VPF_ENHANCED && *smsp & (1<<7))
			smsp++;
		smsp += 7;
		break;
	case GSM340_TP_VPF_NONE:
		sms_vp = 0;
		break;
	default:
		LOGP(DLSMS, LOGL_NOTICE,
		     "SMS Validity period not implemented: 0x%02x\n", sms_vpf);
		rc = GSM411_RP_CAUSE_MO_NET_OUT_OF_ORDER;
		goto out;
	}
	gsms->user_data_len = *smsp++;
	if (gsms->user_data_len) {
		memcpy(gsms->user_data, smsp, gsms->user_data_len);

		switch (sms_alphabet) {
		case DCS_7BIT_DEFAULT:
			gsm_7bit_decode_n(gsms->text, sizeof(gsms->text), smsp,
					  gsms->user_data_len);
			break;
		case DCS_8BIT_DATA:
		case DCS_UCS2:
		case DCS_NONE:
			break;
		}
	}

	osmo_strlcpy(gsms->src.addr, conn->vsub->msisdn, sizeof(gsms->src.addr));

	LOGP(DLSMS, LOGL_INFO, "RX SMS: Sender: %s, MTI: 0x%02x, VPF: 0x%02x, "
	     "MR: 0x%02x PID: 0x%02x, DCS: 0x%02x, DA: %s, "
	     "UserDataLength: 0x%02x, UserData: \"%s\"\n",
	     vlr_subscr_name(conn->vsub), sms_mti, sms_vpf, gsms->msg_ref,
	     gsms->protocol_id, gsms->data_coding_scheme, gsms->dst.addr,
	     gsms->user_data_len,
			sms_alphabet == DCS_7BIT_DEFAULT ? gsms->text :
				osmo_hexdump(gsms->user_data, gsms->user_data_len));

	gsms->validity_minutes = gsm340_validity_period(sms_vpf, sms_vp);

	/* FIXME: This looks very wrong */
	send_signal(0, NULL, gsms, 0);

	rc = sms_route_mt_sms(conn, msg, gsms, sms_mti, deferred);
out:
	if (!deferred)
		sms_free(gsms);

	return rc;
}

/* Prefix msg with a RP-DATA header and send as SMR DATA */
static int gsm411_rp_sendmsg(struct gsm411_smr_inst *inst, struct msgb *msg,
			     uint8_t rp_msg_type, uint8_t rp_msg_ref,
			     int rl_msg_type)
{
	struct gsm411_rp_hdr *rp;
	uint8_t len = msg->len;

	/* GSM 04.11 RP-DATA header */
	rp = (struct gsm411_rp_hdr *)msgb_push(msg, sizeof(*rp));
	rp->len = len + 2;
	rp->msg_type = rp_msg_type;
	rp->msg_ref = rp_msg_ref;

	return gsm411_smr_send(inst, rl_msg_type, msg);
}

int gsm411_send_rp_ack(struct gsm_trans *trans, uint8_t msg_ref)
{
	struct msgb *msg = gsm411_msgb_alloc();

	DEBUGP(DLSMS, "TX: SMS RP ACK\n");

	return gsm411_rp_sendmsg(&trans->sms.smr_inst, msg, GSM411_MT_RP_ACK_MT,
		msg_ref, GSM411_SM_RL_REPORT_REQ);
}

int gsm411_send_rp_error(struct gsm_trans *trans, uint8_t msg_ref,
			 uint8_t cause)
{
	struct msgb *msg = gsm411_msgb_alloc();

	msgb_tv_put(msg, 1, cause);

	LOGP(DLSMS, LOGL_NOTICE, "TX: SMS RP ERROR, cause %d (%s)\n", cause,
		get_value_string(gsm411_rp_cause_strs, cause));

	return gsm411_rp_sendmsg(&trans->sms.smr_inst, msg,
		GSM411_MT_RP_ERROR_MT, msg_ref, GSM411_SM_RL_REPORT_REQ);
}

/* Receive a 04.11 TPDU inside RP-DATA / user data */
static int gsm411_rx_rp_ud(struct msgb *msg, struct gsm_trans *trans,
			  struct gsm411_rp_hdr *rph,
			  uint8_t src_len, uint8_t *src,
			  uint8_t dst_len, uint8_t *dst,
			  uint8_t tpdu_len, uint8_t *tpdu)
{
	bool deferred = false;
	int rc = 0;

	if (src_len && src)
		LOGP(DLSMS, LOGL_ERROR, "RP-DATA (MO) with SRC ?!?\n");

	if (!dst_len || !dst || !tpdu_len || !tpdu) {
		LOGP(DLSMS, LOGL_ERROR,
			"RP-DATA (MO) without DST or TPDU ?!?\n");
		gsm411_send_rp_error(trans, rph->msg_ref,
				     GSM411_RP_CAUSE_INV_MAND_INF);
		return -EIO;
	}
	msg->l4h = tpdu;

	DEBUGP(DLSMS, "DST(%u,%s)\n", dst_len, osmo_hexdump(dst, dst_len));

	rc = gsm340_rx_tpdu(trans, msg, rph->msg_ref, &deferred);
	if (rc == 0 && !deferred)
		return gsm411_send_rp_ack(trans, rph->msg_ref);
	else if (rc > 0)
		return gsm411_send_rp_error(trans, rph->msg_ref, rc);
	else
		return rc;
}

/* Receive a 04.11 RP-DATA message in accordance with Section 7.3.1.2 */
static int gsm411_rx_rp_data(struct msgb *msg, struct gsm_trans *trans,
			     struct gsm411_rp_hdr *rph)
{
	uint8_t src_len, dst_len, rpud_len;
	uint8_t *src = NULL, *dst = NULL , *rp_ud = NULL;

	/* in the MO case, this should always be zero length */
	src_len = rph->data[0];
	if (src_len)
		src = &rph->data[1];

	dst_len = rph->data[1+src_len];
	if (dst_len)
		dst = &rph->data[1+src_len+1];

	rpud_len = rph->data[1+src_len+1+dst_len];
	if (rpud_len)
		rp_ud = &rph->data[1+src_len+1+dst_len+1];

	DEBUGP(DLSMS, "RX_RP-DATA: src_len=%u, dst_len=%u ud_len=%u\n",
		src_len, dst_len, rpud_len);
	return gsm411_rx_rp_ud(msg, trans, rph, src_len, src, dst_len, dst,
				rpud_len, rp_ud);
}

/* Receive a 04.11 RP-ACK message (response to RP-DATA from us) */
static int gsm411_rx_rp_ack(struct msgb *msg, struct gsm_trans *trans,
			    struct gsm411_rp_hdr *rph)
{
	struct gsm_sms *sms = trans->sms.sms;

	/* Acnkowledgement to MT RP_DATA, i.e. the MS confirms it
	 * successfully received a SMS.  We can now safely mark it as
	 * transmitted */

	if (!sms) {
		LOGP(DLSMS, LOGL_ERROR, "RX RP-ACK but no sms in transaction?!?\n");
		return gsm411_send_rp_error(trans, rph->msg_ref,
					    GSM411_RP_CAUSE_PROTOCOL_ERR);
	}

	/* mark this SMS as sent in database */
	db_sms_mark_delivered(sms);

	send_signal(S_SMS_DELIVERED, trans, sms, 0);

	sms_free(sms);
	trans->sms.sms = NULL;

	return 0;
}

static int gsm411_rx_rp_error(struct msgb *msg, struct gsm_trans *trans,
			      struct gsm411_rp_hdr *rph)
{
	struct gsm_network *net = trans->conn->network;
	struct gsm_sms *sms = trans->sms.sms;
	uint8_t cause_len = rph->data[0];
	uint8_t cause = rph->data[1];

	/* Error in response to MT RP_DATA, i.e. the MS did not
	 * successfully receive the SMS.  We need to investigate
	 * the cause and take action depending on it */

	LOGP(DLSMS, LOGL_NOTICE, "%s: RX SMS RP-ERROR, cause %d:%d (%s)\n",
	     vlr_subscr_name(trans->conn->vsub), cause_len, cause,
	     get_value_string(gsm411_rp_cause_strs, cause));

	if (!sms) {
		LOGP(DLSMS, LOGL_ERROR,
			"RX RP-ERR, but no sms in transaction?!?\n");
		return -EINVAL;
#if 0
		return gsm411_send_rp_error(trans, rph->msg_ref,
					    GSM411_RP_CAUSE_PROTOCOL_ERR);
#endif
	}

	if (cause == GSM411_RP_CAUSE_MT_MEM_EXCEEDED) {
		/* MS has not enough memory to store the message.  We need
		 * to store this in our database and wait for a SMMA message */
		/* FIXME */
		send_signal(S_SMS_MEM_EXCEEDED, trans, sms, 0);
		rate_ctr_inc(&net->msc_ctrs->ctr[MSC_CTR_SMS_RP_ERR_MEM]);
	} else {
		send_signal(S_SMS_UNKNOWN_ERROR, trans, sms, 0);
		rate_ctr_inc(&net->msc_ctrs->ctr[MSC_CTR_SMS_RP_ERR_OTHER]);
	}

	sms_free(sms);
	trans->sms.sms = NULL;

	return 0;
}

static int gsm411_rx_rp_smma(struct msgb *msg, struct gsm_trans *trans,
			     struct gsm411_rp_hdr *rph)
{
	int rc;

	rc = gsm411_send_rp_ack(trans, rph->msg_ref);

	/* MS tells us that it has memory for more SMS, we need
	 * to check if we have any pending messages for it and then
	 * transfer those */
	send_signal(S_SMS_SMMA, trans, NULL, 0);

	return rc;
}

/* receive RL DATA */
static int gsm411_rx_rl_data(struct msgb *msg, struct gsm48_hdr *gh,
			     struct gsm_trans *trans)
{
	struct gsm411_rp_hdr *rp_data = (struct gsm411_rp_hdr*)&gh->data;
	uint8_t msg_type =  rp_data->msg_type & 0x07;
	int rc = 0;

	switch (msg_type) {
	case GSM411_MT_RP_DATA_MO:
		DEBUGP(DLSMS, "RX SMS RP-DATA (MO)\n");
		rc = gsm411_rx_rp_data(msg, trans, rp_data);
		break;
	case GSM411_MT_RP_SMMA_MO:
		DEBUGP(DLSMS, "RX SMS RP-SMMA\n");
		rc = gsm411_rx_rp_smma(msg, trans, rp_data);
		break;
	default:
		LOGP(DLSMS, LOGL_NOTICE, "Invalid RP type 0x%02x\n", msg_type);
		rc = -EINVAL;
		break;
	}

	return rc;
}

/* receive RL REPORT */
static int gsm411_rx_rl_report(struct msgb *msg, struct gsm48_hdr *gh,
			     struct gsm_trans *trans)
{
	struct gsm411_rp_hdr *rp_data = (struct gsm411_rp_hdr*)&gh->data;
	uint8_t msg_type =  rp_data->msg_type & 0x07;
	int rc = 0;

	switch (msg_type) {
	case GSM411_MT_RP_ACK_MO:
		DEBUGP(DLSMS, "RX SMS RP-ACK (MO)\n");
		rc = gsm411_rx_rp_ack(msg, trans, rp_data);
		break;
	case GSM411_MT_RP_ERROR_MO:
		DEBUGP(DLSMS, "RX SMS RP-ERROR (MO)\n");
		rc = gsm411_rx_rp_error(msg, trans, rp_data);
		break;
	default:
		LOGP(DLSMS, LOGL_NOTICE, "Invalid RP type 0x%02x\n", msg_type);
		rc = -EINVAL;
		break;
	}

	return rc;
}

/* receive SM-RL sap message from SMR
 * NOTE: Message is freed by sender
 */
int gsm411_rl_recv(struct gsm411_smr_inst *inst, int msg_type,
                        struct msgb *msg)
{
	struct gsm_trans *trans =
		container_of(inst, struct gsm_trans, sms.smr_inst);
	struct gsm48_hdr *gh = msgb_l3(msg);
	int rc = 0;

	switch (msg_type) {
	case GSM411_SM_RL_DATA_IND:
		rc = gsm411_rx_rl_data(msg, gh, trans);
		break;
	case GSM411_SM_RL_REPORT_IND:
		if (gh)
			rc = gsm411_rx_rl_report(msg, gh, trans);
		break;
	default:
		LOGP(DLSMS, LOGL_NOTICE, "Unhandled SM-RL message 0x%x\n", msg_type);
		rc = -EINVAL;
	}

	return rc;
}

/* receive MNCCSMS sap message from SMC
 * NOTE: Message is freed by sender
 */
static int gsm411_mn_recv(struct gsm411_smc_inst *inst, int msg_type,
			struct msgb *msg)
{
	struct gsm_trans *trans =
		container_of(inst, struct gsm_trans, sms.smc_inst);
	struct gsm48_hdr *gh = msgb_l3(msg);
	int rc = 0;

	switch (msg_type) {
	case GSM411_MNSMS_EST_IND:
	case GSM411_MNSMS_DATA_IND:
		DEBUGP(DLSMS, "MNSMS-DATA/EST-IND\n");
		rc = gsm411_smr_recv(&trans->sms.smr_inst, msg_type, msg);
		break;
	case GSM411_MNSMS_ERROR_IND:
		if (gh)
			DEBUGP(DLSMS, "MNSMS-ERROR-IND, cause %d (%s)\n",
				gh->data[0],
				get_value_string(gsm411_cp_cause_strs,
				gh->data[0]));
		else
			DEBUGP(DLSMS, "MNSMS-ERROR-IND, no cause\n");
		rc = gsm411_smr_recv(&trans->sms.smr_inst, msg_type, msg);
		break;
	default:
		LOGP(DLSMS, LOGL_NOTICE, "Unhandled MNCCSMS msg 0x%x\n", msg_type);
		rc = -EINVAL;
	}

	return rc;
}

/* Entry point for incoming GSM48_PDISC_SMS from abis_rsl.c */
int gsm0411_rcv_sms(struct gsm_subscriber_connection *conn,
		    struct msgb *msg)
{
	struct gsm48_hdr *gh = msgb_l3(msg);
	uint8_t msg_type = gh->msg_type;
	uint8_t transaction_id = gsm48_hdr_trans_id_flip_ti(gh);
	struct gsm_trans *trans;
	int new_trans = 0;
	int rc = 0;

	if (!conn->vsub)
		return -EIO;
		/* FIXME: send some error message */

	DEBUGP(DLSMS, "receiving data (trans_id=%x)\n", transaction_id);
	trans = trans_find_by_id(conn, GSM48_PDISC_SMS, transaction_id);

	/*
	 * A transaction we created but don't know about?
	 */
	if (!trans && (transaction_id & 0x8) == 0) {
		LOGP(DLSMS, LOGL_ERROR, "trans_id=%x allocated by us but known "
			"to us anymore. We are ignoring it, maybe a CP-ERROR "
			"from a MS?\n",
			transaction_id);
		return -EINVAL;
	}

	if (!trans) {
		DEBUGP(DLSMS, " -> (new transaction)\n");
		trans = trans_alloc(conn->network, conn->vsub,
				    GSM48_PDISC_SMS,
				    transaction_id, new_callref++);
		if (!trans) {
			DEBUGP(DLSMS, " -> No memory for trans\n");
			/* FIXME: send some error message */
			return -ENOMEM;
		}
		gsm411_smc_init(&trans->sms.smc_inst, 0, 1,
			gsm411_mn_recv, gsm411_mm_send);
		gsm411_smr_init(&trans->sms.smr_inst, 0, 1,
			gsm411_rl_recv, gsm411_mn_send);

		trans->conn = msc_subscr_conn_get(conn);

		new_trans = 1;
		cm_service_request_concludes(conn, msg);
	}

	/* 5.4: For MO, if a CP-DATA is received for a new
	 * transaction, equals reception of an implicit
	 * last CP-ACK for previous transaction */
	if (trans->sms.smc_inst.cp_state == GSM411_CPS_IDLE
	 && msg_type == GSM411_MT_CP_DATA) {
		int i;
		struct gsm_trans *ptrans;

		/* Scan through all remote initiated transactions */
		for (i=8; i<15; i++) {
			if (i == transaction_id)
				continue;

			ptrans = trans_find_by_id(conn, GSM48_PDISC_SMS, i);
			if (!ptrans)
				continue;

			DEBUGP(DLSMS, "Implicit CP-ACK for trans_id=%x\n", i);

			/* Finish it for good */
			trans_free(ptrans);
		}
	}

	msc_subscr_conn_communicating(conn);

	gsm411_smc_recv(&trans->sms.smc_inst,
		(new_trans) ? GSM411_MMSMS_EST_IND : GSM411_MMSMS_DATA_IND,
		msg, msg_type);

	return rc;
}

/* Take a SMS in gsm_sms structure and send it through an already
 * existing lchan. We also assume that the caller ensured this lchan already
 * has a SAPI3 RLL connection! */
int gsm411_send_sms(struct gsm_subscriber_connection *conn, struct gsm_sms *sms)
{
	struct msgb *msg = gsm411_msgb_alloc();
	struct gsm_trans *trans;
	uint8_t *data, *rp_ud_len;
	uint8_t msg_ref = sms_next_rp_msg_ref(&conn->next_rp_ref);
	int transaction_id;
	int rc;

	transaction_id =
		trans_assign_trans_id(conn->network, conn->vsub,
				      GSM48_PDISC_SMS, 0);
	if (transaction_id == -1) {
		LOGP(DLSMS, LOGL_ERROR, "No available transaction ids\n");
		send_signal(S_SMS_UNKNOWN_ERROR, NULL, sms, 0);
		sms_free(sms);
		msgb_free(msg);
		return -EBUSY;
	}

	DEBUGP(DLSMS, "%s()\n", __func__);

	/* FIXME: allocate transaction with message reference */
	trans = trans_alloc(conn->network, conn->vsub,
			    GSM48_PDISC_SMS,
			    transaction_id, new_callref++);
	if (!trans) {
		LOGP(DLSMS, LOGL_ERROR, "No memory for trans\n");
		send_signal(S_SMS_UNKNOWN_ERROR, NULL, sms, 0);
		sms_free(sms);
		msgb_free(msg);
		/* FIXME: send some error message */
		return -ENOMEM;
	}
	gsm411_smc_init(&trans->sms.smc_inst, sms->id, 1,
		gsm411_mn_recv, gsm411_mm_send);
	gsm411_smr_init(&trans->sms.smr_inst, sms->id, 1,
		gsm411_rl_recv, gsm411_mn_send);
	trans->sms.sms = sms;

	trans->conn = msc_subscr_conn_get(conn);

	/* Hardcode SMSC Originating Address for now */
	data = (uint8_t *)msgb_put(msg, 8);
	data[0] = 0x07;	/* originator length == 7 */
	data[1] = 0x91; /* type of number: international, ISDN */
	data[2] = 0x44; /* 447785016005 */
	data[3] = 0x77;
	data[4] = 0x58;
	data[5] = 0x10;
	data[6] = 0x06;
	data[7] = 0x50;

	/* Hardcoded Destination Address */
	data = (uint8_t *)msgb_put(msg, 1);
	data[0] = 0;	/* destination length == 0 */

	/* obtain a pointer for the rp_ud_len, so we can fill it later */
	rp_ud_len = (uint8_t *)msgb_put(msg, 1);

	/* generate the 03.40 SMS-DELIVER TPDU */
	rc = gsm340_gen_sms_deliver_tpdu(msg, sms);
	if (rc < 0) {
		send_signal(S_SMS_UNKNOWN_ERROR, trans, sms, 0);
		sms_free(sms);
		trans->sms.sms = NULL;
		trans_free(trans);
		msgb_free(msg);
		return rc;
	}

	*rp_ud_len = rc;

	DEBUGP(DLSMS, "TX: SMS DELIVER\n");

	rate_ctr_inc(&conn->network->msc_ctrs->ctr[MSC_CTR_SMS_DELIVERED]);
	db_sms_inc_deliver_attempts(trans->sms.sms);

	return gsm411_rp_sendmsg(&trans->sms.smr_inst, msg,
		GSM411_MT_RP_DATA_MT, msg_ref, GSM411_SM_RL_DATA_REQ);
}

/* paging callback. Here we get called if paging a subscriber has
 * succeeded or failed. */
static int paging_cb_send_sms(unsigned int hooknum, unsigned int event,
			      struct msgb *msg, void *_conn, void *_sms)
{
	struct gsm_subscriber_connection *conn = _conn;
	struct gsm_sms *sms = _sms;
	int rc = 0;

	DEBUGP(DLSMS, "paging_cb_send_sms(hooknum=%u, event=%u, msg=%p,"
		"conn=%p, sms=%p/id: %llu)\n", hooknum, event, msg, conn, sms, sms->id);

	if (hooknum != GSM_HOOK_RR_PAGING)
		return -EINVAL;

	switch (event) {
	case GSM_PAGING_SUCCEEDED:
		gsm411_send_sms(conn, sms);
		break;
	case GSM_PAGING_EXPIRED:
	case GSM_PAGING_OOM:
	case GSM_PAGING_BUSY:
		send_signal(S_SMS_UNKNOWN_ERROR, NULL, sms, event);
		sms_free(sms);
		rc = -ETIMEDOUT;
		break;
	default:
		LOGP(DLSMS, LOGL_ERROR, "Unhandled paging event: %d\n", event);
	}

	return rc;
}

/* high-level function to send a SMS to a given subscriber. The function
 * will take care of paging the subscriber, establishing the RLL SAPI3
 * connection, etc. */
int gsm411_send_sms_subscr(struct vlr_subscr *vsub,
			   struct gsm_sms *sms)
{
	struct gsm_subscriber_connection *conn;
	void *res;

	/* check if we already have an open lchan to the subscriber.
	 * if yes, send the SMS this way */
	conn = connection_for_subscr(vsub);
	if (conn) {
		LOGP(DLSMS, LOGL_DEBUG, "Sending SMS via already open connection %p to %s\n",
		     conn, vlr_subscr_name(vsub));
		return gsm411_send_sms(conn, sms);
	}

	/* if not, we have to start paging */
	LOGP(DLSMS, LOGL_DEBUG, "Sending SMS: no connection open, start paging %s\n",
	     vlr_subscr_name(vsub));
	res = subscr_request_channel(vsub, RSL_CHANNEED_SDCCH,
				     paging_cb_send_sms, sms);
	if (!res) {
		send_signal(S_SMS_UNKNOWN_ERROR, NULL, sms, GSM_PAGING_BUSY);
		sms_free(sms);
	}
	return 0;
}

void _gsm411_sms_trans_free(struct gsm_trans *trans)
{
	/* cleanup SMS instance */
	gsm411_smr_clear(&trans->sms.smr_inst);
	trans->sms.smr_inst.rl_recv = NULL;
	trans->sms.smr_inst.mn_send = NULL;

	gsm411_smc_clear(&trans->sms.smc_inst);
	trans->sms.smc_inst.mn_recv = NULL;
	trans->sms.smc_inst.mm_send = NULL;

	if (trans->sms.sms) {
		LOGP(DLSMS, LOGL_ERROR, "Transaction contains SMS.\n");
		send_signal(S_SMS_UNKNOWN_ERROR, trans, trans->sms.sms, 0);
		sms_free(trans->sms.sms);
		trans->sms.sms = NULL;
	}
}

/* Process incoming SAPI N-REJECT from BSC */
void gsm411_sapi_n_reject(struct gsm_subscriber_connection *conn)
{
	struct gsm_network *net;
	struct gsm_trans *trans, *tmp;

	net = conn->network;

	llist_for_each_entry_safe(trans, tmp, &net->trans_list, entry) {
		struct gsm_sms *sms;

		if (trans->conn != conn)
			continue;
		if (trans->protocol != GSM48_PDISC_SMS)
			continue;

		sms = trans->sms.sms;
		if (!sms) {
			LOGP(DLSMS, LOGL_ERROR, "SAPI Reject but no SMS.\n");
			continue;
		}

		send_signal(S_SMS_UNKNOWN_ERROR, trans, sms, 0);
		sms_free(sms);
		trans->sms.sms = NULL;
		trans_free(trans);
	}
}

