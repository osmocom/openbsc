/* Osmocom Visitor Location Register (VLR) code base */

/* (C) 2016 by Harald Welte <laforge@gnumonks.org>
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

#include <osmocom/core/linuxlist.h>
#include <osmocom/core/fsm.h>
#include <osmocom/core/utils.h>
#include <osmocom/gsm/protocol/gsm_04_08_gprs.h>
#include <osmocom/gsm/gsup.h>
#include <osmocom/gsm/apn.h>
#include <openbsc/gsm_subscriber.h>
#include <openbsc/gsup_client.h>
#include <openbsc/vlr.h>
#include <openbsc/gprs_sgsn.h>
#include <openbsc/gprs_utils.h>
#include <openbsc/debug.h>

#include <openssl/rand.h>

#include <netinet/in.h>
#include <arpa/inet.h>
#include <limits.h>

#include "vlr_core.h"
#include "vlr_auth_fsm.h"
#include "vlr_lu_fsm.h"
#include "vlr_access_req_fsm.h"

#define SGSN_SUBSCR_MAX_RETRIES 3
#define SGSN_SUBSCR_RETRY_INTERVAL 10

/***********************************************************************
 * Convenience functions
 ***********************************************************************/

const struct value_string vlr_ciph_names[] = {
	OSMO_VALUE_STRING(VLR_CIPH_NONE),
	OSMO_VALUE_STRING(VLR_CIPH_A5_1),
	OSMO_VALUE_STRING(VLR_CIPH_A5_2),
	OSMO_VALUE_STRING(VLR_CIPH_A5_3),
	{ 0, NULL }
};

uint32_t vlr_timer(struct vlr_instance *vlr, uint32_t timer)
{
	uint32_t tidx = 0xffffffff;

	switch (timer) {
	case 3270:
		tidx = VLR_T_3270;
		break;
	case 3260:
		tidx = VLR_T_3260;
		break;
	case 3250:
		tidx = VLR_T_3250;
		break;
	}

	OSMO_ASSERT(tidx < sizeof(vlr->cfg.timer));
	return vlr->cfg.timer[tidx];
}

struct vlr_subscr *_vlr_subscr_find_by_imsi(struct vlr_instance *vlr,
					    const char *imsi,
					    const char *file, int line)
{
	struct vlr_subscr *vsub;

	if (!imsi || !*imsi)
		return NULL;

	llist_for_each_entry(vsub, &vlr->subscribers, list) {
		if (vlr_subscr_matches_imsi(vsub, imsi))
			return _vlr_subscr_get(vsub, file, line);
	}
	return NULL;
}

struct vlr_subscr *_vlr_subscr_find_by_tmsi(struct vlr_instance *vlr,
					    uint32_t tmsi,
					    const char *file, int line)
{
	struct vlr_subscr *vsub;

	if (tmsi == GSM_RESERVED_TMSI)
		return NULL;

	llist_for_each_entry(vsub, &vlr->subscribers, list) {
		if (vlr_subscr_matches_tmsi(vsub, tmsi))
			return _vlr_subscr_get(vsub, file, line);
	}
	return NULL;
}

struct vlr_subscr *_vlr_subscr_find_by_msisdn(struct vlr_instance *vlr,
					      const char *msisdn,
					      const char *file, int line)
{
	struct vlr_subscr *vsub;

	if (!msisdn || !*msisdn)
		return NULL;

	llist_for_each_entry(vsub, &vlr->subscribers, list) {
		if (vlr_subscr_matches_msisdn(vsub, msisdn))
			return _vlr_subscr_get(vsub, file, line);
	}
	return NULL;
}

/* Transmit GSUP message to HLR */
static int vlr_tx_gsup_message(struct vlr_instance *vlr,
			       struct osmo_gsup_message *gsup_msg)
{
	struct msgb *msg = gsup_client_msgb_alloc();

	osmo_gsup_encode(msg, gsup_msg);

	if (!vlr->gsup_client) {
		LOGP(DVLR, LOGL_NOTICE, "GSUP link is down, cannot "
			"send GSUP: %s\n", msgb_hexdump(msg));
		msgb_free(msg);
		return -ENOTSUP;
	}

	LOGP(DVLR, LOGL_DEBUG, "GSUP tx: %s\n",
	     osmo_hexdump_nospc(msg->data, msg->len));

	return gsup_client_send(vlr->gsup_client, msg);
}

/* Transmit GSUP message for subscriber to HLR, using IMSI from subscriber */
static int vlr_subscr_tx_gsup_message(struct vlr_subscr *vsub,
				      struct osmo_gsup_message *gsup_msg)
{
	struct vlr_instance *vlr = vsub->vlr;

	if (strlen(gsup_msg->imsi) == 0)
		osmo_strlcpy(gsup_msg->imsi, vsub->imsi, sizeof(gsup_msg->imsi));

	return vlr_tx_gsup_message(vlr, gsup_msg);
}

/* Transmit GSUP error in response to original message */
static int vlr_tx_gsup_error_reply(struct vlr_instance *vlr,
				   struct osmo_gsup_message *gsup_orig,
				   enum gsm48_gmm_cause cause)
{
	struct osmo_gsup_message gsup_reply = {0};

	osmo_strlcpy(gsup_reply.imsi, gsup_orig->imsi, sizeof(gsup_reply.imsi));
	gsup_reply.cause = cause;
	gsup_reply.message_type =
		OSMO_GSUP_TO_MSGT_ERROR(gsup_orig->message_type);

	return vlr_tx_gsup_message(vlr, &gsup_reply);
}

struct vlr_subscr *_vlr_subscr_get(struct vlr_subscr *sub, const char *file, int line)
{
	if (!sub)
		return NULL;
	OSMO_ASSERT(sub->use_count < INT_MAX);
	sub->use_count++;
	LOGPSRC(DREF, LOGL_DEBUG, file, line,
		"VLR subscr %s usage increases to: %d\n",
		vlr_subscr_name(sub), sub->use_count);
	return sub;
}

struct vlr_subscr *_vlr_subscr_put(struct vlr_subscr *sub, const char *file, int line)
{
	if (!sub)
		return NULL;
	sub->use_count--;
	LOGPSRC(DREF, sub->use_count >= 0? LOGL_DEBUG : LOGL_ERROR,
		file, line,
		"VLR subscr %s usage decreases to: %d\n",
		vlr_subscr_name(sub), sub->use_count);
	if (sub->use_count <= 0)
		vlr_subscr_free(sub);
	return NULL;
}

/* Allocate a new subscriber and insert it into list */
static struct vlr_subscr *_vlr_subscr_alloc(struct vlr_instance *vlr)
{
	struct vlr_subscr *vsub;
	int i;

	vsub = talloc_zero(vlr, struct vlr_subscr);
	vsub->vlr = vlr;
	vsub->tmsi = GSM_RESERVED_TMSI;
	vsub->tmsi_new = GSM_RESERVED_TMSI;

	for (i = 0; i < ARRAY_SIZE(vsub->auth_tuples); i++)
		vsub->auth_tuples[i].key_seq = GSM_KEY_SEQ_INVAL;

	INIT_LLIST_HEAD(&vsub->cs.requests);
	INIT_LLIST_HEAD(&vsub->ps.pdp_list);

	llist_add_tail(&vsub->list, &vlr->subscribers);
	return vsub;
}

struct vlr_subscr *vlr_subscr_alloc(struct vlr_instance *vlr)
{
	return vlr_subscr_get(_vlr_subscr_alloc(vlr));
}

/* Send a GSUP Purge MS request.
 * TODO: this should be sent to the *previous* VLR when this VLR is "taking"
 * this subscriber, not to the HLR? */
int vlr_subscr_purge(struct vlr_subscr *vsub)
{
	struct osmo_gsup_message gsup_msg = {0};

	gsup_msg.message_type = OSMO_GSUP_MSGT_PURGE_MS_REQUEST;

	/* provide HLR number in case we know it */
	gsup_msg.hlr_enc_len = vsub->hlr.len;
	gsup_msg.hlr_enc = vsub->hlr.buf;

	return vlr_subscr_tx_gsup_message(vsub, &gsup_msg);
}

void vlr_subscr_cancel(struct vlr_subscr *vsub, enum gsm48_gmm_cause cause)
{
	if (!vsub)
		return;

	if (vsub->lu_fsm) {
		if (vsub->lu_fsm->state == VLR_ULA_S_WAIT_HLR_UPD)
			osmo_fsm_inst_dispatch(vsub->lu_fsm,
					       VLR_ULA_E_HLR_LU_RES,
					       (void*)&cause);
		else
			osmo_fsm_inst_term(vsub->lu_fsm, OSMO_FSM_TERM_ERROR,
					   0);
	}

	if (vsub->proc_arq_fsm)
		osmo_fsm_inst_term(vsub->proc_arq_fsm, OSMO_FSM_TERM_ERROR, 0);
}

/* Call vlr_subscr_cancel(), then completely drop the entry from the VLR */
void vlr_subscr_free(struct vlr_subscr *vsub)
{
	llist_del(&vsub->list);
	DEBUGP(DREF, "freeing VLR subscr %s\n", vlr_subscr_name(vsub));
	talloc_free(vsub);
}

/* Generate a new TMSI and store in vsub->tmsi_new.
 * Search all known subscribers to ensure that the TMSI is unique. */
int vlr_subscr_alloc_tmsi(struct vlr_subscr *vsub)
{
	struct vlr_instance *vlr = vsub->vlr;
	uint32_t tmsi;
	int tried;

	for (tried = 0; tried < 100; tried++) {
		if (RAND_bytes((uint8_t *) &tmsi, sizeof(tmsi)) != 1) {
			LOGP(DVLR, LOGL_ERROR, "RAND_bytes failed\n");
			return -1;
		}
		/* throw the dice again, if the TSMI doesn't fit */
		if (tmsi == GSM_RESERVED_TMSI)
			continue;

		/* Section 2.4 of 23.003: MSC has two MSB 00/01/10, SGSN 11 */
		if (vlr->cfg.is_ps) {
			/* SGSN */
			tmsi |= 0xC000000;
		} else {
			/* MSC */
			if ((tmsi & 0xC0000000) == 0xC0000000)
				tmsi &= ~0xC0000000;
		}

		/* If this TMSI is already in use, try another one. */
		if (vlr_subscr_find_by_tmsi(vlr, tmsi))
			continue;

		vsub->tmsi_new = tmsi;
		return 0;
	}

	LOGP(DVLR, LOGL_ERROR, "subscr %s: unable to generate valid TMSI"
	     " after %d tries\n", vlr_subscr_name(vsub), tried);
	return -1;
}

/* Find subscriber by IMSI, or create new subscriber if not found.
 * \param[in] vlr  VLR instace.
 * \param[in] imsi  IMSI string.
 * \param[out] created  if non-NULL, returns whether a new entry was created. */
struct vlr_subscr *_vlr_subscr_find_or_create_by_imsi(struct vlr_instance *vlr,
						      const char *imsi,
						      bool *created,
						      const char *file,
						      int line)
{
	struct vlr_subscr *vsub;
	vsub = _vlr_subscr_find_by_imsi(vlr, imsi, file, line);
	if (vsub) {
		if (created)
			*created = false;
		return vsub;
	}

	vsub = _vlr_subscr_get(_vlr_subscr_alloc(vlr), file, line);
	if (!vsub)
		return NULL;
	vlr_subscr_set_imsi(vsub, imsi);
	LOGP(DVLR, LOGL_INFO, "New subscr, IMSI: %s\n", vsub->imsi);
	if (created)
		*created = true;
	return vsub;
}

/* Find subscriber by TMSI, or create new subscriber if not found.
 * \param[in] vlr  VLR instace.
 * \param[in] tmsi  TMSI.
 * \param[out] created  if non-NULL, returns whether a new entry was created. */
struct vlr_subscr *_vlr_subscr_find_or_create_by_tmsi(struct vlr_instance *vlr,
						      uint32_t tmsi,
						      bool *created,
						      const char *file,
						      int line)
{
	struct vlr_subscr *vsub;
	vsub = _vlr_subscr_find_by_tmsi(vlr, tmsi, file, line);
	if (vsub) {
		if (created)
			*created = false;
		return vsub;
	}

	vsub = _vlr_subscr_get(_vlr_subscr_alloc(vlr), file, line);
	if (!vsub)
		return NULL;
	vsub->tmsi = tmsi;
	LOGP(DVLR, LOGL_INFO, "New subscr, TMSI: 0x%08x\n", vsub->tmsi);
	if (created)
		*created = true;
	return vsub;
}

void vlr_subscr_set_imsi(struct vlr_subscr *vsub, const char *imsi)
{
	if (!vsub)
		return;
	osmo_strlcpy(vsub->imsi, imsi, sizeof(vsub->imsi));
	vsub->id = atoll(vsub->imsi);
	DEBUGP(DVLR, "set IMSI on subscriber; IMSI=%s id=%llu\n",
	       vsub->imsi, vsub->id);
}

void vlr_subscr_set_imei(struct vlr_subscr *vsub, const char *imei)
{
	if (!vsub)
		return;
	osmo_strlcpy(vsub->imei, imei, sizeof(vsub->imei));
	DEBUGP(DVLR, "set IMEI on subscriber; IMSI=%s IMEI=%s\n",
	       vsub->imsi, vsub->imei);
}

void vlr_subscr_set_imeisv(struct vlr_subscr *vsub, const char *imeisv)
{
	if (!vsub)
		return;
	osmo_strlcpy(vsub->imeisv, imeisv, sizeof(vsub->imeisv));
	DEBUGP(DVLR, "set IMEISV on subscriber; IMSI=%s IMEISV=%s\n",
	       vsub->imsi, vsub->imeisv);
}

/* Safely copy the given MSISDN string to vsub->msisdn */
void vlr_subscr_set_msisdn(struct vlr_subscr *vsub, const char *msisdn)
{
	if (!vsub)
		return;
	osmo_strlcpy(vsub->msisdn, msisdn, sizeof(vsub->msisdn));
	DEBUGP(DVLR, "set MSISDN on subscriber; IMSI=%s MSISDN=%s\n",
	       vsub->imsi, vsub->msisdn);
}

bool vlr_subscr_matches_imsi(struct vlr_subscr *vsub, const char *imsi)
{
	return vsub && imsi && vsub->imsi[0] && !strcmp(vsub->imsi, imsi);
}

bool vlr_subscr_matches_tmsi(struct vlr_subscr *vsub, uint32_t tmsi)
{
	return vsub && tmsi != GSM_RESERVED_TMSI
		&& (vsub->tmsi == tmsi || vsub->tmsi_new == tmsi);
}

bool vlr_subscr_matches_msisdn(struct vlr_subscr *vsub, const char *msisdn)
{
	return vsub && msisdn && vsub->msisdn[0]
		&& !strcmp(vsub->msisdn, msisdn);
}

bool vlr_subscr_matches_imei(struct vlr_subscr *vsub, const char *imei)
{
	return vsub && imei && vsub->imei[0]
		&& !strcmp(vsub->imei, imei);
}

/* Send updated subscriber information to HLR */
int vlr_subscr_changed(struct vlr_subscr *vsub)
{
	/* FIXME */
	LOGP(DVLR, LOGL_ERROR, "Not implemented: %s\n", __func__);
	return 0;
}

/***********************************************************************
 * PDP context data
 ***********************************************************************/

struct sgsn_subscriber_pdp_data *
vlr_subscr_pdp_data_alloc(struct vlr_subscr *vsub)
{
	struct sgsn_subscriber_pdp_data* pdata;

	pdata = talloc_zero(vsub, struct sgsn_subscriber_pdp_data);

	llist_add_tail(&pdata->list, &vsub->ps.pdp_list);

	return pdata;
}

static int vlr_subscr_pdp_data_clear(struct vlr_subscr *vsub)
{
	struct sgsn_subscriber_pdp_data *pdp, *pdp2;
	int count = 0;

	llist_for_each_entry_safe(pdp, pdp2, &vsub->ps.pdp_list, list) {
		llist_del(&pdp->list);
		talloc_free(pdp);
		count += 1;
	}

	return count;
}

static struct sgsn_subscriber_pdp_data *
vlr_subscr_pdp_data_get_by_id(struct vlr_subscr *vsub, unsigned context_id)
{
	struct sgsn_subscriber_pdp_data *pdp;

	llist_for_each_entry(pdp, &vsub->ps.pdp_list, list) {
		if (pdp->context_id == context_id)
			return pdp;
	}

	return NULL;
}

/***********************************************************************
 * Actual Implementation
 ***********************************************************************/

static int vlr_rx_gsup_unknown_imsi(struct vlr_instance *vlr,
				   struct osmo_gsup_message *gsup_msg)
{
	if (OSMO_GSUP_IS_MSGT_REQUEST(gsup_msg->message_type)) {
		vlr_tx_gsup_error_reply(vlr, gsup_msg,
					GMM_CAUSE_IMSI_UNKNOWN);
		LOGP(DVLR, LOGL_NOTICE,
		     "Unknown IMSI %s, discarding GSUP request "
		     "of type 0x%02x\n",
		     gsup_msg->imsi, gsup_msg->message_type);
	} else if (OSMO_GSUP_IS_MSGT_ERROR(gsup_msg->message_type)) {
		LOGP(DVLR, LOGL_NOTICE,
		     "Unknown IMSI %s, discarding GSUP error "
		     "of type 0x%02x, cause '%s' (%d)\n",
		     gsup_msg->imsi, gsup_msg->message_type,
		     get_value_string(gsm48_gmm_cause_names, gsup_msg->cause),
		     gsup_msg->cause);
	} else {
		LOGP(DVLR, LOGL_NOTICE,
		     "Unknown IMSI %s, discarding GSUP response "
		     "of type 0x%02x\n",
		     gsup_msg->imsi, gsup_msg->message_type);
	}

	return -GMM_CAUSE_IMSI_UNKNOWN;
}

static int vlr_rx_gsup_purge_no_subscr(struct vlr_instance *vlr,
				struct osmo_gsup_message *gsup_msg)
{
	if (OSMO_GSUP_IS_MSGT_ERROR(gsup_msg->message_type)) {
		LOGGSUPP(LOGL_NOTICE, gsup_msg,
			 "Purge MS has failed with cause '%s' (%d)\n",
			 get_value_string(gsm48_gmm_cause_names, gsup_msg->cause),
			 gsup_msg->cause);
		return -gsup_msg->cause;
	}
	LOGGSUPP(LOGL_INFO, gsup_msg, "Completing purge MS\n");
	return 0;
}

/* VLR internal call to request UpdateLocation from HLR */
int vlr_subscr_req_lu(struct vlr_subscr *vsub, bool is_ps)
{
	struct osmo_gsup_message gsup_msg = {0};
	int rc;

	gsup_msg.message_type = OSMO_GSUP_MSGT_UPDATE_LOCATION_REQUEST;
	rc = vlr_subscr_tx_gsup_message(vsub, &gsup_msg);

	return rc;
}

/* VLR internal call to request tuples from HLR */
int vlr_subscr_req_sai(struct vlr_subscr *vsub,
		       const uint8_t *auts, const uint8_t *auts_rand)
{
	struct osmo_gsup_message gsup_msg = {0};

	gsup_msg.message_type = OSMO_GSUP_MSGT_SEND_AUTH_INFO_REQUEST;
	gsup_msg.auts = auts;
	gsup_msg.rand = auts_rand;

	return vlr_subscr_tx_gsup_message(vsub, &gsup_msg);
}

/* Tell HLR that authentication failure occurred */
int vlr_subscr_tx_auth_fail_rep(struct vlr_subscr *vsub)
{
	struct osmo_gsup_message gsup_msg = {0};

	gsup_msg.message_type = OSMO_GSUP_MSGT_AUTH_FAIL_REPORT;
	osmo_strlcpy(gsup_msg.imsi, vsub->imsi, sizeof(gsup_msg.imsi));
	return vlr_tx_gsup_message(vsub->vlr, &gsup_msg);
}

/* Update the subscriber with GSUP-received auth tuples */
void vlr_subscr_update_tuples(struct vlr_subscr *vsub,
			      const struct osmo_gsup_message *gsup)
{
	unsigned int i;
	unsigned int got_tuples;

	if (gsup->num_auth_vectors) {
		memset(&vsub->auth_tuples, 0, sizeof(vsub->auth_tuples));
		for (i = 0; i < ARRAY_SIZE(vsub->auth_tuples); i++)
			vsub->auth_tuples[i].key_seq = GSM_KEY_SEQ_INVAL;
	}

	got_tuples = 0;
	for (i = 0; i < gsup->num_auth_vectors; i++) {
		size_t key_seq = i;

		if (key_seq >= ARRAY_SIZE(vsub->auth_tuples)) {
			LOGVSUBP(LOGL_NOTICE, vsub,
				"Skipping auth tuple wih invalid cksn %zu\n",
				key_seq);
			continue;
		}
		vsub->auth_tuples[i].vec = gsup->auth_vectors[i];
		vsub->auth_tuples[i].key_seq = key_seq;
		got_tuples ++;
	}

	LOGVSUBP(LOGL_DEBUG, vsub, "Received %u auth tuples\n", got_tuples);

	if (!got_tuples) {
		/* FIXME what now? */
		// vlr_subscr_cancel(vsub, GMM_CAUSE_GSM_AUTH_UNACCEPT); ?
	}

	/* New tuples means last_tuple becomes invalid */
	vsub->last_tuple = NULL;
}

/* Handle SendAuthInfo Result/Error from HLR */
static int vlr_subscr_handle_sai_res(struct vlr_subscr *vsub,
				     const struct osmo_gsup_message *gsup)
{
	struct osmo_fsm_inst *auth_fi = vsub->auth_fsm;
	void *data = (void *) gsup;

	switch (gsup->message_type) {
	case OSMO_GSUP_MSGT_SEND_AUTH_INFO_RESULT:
		osmo_fsm_inst_dispatch(auth_fi, VLR_AUTH_E_HLR_SAI_ACK, data);
		break;
	case OSMO_GSUP_MSGT_SEND_AUTH_INFO_ERROR:
		osmo_fsm_inst_dispatch(auth_fi, VLR_AUTH_E_HLR_SAI_NACK, data);
		break;
	default:
		return -1;
	}

	return 0;
}

static int decode_bcd_number_safe(char *output, int output_len,
				  const uint8_t *bcd_lv, int input_len,
				  int h_len)
{
	uint8_t len;
	OSMO_ASSERT(output_len >= 1);
	*output = '\0';
	if (input_len < 1)
		return -EIO;
	len = bcd_lv[0];
	if (input_len < len)
		return -EIO;
	return gsm48_decode_bcd_number(output, output_len, bcd_lv, h_len);
}

static void vlr_subscr_gsup_insert_data(struct vlr_subscr *vsub,
					const struct osmo_gsup_message *gsup_msg)
{
	unsigned idx;
	int rc;

	if (gsup_msg->msisdn_enc) {
		decode_bcd_number_safe(vsub->msisdn, sizeof(vsub->msisdn),
				       gsup_msg->msisdn_enc,
				       gsup_msg->msisdn_enc_len, 0);
		LOGP(DVLR, LOGL_DEBUG, "IMSI:%s has MSISDN:%s\n",
		     vsub->imsi, vsub->msisdn);
	}

	if (gsup_msg->hlr_enc) {
		if (gsup_msg->hlr_enc_len > sizeof(vsub->hlr.buf)) {
			LOGP(DVLR, LOGL_ERROR, "HLR-Number too long (%zu)\n",
				gsup_msg->hlr_enc_len);
			vsub->hlr.len = 0;
		} else {
			memcpy(vsub->hlr.buf, gsup_msg->hlr_enc,
				gsup_msg->hlr_enc_len);
			vsub->hlr.len = gsup_msg->hlr_enc_len;
		}
	}

	if (gsup_msg->pdp_info_compl) {
		rc = vlr_subscr_pdp_data_clear(vsub);
		if (rc > 0)
			LOGP(DVLR, LOGL_INFO, "Cleared existing PDP info\n");
	}

	for (idx = 0; idx < gsup_msg->num_pdp_infos; idx++) {
		const struct osmo_gsup_pdp_info *pdp_info = &gsup_msg->pdp_infos[idx];
		size_t ctx_id = pdp_info->context_id;
		struct sgsn_subscriber_pdp_data *pdp_data;

		if (pdp_info->apn_enc_len >= sizeof(pdp_data->apn_str)-1) {
			LOGVSUBP(LOGL_ERROR, vsub,
			     "APN too long, context id = %zu, APN = %s\n",
			     ctx_id, osmo_hexdump(pdp_info->apn_enc,
						  pdp_info->apn_enc_len));
			continue;
		}

		if (pdp_info->qos_enc_len > sizeof(pdp_data->qos_subscribed)) {
			LOGVSUBP(LOGL_ERROR, vsub,
				"QoS info too long (%zu)\n",
				pdp_info->qos_enc_len);
			continue;
		}

		LOGVSUBP(LOGL_INFO, vsub,
		     "Will set PDP info, context id = %zu, APN = %s\n",
		     ctx_id, osmo_hexdump(pdp_info->apn_enc, pdp_info->apn_enc_len));

		/* Set PDP info [ctx_id] */
		pdp_data = vlr_subscr_pdp_data_get_by_id(vsub, ctx_id);
		if (!pdp_data) {
			pdp_data = vlr_subscr_pdp_data_alloc(vsub);
			pdp_data->context_id = ctx_id;
		}

		OSMO_ASSERT(pdp_data != NULL);
		pdp_data->pdp_type = pdp_info->pdp_type;
		osmo_apn_to_str(pdp_data->apn_str,
				pdp_info->apn_enc, pdp_info->apn_enc_len);
		memcpy(pdp_data->qos_subscribed, pdp_info->qos_enc, pdp_info->qos_enc_len);
		pdp_data->qos_subscribed_len = pdp_info->qos_enc_len;
	}
}


/* Handle InsertSubscrData Result from HLR */
static int vlr_subscr_handle_isd_req(struct vlr_subscr *vsub,
				     const struct osmo_gsup_message *gsup)
{
	struct osmo_gsup_message gsup_reply = {0};

	vlr_subscr_gsup_insert_data(vsub, gsup);
	vsub->vlr->ops.subscr_update(vsub);

	gsup_reply.message_type = OSMO_GSUP_MSGT_INSERT_DATA_RESULT;
	return vlr_subscr_tx_gsup_message(vsub, &gsup_reply);
}

/* Handle UpdateLocation Result from HLR */
static int vlr_subscr_handle_lu_res(struct vlr_subscr *vsub,
				    const struct osmo_gsup_message *gsup)
{
	if (!vsub->lu_fsm) {
		LOGVSUBP(LOGL_ERROR, vsub, "Rx GSUP LU Result "
			 "without LU in progress\n");
		return -ENODEV;
	}

	/* contrary to MAP, we allow piggy-backing subscriber data onto the
	 * UPDATE LOCATION RESULT, and don't mandate the use of a separate
	 * nested INSERT SUBSCRIBER DATA transaction */
	vlr_subscr_gsup_insert_data(vsub, gsup);

	osmo_fsm_inst_dispatch(vsub->lu_fsm, VLR_ULA_E_HLR_LU_RES, NULL);

	return 0;
}

/* Handle UpdateLocation Result from HLR */
static int vlr_subscr_handle_lu_err(struct vlr_subscr *vsub,
				    const struct osmo_gsup_message *gsup)
{
	if (!vsub->lu_fsm) {
		LOGVSUBP(LOGL_ERROR, vsub, "Rx GSUP LU Error "
			 "without LU in progress\n");
		return -ENODEV;
	}

	LOGVSUBP(LOGL_DEBUG, vsub, "UpdateLocation failed; gmm_cause: %s\n",
		 get_value_string(gsm48_gmm_cause_names, gsup->cause));

	osmo_fsm_inst_dispatch(vsub->lu_fsm, VLR_ULA_E_HLR_LU_RES,
				(void *)&gsup->cause);

	return 0;
}

/* Handle LOCATION CANCEL request from HLR */
static int vlr_subscr_handle_cancel_req(struct vlr_subscr *vsub,
					struct osmo_gsup_message *gsup_msg)
{
	struct osmo_gsup_message gsup_reply = {0};
	int is_update_procedure = !gsup_msg->cancel_type ||
		gsup_msg->cancel_type == OSMO_GSUP_CANCEL_TYPE_UPDATE;

	LOGVSUBP(LOGL_INFO, vsub, "Cancelling MS subscriber (%s)\n",
		 is_update_procedure ?
		 "update procedure" : "subscription withdraw");

	gsup_reply.message_type = OSMO_GSUP_MSGT_LOCATION_CANCEL_RESULT;
	vlr_subscr_tx_gsup_message(vsub, &gsup_reply);

	vlr_subscr_cancel(vsub, gsup_msg->cause);

	return 0;
}

/* Incoming handler for GSUP from HLR.
 * Keep this function non-static for direct invocation by unit tests. */
int vlr_gsupc_read_cb(struct gsup_client *gsupc, struct msgb *msg)
{
	struct vlr_instance *vlr = (struct vlr_instance *) gsupc->data;
	struct vlr_subscr *vsub;
	struct osmo_gsup_message gsup;
	int rc;

	DEBUGP(DVLR, "GSUP rx %u: %s\n", msgb_l2len(msg),
	       osmo_hexdump_nospc(msgb_l2(msg), msgb_l2len(msg)));

	rc = osmo_gsup_decode(msgb_l2(msg), msgb_l2len(msg), &gsup);
	if (rc < 0) {
		LOGP(DVLR, LOGL_ERROR,
			"decoding GSUP message fails with error '%s' (%d)\n",
			get_value_string(gsm48_gmm_cause_names, -rc), -rc);
		return rc;
	}

	if (!gsup.imsi[0]) {
		LOGP(DVLR, LOGL_ERROR, "Missing IMSI in GSUP message\n");
		if (OSMO_GSUP_IS_MSGT_REQUEST(gsup.message_type))
			vlr_tx_gsup_error_reply(vlr, &gsup,
						GMM_CAUSE_INV_MAND_INFO);
		return -GMM_CAUSE_INV_MAND_INFO;
	}

	vsub = vlr_subscr_find_by_imsi(vlr, gsup.imsi);
	if (!vsub) {
		switch (gsup.message_type) {
		case OSMO_GSUP_MSGT_PURGE_MS_RESULT:
		case OSMO_GSUP_MSGT_PURGE_MS_ERROR:
			return vlr_rx_gsup_purge_no_subscr(vlr, &gsup);
		default:
			return vlr_rx_gsup_unknown_imsi(vlr, &gsup);
		}
	}

	switch (gsup.message_type) {
	case OSMO_GSUP_MSGT_SEND_AUTH_INFO_RESULT:
	case OSMO_GSUP_MSGT_SEND_AUTH_INFO_ERROR:
		rc = vlr_subscr_handle_sai_res(vsub, &gsup);
		break;
	case OSMO_GSUP_MSGT_INSERT_DATA_REQUEST:
		rc = vlr_subscr_handle_isd_req(vsub, &gsup);
		break;
	case OSMO_GSUP_MSGT_LOCATION_CANCEL_REQUEST:
		rc = vlr_subscr_handle_cancel_req(vsub, &gsup);
		break;
	case OSMO_GSUP_MSGT_UPDATE_LOCATION_RESULT:
		rc = vlr_subscr_handle_lu_res(vsub, &gsup);
		break;
	case OSMO_GSUP_MSGT_UPDATE_LOCATION_ERROR:
		rc = vlr_subscr_handle_lu_err(vsub, &gsup);
		break;
	case OSMO_GSUP_MSGT_PURGE_MS_ERROR:
	case OSMO_GSUP_MSGT_PURGE_MS_RESULT:
	case OSMO_GSUP_MSGT_DELETE_DATA_REQUEST:
		LOGVSUBP(LOGL_ERROR, vsub,
			"Rx GSUP msg_type=%d not yet implemented\n",
			gsup.message_type);
		rc = -GMM_CAUSE_MSGT_NOTEXIST_NOTIMPL;
		break;
	default:
		LOGVSUBP(LOGL_ERROR, vsub,
			"Rx GSUP msg_type=%d not valid at VLR/SGSN side\n",
			gsup.message_type);
		rc = -GMM_CAUSE_MSGT_NOTEXIST_NOTIMPL;
		break;
	}

	vlr_subscr_put(vsub);
	return rc;
}

/* MSC->VLR: Subscriber has provided IDENTITY RESPONSE */
int vlr_subscr_rx_id_resp(struct vlr_subscr *vsub,
			  const uint8_t *mi, size_t mi_len)
{
	char mi_string[GSM48_MI_SIZE];
	uint8_t mi_type = mi[0] & GSM_MI_TYPE_MASK;

	gsm48_mi_to_string(mi_string, sizeof(mi_string), mi, mi_len);

	/* update the vlr_subscr with the given identity */
	switch (mi_type) {
	case GSM_MI_TYPE_IMSI:
		if (vsub->imsi[0]
		    && !vlr_subscr_matches_imsi(vsub, mi_string)) {
			LOGVSUBP(LOGL_ERROR, vsub, "IMSI in ID RESP differs:"
				 " %s\n", mi_string);
		} else
			vlr_subscr_set_imsi(vsub, mi_string);
		break;
	case GSM_MI_TYPE_IMEI:
		vlr_subscr_set_imei(vsub, mi_string);
		break;
	case GSM_MI_TYPE_IMEISV:
		vlr_subscr_set_imeisv(vsub, mi_string);
		break;
	}

	if (vsub->auth_fsm) {
		switch (mi_type) {
		case GSM_MI_TYPE_IMSI:
			osmo_fsm_inst_dispatch(vsub->auth_fsm,
					VLR_AUTH_E_MS_ID_IMSI, mi_string);
			break;
		}
	}

	if (vsub->lu_fsm) {
		uint32_t event = 0;
		switch (mi_type) {
		case GSM_MI_TYPE_IMSI:
			event = VLR_ULA_E_ID_IMSI;
			break;
		case GSM_MI_TYPE_IMEI:
			event = VLR_ULA_E_ID_IMEI;
			break;
		case GSM_MI_TYPE_IMEISV:
			event = VLR_ULA_E_ID_IMEISV;
			break;
		default:
			OSMO_ASSERT(0);
			break;
		}
		osmo_fsm_inst_dispatch(vsub->lu_fsm, event, mi_string);
	} else {
		LOGVSUBP(LOGL_NOTICE,  vsub, "gratuitous ID RESPONSE?!?\n");
	}

	return 0;
}

/* MSC->VLR: Subscriber has provided IDENTITY RESPONSE */
int vlr_subscr_rx_tmsi_reall_compl(struct vlr_subscr *vsub)
{
	if (vsub->lu_fsm) {
		return osmo_fsm_inst_dispatch(vsub->lu_fsm,
					      VLR_ULA_E_NEW_TMSI_ACK, NULL);
	} else if (vsub->proc_arq_fsm) {
		return osmo_fsm_inst_dispatch(vsub->proc_arq_fsm,
					      PR_ARQ_E_TMSI_ACK, NULL);
	} else {
		LOGVSUBP(LOGL_NOTICE, vsub,
			 "gratuitous TMSI REALLOC COMPL");
		return -EINVAL;
	}
}

int vlr_subscr_rx_imsi_detach(struct vlr_subscr *vsub)
{
	/* paranoia: should any LU or PARQ FSMs still be running, stop them. */
	vlr_subscr_cancel(vsub, GMM_CAUSE_IMPL_DETACHED);

	vsub->imsi_detached_flag = true;
	if (vsub->lu_complete) {
		vsub->lu_complete = false;
		/* balancing the get from vlr_lu_compl_fsm_success() */
		vlr_subscr_put(vsub);
	}
	return 0;
}

/* Tear down any running FSMs due to MSC connection timeout.
 * Visit all vsub->*_fsm pointers and give them a queue to send a final reject
 * message before the entire connection is torn down.
 * \param[in] vsub  subscriber to tear down
 */
void vlr_subscr_conn_timeout(struct vlr_subscr *vsub)
{
	if (!vsub)
		return;

	vlr_loc_update_conn_timeout(vsub->lu_fsm);
	vlr_parq_conn_timeout(vsub->proc_arq_fsm);
}

struct vlr_instance *vlr_alloc(void *ctx, const struct vlr_ops *ops)
{
	struct vlr_instance *vlr = talloc_zero(ctx, struct vlr_instance);
	OSMO_ASSERT(vlr);

	/* Some of these are needed only on UTRAN, but in case the caller wants
	 * only GERAN, she should just provide dummy callbacks. */
	OSMO_ASSERT(ops->tx_auth_req);
	OSMO_ASSERT(ops->tx_auth_rej);
	OSMO_ASSERT(ops->tx_id_req);
	OSMO_ASSERT(ops->tx_lu_acc);
	OSMO_ASSERT(ops->tx_lu_rej);
	OSMO_ASSERT(ops->tx_cm_serv_acc);
	OSMO_ASSERT(ops->tx_cm_serv_rej);
	OSMO_ASSERT(ops->set_ciph_mode);
	OSMO_ASSERT(ops->tx_common_id);
	OSMO_ASSERT(ops->subscr_update);
	OSMO_ASSERT(ops->subscr_assoc);

	INIT_LLIST_HEAD(&vlr->subscribers);
	INIT_LLIST_HEAD(&vlr->operations);
	memcpy(&vlr->ops, ops, sizeof(vlr->ops));

	/* osmo_auth_fsm.c */
	osmo_fsm_register(&vlr_auth_fsm);
	/* osmo_lu_fsm.c */
	vlr_lu_fsm_init();
	/* vlr_access_request_fsm.c */
	vlr_parq_fsm_init();

	return vlr;
}

int vlr_start(const char *gsup_unit_name, struct vlr_instance *vlr,
	      const char *gsup_server_addr_str, uint16_t gsup_server_port)
{
	OSMO_ASSERT(vlr);

	vlr->gsup_client = gsup_client_create(gsup_unit_name,
					      gsup_server_addr_str,
					      gsup_server_port,
					      &vlr_gsupc_read_cb, NULL);
	if (!vlr->gsup_client)
		return -ENOMEM;
	vlr->gsup_client->data = vlr;

	return 0;
}

/* MSC->VLR: Subscribre has disconnected */
int vlr_subscr_disconnected(struct vlr_subscr *vsub)
{
	/* This corresponds to a MAP-ABORT from MSC->VLR on a classic B
	 * interface */
	osmo_fsm_inst_term(vsub->lu_fsm, OSMO_FSM_TERM_REQUEST, NULL);
	osmo_fsm_inst_term(vsub->auth_fsm, OSMO_FSM_TERM_REQUEST, NULL);
	vsub->msc_conn_ref = NULL;

	return 0;
}

/* MSC->VLR: Receive Authentication Failure from Subscriber */
int vlr_subscr_rx_auth_fail(struct vlr_subscr *vsub, const uint8_t *auts)
{
	struct vlr_auth_resp_par par = {0};
	par.auts = auts;

	osmo_fsm_inst_dispatch(vsub->auth_fsm, VLR_AUTH_E_MS_AUTH_FAIL, &par);
	return 0;
}

/* MSC->VLR: Receive Authentication Response from MS
 * \returns 1 in case of success, 0 in case of delay, -1 on auth error */
int vlr_subscr_rx_auth_resp(struct vlr_subscr *vsub, bool is_r99,
			 bool is_utran, const uint8_t *res, uint8_t res_len)
{
	struct osmo_fsm_inst *auth_fi = vsub->auth_fsm;
	struct vlr_auth_resp_par par;

	par.is_r99 = is_r99;
	par.is_utran = is_utran;
	par.res = res;
	par.res_len = res_len;
	osmo_fsm_inst_dispatch(auth_fi, VLR_AUTH_E_MS_AUTH_RESP, (void *) &par);

	return 0;
}

/* MSC->VLR: Receive result of Ciphering Mode Command from MS */
void vlr_subscr_rx_ciph_res(struct vlr_subscr *vsub, struct vlr_ciph_result *res)
{
	if (vsub->lu_fsm && vsub->lu_fsm->state == VLR_ULA_S_WAIT_CIPH)
		osmo_fsm_inst_dispatch(vsub->lu_fsm, VLR_ULA_E_CIPH_RES, res);
	if (vsub->proc_arq_fsm
	    && vsub->proc_arq_fsm->state == PR_ARQ_S_WAIT_CIPH)
		osmo_fsm_inst_dispatch(vsub->proc_arq_fsm, PR_ARQ_E_CIPH_RES,
				       res);
}

/* Internal evaluation of requested ciphering mode.
 * Send set_ciph_mode() to MSC depending on the ciph_mode argument.
 * \param[in] vlr  VLR instance.
 * \param[in] fi  Calling FSM instance, for logging.
 * \param[in] msc_conn_ref  MSC conn to send to.
 * \param[in] ciph_mode  Ciphering config, to decide whether to do ciphering.
 * \returns 0 if no ciphering is needed or message was sent successfully,
 *          or a negative value if ciph_mode is invalid or sending failed.
 */
int vlr_set_ciph_mode(struct vlr_instance *vlr,
		      struct osmo_fsm_inst *fi,
		      void *msc_conn_ref,
		      enum vlr_ciph ciph_mode,
		      bool retrieve_imeisv)
{
	switch (ciph_mode) {
	case VLR_CIPH_NONE:
		return 0;

	case VLR_CIPH_A5_1:
	case VLR_CIPH_A5_3:
		return vlr->ops.set_ciph_mode(msc_conn_ref,
					      ciph_mode,
					      retrieve_imeisv);

	case VLR_CIPH_A5_2:
		/* TODO policy by user config? */
		LOGPFSML(fi, LOGL_ERROR, "A5/2 ciphering is not allowed\n");
		return -EINVAL;

	default:
		LOGPFSML(fi, LOGL_ERROR, "unknown ciphering value: %d\n",
			 ciph_mode);
		return -EINVAL;
	}
}

void log_set_filter_vlr_subscr(struct log_target *target,
			       struct vlr_subscr *vlr_subscr)
{
	struct vlr_subscr **fsub = (void*)&target->filter_data[LOG_FLT_VLR_SUBSCR];

	/* free the old data */
	if (*fsub) {
		vlr_subscr_put(*fsub);
		*fsub = NULL;
	}

	if (vlr_subscr) {
		target->filter_map |= (1 << LOG_FLT_VLR_SUBSCR);
		*fsub = vlr_subscr_get(vlr_subscr);
	} else
		target->filter_map &= ~(1 << LOG_FLT_VLR_SUBSCR);
}
