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
#include <osmocom/gsm/protocol/gsm_04_08_gprs.h>
#include <osmocom/gsm/gsup.h>
#include <osmocom/gsm/apn.h>
#include <openbsc/gsm_subscriber.h>
#include <openbsc/gprs_gsup_client.h>
#include <openbsc/vlr.h>
#include <openbsc/gprs_sgsn.h>
#include <openbsc/gprs_utils.h>
#include <openbsc/debug.h>

#include <openssl/rand.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#include "vlr_core.h"
#include "vlr_auth_fsm.h"
#include "vlr_access_req_fsm.h"
#include "vlr_lu_fsm.h"

#define SGSN_SUBSCR_MAX_RETRIES 3
#define SGSN_SUBSCR_RETRY_INTERVAL 10

/***********************************************************************
 * Convenience functions
 ***********************************************************************/

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

/* return static buffer with printable name of VLR subscriber */
const char *vlr_sub_name(struct vlr_subscriber *vsub)
{
	static char buf[32];
	if (vsub->imsi[0])
		strncpy(buf, vsub->imsi, sizeof(buf));
	else
		snprintf(buf, sizeof(buf), "0x%08x", vsub->tmsi);
	buf[sizeof(buf)-1] = '\0';
	return buf;
}

struct vlr_subscriber *
vlr_subscr_find_by_imsi(struct vlr_instance *vlr, const char *imsi)
{
	struct vlr_subscriber *vsub;

	llist_for_each_entry(vsub, &vlr->subscribers, list) {
		if (!strcmp(vsub->imsi, imsi))
			return vsub;
	}
	return NULL;
}

struct vlr_subscriber *
vlr_subscr_find_by_tmsi(struct vlr_instance *vlr, uint32_t tmsi)
{
	struct vlr_subscriber *vsub;

	llist_for_each_entry(vsub, &vlr->subscribers, list) {
		if (vsub->tmsi == tmsi)
			return vsub;
	}
	return NULL;
}

/* Transmit GSUP message to HLR */
static int vlr_tx_gsup_message(struct vlr_instance *vlr,
			       struct osmo_gsup_message *gsup_msg)
{
	struct msgb *msg = gprs_gsup_msgb_alloc();

	osmo_gsup_encode(msg, gsup_msg);

	if (!vlr->gsup_client) {
		LOGP(DVLR, LOGL_NOTICE, "GSUP link is down, cannot "
			"send GSUP: %s\n", msgb_hexdump(msg));
		msgb_free(msg);
		return -ENOTSUP;
	}

	LOGP(DVLR, LOGL_DEBUG,
		    "Sending GSUP, will send: %s\n", msgb_hexdump(msg));

	return gprs_gsup_client_send(vlr->gsup_client, msg);
}

/* Transmit GSUP message for subscriber to HLR, using IMSI from subscriber */
static int vlr_subscr_tx_gsup_message(struct vlr_subscriber *vsub,
				      struct osmo_gsup_message *gsup_msg)
{
	struct vlr_instance *vlr = vsub->vlr;

	if (strlen(gsup_msg->imsi) == 0)
		strncpy(gsup_msg->imsi, vsub->imsi, sizeof(gsup_msg->imsi) - 1);

	return vlr_tx_gsup_message(vlr, gsup_msg);
}

/* Transmit GSUP error in response to original message */
static int vlr_tx_gsup_error_reply(struct vlr_instance *vlr,
				   struct osmo_gsup_message *gsup_orig,
				   enum gsm48_gmm_cause cause)
{
	struct osmo_gsup_message gsup_reply = {0};

	strncpy(gsup_reply.imsi, gsup_orig->imsi, sizeof(gsup_reply.imsi) - 1);
	gsup_reply.cause = cause;
	gsup_reply.message_type =
		OSMO_GSUP_TO_MSGT_ERROR(gsup_orig->message_type);

	return vlr_tx_gsup_message(vlr, &gsup_reply);
}

/* Allocate a new subscriber and insert it into list */
struct vlr_subscriber *vlr_sub_alloc(struct vlr_instance *vlr)
{
	struct vlr_subscriber *vsub;
	int i;

	vsub = talloc_zero(vlr, struct vlr_subscriber);
	vsub->vlr = vlr;
	vsub->tmsi = GSM_RESERVED_TMSI;

	for (i = 0; i < ARRAY_SIZE(vsub->auth_tuples); i++)
		vsub->auth_tuples[i].key_seq = GSM_KEY_SEQ_INVAL;

	INIT_LLIST_HEAD(&vsub->ps.pdp_list);

	llist_add_tail(&vsub->list, &vlr->subscribers);

	/* Do not add to list of subscribers yet, as we don't yet want this
	 * subscriber to be found by lookup from e.g. MT-SMS or MT-call
	 * delivery yet. */

	return vsub;
}

static int vlr_sub_purge(struct vlr_subscriber *vsub)
{
	struct osmo_gsup_message gsup_msg = {0};

	gsup_msg.message_type = OSMO_GSUP_MSGT_PURGE_MS_REQUEST;

	/* provide HLR number in case we know it */
	gsup_msg.hlr_enc_len = vsub->hlr.len;
	gsup_msg.hlr_enc = vsub->hlr.buf;

	return vlr_subscr_tx_gsup_message(vsub, &gsup_msg);
}

void vlr_sub_cleanup(struct vlr_subscriber *vsub)
{
	if (vsub->flags & GPRS_SUBSCRIBER_ENABLE_PURGE) {
		vlr_sub_purge(vsub);
		vsub->flags &= ~GPRS_SUBSCRIBER_ENABLE_PURGE;
	}
}

void vlr_sub_cancel(struct vlr_subscriber *vsub)
{
	vsub->authorized = 0;
	vsub->flags |= GPRS_SUBSCRIBER_CANCELLED;
	vsub->flags &= ~GPRS_SUBSCRIBER_ENABLE_PURGE;

	vsub->vlr->ops.subscr_update(vsub);
	vlr_sub_cleanup(vsub);
}

int vlr_sub_alloc_tmsi(struct vlr_subscriber *vsub)
{
	struct vlr_instance *vlr = vsub->vlr;
	uint32_t tmsi;

	for (;;) {
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

		if (!vlr_subscr_find_by_tmsi(vlr, tmsi)) {
			vsub->tmsi = tmsi;
			return 0;
		}
	}

	/* not reached */
	return -1;
}

/***********************************************************************
 * PDP context data
 ***********************************************************************/

struct sgsn_subscriber_pdp_data *
vlr_sub_pdp_data_alloc(struct vlr_subscriber *vsub)
{
	struct sgsn_subscriber_pdp_data* pdata;

	pdata = talloc_zero(vsub, struct sgsn_subscriber_pdp_data);

	llist_add_tail(&pdata->list, &vsub->ps.pdp_list);

	return pdata;
}

static int vlr_sub_pdp_data_clear(struct vlr_subscriber *vsub)
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
vlr_sub_pdp_data_get_by_id(struct vlr_subscriber *vsub, unsigned context_id)
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
int vlr_sub_req_lu(struct vlr_subscriber *vsub, bool is_ps)
{
	struct osmo_gsup_message gsup_msg = {0};
	int rc;

	gsup_msg.message_type = OSMO_GSUP_MSGT_UPDATE_LOCATION_REQUEST;
	rc = vlr_subscr_tx_gsup_message(vsub, &gsup_msg);

	return rc;
}

/* VLR internal call to request tuples from HLR */
int vlr_sub_req_sai(struct vlr_subscriber *vsub,
		    const uint8_t *auts, const uint8_t *auts_rand)
{
	struct osmo_gsup_message gsup_msg = {0};

	gsup_msg.message_type = OSMO_GSUP_MSGT_SEND_AUTH_INFO_REQUEST;
	gsup_msg.auts = auts;
	gsup_msg.rand = auts_rand;

	return vlr_subscr_tx_gsup_message(vsub, &gsup_msg);
}

/* Tell HLR that authentication failure occurred */
int vlr_sub_tx_auth_fail_rep(struct vlr_subscriber *vsub)
{
	struct osmo_gsup_message gsup_msg = {0};

	gsup_msg.message_type = OSMO_GSUP_MSGT_AUTH_FAIL_REPORT;
	strncpy(gsup_msg.imsi, vsub->imsi, sizeof(gsup_msg.imsi) - 1);
	return vlr_tx_gsup_message(vsub->vlr, &gsup_msg);
}

/* Update the subscriber with GSUP-received auth tuples */
void vlr_sub_update_tuples(struct vlr_subscriber *vsub,
			   const struct osmo_gsup_message *gsup)
{
	unsigned int i;

	LOGVSUBP(LOGL_DEBUG, vsub, "Adding %zu auth tuples\n",
		 gsup->num_auth_vectors);

	if (gsup->num_auth_vectors) {
		memset(&vsub->auth_tuples, 0, sizeof(vsub->auth_tuples));
		for (i = 0; i < ARRAY_SIZE(vsub->auth_tuples); i++)
			vsub->auth_tuples[i].key_seq = GSM_KEY_SEQ_INVAL;
	}

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
	}

	vsub->auth_tuples_updated = true;
	vsub->auth_error_cause = SGSN_ERROR_CAUSE_NONE;
}

/* Handle SendAuthInfo Result/Error from HLR */
static int vlr_sub_handle_sai_res(struct vlr_subscriber *vsub,
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

static void vlr_sub_gsup_insert_data(struct vlr_subscriber *vsub,
				     const struct osmo_gsup_message *gsup_msg)
{
	unsigned idx;
	int rc;

	if (gsup_msg->msisdn_enc) {
		gsm48_mi_to_string(vsub->msisdn, sizeof(vsub->msisdn),
				   gsup_msg->msisdn_enc,
				   gsup_msg->msisdn_enc_len);
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
		rc = vlr_sub_pdp_data_clear(vsub);
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
		pdp_data = vlr_sub_pdp_data_get_by_id(vsub, ctx_id);
		if (!pdp_data) {
			pdp_data = vlr_sub_pdp_data_alloc(vsub);
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
static int vlr_sub_handle_isd_req(struct vlr_subscriber *vsub,
				  const struct osmo_gsup_message *gsup)
{
	struct osmo_gsup_message gsup_reply = {0};

	vlr_sub_gsup_insert_data(vsub, gsup);

	vsub->authorized = 1;
	vsub->auth_error_cause = SGSN_ERROR_CAUSE_NONE;
	vsub->flags |= GPRS_SUBSCRIBER_ENABLE_PURGE;
	vsub->vlr->ops.subscr_update(vsub);

	gsup_reply.message_type = OSMO_GSUP_MSGT_INSERT_DATA_RESULT;
	return vlr_subscr_tx_gsup_message(vsub, &gsup_reply);
}

/* Handle UpdateLocation Result from HLR */
static int vlr_sub_handle_lu_res(struct vlr_subscriber *vsub,
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
	vlr_sub_gsup_insert_data(vsub, gsup);

	vsub->authorized = 1;
	vsub->auth_error_cause = SGSN_ERROR_CAUSE_NONE;
	vsub->flags |= GPRS_SUBSCRIBER_ENABLE_PURGE;
	vsub->vlr->ops.subscr_update(vsub);

	osmo_fsm_inst_dispatch(vsub->lu_fsm, VLR_ULA_E_HLR_LU_RES, NULL);

	return 0;
}

/* Handle UpdateLocation Result from HLR */
static int vlr_sub_handle_lu_err(struct vlr_subscriber *vsub,
				 const struct osmo_gsup_message *gsup)
{
	if (!vsub->lu_fsm) {
		LOGVSUBP(LOGL_ERROR, vsub, "Rx GSUP LU Error "
			 "without LU in progress\n");
		return -ENODEV;
	}

	LOGVSUBP(LOGL_DEBUG, vsub, "UpdateLocation failed; gmm_cause: %s\n",
		 get_value_string(gsm48_gmm_cause_names, gsup->cause));

	vsub->authorized = 0;
	vsub->auth_error_cause = gsup->cause;

	osmo_fsm_inst_dispatch(vsub->lu_fsm, VLR_ULA_E_HLR_LU_RES,
				(void *)&gsup->cause);

	return 0;
}

/* Handel LOCATION CANCEL request from HLR */
static int vlr_sub_handle_cancel_req(struct vlr_subscriber *vsub,
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

	if (is_update_procedure)
		vsub->auth_error_cause = SGSN_ERROR_CAUSE_NONE;
	else
		/* Since a withdraw cause is not specified, just abort the
		 * current attachment. The following re-attachment should then
		 * be rejected with a proper cause value.
		 */
		vsub->auth_error_cause = GMM_CAUSE_IMPL_DETACHED;

	vlr_sub_cancel(vsub);

	return 0;
}

/* Incoming handler for GSUP from HLR */
static int vlr_gsupc_read_cb(struct gprs_gsup_client *gsupc, struct msgb *msg)
{
	struct vlr_instance *vlr = (struct vlr_instance *) gsupc->data;
	struct vlr_subscriber *vsub;
	struct osmo_gsup_message gsup;
	int rc;

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
		rc = vlr_sub_handle_sai_res(vsub, &gsup);
		break;
	case OSMO_GSUP_MSGT_INSERT_DATA_REQUEST:
		rc = vlr_sub_handle_isd_req(vsub, &gsup);
		break;
	case OSMO_GSUP_MSGT_LOCATION_CANCEL_REQUEST:
		rc = vlr_sub_handle_cancel_req(vsub, &gsup);
		break;
	case OSMO_GSUP_MSGT_UPDATE_LOCATION_RESULT:
		rc = vlr_sub_handle_lu_res(vsub, &gsup);
		break;
	case OSMO_GSUP_MSGT_UPDATE_LOCATION_ERROR:
		rc = vlr_sub_handle_lu_err(vsub, &gsup);
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

	return rc;
}

/* MSC->VLR: Subscriber has provided IDENTITY RESPONSE */
int vlr_sub_rx_id_resp(struct vlr_subscriber *vsub,
			const uint8_t *mi, size_t mi_len)
{
	char mi_string[GSM48_MI_SIZE];
	uint8_t mi_type = mi[0] & GSM_MI_TYPE_MASK;

	gsm48_mi_to_string(mi_string, sizeof(mi_string), mi, mi_len);

	/* update the vlr_subscriber with the given identity */
	switch (mi_type) {
	case GSM_MI_TYPE_IMSI:
		if (vsub->imsi[0] && strcmp(vsub->imsi, mi_string)) {
			LOGVSUBP(LOGL_ERROR, vsub, "IMSI in ID RESP differs:"
				 " %s\n", mi_string);
		} else {
			strncpy(vsub->imsi, mi_string, sizeof(vsub->imsi));
			vsub->imsi[sizeof(vsub->imsi)-1] = '\0';
		}
		break;
	case GSM_MI_TYPE_IMEI:
		strncpy(vsub->imei, mi_string, sizeof(vsub->imei));
		vsub->imei[sizeof(vsub->imei)-1] = '\0';
		break;
	case GSM_MI_TYPE_IMEISV:
		strncpy(vsub->imeisv, mi_string, sizeof(vsub->imeisv));
		vsub->imeisv[sizeof(vsub->imeisv)-1] = '\0';
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
void vlr_sub_rx_tmsi_reall_compl(struct vlr_subscriber *vsub)
{
	if (vsub->lu_fsm) {
		osmo_fsm_inst_dispatch(vsub->lu_fsm,
					VLR_ULA_E_NEW_TMSI_ACK, NULL);
	} else if (vsub->proc_arq_fsm) {
		osmo_fsm_inst_dispatch(vsub->proc_arq_fsm,
					PR_ARQ_E_TMSI_ACK, NULL);
	} else {
		LOGVSUBP(LOGL_NOTICE, vsub,
			 "gratuitous TMSI REALLOC COMPL");
	}
}

struct vlr_instance *vlr_init(void *ctx, const struct vlr_ops *ops,
			      const char *addr_str, uint16_t port)
{
	struct vlr_instance *vlr = talloc_zero(ctx, struct vlr_instance);
	OSMO_ASSERT(vlr);

	vlr->gsup_client = gprs_gsup_client_create(addr_str, port, &vlr_gsupc_read_cb, NULL);
	if (!vlr->gsup_client) {
		talloc_free(vlr);
		return NULL;
	}
	vlr->gsup_client->data = vlr;

	INIT_LLIST_HEAD(&vlr->subscribers);
	INIT_LLIST_HEAD(&vlr->operations);
	memcpy(&vlr->ops, ops, sizeof(vlr->ops));

	/* osmo_auth_fsm.c */
	osmo_fsm_register(&vlr_auth_fsm);
	/* osmo_lu_fsm.c */
	vlr_lu_fsm_init();

	return vlr;
}

/* MSC->VLR: Subscribre has disconnected */
int vlr_sub_disconnected(struct vlr_subscriber *vsub)
{
	/* This corresponds to a MAP-ABORT from MSC->VLR on a classic B
	 * interface */
	osmo_fsm_inst_term(vsub->lu_fsm, OSMO_FSM_TERM_REQUEST, NULL);
	osmo_fsm_inst_term(vsub->auth_fsm, OSMO_FSM_TERM_REQUEST, NULL);
	vsub->msc_conn_ref = NULL;

	return 0;
}

/* MSC->VLR: Receive Authentication Failure from Subscriber */
int vlr_sub_rx_auth_fail(struct vlr_subscriber *vsub, const uint8_t *auts)
{
	struct vlr_auth_resp_par par = {0};
	par.auts = auts;

	osmo_fsm_inst_dispatch(vsub->auth_fsm, VLR_AUTH_E_MS_AUTH_FAIL, &par);
	return 0;
}

/* MSC->VLR: Receive Authentication Response from MS
 * \returns 1 in case of success, 0 in case of delay, -1 on auth error */
int vlr_sub_rx_auth_resp(struct vlr_subscriber *vsub, bool is_r99,
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
