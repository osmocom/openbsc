/* MS subscriber data handling */

/* (C) 2014 by sysmocom s.f.m.c. GmbH
 * (C) 2015 by Holger Hans Peter Freyther
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

#include <osmocom/gsm/protocol/gsm_04_08_gprs.h>
#include <osmocom/gsm/gsup.h>
#include <osmocom/core/utils.h>
#include <osmocom/core/logging.h>
#include <openbsc/gprs_subscriber.h>
#include <openbsc/gsup_client.h>

#include <openbsc/sgsn.h>
#include <openbsc/gprs_sgsn.h>
#include <openbsc/gprs_gmm.h>
#include <openbsc/gprs_utils.h>

#include <openbsc/debug.h>

#include <netinet/in.h>
#include <arpa/inet.h>
#include <limits.h>

#define SGSN_SUBSCR_MAX_RETRIES 3
#define SGSN_SUBSCR_RETRY_INTERVAL 10

#define LOGGSUPP(level, gsup, fmt, args...) \
	LOGP(DGPRS, level, "GSUP(%s) " fmt, \
	     (gsup)->imsi, \
	     ## args)

extern void *tall_bsc_ctx;

LLIST_HEAD(_gprs_subscribers);
struct llist_head * const gprs_subscribers = &_gprs_subscribers;

static int gsup_read_cb(struct gsup_client *gsupc, struct msgb *msg);

/* TODO: Some functions are specific to the SGSN, but this file is more general
 * (it has gprs_* name). Either move these functions elsewhere, split them and
 * move a part, or replace the gprs_ prefix by sgsn_. The applies to
 * gprs_subscr_init, gsup_read_cb, and gprs_subscr_tx_gsup_message.
 */

int gprs_subscr_init(struct sgsn_instance *sgi)
{
	const char *addr_str;

	if (!sgi->cfg.gsup_server_addr.sin_addr.s_addr)
		return 0;

	addr_str = inet_ntoa(sgi->cfg.gsup_server_addr.sin_addr);

	sgi->gsup_client = gsup_client_create(
		addr_str, sgi->cfg.gsup_server_port,
		&gsup_read_cb,
		&sgi->cfg.oap);

	if (!sgi->gsup_client)
		return -1;

	return 1;
}

static int gsup_read_cb(struct gsup_client *gsupc, struct msgb *msg)
{
	int rc;

	rc = gprs_subscr_rx_gsup_message(msg);
	msgb_free(msg);
	if (rc < 0)
		return -1;

	return rc;
}

int gprs_subscr_purge(struct gprs_subscr *subscr);

static struct sgsn_subscriber_data *sgsn_subscriber_data_alloc(void *ctx)
{
	struct sgsn_subscriber_data *sdata;
	int idx;

	sdata = talloc_zero(ctx, struct sgsn_subscriber_data);

	sdata->error_cause = SGSN_ERROR_CAUSE_NONE;

	for (idx = 0; idx < ARRAY_SIZE(sdata->auth_triplets); idx++)
	     sdata->auth_triplets[idx].key_seq = GSM_KEY_SEQ_INVAL;

	INIT_LLIST_HEAD(&sdata->pdp_list);

	return sdata;
}

struct sgsn_subscriber_pdp_data* sgsn_subscriber_pdp_data_alloc(
	struct sgsn_subscriber_data *sdata)
{
	struct sgsn_subscriber_pdp_data* pdata;

	pdata = talloc_zero(sdata, struct sgsn_subscriber_pdp_data);

	llist_add_tail(&pdata->list, &sdata->pdp_list);

	return pdata;
}

struct gprs_subscr *gprs_subscr_get_by_imsi(const char *imsi)
{
	struct gprs_subscr *gsub;

	if (!imsi || !*imsi)
		return NULL;

	llist_for_each_entry(gsub, gprs_subscribers, entry) {
		if (!strcmp(gsub->imsi, imsi))
			return gprs_subscr_get(gsub);
	}
	return NULL;
}

static struct gprs_subscr *gprs_subscr_alloc(void)
{
	struct gprs_subscr *gsub;
	gsub = talloc_zero(tall_bsc_ctx, struct gprs_subscr);
	if (!gsub)
		return NULL;
	llist_add_tail(&gsub->entry, gprs_subscribers);
	gsub->use_count = 1;
	gsub->tmsi = GSM_RESERVED_TMSI;
	return gsub;
}

struct gprs_subscr *gprs_subscr_get_or_create(const char *imsi)
{
	struct gprs_subscr *gsub;

	gsub = gprs_subscr_get_by_imsi(imsi);
	if (!gsub) {
		gsub = gprs_subscr_alloc();
		if (!gsub)
			return NULL;
		osmo_strlcpy(gsub->imsi, imsi, sizeof(gsub->imsi));
	}

	if (!gsub->sgsn_data)
		gsub->sgsn_data = sgsn_subscriber_data_alloc(gsub);
	return gsub;
}

void gprs_subscr_cleanup(struct gprs_subscr *subscr)
{
	if (subscr->sgsn_data->mm) {
		gprs_subscr_put(subscr->sgsn_data->mm->subscr);
		subscr->sgsn_data->mm->subscr = NULL;
		subscr->sgsn_data->mm = NULL;
	}

	if (subscr->flags & GPRS_SUBSCRIBER_ENABLE_PURGE) {
		gprs_subscr_purge(subscr);
		subscr->flags &= ~GPRS_SUBSCRIBER_ENABLE_PURGE;
	}
}

void gprs_subscr_cancel(struct gprs_subscr *subscr)
{
	subscr->authorized = 0;
	subscr->flags |= GPRS_SUBSCRIBER_CANCELLED;
	subscr->flags &= ~GPRS_SUBSCRIBER_ENABLE_PURGE;

	gprs_subscr_update(subscr);
	gprs_subscr_cleanup(subscr);
}

static int gprs_subscr_tx_gsup_message(struct gprs_subscr *subscr,
				       struct osmo_gsup_message *gsup_msg)
{
	struct msgb *msg = gsup_client_msgb_alloc();

	if (strlen(gsup_msg->imsi) == 0 && subscr)
		osmo_strlcpy(gsup_msg->imsi, subscr->imsi,
			     sizeof(gsup_msg->imsi));
	gsup_msg->cn_domain = OSMO_GSUP_CN_DOMAIN_PS;
	osmo_gsup_encode(msg, gsup_msg);

	LOGGSUBSCRP(LOGL_INFO, subscr,
		    "Sending GSUP, will send: %s\n", msgb_hexdump(msg));

	if (!sgsn->gsup_client) {
		msgb_free(msg);
		return -ENOTSUP;
	}

	return gsup_client_send(sgsn->gsup_client, msg);
}

static int gprs_subscr_tx_gsup_error_reply(struct gprs_subscr *subscr,
					   struct osmo_gsup_message *gsup_orig,
					   enum gsm48_gmm_cause cause)
{
	struct osmo_gsup_message gsup_reply = {0};

	osmo_strlcpy(gsup_reply.imsi, gsup_orig->imsi,
		     sizeof(gsup_reply.imsi));
	gsup_reply.cause = cause;
	gsup_reply.message_type =
		OSMO_GSUP_TO_MSGT_ERROR(gsup_orig->message_type);

	return gprs_subscr_tx_gsup_message(subscr, &gsup_reply);
}

static int gprs_subscr_handle_gsup_auth_res(struct gprs_subscr *subscr,
					    struct osmo_gsup_message *gsup_msg)
{
	unsigned idx;
	struct sgsn_subscriber_data *sdata = subscr->sgsn_data;

	LOGGSUBSCRP(LOGL_INFO, subscr,
		"Got SendAuthenticationInfoResult, num_auth_vectors = %zu\n",
		gsup_msg->num_auth_vectors);

	if (gsup_msg->num_auth_vectors > 0) {
		memset(sdata->auth_triplets, 0, sizeof(sdata->auth_triplets));

		for (idx = 0; idx < ARRAY_SIZE(sdata->auth_triplets); idx++)
			sdata->auth_triplets[idx].key_seq = GSM_KEY_SEQ_INVAL;
	}

	for (idx = 0; idx < gsup_msg->num_auth_vectors; idx++) {
		size_t key_seq = idx;
		LOGGSUBSCRP(LOGL_DEBUG, subscr,
			"Adding auth tuple, cksn = %zu\n", key_seq);
		if (key_seq >= ARRAY_SIZE(sdata->auth_triplets)) {
			LOGGSUBSCRP(LOGL_NOTICE, subscr,
				"Skipping auth triplet with invalid cksn %zu\n",
				key_seq);
			continue;
		}
		sdata->auth_triplets[key_seq].vec = gsup_msg->auth_vectors[idx];
		sdata->auth_triplets[key_seq].key_seq = key_seq;
	}

	sdata->auth_triplets_updated = 1;
	sdata->error_cause = SGSN_ERROR_CAUSE_NONE;

	gprs_subscr_update_auth_info(subscr);

	return 0;
}

static int gprs_subscr_pdp_data_clear(struct gprs_subscr *subscr)
{
	struct sgsn_subscriber_pdp_data *pdp, *pdp2;
	int count = 0;

	llist_for_each_entry_safe(pdp, pdp2, &subscr->sgsn_data->pdp_list, list) {
		llist_del(&pdp->list);
		talloc_free(pdp);
		count += 1;
	}

	return count;
}

static struct sgsn_subscriber_pdp_data *gprs_subscr_pdp_data_get_by_id(
	struct gprs_subscr *subscr, unsigned context_id)
{
	struct sgsn_subscriber_pdp_data *pdp;

	llist_for_each_entry(pdp, &subscr->sgsn_data->pdp_list, list) {
		if (pdp->context_id == context_id)
			return pdp;
	}

	return NULL;
}


static void gprs_subscr_gsup_insert_data(struct gprs_subscr *subscr,
					 struct osmo_gsup_message *gsup_msg)
{
	struct sgsn_subscriber_data *sdata = subscr->sgsn_data;
	unsigned idx;
	int rc;

	if (gsup_msg->msisdn_enc) {
		if (gsup_msg->msisdn_enc_len > sizeof(sdata->msisdn)) {
			LOGP(DGPRS, LOGL_ERROR, "MSISDN too long (%zu)\n",
				gsup_msg->msisdn_enc_len);
			sdata->msisdn_len = 0;
		} else {
			memcpy(sdata->msisdn, gsup_msg->msisdn_enc,
				gsup_msg->msisdn_enc_len);
			sdata->msisdn_len = gsup_msg->msisdn_enc_len;
		}
	}

	if (gsup_msg->hlr_enc) {
		if (gsup_msg->hlr_enc_len > sizeof(sdata->hlr)) {
			LOGP(DGPRS, LOGL_ERROR, "HLR-Number too long (%zu)\n",
				gsup_msg->hlr_enc_len);
			sdata->hlr_len = 0;
		} else {
			memcpy(sdata->hlr, gsup_msg->hlr_enc,
				gsup_msg->hlr_enc_len);
			sdata->hlr_len = gsup_msg->hlr_enc_len;
		}
	}

	if (gsup_msg->pdp_info_compl) {
		rc = gprs_subscr_pdp_data_clear(subscr);
		if (rc > 0)
			LOGP(DGPRS, LOGL_INFO, "Cleared existing PDP info\n");
	}

	for (idx = 0; idx < gsup_msg->num_pdp_infos; idx++) {
		struct osmo_gsup_pdp_info *pdp_info = &gsup_msg->pdp_infos[idx];
		size_t ctx_id = pdp_info->context_id;
		struct sgsn_subscriber_pdp_data *pdp_data;

		if (pdp_info->apn_enc_len >= sizeof(pdp_data->apn_str)-1) {
			LOGGSUBSCRP(LOGL_ERROR, subscr,
			     "APN too long, context id = %zu, APN = %s\n",
			     ctx_id, osmo_hexdump(pdp_info->apn_enc,
						  pdp_info->apn_enc_len));
			continue;
		}

		if (pdp_info->qos_enc_len > sizeof(pdp_data->qos_subscribed)) {
			LOGGSUBSCRP(LOGL_ERROR, subscr,
				"QoS info too long (%zu)\n",
				pdp_info->qos_enc_len);
			continue;
		}

		LOGGSUBSCRP(LOGL_INFO, subscr,
		     "Will set PDP info, context id = %zu, APN = %s\n",
		     ctx_id, osmo_hexdump(pdp_info->apn_enc, pdp_info->apn_enc_len));

		/* Set PDP info [ctx_id] */
		pdp_data = gprs_subscr_pdp_data_get_by_id(subscr, ctx_id);
		if (!pdp_data) {
			pdp_data = sgsn_subscriber_pdp_data_alloc(subscr->sgsn_data);
			pdp_data->context_id = ctx_id;
		}

		OSMO_ASSERT(pdp_data != NULL);
		pdp_data->pdp_type = pdp_info->pdp_type;
		gprs_apn_to_str(pdp_data->apn_str,
				pdp_info->apn_enc, pdp_info->apn_enc_len);
		memcpy(pdp_data->qos_subscribed, pdp_info->qos_enc, pdp_info->qos_enc_len);
		pdp_data->qos_subscribed_len = pdp_info->qos_enc_len;
	}
}

static int gprs_subscr_handle_gsup_upd_loc_res(struct gprs_subscr *subscr,
					       struct osmo_gsup_message *gsup_msg)
{
	/* contrary to MAP, we allow piggy-backing subscriber data onto
	 * the UPDATE LOCATION RESULT, and don't mandate the use of a
	 * separate nested INSERT SUBSCRIBER DATA transaction */
	gprs_subscr_gsup_insert_data(subscr, gsup_msg);

	subscr->authorized = 1;
	subscr->sgsn_data->error_cause = SGSN_ERROR_CAUSE_NONE;

	subscr->flags |= GPRS_SUBSCRIBER_ENABLE_PURGE;

	gprs_subscr_update(subscr);
	return 0;
}

static int gprs_subscr_handle_gsup_dsd_req(struct gprs_subscr *subscr,
					   struct osmo_gsup_message *gsup_msg)
{
	struct osmo_gsup_message gsup_reply = {0};

	if (gsup_msg->cn_domain != OSMO_GSUP_CN_DOMAIN_PS) {
		LOGGSUBSCRP(LOGL_ERROR, subscr,
			    "Rx GSUP message %s not supported for CS\n",
			    osmo_gsup_message_type_name(gsup_msg->message_type));
		gsup_reply.cause = GMM_CAUSE_MSGT_NOTEXIST_NOTIMPL;
		gsup_reply.message_type = OSMO_GSUP_MSGT_DELETE_DATA_ERROR;
	} else {
		gsm0408_gprs_access_cancelled(subscr->sgsn_data->mm,
					      GMM_CAUSE_GPRS_NOTALLOWED);
		gsup_reply.message_type = OSMO_GSUP_MSGT_DELETE_DATA_RESULT;
	}

	return gprs_subscr_tx_gsup_message(subscr, &gsup_reply);
}

static int gprs_subscr_handle_gsup_isd_req(struct gprs_subscr *subscr,
					   struct osmo_gsup_message *gsup_msg)
{
	struct osmo_gsup_message gsup_reply = {0};

	gprs_subscr_gsup_insert_data(subscr, gsup_msg);

	subscr->authorized = 1;
	subscr->sgsn_data->error_cause = SGSN_ERROR_CAUSE_NONE;
	subscr->flags |= GPRS_SUBSCRIBER_ENABLE_PURGE;
	gprs_subscr_update(subscr);

	gsup_reply.message_type = OSMO_GSUP_MSGT_INSERT_DATA_RESULT;
	return gprs_subscr_tx_gsup_message(subscr, &gsup_reply);
}

static int check_cause(int cause)
{
	switch (cause) {
	case GMM_CAUSE_IMSI_UNKNOWN ... GMM_CAUSE_ILLEGAL_ME:
	case GMM_CAUSE_GPRS_NOTALLOWED ... GMM_CAUSE_NO_GPRS_PLMN:
		return EACCES;

	case GMM_CAUSE_MSC_TEMP_NOTREACH ... GMM_CAUSE_CONGESTION:
		return EHOSTUNREACH;

	case GMM_CAUSE_SEM_INCORR_MSG ... GMM_CAUSE_PROTO_ERR_UNSPEC:
	default:
		return EINVAL;
	}
}

static int gprs_subscr_handle_gsup_auth_err(struct gprs_subscr *subscr,
					    struct osmo_gsup_message *gsup_msg)
{
	unsigned idx;
	struct sgsn_subscriber_data *sdata = subscr->sgsn_data;
	int cause_err;

	cause_err = check_cause(gsup_msg->cause);

	LOGGSUBSCRP(LOGL_DEBUG, subscr,
		"Send authentication info has failed with cause %d, "
		"handled as: %s\n",
		gsup_msg->cause, strerror(cause_err));

	switch (cause_err) {
	case EACCES:
		LOGGSUBSCRP(LOGL_NOTICE, subscr,
			"GPRS send auth info req failed, access denied, "
			"GMM cause = '%s' (%d)\n",
			get_value_string(gsm48_gmm_cause_names, gsup_msg->cause),
			gsup_msg->cause);
		/* Clear auth tuples */
		memset(sdata->auth_triplets, 0, sizeof(sdata->auth_triplets));
		for (idx = 0; idx < ARRAY_SIZE(sdata->auth_triplets); idx++)
			sdata->auth_triplets[idx].key_seq = GSM_KEY_SEQ_INVAL;

		subscr->authorized = 0;
		sdata->error_cause = gsup_msg->cause;
		gprs_subscr_update_auth_info(subscr);
		break;

	case EHOSTUNREACH:
		LOGGSUBSCRP(LOGL_NOTICE, subscr,
			"GPRS send auth info req failed, GMM cause = '%s' (%d)\n",
			get_value_string(gsm48_gmm_cause_names, gsup_msg->cause),
			gsup_msg->cause);

		sdata->error_cause = gsup_msg->cause;
		gprs_subscr_update_auth_info(subscr);
		break;

	default:
	case EINVAL:
		LOGGSUBSCRP(LOGL_ERROR, subscr,
			"GSUP protocol remote error, GMM cause = '%s' (%d)\n",
			get_value_string(gsm48_gmm_cause_names, gsup_msg->cause),
			gsup_msg->cause);
		break;
	}

	return -gsup_msg->cause;
}

static int gprs_subscr_handle_gsup_upd_loc_err(struct gprs_subscr *subscr,
					       struct osmo_gsup_message *gsup_msg)
{
	int cause_err;

	cause_err = check_cause(gsup_msg->cause);

	LOGGSUBSCRP(LOGL_DEBUG, subscr,
		"Update location has failed with cause %d, handled as: %s\n",
		gsup_msg->cause, strerror(cause_err));

	switch (cause_err) {
	case EACCES:
		LOGGSUBSCRP(LOGL_NOTICE, subscr,
			"GPRS update location failed, access denied, "
			"GMM cause = '%s' (%d)\n",
			get_value_string(gsm48_gmm_cause_names, gsup_msg->cause),
			gsup_msg->cause);

		subscr->authorized = 0;
		subscr->sgsn_data->error_cause = gsup_msg->cause;
		gprs_subscr_update_auth_info(subscr);
		break;

	case EHOSTUNREACH:
		LOGGSUBSCRP(LOGL_NOTICE, subscr,
			"GPRS update location failed, GMM cause = '%s' (%d)\n",
			get_value_string(gsm48_gmm_cause_names, gsup_msg->cause),
			gsup_msg->cause);

		subscr->sgsn_data->error_cause = gsup_msg->cause;
		gprs_subscr_update_auth_info(subscr);
		break;

	default:
	case EINVAL:
		LOGGSUBSCRP(LOGL_ERROR, subscr,
			"GSUP protocol remote error, GMM cause = '%s' (%d)\n",
			get_value_string(gsm48_gmm_cause_names, gsup_msg->cause),
			gsup_msg->cause);
		break;
	}

	return -gsup_msg->cause;
}

static int gprs_subscr_handle_gsup_purge_no_subscr(
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

static int gprs_subscr_handle_gsup_purge_res(struct gprs_subscr *subscr,
					     struct osmo_gsup_message *gsup_msg)
{
	LOGGSUBSCRP(LOGL_INFO, subscr, "Completing purge MS\n");

	/* Force silent cancellation */
	subscr->sgsn_data->error_cause = SGSN_ERROR_CAUSE_NONE;
	gprs_subscr_cancel(subscr);

	return 0;
}

static int gprs_subscr_handle_gsup_purge_err(struct gprs_subscr *subscr,
					     struct osmo_gsup_message *gsup_msg)
{
	LOGGSUBSCRP(LOGL_NOTICE, subscr,
		    "Purge MS has failed with cause '%s' (%d)\n",
		    get_value_string(gsm48_gmm_cause_names, gsup_msg->cause),
		    gsup_msg->cause);

	/* In GSM 09.02, 19.1.4.4, the text and the SDL diagram imply that
	 * the subscriber data is not removed if the request has failed. On the
	 * other hand, keeping the subscriber data in either error case
	 * (subscriber unknown, syntactical message error, connection error)
	 * doesn't seem to give any advantage, since the data will be restored
	 * on the next Attach Request anyway.
	 * This approach ensures, that the subscriber record will not stick if
	 * an error happens.
	 */

	/* TODO: Check whether this behaviour is acceptable and either just
	 * remove this TODO-notice or change the implementation to not delete
	 * the subscriber data (eventually resetting the ENABLE_PURGE flag and
	 * restarting the expiry timer based on the cause).
	 *
	 * Subscriber Unknown: cancel subscr
	 * Temporary network problems: do nothing (handled by timer based retry)
	 * Message problems (syntax, nyi, ...): cancel subscr (retry won't help)
	 */

	gprs_subscr_handle_gsup_purge_res(subscr, gsup_msg);

	return -gsup_msg->cause;
}

static int gprs_subscr_handle_loc_cancel_req(struct gprs_subscr *subscr,
					     struct osmo_gsup_message *gsup_msg)
{
	struct osmo_gsup_message gsup_reply = {0};
	int is_update_procedure = !gsup_msg->cancel_type ||
		gsup_msg->cancel_type == OSMO_GSUP_CANCEL_TYPE_UPDATE;

	LOGGSUBSCRP(LOGL_INFO, subscr, "Cancelling MS subscriber (%s)\n",
		    is_update_procedure ?
		    "update procedure" : "subscription withdraw");

	gsup_reply.message_type = OSMO_GSUP_MSGT_LOCATION_CANCEL_RESULT;
	gprs_subscr_tx_gsup_message(subscr, &gsup_reply);

	if (is_update_procedure)
		subscr->sgsn_data->error_cause = SGSN_ERROR_CAUSE_NONE;
	else
		/* Since a withdraw cause is not specified, just abort the
		 * current attachment. The following re-attachment should then
		 * be rejected with a proper cause value.
		 */
		subscr->sgsn_data->error_cause = GMM_CAUSE_IMPL_DETACHED;

	gprs_subscr_cancel(subscr);

	return 0;
}

static int gprs_subscr_handle_unknown_imsi(struct osmo_gsup_message *gsup_msg)
{
	if (OSMO_GSUP_IS_MSGT_REQUEST(gsup_msg->message_type)) {
		gprs_subscr_tx_gsup_error_reply(NULL, gsup_msg,
						GMM_CAUSE_IMSI_UNKNOWN);
		LOGP(DGPRS, LOGL_NOTICE,
		     "Unknown IMSI %s, discarding GSUP request "
		     "of type 0x%02x\n",
		     gsup_msg->imsi, gsup_msg->message_type);
	} else if (OSMO_GSUP_IS_MSGT_ERROR(gsup_msg->message_type)) {
		LOGP(DGPRS, LOGL_NOTICE,
		     "Unknown IMSI %s, discarding GSUP error "
		     "of type 0x%02x, cause '%s' (%d)\n",
		     gsup_msg->imsi, gsup_msg->message_type,
		     get_value_string(gsm48_gmm_cause_names, gsup_msg->cause),
		     gsup_msg->cause);
	} else {
		LOGP(DGPRS, LOGL_NOTICE,
		     "Unknown IMSI %s, discarding GSUP response "
		     "of type 0x%02x\n",
		     gsup_msg->imsi, gsup_msg->message_type);
	}

	return -GMM_CAUSE_IMSI_UNKNOWN;
}

int gprs_subscr_rx_gsup_message(struct msgb *msg)
{
	uint8_t *data = msgb_l2(msg);
	size_t data_len = msgb_l2len(msg);
	int rc = 0;

	struct osmo_gsup_message gsup_msg = {0};
	struct gprs_subscr *subscr;

	rc = osmo_gsup_decode(data, data_len, &gsup_msg);
	if (rc < 0) {
		LOGP(DGPRS, LOGL_ERROR,
		     "decoding GSUP message fails with error '%s' (%d)\n",
		     get_value_string(gsm48_gmm_cause_names, -rc), -rc);
		return rc;
	}

	if (!gsup_msg.imsi[0]) {
		LOGP(DGPRS, LOGL_ERROR, "Missing IMSI in GSUP message\n");

		if (OSMO_GSUP_IS_MSGT_REQUEST(gsup_msg.message_type))
			gprs_subscr_tx_gsup_error_reply(NULL, &gsup_msg,
							GMM_CAUSE_INV_MAND_INFO);
		return -GMM_CAUSE_INV_MAND_INFO;
	}

	if (!gsup_msg.cause && OSMO_GSUP_IS_MSGT_ERROR(gsup_msg.message_type))
		gsup_msg.cause = GMM_CAUSE_NET_FAIL;

	subscr = gprs_subscr_get_by_imsi(gsup_msg.imsi);

	if (!subscr) {
		switch (gsup_msg.message_type) {
		case OSMO_GSUP_MSGT_PURGE_MS_RESULT:
		case OSMO_GSUP_MSGT_PURGE_MS_ERROR:
			return gprs_subscr_handle_gsup_purge_no_subscr(&gsup_msg);
		default:
			return gprs_subscr_handle_unknown_imsi(&gsup_msg);
		}
	}

	LOGGSUBSCRP(LOGL_INFO, subscr,
		    "Received GSUP message %s\n",
		    osmo_gsup_message_type_name(gsup_msg.message_type));

	switch (gsup_msg.message_type) {
	case OSMO_GSUP_MSGT_LOCATION_CANCEL_REQUEST:
		rc = gprs_subscr_handle_loc_cancel_req(subscr, &gsup_msg);
		break;

	case OSMO_GSUP_MSGT_SEND_AUTH_INFO_RESULT:
		rc = gprs_subscr_handle_gsup_auth_res(subscr, &gsup_msg);
		break;

	case OSMO_GSUP_MSGT_SEND_AUTH_INFO_ERROR:
		rc = gprs_subscr_handle_gsup_auth_err(subscr, &gsup_msg);
		break;

	case OSMO_GSUP_MSGT_UPDATE_LOCATION_RESULT:
		rc = gprs_subscr_handle_gsup_upd_loc_res(subscr, &gsup_msg);
		break;

	case OSMO_GSUP_MSGT_UPDATE_LOCATION_ERROR:
		rc = gprs_subscr_handle_gsup_upd_loc_err(subscr, &gsup_msg);
		break;

	case OSMO_GSUP_MSGT_PURGE_MS_ERROR:
		rc = gprs_subscr_handle_gsup_purge_err(subscr, &gsup_msg);
		break;

	case OSMO_GSUP_MSGT_PURGE_MS_RESULT:
		rc = gprs_subscr_handle_gsup_purge_res(subscr, &gsup_msg);
		break;

	case OSMO_GSUP_MSGT_INSERT_DATA_REQUEST:
		rc = gprs_subscr_handle_gsup_isd_req(subscr, &gsup_msg);
		break;

	case OSMO_GSUP_MSGT_DELETE_DATA_REQUEST:
		rc = gprs_subscr_handle_gsup_dsd_req(subscr, &gsup_msg);
		break;

	default:
		LOGGSUBSCRP(LOGL_ERROR, subscr,
			    "Rx GSUP message %s not valid at SGSN\n",
			    osmo_gsup_message_type_name(gsup_msg.message_type));
		if (OSMO_GSUP_IS_MSGT_REQUEST(gsup_msg.message_type))
			gprs_subscr_tx_gsup_error_reply(
				subscr, &gsup_msg, GMM_CAUSE_MSGT_NOTEXIST_NOTIMPL);
		rc = -GMM_CAUSE_MSGT_NOTEXIST_NOTIMPL;
		break;
	};

	gprs_subscr_put(subscr);

	return rc;
}

int gprs_subscr_purge(struct gprs_subscr *subscr)
{
	struct sgsn_subscriber_data *sdata = subscr->sgsn_data;
	struct osmo_gsup_message gsup_msg = {0};

	LOGGSUBSCRP(LOGL_INFO, subscr, "purging MS subscriber\n");

	gsup_msg.message_type = OSMO_GSUP_MSGT_PURGE_MS_REQUEST;

	/* Provide the HLR number in case it is known */
	gsup_msg.hlr_enc_len = sdata->hlr_len;
	gsup_msg.hlr_enc = sdata->hlr;

	return gprs_subscr_tx_gsup_message(subscr, &gsup_msg);
}

static int gprs_subscr_query_auth_info(struct gprs_subscr *subscr,
				       const uint8_t *auts,
				       const uint8_t *auts_rand)
{
	struct osmo_gsup_message gsup_msg = {0};

	/* Make sure we have a complete resync or clearly no resync. */
	OSMO_ASSERT((auts != NULL) == (auts_rand != NULL));

	LOGGSUBSCRP(LOGL_INFO, subscr, "requesting auth info%s\n",
		    auts ? " with AUTS (UMTS Resynch)" : "");

	gsup_msg.message_type = OSMO_GSUP_MSGT_SEND_AUTH_INFO_REQUEST;
	gsup_msg.auts = auts;
	gsup_msg.rand = auts_rand;
	return gprs_subscr_tx_gsup_message(subscr, &gsup_msg);
}

int gprs_subscr_location_update(struct gprs_subscr *subscr)
{
	struct osmo_gsup_message gsup_msg = {0};

	LOGGSUBSCRP(LOGL_INFO, subscr,
		"subscriber data is not available\n");

	gsup_msg.message_type = OSMO_GSUP_MSGT_UPDATE_LOCATION_REQUEST;
	return gprs_subscr_tx_gsup_message(subscr, &gsup_msg);
}

void gprs_subscr_update(struct gprs_subscr *subscr)
{
	LOGGSUBSCRP(LOGL_DEBUG, subscr, "Updating subscriber data\n");

	subscr->flags &= ~GPRS_SUBSCRIBER_UPDATE_LOCATION_PENDING;
	subscr->flags &= ~GPRS_SUBSCRIBER_FIRST_CONTACT;

	if (subscr->sgsn_data->mm)
		sgsn_update_subscriber_data(subscr->sgsn_data->mm);
}

void gprs_subscr_update_auth_info(struct gprs_subscr *subscr)
{
	LOGGSUBSCRP(LOGL_DEBUG, subscr,
		"Updating subscriber authentication info\n");

	subscr->flags &= ~GPRS_SUBSCRIBER_UPDATE_AUTH_INFO_PENDING;
	subscr->flags &= ~GPRS_SUBSCRIBER_FIRST_CONTACT;

	if (subscr->sgsn_data->mm)
		sgsn_update_subscriber_data(subscr->sgsn_data->mm);
}

struct gprs_subscr *gprs_subscr_get_or_create_by_mmctx(struct sgsn_mm_ctx *mmctx)
{
	struct gprs_subscr *subscr = NULL;

	if (mmctx->subscr)
		return gprs_subscr_get(mmctx->subscr);

	if (mmctx->imsi[0])
		subscr = gprs_subscr_get_by_imsi(mmctx->imsi);

	if (!subscr) {
		subscr = gprs_subscr_get_or_create(mmctx->imsi);
		subscr->flags |= GPRS_SUBSCRIBER_FIRST_CONTACT;
		subscr->flags &= ~GPRS_SUBSCRIBER_ENABLE_PURGE;
	}

	osmo_strlcpy(subscr->imei, mmctx->imei, sizeof(subscr->imei));

	if (subscr->lac != mmctx->ra.lac)
		subscr->lac = mmctx->ra.lac;

	subscr->sgsn_data->mm = mmctx;
	mmctx->subscr = gprs_subscr_get(subscr);

	return subscr;
}

int gprs_subscr_request_update_location(struct sgsn_mm_ctx *mmctx)
{
	struct gprs_subscr *subscr = NULL;
	int rc;

	LOGMMCTXP(LOGL_DEBUG, mmctx, "Requesting subscriber data update\n");

	subscr = gprs_subscr_get_or_create_by_mmctx(mmctx);

	subscr->flags |= GPRS_SUBSCRIBER_UPDATE_LOCATION_PENDING;

	rc = gprs_subscr_location_update(subscr);
	gprs_subscr_put(subscr);
	return rc;
}

/*! \brief Send Update Auth Info request via GSUP, with or without resync.
 *  \param[in] mmctx  MM context to request authentication tuples for.
 *  \param[in] auts  14 octet AUTS token for UMTS resync, or NULL.
 *  \param[in] auts_rand  16 octet Random token for UMTS resync, or NULL.
 * In case of normal Authentication Info request, both \a auts and \a auts_rand
 * must be NULL. For resync, both must be non-NULL.
 */
int gprs_subscr_request_auth_info(struct sgsn_mm_ctx *mmctx,
				  const uint8_t *auts,
				  const uint8_t *auts_rand)
{
	struct gprs_subscr *subscr = NULL;
	int rc;

	LOGMMCTXP(LOGL_DEBUG, mmctx, "Requesting subscriber authentication info\n");

	subscr = gprs_subscr_get_or_create_by_mmctx(mmctx);

	subscr->flags |= GPRS_SUBSCRIBER_UPDATE_AUTH_INFO_PENDING;

	rc = gprs_subscr_query_auth_info(subscr, auts, auts_rand);
	gprs_subscr_put(subscr);
	return rc;
}

static void gprs_subscr_free(struct gprs_subscr *gsub)
{
	llist_del(&gsub->entry);
	talloc_free(gsub);
}

struct gprs_subscr *_gprs_subscr_get(struct gprs_subscr *gsub,
				     const char *file, int line)
{
	OSMO_ASSERT(gsub->use_count < INT_MAX);
	gsub->use_count++;
	LOGPSRC(DREF, LOGL_DEBUG, file, line,
		"subscr %s usage increases to: %d\n",
		gsub->imsi, gsub->use_count);
	return gsub;
}

struct gprs_subscr *_gprs_subscr_put(struct gprs_subscr *gsub,
				     const char *file, int line)
{
	gsub->use_count--;
	LOGPSRC(DREF, gsub->use_count >= 0? LOGL_DEBUG : LOGL_ERROR,
		file, line,
		"subscr %s usage decreases to: %d%s\n",
		gsub->imsi, gsub->use_count,
		gsub->keep_in_ram? ", keep-in-ram flag is set" : "");
	if (gsub->use_count > 0)
		return gsub;
	if (gsub->keep_in_ram)
		return gsub;
	gprs_subscr_free(gsub);
	return NULL;
}
