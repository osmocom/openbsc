/* MS subscriber data handling */

/* (C) 2014 by sysmocom s.f.m.c. GmbH
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

#include <openbsc/gsm_subscriber.h>
#include <openbsc/gprs_gsup_client.h>

#include <openbsc/sgsn.h>
#include <openbsc/gprs_sgsn.h>
#include <openbsc/gprs_gmm.h>
#include <openbsc/gprs_gsup_messages.h>

#include <openbsc/debug.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#define SGSN_SUBSCR_MAX_RETRIES 3
#define SGSN_SUBSCR_RETRY_INTERVAL 10

extern void *tall_bsc_ctx;

static int gsup_read_cb(struct gprs_gsup_client *gsupc, struct msgb *msg);

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

	sgi->gsup_client = gprs_gsup_client_create(
		addr_str, sgi->cfg.gsup_server_port,
		&gsup_read_cb);

	if (!sgi->gsup_client)
		return -1;

	return 1;
}

static int gsup_read_cb(struct gprs_gsup_client *gsupc, struct msgb *msg)
{
	int rc;

	rc = gprs_subscr_rx_gsup_message(msg);
	msgb_free(msg);
	if (rc < 0)
		return -1;

	return rc;
}

static int check_blocking(
	struct gsm_subscriber *subscr,
	enum sgsn_subscriber_proc what)
{
	if (subscr->sgsn_data->blocked_by == SGSN_SUBSCR_PROC_NONE ||
	    subscr->sgsn_data->blocked_by == what)
		return 1;

	return 0;
}

static void abort_blocking_procedure(struct gsm_subscriber *subscr)
{
	/* reset something */
}

int gprs_subscr_purge(struct gsm_subscriber *subscr);

static void sgsn_subscriber_do_delete(struct gsm_subscriber *subscr)
{
	LOGGSUBSCRP(LOGL_INFO, subscr,
		    "Deleting subscriber entry\n");


	/*
	 * Send a 'purge MS' message to the HLR. They might just
	 * ignore it anyway.
	 */
	subscr_get(subscr);
	gprs_subscr_purge(subscr);
	subscr_put(subscr);
	return;
}

static struct sgsn_subscriber_data *sgsn_subscriber_data_alloc(void *ctx)
{
	struct sgsn_subscriber_data *sdata;
	int idx;

	sdata = talloc_zero(ctx, struct sgsn_subscriber_data);

	sdata->error_cause = SGSN_ERROR_CAUSE_NONE;

	for (idx = 0; idx < ARRAY_SIZE(sdata->auth_triplets); idx++)
	     sdata->auth_triplets[idx].key_seq = GSM_KEY_SEQ_INVAL;

	return sdata;
}

struct gsm_subscriber *gprs_subscr_get_or_create(const char *imsi)
{
	struct gsm_subscriber *subscr;

	subscr = subscr_get_or_create(NULL, imsi);
	if (!subscr)
		return NULL;

	if (!subscr->sgsn_data)
		subscr->sgsn_data = sgsn_subscriber_data_alloc(subscr);
	return subscr;
}

struct gsm_subscriber *gprs_subscr_get_by_imsi(const char *imsi)
{
	return subscr_active_by_imsi(NULL, imsi);
}

void gprs_subscr_delete(struct gsm_subscriber *subscr)
{
	if (subscr->sgsn_data->mm) {
		subscr_put(subscr->sgsn_data->mm->subscr);
		subscr->sgsn_data->mm->subscr = NULL;
		subscr->sgsn_data->mm = NULL;
	}

	if ((subscr->flags & GPRS_SUBSCRIBER_CANCELLED) ||
	    (subscr->flags & GSM_SUBSCRIBER_FIRST_CONTACT)) {
		subscr->keep_in_ram = 0;
	} else {
		subscr->keep_in_ram = 0;
		sgsn_subscriber_do_delete(subscr);
	}

	subscr_put(subscr);
}

void gprs_subscr_put_and_cancel(struct gsm_subscriber *subscr)
{
	subscr->authorized = 0;
	subscr->flags |= GPRS_SUBSCRIBER_CANCELLED;

	gprs_subscr_update(subscr);
	gprs_subscr_delete(subscr);
}

static int gprs_subscr_tx_gsup_message(struct gsm_subscriber *subscr,
				       struct gprs_gsup_message *gsup_msg)
{
	struct msgb *msg = gprs_gsup_msgb_alloc();

	if (strlen(gsup_msg->imsi) == 0 && subscr)
		strncpy(gsup_msg->imsi, subscr->imsi, sizeof(gsup_msg->imsi) - 1);

	gprs_gsup_encode(msg, gsup_msg);

	LOGGSUBSCRP(LOGL_INFO, subscr,
		    "Sending GSUP, will send: %s\n", msgb_hexdump(msg));

	if (!sgsn->gsup_client) {
		msgb_free(msg);
		return -ENOTSUP;
	}

	return gprs_gsup_client_send(sgsn->gsup_client, msg);
}

static int gprs_subscr_tx_gsup_error_reply(struct gsm_subscriber *subscr,
					   struct gprs_gsup_message *gsup_orig,
					   enum gsm48_gmm_cause cause)
{
	struct gprs_gsup_message gsup_reply = {0};

	strncpy(gsup_reply.imsi, gsup_orig->imsi, sizeof(gsup_reply.imsi) - 1);
	gsup_reply.cause = cause;
	gsup_reply.message_type =
		GPRS_GSUP_TO_MSGT_ERROR(gsup_orig->message_type);

	return gprs_subscr_tx_gsup_message(subscr, &gsup_reply);
}

static int gprs_subscr_handle_gsup_auth_res(struct gsm_subscriber *subscr,
					    struct gprs_gsup_message *gsup_msg)
{
	unsigned idx;
	struct sgsn_subscriber_data *sdata = subscr->sgsn_data;

	LOGGSUBSCRP(LOGL_INFO, subscr,
		"Got SendAuthenticationInfoResult, num_auth_tuples = %d\n",
		gsup_msg->num_auth_tuples);

	if (gsup_msg->num_auth_tuples > 0) {
		memset(sdata->auth_triplets, 0, sizeof(sdata->auth_triplets));

		for (idx = 0; idx < ARRAY_SIZE(sdata->auth_triplets); idx++)
			sdata->auth_triplets[idx].key_seq = GSM_KEY_SEQ_INVAL;
	}

	for (idx = 0; idx < gsup_msg->num_auth_tuples; idx++) {
		size_t key_seq = gsup_msg->auth_tuples[idx].key_seq;
		LOGGSUBSCRP(LOGL_DEBUG, subscr,
			"Adding auth tuple, cksn = %d\n", key_seq);
		if (key_seq >= ARRAY_SIZE(sdata->auth_triplets)) {
			LOGGSUBSCRP(LOGL_NOTICE, subscr,
				"Skipping auth triplet with invalid cksn %d\n",
				key_seq);
			continue;
		}
		sdata->auth_triplets[key_seq] = gsup_msg->auth_tuples[idx];
	}

	sdata->auth_triplets_updated = 1;
	sdata->error_cause = SGSN_ERROR_CAUSE_NONE;

	gprs_subscr_update_auth_info(subscr);

	return 0;
}

static int gprs_subscr_handle_gsup_upd_loc_res(struct gsm_subscriber *subscr,
					       struct gprs_gsup_message *gsup_msg)
{
	unsigned idx;

	if (gsup_msg->pdp_info_compl) {
		LOGP(DGPRS, LOGL_INFO, "Would clear existing PDP info\n");

		/* TODO: clear existing PDP info entries */
	}

	for (idx = 0; idx < gsup_msg->num_pdp_infos; idx++) {
		struct gprs_gsup_pdp_info *pdp_info = &gsup_msg->pdp_infos[idx];
		size_t ctx_id = pdp_info->context_id;

		LOGP(DGPRS, LOGL_INFO,
		     "Would set PDP info, context id = %d, APN = %s\n",
		     ctx_id, osmo_hexdump(pdp_info->apn_enc, pdp_info->apn_enc_len));

		/* TODO: set PDP info [ctx_id] */
	}

	subscr->authorized = 1;
	subscr->sgsn_data->error_cause = SGSN_ERROR_CAUSE_NONE;
	gprs_subscr_update(subscr);
	return 0;
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

static int gprs_subscr_handle_gsup_auth_err(struct gsm_subscriber *subscr,
					    struct gprs_gsup_message *gsup_msg)
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

static int gprs_subscr_handle_gsup_upd_loc_err(struct gsm_subscriber *subscr,
					       struct gprs_gsup_message *gsup_msg)
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

static int gprs_subscr_handle_gsup_purge_res(struct gsm_subscriber *subscr,
					     struct gprs_gsup_message *gsup_msg)
{
	LOGGSUBSCRP(LOGL_INFO, subscr, "Completing purge MS\n");

	/* Force silent cancellation */
	subscr->sgsn_data->error_cause = SGSN_ERROR_CAUSE_NONE;
	gprs_subscr_put_and_cancel(subscr_get(subscr));

	return 0;
}

static int gprs_subscr_handle_gsup_purge_err(struct gsm_subscriber *subscr,
					     struct gprs_gsup_message *gsup_msg)
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

static int gprs_subscr_handle_loc_cancel_req(struct gsm_subscriber *subscr,
					     struct gprs_gsup_message *gsup_msg)
{
	struct gprs_gsup_message gsup_reply = {0};

	LOGGSUBSCRP(LOGL_INFO, subscr, "purging MS subscriber\n");

	gsup_reply.message_type = GPRS_GSUP_MSGT_LOCATION_CANCEL_RESULT;
	gprs_subscr_tx_gsup_message(subscr, &gsup_reply);

	subscr->sgsn_data->error_cause = SGSN_ERROR_CAUSE_NONE;
	gprs_subscr_put_and_cancel(subscr_get(subscr));

	return 0;
}

static int gprs_subscr_handle_unknown_imsi(struct gprs_gsup_message *gsup_msg)
{
	if (GPRS_GSUP_IS_MSGT_REQUEST(gsup_msg->message_type)) {
		gprs_subscr_tx_gsup_error_reply(NULL, gsup_msg,
						GMM_CAUSE_IMSI_UNKNOWN);
		LOGP(DGPRS, LOGL_NOTICE,
		     "Unknown IMSI %s, discarding GSUP request "
		     "of type 0x%02x\n",
		     gsup_msg->imsi, gsup_msg->message_type);
	} else if (GPRS_GSUP_IS_MSGT_ERROR(gsup_msg->message_type)) {
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

	struct gprs_gsup_message gsup_msg = {0};
	struct gsm_subscriber *subscr;

	rc = gprs_gsup_decode(data, data_len, &gsup_msg);
	if (rc < 0) {
		LOGP(DGPRS, LOGL_ERROR,
		     "decoding GSUP message fails with error '%s' (%d)\n",
		     get_value_string(gsm48_gmm_cause_names, -rc), -rc);
		return rc;
	}

	if (!gsup_msg.imsi[0])
		return -GMM_CAUSE_INV_MAND_INFO;

	subscr = gprs_subscr_get_by_imsi(gsup_msg.imsi);

	if (!subscr)
		return gprs_subscr_handle_unknown_imsi(&gsup_msg);

	LOGGSUBSCRP(LOGL_INFO, subscr,
		"Received GSUP message of type 0x%02x\n", gsup_msg.message_type);

	switch (gsup_msg.message_type) {
	case GPRS_GSUP_MSGT_LOCATION_CANCEL_REQUEST:
		rc = gprs_subscr_handle_loc_cancel_req(subscr, &gsup_msg);
		break;

	case GPRS_GSUP_MSGT_SEND_AUTH_INFO_RESULT:
		rc = gprs_subscr_handle_gsup_auth_res(subscr, &gsup_msg);
		break;

	case GPRS_GSUP_MSGT_SEND_AUTH_INFO_ERROR:
		rc = gprs_subscr_handle_gsup_auth_err(subscr, &gsup_msg);
		break;

	case GPRS_GSUP_MSGT_UPDATE_LOCATION_RESULT:
		rc = gprs_subscr_handle_gsup_upd_loc_res(subscr, &gsup_msg);
		break;

	case GPRS_GSUP_MSGT_UPDATE_LOCATION_ERROR:
		rc = gprs_subscr_handle_gsup_upd_loc_err(subscr, &gsup_msg);
		break;

	case GPRS_GSUP_MSGT_PURGE_MS_ERROR:
		rc = gprs_subscr_handle_gsup_purge_err(subscr, &gsup_msg);
		break;

	case GPRS_GSUP_MSGT_PURGE_MS_RESULT:
		rc = gprs_subscr_handle_gsup_purge_res(subscr, &gsup_msg);
		break;

	case GPRS_GSUP_MSGT_INSERT_DATA_REQUEST:
	case GPRS_GSUP_MSGT_DELETE_DATA_REQUEST:
		LOGGSUBSCRP(LOGL_ERROR, subscr,
			"Rx GSUP message type %d not yet implemented\n",
			gsup_msg.message_type);
		gprs_subscr_tx_gsup_error_reply(subscr, &gsup_msg,
						GMM_CAUSE_MSGT_NOTEXIST_NOTIMPL);
		rc = -GMM_CAUSE_MSGT_NOTEXIST_NOTIMPL;
		break;

	default:
		LOGGSUBSCRP(LOGL_ERROR, subscr,
			"Rx GSUP message type %d not valid at SGSN\n",
			gsup_msg.message_type);
		if (GPRS_GSUP_IS_MSGT_REQUEST(gsup_msg.message_type))
			gprs_subscr_tx_gsup_error_reply(
				subscr, &gsup_msg, GMM_CAUSE_MSGT_NOTEXIST_NOTIMPL);
		rc = -GMM_CAUSE_MSGT_NOTEXIST_NOTIMPL;
		break;
	};

	subscr_put(subscr);

	return rc;
}

int gprs_subscr_purge(struct gsm_subscriber *subscr)
{
	struct gprs_gsup_message gsup_msg = {0};
	int rc;

	if (!check_blocking(subscr, SGSN_SUBSCR_PROC_PURGE)) {
		LOGGSUBSCRP(
			LOGL_NOTICE, subscr,
			"Cannot purge MS subscriber, blocked\n");
		return -EAGAIN;
	}

	/* GSM 09.02, 19.4.1.4 requires other MAP requests to be blocked until
	 * this procedure is completed
	 */
	subscr->sgsn_data->blocked_by = SGSN_SUBSCR_PROC_PURGE;

	LOGGSUBSCRP(LOGL_INFO, subscr, "purging MS subscriber\n");

	gsup_msg.message_type = GPRS_GSUP_MSGT_PURGE_MS_REQUEST;
	rc = gprs_subscr_tx_gsup_message(subscr, &gsup_msg);
	if (rc < 0)
		subscr->sgsn_data->blocked_by = SGSN_SUBSCR_PROC_NONE;

	return rc;
}

int gprs_subscr_query_auth_info(struct gsm_subscriber *subscr)
{
	struct gprs_gsup_message gsup_msg = {0};

	if (!check_blocking(subscr, SGSN_SUBSCR_PROC_UPD_AUTH)) {
		LOGGSUBSCRP(
			LOGL_NOTICE, subscr,
			"Cannot start update auth info request procedure, blocked\n");
		abort_blocking_procedure(subscr);
		return -EAGAIN;
	}

	LOGGSUBSCRP(LOGL_INFO, subscr,
		"subscriber auth info is not available\n");

	gsup_msg.message_type = GPRS_GSUP_MSGT_SEND_AUTH_INFO_REQUEST;
	return gprs_subscr_tx_gsup_message(subscr, &gsup_msg);
}

int gprs_subscr_location_update(struct gsm_subscriber *subscr)
{
	struct gprs_gsup_message gsup_msg = {0};

	if (!check_blocking(subscr, SGSN_SUBSCR_PROC_UPD_LOC)) {
		LOGGSUBSCRP(
			LOGL_NOTICE, subscr,
			"Cannot start update location procedure, blocked\n");
		abort_blocking_procedure(subscr);
		return -EAGAIN;
	}

	LOGGSUBSCRP(LOGL_INFO, subscr,
		"subscriber data is not available\n");

	gsup_msg.message_type = GPRS_GSUP_MSGT_UPDATE_LOCATION_REQUEST;
	return gprs_subscr_tx_gsup_message(subscr, &gsup_msg);
}

void gprs_subscr_update(struct gsm_subscriber *subscr)
{
	LOGGSUBSCRP(LOGL_DEBUG, subscr, "Updating subscriber data\n");

	subscr->flags &= ~GPRS_SUBSCRIBER_UPDATE_LOCATION_PENDING;
	subscr->flags &= ~GSM_SUBSCRIBER_FIRST_CONTACT;

	sgsn_update_subscriber_data(subscr->sgsn_data->mm, subscr);
}

void gprs_subscr_update_auth_info(struct gsm_subscriber *subscr)
{
	LOGGSUBSCRP(LOGL_DEBUG, subscr,
		"Updating subscriber authentication info\n");

	subscr->flags &= ~GPRS_SUBSCRIBER_UPDATE_AUTH_INFO_PENDING;
	subscr->flags &= ~GSM_SUBSCRIBER_FIRST_CONTACT;

	sgsn_update_subscriber_data(subscr->sgsn_data->mm, subscr);
}

struct gsm_subscriber *gprs_subscr_get_or_create_by_mmctx(struct sgsn_mm_ctx *mmctx)
{
	struct gsm_subscriber *subscr = NULL;

	if (mmctx->subscr)
		return subscr_get(mmctx->subscr);

	if (mmctx->imsi[0])
		subscr = gprs_subscr_get_by_imsi(mmctx->imsi);

	if (!subscr) {
		subscr = gprs_subscr_get_or_create(mmctx->imsi);
		subscr->flags |= GSM_SUBSCRIBER_FIRST_CONTACT;
	}

	if (strcpy(subscr->equipment.imei, mmctx->imei) != 0) {
		strncpy(subscr->equipment.imei, mmctx->imei, GSM_IMEI_LENGTH-1);
		subscr->equipment.imei[GSM_IMEI_LENGTH-1] = 0;
	}

	if (subscr->lac != mmctx->ra.lac)
		subscr->lac = mmctx->ra.lac;

	subscr->sgsn_data->mm = mmctx;
	mmctx->subscr = subscr_get(subscr);

	return subscr;
}

int gprs_subscr_request_update_location(struct sgsn_mm_ctx *mmctx)
{
	struct gsm_subscriber *subscr = NULL;
	int rc;

	LOGMMCTXP(LOGL_DEBUG, mmctx, "Requesting subscriber data update\n");

	subscr = gprs_subscr_get_or_create_by_mmctx(mmctx);

	subscr->flags |= GPRS_SUBSCRIBER_UPDATE_LOCATION_PENDING;

	rc = gprs_subscr_location_update(subscr);
	subscr_put(subscr);
	return rc;
}

int gprs_subscr_request_auth_info(struct sgsn_mm_ctx *mmctx)
{
	struct gsm_subscriber *subscr = NULL;
	int rc;

	LOGMMCTXP(LOGL_DEBUG, mmctx, "Requesting subscriber authentication info\n");

	subscr = gprs_subscr_get_or_create_by_mmctx(mmctx);

	subscr->flags |= GPRS_SUBSCRIBER_UPDATE_AUTH_INFO_PENDING;

	rc = gprs_subscr_query_auth_info(subscr);
	subscr_put(subscr);
	return rc;
}
