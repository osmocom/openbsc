/* MS authorization and subscriber data handling */

/* (C) 2009-2010 by Harald Welte <laforge@gnumonks.org>
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
#include <osmocom/core/utils.h>
#include <openbsc/sgsn.h>
#include <openbsc/gprs_sgsn.h>
#include <openbsc/gprs_gmm.h>
#include <openbsc/gprs_subscriber.h>
#include <openbsc/debug.h>

const struct value_string auth_state_names[] = {
	{ SGSN_AUTH_ACCEPTED,	"accepted"},
	{ SGSN_AUTH_REJECTED,	"rejected"},
	{ SGSN_AUTH_UNKNOWN,	"unknown"},
	{ SGSN_AUTH_AUTHENTICATE, "authenticate" },
	{ SGSN_AUTH_UMTS_RESYNC, "UMTS-resync" },
	{ 0, NULL }
};

const struct value_string *sgsn_auth_state_names = auth_state_names;

void sgsn_auth_init(void)
{
	INIT_LLIST_HEAD(&sgsn->cfg.imsi_acl);
}

/* temporary IMSI ACL hack */
struct imsi_acl_entry *sgsn_acl_lookup(const char *imsi, struct sgsn_config *cfg)
{
	struct imsi_acl_entry *acl;
	llist_for_each_entry(acl, &cfg->imsi_acl, list) {
		if (!strcmp(imsi, acl->imsi))
			return acl;
	}
	return NULL;
}

int sgsn_acl_add(const char *imsi, struct sgsn_config *cfg)
{
	struct imsi_acl_entry *acl;

	if (sgsn_acl_lookup(imsi, cfg))
		return -EEXIST;

	acl = talloc_zero(NULL, struct imsi_acl_entry);
	if (!acl)
		return -ENOMEM;
	osmo_strlcpy(acl->imsi, imsi, sizeof(acl->imsi));

	llist_add(&acl->list, &cfg->imsi_acl);

	return 0;
}

int sgsn_acl_del(const char *imsi, struct sgsn_config *cfg)
{
	struct imsi_acl_entry *acl;

	acl = sgsn_acl_lookup(imsi, cfg);
	if (!acl)
		return -ENODEV;

	llist_del(&acl->list);
	talloc_free(acl);

	return 0;
}

enum sgsn_auth_state sgsn_auth_state(struct sgsn_mm_ctx *mmctx)
{
	char mccmnc[16];
	int check_net = 0;
	int check_acl = 0;

	OSMO_ASSERT(mmctx);

	switch (sgsn->cfg.auth_policy) {
	case SGSN_AUTH_POLICY_OPEN:
		return SGSN_AUTH_ACCEPTED;

	case SGSN_AUTH_POLICY_CLOSED:
		check_net = 1;
		check_acl = 1;
		break;

	case SGSN_AUTH_POLICY_ACL_ONLY:
		check_acl = 1;
		break;

	case SGSN_AUTH_POLICY_REMOTE:
		if (!mmctx->subscr)
			return mmctx->auth_state;

		if (mmctx->subscr->flags & GPRS_SUBSCRIBER_UPDATE_PENDING_MASK)
			return mmctx->auth_state;

		if (sgsn->cfg.require_authentication &&
		    (!mmctx->is_authenticated ||
		     mmctx->subscr->sgsn_data->auth_triplets_updated))
			return SGSN_AUTH_AUTHENTICATE;

		if (mmctx->subscr->authorized)
			return SGSN_AUTH_ACCEPTED;

		return SGSN_AUTH_REJECTED;
	}

	if (!strlen(mmctx->imsi)) {
		LOGMMCTXP(LOGL_NOTICE, mmctx,
			  "Missing IMSI, authorization state not known\n");
		return SGSN_AUTH_UNKNOWN;
	}

	if (check_net) {
		/* We simply assume that the IMSI exists, as long as it is part
		 * of 'our' network */
		snprintf(mccmnc, sizeof(mccmnc), "%03d%02d",
			 mmctx->ra.mcc, mmctx->ra.mnc);
		if (strncmp(mccmnc, mmctx->imsi, 5) == 0)
			return SGSN_AUTH_ACCEPTED;
	}

	if (check_acl && sgsn_acl_lookup(mmctx->imsi, &sgsn->cfg))
		return SGSN_AUTH_ACCEPTED;

	return SGSN_AUTH_REJECTED;
}

/*
 * This function is directly called by e.g. the GMM layer. It returns either
 * after calling sgsn_auth_update directly or after triggering an asynchronous
 * procedure which will call sgsn_auth_update later on.
 */
int sgsn_auth_request(struct sgsn_mm_ctx *mmctx)
{
	struct gprs_subscr *subscr;
	struct gsm_auth_tuple *at;
	int need_update_location;
	int rc;

	LOGMMCTXP(LOGL_DEBUG, mmctx, "Requesting authorization\n");

	if (sgsn->cfg.auth_policy != SGSN_AUTH_POLICY_REMOTE) {
		sgsn_auth_update(mmctx);
		return 0;
	}

	need_update_location = sgsn->cfg.require_update_location &&
		(mmctx->subscr == NULL ||
		 mmctx->pending_req == GSM48_MT_GMM_ATTACH_REQ);

	/* This has the side effect of registering the subscr with the mmctx */
	subscr = gprs_subscr_get_or_create_by_mmctx(mmctx);
	gprs_subscr_put(subscr);

	OSMO_ASSERT(mmctx->subscr != NULL);

	if (sgsn->cfg.require_authentication && !mmctx->is_authenticated) {
		/* Find next tuple */
		at = sgsn_auth_get_tuple(mmctx, mmctx->auth_triplet.key_seq);

		if (!at) {
			/* No valid tuple found, request fresh ones */
			mmctx->auth_triplet.key_seq = GSM_KEY_SEQ_INVAL;
			LOGMMCTXP(LOGL_INFO, mmctx,
				  "Requesting authentication tuples\n");
			rc = gprs_subscr_request_auth_info(mmctx, NULL, NULL);
			if (rc >= 0)
				return 0;

			return rc;
		}

		mmctx->auth_triplet = *at;
	} else if (need_update_location) {
		LOGMMCTXP(LOGL_INFO, mmctx,
			  "Missing information, requesting subscriber data\n");
		rc = gprs_subscr_request_update_location(mmctx);
		if (rc >= 0)
			return 0;

		return rc;
	}

	sgsn_auth_update(mmctx);
	return 0;
}

void sgsn_auth_update(struct sgsn_mm_ctx *mmctx)
{
	enum sgsn_auth_state auth_state;
	struct gprs_subscr *subscr = mmctx->subscr;
	struct gsm_auth_tuple *at;
	int gmm_cause;

	auth_state = sgsn_auth_state(mmctx);

	LOGMMCTXP(LOGL_DEBUG, mmctx, "Updating authorization (%s -> %s)\n",
		  get_value_string(sgsn_auth_state_names, mmctx->auth_state),
		  get_value_string(sgsn_auth_state_names, auth_state));

	if (auth_state == SGSN_AUTH_UNKNOWN && subscr &&
	    !(subscr->flags & GPRS_SUBSCRIBER_UPDATE_PENDING_MASK)) {
		/* Reject requests if gprs_subscr_request_update_location fails */
		LOGMMCTXP(LOGL_ERROR, mmctx,
			  "Missing information, authorization not possible\n");
		auth_state = SGSN_AUTH_REJECTED;
	}

	if (auth_state == SGSN_AUTH_AUTHENTICATE &&
	    mmctx->auth_triplet.key_seq == GSM_KEY_SEQ_INVAL) {
		/* The current tuple is not valid, but we are possibly called
		 * because new auth tuples have been received */
		at = sgsn_auth_get_tuple(mmctx, mmctx->auth_triplet.key_seq);
		if (!at) {
			LOGMMCTXP(LOGL_ERROR, mmctx,
				  "Missing auth tuples, authorization not possible\n");
			auth_state = SGSN_AUTH_REJECTED;
		} else {
			mmctx->auth_triplet = *at;
		}
	}

	if (mmctx->auth_state == auth_state)
		return;

	LOGMMCTXP(LOGL_INFO, mmctx, "Got authorization update: state %s -> %s\n",
		  get_value_string(sgsn_auth_state_names, mmctx->auth_state),
		  get_value_string(sgsn_auth_state_names, auth_state));

	mmctx->auth_state = auth_state;

	switch (auth_state) {
	case SGSN_AUTH_AUTHENTICATE:
		if (subscr)
			subscr->sgsn_data->auth_triplets_updated = 0;

		gsm0408_gprs_authenticate(mmctx);
		break;
	case SGSN_AUTH_ACCEPTED:
		gsm0408_gprs_access_granted(mmctx);
		break;
	case SGSN_AUTH_REJECTED:
		gmm_cause =
			subscr ? subscr->sgsn_data->error_cause :
			SGSN_ERROR_CAUSE_NONE;

		if (subscr && (subscr->flags & GPRS_SUBSCRIBER_CANCELLED) != 0)
			gsm0408_gprs_access_cancelled(mmctx, gmm_cause);
		else
			gsm0408_gprs_access_denied(mmctx, gmm_cause);
		break;
	default:
		break;
	}
}

struct gsm_auth_tuple *sgsn_auth_get_tuple(struct sgsn_mm_ctx *mmctx,
					   unsigned key_seq)
{
	unsigned count;
	unsigned idx;
	struct gsm_auth_tuple *at = NULL;

	struct sgsn_subscriber_data *sdata;

	if (!mmctx->subscr)
		return NULL;

	if (key_seq == GSM_KEY_SEQ_INVAL)
		/* Start with 0 after increment module array size */
		idx = ARRAY_SIZE(sdata->auth_triplets) - 1;
	else
		idx = key_seq;

	sdata = mmctx->subscr->sgsn_data;

	/* Find next tuple */
	for (count = ARRAY_SIZE(sdata->auth_triplets); count > 0; count--) {
		idx = (idx + 1) % ARRAY_SIZE(sdata->auth_triplets);

		if (sdata->auth_triplets[idx].key_seq == GSM_KEY_SEQ_INVAL)
			continue;

		if (sdata->auth_triplets[idx].use_count == 0) {
			at = &sdata->auth_triplets[idx];
			at->use_count = 1;
			return at;
		}
	}

	return NULL;
}
