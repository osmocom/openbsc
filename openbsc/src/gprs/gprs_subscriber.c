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

#include <openbsc/sgsn.h>
#include <openbsc/gprs_sgsn.h>
#include <openbsc/gprs_gmm.h>

#include <openbsc/debug.h>

extern void *tall_bsc_ctx;

void gprs_subscr_init(struct sgsn_instance *sgi)
{
}

static struct sgsn_subscriber_data *sgsn_subscriber_data_alloc(void *ctx)
{
	struct sgsn_subscriber_data *sdata;
	int idx;

	sdata = talloc_zero(ctx, struct sgsn_subscriber_data);

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

	subscr->keep_in_ram = 1;

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
	    (subscr->flags & GSM_SUBSCRIBER_FIRST_CONTACT))
		subscr->keep_in_ram = 0;

	subscr_put(subscr);
}

void gprs_subscr_put_and_cancel(struct gsm_subscriber *subscr)
{
	subscr->authorized = 0;
	subscr->flags |= GPRS_SUBSCRIBER_CANCELLED;

	gprs_subscr_update(subscr);

	gprs_subscr_delete(subscr);
}

int gprs_subscr_query_auth_info(struct gsm_subscriber *subscr)
{
	/* TODO: Implement remote query to HLR, ... */

	LOGMMCTXP(LOGL_INFO, subscr->sgsn_data->mm,
		  "subscriber auth info is not available (remote query NYI)\n");
	return -ENOTSUP;
}

int gprs_subscr_location_update(struct gsm_subscriber *subscr)
{
	/* TODO: Implement remote query to HLR, ... */

	LOGMMCTXP(LOGL_INFO, subscr->sgsn_data->mm,
		  "subscriber data is not available (remote query NYI)\n");
	return -ENOTSUP;
}

void gprs_subscr_update(struct gsm_subscriber *subscr)
{
	LOGMMCTXP(LOGL_DEBUG, subscr->sgsn_data->mm, "Updating subscriber data\n");

	subscr->flags &= ~GPRS_SUBSCRIBER_UPDATE_LOCATION_PENDING;
	subscr->flags &= ~GSM_SUBSCRIBER_FIRST_CONTACT;

	sgsn_update_subscriber_data(subscr->sgsn_data->mm, subscr);
}

void gprs_subscr_update_auth_info(struct gsm_subscriber *subscr)
{
	LOGMMCTXP(LOGL_DEBUG, subscr->sgsn_data->mm,
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
