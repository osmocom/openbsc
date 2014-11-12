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

struct gsm_subscriber *gprs_subscr_get_or_create(const char *imsi)
{
	struct gsm_subscriber *subscr;

	subscr = subscr_get_or_create(NULL, imsi);
	if (!subscr)
		return NULL;

	subscr->keep_in_ram = 1;

	return subscr;
}

struct gsm_subscriber *gprs_subscr_get_by_imsi(const char *imsi)
{
	return subscr_active_by_imsi(NULL, imsi);
}

void gprs_subscr_delete(struct gsm_subscriber *subscr)
{
	if (subscr->mm) {
		subscr_put(subscr->mm->subscr);
		subscr->mm->subscr = NULL;
		subscr->mm = NULL;
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

int gprs_subscr_query(struct gsm_subscriber *subscr)
{
	/* TODO: Implement remote query to MSC, ... */

	LOGMMCTXP(LOGL_INFO, subscr->mm,
		  "subscriber data is not available (remote query NYI)\n");
	return -ENOTSUP;
}

void gprs_subscr_update(struct gsm_subscriber *subscr)
{
	LOGMMCTXP(LOGL_DEBUG, subscr->mm, "Updating subscriber data\n");

	subscr->flags &= ~GPRS_SUBSCRIBER_UPDATE_PENDING;
	subscr->flags &= ~GSM_SUBSCRIBER_FIRST_CONTACT;

	sgsn_update_subscriber_data(subscr->mm, subscr);
}

int gprs_subscr_request_update(struct sgsn_mm_ctx *mmctx)
{
	struct gsm_subscriber *subscr = NULL;
	int need_update = 0;
	int rc;

	LOGMMCTXP(LOGL_DEBUG, mmctx, "Requesting subscriber data update\n");

	if (mmctx->subscr) {
		subscr = subscr_get(mmctx->subscr);
	} else if (mmctx->imsi[0]) {
		subscr = gprs_subscr_get_by_imsi(mmctx->imsi);
		need_update = 1;
	}

	if (!subscr) {
		subscr = gprs_subscr_get_or_create(mmctx->imsi);
		subscr->flags |= GSM_SUBSCRIBER_FIRST_CONTACT;
		need_update = 1;
	}

	if (strcpy(subscr->equipment.imei, mmctx->imei) != 0) {
		strncpy(subscr->equipment.imei, mmctx->imei, GSM_IMEI_LENGTH-1);
		subscr->equipment.imei[GSM_IMEI_LENGTH-1] = 0;
		need_update = 1;
	}

	if (subscr->lac != mmctx->ra.lac) {
		subscr->lac = mmctx->ra.lac;
		need_update = 1;
	}

	if (need_update) {
		subscr->flags |= GPRS_SUBSCRIBER_UPDATE_PENDING;
		if (!mmctx->subscr) {
			subscr->mm = mmctx;
			mmctx->subscr = subscr_get(subscr);
		}

		rc = gprs_subscr_query(subscr);
		subscr_put(subscr);
		return rc;
	}
	gprs_subscr_update(subscr);
	subscr_put(subscr);
	return 0;
}
