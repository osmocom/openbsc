/* GSM subscriber details for use in BSC land */

/*
 * (C) 2016 by sysmocom s.f.m.c. GmbH <info@sysmocom.de>
 *
 * Author: Neels Hofmeyr <nhofmeyr@sysmocom.de>
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

#include <talloc.h>
#include <string.h>
#include <limits.h>

#include <osmocom/gsm/gsm48.h>
#include <osmocom/core/logging.h>

#include <openbsc/bsc_subscriber.h>
#include <openbsc/debug.h>

static struct bsc_subscr *bsc_subscr_alloc(struct llist_head *list)
{
	struct bsc_subscr *bsub;

	bsub = talloc_zero(list, struct bsc_subscr);
	if (!bsub)
		return NULL;

	llist_add_tail(&bsub->entry, list);
	bsub->use_count = 1;

	return bsub;
}

struct bsc_subscr *bsc_subscr_find_by_imsi(struct llist_head *list,
					   const char *imsi)
{
	struct bsc_subscr *bsub;

	if (!imsi || !*imsi)
		return NULL;

	llist_for_each_entry(bsub, list, entry) {
		if (!strcmp(bsub->imsi, imsi))
			return bsc_subscr_get(bsub);
	}
	return NULL;
}

struct bsc_subscr *bsc_subscr_find_by_tmsi(struct llist_head *list,
					   uint32_t tmsi)
{
	struct bsc_subscr *bsub;

	if (tmsi == GSM_RESERVED_TMSI)
		return NULL;

	llist_for_each_entry(bsub, list, entry) {
		if (bsub->tmsi == tmsi)
			return bsc_subscr_get(bsub);
	}
	return NULL;
}

void bsc_subscr_set_imsi(struct bsc_subscr *bsub, const char *imsi)
{
	if (!bsub)
		return;
	osmo_strlcpy(bsub->imsi, imsi, sizeof(bsub->imsi));
}

struct bsc_subscr *bsc_subscr_find_or_create_by_imsi(struct llist_head *list,
						     const char *imsi)
{
	struct bsc_subscr *bsub;
	bsub = bsc_subscr_find_by_imsi(list, imsi);
	if (bsub)
		return bsub;
	bsub = bsc_subscr_alloc(list);
	bsc_subscr_set_imsi(bsub, imsi);
	return bsub;
}

struct bsc_subscr *bsc_subscr_find_or_create_by_tmsi(struct llist_head *list,
						     uint32_t tmsi)
{
	struct bsc_subscr *bsub;
	bsub = bsc_subscr_find_by_tmsi(list, tmsi);
	if (bsub)
		return bsub;
	bsub = bsc_subscr_alloc(list);
	bsub->tmsi = tmsi;
	return bsub;
}

const char *bsc_subscr_name(struct bsc_subscr *bsub)
{
	static char buf[32];
	if (!bsub)
		return "unknown";
	if (bsub->imsi[0])
		snprintf(buf, sizeof(buf), "IMSI:%s", bsub->imsi);
	else
		snprintf(buf, sizeof(buf), "TMSI:0x%08x", bsub->tmsi);
	return buf;
}

static void bsc_subscr_free(struct bsc_subscr *bsub)
{
	llist_del(&bsub->entry);
	talloc_free(bsub);
}

struct bsc_subscr *_bsc_subscr_get(struct bsc_subscr *bsub,
				   const char *file, int line)
{
	OSMO_ASSERT(bsub->use_count < INT_MAX);
	bsub->use_count++;
	LOGPSRC(DREF, LOGL_DEBUG, file, line,
		"BSC subscr %s usage increases to: %d\n",
		bsc_subscr_name(bsub), bsub->use_count);
	return bsub;
}

struct bsc_subscr *_bsc_subscr_put(struct bsc_subscr *bsub,
				   const char *file, int line)
{
	bsub->use_count--;
	LOGPSRC(DREF, bsub->use_count >= 0? LOGL_DEBUG : LOGL_ERROR,
		file, line,
		"BSC subscr %s usage decreases to: %d\n",
		bsc_subscr_name(bsub), bsub->use_count);
	if (bsub->use_count <= 0)
		bsc_subscr_free(bsub);
	return NULL;
}

void log_set_filter_bsc_subscr(struct log_target *target,
			       struct bsc_subscr *bsc_subscr)
{
	struct bsc_subscr **fsub = (void*)&target->filter_data[LOG_FLT_BSC_SUBSCR];

	/* free the old data */
	if (*fsub) {
		bsc_subscr_put(*fsub);
		*fsub = NULL;
	}

	if (bsc_subscr) {
		target->filter_map |= (1 << LOG_FLT_BSC_SUBSCR);
		*fsub = bsc_subscr_get(bsc_subscr);
	} else
		target->filter_map &= ~(1 << LOG_FLT_BSC_SUBSCR);
}
