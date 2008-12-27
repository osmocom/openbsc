/* Dummy implementation of a subscriber database, roghly HLR/VLR functionality */

/* (C) 2008 by Harald Welte <laforge@gnumonks.org>
 *
 * All Rights Reserved
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 */

#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <openbsc/gsm_subscriber.h>
#include <openbsc/db.h>

struct gsm_subscriber *subscr_alloc(void)
{
	struct gsm_subscriber *s;

	s = malloc(sizeof(struct gsm_subscriber));
	if (!s)
		return NULL;

	memset(s, 0, sizeof(*s));

	return s;
}

void subscr_free(struct gsm_subscriber *subscr)
{
	free(subscr);
}

struct gsm_subscriber *subscr_get_by_tmsi(char *tmsi)
{
	struct gsm_subscriber *subscr = subscr_alloc();

	strncpy(subscr->tmsi, tmsi, sizeof(subscr->tmsi));
	subscr->tmsi[sizeof(subscr->tmsi)-1] = '\0';

	if (db_get_subscriber(GSM_SUBSCRIBER_TMSI, subscr) != 0) {
		subscr_free(subscr);
		subscr = NULL;
	}

	return subscr;
}

struct gsm_subscriber *subscr_get_by_imsi(char *imsi)
{
	struct gsm_subscriber *subscr = subscr_alloc();

	strncpy(subscr->imsi, imsi, sizeof(subscr->imsi));
	subscr->imsi[sizeof(subscr->imsi)-1] = '\0';

	if (db_get_subscriber(GSM_SUBSCRIBER_IMSI, subscr) != 0) {
		subscr_free(subscr);
		subscr = NULL;
	}

	return subscr;
}

int subscr_update(struct gsm_subscriber *s, struct gsm_bts *bts)
{
	return db_set_subscriber(s);
}
