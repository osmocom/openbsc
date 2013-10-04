/* (C) 2008 by Jan Luebbe <jluebbe@debian.org>
 * (C) 2009 by Holger Hans Peter Freyther <zecke@selfish.org>
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
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include <openbsc/debug.h>
#include <openbsc/db.h>
#include <openbsc/gsm_subscriber.h>

#include <osmocom/core/application.h>

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

static struct gsm_network dummy_net;

#define SUBSCR_PUT(sub) \
	sub->net = &dummy_net;	\
	subscr_put(sub);

#define COMPARE(original, copy) \
	if (original->id != copy->id) \
		printf("Ids do not match in %s:%d %llu %llu\n", \
			__FUNCTION__, __LINE__, original->id, copy->id); \
	if (original->lac != copy->lac) \
		printf("LAC do not match in %s:%d %d %d\n", \
			__FUNCTION__, __LINE__, original->lac, copy->lac); \
	if (original->authorized != copy->authorized) \
		printf("Authorize do not match in %s:%d %d %d\n", \
			__FUNCTION__, __LINE__, original->authorized, \
			copy->authorized); \
	if (strcmp(original->imsi, copy->imsi) != 0) \
		printf("IMSIs do not match in %s:%d '%s' '%s'\n", \
			__FUNCTION__, __LINE__, original->imsi, copy->imsi); \
	if (original->tmsi != copy->tmsi) \
		printf("TMSIs do not match in %s:%d '%u' '%u'\n", \
			__FUNCTION__, __LINE__, original->tmsi, copy->tmsi); \
	if (strcmp(original->name, copy->name) != 0) \
		printf("names do not match in %s:%d '%s' '%s'\n", \
			__FUNCTION__, __LINE__, original->name, copy->name); \
	if (strcmp(original->extension, copy->extension) != 0) \
		printf("Extensions do not match in %s:%d '%s' '%s'\n", \
			__FUNCTION__, __LINE__, original->extension, copy->extension); \

int main()
{
	printf("Testing subscriber database code.\n");
	osmo_init_logging(&log_info);

	if (db_init("hlr.sqlite3")) {
		printf("DB: Failed to init database. Please check the option settings.\n");
		return 1;
	}	 
	printf("DB: Database initialized.\n");

	if (db_prepare()) {
		printf("DB: Failed to prepare database.\n");
		return 1;
	}
	printf("DB: Database prepared.\n");

	struct gsm_subscriber *alice = NULL;
	struct gsm_subscriber *alice_db;

	char *alice_imsi = "3243245432345";
	alice = db_create_subscriber(alice_imsi);
	db_sync_subscriber(alice);
	alice_db = db_get_subscriber(GSM_SUBSCRIBER_IMSI, alice->imsi);
	COMPARE(alice, alice_db);
	SUBSCR_PUT(alice_db);
	SUBSCR_PUT(alice);

	alice_imsi = "3693245423445";
	alice = db_create_subscriber(alice_imsi);
	db_subscriber_assoc_imei(alice, "1234567890");
	db_subscriber_alloc_tmsi(alice);
	alice->lac=42;
	db_sync_subscriber(alice);
	alice_db = db_get_subscriber(GSM_SUBSCRIBER_IMSI, alice_imsi);
	COMPARE(alice, alice_db);
	SUBSCR_PUT(alice);
	SUBSCR_PUT(alice_db);

	alice_imsi = "9993245423445";
	alice = db_create_subscriber(alice_imsi);
	db_subscriber_alloc_tmsi(alice);
	alice->lac=42;
	db_sync_subscriber(alice);
	db_subscriber_assoc_imei(alice, "1234567890");
	db_subscriber_assoc_imei(alice, "6543560920");
	alice_db = db_get_subscriber(GSM_SUBSCRIBER_IMSI, alice_imsi);
	COMPARE(alice, alice_db);
	SUBSCR_PUT(alice);
	SUBSCR_PUT(alice_db);

	db_fini();

	printf("Done\n");
	return 0;
}

/* stubs */
void vty_out() {}
