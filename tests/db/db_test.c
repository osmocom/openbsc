/* (C) 2008 by Jan Luebbe <jluebbe@debian.org>
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

#include <openbsc/db.h>

#include <stdio.h>
#include <string.h>
#include <malloc.h>

int main() {

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

	alice = db_create_subscriber("3243245432345");
	db_set_subscriber(alice);
	db_get_subscriber(GSM_SUBSCRIBER_IMSI, alice);
	free(alice);

	alice = db_create_subscriber("3693245423445");
	db_subscriber_assoc_imei(alice, "1234567890");
	db_subscriber_alloc_tmsi(alice);
	alice->lac=42;
	db_set_subscriber(alice);
	db_get_subscriber(GSM_SUBSCRIBER_IMSI, alice);
	free(alice);

	alice = db_create_subscriber("9993245423445");
	db_subscriber_alloc_tmsi(alice);
	alice->lac=42;
	db_set_subscriber(alice);
	db_subscriber_assoc_imei(alice, "1234567890");
	db_subscriber_assoc_imei(alice, "6543560920");
	db_get_subscriber(GSM_SUBSCRIBER_IMSI, alice);
	free(alice);

	db_fini();

	return 0;
}
