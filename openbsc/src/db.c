/* Simple HLR/VLR database backend using dbi */
/* (C) 2008 by Jan Luebbe <jluebbe@debian.org>
 * (C) 2009 by Holger Hans Peter Freyther <zecke@selfish.org>
 * (C) 2009 by Harald Welte <laforge@gnumonks.org>
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

#include <openbsc/gsm_data.h>
#include <openbsc/gsm_04_11.h>
#include <openbsc/db.h>
#include <openbsc/talloc.h>

#include <libgen.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <dbi/dbi.h>

static char *db_basename = NULL;
static char *db_dirname = NULL;
static dbi_conn conn;

static char *create_stmts[] = {
	"CREATE TABLE IF NOT EXISTS Meta ("
		"id INTEGER PRIMARY KEY AUTOINCREMENT, "
		"key TEXT UNIQUE NOT NULL, "
		"value TEXT NOT NULL"
		")",
	"INSERT OR IGNORE INTO Meta "
		"(key, value) "
		"VALUES "
		"('revision', '2')",
	"CREATE TABLE IF NOT EXISTS Subscriber ("
		"id INTEGER PRIMARY KEY AUTOINCREMENT, "
		"created TIMESTAMP NOT NULL, "
		"updated TIMESTAMP NOT NULL, "
		"imsi NUMERIC UNIQUE NOT NULL, "
		"name TEXT, "
		"extension TEXT UNIQUE, "
		"authorized INTEGER NOT NULL DEFAULT 0, "
		"tmsi TEXT UNIQUE, "
		"lac INTEGER NOT NULL DEFAULT 0"
		")",
	"CREATE TABLE IF NOT EXISTS AuthToken ("
		"id INTEGER PRIMARY KEY AUTOINCREMENT, "
		"subscriber_id INTEGER UNIQUE NOT NULL, "
		"created TIMESTAMP NOT NULL, "
		"token TEXT UNIQUE NOT NULL"
		")",
	"CREATE TABLE IF NOT EXISTS Equipment ("
		"id INTEGER PRIMARY KEY AUTOINCREMENT, "
		"created TIMESTAMP NOT NULL, "
		"updated TIMESTAMP NOT NULL, "
		"name TEXT, "
		"classmark1 NUMERIC, "
		"classmark2 BLOB, "
		"classmark3 BLOB, "
		"imei NUMERIC UNIQUE NOT NULL"
		")",
	"CREATE TABLE IF NOT EXISTS EquipmentWatch ("
		"id INTEGER PRIMARY KEY AUTOINCREMENT, "
		"created TIMESTAMP NOT NULL, "
		"updated TIMESTAMP NOT NULL, "
		"subscriber_id NUMERIC NOT NULL, "
		"equipment_id NUMERIC NOT NULL, "
		"UNIQUE (subscriber_id, equipment_id) "
		")",
	"CREATE TABLE IF NOT EXISTS SMS ("
		/* metadata, not part of sms */
		"id INTEGER PRIMARY KEY AUTOINCREMENT, "
		"created TIMESTAMP NOT NULL, "
		"sent TIMESTAMP, "
		"sender_id INTEGER NOT NULL, "
		"receiver_id INTEGER NOT NULL, "
		/* data directly copied/derived from SMS */
		"valid_until TIMESTAMP, "
		"reply_path_req INTEGER NOT NULL, "
		"status_rep_req INTEGER NOT NULL, "
		"protocol_id INTEGER NOT NULL, "
		"data_coding_scheme INTEGER NOT NULL, "
		"ud_hdr_ind INTEGER NOT NULL, "
		"dest_addr TEXT, "
		"user_data BLOB, "	/* TP-UD */
		/* additional data, interpreted from SMS */
		"header BLOB, "		/* UD Header */
		"text TEXT "		/* decoded UD after UDH */
		")",
	"CREATE TABLE IF NOT EXISTS VLR ("
		"id INTEGER PRIMARY KEY AUTOINCREMENT, "
		"created TIMESTAMP NOT NULL, "
		"updated TIMESTAMP NOT NULL, "
		"subscriber_id NUMERIC UNIQUE NOT NULL, "
		"last_bts NUMERIC NOT NULL "
		")",
};

void db_error_func(dbi_conn conn, void* data) {
	const char* msg;
	dbi_conn_error(conn, &msg);
	printf("DBI: %s\n", msg);
}

static int check_db_revision(void)
{
	dbi_result result;
	const char *rev;

	result = dbi_conn_query(conn,
				"SELECT value FROM Meta WHERE key='revision'");
	if (!result)
		return -EINVAL;

	if (!dbi_result_next_row(result)) {
		dbi_result_free(result);
		return -EINVAL;
	}
	rev = dbi_result_get_string(result, "value");
	if (!rev || atoi(rev) != 2) {
		dbi_result_free(result);
		return -EINVAL;
	}

	dbi_result_free(result);
	return 0;
}

int db_init(const char *name) {
	dbi_initialize(NULL);
	conn = dbi_conn_new("sqlite3");
	if (conn==NULL) {
		printf("DB: Failed to create connection.\n");
		return 1;
	}

	dbi_conn_error_handler( conn, db_error_func, NULL );

	/* MySQL
	dbi_conn_set_option(conn, "host", "localhost");
	dbi_conn_set_option(conn, "username", "your_name");
	dbi_conn_set_option(conn, "password", "your_password");
	dbi_conn_set_option(conn, "dbname", "your_dbname");
	dbi_conn_set_option(conn, "encoding", "UTF-8");
	*/

	/* SqLite 3 */
	db_basename = strdup(name);
	db_dirname = strdup(name);
	dbi_conn_set_option(conn, "sqlite3_dbdir", dirname(db_dirname));
	dbi_conn_set_option(conn, "dbname", basename(db_basename));

	if (dbi_conn_connect(conn) < 0)
		goto out_err;

	return 0;

out_err:
	free(db_dirname);
	free(db_basename);
	db_dirname = db_basename = NULL;
	return -1;
}


int db_prepare() {
	dbi_result result;
	int i;

	for (i = 0; i < ARRAY_SIZE(create_stmts); i++) {
		result = dbi_conn_query(conn, create_stmts[i]);
		if (result==NULL) {
			printf("DB: Failed to create some table.\n");
			return 1;
		}
		dbi_result_free(result);
	}

	if (check_db_revision() < 0) {
		fprintf(stderr, "Database schema revision invalid, "
			"please update your database schema\n");
                return -1;
	}

	return 0;
}

int db_fini() {
	dbi_conn_close(conn);
	dbi_shutdown();

	if (db_dirname)
	    free(db_dirname);
	if (db_basename)
	    free(db_basename);
	return 0;
}

struct gsm_subscriber* db_create_subscriber(struct gsm_network *net, char *imsi)
{
	dbi_result result;
	struct gsm_subscriber* subscr;

	/* Is this subscriber known in the db? */
	subscr = db_get_subscriber(net, GSM_SUBSCRIBER_IMSI, imsi); 
	if (subscr) {
		result = dbi_conn_queryf(conn,
                         "UPDATE Subscriber set updated = datetime('now') "
                         "WHERE imsi = %s " , imsi);
		if (result==NULL) {
			printf("DB: failed to update timestamp\n");
		} else {
			dbi_result_free(result);
		}
		return subscr;
	}

	subscr = subscr_alloc();
	subscr->flags |= GSM_SUBSCRIBER_FIRST_CONTACT;
	if (!subscr)
		return NULL;
	result = dbi_conn_queryf(conn,
		"INSERT INTO Subscriber "
		"(imsi, created, updated) "
		"VALUES "
		"(%s, datetime('now'), datetime('now')) ",
		imsi
	);
	if (result==NULL) {
		printf("DB: Failed to create Subscriber by IMSI.\n");
	}
	subscr->net = net;
	subscr->id = dbi_conn_sequence_last(conn, NULL);
	strncpy(subscr->imsi, imsi, GSM_IMSI_LENGTH-1);
	dbi_result_free(result);
	printf("DB: New Subscriber: ID %llu, IMSI %s\n", subscr->id, subscr->imsi);
	db_subscriber_alloc_exten(subscr);
	return subscr;
}

struct gsm_subscriber *db_get_subscriber(struct gsm_network *net,
					 enum gsm_subscriber_field field,
					 const char *id)
{
	dbi_result result;
	const char *string;
	char *quoted;
	struct gsm_subscriber *subscr;

	switch (field) {
	case GSM_SUBSCRIBER_IMSI:
		dbi_conn_quote_string_copy(conn, id, &quoted);
		result = dbi_conn_queryf(conn,
			"SELECT * FROM Subscriber "
			"WHERE imsi = %s ",
			quoted
		);
		free(quoted);
		break;
	case GSM_SUBSCRIBER_TMSI:
		dbi_conn_quote_string_copy(conn, id, &quoted);
		result = dbi_conn_queryf(conn,
			"SELECT * FROM Subscriber "
			"WHERE tmsi = %s ",
			quoted
		);
		free(quoted);
		break;
	case GSM_SUBSCRIBER_EXTENSION:
		dbi_conn_quote_string_copy(conn, id, &quoted);
		result = dbi_conn_queryf(conn,
			"SELECT * FROM Subscriber "
			"WHERE extension = %s ",
			quoted
		);
		free(quoted);
		break;
	case GSM_SUBSCRIBER_ID:
		dbi_conn_quote_string_copy(conn, id, &quoted);
		result = dbi_conn_queryf(conn,
			"SELECT * FROM Subscriber "
			"WHERE id = %s ", quoted);
		free(quoted);
		break;
	default:
		printf("DB: Unknown query selector for Subscriber.\n");
		return NULL;
	}
	if (result==NULL) {
		printf("DB: Failed to query Subscriber.\n");
		return NULL;
	}
	if (!dbi_result_next_row(result)) {
		printf("DB: Failed to find the Subscriber. '%u' '%s'\n",
			field, id);
		dbi_result_free(result);
		return NULL;
	}

	subscr = subscr_alloc();
	subscr->net = net;
	subscr->id = dbi_result_get_ulonglong(result, "id");
	string = dbi_result_get_string(result, "imsi");
	if (string)
		strncpy(subscr->imsi, string, GSM_IMSI_LENGTH);

	string = dbi_result_get_string(result, "tmsi");
	if (string)
		strncpy(subscr->tmsi, string, GSM_TMSI_LENGTH);

	string = dbi_result_get_string(result, "name");
	if (string)
		strncpy(subscr->name, string, GSM_NAME_LENGTH);

	string = dbi_result_get_string(result, "extension");
	if (string)
		strncpy(subscr->extension, string, GSM_EXTENSION_LENGTH);

	subscr->lac = dbi_result_get_uint(result, "lac");
	subscr->authorized = dbi_result_get_uint(result, "authorized");
	printf("DB: Found Subscriber: ID %llu, IMSI %s, NAME '%s', TMSI %s, EXTEN '%s', LAC %hu, AUTH %u\n",
		subscr->id, subscr->imsi, subscr->name, subscr->tmsi, subscr->extension,
		subscr->lac, subscr->authorized);
	dbi_result_free(result);
	return subscr;
}

int db_sync_subscriber(struct gsm_subscriber* subscriber) {
	dbi_result result;
	char *q_tmsi;
	if (subscriber->tmsi[0])
		dbi_conn_quote_string_copy(conn,
				   subscriber->tmsi,
				   &q_tmsi);
	else 
		q_tmsi = strdup("NULL");
	result = dbi_conn_queryf(conn,
		"UPDATE Subscriber "
		"SET updated = datetime('now'), "
		"name = '%s', "
		"extension = '%s', "
		"authorized = %i, "
		"tmsi = %s, "
		"lac = %i "
		"WHERE imsi = %s ",
		subscriber->name,
		subscriber->extension,
		subscriber->authorized,
		q_tmsi,
		subscriber->lac,
		subscriber->imsi
	);
	free(q_tmsi);
	if (result==NULL) {
		printf("DB: Failed to update Subscriber (by IMSI).\n");
		return 1;
	}
	dbi_result_free(result);
	return 0;
}

int db_sync_equipment(struct gsm_equipment *equip)
{
	dbi_result result;
	unsigned char *cm2, *cm3;

	dbi_conn_quote_binary_copy(conn, equip->classmark2,
				   equip->classmark2_len, &cm2);
	dbi_conn_quote_binary_copy(conn, equip->classmark3,
				   equip->classmark3_len, &cm3);

	result = dbi_conn_queryf(conn,
		"UPDATE Equipment SET "
			"updated = datetime('now'), "
			"classmark1 = %u, "
			"classmark2 = %s, "
			"classmark3 = %s "
		"WHERE imei = '%s' ",
		equip->classmark1, cm2, cm3, equip->imei);

	free(cm2);
	free(cm3);

	if (!result) {
		printf("DB: Failed to update Equipment\n");
		return -EIO;
	}

	dbi_result_free(result);
	return 0;
}

int db_subscriber_alloc_tmsi(struct gsm_subscriber* subscriber) {
	dbi_result result=NULL;
	char* tmsi_quoted;
	for (;;) {
		sprintf(subscriber->tmsi, "%i", rand());
		dbi_conn_quote_string_copy(conn, subscriber->tmsi, &tmsi_quoted);
		result = dbi_conn_queryf(conn,
			"SELECT * FROM Subscriber "
			"WHERE tmsi = %s ",
			tmsi_quoted
		);
		free(tmsi_quoted);
		if (result==NULL) {
			printf("DB: Failed to query Subscriber while allocating new TMSI.\n");
			return 1;
		}
		if (dbi_result_get_numrows(result)){
			dbi_result_free(result);
			continue;
		}
		if (!dbi_result_next_row(result)) {
			dbi_result_free(result);
			printf("DB: Allocated TMSI %s for IMSI %s.\n", subscriber->tmsi, subscriber->imsi);
			return db_sync_subscriber(subscriber);
		}
		dbi_result_free(result);
	}
	return 0;
}

int db_subscriber_alloc_exten(struct gsm_subscriber* subscriber) {
	dbi_result result=NULL;
	u_int32_t try;
	for (;;) {
		try = (rand()%(GSM_MAX_EXTEN-GSM_MIN_EXTEN+1)+GSM_MIN_EXTEN);
		result = dbi_conn_queryf(conn,
			"SELECT * FROM Subscriber "
			"WHERE extension = %i",
			try
		);
		if (result==NULL) {
			printf("DB: Failed to query Subscriber while allocating new extension.\n");
			return 1;
		}
		if (dbi_result_get_numrows(result)){
			dbi_result_free(result);
			continue;
		}
		if (!dbi_result_next_row(result)) {
			dbi_result_free(result);
			break;
		}
		dbi_result_free(result);
	}
	sprintf(subscriber->extension, "%i", try);
	printf("DB: Allocated extension %i for IMSI %s.\n", try, subscriber->imsi);
	return db_sync_subscriber(subscriber);
}
/*
 * try to allocate a new unique token for this subscriber and return it
 * via a parameter. if the subscriber already has a token, return
 * an error.
 */

int db_subscriber_alloc_token(struct gsm_subscriber* subscriber, u_int32_t* token) {
	dbi_result result=NULL;
	u_int32_t try;
	for (;;) {
		try = rand();
		if (!try) /* 0 is an invalid token */
			continue;
		result = dbi_conn_queryf(conn,
			"SELECT * FROM AuthToken "
			"WHERE subscriber_id = %llu OR token = %08x ",
			subscriber->id, try
		);
		if (result==NULL) {
			printf("DB: Failed to query AuthToken while allocating new token.\n");
			return 1;
		}
		if (dbi_result_get_numrows(result)){
			dbi_result_free(result);
			continue;
		}
		if (!dbi_result_next_row(result)) {
			dbi_result_free(result);
			break;
		}
		dbi_result_free(result);
	}
	result = dbi_conn_queryf(conn,
		"INSERT INTO AuthToken "
		"(subscriber_id, created, token) "
		"VALUES "
		"(%llu, datetime('now'), %08x)) ",
		subscriber->id, try
	);
	if (result==NULL) {
		printf("DB: Failed to create token %08x for IMSI %s.\n", try, subscriber->imsi);
		return 1;
	}
	*token = try;
	printf("DB: Allocated token %08x for IMSI %s.\n", try, subscriber->imsi);
	return 0;
}

int db_subscriber_assoc_imei(struct gsm_subscriber* subscriber, char imei[GSM_IMEI_LENGTH]) {
	u_int64_t equipment_id, watch_id;
	dbi_result result;

	strncpy(subscriber->equipment.imei, imei,
		sizeof(subscriber->equipment.imei)-1),

	result = dbi_conn_queryf(conn,
		"INSERT OR IGNORE INTO Equipment "
		"(imei, created, updated) "
		"VALUES "
		"(%s, datetime('now'), datetime('now')) ",
		imei
	);
	if (result==NULL) {
		printf("DB: Failed to create Equipment by IMEI.\n");
		return 1;
	}
	equipment_id = 0;
	if (dbi_result_get_numrows_affected(result)) {
		equipment_id = dbi_conn_sequence_last(conn, NULL);
	}
	dbi_result_free(result);
	if (equipment_id) {
		printf("DB: New Equipment: ID %llu, IMEI %s\n", equipment_id, imei);
	}
	else {
		result = dbi_conn_queryf(conn,
			"SELECT id FROM Equipment "
			"WHERE imei = %s ",
			imei
		);
		if (result==NULL) {
			printf("DB: Failed to query Equipment by IMEI.\n");
			return 1;
		}
		if (!dbi_result_next_row(result)) {
			printf("DB: Failed to find the Equipment.\n");
			dbi_result_free(result);
			return 1;
		}
		equipment_id = dbi_result_get_ulonglong(result, "id");
		dbi_result_free(result);
	}

	result = dbi_conn_queryf(conn,
		"INSERT OR IGNORE INTO EquipmentWatch "
		"(subscriber_id, equipment_id, created, updated) "
		"VALUES "
		"(%llu, %llu, datetime('now'), datetime('now')) ",
		subscriber->id, equipment_id
	);
	if (result==NULL) {
		printf("DB: Failed to create EquipmentWatch.\n");
		return 1;
	}
	watch_id = 0;
	if (dbi_result_get_numrows_affected(result)) {
		watch_id = dbi_conn_sequence_last(conn, NULL);
	}
	dbi_result_free(result);
	if (watch_id) {
		printf("DB: New EquipmentWatch: ID %llu, IMSI %s, IMEI %s\n", equipment_id, subscriber->imsi, imei);
	}
	else {
		result = dbi_conn_queryf(conn,
			"UPDATE EquipmentWatch "
			"SET updated = datetime('now') "
			"WHERE subscriber_id = %llu AND equipment_id = %llu ",
			subscriber->id, equipment_id
		);
		if (result==NULL) {
			printf("DB: Failed to update EquipmentWatch.\n");
			return 1;
		}
		dbi_result_free(result);
		printf("DB: Updated EquipmentWatch: ID %llu, IMSI %s, IMEI %s\n", equipment_id, subscriber->imsi, imei);
	}

	return 0;
}

/* store an [unsent] SMS to the database */
int db_sms_store(struct gsm_sms *sms)
{
	dbi_result result;
	char *q_text, *q_daddr;
	unsigned char *q_udata;
	char *validity_timestamp = "2222-2-2";

	/* FIXME: generate validity timestamp based on validity_minutes */

	dbi_conn_quote_string_copy(conn, (char *)sms->text, &q_text);
	dbi_conn_quote_string_copy(conn, (char *)sms->dest_addr, &q_daddr);
	dbi_conn_quote_binary_copy(conn, sms->user_data, sms->user_data_len,
				   &q_udata);
	/* FIXME: correct validity period */
	result = dbi_conn_queryf(conn,
		"INSERT INTO SMS "
		"(created, sender_id, receiver_id, valid_until, "
		 "reply_path_req, status_rep_req, protocol_id, "
		 "data_coding_scheme, ud_hdr_ind, dest_addr, "
		 "user_data, text) VALUES "
		"(datetime('now'), %llu, %llu, %u, "
		 "%u, %u, %u, %u, %u, %s, %s, %s)",
		sms->sender->id,
		sms->receiver ? sms->receiver->id : 0, validity_timestamp,
		sms->reply_path_req, sms->status_rep_req, sms->protocol_id,
		sms->data_coding_scheme, sms->ud_hdr_ind,
		q_daddr, q_udata, q_text);
	free(q_text);
	free(q_daddr);
	free(q_udata);

	if (!result)
		return -EIO;

	dbi_result_free(result);
	return 0;
}

static struct gsm_sms *sms_from_result(struct gsm_network *net, dbi_result result)
{
	struct gsm_sms *sms = sms_alloc();
	long long unsigned int sender_id, receiver_id;
	const char *text, *daddr;
	const unsigned char *user_data;

	if (!sms)
		return NULL;

	sms->id = dbi_result_get_ulonglong(result, "id");

	sender_id = dbi_result_get_ulonglong(result, "sender_id");
	sms->sender = subscr_get_by_id(net, sender_id);

	receiver_id = dbi_result_get_ulonglong(result, "receiver_id");
	sms->receiver = subscr_get_by_id(net, receiver_id);

	/* FIXME: validity */
	/* FIXME: those should all be get_uchar, but sqlite3 is braindead */
	sms->reply_path_req = dbi_result_get_uint(result, "reply_path_req");
	sms->status_rep_req = dbi_result_get_uint(result, "status_rep_req");
	sms->ud_hdr_ind = dbi_result_get_uint(result, "ud_hdr_ind");
	sms->protocol_id = dbi_result_get_uint(result, "protocol_id");
	sms->data_coding_scheme = dbi_result_get_uint(result,
						  "data_coding_scheme");
	/* sms->msg_ref is temporary and not stored in DB */

	daddr = dbi_result_get_string(result, "dest_addr");
	if (daddr) {
		strncpy(sms->dest_addr, daddr, sizeof(sms->dest_addr));
		sms->dest_addr[sizeof(sms->dest_addr)-1] = '\0';
	}

	sms->user_data_len = dbi_result_get_field_length(result, "user_data");
	user_data = dbi_result_get_binary(result, "user_data");
	if (sms->user_data_len > sizeof(sms->user_data))
		sms->user_data_len = (u_int8_t) sizeof(sms->user_data);
	memcpy(sms->user_data, user_data, sms->user_data_len);

	text = dbi_result_get_string(result, "text");
	if (text) {
		strncpy(sms->text, text, sizeof(sms->text));
		sms->text[sizeof(sms->text)-1] = '\0';
	}
	return sms;
}

/* retrieve the next unsent SMS with ID >= min_id */
struct gsm_sms *db_sms_get_unsent(struct gsm_network *net, int min_id)
{
	dbi_result result;
	struct gsm_sms *sms;

	result = dbi_conn_queryf(conn,
		"SELECT * FROM SMS "
		"WHERE id >= %llu AND sent is NULL ORDER BY id",
		min_id);
	if (!result)
		return NULL;

	if (!dbi_result_next_row(result)) {
		dbi_result_free(result);
		return NULL;
	}

	sms = sms_from_result(net, result);

	dbi_result_free(result);

	return sms;
}

/* retrieve the next unsent SMS with ID >= min_id */
struct gsm_sms *db_sms_get_unsent_for_subscr(struct gsm_subscriber *subscr)
{
	dbi_result result;
	struct gsm_sms *sms;

	result = dbi_conn_queryf(conn,
		"SELECT * FROM SMS "
		"WHERE receiver_id = %llu AND sent is NULL ORDER BY id",
		subscr->id);
	if (!result)
		return NULL;

	if (!dbi_result_next_row(result)) {
		dbi_result_free(result);
		return NULL;
	}

	sms = sms_from_result(subscr->net, result);

	dbi_result_free(result);

	return sms;
}

/* mark a given SMS as read */
int db_sms_mark_sent(struct gsm_sms *sms)
{
	dbi_result result;

	result = dbi_conn_queryf(conn,
		"UPDATE SMS "
		"SET sent = datetime('now') "
		"WHERE id = %llu", sms->id);
	if (!result) {
		printf("DB: Failed to mark SMS %llu as sent.\n", sms->id);
		return 1;
	}

	dbi_result_free(result);
	return 0;
}
