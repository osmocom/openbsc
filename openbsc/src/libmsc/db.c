/* Simple HLR/VLR database backend using dbi */
/* (C) 2008 by Jan Luebbe <jluebbe@debian.org>
 * (C) 2009 by Holger Hans Peter Freyther <zecke@selfish.org>
 * (C) 2009 by Harald Welte <laforge@gnumonks.org>
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

#include <stdint.h>
#include <inttypes.h>
#include <libgen.h>
#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <dbi/dbi.h>

#include <openbsc/gsm_data.h>
#include <openbsc/gsm_subscriber.h>
#include <openbsc/gsm_04_11.h>
#include <openbsc/db.h>
#include <openbsc/debug.h>
#include <openbsc/vlr.h>

#include <osmocom/gsm/protocol/gsm_23_003.h>
#include <osmocom/core/talloc.h>
#include <osmocom/core/statistics.h>
#include <osmocom/core/rate_ctr.h>
#include <osmocom/core/utils.h>

#include <openssl/rand.h>

static char *db_basename = NULL;
static char *db_dirname = NULL;
static dbi_conn conn;

#define SCHEMA_REVISION "4"

enum {
	SCHEMA_META,
	INSERT_META,
	SCHEMA_SUBSCRIBER,
	SCHEMA_AUTH,
	SCHEMA_EQUIPMENT,
	SCHEMA_EQUIPMENT_WATCH,
	SCHEMA_SMS,
	SCHEMA_VLR,
	SCHEMA_APDU,
	SCHEMA_COUNTERS,
	SCHEMA_RATE,
	SCHEMA_AUTHKEY,
	SCHEMA_AUTHLAST,
};

static const char *create_stmts[] = {
	[SCHEMA_META] = "CREATE TABLE IF NOT EXISTS Meta ("
		"id INTEGER PRIMARY KEY AUTOINCREMENT, "
		"key TEXT UNIQUE NOT NULL, "
		"value TEXT NOT NULL"
		")",
	[INSERT_META] = "INSERT OR IGNORE INTO Meta "
		"(key, value) "
		"VALUES "
		"('revision', " SCHEMA_REVISION ")",
	[SCHEMA_SUBSCRIBER] = "CREATE TABLE IF NOT EXISTS Subscriber ("
		"id INTEGER PRIMARY KEY AUTOINCREMENT, "
		"created TIMESTAMP NOT NULL, "
		"updated TIMESTAMP NOT NULL, "
		"imsi NUMERIC UNIQUE NOT NULL, "
		"name TEXT, "
		"extension TEXT UNIQUE, "
		"authorized INTEGER NOT NULL DEFAULT 0, "
		"tmsi TEXT UNIQUE, "
		"lac INTEGER NOT NULL DEFAULT 0, "
		"expire_lu TIMESTAMP DEFAULT NULL"
		")",
	[SCHEMA_AUTH] = "CREATE TABLE IF NOT EXISTS AuthToken ("
		"id INTEGER PRIMARY KEY AUTOINCREMENT, "
		"subscriber_id INTEGER UNIQUE NOT NULL, "
		"created TIMESTAMP NOT NULL, "
		"token TEXT UNIQUE NOT NULL"
		")",
	[SCHEMA_EQUIPMENT] = "CREATE TABLE IF NOT EXISTS Equipment ("
		"id INTEGER PRIMARY KEY AUTOINCREMENT, "
		"created TIMESTAMP NOT NULL, "
		"updated TIMESTAMP NOT NULL, "
		"name TEXT, "
		"classmark1 NUMERIC, "
		"classmark2 BLOB, "
		"classmark3 BLOB, "
		"imei NUMERIC UNIQUE NOT NULL"
		")",
	[SCHEMA_EQUIPMENT_WATCH] = "CREATE TABLE IF NOT EXISTS EquipmentWatch ("
		"id INTEGER PRIMARY KEY AUTOINCREMENT, "
		"created TIMESTAMP NOT NULL, "
		"updated TIMESTAMP NOT NULL, "
		"subscriber_id NUMERIC NOT NULL, "
		"equipment_id NUMERIC NOT NULL, "
		"UNIQUE (subscriber_id, equipment_id) "
		")",
	[SCHEMA_SMS] = "CREATE TABLE IF NOT EXISTS SMS ("
		/* metadata, not part of sms */
		"id INTEGER PRIMARY KEY AUTOINCREMENT, "
		"created TIMESTAMP NOT NULL, "
		"sent TIMESTAMP, "
		"deliver_attempts INTEGER NOT NULL DEFAULT 0, "
		/* data directly copied/derived from SMS */
		"valid_until TIMESTAMP, "
		"reply_path_req INTEGER NOT NULL, "
		"status_rep_req INTEGER NOT NULL, "
		"protocol_id INTEGER NOT NULL, "
		"data_coding_scheme INTEGER NOT NULL, "
		"ud_hdr_ind INTEGER NOT NULL, "
		"src_addr TEXT NOT NULL, "
		"src_ton INTEGER NOT NULL, "
		"src_npi INTEGER NOT NULL, "
		"dest_addr TEXT NOT NULL, "
		"dest_ton INTEGER NOT NULL, "
		"dest_npi INTEGER NOT NULL, "
		"user_data BLOB, "	/* TP-UD */
		/* additional data, interpreted from SMS */
		"header BLOB, "		/* UD Header */
		"text TEXT "		/* decoded UD after UDH */
		")",
	[SCHEMA_VLR] = "CREATE TABLE IF NOT EXISTS VLR ("
		"id INTEGER PRIMARY KEY AUTOINCREMENT, "
		"created TIMESTAMP NOT NULL, "
		"updated TIMESTAMP NOT NULL, "
		"subscriber_id NUMERIC UNIQUE NOT NULL, "
		"last_bts NUMERIC NOT NULL "
		")",
	[SCHEMA_APDU] = "CREATE TABLE IF NOT EXISTS ApduBlobs ("
		"id INTEGER PRIMARY KEY AUTOINCREMENT, "
		"created TIMESTAMP NOT NULL, "
		"apdu_id_flags INTEGER NOT NULL, "
		"subscriber_id INTEGER NOT NULL, "
		"apdu BLOB "
		")",
	[SCHEMA_COUNTERS] = "CREATE TABLE IF NOT EXISTS Counters ("
		"id INTEGER PRIMARY KEY AUTOINCREMENT, "
		"timestamp TIMESTAMP NOT NULL, "
		"value INTEGER NOT NULL, "
		"name TEXT NOT NULL "
		")",
	[SCHEMA_RATE] = "CREATE TABLE IF NOT EXISTS RateCounters ("
		"id INTEGER PRIMARY KEY AUTOINCREMENT, "
		"timestamp TIMESTAMP NOT NULL, "
		"value INTEGER NOT NULL, "
		"name TEXT NOT NULL, "
		"idx INTEGER NOT NULL "
		")",
	[SCHEMA_AUTHKEY] = "CREATE TABLE IF NOT EXISTS AuthKeys ("
		"subscriber_id INTEGER PRIMARY KEY, "
		"algorithm_id INTEGER NOT NULL, "
		"a3a8_ki BLOB "
		")",
	[SCHEMA_AUTHLAST] = "CREATE TABLE IF NOT EXISTS AuthLastTuples ("
		"subscriber_id INTEGER PRIMARY KEY, "
		"issued TIMESTAMP NOT NULL, "
		"use_count INTEGER NOT NULL DEFAULT 0, "
		"key_seq INTEGER NOT NULL, "
		"rand BLOB NOT NULL, "
		"sres BLOB NOT NULL, "
		"kc BLOB NOT NULL "
		")",
};

void db_error_func(dbi_conn conn, void *data)
{
	const char *msg;
	dbi_conn_error(conn, &msg);
	LOGP(DDB, LOGL_ERROR, "DBI: %s\n", msg);
	osmo_log_backtrace(DDB, LOGL_ERROR);
}

static int update_db_revision_2(void)
{
	dbi_result result;

	result = dbi_conn_query(conn,
				"ALTER TABLE Subscriber "
				"ADD COLUMN expire_lu "
				"TIMESTAMP DEFAULT NULL");
	if (!result) {
		LOGP(DDB, LOGL_ERROR,
		     "Failed to alter table Subscriber (upgrade from rev 2).\n");
		return -EINVAL;
	}
	dbi_result_free(result);

	result = dbi_conn_query(conn,
				"UPDATE Meta "
				"SET value = '3' "
				"WHERE key = 'revision'");
	if (!result) {
		LOGP(DDB, LOGL_ERROR,
		     "Failed to update DB schema revision  (upgrade from rev 2).\n");
		return -EINVAL;
	}
	dbi_result_free(result);

	return 0;
}

/**
 * Copied from the normal sms_from_result_v3 to avoid having
 * to make sure that the real routine will remain backward
 * compatible.
 */
static struct gsm_sms *sms_from_result_v3(dbi_result result)
{
	struct gsm_sms *sms = sms_alloc();
	long long unsigned int sender_id;
	const char *text, *daddr;
	const unsigned char *user_data;
	char buf[32];
	char *quoted;
	dbi_result result2;
	const char *extension;

	if (!sms)
		return NULL;

	sms->id = dbi_result_get_ulonglong(result, "id");

	/* find extension by id, assuming that the subscriber still exists in
	 * the db */
	sender_id = dbi_result_get_ulonglong(result, "sender_id");
	snprintf(buf, sizeof(buf), "%llu", sender_id);

	dbi_conn_quote_string_copy(conn, buf, &quoted);
	result2 = dbi_conn_queryf(conn,
				  "SELECT extension FROM Subscriber "
				  "WHERE id = %s ", quoted);
	free(quoted);
	extension = dbi_result_get_string(result2, "extension");
	if (extension)
		osmo_strlcpy(sms->src.addr, extension, sizeof(sms->src.addr));
	dbi_result_free(result2);
	/* got the extension */

	sms->reply_path_req = dbi_result_get_ulonglong(result, "reply_path_req");
	sms->status_rep_req = dbi_result_get_ulonglong(result, "status_rep_req");
	sms->ud_hdr_ind = dbi_result_get_ulonglong(result, "ud_hdr_ind");
	sms->protocol_id = dbi_result_get_ulonglong(result, "protocol_id");
	sms->data_coding_scheme = dbi_result_get_ulonglong(result,
						  "data_coding_scheme");

	daddr = dbi_result_get_string(result, "dest_addr");
	if (daddr)
		osmo_strlcpy(sms->dst.addr, daddr, sizeof(sms->dst.addr));

	sms->user_data_len = dbi_result_get_field_length(result, "user_data");
	user_data = dbi_result_get_binary(result, "user_data");
	if (sms->user_data_len > sizeof(sms->user_data))
		sms->user_data_len = (uint8_t) sizeof(sms->user_data);
	memcpy(sms->user_data, user_data, sms->user_data_len);

	text = dbi_result_get_string(result, "text");
	if (text)
		osmo_strlcpy(sms->text, text, sizeof(sms->text));
	return sms;
}

static int update_db_revision_3(void)
{
	dbi_result result;
	struct gsm_sms *sms;

	LOGP(DDB, LOGL_NOTICE, "Going to migrate from revision 3\n");

	result = dbi_conn_query(conn, "BEGIN EXCLUSIVE TRANSACTION");
	if (!result) {
		LOGP(DDB, LOGL_ERROR,
			"Failed to begin transaction (upgrade from rev 3)\n");
		return -EINVAL;
	}
	dbi_result_free(result);

	/* Rename old SMS table to be able create a new one */
	result = dbi_conn_query(conn, "ALTER TABLE SMS RENAME TO SMS_3");
	if (!result) {
		LOGP(DDB, LOGL_ERROR,
		     "Failed to rename the old SMS table (upgrade from rev 3).\n");
		goto rollback;
	}
	dbi_result_free(result);

	/* Create new SMS table with all the bells and whistles! */
	result = dbi_conn_query(conn, create_stmts[SCHEMA_SMS]);
	if (!result) {
		LOGP(DDB, LOGL_ERROR,
		     "Failed to create a new SMS table (upgrade from rev 3).\n");
		goto rollback;
	}
	dbi_result_free(result);

	/* Cycle through old messages and convert them to the new format */
	result = dbi_conn_query(conn, "SELECT * FROM SMS_3");
	if (!result) {
		LOGP(DDB, LOGL_ERROR,
		     "Failed fetch messages from the old SMS table (upgrade from rev 3).\n");
		goto rollback;
	}
	while (dbi_result_next_row(result)) {
		sms = sms_from_result_v3(result);
		if (db_sms_store(sms) != 0) {
			LOGP(DDB, LOGL_ERROR, "Failed to store message to the new SMS table(upgrade from rev 3).\n");
			sms_free(sms);
			dbi_result_free(result);
			goto rollback;
		}
		sms_free(sms);
	}
	dbi_result_free(result);

	/* Remove the temporary table */
	result = dbi_conn_query(conn, "DROP TABLE SMS_3");
	if (!result) {
		LOGP(DDB, LOGL_ERROR,
		     "Failed to drop the old SMS table (upgrade from rev 3).\n");
		goto rollback;
	}
	dbi_result_free(result);

	/* We're done. Bump DB Meta revision to 4 */
	result = dbi_conn_query(conn,
				"UPDATE Meta "
				"SET value = '4' "
				"WHERE key = 'revision'");
	if (!result) {
		LOGP(DDB, LOGL_ERROR,
		     "Failed to update DB schema revision (upgrade from rev 3).\n");
		goto rollback;
	}
	dbi_result_free(result);

	result = dbi_conn_query(conn, "COMMIT TRANSACTION");
	if (!result) {
		LOGP(DDB, LOGL_ERROR,
			"Failed to commit the transaction (upgrade from rev 3)\n");
		return -EINVAL;
	} else {
		dbi_result_free(result);
	}

	/* Shrink DB file size by actually wiping out SMS_3 table data */
	result = dbi_conn_query(conn, "VACUUM");
	if (!result)
		LOGP(DDB, LOGL_ERROR,
			"VACUUM failed. Ignoring it (upgrade from rev 3).\n");
	else
		dbi_result_free(result);

	return 0;

rollback:
	result = dbi_conn_query(conn, "ROLLBACK TRANSACTION");
	if (!result)
		LOGP(DDB, LOGL_ERROR,
			"Rollback failed (upgrade from rev 3).\n");
	else
		dbi_result_free(result);
	return -EINVAL;
}

static int check_db_revision(void)
{
	dbi_result result;
	const char *rev_s;
	int db_rev = 0;

	/* Make a query */
	result = dbi_conn_query(conn,
		"SELECT value FROM Meta "
		"WHERE key = 'revision'");

	if (!result)
		return -EINVAL;

	if (!dbi_result_next_row(result)) {
		dbi_result_free(result);
		return -EINVAL;
	}

	/* Fetch the DB schema revision */
	rev_s = dbi_result_get_string(result, "value");
	if (!rev_s) {
		dbi_result_free(result);
		return -EINVAL;
	}

	if (!strcmp(rev_s, SCHEMA_REVISION)) {
		/* Everything is fine */
		dbi_result_free(result);
		return 0;
	}

	db_rev = atoi(rev_s);
	dbi_result_free(result);

	/* Incremental migration waterfall */
	switch (db_rev) {
	case 2:
		if (update_db_revision_2())
			goto error;
	case 3:
		if (update_db_revision_3())
			goto error;

	/* The end of waterfall */
	break;
	default:
		LOGP(DDB, LOGL_FATAL,
			"Invalid database schema revision '%d'.\n", db_rev);
		return -EINVAL;
	}

	return 0;

error:
	LOGP(DDB, LOGL_FATAL, "Failed to update database "
		"from schema revision '%d'.\n", db_rev);
	return -EINVAL;
}

static int db_configure(void)
{
	dbi_result result;

	result = dbi_conn_query(conn,
				"PRAGMA synchronous = FULL");
	if (!result)
		return -EINVAL;

	dbi_result_free(result);
	return 0;
}

int db_init(const char *name)
{
	dbi_initialize(NULL);

	conn = dbi_conn_new("sqlite3");
	if (conn == NULL) {
		LOGP(DDB, LOGL_FATAL, "Failed to create connection.\n");
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


int db_prepare(void)
{
	dbi_result result;
	int i;

	for (i = 0; i < ARRAY_SIZE(create_stmts); i++) {
		result = dbi_conn_query(conn, create_stmts[i]);
		if (!result) {
			LOGP(DDB, LOGL_ERROR,
			     "Failed to create some table.\n");
			return 1;
		}
		dbi_result_free(result);
	}

	if (check_db_revision() < 0) {
		LOGP(DDB, LOGL_FATAL, "Database schema revision invalid, "
			"please update your database schema\n");
                return -1;
	}

	db_configure();

	return 0;
}

int db_fini(void)
{
	dbi_conn_close(conn);
	dbi_shutdown();

	free(db_dirname);
	free(db_basename);
	return 0;
}

/* store an [unsent] SMS to the database */
int db_sms_store(struct gsm_sms *sms)
{
	dbi_result result;
	char *q_text, *q_daddr, *q_saddr;
	unsigned char *q_udata;
	char *validity_timestamp = "2222-2-2";

	/* FIXME: generate validity timestamp based on validity_minutes */

	dbi_conn_quote_string_copy(conn, (char *)sms->text, &q_text);
	dbi_conn_quote_string_copy(conn, (char *)sms->dst.addr, &q_daddr);
	dbi_conn_quote_string_copy(conn, (char *)sms->src.addr, &q_saddr);
	dbi_conn_quote_binary_copy(conn, sms->user_data, sms->user_data_len,
				   &q_udata);

	/* FIXME: correct validity period */
	result = dbi_conn_queryf(conn,
		"INSERT INTO SMS "
		"(created, valid_until, "
		 "reply_path_req, status_rep_req, protocol_id, "
		 "data_coding_scheme, ud_hdr_ind, "
		 "user_data, text, "
		 "dest_addr, dest_ton, dest_npi, "
		 "src_addr, src_ton, src_npi) VALUES "
		"(datetime('now'), %u, "
		"%u, %u, %u, "
		"%u, %u, "
		"%s, %s, "
		"%s, %u, %u, "
		"%s, %u, %u)",
		validity_timestamp,
		sms->reply_path_req, sms->status_rep_req, sms->protocol_id,
		sms->data_coding_scheme, sms->ud_hdr_ind,
		q_udata, q_text,
		q_daddr, sms->dst.ton, sms->dst.npi,
		q_saddr, sms->src.ton, sms->src.npi);
	free(q_text);
	free(q_udata);
	free(q_daddr);
	free(q_saddr);

	if (!result)
		return -EIO;

	dbi_result_free(result);
	return 0;
}

static struct gsm_sms *sms_from_result(struct gsm_network *net, dbi_result result)
{
	struct gsm_sms *sms = sms_alloc();
	const char *text, *daddr, *saddr;
	const unsigned char *user_data;

	if (!sms)
		return NULL;

	sms->id = dbi_result_get_ulonglong(result, "id");

	/* FIXME: validity */
	/* FIXME: those should all be get_uchar, but sqlite3 is braindead */
	sms->reply_path_req = dbi_result_get_ulonglong(result, "reply_path_req");
	sms->status_rep_req = dbi_result_get_ulonglong(result, "status_rep_req");
	sms->ud_hdr_ind = dbi_result_get_ulonglong(result, "ud_hdr_ind");
	sms->protocol_id = dbi_result_get_ulonglong(result, "protocol_id");
	sms->data_coding_scheme = dbi_result_get_ulonglong(result,
						  "data_coding_scheme");
	/* sms->msg_ref is temporary and not stored in DB */

	sms->dst.npi = dbi_result_get_ulonglong(result, "dest_npi");
	sms->dst.ton = dbi_result_get_ulonglong(result, "dest_ton");
	daddr = dbi_result_get_string(result, "dest_addr");
	if (daddr)
		osmo_strlcpy(sms->dst.addr, daddr, sizeof(sms->dst.addr));
	sms->receiver = vlr_subscr_find_by_msisdn(net->vlr, sms->dst.addr);

	sms->src.npi = dbi_result_get_ulonglong(result, "src_npi");
	sms->src.ton = dbi_result_get_ulonglong(result, "src_ton");
	saddr = dbi_result_get_string(result, "src_addr");
	if (saddr)
		osmo_strlcpy(sms->src.addr, saddr, sizeof(sms->src.addr));

	sms->user_data_len = dbi_result_get_field_length(result, "user_data");
	user_data = dbi_result_get_binary(result, "user_data");
	if (sms->user_data_len > sizeof(sms->user_data))
		sms->user_data_len = (uint8_t) sizeof(sms->user_data);
	memcpy(sms->user_data, user_data, sms->user_data_len);

	text = dbi_result_get_string(result, "text");
	if (text)
		osmo_strlcpy(sms->text, text, sizeof(sms->text));
	return sms;
}

struct gsm_sms *db_sms_get(struct gsm_network *net, unsigned long long id)
{
	dbi_result result;
	struct gsm_sms *sms;

	result = dbi_conn_queryf(conn,
		"SELECT * FROM SMS WHERE SMS.id = %llu", id);
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

struct gsm_sms *db_sms_get_next_unsent(struct gsm_network *net,
				       unsigned long long min_sms_id,
				       unsigned int max_failed)
{
	dbi_result result;
	struct gsm_sms *sms;

	result = dbi_conn_queryf(conn,
		"SELECT * FROM SMS"
		" WHERE sent IS NULL"
		" AND id >= %llu"
		" AND deliver_attempts <= %u"
		" ORDER BY id LIMIT 1",
		min_sms_id, max_failed);

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

/* retrieve the next unsent SMS for a given subscriber */
struct gsm_sms *db_sms_get_unsent_for_subscr(struct vlr_subscr *vsub,
					     unsigned int max_failed)
{
	struct gsm_network *net = vsub->vlr->user_ctx;
	dbi_result result;
	struct gsm_sms *sms;

	if (!vsub->lu_complete)
		return NULL;

	result = dbi_conn_queryf(conn,
		"SELECT * FROM SMS"
		" WHERE sent IS NULL"
		" AND dest_addr=%s"
		" AND deliver_attempts <= %u"
		" ORDER BY id LIMIT 1",
		vsub->msisdn, max_failed);
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

struct gsm_sms *db_sms_get_next_unsent_rr_msisdn(struct gsm_network *net,
						 const char *last_msisdn,
						 unsigned int max_failed)
{
	dbi_result result;
	struct gsm_sms *sms;

	result = dbi_conn_queryf(conn,
		"SELECT * FROM SMS"
		" WHERE sent IS NULL"
		" AND dest_addr > '%s'"
		" AND deliver_attempts <= %u"
		" ORDER BY dest_addr, id LIMIT 1",
		last_msisdn, max_failed);
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

/* mark a given SMS as delivered */
int db_sms_mark_delivered(struct gsm_sms *sms)
{
	dbi_result result;

	result = dbi_conn_queryf(conn,
		"UPDATE SMS "
		"SET sent = datetime('now') "
		"WHERE id = %llu", sms->id);
	if (!result) {
		LOGP(DDB, LOGL_ERROR, "Failed to mark SMS %llu as sent.\n", sms->id);
		return 1;
	}

	dbi_result_free(result);
	return 0;
}

/* increase the number of attempted deliveries */
int db_sms_inc_deliver_attempts(struct gsm_sms *sms)
{
	dbi_result result;

	result = dbi_conn_queryf(conn,
		"UPDATE SMS "
		"SET deliver_attempts = deliver_attempts + 1 "
		"WHERE id = %llu", sms->id);
	if (!result) {
		LOGP(DDB, LOGL_ERROR, "Failed to inc deliver attempts for "
			"SMS %llu.\n", sms->id);
		return 1;
	}

	dbi_result_free(result);
	return 0;
}

/* Drop all pending SMS to or from the given extension */
int db_sms_delete_by_msisdn(const char *msisdn)
{
	dbi_result result;
	if (!msisdn || !*msisdn)
		return 0;
	result = dbi_conn_queryf(conn,
		    "DELETE FROM SMS WHERE src_addr=%s OR dest_addr=%s",
		    msisdn, msisdn);
	if (!result) {
		LOGP(DDB, LOGL_ERROR,
		     "Failed to delete SMS for %s\n", msisdn);
		return -1;
	}
	dbi_result_free(result);
	return 0;
}

int db_store_counter(struct osmo_counter *ctr)
{
	dbi_result result;
	char *q_name;

	dbi_conn_quote_string_copy(conn, ctr->name, &q_name);

	result = dbi_conn_queryf(conn,
		"INSERT INTO Counters "
		"(timestamp,name,value) VALUES "
		"(datetime('now'),%s,%lu)", q_name, ctr->value);

	free(q_name);

	if (!result)
		return -EIO;

	dbi_result_free(result);
	return 0;
}

static int db_store_rate_ctr(struct rate_ctr_group *ctrg, unsigned int num,
			     char *q_prefix)
{
	dbi_result result;
	char *q_name;

	dbi_conn_quote_string_copy(conn, ctrg->desc->ctr_desc[num].name,
				   &q_name);

	result = dbi_conn_queryf(conn,
		"Insert INTO RateCounters "
		"(timestamp,name,idx,value) VALUES "
		"(datetime('now'),%s.%s,%u,%"PRIu64")",
		q_prefix, q_name, ctrg->idx, ctrg->ctr[num].current);

	free(q_name);

	if (!result)
		return -EIO;

	dbi_result_free(result);
	return 0;
}

int db_store_rate_ctr_group(struct rate_ctr_group *ctrg)
{
	unsigned int i;
	char *q_prefix;

	dbi_conn_quote_string_copy(conn, ctrg->desc->group_name_prefix, &q_prefix);

	for (i = 0; i < ctrg->desc->num_ctr; i++)
		db_store_rate_ctr(ctrg, i, q_prefix);

	free(q_prefix);

	return 0;
}
