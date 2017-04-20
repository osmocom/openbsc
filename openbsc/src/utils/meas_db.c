/* Routines for storing measurement reports in SQLite3 database */

/* (C) 2012 by Harald Welte <laforge@gnumonks.org>
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

#include <stdint.h>
#include <errno.h>
#include <string.h>

#include <sqlite3.h>

#include <osmocom/core/talloc.h>
#include <osmocom/core/utils.h>
#include <osmocom/gsm/gsm_utils.h>
#include <openbsc/meas_rep.h>

#include "meas_db.h"

#define INS_MR "INSERT INTO meas_rep (time, imsi, name, scenario, nr, bs_power, ms_timing_offset, fpc, ms_l1_pwr, ms_l1_ta) VALUES (?,?,?,?,?,?,?,?,?,?)"
#define INS_UD "INSERT INTO meas_rep_unidir (meas_id, rx_lev_full, rx_lev_sub, rx_qual_full, rx_qual_sub, dtx, uplink) VALUES (?,?,?,?,?,?,?)"
#define UPD_MR "UPDATE meas_rep SET ul_unidir=?, dl_unidir=? WHERE id=?"

struct meas_db_state {
	sqlite3 *db;
	sqlite3_stmt *stmt_ins_ud;
	sqlite3_stmt *stmt_ins_mr;
	sqlite3_stmt *stmt_upd_mr;
};

/* macros to check for SQLite3 result codes */
#define _SCK_OK(db, call, exp)				\
	do {						\
		int rc = call;				\
		if (rc != exp) {			\
			fprintf(stderr,"SQL Error in line %u: %s\n",	\
				__LINE__, sqlite3_errmsg(db));		\
			goto err_io;					\
		}							\
	} while (0)
#define SCK_OK(db, call)	_SCK_OK(db, call, SQLITE_OK)
#define SCK_DONE(db, call)	_SCK_OK(db, call, SQLITE_DONE)

static int _insert_ud(struct meas_db_state *st, unsigned long meas_id, int dtx,
		      int uplink, const struct gsm_meas_rep_unidir *ud)
{
	unsigned long rowid;

	SCK_OK(st->db, sqlite3_bind_int(st->stmt_ins_ud, 1, meas_id));
	SCK_OK(st->db, sqlite3_bind_int(st->stmt_ins_ud, 2,
					rxlev2dbm(ud->full.rx_lev)));
	SCK_OK(st->db, sqlite3_bind_int(st->stmt_ins_ud, 3,
					rxlev2dbm(ud->sub.rx_lev)));
	SCK_OK(st->db, sqlite3_bind_int(st->stmt_ins_ud, 4, ud->full.rx_qual));
	SCK_OK(st->db, sqlite3_bind_int(st->stmt_ins_ud, 5, ud->sub.rx_qual));
	SCK_OK(st->db, sqlite3_bind_int(st->stmt_ins_ud, 6, dtx));
	SCK_OK(st->db, sqlite3_bind_int(st->stmt_ins_ud, 7, uplink));

	SCK_DONE(st->db, sqlite3_step(st->stmt_ins_ud));

	SCK_OK(st->db, sqlite3_reset(st->stmt_ins_ud));

	return sqlite3_last_insert_rowid(st->db);
err_io:
	exit(1);
}

/* insert a measurement report into the database */
int meas_db_insert(struct meas_db_state *st, const char *imsi,
		   const char *name, unsigned long timestamp,
		   const char *scenario,
		   const struct gsm_meas_rep *mr)
{
	int rc;
	sqlite3_int64 rowid, ul_rowid, dl_rowid;

	SCK_OK(st->db, sqlite3_bind_int(st->stmt_ins_mr, 1, timestamp));

	if (imsi)
		SCK_OK(st->db, sqlite3_bind_text(st->stmt_ins_mr, 2,
						 imsi, -1, SQLITE_STATIC));
	else
		SCK_OK(st->db, sqlite3_bind_null(st->stmt_ins_mr, 2));

	if (name)
		SCK_OK(st->db, sqlite3_bind_text(st->stmt_ins_mr, 3,
						 name, -1, SQLITE_STATIC));
	else
		SCK_OK(st->db, sqlite3_bind_null(st->stmt_ins_mr, 3));

	if (scenario)
		SCK_OK(st->db, sqlite3_bind_text(st->stmt_ins_mr, 4,
						 scenario, -1, SQLITE_STATIC));
	else
		SCK_OK(st->db, sqlite3_bind_null(st->stmt_ins_mr, 4));


	SCK_OK(st->db, sqlite3_bind_int(st->stmt_ins_mr, 5, mr->nr));
	SCK_OK(st->db, sqlite3_bind_int(st->stmt_ins_mr, 6, mr->bs_power));

	if (mr->flags & MEAS_REP_F_MS_TO)
		SCK_OK(st->db, sqlite3_bind_int(st->stmt_ins_mr, 7, mr->ms_timing_offset));
	else
		SCK_OK(st->db, sqlite3_bind_null(st->stmt_ins_mr, 7));

	if (mr->flags & MEAS_REP_F_FPC)
		SCK_OK(st->db, sqlite3_bind_int(st->stmt_ins_mr, 8, 1));
	else
		SCK_OK(st->db, sqlite3_bind_int(st->stmt_ins_mr, 8, 0));

	if (mr->flags & MEAS_REP_F_MS_L1) {
		SCK_OK(st->db, sqlite3_bind_int(st->stmt_ins_mr, 9,
						mr->ms_l1.pwr));
		SCK_OK(st->db, sqlite3_bind_int(st->stmt_ins_mr, 10,
						mr->ms_l1.ta));
	}

	SCK_DONE(st->db, sqlite3_step(st->stmt_ins_mr));
	SCK_OK(st->db, sqlite3_reset(st->stmt_ins_mr));

	rowid = sqlite3_last_insert_rowid(st->db);

	/* insert uplink measurement */
	ul_rowid = _insert_ud(st, rowid, mr->flags & MEAS_REP_F_UL_DTX,
				1, &mr->ul);
	SCK_OK(st->db, sqlite3_bind_int(st->stmt_upd_mr, 1, ul_rowid));

	/* insert downlink measurement, if present */
	if (mr->flags & MEAS_REP_F_DL_VALID) {
		dl_rowid = _insert_ud(st, rowid, mr->flags & MEAS_REP_F_DL_DTX,
			       	      0, &mr->dl);
		SCK_OK(st->db, sqlite3_bind_int(st->stmt_upd_mr, 2, dl_rowid));
	} else
		SCK_OK(st->db, sqlite3_bind_null(st->stmt_upd_mr, 2));

	/* update meas_rep with the id's of the unidirectional
	 * measurements */
	SCK_OK(st->db, sqlite3_bind_int(st->stmt_upd_mr, 3, rowid));
	SCK_DONE(st->db, sqlite3_step(st->stmt_upd_mr));
	SCK_OK(st->db, sqlite3_reset(st->stmt_upd_mr));

	return 0;

err_io:
	return -EIO;
}

int meas_db_begin(struct meas_db_state *st)
{
	SCK_OK(st->db, sqlite3_exec(st->db, "BEGIN", NULL, NULL, NULL));

	return 0;

err_io:
	return -EIO;
}

int meas_db_commit(struct meas_db_state *st)
{
	SCK_OK(st->db, sqlite3_exec(st->db, "COMMIT", NULL, NULL, NULL));

	return 0;

err_io:
	return -EIO;
}

static const char *create_stmts[] = {
	"CREATE TABLE IF NOT EXISTS meas_rep ("
		"id INTEGER PRIMARY KEY AUTOINCREMENT,"
		"time TIMESTAMP,"
		"imsi TEXT,"
		"name TEXT,"
		"scenario TEXT,"
		"nr INTEGER,"
		"bs_power INTEGER NOT NULL,"
		"ms_timing_offset INTEGER,"
		"fpc INTEGER NOT NULL DEFAULT 0,"
		"ul_unidir INTEGER REFERENCES meas_rep_unidir(id),"
		"dl_unidir INTEGER REFERENCES meas_rep_unidir(id),"
		"ms_l1_pwr INTEGER,"
		"ms_l1_ta INTEGER"
	")",
	"CREATE TABLE IF NOT EXISTS meas_rep_unidir ("
		"id INTEGER PRIMARY KEY AUTOINCREMENT,"
		"meas_id INTEGER NOT NULL REFERENCES meas_rep(id),"
		"rx_lev_full INTEGER NOT NULL,"
		"rx_lev_sub INTEGER NOT NULL,"
		"rx_qual_full INTEGER NOT NULL,"
		"rx_qual_sub INTEGER NOT NULL,"
		"dtx BOOLEAN NOT NULL DEFAULT 0,"
	       	"uplink BOOLEAN NOT NULL"
	")",
	"CREATE VIEW IF NOT EXISTS path_loss AS "
		"SELECT "
			"meas_rep.id, "
			"datetime(time,'unixepoch') AS timestamp, "
			"imsi, "
			"name, "
			"scenario, "
			"ms_timing_offset, "
			"ms_l1_ta, "
			"fpc, "
			"ms_l1_pwr, "
			"ud_ul.rx_lev_full AS ul_rx_lev_full, "
			"ms_l1_pwr-ud_ul.rx_lev_full AS ul_path_loss_full, "
			"ud_ul.rx_lev_sub ul_rx_lev_sub, "
			"ms_l1_pwr-ud_ul.rx_lev_sub AS ul_path_loss_sub, "
			"ud_ul.rx_qual_full AS ul_rx_qual_full, "
			"ud_ul.rx_qual_sub AS ul_rx_qual_sub, "
			"bs_power, "
			"ud_dl.rx_lev_full AS dl_rx_lev_full, "
			"bs_power-ud_dl.rx_lev_full AS dl_path_loss_full, "
			"ud_dl.rx_lev_sub AS dl_rx_lev_sub, "
			"bs_power-ud_dl.rx_lev_sub AS dl_path_loss_sub, "
			"ud_dl.rx_qual_full AS dl_rx_qual_full, "
			"ud_dl.rx_qual_sub AS dl_rx_qual_sub "
		"FROM "
			"meas_rep, "
			"meas_rep_unidir AS ud_dl, "
			"meas_rep_unidir AS ud_ul "
		"WHERE "
			"ud_ul.id = meas_rep.ul_unidir AND "
			"ud_dl.id = meas_rep.dl_unidir",
	"CREATE VIEW IF NOT EXISTS overview AS "
		"SELECT "
			"id,"
			"timestamp,"
			"imsi,"
			"name,"
			"scenario,"
			"ms_l1_pwr,"
			"ul_rx_lev_full,"
			"ul_path_loss_full,"
			"ul_rx_qual_full,"
			"bs_power,"
			"dl_rx_lev_full,"
			"dl_path_loss_full,"
			"dl_rx_qual_full "
		"FROM path_loss",
};

static int check_create_tbl(struct meas_db_state *st)
{
	int i, rc;

	for (i = 0; i < ARRAY_SIZE(create_stmts); i++) {
		SCK_OK(st->db, sqlite3_exec(st->db, create_stmts[i],
					    NULL, NULL, NULL));
	}

	return 0;
err_io:
	return -EIO;
}


#define PREP_CHK(db, stmt, ptr)						\
	do {								\
		int rc;							\
		rc = sqlite3_prepare_v2(db, stmt, strlen(stmt)+1,	\
					ptr, NULL); 			\
		if (rc != SQLITE_OK) {					\
			fprintf(stderr, "Error during prepare of '%s': %s\n", \
				stmt, sqlite3_errmsg(db)); 		\
			goto err_io;					\
		}							\
	} while (0)

struct meas_db_state *meas_db_open(void *ctx, const char *fname)
{
	int rc;
	struct meas_db_state *st = talloc_zero(ctx, struct meas_db_state);

	if (!st)
		return NULL;

	rc = sqlite3_open_v2(fname, &st->db,
			     SQLITE_OPEN_READWRITE|SQLITE_OPEN_CREATE,
			     NULL);
	if (rc != SQLITE_OK) {
		fprintf(stderr, "Unable to open DB: %s\n",
			sqlite3_errmsg(st->db));
		goto err_io;
	}

	rc = check_create_tbl(st);

	PREP_CHK(st->db, INS_MR, &st->stmt_ins_mr);
	PREP_CHK(st->db, INS_UD, &st->stmt_ins_ud);
	PREP_CHK(st->db, UPD_MR, &st->stmt_upd_mr);

	return st;
err_io:
	talloc_free(st);
	return NULL;
}

void meas_db_close(struct meas_db_state *st)
{
	if (sqlite3_finalize(st->stmt_ins_mr) != SQLITE_OK)
		fprintf(stderr, "DB insert measurement report finalize error: %s\n",
			sqlite3_errmsg(st->db));
	if (sqlite3_finalize(st->stmt_ins_ud) != SQLITE_OK)
		fprintf(stderr, "DB insert unidir finalize error: %s\n",
			sqlite3_errmsg(st->db));
	if (sqlite3_finalize(st->stmt_upd_mr) != SQLITE_OK)
		fprintf(stderr, "DB update measurement report finalize error: %s\n",
			sqlite3_errmsg(st->db));
	if (sqlite3_close(st->db) != SQLITE_OK)
		fprintf(stderr, "Unable to close DB, abandoning.\n");

	talloc_free(st);

}
