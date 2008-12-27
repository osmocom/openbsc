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
#include <dbi/dbi.h>

dbi_conn conn;

void db__error_func(dbi_conn conn, void* data) {
    const char* msg;
    dbi_conn_error(conn, &msg);
    printf("DBI: %s\n", msg);
}

int db_init() {
    dbi_initialize(NULL);
    conn = dbi_conn_new("sqlite3");
    
    dbi_conn_error_handler( conn, db__error_func, NULL );

    /* MySQL
    dbi_conn_set_option(conn, "host", "localhost");
    dbi_conn_set_option(conn, "username", "your_name");
    dbi_conn_set_option(conn, "password", "your_password");
    dbi_conn_set_option(conn, "dbname", "your_dbname");
    dbi_conn_set_option(conn, "encoding", "UTF-8");
    */

    /* SqLite 3 */
    dbi_conn_set_option(conn, "sqlite3_dbdir", "/tmp");
    dbi_conn_set_option(conn, "dbname", "hlr.sqlite3");

    if (dbi_conn_connect(conn) < 0) {
        return 1;
    }

    return 0;
}

int db_prepare() {
    dbi_result result;
    result = dbi_conn_query(conn,
        "CREATE TABLE IF NOT EXISTS Subscriber ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT, "
        "imsi INTEGER UNIQUE NOT NULL, "
        "tmsi INTEGER UNIQUE, "
        "extension TEXT UNIQUE, "
        "lac INTEGER"
        ")"
    );
    if (result==NULL) {
        printf("DB: Failed to create Subscriber table.\n");
        return 1;
    }
    dbi_result_free(result);
    result = dbi_conn_query(conn,
        "CREATE TABLE IF NOT EXISTS Equipment ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT, "
        "imei INTEGER UNIQUE NOT NULL"
        ")"
    );
    if (result==NULL) {
        printf("DB: Failed to create Equipment table.\n");
        return 1;
    }
    dbi_result_free(result);
    return 0;
}

int db_fini() {
    dbi_conn_close(conn);
    dbi_shutdown();
}

int db_insert_imei(uint64_t imei) {
    dbi_result result;
    result = dbi_conn_queryf(conn,
        "INSERT OR IGNORE INTO Equipment "
        "(imei) "
        "VALUES "
        "(%llu) ",
        imei
    );
    if (result==NULL) {
        printf("DB: Failed to create Equipment by IMEI.\n");
        return 1;
    }
    dbi_result_free(result);
    return 0;
}

int db_insert_imsi(uint64_t imsi) {
    dbi_result result;
    result = dbi_conn_queryf(conn,
        "INSERT OR IGNORE INTO Subscriber "
        "(imsi) "
        "VALUES "
        "(%llu) ",
        imsi
    );
    if (result==NULL) {
        printf("DB: Failed to create Subscriber by IMSI.\n");
        return 1;
    }
    dbi_result_free(result);
    return 0;
}

int db_imsi_set_tmsi(uint64_t imsi, uint64_t tmsi) {
    if (db_insert_imsi(imsi)) {
        return 1;
    }
    dbi_result result;
    result = dbi_conn_queryf(conn,
        "UPDATE Subscriber "
        "SET tmsi = %llu "
        "WHERE imsi = %llu ",
        tmsi, imsi
    );
    if (result==NULL) {
        printf("DB: Failed to update Subscriber with TMSI by IMSI.\n");
        return 1;
    }
    dbi_result_free(result);
    return 0;
}

int db_imsi_set_lac(uint64_t imsi, uint16_t lac) {
    if (db_insert_imsi(imsi)) {
        return 1;
    }
    dbi_result result;
    result = dbi_conn_queryf(conn,
        "UPDATE Subscriber "
        "SET lac = %u "
        "WHERE imsi = %llu ",
        lac, imsi
    );
    if (result==NULL) {
        printf("DB: Failed to update Subscriber with LAC by IMSI.\n");
        return 1;
    }
    dbi_result_free(result);
    return 0;
}

int db__parse_subscriber(dbi_result result, db_subscriber* subscriber) {
    if (!dbi_result_first_row(result)) {
        printf("DB: Failed to find Subscriber.\n");
        return 1;
    }
    subscriber->imsi = dbi_result_get_ulonglong(result, "imsi");
    subscriber->tmsi = dbi_result_get_ulonglong(result, "tmsi");
    // FIXME handle extension
    subscriber->lac = dbi_result_get_uint(result, "lac");
    printf("DB: Subscriber: IMSI %llu, TMSI %llu, LAC %hu\n", subscriber->imsi, subscriber->tmsi, subscriber->lac);
    return 0;
}

int db_imsi_get_subscriber(uint64_t imsi, db_subscriber* subscriber) {
    dbi_result result;
    result = dbi_conn_queryf(conn,
        "SELECT * FROM Subscriber "
        "WHERE imsi = %llu ",
        imsi
    );
    if (result==NULL) {
        printf("DB: Failed to find Subscriber by IMSI.\n");
        return 1;
    }
    if (db__parse_subscriber(result, subscriber)) {
        printf("DB: Failed to parse Subscriber.\n");
        dbi_result_free(result);
        return 1;
    }
    dbi_result_free(result);
    return 0;
}

int db_tmsi_get_subscriber(uint64_t tmsi, db_subscriber* subscriber) {
    dbi_result result;
    result = dbi_conn_queryf(conn,
        "SELECT * FROM Subscriber "
        "WHERE tmsi = %llu ",
        tmsi
    );
    if (result==NULL) {
        printf("DB: Failed to find Subscriber by TMSI.\n");
        return 1;
    }
    if (db__parse_subscriber(result, subscriber)) {
        printf("DB: Failed to parse Subscriber.\n");
        dbi_result_free(result);
        return 1;
    }
    dbi_result_free(result);
    return 0;
}

