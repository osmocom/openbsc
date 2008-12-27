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

#ifndef _DB_H
#define _DB_H

#include <stdint.h>

#define NUMBER_LENGTH 32

typedef struct {
    uint64_t imsi;
    uint64_t tmsi;
    char number[NUMBER_LENGTH];
    uint16_t lac;
} db_subscriber;

int db_init();
int db_prepare();
int db_fini();

int db_insert_imei(uint64_t imei);

int db_insert_imsi(uint64_t imsi);
int db_imsi_set_tmsi(uint64_t imsi, uint64_t tmsi);
int db_imsi_set_lac(uint64_t imsi, uint16_t lac);
int db_imsi_get_subscriber(uint64_t imsi, db_subscriber* subscriber);
int db_tmsi_get_subscriber(uint64_t tmsi, db_subscriber* subscriber);

#endif /* _DB_H */
