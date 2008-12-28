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

#include <sys/types.h>

#include <openbsc/gsm_subscriber.h>

int db_init(const char *name);
int db_prepare();
int db_fini();

struct gsm_subscriber* db_create_subscriber(char imsi[GSM_IMSI_LENGTH]);
int db_get_subscriber(enum gsm_subscriber_field field, struct gsm_subscriber* subscriber);
int db_set_subscriber(struct gsm_subscriber* subscriber);
int db_subscriber_alloc_tmsi(struct gsm_subscriber* subscriber);
int db_subscriber_assoc_imei(struct gsm_subscriber* subscriber, char imei[GSM_IMEI_LENGTH]);

#endif /* _DB_H */
