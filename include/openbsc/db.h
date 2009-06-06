/* (C) 2008 by Jan Luebbe <jluebbe@debian.org>
 * (C) 2009 by Holger Hans Peter Freyther <zecke@selfish.org>
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

/* one time initialisation */
int db_init(const char *name);
int db_prepare();
int db_fini();

/* subscriber management */
struct gsm_subscriber* db_create_subscriber(char *imsi);
struct gsm_subscriber* db_get_subscriber(enum gsm_subscriber_field field, const char *subscr);
int db_sync_subscriber(struct gsm_subscriber* subscriber);
int db_subscriber_alloc_tmsi(struct gsm_subscriber* subscriber);
int db_subscriber_assoc_imei(struct gsm_subscriber* subscriber, char *imei);

/* SMS store-and-forward */
int db_sms_store(struct gsm_sms *sms);
struct gsm_sms *db_sms_get_unsent(int min_id);
int db_sms_mark_sent(struct gsm_sms *sms);
#endif /* _DB_H */
