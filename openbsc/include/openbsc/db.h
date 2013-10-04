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
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#ifndef _DB_H
#define _DB_H

#include "gsm_subscriber.h"

struct gsm_equipment;
struct gsm_network;
struct gsm_auth_info;
struct gsm_auth_tuple;
struct gsm_sms;
struct gsm_subscriber;

/* one time initialisation */
int db_init(const char *name);
int db_prepare(void);
int db_fini(void);

/* subscriber management */
struct gsm_subscriber *db_create_subscriber(const char *imsi);
struct gsm_subscriber *db_get_subscriber(enum gsm_subscriber_field field,
					 const char *subscr);
int db_sync_subscriber(struct gsm_subscriber *subscriber);
int db_subscriber_expire(void *priv, void (*callback)(void *priv, long long unsigned int id));
int db_subscriber_alloc_tmsi(struct gsm_subscriber *subscriber);
int db_subscriber_alloc_exten(struct gsm_subscriber *subscriber);
int db_subscriber_alloc_token(struct gsm_subscriber *subscriber, uint32_t* token);
int db_subscriber_assoc_imei(struct gsm_subscriber *subscriber, char *imei);
int db_sync_equipment(struct gsm_equipment *equip);
int db_subscriber_update(struct gsm_subscriber *subscriber);

/* auth info */
int db_get_authinfo_for_subscr(struct gsm_auth_info *ainfo,
                               struct gsm_subscriber *subscr);
int db_sync_authinfo_for_subscr(struct gsm_auth_info *ainfo,
                                struct gsm_subscriber *subscr);
int db_get_lastauthtuple_for_subscr(struct gsm_auth_tuple *atuple,
                                    struct gsm_subscriber *subscr);
int db_sync_lastauthtuple_for_subscr(struct gsm_auth_tuple *atuple,
                                     struct gsm_subscriber *subscr);

/* SMS store-and-forward */
int db_sms_store(struct gsm_sms *sms);
struct gsm_sms *db_sms_get(struct gsm_network *net, unsigned long long id);
struct gsm_sms *db_sms_get_unsent(struct gsm_network *net, unsigned long long min_id);
struct gsm_sms *db_sms_get_unsent_by_subscr(struct gsm_network *net, unsigned long long min_subscr_id, unsigned int failed);
struct gsm_sms *db_sms_get_unsent_for_subscr(struct gsm_subscriber *subscr);
int db_sms_mark_sent(struct gsm_sms *sms);
int db_sms_inc_deliver_attempts(struct gsm_sms *sms);

/* APDU blob storage */
int db_apdu_blob_store(struct gsm_subscriber *subscr, 
			uint8_t apdu_id_flags, uint8_t len,
			uint8_t *apdu);

/* Statistics counter storage */
struct osmo_counter;
int db_store_counter(struct osmo_counter *ctr);
struct rate_ctr_group;
int db_store_rate_ctr_group(struct rate_ctr_group *ctrg);

#endif /* _DB_H */
