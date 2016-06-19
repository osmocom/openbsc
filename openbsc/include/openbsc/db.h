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

#include <stdbool.h>

#include "gsm_subscriber.h"

struct gsm_equipment;
struct gsm_network;
struct gsm_auth_info;
struct gsm_auth_tuple;
struct gsm_sms;

/* one time initialisation */
int db_init(const char *name);
int db_prepare(void);
int db_fini(void);

/* SMS store-and-forward */
int db_sms_store(struct gsm_sms *sms);
struct gsm_sms *db_sms_get(struct gsm_network *net, unsigned long long id);
struct gsm_sms *db_sms_get_next_unsent(struct gsm_network *net,
				       unsigned long long min_sms_id,
				       unsigned int max_failed);
struct gsm_sms *db_sms_get_next_unsent_rr_msisdn(struct gsm_network *net,
						 const char *last_msisdn,
						 unsigned int max_failed);
struct gsm_sms *db_sms_get_unsent_for_subscr(struct vlr_subscr *vsub,
					     unsigned int max_failed);
int db_sms_mark_delivered(struct gsm_sms *sms);
int db_sms_inc_deliver_attempts(struct gsm_sms *sms);
int db_sms_delete_by_msisdn(const char *msisdn);

/* Statistics counter storage */
struct osmo_counter;
int db_store_counter(struct osmo_counter *ctr);
struct rate_ctr_group;
int db_store_rate_ctr_group(struct rate_ctr_group *ctrg);

#endif /* _DB_H */
