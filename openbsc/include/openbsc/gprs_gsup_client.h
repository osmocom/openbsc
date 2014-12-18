/* GPRS Subscriber Update Protocol client */

/* (C) 2014 by Sysmocom s.f.m.c. GmbH
 * All Rights Reserved
 *
 * Author: Jacob Erlbeck
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
#pragma once

#include <osmocom/core/timer.h>

#define GPRS_GSUP_RECONNECT_INTERVAL 10

struct msgb;
struct ipa_client_conn;
struct gprs_gsup_client;

/* Expects message in msg->l2h */
typedef int (*gprs_gsup_read_cb_t)(struct gprs_gsup_client *gsupc, struct msgb *msg);

struct gprs_gsup_client {
	struct ipa_client_conn	*link;
	gprs_gsup_read_cb_t	read_cb;
	void			*data;

	struct osmo_timer_list	connect_timer;
	int			is_connected;
};

struct gprs_gsup_client *gprs_gsup_client_create(const char *ip_addr,
						 unsigned int tcp_port,
						 gprs_gsup_read_cb_t read_cb);

void gprs_gsup_client_destroy(struct gprs_gsup_client *gsupc);
int gprs_gsup_client_send(struct gprs_gsup_client *gsupc, struct msgb *msg);
struct msgb *gprs_gsup_msgb_alloc(void);

