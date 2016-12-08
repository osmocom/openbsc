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

#include <openbsc/oap_client.h>

#define GSUP_CLIENT_RECONNECT_INTERVAL 10
#define GSUP_CLIENT_PING_INTERVAL 20

struct msgb;
struct ipa_client_conn;
struct gsup_client;

/* Expects message in msg->l2h */
typedef int (*gsup_client_read_cb_t)(struct gsup_client *gsupc,
				     struct msgb *msg);

struct gsup_client {
	struct ipa_client_conn *link;
	gsup_client_read_cb_t read_cb;
	void *data;

	struct oap_client_state oap_state;

	struct osmo_timer_list ping_timer;
	struct osmo_timer_list connect_timer;
	int is_connected;
	int got_ipa_pong;
};

struct gsup_client *gsup_client_create(const char *ip_addr,
				       unsigned int tcp_port,
				       gsup_client_read_cb_t read_cb,
				       struct oap_client_config *oap_config);

void gsup_client_destroy(struct gsup_client *gsupc);
int gsup_client_send(struct gsup_client *gsupc, struct msgb *msg);
struct msgb *gsup_client_msgb_alloc(void);

