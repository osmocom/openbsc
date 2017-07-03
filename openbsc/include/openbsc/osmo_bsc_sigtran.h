/* (C) 2017 by Sysmocom s.f.m.c. GmbH
 * All Rights Reserved
 *
 * Author: Philipp Maier
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

#include <openbsc/gsm_data.h>
#include <openbsc/bsc_msc_data.h>

/* Allocate resources to make a new connection oriented sigtran connection
 * (not the connection ittself!) */
enum bsc_con osmo_bsc_sigtran_new_conn(struct gsm_subscriber_connection *conn, struct bsc_msc_data *msc);

/* Open a new connection oriented sigtran connection */
int osmo_bsc_sigtran_open_conn(const struct osmo_bsc_sccp_con *conn, struct msgb *msg);

/* Send data to MSC */
int osmo_bsc_sigtran_send(const struct osmo_bsc_sccp_con *conn, struct msgb *msg);

/* Delete a connection from the list with open connections
 * (called by osmo_bsc_api.c on failing open connections and
 * locally, when a connection is closed by the MSC */
int osmo_bsc_sigtran_del_conn(struct osmo_bsc_sccp_con *sccp);

/* Initalize osmo sigtran backhaul */
int osmo_bsc_sigtran_init(struct llist_head *mscs);

/* Close all open sigtran connections and channels */
void osmo_bsc_sigtran_reset(const struct bsc_msc_data *msc);

/* Send reset-ack to MSC */
void osmo_bsc_sigtran_tx_reset_ack(const struct bsc_msc_data *msc);
