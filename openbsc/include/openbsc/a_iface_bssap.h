/* (C) 2017 by sysmocom s.f.m.c. GmbH
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

/* A structure to hold tha most basic information about a sigtran connection
 * we use this struct internally here to pass connection data around */
struct a_conn_info {
	struct osmo_sccp_addr *called_addr;
	struct osmo_sccp_addr *calling_addr;
	int conn_id;
	struct gsm_network *network;
};

/* A structure to pack BSC calling addresses into a list */
struct a_bsc_addr {
	struct llist_head list;
	struct osmo_sccp_addr called_addr;
	struct osmo_sccp_addr calling_addr;
	struct osmo_sccp_user *scu;
};

/* Handle incoming connection less data messages */
void msc_handle_udt(struct osmo_sccp_user *scu, struct a_conn_info *a_conn_info, struct msgb *msg);

/* Handle incoming connection oriented messages */
int msc_handle_dt1(struct osmo_sccp_user *scu, struct a_conn_info *a_conn_info, struct msgb *msg);

/* Get a list with all known BSCs */
struct llist_head *get_bsc_addr_list(void);
