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

#include <openbsc/a_reset.h>

/* A struct to keep a context information about the BSCs we are associated with */
struct bsc_context {
	struct llist_head list;

	/* Holds a copy of the sccp address of the BSC,
	 * this address will become known as soon as
	 * a remote BSC tries to make a connection or
	 * sends a RESET request via UNIDATA */
	struct osmo_sccp_addr bsc_addr;

	/* Holds a copy of the our local MSC address,
	 * this will be the sccp-address that is associated
	 * with the A interface */
	struct osmo_sccp_addr msc_addr;

	/* A pointer to the reset handler FSM, the
	 * state machine is allocated when the BSC
	 * is registerd. */
	struct a_reset_ctx *reset;

	/* A pointer to the sccp_user that is associated
	 * with the A interface. We need this information
	 * to send the resets and to send paging requests */
	struct osmo_sccp_user *sccp_user;
};

/* Initalize A interface connection between to MSC and BSC */
int a_init(struct osmo_sccp_instance *sccp, struct gsm_network *network);

/* Send DTAP message via A-interface */
int a_iface_tx_dtap(struct msgb *msg);

/* Send Cipher mode command via A-interface */
int a_iface_tx_cipher_mode(const struct gsm_subscriber_connection *conn,
			   int cipher, const const uint8_t *key, int len, int include_imeisv);

/* Page a subscriber via A-interface */
int a_iface_tx_paging(const char *imsi, uint32_t tmsi, uint16_t lac);

/* Send assignment request via A-interface */
int a_iface_tx_assignment(const struct gsm_trans *trans);

/* Send clear command via A-interface */
int a_iface_tx_clear_cmd(struct gsm_subscriber_connection *conn);

/* Clear all subscriber connections on a specified BSC
 * (Helper function for a_iface_bssap.c) */
void a_clear_all(struct osmo_sccp_user *scu, const struct osmo_sccp_addr *bsc_addr);

/* Delete info of a closed connection from the active connection list
 * (Helper function for a_iface_bssap.c) */
void a_delete_bsc_con(uint32_t conn_id);
