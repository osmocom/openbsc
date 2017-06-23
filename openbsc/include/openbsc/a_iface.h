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

	/* To be filled up by the user (VTY) */
	struct osmo_sccp_addr called_addr;	/* BSC (remote) */
	struct osmo_sccp_addr calling_addr;	/* MSC (local) */

	/* Automatically filled up by a_init() */
	struct a_reset_ctx reset;		/* Reset FSM (one per BSC) */
	struct osmo_sccp_user *sccp_user;	/* SCCP user (the same for all) */
};

/* Initalize A interface connection between to MSC and BSC */
int a_init(void *ctx, struct osmo_sccp_instance *sccp, struct gsm_network *network);

/* Send DTAP message via A-interface */
int a_iface_tx_dtap(struct msgb *msg);

/* Send Cipher mode command via A-interface */
int a_iface_tx_cipher_mode(struct gsm_subscriber_connection *conn,
			   int cipher, const uint8_t *key, int len, int include_imeisv);

/* Page a subscriber via A-interface */
int a_iface_tx_paging(const char *imsi, uint32_t tmsi, uint16_t lac);

/* Send assignment request via A-interface */
int a_iface_tx_assignment(struct gsm_trans *trans);

/* Clear all subscriber connections on a specified BSC */
void a_clear_all(struct osmo_sccp_user *scu, struct osmo_sccp_addr *bsc_addr);

/* Delete info of a closed connection from the active connection list */
void a_delete_bsc_con(uint32_t conn_id);
