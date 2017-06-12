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

/* Initalize A interface connection between to MSC and BSC */
int a_init(void *ctx, const char *name, uint32_t local_pc, const char *listen_addr,
	   const char *remote_addr, uint16_t local_port, struct gsm_network *network);

/* Send DTAP message via A-interface */
int a_iface_tx_dtap(struct msgb *msg);

/* Send Cipher mode command via A-interface */
int a_iface_tx_cipher_mode(struct gsm_subscriber_connection *conn,
			   int cipher, const uint8_t *key, int len, int include_imeisv);

/* Page a subscriber via A-interface */
int a_iface_tx_paging(const char *imsi, uint32_t tmsi, uint16_t lac);

/* Send assignment request via A-interface */
int a_iface_tx_assignment(struct gsm_trans *trans);

#pragma once
