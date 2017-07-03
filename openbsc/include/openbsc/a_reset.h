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



/* Reset context data (callbacks, state machine etc...) */
struct a_reset_ctx {

	/* FSM instance, which handles the reset procedure */
	struct osmo_fsm_inst *fsm;

	/* Connection failure counter. When this counter
	 * reaches a certain threshold, the reset procedure
	 * will be triggered */
	int conn_loss_counter;

	/* A human readable name to display in the logs */
	char name[256];

	/* Callback function to be called when a connection
	 * failure is detected and a rest must occur */
	void (*cb)(void *priv);

	/* Privated data for the callback function */
	void *priv;
};

/* Create and start state machine which handles the reset/reset-ack procedure */
struct a_reset_ctx *a_reset_alloc(const void *ctx, const char *name, void *cb, void *priv);

/* Tear down state machine */
void a_reset_free(struct a_reset_ctx *reset);

/* Confirm that we sucessfully received a reset acknowlege message */
void a_reset_ack_confirm(struct a_reset_ctx *reset);

/* Report a failed connection */
void a_reset_conn_fail(struct a_reset_ctx *reset);

/* Report a successful connection */
void a_reset_conn_success(struct a_reset_ctx *reset);

/* Check if we have a connection to a specified msc */
bool a_reset_conn_ready(struct a_reset_ctx *reset);
