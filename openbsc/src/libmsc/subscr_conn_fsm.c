/* (C) 2016 by Harald Welte <laforge@gnumonks.org>
 *
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

#include <osmocom/core/fsm.h>

#include <openbsc/bsc_api.h>
#include <openbsc/debug.h>
#include <openbsc/vlr.h>
#include <openbsc/osmo_msc.h>

#define S(x)	(1 << (x))

/* This FSM primarily exists as a root/anchor to the various other FSM's
 * that we are starting during the life time of a subscriber_connection.
 * By having this FSM as part of the subscriber_connection, the other
 * FSMs can interact naturally with it, i.e. signal it on child
 * termination, keep a linked list of all child FSMs, ... */

enum subscr_conn_fsm_state {
	/* Initial state, most of its lifetime */
	SUB_CON_S_INIT,
	/* Release has been initiated and is ongoing */
	SUB_CON_S_RELEASING,
	/* Release completed, connection closed */
	SUB_CON_S_CLOSED,
};

static const struct value_string subscr_conn_fsm_event_names[] = {
	{ SUB_CON_E_LU_RES, "LU-RES" },
	{ SUB_CON_E_PARQ_RES, "PROC-ARQ-RES" },
	{ SUB_CON_E_MO_CLOSE, "MO-CLOSE" },
	{ SUB_CON_E_CN_CLOSE, "CN-CLOSE" },
	{ SUB_CON_E_CLOSE_CONF, "CLOSE-CONF" },
	{ 0, NULL }
};

static void subscr_conn_fsm_f_init(struct osmo_fsm_inst *fi,
				uint32_t event, void *data)
{
	struct gsm_subscriber_connection *conn = fi->priv;

	switch (event) {
	case SUB_CON_E_LU_RES:
		/* LU has completed, drop ref count */
		subscr_con_put(conn);
		break;
	case SUB_CON_E_PARQ_RES:
		/* Proc Acc Req has completed, drop ref count */
		subscr_con_put(conn);
		break;
	case SUB_CON_E_MO_CLOSE:
	case SUB_CON_E_CN_CLOSE:
		/* TODO: move msc_release_connection() here */
		msc_release_connection(conn);
		osmo_fsm_inst_state_chg(fi, SUB_CON_S_RELEASING, 0, 0);
		break;
	}
}

static void subscr_conn_fsm_f_releasing(struct osmo_fsm_inst *fi,
				uint32_t event, void *data)
{
	struct gsm_subscriber_connection *conn = fi->priv;
	OSMO_ASSERT(event == SUB_CON_E_CLOSE_CONF);

	subscr_conn_free(conn);
	osmo_fsm_inst_state_chg(fi, SUB_CON_S_CLOSED, 0, 0);
	osmo_fsm_inst_term(fi, OSMO_FSM_TERM_REGULAR, NULL);
}

static const struct osmo_fsm_state subscr_conn_fsm_states[] = {
	[SUB_CON_S_INIT] = {
		.in_event_mask = S(SUB_CON_E_LU_RES) |
				 S(SUB_CON_E_PARQ_RES) |
				 S(SUB_CON_E_MO_CLOSE) |
				 S(SUB_CON_E_CN_CLOSE),
		.out_state_mask = S(SUB_CON_S_RELEASING) |
				  S(SUB_CON_S_CLOSED),
		.name = "INIT",
		.action = subscr_conn_fsm_f_init,
	},
	[SUB_CON_S_RELEASING] = {
		.in_event_mask = S(SUB_CON_E_CLOSE_CONF),
		.out_state_mask = S(SUB_CON_S_CLOSED),
		.name = "RELEASING",
		.action = subscr_conn_fsm_f_releasing,
	},
	[SUB_CON_S_CLOSED] = {
		.name = "CLOSED",
	},
};

static struct osmo_fsm subscr_conn_fsm = {
	.name = "subscr_conn",
	.states = subscr_conn_fsm_states,
	.num_states = ARRAY_SIZE(subscr_conn_fsm_states),
	.log_subsys = DMM,
	.event_names = subscr_conn_fsm_event_names,
};

struct osmo_fsm_inst *
msc_create_conn_fsm(struct gsm_subscriber_connection *conn,
		    const char *id)
{
	struct osmo_fsm_inst *fi;

	OSMO_ASSERT(!conn->master_fsm);

	fi = osmo_fsm_inst_alloc(&subscr_conn_fsm, conn, conn,
				 LOGL_NOTICE, id);
	if (!fi)
		return NULL;

	fi->priv = conn;
	conn->master_fsm = conn;
}
