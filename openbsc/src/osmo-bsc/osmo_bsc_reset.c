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

#include <osmocom/core/logging.h>
#include <osmocom/core/utils.h>
#include <osmocom/core/timer.h>
#include <osmocom/core/fsm.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <openbsc/debug.h>
#include <openbsc/bsc_msc_data.h>
#include <openbsc/osmo_bsc_sigtran.h>

#define RESET_RESEND_INTERVAL 2	/* sec */
#define RESET_RESEND_TIMER_NO 1234	/* FIXME: dig out the real timer number */
#define BAD_CONNECTION_THRESOLD 3	/* connection failures */

enum fsm_states {
	ST_DISC,		/* Disconnected from MSC */
	ST_CONN,		/* We have a confirmed connection to the MSC */
};

static const struct value_string fsm_state_names[] = {
	{ST_DISC, "ST_DISC (disconnected)"},
	{ST_CONN, "ST_CONN (connected)"},
	{0, NULL},
};

enum fsm_evt {
	EV_RESET_ACK,		/* got reset acknowlegement from the MSC */
	EV_N_DISCONNECT,	/* lost a connection */
	EV_N_CONNECT,		/* made a successful connection */
};

static const struct value_string fsm_evt_names[] = {
	{EV_RESET_ACK, "EV_RESET_ACK"},
	{EV_N_DISCONNECT, "EV_N_DISCONNECT"},
	{EV_N_CONNECT, "EV_N_CONNECT"},
	{0, NULL},
};

/* Disconnected state */
static void fsm_disc_cb(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct bsc_msc_data *msc = (struct bsc_msc_data *)data;

	LOGP(DMSC, LOGL_NOTICE, "fsm-state (msc-reset): %s, fsm-event: %s, MSC No.: %i\n",
	     get_value_string(fsm_state_names, ST_DISC), get_value_string(fsm_evt_names, event), msc->nr);
	msc->msc_con->msc_conn_loss_count = 0;
	osmo_fsm_inst_state_chg(fi, ST_CONN, 0, 0);
}

/* Connected state */
static void fsm_conn_cb(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct bsc_msc_data *msc = (struct bsc_msc_data *)data;

	LOGP(DMSC, LOGL_NOTICE, "fsm-state (msc-reset): %s, fsm-event: %s, MSC No.: %i\n",
	     get_value_string(fsm_state_names, ST_CONN), get_value_string(fsm_evt_names, event), msc->nr);

	OSMO_ASSERT(msc);

	switch (event) {
	case EV_N_DISCONNECT:
		if (msc->msc_con->msc_conn_loss_count >= BAD_CONNECTION_THRESOLD) {
			LOGP(DMSC, LOGL_NOTICE, "SIGTRAN connection to MSC No.: %i down, reconnecting...\n", msc->nr);
			osmo_fsm_inst_state_chg(fi, ST_DISC, RESET_RESEND_INTERVAL, RESET_RESEND_TIMER_NO);
		} else
			msc->msc_con->msc_conn_loss_count++;
		break;
	case EV_N_CONNECT:
		msc->msc_con->msc_conn_loss_count = 0;
		break;
	}
}

/* Timer callback to retransmit the reset signal */
static int fsm_reset_ack_timeout_cb(struct osmo_fsm_inst *fi)
{
	struct bsc_msc_data *msc = (struct bsc_msc_data *)fi->priv;

	LOGP(DMSC, LOGL_NOTICE, "reset-ack timeout (T%i) in state %s, MSC No.: %i, resending...\n", fi->T,
	     get_value_string(fsm_state_names, fi->state), msc->nr);

	osmo_bsc_sigtran_reset(msc);
	osmo_bsc_sigtran_tx_reset(msc);

	osmo_fsm_inst_state_chg(fi, ST_DISC, RESET_RESEND_INTERVAL, RESET_RESEND_TIMER_NO);
	return 0;
}

static struct osmo_fsm_state fsm_states[] = {
	[ST_DISC] = {
		     .in_event_mask = (1 << EV_RESET_ACK),
		     .out_state_mask = (1 << ST_DISC) | (1 << ST_CONN),
		     .name = "DISC",
		     .action = fsm_disc_cb,
		     },
	[ST_CONN] = {
		     .in_event_mask = (1 << EV_N_DISCONNECT) | (1 << EV_N_CONNECT),
		     .out_state_mask = (1 << ST_DISC) | (1 << ST_CONN),
		     .name = "CONN",
		     .action = fsm_conn_cb,
		     },
};

/* State machine definition */
static struct osmo_fsm fsm = {
	.name = "FSM RESET",
	.states = fsm_states,
	.num_states = ARRAY_SIZE(fsm_states),
	.log_subsys = DMSC,
	.timer_cb = fsm_reset_ack_timeout_cb,
};

/* Create and start state machine which handles the reset/reset-ack procedure */
void start_reset_fsm(struct bsc_msc_data *msc)
{
	OSMO_ASSERT(msc);
	OSMO_ASSERT(msc->msc_con);

	osmo_fsm_register(&fsm);
	msc->msc_con->fsm_reset = osmo_fsm_inst_alloc(&fsm, NULL, NULL, LOGL_DEBUG, "FSM RESET INST");
	OSMO_ASSERT(msc->msc_con->fsm_reset);

	msc->msc_con->fsm_reset->priv = msc;

	/* kick off reset-ack sending mechanism */
	osmo_fsm_inst_state_chg(msc->msc_con->fsm_reset, ST_DISC, RESET_RESEND_INTERVAL, RESET_RESEND_TIMER_NO);
}

/* Confirm that we sucessfully received a reset acknowlege message */
void reset_ack_confirm(struct bsc_msc_data *msc)
{
	OSMO_ASSERT(msc);
	OSMO_ASSERT(msc->msc_con);
	OSMO_ASSERT(msc->msc_con->fsm_reset);

	osmo_fsm_inst_dispatch(msc->msc_con->fsm_reset, EV_RESET_ACK, msc);
}

/* Report a failed connection */
void report_conn_fail(struct bsc_msc_data *msc)
{
	OSMO_ASSERT(msc);
	OSMO_ASSERT(msc->msc_con);
	OSMO_ASSERT(msc->msc_con->fsm_reset);

	osmo_fsm_inst_dispatch(msc->msc_con->fsm_reset, EV_N_DISCONNECT, msc);
}

/* Report a successful connection */
void report_conn_success(struct bsc_msc_data *msc)
{
	OSMO_ASSERT(msc);
	OSMO_ASSERT(msc->msc_con);
	OSMO_ASSERT(msc->msc_con->fsm_reset);

	osmo_fsm_inst_dispatch(msc->msc_con->fsm_reset, EV_N_CONNECT, msc);
}

/* Check if we have a connection to a specified msc */
bool sccp_conn_ready(struct bsc_msc_data *msc)
{
	OSMO_ASSERT(msc);
	OSMO_ASSERT(msc->msc_con);
	OSMO_ASSERT(msc->msc_con->fsm_reset);
	if (msc->msc_con->fsm_reset->state == ST_CONN)
		return true;

	return false;
}
