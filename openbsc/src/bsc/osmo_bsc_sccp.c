/* Interaction with the SCCP subsystem */
/*
 * (C) 2009-2010 by Holger Hans Peter Freyther <zecke@selfish.org>
 * (C) 2009-2010 by On-Waves
 * All Rights Reserved
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 */

#include <openbsc/gsm_data.h>
#include <openbsc/osmo_bsc.h>
#include <openbsc/osmo_bsc_grace.h>
#include <openbsc/osmo_msc_data.h>
#include <openbsc/debug.h>
#include <openbsc/ipaccess.h>
#include <openbsc/signal.h>

#include <osmocore/gsm0808.h>
#include <osmocore/talloc.h>
#include <osmocore/protocol/gsm_08_08.h>

#include <osmocom/sccp/sccp.h>

/* SCCP helper */
#define SCCP_IT_TIMER 60

static LLIST_HEAD(active_connections);

static void msc_outgoing_sccp_data(struct sccp_connection *conn,
				   struct msgb *msg, unsigned int len)
{
	struct osmo_bsc_sccp_con *bsc_con =
			(struct osmo_bsc_sccp_con *) conn->data_ctx;

	bsc_handle_dt1(bsc_con, msg, len);
}

static void msc_outgoing_sccp_state(struct sccp_connection *conn, int old_state)
{
	struct osmo_bsc_sccp_con *con_data;

	if (conn->connection_state >= SCCP_CONNECTION_STATE_RELEASE_COMPLETE) {
		con_data = (struct osmo_bsc_sccp_con *) conn->data_ctx;
		if(con_data->conn) {
			LOGP(DMSC, LOGL_ERROR,
				"ERROR: The lchan is still associated\n.");
			gsm0808_clear(con_data->conn);
			subscr_con_free(con_data->conn);
			con_data->conn = NULL;
		}

		con_data->sccp = NULL;
		sccp_connection_free(conn);
		bsc_delete_connection(con_data);
	} else if (conn->connection_state == SCCP_CONNECTION_STATE_ESTABLISHED) {
		LOGP(DMSC, LOGL_DEBUG, "Connection established: %p\n", conn);
		con_data = (struct osmo_bsc_sccp_con *) conn->data_ctx;

		bsc_del_timer(&con_data->sccp_cc_timeout);
		bsc_schedule_timer(&con_data->sccp_it_timeout, SCCP_IT_TIMER, 0);
	}
}

static void bsc_sccp_force_free(struct osmo_bsc_sccp_con *data)
{
	if (data->conn) {
		gsm0808_clear(data->conn);
		subscr_con_free(data->conn);
		data->conn = NULL;
	}

	sccp_connection_force_free(data->sccp);
	data->sccp = NULL;
	bsc_delete_connection(data);
}

static void sccp_it_timeout(void *_data)
{
	struct osmo_bsc_sccp_con *data =
		(struct osmo_bsc_sccp_con *) _data;

	sccp_connection_send_it(data->sccp);
	bsc_schedule_timer(&data->sccp_it_timeout, SCCP_IT_TIMER, 0);
}

static void sccp_cc_timeout(void *_data)
{
	struct osmo_bsc_sccp_con *data =
		(struct osmo_bsc_sccp_con *) _data;

	if (data->sccp->connection_state >= SCCP_CONNECTION_STATE_ESTABLISHED)
		return;

	LOGP(DMSC, LOGL_ERROR, "The connection was never established.\n");
	bsc_sccp_force_free(data);
}

static void msc_sccp_write_ipa(struct sccp_connection *conn, struct msgb *msg, void *data)
{
	struct gsm_network *net = (struct gsm_network *) data;
	msc_queue_write(net->msc_data->msc_con, msg, IPAC_PROTO_SCCP);
}

static int msc_sccp_accept(struct sccp_connection *connection, void *data)
{
	LOGP(DMSC, LOGL_DEBUG, "Rejecting incoming SCCP connection.\n");
	return -1;
}

static int msc_sccp_read(struct msgb *msgb, unsigned int length, void *data)
{
	struct gsm_network *net = (struct gsm_network *) data;
	return bsc_handle_udt(net, net->msc_data->msc_con, msgb, length);
}

int bsc_queue_for_msc(struct osmo_bsc_sccp_con *conn, struct msgb *msg)
{
	struct sccp_connection *sccp = conn->sccp;

	if (sccp->connection_state != SCCP_CONNECTION_STATE_ESTABLISHED) {
		LOGP(DMSC, LOGL_ERROR, "The connection is not established.\n");
		msgb_free(msg);
		return -1;
	}

	sccp_connection_write(sccp, msg);
	msgb_free(msg);
	return 0;
}

int bsc_create_new_connection(struct gsm_subscriber_connection *conn)
{
	struct gsm_network *net;
	struct osmo_bsc_sccp_con *bsc_con;
	struct sccp_connection *sccp;

	net = conn->bts->network;
	if (!net->msc_data->msc_con->is_authenticated) {
		LOGP(DMSC, LOGL_ERROR, "Not connected to a MSC. Not forwarding data.\n");
		return -1;
	}

	if (!bsc_grace_allow_new_connection(net)) {
		LOGP(DMSC, LOGL_NOTICE, "BSC in grace period. No new connections.\n");
		return -1;
	}

	sccp = sccp_connection_socket();
	if (!sccp) {
		LOGP(DMSC, LOGL_ERROR, "Failed to allocate memory.\n");
		return -ENOMEM;
	}

	bsc_con = talloc_zero(conn->bts, struct osmo_bsc_sccp_con);
	if (!bsc_con) {
		LOGP(DMSC, LOGL_ERROR, "Failed to allocate.\n");
		sccp_connection_free(sccp);
		return -1;
	}

	/* callbacks */
	sccp->state_cb = msc_outgoing_sccp_state;
	sccp->data_cb = msc_outgoing_sccp_data;
	sccp->data_ctx = bsc_con;

	/* prepare the timers */
	bsc_con->sccp_it_timeout.cb = sccp_it_timeout;
	bsc_con->sccp_it_timeout.data = bsc_con;
	bsc_con->sccp_cc_timeout.cb = sccp_cc_timeout;
	bsc_con->sccp_cc_timeout.data = bsc_con;

	bsc_con->sccp = sccp;
	bsc_con->msc_con = net->msc_data->msc_con;
	bsc_con->conn = conn;
	llist_add(&bsc_con->entry, &active_connections);
	conn->sccp_con = bsc_con;
	return 0;
}

int bsc_open_connection(struct osmo_bsc_sccp_con *conn, struct msgb *msg)
{
	bsc_schedule_timer(&conn->sccp_cc_timeout, 10, 0);
	sccp_connection_connect(conn->sccp, &sccp_ssn_bssap, msg);
	msgb_free(msg);
	return 0;
}

int bsc_delete_connection(struct osmo_bsc_sccp_con *sccp)
{
	if (!sccp)
		return 0;

	if (sccp->conn)
		LOGP(DMSC, LOGL_ERROR, "Should have been cleared.\n");

	llist_del(&sccp->entry);
	bsc_del_timer(&sccp->sccp_it_timeout);
	bsc_del_timer(&sccp->sccp_cc_timeout);
	talloc_free(sccp);
	return 0;
}

static void bsc_close_connections(struct bsc_msc_connection *msc_con)
{
	struct osmo_bsc_sccp_con *con, *tmp;

	llist_for_each_entry_safe(con, tmp, &active_connections, entry)
		bsc_sccp_force_free(con);
}

static int handle_msc_signal(unsigned int subsys, unsigned int signal,
			     void *handler_data, void *signal_data)
{
	struct osmo_msc_data *data;

	if (subsys != SS_MSC)
		return 0;

	data = (struct osmo_msc_data *) signal_data;
	if (signal == S_MSC_LOST)
		bsc_close_connections(data->msc_con);

	return 0;
}

int osmo_bsc_sccp_init(struct gsm_network *gsmnet)
{
	sccp_set_log_area(DSCCP);
	sccp_system_init(msc_sccp_write_ipa, gsmnet);
	sccp_connection_set_incoming(&sccp_ssn_bssap, msc_sccp_accept, NULL);
	sccp_set_read(&sccp_ssn_bssap, msc_sccp_read, gsmnet);

	register_signal_handler(SS_MSC, handle_msc_signal, gsmnet);

	return 0;
}
