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

#include <osmocom/core/utils.h>
#include <osmocom/core/logging.h>
#include <osmocom/sigtran/osmo_ss7.h>
#include <osmocom/sigtran/sccp_sap.h>
#include <osmocom/sccp/sccp_types.h>
#include <osmocom/core/linuxlist.h>
#include <osmocom/gsm/gsm0808.h>
#include <osmocom/core/msgb.h>
#include <openbsc/bsc_msc_data.h>
#include <openbsc/debug.h>
#include <openbsc/osmo_bsc.h>
#include <openbsc/osmo_bsc_grace.h>
#include <openbsc/osmo_bsc_sigtran.h>
#include <openbsc/a_reset.h>
#include <openbsc/gsm_04_80.h>

/* A pointer to a list with all involved MSCs
 * (a copy of the pointer location submitted with osmo_bsc_sigtran_init() */
static struct llist_head *msc_list;

#define RESET_INTERVAL 1	/* sek */
#define SCCP_MSG_MAXSIZE 1024

static LLIST_HEAD(active_connections);

/* Helper function to Check if the given connection id is already assigned */
static struct osmo_bsc_sccp_con *get_bsc_conn_by_conn_id(int conn_id)
{
	conn_id &= 0xFFFFFF;
	struct osmo_bsc_sccp_con *bsc_con;

	llist_for_each_entry(bsc_con, &active_connections, entry) {
		if (bsc_con->conn_id == conn_id)
			return bsc_con;
	}

	return NULL;
}

/* Pick a free connection id */
static int pick_free_conn_id(struct bsc_msc_data *msc)
{
	int conn_id = msc->msc_con->conn_id_counter;
	int i;

	for (i = 0; i < 0xFFFFFF; i++) {
		conn_id++;
		conn_id &= 0xFFFFFF;
		if (get_bsc_conn_by_conn_id(conn_id) == false) {
			msc->msc_con->conn_id_counter = conn_id;
			return conn_id;
		}
	}

	return -1;
}

/* Send reset to MSC */
static void osmo_bsc_sigtran_tx_reset(struct bsc_msc_data *msc)
{
	struct msgb *msg;
	LOGP(DMSC, LOGL_NOTICE, "Sending RESET to MSC No.: %i\n", msc->nr);
	msg = gsm0808_create_reset();
	osmo_sccp_tx_unitdata_msg(msc->msc_con->sccp_user, &msc->msc_con->g_calling_addr,
				  &msc->msc_con->g_called_addr, msg);
}

/* Send reset-ack to MSC */
void osmo_bsc_sigtran_tx_reset_ack(struct bsc_msc_data *msc)
{
	struct msgb *msg;
	LOGP(DMSC, LOGL_NOTICE, "Sending RESET RACK to MSC No.: %i\n", msc->nr);
	msg = gsm0808_create_reset_ack();
	osmo_sccp_tx_unitdata_msg(msc->msc_con->sccp_user, &msc->msc_con->g_calling_addr,
				  &msc->msc_con->g_called_addr, msg);
}


/* Find an MSC by its sigtran point code */
static struct bsc_msc_data *get_msc_by_addr(struct osmo_sccp_addr *calling_addr)
{
	struct bsc_msc_data *msc;
	llist_for_each_entry(msc, msc_list, entry) {
		if (memcmp(calling_addr, &msc->msc_con->g_called_addr, sizeof(*calling_addr)) == 0)
			return msc;
	}

	LOGP(DMSC, LOGL_ERROR, "Unable to find MSC data under address: %s\n", osmo_sccp_addr_dump(calling_addr));
	return NULL;
}

/* Send data to MSC, use the connection id which MSC it is */
static int handle_data_from_msc(int conn_id, struct msgb *msg)
{
	struct osmo_bsc_sccp_con *bsc_con = get_bsc_conn_by_conn_id(conn_id);
	int rc = -EINVAL;

	if (bsc_con) {
		msg->l3h = msgb_l2(msg);
		rc = bsc_handle_dt1(bsc_con, msg, msgb_l2len(msg));
	} else
		LOGP(DMSC, LOGL_NOTICE, "incoming data from unknown connection id: %i\n", conn_id);

	return rc;
}

/* Sent unitdata to MSC, use the point code to determine which MSC it is */
static int handle_unitdata_from_msc(struct osmo_sccp_addr *calling_addr, struct msgb *msg)
{
	struct bsc_msc_data *msc = get_msc_by_addr(calling_addr);
	int rc = -EINVAL;

	if (msc) {
		msg->l3h = msgb_l2(msg);
		rc = bsc_handle_udt(msc, msg, msgb_l2len(msg));
	} else
		LOGP(DMSC, LOGL_NOTICE, "incoming unitdata data from unknown remote address: %s\n",
		     osmo_sccp_addr_dump(calling_addr));

	return rc;
}

/* Callback function, called by the SSCP stack when data arrives */
static int sccp_sap_up(struct osmo_prim_hdr *oph, void *_scu)
{
	struct osmo_scu_prim *scu_prim = (struct osmo_scu_prim *)oph;
	struct osmo_sccp_user *scu = _scu;
	struct osmo_bsc_sccp_con *bsc_con;
	int rc = 0;

	switch (OSMO_PRIM_HDR(&scu_prim->oph)) {
	case OSMO_PRIM(OSMO_SCU_PRIM_N_UNITDATA, PRIM_OP_INDICATION):
		/* Handle inbound UNITDATA */
		DEBUGP(DMSC, "N-UNITDATA.ind(%s)\n", osmo_hexdump(msgb_l2(oph->msg), msgb_l2len(oph->msg)));
		rc = handle_unitdata_from_msc(&scu_prim->u.unitdata.calling_addr, oph->msg);
		break;

	case OSMO_PRIM(OSMO_SCU_PRIM_N_CONNECT, PRIM_OP_INDICATION):
		/* Handle (Reject) inbound connections */
		DEBUGP(DMSC, "N-CONNECT.ind(X->%u)\n", scu_prim->u.connect.conn_id);
		LOGP(DMSC, LOGL_DEBUG, "Rejecting inbound SCCP connection...\n");
		rc = osmo_sccp_tx_disconn(scu, scu_prim->u.connect.conn_id, &scu_prim->u.connect.called_addr, 0);
		break;

	case OSMO_PRIM(OSMO_SCU_PRIM_N_CONNECT, PRIM_OP_CONFIRM):
		/* Handle outbound connection confirmation */
		if (msgb_l2len(oph->msg) > 0) {
			DEBUGP(DMSC, "N-CONNECT.cnf(%u, %s)\n", scu_prim->u.connect.conn_id,
			       osmo_hexdump(msgb_l2(oph->msg), msgb_l2len(oph->msg)));
			rc = handle_data_from_msc(scu_prim->u.connect.conn_id, oph->msg);
		} else
			DEBUGP(DRANAP, "N-CONNECT.cnf(%u)\n", scu_prim->u.connect.conn_id);
		break;

	case OSMO_PRIM(OSMO_SCU_PRIM_N_DATA, PRIM_OP_INDICATION):
		/* Handle incoming connection oriented data */
		DEBUGP(DMSC, "N-DATA.ind(%u, %s)\n", scu_prim->u.data.conn_id,
		       osmo_hexdump(msgb_l2(oph->msg), msgb_l2len(oph->msg)));

		/* Incoming data is a sign of a vital connection */
		bsc_con = get_bsc_conn_by_conn_id(scu_prim->u.disconnect.conn_id);
		if (bsc_con)
			a_reset_conn_success(bsc_con->msc->msc_con->reset);

		rc = handle_data_from_msc(scu_prim->u.data.conn_id, oph->msg);
		break;

	case OSMO_PRIM(OSMO_SCU_PRIM_N_DISCONNECT, PRIM_OP_INDICATION):
		/* indication of disconnect */
		if (msgb_l2len(oph->msg) > 0) {
			DEBUGP(DMSC, "N-DISCONNECT.ind(%u, %s, cause=%i)\n", scu_prim->u.disconnect.conn_id,
			       osmo_hexdump(msgb_l2(oph->msg), msgb_l2len(oph->msg)), scu_prim->u.disconnect.cause);
			handle_data_from_msc(scu_prim->u.disconnect.conn_id, oph->msg);
		} else
			DEBUGP(DRANAP, "N-DISCONNECT.ind(%u, cause=%i)\n", scu_prim->u.disconnect.conn_id,
			       scu_prim->u.disconnect.cause);

		bsc_con = get_bsc_conn_by_conn_id(scu_prim->u.disconnect.conn_id);
		if (bsc_con) {
			/* We might have a connectivity problem. Maybe we need to go
			 * through the reset procedure again? */
			if (scu_prim->u.disconnect.cause == 0)
				a_reset_conn_fail(bsc_con->msc->msc_con->reset);

			rc = osmo_bsc_sigtran_del_conn(bsc_con);
		}
		break;

	default:
		LOGP(DMSC, LOGL_ERROR, "Unhandled SIGTRAN primitive: %u:%u\n", oph->primitive, oph->operation);
		break;
	}

	msgb_free(oph->msg);
	return rc;
}

/* Allocate resources to make a new connection oriented sigtran connection
 * (not the connection ittself!) */
enum bsc_con osmo_bsc_sigtran_new_conn(struct gsm_subscriber_connection *conn, struct bsc_msc_data *msc)
{
	struct osmo_bsc_sccp_con *bsc_con;
	int conn_id;

	OSMO_ASSERT(conn);
	OSMO_ASSERT(msc);

	LOGP(DMSC, LOGL_NOTICE, "Initalizing resources for new SIGTRAN connection to MSC No.: %i...\n", msc->nr);

	if (a_reset_conn_ready(msc->msc_con->reset) == false) {
		LOGP(DMSC, LOGL_ERROR, "MSC is not connected. Dropping.\n");
		return BSC_CON_REJECT_NO_LINK;
	}

	if (!bsc_grace_allow_new_connection(conn->bts->network, conn->bts)) {
		LOGP(DMSC, LOGL_NOTICE, "BSC in grace period. No new connections.\n");
		return BSC_CON_REJECT_RF_GRACE;
	}

	bsc_con = talloc_zero(conn->bts, struct osmo_bsc_sccp_con);
	if (!bsc_con) {
		LOGP(DMSC, LOGL_ERROR, "Failed to allocate new SIGTRAN connection.\n");
		return BSC_CON_NO_MEM;
	}

	bsc_con->msc = msc;
	bsc_con->conn = conn;
	llist_add_tail(&bsc_con->entry, &active_connections);
	conn->sccp_con = bsc_con;

	/* Pick a free connection id */
	conn_id = pick_free_conn_id(msc);
	if (conn_id < 0)
		return BSC_CON_REJECT_NO_LINK;
	bsc_con->conn_id = conn_id;

	LOGP(DMSC, LOGL_NOTICE, "Allocated new connection id: %i\n", conn_id);

	return BSC_CON_SUCCESS;
}

/* Open a new connection oriented sigtran connection */
int osmo_bsc_sigtran_open_conn(struct osmo_bsc_sccp_con *conn, struct msgb *msg)
{
	struct bsc_msc_data *msc;
	int conn_id;
	int rc;

	OSMO_ASSERT(conn);
	OSMO_ASSERT(msg);
	OSMO_ASSERT(conn->msc);

	msc = conn->msc;

	if (a_reset_conn_ready(msc->msc_con->reset) == false) {
		LOGP(DMSC, LOGL_ERROR, "MSC is not connected. Dropping.\n");
		return -EINVAL;
	}

	conn_id = conn->conn_id;
	LOGP(DMSC, LOGL_NOTICE, "Opening new SIGTRAN connection (id=%i) to MSC No.: %i...\n", conn_id, msc->nr);

	rc = osmo_sccp_tx_conn_req_msg(msc->msc_con->sccp_user, conn_id, &msc->msc_con->g_calling_addr,
				       &msc->msc_con->g_called_addr, msg);

	return rc;
}

/* Send data to MSC */
int osmo_bsc_sigtran_send(struct osmo_bsc_sccp_con *conn, struct msgb *msg)
{
	int conn_id;
	int rc;
	struct bsc_msc_data *msc;

	OSMO_ASSERT(conn);
	OSMO_ASSERT(msg);
	OSMO_ASSERT(conn->msc);

	msc = conn->msc;

	if (a_reset_conn_ready(msc->msc_con->reset) == false) {
		LOGP(DMSC, LOGL_ERROR, "MSC is not connected. Dropping.\n");
		return -EINVAL;
	}

	conn_id = conn->conn_id;

	LOGP(DMSC, LOGL_DEBUG, "Sending connection (id=%i) oriented data to MSC No.: %i...\n", conn_id, msc->nr);

	rc = osmo_sccp_tx_data_msg(msc->msc_con->sccp_user, conn_id, msg);

	return rc;
}

/* Delete a connection from the list with open connections
 * (called by osmo_bsc_api.c on failing open connections and
 * locally, when a connection is closed by the MSC */
int osmo_bsc_sigtran_del_conn(struct osmo_bsc_sccp_con *conn)
{
	if (!conn)
		return 0;

	if (conn->conn) {
		LOGP(DMSC, LOGL_ERROR,
		     "sccp connection (id=%i) not cleared (gsm subscriber connection still active) -- forcefully clearing it now!\n",
		     conn->conn_id);
		bsc_subscr_con_free(conn->conn);
		conn->conn = NULL;

		/* This bahaviour might be caused by a bad connection. Maybe we
		 * will have to go through the reset procedure again */
		a_reset_conn_fail(conn->msc->msc_con->reset);
	}

	llist_del(&conn->entry);
	talloc_free(conn);

	return 0;
}

static void bsc_notify_msc_lost(struct osmo_bsc_sccp_con *con)
{
	struct gsm_subscriber_connection *conn = con->conn;

	/* send USSD notification if string configured and con->data is set */
	if (!conn)
		return;

	/* check for config string */
	if (!con->msc->ussd_msc_lost_txt)
		return;
	if (con->msc->ussd_msc_lost_txt[0] == '\0')
		return;

	/* send USSD notification */
	bsc_send_ussd_notify(conn, 1, conn->sccp_con->msc->ussd_msc_lost_txt);
	bsc_send_ussd_release_complete(conn);
}

/* Close all open sigtran connections and channels */
void osmo_bsc_sigtran_reset(struct bsc_msc_data *msc)
{
	struct osmo_bsc_sccp_con *conn;
	struct osmo_bsc_sccp_con *conn_temp;
	OSMO_ASSERT(msc);

	/* Close all open connections */
	llist_for_each_entry_safe(conn, conn_temp, &active_connections, entry) {
		if (conn->conn)
			gsm0808_clear(conn->conn);
		bsc_notify_msc_lost(conn);
		osmo_bsc_sigtran_del_conn(conn);
	}
	msc->msc_con->conn_id_counter = 0;
}

/* Callback function: Close all open connections */
static void osmo_bsc_sigtran_reset_cb(void *priv)
{
	struct bsc_msc_data *msc = (struct bsc_msc_data*) priv;

	/* Shut down all ongoint traffic */
	osmo_bsc_sigtran_reset(msc);

	/* Send reset to MSC */
	osmo_bsc_sigtran_tx_reset(msc);
}

/* Initalize osmo sigtran backhaul */
int osmo_bsc_sigtran_init(struct llist_head *mscs)
{
	/* FIXME: Remove hardcoded IP-Addresses */
	struct bsc_msc_data *msc;
	char msc_name[256];

	OSMO_ASSERT(mscs);

	osmo_ss7_init();

	msc_list = mscs;

	llist_for_each_entry(msc, msc_list, entry) {
		snprintf(msc_name, sizeof(msc_name), "MSC No.: %u", msc->nr);
		LOGP(DMSC, LOGL_NOTICE, "Initalizing SCCP connection to %s\n", msc_name);

		/* SCCP Protocol stack */
		msc->msc_con->sccp =
		    osmo_sccp_simple_client(NULL, msc_name, msc->msc_con->g_calling_addr.pc,
					    OSMO_SS7_ASP_PROT_M3UA, 0, NULL, M3UA_PORT, "127.0.0.1");
		msc->msc_con->sccp_user =
		    osmo_sccp_user_bind(msc->msc_con->sccp, msc_name, sccp_sap_up, SCCP_SSN_BSSAP);

		/* Start MSC reset procedure */
		msc->msc_con->reset = a_reset_alloc(NULL, msc_name, osmo_bsc_sigtran_reset_cb, msc);
	}

	return 0;
}
