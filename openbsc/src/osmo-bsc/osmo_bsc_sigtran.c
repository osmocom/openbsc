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
#define CS7_POINTCODE_DEFAULT_OFFSET 2

/* Internal list with connections we currently maintain. This
 * list is of type struct osmo_bsc_sccp_con */
static LLIST_HEAD(active_connections);

/* The SCCP stack will not assign connection IDs to us automatically, we
 * will do this ourselves using a counter variable, that counts one up
 * for every new connection */
static uint32_t conn_id_counter;

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
static int pick_free_conn_id(const struct bsc_msc_data *msc)
{
	int conn_id = conn_id_counter;
	int i;

	for (i = 0; i < 0xFFFFFF; i++) {
		conn_id++;
		conn_id &= 0xFFFFFF;
		if (get_bsc_conn_by_conn_id(conn_id) == false) {
			conn_id_counter = conn_id;
			return conn_id;
		}
	}

	return -1;
}

/* Send reset to MSC */
static void osmo_bsc_sigtran_tx_reset(const struct bsc_msc_data *msc)
{
	struct osmo_ss7_instance *ss7;
	struct msgb *msg;

	ss7 = osmo_ss7_instance_find(msc->a.cs7_instance);
	OSMO_ASSERT(ss7);
	LOGP(DMSC, LOGL_NOTICE, "Sending RESET to MSC: %s\n", osmo_sccp_addr_name(ss7, &msc->a.msc_addr));
	msg = gsm0808_create_reset();
	osmo_sccp_tx_unitdata_msg(msc->a.sccp_user, &msc->a.bsc_addr,
				  &msc->a.msc_addr, msg);
}

/* Send reset-ack to MSC */
void osmo_bsc_sigtran_tx_reset_ack(const struct bsc_msc_data *msc)
{
	struct osmo_ss7_instance *ss7;
	struct msgb *msg;
	OSMO_ASSERT(msc);

	ss7 = osmo_ss7_instance_find(msc->a.cs7_instance);
	OSMO_ASSERT(ss7);
	LOGP(DMSC, LOGL_NOTICE, "Sending RESET ACK to MSC: %s\n", osmo_sccp_addr_name(ss7, &msc->a.msc_addr));
	msg = gsm0808_create_reset_ack();
	osmo_sccp_tx_unitdata_msg(msc->a.sccp_user, &msc->a.bsc_addr,
				  &msc->a.msc_addr, msg);
}

/* Find an MSC by its sigtran point code */
static struct bsc_msc_data *get_msc_by_addr(const struct osmo_sccp_addr *msc_addr)
{
	struct osmo_ss7_instance *ss7;
	struct bsc_msc_data *msc;
	llist_for_each_entry(msc, msc_list, entry) {
		if (memcmp(msc_addr, &msc->a.msc_addr, sizeof(*msc_addr)) == 0)
			return msc;
	}

	ss7 = osmo_ss7_instance_find(msc->a.cs7_instance);
	OSMO_ASSERT(ss7);
	LOGP(DMSC, LOGL_ERROR, "Unable to find MSC data under address: %s\n", osmo_sccp_addr_name(ss7, msc_addr));
	return NULL;
}

/* Send data to MSC, use the connection id which MSC it is */
static int handle_data_from_msc(int conn_id, struct msgb *msg)
{
	struct osmo_bsc_sccp_con *bsc_con = get_bsc_conn_by_conn_id(conn_id);
	int rc = -EINVAL;

	if (bsc_con) {
		msg->l3h = msgb_l2(msg);
		rc = bsc_handle_dt(bsc_con, msg, msgb_l2len(msg));
	} else
		LOGP(DMSC, LOGL_NOTICE, "incoming data from unknown connection id: %i\n", conn_id);

	return rc;
}

/* Sent unitdata to MSC, use the point code to determine which MSC it is */
static int handle_unitdata_from_msc(const struct osmo_sccp_addr *msc_addr, struct msgb *msg,
				    const struct osmo_sccp_user *scu)
{
	struct osmo_ss7_instance *ss7;
	struct bsc_msc_data *msc = get_msc_by_addr(msc_addr);
	int rc = -EINVAL;

	if (msc) {
		msg->l3h = msgb_l2(msg);
		rc = bsc_handle_udt(msc, msg, msgb_l2len(msg));
	} else {
		ss7 = osmo_sccp_get_ss7(osmo_sccp_get_sccp(scu));
		OSMO_ASSERT(ss7);
		LOGP(DMSC, LOGL_NOTICE, "incoming unitdata data from unknown remote address: %s\n",
		     osmo_sccp_addr_name(ss7, msc_addr));
	}
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
		rc = handle_unitdata_from_msc(&scu_prim->u.unitdata.calling_addr, oph->msg, scu);
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
			a_reset_conn_success(bsc_con->msc->a.reset);

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
				a_reset_conn_fail(bsc_con->msc->a.reset);

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
	struct osmo_ss7_instance *ss7;
	struct osmo_bsc_sccp_con *bsc_con;
	int conn_id;

	OSMO_ASSERT(conn);
	OSMO_ASSERT(msc);

	ss7 = osmo_ss7_instance_find(msc->a.cs7_instance);
	OSMO_ASSERT(ss7);
	LOGP(DMSC, LOGL_NOTICE, "Initializing resources for new SIGTRAN connection to MSC: %s...\n",
	     osmo_sccp_addr_name(ss7, &msc->a.msc_addr));

	if (a_reset_conn_ready(msc->a.reset) == false) {
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
int osmo_bsc_sigtran_open_conn(const struct osmo_bsc_sccp_con *conn, struct msgb *msg)
{
	struct osmo_ss7_instance *ss7;
	struct bsc_msc_data *msc;
	int conn_id;
	int rc;

	OSMO_ASSERT(conn);
	OSMO_ASSERT(msg);
	OSMO_ASSERT(conn->msc);

	msc = conn->msc;

	if (a_reset_conn_ready(msc->a.reset) == false) {
		LOGP(DMSC, LOGL_ERROR, "MSC is not connected. Dropping.\n");
		return -EINVAL;
	}

	conn_id = conn->conn_id;
	ss7 = osmo_ss7_instance_find(msc->a.cs7_instance);
	OSMO_ASSERT(ss7);
	LOGP(DMSC, LOGL_NOTICE, "Opening new SIGTRAN connection (id=%i) to MSC: %s\n", conn_id,
	     osmo_sccp_addr_name(ss7, &msc->a.msc_addr));

	rc = osmo_sccp_tx_conn_req_msg(msc->a.sccp_user, conn_id, &msc->a.bsc_addr,
				       &msc->a.msc_addr, msg);

	return rc;
}

/* Send data to MSC */
int osmo_bsc_sigtran_send(const struct osmo_bsc_sccp_con *conn, struct msgb *msg)
{
	struct osmo_ss7_instance *ss7;
	int conn_id;
	int rc;
	struct bsc_msc_data *msc;

	OSMO_ASSERT(conn);
	OSMO_ASSERT(msg);
	OSMO_ASSERT(conn->msc);

	msc = conn->msc;

	if (a_reset_conn_ready(msc->a.reset) == false) {
		LOGP(DMSC, LOGL_ERROR, "MSC is not connected. Dropping.\n");
		return -EINVAL;
	}

	conn_id = conn->conn_id;

	ss7 = osmo_ss7_instance_find(msc->a.cs7_instance);
	OSMO_ASSERT(ss7);
	LOGP(DMSC, LOGL_DEBUG, "Sending connection (id=%i) oriented data to MSC: %si\n",
	     conn_id, osmo_sccp_addr_name(ss7, &msc->a.msc_addr));

	rc = osmo_sccp_tx_data_msg(msc->a.sccp_user, conn_id, msg);

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
		a_reset_conn_fail(conn->msc->a.reset);
	}

	llist_del(&conn->entry);
	talloc_free(conn);

	return 0;
}

/* Send an USSD notification in case we loose the connection to the MSC */
static void bsc_notify_msc_lost(const struct osmo_bsc_sccp_con *conn)
{
	struct gsm_subscriber_connection *subscr_conn;

	/* Check if sccp conn is still present */
	if (!conn)
		return;
	subscr_conn = conn->conn;

	/* send USSD notification if string configured and conn->data is set */
	if (!subscr_conn)
		return;

	/* check for config string */
	if (!conn->msc->ussd_msc_lost_txt)
		return;
	if (conn->msc->ussd_msc_lost_txt[0] == '\0')
		return;

	/* send USSD notification */
	bsc_send_ussd_notify(subscr_conn, 1, subscr_conn->sccp_con->msc->ussd_msc_lost_txt);
	bsc_send_ussd_release_complete(subscr_conn);
}

/* Close all open sigtran connections and channels */
void osmo_bsc_sigtran_reset(const struct bsc_msc_data *msc)
{
	struct osmo_bsc_sccp_con *conn;
	struct osmo_bsc_sccp_con *conn_temp;
	OSMO_ASSERT(msc);

	/* Close all open connections */
	llist_for_each_entry_safe(conn, conn_temp, &active_connections, entry) {

		/* We only may close connections which actually belong to this
		 * MSC. All other open connections are left untouched */
		if (conn->msc == msc) {
			/* Notify active connection users via USSD that the MSC is down */
			bsc_notify_msc_lost(conn);

			/* Take down all occopied RF channels */
			if (conn->conn)
				gsm0808_clear(conn->conn);

			/* Disconnect all Sigtran connections */
			osmo_sccp_tx_disconn(msc->a.sccp_user, conn->conn_id, &msc->a.bsc_addr, 0);

			/* Delete subscriber connection */
			osmo_bsc_sigtran_del_conn(conn);
		}
	}
}

/* Callback function: Close all open connections */
static void osmo_bsc_sigtran_reset_cb(const void *priv)
{
	struct bsc_msc_data *msc = (struct bsc_msc_data*) priv;

	/* Shut down all ongoing traffic */
	osmo_bsc_sigtran_reset(msc);

	/* Send reset to MSC */
	osmo_bsc_sigtran_tx_reset(msc);
}

/* Default point-code to be used as local address (BSC) */
#define BSC_DEFAULT_PC "0.23.3"

/* Default point-code to be used as remote address (MSC) */
#define MSC_DEFAULT_PC "0.23.1"

/* Initalize osmo sigtran backhaul */
int osmo_bsc_sigtran_init(struct llist_head *mscs)
{
	bool free_attempt_used = false;
	bool fail_on_next_invalid_cfg = false;

	struct bsc_msc_data *msc;
	char msc_name[32];
	uint32_t default_pc;

	OSMO_ASSERT(mscs);
	msc_list = mscs;

	llist_for_each_entry(msc, msc_list, entry) {
		snprintf(msc_name, sizeof(msc_name), "msc-%u", msc->nr);
		LOGP(DMSC, LOGL_NOTICE, "Initializing SCCP connection to MSC %s\n", msc_name);

		/* Check if the VTY could determine a valid CS7 instance,
		 * use safe default in case none is set */
		if (msc->a.cs7_instance_valid == false) {
			msc->a.cs7_instance = 0;
			if (fail_on_next_invalid_cfg)
				goto fail_auto_cofiguration;
			free_attempt_used = true;
		}
		LOGP(DMSC, LOGL_NOTICE, "CS7 Instance identifier, A-Interface: %u\n", msc->a.cs7_instance);

		/* Pre-Check if there is an ss7 instance present */
		if (osmo_ss7_instance_find(msc->a.cs7_instance) == NULL) {
			if (fail_on_next_invalid_cfg)
				goto fail_auto_cofiguration;
			free_attempt_used = true;
		}

		/* SS7 Protocol stack */
		default_pc = osmo_ss7_pointcode_parse(NULL, BSC_DEFAULT_PC);
		msc->a.sccp =
		    osmo_sccp_simple_client_on_ss7_id(msc, msc->a.cs7_instance, msc_name, default_pc,
						      OSMO_SS7_ASP_PROT_M3UA, 0, NULL, 0, NULL);
		if (!msc->a.sccp)
			return -EINVAL;

		/* Check if the sccp-address fullfills minimum requirements (SSN+PC is present,
		 * automatically recover addresses if the addresses are not set up properly) */
		if (!osmo_sccp_check_addr(&msc->a.bsc_addr, OSMO_SCCP_ADDR_T_SSN | OSMO_SCCP_ADDR_T_PC)) {
			if (fail_on_next_invalid_cfg)
				goto fail_auto_cofiguration;
			free_attempt_used = true;

			LOGP(DMSC, LOGL_NOTICE,
			     "A-interface: invalid or missing local (BSC) SCCP address (a.bsc_addr=%s)\n",
			     osmo_sccp_addr_name(osmo_ss7_instance_find(msc->a.cs7_instance), &msc->a.bsc_addr));
			osmo_sccp_local_addr_by_instance(&msc->a.bsc_addr, msc->a.sccp, SCCP_SSN_BSSAP);
			LOGP(DMSC, LOGL_NOTICE,
			     "A-interface: using automatically generated local (BSC) SCCP address (a.bsc_addr=%s)\n",
			     osmo_sccp_addr_name(osmo_ss7_instance_find(msc->a.cs7_instance), &msc->a.bsc_addr));
		} else {
			LOGP(DMSC, LOGL_NOTICE,
			     "A-interface: using local (BSC) automatically SCCP address (a.msc_addr=%s)\n",
			     osmo_sccp_addr_name(osmo_ss7_instance_find(msc->a.cs7_instance), &msc->a.bsc_addr));
		}

		if (!osmo_sccp_check_addr(&msc->a.msc_addr, OSMO_SCCP_ADDR_T_SSN | OSMO_SCCP_ADDR_T_PC)) {
			if (fail_on_next_invalid_cfg)
				goto fail_auto_cofiguration;
			free_attempt_used = true;

			LOGP(DMSC, LOGL_NOTICE,
			     "A-interface: invalid or missing remote (MSC) SCCP address for the MSC (a.msc_addr=%s)\n",
			     osmo_sccp_addr_name(osmo_ss7_instance_find(msc->a.cs7_instance), &msc->a.msc_addr));
			osmo_sccp_local_addr_by_instance(&msc->a.msc_addr, msc->a.sccp, SCCP_SSN_BSSAP);
			msc->a.msc_addr.pc = osmo_ss7_pointcode_parse(NULL, MSC_DEFAULT_PC);
			LOGP(DMSC, LOGL_NOTICE,
			     "A-interface: using automatically generated remote (MSC) SCCP address (a.msc_addr=%s)\n",
			     osmo_sccp_addr_name(osmo_ss7_instance_find(msc->a.cs7_instance), &msc->a.msc_addr));
			free_attempt_used = true;
		} else {
			LOGP(DMSC, LOGL_NOTICE,
			     "A-interface: using remote (MSC) automatically SCCP address (a.msc_addr=%s)\n",
			     osmo_sccp_addr_name(osmo_ss7_instance_find(msc->a.cs7_instance), &msc->a.msc_addr));
		}

		/* Bind SCCP user */
		msc->a.sccp_user = osmo_sccp_user_bind(msc->a.sccp, msc_name, sccp_sap_up, msc->a.bsc_addr.ssn);
		if (!msc->a.sccp_user)
			return -EINVAL;

		/* Start MSC-Reset procedure */
		msc->a.reset = a_reset_alloc(msc, msc_name, osmo_bsc_sigtran_reset_cb, msc);
		if (!msc->a.reset)
			return -EINVAL;

		/* If we have detected that the SS7 configuration of the MSC we have just initalized
		 * was incomplete or completely missing, we can not tolerate another incomplete
		 * configuration. The reson for this is that we do only specify exactly one default
		 * pointcode pair. We also specify localhost as default IP-Address. If we have wanted
		 * to support multiple MSCs with automatic configuration we would be forced to invent
		 * a complex ruleset how to allocate the pointcodes and respective IP-Addresses.
		 * Furthermore, the situation where a single BSC is connected to multiple MSCs
		 * is a very rare situation anyway. In this case we expect the user to experienced
		 * enough to create a valid SS7/CS7 VTY configuration that does not lack any
		 * components */
		if (free_attempt_used)
			fail_on_next_invalid_cfg = true;
	}

	return 0;

fail_auto_cofiguration:
	LOGP(DMSC, LOGL_ERROR,
	     "A-interface: More than one invalid/inclomplete configuration detected, unable to revover - check config file!\n");
	return -EINVAL;
}
