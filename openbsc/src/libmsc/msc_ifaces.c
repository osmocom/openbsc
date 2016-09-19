/* Implementation for MSC decisions which interface to send messages out on. */

/* (C) 2016 by sysmocom s.m.f.c GmbH <info@sysmocom.de>
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
 */

#include <osmocom/core/logging.h>

#include <openbsc/debug.h>
#include <openbsc/gsm_data.h>
#include <openbsc/msc_ifaces.h>
#include <openbsc/iu.h>
#include <openbsc/gsm_subscriber.h>
#include <openbsc/transaction.h>
#include <openbsc/mgcp.h>
#include <openbsc/mgcpgw_client.h>

#include "../../bscconfig.h"

extern struct msgb *ranap_new_msg_rab_assign_voice(uint8_t rab_id,
						   uint32_t rtp_ip,
						   uint16_t rtp_port,
						   bool use_x213_nsap);

static int msc_tx(struct gsm_subscriber_connection *conn, struct msgb *msg)
{
	switch (conn->via_iface) {
	case IFACE_A:
		msg->dst = conn;
		return a_tx(msg);

	case IFACE_IU:
		msg->dst = conn->iu.ue_ctx;
		return iu_tx(msg, 0);

	default:
		LOGP(DMSC, LOGL_ERROR,
		     "msc_tx(): conn->via_iface invalid (%d)\n",
		     conn->via_iface);
		return -1;
	}
}


int msc_tx_dtap(struct gsm_subscriber_connection *conn,
		struct msgb *msg)
{
	return msc_tx(conn, msg);
}


/* 9.2.5 CM service accept */
int msc_gsm48_tx_mm_serv_ack(struct gsm_subscriber_connection *conn)
{
	struct msgb *msg = gsm48_msgb_alloc_name("GSM 04.08 SERV ACC");
	struct gsm48_hdr *gh = (struct gsm48_hdr *) msgb_put(msg, sizeof(*gh));

	gh->proto_discr = GSM48_PDISC_MM;
	gh->msg_type = GSM48_MT_MM_CM_SERV_ACC;

	DEBUGP(DMM, "-> CM SERVICE ACCEPT\n");

	return msc_tx_dtap(conn, msg);
}

/* 9.2.6 CM service reject */
int msc_gsm48_tx_mm_serv_rej(struct gsm_subscriber_connection *conn,
			     enum gsm48_reject_value value)
{
	struct msgb *msg;

	msg = gsm48_create_mm_serv_rej(value);
	if (!msg) {
		LOGP(DMM, LOGL_ERROR, "Failed to allocate CM Service Reject.\n");
		return -1;
	}

	DEBUGP(DMM, "-> CM SERVICE Reject cause: %d\n", value);

	return msc_tx_dtap(conn, msg);
}

int msc_tx_common_id(struct gsm_subscriber_connection *conn)
{
	/* Common ID is only sent over IuCS */
	if (conn->via_iface != IFACE_IU)
		return 0;

#ifdef BUILD_IU
	return iu_tx_common_id(conn->iu.ue_ctx, conn->subscr->imsi);
#else
	LOGP(DMM, LOGL_ERROR,
	     "Cannot send CommonID: IFACE_IU but IuCS support not built\n");
	return -ENOTSUP;
#endif
}

#ifdef BUILD_IU
static int iu_rab_act_cs(struct ue_conn_ctx *uectx, uint8_t rab_id,
			 uint32_t rtp_ip, uint16_t rtp_port,
			 bool use_x213_nsap)
{
	struct msgb *msg;

	LOGP(DIUCS, LOGL_DEBUG, "Assigning RAB: rab_id=%d, rtp=%x:%u,"
	     " use_x213_nsap=%d\n", rab_id, rtp_ip, rtp_port, use_x213_nsap);

	msg = ranap_new_msg_rab_assign_voice(rab_id, rtp_ip, rtp_port,
					     use_x213_nsap);
	msg->l2h = msg->data;

	return iu_rab_act(uectx, msg);
}

static int conn_iu_rab_act_cs(struct gsm_trans *trans)
{
	struct gsm_subscriber_connection *conn = trans->conn;
	struct ue_conn_ctx *uectx = conn->iu.ue_ctx;

	/* HACK. where to scope the RAB Id? At the conn / subscriber /
	 * ue_conn_ctx? */
	static uint8_t next_rab_id = 1;
	conn->iu.rab_id = next_rab_id ++;

	conn->iu.mgcp_rtp_endpoint =
		mgcpgw_client_next_endpoint(conn->network->mgcpgw.client);
	/* HACK: the addresses should be known from CRCX response
	 * and config. */
	conn->iu.mgcp_rtp_port_ue = 4000 + 2 * conn->iu.mgcp_rtp_endpoint;
	conn->iu.mgcp_rtp_port_cn = 16000 + 2 * conn->iu.mgcp_rtp_endpoint;

	/* Establish the RTP stream first as looping back to the originator.
	 * The MDCX will patch through to the counterpart. TODO: play a ring
	 * tone instead. */
	mgcpgw_client_tx_crcx(conn->network->mgcpgw.client,
			      conn->iu.mgcp_rtp_endpoint, trans->callref,
			      MGCP_CONN_LOOPBACK);

	uint32_t rtp_ip =
		mgcpgw_client_remote_addr_n(conn->network->mgcpgw.client);

	return iu_rab_act_cs(uectx, conn->iu.rab_id, rtp_ip,
			     conn->iu.mgcp_rtp_port_ue, 1);
	/* use_x213_nsap == 0 for ip.access nano3G */
}
#endif

int msc_call_assignment(struct gsm_trans *trans)
{
	struct gsm_subscriber_connection *conn = trans->conn;

	switch (conn->via_iface) {
	case IFACE_A:
		LOGP(DMSC, LOGL_ERROR,
		     "msc_call_assignment(): A-interface BSSMAP Assignment"
		     " Request not yet implemented\n");
		return -ENOTSUP;

	case IFACE_IU:
#ifdef BUILD_IU
		return conn_iu_rab_act_cs(trans);
#else
		LOGP(DMSC, LOGL_ERROR,
		     "msc_call_assignment(): IuCS RAB Activation not supported"
		     " in this build\n");
		return -ENOTSUP;
#endif

	default:
		LOGP(DMSC, LOGL_ERROR,
		     "msc_tx(): conn->via_iface invalid (%d)\n",
		     conn->via_iface);
		return -EINVAL;
	}
}

int msc_call_bridge(struct gsm_trans *trans1, struct gsm_trans *trans2)
{
	struct gsm_subscriber_connection *conn1 = trans1->conn;
	struct gsm_subscriber_connection *conn2 = trans2->conn;

	struct mgcpgw_client *mgcp = conn1->network->mgcpgw.client;
	OSMO_ASSERT(mgcp);

	const char *ip = mgcpgw_client_remote_addr_str(mgcp);

	/* First setup the counterparts' endpoints, so that when transmission
	 * starts the originating addresses are already known to be valid. */
	mgcpgw_client_tx_mdcx(mgcp, conn1->iu.mgcp_rtp_endpoint,
			      ip, conn2->iu.mgcp_rtp_port_cn,
			      MGCP_CONN_LOOPBACK);
	mgcpgw_client_tx_mdcx(mgcp, conn2->iu.mgcp_rtp_endpoint,
			      ip, conn1->iu.mgcp_rtp_port_cn,
			      MGCP_CONN_LOOPBACK);
	/* Now enable sending to and receiving from the peer. */
	mgcpgw_client_tx_mdcx(mgcp, conn1->iu.mgcp_rtp_endpoint,
			      ip, conn2->iu.mgcp_rtp_port_cn,
			      MGCP_CONN_RECV_SEND);
	mgcpgw_client_tx_mdcx(mgcp, conn2->iu.mgcp_rtp_endpoint,
			      ip, conn1->iu.mgcp_rtp_port_cn,
			      MGCP_CONN_RECV_SEND);

	return 0;
}
