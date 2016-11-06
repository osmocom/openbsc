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
static void iu_rab_act_cs(struct ue_conn_ctx *uectx, uint8_t rab_id,
			  uint32_t rtp_ip, uint16_t rtp_port)
{
	struct msgb *msg;
	bool use_x213_nsap;
	uint32_t conn_id = uectx->conn_id;

	use_x213_nsap = (uectx->rab_assign_addr_enc == NSAP_ADDR_ENC_X213);

	LOGP(DIUCS, LOGL_DEBUG, "Assigning RAB: conn_id=%u, rab_id=%d,"
	     " rtp=%x:%u, use_x213_nsap=%d\n", conn_id, rab_id, rtp_ip,
	     rtp_port, use_x213_nsap);

	msg = ranap_new_msg_rab_assign_voice(rab_id, rtp_ip, rtp_port,
					     use_x213_nsap);
	msg->l2h = msg->data;

	if (iu_rab_act(uectx, msg))
		LOGP(DIUCS, LOGL_ERROR, "Failed to send RAB Assignment:"
		     " conn_id=%d rab_id=%d rtp=%x:%u\n",
		     conn_id, rab_id, rtp_ip, rtp_port);
}

static void mgcp_response_rab_act_cs_crcx(struct mgcp_response *r, void *priv)
{
	struct gsm_trans *trans = priv;
	struct gsm_subscriber_connection *conn = trans->conn;
	struct ue_conn_ctx *uectx = conn->iu.ue_ctx;
	uint32_t rtp_ip;
	int rc;

	if (r->head.response_code != 200) {
		LOGP(DMGCP, LOGL_ERROR,
		     "MGCPGW response yields error: %d %s\n",
		     r->head.response_code, r->head.comment);
		goto rab_act_cs_error;
	}
	
	rc = mgcp_response_parse_params(r);
	if (rc) {
		LOGP(DMGCP, LOGL_ERROR,
		     "Cannot parse MGCP response, for %s\n",
		     subscr_name(trans->subscr));
		goto rab_act_cs_error;
	}

	conn->iu.mgcp_rtp_port_cn = r->audio_port;
	DEBUGP(DMGCP, "MGCP audio port %u for %s\n",
	       conn->iu.mgcp_rtp_port_cn, subscr_name(trans->subscr));

	rtp_ip = mgcpgw_client_remote_addr_n(conn->network->mgcpgw.client);
	iu_rab_act_cs(uectx, conn->iu.rab_id, rtp_ip,
		      conn->iu.mgcp_rtp_port_ue);
	/* use_x213_nsap == 0 for ip.access nano3G */

rab_act_cs_error:
	/* FIXME abort call, invalidate conn, ... */
	return;
}

static int conn_iu_rab_act_cs(struct gsm_trans *trans)
{
	struct gsm_subscriber_connection *conn = trans->conn;
	struct mgcpgw_client *mgcp = conn->network->mgcpgw.client;
	struct msgb *msg;

	/* HACK. where to scope the RAB Id? At the conn / subscriber /
	 * ue_conn_ctx? */
	static uint8_t next_rab_id = 234;
	conn->iu.rab_id = next_rab_id ++;

	conn->iu.mgcp_rtp_endpoint =
		mgcpgw_client_next_endpoint(conn->network->mgcpgw.client);
	/* HACK: the addresses should be known from CRCX response
	 * and config. */
	conn->iu.mgcp_rtp_port_ue = 4000 + 2 * conn->iu.mgcp_rtp_endpoint;

	/* Establish the RTP stream first as looping back to the originator.
	 * The MDCX will patch through to the counterpart. TODO: play a ring
	 * tone instead. */
	msg = mgcp_msg_crcx(mgcp, conn->iu.mgcp_rtp_endpoint, trans->callref,
			    MGCP_CONN_LOOPBACK);
	return mgcpgw_client_tx(mgcp, msg, mgcp_response_rab_act_cs_crcx, trans);
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

static void mgcp_response_bridge_mdcx(struct mgcp_response *r, void *priv);

static void mgcp_bridge(struct gsm_trans *from, struct gsm_trans *to,
			enum bridge_state state,
			enum mgcp_connection_mode mode)
{
	struct gsm_subscriber_connection *conn1 = from->conn;
	struct gsm_subscriber_connection *conn2 = to->conn;
	struct mgcpgw_client *mgcp = conn1->network->mgcpgw.client;
	const char *ip;
	struct msgb *msg;

	OSMO_ASSERT(mgcp);

	DEBUGP(DMGCP, "mgcpgw_client_tx(trans=%p) in state %d -> %d\n", from, from->bridge.state, state);

	from->bridge.peer = to;
	from->bridge.state = state;

	/* Loop back to the same MGCP GW */
	ip = mgcpgw_client_remote_addr_str(mgcp);

	msg = mgcp_msg_mdcx(mgcp,
			    conn1->iu.mgcp_rtp_endpoint,
			    ip, conn2->iu.mgcp_rtp_port_cn,
			    mode);
	if (mgcpgw_client_tx(mgcp, msg, mgcp_response_bridge_mdcx, from))
		LOGP(DMGCP, LOGL_ERROR,
		     "Failed to send MDCX message for %s\n",
		     subscr_name(from->subscr));
}

static void mgcp_response_bridge_mdcx(struct mgcp_response *r, void *priv)
{
	struct gsm_trans *trans = priv;
	struct gsm_trans *peer = trans->bridge.peer;

	DEBUGP(DMGCP, "mgcp_response_bridge_mdcx(trans=%p) in state %d\n", trans, trans->bridge.state);

	switch (trans->bridge.state) {
	case BRIDGE_STATE_LOOPBACK_PENDING:
		trans->bridge.state = BRIDGE_STATE_LOOPBACK_ESTABLISHED;
		DEBUGP(DMGCP, "trans=%p --> state %d\n", trans, trans->bridge.state);

		switch (peer->bridge.state) {
		case BRIDGE_STATE_LOOPBACK_PENDING:
			/* Wait until the other is done as well. */
			return;
		case BRIDGE_STATE_LOOPBACK_ESTABLISHED:
			/* Now that both are in loopback, switch both to
			 * forwarding. */
			mgcp_bridge(trans, peer, BRIDGE_STATE_BRIDGE_PENDING,
				    MGCP_CONN_RECV_SEND);
			mgcp_bridge(peer, trans, BRIDGE_STATE_BRIDGE_PENDING,
				    MGCP_CONN_RECV_SEND);
			break;
		default:
			LOGP(DMGCP, LOGL_ERROR,
			     "Unexpected bridge state: %d for %s\n",
			     trans->bridge.state, subscr_name(trans->subscr));
			break;
		}
		break;

	case BRIDGE_STATE_BRIDGE_PENDING:
		trans->bridge.state = BRIDGE_STATE_BRIDGE_ESTABLISHED;
		DEBUGP(DMGCP, "trans=%p --> state %d\n", trans, trans->bridge.state);
		break;
		
	default:
		LOGP(DMGCP, LOGL_ERROR,
		     "Unexpected bridge state: %d for %s\n",
		     trans->bridge.state, subscr_name(trans->subscr));
		break;
	}
}

int msc_call_bridge(struct gsm_trans *trans1, struct gsm_trans *trans2)
{
	/* First setup as loopback and configure the counterparts' endpoints,
	 * so that when transmission starts the originating addresses are
	 * already known to be valid. The mgcp callback will continue. */
	mgcp_bridge(trans1, trans2, BRIDGE_STATE_LOOPBACK_PENDING,
		    MGCP_CONN_LOOPBACK);
	mgcp_bridge(trans2, trans1, BRIDGE_STATE_LOOPBACK_PENDING,
		    MGCP_CONN_LOOPBACK);

	return 0;
}
