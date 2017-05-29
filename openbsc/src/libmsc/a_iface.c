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
#include <osmocom/core/msgb.h>
#include <osmocom/core/logging.h>
#include <osmocom/sigtran/sccp_helpers.h>
#include <osmocom/gsm/gsm0808.h>
#include <osmocom/gsm/protocol/gsm_08_08.h>
#include <openbsc/debug.h>
#include <openbsc/msc_ifaces.h>
#include <openbsc/a_iface.h>
#include <openbsc/a_iface_bssap.h>
#include <openbsc/transaction.h>
#include <openbsc/mgcpgw_client.h>
#include <osmocom/core/byteswap.h>

/* A pointer to the GSM network we work with. By the current paradigm,
 * there can only be one gsm_network per MSC. The pointer is set once
 * when calling a_init() */
static struct gsm_network *gsm_network = NULL;

/* Send DTAP message via A-interface */
int a_tx(struct msgb *msg)
{
	struct gsm_subscriber_connection *conn;
	struct msgb *msg_resp;

	/* FIXME: Set this to some meaninful value! */
	uint8_t link_id = 0x00;
	OSMO_ASSERT(msg);
	conn = (struct gsm_subscriber_connection *)msg->dst;
	OSMO_ASSERT(conn);
	OSMO_ASSERT(conn->a.scu);

	LOGP(DMSC, LOGL_DEBUG, "Passing DTAP message from MSC to BSC (conn_id=%i)\n", conn->a.conn_id);

	msg->l3h = msg->data;
	msg_resp = gsm0808_create_dtap(msg, link_id);
	if (!msg_resp) {
		LOGP(DMSC, LOGL_ERROR, "Unable to generate BSSMAP DTAP message!\n");
		return -EINVAL;
	} else
		LOGP(DMSC, LOGL_DEBUG, "Massage will be sent as BSSMAP DTAP message!\n");

	LOGP(DMSC, LOGL_DEBUG, "N-DATA.req(%u, %s)\n", conn->a.conn_id, osmo_hexdump(msg_resp->data, msg_resp->len));
	return osmo_sccp_tx_data_msg(conn->a.scu, conn->a.conn_id, msg_resp);
}

/* Send Cipher mode command via A-interface */
int msc_gsm0808_tx_cipher_mode(struct gsm_subscriber_connection *conn,
			       int cipher, const uint8_t *key, int len, int include_imeisv)
{
	/* TODO generalize for A- and Iu interfaces, don't name after 08.08 */
	struct msgb *msg_resp;
	struct gsm0808_encrypt_info ei;
	LOGP(DMSC, LOGL_DEBUG, "Passing Cipher mode command message from MSC to BSC (conn_id=%i)\n", conn->a.conn_id);
	uint8_t crm = 0x01;
	uint8_t *crm_ptr = NULL;

	/* Setup encryption information */
	if (len > ENCRY_INFO_KEY_MAXLEN || !key) {
		LOGP(DMSC, LOGL_ERROR,
		     "Cipher mode command message could not be generated due to invalid key! (conn_id=%i)\n",
		     conn->a.conn_id);
		return -EINVAL;
	} else {
		memcpy(&ei.key, key, len);
		ei.key_len = len;
	}

	if (include_imeisv)
		crm_ptr = &crm;

	ei.perm_algo[0] = (uint8_t) (1 << cipher);
	ei.perm_algo_len = 1;

	msg_resp = gsm0808_create_cipher(&ei, crm_ptr);
	LOGP(DMSC, LOGL_DEBUG, "N-DATA.req(%u, %s)\n", conn->a.conn_id, osmo_hexdump(msg_resp->data, msg_resp->len));

	return osmo_sccp_tx_data_msg(conn->a.scu, conn->a.conn_id, msg_resp);
}

/* Page a subscriber via A-interface */
int a_page(const char *imsi, uint32_t tmsi, uint16_t lac)
{
	struct a_bsc_addr *addr;
	struct llist_head *bsc_addr_list = get_bsc_addr_list();
	struct gsm0808_cell_id_list cil;
	int page_count = 0;

	cil.id_discr = CELL_IDENT_LAC;
	cil.id_list_lac[0] = lac;
	cil.id_list_len = 1;

	/* Deliver paging request to all known BSCs */
	llist_for_each_entry(addr, bsc_addr_list, list) {
		LOGP(DMSC, LOGL_DEBUG, "Passing paging message from MSC to BSC %s (imsi=%s, tmsi=0x%08x, lac=%u)\n",
		     osmo_sccp_addr_dump(&addr->calling_addr), imsi, tmsi, lac);
		osmo_sccp_tx_unitdata_msg(addr->scu, &addr->called_addr, &addr->calling_addr,
					  gsm0808_create_paging(imsi, &tmsi, &cil, NULL));
		page_count++;
	}

	if (page_count <= 0)
		LOGP(DMSC, LOGL_ERROR, "Could not deliver paging because no BSC is available!\n");

	return page_count;
}

/* Send assignment request via A-interface */
int a_assign(struct gsm_trans *trans)
{
	struct gsm_subscriber_connection *conn;
	struct gsm0808_channel_type ct;
	struct gsm0808_speech_codec_list *scl = NULL;
	uint32_t *ci_ptr = NULL;
	struct msgb *msg;
	struct sockaddr_storage rtp_addr;
	struct sockaddr_in rtp_addr_in;

	conn = trans->conn;
	OSMO_ASSERT(conn);

	/* FIXME: This is still work in progress */
	/* Some fake parameters for testing */
	ct.ch_indctr = GSM0808_CHAN_SPEECH;
	ct.ch_rate_type = GSM0808_SPEECH_FULL_BM;
	ct.perm_spch[0] = GSM0808_PERM_FR1;
	ct.perm_spch_len = 1;

	/* Package RTP-Address data */
	memset(&rtp_addr_in, 0, sizeof(rtp_addr_in));
	rtp_addr_in.sin_family = AF_INET;
	rtp_addr_in.sin_port = osmo_htons(conn->iu.mgcp_rtp_port_ue);
	rtp_addr_in.sin_addr.s_addr = osmo_htonl(mgcpgw_client_remote_addr_n(gsm_network->mgcpgw.client));

	memset(&rtp_addr, 0, sizeof(rtp_addr));
	memcpy(&rtp_addr, &rtp_addr_in, sizeof(rtp_addr_in));

	msg = gsm0808_create_ass(&ct, NULL, &rtp_addr, scl, ci_ptr);

	LOGP(DMSC, LOGL_DEBUG, "N-DATA.req(%u, %s)\n", conn->a.conn_id, osmo_hexdump(msg->data, msg->len));
	return osmo_sccp_tx_data_msg(conn->a.scu, conn->a.conn_id, msg);
}

/* Callback function, called by the SSCP stack when data arrives */
static int sccp_sap_up(struct osmo_prim_hdr *oph, void *_scu)
{
	struct osmo_sccp_user *scu = _scu;
	struct osmo_scu_prim *scu_prim = (struct osmo_scu_prim *)oph;
	int rc = 0;
	struct a_conn_info a_conn_info;
	memset(&a_conn_info, 0, sizeof(a_conn_info));
	a_conn_info.network = gsm_network;

	switch (OSMO_PRIM_HDR(&scu_prim->oph)) {
	case OSMO_PRIM(OSMO_SCU_PRIM_N_CONNECT, PRIM_OP_INDICATION):
		/* Handle inbound connection indication */
		a_conn_info.conn_id = scu_prim->u.connect.conn_id;
		a_conn_info.called_addr = &scu_prim->u.connect.called_addr;
		a_conn_info.calling_addr = &scu_prim->u.connect.calling_addr;
		osmo_sccp_tx_conn_resp(scu, scu_prim->u.connect.conn_id, &scu_prim->u.connect.called_addr, NULL, 0);
		if (msgb_l2len(oph->msg) > 0) {
			LOGP(DMSC, LOGL_DEBUG, "N-CONNECT.ind(%u, %s)\n",
			     scu_prim->u.connect.conn_id, osmo_hexdump(msgb_l2(oph->msg), msgb_l2len(oph->msg)));
			rc = msc_handle_dt1(scu, &a_conn_info, oph->msg);
		} else
			LOGP(DMSC, LOGL_DEBUG, "N-CONNECT.ind(%u)\n", scu_prim->u.connect.conn_id);
		break;

	case OSMO_PRIM(OSMO_SCU_PRIM_N_DATA, PRIM_OP_INDICATION):
		/* Handle incoming connection oriented data */
		a_conn_info.conn_id = scu_prim->u.data.conn_id;
		LOGP(DMSC, LOGL_DEBUG, "N-DATA.ind(%u, %s)\n",
		     scu_prim->u.data.conn_id, osmo_hexdump(msgb_l2(oph->msg), msgb_l2len(oph->msg)));
		msc_handle_dt1(scu, &a_conn_info, oph->msg);
		break;

	case OSMO_PRIM(OSMO_SCU_PRIM_N_UNITDATA, PRIM_OP_INDICATION):
		/* Handle inbound UNITDATA */
		a_conn_info.called_addr = &scu_prim->u.unitdata.called_addr;
		a_conn_info.calling_addr = &scu_prim->u.unitdata.calling_addr;
		DEBUGP(DMSC, "N-UNITDATA.ind(%s)\n", osmo_hexdump(msgb_l2(oph->msg), msgb_l2len(oph->msg)));
		msc_handle_udt(scu, &a_conn_info, oph->msg);
		break;

	default:
		LOGP(DMSC, LOGL_ERROR, "Unhandled SIGTRAN primitive: %u:%u\n", oph->primitive, oph->operation);
		break;
	}

	return rc;
}

/* Initalize A interface connection between to MSC and BSC */
int a_init(void *ctx, const char *name, uint32_t local_pc,
	   const char *listen_addr, const char *remote_addr, uint16_t local_port, struct gsm_network *network)
{
	/* FIXME: Clean this up! */
	/* FIXME: Don't use the simple_server, use the simple_client instead! */
#define RECEIVER_PC	23
#define SSN_BSSAP	254	/* SCCP_SSN_BSSAP */
#define SENDER_PC	1

	struct osmo_sccp_instance *sccp;

	gsm_network = network;
	osmo_ss7_init();

	sccp = osmo_sccp_simple_server(NULL, SENDER_PC, OSMO_SS7_ASP_PROT_M3UA, -1, "127.0.0.2");

	/* Why? */
	osmo_sccp_simple_server_add_clnt(sccp, OSMO_SS7_ASP_PROT_M3UA, "RECEIVER", RECEIVER_PC, -1, 0, NULL);

	osmo_sccp_user_bind(sccp, "MSC", &sccp_sap_up, SSN_BSSAP);

	return 0;
}
