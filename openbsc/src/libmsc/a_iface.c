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
#include <osmocom/sigtran/sccp_sap.h>
#include <osmocom/sigtran/osmo_ss7.h>
#include <osmocom/sigtran/protocol/m3ua.h>
#include <osmocom/gsm/gsm0808.h>
#include <osmocom/gsm/protocol/gsm_08_08.h>
#include <osmocom/gsm/protocol/gsm_04_08.h>
#include <osmocom/gsm/gsm0808_utils.h>
#include <openbsc/debug.h>
#include <openbsc/msc_ifaces.h>
#include <openbsc/a_iface.h>
#include <openbsc/a_iface_bssap.h>
#include <openbsc/transaction.h>
#include <openbsc/mgcpgw_client.h>
#include <osmocom/core/byteswap.h>
#include <osmocom/sccp/sccp_types.h>
#include <openbsc/a_reset.h>
#include <openbsc/osmo_msc.h>

#define SSN_BSSAP	254	/* SCCP_SSN_BSSAP */
#define SENDER_PC	1	/* Our local point code */

/* A pointer to the GSM network we work with. By the current paradigm,
 * there can only be one gsm_network per MSC. The pointer is set once
 * when calling a_init() */
static struct gsm_network *gsm_network = NULL;

/* A struct to track currently active connections. We need that information
 * to handle failure sitautions. In case of a problem, we must know which
 * connections are currently open and which BSC is responsible. We also need
 * the data to perform our connection checks (a_reset). All other logic will
 * look at the connection ids and addresses that are supplied by the
 * primitives */
struct bsc_conn {
	struct llist_head list;
	struct osmo_sccp_addr called_addr;	/* BSC (remote) */
	struct osmo_sccp_addr calling_addr;	/* MSC (local) */
	uint32_t conn_id;			/* Connection identifier */
};

/* Internal list with connections we currently maintain. This
 * list is of type struct bsc_conn (see above) */
static LLIST_HEAD(active_connections);

/* Context information about the BSC, will be used only internally in this
 * file to manage the BSCs we are associated with */
struct bsc_context {
	struct llist_head list;
	struct a_reset_ctx reset;		/* Reset FSM (one per BSC) */
	struct osmo_sccp_addr called_addr;	/* BSC (remote) */
	struct osmo_sccp_addr calling_addr;	/* MSC (local) */
	struct osmo_sccp_user *sccp_user;	/* SCCP user (the same for all) */
};

/* List with BSCs we are associated with. This list is of type
 * struct bsc_context (see above) */
static LLIST_HEAD(bsc_context_list);

/* Record info of a new active connection in the active connection list */
static void record_bsc_con(void *ctx, struct osmo_sccp_addr *called_addr, struct osmo_sccp_addr *calling_addr,
			   uint32_t conn_id)
{
	struct bsc_conn *conn;

	conn = talloc_zero(ctx, struct bsc_conn);
	OSMO_ASSERT(conn);

	memcpy(&conn->called_addr, called_addr, sizeof(*called_addr));
	memcpy(&conn->calling_addr, calling_addr, sizeof(*calling_addr));
	conn->conn_id = conn_id;

	llist_add_tail(&conn->list, &active_connections);
}

/* Delete info of a closed connection from the active connection list */
void a_delete_bsc_con(uint32_t conn_id)
{
	struct bsc_conn *conn;
	struct bsc_conn *conn_temp;

	llist_for_each_entry_safe(conn, conn_temp, &active_connections, list) {
		if (conn->conn_id == conn_id) {
			llist_del(&conn->list);
			talloc_free(conn);
		}
	}
}

/* Check if a specified connection id has an active SCCP connection */
static bool check_connection_active(uint32_t conn_id)
{
	struct bsc_conn *conn;

	/* Find the address for the current connection id */
	llist_for_each_entry(conn, &active_connections, list) {
		if (conn->conn_id == conn_id) {
			return true;
		}
	}

	return false;
}

/* Get the reset context for a specifiec calling (BSC) address */
static struct a_reset_ctx *get_reset_ctx_by_sccp_addr(struct osmo_sccp_addr *addr)
{
	struct bsc_context *bsc_ctx;

	if (!addr)
		return NULL;

	llist_for_each_entry(bsc_ctx, &bsc_context_list, list) {
		if (memcmp(&bsc_ctx->called_addr, addr, sizeof(*addr)) == 0)
			return &bsc_ctx->reset;
	}

	LOGP(DMSC, LOGL_ERROR, "The calling BSC (%s) is unknown to this MSC ...\n",
	     osmo_sccp_addr_dump(addr));
	return NULL;
}

/* Send DTAP message via A-interface */
int a_iface_tx_dtap(struct msgb *msg)
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
int a_iface_tx_cipher_mode(struct gsm_subscriber_connection *conn,
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
int a_iface_tx_paging(const char *imsi, uint32_t tmsi, uint16_t lac)
{
	struct bsc_context *bsc_ctx;
	struct gsm0808_cell_id_list cil;
	struct msgb *msg;
	int page_count = 0;

	cil.id_discr = CELL_IDENT_LAC;
	cil.id_list_lac[0] = lac;
	cil.id_list_len = 1;

	/* Deliver paging request to all known BSCs */
	llist_for_each_entry(bsc_ctx, &bsc_context_list, list) {
		if (a_reset_conn_ready(&bsc_ctx->reset)) {
			LOGP(DMSC, LOGL_DEBUG,
			     "Passing paging message from MSC %s to BSC %s (imsi=%s, tmsi=0x%08x, lac=%u)\n",
			     osmo_sccp_addr_dump(&bsc_ctx->calling_addr),
			     osmo_sccp_addr_dump(&bsc_ctx->called_addr), imsi, tmsi, lac);
			msg = gsm0808_create_paging(imsi, &tmsi, &cil, NULL);
			osmo_sccp_tx_unitdata_msg(bsc_ctx->sccp_user,
						  &bsc_ctx->calling_addr, &bsc_ctx->called_addr, msg);
			page_count++;
		} else {
			LOGP(DMSC, LOGL_DEBUG,
			     "Connection down, dropping paging from MSC %s to BSC %s (imsi=%s, tmsi=0x%08x, lac=%u)\n",
			     osmo_sccp_addr_dump(&bsc_ctx->calling_addr),
			     osmo_sccp_addr_dump(&bsc_ctx->called_addr), imsi, tmsi, lac);
		}
	}

	if (page_count <= 0)
		LOGP(DMSC, LOGL_ERROR, "Could not deliver paging because none of the associated BSCs is available!\n");

	return page_count;
}

/* Convert speech version field */
static uint8_t convert_Abis_sv_to_A_sv(int speech_ver)
{
	/* The speech versions that are transmitted in the Bearer capability
	 * information element, that is transmitted on the Abis interfece
	 * use a different encoding than the permitted speech version
	 * identifier, that is signalled in the channel type element on the A
	 * interface. (See also 3GPP TS 48.008, 3.2.2.1 and 3GPP TS 24.008,
	 * 10.5.103 */

	switch (speech_ver) {
	case GSM48_BCAP_SV_FR:
		return GSM0808_PERM_FR1;
		break;
	case GSM48_BCAP_SV_HR:
		return GSM0808_PERM_HR1;
		break;
	case GSM48_BCAP_SV_EFR:
		return GSM0808_PERM_FR2;
		break;
	case GSM48_BCAP_SV_AMR_F:
		return GSM0808_PERM_FR3;
		break;
	case GSM48_BCAP_SV_AMR_H:
		return GSM0808_PERM_HR3;
		break;
	case GSM48_BCAP_SV_AMR_OFW:
		return GSM0808_PERM_FR4;
		break;
	case GSM48_BCAP_SV_AMR_OHW:
		return GSM0808_PERM_HR4;
		break;
	case GSM48_BCAP_SV_AMR_FW:
		return GSM0808_PERM_FR5;
		break;
	case GSM48_BCAP_SV_AMR_OH:
		return GSM0808_PERM_HR6;
		break;
	}

	/* If nothing matches, tag the result as invalid */
	LOGP(DMSC, LOGL_ERROR, "Invalid permitted speech version / rate detected, discarding.\n");
	return 0xFF;
}

/* Convert speech preference field */
static uint8_t convert_Abis_prev_to_A_pref(int radio)
{
	/* The Radio channel requirement field that is transmitted in the
	 * Bearer capability information element, that is transmitted on the
	 * Abis interfece uses a different encoding than the Channel rate and
	 * type field that is signalled in the channel type element on the A
	 * interface. (See also 3GPP TS 48.008, 3.2.2.1 and 3GPP TS 24.008,
	 * 10.5.102 */

	switch (radio) {
	case GSM48_BCAP_RRQ_FR_ONLY:
		return GSM0808_SPEECH_FULL_BM;
	case GSM48_BCAP_RRQ_DUAL_FR:
		return GSM0808_SPEECH_FULL_PREF;
	case GSM48_BCAP_RRQ_DUAL_HR:
		return GSM0808_SPEECH_HALF_PREF;
	}

	LOGP(DMSC, LOGL_ERROR, "Invalid speech version / rate combination preference, defaulting to full rate.\n");
	return GSM0808_SPEECH_FULL_BM;
}

/* Assemble the channel type field */
int enc_channel_type(struct gsm0808_channel_type *ct, const struct gsm_mncc_bearer_cap *bc)
{
	unsigned int i;
	uint8_t sv;
	unsigned int count = 0;
	bool only_gsm_hr = true;

	ct->ch_indctr = GSM0808_CHAN_SPEECH;

	for (i = 0; i < ARRAY_SIZE(bc->speech_ver); i++) {
		if (bc->speech_ver[i] == -1)
			break;
		sv = convert_Abis_sv_to_A_sv(bc->speech_ver[i]);
		if (sv != 0xFF) {
			/* Detect if something else than
			 * GSM HR V1 is supported */
			if (sv == GSM0808_PERM_HR2 ||
			    sv == GSM0808_PERM_HR3 || sv == GSM0808_PERM_HR4 || sv == GSM0808_PERM_HR6)
				only_gsm_hr = false;

			ct->perm_spch[count] = sv;
			count++;
		}
	}
	ct->perm_spch_len = count;

	if (only_gsm_hr)
		/* Note: We must avoid the usage of GSM HR1 as this
		 * codec only offers very poor audio quality. If the
		 * MS only supports GSM HR1 (and full rate), and has
		 * a preference for half rate. Then we will ignore the
		 * preference and assume a preference for full rate. */
		ct->ch_rate_type = GSM0808_SPEECH_FULL_BM;
	else
		ct->ch_rate_type = convert_Abis_prev_to_A_pref(bc->radio);

	if (count)
		return 0;
	else
		return -EINVAL;
}

/* Assemble the speech codec field */
static int enc_speech_codec_list(struct gsm0808_speech_codec_list *scl, const struct gsm0808_channel_type *ct)
{
	unsigned int i;
	int rc;

	memset(scl, 0, sizeof(*scl));
	for (i = 0; i < ct->perm_spch_len; i++) {
		rc = gsm0808_speech_codec_from_chan_type(&scl->codec[i], ct->perm_spch[i]);
		if (rc != 0)
			return -EINVAL;
	}
	scl->len = i;

	return 0;
}

/* Send assignment request via A-interface */
int a_iface_tx_assignment(struct gsm_trans *trans)
{
	struct gsm_subscriber_connection *conn;
	struct gsm0808_channel_type ct;
	struct gsm0808_speech_codec_list scl;
	uint32_t *ci_ptr = NULL;
	struct msgb *msg;
	struct sockaddr_storage rtp_addr;
	struct sockaddr_in rtp_addr_in;
	int rc;

	conn = trans->conn;
	OSMO_ASSERT(conn);

	/* Channel type */
	rc = enc_channel_type(&ct, &trans->bearer_cap);
	if (rc < 0) {
		LOGP(DMSC, LOGL_ERROR, "Faild to generate channel type -- assignment not sent!\n");
		return -EINVAL;
	}

	/* Speech codec list */
	rc = enc_speech_codec_list(&scl, &ct);
	if (rc < 0) {
		LOGP(DMSC, LOGL_ERROR, "Faild to generate Speech codec list -- assignment not sent!\n");
		return -EINVAL;
	}

	/* Package RTP-Address data */
	memset(&rtp_addr_in, 0, sizeof(rtp_addr_in));
	rtp_addr_in.sin_family = AF_INET;
	rtp_addr_in.sin_port = osmo_htons(conn->iu.mgcp_rtp_port_ue);
	rtp_addr_in.sin_addr.s_addr = osmo_htonl(mgcpgw_client_remote_addr_n(gsm_network->mgcpgw.client));

	memset(&rtp_addr, 0, sizeof(rtp_addr));
	memcpy(&rtp_addr, &rtp_addr_in, sizeof(rtp_addr_in));

	msg = gsm0808_create_ass(&ct, NULL, &rtp_addr, &scl, ci_ptr);

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
	a_conn_info.reset = NULL;

	switch (OSMO_PRIM_HDR(&scu_prim->oph)) {
	case OSMO_PRIM(OSMO_SCU_PRIM_N_CONNECT, PRIM_OP_INDICATION):
		/* Handle inbound connection indication */
		a_conn_info.conn_id = scu_prim->u.connect.conn_id;
		a_conn_info.called_addr = &scu_prim->u.connect.called_addr;
		a_conn_info.calling_addr = &scu_prim->u.connect.calling_addr;
		a_conn_info.reset = get_reset_ctx_by_sccp_addr(&scu_prim->u.unitdata.calling_addr);

		if (a_reset_conn_ready(a_conn_info.reset) == false) {
			rc = osmo_sccp_tx_disconn(scu, a_conn_info.conn_id, a_conn_info.called_addr,
						  SCCP_RETURN_CAUSE_UNQUALIFIED);
			break;
		}

		osmo_sccp_tx_conn_resp(scu, scu_prim->u.connect.conn_id, &scu_prim->u.connect.called_addr, NULL, 0);
		if (msgb_l2len(oph->msg) > 0) {
			LOGP(DMSC, LOGL_DEBUG, "N-CONNECT.ind(%u, %s)\n",
			     scu_prim->u.connect.conn_id, osmo_hexdump(msgb_l2(oph->msg), msgb_l2len(oph->msg)));
			rc = sccp_rx_dt(scu, &a_conn_info, oph->msg);
		} else
			LOGP(DMSC, LOGL_DEBUG, "N-CONNECT.ind(%u)\n", scu_prim->u.connect.conn_id);

		record_bsc_con(scu, &scu_prim->u.connect.calling_addr, &scu_prim->u.connect.called_addr, scu_prim->u.connect.conn_id);
		break;

	case OSMO_PRIM(OSMO_SCU_PRIM_N_DATA, PRIM_OP_INDICATION):
		/* Handle incoming connection oriented data */
		a_conn_info.conn_id = scu_prim->u.data.conn_id;
		LOGP(DMSC, LOGL_DEBUG, "N-DATA.ind(%u, %s)\n",
		     scu_prim->u.data.conn_id, osmo_hexdump(msgb_l2(oph->msg), msgb_l2len(oph->msg)));
		sccp_rx_dt(scu, &a_conn_info, oph->msg);
		break;

	case OSMO_PRIM(OSMO_SCU_PRIM_N_UNITDATA, PRIM_OP_INDICATION):
		/* Handle inbound UNITDATA */
		a_conn_info.called_addr = &scu_prim->u.unitdata.called_addr;
		a_conn_info.calling_addr = &scu_prim->u.unitdata.calling_addr;
		a_conn_info.reset = get_reset_ctx_by_sccp_addr(&scu_prim->u.unitdata.calling_addr);

		DEBUGP(DMSC, "N-UNITDATA.ind(%s)\n", osmo_hexdump(msgb_l2(oph->msg), msgb_l2len(oph->msg)));
		sccp_rx_udt(scu, &a_conn_info, oph->msg);
		break;

	default:
		LOGP(DMSC, LOGL_ERROR, "Unhandled SIGTRAN primitive: %u:%u\n", oph->primitive, oph->operation);
		break;
	}

	return rc;
}

/* Clear all subscriber connections on a specified BSC */
void a_clear_all(struct osmo_sccp_user *scu, struct osmo_sccp_addr *bsc_addr)
{
	struct gsm_subscriber_connection *conn;
	struct gsm_subscriber_connection *conn_temp;
	struct gsm_network *network = gsm_network;

	llist_for_each_entry_safe(conn, conn_temp, &network->subscr_conns, entry) {
		/* Clear only A connections and connections that actually
		 * belong to the specified BSC */
		if (conn->via_ran == RAN_GERAN_A
		    && memcmp(bsc_addr, &conn->a.bsc_addr, sizeof(conn->a.bsc_addr)) == 0) {
			LOGP(DMSC, LOGL_NOTICE, "Dropping orphaned subscriber connection (conn_id %i)\n", conn->a.conn_id);
			msc_clear_request(conn, GSM48_CC_CAUSE_SWITCH_CONG);

			/* If there is still an SCCP connection active, remove it now */
			if (check_connection_active(conn->a.conn_id)) {
				osmo_sccp_tx_disconn(scu, conn->a.conn_id, bsc_addr, SCCP_RELEASE_CAUSE_END_USER_ORIGINATED);
				a_delete_bsc_con(conn->a.conn_id);
			}
		}
	}
}

/* Callback function: Close all open connections */
static void a_reset_cb(void *priv)
{
	struct msgb *msg;
	struct bsc_context *bsc_ctx = (struct bsc_context*) priv;

	/* Clear all now orphaned subscriber connections */
	a_clear_all(bsc_ctx->sccp_user, &bsc_ctx->called_addr);

	LOGP(DMSC, LOGL_NOTICE, "Sending RESET to BSC %s\n", osmo_sccp_addr_dump(&bsc_ctx->called_addr));
	msg = gsm0808_create_reset();
	osmo_sccp_tx_unitdata_msg(bsc_ctx->sccp_user, &bsc_ctx->calling_addr,
				  &bsc_ctx->called_addr, msg);
}

/* Initalize A interface connection between to MSC and BSC */
int a_init(void *ctx, const char *name, uint32_t local_pc,
	   const char *listen_addr, const char *remote_addr, uint16_t local_port, struct gsm_network *network)
{
	/* FIXME: Remove hardcoded parameters, use parameters in parameter list */
	struct osmo_sccp_instance *sccp;
	struct osmo_sccp_user *scu;
	struct bsc_context *bsc_ctx;

	LOGP(DMSC, LOGL_NOTICE, "Initalizing SCCP connection to stp...\n");

	gsm_network = network;
	osmo_ss7_init();

	/* SCCP Protocol stack */
	sccp =
	    osmo_sccp_simple_client(NULL, "osmo-msc", SENDER_PC, OSMO_SS7_ASP_PROT_M3UA, 0, NULL, M3UA_PORT,
				    "127.0.0.1");
	scu = osmo_sccp_user_bind(sccp, "osmo-msc", sccp_sap_up, SSN_BSSAP);

	/* Add some BSCs to the context list */
	/* FIXME: Make this configurable (VTY!) */
	bsc_ctx = talloc_zero(NULL, struct bsc_context);
	bsc_ctx->reset.priv = bsc_ctx;
	bsc_ctx->reset.cb = a_reset_cb;
	llist_add_tail(&bsc_ctx->list, &bsc_context_list);
	bsc_ctx->called_addr.presence = OSMO_SCCP_ADDR_T_SSN | OSMO_SCCP_ADDR_T_PC;
	bsc_ctx->called_addr.ssn = SCCP_SSN_BSSAP;
	bsc_ctx->called_addr.ri = OSMO_SCCP_RI_SSN_PC;
	bsc_ctx->called_addr.pc = 23;
	bsc_ctx->calling_addr.presence = OSMO_SCCP_ADDR_T_SSN | OSMO_SCCP_ADDR_T_PC;
	bsc_ctx->calling_addr.ssn = SCCP_SSN_BSSAP;
	bsc_ctx->calling_addr.ri = OSMO_SCCP_RI_SSN_PC;
	bsc_ctx->calling_addr.pc = 1;
	bsc_ctx->sccp_user = scu;
	bsc_ctx = NULL;

	/* Start reset procedure for all BSC connections */
	llist_for_each_entry(bsc_ctx, &bsc_context_list, list) {
		a_reset_start(&bsc_ctx->reset);
	}

	return 0;
}
