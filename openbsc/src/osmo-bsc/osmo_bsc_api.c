/* (C) 2009-2011 by Holger Hans Peter Freyther <zecke@selfish.org>
 * (C) 2009-2011 by On-Waves
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

#include <openbsc/osmo_bsc.h>
#include <openbsc/osmo_msc_data.h>
#include <openbsc/debug.h>

#include <osmocom/gsm/protocol/gsm_08_08.h>
#include <osmocom/gsm/gsm0808.h>

#include <osmocom/sccp/sccp.h>

#define return_when_not_connected(conn) \
	if (!conn->sccp_con) {\
		LOGP(DMSC, LOGL_ERROR, "MSC Connection not present.\n"); \
		return; \
	}

#define return_when_not_connected_val(conn, ret) \
	if (!conn->sccp_con) {\
		LOGP(DMSC, LOGL_ERROR, "MSC Connection not present.\n"); \
		return ret; \
	}

#define queue_msg_or_return(resp) \
	if (!resp) { \
		LOGP(DMSC, LOGL_ERROR, "Failed to allocate response.\n"); \
		return; \
	} \
	bsc_queue_for_msc(conn->sccp_con, resp);

static uint16_t get_network_code_for_msc(struct osmo_msc_data *msc)
{
	if (msc->core_ncc != -1)
		return msc->core_ncc;
	return msc->network->network_code;
}

static uint16_t get_country_code_for_msc(struct osmo_msc_data *msc)
{
	if (msc->core_mcc != -1)
		return msc->core_mcc;
	return msc->network->country_code;
}

static void bsc_sapi_n_reject(struct gsm_subscriber_connection *conn, int dlci)
{
	struct msgb *resp;
	return_when_not_connected(conn);

	LOGP(DMSC, LOGL_NOTICE, "Tx MSC SAPI N REJECT DLCI=0x%02x\n", dlci);

	resp = gsm0808_create_sapi_reject(dlci);
	queue_msg_or_return(resp);
}

static void bsc_cipher_mode_compl(struct gsm_subscriber_connection *conn,
				  struct msgb *msg, uint8_t chosen_encr)
{
	struct msgb *resp;
	return_when_not_connected(conn);

	LOGP(DMSC, LOGL_DEBUG, "CIPHER MODE COMPLETE from MS, forwarding to MSC\n");
	resp = gsm0808_create_cipher_complete(msg, chosen_encr);
	queue_msg_or_return(resp);
}

/*
 * Instruct to reserve data for a new connectiom, create the complete
 * layer three message, send it to open the connection.
 */
static int bsc_compl_l3(struct gsm_subscriber_connection *conn, struct msgb *msg,
			uint16_t chosen_channel)
{
	struct msgb *resp;
	struct osmo_msc_data *msc;
	uint16_t network_code;
	uint16_t country_code;

	LOGP(DMSC, LOGL_INFO, "Tx MSC COMPL L3\n");

	/* find the MSC link we want to use */
	msc = bsc_find_msc(conn, msg);
	if (!msc) {
		LOGP(DMSC, LOGL_ERROR, "Failed to find a MSC for a connection.\n");
		return -1;
	}

	/* allocate resource for a new connection */
	if (bsc_create_new_connection(conn, msc) != 0)
		return BSC_API_CONN_POL_REJECT;

	network_code = get_network_code_for_msc(conn->sccp_con->msc);
	country_code = get_country_code_for_msc(conn->sccp_con->msc);

	bsc_scan_bts_msg(conn, msg);
	resp = gsm0808_create_layer3(msg, network_code, country_code,
				     conn->bts->location_area_code,
				     conn->bts->cell_identity);
	if (!resp) {
		LOGP(DMSC, LOGL_DEBUG, "Failed to create layer3 message.\n");
		sccp_connection_free(conn->sccp_con->sccp);
		bsc_delete_connection(conn->sccp_con);
		return BSC_API_CONN_POL_REJECT;
	}

	if (bsc_open_connection(conn->sccp_con, resp) != 0) {
		sccp_connection_free(conn->sccp_con->sccp);
		bsc_delete_connection(conn->sccp_con);
		msgb_free(resp);
		return BSC_API_CONN_POL_REJECT;
	}

	return BSC_API_CONN_POL_ACCEPT;
}

static void bsc_dtap(struct gsm_subscriber_connection *conn, uint8_t link_id, struct msgb *msg)
{
	struct msgb *resp;
	return_when_not_connected(conn);

	LOGP(DMSC, LOGL_INFO, "Tx MSC DTAP LINK_ID=0x%02x\n", link_id);

	bsc_scan_bts_msg(conn, msg);
	resp = gsm0808_create_dtap(msg, link_id);
	queue_msg_or_return(resp);
}

static void bsc_assign_compl(struct gsm_subscriber_connection *conn, uint8_t rr_cause,
			     uint8_t chosen_channel, uint8_t encr_alg_id,
			     uint8_t speech_model)
{
	struct msgb *resp;
	return_when_not_connected(conn);

	LOGP(DMSC, LOGL_INFO, "Tx MSC ASSIGN COMPL\n");

	resp = gsm0808_create_assignment_completed(rr_cause, chosen_channel,
						   encr_alg_id, speech_model);
	queue_msg_or_return(resp);
}

static void bsc_assign_fail(struct gsm_subscriber_connection *conn,
			    uint8_t cause, uint8_t *rr_cause)
{
	struct msgb *resp;
	return_when_not_connected(conn);

	LOGP(DMSC, LOGL_INFO, "Tx MSC ASSIGN FAIL\n");

	resp = gsm0808_create_assignment_failure(cause, rr_cause);
	queue_msg_or_return(resp);
}

static int bsc_clear_request(struct gsm_subscriber_connection *conn, uint32_t cause)
{
	struct osmo_bsc_sccp_con *sccp;
	struct msgb *resp;
	return_when_not_connected_val(conn, 1);

	LOGP(DMSC, LOGL_INFO, "Tx MSC CLEAR REQUEST\n");

	/*
	 * Remove the connection from BSC<->SCCP part, the SCCP part
	 * will either be cleared by channel release or MSC disconnect
	 */
	sccp = conn->sccp_con;
	sccp->conn = NULL;
	conn->sccp_con = NULL;

	resp = gsm0808_create_clear_rqst(GSM0808_CAUSE_RADIO_INTERFACE_FAILURE);
	if (!resp) {
		LOGP(DMSC, LOGL_ERROR, "Failed to allocate response.\n");
		return 1;
	}

	bsc_queue_for_msc(sccp, resp);
	return 1;
}

static void bsc_cm_update(struct gsm_subscriber_connection *conn,
			  const uint8_t *cm2, uint8_t cm2_len,
			  const uint8_t *cm3, uint8_t cm3_len)
{
	struct msgb *resp;
	return_when_not_connected(conn);

	resp = gsm0808_create_classmark_update(cm2, cm2_len, cm3, cm3_len);

	queue_msg_or_return(resp);
}

static struct bsc_api bsc_handler = {
	.sapi_n_reject = bsc_sapi_n_reject,
	.cipher_mode_compl = bsc_cipher_mode_compl,
	.compl_l3 = bsc_compl_l3,
	.dtap  = bsc_dtap,
	.assign_compl = bsc_assign_compl,
	.assign_fail = bsc_assign_fail,
	.clear_request = bsc_clear_request,
	.classmark_chg = bsc_cm_update,
};

struct bsc_api *osmo_bsc_api()
{
	return &bsc_handler;
}
