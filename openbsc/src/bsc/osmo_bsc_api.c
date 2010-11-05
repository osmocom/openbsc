/* (C) 2009-2010 by Holger Hans Peter Freyther <zecke@selfish.org>
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

#include <openbsc/osmo_bsc.h>
#include <openbsc/debug.h>

#include <osmocore/protocol/gsm_08_08.h>
#include <osmocore/gsm0808.h>

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
	bsc_queue_for_msc(conn, resp);

static void bsc_sapi_n_reject(struct gsm_subscriber_connection *conn, int dlci)
{
	struct msgb *resp;
	return_when_not_connected(conn);

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

static int bsc_compl_l3(struct gsm_subscriber_connection *conn, struct msgb *msg,
			uint16_t chosen_channel)
{
	if (bsc_create_new_connection(conn, msg, chosen_channel) == 0) {
		bsc_scan_bts_msg(conn, msg);
		return BSC_API_CONN_POL_ACCEPT;
	}

	return BSC_API_CONN_POL_REJECT;
}

static void bsc_dtap(struct gsm_subscriber_connection *conn, uint8_t link_id, struct msgb *msg)
{
	struct msgb *resp;
	return_when_not_connected(conn);

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

	resp = gsm0808_create_assignment_completed(rr_cause, chosen_channel,
						   encr_alg_id, speech_model);
	queue_msg_or_return(resp);
}

static void bsc_assign_fail(struct gsm_subscriber_connection *conn,
			    uint8_t cause, uint8_t *rr_cause)
{
	struct msgb *resp;
	return_when_not_connected(conn);

	resp = gsm0808_create_assignment_failure(cause, rr_cause);
	queue_msg_or_return(resp);
}

static int bsc_clear_request(struct gsm_subscriber_connection *conn, uint32_t cause)
{
	struct msgb *resp;
	return_when_not_connected_val(conn, 1);

	resp = gsm0808_create_clear_rqst(GSM0808_CAUSE_RADIO_INTERFACE_FAILURE);
	if (!resp) {
		LOGP(DMSC, LOGL_ERROR, "Failed to allocate response.\n");
		return 0;
	}

	bsc_queue_for_msc(conn, resp);
	return 0;
}

static struct bsc_api bsc_handler = {
	.sapi_n_reject = bsc_sapi_n_reject,
	.cipher_mode_compl = bsc_cipher_mode_compl,
	.compl_l3 = bsc_compl_l3,
	.dtap  = bsc_dtap,
	.assign_compl = bsc_assign_compl,
	.assign_fail = bsc_assign_fail,
	.clear_request = bsc_clear_request,
};

struct bsc_api *osmo_bsc_api()
{
	return &bsc_handler;
}
