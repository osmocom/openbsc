/* main MSC management code... */

/*
 * (C) 2010,2013 by Holger Hans Peter Freyther <zecke@selfish.org>
 * (C) 2010 by On-Waves
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
 *
 */

#include <openbsc/osmo_msc.h>
#include <openbsc/bsc_api.h>
#include <openbsc/debug.h>
#include <openbsc/transaction.h>
#include <openbsc/db.h>
#include <openbsc/vlr.h>
#include <openbsc/osmo_msc.h>

#include <openbsc/gsm_04_11.h>

/* Receive a SAPI-N-REJECT from BSC */
static void msc_sapi_n_reject(struct gsm_subscriber_connection *conn, int dlci)
{
	int sapi = dlci & 0x7;

	if (sapi == UM_SAPI_SMS)
		gsm411_sapi_n_reject(conn);
}

/* Receive a CLEAR REQUEST from BSC */
static int msc_clear_request(struct gsm_subscriber_connection *conn, uint32_t cause)
{
	gsm0408_clear_request(conn, cause);
	return 1;
}

static bool keep_conn(struct gsm_subscriber_connection *conn)
{
	/* TODO: what about a silent call? */

	if (!conn->conn_fsm) {
		DEBUGP(DMM, "No conn_fsm, release conn\n");
		return false;
	}

	switch (conn->conn_fsm->state) {
	case SUBSCR_CONN_S_NEW:
	case SUBSCR_CONN_S_ACCEPTED:
		return true;
	default:
		return false;
	}
}

/* receive a Level 3 Complete message and return MSC_CONN_ACCEPT or
 * MSC_CONN_REJECT */
enum msc_compl_l3_rc msc_compl_l3(struct gsm_subscriber_connection *conn,
				  struct msgb *msg, uint16_t chosen_channel)
{
	gsm0408_new_conn(conn);
	gsm0408_dispatch(conn, msg);

	/* NOTE: after the MSC split, returning BSC_API_CONN_POL_REJECT shall
	 * be replaced with a call to msc_subscr_con_free() */

	if (!keep_conn(conn)) {
		DEBUGP(DMM, "compl_l3: Discarding conn\n");
		return MSC_CONN_REJECT;
	}
	DEBUGP(DMM, "compl_l3: Keeping conn\n");
	conn->owned_by_msc = true;
	DEBUGP(DMM, "%s owned_by_msc = true\n",
	       vlr_subscr_name(conn->vsub));
	return MSC_CONN_ACCEPT;

#if 0
	/*
	 * If this is a silent call we want the channel to remain open as long as
	 * possible and this is why we accept this connection regardless of any
	 * pending transaction or ongoing operation.
	 */
	if (conn->silent_call)
		return MSC_CONN_ACCEPT;
	if (conn->loc_operation || conn->sec_operation || conn->anch_operation)
		return MSC_CONN_ACCEPT;
	if (trans_has_conn(conn))
		return MSC_CONN_ACCEPT;

	LOGP(DRR, LOGL_INFO, "MSC Complete L3: Rejecting connection.\n");
	return MSC_CONN_REJECT;
#endif
}

static void subscr_conn_bump(struct gsm_subscriber_connection *conn)
{
	if (!conn)
		return;
	if (!conn->conn_fsm)
		return;
	if (!(conn->conn_fsm->state == SUBSCR_CONN_S_ACCEPTED
	      || conn->conn_fsm->state == SUBSCR_CONN_S_COMMUNICATING))
		return;
	osmo_fsm_inst_dispatch(conn->conn_fsm, SUBSCR_CONN_E_BUMP, NULL);
}

/* Receive a DTAP message from BSC */
static void msc_dtap(struct gsm_subscriber_connection *conn, uint8_t link_id, struct msgb *msg)
{
	gsm0408_dispatch(conn, msg);

	/* Bump whether the conn wants to be closed */
	subscr_conn_bump(conn);
}

/* Receive an ASSIGNMENT COMPLETE from BSC */
static void msc_assign_compl(struct gsm_subscriber_connection *conn,
			     uint8_t rr_cause, uint8_t chosen_channel,
			     uint8_t encr_alg_id, uint8_t speec)
{
	LOGP(DRR, LOGL_DEBUG, "MSC assign complete (do nothing).\n");
}

/* Receive an ASSIGNMENT FAILURE from BSC */
static void msc_assign_fail(struct gsm_subscriber_connection *conn,
			    uint8_t cause, uint8_t *rr_cause)
{
	LOGP(DRR, LOGL_DEBUG, "MSC assign failure (do nothing).\n");
}

/* Receive a CLASSMARK CHNAGE from BSC */
static void msc_classmark_chg(struct gsm_subscriber_connection *conn,
			      const uint8_t *cm2, uint8_t cm2_len,
			      const uint8_t *cm3, uint8_t cm3_len)
{
	conn->classmark.classmark2_len = cm2_len;
	memcpy(conn->classmark.classmark2, cm2, cm2_len);
	if (cm3) {
		conn->classmark.classmark3_len = cm3_len;
		memcpy(conn->classmark.classmark3, cm3, cm3_len);
	}
}

/* Receive a CIPHERING MODE COMPLETE from BSC */
static void msc_ciph_m_compl(struct gsm_subscriber_connection *conn,
			     struct msgb *msg, uint8_t alg_id)
{
	struct gsm48_hdr *gh = msgb_l3(msg);
	unsigned int payload_len = msgb_l3len(msg) - sizeof(*gh);
	struct tlv_parsed tp;
	uint8_t mi_type;
	char imeisv[GSM48_MI_SIZE] = "";
	struct vlr_ciph_result ciph_res = { .cause = VLR_CIPH_REJECT };

	if (!gh) {
		LOGP(DRR, LOGL_ERROR, "invalid: msgb without l3 header\n");
		return;
	}

	if (!conn) {
		LOGP(DRR, LOGL_ERROR,
		     "invalid: rx Ciphering Mode Complete on NULL conn\n");
		return;
	}
	if (!conn->vsub) {
		LOGP(DRR, LOGL_ERROR,
		     "invalid: rx Ciphering Mode Complete for NULL subscr\n");
		return;
	}

	DEBUGP(DRR, "%s: CIPHERING MODE COMPLETE\n",
	       vlr_subscr_name(conn->vsub));

	tlv_parse(&tp, &gsm48_att_tlvdef, gh->data, payload_len, 0, 0);

	/* bearer capability */
	if (TLVP_PRESENT(&tp, GSM48_IE_MOBILE_ID)) {
		mi_type = TLVP_VAL(&tp, GSM48_IE_MOBILE_ID)[0] & GSM_MI_TYPE_MASK;
		if (mi_type == GSM_MI_TYPE_IMEISV
		    && TLVP_LEN(&tp, GSM48_IE_MOBILE_ID) > 0) {
			gsm48_mi_to_string(imeisv, sizeof(imeisv),
					   TLVP_VAL(&tp, GSM48_IE_MOBILE_ID),
					   TLVP_LEN(&tp, GSM48_IE_MOBILE_ID));
			ciph_res.imeisv = imeisv;
		}
	}

	ciph_res.cause = VLR_CIPH_COMPL;
	vlr_subscr_rx_ciph_res(conn->vsub, &ciph_res);
}

struct gsm_subscriber_connection *msc_subscr_con_allocate(struct gsm_network *network)
{
	struct gsm_subscriber_connection *conn;

	conn = talloc_zero(network, struct gsm_subscriber_connection);
	if (!conn)
		return NULL;

	conn->network = network;
	llist_add_tail(&conn->entry, &network->subscr_conns);
	return conn;
}

void msc_subscr_cleanup(struct vlr_subscr *vsub)
{
	if (!vsub)
		return;
	vsub->lu_fsm = NULL;
}

void msc_subscr_con_cleanup(struct gsm_subscriber_connection *conn)
{
	if (!conn)
		return;

	msc_release_anchor(conn);

	if (conn->vsub) {
		DEBUGP(DRLL, "subscr %s: Freeing subscriber connection\n",
		       vlr_subscr_name(conn->vsub));
		msc_subscr_cleanup(conn->vsub);
		vlr_subscr_put(conn->vsub);
		conn->vsub = NULL;
	} else
		DEBUGP(DRLL, "Freeing subscriber connection"
		       " with NULL subscriber\n");

	if (!conn->conn_fsm)
		return;

	osmo_fsm_inst_term(conn->conn_fsm,
			   (conn->conn_fsm->state == SUBSCR_CONN_S_RELEASED)
				? OSMO_FSM_TERM_REGULAR
				: OSMO_FSM_TERM_ERROR,
			   NULL);
	conn->conn_fsm = NULL;
}

void msc_subscr_con_free(struct gsm_subscriber_connection *conn)
{
	if (!conn)
		return;

	msc_subscr_con_cleanup(conn);

	llist_del(&conn->entry);
	talloc_free(conn);
}


/* MSC-level operations to be called by libbsc in NITB */
static struct bsc_api msc_handler = {
	.sapi_n_reject = msc_sapi_n_reject,
	.compl_l3 = msc_compl_l3,
	.dtap = msc_dtap,
	.clear_request = msc_clear_request,
	.assign_compl = msc_assign_compl,
	.assign_fail = msc_assign_fail,
	.classmark_chg = msc_classmark_chg,
	.cipher_mode_compl = msc_ciph_m_compl,
	.conn_cleanup = msc_subscr_con_cleanup,
};

struct bsc_api *msc_bsc_api() {
	return &msc_handler;
}

void msc_close_connection(struct gsm_subscriber_connection *conn)
{
	if (!conn)
		return;
	if (conn->in_release)
		return;
	if (!conn->conn_fsm) {
		/* No FSM means no valid process is ongoing. Discard right
		 * away. */
		msc_subscr_con_free(conn);
		return;
	}
	if (conn->conn_fsm->state == SUBSCR_CONN_S_RELEASED)
		return;
	osmo_fsm_inst_dispatch(conn->conn_fsm, SUBSCR_CONN_E_CN_CLOSE, NULL);
}

/* increment the ref-count. Needs to be called by every user */
struct gsm_subscriber_connection *_subscr_con_get(struct gsm_subscriber_connection *conn,
						  const char *file, int line)
{
	OSMO_ASSERT(conn);

	if (conn->in_release)
		return NULL;

	conn->use_count++;
	LOGPSRC(DMSC, LOGL_DEBUG, file, line,
		"subscr %s: increased subscr_con use_count to %u\n",
		vlr_subscr_name(conn->vsub), conn->use_count);

	return conn;
}

/* decrement the ref-count. Once it reaches zero, we release */
void _subscr_con_put(struct gsm_subscriber_connection *conn,
		     const char *file, int line)
{
	OSMO_ASSERT(conn);

	if (conn->use_count == 0) {
		LOGP(DMSC, LOGL_ERROR, "trying to decrement conn use count, but is alrady 0\n");
		return;
	}

	conn->use_count--;
	LOGPSRC(DMSC, LOGL_DEBUG, file, line,
		"subscr %s: decreased subscr_conn use_count to %u\n",
		vlr_subscr_name(conn->vsub), conn->use_count);

#if 0
	if (conn->use_count == 0 && conn->conn_fsm)
		osmo_fsm_inst_dispatch(conn->conn_fsm, SUBSCR_CONN_E_MO_CLOSE, NULL);
#endif
}
