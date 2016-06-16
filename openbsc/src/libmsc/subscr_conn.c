/* MSC subscriber connection implementation */

/*
 * (C) 2016 by sysmocom s.m.f.c. <info@sysmocom.de>
 * All Rights Reserved
 *
 * Author: Neels Hofmeyr
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

#include <osmocom/core/logging.h>
#include <osmocom/core/fsm.h>

#include <openbsc/osmo_msc.h>
#include <openbsc/vlr.h>
#include <openbsc/debug.h>
#include <openbsc/transaction.h>

static const struct value_string subscr_conn_fsm_event_names[] = {
	OSMO_VALUE_STRING(SUBSCR_CONN_E_INVALID),
	OSMO_VALUE_STRING(SUBSCR_CONN_E_ACCEPTED),
	OSMO_VALUE_STRING(SUBSCR_CONN_E_BUMP),
	OSMO_VALUE_STRING(SUBSCR_CONN_E_MO_CLOSE),
	OSMO_VALUE_STRING(SUBSCR_CONN_E_CN_CLOSE),
	OSMO_VALUE_STRING(SUBSCR_CONN_E_CLOSE_CONF),
	{ 0, NULL }
};

const struct value_string subscr_conn_from_names[] = {
	OSMO_VALUE_STRING(SUBSCR_CONN_FROM_INVALID),
	OSMO_VALUE_STRING(SUBSCR_CONN_FROM_LU),
	OSMO_VALUE_STRING(SUBSCR_CONN_FROM_CM_SERVICE_REQ),
	OSMO_VALUE_STRING(SUBSCR_CONN_FROM_PAGING_RESP),
	{ 0, NULL }
};

static void paging_resp(struct gsm_subscriber_connection *conn,
			       enum gsm_paging_event pe)
{
	subscr_paging_dispatch(GSM_HOOK_RR_PAGING, pe, NULL, conn, conn->subscr);
}

void subscr_conn_fsm_new(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct gsm_subscriber_connection *conn = fi->priv;
	enum subscr_conn_from from = SUBSCR_CONN_FROM_INVALID;
	enum gsm_paging_event pe;

	if (data) {
		from = *(enum subscr_conn_from*)data;
		LOGPFSM(fi, "%s\n", subscr_conn_from_name(from));
	}

	/* If accepted, transition the state, all other cases mean failure. */
	switch (event) {
	case SUBSCR_CONN_E_ACCEPTED:
		osmo_fsm_inst_state_chg(fi, SUBSCR_CONN_S_ACCEPTED, 0, 0);
		break;

	case SUBSCR_CONN_E_MO_CLOSE:
	case SUBSCR_CONN_E_CN_CLOSE:
	case SUBSCR_CONN_E_CLOSE_CONF:
		break;

	default:
		LOGPFSM(fi, "Unexpected event: %d %s\n",
			event, osmo_fsm_event_name(fi->fsm, event));
		break;
	}

	/* if appropriate, signal paging success or failure */
	if (from == SUBSCR_CONN_FROM_PAGING_RESP) {
		pe = (fi->state == SUBSCR_CONN_S_ACCEPTED)?
			GSM_PAGING_SUCCEEDED : GSM_PAGING_EXPIRED;
		paging_resp(conn, pe);
	}

	/* On failure, discard the conn */
	if (fi->state != SUBSCR_CONN_S_ACCEPTED) {
		/* TODO: on MO_CLOSE or CN_CLOSE, first go to RELEASING and
		 * await BSC confirmation? */
		osmo_fsm_inst_state_chg(fi, SUBSCR_CONN_S_RELEASED, 0, 0);
		return;
	}

	/* On success, handle pending requests and/or close conn */

	if (from == SUBSCR_CONN_FROM_CM_SERVICE_REQ) {
		conn->received_cm_service_request = true;
		LOGPFSM(fi, "received_cm_service_request = true\n");
	}

	osmo_fsm_inst_dispatch(fi, SUBSCR_CONN_E_BUMP, data);
}

#if 0
	case SUBSCR_CONN_E_PARQ_SUCCESS:
		osmo_fsm_inst_state_chg(fi, SUBSCR_CONN_S_ACCEPTED, 0, 0);
		accept_conn = true;
		/* fall through */
	case SUBSCR_CONN_E_PARQ_FAILURE:
		parq_type = data ? *(enum vlr_parq_type*)data : VLR_PR_ARQ_T_INVALID;
		switch (parq_type) {

		case VLR_PR_ARQ_T_CM_SERV_REQ:
			accept_conn = handle_cm_serv_result(fi, accept_conn);
			break;

		case VLR_PR_ARQ_T_PAGING_RESP:
			accept_conn = handle_paging_result(fi, accept_conn);
			break;

		default:
			LOGPFSML(fi, LOGL_ERROR,
				 "Invalid VLR Process Access Request type"
				 " %d\n", parq_type);
			accept_conn = false;
			break;
		}
		break;
#endif

static void subscr_conn_fsm_bump(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct gsm_subscriber_connection *conn = fi->priv;

	if (conn->silent_call)
		return;

	if (conn->received_cm_service_request)
		return;

	/* is this needed? */
	if (conn->subscr && !llist_empty(&conn->subscr->requests))
		return;

	if (trans_has_conn(conn))
		return;

	osmo_fsm_inst_state_chg(fi, SUBSCR_CONN_S_RELEASED, 0, 0);
}

static void subscr_conn_fsm_accepted(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	switch (event) {
	case SUBSCR_CONN_E_BUMP:
		subscr_conn_fsm_bump(fi, event, data);
		return;

	default:
		break;
	}
	/* Whatever unexpected happens in the accepted state, it means release.
	 * Even if an unexpected event is passed, the safest thing to do is
	 * discard the conn. We don't expect another SUBSCR_CONN_E_ACCEPTED. */
	osmo_fsm_inst_state_chg(fi, SUBSCR_CONN_S_RELEASED, 0, 0);
}

static void subscr_conn_fsm_release(struct osmo_fsm_inst *fi, uint32_t prev_state)
{
	struct gsm_subscriber_connection *conn = fi->priv;
	if (!conn)
		return;

	/* temporary hack, see owned_by_msc */
	if (!conn->owned_by_msc) {
		DEBUGP(DMM, "%s leaving bsc_subscr_con_free() to bsc_api.c, owned_by_msc = false\n",
		       subscr_name(conn->subscr));
		return;
	}

	DEBUGP(DMM, "%s calling bsc_subscr_con_free(), owned_by_msc = true\n",
	       subscr_name(conn->subscr));
	gsm0808_clear(conn);
	bsc_subscr_con_free(conn);
}

#define S(x)	(1 << (x))

static const struct osmo_fsm_state subscr_conn_fsm_states[] = {
	[SUBSCR_CONN_S_NEW] = {
		.name = OSMO_STRINGIFY(SUBSCR_CONN_S_NEW),
		.in_event_mask = S(SUBSCR_CONN_E_ACCEPTED) |
				 S(SUBSCR_CONN_E_MO_CLOSE) |
				 S(SUBSCR_CONN_E_CN_CLOSE) |
				 S(SUBSCR_CONN_E_CLOSE_CONF),
		.out_state_mask = S(SUBSCR_CONN_S_ACCEPTED) |
				  S(SUBSCR_CONN_S_RELEASED),
		.action = subscr_conn_fsm_new,
	},
	[SUBSCR_CONN_S_ACCEPTED] = {
		.name = OSMO_STRINGIFY(SUBSCR_CONN_S_ACCEPTED),
		/* allow everything to release for any odd behavior */
		.in_event_mask = S(SUBSCR_CONN_E_ACCEPTED) |
				 S(SUBSCR_CONN_E_BUMP) |
				 S(SUBSCR_CONN_E_MO_CLOSE) |
				 S(SUBSCR_CONN_E_CN_CLOSE) |
				 S(SUBSCR_CONN_E_CLOSE_CONF),
		.out_state_mask = S(SUBSCR_CONN_S_RELEASED),
		.action = subscr_conn_fsm_accepted,
	},
	[SUBSCR_CONN_S_RELEASED] = {
		.name = OSMO_STRINGIFY(SUBSCR_CONN_S_RELEASED),
		.onenter = subscr_conn_fsm_release,
	},
};

static struct osmo_fsm subscr_conn_fsm = {
	.name = "Subscr_Conn",
	.states = subscr_conn_fsm_states,
	.num_states = ARRAY_SIZE(subscr_conn_fsm_states),
	.allstate_event_mask = 0,
	.allstate_action = NULL,
	.log_subsys = DVLR,
	.event_names = subscr_conn_fsm_event_names,
};

int msc_create_conn_fsm(struct gsm_subscriber_connection *conn, const char *id)
{
	struct osmo_fsm_inst *fi;
	OSMO_ASSERT(conn);

	if (conn->conn_fsm) {
		LOGP(DMM, LOGL_ERROR,
		     "%s: Error: connection already in use\n", id);
		return -EINVAL;
	}

	fi = osmo_fsm_inst_alloc(&subscr_conn_fsm, conn, conn, LOGL_DEBUG, id);

	if (!fi) {
		LOGP(DMM, LOGL_ERROR,
		     "%s: Failed to allocate subscr conn master FSM\n", id);
		return -ENOMEM;
	}
	conn->conn_fsm = fi;
	return 0;
}

bool msc_subscr_conn_is_accepted(struct gsm_subscriber_connection *conn)
{
	if (!conn)
		return false;
	if (!conn->subscr)
		return false;
	if (!conn->conn_fsm)
		return false;
	if (conn->conn_fsm->state != SUBSCR_CONN_S_ACCEPTED)
		return false;
	return true;
}

void msc_subscr_conn_init(void)
{
	osmo_fsm_register(&subscr_conn_fsm);
}
