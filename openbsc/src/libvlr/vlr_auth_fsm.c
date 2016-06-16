/* Osmocom Visitor Location Register (VLR) Autentication FSM */

/* (C) 2016 by Harald Welte <laforge@gnumonks.org>
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


#include <osmocom/core/fsm.h>
#include <osmocom/core/utils.h>
#include <osmocom/gsm/gsup.h>
#include <openbsc/vlr.h>
#include <openbsc/debug.h>

#include "vlr_core.h"
#include "vlr_auth_fsm.h"

#define S(x)	(1 << (x))

static const struct value_string fsm_auth_event_names[] = {
	OSMO_VALUE_STRING(VLR_AUTH_E_START),
	OSMO_VALUE_STRING(VLR_AUTH_E_HLR_SAI_ACK),
	OSMO_VALUE_STRING(VLR_AUTH_E_HLR_SAI_NACK),
	OSMO_VALUE_STRING(VLR_AUTH_E_HLR_SAI_ABORT),
	OSMO_VALUE_STRING(VLR_AUTH_E_MS_AUTH_RESP),
	OSMO_VALUE_STRING(VLR_AUTH_E_MS_AUTH_FAIL),
	OSMO_VALUE_STRING(VLR_AUTH_E_MS_ID_IMSI),
	{ 0, NULL }
};

const struct value_string vlr_auth_fsm_result_names[] = {
	OSMO_VALUE_STRING(VLR_AUTH_RES_ABORTED),
	OSMO_VALUE_STRING(VLR_AUTH_RES_UNKNOWN_SUBSCR),
	OSMO_VALUE_STRING(VLR_AUTH_RES_PROC_ERR),
	OSMO_VALUE_STRING(VLR_AUTH_RES_AUTH_FAILED),
	OSMO_VALUE_STRING(VLR_AUTH_RES_PASSED),
	{0, NULL}
};

/* private state of the auth_fsm_instance */
struct auth_fsm_priv {
	struct vlr_subscr *vsub;
	bool by_imsi;
	bool is_r99;
	bool is_utran;
	bool auth_requested;

	int auth_tuple_max_use_count; /* see vlr->cfg instead */
};

/***********************************************************************
 * Utility functions
 ***********************************************************************/

/* Always use either vlr_subscr_get_auth_tuple() or vlr_subscr_has_auth_tuple()
 * instead, to ensure proper use count.
 * Return an auth tuple with the lowest use_count among the auth tuples. If
 * max_use_count >= 0, return NULL if all available auth tuples have a use
 * count > max_use_count. If max_use_count is negative, return a currently
 * least used auth tuple without enforcing a maximum use count.  If there are
 * no auth tuples, return NULL.
 */
static struct gsm_auth_tuple *
_vlr_subscr_next_auth_tuple(struct vlr_subscr *vsub, int max_use_count)
{
	unsigned int count;
	unsigned int idx;
	struct gsm_auth_tuple *at = NULL;
	unsigned int key_seq = GSM_KEY_SEQ_INVAL;

	if (!vsub)
		return NULL;

	if (vsub->last_tuple)
		key_seq = vsub->last_tuple->key_seq;

	if (key_seq == GSM_KEY_SEQ_INVAL)
		/* Start with 0 after increment modulo array size */
		idx = ARRAY_SIZE(vsub->auth_tuples) - 1;
	else
		idx = key_seq;

	for (count = ARRAY_SIZE(vsub->auth_tuples); count > 0; count--) {
		idx = (idx + 1) % ARRAY_SIZE(vsub->auth_tuples);

		if (vsub->auth_tuples[idx].key_seq == GSM_KEY_SEQ_INVAL)
			continue;

		if (!at || vsub->auth_tuples[idx].use_count < at->use_count)
			at = &vsub->auth_tuples[idx];
	}

	if (!at || (max_use_count >= 0 && at->use_count > max_use_count))
		return NULL;

	return at;
}

/* Return an auth tuple and increment its use count. */
static struct gsm_auth_tuple *
vlr_subscr_get_auth_tuple(struct vlr_subscr *vsub, int max_use_count)
{
	struct gsm_auth_tuple *at = _vlr_subscr_next_auth_tuple(vsub,
							       max_use_count);
	if (!at)
		return NULL;
	at->use_count++;
	return at;
}

/* Return whether an auth tuple with the given max_use_count is available. */
static bool vlr_subscr_has_auth_tuple(struct vlr_subscr *vsub,
				      int max_use_count)
{
	return _vlr_subscr_next_auth_tuple(vsub, max_use_count) != NULL;
}

static bool check_auth_resp(struct vlr_subscr *vsub, bool is_r99,
			    bool is_utran, const uint8_t *res,
			    uint8_t res_len)
{
	struct gsm_auth_tuple *at = vsub->last_tuple;
	struct osmo_auth_vector *vec = &at->vec;
	bool check_umts;
	OSMO_ASSERT(at);

	LOGVSUBP(LOGL_DEBUG, vsub, "received res: %s\n",
		 osmo_hexdump(res, res_len));

	/* RES must be present and at least 32bit */
	if (!res || res_len < sizeof(vec->sres)) {
		LOGVSUBP(LOGL_NOTICE, vsub, "AUTH RES missing or too short "
			 "(%u)\n", res_len);
		goto out_false;
	}

	check_umts = false;
	if (is_r99 && (vec->auth_types & OSMO_AUTH_TYPE_UMTS)) {
		check_umts = true;
		/* We have a R99 capable UE and have a UMTS AKA capable USIM.
		 * However, the ME may still choose to only perform GSM AKA, as
		 * long as the bearer is GERAN */
		if (res_len != vec->res_len) {
			if (is_utran) {
				LOGVSUBP(LOGL_NOTICE, vsub,
					 "AUTH via UTRAN but "
					 "res_len(%u) != vec->res_len(%u)\n",
					 res_len, vec->res_len);
				goto out_false;
			}
			check_umts = false;
		}
	}

	if (check_umts) {
		if (res_len != vec->res_len
		    || memcmp(res, vec->res, res_len)) {
			LOGVSUBP(LOGL_INFO, vsub, "UMTS AUTH failure:"
				 " mismatching res (expected res=%s)\n",
				 osmo_hexdump(vec->res, vec->res_len));
			goto out_false;
		}

		LOGVSUBP(LOGL_INFO, vsub, "AUTH established UMTS security"
			 " context\n");
		vsub->sec_ctx = VLR_SEC_CTX_UMTS;
		return true;
	} else {
		if (res_len != sizeof(vec->sres)
		    || memcmp(res, vec->sres, sizeof(vec->sres))) {
			LOGVSUBP(LOGL_INFO, vsub, "GSM AUTH failure:"
				 " mismatching sres (expected sres=%s)\n",
				 osmo_hexdump(vec->sres, sizeof(vec->sres)));
			goto out_false;
		}

		LOGVSUBP(LOGL_INFO, vsub, "AUTH established GSM security"
			 " context\n");
		vsub->sec_ctx = VLR_SEC_CTX_GSM;
		return true;
	}

out_false:
	vsub->sec_ctx = VLR_SEC_CTX_NONE;
	return false;
}

static void auth_fsm_onenter_failed(struct osmo_fsm_inst *fi, uint32_t prev_state)
{
	struct auth_fsm_priv *afp = fi->priv;
	struct vlr_subscr *vsub = afp->vsub;

	/* If authentication hasn't even started, e.g. the HLR sent no auth
	 * info, then we also don't need to tell the HLR about an auth failure.
	 */
	if (afp->auth_requested)
		vlr_subscr_tx_auth_fail_rep(vsub);
}

static bool is_umts_auth(struct auth_fsm_priv *afp,
			 uint32_t auth_types)
{
	if (!afp->is_r99)
		return false;
	if (!(auth_types & OSMO_AUTH_TYPE_UMTS))
		return false;
	return true;
}

/* Terminate the Auth FSM Instance and notify parent */
static void auth_fsm_term(struct osmo_fsm_inst *fi, enum vlr_auth_fsm_result res)
{
	struct auth_fsm_priv *afp = fi->priv;
	struct vlr_subscr *vsub = afp->vsub;

	LOGPFSM(fi, "Authentication terminating with result %s\n",
		vlr_auth_fsm_result_name(res));

	/* Do one final state transition (mostly for logging purpose) */
	if (res == VLR_AUTH_RES_PASSED)
		osmo_fsm_inst_state_chg(fi, VLR_SUB_AS_AUTHENTICATED, 0, 0);
	else
		osmo_fsm_inst_state_chg(fi, VLR_SUB_AS_AUTH_FAILED, 0, 0);

	/* return the result to the parent FSM */
	osmo_fsm_inst_term(fi, OSMO_FSM_TERM_REGULAR, &res);
	vsub->auth_fsm = NULL;
}

/* back-end function transmitting authentication. Caller ensures we have valid
 * tuple */
static int _vlr_subscr_authenticate(struct osmo_fsm_inst *fi)
{
	struct auth_fsm_priv *afp = fi->priv;
	struct vlr_subscr *vsub = afp->vsub;
	struct gsm_auth_tuple *at;

	/* Caller ensures we have vectors available */
	at = vlr_subscr_get_auth_tuple(vsub, afp->auth_tuple_max_use_count);
	if (!at) {
		LOGPFSML(fi, LOGL_ERROR, "A previous check ensured that an"
			 " auth tuple was available, but now there is in fact"
			 " none.\n");
		auth_fsm_term(fi, VLR_AUTH_RES_PROC_ERR);
		return -1;
	}

	LOGPFSM(fi, "got auth tuple: use_count=%d key_seq=%d\n",
		at->use_count, at->key_seq);

	OSMO_ASSERT(at);

	/* Transmit auth req to subscriber */
	afp->auth_requested = true;
	vsub->last_tuple = at;
	vsub->vlr->ops.tx_auth_req(vsub->msc_conn_ref, at,
				   is_umts_auth(afp, at->vec.auth_types));
	return 0;
}

/***********************************************************************
 * FSM State Action functions
 ***********************************************************************/

/* Initial State of TS 23.018 AUT_VLR */
static void auth_fsm_needs_auth(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct auth_fsm_priv *afp = fi->priv;
	struct vlr_subscr *vsub = afp->vsub;

	OSMO_ASSERT(event == VLR_AUTH_E_START);

	/* Start off with the default max_use_count, possibly change that if we
	 * need to re-use an old tuple. */
	afp->auth_tuple_max_use_count = vsub->vlr->cfg.auth_tuple_max_use_count;

	/* Check if we have vectors available */
	if (!vlr_subscr_has_auth_tuple(vsub, afp->auth_tuple_max_use_count)) {
		/* Obtain_Authentication_Sets_VLR */
		vlr_subscr_req_sai(vsub, NULL, NULL);
		osmo_fsm_inst_state_chg(fi, VLR_SUB_AS_NEEDS_AUTH_WAIT_AI,
					GSM_29002_TIMER_M, 0);
	} else {
		/* go straight ahead with sending auth request */
		osmo_fsm_inst_state_chg(fi, VLR_SUB_AS_WAIT_RESP,
					vlr_timer(vsub->vlr, 3260), 3260);
		_vlr_subscr_authenticate(fi);
	}
}

/* Waiting for Authentication Info from HLR */
static void auth_fsm_wait_ai(struct osmo_fsm_inst *fi, uint32_t event,
			     void *data)
{
	struct auth_fsm_priv *afp = fi->priv;
	struct vlr_subscr *vsub = afp->vsub;
	struct osmo_gsup_message *gsup = data;

	if (event == VLR_AUTH_E_HLR_SAI_NACK)
		LOGPFSM(fi, "GSUP: rx Auth Info Error cause: %d: %s\n",
			gsup->cause,
			get_value_string(gsm48_gmm_cause_names, gsup->cause));

	/* We are in what corresponds to the
	 * Wait_For_Authentication_Sets state of TS 23.018 OAS_VLR */
	if ((event == VLR_AUTH_E_HLR_SAI_ACK && !gsup->num_auth_vectors)
	    || (event == VLR_AUTH_E_HLR_SAI_NACK &&
		gsup->cause != GMM_CAUSE_IMSI_UNKNOWN)
	    || (event == VLR_AUTH_E_HLR_SAI_ABORT)) {
		if (vsub->vlr->cfg.auth_reuse_old_sets_on_error
		    && vlr_subscr_has_auth_tuple(vsub, -1)) {
			/* To re-use an old tuple, disable the max_use_count
			 * constraint. */
			afp->auth_tuple_max_use_count = -1;
			goto pass;
		}
		/* result = procedure error */
		auth_fsm_term(fi, VLR_AUTH_RES_PROC_ERR);
		return;
	}

	switch (event) {
	case VLR_AUTH_E_HLR_SAI_ACK:
		vlr_subscr_update_tuples(vsub, gsup);
		goto pass;
		break;
	case VLR_AUTH_E_HLR_SAI_NACK:
		auth_fsm_term(fi,
			      gsup->cause == GMM_CAUSE_IMSI_UNKNOWN?
				      VLR_AUTH_RES_UNKNOWN_SUBSCR
				      : VLR_AUTH_RES_PROC_ERR);
		break;
	}

	return;
pass:
	osmo_fsm_inst_state_chg(fi, VLR_SUB_AS_WAIT_RESP,
				vlr_timer(vsub->vlr, 3260), 3260);
	_vlr_subscr_authenticate(fi);
}

/* Waiting for Authentication Response from MS */
static void auth_fsm_wait_auth_resp(struct osmo_fsm_inst *fi, uint32_t event,
				    void *data)
{
	struct auth_fsm_priv *afp = fi->priv;
	struct vlr_subscr *vsub = afp->vsub;
	struct vlr_instance *vlr = vsub->vlr;
	struct vlr_auth_resp_par *par = data;
	int rc;

	switch (event) {
	case VLR_AUTH_E_MS_AUTH_RESP:
		rc = check_auth_resp(vsub, par->is_r99, par->is_utran,
				     par->res, par->res_len);
		if (rc == false) {
			if (!afp->by_imsi) {
				vlr->ops.tx_id_req(vsub->msc_conn_ref,
						   GSM_MI_TYPE_IMSI);
				osmo_fsm_inst_state_chg(fi,
						VLR_SUB_AS_WAIT_ID_IMSI,
						vlr_timer(vlr, 3270), 3270);
			} else {
				auth_fsm_term(fi, VLR_AUTH_RES_AUTH_FAILED);
			}
		} else {
			auth_fsm_term(fi, VLR_AUTH_RES_PASSED);
		}
		break;
	case VLR_AUTH_E_MS_AUTH_FAIL:
		if (par->auts) {
			/* First failure, start re-sync attempt */
			vlr_subscr_req_sai(vsub, par->auts,
					   vsub->last_tuple->vec.rand);
			osmo_fsm_inst_state_chg(fi,
					VLR_SUB_AS_NEEDS_AUTH_WAIT_SAI_RESYNC,
					GSM_29002_TIMER_M, 0);
		} else
			auth_fsm_term(fi, VLR_AUTH_RES_AUTH_FAILED);
		break;
	}
}

/* Waiting for Authentication Info from HLR (resync case) */
static void auth_fsm_wait_ai_resync(struct osmo_fsm_inst *fi,
				    uint32_t event, void *data)
{
	struct auth_fsm_priv *afp = fi->priv;
	struct vlr_subscr *vsub = afp->vsub;
	struct osmo_gsup_message *gsup = data;

	/* We are in what corresponds to the
	 * Wait_For_Authentication_Sets state of TS 23.018 OAS_VLR */
	if ((event == VLR_AUTH_E_HLR_SAI_ACK && !gsup->num_auth_vectors) ||
	    (event == VLR_AUTH_E_HLR_SAI_NACK &&
	     gsup->cause != GMM_CAUSE_IMSI_UNKNOWN) ||
	    (event == VLR_AUTH_E_HLR_SAI_ABORT)) {
		/* result = procedure error */
		auth_fsm_term(fi, VLR_AUTH_RES_PROC_ERR);
	}
	switch (event) {
	case VLR_AUTH_E_HLR_SAI_ACK:
		vlr_subscr_update_tuples(vsub, gsup);
		goto pass;
		break;
	case VLR_AUTH_E_HLR_SAI_NACK:
		auth_fsm_term(fi,
			      gsup->cause == GMM_CAUSE_IMSI_UNKNOWN?
				      VLR_AUTH_RES_UNKNOWN_SUBSCR
				      : VLR_AUTH_RES_PROC_ERR);
		break;
	}

	return;
pass:
	osmo_fsm_inst_state_chg(fi, VLR_SUB_AS_WAIT_RESP_RESYNC,
				vlr_timer(vsub->vlr, 3260), 3260);
	_vlr_subscr_authenticate(fi);
}

/* Waiting for AUTH RESP from MS (re-sync case) */
static void auth_fsm_wait_auth_resp_resync(struct osmo_fsm_inst *fi,
					   uint32_t event, void *data)
{
	struct auth_fsm_priv *afp = fi->priv;
	struct vlr_subscr *vsub = afp->vsub;
	struct vlr_auth_resp_par *par = data;
	struct vlr_instance *vlr = vsub->vlr;
	int rc;

	switch (event) {
	case VLR_AUTH_E_MS_AUTH_RESP:
		rc = check_auth_resp(vsub, par->is_r99, par->is_utran,
				     par->res, par->res_len);
		if (rc == false) {
			if (!afp->by_imsi) {
				vlr->ops.tx_id_req(vsub->msc_conn_ref,
						   GSM_MI_TYPE_IMSI);
				osmo_fsm_inst_state_chg(fi,
						VLR_SUB_AS_WAIT_ID_IMSI,
						vlr_timer(vlr, 3270), 3270);
			} else {
				/* Result = Aborted */
				auth_fsm_term(fi, VLR_AUTH_RES_ABORTED);
			}
		} else {
			/* Result = Pass */
			auth_fsm_term(fi, VLR_AUTH_RES_PASSED);
		}
		break;
	case VLR_AUTH_E_MS_AUTH_FAIL:
		/* Second failure: Result = Fail */
		auth_fsm_term(fi, VLR_AUTH_RES_AUTH_FAILED);
		break;
	}
}

/* AUT_VLR waiting for Obtain_IMSI_VLR result */
static void auth_fsm_wait_imsi(struct osmo_fsm_inst *fi, uint32_t event,
				void *data)
{
	struct auth_fsm_priv *afp = fi->priv;
	struct vlr_subscr *vsub = afp->vsub;
	const char *mi_string = data;

	switch (event) {
	case VLR_AUTH_E_MS_ID_IMSI:
		if (vsub->imsi[0]
		    && !vlr_subscr_matches_imsi(vsub, mi_string)) {
			LOGVSUBP(LOGL_ERROR, vsub, "IMSI in ID RESP differs:"
				 " %s\n", mi_string);
		} else {
			strncpy(vsub->imsi, mi_string, sizeof(vsub->imsi));
			vsub->imsi[sizeof(vsub->imsi)-1] = '\0';
		}
		/* retry with identity=IMSI */
		afp->by_imsi = true;
		osmo_fsm_inst_state_chg(fi, VLR_SUB_AS_NEEDS_AUTH, 0, 0);
		osmo_fsm_inst_dispatch(fi, VLR_AUTH_E_START, NULL);
		break;
	}
}

static const struct osmo_fsm_state auth_fsm_states[] = {
	[VLR_SUB_AS_NEEDS_AUTH] = {
		.name = OSMO_STRINGIFY(VLR_SUB_AS_NEEDS_AUTH),
		.in_event_mask = S(VLR_AUTH_E_START),
		.out_state_mask = S(VLR_SUB_AS_NEEDS_AUTH_WAIT_AI) |
				  S(VLR_SUB_AS_WAIT_RESP),
		.action = auth_fsm_needs_auth,
	},
	[VLR_SUB_AS_NEEDS_AUTH_WAIT_AI] = {
		.name = OSMO_STRINGIFY(VLR_SUB_AS_NEEDS_AUTH_WAIT_AI),
		.in_event_mask = S(VLR_AUTH_E_HLR_SAI_ACK) |
				 S(VLR_AUTH_E_HLR_SAI_NACK),
		.out_state_mask = S(VLR_SUB_AS_AUTH_FAILED) |
				  S(VLR_SUB_AS_WAIT_RESP),
		.action = auth_fsm_wait_ai,
	},
	[VLR_SUB_AS_WAIT_RESP] = {
		.name = OSMO_STRINGIFY(VLR_SUB_AS_WAIT_RESP),
		.in_event_mask = S(VLR_AUTH_E_MS_AUTH_RESP) |
				 S(VLR_AUTH_E_MS_AUTH_FAIL),
		.out_state_mask = S(VLR_SUB_AS_WAIT_ID_IMSI) |
				  S(VLR_SUB_AS_AUTH_FAILED) |
				  S(VLR_SUB_AS_AUTHENTICATED) |
				  S(VLR_SUB_AS_NEEDS_AUTH_WAIT_SAI_RESYNC),
		.action = auth_fsm_wait_auth_resp,
	},
	[VLR_SUB_AS_NEEDS_AUTH_WAIT_SAI_RESYNC] = {
		.name = OSMO_STRINGIFY(VLR_SUB_AS_NEEDS_AUTH_WAIT_SAI_RESYNC),
		.in_event_mask = S(VLR_AUTH_E_HLR_SAI_ACK) |
				 S(VLR_AUTH_E_HLR_SAI_NACK),
		.out_state_mask = S(VLR_SUB_AS_AUTH_FAILED) |
				  S(VLR_SUB_AS_WAIT_RESP_RESYNC),
		.action = auth_fsm_wait_ai_resync,
	},
	[VLR_SUB_AS_WAIT_RESP_RESYNC] = {
		.name = OSMO_STRINGIFY(VLR_SUB_AS_WAIT_RESP_RESYNC),
		.in_event_mask = S(VLR_AUTH_E_MS_AUTH_RESP) |
				 S(VLR_AUTH_E_MS_AUTH_FAIL),
		.out_state_mask = S(VLR_SUB_AS_AUTH_FAILED) |
				  S(VLR_SUB_AS_AUTHENTICATED),
		.action = auth_fsm_wait_auth_resp_resync,
	},
	[VLR_SUB_AS_WAIT_ID_IMSI] = {
		.name = OSMO_STRINGIFY(VLR_SUB_AS_WAIT_ID_IMSI),
		.in_event_mask = S(VLR_AUTH_E_MS_ID_IMSI),
		.out_state_mask = S(VLR_SUB_AS_NEEDS_AUTH),
		.action = auth_fsm_wait_imsi,
	},
	[VLR_SUB_AS_AUTHENTICATED] = {
		.name = OSMO_STRINGIFY(VLR_SUB_AS_AUTHENTICATED),
		.in_event_mask = 0,
		.out_state_mask = 0,
	},
	[VLR_SUB_AS_AUTH_FAILED] = {
		.name = OSMO_STRINGIFY(VLR_SUB_AS_AUTH_FAILED),
		.in_event_mask = 0,
		.out_state_mask = 0,
		.onenter = auth_fsm_onenter_failed,
	},
};

struct osmo_fsm vlr_auth_fsm = {
	.name = "VLR_Authenticate",
	.states = auth_fsm_states,
	.num_states = ARRAY_SIZE(auth_fsm_states),
	.allstate_event_mask = 0,
	.allstate_action = NULL,
	.log_subsys = DVLR,
	.event_names = fsm_auth_event_names,
};

/***********************************************************************
 * User API (for SGSN/MSC code)
 ***********************************************************************/

/* MSC->VLR: Start Procedure Authenticate_VLR (TS 23.012 Ch. 4.1.2.2) */
struct osmo_fsm_inst *auth_fsm_start(struct vlr_subscr *vsub,
				     uint32_t log_level,
				     struct osmo_fsm_inst *parent,
				     uint32_t parent_term_event,
				     bool is_r99,
				     bool is_utran)
{
	struct osmo_fsm_inst *fi;
	struct auth_fsm_priv *afp;

	fi = osmo_fsm_inst_alloc_child(&vlr_auth_fsm, parent,
					parent_term_event);


	afp = talloc_zero(fi, struct auth_fsm_priv);
	if (!afp) {
		osmo_fsm_inst_dispatch(parent, parent_term_event, 0);
		return NULL;
	}

	afp->vsub = vsub;
	if (vsub->imsi[0])
		afp->by_imsi = true;
	afp->is_r99 = is_r99;
	afp->is_utran = is_utran;
	fi->priv = afp;
	vsub->auth_fsm = fi;

	osmo_fsm_inst_dispatch(fi, VLR_AUTH_E_START, NULL);

	return fi;
}
