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
#include <osmocom/gsm/gsup.h>
#include <openbsc/vlr.h>
#include <openbsc/debug.h>

#include "vlr_core.h"
#include "vlr_auth_fsm.h"

#define S(x)	(1 << (x))

static const struct value_string fsm_auth_event_names[] = {
	{ VLR_AUTH_E_START, 		"START" },
	{ VLR_AUTH_E_HLR_SAI_ACK,	"HLR-SAI-ACK" },
	{ VLR_AUTH_E_HLR_SAI_NACK,	"HLR-SAI-NACK" },
	{ VLR_AUTH_E_HLR_SAI_ABORT,	"HLR-SAI-ABORT" },
	{ VLR_AUTH_E_MS_AUTH_RESP,	"MS-AUTH-RESP" },
	{ VLR_AUTH_E_MS_AUTH_FAIL,	"MS-AUTH-FAIL" },
	{ VLR_AUTH_E_MS_ID_IMSI,	"MS-ID-IMSI" },
	{ 0, NULL }
};

/* private state of the auth_fsm_instance */
struct auth_fsm_priv {
	struct vlr_subscriber *vsub;
	bool by_imsi;
};

/***********************************************************************
 * Utility functions
 ***********************************************************************/

static struct gsm_auth_tuple *
vlr_sub_get_auth_tuple(struct vlr_subscriber *vsub, unsigned int key_seq)
{
	unsigned int count;
	unsigned int idx;
	struct gsm_auth_tuple *at = NULL;

	if (!vsub)
		return NULL;

	if (key_seq == GSM_KEY_SEQ_INVAL)
		/* Start with 0 after increment moduleo array size */
		idx = ARRAY_SIZE(vsub->auth_tuples) - 1;
	else
		idx = key_seq;

	for (count = ARRAY_SIZE(vsub->auth_tuples); count > 0; count--) {
		idx = (idx + 1) % ARRAY_SIZE(vsub->auth_tuples);

		if (vsub->auth_tuples[idx].key_seq == GSM_KEY_SEQ_INVAL)
			continue;

		if (vsub->auth_tuples[idx].use_count == 0) {
			at = &vsub->auth_tuples[idx];
			at->use_count++;
			return at;
		}
	}
	return NULL;
}

static bool check_auth_resp(struct vlr_subscriber *vsub, bool is_r99,
			    bool is_utran, const uint8_t *res,
			    uint8_t res_len)
{
	struct gsm_auth_tuple *at = vsub->last_tuple;
	struct osmo_auth_vector *vec = &at->vec;
	OSMO_ASSERT(at);

	LOGVSUBP(LOGL_DEBUG, vsub, "expected res: %s\n",
		 osmo_hexdump(vec->res, vec->res_len));
	LOGVSUBP(LOGL_DEBUG, vsub, "received res: %s\n",
		 osmo_hexdump(res, res_len));

	/* RES must be present and at leat 32bit */
	if (!res || res_len < 4) {
		LOGVSUBP(LOGL_NOTICE, vsub, "AUTH RES missing or too short "
			 "(%u)\n", res_len);
		goto out_false;
	}

	if (is_r99 && vec->auth_types & OSMO_AUTH_TYPE_UMTS) {
		/* We have a R99 capable UE and have a UMTS AKA capable USIM.
		 * However, the ME may still chose to only perform GSM AKA, as
		 * long as the bearer is GERAN */
		if (is_utran && res_len != vec->res_len) {
			LOGVSUBP(LOGL_NOTICE, vsub, "AUTH via UTRAN but "
				 "res_len(%u) != vec->res_len(%u)\n",
				 res_len, vec->res_len);
			goto out_false;
		}
	}

	if (res_len == vec->res_len && !memcmp(res, vec->res, res_len)) {
		/* We have established a UMTS Security Context */
		LOGVSUBP(LOGL_INFO, vsub, "AUTH established UMTS security "
			 "context\n");
		vsub->sec_ctx = VLR_SEC_CTX_UMTS;
		return true;
	} else if (res_len == 4 && !memcmp(res, vec->sres, 4)) {
		/* We have establieshed a GSM Security Context */
		LOGVSUBP(LOGL_INFO, vsub, "AUTH established GSM security "
			 "context\n");
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
	struct vlr_subscriber *vsub = afp->vsub;

	vlr_sub_tx_auth_fail_rep(vsub);
}

/* back-end function transmitting authentication. Caller ensures we have valid
 * tuple */
static int _vlr_sub_authenticate(struct vlr_subscriber *vsub)
{
	struct gsm_auth_tuple *at;
	unsigned int last_keyseq = GSM_KEY_SEQ_INVAL;

	if (vsub->last_tuple)
		last_keyseq = vsub->last_tuple->key_seq;

	/* Caller ensures we have vectors available */
	at = vlr_sub_get_auth_tuple(vsub, last_keyseq);
	OSMO_ASSERT(at && at->vec.res && at->vec.res_len >=4);

	/* Transmit auth req to subscriber */
	vsub->last_tuple = at;
	vsub->vlr->ops.tx_auth_req(vsub->msc_conn_ref, at);

	return 0;
}

/* Terminate the Auth FSM Instance and notify parent */
static void auth_fsm_term(struct osmo_fsm_inst *fi, enum vlr_auth_fsm_result res)
{
	struct auth_fsm_priv *afp = fi->priv;
	struct vlr_subscriber *vsub = afp->vsub;

	/* Do one final state transition (mostly for logging purpose) */
	if (res == VLR_AUTH_RES_PASSED)
		osmo_fsm_inst_state_chg(fi, VLR_SUB_AS_AUTHENTICATED, 0, 0);
	else
		osmo_fsm_inst_state_chg(fi, VLR_SUB_AS_AUTH_FAILED, 0, 0);

	/* return the result to the parent FSM */
	osmo_fsm_inst_term(fi, OSMO_FSM_TERM_REGULAR, &res);
	vsub->auth_fsm = NULL;
}

/***********************************************************************
 * FSM State Action functions
 ***********************************************************************/

/* Initial State of TS 23.018 AUT_VLR */
static void auth_fsm_needs_auth(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct auth_fsm_priv *afp = fi->priv;
	struct vlr_subscriber *vsub = afp->vsub;
	unsigned int last_keyseq = GSM_KEY_SEQ_INVAL;
	struct gsm_auth_tuple *at;

	OSMO_ASSERT(event == VLR_AUTH_E_START);

	if (vsub->last_tuple)
		last_keyseq = vsub->last_tuple->key_seq;

	/* Check if we have vectors available */
	at = vlr_sub_get_auth_tuple(vsub, last_keyseq);
	if (!at) {
		/* Obtain_Authentication_Sets_VLR */
		vlr_sub_req_sai(vsub, NULL, NULL);
		osmo_fsm_inst_state_chg(fi, VLR_SUB_AS_NEEDS_AUTH_WAIT_AI,
					GSM_29002_TIMER_M, 0);
	} else {
		/* go straight ahead with sending auth request */
		osmo_fsm_inst_state_chg(fi, VLR_SUB_AS_WAIT_RESP,
					vlr_timer(vsub->vlr, 3260), 3260);
		_vlr_sub_authenticate(vsub);
	}
}

/* Waiting for Authentication Info from HLR */
static void auth_fsm_wait_ai(struct osmo_fsm_inst *fi, uint32_t event,
			     void *data)
{
	struct auth_fsm_priv *afp = fi->priv;
	struct vlr_subscriber *vsub = afp->vsub;
	struct osmo_gsup_message *gsup = data;
	bool auth_sets_available_in_vlr;

	if (vlr_sub_get_auth_tuple(vsub, 0))
		auth_sets_available_in_vlr = true;

	/* We are in what corresponds to the
	 * Wait_For_Authentication_Sets state of TS 23.018 OAS_VLR */
	if ((event == VLR_AUTH_E_HLR_SAI_ACK && !gsup->num_auth_vectors) ||
	    (event == VLR_AUTH_E_HLR_SAI_NACK &&
	     gsup->cause != GMM_CAUSE_IMSI_UNKNOWN) ||
	    (event == VLR_AUTH_E_HLR_SAI_ABORT)) {
		if (auth_sets_available_in_vlr) {
			if (vsub->vlr->cfg.auth_reuse_old_sets) {
				goto pass;
			} else {
				/* result = procedure error */
				auth_fsm_term(fi, VLR_AUTH_RES_PROC_ERR);
			}
		}
	}
	switch (event) {
	case VLR_AUTH_E_HLR_SAI_ACK:
		vlr_sub_update_tuples(vsub, gsup);
		goto pass;
		break;
	case VLR_AUTH_E_HLR_SAI_NACK:
		/* lesult = unknown subscriber */
		auth_fsm_term(fi, VLR_AUTH_RES_UNKNOWN_SUBSCR);
		break;
	}

	return;
pass:
	osmo_fsm_inst_state_chg(fi, VLR_SUB_AS_WAIT_RESP,
				vlr_timer(vsub->vlr, 3260), 3260);
	_vlr_sub_authenticate(vsub);
}

/* Waiting for Authentication Response from MS */
static void auth_fsm_wait_auth_resp(struct osmo_fsm_inst *fi, uint32_t event,
				    void *data)
{
	struct auth_fsm_priv *afp = fi->priv;
	struct vlr_subscriber *vsub = afp->vsub;
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
		/* First failure, start re-sync attempt */
		vlr_sub_req_sai(vsub, par->auts, vsub->last_tuple->vec.rand);
		osmo_fsm_inst_state_chg(fi,
				VLR_SUB_AS_NEEDS_AUTH_WAIT_SAI_RESYNC,
				GSM_29002_TIMER_M, 0);
		break;
	}
}

/* Waiting for Authentication Info from HLR (resync case) */
static void auth_fsm_wait_ai_resync(struct osmo_fsm_inst *fi,
				    uint32_t event, void *data)
{
	struct auth_fsm_priv *afp = fi->priv;
	struct vlr_subscriber *vsub = afp->vsub;
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
		vlr_sub_update_tuples(vsub, gsup);
		goto pass;
		break;
	case VLR_AUTH_E_HLR_SAI_NACK:
		auth_fsm_term(fi, VLR_AUTH_RES_UNKNOWN_SUBSCR);
		break;
	}

	return;
pass:
	osmo_fsm_inst_state_chg(fi, VLR_SUB_AS_WAIT_RESP_RESYNC,
				vlr_timer(vsub->vlr, 3260), 3260);
	_vlr_sub_authenticate(vsub);
}

/* Waiting for AUTH RESP from MS (re-sync case) */
static void auth_fsm_wait_auth_resp_resync(struct osmo_fsm_inst *fi,
					   uint32_t event, void *data)
{
	struct auth_fsm_priv *afp = fi->priv;
	struct vlr_subscriber *vsub = afp->vsub;
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
	struct vlr_subscriber *vsub = afp->vsub;
	const char *mi_string = data;

	switch (event) {
	case VLR_AUTH_E_MS_ID_IMSI:
		if (vsub->imsi[0]&& strcmp(vsub->imsi, mi_string)) {
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
		.in_event_mask = S(VLR_AUTH_E_START),
		.out_state_mask = S(VLR_SUB_AS_NEEDS_AUTH_WAIT_AI) |
				  S(VLR_SUB_AS_WAIT_RESP),
		.name = "NEEDS-AUTH",
		.action = auth_fsm_needs_auth,
	},
	[VLR_SUB_AS_NEEDS_AUTH_WAIT_AI] = {
		.in_event_mask = S(VLR_AUTH_E_HLR_SAI_ACK) |
				 S(VLR_AUTH_E_HLR_SAI_NACK),
		.out_state_mask = S(VLR_SUB_AS_AUTH_FAILED) |
				  S(VLR_SUB_AS_WAIT_RESP),
		.name = "NEEDS-AUTH(WAIT-AI-HLR)",
		.action = auth_fsm_wait_ai,
	},
	[VLR_SUB_AS_WAIT_RESP] = {
		.in_event_mask = S(VLR_AUTH_E_MS_AUTH_RESP) |
				 S(VLR_AUTH_E_MS_AUTH_FAIL),
		.out_state_mask = S(VLR_SUB_AS_WAIT_ID_IMSI) |
				  S(VLR_SUB_AS_AUTH_FAILED) |
				  S(VLR_SUB_AS_AUTHENTICATED) |
				  S(VLR_SUB_AS_NEEDS_AUTH_WAIT_SAI_RESYNC),
		.name = "WAIT-AUTH-RESP",
		.action = auth_fsm_wait_auth_resp,
	},
	[VLR_SUB_AS_NEEDS_AUTH_WAIT_SAI_RESYNC] = {
		.in_event_mask = S(VLR_AUTH_E_HLR_SAI_ACK) |
				 S(VLR_AUTH_E_HLR_SAI_NACK),
		.out_state_mask = S(VLR_SUB_AS_AUTH_FAILED) |
				  S(VLR_SUB_AS_WAIT_RESP_RESYNC),
		.name = "NEEDS-AUTH(WAIT-AI-HKR-RESYNC)",
		.action = auth_fsm_wait_ai_resync,
	},
	[VLR_SUB_AS_WAIT_RESP_RESYNC] = {
		.in_event_mask = S(VLR_AUTH_E_MS_AUTH_RESP) |
				 S(VLR_AUTH_E_MS_AUTH_FAIL),
		.out_state_mask = S(VLR_SUB_AS_AUTH_FAILED) |
				  S(VLR_SUB_AS_AUTHENTICATED),
		.name = "NEEDS-AUTH(WAIT-AUTH-RESP-RESYNC)",
		.action = auth_fsm_wait_auth_resp_resync,
	},
	[VLR_SUB_AS_WAIT_ID_IMSI] = {
		.in_event_mask = S(VLR_AUTH_E_MS_ID_IMSI),
		.out_state_mask = S(VLR_SUB_AS_NEEDS_AUTH),
		.name = "WAIT-IMSI",
		.action = auth_fsm_wait_imsi,
	},
	[VLR_SUB_AS_AUTHENTICATED] = {
		.in_event_mask = 0,
		.out_state_mask = 0,
		.name = "AUTHENTICATED",
	},
	[VLR_SUB_AS_AUTH_FAILED] = {
		.in_event_mask = 0,
		.out_state_mask = 0,
		.name = "AUTH-FAILED",
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
struct osmo_fsm_inst *
auth_fsm_start(struct vlr_subscriber *vsub, uint32_t log_level,
		struct osmo_fsm_inst *parent, uint32_t parent_term_event)
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
	fi->priv = afp;
	vsub->auth_fsm = fi;

	osmo_fsm_inst_dispatch(fi, VLR_AUTH_E_START, NULL);

	return fi;
}
