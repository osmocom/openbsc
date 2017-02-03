/* Osmocom Visitor Location Register (VLR): Access Request FSMs */

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
#include "vlr_lu_fsm.h"
#include "vlr_access_req_fsm.h"

#define S(x)	(1 << (x))

/***********************************************************************
 * Process_Access_Request_VLR, TS 29.002 Chapter 25.4.2
 ***********************************************************************/

const struct value_string vlr_proc_arq_result_names[] = {
	OSMO_VALUE_STRING(VLR_PR_ARQ_RES_NONE),
	OSMO_VALUE_STRING(VLR_PR_ARQ_RES_SYSTEM_FAILURE),
	OSMO_VALUE_STRING(VLR_PR_ARQ_RES_ILLEGAL_SUBSCR),
	OSMO_VALUE_STRING(VLR_PR_ARQ_RES_UNIDENT_SUBSCR),
	OSMO_VALUE_STRING(VLR_PR_ARQ_RES_ROAMING_NOTALLOWED),
	OSMO_VALUE_STRING(VLR_PR_ARQ_RES_ILLEGAL_EQUIP),
	OSMO_VALUE_STRING(VLR_PR_ARQ_RES_UNKNOWN_ERROR),
	OSMO_VALUE_STRING(VLR_PR_ARQ_RES_TIMEOUT),
	OSMO_VALUE_STRING(VLR_PR_ARQ_RES_PASSED),
	{ 0, NULL }
};

static const struct value_string proc_arq_vlr_event_names[] = {
	OSMO_VALUE_STRING(PR_ARQ_E_START),
	OSMO_VALUE_STRING(PR_ARQ_E_ID_IMSI),
	OSMO_VALUE_STRING(PR_ARQ_E_AUTH_RES),
	OSMO_VALUE_STRING(PR_ARQ_E_CIPH_RES),
	OSMO_VALUE_STRING(PR_ARQ_E_UPD_LOC_RES),
	OSMO_VALUE_STRING(PR_ARQ_E_TRACE_RES),
	OSMO_VALUE_STRING(PR_ARQ_E_IMEI_RES),
	OSMO_VALUE_STRING(PR_ARQ_E_PRES_RES),
	OSMO_VALUE_STRING(PR_ARQ_E_TMSI_ACK),
	{ 0, NULL }
};

struct proc_arq_priv {
	struct vlr_instance *vlr;
	struct vlr_subscr *vsub;
	void *msc_conn_ref;
	struct osmo_fsm_inst *ul_child_fsm;
	struct osmo_fsm_inst *sub_pres_vlr_fsm;
	uint32_t parent_event_success;
	uint32_t parent_event_failure;
	void *parent_event_data;

	enum vlr_parq_type type;
	enum vlr_proc_arq_result result;
	bool by_tmsi;
	char imsi[16];
	uint32_t tmsi;
	struct osmo_location_area_id lai;
	bool authentication_required;
	enum vlr_ciph ciphering_required;
	bool is_r99;
	bool is_utran;
};

static void assoc_par_with_subscr(struct osmo_fsm_inst *fi, struct vlr_subscr *vsub)
{
	struct proc_arq_priv *par = fi->priv;
	struct vlr_instance *vlr = par->vlr;

	vsub->msc_conn_ref = par->msc_conn_ref;
	par->vsub = vsub;
	/* Tell MSC to associate this subscriber with the given
	 * connection */
	vlr->ops.subscr_assoc(par->msc_conn_ref, par->vsub);
}

#define proc_arq_fsm_done(fi, res) _proc_arq_fsm_done(fi, res, __FILE__, __LINE__)
static void _proc_arq_fsm_done(struct osmo_fsm_inst *fi,
			       enum vlr_proc_arq_result res,
			       const char *file, int line)
{
	struct proc_arq_priv *par = fi->priv;
	LOGPFSMSRC(fi, file, line, "proc_arq_fsm_done(%s)\n",
		   vlr_proc_arq_result_name(res));
	par->result = res;
	osmo_fsm_inst_state_chg(fi, PR_ARQ_S_DONE, 0, 0);
}

static void proc_arq_vlr_dispatch_result(struct osmo_fsm_inst *fi,
					 uint32_t prev_state)
{
	struct proc_arq_priv *par = fi->priv;
	bool success;
	int rc;
	LOGPFSM(fi, "Process Access Request result: %s\n",
		vlr_proc_arq_result_name(par->result));

	success = (par->result == VLR_PR_ARQ_RES_PASSED);

	/* It would be logical to first dispatch the success event to the
	 * parent FSM, but that could start actions that send messages to the
	 * MS. Rather send the CM Service Accept message first and then signal
	 * success. Since messages are handled synchronously, the success event
	 * will be processed before we handle new incoming data from the MS. */

	if (par->type == VLR_PR_ARQ_T_CM_SERV_REQ) {
		if (success) {
			rc = par->vlr->ops.tx_cm_serv_acc(par->msc_conn_ref);
			if (rc) {
				LOGPFSML(fi, LOGL_ERROR,
					 "Failed to send CM Service Accept\n");
				success = false;
			}
		}
		if (!success) {
			rc = par->vlr->ops.tx_cm_serv_rej(par->msc_conn_ref,
							  par->result);
			if (rc)
				LOGPFSML(fi, LOGL_ERROR,
					 "Failed to send CM Service Reject\n");
		}
	}

	/* For VLR_PR_ARQ_T_PAGING_RESP, there is nothing to send. The conn_fsm
	 * will start handling pending paging transactions. */

	if (!fi->proc.parent) {
		LOGPFSML(fi, LOGL_ERROR, "No parent FSM");
		return;
	}
	osmo_fsm_inst_dispatch(fi->proc.parent,
			       success ? par->parent_event_success
				       : par->parent_event_failure,
			       par->parent_event_data);
}

void proc_arq_vlr_cleanup(struct osmo_fsm_inst *fi,
			  enum osmo_fsm_term_cause cause)
{
	struct proc_arq_priv *par = fi->priv;
	if (par->vsub && par->vsub->proc_arq_fsm == fi)
		par->vsub->proc_arq_fsm = NULL;
}

static void _proc_arq_vlr_post_imei(struct osmo_fsm_inst *fi)
{
	struct proc_arq_priv *par = fi->priv;
	struct vlr_subscr *vsub = par->vsub;

	LOGPFSM(fi, "%s()\n", __func__);

	/* TODO: Identity := IMSI */
	if (0 /* TODO: TMSI reallocation at access: vlr->cfg.alloc_tmsi_arq */) {
		vlr_subscr_alloc_tmsi(vsub);
		/* TODO: forward TMSI to MS, wait for TMSI
		 * REALLOC COMPLETE */
		/* TODO: Freeze old TMSI */
		osmo_fsm_inst_state_chg(fi, PR_ARQ_S_WAIT_TMSI_ACK, 0, 0);
		return;
	}

	proc_arq_fsm_done(fi, VLR_PR_ARQ_RES_PASSED);
}

static void _proc_arq_vlr_post_trace(struct osmo_fsm_inst *fi)
{
	struct proc_arq_priv *par = fi->priv;
	struct vlr_subscr *vsub = par->vsub;
	struct vlr_instance *vlr = vsub->vlr;

	LOGPFSM(fi, "%s()\n", __func__);

	/* Node 3 */
	if (0 /* IMEI check required */) {
		/* Chck_IMEI_VLR */
		vlr->ops.tx_id_req(par->msc_conn_ref, GSM_MI_TYPE_IMEI);
		osmo_fsm_inst_state_chg(fi, PR_ARQ_S_WAIT_CHECK_IMEI,
					vlr_timer(vlr, 3270), 3270);
	} else
		_proc_arq_vlr_post_imei(fi);
}

/* After Subscriber_Present_VLR */
static void _proc_arq_vlr_post_pres(struct osmo_fsm_inst *fi)
{
	LOGPFSM(fi, "%s()\n", __func__);
	if (0 /* TODO: tracing required */) {
		/* TODO: Trace_Subscriber_Activity_VLR */
		osmo_fsm_inst_state_chg(fi, PR_ARQ_S_WAIT_TRACE_SUB, 0, 0);
	}
	_proc_arq_vlr_post_trace(fi);
}

/* After Update_Location_Child_VLR */
static void _proc_arq_vlr_node2_post_vlr(struct osmo_fsm_inst *fi)
{
	struct proc_arq_priv *par = fi->priv;
	struct vlr_subscr *vsub = par->vsub;

	LOGPFSM(fi, "%s()\n", __func__);

	if (!vsub->sub_dataconf_by_hlr_ind) {
		/* Set User Error: Unidentified Subscriber */
		proc_arq_fsm_done(fi, VLR_PR_ARQ_RES_UNIDENT_SUBSCR);
		return;
	}
	if (0 /* roaming not allowed in LA */) {
		/* Set User Error: Roaming not allowed in this LA */
		proc_arq_fsm_done(fi, VLR_PR_ARQ_RES_ROAMING_NOTALLOWED);
		return;
	}
	vsub->imsi_detached_flag = false;
	if (vsub->ms_not_reachable_flag) {
		/* Start Subscriber_Present_VLR */
		osmo_fsm_inst_state_chg(fi, PR_ARQ_S_WAIT_SUB_PRES, 0, 0);
		par->sub_pres_vlr_fsm = sub_pres_vlr_fsm_start(fi, vsub,
							PR_ARQ_E_PRES_RES);
		return;
	}
	_proc_arq_vlr_post_pres(fi);
}

static void _proc_arq_vlr_node2_post_ciph(struct osmo_fsm_inst *fi)
{
	struct proc_arq_priv *par = fi->priv;
	struct vlr_subscr *vsub = par->vsub;

	LOGPFSM(fi, "%s()\n", __func__);

	vsub->conf_by_radio_contact_ind = true;
	if (vsub->loc_conf_in_hlr_ind == false) {
		/* start Update_Location_Child_VLR.  WE use
		 * Update_HLR_VLR instead, the differences appear
		 * insignificant for now. */
		par->ul_child_fsm = upd_hlr_vlr_proc_start(fi, vsub,
							PR_ARQ_E_UPD_LOC_RES);
		osmo_fsm_inst_state_chg(fi, PR_ARQ_S_WAIT_UPD_LOC_CHILD, 0, 0);
		return;
	}
	_proc_arq_vlr_node2_post_vlr(fi);
}

static bool is_ciph_required(struct proc_arq_priv *par)
{
	return par->ciphering_required != VLR_CIPH_NONE;
}

static void _proc_arq_vlr_node2(struct osmo_fsm_inst *fi)
{
	struct proc_arq_priv *par = fi->priv;
	struct vlr_subscr *vsub = par->vsub;

	LOGPFSM(fi, "%s()\n", __func__);

	if (!is_ciph_required(par)) {
		_proc_arq_vlr_node2_post_ciph(fi);
		return;
	}

	if (vlr_set_ciph_mode(vsub->vlr, fi, par->msc_conn_ref,
			      par->ciphering_required,
			      vsub->vlr->cfg.retrieve_imeisv)) {
		LOGPFSML(fi, LOGL_ERROR,
			 "Failed to send Ciphering Mode Command\n");
		proc_arq_fsm_done(fi, VLR_PR_ARQ_RES_SYSTEM_FAILURE);
		return;
	}

	osmo_fsm_inst_state_chg(fi, PR_ARQ_S_WAIT_CIPH, 0, 0);
}

static bool is_auth_required(struct proc_arq_priv *par)
{
	/* The cases where the authentication procedure should be used
	 * are defined in 3GPP TS 33.102 */
	/* For now we use a default value passed in to vlr_lu_fsm(). */
	return par->authentication_required
	       || (par->ciphering_required != VLR_CIPH_NONE);
}

/* after the IMSI is known */
static void proc_arq_vlr_fn_post_imsi(struct osmo_fsm_inst *fi)
{
	struct proc_arq_priv *par = fi->priv;
	struct vlr_subscr *vsub = par->vsub;

	LOGPFSM(fi, "%s()\n", __func__);

	OSMO_ASSERT(vsub);

	/* TODO: Identity IMEI -> System Failure */
	if (is_auth_required(par)) {
		osmo_fsm_inst_state_chg(fi, PR_ARQ_S_WAIT_AUTH,
					0, 0);
		vsub->auth_fsm = auth_fsm_start(vsub, fi->log_level, fi,
						PR_ARQ_E_AUTH_RES,
						par->is_r99,
						par->is_utran);
	} else {
		_proc_arq_vlr_node2(fi);
	}
}

static void proc_arq_vlr_fn_init(struct osmo_fsm_inst *fi,
				 uint32_t event, void *data)
{
	struct proc_arq_priv *par = fi->priv;
	struct vlr_instance *vlr = par->vlr;
	struct vlr_subscr *vsub = NULL;

	OSMO_ASSERT(event == PR_ARQ_E_START);

	/* Obtain_Identity_VLR */
	if (!par->by_tmsi) {
		/* IMSI was included */
		vsub = vlr_subscr_find_by_imsi(par->vlr, par->imsi);
	} else {
		/* TMSI was included */
		vsub = vlr_subscr_find_by_tmsi(par->vlr, par->tmsi);
	}
	if (vsub) {
		log_set_context(LOG_CTX_VLR_SUBSCR, vsub);
		if (vsub->proc_arq_fsm && fi != vsub->proc_arq_fsm) {
			LOGPFSML(fi, LOGL_ERROR,
				 "Another proc_arq_fsm is already"
				 " associated with subscr %s,"
				 " terminating the other FSM.\n",
				 vlr_subscr_name(vsub));
			proc_arq_fsm_done(vsub->proc_arq_fsm,
					  VLR_PR_ARQ_RES_SYSTEM_FAILURE);
		}
		vsub->proc_arq_fsm = fi;
		assoc_par_with_subscr(fi, vsub);
		proc_arq_vlr_fn_post_imsi(fi);
		vlr_subscr_put(vsub);
		return;
	}
	/* No VSUB could be resolved. What now? */

	if (!par->by_tmsi) {
		/* We couldn't find a subscriber even by IMSI,
		 * Set User Error: Unidentified Subscriber */
		proc_arq_fsm_done(fi, VLR_PR_ARQ_RES_UNIDENT_SUBSCR);
		return;
	} else {
		/* TMSI was included, are we permitted to use it? */
		if (vlr->cfg.parq_retrieve_imsi) {
			/* Obtain_IMSI_VLR */
			osmo_fsm_inst_state_chg(fi, PR_ARQ_S_WAIT_OBTAIN_IMSI,
						vlr_timer(vlr, 3270), 3270);
			return;
		} else {
			/* Set User Error: Unidentified Subscriber */
			proc_arq_fsm_done(fi, VLR_PR_ARQ_RES_UNIDENT_SUBSCR);
			return;
		}
	}
}

/* ID REQ(IMSI) has returned */
static void proc_arq_vlr_fn_w_obt_imsi(struct osmo_fsm_inst *fi,
					uint32_t event, void *data)
{
	struct proc_arq_priv *par = fi->priv;
	struct vlr_instance *vlr = par->vlr;
	struct vlr_subscr *vsub;

	OSMO_ASSERT(event == PR_ARQ_E_ID_IMSI);

	vsub = vlr_subscr_find_by_imsi(vlr, par->imsi);
	if (!vsub) {
		/* Set User Error: Unidentified Subscriber */
		proc_arq_fsm_done(fi, VLR_PR_ARQ_RES_UNIDENT_SUBSCR);
		return;
	}
	assoc_par_with_subscr(fi, vsub);
	proc_arq_vlr_fn_post_imsi(fi);
	vlr_subscr_put(vsub);
}

/* Authenticate_VLR has completed */
static void proc_arq_vlr_fn_w_auth(struct osmo_fsm_inst *fi,
				   uint32_t event, void *data)
{
	enum vlr_auth_fsm_result *res = data;
	enum vlr_proc_arq_result ret = VLR_PR_ARQ_RES_UNKNOWN_ERROR;

	OSMO_ASSERT(res);
	LOGPFSM(fi, "got %s\n", vlr_auth_fsm_result_name(*res));

	OSMO_ASSERT(event == PR_ARQ_E_AUTH_RES);

	if (res) {
		switch (*res) {
		case VLR_AUTH_RES_PASSED:
			/* Node 2 */
			_proc_arq_vlr_node2(fi);
			return;
		case VLR_AUTH_RES_ABORTED:
			/* Error */
			ret = VLR_PR_ARQ_RES_UNKNOWN_ERROR;
			break;
		case VLR_AUTH_RES_UNKNOWN_SUBSCR:
			/* Set User Error: Unidentified Subscriber */
			ret = VLR_PR_ARQ_RES_UNIDENT_SUBSCR;
			break;
		case VLR_AUTH_RES_AUTH_FAILED:
			/* Set User Error: Illegal Subscriber */
			ret = VLR_PR_ARQ_RES_ILLEGAL_SUBSCR;
			break;
		case VLR_AUTH_RES_PROC_ERR:
			/* Set User Error: System failure */
			ret = VLR_PR_ARQ_RES_SYSTEM_FAILURE;
			break;
		}
	}
	/* send process_access_req response to caller */
	/* enter error state */
	proc_arq_fsm_done(fi, ret);
}

static void proc_arq_vlr_fn_w_ciph(struct osmo_fsm_inst *fi,
				   uint32_t event, void *data)
{
	struct proc_arq_priv *par = fi->priv;
	struct vlr_subscr *vsub = par->vsub;
	struct vlr_ciph_result res = { .cause = VLR_CIPH_REJECT };

	OSMO_ASSERT(event == PR_ARQ_E_CIPH_RES);

	if (!data)
		LOGPFSML(fi, LOGL_ERROR, "invalid ciphering result: NULL\n");
	else
		res = *(struct vlr_ciph_result*)data;

	switch (res.cause) {
	case VLR_CIPH_COMPL:
		break;
	case VLR_CIPH_REJECT:
		LOGPFSM(fi, "ciphering rejected\n");
		proc_arq_fsm_done(fi, VLR_PR_ARQ_RES_ILLEGAL_SUBSCR);
		return;
	default:
		LOGPFSML(fi, LOGL_ERROR, "invalid ciphering result: %d\n",
			 res.cause);
		proc_arq_fsm_done(fi, VLR_PR_ARQ_RES_ILLEGAL_SUBSCR);
		return;
	}


	if (res.imeisv) {
		LOGPFSM(fi, "got IMEISV: %s\n", res.imeisv);
		vlr_subscr_set_imeisv(vsub, res.imeisv);
	}
	_proc_arq_vlr_node2_post_ciph(fi);
}

/* Update_Location_Child_VLR has completed */
static void proc_arq_vlr_fn_w_upd_loc(struct osmo_fsm_inst *fi,
					uint32_t event, void *data)
{
	OSMO_ASSERT(event == PR_ARQ_E_UPD_LOC_RES);

	_proc_arq_vlr_node2_post_vlr(fi);
}

/* Subscriber_Present_VLR has completed */
static void proc_arq_vlr_fn_w_pres(struct osmo_fsm_inst *fi,
					uint32_t event, void *data)
{
	OSMO_ASSERT(event == PR_ARQ_E_PRES_RES);

	_proc_arq_vlr_post_pres(fi);
}

static void proc_arq_vlr_fn_w_trace(struct osmo_fsm_inst *fi,
					uint32_t event, void *data)
{
	OSMO_ASSERT(event == PR_ARQ_E_TRACE_RES);

	_proc_arq_vlr_post_trace(fi);
}

/* we have received the ID RESPONSE (IMEI) */
static void proc_arq_vlr_fn_w_imei(struct osmo_fsm_inst *fi,
				uint32_t event, void *data)
{
	OSMO_ASSERT(event == PR_ARQ_E_IMEI_RES);

	_proc_arq_vlr_post_imei(fi);
}

/* MSC tells us that MS has acknowleded TMSI re-allocation */
static void proc_arq_vlr_fn_w_tmsi(struct osmo_fsm_inst *fi,
				uint32_t event, void *data)
{
	OSMO_ASSERT(event == PR_ARQ_E_TMSI_ACK);

	/* FIXME: check confirmation? unfreeze? */
	proc_arq_fsm_done(fi, VLR_PR_ARQ_RES_PASSED);
}

static const struct osmo_fsm_state proc_arq_vlr_states[] = {
	[PR_ARQ_S_INIT] = {
		.name = OSMO_STRINGIFY(PR_ARQ_S_INIT),
		.in_event_mask = S(PR_ARQ_E_START),
		.out_state_mask = S(PR_ARQ_S_DONE) |
				  S(PR_ARQ_S_WAIT_OBTAIN_IMSI) |
				  S(PR_ARQ_S_WAIT_AUTH) |
				  S(PR_ARQ_S_WAIT_UPD_LOC_CHILD) |
				  S(PR_ARQ_S_WAIT_SUB_PRES) |
				  S(PR_ARQ_S_WAIT_TRACE_SUB) |
				  S(PR_ARQ_S_WAIT_CHECK_IMEI) |
				  S(PR_ARQ_S_WAIT_TMSI_ACK),
		.action = proc_arq_vlr_fn_init,
	},
	[PR_ARQ_S_WAIT_OBTAIN_IMSI] = {
		.name = OSMO_STRINGIFY(PR_ARQ_S_WAIT_OBTAIN_IMSI),
		.in_event_mask = S(PR_ARQ_E_ID_IMSI),
		.out_state_mask = S(PR_ARQ_S_DONE) |
				  S(PR_ARQ_S_WAIT_AUTH) |
				  S(PR_ARQ_S_WAIT_UPD_LOC_CHILD) |
				  S(PR_ARQ_S_WAIT_SUB_PRES) |
				  S(PR_ARQ_S_WAIT_TRACE_SUB) |
				  S(PR_ARQ_S_WAIT_CHECK_IMEI) |
				  S(PR_ARQ_S_WAIT_TMSI_ACK),
		.action = proc_arq_vlr_fn_w_obt_imsi,
	},
	[PR_ARQ_S_WAIT_AUTH] = {
		.name = OSMO_STRINGIFY(PR_ARQ_S_WAIT_AUTH),
		.in_event_mask = S(PR_ARQ_E_AUTH_RES),
		.out_state_mask = S(PR_ARQ_S_DONE) |
				  S(PR_ARQ_S_WAIT_CIPH) |
				  S(PR_ARQ_S_WAIT_UPD_LOC_CHILD) |
				  S(PR_ARQ_S_WAIT_SUB_PRES) |
				  S(PR_ARQ_S_WAIT_TRACE_SUB) |
				  S(PR_ARQ_S_WAIT_CHECK_IMEI) |
				  S(PR_ARQ_S_WAIT_TMSI_ACK),
		.action = proc_arq_vlr_fn_w_auth,
	},
	[PR_ARQ_S_WAIT_CIPH] = {
		.name = OSMO_STRINGIFY(PR_ARQ_S_WAIT_CIPH),
		.in_event_mask = S(PR_ARQ_E_CIPH_RES),
		.out_state_mask = S(PR_ARQ_S_DONE) |
				  S(PR_ARQ_S_WAIT_UPD_LOC_CHILD) |
				  S(PR_ARQ_S_WAIT_SUB_PRES) |
				  S(PR_ARQ_S_WAIT_TRACE_SUB) |
				  S(PR_ARQ_S_WAIT_CHECK_IMEI) |
				  S(PR_ARQ_S_WAIT_TMSI_ACK),
		.action = proc_arq_vlr_fn_w_ciph,
	},
	[PR_ARQ_S_WAIT_UPD_LOC_CHILD] = {
		.name = OSMO_STRINGIFY(PR_ARQ_S_WAIT_UPD_LOC_CHILD),
		.in_event_mask = S(PR_ARQ_E_UPD_LOC_RES),
		.out_state_mask = S(PR_ARQ_S_DONE) |
				  S(PR_ARQ_S_WAIT_SUB_PRES) |
				  S(PR_ARQ_S_WAIT_TRACE_SUB) |
				  S(PR_ARQ_S_WAIT_CHECK_IMEI) |
				  S(PR_ARQ_S_WAIT_TMSI_ACK),
		.action = proc_arq_vlr_fn_w_upd_loc,
	},
	[PR_ARQ_S_WAIT_SUB_PRES] = {
		.name = OSMO_STRINGIFY(PR_ARQ_S_WAIT_SUB_PRES),
		.in_event_mask = S(PR_ARQ_E_PRES_RES),
		.out_state_mask = S(PR_ARQ_S_DONE) |
				  S(PR_ARQ_S_WAIT_TRACE_SUB) |
				  S(PR_ARQ_S_WAIT_CHECK_IMEI) |
				  S(PR_ARQ_S_WAIT_TMSI_ACK),
		.action = proc_arq_vlr_fn_w_pres,
	},
	[PR_ARQ_S_WAIT_TRACE_SUB] = {
		.name = OSMO_STRINGIFY(PR_ARQ_S_WAIT_TRACE_SUB),
		.in_event_mask = S(PR_ARQ_E_TRACE_RES),
		.out_state_mask = S(PR_ARQ_S_DONE) |
				  S(PR_ARQ_S_WAIT_CHECK_IMEI) |
				  S(PR_ARQ_S_WAIT_TMSI_ACK),
		.action = proc_arq_vlr_fn_w_trace,
	},
	[PR_ARQ_S_WAIT_CHECK_IMEI] = {
		.name = OSMO_STRINGIFY(PR_ARQ_S_WAIT_CHECK_IMEI),
		.in_event_mask = S(PR_ARQ_E_IMEI_RES),
		.out_state_mask = S(PR_ARQ_S_DONE) |
				  S(PR_ARQ_S_WAIT_TMSI_ACK),
		.action = proc_arq_vlr_fn_w_imei,
	},
	[PR_ARQ_S_WAIT_TMSI_ACK] = {
		.name = OSMO_STRINGIFY(PR_ARQ_S_WAIT_TMSI_ACK),
		.in_event_mask = S(PR_ARQ_E_TMSI_ACK),
		.out_state_mask = S(PR_ARQ_S_DONE),
		.action = proc_arq_vlr_fn_w_tmsi,
	},
	[PR_ARQ_S_DONE] = {
		.name = OSMO_STRINGIFY(PR_ARQ_S_DONE),
		.onenter = proc_arq_vlr_dispatch_result,
	},
};

static struct osmo_fsm proc_arq_vlr_fsm = {
	.name = "Process_Access_Request_VLR",
	.states = proc_arq_vlr_states,
	.num_states = ARRAY_SIZE(proc_arq_vlr_states),
	.allstate_event_mask = 0,
	.allstate_action = NULL,
	.log_subsys = DVLR,
	.event_names = proc_arq_vlr_event_names,
	.cleanup = proc_arq_vlr_cleanup,
};

void
vlr_proc_acc_req(struct osmo_fsm_inst *parent,
		 uint32_t parent_event_success,
		 uint32_t parent_event_failure,
		 void *parent_event_data,
		 struct vlr_instance *vlr, void *msc_conn_ref,
		 enum vlr_parq_type type, const uint8_t *mi_lv,
		 const struct osmo_location_area_id *lai,
		 bool authentication_required,
		 enum vlr_ciph ciphering_required,
		 bool is_r99, bool is_utran)
{
	struct osmo_fsm_inst *fi;
	struct proc_arq_priv *par;
	char mi_string[GSM48_MI_SIZE];
	uint8_t mi_type;

	fi = osmo_fsm_inst_alloc_child(&proc_arq_vlr_fsm, parent,
				       parent_event_failure);
	if (!fi)
		return;

	par = talloc_zero(fi, struct proc_arq_priv);
	fi->priv = par;
	par->vlr = vlr;
	par->msc_conn_ref = msc_conn_ref;
	par->type = type;
	par->lai = *lai;
	par->parent_event_success = parent_event_success;
	par->parent_event_failure = parent_event_failure;
	par->parent_event_data = parent_event_data;
	par->authentication_required = authentication_required;
	par->ciphering_required = ciphering_required;
	par->is_r99 = is_r99;
	par->is_utran = is_utran;

	LOGPFSM(fi, "rev=%s net=%s%s%s\n",
		is_r99 ? "R99" : "GSM",
		is_utran ? "UTRAN" : "GERAN",
		(authentication_required || ciphering_required)?
		" Auth" : " (no Auth)",
		(authentication_required || ciphering_required)?
			(ciphering_required? "+Ciph" : " (no Ciph)")
			: "");

	gsm48_mi_to_string(mi_string, sizeof(mi_string), mi_lv+1, mi_lv[0]);
	mi_type = mi_lv[1] & GSM_MI_TYPE_MASK;
	switch (mi_type) {
	case GSM_MI_TYPE_IMSI:
		strncpy(par->imsi, mi_string, sizeof(par->imsi)-1);
		par->imsi[sizeof(par->imsi)-1] = '\0';
		par->by_tmsi = false;
		break;
	case GSM_MI_TYPE_TMSI:
		par->by_tmsi = true;
		par->tmsi = osmo_load32be(mi_lv+2);
		break;
	case GSM_MI_TYPE_IMEI:
		/* TODO: IMEI (emergency call) */
	default:
		/* FIXME: directly send reject? */
		proc_arq_fsm_done(fi, VLR_PR_ARQ_RES_UNIDENT_SUBSCR);
		return;
	}

	osmo_fsm_inst_dispatch(fi, PR_ARQ_E_START, NULL);
}

/* Gracefully terminate an FSM created by vlr_proc_acc_req() in case of
 * external timeout (i.e. from MSC). */
void vlr_parq_conn_timeout(struct osmo_fsm_inst *fi)
{
	if (!fi || fi->state == PR_ARQ_S_DONE)
		return;
	LOGPFSM(fi, "Connection timed out\n");
	proc_arq_fsm_done(fi, VLR_PR_ARQ_RES_TIMEOUT);
}


#if 0
/***********************************************************************
 * Update_Location_Child_VLR, TS 29.002 Chapter 25.4.4
 ***********************************************************************/

enum upd_loc_child_vlr_state {
	ULC_S_IDLE,
	ULC_S_WAIT_HLR_RESP,
	ULC_S_DONE,
};

enum upd_loc_child_vlr_event {
	ULC_E_START,
};

static const struct value_string upd_loc_child_vlr_event_names[] = {
	{ ULC_E_START, "START" },
	{ 0, NULL }
};

static void upd_loc_child_f_idle(struct osmo_fsm_inst *fi, uint32_t event,
				 void *data)
{
	OSMO_ASSERT(event == ULC_E_START);

	/* send update location */
}

static void upd_loc_child_f_w_hlr(struct osmo_fsm_inst *fi, uint32_t event,
				  void *data)
{
}

static const struct osmo_fsm_state upd_loc_child_vlr_states[] = {
	[ULC_S_IDLE] = {
		.in_event_mask = ,
		.out_state_mask = S(ULC_S_WAIT_HLR_RESP) |
				  S(ULC_S_DONE),
		.name = "IDLE",
		.action = upd_loc_child_f_idle,
	},
	[ULC_S_WAIT_HLR_RESP] = {
		.in_event_mask = ,
		.out_state_mask = S(ULC_S_DONE),
		.name = "WAIT-HLR-RESP",
		.action = upd_loc_child_f_w_hlr,
	},
	[ULC_S_DONE] = {
		.name = "DONE",
	},
};

static struct osmo_fsm upd_loc_child_vlr_fsm = {
	.name = "Update_Location_Child_VLR",
	.states = upd_loc_child_vlr_states,
	.num_states = ARRAY_SIZE(upd_loc_child_vlr_states),
	.log_subsys = DVLR,
	.event_names = upd_loc_child_vlr_event_names,
};
#endif

void vlr_parq_fsm_init(void)
{
	//osmo_fsm_register(&upd_loc_child_vlr_fsm);
	osmo_fsm_register(&proc_arq_vlr_fsm);
}
