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

#define S(x)	(1 << (x))

/***********************************************************************
 * Process_Access_Request_VLR, TS 29.002 Chapter 25.4.2
 ***********************************************************************/

enum proc_arq_vlr_state {
	PR_ARQ_S_INIT,
	/* Waiting for Obtain_Identity_VLR (IMSI) result */
	PR_ARQ_S_WAIT_OBTAIN_IMSI,
	/* Waiting for Authenticate_VLR result */
	PR_ARQ_S_WAIT_AUTH,
	PR_ARQ_S_WAIT_UPD_LOC_CHILD,
	PR_ARQ_S_WAIT_SUB_PRES,
	PR_ARQ_S_WAIT_TRACE_SUB,
	PR_ARQ_S_WAIT_CHECK_IMEI,
	PR_ARQ_S_WAIT_TMSI_ACK,
	PR_ARQ_S_WAIT_CECK_CONF,
	PR_ARQ_S_DONE,
};

static const struct value_string proc_arq_vlr_event_names[] = {
	{ PR_ARQ_E_START, "START" },
	{ PR_ARQ_E_ID_IMSI, "ID-IMSI-RES" },
	{ PR_ARQ_E_AUTH_RES, "AUTH-RES" },
	{ PR_ARQ_E_UPD_LOC_RES, "UPD-LOC-RES" },
	{ PR_ARQ_E_TRACE_RES, "TRACE-RES" },
	{ PR_ARQ_E_IMEI_RES, "ID-IMEI-RES" },
	{ PR_ARQ_E_PRES_RES, "SUBSCR-PRES-VLR-RES" },
	{ PR_ARQ_E_TMSI_ACK, "TMSI-REALLOC-ACK" },
	{ 0, NULL }
};

struct proc_arq_priv {
	struct vlr_instance *vlr;
	struct vlr_subscriber *vsub;
	void *msc_conn_ref;
	struct osmo_fsm_inst *ul_child_fsm;
	struct osmo_fsm_inst *sub_pres_vlr_fsm;

	enum vlr_parq_type type;
	bool by_tmsi;
	char imsi[16];
	uint32_t tmsi;
	struct osmo_location_area_id lai;
};

static void assoc_par_with_subscr(struct osmo_fsm_inst *fi, struct vlr_subscriber *vsub)
{
	struct proc_arq_priv *par = fi->priv;
	struct vlr_instance *vlr = par->vlr;

	OSMO_ASSERT(vsub->proc_arq_fsm == NULL);
	vsub->msc_conn_ref = par->msc_conn_ref;
	par->vsub = vsub;
	/* Tell MSC to associate this subscriber with the given
	 * connection */
	vlr->ops.subscr_assoc(par->msc_conn_ref, par->vsub);
}

static void proc_arq_fsm_done(struct osmo_fsm_inst *fi,
			      enum osmo_fsm_term_cause cause,
			      enum vlr_proc_arq_result res)
{
	osmo_fsm_inst_state_chg(fi, PR_ARQ_S_DONE, 0, 0);
	osmo_fsm_inst_term(fi, cause, &res);
}

static void _proc_arq_vlr_post_imei(struct osmo_fsm_inst *fi)
{
	struct proc_arq_priv *par = fi->priv;
	struct vlr_subscriber *vsub = par->vsub;

	/* TODO: Identity := IMSI */
	/* FIXME: send process acess response already now?!? */
	if (1 /* ciphering required */) {
		if (0 /* TODO: TMSI reallocation at access: vlr->cfg.alloc_tmsi_arq */) {
			vlr_sub_alloc_tmsi(vsub);
			/* TODO: forward TMSI to MS, wait for TMSI
			 * REALLOC COMPLETE */
			/* TODO: Freeze old TMSI */
			osmo_fsm_inst_state_chg(fi, PR_ARQ_S_WAIT_TMSI_ACK, 0, 0);
			return;
		}
	} else
		proc_arq_fsm_done(fi, OSMO_FSM_TERM_REGULAR, VLR_PR_ARQ_RES_PASSED);
}

/* After Subscriber_Present_VLR */
static void _proc_arq_vlr_post_trace(struct osmo_fsm_inst *fi)
{
	struct proc_arq_priv *par = fi->priv;
	struct vlr_subscriber *vsub = par->vsub;
	struct vlr_instance *vlr = vsub->vlr;

	if (1 /* ciphering required */) {
		vlr->ops.set_ciph_mode(par->msc_conn_ref);
		/* Node 3 */
		if (0 /* IMEI check required */) {
			/* Chck_IMEI_VLR */
			vlr->ops.tx_id_req(par->msc_conn_ref, GSM_MI_TYPE_IMEI);
			osmo_fsm_inst_state_chg(fi, PR_ARQ_S_WAIT_CHECK_IMEI,
						vlr_timer(vlr, 3270), 3270);
		} else
			_proc_arq_vlr_post_imei(fi);
	} else {
		/* Node 4 */
		if (0 /* IMEI check required */) {
			vlr->ops.tx_id_req(par->msc_conn_ref, GSM_MI_TYPE_IMEI);
			osmo_fsm_inst_state_chg(fi, PR_ARQ_S_WAIT_CHECK_IMEI,
						vlr_timer(vlr, 3270), 3270);
		} else
			_proc_arq_vlr_post_imei(fi);
	}
}

/* After Subscriber_Present_VLR */
static void _proc_arq_vlr_post_pres(struct osmo_fsm_inst *fi)
{
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
	struct vlr_subscriber *vsub = par->vsub;

	if (!vsub->sub_dataconf_by_hlr_ind) {
		/* Set User Error: Unidentified Subscriber */
		proc_arq_fsm_done(fi, OSMO_FSM_TERM_ERROR,
					VLR_PR_ARQ_RES_UNIDENT_SUBSCR);
	}
	if (0 /* roaming not allowed in LA */) {
		/* Set User Error: Roaming not allowed in this LA */
		proc_arq_fsm_done(fi, OSMO_FSM_TERM_ERROR,
					VLR_PR_ARQ_RES_ROAMING_NOTALLOWED);
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

static void _proc_arq_vlr_node2(struct osmo_fsm_inst *fi)
{
	struct proc_arq_priv *par = fi->priv;
	struct vlr_subscriber *vsub = par->vsub;

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

/* after the IMSI is known */
static void proc_arq_vlr_fn_post_imsi(struct osmo_fsm_inst *fi)
{
	struct proc_arq_priv *par = fi->priv;
	struct vlr_subscriber *vsub = par->vsub;

	OSMO_ASSERT(vsub);

	/* TODO: Identity IMEI -> System Failure */
	if (1 /* auth_required */) {
		osmo_fsm_inst_state_chg(fi, PR_ARQ_S_WAIT_AUTH,
					0, 0);
		vsub->auth_fsm = auth_fsm_start(vsub, fi->log_level, fi,
						PR_ARQ_E_AUTH_RES);
	} else {
		_proc_arq_vlr_node2(fi);
	}
}

static void proc_arq_vlr_fn_init(struct osmo_fsm_inst *fi,
				 uint32_t event, void *data)
{
	struct proc_arq_priv *par = fi->priv;
	struct vlr_instance *vlr = par->vlr;
	struct vlr_subscriber *vsub = NULL;

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
		assoc_par_with_subscr(fi, vsub);
		proc_arq_vlr_fn_post_imsi(fi);
		return;
	}
	/* No VSUB could be resolved. What now? */

	if (!par->by_tmsi) {
		/* We couldn't find a subscriber even by IMSI,
		 * Set User Error: Unidentified Subscriber */
		proc_arq_fsm_done(fi, OSMO_FSM_TERM_ERROR,
						VLR_PR_ARQ_RES_UNIDENT_SUBSCR);
			return;
	} else {
		/* TMSI was included, are we permitted to use it? */
		if (vlr->cfg.parq_retrieve_imsi) {
			/* Obtain_IMSI_VLR */
			osmo_fsm_inst_state_chg(fi, PR_ARQ_S_WAIT_OBTAIN_IMSI,
						vlr_timer(vlr, 3270), 3270);
		} else {
			/* Set User Error: Unidentified Subscriber */
			proc_arq_fsm_done(fi, OSMO_FSM_TERM_ERROR,
					VLR_PR_ARQ_RES_UNIDENT_SUBSCR);
		}
	}
}

/* ID REQ(IMSI) has returned */
static void proc_arq_vlr_fn_w_obt_imsi(struct osmo_fsm_inst *fi,
					uint32_t event, void *data)
{
	struct proc_arq_priv *par = fi->priv;
	struct vlr_instance *vlr = par->vlr;
	struct vlr_subscriber *vsub;

	OSMO_ASSERT(event == PR_ARQ_E_ID_IMSI);

	vsub = vlr_subscr_find_by_imsi(vlr, par->imsi);
	if (!vsub) {
		/* Set User Error: Unidentified Subscriber */
		proc_arq_fsm_done(fi, OSMO_FSM_TERM_ERROR,
				VLR_PR_ARQ_RES_UNIDENT_SUBSCR);
		return;
	}
	assoc_par_with_subscr(fi, vsub);
	proc_arq_vlr_fn_post_imsi(fi);
}

/* Authenticate_VLR has completed */
static void proc_arq_vlr_fn_w_auth(struct osmo_fsm_inst *fi,
				   uint32_t event, void *data)
{
	enum vlr_auth_fsm_result *res = data;
	enum vlr_proc_arq_result ret = VLR_PR_ARQ_RES_UNKNOWN_ERROR;

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
	proc_arq_fsm_done(fi, OSMO_FSM_TERM_ERROR, ret);
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
	proc_arq_fsm_done(fi, OSMO_FSM_TERM_REGULAR, VLR_PR_ARQ_RES_PASSED);
}

static const struct osmo_fsm_state proc_arq_vlr_states[] = {
	[PR_ARQ_S_INIT] = {
		.in_event_mask = S(PR_ARQ_E_START),
		.out_state_mask = S(PR_ARQ_S_DONE) |
				  S(PR_ARQ_S_WAIT_OBTAIN_IMSI) |
				  S(PR_ARQ_S_WAIT_AUTH) |
				  S(PR_ARQ_S_WAIT_UPD_LOC_CHILD) |
				  S(PR_ARQ_S_WAIT_SUB_PRES) |
				  S(PR_ARQ_S_WAIT_TRACE_SUB) |
				  S(PR_ARQ_S_WAIT_CHECK_IMEI) |
				  S(PR_ARQ_S_WAIT_TMSI_ACK),
		.name = "INIT",
		.action = proc_arq_vlr_fn_init,
	},
	[PR_ARQ_S_WAIT_OBTAIN_IMSI] = {
		.in_event_mask = S(PR_ARQ_E_ID_IMSI),
		.out_state_mask = S(PR_ARQ_S_DONE) |
				  S(PR_ARQ_S_WAIT_AUTH) |
				  S(PR_ARQ_S_WAIT_UPD_LOC_CHILD) |
				  S(PR_ARQ_S_WAIT_SUB_PRES) |
				  S(PR_ARQ_S_WAIT_TRACE_SUB) |
				  S(PR_ARQ_S_WAIT_CHECK_IMEI) |
				  S(PR_ARQ_S_WAIT_TMSI_ACK),
		.name = "WAIT-IMSI",
		.action = proc_arq_vlr_fn_w_obt_imsi,
	},
	[PR_ARQ_S_WAIT_AUTH] = {
		.in_event_mask = S(PR_ARQ_E_AUTH_RES),
		.out_state_mask = S(PR_ARQ_S_DONE) |
				  S(PR_ARQ_S_WAIT_UPD_LOC_CHILD) |
				  S(PR_ARQ_S_WAIT_SUB_PRES) |
				  S(PR_ARQ_S_WAIT_TRACE_SUB) |
				  S(PR_ARQ_S_WAIT_CHECK_IMEI) |
				  S(PR_ARQ_S_WAIT_TMSI_ACK),
		.name = "WAIT-AUTH",
		.action = proc_arq_vlr_fn_w_auth,
	},
	[PR_ARQ_S_WAIT_UPD_LOC_CHILD] = {
		.in_event_mask = S(PR_ARQ_E_UPD_LOC_RES),
		.out_state_mask = S(PR_ARQ_S_DONE) |
				  S(PR_ARQ_S_WAIT_SUB_PRES) |
				  S(PR_ARQ_S_WAIT_TRACE_SUB) |
				  S(PR_ARQ_S_WAIT_CHECK_IMEI) |
				  S(PR_ARQ_S_WAIT_TMSI_ACK),
		.name = "WAIT-UPD-LOC-CHILD",
		.action = proc_arq_vlr_fn_w_upd_loc,
	},
	[PR_ARQ_S_WAIT_SUB_PRES] = {
		.in_event_mask = S(PR_ARQ_E_PRES_RES),
		.out_state_mask = S(PR_ARQ_S_DONE) |
				  S(PR_ARQ_S_WAIT_TRACE_SUB) |
				  S(PR_ARQ_S_WAIT_CHECK_IMEI) |
				  S(PR_ARQ_S_WAIT_TMSI_ACK),
		.name = "WAIT-SUBSCR-PRES",
		.action = proc_arq_vlr_fn_w_pres,
	},
	[PR_ARQ_S_WAIT_TRACE_SUB] = {
		.in_event_mask = S(PR_ARQ_E_TRACE_RES),
		.out_state_mask = S(PR_ARQ_S_DONE) |
				  S(PR_ARQ_S_WAIT_CHECK_IMEI) |
				  S(PR_ARQ_S_WAIT_TMSI_ACK),
		.name = "WAIT-TRACE",
		.action = proc_arq_vlr_fn_w_trace,
	},
	[PR_ARQ_S_WAIT_CHECK_IMEI] = {
		.in_event_mask = S(PR_ARQ_E_IMEI_RES),
		.out_state_mask = S(PR_ARQ_S_DONE) |
				  S(PR_ARQ_S_WAIT_TMSI_ACK),
		.name = "WAIT-CHECK-IMEI",
		.action = proc_arq_vlr_fn_w_imei,
	},
	[PR_ARQ_S_WAIT_TMSI_ACK] = {
		.in_event_mask = S(PR_ARQ_E_TMSI_ACK),
		.out_state_mask = S(PR_ARQ_S_DONE),
		.name = "WAIT-TMSI-ACK",
		.action = proc_arq_vlr_fn_w_tmsi,
	},
	[PR_ARQ_S_DONE] = {
		.name = "DONE",
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
};

struct osmo_fsm_inst *
vlr_proc_acc_req(struct osmo_fsm_inst *parent, uint32_t parent_term,
		 struct vlr_instance *vlr, void *msc_conn_ref,
		 enum vlr_parq_type type, const uint8_t *mi_lv,
		 const struct osmo_location_area_id *lai)
{
	struct osmo_fsm_inst *fi;
	struct proc_arq_priv *par;
	char mi_string[GSM48_MI_SIZE];
	uint8_t mi_type;

	fi = osmo_fsm_inst_alloc_child(&proc_arq_vlr_fsm, parent,
					parent_term);;
	if (!fi)
		return NULL;

	par = talloc_zero(fi, struct proc_arq_priv);
	fi->priv = par;
	par->vlr = vlr;
	par->msc_conn_ref = msc_conn_ref;
	par->type = type;
	par->lai = *lai;

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
		osmo_fsm_inst_term(fi, OSMO_FSM_TERM_ERROR, NULL);
		return NULL;
	}

	osmo_fsm_inst_dispatch(fi, PR_ARQ_E_START, NULL);

	return fi;
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
