/* Osmocom Visitor Location Register (VLR): Location Update FSMs */

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

#define LU_TIMEOUT_LONG		30

enum vlr_fsm_result {
	VLR_FSM_RESULT_NONE,
	VLR_FSM_RESULT_SUCCESS,
	VLR_FSM_RESULT_FAILURE,
};


/***********************************************************************
 * Update_HLR_VLR, TS 23.012 Chapter 4.1.2.4
 ***********************************************************************/

enum upd_hlr_vlr_state {
	UPD_HLR_VLR_S_INIT,
	UPD_HLR_VLR_S_WAIT_FOR_DATA,
	UPD_HLR_VLR_S_DONE,
};

enum upd_hlr_vlr_evt {
	UPD_HLR_VLR_E_START,
	UPD_HLR_VLR_E_INS_SUB_DATA,
	UPD_HLR_VLR_E_ACT_TRACE_MODE,
	UPD_HLR_VLR_E_FW_CHECK_SS_IND,
	UPD_HLR_VLR_E_UPD_LOC_ACK,
	UPD_HLR_VLR_E_UPD_LOC_NACK,
};

static const struct value_string upd_hlr_vlr_event_names[] = {
	OSMO_VALUE_STRING(UPD_HLR_VLR_E_START),
	OSMO_VALUE_STRING(UPD_HLR_VLR_E_INS_SUB_DATA),
	OSMO_VALUE_STRING(UPD_HLR_VLR_E_ACT_TRACE_MODE),
	OSMO_VALUE_STRING(UPD_HLR_VLR_E_FW_CHECK_SS_IND),
	OSMO_VALUE_STRING(UPD_HLR_VLR_E_UPD_LOC_ACK),
	OSMO_VALUE_STRING(UPD_HLR_VLR_E_UPD_LOC_NACK),
	{ 0, NULL }
};

static void upd_hlr_vlr_fsm_init(struct osmo_fsm_inst *fi, uint32_t event,
				 void *data)
{
	struct vlr_subscr *vsub = fi->priv;

	OSMO_ASSERT(event == UPD_HLR_VLR_E_START);

	/* Send UpdateLocation to HLR */
	vlr_subscr_req_lu(vsub, vsub->vlr->cfg.is_ps);
	osmo_fsm_inst_state_chg(fi, UPD_HLR_VLR_S_WAIT_FOR_DATA,
				LU_TIMEOUT_LONG, 0);
}

static void upd_hlr_vlr_fsm_wait_data(struct osmo_fsm_inst *fi, uint32_t event,
				      void *data)
{
	struct vlr_subscr *vsub = fi->priv;

	switch (event) {
	case UPD_HLR_VLR_E_INS_SUB_DATA:
		/* FIXME: Insert_Subscr_Data_VLR */
		break;
	case UPD_HLR_VLR_E_ACT_TRACE_MODE:
		/* TODO: Activate_Tracing_VLR */
		break;
	case UPD_HLR_VLR_E_FW_CHECK_SS_IND:
		/* TODO: Forward Check SS Ind to MSC */
		break;
	case UPD_HLR_VLR_E_UPD_LOC_ACK:
		/* Inside Update_HLR_VLR after UpdateLocationAck */
		vsub->sub_dataconf_by_hlr_ind = true;
		vsub->loc_conf_in_hlr_ind = true;
		osmo_fsm_inst_state_chg(fi, UPD_HLR_VLR_S_DONE, 0, 0);
		osmo_fsm_inst_term(fi, OSMO_FSM_TERM_REGULAR, NULL);
		break;
	case UPD_HLR_VLR_E_UPD_LOC_NACK:
		/* Inside Update_HLR_VLR after UpdateLocationNack */
		/* TODO: Check_User_Error_In_Serving_Network_Entity */
		vsub->sub_dataconf_by_hlr_ind = false;
		vsub->loc_conf_in_hlr_ind = false;
		osmo_fsm_inst_state_chg(fi, UPD_HLR_VLR_S_DONE, 0, 0);
		/* Data is a pointer to a gsm48_gmm_cause which we
		 * simply pass through */
		osmo_fsm_inst_term(fi, OSMO_FSM_TERM_REGULAR, data);
		break;
	}
}

static const struct osmo_fsm_state upd_hlr_vlr_states[] = {
	[UPD_HLR_VLR_S_INIT] = {
		.in_event_mask = S(UPD_HLR_VLR_E_START),
		.out_state_mask = S(UPD_HLR_VLR_S_WAIT_FOR_DATA),
		.name = OSMO_STRINGIFY(UPD_HLR_VLR_S_INIT),
		.action = upd_hlr_vlr_fsm_init,
	},
	[UPD_HLR_VLR_S_WAIT_FOR_DATA] = {
		.in_event_mask = S(UPD_HLR_VLR_E_INS_SUB_DATA) |
				 S(UPD_HLR_VLR_E_ACT_TRACE_MODE) |
				 S(UPD_HLR_VLR_E_FW_CHECK_SS_IND) |
				 S(UPD_HLR_VLR_E_UPD_LOC_ACK) |
				 S(UPD_HLR_VLR_E_UPD_LOC_NACK),
		.out_state_mask = S(UPD_HLR_VLR_S_DONE),
		.name = OSMO_STRINGIFY(UPD_HLR_VLR_S_WAIT_FOR_DATA),
		.action = upd_hlr_vlr_fsm_wait_data,
	},
	[UPD_HLR_VLR_S_DONE] = {
		.name = OSMO_STRINGIFY(UPD_HLR_VLR_S_DONE),
	},
};

static struct osmo_fsm upd_hlr_vlr_fsm = {
	.name = "upd_hlr_vlr_fsm",
	.states = upd_hlr_vlr_states,
	.num_states = ARRAY_SIZE(upd_hlr_vlr_states),
	.allstate_event_mask = 0,
	.allstate_action = NULL,
	.log_subsys = DVLR,
	.event_names = upd_hlr_vlr_event_names,
};

struct osmo_fsm_inst *
upd_hlr_vlr_proc_start(struct osmo_fsm_inst *parent,
		       struct vlr_subscr *vsub,
		       uint32_t parent_event)
{
	struct osmo_fsm_inst *fi;

	fi = osmo_fsm_inst_alloc_child(&upd_hlr_vlr_fsm, parent,
					parent_event);
	if (!fi)
		return NULL;

	fi->priv = vsub;
	osmo_fsm_inst_dispatch(fi, UPD_HLR_VLR_E_START, NULL);

	return fi;
}


/***********************************************************************
 * Subscriber_Present_VLR, TS 29.002 Chapter 25.10.1
 ***********************************************************************/

enum sub_pres_vlr_state {
	SUB_PRES_VLR_S_INIT,
	SUB_PRES_VLR_S_WAIT_FOR_HLR,
	SUB_PRES_VLR_S_DONE,
};

enum sub_pres_vlr_event {
	SUB_PRES_VLR_E_START,
	SUB_PRES_VLR_E_READY_SM_CNF,
	SUB_PRES_VLR_E_READY_SM_ERR,
};

static const struct value_string sub_pres_vlr_event_names[] = {
	OSMO_VALUE_STRING(SUB_PRES_VLR_E_START),
	OSMO_VALUE_STRING(SUB_PRES_VLR_E_READY_SM_CNF),
	OSMO_VALUE_STRING(SUB_PRES_VLR_E_READY_SM_ERR),
	{ 0, NULL }
};

static void sub_pres_vlr_fsm_init(struct osmo_fsm_inst *fi, uint32_t event,
				  void *data)
{
	struct vlr_subscr *vsub = fi->priv;
	OSMO_ASSERT(event == SUB_PRES_VLR_E_START);

	if (!vsub->ms_not_reachable_flag) {
		osmo_fsm_inst_state_chg(fi, SUB_PRES_VLR_S_DONE, 0, 0);
		osmo_fsm_inst_term(fi, OSMO_FSM_TERM_REGULAR, NULL);
		return;
	}
	/* FIXME: Send READY_FOR_SM via GSUP */
	osmo_fsm_inst_state_chg(fi, SUB_PRES_VLR_S_WAIT_FOR_HLR,
				LU_TIMEOUT_LONG, 0);
}

static void sub_pres_vlr_fsm_wait_hlr(struct osmo_fsm_inst *fi, uint32_t event,
				      void *data)
{
	struct vlr_subscr *vsub = fi->priv;

	switch (event) {
	case SUB_PRES_VLR_E_READY_SM_CNF:
		vsub->ms_not_reachable_flag = false;
		break;
	case SUB_PRES_VLR_E_READY_SM_ERR:
		break;
	}
	osmo_fsm_inst_state_chg(fi, SUB_PRES_VLR_S_DONE, 0, 0);
	osmo_fsm_inst_term(fi, OSMO_FSM_TERM_REGULAR, NULL);
}

static const struct osmo_fsm_state sub_pres_vlr_states[] = {
	[SUB_PRES_VLR_S_INIT] = {
		.in_event_mask = S(SUB_PRES_VLR_E_START),
		.out_state_mask = S(SUB_PRES_VLR_S_WAIT_FOR_HLR) |
				  S(SUB_PRES_VLR_S_DONE),
		.name = OSMO_STRINGIFY(SUB_PRES_VLR_S_INIT),
		.action = sub_pres_vlr_fsm_init,
	},
	[SUB_PRES_VLR_S_WAIT_FOR_HLR] = {
		.in_event_mask = S(SUB_PRES_VLR_E_READY_SM_CNF) |
				 S(SUB_PRES_VLR_E_READY_SM_ERR),
		.out_state_mask = S(SUB_PRES_VLR_S_DONE),
		.name = OSMO_STRINGIFY(SUB_PRES_VLR_S_WAIT_FOR_HLR),
		.action = sub_pres_vlr_fsm_wait_hlr,
	},
	[SUB_PRES_VLR_S_DONE] = {
		.name = OSMO_STRINGIFY(SUB_PRES_VLR_S_DONE),
	},
};

static struct osmo_fsm sub_pres_vlr_fsm = {
	.name = "sub_pres_vlr_fsm",
	.states = sub_pres_vlr_states,
	.num_states = ARRAY_SIZE(sub_pres_vlr_states),
	.allstate_event_mask = 0,
	.allstate_action = NULL,
	.log_subsys = DVLR,
	.event_names = sub_pres_vlr_event_names,
};

struct osmo_fsm_inst *sub_pres_vlr_fsm_start(struct osmo_fsm_inst *parent,
					     struct vlr_subscr *vsub,
					     uint32_t term_event)
{
	struct osmo_fsm_inst *fi;

	fi = osmo_fsm_inst_alloc_child(&sub_pres_vlr_fsm, parent,
					term_event);
	if (!fi)
		return NULL;

	fi->priv = vsub;
	osmo_fsm_inst_dispatch(fi, SUB_PRES_VLR_E_START, NULL);

	return fi;
}

/***********************************************************************
 * Location_Update_Completion_VLR, TS 23.012 Chapter 4.1.2.3
 ***********************************************************************/

enum lu_compl_vlr_state {
	LU_COMPL_VLR_S_INIT,
	LU_COMPL_VLR_S_WAIT_SUB_PRES,
	LU_COMPL_VLR_S_WAIT_IMEI,
	LU_COMPL_VLR_S_WAIT_IMEI_TMSI,
	LU_COMPL_VLR_S_WAIT_TMSI_CNF,
	LU_COMPL_VLR_S_DONE,
};

enum lu_compl_vlr_event {
	LU_COMPL_VLR_E_START,
	LU_COMPL_VLR_E_SUB_PRES_COMPL,
	LU_COMPL_VLR_E_IMEI_CHECK_ACK,
	LU_COMPL_VLR_E_IMEI_CHECK_NACK,
	LU_COMPL_VLR_E_NEW_TMSI_ACK,
};

static const struct value_string lu_compl_vlr_event_names[] = {
	OSMO_VALUE_STRING(LU_COMPL_VLR_E_START),
	OSMO_VALUE_STRING(LU_COMPL_VLR_E_SUB_PRES_COMPL),
	OSMO_VALUE_STRING(LU_COMPL_VLR_E_IMEI_CHECK_ACK),
	OSMO_VALUE_STRING(LU_COMPL_VLR_E_IMEI_CHECK_NACK),
	OSMO_VALUE_STRING(LU_COMPL_VLR_E_NEW_TMSI_ACK),
	{ 0, NULL }
};

struct lu_compl_vlr_priv {
	struct vlr_subscr *vsub;
	void *msc_conn_ref;
	struct osmo_fsm_inst *sub_pres_vlr_fsm;
	uint32_t parent_event_success;
	uint32_t parent_event_failure;
	void *parent_event_data;
	enum vlr_fsm_result result;
	uint8_t cause;
	bool assign_tmsi;
};

static void _vlr_lu_compl_fsm_done(struct osmo_fsm_inst *fi,
				   enum vlr_fsm_result result,
				   uint8_t cause)
{
	struct lu_compl_vlr_priv *lcvp = fi->priv;
	lcvp->result = result;
	lcvp->cause = cause;
	osmo_fsm_inst_state_chg(fi, LU_COMPL_VLR_S_DONE, 0, 0);
}

static void vlr_lu_compl_fsm_success(struct osmo_fsm_inst *fi)
{
	struct lu_compl_vlr_priv *lcvp = fi->priv;
	struct vlr_subscr *vsub = lcvp->vsub;
	if (!vsub->lu_complete) {
		vsub->lu_complete = true;
		/* Balanced by vlr_subscr_rx_imsi_detach() */
		vlr_subscr_get(vsub);
	}
	_vlr_lu_compl_fsm_done(fi, VLR_FSM_RESULT_SUCCESS, 0);
}

static void vlr_lu_compl_fsm_failure(struct osmo_fsm_inst *fi, uint8_t cause)
{
	struct lu_compl_vlr_priv *lcvp = fi->priv;
	lcvp->vsub->vlr->ops.tx_lu_rej(lcvp->msc_conn_ref, cause);
	_vlr_lu_compl_fsm_done(fi, VLR_FSM_RESULT_FAILURE, cause);
}

static void vlr_lu_compl_fsm_dispatch_result(struct osmo_fsm_inst *fi,
					     uint32_t prev_state)
{
	struct lu_compl_vlr_priv *lcvp = fi->priv;
	if (!fi->proc.parent) {
		LOGPFSML(fi, LOGL_ERROR, "No parent FSM\n");
		return;
	}
	osmo_fsm_inst_dispatch(fi->proc.parent,
			       (lcvp->result == VLR_FSM_RESULT_SUCCESS)
			       ? lcvp->parent_event_success
			       : lcvp->parent_event_failure,
			       &lcvp->cause);
}

static void lu_compl_vlr_init(struct osmo_fsm_inst *fi, uint32_t event,
			      void *data)
{
	struct lu_compl_vlr_priv *lcvp = fi->priv;
	struct vlr_subscr *vsub = lcvp->vsub;
	struct vlr_instance *vlr;
	OSMO_ASSERT(vsub);
	vlr = vsub->vlr;
	OSMO_ASSERT(vlr);

	OSMO_ASSERT(event == LU_COMPL_VLR_E_START);

	/* TODO: National Roaming restrictions? */
	/* TODO: Roaming restriction due to unsupported feature in subscriber
	 * data? */
	/* TODO: Regional subscription restriction? */
	/* TODO: Administrative restriction of subscribres' access feature? */
	/* TODO: AccessRestrictuionData parameter available? */
	/* TODO: AccessRestrictionData permits RAT? */
	/* Node 1 */
	/* TODO: Autonomous CSG supported in VPLMN and allowed by HPLMN? */
	/* TODO: Hybrid Cel / CSG Cell */
	/* Node 2 */
	vsub->la_allowed = true;
	vsub->imsi_detached_flag = false;
	/* Start Subscriber_Present_VLR Procedure */
	osmo_fsm_inst_state_chg(fi, LU_COMPL_VLR_S_WAIT_SUB_PRES,
				LU_TIMEOUT_LONG, 0);

	lcvp->sub_pres_vlr_fsm = sub_pres_vlr_fsm_start(fi, vsub,
						LU_COMPL_VLR_E_SUB_PRES_COMPL);

}

static void lu_compl_vlr_new_tmsi(struct osmo_fsm_inst *fi)
{
	struct lu_compl_vlr_priv *lcvp = fi->priv;
	struct vlr_subscr *vsub = lcvp->vsub;
	struct vlr_instance *vlr = vsub->vlr;

	LOGPFSM(fi, "%s()\n", __func__);

	if (vlr_subscr_alloc_tmsi(vsub)) {
		vlr_lu_compl_fsm_failure(fi,
					 GSM48_REJECT_SRV_OPT_TMP_OUT_OF_ORDER);
		return;
	}

	osmo_fsm_inst_state_chg(fi, LU_COMPL_VLR_S_WAIT_TMSI_CNF,
				vlr_timer(vlr, 3250), 3250);

	vlr->ops.tx_lu_acc(lcvp->msc_conn_ref, vsub->tmsi_new);
}

/* After completion of Subscriber_Present_VLR */
static void lu_compl_vlr_wait_subscr_pres(struct osmo_fsm_inst *fi,
					  uint32_t event,
					  void *data)
{
	struct lu_compl_vlr_priv *lcvp = fi->priv;
	struct vlr_subscr *vsub = lcvp->vsub;
	struct vlr_instance *vlr = vsub->vlr;

	OSMO_ASSERT(event == LU_COMPL_VLR_E_SUB_PRES_COMPL);

	lcvp->sub_pres_vlr_fsm = NULL;

	/* TODO: Trace_Subscriber_Activity_VLR */

	if (vlr->cfg.check_imei_rqd) {
		/* Check IMEI VLR */
		osmo_fsm_inst_state_chg(fi,
					lcvp->assign_tmsi ?
					  LU_COMPL_VLR_S_WAIT_IMEI_TMSI
					: LU_COMPL_VLR_S_WAIT_IMEI,
					vlr_timer(vlr, 3270), 3270);
		vlr->ops.tx_id_req(lcvp->msc_conn_ref, GSM_MI_TYPE_IMEI);
		return;
	}

	/* Do we need to allocate a TMSI? */
	if (lcvp->assign_tmsi) {
		lu_compl_vlr_new_tmsi(fi);
		return;
	}

	/* Location Updating Accept */
	vlr->ops.tx_lu_acc(lcvp->msc_conn_ref, GSM_RESERVED_TMSI);
	vlr_lu_compl_fsm_success(fi);
}

/* Waiting for completion of CHECK_IMEI_VLR */
static void lu_compl_vlr_wait_imei(struct osmo_fsm_inst *fi, uint32_t event,
				   void *data)
{
	struct lu_compl_vlr_priv *lcvp = fi->priv;
	struct vlr_subscr *vsub = lcvp->vsub;
	struct vlr_instance *vlr = vsub->vlr;

	switch (event) {
	case LU_COMPL_VLR_E_IMEI_CHECK_ACK:
		if (!vsub->imei[0]) {
			/* Abort: Do nothing */
			vlr_lu_compl_fsm_failure(fi,
						 GSM48_REJECT_PROTOCOL_ERROR);
			return;
		}
		/* Pass */
		break;

	case LU_COMPL_VLR_E_IMEI_CHECK_NACK:
		vlr_lu_compl_fsm_failure(fi, GSM48_REJECT_ILLEGAL_ME);
		/* FIXME: IMEI Check Fail to VLR Application (Detach IMSI VLR) */
		return;
	}

	/* IMEI is available. Allocate TMSI if needed. */
	if (lcvp->assign_tmsi) {
		if (fi->state != LU_COMPL_VLR_S_WAIT_IMEI_TMSI)
			LOGPFSML(fi, LOGL_ERROR,
				 "TMSI required, expected to be in state"
				 " LU_COMPL_VLR_S_WAIT_IMEI_TMSI,"
				 " am in %s instead\n",
				 osmo_fsm_state_name(fi->fsm, fi->state));
			/* Logged an error, continue anyway. */

		lu_compl_vlr_new_tmsi(fi);

		/* Wait for TMSI ack */
		return;
	}

	/* No TMSI needed, accept now. */
	vlr->ops.tx_lu_acc(lcvp->msc_conn_ref, GSM_RESERVED_TMSI);
	vlr_lu_compl_fsm_success(fi);
}

/* Waiting for TMSI confirmation */
static void lu_compl_vlr_wait_tmsi(struct osmo_fsm_inst *fi, uint32_t event,
				   void *data)
{
	struct lu_compl_vlr_priv *lcvp = fi->priv;
	struct vlr_subscr *vsub = lcvp->vsub;

	OSMO_ASSERT(event == LU_COMPL_VLR_E_NEW_TMSI_ACK);

	if (!vsub || vsub->tmsi_new == GSM_RESERVED_TMSI) {
		LOGPFSML(fi, LOGL_ERROR, "TMSI Realloc Compl implies that"
			 " the subscriber has a new TMSI allocated, but"
			 " the new TMSI is unset.\n");
		vlr_lu_compl_fsm_failure(fi, GSM48_REJECT_NETWORK_FAILURE);
		return;
	}

	vsub->tmsi = vsub->tmsi_new;
	vsub->tmsi_new = GSM_RESERVED_TMSI;

	vlr_lu_compl_fsm_success(fi);
}

static const struct osmo_fsm_state lu_compl_vlr_states[] = {
	[LU_COMPL_VLR_S_INIT] = {
		.in_event_mask = S(LU_COMPL_VLR_E_START),
		.out_state_mask = S(LU_COMPL_VLR_S_DONE) |
				  S(LU_COMPL_VLR_S_WAIT_SUB_PRES) |
				  S(LU_COMPL_VLR_S_WAIT_IMEI),
		.name = OSMO_STRINGIFY(LU_COMPL_VLR_S_INIT),
		.action = lu_compl_vlr_init,
	},
	[LU_COMPL_VLR_S_WAIT_SUB_PRES] = {
		.in_event_mask = S(LU_COMPL_VLR_E_SUB_PRES_COMPL),
		.out_state_mask = S(LU_COMPL_VLR_S_WAIT_IMEI) |
				  S(LU_COMPL_VLR_S_WAIT_IMEI_TMSI) |
				  S(LU_COMPL_VLR_S_WAIT_TMSI_CNF) |
				  S(LU_COMPL_VLR_S_DONE),
		.name = OSMO_STRINGIFY(LU_COMPL_VLR_S_WAIT_SUB_PRES),
		.action = lu_compl_vlr_wait_subscr_pres,
	},
	[LU_COMPL_VLR_S_WAIT_IMEI] = {
		.in_event_mask = S(LU_COMPL_VLR_E_IMEI_CHECK_ACK) |
				 S(LU_COMPL_VLR_E_IMEI_CHECK_NACK),
		.out_state_mask = S(LU_COMPL_VLR_S_DONE),
		.name = OSMO_STRINGIFY(LU_COMPL_VLR_S_WAIT_IMEI),
		.action = lu_compl_vlr_wait_imei,
	},
	[LU_COMPL_VLR_S_WAIT_IMEI_TMSI] = {
		.in_event_mask = S(LU_COMPL_VLR_E_IMEI_CHECK_ACK) |
				 S(LU_COMPL_VLR_E_IMEI_CHECK_NACK),
		.out_state_mask = S(LU_COMPL_VLR_S_DONE) |
				  S(LU_COMPL_VLR_S_WAIT_TMSI_CNF),
		.name = OSMO_STRINGIFY(LU_COMPL_VLR_S_WAIT_IMEI_TMSI),
		.action = lu_compl_vlr_wait_imei,
	},
	[LU_COMPL_VLR_S_WAIT_TMSI_CNF] = {
		.in_event_mask = S(LU_COMPL_VLR_E_NEW_TMSI_ACK),
		.out_state_mask = S(LU_COMPL_VLR_S_DONE),
		.name = OSMO_STRINGIFY(LU_COMPL_VLR_S_WAIT_TMSI_CNF),
		.action = lu_compl_vlr_wait_tmsi,
	},
	[LU_COMPL_VLR_S_DONE] = {
		.name = OSMO_STRINGIFY(LU_COMPL_VLR_S_DONE),
		.onenter = vlr_lu_compl_fsm_dispatch_result,
	},
};

static struct osmo_fsm lu_compl_vlr_fsm = {
	.name = "lu_compl_vlr_fsm",
	.states = lu_compl_vlr_states,
	.num_states = ARRAY_SIZE(lu_compl_vlr_states),
	.allstate_event_mask = 0,
	.allstate_action = NULL,
	.log_subsys = DVLR,
	.event_names = lu_compl_vlr_event_names,
};

struct osmo_fsm_inst *
lu_compl_vlr_proc_alloc(struct osmo_fsm_inst *parent,
			struct vlr_subscr *vsub,
			void *msc_conn_ref,
			uint32_t parent_event_success,
			uint32_t parent_event_failure,
			bool assign_tmsi)
{
	struct osmo_fsm_inst *fi;
	struct lu_compl_vlr_priv *lcvp;

	fi = osmo_fsm_inst_alloc_child(&lu_compl_vlr_fsm, parent,
				       parent_event_failure);
	if (!fi)
		return NULL;

	lcvp = talloc_zero(fi, struct lu_compl_vlr_priv);
	lcvp->vsub = vsub;
	lcvp->msc_conn_ref = msc_conn_ref;
	lcvp->parent_event_success = parent_event_success;
	lcvp->parent_event_failure = parent_event_failure;
	lcvp->assign_tmsi = assign_tmsi;
	fi->priv = lcvp;

	return fi;
}


/***********************************************************************
 * Update_Location_Area_VLR, TS 23.012 Chapter 4.1.2.1
 ***********************************************************************/

static const struct value_string fsm_lu_event_names[] = {
	OSMO_VALUE_STRING(VLR_ULA_E_UPDATE_LA),
	OSMO_VALUE_STRING(VLR_ULA_E_SEND_ID_ACK),
	OSMO_VALUE_STRING(VLR_ULA_E_SEND_ID_NACK),
	OSMO_VALUE_STRING(VLR_ULA_E_AUTH_RES),
	OSMO_VALUE_STRING(VLR_ULA_E_CIPH_RES),
	OSMO_VALUE_STRING(VLR_ULA_E_ID_IMSI),
	OSMO_VALUE_STRING(VLR_ULA_E_ID_IMEI),
	OSMO_VALUE_STRING(VLR_ULA_E_ID_IMEISV),
	OSMO_VALUE_STRING(VLR_ULA_E_HLR_LU_RES),
	OSMO_VALUE_STRING(VLR_ULA_E_UPD_HLR_COMPL),
	OSMO_VALUE_STRING(VLR_ULA_E_LU_COMPL_SUCCESS),
	OSMO_VALUE_STRING(VLR_ULA_E_LU_COMPL_FAILURE),
	OSMO_VALUE_STRING(VLR_ULA_E_NEW_TMSI_ACK),
	{ 0, NULL }
};

struct lu_fsm_priv {
	struct vlr_instance *vlr;
	struct vlr_subscr *vsub;
	void *msc_conn_ref;
	struct osmo_fsm_inst *upd_hlr_vlr_fsm;
	struct osmo_fsm_inst *lu_compl_vlr_fsm;
	uint32_t parent_event_success;
	uint32_t parent_event_failure;
	void *parent_event_data;
	enum vlr_fsm_result result;
	uint8_t rej_cause;

	enum vlr_lu_type type;
	bool lu_by_tmsi;
	char imsi[16];
	uint32_t tmsi;
	struct osmo_location_area_id old_lai;
	struct osmo_location_area_id new_lai;
	bool authentication_required;
	enum vlr_ciph ciphering_required;
	bool is_r99;
	bool is_utran;
	bool assign_tmsi;
};


/* Determine if given location area is served by this VLR */
static bool lai_in_this_vlr(struct vlr_instance *vlr,
			    const struct osmo_location_area_id *lai)
{
	/* TODO: VLR needs to keep a locally configued list of LAIs */
	return true;
}

/* Determine if authentication is required */
static bool is_auth_required(struct lu_fsm_priv *lfp)
{
	/* The cases where the authentication procedure should be used
	 * are defined in 3GPP TS 33.102 */
	/* For now we use a default value passed in to vlr_lu_fsm(). */
	return lfp->authentication_required
	       || (lfp->ciphering_required != VLR_CIPH_NONE);
}

/* Determine if ciphering is required */
static bool is_ciph_required(struct lu_fsm_priv *lfp)
{
	return lfp->ciphering_required != VLR_CIPH_NONE;
}

/* Determine if a HLR Update is required */
static bool hlr_update_needed(struct vlr_subscr *vsub)
{
	/* TODO: properly decide this, rather than always assuming we
	 * need to update the HLR. */
	return true;
}

static void lu_fsm_dispatch_result(struct osmo_fsm_inst *fi,
				   uint32_t prev_state)
{
	struct lu_fsm_priv *lfp = fi->priv;
	if (!fi->proc.parent) {
		LOGPFSML(fi, LOGL_ERROR, "No parent FSM\n");
		return;
	}
	osmo_fsm_inst_dispatch(fi->proc.parent,
			       (lfp->result == VLR_FSM_RESULT_SUCCESS)
			       ? lfp->parent_event_success
			       : lfp->parent_event_failure,
			       lfp->parent_event_data);
}

static void _lu_fsm_done(struct osmo_fsm_inst *fi,
			 enum vlr_fsm_result result)
{
	struct lu_fsm_priv *lfp = fi->priv;
	lfp->result = result;
	osmo_fsm_inst_state_chg(fi, VLR_ULA_S_DONE, 0, 0);
}

static void lu_fsm_success(struct osmo_fsm_inst *fi)
{
	_lu_fsm_done(fi, VLR_FSM_RESULT_SUCCESS);
}

static void lu_fsm_failure(struct osmo_fsm_inst *fi, uint8_t rej_cause)
{
	struct lu_fsm_priv *lfp = fi->priv;
	if (rej_cause)
		lfp->vlr->ops.tx_lu_rej(lfp->msc_conn_ref, rej_cause);
	_lu_fsm_done(fi, VLR_FSM_RESULT_FAILURE);
}

static void vlr_loc_upd_start_lu_compl_fsm(struct osmo_fsm_inst *fi)
{
	struct lu_fsm_priv *lfp = fi->priv;
	lfp->lu_compl_vlr_fsm =
		lu_compl_vlr_proc_alloc(fi, lfp->vsub, lfp->msc_conn_ref,
					VLR_ULA_E_LU_COMPL_SUCCESS,
					VLR_ULA_E_LU_COMPL_FAILURE,
					lfp->assign_tmsi);

	osmo_fsm_inst_dispatch(lfp->lu_compl_vlr_fsm, LU_COMPL_VLR_E_START, NULL);
}

static void lu_fsm_discard_lu_compl_fsm(struct osmo_fsm_inst *fi)
{
	struct lu_fsm_priv *lfp = fi->priv;
	if (!lfp->lu_compl_vlr_fsm)
		return;
	osmo_fsm_inst_term(lfp->lu_compl_vlr_fsm, OSMO_FSM_TERM_PARENT, NULL);
}

/* 4.1.2.1 Node 4 */
static void vlr_loc_upd_node_4(struct osmo_fsm_inst *fi)
{
	struct lu_fsm_priv *lfp = fi->priv;
	struct vlr_subscr *vsub = lfp->vsub;
	bool hlr_unknown = false;

	LOGPFSM(fi, "%s()\n", __func__);

	if (hlr_unknown) {
		/* FIXME: Delete subscriber record */
		/* LU REJ: Roaming not allowed */
		lu_fsm_failure(fi, GSM48_REJECT_ROAMING_NOT_ALLOWED);
	} else {
		/* Update_HLR_VLR */
		osmo_fsm_inst_state_chg(fi, VLR_ULA_S_WAIT_HLR_UPD,
					LU_TIMEOUT_LONG, 0);
		lfp->upd_hlr_vlr_fsm =
			upd_hlr_vlr_proc_start(fi, vsub, VLR_ULA_E_UPD_HLR_COMPL);
	}
}

/* 4.1.2.1 Node B */
static void vlr_loc_upd_node_b(struct osmo_fsm_inst *fi)
{
	LOGPFSM(fi, "%s()\n", __func__);

	/* FIXME */
	if (0) { /* IMEISV or PgA to send */
		vlr_loc_upd_node_4(fi);
	} else {
		/* Location_Update_Completion */
		osmo_fsm_inst_state_chg(fi, VLR_ULA_S_WAIT_LU_COMPL,
					LU_TIMEOUT_LONG, 0);
		vlr_loc_upd_start_lu_compl_fsm(fi);
	}
}

/* Non-standard: after Ciphering Mode Complete (or no ciph required) */
static void vlr_loc_upd_post_ciph(struct osmo_fsm_inst *fi)
{
	struct lu_fsm_priv *lfp = fi->priv;
	struct vlr_subscr *vsub = lfp->vsub;

	LOGPFSM(fi, "%s()\n", __func__);

	OSMO_ASSERT(vsub);

	vsub->conf_by_radio_contact_ind = true;
	/* Update LAI */
	vsub->cgi.lai = lfp->new_lai;
	vsub->dormant_ind = false;
	vsub->cancel_loc_rx = false;
	if (hlr_update_needed(vsub)) {
		vlr_loc_upd_node_4(fi);
	} else {
		/* TODO: ADD Support */
		/* TODO: Node A: PgA Support */
		vlr_loc_upd_node_b(fi);
	}
}

/* 4.1.2.1 after Authentication successful (or no auth rqd) */
static void vlr_loc_upd_post_auth(struct osmo_fsm_inst *fi)
{
	struct lu_fsm_priv *lfp = fi->priv;
	struct vlr_subscr *vsub = lfp->vsub;

	LOGPFSM(fi, "%s()\n", __func__);

	OSMO_ASSERT(vsub);

	if (!is_ciph_required(lfp)) {
		vlr_loc_upd_post_ciph(fi);
		return;
	}

	if (vlr_set_ciph_mode(vsub->vlr, fi, lfp->msc_conn_ref,
			      lfp->ciphering_required,
			      vsub->vlr->cfg.retrieve_imeisv)) {
		LOGPFSML(fi, LOGL_ERROR,
			 "Failed to send Ciphering Mode Command\n");
		vlr_lu_compl_fsm_failure(fi, GSM48_REJECT_NETWORK_FAILURE);
		return;
	}

	osmo_fsm_inst_state_chg(fi, VLR_ULA_S_WAIT_CIPH, LU_TIMEOUT_LONG, 0);
}

static void vlr_loc_upd_node1(struct osmo_fsm_inst *fi)
{
	struct lu_fsm_priv *lfp = fi->priv;
	struct vlr_subscr *vsub = lfp->vsub;

	LOGPFSM(fi, "%s()\n", __func__);

	OSMO_ASSERT(vsub);

	if (is_auth_required(lfp)) {
		/* Authenticate_VLR */
		osmo_fsm_inst_state_chg(fi, VLR_ULA_S_WAIT_AUTH,
					LU_TIMEOUT_LONG, 0);
		vsub->auth_fsm = auth_fsm_start(lfp->vsub, fi->log_level,
						fi, VLR_ULA_E_AUTH_RES,
						lfp->is_r99,
						lfp->is_utran);
	} else {
		/* no need for authentication */
		vlr_loc_upd_post_auth(fi);
	}
}

static void vlr_loc_upd_want_imsi(struct osmo_fsm_inst *fi)
{
	struct lu_fsm_priv *lfp = fi->priv;
	struct vlr_instance *vlr = lfp->vlr;

	LOGPFSM(fi, "%s()\n", __func__);

	OSMO_ASSERT(lfp->vsub);

	/* Obtain_IMSI_VLR */
	osmo_fsm_inst_state_chg(fi, VLR_ULA_S_WAIT_IMSI,
				vlr_timer(vlr, 3270), 3270);
	vlr->ops.tx_id_req(lfp->msc_conn_ref, GSM_MI_TYPE_IMSI);
	/* will continue at vlr_loc_upd_node1() once IMSI arrives */
}

static int assoc_lfp_with_sub(struct osmo_fsm_inst *fi, struct vlr_subscr *vsub)
{
	struct lu_fsm_priv *lfp = fi->priv;
	struct vlr_instance *vlr = lfp->vlr;

	if (vsub->lu_fsm) {
		LOGPFSML(fi, LOGL_ERROR,
			 "A Location Updating process is already pending for"
			 " this subscriber. Aborting.\n");
		/* Also get rid of the other pending LU attempt? */
		/*lu_fsm_failure(vsub->lu_fsm, GSM48_REJECT_CONGESTION);*/
		lu_fsm_failure(fi, GSM48_REJECT_CONGESTION);
		return -EINVAL;
	}
	vsub->lu_fsm = fi;
	vsub->msc_conn_ref = lfp->msc_conn_ref;
	/* FIXME: send new LAC to HLR? */
	vsub->lac = lfp->new_lai.lac;
	lfp->vsub = vsub;
	/* Tell MSC to associate this subscriber with the given
	 * connection */
	vlr->ops.subscr_assoc(lfp->msc_conn_ref, lfp->vsub);
	return 0;
}

static const char *lai_name(struct osmo_location_area_id *lai)
{
	static char buf[64];
	snprintf(buf, sizeof(buf),"MCC:%u, MNC:%u, LAC:%u",
		 lai->plmn.mcc, lai->plmn.mnc, lai->lac);
	return buf;
}

/* 4.1.2.1: Subscriber (via MSC/SGSN) requests location update */
static void _start_lu_main(struct osmo_fsm_inst *fi)
{
	struct lu_fsm_priv *lfp = fi->priv;
	struct vlr_instance *vlr = lfp->vlr;
	struct vlr_subscr *vsub = NULL;
	bool created;

	/* TODO: PUESBINE related handling */

	/* Is previous LAI in this VLR? */
	if (!lai_in_this_vlr(vlr, &lfp->old_lai)) {
#if 0
		/* FIXME: check previous VLR, (3) */
		osmo_fsm_inst_state_chg(fi, VLR_ULA_S_WAIT_PVLR,
					LU_TIMEOUT_LONG, 0);
		return;
#endif
		LOGPFSML(fi, LOGL_NOTICE, "LAI change from %s,"
			 " but checking previous VLR not implemented\n",
			 lai_name(&lfp->old_lai));
	}

	if (!lfp->imsi[0]) {
		/* TMSI was used */
		lfp->lu_by_tmsi = true;
		/* TMSI clash: if a different subscriber already has this TMSI,
		 * we will find that other subscriber in the VLR. So the IMSIs
		 * would mismatch, but we don't know about it. Theoretically,
		 * an authentication process would thwart any attempt to use
		 * someone else's TMSI.
		 * TODO: Otherwise we can ask for the IMSI and verify that it
		 * matches the IMSI on record. */
		vsub = vlr_subscr_find_or_create_by_tmsi(vlr, lfp->tmsi,
							 &created);

		if (!vsub) {
			LOGPFSML(fi, LOGL_ERROR,
				 "VLR subscriber allocation failed\n");
			lu_fsm_failure(fi, GSM48_REJECT_SRV_OPT_TMP_OUT_OF_ORDER);
			return;
		}

		vsub->sub_dataconf_by_hlr_ind = false;
		if (assoc_lfp_with_sub(fi, vsub)) {
			vlr_subscr_put(vsub);
			return; /* error */
		}

		if (created)
			vlr_loc_upd_want_imsi(fi);
		else
			vlr_loc_upd_node1(fi);
		/* We cannot have MSC area change, as the VLR
		 * serves only one MSC */
		vlr_subscr_put(vsub);
	} else {
		/* IMSI was used */
		vsub = vlr_subscr_find_or_create_by_imsi(vlr, lfp->imsi, NULL);

		if (!vsub) {
			LOGPFSML(fi, LOGL_ERROR,
				 "VLR subscriber allocation failed\n");
			lu_fsm_failure(fi, GSM48_REJECT_SRV_OPT_TMP_OUT_OF_ORDER);
			vlr_subscr_put(vsub);
			return;
		}

		vsub->sub_dataconf_by_hlr_ind = false;
		if (assoc_lfp_with_sub(fi, vsub)) {
			vlr_subscr_put(vsub);
			return; /* error */
		}
		vlr_loc_upd_node1(fi);
		vlr_subscr_put(vsub);
	}
}


static void lu_fsm_idle(struct osmo_fsm_inst *fi, uint32_t event,
			void *data)
{
	struct lu_fsm_priv *lfp = fi->priv;
	struct vlr_instance *vlr = lfp->vlr;

	OSMO_ASSERT(event == VLR_ULA_E_UPDATE_LA);

	if (1) { // FIXME
	//if (lfp->type == VLR_LU_TYPE_PERIODIC && lfp->vsub->imeisv[0])
		/* R_IMEISV_IR1 passed */
		_start_lu_main(fi);
	} else {
		vlr->ops.tx_id_req(lfp->msc_conn_ref, GSM_MI_TYPE_IMEISV);
		osmo_fsm_inst_state_chg(fi, VLR_ULA_S_WAIT_IMEISV,
					vlr_timer(vlr, 3270), 3270);
	}
}

static void lu_fsm_wait_imeisv(struct osmo_fsm_inst *fi, uint32_t event,
			       void *data)
{
	switch (event) {
	case VLR_ULA_E_ID_IMEISV:
		/* FIXME: copy IMEISV */
		_start_lu_main(fi);
		break;
	default:
		LOGPFSML(fi, LOGL_ERROR, "event without effect: %s\n",
			 osmo_fsm_event_name(fi->fsm, event));
		break;
	}
}

/* Wait for response from Send_Identification to PVLR */
static void lu_fsm_wait_pvlr(struct osmo_fsm_inst *fi, uint32_t event,
			     void *data)
{
	switch (event) {
	case VLR_ULA_E_SEND_ID_ACK:
		vlr_loc_upd_node1(fi);
		break;
	case VLR_ULA_E_SEND_ID_NACK:
		vlr_loc_upd_want_imsi(fi);
		break;
	default:
		LOGPFSML(fi, LOGL_ERROR, "event without effect: %s\n",
			 osmo_fsm_event_name(fi->fsm, event));
		break;
	}
}

/* Wait for result of Authenticate_VLR procedure */
static void lu_fsm_wait_auth(struct osmo_fsm_inst *fi, uint32_t event,
			     void *data)
{
	struct lu_fsm_priv *lfp = fi->priv;
	enum vlr_auth_fsm_result *res = data;
	uint8_t rej_cause = 0;

	OSMO_ASSERT(event == VLR_ULA_E_AUTH_RES);

	lfp->upd_hlr_vlr_fsm = NULL;

	if (res) {
		switch (*res) {
		case VLR_AUTH_RES_PASSED:
			/* Result == Pass */
			vlr_loc_upd_post_auth(fi);
			return;
		case VLR_AUTH_RES_ABORTED:
			/* go to Idle with no response */
			rej_cause = 0;
			break;
		case VLR_AUTH_RES_UNKNOWN_SUBSCR:
			/* FIXME: delete subscribe record */
			rej_cause = GSM48_REJECT_IMSI_UNKNOWN_IN_HLR;
			break;
		case VLR_AUTH_RES_AUTH_FAILED:
			/* cause = illegal subscriber */
			rej_cause = GSM48_REJECT_ILLEGAL_MS;
			break;
		case VLR_AUTH_RES_PROC_ERR:
			/* cause = system failure */
			rej_cause = GSM48_REJECT_NETWORK_FAILURE;
			break;
		default:
			LOGPFSML(fi, LOGL_ERROR, "event without effect: %s\n",
				 osmo_fsm_event_name(fi->fsm, event));
			break;
		}
	} else
		rej_cause = GSM48_REJECT_NETWORK_FAILURE;

	lu_fsm_failure(fi, rej_cause);
}

static void lu_fsm_wait_ciph(struct osmo_fsm_inst *fi, uint32_t event,
			     void *data)
{
	struct lu_fsm_priv *lfp = fi->priv;
	struct vlr_subscr *vsub = lfp->vsub;
	struct vlr_ciph_result res = { .cause = VLR_CIPH_REJECT };

	OSMO_ASSERT(event == VLR_ULA_E_CIPH_RES);

	if (!data)
		LOGPFSML(fi, LOGL_ERROR, "invalid ciphering result: NULL\n");
	else
		res = *(struct vlr_ciph_result*)data;

	switch (res.cause) {
	case VLR_CIPH_COMPL:
		break;
	case VLR_CIPH_REJECT:
		LOGPFSM(fi, "ciphering rejected\n");
		lu_fsm_failure(fi, GSM48_REJECT_INVALID_MANDANTORY_INF);
		return;
	default:
		LOGPFSML(fi, LOGL_ERROR, "invalid ciphering result: %d\n",
			 res.cause);
		lu_fsm_failure(fi, GSM48_REJECT_INVALID_MANDANTORY_INF);
		return;
	}

	if (res.imeisv) {
		LOGPFSM(fi, "got IMEISV: %s\n", res.imeisv);
		vlr_subscr_set_imeisv(vsub, res.imeisv);
	}
	vlr_loc_upd_post_ciph(fi);
}

static void lu_fsm_wait_imsi(struct osmo_fsm_inst *fi, uint32_t event,
			     void *data)
{
	struct lu_fsm_priv *lfp = fi->priv;
	struct vlr_subscr *vsub = lfp->vsub;
	char *mi_string = data;

	switch (event) {
	case VLR_ULA_E_ID_IMSI:
		vlr_subscr_set_imsi(vsub, mi_string);
		vlr_loc_upd_node1(fi);
		break;
	default:
		LOGPFSML(fi, LOGL_ERROR, "event without effect: %s\n",
			 osmo_fsm_event_name(fi->fsm, event));
		break;
	}
}

/* At the end of Update_HLR_VLR */
static void lu_fsm_wait_hlr_ul_res(struct osmo_fsm_inst *fi, uint32_t event,
				   void *data)
{
	struct lu_fsm_priv *lfp = fi->priv;

	switch (event) {
	case VLR_ULA_E_HLR_LU_RES:
		/* pass-through this event to Update_HLR_VLR */
		if (data == NULL)
			osmo_fsm_inst_dispatch(lfp->upd_hlr_vlr_fsm, UPD_HLR_VLR_E_UPD_LOC_ACK, NULL);
		else
			osmo_fsm_inst_dispatch(lfp->upd_hlr_vlr_fsm, UPD_HLR_VLR_E_UPD_LOC_NACK, data);
		break;
	case VLR_ULA_E_UPD_HLR_COMPL:
		if (data == NULL) {
			/* successful case */
			osmo_fsm_inst_state_chg(fi, VLR_ULA_S_WAIT_LU_COMPL,
						LU_TIMEOUT_LONG, 0);
			vlr_loc_upd_start_lu_compl_fsm(fi);
			/* continue in MSC ?!? */
		} else {
			/* unsuccessful case */
			enum gsm48_gmm_cause cause =
				*(enum gsm48_gmm_cause *)data;
			if (0 /* procedure_error && vlr->cfg.standalone_mode */) {
				osmo_fsm_inst_state_chg(fi,
						VLR_ULA_S_WAIT_LU_COMPL_STANDALONE,
						LU_TIMEOUT_LONG, 0);
				vlr_loc_upd_start_lu_compl_fsm(fi);
			} else {
				lu_fsm_failure(fi, cause);
			}
		}
		break;
	default:
		LOGPFSML(fi, LOGL_ERROR, "event without effect: %s\n",
			 osmo_fsm_event_name(fi->fsm, event));
		break;
	}
}

/* Wait for end of Location_Update_Completion_VLR */
static void lu_fsm_wait_lu_compl(struct osmo_fsm_inst *fi, uint32_t event,
				 void *data)
{
	struct lu_fsm_priv *lfp = fi->priv;
	uint8_t cause;

	switch (event) {
	case VLR_ULA_E_NEW_TMSI_ACK:
		osmo_fsm_inst_dispatch(lfp->lu_compl_vlr_fsm,
				       LU_COMPL_VLR_E_NEW_TMSI_ACK, NULL);
		break;
	case VLR_ULA_E_ID_IMEI:
		osmo_fsm_inst_dispatch(lfp->lu_compl_vlr_fsm,
				       LU_COMPL_VLR_E_IMEI_CHECK_ACK, NULL);
		break;
	case VLR_ULA_E_LU_COMPL_SUCCESS:
		lu_fsm_discard_lu_compl_fsm(fi);

		/* Update Register */
		/* TODO: Set_Notification_Type 23.078 */
		/* TODO: Notify_gsmSCF 23.078 */
		/* TODO: Authenticated Radio Contact Established -> ARC */
		lu_fsm_success(fi);
		break;
	case VLR_ULA_E_LU_COMPL_FAILURE:
		cause = GSM48_REJECT_NETWORK_FAILURE;
		if (data)
			cause = *(uint8_t*)data;
		lu_fsm_discard_lu_compl_fsm(fi);
		lu_fsm_failure(fi, cause);
		break;
	default:
		LOGPFSML(fi, LOGL_ERROR, "event without effect: %s\n",
			 osmo_fsm_event_name(fi->fsm, event));
		break;
	}
}

/* Wait for end of Location_Update_Completion_VLR (standalone case) */
static void lu_fsm_wait_lu_compl_standalone(struct osmo_fsm_inst *fi,
					uint32_t event, void *data)
{
	struct lu_fsm_priv *lfp = fi->priv;
	struct vlr_subscr *vsub = lfp->vsub;
	uint8_t cause;

	switch (event) {
	case VLR_ULA_E_NEW_TMSI_ACK:
		osmo_fsm_inst_dispatch(lfp->lu_compl_vlr_fsm,
				       LU_COMPL_VLR_E_NEW_TMSI_ACK, NULL);
		break;
	case VLR_ULA_E_LU_COMPL_SUCCESS:
		lu_fsm_discard_lu_compl_fsm(fi);
		vsub->sub_dataconf_by_hlr_ind = false;
		lu_fsm_success(fi);
		break;
	case VLR_ULA_E_LU_COMPL_FAILURE:
		vsub->sub_dataconf_by_hlr_ind = false;
		cause = GSM48_REJECT_NETWORK_FAILURE;
		if (data)
			cause = *(uint8_t*)data;
		lu_fsm_discard_lu_compl_fsm(fi);
		lu_fsm_failure(fi, cause);
		break;
	default:
		LOGPFSML(fi, LOGL_ERROR, "event without effect: %s\n",
			 osmo_fsm_event_name(fi->fsm, event));
		break;
	}
}

static const struct osmo_fsm_state vlr_lu_fsm_states[] = {
	[VLR_ULA_S_IDLE] = {
		.in_event_mask = S(VLR_ULA_E_UPDATE_LA),
		.out_state_mask = S(VLR_ULA_S_WAIT_IMEISV) |
				  S(VLR_ULA_S_WAIT_PVLR) |
				  S(VLR_ULA_S_WAIT_IMSI) |
				  S(VLR_ULA_S_WAIT_AUTH) |
				  S(VLR_ULA_S_WAIT_HLR_UPD) |
				  S(VLR_ULA_S_DONE),
		.name = OSMO_STRINGIFY(VLR_ULA_S_IDLE),
		.action = lu_fsm_idle,
	},
	[VLR_ULA_S_WAIT_IMEISV] = {
		.in_event_mask = S(VLR_ULA_E_ID_IMEISV),
		.out_state_mask = S(VLR_ULA_S_WAIT_PVLR) |
				  S(VLR_ULA_S_WAIT_IMSI) |
				  S(VLR_ULA_S_DONE),
		.name = OSMO_STRINGIFY(VLR_ULA_S_WAIT_IMEISV),
		.action = lu_fsm_wait_imeisv,
	},
	[VLR_ULA_S_WAIT_PVLR] = {
		.in_event_mask = S(VLR_ULA_E_SEND_ID_ACK) |
				 S(VLR_ULA_E_SEND_ID_NACK),
		.out_state_mask = S(VLR_ULA_S_WAIT_IMSI) |
				  S(VLR_ULA_S_WAIT_AUTH) |
				  S(VLR_ULA_S_DONE),
		.name = OSMO_STRINGIFY(VLR_ULA_S_WAIT_PVLR),
		.action = lu_fsm_wait_pvlr,
	},
	[VLR_ULA_S_WAIT_AUTH] = {
		.in_event_mask = S(VLR_ULA_E_AUTH_RES),
		.out_state_mask = S(VLR_ULA_S_WAIT_CIPH) |
				  S(VLR_ULA_S_WAIT_LU_COMPL) |
				  S(VLR_ULA_S_WAIT_HLR_UPD) |
				  S(VLR_ULA_S_DONE),
		.name = OSMO_STRINGIFY(VLR_ULA_S_WAIT_AUTH),
		.action = lu_fsm_wait_auth,
	},
	[VLR_ULA_S_WAIT_CIPH] = {
		.name = OSMO_STRINGIFY(VLR_ULA_S_WAIT_CIPH),
		.in_event_mask = S(VLR_ULA_E_CIPH_RES),
		.out_state_mask = S(VLR_ULA_S_WAIT_LU_COMPL) |
				  S(VLR_ULA_S_WAIT_HLR_UPD) |
				  S(VLR_ULA_S_DONE),
		.action = lu_fsm_wait_ciph,
	},
	[VLR_ULA_S_WAIT_IMSI] = {
		.in_event_mask = S(VLR_ULA_E_ID_IMSI),
		.out_state_mask = S(VLR_ULA_S_WAIT_AUTH) |
				  S(VLR_ULA_S_WAIT_HLR_UPD) |
				  S(VLR_ULA_S_DONE),
		.name = OSMO_STRINGIFY(VLR_ULA_S_WAIT_IMSI),
		.action = lu_fsm_wait_imsi,
	},
	[VLR_ULA_S_WAIT_HLR_UPD] = {
		.in_event_mask = S(VLR_ULA_E_HLR_LU_RES) |
				 S(VLR_ULA_E_UPD_HLR_COMPL),
		.out_state_mask = S(VLR_ULA_S_WAIT_LU_COMPL) |
				  S(VLR_ULA_S_WAIT_LU_COMPL_STANDALONE) |
				  S(VLR_ULA_S_DONE),
		.name = OSMO_STRINGIFY(VLR_ULA_S_WAIT_HLR_UPD),
		.action = lu_fsm_wait_hlr_ul_res,
	},
	[VLR_ULA_S_WAIT_LU_COMPL] = {
		.in_event_mask = S(VLR_ULA_E_LU_COMPL_SUCCESS) |
				 S(VLR_ULA_E_LU_COMPL_FAILURE) |
				 S(VLR_ULA_E_NEW_TMSI_ACK) |
				 S(VLR_ULA_E_ID_IMEI) |
				 S(VLR_ULA_E_ID_IMEISV),
		.out_state_mask = S(VLR_ULA_S_DONE),
		.name = OSMO_STRINGIFY(VLR_ULA_S_WAIT_LU_COMPL),
		.action = lu_fsm_wait_lu_compl,
	},
	[VLR_ULA_S_WAIT_LU_COMPL_STANDALONE] = {
		.in_event_mask = S(VLR_ULA_E_LU_COMPL_SUCCESS) |
				 S(VLR_ULA_E_LU_COMPL_FAILURE) |
				 S(VLR_ULA_E_NEW_TMSI_ACK),
		.out_state_mask = S(VLR_ULA_S_DONE),
		.name = OSMO_STRINGIFY(VLR_ULA_S_WAIT_LU_COMPL_STANDALONE),
		.action = lu_fsm_wait_lu_compl_standalone,
	},
	[VLR_ULA_S_DONE] = {
		.name = OSMO_STRINGIFY(VLR_ULA_S_DONE),
		.onenter = lu_fsm_dispatch_result,
	},
};

static void fsm_lu_cleanup(struct osmo_fsm_inst *fi, enum osmo_fsm_term_cause cause)
{
	struct lu_fsm_priv *lfp = fi->priv;
	struct vlr_subscr *vsub = lfp->vsub;

	LOGPFSM(fi, "fsm_lu_cleanup called with cause %s\n",
		osmo_fsm_term_cause_name(cause));
	if (vsub && vsub->lu_fsm == fi)
		vsub->lu_fsm = NULL;
}

static struct osmo_fsm vlr_lu_fsm = {
	.name = "vlr_lu_fsm",
	.states = vlr_lu_fsm_states,
	.num_states = ARRAY_SIZE(vlr_lu_fsm_states),
	.allstate_event_mask = 0,
	.allstate_action = NULL,
	.log_subsys = DVLR,
	.event_names = fsm_lu_event_names,
	.cleanup = fsm_lu_cleanup,
};

struct osmo_fsm_inst *
vlr_loc_update(struct osmo_fsm_inst *parent,
	       uint32_t parent_event_success,
	       uint32_t parent_event_failure,
	       void *parent_event_data,
	       struct vlr_instance *vlr, void *msc_conn_ref,
	       enum vlr_lu_type type, uint32_t tmsi, const char *imsi,
	       const struct osmo_location_area_id *old_lai,
	       const struct osmo_location_area_id *new_lai,
	       bool authentication_required,
	       enum vlr_ciph ciphering_required,
	       bool is_r99, bool is_utran,
	       bool assign_tmsi)
{
	struct osmo_fsm_inst *fi;
	struct lu_fsm_priv *lfp;

	fi = osmo_fsm_inst_alloc_child(&vlr_lu_fsm, parent, parent_event_failure);
	if (!fi)
		return NULL;

	lfp = talloc_zero(fi, struct lu_fsm_priv);
	lfp->vlr = vlr;
	lfp->msc_conn_ref = msc_conn_ref;
	lfp->tmsi = tmsi;
	lfp->type = type;
	lfp->old_lai = *old_lai;
	lfp->new_lai = *new_lai;
	lfp->lu_by_tmsi = true;
	lfp->parent_event_success = parent_event_success;
	lfp->parent_event_failure = parent_event_failure;
	lfp->parent_event_data = parent_event_data;
	lfp->authentication_required = authentication_required;
	lfp->ciphering_required = ciphering_required;
	lfp->is_r99 = is_r99;
	lfp->is_utran = is_utran;
	lfp->assign_tmsi = assign_tmsi;
	if (imsi) {
		strncpy(lfp->imsi, imsi, sizeof(lfp->imsi)-1);
		lfp->imsi[sizeof(lfp->imsi)-1] = '\0';
		lfp->lu_by_tmsi = false;
	}
	fi->priv = lfp;

	LOGPFSM(fi, "rev=%s net=%s%s%s\n",
		is_r99 ? "R99" : "GSM",
		is_utran ? "UTRAN" : "GERAN",
		(authentication_required || ciphering_required)?
		" Auth" : " (no Auth)",
		(authentication_required || ciphering_required)?
			(ciphering_required? "+Ciph" : " (no Ciph)")
			: "");

	osmo_fsm_inst_dispatch(fi, VLR_ULA_E_UPDATE_LA, NULL);

	return fi;
}

/* Gracefully terminate an FSM created by vlr_loc_update() in case of external
 * timeout (i.e. from MSC). */
void vlr_loc_update_conn_timeout(struct osmo_fsm_inst *fi)
{
	if (!fi || fi->state == VLR_ULA_S_DONE)
		return;
	LOGPFSM(fi, "Connection timed out\n");
	lu_fsm_failure(fi, GSM48_REJECT_CONGESTION);
}

void vlr_lu_fsm_init(void)
{
	osmo_fsm_register(&vlr_lu_fsm);
	osmo_fsm_register(&upd_hlr_vlr_fsm);
	osmo_fsm_register(&sub_pres_vlr_fsm);
	osmo_fsm_register(&lu_compl_vlr_fsm);
}
