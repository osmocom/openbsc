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

#define S(x)	(1 << (x))

#define LU_TIMEOUT_LONG		30

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
	{ UPD_HLR_VLR_E_START, 			"START" },
	{ UPD_HLR_VLR_E_INS_SUB_DATA,		"INS-SUB-DATA" },
	{ UPD_HLR_VLR_E_ACT_TRACE_MODE,		"ACT-TRACE-MODE" },
	{ UPD_HLR_VLR_E_FW_CHECK_SS_IND,	"FW-CHECK-SS-IND" },
	{ UPD_HLR_VLR_E_UPD_LOC_ACK,		"UPD-LOC-ACK" },
	{ UPD_HLR_VLR_E_UPD_LOC_NACK,		"UPD-LOC-NACK" },
	{ 0, NULL }
};

static void upd_hlr_vlr_fsm_init(struct osmo_fsm_inst *fi, uint32_t event,
				 void *data)
{
	struct vlr_subscriber *vsub = fi->priv;

	OSMO_ASSERT(event == UPD_HLR_VLR_E_START);

	/* Send UpdateLocation to HLR */
	vlr_sub_req_lu(vsub, vsub->vlr->cfg.is_ps);
	osmo_fsm_inst_state_chg(fi, UPD_HLR_VLR_S_WAIT_FOR_DATA,
				LU_TIMEOUT_LONG, 0);
}

static void upd_hlr_vlr_fsm_wait_data(struct osmo_fsm_inst *fi, uint32_t event,
				      void *data)
{
	struct vlr_subscriber *vsub = fi->priv;

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
		.name = "INIT",
		.action = upd_hlr_vlr_fsm_init,
	},
	[UPD_HLR_VLR_S_WAIT_FOR_DATA] = {
		.in_event_mask = S(UPD_HLR_VLR_E_INS_SUB_DATA) |
				 S(UPD_HLR_VLR_E_ACT_TRACE_MODE) |
				 S(UPD_HLR_VLR_E_FW_CHECK_SS_IND) |
				 S(UPD_HLR_VLR_E_UPD_LOC_ACK) |
				 S(UPD_HLR_VLR_E_UPD_LOC_NACK),
		.out_state_mask = S(UPD_HLR_VLR_S_DONE),
		.name = "WAIT_FOR_DATA",
		.action = upd_hlr_vlr_fsm_wait_data,
	},
	[UPD_HLR_VLR_S_DONE] = {
		.name = "DONE",
	},
};

static struct osmo_fsm upd_hlr_vlr_fsm = {
	.name = "Update_HLR_VLR",
	.states = upd_hlr_vlr_states,
	.num_states = ARRAY_SIZE(upd_hlr_vlr_states),
	.allstate_event_mask = 0,
	.allstate_action = NULL,
	.log_subsys = DVLR,
	.event_names = upd_hlr_vlr_event_names,
};

struct osmo_fsm_inst *
upd_hlr_vlr_proc_start(struct osmo_fsm_inst *parent,
		        struct vlr_subscriber *vsub,
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
	{ SUB_PRES_VLR_E_START, "START" },
	{ SUB_PRES_VLR_E_READY_SM_CNF, "READY_FOR_SM-CNF" },
	{ SUB_PRES_VLR_E_READY_SM_ERR, "READY_FOR_SM-ERR" },
	{ 0, NULL }
};

static void sub_pres_vlr_fsm_init(struct osmo_fsm_inst *fi, uint32_t event,
				  void *data)
{
	struct vlr_subscriber *vsub = fi->priv;
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
	struct vlr_subscriber *vsub = fi->priv;

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
		.name = "INIT",
		.action = sub_pres_vlr_fsm_init,
	},
	[SUB_PRES_VLR_S_WAIT_FOR_HLR] = {
		.in_event_mask = S(SUB_PRES_VLR_E_READY_SM_CNF) |
				 S(SUB_PRES_VLR_E_READY_SM_ERR),
		.out_state_mask = S(SUB_PRES_VLR_S_DONE),
		.name = "WAIT_FOR_HLR",
		.action = sub_pres_vlr_fsm_wait_hlr,
	},
	[SUB_PRES_VLR_S_DONE] = {
		.name = "DONE",
	},
};

static struct osmo_fsm sub_pres_vlr_fsm = {
	.name = "Subscriber_Present_VLR",
	.states = sub_pres_vlr_states,
	.num_states = ARRAY_SIZE(sub_pres_vlr_states),
	.allstate_event_mask = 0,
	.allstate_action = NULL,
	.log_subsys = DVLR,
	.event_names = sub_pres_vlr_event_names,
};

struct osmo_fsm_inst *sub_pres_vlr_fsm_start(struct osmo_fsm_inst *parent,
					     struct vlr_subscriber *vsub,
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
	{ LU_COMPL_VLR_E_START, 	  "START" },
	{ LU_COMPL_VLR_E_SUB_PRES_COMPL,  "SUBSCR-PRES-COMPL" },
	{ LU_COMPL_VLR_E_IMEI_CHECK_ACK,  "IMEI-CHECK-ACK" },
	{ LU_COMPL_VLR_E_IMEI_CHECK_NACK, "IMEI-CHECK-NACK" },
	{ LU_COMPL_VLR_E_NEW_TMSI_ACK,	  "NEW-TMSI-ACK" },
	{ 0, NULL }
};

struct lu_compl_vlr_priv {
	struct vlr_subscriber *vsub;
	void *msc_conn_ref;
	struct osmo_fsm_inst *sub_pres_vlr_fsm;
};

static void lu_compl_vlr_init(struct osmo_fsm_inst *fi, uint32_t event,
			      void *data)
{
	struct lu_compl_vlr_priv *lcvp = fi->priv;
	struct vlr_subscriber *vsub = lcvp->vsub;
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

/* After completion of Subscriber_Present_VLR */
static void lu_compl_vlr_wait_subscr_pres(struct osmo_fsm_inst *fi,
					  uint32_t event,
					  void *data)
{
	struct lu_compl_vlr_priv *lcvp = fi->priv;
	struct vlr_subscriber *vsub = lcvp->vsub;
	struct vlr_instance *vlr = vsub->vlr;

	OSMO_ASSERT(event == LU_COMPL_VLR_E_SUB_PRES_COMPL);

	lcvp->sub_pres_vlr_fsm = NULL;

	/* TODO: Trace_Subscriber_Activity_VLR */

	/* Do we need to allocate a TMSI? */
	if (vlr->cfg.alloc_tmsi) {
		/* actually allocate a new TMSI */
		vlr_sub_alloc_tmsi(vsub);
		/* Set Ciphering Mode */
		vlr->ops.set_ciph_mode(lcvp->msc_conn_ref);
		if (vlr->cfg.check_imei_rqd) {
			/* Check IMEI VLR */
			osmo_fsm_inst_state_chg(fi, LU_COMPL_VLR_S_WAIT_IMEI_TMSI,
						vlr_timer(vlr, 3270), 3270);
			vlr->ops.tx_id_req(lcvp->msc_conn_ref, GSM_MI_TYPE_IMEI);
		} else {
			/* FIXME: New TMSI.ind to MSC (*/
			/* WAIT_FOR_TMSI_Cnf */
			osmo_fsm_inst_state_chg(fi, LU_COMPL_VLR_S_WAIT_TMSI_CNF,
						vlr_timer(vlr, 3250), 3250);
			/* Update Location Area Ack */
			vlr->ops.tx_lu_ack(lcvp->msc_conn_ref);
		}
	} else {
		if (vlr->cfg.check_imei_rqd) {
			/* Check IMEI VLR */
			osmo_fsm_inst_state_chg(fi, LU_COMPL_VLR_S_WAIT_IMEI,
						vlr_timer(vlr, 3270), 3270);
			vlr->ops.tx_id_req(lcvp->msc_conn_ref, GSM_MI_TYPE_IMEI);
		} else {
			/* Update Location Area Ack */
			vsub->vlr->ops.tx_lu_ack(lcvp->msc_conn_ref);
			osmo_fsm_inst_state_chg(fi, LU_COMPL_VLR_S_DONE, 0, 0);
			osmo_fsm_inst_term(fi, OSMO_FSM_TERM_REGULAR, NULL);
		}
	}
}

/* Waiting for completion of CHECK_IMEI_VLR */
static void lu_compl_vlr_wait_imei(struct osmo_fsm_inst *fi, uint32_t event,
				   void *data)
{
	struct lu_compl_vlr_priv *lcvp = fi->priv;
	struct vlr_subscriber *vsub = lcvp->vsub;
	struct vlr_instance *vlr = vsub->vlr;
	const char *imei = data;

	switch (event) {
	case LU_COMPL_VLR_E_IMEI_CHECK_ACK:
		if (imei) {
			/* Pass */
			if (fi->state == LU_COMPL_VLR_S_WAIT_IMEI_TMSI) {
				/* TMSI is to be allocated */
				vlr_sub_alloc_tmsi(vsub);
				vlr->ops.tx_lu_ack(lcvp->msc_conn_ref);
				osmo_fsm_inst_state_chg(fi, LU_COMPL_VLR_S_WAIT_TMSI_CNF,
							vlr_timer(vlr, 3250), 3250);
			} else {
				osmo_fsm_inst_state_chg(fi, LU_COMPL_VLR_S_DONE, 0, 0);
				osmo_fsm_inst_term(fi, OSMO_FSM_TERM_REGULAR, NULL);
			}
			return;
		} else {
			/* Abort: Do nothing */
		}
		break;
	case LU_COMPL_VLR_E_IMEI_CHECK_NACK:
		/* Fail */
		/* FIXME: IMEI Check Fail to VLR Application (Detach IMSI VLR) */
		/* LU REJECT ILLEGAL ME */
		vsub->vlr->ops.tx_lu_rej(vsub, GMM_CAUSE_ILLEGAL_ME);
		break;
	}
	osmo_fsm_inst_state_chg(fi, LU_COMPL_VLR_S_DONE, 0, 0);
	osmo_fsm_inst_term(fi, OSMO_FSM_TERM_REGULAR, NULL);
}

/* Waiting for TMSI confirmation */
static void lu_compl_vlr_wait_tmsi(struct osmo_fsm_inst *fi, uint32_t event,
				   void *data)
{
	OSMO_ASSERT(event == LU_COMPL_VLR_E_NEW_TMSI_ACK);
	osmo_fsm_inst_state_chg(fi, LU_COMPL_VLR_S_DONE, 0, 0);
	osmo_fsm_inst_term(fi, OSMO_FSM_TERM_REGULAR, NULL);
}

static const struct osmo_fsm_state lu_compl_vlr_states[] = {
	[LU_COMPL_VLR_S_INIT] = {
		.in_event_mask = S(LU_COMPL_VLR_E_START),
		.out_state_mask = S(LU_COMPL_VLR_S_DONE) |
				  S(LU_COMPL_VLR_S_WAIT_SUB_PRES) |
				  S(LU_COMPL_VLR_S_WAIT_IMEI),
		.name = "INIT",
		.action = lu_compl_vlr_init,
	},
	[LU_COMPL_VLR_S_WAIT_SUB_PRES] = {
		.in_event_mask = S(LU_COMPL_VLR_E_SUB_PRES_COMPL),
		.out_state_mask = S(LU_COMPL_VLR_S_WAIT_IMEI) |
				  S(LU_COMPL_VLR_S_WAIT_IMEI_TMSI) |
				  S(LU_COMPL_VLR_S_WAIT_TMSI_CNF) |
				  S(LU_COMPL_VLR_S_DONE),
		.name = "WAIT-SUBSCR-PRES-COMPL",
		.action = lu_compl_vlr_wait_subscr_pres,
	},
	[LU_COMPL_VLR_S_WAIT_IMEI] = {
		.in_event_mask = S(LU_COMPL_VLR_E_IMEI_CHECK_ACK) |
				 S(LU_COMPL_VLR_E_IMEI_CHECK_NACK),
		.out_state_mask = S(LU_COMPL_VLR_S_DONE),
		.name = "WAIT-CHECK-IMEI",
		.action = lu_compl_vlr_wait_imei,
	},
	[LU_COMPL_VLR_S_WAIT_IMEI_TMSI] = {
		.in_event_mask = S(LU_COMPL_VLR_E_IMEI_CHECK_ACK) |
				 S(LU_COMPL_VLR_E_IMEI_CHECK_NACK),
		.out_state_mask = S(LU_COMPL_VLR_S_DONE) |
				  S(LU_COMPL_VLR_S_WAIT_TMSI_CNF),
		.name = "WAIT-CHECK-IMEI(TMSI)",
		.action = lu_compl_vlr_wait_imei,
	},
	[LU_COMPL_VLR_S_WAIT_TMSI_CNF] = {
		.in_event_mask = S(LU_COMPL_VLR_E_NEW_TMSI_ACK),
		.out_state_mask = S(LU_COMPL_VLR_S_DONE),
		.name = "WAIT-TMSI-CONF",
		.action = lu_compl_vlr_wait_tmsi,
	},
	[LU_COMPL_VLR_S_DONE] = {
		.name = "DONE",
	},
};

static struct osmo_fsm lu_compl_vlr_fsm = {
	.name = "Location_Update_Completion_VLR",
	.states = lu_compl_vlr_states,
	.num_states = ARRAY_SIZE(lu_compl_vlr_states),
	.allstate_event_mask = 0,
	.allstate_action = NULL,
	.log_subsys = DVLR,
	.event_names = lu_compl_vlr_event_names,
};

struct osmo_fsm_inst *
lu_compl_vlr_proc_start(struct osmo_fsm_inst *parent,
			struct vlr_subscriber *vsub,
			void *msc_conn_ref,
			uint32_t term_event)
{
	struct osmo_fsm_inst *fi;
	struct lu_compl_vlr_priv *lcvp;

	fi = osmo_fsm_inst_alloc_child(&lu_compl_vlr_fsm, parent,
					term_event);
	if (!fi)
		return NULL;

	lcvp = talloc_zero(fi, struct lu_compl_vlr_priv);
	lcvp->vsub = vsub;
	lcvp->msc_conn_ref = msc_conn_ref;
	fi->priv = lcvp;

	osmo_fsm_inst_dispatch(fi, LU_COMPL_VLR_E_START, NULL);

	return fi;
}


/***********************************************************************
 * Update_Location_Area_VLR, TS 23.012 Chapter 4.1.2.1
 ***********************************************************************/

enum vlr_lu_state {
	VLR_ULA_S_IDLE,
	VLR_ULA_S_WAIT_IMEISV,
	VLR_ULA_S_WAIT_PVLR,	/* Waiting for ID from PVLR */
	VLR_ULA_S_WAIT_AUTH,	/* Waiting for Authentication */
	VLR_ULA_S_WAIT_IMSI,	/* Waiting for IMSI from MS */
	VLR_ULA_S_WAIT_HLR_UPD,	/* Waiting for end of HLR update */
	VLR_ULA_S_WAIT_LU_COMPL,/* Waiting for LU complete */
	VLR_ULA_S_WAIT_LU_COMPL_STANDALONE, /* Standalone VLR */
	VLR_ULA_S_DONE
};

static const struct value_string fsm_lu_event_names[] = {
	{ VLR_ULA_E_UPDATE_LA,		"UPDATE-LOCATION" },
	{ VLR_ULA_E_SEND_ID_ACK,	"PVLR-SEND-ID-ACK" },
	{ VLR_ULA_E_SEND_ID_NACK,	"PVLR-SEND-ID-NACK" },
	{ VLR_ULA_E_AUTH_RES,		"AUTH-RES" },
	{ VLR_ULA_E_ID_IMSI,		"MS-ID-IMSI" },
	{ VLR_ULA_E_ID_IMEI,		"MS-ID-IMEI" },
	{ VLR_ULA_E_ID_IMEISV,		"MS-ID-IMEISV" },
	{ VLR_ULA_E_HLR_LU_RES,		"HLR-LU-RES" },
	{ VLR_ULA_E_UPD_HLR_COMPL,	"UPD-HLR-VLR-COMPL-RES" },
	{ VLR_ULA_E_LU_COMPL_TERM,	"LU-COMPL-VLR-RES" },
	{ VLR_ULA_E_NEW_TMSI_ACK,	"NEW-TMSI-ACK" },
	{ 0, NULL }
};

struct lu_fsm_priv {
	struct vlr_instance *vlr;
	struct vlr_subscriber *vsub;
	void *msc_conn_ref;
	struct osmo_fsm_inst *upd_hlr_vlr_fsm;
	struct osmo_fsm_inst *lu_compl_vlr_fsm;

	enum vlr_lu_type type;
	bool lu_by_tmsi;
	char imsi[16];
	uint32_t tmsi;
	struct osmo_location_area_id old_lai;
	struct osmo_location_area_id new_lai;
};


/* Determine if given location area is served by this VLR */
static bool lai_in_this_vlr(struct vlr_instance *vlr,
			    const struct osmo_location_area_id *lai)
{
	/* TODO: VLR needs to keep a locally configued list of LAIs */
	return true;
}

/* Determine if authentication is required */
static bool is_auth_required(struct vlr_subscriber *vsub)
{
	/* The cases where the authentication procedure should be used
	 * are defined in 3GPP TS 33.102 */
	/* We always require authentication, for now */
	return true;
}

/* Determine if a HLR Update is required */
static bool hlr_update_needed(struct vlr_subscriber *vsub)
{
	/* TODO: properly decide this, rather than always assuming we
	 * need to update the HLR. */
	return true;
}

/* Terminate a Location Update FSM Instance */
static void lu_fsm_term(struct osmo_fsm_inst *fi)
{
	/* if the MSC is registered as parent, it will get notified via
	 * the usual signalling */
	osmo_fsm_inst_term(fi, OSMO_FSM_TERM_REGULAR, NULL);
}

/* 4.1.2.1 Node 4 */
static void vlr_loc_upd_node_4(struct osmo_fsm_inst *fi)
{
	struct lu_fsm_priv *lfp = fi->priv;
	struct vlr_subscriber *vsub = lfp->vsub;
	struct vlr_instance *vlr = lfp->vlr;
	bool hlr_unknown = false;

	if (hlr_unknown) {
		/* FIXME: Delete subscriber record */
		/* LU REJ: Roaming not allowed */
		vlr->ops.tx_lu_rej(lfp->msc_conn_ref, GSM48_REJECT_ROAMING_NOT_ALLOWED);
		osmo_fsm_inst_state_chg(fi, VLR_ULA_S_DONE, 0, 0);
		lu_fsm_term(fi);
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
	struct lu_fsm_priv *lfp = fi->priv;
	if (0) { /* IMEISV or PgA to send */
		vlr_loc_upd_node_4(fi);
	} else {
		/* Location_Update_Completion */
		osmo_fsm_inst_state_chg(fi, VLR_ULA_S_WAIT_LU_COMPL,
					LU_TIMEOUT_LONG, 0);
		lfp->lu_compl_vlr_fsm =
			lu_compl_vlr_proc_start(fi, lfp->vsub,
					lfp->msc_conn_ref,
					VLR_ULA_E_LU_COMPL_TERM);
	}
}

/* 4.1.2.1 after Authentication successful (or no auth rqd) */
static void vlr_loc_upd_post_auth(struct osmo_fsm_inst *fi)
{
	struct lu_fsm_priv *lfp = fi->priv;
	struct vlr_subscriber *vsub = lfp->vsub;
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

static void vlr_loc_upd_node1(struct osmo_fsm_inst *fi)
{
	struct lu_fsm_priv *lfp = fi->priv;
	struct vlr_subscriber *vsub = lfp->vsub;

	OSMO_ASSERT(vsub);

	if (is_auth_required(lfp->vsub)) {
		/* Authenticate_VLR */
		osmo_fsm_inst_state_chg(fi, VLR_ULA_S_WAIT_AUTH,
					LU_TIMEOUT_LONG, 0);
		vsub->auth_fsm = auth_fsm_start(lfp->vsub, fi->log_level,
						fi, VLR_ULA_E_AUTH_RES);
	} else {
		/* no need for authentication */
		vlr_loc_upd_post_auth(fi);
	}
}

static void vlr_loc_upd_node2(struct osmo_fsm_inst *fi)
{
	struct lu_fsm_priv *lfp = fi->priv;
	struct vlr_instance *vlr = lfp->vlr;

	OSMO_ASSERT(lfp->vsub);

	/* Obtain_IMSI_VLR */
	osmo_fsm_inst_state_chg(fi, VLR_ULA_S_WAIT_IMSI,
				vlr_timer(vlr, 3270), 3270);
	vlr->ops.tx_id_req(lfp->msc_conn_ref, GSM_MI_TYPE_IMSI);
	/* will continue at vlr_loc_upd_node1() once IMSI arrives */
}

static void assoc_lfp_with_sub(struct osmo_fsm_inst *fi, struct vlr_subscriber *vsub)
{
	struct lu_fsm_priv *lfp = fi->priv;
	struct vlr_instance *vlr = lfp->vlr;

	OSMO_ASSERT(vsub->lu_fsm == NULL);
	vsub->lu_fsm = fi;
	vsub->msc_conn_ref = lfp->msc_conn_ref;
	lfp->vsub = vsub;
	/* Tell MSC to associate this subscriber with the given
	 * connection */
	vlr->ops.subscr_assoc(lfp->msc_conn_ref, lfp->vsub);
}

/* 4.1.2.1: Subscriber (via MSC/SGSN) requests location update */
static void _start_lu_main(struct osmo_fsm_inst *fi)
{
	struct lu_fsm_priv *lfp = fi->priv;
	struct vlr_instance *vlr = lfp->vlr;
	struct vlr_subscriber *vsub = NULL;

	/* TODO: PUESBINE related handling */
	if (!lfp->imsi[0]) {
		/* TMSI was used */
		lfp->lu_by_tmsi = true;
		/* Is previous LAI in this VLR? */
		if (!lai_in_this_vlr(vlr, &lfp->old_lai)) {
			vsub = vlr_sub_alloc(vlr);
			OSMO_ASSERT(vsub);
			vsub->tmsi = lfp->tmsi;	/* FIXME: what if clash? */
			vsub->sub_dataconf_by_hlr_ind = false;
			assoc_lfp_with_sub(fi, vsub);
#if 0
			/* FIXME: check previous VLR, (3) */
			osmo_fsm_inst_state_chg(fi, VLR_ULA_S_WAIT_PVLR,
						LU_TIMEOUT_LONG, 0);
#endif
			vlr_loc_upd_node2(fi);
		} else {
			/* Is TMSI known */
			vsub = vlr_subscr_find_by_tmsi(vlr, lfp->tmsi);
			if (!vsub) {
				vsub = vlr_sub_alloc(vlr);
				OSMO_ASSERT(vsub);
				vsub->sub_dataconf_by_hlr_ind = false;
				vsub->tmsi = lfp->tmsi;	/* FIXME: what if clash? */
				assoc_lfp_with_sub(fi, vsub);
				vlr_loc_upd_node2(fi);
			} else {
				assoc_lfp_with_sub(fi, vsub);
				/* We cannot have MSC area change, as the VLR
				 * serves only one MSC */
				vlr_loc_upd_node1(fi);
			}
		}
	} else {
		/* IMSI was used */
		/* Is subscriber known in VLR? */
		vsub = vlr_subscr_find_by_imsi(vlr, lfp->imsi);
		if (!vsub) {
			vsub = vlr_sub_alloc(vlr);
			OSMO_ASSERT(vsub);
			strncpy(vsub->imsi, lfp->imsi, sizeof(vsub->imsi));
			vsub->imsi[sizeof(vsub->imsi)-1] = '\0';
		}
		vsub->sub_dataconf_by_hlr_ind = false;
		assoc_lfp_with_sub(fi, vsub);
		vlr_loc_upd_node1(fi);
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
		vlr_loc_upd_node2(fi);
		break;
	}
}

/* Wait for result of Authenticate_VLR procedure */
static void lu_fsm_wait_auth(struct osmo_fsm_inst *fi, uint32_t event,
			     void *data)
{
	struct lu_fsm_priv *lfp = fi->priv;
	struct vlr_instance *vlr = lfp->vlr;
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
			break;
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
		}
	} else
		rej_cause = GSM48_REJECT_NETWORK_FAILURE;

	if (rej_cause)
		vlr->ops.tx_lu_rej(lfp->msc_conn_ref, rej_cause);
	osmo_fsm_inst_state_chg(fi, VLR_ULA_S_DONE, 0, 0);
	lu_fsm_term(fi);
}

static void lu_fsm_wait_imsi(struct osmo_fsm_inst *fi, uint32_t event,
			     void *data)
{
	struct lu_fsm_priv *lfp = fi->priv;
	struct vlr_subscriber *vsub = lfp->vsub;
	char *mi_string = data;

	switch (event) {
	case VLR_ULA_E_ID_IMSI:
		strncpy(vsub->imsi, mi_string, sizeof(vsub->imsi));
		vsub->imsi[sizeof(vsub->imsi)-1] = '\0';
		vlr_loc_upd_node1(fi);
		break;
	}
}

/* At the end of Update_HLR_VLR */
static void lu_fsm_wait_hlr_ul_res(struct osmo_fsm_inst *fi, uint32_t event,
				   void *data)
{
	struct lu_fsm_priv *lfp = fi->priv;
	struct vlr_subscriber *vsub = lfp->vsub;
	struct vlr_instance *vlr = lfp->vlr;

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
			lfp->lu_compl_vlr_fsm =
				lu_compl_vlr_proc_start(fi, vsub, lfp->msc_conn_ref,
						VLR_ULA_E_LU_COMPL_TERM);
			/* continue in MSC ?!? */
		} else {
			/* unsuccessful case */
			enum gsm48_gmm_cause cause =
				*(enum gsm48_gmm_cause *)data;
			if (0 /* procedure_error && vlr->cfg.standalone_mode */) {
				osmo_fsm_inst_state_chg(fi,
						VLR_ULA_S_WAIT_LU_COMPL_STANDALONE,
						LU_TIMEOUT_LONG, 0);
				lfp->lu_compl_vlr_fsm =
					lu_compl_vlr_proc_start(fi, vsub,
							lfp->msc_conn_ref,
							VLR_ULA_E_LU_COMPL_TERM);
			} else {
				vlr->ops.tx_lu_rej(vsub, cause);
				osmo_fsm_inst_state_chg(fi, VLR_ULA_S_DONE, 0, 0);
				lu_fsm_term(fi);
				/* continue in MSC ?!? */
			}
		}
		break;
	}
}

/* Wait for end of Location_Update_Completion_VLR */
static void lu_fsm_wait_lu_compl(struct osmo_fsm_inst *fi, uint32_t event,
				   void *data)
{
	struct lu_fsm_priv *lfp = fi->priv;

	switch (event) {
	case VLR_ULA_E_NEW_TMSI_ACK:
		osmo_fsm_inst_dispatch(lfp->lu_compl_vlr_fsm,
					LU_COMPL_VLR_E_NEW_TMSI_ACK, NULL);
		break;
	case VLR_ULA_E_LU_COMPL_TERM:
		lfp->lu_compl_vlr_fsm = NULL;

		if (1 /* pass */) {
			/* Update Register */
			/* TODO: Set_Notification_Type 23.078 */
			/* TODO: Notify_gsmSCF 23.078 */
			/* TODO: Authenticated Radio Contact Established -> ARC */
		}
		osmo_fsm_inst_state_chg(fi, VLR_ULA_S_DONE, 0, 0);
		lu_fsm_term(fi);
		break;
	}
}

/* Wait for end of Location_Update_Completion_VLR (standalone case) */
static void lu_fsm_wait_lu_compl_standalone(struct osmo_fsm_inst *fi,
					uint32_t event, void *data)
{
	struct lu_fsm_priv *lfp = fi->priv;
	struct vlr_subscriber *vsub = lfp->vsub;

	switch (event) {
	case VLR_ULA_E_NEW_TMSI_ACK:
		osmo_fsm_inst_dispatch(lfp->lu_compl_vlr_fsm,
					LU_COMPL_VLR_E_NEW_TMSI_ACK, NULL);
		break;
	case VLR_ULA_E_LU_COMPL_TERM:
		vsub->sub_dataconf_by_hlr_ind = false;
		osmo_fsm_inst_state_chg(fi, VLR_ULA_S_DONE, 0, 0);
		lu_fsm_term(fi);
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
				  S(VLR_ULA_S_DONE),
		.name = "IDLE",
		.action = lu_fsm_idle,
	},
	[VLR_ULA_S_WAIT_IMEISV] = {
		.in_event_mask = S(VLR_ULA_E_ID_IMEISV),
		.out_state_mask = S(VLR_ULA_S_WAIT_PVLR) |
				  S(VLR_ULA_S_WAIT_IMSI) |
				  S(VLR_ULA_S_DONE),
		.name = "WAIT-ID-IMEISV",
		.action = lu_fsm_wait_imeisv,
	},
	[VLR_ULA_S_WAIT_PVLR] = {
		.in_event_mask = S(VLR_ULA_E_SEND_ID_ACK) |
				 S(VLR_ULA_E_SEND_ID_NACK),
		.out_state_mask = S(VLR_ULA_S_WAIT_IMSI) |
				  S(VLR_ULA_S_WAIT_AUTH) |
				  S(VLR_ULA_S_DONE),
		.name = "WAIT-PVLR-RESP",
		.action = lu_fsm_wait_pvlr,
	},
	[VLR_ULA_S_WAIT_AUTH] = {
		.in_event_mask = S(VLR_ULA_E_AUTH_RES),
		.out_state_mask = S(VLR_ULA_S_WAIT_LU_COMPL) |
				  S(VLR_ULA_S_WAIT_HLR_UPD) |
				  S(VLR_ULA_S_DONE),
		.name = "WAIT-AUTH-COMPL",
		.action = lu_fsm_wait_auth,
	},
	[VLR_ULA_S_WAIT_IMSI] = {
		.in_event_mask = S(VLR_ULA_E_ID_IMSI),
		.out_state_mask = S(VLR_ULA_S_WAIT_AUTH) |
				  S(VLR_ULA_S_WAIT_HLR_UPD) |
				  S(VLR_ULA_S_DONE),
		.name = "WAIT-ID-IMSI",
		.action = lu_fsm_wait_imsi,
	},
	[VLR_ULA_S_WAIT_HLR_UPD] = {
		.in_event_mask = S(VLR_ULA_E_HLR_LU_RES) |
				 S(VLR_ULA_E_UPD_HLR_COMPL),
		.out_state_mask = S(VLR_ULA_S_WAIT_LU_COMPL) |
				  S(VLR_ULA_S_WAIT_LU_COMPL_STANDALONE) |
				  S(VLR_ULA_S_DONE),
		.name = "WAIT-HLR-LU-COMPL",
		.action = lu_fsm_wait_hlr_ul_res,
	},
	[VLR_ULA_S_WAIT_LU_COMPL] = {
		.in_event_mask = S(VLR_ULA_E_LU_COMPL_TERM) |
				 S(VLR_ULA_E_NEW_TMSI_ACK),
		.out_state_mask = S(VLR_ULA_S_DONE),
		.name = "WAIT-LU-COMPL",
		.action = lu_fsm_wait_lu_compl,
	},
	[VLR_ULA_S_WAIT_LU_COMPL_STANDALONE] = {
		.in_event_mask = S(VLR_ULA_E_LU_COMPL_TERM) |
				 S(VLR_ULA_E_NEW_TMSI_ACK),
		.out_state_mask = S(VLR_ULA_S_DONE),
		.name = "WAIT-LU-COMPL(STANDALONE)",
		.action = lu_fsm_wait_lu_compl_standalone,
	},
	[VLR_ULA_S_DONE] = {
		.name = "DONE",
	},
};

static struct osmo_fsm vlr_lu_fsm = {
	.name = "Update_Location_Area_VLR",
	.states = vlr_lu_fsm_states,
	.num_states = ARRAY_SIZE(vlr_lu_fsm_states),
	.allstate_event_mask = 0,
	.allstate_action = NULL,
	.log_subsys = DVLR,
	.event_names = fsm_lu_event_names,
};

struct osmo_fsm_inst *
vlr_loc_update(struct osmo_fsm_inst *parent, uint32_t parent_term,
		struct vlr_instance *vlr, void *msc_conn_ref,
		enum vlr_lu_type type, uint32_t tmsi, const char *imsi,
		const struct osmo_location_area_id *old_lai,
		const struct osmo_location_area_id *new_lai)
{
	struct osmo_fsm_inst *fi;
	struct lu_fsm_priv *lfp;

	fi = osmo_fsm_inst_alloc_child(&vlr_lu_fsm, parent, parent_term);
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
	if (imsi) {
		strncpy(lfp->imsi, imsi, sizeof(lfp->imsi)-1);
		lfp->imsi[sizeof(lfp->imsi)-1] = '\0';
		lfp->lu_by_tmsi = false;
	}
	fi->priv = lfp;

	osmo_fsm_inst_dispatch(fi, VLR_ULA_E_UPDATE_LA, NULL);

	return fi;
}

void vlr_lu_fsm_init(void)
{
	osmo_fsm_register(&vlr_lu_fsm);
	osmo_fsm_register(&upd_hlr_vlr_fsm);
	osmo_fsm_register(&sub_pres_vlr_fsm);
	osmo_fsm_register(&lu_compl_vlr_fsm);
}
