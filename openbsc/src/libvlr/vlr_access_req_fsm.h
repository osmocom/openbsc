#pragma once

enum vlr_proc_arq_result {
	VLR_PR_ARQ_RES_SYSTEM_FAILURE,
	VLR_PR_ARQ_RES_ILLEGAL_SUBSCR,
	VLR_PR_ARQ_RES_UNIDENT_SUBSCR,
	VLR_PR_ARQ_RES_ROAMING_NOTALLOWED,
	VLR_PR_ARQ_RES_ILLEGAL_EQUIP,
	VLR_PR_ARQ_RES_UNKNOWN_ERROR,
	VLR_PR_ARQ_RES_PASSED,
};

enum proc_arq_vlr_event {
	PR_ARQ_E_START,
	PR_ARQ_E_ID_IMSI,
	PR_ARQ_E_AUTH_RES,
	PR_ARQ_E_UPD_LOC_RES,
	PR_ARQ_E_TRACE_RES,
	PR_ARQ_E_IMEI_RES,
	PR_ARQ_E_PRES_RES,
	PR_ARQ_E_TMSI_ACK,
};

enum vlr_parq_type {
	VLR_PR_ARQ_T_CM_SERV_REQ,
	VLR_PR_ARQ_T_PAGING_RESP,
	/* FIXME: differentiate between services of 24.008 10.5.3.3 */
};


struct osmo_fsm_inst *
vlr_proc_acc_req(struct vlr_instance *vlr, void *msc_conn_ref,
		   enum vlr_parq_type type, uint32_t tmsi, const char *imsi,
		   const struct osmo_location_area_id *lai);

void vlr_parq_fsm_init(void);
