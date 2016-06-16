#pragma once

#include <osmocom/core/utils.h>

/* Parameters to VLR_AUTH_E_MS_AUTH_RESP */
struct vlr_auth_resp_par {
	bool is_r99;
	bool is_utran;
	const uint8_t *res;
	unsigned int res_len;
	const uint8_t *auts;
};

/* Result communicated back to parent FMS */
enum vlr_auth_fsm_result {
	VLR_AUTH_RES_ABORTED,
	VLR_AUTH_RES_UNKNOWN_SUBSCR,
	VLR_AUTH_RES_PROC_ERR,
	VLR_AUTH_RES_AUTH_FAILED,
	VLR_AUTH_RES_PASSED,
};

extern const struct value_string vlr_auth_fsm_result_names[];
static inline const char *vlr_auth_fsm_result_name(enum vlr_auth_fsm_result val)
{
	return get_value_string(vlr_auth_fsm_result_names, val);
}

enum vlr_fsm_auth_event {
	VLR_AUTH_E_START,
	/* TS 23.018 OAS_VLR1(2): SendAuthInfo ACK from HLR */
	VLR_AUTH_E_HLR_SAI_ACK,
	/* TS 23.018 OAS_VLR1(2): SendAuthInfo NACK from HLR */
	VLR_AUTH_E_HLR_SAI_NACK,
	/* FIXME: merge with NACK? */
	VLR_AUTH_E_HLR_SAI_ABORT,
	/* Authentication Response from MS */
	VLR_AUTH_E_MS_AUTH_RESP,
	/* Authentication Failure from MS */
	VLR_AUTH_E_MS_AUTH_FAIL,
	/* Identity Response (IMSI) from MS */
	VLR_AUTH_E_MS_ID_IMSI,
};

struct osmo_fsm vlr_auth_fsm;

struct osmo_fsm_inst *auth_fsm_start(struct vlr_subscr *vsub,
				     uint32_t log_level,
				     struct osmo_fsm_inst *parent,
				     uint32_t parent_term_event,
				     bool is_r99,
				     bool is_utran);
