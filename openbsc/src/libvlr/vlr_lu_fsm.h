#pragma once

#include <osmocom/core/fsm.h>

enum vlr_lu_state {
	VLR_ULA_S_IDLE,
	VLR_ULA_S_WAIT_IMEISV,
	VLR_ULA_S_WAIT_PVLR,	/* Waiting for ID from PVLR */
	VLR_ULA_S_WAIT_AUTH,	/* Waiting for Authentication */
	VLR_ULA_S_WAIT_CIPH,	/* Waiting for Ciphering Complete */
	VLR_ULA_S_WAIT_IMSI,	/* Waiting for IMSI from MS */
	VLR_ULA_S_WAIT_HLR_UPD,	/* Waiting for end of HLR update */
	VLR_ULA_S_WAIT_LU_COMPL,/* Waiting for LU complete */
	VLR_ULA_S_WAIT_LU_COMPL_STANDALONE, /* Standalone VLR */
	VLR_ULA_S_DONE
};

void vlr_lu_fsm_init(void);
