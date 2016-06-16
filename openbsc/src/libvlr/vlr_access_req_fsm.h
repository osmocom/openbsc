#pragma once

enum proc_arq_vlr_state {
	PR_ARQ_S_INIT,
	/* Waiting for Obtain_Identity_VLR (IMSI) result */
	PR_ARQ_S_WAIT_OBTAIN_IMSI,
	/* Waiting for Authenticate_VLR result */
	PR_ARQ_S_WAIT_AUTH,
	PR_ARQ_S_WAIT_CIPH,
	PR_ARQ_S_WAIT_UPD_LOC_CHILD,
	PR_ARQ_S_WAIT_SUB_PRES,
	PR_ARQ_S_WAIT_TRACE_SUB,
	PR_ARQ_S_WAIT_CHECK_IMEI,
	PR_ARQ_S_WAIT_TMSI_ACK,
	PR_ARQ_S_WAIT_CECK_CONF,
	PR_ARQ_S_DONE,
};
