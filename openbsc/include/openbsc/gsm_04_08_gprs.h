#pragma once

#include <osmocom/gsm/protocol/gsm_04_08_gprs.h>

/* TODO: Move this to osmocom/gsm/protocol/gsm_04_08_gprs.h ? */

/* Table 10.4 in 3GPP TS 24.008 (successor to 04.08) */
#define GSM48_MT_GMM_SERVICE_REQ	0x0c
#define GSM48_MT_GMM_SERVICE_ACK	0x0d
#define GSM48_MT_GMM_SERVICE_REJ	0x0e

/* 3GPP 24.008 / Chapter 10.5.5.20 / Table 10.5.153a */
enum gsm48_gmm_service_type {
	GPRS_SERVICE_T_SIGNALLING	= 0x00,
	GPRS_SERVICE_T_DATA		= 0x01,
	GPRS_SERVICE_T_PAGING_RESP	= 0x02,
	GPRS_SERVICE_T_MBMS_MC_SERV	= 0x03,
	GPRS_SERVICE_T_MBMS_BC_SERV	= 0x04,
};

extern const struct value_string *gprs_service_t_strs;
