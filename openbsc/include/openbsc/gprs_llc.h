#ifndef _GPRS_LLC_H
#define _GPRS_LLC_H

/* Section 4.7 LLC Layer Structure */
enum gprs_llc_sapi {
	GPRS_SAPI_GMM		= 1,
	GPRS_SAPI_TOM2		= 2,
	GPRS_SAPI_SNDCP3	= 3,
	GPRS_SAPI_SNDCP5	= 5,
	GPRS_SAPI_SMS		= 7,
	GPRS_SAPI_TOM8		= 8,
	GPRS_SAPI_SNDCP9	= 9,
	GPRS_SAPI_SNDCP11	= 11,
};


int gprs_llc_rcvmsg(struct msgb *msg, struct tlv_parsed *tv);
int gprs_llc_tx_ui(struct msgb *msg, u_int8_t sapi, int command);

#endif
