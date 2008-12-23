#ifndef _GSM_DATA_H
#define _GSM_DATA_H

#include <sys/types.h>

#define GSM_MAX_BTS	8
#define BTS_MAX_TRX	8

#define HARDCODED_ARFCN 123

/* communications link with a BTS */
struct gsm_bts_link {
	struct gsm_bts *bts;
};

#define BTS_TRX_F_ACTIVATED	0x0001
/* One Timeslot in a TRX */
struct gsm_bts_trx_ts {
	struct gsm_bts_trx *trx;
	/* number of this timeslot at the TRX */
	u_int8_t nr;

	unsigned int flags;
};

/* One TRX in a BTS */
struct gsm_bts_trx {
	struct gsm_bts *bts;
	/* number of this TRX in the BTS */
	u_int8_t nr;

	u_int16_t arfcn;
	struct gsm_bts_trx_ts ts[8];
};

/* One BTS */
struct gsm_bts {
	struct gsm_network *network;
	/* number of ths BTS in network */
	u_int8_t nr;
	/* location area code of this BTS */
	u_int8_t location_area_code;

	/* Abis network management O&M handle */
	struct abis_nm_h *nmh;
	/* number of this BTS on given E1 link */
	u_int8_t bts_nr;

	/* CCCH is on C0 */
	struct gsm_bts_trx *c0;
	/* transceivers */
	int num_trx;
	struct gsm_bts_trx trx[BTS_MAX_TRX+1];
};

struct gsm_ms {
	unsigned long imei;
};

struct gsm_network {
	/* global parameters */
	u_int8_t country_code;
	u_int8_t network_code;

	unsigned int num_bts;
	/* private lists */
	struct gsm_bts	bts[GSM_MAX_BTS+1];
	struct gsm_ms	*ms;
	struct gsm_subscriber *subscriber;
};

struct gsm_network *gsm_network_init(unsigned int num_bts, u_int8_t country_code,
				     u_int8_t network_code);
#endif
