#ifndef _GSM_DATA_H
#define _GSM_DATA_H

#include <sys/types.h>

#include <openbsc/timer.h>

#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))

#define GSM_MAX_BTS	8
#define BTS_MAX_TRX	8
#define TS_MAX_LCHAN	8

#define HARDCODED_ARFCN 123

/* communications link with a BTS */
struct gsm_bts_link {
	struct gsm_bts *bts;
};

enum gsm_call_type {
	GSM_CT_NONE,
	GSM_CT_MO,
	GSM_CT_MT,
};

enum gsm_call_state {
	GSM_CSTATE_NULL,
	GSM_CSTATE_INITIATED,
	GSM_CSTATE_ACTIVE,
	GSM_CSTATE_RELEASE_REQ,
};

/* One end of a call */
struct gsm_call {
	enum gsm_call_type type;
	enum gsm_call_state state;
	u_int8_t transaction_id;	/* 10.3.2 */

	/* the 'local' subscriber */
	struct gsm_subscriber *subscr;
};


enum gsm_phys_chan_config {
	GSM_PCHAN_NONE,
	GSM_PCHAN_CCCH,
	GSM_PCHAN_CCCH_SDCCH4,
	GSM_PCHAN_TCH_F,
	GSM_PCHAN_TCH_H,
	GSM_PCHAN_SDCCH8_SACCH8C,
	GSM_PCHAN_UNKNOWN,
};

enum gsm_chan_t {
	GSM_LCHAN_NONE,
	GSM_LCHAN_SDCCH,
	GSM_LCHAN_TCH_F,
	GSM_LCHAN_TCH_H,
	GSM_LCHAN_UNKNOWN,
};

struct gsm_lchan {
	/* The TS that we're part of */
	struct gsm_bts_trx_ts *ts;
	/* The logical subslot number in the TS */
	u_int8_t nr;
	/* The lotical channel type */
	enum gsm_chan_t type;
	/* To whom we are allocated at the moment */
	struct gsm_subscriber *subscr;
	/* Universal timer, undefined use ;) */
	struct timer_list timer;

	/* local end of a call, if any */
	struct gsm_call call;
};

#define BTS_TRX_F_ACTIVATED	0x0001
/* One Timeslot in a TRX */
struct gsm_bts_trx_ts {
	struct gsm_bts_trx *trx;
	/* number of this timeslot at the TRX */
	u_int8_t nr;

	enum gsm_phys_chan_config pchan;

	unsigned int flags;

	struct gsm_lchan lchan[TS_MAX_LCHAN];
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

enum gsm_e1_event {
	EVT_E1_NONE,
	EVT_E1_OML_UP,
	EVT_E1_RSL_UP,
	EVT_E1_OML_DN,
	EVT_E1_RSL_DN,
};

#endif
