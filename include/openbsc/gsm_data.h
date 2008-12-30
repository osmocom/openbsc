#ifndef _GSM_DATA_H
#define _GSM_DATA_H

#include <sys/types.h>

#include <openbsc/timer.h>

#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))

#define GSM_MAX_BTS	8
#define BTS_MAX_TRX	8
#define TS_MAX_LCHAN	8

#define HARDCODED_ARFCN 123

/*
 * Use the channel. As side effect the lchannel recycle timer
 * will be started.
 */
#define LCHAN_RELEASE_TIMEOUT 4, 0
#define use_lchan(lchan) \
	do {	lchan->use_count++; \
		schedule_timer(&lchan->release_timer, LCHAN_RELEASE_TIMEOUT); } while(0);

#define put_lchan(lchan) \
	do { lchan->use_count--; } while(0);

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


/* Channel Request reason */
enum gsm_chreq_reason_t {
	GSM_CHREQ_REASON_EMERG,
	GSM_CHREQ_REASON_PAG,
	GSM_CHREQ_REASON_CALL,
	GSM_CHREQ_REASON_LOCATION_UPD,
	GSM_CHREQ_REASON_OTHER,
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

	/* Timer started to release the channel */
	struct timer_list release_timer;
	struct timer_list updating_timer;

	/* local end of a call, if any */
	struct gsm_call call;

	/* temporary user data, to be removed... and merged into gsm_call */
	void *user_data;

	/* use count. how many users use this channel */
	unsigned int use_count;
	unsigned int pending_update_request : 1;
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
	u_int16_t country_code;
	u_int16_t network_code;
	char *name_long;
	char *name_short;

	unsigned int num_bts;
	/* private lists */
	struct gsm_bts	bts[GSM_MAX_BTS+1];
	struct gsm_ms	*ms;
	struct gsm_subscriber *subscriber;

	/* management of the lower layers to allow the bsc to hook into it */
	void (*update_request)(struct gsm_bts *, u_int32_t tmsi, int accepted);
	void (*channel_allocated)(struct gsm_lchan *bts, enum gsm_chreq_reason_t);
	void (*channel_deallocated)(struct gsm_lchan *bts);
	void (*channel_response)(struct gsm_lchan *, int acked);
	void (*channel_subscriber_assigned)(struct gsm_lchan *);
	void (*call_state_changed)(struct gsm_lchan *, enum gsm_call_state new_state);
};

struct gsm_network *gsm_network_init(unsigned int num_bts, u_int16_t country_code,
				     u_int16_t network_code);

enum gsm_e1_event {
	EVT_E1_NONE,
	EVT_E1_OML_UP,
	EVT_E1_RSL_UP,
	EVT_E1_OML_DN,
	EVT_E1_RSL_DN,
};

#endif
