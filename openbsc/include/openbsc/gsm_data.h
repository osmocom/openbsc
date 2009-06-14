#ifndef _GSM_DATA_H
#define _GSM_DATA_H

#include <sys/types.h>

#include <openbsc/timer.h>
#include <openbsc/gsm_04_08.h>

#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))

#define GSM_MAX_BTS	8
#define BTS_MAX_TRX	8
#define TRX_NR_TS	8
#define TS_MAX_LCHAN	8

#define HARDCODED_ARFCN 123
#define HARDCODED_TSC	7
#define HARDCODED_BSIC	0x3f	/* NCC = 7 / BCC = 7 */

enum gsm_hooks {
	GSM_HOOK_NM_SWLOAD,
	GSM_HOOK_RR_PAGING,
};

enum gsm_paging_event {
	GSM_PAGING_SUCCEEDED,
	GSM_PAGING_EXPIRED,
	GSM_PAGING_OOM,
};

struct msgb;
typedef int gsm_cbfn(unsigned int hooknum,
		     unsigned int event,
		     struct msgb *msg,
		     void *data, void *param);

/*
 * Use the channel. As side effect the lchannel recycle timer
 * will be started.
 */
#define LCHAN_RELEASE_TIMEOUT 4, 0
#define use_lchan(lchan) \
	do {	lchan->use_count++; \
		DEBUGP(DCC, "lchan (bts=%d,trx=%d,ts=%d,ch=%d) increases usage to: %d\n", \
			lchan->ts->trx->bts->nr, lchan->ts->trx->nr, lchan->ts->nr, \
			lchan->nr, lchan->use_count); \
		bsc_schedule_timer(&lchan->release_timer, LCHAN_RELEASE_TIMEOUT); } while(0);

#define put_lchan(lchan) \
	do { lchan->use_count--; \
		DEBUGP(DCC, "lchan (bts=%d,trx=%d,ts=%d,ch=%d) decreases usage to: %d\n", \
			lchan->ts->trx->bts->nr, lchan->ts->trx->nr, lchan->ts->nr, \
			lchan->nr, lchan->use_count); \
	} while(0);


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

struct gsm_lchan;
struct gsm_subscriber;

/* One end of a call */
struct gsm_call {
	enum gsm_call_type type;
	enum gsm_call_state state;
	u_int8_t transaction_id;	/* 10.3.2 */

	/* the 'local' channel */
	struct gsm_lchan *local_lchan;
	/* the 'remote' channel */
	struct gsm_lchan *remote_lchan;

	/* the 'remote' subscriber */
	struct gsm_subscriber *called_subscr;
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

/* Network Management State */
struct gsm_nm_state {
	u_int8_t operational;
	u_int8_t administrative;
	u_int8_t availability;
};
struct gsm_attr {
	u_int8_t len;
	u_int8_t data[0];
};

/*
 * LOCATION UPDATING REQUEST state
 *
 * Our current operation is:
 *	- Get imei/tmsi
 *	- Accept/Reject according to global policy
 */
struct gsm_loc_updating_operation {
        struct timer_list updating_timer;
	int waiting_for_imsi : 1;
	int waiting_for_imei : 1;
};

struct gsm_lchan {
	/* The TS that we're part of */
	struct gsm_bts_trx_ts *ts;
	/* The logical subslot number in the TS */
	u_int8_t nr;
	/* The logical channel type */
	enum gsm_chan_t type;
	/* If TCH, traffic channel mode */
	enum gsm_chan_t tch_mode;
	/* Power levels for MS and BTS */
	u_int8_t bs_power;
	u_int8_t ms_power;
	
	/* To whom we are allocated at the moment */
	struct gsm_subscriber *subscr;

	/* Timer started to release the channel */
	struct timer_list release_timer;

	/* local end of a call, if any */
	struct gsm_call call;

	/* temporary user data, to be removed... and merged into gsm_call */
	void *user_data;

	/*
	 * Operations that have a state and might be pending
	 */
	struct gsm_loc_updating_operation *loc_operation;

	/* use count. how many users use this channel */
	unsigned int use_count;
};

struct gsm_e1_subslot {
	/* Number of E1 link */
	u_int8_t	e1_nr;
	/* Number of E1 TS inside E1 link */
	u_int8_t	e1_ts;
	/* Sub-slot within the E1 TS, 0xff if full TS */
	u_int8_t	e1_ts_ss;
};

#define BTS_TRX_F_ACTIVATED	0x0001
/* One Timeslot in a TRX */
struct gsm_bts_trx_ts {
	struct gsm_bts_trx *trx;
	/* number of this timeslot at the TRX */
	u_int8_t nr;

	enum gsm_phys_chan_config pchan;

	unsigned int flags;
	struct gsm_nm_state nm_state;
	struct gsm_attr *nm_attr;

	/* To which E1 subslot are we connected */
	struct gsm_e1_subslot e1_link;
	struct {
		u_int32_t bound_ip;
		u_int16_t bound_port;
		u_int8_t attr_fc;
		u_int16_t attr_f8;
	} abis_ip;

	struct gsm_lchan lchan[TS_MAX_LCHAN];
};

/* One TRX in a BTS */
struct gsm_bts_trx {
	struct gsm_bts *bts;
	/* number of this TRX in the BTS */
	u_int8_t nr;
	/* how do we talk RSL with this TRX? */
	struct e1inp_sign_link *rsl_link;
	struct gsm_nm_state nm_state;
	struct gsm_attr *nm_attr;
	struct {
		struct gsm_nm_state nm_state;
	} bb_transc;

	u_int16_t arfcn;

	union {
		struct {
			struct {
				struct gsm_nm_state nm_state;
			} bbsig;
			struct {
				struct gsm_nm_state nm_state;
			} pa;
		} bs11;
	};
	struct gsm_bts_trx_ts ts[TRX_NR_TS];
};

enum gsm_bts_type {
	GSM_BTS_TYPE_UNKNOWN,
	GSM_BTS_TYPE_BS11,
	GSM_BTS_TYPE_NANOBTS_900,
	GSM_BTS_TYPE_NANOBTS_1800,
};

/**
 * A pending paging request 
 */
struct gsm_paging_request {
	/* list_head for list of all paging requests */
	struct llist_head entry;
	/* the subscriber which we're paging. Later gsm_paging_request
	 * should probably become a part of the gsm_subscriber struct? */
	struct gsm_subscriber *subscr;
	/* back-pointer to the BTS on which we are paging */
	struct gsm_bts *bts;
	/* what kind of channel type do we ask the MS to establish */
	int chan_type;

	/* Timer 3113: how long do we try to page? */
	struct timer_list T3113;

	/* callback to be called in case paging completes */
	gsm_cbfn *cbfn;
	void *cbfn_param;
};
#define T3113_VALUE	60, 0

/*
 * This keeps track of the paging status of one BTS. It
 * includes a number of pending requests, a back pointer
 * to the gsm_bts, a timer and some more state.
 */
struct gsm_bts_paging_state {
	/* pending requests */
	struct llist_head pending_requests;
	struct gsm_paging_request *last_request;
	struct gsm_bts *bts;

	struct timer_list work_timer;

	/* load */
	u_int16_t available_slots;
};

struct gsm_envabtse {
	struct gsm_nm_state nm_state;
};

/* One BTS */
struct gsm_bts {
	struct gsm_network *network;
	/* number of ths BTS in network */
	u_int8_t nr;
	/* location area code of this BTS */
	u_int8_t location_area_code;
	/* Training Sequence Code */
	u_int8_t tsc;
	/* Base Station Identification Code (BSIC) */
	u_int8_t bsic;
	/* type of BTS */
	enum gsm_bts_type type;
	/* how do we talk OML with this TRX? */
	struct e1inp_sign_link *oml_link;

	/* Abis network management O&M handle */
	struct abis_nm_h *nmh;
	struct gsm_nm_state nm_state;
	struct gsm_attr *nm_attr;

	/* number of this BTS on given E1 link */
	u_int8_t bts_nr;

	struct gsm48_control_channel_descr chan_desc;

	/* paging state and control */
	struct gsm_bts_paging_state paging;

	/* CCCH is on C0 */
	struct gsm_bts_trx *c0;

	struct {
		struct gsm_nm_state nm_state;
	} site_mgr;

	/* ip.accesss Unit ID's have Site/BTS/TRX layout */
	union {
		struct {
			u_int16_t site_id;
			u_int16_t bts_id;
		} ip_access;
		struct {
			struct {
				struct gsm_nm_state nm_state;
			} cclk;
			struct {
				struct gsm_nm_state nm_state;
			} rack;
			struct gsm_envabtse envabtse[4];
		} bs11;
	};
	
	/* transceivers */
	int num_trx;
	struct gsm_bts_trx trx[BTS_MAX_TRX+1];
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
};

#define SMS_HDR_SIZE	128
#define SMS_TEXT_SIZE	256
struct gsm_sms {
	u_int64_t id;
	struct gsm_subscriber *sender;
	struct gsm_subscriber *receiver;

	unsigned char header[SMS_HDR_SIZE];
	char text[SMS_TEXT_SIZE];
};

struct gsm_network *gsm_network_init(unsigned int num_bts, enum gsm_bts_type bts_type,
				     u_int16_t country_code, u_int16_t network_code);

const char *gsm_pchan_name(enum gsm_phys_chan_config c);
const char *gsm_lchan_name(enum gsm_chan_t c);
const char *gsm_chreq_name(enum gsm_chreq_reason_t c);
char *gsm_ts_name(struct gsm_bts_trx_ts *ts);

enum gsm_e1_event {
	EVT_E1_NONE,
	EVT_E1_TEI_UP,
	EVT_E1_TEI_DN,
};

void set_ts_e1link(struct gsm_bts_trx_ts *ts, u_int8_t e1_nr,
		   u_int8_t e1_ts, u_int8_t e1_ts_ss);
enum gsm_bts_type parse_btstype(char *arg);
const char *btstype2str(enum gsm_bts_type type);
struct gsm_bts *gsm_bts_by_lac(struct gsm_network *net, unsigned int lac,
				struct gsm_bts *start_bts);

static inline int is_ipaccess_bts(struct gsm_bts *bts)
{
	switch (bts->type) {
	case GSM_BTS_TYPE_NANOBTS_900:
	case GSM_BTS_TYPE_NANOBTS_1800:
		return 1;
	default:
		break;
	}
	return 0;
}

#endif
