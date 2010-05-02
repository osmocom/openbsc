#ifndef _GSM_DATA_H
#define _GSM_DATA_H

#include <sys/types.h>

enum gsm_phys_chan_config {
	GSM_PCHAN_NONE,
	GSM_PCHAN_CCCH,
	GSM_PCHAN_CCCH_SDCCH4,
	GSM_PCHAN_TCH_F,
	GSM_PCHAN_TCH_H,
	GSM_PCHAN_SDCCH8_SACCH8C,
	GSM_PCHAN_PDCH,		/* GPRS PDCH */
	GSM_PCHAN_TCH_F_PDCH,	/* TCH/F if used, PDCH otherwise */
	GSM_PCHAN_UNKNOWN,
};

enum gsm_chan_t {
	GSM_LCHAN_NONE,
	GSM_LCHAN_SDCCH,
	GSM_LCHAN_TCH_F,
	GSM_LCHAN_TCH_H,
	GSM_LCHAN_UNKNOWN,
};

/* RRLP mode of operation */
enum rrlp_mode {
	RRLP_MODE_NONE,
	RRLP_MODE_MS_BASED,
	RRLP_MODE_MS_PREF,
	RRLP_MODE_ASS_PREF,
};

/* Channel Request reason */
enum gsm_chreq_reason_t {
	GSM_CHREQ_REASON_EMERG,
	GSM_CHREQ_REASON_PAG,
	GSM_CHREQ_REASON_CALL,
	GSM_CHREQ_REASON_LOCATION_UPD,
	GSM_CHREQ_REASON_OTHER,
};

#include <osmocore/timer.h>
#include <openbsc/gsm_04_08.h>
#include <openbsc/abis_rsl.h>
#include <openbsc/mncc.h>
#include <osmocore/tlv.h>
#include <osmocore/bitvec.h>
#include <osmocore/statistics.h>
#include <osmocore/gsm_utils.h>
#include <osmocore/utils.h>

#define TRX_NR_TS	8
#define TS_MAX_LCHAN	8

#define HARDCODED_ARFCN 123
#define HARDCODED_TSC	7
#define HARDCODED_BSIC	0x3f	/* NCC = 7 / BCC = 7 */

/* for multi-drop config */
#define HARDCODED_BTS0_TS	1
#define HARDCODED_BTS1_TS	6
#define HARDCODED_BTS2_TS	11

enum gsm_hooks {
	GSM_HOOK_NM_SWLOAD,
	GSM_HOOK_RR_PAGING,
};

enum gsm_paging_event {
	GSM_PAGING_SUCCEEDED,
	GSM_PAGING_EXPIRED,
	GSM_PAGING_OOM,
};

enum bts_gprs_mode {
	BTS_GPRS_NONE = 0,
	BTS_GPRS_GPRS = 1,
	BTS_GPRS_EGPRS = 2,
};

/* the data structure stored in msgb->cb for openbsc apps */
struct openbsc_msgb_cb {
	unsigned char *bssgph;
	unsigned char *llch;

	u_int16_t nsei;
	u_int16_t bvci;

	u_int32_t tlli;
} __attribute__((packed));
#define OBSC_MSGB_CB(__msgb)	((struct openbsc_msgb_cb *)&((__msgb)->cb[0]))
#define msgb_tlli(__x)		OBSC_MSGB_CB(__x)->tlli
#define msgb_nsei(__x)		OBSC_MSGB_CB(__x)->nsei
#define msgb_bvci(__x)		OBSC_MSGB_CB(__x)->bvci
#define msgb_gmmh(__x)		(__x)->l3h
#define msgb_bssgph(__x)	OBSC_MSGB_CB(__x)->bssgph
#define msgb_llch(__x)		OBSC_MSGB_CB(__x)->llch

struct msgb;
typedef int gsm_cbfn(unsigned int hooknum,
		     unsigned int event,
		     struct msgb *msg,
		     void *data, void *param);

/*
 * Use the channel. As side effect the lchannel recycle timer
 * will be started.
 */
#define LCHAN_RELEASE_TIMEOUT 20, 0
#define use_subscr_con(con) \
	do {	(con)->use_count++; \
		DEBUGP(DREF, "lchan (bts=%d,trx=%d,ts=%d,ch=%d) increases usage to: %d\n", \
			(con)->lchan->ts->trx->bts->nr, (con)->lchan->ts->trx->nr, (con)->lchan->ts->nr, \
			(con)->lchan->nr, (con)->use_count); \
		bsc_schedule_timer(&(con)->release_timer, LCHAN_RELEASE_TIMEOUT); } while(0);

#define put_subscr_con(con) \
	do { (con)->use_count--; \
		DEBUGP(DREF, "lchan (bts=%d,trx=%d,ts=%d,ch=%d) decreases usage to: %d\n", \
			(con)->lchan->ts->trx->bts->nr, (con)->lchan->ts->trx->nr, (con)->lchan->ts->nr, \
			(con)->lchan->nr, (con)->use_count); \
	} while(0);


/* Real authentication information containing Ki */
enum gsm_auth_algo {
	AUTH_ALGO_NONE,
	AUTH_ALGO_XOR,
	AUTH_ALGO_COMP128v1,
};

struct gsm_auth_info {
	enum gsm_auth_algo auth_algo;
	unsigned int a3a8_ki_len;
	u_int8_t a3a8_ki[16];
};

struct gsm_auth_tuple {
	int use_count;
	int key_seq;
	u_int8_t rand[16];
	u_int8_t sres[4];
	u_int8_t kc[8];
};


struct gsm_lchan;
struct gsm_subscriber;
struct gsm_mncc;
struct rtp_socket;

/* Network Management State */
struct gsm_nm_state {
	u_int8_t operational;
	u_int8_t administrative;
	u_int8_t availability;
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
	unsigned int waiting_for_imsi : 1;
	unsigned int waiting_for_imei : 1;
};

/* Maximum number of neighbor cells whose average we track */
#define MAX_NEIGH_MEAS		10
/* Maximum size of the averaging window for neighbor cells */
#define MAX_WIN_NEIGH_AVG	10

/* processed neighbor measurements for one cell */
struct neigh_meas_proc {
	u_int16_t arfcn;
	u_int8_t bsic;
	u_int8_t rxlev[MAX_WIN_NEIGH_AVG];
	unsigned int rxlev_cnt;
	u_int8_t last_seen_nr;
};

#define MAX_A5_KEY_LEN	(128/8)
#define RSL_ENC_ALG_A5(x)	(x+1)

/* is the data link established? who established it? */
#define LCHAN_SAPI_UNUSED	0
#define LCHAN_SAPI_MS		1
#define LCHAN_SAPI_NET		2

/* state of a logical channel */
enum gsm_lchan_state {
	LCHAN_S_NONE,		/* channel is not active */
	LCHAN_S_ACT_REQ,	/* channel activatin requested */
	LCHAN_S_ACTIVE,		/* channel is active and operational */
	LCHAN_S_REL_REQ,	/* channel release has been requested */
	LCHAN_S_INACTIVE,	/* channel is set inactive */
};

/* the per subscriber data for lchan */
struct gsm_subscriber_connection {
	/* To whom we are allocated at the moment */
	struct gsm_subscriber *subscr;

	/* Timer started to release the channel */
	struct timer_list release_timer;

	/*
	 * Operations that have a state and might be pending
	 */
	struct gsm_loc_updating_operation *loc_operation;

	/* use count. how many users use this channel */
	unsigned int use_count;

	/* Are we part of a special "silent" call */
	int silent_call;

	/* back pointers */
	struct gsm_lchan *lchan;
	struct gsm_bts *bts;
};

struct gsm_lchan {
	/* The TS that we're part of */
	struct gsm_bts_trx_ts *ts;
	/* The logical subslot number in the TS */
	u_int8_t nr;
	/* The logical channel type */
	enum gsm_chan_t type;
	/* RSL channel mode */
	enum rsl_cmod_spd rsl_cmode;
	/* If TCH, traffic channel mode */
	enum gsm48_chan_mode tch_mode;
	/* State */
	enum gsm_lchan_state state;
	/* Power levels for MS and BTS */
	u_int8_t bs_power;
	u_int8_t ms_power;
	/* Encryption information */
	struct {
		u_int8_t alg_id;
		u_int8_t key_len;
		u_int8_t key[MAX_A5_KEY_LEN];
	} encr;

	struct timer_list T3101;

	/* AMR bits */
	struct gsm48_multi_rate_conf mr_conf;
	
	/* Established data link layer services */
	u_int8_t sapis[8];

	/* cache of last measurement reports on this lchan */
	struct gsm_meas_rep meas_rep[6];
	int meas_rep_idx;

	/* table of neighbor cell measurements */
	struct neigh_meas_proc neigh_meas[MAX_NEIGH_MEAS];

	struct {
		u_int32_t bound_ip;
		u_int32_t connect_ip;
		u_int16_t bound_port;
		u_int16_t connect_port;
		u_int16_t conn_id;
		u_int8_t rtp_payload;
		u_int8_t rtp_payload2;
		u_int8_t speech_mode;
		struct rtp_socket *rtp_socket;
	} abis_ip;

	struct gsm_subscriber_connection conn;
};

struct gsm_e1_subslot {
	/* Number of E1 link */
	u_int8_t	e1_nr;
	/* Number of E1 TS inside E1 link */
	u_int8_t	e1_ts;
	/* Sub-slot within the E1 TS, 0xff if full TS */
	u_int8_t	e1_ts_ss;
};

#define TS_F_PDCH_MODE	0x1000
/* One Timeslot in a TRX */
struct gsm_bts_trx_ts {
	struct gsm_bts_trx *trx;
	/* number of this timeslot at the TRX */
	u_int8_t nr;

	enum gsm_phys_chan_config pchan;

	unsigned int flags;
	struct gsm_nm_state nm_state;
	struct tlv_parsed nm_attr;
	u_int8_t nm_chan_comb;

	/* To which E1 subslot are we connected */
	struct gsm_e1_subslot e1_link;

	struct gsm_lchan lchan[TS_MAX_LCHAN];
};

/* One TRX in a BTS */
struct gsm_bts_trx {
	/* list header in bts->trx_list */
	struct llist_head list;

	struct gsm_bts *bts;
	/* number of this TRX in the BTS */
	u_int8_t nr;
	/* how do we talk RSL with this TRX? */
	struct gsm_e1_subslot rsl_e1_link;
	u_int8_t rsl_tei;
	struct e1inp_sign_link *rsl_link;

	struct gsm_nm_state nm_state;
	struct tlv_parsed nm_attr;
	struct {
		struct gsm_nm_state nm_state;
	} bb_transc;

	u_int16_t arfcn;
	int nominal_power;		/* in dBm */
	unsigned int max_power_red;	/* in actual dB */

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
	GSM_BTS_TYPE_NANOBTS,
};

struct gsm_bts_model {
	struct llist_head list;

	enum gsm_bts_type type;
	const char *name;

	struct tlv_definition nm_att_tlvdef;
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

/*
 * This keeps track of the paging status of one BTS. It
 * includes a number of pending requests, a back pointer
 * to the gsm_bts, a timer and some more state.
 */
struct gsm_bts_paging_state {
	/* pending requests */
	struct llist_head pending_requests;
	struct gsm_bts *bts;

	struct timer_list work_timer;

	/* load */
	u_int16_t available_slots;
};

struct gsm_envabtse {
	struct gsm_nm_state nm_state;
};

struct gsm_bts_gprs_nsvc {
	struct gsm_bts *bts;
	/* data read via VTY config file, to configure the BTS
	 * via OML from BSC */
	int id;
	u_int16_t nsvci;
	u_int16_t local_port;	/* on the BTS */
	u_int16_t remote_port;	/* on the SGSN */
	u_int32_t remote_ip;	/* on the SGSN */

	struct gsm_nm_state nm_state;
};

/* One BTS */
struct gsm_bts {
	/* list header in net->bts_list */
	struct llist_head list;

	struct gsm_network *network;
	/* number of ths BTS in network */
	u_int8_t nr;
	/* Cell Identity */
	u_int16_t cell_identity;
	/* location area code of this BTS */
	u_int16_t location_area_code;
	/* Training Sequence Code */
	u_int8_t tsc;
	/* Base Station Identification Code (BSIC) */
	u_int8_t bsic;
	/* type of BTS */
	enum gsm_bts_type type;
	struct gsm_bts_model *model;
	enum gsm_band band;
	/* should the channel allocator allocate channels from high TRX to TRX0,
	 * rather than starting from TRX0 and go upwards? */
	int chan_alloc_reverse;
	/* maximum Tx power that the MS is permitted to use in this cell */
	int ms_max_power;

	/* how do we talk OML with this TRX? */
	struct gsm_e1_subslot oml_e1_link;
	u_int8_t oml_tei;
	struct e1inp_sign_link *oml_link;

	/* Abis network management O&M handle */
	struct abis_nm_h *nmh;
	struct gsm_nm_state nm_state;
	struct tlv_parsed nm_attr;

	/* number of this BTS on given E1 link */
	u_int8_t bts_nr;

	/* paging state and control */
	struct gsm_bts_paging_state paging;

	/* CCCH is on C0 */
	struct gsm_bts_trx *c0;

	struct {
		struct gsm_nm_state nm_state;
	} site_mgr;

	/* parameters from which we build SYSTEM INFORMATION */
	struct {
		struct gsm48_rach_control rach_control;
		u_int8_t ncc_permitted;
		struct gsm48_cell_sel_par cell_sel_par;
		struct gsm48_cell_options cell_options;
		struct gsm48_control_channel_descr chan_desc;
		struct bitvec neigh_list;
		struct bitvec cell_alloc;
		struct {
			/* bitmask large enough for all possible ARFCN's */
			u_int8_t neigh_list[1024/8];
			u_int8_t cell_alloc[1024/8];
		} data;
	} si_common;

	/* ip.accesss Unit ID's have Site/BTS/TRX layout */
	union {
		struct {
			u_int16_t site_id;
			u_int16_t bts_id;
			u_int32_t flags;
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

	/* Not entirely sure how ip.access specific this is */
	struct {
		enum bts_gprs_mode mode;
		struct {
			struct gsm_nm_state nm_state;
			u_int16_t nsei;
		} nse;
		struct {
			struct gsm_nm_state nm_state;
			u_int16_t bvci;
		} cell;
		struct gsm_bts_gprs_nsvc nsvc[2];
		u_int8_t rac;
	} gprs;

	/* RACH NM values */
	int rach_b_thresh;
	int rach_ldavg_slots;
	
	/* transceivers */
	int num_trx;
	struct llist_head trx_list;
};

/* Some statistics of our network */
struct gsmnet_stats {
	struct {
		struct counter *total;
		struct counter *no_channel;
	} chreq;
	struct {
		struct counter *attempted;
		struct counter *no_channel;	/* no channel available */
		struct counter *timeout;		/* T3103 timeout */
		struct counter *completed;	/* HO COMPL received */
		struct counter *failed;		/* HO FAIL received */
	} handover;
	struct {
		struct counter *attach;
		struct counter *normal;
		struct counter *periodic;
		struct counter *detach;
	} loc_upd_type;
	struct {
		struct counter *reject;
		struct counter *accept;
	} loc_upd_resp;
	struct {
		struct counter *attempted;
		struct counter *detached;
		struct counter *completed;
		struct counter *expired;
	} paging;
	struct {
		struct counter *submitted; /* MO SMS submissions */
		struct counter *no_receiver;
		struct counter *delivered; /* MT SMS deliveries */
		struct counter *rp_err_mem;
		struct counter *rp_err_other;
	} sms;
	struct {
		struct counter *dialled;	/* total number of dialled calls */
		struct counter *alerted;	/* we alerted the other end */
		struct counter *connected;/* how many calls were accepted */
	} call;
	struct {
		struct counter *rf_fail;
		struct counter *rll_err;
	} chan;
	struct {
		struct counter *oml_fail;
		struct counter *rsl_fail;
	} bts;
};

enum gsm_auth_policy {
	GSM_AUTH_POLICY_CLOSED, /* only subscribers authorized in DB */
	GSM_AUTH_POLICY_ACCEPT_ALL, /* accept everyone, even if not authorized in DB */
	GSM_AUTH_POLICY_TOKEN, /* accept first, send token per sms, then revoke authorization */
};

#define GSM_T3101_DEFAULT 10
#define GSM_T3113_DEFAULT 60

struct gsm_network {
	/* global parameters */
	u_int16_t country_code;
	u_int16_t network_code;
	char *name_long;
	char *name_short;
	enum gsm_auth_policy auth_policy;
	enum gsm48_reject_value reject_cause;
	int a5_encryption;
	int neci;
	int send_mm_info;
	struct {
		int active;
		/* Window RXLEV averaging */
		unsigned int win_rxlev_avg;	/* number of SACCH frames */
		/* Window RXQUAL averaging */
		unsigned int win_rxqual_avg;	/* number of SACCH frames */
		/* Window RXLEV neighbouring cells averaging */
		unsigned int win_rxlev_avg_neigh; /* number of SACCH frames */

		/* how often should we check for power budget HO */
		unsigned int pwr_interval;	/* SACCH frames */
		/* how much better does a neighbor cell have to be ? */
		unsigned int pwr_hysteresis;	/* dBm */
		/* maximum distacne before we try a handover */
		unsigned int max_distance;	/* TA values */
	} handover;

	struct gsmnet_stats stats;

	/* layer 4 */
	int (*mncc_recv) (struct gsm_network *net, int msg_type, void *arg);
	struct llist_head upqueue;
	struct llist_head trans_list;

	unsigned int num_bts;
	struct llist_head bts_list;

	/* timer values */
	int T3101;
	int T3103;
	int T3105;
	int T3107;
	int T3109;
	int T3111;
	int T3113;
	int T3115;
	int T3117;
	int T3119;
	int T3141;

	/* Radio Resource Location Protocol (TS 04.31) */
	struct {
		enum rrlp_mode mode;
	} rrlp;
};

#define SMS_HDR_SIZE	128
#define SMS_TEXT_SIZE	256
struct gsm_sms {
	unsigned long long id;
	struct gsm_subscriber *sender;
	struct gsm_subscriber *receiver;

	unsigned long validity_minutes;
	u_int8_t reply_path_req;
	u_int8_t status_rep_req;
	u_int8_t ud_hdr_ind;
	u_int8_t protocol_id;
	u_int8_t data_coding_scheme;
	u_int8_t msg_ref;
	char dest_addr[20+1];	/* DA LV is 12 bytes max, i.e. 10 bytes
				 * BCD == 20 bytes string */
	u_int8_t user_data_len;
	u_int8_t user_data[SMS_TEXT_SIZE];

	char text[SMS_TEXT_SIZE];
};


struct gsm_network *gsm_network_init(u_int16_t country_code, u_int16_t network_code,
				     int (*mncc_recv)(struct gsm_network *, int, void *));
struct gsm_bts *gsm_bts_alloc(struct gsm_network *net, enum gsm_bts_type type,
			      u_int8_t tsc, u_int8_t bsic);
struct gsm_bts_trx *gsm_bts_trx_alloc(struct gsm_bts *bts);
int gsm_set_bts_type(struct gsm_bts *bts, enum gsm_bts_type type);

struct gsm_bts *gsm_bts_num(struct gsm_network *net, int num);

/* Get reference to a neighbor cell on a given BCCH ARFCN */
struct gsm_bts *gsm_bts_neighbor(const struct gsm_bts *bts,
				 u_int16_t arfcn, u_int8_t bsic);

struct gsm_bts_trx *gsm_bts_trx_num(struct gsm_bts *bts, int num);

const char *gsm_pchan_name(enum gsm_phys_chan_config c);
enum gsm_phys_chan_config gsm_pchan_parse(const char *name);
const char *gsm_lchant_name(enum gsm_chan_t c);
const char *gsm_chreq_name(enum gsm_chreq_reason_t c);
char *gsm_trx_name(struct gsm_bts_trx *trx);
char *gsm_ts_name(struct gsm_bts_trx_ts *ts);
char *gsm_lchan_name(struct gsm_lchan *lchan);
const char *gsm_lchans_name(enum gsm_lchan_state s);

enum gsm_e1_event {
	EVT_E1_NONE,
	EVT_E1_TEI_UP,
	EVT_E1_TEI_DN,
};

void set_ts_e1link(struct gsm_bts_trx_ts *ts, u_int8_t e1_nr,
		   u_int8_t e1_ts, u_int8_t e1_ts_ss);
enum gsm_bts_type parse_btstype(const char *arg);
const char *btstype2str(enum gsm_bts_type type);
struct gsm_bts_trx *gsm_bts_trx_by_nr(struct gsm_bts *bts, int nr);
struct gsm_bts *gsm_bts_by_lac(struct gsm_network *net, unsigned int lac,
				struct gsm_bts *start_bts);

extern void *tall_bsc_ctx;
extern int ipacc_rtp_direct;

static inline int is_ipaccess_bts(struct gsm_bts *bts)
{
	switch (bts->type) {
	case GSM_BTS_TYPE_NANOBTS:
		return 1;
	default:
		break;
	}
	return 0;
}

static inline int is_siemens_bts(struct gsm_bts *bts)
{
	switch (bts->type) {
	case GSM_BTS_TYPE_BS11:
		return 1;
	default:
		break;
	}

	return 0;
}


enum gsm_auth_policy gsm_auth_policy_parse(const char *arg);
const char *gsm_auth_policy_name(enum gsm_auth_policy policy);

enum rrlp_mode rrlp_mode_parse(const char *arg);
const char *rrlp_mode_name(enum rrlp_mode mode);

enum bts_gprs_mode bts_gprs_mode_parse(const char *arg);
const char *bts_gprs_mode_name(enum bts_gprs_mode mode);

void gsm_trx_lock_rf(struct gsm_bts_trx *trx, int locked);

int gsm48_ra_id_by_bts(u_int8_t *buf, struct gsm_bts *bts);
void gprs_ra_id_by_bts(struct gprs_ra_id *raid, struct gsm_bts *bts);
struct gsm_meas_rep *lchan_next_meas_rep(struct gsm_lchan *lchan);

int gsm_bts_model_register(struct gsm_bts_model *model);

#endif
