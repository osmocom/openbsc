#ifndef _GSM_DATA_H
#define _GSM_DATA_H

#include <stdint.h>
#include <regex.h>
#include <sys/types.h>
#include <stdbool.h>

#include <osmocom/core/timer.h>
#include <osmocom/core/rate_ctr.h>
#include <osmocom/core/select.h>
#include <osmocom/core/stats.h>

#include <osmocom/crypt/auth.h>

#include <openbsc/rest_octets.h>
#include <openbsc/common_cs.h>

/** annotations for msgb ownership */
#define __uses

#define OBSC_NM_W_ACK_CB(__msgb) (__msgb)->cb[3]

struct mncc_sock_state;
struct gsm_subscriber_group;
struct bsc_subscr;

#define OBSC_LINKID_CB(__msgb)	(__msgb)->cb[3]

#define tmsi_from_string(str) strtoul(str, NULL, 10)

/* 3-bit long values */
#define EARFCN_PRIO_INVALID 8
#define EARFCN_MEAS_BW_INVALID 8
/* 5-bit long values */
#define EARFCN_QRXLV_INVALID 32
#define EARFCN_THRESH_LOW_INVALID 32

enum gsm_security_event {
	GSM_SECURITY_NOAVAIL,
	GSM_SECURITY_AUTH_FAILED,
	GSM_SECURITY_SUCCEEDED,
	GSM_SECURITY_ALREADY,
};

struct msgb;
typedef int gsm_cbfn(unsigned int hooknum,
		     unsigned int event,
		     struct msgb *msg,
		     void *data, void *param);

/* Real authentication information containing Ki */
enum gsm_auth_algo {
	AUTH_ALGO_NONE,
	AUTH_ALGO_XOR,
	AUTH_ALGO_COMP128v1,
};

struct gsm_auth_info {
	enum gsm_auth_algo auth_algo;
	unsigned int a3a8_ki_len;
	uint8_t a3a8_ki[16];
};

struct gsm_auth_tuple {
	int use_count;
	int key_seq;
	struct osmo_auth_vector vec;
};
#define GSM_KEY_SEQ_INVAL	7	/* GSM 04.08 - 10.5.1.2 */

/*
 * LOCATION UPDATING REQUEST state
 *
 * Our current operation is:
 *	- Get imei/tmsi
 *	- Accept/Reject according to global policy
 */
struct gsm_loc_updating_operation {
        struct osmo_timer_list updating_timer;
	unsigned int waiting_for_imsi : 1;
	unsigned int waiting_for_imei : 1;
	unsigned int key_seq : 4;
};

/*
 * AUTHENTICATION/CIPHERING state
 */
struct gsm_security_operation {
	struct gsm_auth_tuple atuple;
	gsm_cbfn *cb;
	void *cb_data;
};

/*
 * A dummy to keep a connection up for at least
 * a couple of seconds to work around MSC issues.
 */
struct gsm_anchor_operation {
	struct osmo_timer_list timeout;
};

/* Maximum number of neighbor cells whose average we track */
#define MAX_NEIGH_MEAS		10
/* Maximum size of the averaging window for neighbor cells */
#define MAX_WIN_NEIGH_AVG	10

/* processed neighbor measurements for one cell */
struct neigh_meas_proc {
	uint16_t arfcn;
	uint8_t bsic;
	uint8_t rxlev[MAX_WIN_NEIGH_AVG];
	unsigned int rxlev_cnt;
	uint8_t last_seen_nr;
};

enum ran_type {
       RAN_UNKNOWN,
       RAN_GERAN_A,	/* 2G / A-interface */
       RAN_UTRAN_IU,	/* 3G / Iu-interface (IuCS or IuPS) */
};

/* active radio connection of a mobile subscriber */
struct gsm_subscriber_connection {
	struct llist_head entry;

	/* To whom we are allocated at the moment */
	struct gsm_subscriber *subscr;

	/* libbsc subscriber information */
	struct bsc_subscr *bsub;

	/* LU expiration handling */
	uint8_t expire_timer_stopped;
	/* SMS helpers for libmsc */
	uint8_t next_rp_ref;

	/*
	 * Operations that have a state and might be pending
	 */
	struct gsm_loc_updating_operation *loc_operation;
	struct gsm_security_operation *sec_operation;
	struct gsm_anchor_operation *anch_operation;

	/* Are we part of a special "silent" call */
	int silent_call;

	/* MNCC rtp bridge markers */
	int mncc_rtp_bridge;
	int mncc_rtp_create_pending;
	int mncc_rtp_connect_pending;

	/* bsc structures */
	struct osmo_bsc_sccp_con *sccp_con; /* BSC */

	/* back pointers */
	struct gsm_network *network;

	int in_release;
	struct gsm_lchan *lchan; /* BSC */
	struct gsm_lchan *ho_lchan; /* BSC */
	struct gsm_bts *bts; /* BSC */

	/* for assignment handling */
	struct osmo_timer_list T10; /* BSC */
	struct gsm_lchan *secondary_lchan; /* BSC */

	/* connected via 2G or 3G? */
	enum ran_type via_ran;
};


#define ROLE_BSC
#include "gsm_data_shared.h"


enum {
	BSC_CTR_CHREQ_TOTAL,
	BSC_CTR_CHREQ_NO_CHANNEL,
	BSC_CTR_HANDOVER_ATTEMPTED,
	BSC_CTR_HANDOVER_NO_CHANNEL,
	BSC_CTR_HANDOVER_TIMEOUT,
	BSC_CTR_HANDOVER_COMPLETED,
	BSC_CTR_HANDOVER_FAILED,
	BSC_CTR_PAGING_ATTEMPTED,
	BSC_CTR_PAGING_DETACHED,
	BSC_CTR_PAGING_COMPLETED,
	BSC_CTR_PAGING_EXPIRED,
	BSC_CTR_CHAN_RF_FAIL,
	BSC_CTR_CHAN_RLL_ERR,
	BSC_CTR_BTS_OML_FAIL,
	BSC_CTR_BTS_RSL_FAIL,
	BSC_CTR_CODEC_AMR_F,
	BSC_CTR_CODEC_AMR_H,
	BSC_CTR_CODEC_EFR,
	BSC_CTR_CODEC_V1_FR,
	BSC_CTR_CODEC_V1_HR,
};

static const struct rate_ctr_desc bsc_ctr_description[] = {
	[BSC_CTR_CHREQ_TOTAL] = 		{"chreq.total", "Received channel requests."},
	[BSC_CTR_CHREQ_NO_CHANNEL] = 		{"chreq.no_channel", "Sent to MS no channel available."},
	[BSC_CTR_HANDOVER_ATTEMPTED] = 		{"handover.attempted", "Received handover attempts."},
	[BSC_CTR_HANDOVER_NO_CHANNEL] = 		{"handover.no_channel", "Sent no channel available responses."},
	[BSC_CTR_HANDOVER_TIMEOUT] = 		{"handover.timeout", "Count the amount of timeouts of timer T3103."},
	[BSC_CTR_HANDOVER_COMPLETED] = 		{"handover.completed", "Received handover completed."},
	[BSC_CTR_HANDOVER_FAILED] = 		{"handover.failed", "Receive HO FAIL messages."},
	[BSC_CTR_PAGING_ATTEMPTED] = 		{"paging.attempted", "Paging attempts for a MS."},
	[BSC_CTR_PAGING_DETACHED] = 		{"paging.detached", "Counts the amount of paging attempts which couldn't sent out any paging request because no responsible bts found."},
	[BSC_CTR_PAGING_COMPLETED] = 		{"paging.completed", "Paging successful completed."},
	[BSC_CTR_PAGING_EXPIRED] = 		{"paging.expired", "Paging Request expired because of timeout T3113."},
	[BSC_CTR_CHAN_RF_FAIL] = 		{"chan.rf_fail", "Received a RF failure indication from BTS."},
	[BSC_CTR_CHAN_RLL_ERR] = 		{"chan.rll_err", "Received a RLL failure with T200 cause from BTS."},
	[BSC_CTR_BTS_OML_FAIL] = 		{"bts.oml_fail", "Received a TEI down on a OML link."},
	[BSC_CTR_BTS_RSL_FAIL] = 		{"bts.rsl_fail", "Received a TEI down on a OML link."},
	[BSC_CTR_CODEC_AMR_F] =			{"bts.codec_amr_f", "Count the usage of AMR/F codec by channel mode requested."},
	[BSC_CTR_CODEC_AMR_H] =			{"bts.codec_amr_h", "Count the usage of AMR/H codec by channel mode requested."},
	[BSC_CTR_CODEC_EFR] = 			{"bts.codec_efr", "Count the usage of EFR codec by channel mode requested."},
	[BSC_CTR_CODEC_V1_FR] =			{"bts.codec_fr", "Count the usage of FR codec by channel mode requested."},
	[BSC_CTR_CODEC_V1_HR] =			{"bts.codec_hr", "Count the usage of HR codec by channel mode requested."},
};

enum {
	MSC_CTR_LOC_UPDATE_TYPE_ATTACH,
	MSC_CTR_LOC_UPDATE_TYPE_NORMAL,
	MSC_CTR_LOC_UPDATE_TYPE_PERIODIC,
	MSC_CTR_LOC_UPDATE_TYPE_DETACH,
	MSC_CTR_LOC_UPDATE_FAILED,
	MSC_CTR_LOC_UPDATE_COMPLETED,
	MSC_CTR_SMS_SUBMITTED,
	MSC_CTR_SMS_NO_RECEIVER,
	MSC_CTR_SMS_DELIVERED,
	MSC_CTR_SMS_RP_ERR_MEM,
	MSC_CTR_SMS_RP_ERR_OTHER,
	MSC_CTR_SMS_DELIVER_UNKNOWN_ERROR,
	MSC_CTR_CALL_MO_SETUP,
	MSC_CTR_CALL_MO_CONNECT_ACK,
	MSC_CTR_CALL_MT_SETUP,
	MSC_CTR_CALL_MT_CONNECT,
	MSC_CTR_CALL_ACTIVE,
	MSC_CTR_CALL_COMPLETE,
	MSC_CTR_CALL_INCOMPLETE,
};

static const struct rate_ctr_desc msc_ctr_description[] = {
	[MSC_CTR_LOC_UPDATE_TYPE_ATTACH] = 		{"loc_update_type.attach", "Received location update imsi attach requests."},
	[MSC_CTR_LOC_UPDATE_TYPE_NORMAL] = 		{"loc_update_type.normal", "Received location update normal requests."},
	[MSC_CTR_LOC_UPDATE_TYPE_PERIODIC] = 		{"loc_update_type.periodic", "Received location update periodic requests."},
	[MSC_CTR_LOC_UPDATE_TYPE_DETACH] = 		{"loc_update_type.detach", "Received location update detach indication."},
	[MSC_CTR_LOC_UPDATE_FAILED] = 		{"loc_update_resp.failed", "Rejected location updates."},
	[MSC_CTR_LOC_UPDATE_COMPLETED] = 	{"loc_update_resp.completed", "Successful location updates."},
	[MSC_CTR_SMS_SUBMITTED] = 		{"sms.submitted", "Received a RPDU from a MS (MO)."},
	[MSC_CTR_SMS_NO_RECEIVER] = 		{"sms.no_receiver", "Counts SMS which couldn't routed because no receiver found."},
	[MSC_CTR_SMS_DELIVERED] = 		{"sms.delivered", "Global SMS Deliver attempts."},
	[MSC_CTR_SMS_RP_ERR_MEM] = 		{"sms.rp_err_mem", "CAUSE_MT_MEM_EXCEEDED errors of MS responses on a sms deliver attempt."},
	[MSC_CTR_SMS_RP_ERR_OTHER] = 		{"sms.rp_err_other", "Other error of MS responses on a sms delive attempt."},
	[MSC_CTR_SMS_DELIVER_UNKNOWN_ERROR] =	{"sms.deliver_unknown_error", "Unknown error occured during sms delivery."},
	/* FIXME: count also sms delivered */
	[MSC_CTR_CALL_MO_SETUP] = 		{"call.mo_setup", "Received setup requests from a MS to init a MO call."},
	[MSC_CTR_CALL_MO_CONNECT_ACK] = 		{"call.mo_connect_ack", "Received a connect ack from MS of a MO call. Call is now succesful connected up."},
	[MSC_CTR_CALL_MT_SETUP] = 		{"call.mt_setup", "Sent setup requests to the MS (MT)."},
	[MSC_CTR_CALL_MT_CONNECT] = 		{"call.mt_connect", "Sent a connect to the MS (MT)."},
	[MSC_CTR_CALL_ACTIVE] =			{"call.active", "Count total amount of calls that ever reached active state."},
	[MSC_CTR_CALL_COMPLETE] = 		{"call.complete", "Count total amount of calls which got terminated by disconnect req or ind after reaching active state."},
	[MSC_CTR_CALL_INCOMPLETE] = 		{"call.incomplete", "Count total amount of call which got terminated by any other reason after reaching active state."},
};


static const struct rate_ctr_group_desc bsc_ctrg_desc = {
	"bsc",
	"base station controller",
	OSMO_STATS_CLASS_GLOBAL,
	ARRAY_SIZE(bsc_ctr_description),
	bsc_ctr_description,
};

static const struct rate_ctr_group_desc msc_ctrg_desc = {
	"msc",
	"mobile switching center",
	OSMO_STATS_CLASS_GLOBAL,
	ARRAY_SIZE(msc_ctr_description),
	msc_ctr_description,
};

enum gsm_auth_policy {
	GSM_AUTH_POLICY_CLOSED, /* only subscribers authorized in DB */
	GSM_AUTH_POLICY_ACCEPT_ALL, /* accept everyone, even if not authorized in DB */
	GSM_AUTH_POLICY_TOKEN, /* accept first, send token per sms, then revoke authorization */
	GSM_AUTH_POLICY_REGEXP, /* accept IMSIs matching given regexp */
};

#define GSM_T3101_DEFAULT 10
#define GSM_T3105_DEFAULT 40
#define GSM_T3113_DEFAULT 60
#define GSM_T3122_DEFAULT 10

struct gsm_tz {
	int override; /* if 0, use system's time zone instead. */
	int hr; /* hour */
	int mn; /* minute */
	int dst; /* daylight savings */
};

struct gsm_network {
	/* global parameters */
	uint16_t country_code;
	uint16_t network_code;
	char *name_long;
	char *name_short;
	enum gsm_auth_policy auth_policy;
	regex_t authorized_regexp;
	char *authorized_reg_str;
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

	struct rate_ctr_group *bsc_ctrs;
	struct rate_ctr_group *msc_ctrs;
	struct osmo_counter *active_calls;

	/* layer 4 */
	struct mncc_sock_state *mncc_state;
	mncc_recv_cb_t mncc_recv;
	struct llist_head upqueue;
	struct llist_head trans_list;
	struct bsc_api *bsc_api;

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
	int T3122;
	int T3141;

	/* timer to expire old location updates */
	struct osmo_timer_list subscr_expire_timer;

	/* Radio Resource Location Protocol (TS 04.31) */
	struct {
		enum rrlp_mode mode;
	} rrlp;

	enum gsm_chan_t ctype_by_chreq[18];

	/* Use a TCH for handling requests of type paging any */
	int pag_any_tch;

	/* MSC data in case we are a true BSC */
	struct osmo_bsc_data *bsc_data;

	/* subscriber related features */
	bool auto_create_subscr;
	bool auto_assign_exten;
	uint64_t ext_min;
	uint64_t ext_max;
	struct gsm_subscriber_group *subscr_group;
	struct gsm_sms_queue *sms_queue;

	/* nitb related control */
	int avoid_tmsi;

	/* control interface */
	struct ctrl_handle *ctrl;

	/* Allow or disallow TCH/F on dynamic TCH/F_TCH/H_PDCH; OS#1778 */
	bool dyn_ts_allow_tch_f;

	/* all active subscriber connections. */
	struct llist_head subscr_conns;

	/* if override is nonzero, this timezone data is used for all MM
	 * contexts. */
	/* TODO: in OsmoNITB, tz-override used to be BTS-specific. To enable
	 * BTS|RNC specific timezone overrides for multi-tz networks in
	 * OsmoMSC, this should be tied to the location area code (LAC). */
	struct gsm_tz tz;

	/* List of all struct bsc_subscr used in libbsc. This llist_head is
	 * allocated so that the llist_head pointer itself can serve as a
	 * talloc context (useful to not have to pass the entire gsm_network
	 * struct to the bsc_subscr_* API, and for bsc_susbscr unit tests to
	 * not require gsm_data.h). In an MSC-without-BSC environment, this
	 * pointer is NULL to indicate absence of a bsc_subscribers list. */
	struct llist_head *bsc_subscribers;
};

struct osmo_esme;

enum gsm_sms_source_id {
	SMS_SOURCE_UNKNOWN = 0,
	SMS_SOURCE_MS,		/* received from MS */
	SMS_SOURCE_VTY,		/* received from VTY */
	SMS_SOURCE_SMPP,	/* received via SMPP */
};

#define SMS_HDR_SIZE	128
#define SMS_TEXT_SIZE	256

struct gsm_sms_addr {
	uint8_t ton;
	uint8_t npi;
	char addr[21+1];
};

struct gsm_sms {
	unsigned long long id;
	struct gsm_subscriber *receiver;
	struct gsm_sms_addr src, dst;
	enum gsm_sms_source_id source;

	struct {
		uint8_t transaction_id;
		uint32_t msg_ref;
	} gsm411;

	struct {
		struct osmo_esme *esme;
		uint32_t sequence_nr;
		int transaction_mode;
		char msg_id[16];
	} smpp;

	unsigned long validity_minutes;
	uint8_t reply_path_req;
	uint8_t status_rep_req;
	uint8_t ud_hdr_ind;
	uint8_t protocol_id;
	uint8_t data_coding_scheme;
	uint8_t msg_ref;
	uint8_t user_data_len;
	uint8_t user_data[SMS_TEXT_SIZE];

	char text[SMS_TEXT_SIZE];
};

extern void talloc_ctx_init(void *ctx_root);

int gsm_set_bts_type(struct gsm_bts *bts, enum gsm_bts_type type);

/* Get reference to a neighbor cell on a given BCCH ARFCN */
struct gsm_bts *gsm_bts_neighbor(const struct gsm_bts *bts,
				 uint16_t arfcn, uint8_t bsic);

enum gsm_bts_type parse_btstype(const char *arg);
const char *btstype2str(enum gsm_bts_type type);
struct gsm_bts *gsm_bts_by_lac(struct gsm_network *net, unsigned int lac,
				struct gsm_bts *start_bts);

extern void *tall_bsc_ctx;
extern int ipacc_rtp_direct;

/* this actaully refers to the IPA transport, not the BTS model */
static inline int is_ipaccess_bts(struct gsm_bts *bts)
{
	switch (bts->type) {
	case GSM_BTS_TYPE_NANOBTS:
	case GSM_BTS_TYPE_OSMOBTS:
		return 1;
	default:
		break;
	}
	return 0;
}

static inline int is_sysmobts_v2(struct gsm_bts *bts)
{
	switch (bts->type) {
	case GSM_BTS_TYPE_OSMOBTS:
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

static inline int is_nokia_bts(struct gsm_bts *bts)
{
	switch (bts->type) {
	case GSM_BTS_TYPE_NOKIA_SITE:
		return 1;
	default:
		break;
	}

	return 0;
}

static inline int is_e1_bts(struct gsm_bts *bts)
{
	switch (bts->type) {
	case GSM_BTS_TYPE_BS11:
	case GSM_BTS_TYPE_RBS2000:
	case GSM_BTS_TYPE_NOKIA_SITE:
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

enum bts_gprs_mode bts_gprs_mode_parse(const char *arg, int *valid);
const char *bts_gprs_mode_name(enum bts_gprs_mode mode);
int bts_gprs_mode_is_compat(struct gsm_bts *bts, enum bts_gprs_mode mode);

int gsm48_ra_id_by_bts(uint8_t *buf, struct gsm_bts *bts);
void gprs_ra_id_by_bts(struct gprs_ra_id *raid, struct gsm_bts *bts);
struct gsm_meas_rep *lchan_next_meas_rep(struct gsm_lchan *lchan);

int gsm_btsmodel_set_feature(struct gsm_bts_model *model, enum gsm_bts_features feat);
int gsm_bts_model_register(struct gsm_bts_model *model);

struct gsm_subscriber_connection *bsc_subscr_con_allocate(struct gsm_lchan *lchan);
void bsc_subscr_con_free(struct gsm_subscriber_connection *conn);

struct gsm_subscriber_connection *msc_subscr_con_allocate(struct gsm_network *network);
void msc_subscr_con_free(struct gsm_subscriber_connection *conn);

struct gsm_bts *gsm_bts_alloc_register(struct gsm_network *net,
					enum gsm_bts_type type,
					uint8_t bsic);

void set_ts_e1link(struct gsm_bts_trx_ts *ts, uint8_t e1_nr,
		   uint8_t e1_ts, uint8_t e1_ts_ss);

void gsm_trx_lock_rf(struct gsm_bts_trx *trx, int locked);
bool gsm_btsmodel_has_feature(struct gsm_bts_model *model, enum gsm_bts_features feat);
struct gsm_bts_trx *gsm_bts_trx_by_nr(struct gsm_bts *bts, int nr);
int gsm_bts_trx_set_system_infos(struct gsm_bts_trx *trx);
int gsm_bts_set_system_infos(struct gsm_bts *bts);

/* generic E1 line operations for all ISDN-based BTS. */
extern struct e1inp_line_ops bts_isdn_e1inp_line_ops;

extern const struct value_string bts_type_names[_NUM_GSM_BTS_TYPE+1];
extern const struct value_string bts_type_descs[_NUM_GSM_BTS_TYPE+1];

/* control interface handling */
int bsc_base_ctrl_cmds_install(void);
int msc_ctrl_cmds_install(void);

/* dependency handling */
void bts_depend_mark(struct gsm_bts *bts, int dep);
void bts_depend_clear(struct gsm_bts *bts, int dep);
int bts_depend_check(struct gsm_bts *bts);
int bts_depend_is_depedency(struct gsm_bts *base, struct gsm_bts *other);

int gsm_bts_get_radio_link_timeout(const struct gsm_bts *bts);
void gsm_bts_set_radio_link_timeout(struct gsm_bts *bts, int value);

#endif /* _GSM_DATA_H */
