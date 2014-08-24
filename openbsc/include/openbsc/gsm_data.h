#ifndef _GSM_DATA_H
#define _GSM_DATA_H

#include <stdint.h>

#include <osmocom/core/timer.h>
#include <osmocom/core/select.h>

#include <openbsc/rest_octets.h>

/** annotations for msgb ownership */
#define __uses

#define OBSC_NM_W_ACK_CB(__msgb) (__msgb)->cb[3]

struct mncc_sock_state;

#define OBSC_LINKID_CB(__msgb)	(__msgb)->cb[3]

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
	uint8_t rand[16];
	uint8_t sres[4];
	uint8_t kc[8];
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

/* the per subscriber data for lchan */
struct gsm_subscriber_connection {
	struct llist_head entry;

	/* To whom we are allocated at the moment */
	struct gsm_subscriber *subscr;

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
	int put_channel;

	/* bsc structures */
	struct osmo_bsc_sccp_con *sccp_con;

	/* back pointers */
	int in_release;
	struct gsm_lchan *lchan;
	struct gsm_lchan *ho_lchan;
	struct gsm_bts *bts;

	/* for assignment handling */
	struct osmo_timer_list T10;
	struct gsm_lchan *secondary_lchan;

};


#define ROLE_BSC
#include "gsm_data_shared.h"


/* Some statistics of our network */
struct gsmnet_stats {
	struct {
		struct osmo_counter *total;
		struct osmo_counter *no_channel;
	} chreq;
	struct {
		struct osmo_counter *attempted;
		struct osmo_counter *no_channel;	/* no channel available */
		struct osmo_counter *timeout;		/* T3103 timeout */
		struct osmo_counter *completed;	/* HO COMPL received */
		struct osmo_counter *failed;		/* HO FAIL received */
	} handover;
	struct {
		struct osmo_counter *attach;
		struct osmo_counter *normal;
		struct osmo_counter *periodic;
		struct osmo_counter *detach;
	} loc_upd_type;
	struct {
		struct osmo_counter *reject;
		struct osmo_counter *accept;
	} loc_upd_resp;
	struct {
		struct osmo_counter *attempted;
		struct osmo_counter *detached;
		struct osmo_counter *completed;
		struct osmo_counter *expired;
	} paging;
	struct {
		struct osmo_counter *submitted; /* MO SMS submissions */
		struct osmo_counter *no_receiver;
		struct osmo_counter *delivered; /* MT SMS deliveries */
		struct osmo_counter *rp_err_mem;
		struct osmo_counter *rp_err_other;
	} sms;
	struct {
		struct osmo_counter *mo_setup;
		struct osmo_counter *mo_connect_ack;
		struct osmo_counter *mt_setup;
		struct osmo_counter *mt_connect;
	} call;
	struct {
		struct osmo_counter *rf_fail;
		struct osmo_counter *rll_err;
	} chan;
	struct {
		struct osmo_counter *oml_fail;
		struct osmo_counter *rsl_fail;
	} bts;
};

enum gsm_auth_policy {
	GSM_AUTH_POLICY_CLOSED, /* only subscribers authorized in DB */
	GSM_AUTH_POLICY_ACCEPT_ALL, /* accept everyone, even if not authorized in DB */
	GSM_AUTH_POLICY_TOKEN, /* accept first, send token per sms, then revoke authorization */
};

#define GSM_T3101_DEFAULT 10
#define GSM_T3105_DEFAULT 40
#define GSM_T3113_DEFAULT 60
#define GSM_T3122_DEFAULT 10

struct gsm_network {
	/* global parameters */
	uint16_t country_code;
	uint16_t network_code;
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
	struct mncc_sock_state *mncc_state;
	int (*mncc_recv) (struct gsm_network *net, struct msgb *msg);
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

	/* enable the DTXu and DTXd for this network */
	int dtx_enabled;

	enum gsm_chan_t ctype_by_chreq[16];

	/* Use a TCH for handling requests of type paging any */
	int pag_any_tch;

	/* MSC data in case we are a true BSC */
	struct osmo_bsc_data *bsc_data;

	/* subscriber related features */
	int keep_subscr;
	struct gsm_sms_queue *sms_queue;

	/* control interface */
	struct ctrl_handle *ctrl;
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

struct gsm_network *gsm_network_init(uint16_t country_code, uint16_t network_code,
				     int (*mncc_recv)(struct gsm_network *, struct msgb *));
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
	case GSM_BTS_TYPE_OSMO_SYSMO:
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

enum bts_gprs_mode bts_gprs_mode_parse(const char *arg);
const char *bts_gprs_mode_name(enum bts_gprs_mode mode);

int gsm48_ra_id_by_bts(uint8_t *buf, struct gsm_bts *bts);
void gprs_ra_id_by_bts(struct gprs_ra_id *raid, struct gsm_bts *bts);
struct gsm_meas_rep *lchan_next_meas_rep(struct gsm_lchan *lchan);

int gsm_btsmodel_set_feature(struct gsm_bts_model *model, enum gsm_bts_features feat);
int gsm_bts_model_register(struct gsm_bts_model *model);

struct gsm_subscriber_connection *subscr_con_allocate(struct gsm_lchan *lchan);
void subscr_con_free(struct gsm_subscriber_connection *conn);

struct gsm_bts *gsm_bts_alloc_register(struct gsm_network *net,
					enum gsm_bts_type type,
					uint8_t tsc, uint8_t bsic);
void set_ts_e1link(struct gsm_bts_trx_ts *ts, uint8_t e1_nr,
		   uint8_t e1_ts, uint8_t e1_ts_ss);

void gsm_trx_lock_rf(struct gsm_bts_trx *trx, int locked);
int gsm_bts_has_feature(struct gsm_bts *bts, enum gsm_bts_features feat);
struct gsm_bts_trx *gsm_bts_trx_by_nr(struct gsm_bts *bts, int nr);

/* generic E1 line operations for all ISDN-based BTS. */
extern struct e1inp_line_ops bts_isdn_e1inp_line_ops;

extern const struct value_string bts_type_names[_NUM_GSM_BTS_TYPE+1];
extern const struct value_string bts_type_descs[_NUM_GSM_BTS_TYPE+1];

/* control interface handling */
int bsc_base_ctrl_cmds_install(void);
int msc_ctrl_cmds_install(void);

#endif /* _GSM_DATA_H */
