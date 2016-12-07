#pragma once

#include <stdint.h>
#include <osmocom/core/linuxlist.h>
#include <osmocom/core/fsm.h>
#include <osmocom/gsm/protocol/gsm_23_003.h>
#include <osmocom/gsm/gsm23003.h>
#include <openbsc/gsm_data.h>
// for GSM_NAME_LENGTH
#include <openbsc/gsm_subscriber.h>

/* from 3s to 10s */
#define GSM_29002_TIMER_S	10
/* from 15s to 30s */
#define GSM_29002_TIMER_M	30
/* from 1min to 10min */
#define GSM_29002_TIMER_ML	(10*60)
/* from 28h to 38h */
#define GSM_29002_TIMER_L	(32*60*60)


/* VLR subscriber authentication state */
enum vlr_sub_auth_state {
	/* subscriber needs to be autenticated */
	VLR_SUB_AS_NEEDS_AUTH,
	/* waiting for AuthInfo from HLR/AUC */
	VLR_SUB_AS_NEEDS_AUTH_WAIT_AI,
	/* waiting for response from subscriber */
	VLR_SUB_AS_WAIT_RESP,
	/* successfully authenticated */
	VLR_SUB_AS_AUTHENTICATED,
	/* subscriber needs re-sync */
	VLR_SUB_AS_NEEDS_RESYNC,
	/* waiting for AuthInfo with ReSync */
	VLR_SUB_AS_NEEDS_AUTH_WAIT_SAI_RESYNC,
	/* waiting for response from subscr, resync case */
	VLR_SUB_AS_WAIT_RESP_RESYNC,
	/* waiting for IMSI from subscriber */
	VLR_SUB_AS_WAIT_ID_IMSI,
	/* authentication has failed */
	VLR_SUB_AS_AUTH_FAILED,
};

enum vlr_lu_event {
	VLR_ULA_E_UPDATE_LA,	/* Initial trigger (LU from MS) */
	VLR_ULA_E_SEND_ID_ACK,	/* Result of Send-ID from PVLR */
	VLR_ULA_E_SEND_ID_NACK,	/* Result of Send-ID from PVLR */
	VLR_ULA_E_AUTH_RES,	/* Result of auth procedure */
	VLR_ULA_E_ID_IMSI,	/* IMSI recieved from MS */
	VLR_ULA_E_ID_IMEI,	/* IMEI received from MS */
	VLR_ULA_E_ID_IMEISV,	/* IMEISV received from MS */
	VLR_ULA_E_HLR_LU_RES,	/* HLR UpdateLocation result */
	VLR_ULA_E_UPD_HLR_COMPL,/* UpdatE_HLR_VLR result */
	VLR_ULA_E_LU_COMPL_TERM,/* Location_Update_Completion_VLR result */
	VLR_ULA_E_NEW_TMSI_ACK,	/* TMSI Reallocation Complete */
};

enum vlr_sub_security_context {
	VLR_SEC_CTX_NONE,
	VLR_SEC_CTX_GSM,
	VLR_SEC_CTX_UMTS,
};

enum vlr_lu_type {
	VLR_LU_TYPE_PERIODIC,
	VLR_LU_TYPE_IMSI_ATTACH,
	VLR_LU_TYPE_REGULAR,
};

#define OSMO_LBUF_DECL(name, xlen) 		\
	struct {				\
		uint8_t buf[xlen];		\
		size_t len;			\
	} name

struct sgsn_mm_ctx;
struct vlr_instance;

/* The VLR subscriber is the part of the GSM subscriber state in VLR (CS) or
 * SGSN (PS), particularly while interacting with the HLR via GSUP */
struct vlr_subscriber {
	struct llist_head list;
	struct vlr_instance *vlr;

	/* Data from HLR */                             /* 3GPP TS 23.008 */
	char imsi[GSM23003_IMSI_MAX_DIGITS+1];		/* 2.1.1.1 */
	char msisdn[15+1];				/* 2.1.2 */
	OSMO_LBUF_DECL(hlr, 16);			/* 2.4.7 */
	uint32_t periodic_lu_timer;			/* 2.4.24 */
	uint32_t age_indicator;				/* 2.17.1 */
	char name[GSM_NAME_LENGTH];			/* proprietary */

	/* Authentication Data */
	struct gsm_auth_tuple auth_tuples[5];		/* 2.3.1-2.3.4 */
	struct gsm_auth_tuple *last_tuple;
	enum vlr_sub_security_context sec_ctx;

	/* Data local to VLR is below */
	uint32_t tmsi;					/* 2.1.4 */

	/* some redundancy in information below? */
	struct osmo_cell_global_id cgi;			/* 2.4.16 */
	uint16_t lac;					/* 2.4.2 */

	char imeisv[GSM23003_IMEISV_NUM_DIGITS+1];	/* 2.2.3 */
	char imei[GSM23003_IMEISV_NUM_DIGITS+1];	/* 2.1.9 */
	bool imsi_detached_flag;			/* 2.7.1 */
	bool conf_by_radio_contact_ind;			/* 2.7.4.1 */
	bool sub_dataconf_by_hlr_ind;			/* 2.7.4.2 */
	bool loc_conf_in_hlr_ind;			/* 2.7.4.3 */
	bool dormant_ind;				/* 2.7.8 */
	bool cancel_loc_rx;				/* 2.7.8A */
	bool ms_not_reachable_flag;			/* 2.10.2 (MNRF) */
	bool la_allowed;

	uint32_t flags;
	int auth_error_cause;
	int auth_tuples_updated;
	int authorized;
	int use_count;
	time_t expire_lu;	/* FIXME: overlap with periodic_lu_timer/age_indicator */

	struct osmo_fsm_inst *lu_fsm;
	struct osmo_fsm_inst *auth_fsm;
	struct osmo_fsm_inst *proc_arq_fsm;

	void *msc_conn_ref;

	/* PS (SGSN) specific parts */
	struct {
		struct llist_head pdp_list;
		uint8_t rac;
		uint8_t sac;
		struct gprs_mm_ctx *mmctx;
	} ps;
	/* VLR specific parts */
	struct {
		/* pending requests */
		int is_paging;
		struct llist_head requests;
	} cs;
};

struct vlr_ops {
	/* encode + transmit an AUTH REQ towards the MS */
	int (*tx_auth_req)(void *msc_conn_ref,
			   struct gsm_auth_tuple *at);
	/* encode + transmit an AUTH REJECT towards the MS */
	int (*tx_auth_rej)(void *msc_conn_ref);

	/* encode + transmit an IDENTITY REQUEST towards the MS */
	int (*tx_id_req)(void *msc_conn_ref, uint8_t mi_type);
	int (*tx_lu_ack)(void *msc_conn_ref);
	int (*tx_lu_rej)(void *msc_conn_ref, uint8_t cause);

	int (*set_ciph_mode)(void *msc_conn_ref);

	/* notify MSC/SGSN that the subscriber data in VLR has been updated */
	void (*subscr_update)(struct vlr_subscriber *vsub);
	/* notify MSC/SGSN that the given subscriber has been associated
	 * with this msc_conn_ref */
	void (*subscr_assoc)(void *msc_conn_ref, struct vlr_subscriber *vsub);
};

enum vlr_timer {
	VLR_T_3250,
	VLR_T_3260,
	VLR_T_3270,
	_NUM_VLR_TIMERS
};

/* An instance of the VLR codebase */
struct vlr_instance {
	struct llist_head subscribers;
	struct llist_head operations;
	struct gprs_gsup_client *gsup_client;
	struct vlr_ops ops;
	struct {
		bool retrieve_imeisv;
		bool alloc_tmsi;
		bool check_imei_rqd;
		bool auth_reuse_old_sets;
		bool parq_retrieve_imsi;
		bool is_ps;
		uint32_t timer[_NUM_VLR_TIMERS];
	} cfg;
};

struct osmo_fsm_inst *
vlr_loc_update(struct osmo_fsm_inst *parent, uint32_t parent_term,
		struct vlr_instance *vlr, void *msc_conn_ref,
		enum vlr_lu_type type, uint32_t tmsi, const char *imsi,
		const struct osmo_location_area_id *old_lai,
		const struct osmo_location_area_id *new_lai);

/* Process_Access_Request (CM SERV REQ / PAGING RESP) */
struct osmo_fsm_inst *
vlr_process_access_req(struct osmo_fsm_inst *parent, uint32_t parent_term,
			struct vlr_instance *vlr, void *msc_conn_ref, uint32_t tmsi,
		const char *imsi, const struct osmo_location_area_id *lai);

/* tell the VLR that the subscriber connection is gone */
int vlr_sub_disconnected(struct vlr_subscriber *vsub);

int vlr_sub_rx_id_resp(struct vlr_subscriber *vsub, const uint8_t *mi, size_t mi_len);
int vlr_sub_rx_auth_resp(struct vlr_subscriber *vsub, bool is_r99, bool is_utran,
			 const uint8_t *res, uint8_t res_len);
int vlr_sub_rx_auth_fail(struct vlr_subscriber *vsub, const uint8_t *auts);
int vlr_sub_tx_auth_fail_rep(struct vlr_subscriber *vsub);

struct vlr_instance *
vlr_init(void *ctx, const struct vlr_ops *ops, const char *addr_str, uint16_t port);


/* internal use only */

struct osmo_fsm_inst *sub_pres_vlr_fsm_start(struct osmo_fsm_inst *parent,
					     struct vlr_subscriber *vsub,
					     uint32_t term_event);
struct osmo_fsm_inst *
upd_hlr_vlr_proc_start(struct osmo_fsm_inst *parent,
		        struct vlr_subscriber *vsub,
			uint32_t parent_event);

struct osmo_fsm_inst *
lu_compl_vlr_proc_start(struct osmo_fsm_inst *parent,
			struct vlr_subscriber *vsub,
			void *msc_conn_ref,
			uint32_t term_event);


const char *vlr_sub_name(struct vlr_subscriber *vsub);
struct vlr_subscriber *
vlr_subscr_find_by_imsi(struct vlr_instance *vlr, const char *imsi);
struct vlr_subscriber *
vlr_subscr_find_by_tmsi(struct vlr_instance *vlr, uint32_t tmsi);
struct vlr_subscriber *vlr_sub_alloc(struct vlr_instance *vlr);
void vlr_sub_cleanup(struct vlr_subscriber *vsub);
void vlr_sub_cancel(struct vlr_subscriber *vsub);
int vlr_sub_alloc_tmsi(struct vlr_subscriber *vsub);

uint32_t vlr_timer(struct vlr_instance *vlr, uint32_t timer);



/* Process Acccess Request FSM */

enum vlr_proc_arq_result {
	VLR_PR_ARQ_RES_SYSTEM_FAILURE,
	VLR_PR_ARQ_RES_ILLEGAL_SUBSCR,
	VLR_PR_ARQ_RES_UNIDENT_SUBSCR,
	VLR_PR_ARQ_RES_ROAMING_NOTALLOWED,
	VLR_PR_ARQ_RES_ILLEGAL_EQUIP,
	VLR_PR_ARQ_RES_UNKNOWN_ERROR,
	VLR_PR_ARQ_RES_PASSED,
};

enum proc_arq_vlr_event {
	PR_ARQ_E_START,
	PR_ARQ_E_ID_IMSI,
	PR_ARQ_E_AUTH_RES,
	PR_ARQ_E_UPD_LOC_RES,
	PR_ARQ_E_TRACE_RES,
	PR_ARQ_E_IMEI_RES,
	PR_ARQ_E_PRES_RES,
	PR_ARQ_E_TMSI_ACK,
};

enum vlr_parq_type {
	VLR_PR_ARQ_T_CM_SERV_REQ,
	VLR_PR_ARQ_T_PAGING_RESP,
	/* FIXME: differentiate between services of 24.008 10.5.3.3 */
};

struct osmo_fsm_inst *
vlr_proc_acc_req(struct osmo_fsm_inst *parent, uint32_t parent_term,
		 struct vlr_instance *vlr, void *msc_conn_ref,
		 enum vlr_parq_type type, const uint8_t *mi_lv,
		 const struct osmo_location_area_id *lai);

void vlr_parq_fsm_init(void);
