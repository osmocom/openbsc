#ifndef _GPRS_SGSN_H
#define _GPRS_SGSN_H

#include <stdint.h>
#include <netinet/in.h>

#include <osmocom/core/timer.h>

#include <osmocom/gsm/gsm48.h>

#include <osmocom/crypt/gprs_cipher.h>
#include <osmocom/gsm/protocol/gsm_23_003.h>

#include <openbsc/gsm_data.h>

#define GSM_EXTENSION_LENGTH 15
#define GSM_APN_LENGTH 102

struct gprs_llc_lle;
struct ctrl_handle;
struct gprs_subscr;

enum gsm48_gsm_cause;

/* TS 04.08 4.1.3.3 GMM mobility management states on the network side */
enum gprs_gmm_state {
	GMM_DEREGISTERED,		/* 4.1.3.3.1.1 */
	GMM_COMMON_PROC_INIT,		/* 4.1.3.3.1.2 */
	GMM_REGISTERED_NORMAL,		/* 4.1.3.3.2.1 */
	GMM_REGISTERED_SUSPENDED,	/* 4.1.3.3.2.2 */
	GMM_DEREGISTERED_INIT,		/* 4.1.3.3.1.4 */
};

/* TS 23.060 6.1.1 and 6.1.2 Mobility management states A/Gb and Iu mode */
enum gprs_pmm_state {
	PMM_DETACHED,
	PMM_CONNECTED,
	PMM_IDLE,
	MM_IDLE,
	MM_READY,
	MM_STANDBY,
};

enum gprs_mm_ctr {
	GMM_CTR_PKTS_SIG_IN,
	GMM_CTR_PKTS_SIG_OUT,
	GMM_CTR_PKTS_UDATA_IN,
	GMM_CTR_PKTS_UDATA_OUT,
	GMM_CTR_BYTES_UDATA_IN,
	GMM_CTR_BYTES_UDATA_OUT,
	GMM_CTR_PDP_CTX_ACT,
	GMM_CTR_SUSPEND,
	GMM_CTR_PAGING_PS,
	GMM_CTR_PAGING_CS,
	GMM_CTR_RA_UPDATE,
};

enum gprs_pdp_ctx {
	PDP_CTR_PKTS_UDATA_IN,
	PDP_CTR_PKTS_UDATA_OUT,
	PDP_CTR_BYTES_UDATA_IN,
	PDP_CTR_BYTES_UDATA_OUT,
};

enum gprs_t3350_mode {
	GMM_T3350_MODE_NONE,
	GMM_T3350_MODE_ATT,
	GMM_T3350_MODE_RAU,
	GMM_T3350_MODE_PTMSI_REALL,
};

/* Authorization/ACL handling */
enum sgsn_auth_state {
	SGSN_AUTH_UNKNOWN,
	SGSN_AUTH_AUTHENTICATE,
	SGSN_AUTH_UMTS_RESYNC,
	SGSN_AUTH_ACCEPTED,
	SGSN_AUTH_REJECTED
};

#define MS_RADIO_ACCESS_CAPA

enum sgsn_ggsn_lookup_state {
	SGSN_GGSN_2DIGIT,
	SGSN_GGSN_3DIGIT,
};

struct sgsn_ggsn_lookup {
	int state;

	struct sgsn_mm_ctx *mmctx;

	/* APN string */
	char apn_str[GSM_APN_LENGTH];

	/* the original data */
	struct msgb *orig_msg;
	struct tlv_parsed tp;

	/* for dealing with re-transmissions */
	uint8_t nsapi;
	uint8_t sapi;
	uint8_t ti;
};

enum sgsn_ran_type {
	/* GPRS/EDGE via Gb */
	MM_CTX_T_GERAN_Gb,
	/* UMTS via Iu */
	MM_CTX_T_UTRAN_Iu,
	/* GPRS/EDGE via Iu */
	MM_CTX_T_GERAN_Iu,
};

struct service_info {
	uint8_t type;
	uint16_t pdp_status;
};

struct ue_conn_ctx;

/* According to TS 03.60, Table 5: SGSN MM and PDP Contexts */
/* Extended by 3GPP TS 23.060, Table 6: SGSN MM and PDP Contexts */
struct sgsn_mm_ctx {
	struct llist_head	list;

	enum sgsn_ran_type	ran_type;

	char 			imsi[GSM23003_IMSI_MAX_DIGITS+1];
	enum gprs_gmm_state	gmm_state;
	enum gprs_pmm_state	pmm_state;	/* Iu: page when in PMM-IDLE mode */
	uint32_t 		p_tmsi;
	uint32_t 		p_tmsi_old;	/* old P-TMSI before new is confirmed */
	uint32_t 		p_tmsi_sig;
	char 			imei[GSM23003_IMEISV_NUM_DIGITS+1];
	/* Opt: Software Version Numbber / TS 23.195 */
	char 			msisdn[GSM_EXTENSION_LENGTH];
	struct gprs_ra_id	ra;
	struct {
		uint16_t		cell_id;	/* Gb only */
		uint32_t		cell_id_age;	/* Gb only */
		uint8_t			radio_prio_sms;

		/* Additional bits not present in the GSM TS */
		uint16_t		nsei;
		uint16_t		bvci;
		struct gprs_llc_llme	*llme;
		uint32_t		tlli;
		uint32_t		tlli_new;
	} gb;
	struct {
		int			new_key;
		uint16_t		sac;		/* Iu: Service Area Code */
		uint32_t		sac_age;	/* Iu: Service Area Code age */
		/* CSG ID */
		/* CSG Membership */
		/* Access Mode */
		/* Seelected CN Operator ID (TS 23.251) */
		/* CSG Subscription Data */
		/* LIPA Allowed */
		/* Voice Support Match Indicator */
		struct ue_conn_ctx	*ue_ctx;
		struct service_info	service;
	} iu;
	/* VLR number */
	uint32_t		new_sgsn_addr;
	/* Authentication Triplet */
	struct gsm_auth_tuple	auth_triplet;
	/* Kc */
	/* Iu: CK, IK, KSI */
	/* CKSN */
	enum gprs_ciph_algo	ciph_algo;
	/* Auth & Ciphering Request reference from 3GPP TS 24.008 § 10.5.5.19: */
	uint8_t ac_ref_nr_used;

	struct {
		uint8_t	len;
		uint8_t	buf[50];	/* GSM 04.08 10.5.5.12a, extended in TS 24.008 */
	} ms_radio_access_capa;
	/* Supported Codecs (SRVCC) */
	struct {
		uint8_t	len;
		uint8_t	buf[8];		/* GSM 04.08 10.5.5.12, extended in TS 24.008 */
	} ms_network_capa;
	/* UE Netowrk Capability (E-UTRAN) */
	uint16_t		drx_parms;
	/* Active Time value for PSM */
	int			mnrg;	/* MS reported to HLR? */
	int			ngaf;	/* MS reported to MSC/VLR? */
	int			ppf;	/* paging for GPRS + non-GPRS? */
	/* Subscribed Charging Characteristics */
	/* Trace Reference */
	/* Trace Type */
	/* Trigger ID */
	/* OMC Identity */
	/* SMS Parameters */
	int			recovery;
	/* Access Restriction */
	/* GPRS CSI (CAMEL) */
	/* MG-CSI (CAMEL) */
	/* Subscribed UE-AMBR */
	/* UE-AMBR */
	/* APN Subscribed */

	struct llist_head	pdp_list;

	struct rate_ctr_group	*ctrg;
	struct osmo_timer_list	timer;
	unsigned int		T;		/* Txxxx number */
	unsigned int		num_T_exp;	/* number of consecutive T expirations */

	enum gprs_t3350_mode	t3350_mode;
	uint8_t			t3370_id_type;
	uint8_t			pending_req;	/* the request's message type */
	/* TODO: There isn't much semantic difference between t3350_mode
	 * (refers to the timer) and pending_req (refers to the procedure),
	 * where mm->T == 3350 => mm->t3350_mode == f(mm->pending_req). Check
	 * whether one of them can be dropped. */

	enum sgsn_auth_state	auth_state;
	int			is_authenticated;

	/* the string representation of the current hlr */
	char 			hlr[GSM_EXTENSION_LENGTH];

	/* the current GGSN look-up operation */
	struct sgsn_ggsn_lookup *ggsn_lookup;

	struct gprs_subscr	*subscr;
};

#define LOGMMCTXP(level, mm, fmt, args...) \
	LOGP(DMM, level, "MM(%s/%08x) " fmt, (mm) ? (mm)->imsi : "---", \
	     (mm) ? (mm)->p_tmsi : GSM_RESERVED_TMSI, ## args)

/* look-up a SGSN MM context based on TLLI + RAI */
struct sgsn_mm_ctx *sgsn_mm_ctx_by_tlli(uint32_t tlli,
					const struct gprs_ra_id *raid);
struct sgsn_mm_ctx *sgsn_mm_ctx_by_ptmsi(uint32_t tmsi);
struct sgsn_mm_ctx *sgsn_mm_ctx_by_imsi(const char *imsi);
struct sgsn_mm_ctx *sgsn_mm_ctx_by_ue_ctx(const void *uectx);

/* look-up by matching TLLI and P-TMSI (think twice before using this) */
struct sgsn_mm_ctx *sgsn_mm_ctx_by_tlli_and_ptmsi(uint32_t tlli,
					const struct gprs_ra_id *raid);

/* Allocate a new SGSN MM context */
struct sgsn_mm_ctx *sgsn_mm_ctx_alloc_gb(uint32_t tlli,
					const struct gprs_ra_id *raid);
struct sgsn_mm_ctx *sgsn_mm_ctx_alloc_iu(void *uectx);

void sgsn_mm_ctx_cleanup_free(struct sgsn_mm_ctx *ctx);

struct sgsn_ggsn_ctx *sgsn_mm_ctx_find_ggsn_ctx(struct sgsn_mm_ctx *mmctx,
						struct tlv_parsed *tp,
						enum gsm48_gsm_cause *gsm_cause,
						char *apn_str);

enum pdp_ctx_state {
	PDP_STATE_NONE,
	PDP_STATE_CR_REQ,
	PDP_STATE_CR_CONF,

	/* 04.08 / Figure 6.2 / 6.1.2.2 */
	PDP_STATE_INACT_PEND,
	PDP_STATE_INACTIVE = PDP_STATE_NONE,
};

enum pdp_type {
	PDP_TYPE_NONE,
	PDP_TYPE_ETSI_PPP,
	PDP_TYPE_IANA_IPv4,
	PDP_TYPE_IANA_IPv6,
};

struct sgsn_pdp_ctx {
	struct llist_head	list;	/* list_head for mmctx->pdp_list */
	struct llist_head	g_list;	/* list_head for global list */
	struct sgsn_mm_ctx	*mm;	/* back pointer to MM CTX */
	int			destroy_ggsn; /* destroy it on destruction */
	struct sgsn_ggsn_ctx	*ggsn;	/* which GGSN serves this PDP */
	struct rate_ctr_group	*ctrg;

	//unsigned int		id;
	struct pdp_t		*lib;	/* pointer to libgtp PDP ctx */
	enum pdp_ctx_state	state;
	enum pdp_type		type;
	uint32_t		address;
	char 			*apn_subscribed;
	//char 			*apn_used;
	uint16_t		nsapi;	/* SNDCP */
	uint16_t		sapi;	/* LLC */
	uint8_t			ti;	/* transaction identifier */
	int			vplmn_allowed;
	uint32_t		qos_profile_subscr;
	//uint32_t		qos_profile_req;
	//uint32_t		qos_profile_neg;
	uint8_t			radio_prio;
	//uint32_t		charging_id;

	struct osmo_timer_list	timer;
	unsigned int		T;		/* Txxxx number */
	unsigned int		num_T_exp;	/* number of consecutive T expirations */

	struct osmo_timer_list	cdr_timer;	/* CDR record wird timer */
	struct timespec		cdr_start;	/* The start of the CDR */
	uint64_t		cdr_bytes_in;
	uint64_t		cdr_bytes_out;
	uint32_t		cdr_charging_id;
};

#define LOGPDPCTXP(level, pdp, fmt, args...) \
	LOGP(DGPRS, level, "PDP(%s/%u) " \
	     fmt, (pdp)->mm ? (pdp)->mm->imsi : "---", (pdp)->ti, ## args)

/* look up PDP context by MM context and NSAPI */
struct sgsn_pdp_ctx *sgsn_pdp_ctx_by_nsapi(const struct sgsn_mm_ctx *mm,
					   uint8_t nsapi);
/* look up PDP context by MM context and transaction ID */
struct sgsn_pdp_ctx *sgsn_pdp_ctx_by_tid(const struct sgsn_mm_ctx *mm,
					 uint8_t tid);

struct sgsn_pdp_ctx *sgsn_pdp_ctx_alloc(struct sgsn_mm_ctx *mm,
					uint8_t nsapi);
void sgsn_pdp_ctx_terminate(struct sgsn_pdp_ctx *pdp);
void sgsn_pdp_ctx_free(struct sgsn_pdp_ctx *pdp);


struct sgsn_ggsn_ctx {
	struct llist_head list;
	uint32_t id;
	unsigned int gtp_version;
	struct in_addr remote_addr;
	int remote_restart_ctr;
	struct gsn_t *gsn;
};
struct sgsn_ggsn_ctx *sgsn_ggsn_ctx_alloc(uint32_t id);
void sgsn_ggsn_ctx_free(struct sgsn_ggsn_ctx *ggc);
struct sgsn_ggsn_ctx *sgsn_ggsn_ctx_by_id(uint32_t id);
struct sgsn_ggsn_ctx *sgsn_ggsn_ctx_by_addr(struct in_addr *addr);
struct sgsn_ggsn_ctx *sgsn_ggsn_ctx_find_alloc(uint32_t id);

struct apn_ctx {
	struct llist_head list;
	struct sgsn_ggsn_ctx *ggsn;
	char *name;
	char *imsi_prefix;
	char *description;
};

struct apn_ctx *sgsn_apn_ctx_find_alloc(const char *name, const char *imsi_prefix);
void sgsn_apn_ctx_free(struct apn_ctx *actx);
struct apn_ctx *sgsn_apn_ctx_by_name(const char *name, const char *imsi_prefix);
struct apn_ctx *sgsn_apn_ctx_match(const char *name, const char *imsi_prefix);

extern struct llist_head sgsn_mm_ctxts;
extern struct llist_head sgsn_ggsn_ctxts;
extern struct llist_head sgsn_apn_ctxts;
extern struct llist_head sgsn_pdp_ctxts;

uint32_t sgsn_alloc_ptmsi(void);
void sgsn_inst_init(void);

/* High-level function to be called in case a GGSN has disappeared or
 * ottherwise lost state (recovery procedure) */
int drop_all_pdp_for_ggsn(struct sgsn_ggsn_ctx *ggsn);

char *gprs_pdpaddr2str(uint8_t *pdpa, uint8_t len);

/*
 * ctrl interface related work
 */
struct gsm_network;
struct ctrl_handle *sgsn_controlif_setup(struct gsm_network *,
					 const char *bind_addr, uint16_t port);
int sgsn_ctrl_cmds_install(void);

/*
 * Authorization/ACL handling
 */
struct imsi_acl_entry {
	struct llist_head list;
	char imsi[16+1];
};

/* see GSM 09.02, 17.7.1, PDP-Context and GPRSSubscriptionData */
/* see GSM 09.02, B.1, gprsSubscriptionData */
struct sgsn_subscriber_pdp_data {
	struct llist_head	list;

	unsigned int		context_id;
	uint16_t		pdp_type;
	char			apn_str[GSM_APN_LENGTH];
	uint8_t			qos_subscribed[20];
	size_t			qos_subscribed_len;
	uint8_t			pdp_charg[2];
	bool			has_pdp_charg;
};

struct sgsn_subscriber_data {
	struct sgsn_mm_ctx	*mm;
	struct gsm_auth_tuple	auth_triplets[5];
	int			auth_triplets_updated;
	struct llist_head	pdp_list;
	int			error_cause;

	uint8_t			msisdn[9];
	size_t			msisdn_len;

	uint8_t			hlr[9];
	size_t			hlr_len;

	uint8_t			pdp_charg[2];
	bool			has_pdp_charg;
};

#define SGSN_ERROR_CAUSE_NONE (-1)

#define LOGGSUBSCRP(level, subscr, fmt, args...) \
	LOGP(DGPRS, level, "SUBSCR(%s) " fmt, \
	     (subscr) ? (subscr)->imsi : "---", \
	     ## args)

struct sgsn_config;
struct sgsn_instance;
extern const struct value_string *sgsn_auth_state_names;

void sgsn_auth_init(void);
struct imsi_acl_entry *sgsn_acl_lookup(const char *imsi, struct sgsn_config *cfg);
int sgsn_acl_add(const char *imsi, struct sgsn_config *cfg);
int sgsn_acl_del(const char *imsi, struct sgsn_config *cfg);
/* Request authorization */
int sgsn_auth_request(struct sgsn_mm_ctx *mm);
enum sgsn_auth_state sgsn_auth_state(struct sgsn_mm_ctx *mm);
void sgsn_auth_update(struct sgsn_mm_ctx *mm);
struct gsm_auth_tuple *sgsn_auth_get_tuple(struct sgsn_mm_ctx *mmctx,
					   unsigned key_seq);

/*
 * GPRS subscriber data
 */
#define GPRS_SUBSCRIBER_FIRST_CONTACT	0x00000001
#define GPRS_SUBSCRIBER_UPDATE_AUTH_INFO_PENDING	(1 << 16)
#define GPRS_SUBSCRIBER_UPDATE_LOCATION_PENDING		(1 << 17)
#define GPRS_SUBSCRIBER_CANCELLED			(1 << 18)
#define GPRS_SUBSCRIBER_ENABLE_PURGE			(1 << 19)

#define GPRS_SUBSCRIBER_UPDATE_PENDING_MASK ( \
		GPRS_SUBSCRIBER_UPDATE_LOCATION_PENDING | \
		GPRS_SUBSCRIBER_UPDATE_AUTH_INFO_PENDING  \
)

int gprs_subscr_init(struct sgsn_instance *sgi);
int gprs_subscr_request_update_location(struct sgsn_mm_ctx *mmctx);
int gprs_subscr_request_auth_info(struct sgsn_mm_ctx *mmctx,
				  const uint8_t *auts,
				  const uint8_t *auts_rand);
int gprs_subscr_auth_sync(struct gprs_subscr *subscr,
			  const uint8_t *auts, const uint8_t *auts_rand);
void gprs_subscr_cleanup(struct gprs_subscr *subscr);
struct gprs_subscr *gprs_subscr_get_or_create(const char *imsi);
struct gprs_subscr *gprs_subscr_get_or_create_by_mmctx( struct sgsn_mm_ctx *mmctx);
struct gprs_subscr *gprs_subscr_get_by_imsi(const char *imsi);
void gprs_subscr_cancel(struct gprs_subscr *subscr);
void gprs_subscr_update(struct gprs_subscr *subscr);
void gprs_subscr_update_auth_info(struct gprs_subscr *subscr);
int gprs_subscr_rx_gsup_message(struct msgb *msg);

/* Called on subscriber data updates */
void sgsn_update_subscriber_data(struct sgsn_mm_ctx *mmctx);

int gprs_sndcp_vty_init(void);
struct sgsn_instance;
int sgsn_gtp_init(struct sgsn_instance *sgi);

void sgsn_rate_ctr_init();

#endif /* _GPRS_SGSN_H */
