#ifndef _GB_PROXY_H
#define _GB_PROXY_H


#include <osmocom/core/msgb.h>

#include <osmocom/gprs/gprs_ns.h>
#include <osmocom/vty/command.h>

#include <sys/types.h>
#include <regex.h>

struct rate_ctr_group;
struct gprs_gb_parse_context;
struct tlv_parsed;

enum gbproxy_patch_mode {
	GBPROX_PATCH_DEFAULT,
	GBPROX_PATCH_BSSGP,		/*!< BSGGP messages only */
	GBPROX_PATCH_LLC_ATTACH_REQ,	/*!< BSSGP and Attach Request */
	GBPROX_PATCH_LLC_ATTACH,	/*!< BSSGP and Attach Request/Response */
	GBPROX_PATCH_LLC_GMM,		/*!< BSSGP and all GMM msgs */
	GBPROX_PATCH_LLC_GSM,		/*!< BSSGP and all GMM and GSM msgs */
	GBPROX_PATCH_LLC,		/*!< BSSGP and all supported LLC msgs */
};

enum gbproxy_global_ctr {
	GBPROX_GLOB_CTR_INV_BVCI,
	GBPROX_GLOB_CTR_INV_LAI,
	GBPROX_GLOB_CTR_INV_RAI,
	GBPROX_GLOB_CTR_INV_NSEI,
	GBPROX_GLOB_CTR_PROTO_ERR_BSS,
	GBPROX_GLOB_CTR_PROTO_ERR_SGSN,
	GBPROX_GLOB_CTR_NOT_SUPPORTED_BSS,
	GBPROX_GLOB_CTR_NOT_SUPPORTED_SGSN,
	GBPROX_GLOB_CTR_RESTART_RESET_SGSN,
	GBPROX_GLOB_CTR_TX_ERR_SGSN,
	GBPROX_GLOB_CTR_OTHER_ERR,
	GBPROX_GLOB_CTR_PATCH_PEER_ERR,
};

enum gbproxy_peer_ctr {
	GBPROX_PEER_CTR_BLOCKED,
	GBPROX_PEER_CTR_UNBLOCKED,
	GBPROX_PEER_CTR_DROPPED,
	GBPROX_PEER_CTR_INV_NSEI,
	GBPROX_PEER_CTR_TX_ERR,
	GBPROX_PEER_CTR_RAID_PATCHED_BSS,
	GBPROX_PEER_CTR_RAID_PATCHED_SGSN,
	GBPROX_PEER_CTR_APN_PATCHED,
	GBPROX_PEER_CTR_TLLI_PATCHED_BSS,
	GBPROX_PEER_CTR_TLLI_PATCHED_SGSN,
	GBPROX_PEER_CTR_PTMSI_PATCHED_BSS,
	GBPROX_PEER_CTR_PTMSI_PATCHED_SGSN,
	GBPROX_PEER_CTR_PATCH_CRYPT_ERR,
	GBPROX_PEER_CTR_PATCH_ERR,
	GBPROX_PEER_CTR_ATTACH_REQS,
	GBPROX_PEER_CTR_ATTACH_REJS,
	GBPROX_PEER_CTR_TLLI_UNKNOWN,
	GBPROX_PEER_CTR_TLLI_CACHE_SIZE,
};

struct gbproxy_config {
	/* parsed from config file */
	uint16_t nsip_sgsn_nsei;

	/* misc */
	struct gprs_ns_inst *nsi;

	/* Linked list of all Gb peers (except SGSN) */
	struct llist_head bts_peers;

	/* Counter */
	struct rate_ctr_group *ctrg;

	/* force mcc/mnc */
	int core_mnc;
	int core_mcc;
	uint8_t* core_apn;
	size_t core_apn_size;
	char * match_re;
	enum gbproxy_patch_mode patch_mode;
	int tlli_max_age;
	int tlli_max_len;

	/* Experimental config */
	int patch_ptmsi;
	int acquire_imsi;

	/* IMSI checking/matching */
	int check_imsi;
	regex_t imsi_re_comp;

	/* Used to generate identifiers */
	unsigned bss_ptmsi_state;
	unsigned sgsn_tlli_state;
};

struct gbproxy_patch_state {
	int local_mnc;
	int local_mcc;

	/* List of TLLIs for which patching is enabled */
	struct llist_head enabled_tllis;
	int enabled_tllis_count;
};

struct gbproxy_peer {
	struct llist_head list;

	/* point back to the config */
	struct gbproxy_config *cfg;

	/* NSEI of the peer entity */
	uint16_t nsei;

	/* BVCI used for Point-to-Point to this peer */
	uint16_t bvci;
	int blocked;

	/* Routeing Area that this peer is part of (raw 04.08 encoding) */
	uint8_t ra[6];

	/* Counter */
	struct rate_ctr_group *ctrg;

	struct gbproxy_patch_state patch_state;
};

struct gbproxy_tlli_state {
	uint32_t current;
	uint32_t assigned;
	int bss_validated;
	int net_validated;

	uint32_t ptmsi;
};

struct gbproxy_tlli_info {
	struct llist_head list;

	struct gbproxy_tlli_state tlli;
	struct gbproxy_tlli_state sgsn_tlli;

	time_t timestamp;
	uint8_t *mi_data;
	size_t mi_data_len;

	int imsi_acq_pending;
	struct llist_head stored_msgs;

	int enable_patching;
};


/* gb_proxy_vty .c */

int gbproxy_vty_init(void);
int gbproxy_parse_config(const char *config_file, struct gbproxy_config *cfg);


/* gb_proxy.c */
int gbproxy_init_config(struct gbproxy_config *cfg);

/* Main input function for Gb proxy */
int gbprox_rcvmsg(struct gbproxy_config *cfg, struct msgb *msg, uint16_t nsei, uint16_t ns_bvci, uint16_t nsvci);

int gbprox_signal(unsigned int subsys, unsigned int signal,
		  void *handler_data, void *signal_data);

/* Reset all persistent NS-VC's */
int gbprox_reset_persistent_nsvcs(struct gprs_ns_inst *nsi);

void gbprox_reset(struct gbproxy_config *cfg);

/* TLLI state handling */
void gbproxy_delete_tllis(struct gbproxy_peer *peer);
int gbproxy_check_tlli(struct gbproxy_peer *peer, uint32_t tlli);
struct gbproxy_tlli_info *gbprox_find_tlli_by_ptmsi(
	struct gbproxy_peer *peer,
	uint32_t ptmsi);
uint32_t gbproxy_map_tlli(
	uint32_t other_tlli, struct gbproxy_tlli_info *tlli_info, int to_bss);
struct gbproxy_tlli_info *gbproxy_update_tlli_state_ul(
	struct gbproxy_peer *peer, time_t now,
	struct gprs_gb_parse_context *parse_ctx);
struct gbproxy_tlli_info *gbproxy_update_tlli_state_dl(
	struct gbproxy_peer *peer, time_t now,
	struct gprs_gb_parse_context *parse_ctx);
void gbproxy_update_tlli_state_after(
	struct gbproxy_peer *peer, struct gbproxy_tlli_info *tlli_info,
	time_t now, struct gprs_gb_parse_context *parse_ctx);
int gbproxy_remove_stale_tllis(struct gbproxy_peer *peer, time_t now);
void gbproxy_delete_tlli(struct gbproxy_peer *peer,
			 struct gbproxy_tlli_info *tlli_info);

struct gbproxy_tlli_info *gbproxy_register_tlli(
	struct gbproxy_peer *peer, uint32_t tlli,
	const uint8_t *imsi, size_t imsi_len, time_t now);

struct gbproxy_tlli_info *gbproxy_find_tlli(
	struct gbproxy_peer *peer, uint32_t tlli);
struct gbproxy_tlli_info *gbproxy_find_tlli_by_mi(
	struct gbproxy_peer *peer, const uint8_t *mi_data, size_t mi_data_len);
struct gbproxy_tlli_info *gbproxy_find_tlli_by_sgsn_tlli(
	struct gbproxy_peer *peer,
	uint32_t tlli);
struct gbproxy_tlli_info *gbproxy_find_tlli_by_ptmsi(
	struct gbproxy_peer *peer,
	uint32_t ptmsi);

/* needed by gb_proxy_tlli.h */
uint32_t gbproxy_make_bss_ptmsi(struct gbproxy_peer *peer, uint32_t sgsn_ptmsi);
uint32_t gbproxy_make_sgsn_tlli(
	struct gbproxy_peer *peer, struct gbproxy_tlli_info *tlli_info,
	uint32_t bss_tlli);
int gbproxy_check_imsi(
	struct gbproxy_peer *peer, const uint8_t *imsi, size_t imsi_len);

/* Message patching */
void gbproxy_patch_bssgp(
	struct msgb *msg, uint8_t *bssgp, size_t bssgp_len,
	struct gbproxy_peer *peer, struct gbproxy_tlli_info *tlli_info,
	int *len_change, struct gprs_gb_parse_context *parse_ctx);

int gbproxy_patch_llc(
	struct msgb *msg, uint8_t *llc, size_t llc_len,
	struct gbproxy_peer *peer, struct gbproxy_tlli_info *tlli_info,
	int *len_change, struct gprs_gb_parse_context *parse_ctx);

int gbproxy_set_patch_filter(
	struct gbproxy_config *cfg, const char *filter, const char **err_msg);
void gbproxy_clear_patch_filter(struct gbproxy_config *cfg);
int gbproxy_check_imsi(
	struct gbproxy_peer *peer, const uint8_t *imsi, size_t imsi_len);

/* Peer handling */
struct gbproxy_peer *gbproxy_peer_by_bvci(
	struct gbproxy_config *cfg, uint16_t bvci);
struct gbproxy_peer *gbproxy_peer_by_nsei(
	struct gbproxy_config *cfg, uint16_t nsei);
struct gbproxy_peer *gbproxy_peer_by_rai(
	struct gbproxy_config *cfg, const uint8_t *ra);
struct gbproxy_peer *gbproxy_peer_by_lai(
	struct gbproxy_config *cfg, const uint8_t *la);
struct gbproxy_peer *gbproxy_peer_by_bssgp_tlv(
	struct gbproxy_config *cfg, struct tlv_parsed *tp);
struct gbproxy_peer *gbproxy_peer_alloc(struct gbproxy_config *cfg, uint16_t bvci);
void gbproxy_peer_free(struct gbproxy_peer *peer);
int gbproxy_cleanup_peers(struct gbproxy_config *cfg, uint16_t nsei, uint16_t bvci);

#endif
