#ifndef _GB_PROXY_H
#define _GB_PROXY_H


#include <osmocom/core/msgb.h>

#include <osmocom/gprs/gprs_ns.h>
#include <osmocom/vty/command.h>

#include <sys/types.h>
#include <regex.h>

#define GBPROXY_INIT_VU_GEN_TX 256

struct rate_ctr_group;
struct gprs_gb_parse_context;
struct tlv_parsed;

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
	GBPROX_PEER_CTR_ATTACH_ACKS,
	GBPROX_PEER_CTR_ATTACH_COMPLS,
	GBPROX_PEER_CTR_RA_UPD_REQS,
	GBPROX_PEER_CTR_RA_UPD_REJS,
	GBPROX_PEER_CTR_RA_UPD_ACKS,
	GBPROX_PEER_CTR_RA_UPD_COMPLS,
	GBPROX_PEER_CTR_GMM_STATUS_BSS,
	GBPROX_PEER_CTR_GMM_STATUS_SGSN,
	GBPROX_PEER_CTR_DETACH_REQS,
	GBPROX_PEER_CTR_DETACH_ACKS,
	GBPROX_PEER_CTR_PDP_ACT_REQS,
	GBPROX_PEER_CTR_PDP_ACT_REJS,
	GBPROX_PEER_CTR_PDP_ACT_ACKS,
	GBPROX_PEER_CTR_PDP_DEACT_REQS,
	GBPROX_PEER_CTR_PDP_DEACT_ACKS,
	GBPROX_PEER_CTR_TLLI_UNKNOWN,
	GBPROX_PEER_CTR_TLLI_CACHE_SIZE,
	GBPROX_PEER_CTR_LAST,
};

enum gbproxy_keep_mode {
	GBPROX_KEEP_NEVER,
	GBPROX_KEEP_REATTACH,
	GBPROX_KEEP_IDENTIFIED,
	GBPROX_KEEP_ALWAYS,
};

enum gbproxy_match_id {
	GBPROX_MATCH_PATCHING,
	GBPROX_MATCH_ROUTING,
	GBPROX_MATCH_LAST
};

struct gbproxy_match {
	int   enable;
	char *re_str;
	regex_t re_comp;
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
	int tlli_max_age;
	int tlli_max_len;

	/* Experimental config */
	int patch_ptmsi;
	int acquire_imsi;
	int route_to_sgsn2;
	uint16_t nsip_sgsn2_nsei;
	enum gbproxy_keep_mode keep_link_infos;

	/* IMSI checking/matching */
	struct gbproxy_match matches[GBPROX_MATCH_LAST];
};

struct gbproxy_patch_state {
	int local_mnc;
	int local_mcc;

	/* List of TLLIs for which patching is enabled */
	struct llist_head logical_links;
	int logical_link_count;
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

struct gbproxy_link_info {
	struct llist_head list;

	struct gbproxy_tlli_state tlli;
	struct gbproxy_tlli_state sgsn_tlli;
	uint32_t sgsn_nsei;

	time_t timestamp;
	uint8_t *imsi;
	size_t imsi_len;

	int imsi_acq_pending;
	struct llist_head stored_msgs;
	unsigned vu_gen_tx_bss;

	int is_deregistered;

	int is_matching[GBPROX_MATCH_LAST];
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

/* TLLI info handling */
void gbproxy_delete_link_infos(struct gbproxy_peer *peer);
struct gbproxy_link_info *gbproxy_update_link_state_ul(
	struct gbproxy_peer *peer, time_t now,
	struct gprs_gb_parse_context *parse_ctx);
struct gbproxy_link_info *gbproxy_update_link_state_dl(
	struct gbproxy_peer *peer, time_t now,
	struct gprs_gb_parse_context *parse_ctx);
int gbproxy_update_link_state_after(
	struct gbproxy_peer *peer, struct gbproxy_link_info *link_info,
	time_t now, struct gprs_gb_parse_context *parse_ctx);
int gbproxy_remove_stale_link_infos(struct gbproxy_peer *peer, time_t now);
void gbproxy_delete_link_info(struct gbproxy_peer *peer,
			 struct gbproxy_link_info *link_info);
void gbproxy_link_info_discard_messages(struct gbproxy_link_info *link_info);

void gbproxy_attach_link_info(struct gbproxy_peer *peer, time_t now,
			      struct gbproxy_link_info *link_info);
void gbproxy_update_link_info(struct gbproxy_link_info *link_info,
			      const uint8_t *imsi, size_t imsi_len);
void gbproxy_detach_link_info(struct gbproxy_peer *peer,
			      struct gbproxy_link_info *link_info);
struct gbproxy_link_info *gbproxy_link_info_alloc( struct gbproxy_peer *peer);

struct gbproxy_link_info *gbproxy_link_info_by_tlli(
	struct gbproxy_peer *peer, uint32_t tlli);
struct gbproxy_link_info *gbproxy_link_info_by_imsi(
	struct gbproxy_peer *peer, const uint8_t *imsi, size_t imsi_len);
struct gbproxy_link_info *gbproxy_link_info_by_any_sgsn_tlli(
	struct gbproxy_peer *peer, uint32_t tlli);
struct gbproxy_link_info *gbproxy_link_info_by_sgsn_tlli(
	struct gbproxy_peer *peer,
	uint32_t tlli, uint32_t sgsn_nsei);
struct gbproxy_link_info *gbproxy_link_info_by_ptmsi(
	struct gbproxy_peer *peer,
	uint32_t ptmsi);

int gbproxy_imsi_matches(
	struct gbproxy_config *cfg,
	enum gbproxy_match_id match_id,
	struct gbproxy_link_info *link_info);
uint32_t gbproxy_map_tlli(
	uint32_t other_tlli, struct gbproxy_link_info *link_info, int to_bss);

/* needed by gb_proxy_tlli.h */
uint32_t gbproxy_make_bss_ptmsi(struct gbproxy_peer *peer, uint32_t sgsn_ptmsi);
uint32_t gbproxy_make_sgsn_tlli(
	struct gbproxy_peer *peer, struct gbproxy_link_info *link_info,
	uint32_t bss_tlli);
void gbproxy_reset_link(struct gbproxy_link_info *link_info);
int gbproxy_check_imsi(
	struct gbproxy_match *match, const uint8_t *imsi, size_t imsi_len);

/* Message patching */
void gbproxy_patch_bssgp(
	struct msgb *msg, uint8_t *bssgp, size_t bssgp_len,
	struct gbproxy_peer *peer, struct gbproxy_link_info *link_info,
	int *len_change, struct gprs_gb_parse_context *parse_ctx);

int gbproxy_patch_llc(
	struct msgb *msg, uint8_t *llc, size_t llc_len,
	struct gbproxy_peer *peer, struct gbproxy_link_info *link_info,
	int *len_change, struct gprs_gb_parse_context *parse_ctx);

int gbproxy_set_patch_filter(
	struct gbproxy_match *match, const char *filter, const char **err_msg);
void gbproxy_clear_patch_filter(struct gbproxy_match *match);

/* Peer handling */
struct gbproxy_peer *gbproxy_peer_by_bvci(
	struct gbproxy_config *cfg, uint16_t bvci);
struct gbproxy_peer *gbproxy_peer_by_nsei(
	struct gbproxy_config *cfg, uint16_t nsei);
struct gbproxy_peer *gbproxy_peer_by_rai(
	struct gbproxy_config *cfg, const uint8_t *ra);
struct gbproxy_peer *gbproxy_peer_by_lai(
	struct gbproxy_config *cfg, const uint8_t *la);
struct gbproxy_peer *gbproxy_peer_by_lac(
	struct gbproxy_config *cfg, const uint8_t *la);
struct gbproxy_peer *gbproxy_peer_by_bssgp_tlv(
	struct gbproxy_config *cfg, struct tlv_parsed *tp);
struct gbproxy_peer *gbproxy_peer_alloc(struct gbproxy_config *cfg, uint16_t bvci);
void gbproxy_peer_free(struct gbproxy_peer *peer);
int gbproxy_cleanup_peers(struct gbproxy_config *cfg, uint16_t nsei, uint16_t bvci);

#endif
