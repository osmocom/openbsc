#ifndef _GB_PROXY_H
#define _GB_PROXY_H


#include <osmocom/core/msgb.h>

#include <osmocom/gprs/gprs_ns.h>
#include <osmocom/vty/command.h>

#include <sys/types.h>
#include <regex.h>

struct rate_ctr_group;

enum gbproxy_patch_mode {
	GBPROX_PATCH_DEFAULT,
	GBPROX_PATCH_BSSGP,		/*!< BSGGP messages only */
	GBPROX_PATCH_LLC_ATTACH_REQ,	/*!< BSSGP and Attach Request */
	GBPROX_PATCH_LLC_ATTACH,	/*!< BSSGP and Attach Request/Response */
	GBPROX_PATCH_LLC_GMM,		/*!< BSSGP and all GMM msgs */
	GBPROX_PATCH_LLC_GSM,		/*!< BSSGP and all GMM and GSM msgs */
	GBPROX_PATCH_LLC,		/*!< BSSGP and all supported LLC msgs */
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
	int patch_ptmsi;

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

int gbprox_set_patch_filter(struct gbproxy_config *cfg, const char *filter,
		const char **err_msg);
void gbprox_clear_patch_filter(struct gbproxy_config *cfg);

void gbprox_delete_tlli(struct gbproxy_peer *peer,
			       struct gbproxy_tlli_info *tlli_info);
int gbprox_remove_stale_tllis(struct gbproxy_peer *peer, time_t now);
int gbprox_cleanup_peers(struct gbproxy_config *cfg, uint16_t nsei, uint16_t bvci);

struct gbproxy_peer *gbprox_peer_by_nsei(struct gbproxy_config *cfg, uint16_t nsei);

struct gbproxy_tlli_info *gbprox_find_tlli(struct gbproxy_peer *peer,
					   uint32_t tlli);
struct gbproxy_tlli_info *gbprox_find_tlli_by_mi(struct gbproxy_peer *peer,
						 const uint8_t *mi_data,
						 size_t mi_data_len);
struct gbproxy_tlli_info *gbprox_find_tlli_by_sgsn_tlli(
	struct gbproxy_peer *peer,
	uint32_t tlli);
struct gbproxy_tlli_info *gbprox_register_tlli(
	struct gbproxy_peer *peer, uint32_t tlli,
	const uint8_t *imsi, size_t imsi_len, time_t now);
struct gbproxy_peer *gbproxy_peer_alloc(struct gbproxy_config *cfg, uint16_t bvci);
void gbproxy_peer_free(struct gbproxy_peer *peer);

int gbprox_check_imsi(struct gbproxy_peer *peer,
		const uint8_t *imsi, size_t imsi_len);
#endif
