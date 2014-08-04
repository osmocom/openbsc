#ifndef _GB_PROXY_H
#define _GB_PROXY_H


#include <osmocom/core/msgb.h>

#include <osmocom/gprs/gprs_ns.h>
#include <osmocom/vty/command.h>

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
};

struct gbprox_patch_state {
	int local_mnc;
	int local_mcc;

	/* List of TLLIs for which patching is enabled */
	struct llist_head enabled_tllis;
	int enabled_tllis_count;
};

struct gbprox_peer {
	struct llist_head list;

	/* NSEI of the peer entity */
	uint16_t nsei;

	/* BVCI used for Point-to-Point to this peer */
	uint16_t bvci;
	int blocked;

	/* Routeing Area that this peer is part of (raw 04.08 encoding) */
	uint8_t ra[6];

	/* Counter */
	struct rate_ctr_group *ctrg;

	struct gbprox_patch_state patch_state;
};

struct gbprox_tlli_info {
	struct llist_head list;

	uint32_t tlli;
	time_t timestamp;
	uint8_t *mi_data;
	size_t mi_data_len;
};


extern struct gbproxy_config gbcfg;

/* gb_proxy_vty .c */

int gbproxy_vty_init(void);
int gbproxy_parse_config(const char *config_file, struct gbproxy_config *cfg);


/* gb_proxy.c */
int gbproxy_init_config(struct gbproxy_config *cfg);

/* Main input function for Gb proxy */
int gbprox_rcvmsg(struct msgb *msg, uint16_t nsei, uint16_t ns_bvci, uint16_t nsvci);

int gbprox_signal(unsigned int subsys, unsigned int signal,
		  void *handler_data, void *signal_data);

/* Reset all persistent NS-VC's */
int gbprox_reset_persistent_nsvcs(struct gprs_ns_inst *nsi);

void gbprox_reset();

char *gbprox_apn_to_str(char *str, const uint8_t *apn_enc, size_t max_chars);
int gbprox_str_to_apn(uint8_t *apn_enc, const char *str, size_t max_chars);

int gbprox_set_patch_filter(const char *filter, const char **err_msg);

void gbprox_delete_tlli(struct gbprox_peer *peer,
			       struct gbprox_tlli_info *tlli_info);
int gbprox_remove_stale_tllis(struct gbprox_peer *peer, time_t now);
int gbprox_cleanup_peers(uint16_t nsei, uint16_t bvci);

struct gbprox_peer *gbprox_peer_by_nsei(uint16_t nsei);
#endif
