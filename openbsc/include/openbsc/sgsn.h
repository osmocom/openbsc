#ifndef _SGSN_H
#define _SGSN_H


#include <osmocom/core/msgb.h>
#include <osmocom/crypt/gprs_cipher.h>
#include <osmocom/gprs/gprs_ns.h>
#include <openbsc/gprs_sgsn.h>
#include <openbsc/oap_client.h>

#include <ares.h>

struct gprs_gsup_client;
struct hostent;

enum sgsn_auth_policy {
	SGSN_AUTH_POLICY_OPEN,
	SGSN_AUTH_POLICY_CLOSED,
	SGSN_AUTH_POLICY_ACL_ONLY,
	SGSN_AUTH_POLICY_REMOTE
};


enum sgsn_rate_ctr_keys {
	CTR_LLC_DL_BYTES,
	CTR_LLC_UL_BYTES,
	CTR_LLC_DL_PACKETS,
	CTR_LLC_UL_PACKETS,
	CTR_GPRS_ATTACH_REQUEST,
	CTR_GPRS_ATTACH_ACKED,
	CTR_GPRS_ATTACH_REJECTED,
	CTR_GPRS_DETACH_REQUEST,
	CTR_GPRS_DETACH_ACKED,
	CTR_GPRS_ROUTING_AREA_REQUEST,
	CTR_GPRS_ROUTING_AREA_ACKED,
	CTR_GPRS_ROUTING_AREA_REJECT,
	/* PDP single packet counter / GSM 04.08 9.5.1 - 9.5.9 */
	CTR_PDP_ACTIVATE_REQUEST,
	CTR_PDP_ACTIVATE_REJECT,
	CTR_PDP_ACTIVATE_ACCEPT,
	CTR_PDP_REQUEST_ACTIVATE, /* unused */
	CTR_PDP_REQUEST_ACTIVATE_REJ, /* unused */
	CTR_PDP_MODIFY_REQUEST, /* unsued */
	CTR_PDP_MODIFY_ACCEPT, /* unused */
	CTR_PDP_DL_DEACTIVATE_REQUEST,
	CTR_PDP_DL_DEACTIVATE_ACCEPT,
	CTR_PDP_UL_DEACTIVATE_REQUEST,
	CTR_PDP_UL_DEACTIVATE_ACCEPT,
};

struct sgsn_cdr {
	char *filename;
	int interval;
};

struct sgsn_config {
	/* parsed from config file */

	char *gtp_statedir;
	struct sockaddr_in gtp_listenaddr;

	/* misc */
	struct gprs_ns_inst *nsi;

	enum sgsn_auth_policy auth_policy;
	enum gprs_ciph_algo cipher;
	struct llist_head imsi_acl;

	struct sockaddr_in gsup_server_addr;
	int gsup_server_port;

	int require_authentication;
	int require_update_location;

	/* CDR configuration */
	struct sgsn_cdr cdr;

	struct {
		int T3312;
		int T3322;
		int T3350;
		int T3360;
		int T3370;
		int T3313;
		int T3314;
		int T3316;
		int T3385;
		int T3386;
		int T3395;
		int T3397;
	} timers;

	int dynamic_lookup;

	struct oap_client_config oap;

	/* RFC1144 TCP/IP header compression */
	struct {
		int active;
		int passive;
		int s01;
	} pcomp_rfc1144;

	/* V.42vis data compression */
	struct {
		int active;
		int passive;
		int p0;
		int p1;
		int p2;
	} dcomp_v42bis;
};

struct sgsn_instance {
	char *config_file;
	struct sgsn_config cfg;
	/* File descriptor wrappers for LibGTP */
	struct osmo_fd gtp_fd0;
	struct osmo_fd gtp_fd1c;
	struct osmo_fd gtp_fd1u;
	/* Timer for libGTP */
	struct osmo_timer_list gtp_timer;
	/* GSN instance for libgtp */
	struct gsn_t *gsn;
	/* Subscriber */
	struct gsup_client *gsup_client;
	/* LLME inactivity timer */
	struct osmo_timer_list llme_timer;

	/* c-ares event loop integration */
	struct osmo_timer_list ares_timer;
	struct llist_head ares_fds;
	ares_channel ares_channel;
	struct ares_addr_node *ares_servers;

	struct rate_ctr_group *rate_ctrs;
};

extern struct sgsn_instance *sgsn;

/* sgsn_vty.c */

int sgsn_vty_init(void);
int sgsn_parse_config(const char *config_file, struct sgsn_config *cfg);

/* sgsn.c */

/* Main input function for Gb proxy */
int sgsn_rcvmsg(struct msgb *msg, struct gprs_nsvc *nsvc, uint16_t ns_bvci);


struct sgsn_pdp_ctx *sgsn_create_pdp_ctx(struct sgsn_ggsn_ctx *ggsn,
					 struct sgsn_mm_ctx *mmctx,
					 uint16_t nsapi,
					 struct tlv_parsed *tp);
int sgsn_delete_pdp_ctx(struct sgsn_pdp_ctx *pctx);
void sgsn_pdp_upd_gtp_u(struct sgsn_pdp_ctx *pdp, void *addr, size_t alen);

/* gprs_sndcp.c */

/* Entry point for the SNSM-ACTIVATE.indication */
int sndcp_sm_activate_ind(struct gprs_llc_lle *lle, uint8_t nsapi);
/* Entry point for the SNSM-DEACTIVATE.indication */
int sndcp_sm_deactivate_ind(struct gprs_llc_lle *lle, uint8_t nsapi);
/* Called by SNDCP when it has received/re-assembled a N-PDU */
int sgsn_rx_sndcp_ud_ind(struct gprs_ra_id *ra_id, int32_t tlli, uint8_t nsapi,
			 struct msgb *msg, uint32_t npdu_len, uint8_t *npdu);
int sndcp_unitdata_req(struct msgb *msg, struct gprs_llc_lle *lle, uint8_t nsapi,
			void *mmcontext);
int sndcp_llunitdata_ind(struct msgb *msg, struct gprs_llc_lle *lle,
			 uint8_t *hdr, uint16_t len);


/*
 * CDR related functionality
 */
int sgsn_cdr_init(struct sgsn_instance *sgsn);


/*
 * C-ARES related functionality
 */
int sgsn_ares_init(struct sgsn_instance *sgsn);
int sgsn_ares_query(struct sgsn_instance *sgsm, const char *name, ares_host_callback cb, void *data);

#endif
