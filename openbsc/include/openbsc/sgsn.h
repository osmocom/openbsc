#ifndef _SGSN_H
#define _SGSN_H


#include <osmocom/core/msgb.h>

#include <osmocom/gprs/gprs_ns.h>
#include <openbsc/gprs_sgsn.h>

struct sgsn_config {
	/* parsed from config file */

	char *gtp_statedir;
	struct sockaddr_in gtp_listenaddr;

	/* misc */
	struct gprs_ns_inst *nsi;

	int acl_enabled;
	struct llist_head imsi_acl;
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

#endif
