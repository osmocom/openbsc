#pragma once

struct sgsn_pdp_ctx;
struct msgb;
struct gprs_ra_id;

struct RANAP_RAB_SetupOrModifiedItemIEs_s;

struct ue_conn_ctx {
	struct llist_head list;
	struct osmo_sua_link *link;
	uint32_t conn_id;
};

/* Implementations of iu_recv_cb_t shall find the ue_conn_ctx in msg->dst. */
typedef int (* iu_recv_cb_t )(struct msgb *msg, struct gprs_ra_id *ra_id,
			      /* TODO is ra_id only used for gprs? ^ */
			      uint16_t *sai);

typedef int (* iu_rab_ass_resp_cb_t )(struct ue_conn_ctx *ue_ctx, uint8_t rab_id,
		struct RANAP_RAB_SetupOrModifiedItemIEs_s *setup_ies);

int iu_init(void *ctx, const char *listen_addr, uint16_t listen_port,
	    iu_recv_cb_t iu_recv_cb, iu_rab_ass_resp_cb_t ui_rab_ass_resp_cb);

int iu_tx(struct msgb *msg, uint8_t sapi);

int iu_rab_act_cs(struct ue_conn_ctx *ue_ctx, uint32_t rtp_ip, uint16_t rtp_port);
int iu_rab_act_ps(struct sgsn_pdp_ctx *pdp);
int iu_rab_deact(struct ue_conn_ctx *ue_ctx, uint8_t rab_id);
