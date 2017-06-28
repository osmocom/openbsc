#pragma once

#include <stdint.h>

#include <osmocom/core/linuxlist.h>
#include <osmocom/core/write_queue.h>

enum mgcp_connection_mode;

struct msgb;
struct vty;

#define MGCPGW_CLIENT_LOCAL_ADDR_DEFAULT "0.0.0.0"
#define MGCPGW_CLIENT_LOCAL_PORT_DEFAULT 0
#define MGCPGW_CLIENT_REMOTE_ADDR_DEFAULT "127.0.0.1"
#define MGCPGW_CLIENT_REMOTE_PORT_DEFAULT 2427

#define MSGB_CB_MGCP_TRANS_ID 0

typedef unsigned int mgcp_trans_id_t;

struct mgcpgw_client_conf {
	const char *local_addr;
	int local_port;
	const char *remote_addr;
	int remote_port;
	uint16_t first_endpoint;
	uint16_t last_endpoint;
	uint16_t bts_base;
};

struct mgcp_response_head {
       int response_code;
       mgcp_trans_id_t trans_id;
       const char *comment;
};

struct mgcp_response {
	char *body;
	struct mgcp_response_head head;
	uint16_t audio_port;
};

struct mgcpgw_client {
	struct mgcpgw_client_conf actual;
	uint32_t remote_addr;
	struct osmo_wqueue wq;
	mgcp_trans_id_t next_trans_id;
	struct llist_head responses_pending;
	struct llist_head inuse_endpoints;
};

struct mgcp_inuse_endpoint {
	struct llist_head entry;
	uint16_t id;
};

/* Invoked when an MGCP response is received or sending failed.  When the
 * response is passed as NULL, this indicates failure during transmission. */
typedef void (* mgcp_response_cb_t )(struct mgcp_response *response, void *priv);

struct mgcp_response_pending {
	struct llist_head entry;

	mgcp_trans_id_t trans_id;
	mgcp_response_cb_t response_cb;
	void *priv;
};


void mgcpgw_client_conf_init(struct mgcpgw_client_conf *conf);

struct mgcpgw_client *mgcpgw_client_init(void *ctx,
					 struct mgcpgw_client_conf *conf);
int mgcpgw_client_connect(struct mgcpgw_client *mgcp);

const char *mgcpgw_client_remote_addr_str(struct mgcpgw_client *mgcp);
uint16_t mgcpgw_client_remote_port(struct mgcpgw_client *mgcp);
uint32_t mgcpgw_client_remote_addr_n(struct mgcpgw_client *mgcp);

/* Find and seize an unsused endpoint id */
int mgcpgw_client_next_endpoint(struct mgcpgw_client *client);

/* Release a seized endpoint id to make it available again for other calls */
void mgcpgw_client_release_endpoint(uint16_t id, struct mgcpgw_client *client);

int mgcp_response_parse_params(struct mgcp_response *r);

int mgcpgw_client_tx(struct mgcpgw_client *mgcp, struct msgb *msg,
		     mgcp_response_cb_t response_cb, void *priv);

struct msgb *mgcp_msg_crcx(struct mgcpgw_client *mgcp,
			   uint16_t rtp_endpoint, unsigned int call_id,
			   enum mgcp_connection_mode mode);

struct msgb *mgcp_msg_mdcx(struct mgcpgw_client *mgcp,
			   uint16_t rtp_endpoint, const char *rtp_conn_addr,
			   uint16_t rtp_port, enum mgcp_connection_mode mode);

struct msgb *mgcp_msg_dlcx(struct mgcpgw_client *mgcp, uint16_t rtp_endpoint,
			   unsigned int call_id);

void mgcpgw_client_vty_init(int node, struct mgcpgw_client_conf *conf);
int mgcpgw_client_config_write(struct vty *vty, const char *indent);

struct mgcp_response_pending * mgcpgw_client_pending_add(
					struct mgcpgw_client *mgcp,
					mgcp_trans_id_t trans_id,
					mgcp_response_cb_t response_cb,
					void *priv);
int mgcpgw_client_rx(struct mgcpgw_client *mgcp, struct msgb *msg);
