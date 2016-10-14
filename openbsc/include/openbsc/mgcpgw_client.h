#pragma once

#include <stdint.h>

#include <osmocom/core/linuxlist.h>

enum mgcp_connection_mode;

struct msgb;
struct mgcpgw_client;

#define MGCPGW_CLIENT_LOCAL_ADDR_DEFAULT "0.0.0.0"
#define MGCPGW_CLIENT_LOCAL_PORT_DEFAULT 0
#define MGCPGW_CLIENT_REMOTE_ADDR_DEFAULT "127.0.0.1"
#define MGCPGW_CLIENT_REMOTE_PORT_DEFAULT 2427

struct mgcpgw_client_conf {
	const char *local_addr;
	int local_port;
	const char *remote_addr;
	int remote_port;
};

struct mgcp_response_head {
       int response_code;
       unsigned int trans_id;
       const char *comment;
};

struct mgcp_response {
	char *data;
	struct mgcp_response_head head;
	uint16_t audio_port;
};

/* Invoked when an MGCP response is received or sending failed.  When the
 * response is passed as NULL, this indicates failure during transmission. */
typedef void (* mgcp_response_cb_t )(struct mgcp_response *response, void *priv);

struct mgcp_response_pending {
	struct llist_head entry;

	unsigned int trans_id;
	mgcp_response_cb_t response_cb;
	void *priv;
};


void mgcpgw_client_conf_init(struct mgcpgw_client_conf *conf);

struct mgcpgw_client *mgcpgw_client_init(void *ctx,
					 struct mgcpgw_client_conf *conf);

const char *mgcpgw_client_remote_addr_str(struct mgcpgw_client *mgcp);
uint16_t mgcpgw_client_remote_port(struct mgcpgw_client *mgcp);
uint32_t mgcpgw_client_remote_addr_n(struct mgcpgw_client *mgcp);

unsigned int mgcpgw_client_next_endpoint(struct mgcpgw_client *client);

int mgcp_response_parse_params(struct mgcp_response *r);

int mgcpgw_client_tx_crcx(struct mgcpgw_client *mgcp,
			  mgcp_response_cb_t response_cb, void *priv,
			  uint16_t rtp_endpoint, unsigned int call_id,
			  enum mgcp_connection_mode mode);
int mgcpgw_client_tx_mdcx(struct mgcpgw_client *mgcp,
			  mgcp_response_cb_t response_cb, void *priv,
			  uint16_t rtp_endpoint, const char *rtp_conn_addr,
			  uint16_t rtp_port, enum mgcp_connection_mode mode);

int mgcpgw_client_tx_str(struct mgcpgw_client *mgcp,
			 mgcp_response_cb_t response_cb, void *priv,
			 unsigned int trans_id,
			 const char *fmt, ...);
int mgcpgw_client_tx_buf(struct mgcpgw_client *mgcp,
			 mgcp_response_cb_t response_cb, void *priv,
			 const char *buf, int len,
			 unsigned int trans_id);
int mgcpgw_client_tx(struct mgcpgw_client *mgcp,
		     mgcp_response_cb_t response_cb, void *priv,
		     struct msgb *msg, unsigned int trans_id);

void mgcpgw_client_vty_init(int node, struct mgcpgw_client_conf *conf);
int mgcpgw_client_config_write(struct vty *vty, const char *indent);
