#pragma once

#include <stdint.h>
enum mgcp_connection_mode;

struct msgb;
struct mgcpgw_client;

#define MGCPGW_CLIENT_LOCAL_ADDR_DEFAULT "0.0.0.0"
#define MGCPGW_CLIENT_LOCAL_PORT_DEFAULT 0
#define MGCPGW_CLIENT_REMOTE_ADDR_DEFAULT "127.0.0.1"
#define MGCPGW_CLIENT_REMOTE_PORT_DEFAULT 2427

typedef void (* mgcp_rx_cb_t )(struct msgb *msg, void *priv);

struct mgcpgw_client_conf {
	const char *local_addr;
	int local_port;
	const char *remote_addr;
	int remote_port;
};

void mgcpgw_client_conf_init(struct mgcpgw_client_conf *conf);

struct mgcpgw_client *mgcpgw_client_init(void *ctx,
					 struct mgcpgw_client_conf *conf,
					 mgcp_rx_cb_t rx_cb, void *rx_cb_priv);

const char *mgcpgw_client_remote_addr_str(struct mgcpgw_client *mgcp);
uint16_t mgcpgw_client_remote_port(struct mgcpgw_client *mgcp);
uint32_t mgcpgw_client_remote_addr_n(struct mgcpgw_client *mgcp);

unsigned int mgcpgw_client_next_endpoint(struct mgcpgw_client *client);

int mgcpgw_client_tx_crcx(struct mgcpgw_client *client,
			  uint16_t rtp_endpoint, unsigned int call_id,
			  enum mgcp_connection_mode mode);
int mgcpgw_client_tx_mdcx(struct mgcpgw_client *client, uint16_t rtp_endpoint,
			  const char *rtp_conn_addr, uint16_t rtp_port,
			  enum mgcp_connection_mode mode);

int mgcpgw_client_tx_str(struct mgcpgw_client *mgcp, const char *fmt, ...);
int mgcpgw_client_tx_buf(struct mgcpgw_client *mgcp, const char *buf, int len);
int mgcpgw_client_tx(struct mgcpgw_client *mgcp, struct msgb *msg);

void mgcpgw_client_vty_init(int node, struct mgcpgw_client_conf *conf);
int mgcpgw_client_config_write(struct vty *vty, const char *indent);
