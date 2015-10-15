#pragma once

#include <osmocom/core/timer.h>

#define SIP_RECONNECT_INTERVAL 10

struct msgb;
struct ipa_client_conn;
struct sip_client;

/* Expects message in msg->l2h */
typedef int (*sip_read_cb_t)(struct sip_client *sip_client, struct msgb *msg);

struct sip_client {
	struct tcp_client_conn	*link;
	sip_read_cb_t	read_cb;
	void			*data;

	struct osmo_timer_list	connect_timer;
	int			is_connected;

	char *src_ip;
	char *dst_ip;
	u_int16_t src_port;
	u_int16_t dst_port;
};

struct sip_client *sip_client_create(const char *src_ip, u_int16_t src_port,
                                     const char *dst_ip, u_int16_t dst_port,
                                          sip_read_cb_t read_cb, void *data);

void sip_client_destroy(struct sip_client *sip_client);
int sip_client_send(struct sip_client *sip_client, struct msgb *msg);
struct msgb *sip_msgb_alloc(void);
