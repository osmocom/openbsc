#ifndef _TCP_CLIENT_H_
#define _TCP_CLIENT_H_

#include <stdint.h>
#include <osmocom/core/linuxlist.h>
#include <osmocom/core/timer.h>
#include <osmocom/core/select.h>


struct msgb;

enum tcp_client_conn_state {
	TCP_CLIENT_LINK_STATE_NONE         = 0,
	TCP_CLIENT_LINK_STATE_CONNECTING   = 1,
	TCP_CLIENT_LINK_STATE_CONNECTED    = 2,
	TCP_CLIENT_LINK_STATE_MAX
};

struct tcp_client_conn {
	struct osmo_fd			*ofd;
	struct llist_head		tx_queue;
	struct osmo_timer_list		timer;
	enum tcp_client_conn_state	state;
	const char			*src_addr;
	uint16_t			src_port;
	const char			*dst_addr;
	uint16_t			dst_port;
	void (*updown_cb)(struct tcp_client_conn *link, int up);
	int (*read_cb)(struct tcp_client_conn *link, struct msgb *msg);
	int (*write_cb)(struct tcp_client_conn *link);
	void				*data;
	struct msgb			*pending_msg;
};

struct tcp_client_conn *
tcp_client_conn_create(void *ctx, int priv_nr,
			const char *dst_addr, uint16_t dst_port,
			const char *src_addr, uint16_t src_port,
			void (*updown)(struct tcp_client_conn *link, int),
			int (*read_cb)(struct tcp_client_conn *link, struct msgb *msgb),
			int (*write_cb)(struct tcp_client_conn *link),
			void *data);
void tcp_client_conn_destroy(struct tcp_client_conn *link);

int tcp_client_conn_open(struct tcp_client_conn *link);
void tcp_client_conn_close(struct tcp_client_conn *link);

void tcp_client_conn_send(struct tcp_client_conn *link, struct msgb *msg);
size_t tcp_client_conn_clear_queue(struct tcp_client_conn *link);

#endif
