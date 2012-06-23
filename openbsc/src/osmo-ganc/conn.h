#ifndef _OSMO_CONN_H
#define _OSMO_CONN_H

#include <osmocom/core/select.h>
#include <osmocom/core/linuxlist.h>
#include <osmocom/core/socket.h>
#include <osmocom/core/write_queue.h>

struct osmo_conn;

struct osmo_link {
	struct llist_head list;
	struct osmo_fd ofd;
	const char *addr;
	uint16_t port;
	struct llist_head conns;
	int slave_max_qlen;

	void (*accept_cb)(struct osmo_conn *conn);
	int (*slave_read_cb)(struct osmo_conn *conn);
};

struct osmo_conn {
	struct llist_head list;
	struct osmo_link *link;
	struct osmo_wqueue queue;
	struct {
		const char *host;
		uint16_t port;
	} remote;
	void *priv;
};

int osmo_conn_enqueue(struct osmo_conn *conn, struct msgb *msg);
void osmo_conn_close(struct osmo_conn *conn);

struct osmo_link *osmo_link_create(void *ctx, const char *addr, uint16_t port,
				   int (*read_cb)(struct osmo_conn *),
				   int slave_max_qlen);
int osmo_link_listen(struct osmo_link *link,
		     void (*accept_cb)(struct osmo_conn *));
int osmo_link_close(struct osmo_link *link);

#endif
