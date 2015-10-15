#ifndef _SUP_SERVER_H
#define _SUP_SERVER_H

#include <osmocom/abis/ipa.h>

//struct msgb;
struct ipa_server_conn;
struct gsm_sup_server;

/* Expects message in msg->l2h */
typedef int (*sup_read_cb_t)(struct gsm_sup_server *sup_server, struct msgb *msg);

struct gsm_sup_server {
	struct ipa_server_link	*link;
	sup_read_cb_t	read_cb;
	void			*data;
	struct osmo_fd fd;
	struct ipa_server_conn *server_conn;
	void *app;
};

struct gsm_sup_server *sup_server_create(const char *ip_addr,
						 unsigned int tcp_port,
						 sup_read_cb_t read_cb,
						 void *app);

int sup_server_send(struct gsm_sup_server *sup_server, struct msgb *msg);

#endif /* _SUP_SERVER_H */
