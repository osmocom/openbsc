
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/fcntl.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#include <osmocom/core/talloc.h>
#include <osmocom/core/select.h>
#include <osmocom/core/logging.h>
#include <osmocom/core/socket.h>
#include <osmocom/core/write_queue.h>

#include "conn.h"


static int slave_read_cb(struct osmo_fd *ofd)
{
	struct osmo_conn *conn = ofd->data;

	return conn->link->slave_read_cb(conn);
}

static int slave_write_cb(struct osmo_fd *ofd, struct msgb *msg)
{
	int rc;

	rc = send(ofd->fd, msg->data, msg->len, 0);
	if (rc < 0) {
		LOGP(DLINP, LOGL_ERROR, "error %d on send()\n", rc);
	}

	return rc;
}

static int server_fd_cb(struct osmo_fd *ofd, unsigned int what)
{
	int rc;
	struct sockaddr_in sa;
	socklen_t sa_len = sizeof(sa);
	struct osmo_link *link = ofd->data;
	struct osmo_conn *conn;

	rc = accept(ofd->fd, (struct sockaddr *)&sa, &sa_len);
	if (rc < 0)
		return rc;

	conn = talloc_zero(link, struct osmo_conn);
	if (!conn) {
		close(rc);
		return -ENOMEM;
	}

	conn->link = link;
	osmo_wqueue_init(&conn->queue, link->slave_max_qlen);
	conn->queue.read_cb = slave_read_cb;
	conn->queue.write_cb = slave_write_cb;

	conn->queue.bfd.fd = rc;
	conn->queue.bfd.when = BSC_FD_READ | BSC_FD_WRITE;
	conn->queue.bfd.data = conn;

	osmo_fd_register(&conn->queue.bfd);

	conn->remote.host = talloc_strdup(conn, inet_ntoa(sa.sin_addr));
	conn->remote.port = ntohs(sa.sin_port);

	llist_add_tail(&conn->list, &link->conns);

	LOGP(DLINP, LOGL_NOTICE, "accept()ed new UNC link from %s:%u to port %u\n",
		conn->remote.host, conn->remote.port, link->port);

	if (link->accept_cb)
		link->accept_cb(conn);

	return 0;
}

struct osmo_link *osmo_link_create(void *ctx, const char *addr, uint16_t port,
				   int (*read_cb)(struct osmo_conn *),
				   int slave_max_qlen)
{
	struct osmo_link *link;

	link = talloc_zero(ctx, struct osmo_link);
	if (!link)
		return NULL;

	link->ofd.when = BSC_FD_READ | BSC_FD_WRITE;
	link->ofd.cb = server_fd_cb;
	link->ofd.data = link;
	link->addr = talloc_strdup(link, addr);
	link->port = port;
	link->slave_read_cb = read_cb;
	link->slave_max_qlen = slave_max_qlen;
	INIT_LLIST_HEAD(&link->conns);

	return link;
}


int osmo_link_listen(struct osmo_link *link,
		     void (*accept_cb)(struct osmo_conn *))
{
	int rc;

	rc = osmo_sock_init(AF_INET, SOCK_STREAM, IPPROTO_TCP,
			    link->addr, link->port, OSMO_SOCK_F_BIND);

	link->ofd.fd = rc;

	if (osmo_fd_register(&link->ofd) < 0) {
		close(rc);
		return -EIO;
	}
	link->accept_cb = accept_cb;

	return 0;
}

int osmo_conn_enqueue(struct osmo_conn *conn, struct msgb *msg)
{
	return osmo_wqueue_enqueue(&conn->queue, msg);
}

void osmo_conn_close(struct osmo_conn *conn)
{
	close(conn->queue.bfd.fd);
	osmo_wqueue_clear(&conn->queue);
	llist_del(&conn->list);

	talloc_free(conn);
}

int osmo_link_close(struct osmo_link *link)
{
	struct osmo_conn *conn, *conn2;

	osmo_fd_unregister(&link->ofd);
	close(link->ofd.fd);

	llist_for_each_entry_safe(conn, conn2, &link->conns, list)
		osmo_conn_close(conn);

	return 0;
}
