//#include "internal.h"

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <time.h>
#include <sys/fcntl.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <ifaddrs.h>
#include <sys/types.h>
#include <netdb.h>

#include <osmocom/core/select.h>
#include <osmocom/gsm/tlv.h>
#include <osmocom/core/msgb.h>
#include <osmocom/core/logging.h>
#include <osmocom/core/talloc.h>
//#include <osmocom/abis/e1_input.h>
//#include <osmocom/abis/ipaccess.h>
//#include <osmocom/core/socket.h>
#include <osmocom/core/backtrace.h>
#include <openbsc/tcp_client.h>

void tcp_client_conn_close(struct tcp_client_conn *link)
{
	/* be safe against multiple calls */
	if (link->ofd->fd != -1) {
		osmo_fd_unregister(link->ofd);
		close(link->ofd->fd);
		link->ofd->fd = -1;
	}
	msgb_free(link->pending_msg);
	link->pending_msg = NULL;
}

static void tcp_client_read(struct tcp_client_conn *link)
{
	struct osmo_fd *ofd = link->ofd;
	struct msgb *msg;
	int ret;

	LOGP(DLINP, LOGL_DEBUG, "message received\n");

	// FIX 1500
	msg = msgb_alloc(1500, "TCP");
	if (!msg)
		return;

	printf("try to recv data msg->data = %d msg->data_len = %d \n", msg->data, msg->data_len);
	ret = recv(ofd->fd, msg->data, msg->data_len, 0);
	if (ret < 0) {
		if (ret == -EAGAIN)
			return;
		if (ret == -EPIPE || ret == -ECONNRESET)
			LOGP(DLINP, LOGL_ERROR, "lost connection with server\n");
		tcp_client_conn_close(link);
		if (link->updown_cb)
			link->updown_cb(link, 0);
		return;
	} else if (ret == 0) {
		LOGP(DLINP, LOGL_ERROR, "connection closed with server\n");
		tcp_client_conn_close(link);
		if (link->updown_cb)
			link->updown_cb(link, 0);
		return;
	}
	// TODO set len = ret
	msg->data_len = ret;
	printf("RECV SIP LEN = %d \n", ret);
	if (link->read_cb)
		link->read_cb(link, msg);
}

static void tcp_client_write(struct tcp_client_conn *link)
{
	if (link->write_cb)
		link->write_cb(link);
}

static int tcp_client_write_default_cb(struct tcp_client_conn *link)
{
	struct osmo_fd *ofd = link->ofd;
	struct msgb *msg;
	struct llist_head *lh;
	int ret;

	LOGP(DLINP, LOGL_DEBUG, "sending data\n");

	if (llist_empty(&link->tx_queue)) {
		ofd->when &= ~BSC_FD_WRITE;
		return 0;
	}
	lh = link->tx_queue.next;
	llist_del(lh);
	msg = llist_entry(lh, struct msgb, list);

	ret = send(link->ofd->fd, msg->data, msg->len, 0);
	if (ret < 0) {
		if (errno == EPIPE || errno == ENOTCONN) {
			tcp_client_conn_close(link);
			if (link->updown_cb)
				link->updown_cb(link, 0);
		}
		LOGP(DLINP, LOGL_ERROR, "error to send\n");
	}
	msgb_free(msg);
	return 0;
}

static int tcp_client_fd_cb(struct osmo_fd *ofd, unsigned int what)
{
	struct tcp_client_conn *link = ofd->data;
	int error, ret;
	socklen_t len = sizeof(error);

	switch(link->state) {
	case TCP_CLIENT_LINK_STATE_CONNECTING:
		ret = getsockopt(ofd->fd, SOL_SOCKET, SO_ERROR, &error, &len);
		if (ret >= 0 && error > 0) {
			tcp_client_conn_close(link);
			if (link->updown_cb)
				link->updown_cb(link, 0);
			return 0;
		}
		ofd->when &= ~BSC_FD_WRITE;
		LOGP(DLINP, LOGL_NOTICE, "connection done.\n");
		link->state = TCP_CLIENT_LINK_STATE_CONNECTED;
		if (link->updown_cb)
			link->updown_cb(link, 1);
		break;
	case TCP_CLIENT_LINK_STATE_CONNECTED:
		if (what & BSC_FD_READ) {
			LOGP(DLINP, LOGL_DEBUG, "connected read\n");
			tcp_client_read(link);
		}
		if (what & BSC_FD_WRITE) {
			LOGP(DLINP, LOGL_DEBUG, "connected write\n");
			tcp_client_write(link);
		}
		break;
	default:
		break;
	}
	return 0;
}

struct tcp_client_conn * tcp_client_conn_create(void *ctx, int priv_nr,
		       const char *dst_addr, uint16_t dst_port,
		       const char *src_addr, uint16_t src_port,
		       void (*updown_cb)(struct tcp_client_conn *link, int up),
		       int (*read_cb)(struct tcp_client_conn *link,
				      struct msgb *msgb),
		       int (*write_cb)(struct tcp_client_conn *link),
		       void *data)
{
	struct tcp_client_conn *tcp_link;

	tcp_link = talloc_zero(ctx, struct tcp_client_conn);
	if (!tcp_link)
		return NULL;

	tcp_link->ofd = talloc_zero(ctx, struct osmo_fd);
	if (tcp_link->ofd == NULL) {
		talloc_free(tcp_link);
		return NULL;
	}

	tcp_link->ofd->when |= BSC_FD_READ | BSC_FD_WRITE;
	tcp_link->ofd->priv_nr = priv_nr;
	tcp_link->ofd->cb = tcp_client_fd_cb;
	tcp_link->ofd->data = tcp_link;
	tcp_link->ofd->fd = -1;
	tcp_link->state = TCP_CLIENT_LINK_STATE_CONNECTING;
	tcp_link->src_addr = talloc_strdup(tcp_link, src_addr);
	tcp_link->src_port = src_port;
	tcp_link->dst_addr = talloc_strdup(tcp_link, dst_addr);
	tcp_link->dst_port = dst_port;
	tcp_link->updown_cb = updown_cb;
	tcp_link->read_cb = read_cb;
	/* default to generic write callback if not set. */
	if (write_cb == NULL)
		tcp_link->write_cb = tcp_client_write_default_cb;
	else
		tcp_link->write_cb = write_cb;

	tcp_link->data = data;
	INIT_LLIST_HEAD(&tcp_link->tx_queue);

	return tcp_link;
}

void tcp_client_conn_destroy(struct tcp_client_conn *link)
{
	talloc_free(link);
}

int tcp_client_conn_open(struct tcp_client_conn *link)
{
	int ret;
	struct addrinfo hints, *bind_addr, *connect_addr;
	int sfd, rc, on = 1;
	char src_port_buf[16];
	char dst_port_buf[16];


	link->state = TCP_CLIENT_LINK_STATE_CONNECTING;
//	ret = osmo_sock_init(AF_INET, SOCK_STREAM, IPPROTO_TCP,
//			     link->addr, link->port,
//			     OSMO_SOCK_F_CONNECT|OSMO_SOCK_F_NONBLOCK);
			     
	sprintf(src_port_buf, "%u", link->src_port);		     
	sprintf(dst_port_buf, "%u", link->dst_port);		     

	memset(&hints, 0, sizeof(struct addrinfo));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;

	rc = getaddrinfo(link->dst_addr, dst_port_buf, &hints, &connect_addr);
	if (rc != 0) {
		perror("getaddrinfo returned NULL");
		return -EINVAL;
	}

	hints.ai_flags |= AI_PASSIVE;

	rc = getaddrinfo(link->src_addr, src_port_buf, &hints, &bind_addr);
	if (rc != 0) {
		perror("getaddrinfo returned NULL");
		return -EINVAL;
	}

	sfd = socket(connect_addr->ai_family, connect_addr->ai_socktype, connect_addr->ai_protocol);
	if (sfd < 0) {
		perror("cannot create socket");
        return sfd;
	}
	if (ioctl(sfd, FIONBIO, (unsigned char *)&on) < 0) {
		perror("cannot set this socket unblocking");
		close(sfd);
		return -EINVAL;
	}

	rc = setsockopt(sfd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
	if (rc < 0) {
		perror("cannot setsockopt socket");
		close(sfd);
		return -EINVAL;
	}

	rc = bind(sfd, bind_addr->ai_addr, bind_addr->ai_addrlen);
	if (rc < 0) {
		perror("cannot bind socket");
		close(sfd);
		return -ENODEV;
	}

	rc = connect(sfd, connect_addr->ai_addr, connect_addr->ai_addrlen);
	if (rc <0 && errno != EINPROGRESS) {
		perror("cannot connect socket");
		close(sfd);
		return -ENODEV;
	}

	freeaddrinfo(bind_addr);
	freeaddrinfo(connect_addr);

	listen(sfd, 10);

	link->ofd->fd = sfd;
	link->ofd->when |= BSC_FD_WRITE;
	if (osmo_fd_register(link->ofd) < 0) {
		close(sfd);
		link->ofd->fd = -1;
		return -EIO;
	}

	return 0;
}

void tcp_client_conn_send(struct tcp_client_conn *link, struct msgb *msg)
{
	msgb_enqueue(&link->tx_queue, msg);
	link->ofd->when |= BSC_FD_WRITE;
}

size_t tcp_client_conn_clear_queue(struct tcp_client_conn *link)
{
	size_t deleted = 0;

	while (!llist_empty(&link->tx_queue)) {
		struct msgb *msg = msgb_dequeue(&link->tx_queue);
		msgb_free(msg);
		deleted += 1;
	}

	link->ofd->when &= ~BSC_FD_WRITE;
	return deleted;
}
