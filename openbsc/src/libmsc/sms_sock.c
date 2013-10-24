/* sms_sock.c: SMS interface to a unix domain socket */

/* (C) 2008-2010 by Harald Welte <laforge@gnumonks.org>
 * (C) 2009 by Andreas Eversberg <Andreas.Eversberg@versatel.de>
 * (C) 2012 by Holger Hans Peter Freyther
 * All Rights Reserved
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 */

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <assert.h>
#include <sys/socket.h>
#include <sys/un.h>

#include <osmocom/core/talloc.h>
#include <osmocom/core/select.h>
#include <osmocom/gsm/protocol/gsm_04_08.h>

#include <openbsc/debug.h>
#include <openbsc/gsm_data.h>

struct sms_sock_state {
	struct gsm_network *net;
	struct osmo_fd listen_bfd;	/* fd for listen socket */
	struct osmo_fd conn_bfd;		/* fd for connection to lcr */
};

int sms_sock_try_deliver(struct gsm_network *net, struct msgb *msg)
{
	/* Check if we currently have a MNCC handler connected */
	if (net->sms_state->conn_bfd.fd < 0) {
		LOGP(DMNCC, LOGL_ERROR, "sms_sock receives for external CC app "
			"but socket is gone\n");
		/* free the original message */
		msgb_free(msg);
		return -1;
	}

	/* FIXME: check for some maximum queue depth? */

	/* Actually enqueue the message and mark socket write need */
	msgb_enqueue(&net->smsqueue, msg);
	net->sms_state->conn_bfd.when |= BSC_FD_WRITE;
	return 0;
}

static void sms_sock_close(struct sms_sock_state *state)
{
	struct osmo_fd *bfd = &state->conn_bfd;

	LOGP(DMNCC, LOGL_NOTICE, "SMS Socket has LOST connection\n");

	close(bfd->fd);
	bfd->fd = -1;
	osmo_fd_unregister(bfd);

	/* re-enable the generation of ACCEPT for new connections */
	state->listen_bfd.when |= BSC_FD_READ;

	/* flush the queue */
	while (!llist_empty(&state->net->smsqueue)) {
		struct msgb *msg = msgb_dequeue(&state->net->smsqueue);
		msgb_free(msg);
	}
}

static int sms_sock_read(struct osmo_fd *bfd)
{
	struct sms_sock_state *state = (struct sms_sock_state *)bfd->data;
	struct msgb *msg;
	int rc;
	
	msg = msgb_alloc(256, "sms_sock_rx");
	if (!msg)
		return -ENOMEM;

	rc = recv(bfd->fd, msg->tail, msgb_tailroom(msg), 0);
	if (rc == 0)
		goto close;

	if (rc < 0) {
		if (errno == EAGAIN)
			return 0;
		goto close;
	}


	// TODO: We should parse message here.
	LOGP(DMNCC, LOGL_ERROR, "We should parse message here %s \n", osmo_hexdump(msg->tail, msgb_tailroom(msg)));
	
	msgb_free(msg);

	return rc;

close:
	msgb_free(msg);
	sms_sock_close(state);
	return -1;
}

static int sms_sock_write(struct osmo_fd *bfd)
{
	struct sms_sock_state *state = bfd->data;
	struct gsm_network *net = state->net;
	int rc;

	while (!llist_empty(&net->smsqueue)) {
		struct msgb *msg, *msg2;

		/* peek at the beginning of the queue */
		msg = llist_entry(net->smsqueue.next, struct msgb, list);

		bfd->when &= ~BSC_FD_WRITE;

		/* bug hunter 8-): maybe someone forgot msgb_put(...) ? */
		if (!msgb_length(msg)) {
			LOGP(DMNCC, LOGL_ERROR, "message type with ZERO "
				"bytes!\n");
			goto dontsend;
		}

		/* try to send it over the socket */
		rc = write(bfd->fd, msgb_sms(msg), (unsigned) (msg->tail - (uint8_t *)msgb_sms(msg)));
		if (rc == 0)
			goto close;
		if (rc < 0) {
			if (errno == EAGAIN) {
				bfd->when |= BSC_FD_WRITE;
				break;
			}
			goto close;
		}

dontsend:
		/* _after_ we send it, we can deueue */
		msg2 = msgb_dequeue(&net->smsqueue);
		assert(msg == msg2);
	}
	return 0;

close:
	sms_sock_close(state);
	return -1;
}

static int sms_sock_cb(struct osmo_fd *bfd, unsigned int flags)
{
	int rc = 0;

	if (flags & BSC_FD_READ)
		rc = sms_sock_read(bfd);
	if (rc < 0)
		return rc;

	if (flags & BSC_FD_WRITE)
		rc = sms_sock_write(bfd);

	return rc;
}

/* accept a new connection */
static int sms_sock_accept(struct osmo_fd *bfd, unsigned int flags)
{
	struct sms_sock_state *state = (struct sms_sock_state *)bfd->data;
	struct osmo_fd *conn_bfd = &state->conn_bfd;
	struct sockaddr_un un_addr;
	socklen_t len;
	int rc;

	len = sizeof(un_addr);
	rc = accept(bfd->fd, (struct sockaddr *) &un_addr, &len);
	if (rc < 0) {
		LOGP(DMNCC, LOGL_ERROR, "Failed to accept a new connection\n");
		return -1;
	}

	if (conn_bfd->fd >= 0) {
		LOGP(DMNCC, LOGL_NOTICE, "SMS app connects but we already have "
			"another active connection ?!?\n");
		/* We already have one SMS app connected, this is all we support */
		state->listen_bfd.when &= ~BSC_FD_READ;
		close(rc);
		return 0;
	}

	conn_bfd->fd = rc;
	conn_bfd->when = BSC_FD_READ;
	conn_bfd->cb = sms_sock_cb;
	conn_bfd->data = state;

	if (osmo_fd_register(conn_bfd) != 0) {
		LOGP(DMNCC, LOGL_ERROR, "Failed to register new connection fd\n");
		close(conn_bfd->fd);
		conn_bfd->fd = -1;
		return -1;
	}

	LOGP(DMNCC, LOGL_NOTICE, "SMS Socket has connection with external "
		"SMS application\n");

	return 0;
}


int sms_sock_init(struct gsm_network *net)
{
	struct sms_sock_state *state;
	struct osmo_fd *bfd;
	int rc;

	state = talloc_zero(tall_bsc_ctx, struct sms_sock_state);
	if (!state)
		return -ENOMEM;

	state->net = net;
	state->conn_bfd.fd = -1;

	bfd = &state->listen_bfd;

	rc = osmo_unixsock_listen(bfd, SOCK_STREAM, "/tmp/bsc_sms");
	if (rc < 0) {
		LOGP(DMNCC, LOGL_ERROR, "Could not create unix socket: %s\n",
			strerror(errno));
		talloc_free(state);
		return rc;
	}

	bfd->when = BSC_FD_READ;
	bfd->cb = sms_sock_accept;
	bfd->data = state;

	rc = osmo_fd_register(bfd);
	if (rc < 0) {
		LOGP(DMNCC, LOGL_ERROR, "Could not register listen fd: %d\n", rc);
		close(bfd->fd);
		talloc_free(state);
		return rc;
	}

	net->sms_state = state;

	return 0;
}
