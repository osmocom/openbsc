/* RF Ctl handling socket */

/* (C) 2010 by Harald Welte <laforge@gnumonks.org>
 * (C) 2010 by Holger Hans Peter Freyther <zecke@selfish.org>
 * (C) 2010 by On-Waves
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

#include <openbsc/osmo_bsc_rf.h>
#include <openbsc/debug.h>
#include <openbsc/gsm_data.h>
#include <openbsc/signal.h>

#include <osmocore/talloc.h>
#include <osmocore/protocol/gsm_12_21.h>

#include <sys/socket.h>
#include <sys/un.h>

#include <errno.h>
#include <unistd.h>

#define RF_CMD_QUERY '?'
#define RF_CMD_OFF   '0'
#define RF_CMD_ON    '1'
#define RF_CMD_GRACE 'g'

static int lock_each_trx(struct gsm_network *net, int lock)
{
	struct gsm_bts *bts;

	llist_for_each_entry(bts, &net->bts_list, list) {
		struct gsm_bts_trx *trx;
		llist_for_each_entry(trx, &bts->trx_list, list) {
			gsm_trx_lock_rf(trx, lock);
		}
	}

	return 0;
}

/*
 * Send a '1' when one TRX is online, otherwise send 0
 */
static void handle_query(struct osmo_bsc_rf_conn *conn)
{
	struct msgb *msg;
	struct gsm_bts *bts;
	char send = RF_CMD_OFF;

	llist_for_each_entry(bts, &conn->gsm_network->bts_list, list) {
		struct gsm_bts_trx *trx;
		llist_for_each_entry(trx, &bts->trx_list, list) {
			if (trx->nm_state.availability == NM_AVSTATE_OK &&
			    trx->nm_state.operational != NM_STATE_LOCKED) {
					send = RF_CMD_ON;
					break;
			}
		}
	}

	msg = msgb_alloc(10, "RF Query");
	if (!msg) {
		LOGP(DINP, LOGL_ERROR, "Failed to allocate response msg.\n");
		return;
	}

	msg->l2h = msgb_put(msg, 1);
	msg->l2h[0] = send;

	if (write_queue_enqueue(&conn->queue, msg) != 0) {
		LOGP(DINP, LOGL_ERROR, "Failed to enqueue the answer.\n");
		msgb_free(msg);
		return;
	}

	return;
}

static void send_signal(struct osmo_bsc_rf_conn *conn, int val)
{
	struct rf_signal_data sig;
	sig.net = conn->gsm_network;

	dispatch_signal(SS_RF, val, &sig);
}

static int rf_read_cmd(struct bsc_fd *fd)
{
	struct osmo_bsc_rf_conn *conn = fd->data;
	char buf[1];
	int rc;

	rc = read(fd->fd, buf, sizeof(buf));
	if (rc != sizeof(buf)) {
		LOGP(DINP, LOGL_ERROR, "Short read %d/%s\n", errno, strerror(errno));
		bsc_unregister_fd(fd);
		close(fd->fd);
		write_queue_clear(&conn->queue);
		talloc_free(conn);
		return -1;
	}

	switch (buf[0]) {
	case RF_CMD_QUERY:
		handle_query(conn);
		break;
	case RF_CMD_OFF:
		lock_each_trx(conn->gsm_network, 1);
		send_signal(conn, S_RF_OFF);
		break;
	case RF_CMD_ON:
		lock_each_trx(conn->gsm_network, 0);
		send_signal(conn, S_RF_ON);
		break;
	case RF_CMD_GRACE:
		send_signal(conn, S_RF_GRACE);
		break;
	default:
		LOGP(DINP, LOGL_ERROR, "Unknown command %d\n", buf[0]);
		break;
	}

	return 0;
}

static int rf_write_cmd(struct bsc_fd *fd, struct msgb *msg)
{
	int rc;

	rc = write(fd->fd, msg->data, msg->len);
	if (rc != msg->len) {
		LOGP(DINP, LOGL_ERROR, "Short write %d/%s\n", errno, strerror(errno));
		return -1;
	}

	return 0;
}

static int rf_ctl_accept(struct bsc_fd *bfd, unsigned int what)
{
	struct osmo_bsc_rf_conn *conn;
	struct osmo_bsc_rf *rf = bfd->data;
	struct sockaddr_un addr;
	socklen_t len = sizeof(addr);
	int fd;

	fd = accept(bfd->fd, (struct sockaddr *) &addr, &len);
	if (fd < 0) {
		LOGP(DINP, LOGL_ERROR, "Failed to accept. errno: %d/%s\n",
		     errno, strerror(errno));
		return -1;
	}

	conn = talloc_zero(rf, struct osmo_bsc_rf_conn);
	if (!conn) {
		LOGP(DINP, LOGL_ERROR, "Failed to allocate mem.\n");
		close(fd);
		return -1;
	}

	write_queue_init(&conn->queue, 10);
	conn->queue.bfd.data = conn;
	conn->queue.bfd.fd = fd;
	conn->queue.bfd.when = BSC_FD_READ | BSC_FD_WRITE;
	conn->queue.read_cb = rf_read_cmd;
	conn->queue.write_cb = rf_write_cmd;
	conn->gsm_network = rf->gsm_network;

	if (bsc_register_fd(&conn->queue.bfd) != 0) {
		close(fd);
		talloc_free(conn);
		return -1;
	}

	return 0;
}

struct osmo_bsc_rf *osmo_bsc_rf_create(const char *path, struct gsm_network *net)
{
	unsigned int namelen;
	struct sockaddr_un local;
	struct bsc_fd *bfd;
	struct osmo_bsc_rf *rf;
	int rc;

	rf = talloc_zero(NULL, struct osmo_bsc_rf);
	if (!rf) {
		LOGP(DINP, LOGL_ERROR, "Failed to create osmo_bsc_rf.\n");
		return NULL;
	}

	bfd = &rf->listen;
	bfd->fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (bfd->fd < 0) {
		LOGP(DINP, LOGL_ERROR, "Can not create socket. %d/%s\n",
		     errno, strerror(errno));
		return NULL;
	}

	local.sun_family = AF_UNIX;
	strncpy(local.sun_path, path, sizeof(local.sun_path));
	local.sun_path[sizeof(local.sun_path) - 1] = '\0';
	unlink(local.sun_path);

	/* we use the same magic that X11 uses in Xtranssock.c for
	 * calculating the proper length of the sockaddr */
#if defined(BSD44SOCKETS) || defined(__UNIXWARE__)
	local.sun_len = strlen(local.sun_path);
#endif
#if defined(BSD44SOCKETS) || defined(SUN_LEN)
	namelen = SUN_LEN(&local);
#else
	namelen = strlen(local.sun_path) +
		  offsetof(struct sockaddr_un, sun_path);
#endif

	rc = bind(bfd->fd, (struct sockaddr *) &local, namelen);
	if (rc != 0) {
		LOGP(DINP, LOGL_ERROR, "Failed to bind '%s' errno: %d/%s\n",
		     local.sun_path, errno, strerror(errno));
		close(bfd->fd);
		talloc_free(rf);
		return NULL;
	}

	if (listen(bfd->fd, 0) != 0) {
		LOGP(DINP, LOGL_ERROR, "Failed to listen: %d/%s\n", errno, strerror(errno));
		close(bfd->fd);
		talloc_free(rf);
		return NULL;
	}

	bfd->when = BSC_FD_READ;
	bfd->cb = rf_ctl_accept;
	bfd->data = rf;

	if (bsc_register_fd(bfd) != 0) {
		LOGP(DINP, LOGL_ERROR, "Failed to register bfd.\n");
		close(bfd->fd);
		talloc_free(rf);
		return NULL;
	}

	rf->gsm_network = net;

	return rf;
}

