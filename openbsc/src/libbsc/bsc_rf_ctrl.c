/* RF Ctl handling socket */

/* (C) 2010 by Harald Welte <laforge@gnumonks.org>
 * (C) 2010-2014 by Holger Hans Peter Freyther <zecke@selfish.org>
 * (C) 2010-2014 by On-Waves
 * All Rights Reserved
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include <openbsc/osmo_bsc_rf.h>
#include <openbsc/debug.h>
#include <openbsc/gsm_data.h>
#include <openbsc/signal.h>
#include <openbsc/bsc_msc_data.h>
#include <openbsc/ipaccess.h>

#include <osmocom/core/talloc.h>
#include <osmocom/core/utils.h>
#include <osmocom/gsm/protocol/gsm_12_21.h>

#include <sys/socket.h>
#include <sys/un.h>

#include <errno.h>
#include <unistd.h>

#define RF_CMD_QUERY '?'
#define RF_CMD_OFF   '0'
#define RF_CMD_ON    '1'
#define RF_CMD_D_OFF 'd'
#define RF_CMD_ON_G  'g'

static const struct value_string opstate_names[] = {
	{ OSMO_BSC_RF_OPSTATE_INOPERATIONAL, "inoperational" },
	{ OSMO_BSC_RF_OPSTATE_OPERATIONAL, "operational" },
	{ 0, NULL }
};

static const struct value_string adminstate_names[] = {
	{ OSMO_BSC_RF_ADMINSTATE_UNLOCKED, "unlocked" },
	{ OSMO_BSC_RF_ADMINSTATE_LOCKED, "locked" },
	{ 0, NULL }
};

static const struct value_string policy_names[] = {
	{ OSMO_BSC_RF_POLICY_OFF, "off" },
	{ OSMO_BSC_RF_POLICY_ON, "on" },
	{ OSMO_BSC_RF_POLICY_GRACE, "grace" },
	{ OSMO_BSC_RF_POLICY_UNKNOWN, "unknown" },
	{ 0, NULL }
};

const char *osmo_bsc_rf_get_opstate_name(enum osmo_bsc_rf_opstate opstate)
{
	return get_value_string(opstate_names, opstate);
}

const char *osmo_bsc_rf_get_adminstate_name(enum osmo_bsc_rf_adminstate adminstate)
{
	return get_value_string(adminstate_names, adminstate);
}

const char *osmo_bsc_rf_get_policy_name(enum osmo_bsc_rf_policy policy)
{
	return get_value_string(policy_names, policy);
}

enum osmo_bsc_rf_opstate osmo_bsc_rf_get_opstate_by_bts(struct gsm_bts *bts)
{
	struct gsm_bts_trx *trx;

	llist_for_each_entry(trx, &bts->trx_list, list) {
		if (trx->mo.nm_state.operational == NM_OPSTATE_ENABLED)
			return OSMO_BSC_RF_OPSTATE_OPERATIONAL;
	}

	/* No trx were active, so this bts is disabled */
	return OSMO_BSC_RF_OPSTATE_INOPERATIONAL;
}

enum osmo_bsc_rf_adminstate osmo_bsc_rf_get_adminstate_by_bts(struct gsm_bts *bts)
{
	struct gsm_bts_trx *trx;

	llist_for_each_entry(trx, &bts->trx_list, list) {
		if (trx->mo.nm_state.administrative == NM_STATE_UNLOCKED)
			return OSMO_BSC_RF_ADMINSTATE_UNLOCKED;
	}

	/* All trx administrative states were locked */
	return OSMO_BSC_RF_ADMINSTATE_LOCKED;
}

enum osmo_bsc_rf_policy osmo_bsc_rf_get_policy_by_bts(struct gsm_bts *bts)
{
	struct osmo_bsc_data *bsc_data = bts->network->bsc_data;

	if (!bsc_data)
		return OSMO_BSC_RF_POLICY_UNKNOWN;

	switch (bsc_data->rf_ctrl->policy) {
	case S_RF_ON:
		return OSMO_BSC_RF_POLICY_ON;
	case S_RF_OFF:
		return OSMO_BSC_RF_POLICY_OFF;
	case S_RF_GRACE:
		return OSMO_BSC_RF_POLICY_GRACE;
	default:
		return OSMO_BSC_RF_POLICY_UNKNOWN;
	}
}

static int lock_each_trx(struct gsm_network *net, int lock)
{
	struct gsm_bts *bts;

	llist_for_each_entry(bts, &net->bts_list, list) {
		struct gsm_bts_trx *trx;

		/* Exclude the BTS from the global lock */
		if (bts->excl_from_rf_lock) {
			LOGP(DLINP, LOGL_DEBUG,
				"Excluding BTS(%d) from trx lock.\n", bts->nr);
			continue;
		}

		llist_for_each_entry(trx, &bts->trx_list, list) {
			gsm_trx_lock_rf(trx, lock);
		}
	}

	return 0;
}

static void send_resp(struct osmo_bsc_rf_conn *conn, char send)
{
	struct msgb *msg;

	msg = msgb_alloc(10, "RF Query");
	if (!msg) {
		LOGP(DLINP, LOGL_ERROR, "Failed to allocate response msg.\n");
		return;
	}

	msg->l2h = msgb_put(msg, 1);
	msg->l2h[0] = send;

	if (osmo_wqueue_enqueue(&conn->queue, msg) != 0) {
		LOGP(DLINP, LOGL_ERROR, "Failed to enqueue the answer.\n");
		msgb_free(msg);
		return;
	}

	return;
}


/*
 * Send a
 *    'g' when we are in grace mode
 *    '1' when one TRX is online,
 *    '0' otherwise
 */
static void handle_query(struct osmo_bsc_rf_conn *conn)
{
	struct gsm_bts *bts;
	char send = RF_CMD_OFF;

	if (conn->rf->policy == S_RF_GRACE)
		return send_resp(conn, RF_CMD_ON_G);

	llist_for_each_entry(bts, &conn->rf->gsm_network->bts_list, list) {
		struct gsm_bts_trx *trx;

		/* Exclude the BTS from the global lock */
		if (bts->excl_from_rf_lock) {
			LOGP(DLINP, LOGL_DEBUG,
				"Excluding BTS(%d) from query.\n", bts->nr);
			continue;
		}
		llist_for_each_entry(trx, &bts->trx_list, list) {
			if (trx->mo.nm_state.availability == NM_AVSTATE_OK &&
			    trx->mo.nm_state.operational != NM_OPSTATE_DISABLED) {
					send = RF_CMD_ON;
					break;
			}
		}
	}

	send_resp(conn, send);
}

static void rf_check_cb(void *_data)
{
	struct gsm_bts *bts;
	struct osmo_bsc_rf *rf = _data;

	llist_for_each_entry(bts, &rf->gsm_network->bts_list, list) {
		struct gsm_bts_trx *trx;

		/* don't bother to check a booting or missing BTS */
		if (!bts->oml_link || !is_ipaccess_bts(bts))
			continue;

		/* Exclude the BTS from the global lock */
		if (bts->excl_from_rf_lock) {
			LOGP(DLINP, LOGL_DEBUG,
				"Excluding BTS(%d) from query.\n", bts->nr);
			continue;
		}

		llist_for_each_entry(trx, &bts->trx_list, list) {
			if (trx->mo.nm_state.availability != NM_AVSTATE_OK ||
			    trx->mo.nm_state.operational != NM_OPSTATE_ENABLED ||
			    trx->mo.nm_state.administrative != NM_STATE_UNLOCKED) {
				LOGP(DNM, LOGL_ERROR, "RF activation failed. Starting again.\n");
				ipaccess_drop_oml(bts);
				break;
			}
		}
	}
}

static void send_signal(struct osmo_bsc_rf *rf, int val)
{
	struct rf_signal_data sig;
	sig.net = rf->gsm_network;

	rf->policy = val;
	osmo_signal_dispatch(SS_RF, val, &sig);
}

static int switch_rf_off(struct osmo_bsc_rf *rf)
{
	lock_each_trx(rf->gsm_network, 1);
	send_signal(rf, S_RF_OFF);

	return 0;
}

static void grace_timeout(void *_data)
{
	struct osmo_bsc_rf *rf = (struct osmo_bsc_rf *) _data;

	LOGP(DLINP, LOGL_NOTICE, "Grace timeout. Going to disable all BTS/TRX.\n");
	switch_rf_off(rf);
}

static int enter_grace(struct osmo_bsc_rf *rf)
{
	if (osmo_timer_pending(&rf->grace_timeout)) {
		LOGP(DLINP, LOGL_NOTICE, "RF Grace timer is pending. Not restarting.\n");
		return 0;
	}

	osmo_timer_setup(&rf->grace_timeout, grace_timeout, rf);
	osmo_timer_schedule(&rf->grace_timeout, rf->gsm_network->bsc_data->mid_call_timeout, 0);
	LOGP(DLINP, LOGL_NOTICE, "Going to switch RF off in %d seconds.\n",
	     rf->gsm_network->bsc_data->mid_call_timeout);

	send_signal(rf, S_RF_GRACE);
	return 0;
}

static void rf_delay_cmd_cb(void *data)
{
	struct osmo_bsc_rf *rf = data;

	switch (rf->last_request) {
	case RF_CMD_D_OFF:
		rf->last_state_command = "RF Direct Off";
		osmo_timer_del(&rf->rf_check);
		osmo_timer_del(&rf->grace_timeout);
		switch_rf_off(rf);
		break;
	case RF_CMD_ON:
		rf->last_state_command = "RF Direct On";
		osmo_timer_del(&rf->grace_timeout);
		lock_each_trx(rf->gsm_network, 0);
		send_signal(rf, S_RF_ON);
		osmo_timer_schedule(&rf->rf_check, 3, 0);
		break;
	case RF_CMD_OFF:
		rf->last_state_command = "RF Scheduled Off";
		osmo_timer_del(&rf->rf_check);
		enter_grace(rf);
		break;
	}
}

static int rf_read_cmd(struct osmo_fd *fd)
{
	struct osmo_bsc_rf_conn *conn = fd->data;
	char buf[1];
	int rc;

	rc = read(fd->fd, buf, sizeof(buf));
	if (rc != sizeof(buf)) {
		LOGP(DLINP, LOGL_ERROR, "Short read %d/%s\n", errno, strerror(errno));
		osmo_fd_unregister(fd);
		close(fd->fd);
		osmo_wqueue_clear(&conn->queue);
		talloc_free(conn);
		return -1;
	}

	switch (buf[0]) {
	case RF_CMD_QUERY:
		handle_query(conn);
		break;
	case RF_CMD_D_OFF:
	case RF_CMD_ON:
	case RF_CMD_OFF:
		osmo_bsc_rf_schedule_lock(conn->rf, buf[0]);
		break;
	default:
		conn->rf->last_state_command = "Unknown command";
		LOGP(DLINP, LOGL_ERROR, "Unknown command %d\n", buf[0]);
		break;
	}

	return 0;
}

static int rf_write_cmd(struct osmo_fd *fd, struct msgb *msg)
{
	int rc;

	rc = write(fd->fd, msg->data, msg->len);
	if (rc != msg->len) {
		LOGP(DLINP, LOGL_ERROR, "Short write %d/%s\n", errno, strerror(errno));
		return -1;
	}

	return 0;
}

static int rf_ctrl_accept(struct osmo_fd *bfd, unsigned int what)
{
	struct osmo_bsc_rf_conn *conn;
	struct osmo_bsc_rf *rf = bfd->data;
	struct sockaddr_un addr;
	socklen_t len = sizeof(addr);
	int fd;

	fd = accept(bfd->fd, (struct sockaddr *) &addr, &len);
	if (fd < 0) {
		LOGP(DLINP, LOGL_ERROR, "Failed to accept. errno: %d/%s\n",
		     errno, strerror(errno));
		return -1;
	}

	conn = talloc_zero(rf, struct osmo_bsc_rf_conn);
	if (!conn) {
		LOGP(DLINP, LOGL_ERROR, "Failed to allocate mem.\n");
		close(fd);
		return -1;
	}

	osmo_wqueue_init(&conn->queue, 10);
	conn->queue.bfd.data = conn;
	conn->queue.bfd.fd = fd;
	conn->queue.bfd.when = BSC_FD_READ | BSC_FD_WRITE;
	conn->queue.read_cb = rf_read_cmd;
	conn->queue.write_cb = rf_write_cmd;
	conn->rf = rf;

	if (osmo_fd_register(&conn->queue.bfd) != 0) {
		close(fd);
		talloc_free(conn);
		return -1;
	}

	return 0;
}

static void rf_auto_off_cb(void *_timer)
{
	struct osmo_bsc_rf *rf = _timer;

	LOGP(DLINP, LOGL_NOTICE,
		"Going to switch off RF due lack of a MSC connection.\n");
	osmo_bsc_rf_schedule_lock(rf, RF_CMD_D_OFF);
}

static int msc_signal_handler(unsigned int subsys, unsigned int signal,
			void *handler_data, void *signal_data)
{
	struct gsm_network *net;
	struct msc_signal_data *msc;
	struct osmo_bsc_rf *rf;

	/* check if we want to handle this signal */
	if (subsys != SS_MSC)
		return 0;

	net = handler_data;
	msc = signal_data;

	/* check if we have the needed information */
	if (!net->bsc_data)
		return 0;
	if (msc->data->type != MSC_CON_TYPE_NORMAL)
		return 0;

	rf = net->bsc_data->rf_ctrl;
	switch (signal) {
	case S_MSC_LOST:
		if (net->bsc_data->auto_off_timeout < 0)
			return 0;
		if (osmo_timer_pending(&rf->auto_off_timer))
			return 0;
		osmo_timer_schedule(&rf->auto_off_timer,
				net->bsc_data->auto_off_timeout, 0);
		break;
	case S_MSC_CONNECTED:
		osmo_timer_del(&rf->auto_off_timer);
		break;
	}

	return 0;
}

static int rf_create_socket(struct osmo_bsc_rf *rf, const char *path)
{
	unsigned int namelen;
	struct sockaddr_un local;
	struct osmo_fd *bfd;
	int rc;

	bfd = &rf->listen;
	bfd->fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (bfd->fd < 0) {
		LOGP(DLINP, LOGL_ERROR, "Can not create socket. %d/%s\n",
		     errno, strerror(errno));
		return -1;
	}

	local.sun_family = AF_UNIX;
	osmo_strlcpy(local.sun_path, path, sizeof(local.sun_path));
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
		LOGP(DLINP, LOGL_ERROR, "Failed to bind '%s' errno: %d/%s\n",
		     local.sun_path, errno, strerror(errno));
		close(bfd->fd);
		return -1;
	}

	if (listen(bfd->fd, 0) != 0) {
		LOGP(DLINP, LOGL_ERROR, "Failed to listen: %d/%s\n", errno, strerror(errno));
		close(bfd->fd);
		return -1;
	}

	bfd->when = BSC_FD_READ;
	bfd->cb = rf_ctrl_accept;
	bfd->data = rf;

	if (osmo_fd_register(bfd) != 0) {
		LOGP(DLINP, LOGL_ERROR, "Failed to register bfd.\n");
		close(bfd->fd);
		return -1;
	}

	return 0;
}

struct osmo_bsc_rf *osmo_bsc_rf_create(const char *path, struct gsm_network *net)
{
	struct osmo_bsc_rf *rf;

	rf = talloc_zero(NULL, struct osmo_bsc_rf);
	if (!rf) {
		LOGP(DLINP, LOGL_ERROR, "Failed to create osmo_bsc_rf.\n");
		return NULL;
	}

	if (path && rf_create_socket(rf, path) != 0) {
		talloc_free(rf);
		return NULL;
	}

	rf->gsm_network = net;
	rf->policy = S_RF_ON;
	rf->last_state_command = "";
	rf->last_rf_lock_ctrl_command = talloc_strdup(rf, "");

	/* check the rf state */
	osmo_timer_setup(&rf->rf_check, rf_check_cb, rf);

	/* delay cmd handling */
	osmo_timer_setup(&rf->delay_cmd, rf_delay_cmd_cb, rf);

	osmo_timer_setup(&rf->auto_off_timer, rf_auto_off_cb, rf);

	/* listen to RF signals */
	osmo_signal_register_handler(SS_MSC, msc_signal_handler, net);

	return rf;
}

void osmo_bsc_rf_schedule_lock(struct osmo_bsc_rf *rf, char cmd)
{
	rf->last_request = cmd;
	if (!osmo_timer_pending(&rf->delay_cmd))
		osmo_timer_schedule(&rf->delay_cmd, 1, 0);
}
