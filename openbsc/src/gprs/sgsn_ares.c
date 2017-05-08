/* C-ARES DNS resolver integration */

/*
 * (C) 2015 by Holger Hans Peter Freyther
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

#include <openbsc/sgsn.h>
#include <openbsc/debug.h>

#include <netdb.h>

struct cares_event_fd {
	struct llist_head head;
	struct osmo_fd fd;
};

struct cares_cb_data {
	ares_host_callback cb;
	void *data;
};

static void osmo_ares_reschedule(struct sgsn_instance *sgsn);
static void ares_cb(void *_arg, int status, int timeouts, struct hostent *hostent)
{
	struct cares_cb_data *arg = _arg;

	arg->cb(arg->data, status, timeouts, hostent);
	osmo_ares_reschedule(sgsn);
	talloc_free(arg);
}

static int ares_osmo_fd_cb(struct osmo_fd *fd, unsigned int what)
{
	LOGP(DGPRS, LOGL_DEBUG, "C-ares fd(%d) ready(%d)\n", fd->fd, what);

	ares_process_fd(sgsn->ares_channel,
			(what & BSC_FD_READ) ? fd->fd : ARES_SOCKET_BAD,
			(what & BSC_FD_WRITE) ? fd->fd : ARES_SOCKET_BAD);
	osmo_ares_reschedule(sgsn);
	return 0;
}

static void ares_timeout_cb(void *data)
{
	struct sgsn_instance *sgsn = data;

	LOGP(DGPRS, LOGL_DEBUG, "C-ares triggering timeout\n");
	ares_process_fd(sgsn->ares_channel, ARES_SOCKET_BAD, ARES_SOCKET_BAD);
	osmo_ares_reschedule(sgsn);
}

static void osmo_ares_reschedule(struct sgsn_instance *sgsn)
{
	struct timeval *timeout, tv;

	osmo_timer_del(&sgsn->ares_timer);
	timeout = ares_timeout(sgsn->ares_channel, NULL, &tv);
	if (timeout) {
		LOGP(DGPRS, LOGL_DEBUG, "C-ares scheduling timeout %llu.%llu\n",
			(unsigned long long) tv.tv_sec,
			(unsigned long long) tv.tv_usec);
		osmo_timer_setup(&sgsn->ares_timer, ares_timeout_cb, sgsn);
		osmo_timer_schedule(&sgsn->ares_timer, tv.tv_sec, tv.tv_usec);
	}
}

static void setup_ares_osmo_fd(void *data, int fd, int read, int write)
{
	struct cares_event_fd *ufd, *tmp;

	/* delete the entry */
	if (read == 0 && write == 0) {
		llist_for_each_entry_safe(ufd, tmp, &sgsn->ares_fds, head) {
			if (ufd->fd.fd != fd)
				continue;

			LOGP(DGPRS, LOGL_DEBUG,
				"Removing C-ares watched fd (%d)\n", fd);
			osmo_fd_unregister(&ufd->fd);
			llist_del(&ufd->head);
			talloc_free(ufd);
			return;
		}
	}

	/* Search for the fd or create a new one */
	llist_for_each_entry(ufd, &sgsn->ares_fds, head) {
		if (ufd->fd.fd != fd)
			continue;

		LOGP(DGPRS, LOGL_DEBUG, "Updating C-ares fd (%d)\n", fd);
		goto update_fd;
	}

	LOGP(DGPRS, LOGL_DEBUG, "Registering C-ares fd (%d)\n", fd);
	ufd = talloc_zero(tall_bsc_ctx, struct cares_event_fd);
	ufd->fd.fd = fd;
	ufd->fd.cb = ares_osmo_fd_cb;
	ufd->fd.data = data;
	if (osmo_fd_register(&ufd->fd) != 0)
		LOGP(DGPRS, LOGL_ERROR, "Failed to register C-ares fd (%d)\n", fd);
	llist_add(&ufd->head, &sgsn->ares_fds);

update_fd:
	if (read)
		ufd->fd.when |= BSC_FD_READ;
	else
		ufd->fd.when &= ~BSC_FD_READ;

	if (write)
		ufd->fd.when |= BSC_FD_WRITE;
	else
		ufd->fd.when &= ~BSC_FD_WRITE;

	osmo_ares_reschedule(sgsn);
}

int sgsn_ares_query(struct sgsn_instance *sgsn, const char *name,
			ares_host_callback cb, void *data)
{
	struct cares_cb_data *cb_data;

	cb_data = talloc_zero(tall_bsc_ctx, struct cares_cb_data);
	cb_data->cb = cb;
	cb_data->data = data;
	ares_gethostbyname(sgsn->ares_channel, name, AF_INET, ares_cb, cb_data);
	osmo_ares_reschedule(sgsn);
	return 0;
}

int sgsn_ares_init(struct sgsn_instance *sgsn)
{
	struct ares_options options;
	int optmask;
	int rc;

	INIT_LLIST_HEAD(&sgsn->ares_fds);
	memset(&options, 0, sizeof(options));
	options.sock_state_cb = setup_ares_osmo_fd;
	options.sock_state_cb_data = sgsn;

	optmask = ARES_OPT_FLAGS | ARES_OPT_SOCK_STATE_CB | ARES_OPT_DOMAINS;

	if (sgsn->ares_servers)
		optmask |= ARES_OPT_SERVERS;

	ares_library_init(ARES_LIB_INIT_ALL);
	rc = ares_init_options(&sgsn->ares_channel, &options, optmask);
	if (rc != ARES_SUCCESS)
		return rc;

	if (sgsn->ares_servers)
		rc = ares_set_servers(sgsn->ares_channel, sgsn->ares_servers);

	return rc;
}

osmo_static_assert(ARES_SUCCESS == 0, ares_success_zero);
