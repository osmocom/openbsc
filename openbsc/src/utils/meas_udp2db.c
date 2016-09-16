/* liesten to meas_feed on UDP and write it to sqlite3 database */

/* (C) 2012 by Harald Welte <laforge@gnumonks.org>
 *
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

#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>

#include <netinet/in.h>

#include <osmocom/core/socket.h>
#include <osmocom/core/utils.h>
#include <osmocom/core/msgb.h>
#include <osmocom/core/select.h>
#include <osmocom/core/talloc.h>

#include <osmocom/gsm/gsm_utils.h>

#include <openbsc/meas_feed.h>

#include "meas_db.h"

static struct osmo_fd udp_ofd;
static struct meas_db_state *db;

static int handle_msg(struct msgb *msg)
{
	struct meas_feed_hdr *mfh = (struct meas_feed_hdr *) msgb_data(msg);
	struct meas_feed_meas *mfm = (struct meas_feed_meas *) msgb_data(msg);
	const char *scenario;
	time_t now = time(NULL);

	if (mfh->version != MEAS_FEED_VERSION)
		return -EINVAL;

	if (mfh->msg_type != MEAS_FEED_MEAS)
		return -EINVAL;

	if (strlen(mfm->scenario))
		scenario = mfm->scenario;
	else
		scenario = NULL;

	meas_db_insert(db, mfm->imsi, mfm->name, now,
			scenario, &mfm->mr);

	return 0;
}

static int udp_fd_cb(struct osmo_fd *ofd, unsigned int what)
{
	int rc;

	if (what & BSC_FD_READ) {
		struct msgb *msg = msgb_alloc(1024, "UDP Rx");

		rc = read(ofd->fd, msgb_data(msg), msgb_tailroom(msg));
		if (rc < 0)
			return rc;
		msgb_put(msg, rc);
		handle_msg(msg);
		msgb_free(msg);
	}

	return 0;
}

int main(int argc, char **argv)
{
	char *db_fname;
	int rc;

	msgb_talloc_ctx_init(NULL, 0);

	if (argc < 2) {
		fprintf(stderr, "You have to specify the database file name\n");
		exit(2);
	}

	db_fname = argv[1];

	udp_ofd.cb = udp_fd_cb;
	rc =  osmo_sock_init_ofd(&udp_ofd, AF_INET, SOCK_DGRAM,
			 	 IPPROTO_UDP, NULL, 8888, OSMO_SOCK_F_BIND);
	if (rc < 0) {
		fprintf(stderr, "Unable to create UDP listen socket\n");
		exit(1);
	}

	db = meas_db_open(NULL, db_fname);
	if (!db) {
		fprintf(stderr, "Unable to open database\n");
		exit(1);
	}

	/* FIXME: timer-based BEGIN/COMMIT */

	while (1) {
		osmo_select_main(0);
	};

	meas_db_close(db);

	exit(0);
}

