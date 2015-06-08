/* Routines to talk to the MSC using the IPA Protocol */
/*
 * (C) 2010 by Holger Hans Peter Freyther <zecke@selfish.org>
 * (C) 2010 by On-Waves
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

#ifndef BSC_MSC_H
#define BSC_MSC_H

#include <osmocom/core/write_queue.h>
#include <osmocom/core/timer.h>

#include <netinet/in.h>

struct bsc_msc_dest {
	struct llist_head list;

	char *ip;
	int port;
	int dscp;
};


struct bsc_msc_connection {
	struct osmo_wqueue write_queue;
	int is_connected;
	int is_authenticated;
	int first_contact;

	struct llist_head *dests;

	const char *name;

	void (*connection_loss) (struct bsc_msc_connection *);
	void (*connected) (struct bsc_msc_connection *);
	struct osmo_timer_list reconnect_timer;
	struct osmo_timer_list timeout_timer;

	struct msgb *pending_msg;
};

struct bsc_msc_connection *bsc_msc_create(void *ctx, struct llist_head *dest);
int bsc_msc_connect(struct bsc_msc_connection *);
void bsc_msc_schedule_connect(struct bsc_msc_connection *);

void bsc_msc_lost(struct bsc_msc_connection *);

struct msgb *bsc_msc_id_get_resp(int fixed, const char *token, const uint8_t *res, int len);

#endif
