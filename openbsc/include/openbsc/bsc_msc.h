/* Routines to talk to the MSC using the IPA Protocol */
/*
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

#ifndef BSC_MSC_H
#define BSC_MSC_H

#include <osmocore/write_queue.h>
#include <osmocore/timer.h>

struct bsc_msc_connection {
	struct write_queue write_queue;
	int is_connected;
	const char *ip;
	int port;

	void (*connection_loss) (struct bsc_msc_connection *);
	void (*connected) (struct bsc_msc_connection *);
	struct timer_list reconnect_timer;
};

struct bsc_msc_connection *bsc_msc_create(const char *ip, int port);
int bsc_msc_connect(struct bsc_msc_connection *);
void bsc_msc_schedule_connect(struct bsc_msc_connection *);

void bsc_msc_lost(struct bsc_msc_connection *);

#endif
