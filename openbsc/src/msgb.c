/* (C) 2008 by Harald Welte <laforge@gnumonks.org>
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


#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>

#include <openbsc/msgb.h>
#include <openbsc/gsm_data.h>
#include <openbsc/talloc.h>

static void *tall_msgb_ctx;

struct msgb *msgb_alloc(u_int16_t size)
{
	struct msgb *msg;

	if (!tall_msgb_ctx)
		tall_msgb_ctx = talloc_named_const(tall_bsc_ctx, 1, "msgb");

	msg = talloc_size(tall_msgb_ctx, sizeof(*msg) + size);

	if (!msg)
		return NULL;
	memset(msg, 0, sizeof(*msg)+size);

	msg->data_len = size;
	msg->len = 0;
	msg->data = msg->_data;

	msg->head = msg->data;
	msg->data = msg->data;
	/* reset tail pointer */
	msg->tail = msg->data;
	//msg->end = msg->tail + size;

	return msg;
}

void msgb_free(struct msgb *m)
{
	talloc_free(m);
}

void msgb_enqueue(struct llist_head *queue, struct msgb *msg)
{
	llist_add_tail(&msg->list, queue);
}

struct msgb *msgb_dequeue(struct llist_head *queue)
{
	struct llist_head *lh;

	if (llist_empty(queue))
		return NULL;

	lh = queue->next;
	llist_del(lh);
	
	return llist_entry(lh, struct msgb, list);
}
