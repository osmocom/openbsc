/* Generic signalling/notification infrastructure */
/* (C) 2009 by Holger Hans Peter Freyther <zecke@selfish.org>
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

#include <openbsc/signal.h>
#include <malloc.h>
#include <string.h>


static LLIST_HEAD(signal_handler_list);

struct signal_handler {
	struct llist_head entry;
	int areas;

	int (*sig_handler)(struct signal_data *, void*);
	void *data;
};


void register_signal_handler(int areas,
	int (*handler)(struct signal_data *, void *), void *data)
{
	struct signal_handler *sig_data =
		(struct signal_handler *)malloc(sizeof(*sig_data));
	memset(sig_data, 0, sizeof(*sig_data));


	sig_data->areas = areas;
	sig_data->data = data;
	sig_data->sig_handler = handler;
	llist_add_tail(&signal_handler_list, &sig_data->entry);
}

void remove_signal_handler(int (*sig_handler)(struct signal_data *, void *), void *data)
{
	struct signal_handler *handler;

	llist_for_each_entry(handler, &signal_handler_list, entry) {
		if (handler->sig_handler == sig_handler && handler->data == data) {
			llist_del(&handler->entry);
			free(handler);
			break;
		}
	}
}


void dispatch_signal(int area, struct signal_data *data)
{
	struct signal_handler *handler;

	llist_for_each_entry(handler, &signal_handler_list, entry) {
		if (handler->areas & area) {
		    (*handler->sig_handler)(data, handler->data);
		}
	}
}
