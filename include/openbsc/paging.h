/* Paging helper and manager.... */
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

#ifndef PAGING_H
#define PAGING_H

#include <malloc.h>
#include <string.h>

#include "linuxlist.h"
#include "gsm_data.h"
#include "gsm_subscriber.h"
#include "timer.h"

/**
 * A pending paging request 
 */
struct paging_request {
	struct llist_head entry;
	struct gsm_subscriber *subscr;
	struct gsm_bts *bts;

	int chan_type;
};

/*
 * struct for each bts we serve...
 */
struct paging_bts {
	/* public callbacks */
	void (*channel_allocated)(struct gsm_lchan *lchan);

	/* list for each bts */
	struct llist_head bts_list;

	/* pending requests */
	struct llist_head pending_requests;
	struct paging_request *last_request;
	struct gsm_bts *bts;

	/* tick timer */
	struct timer_list page_timer;
};

/* call once for every gsm_bts... */
struct paging_bts* page_allocate(struct gsm_bts *bts);

/* schedule paging request */
void page_request(struct gsm_bts *bts, struct gsm_subscriber *subscr, int type);

#endif
