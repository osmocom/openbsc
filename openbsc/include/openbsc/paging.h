/* Paging helper and manager.... */
/* (C) 2009 by Holger Hans Peter Freyther <zecke@selfish.org>
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

#ifndef PAGING_H
#define PAGING_H

#include <stdlib.h>
#include <string.h>

#include <osmocom/core/linuxlist.h>
#include <osmocom/core/timer.h>

#include <openbsc/gsm_data.h>
#include <openbsc/bsc_subscriber.h>

/**
 * A pending paging request
 */
struct gsm_paging_request {
	/* list_head for list of all paging requests */
	struct llist_head entry;
	/* the subscriber which we're paging. Later gsm_paging_request
	 * should probably become a part of the bsc_subsrc struct? */
	struct bsc_subscr *bsub;
	/* back-pointer to the BTS on which we are paging */
	struct gsm_bts *bts;
	/* what kind of channel type do we ask the MS to establish */
	int chan_type;

	/* Timer 3113: how long do we try to page? */
	struct osmo_timer_list T3113;

	/* How often did we ask the BTS to page? */
	int attempts;

	/* callback to be called in case paging completes */
	gsm_cbfn *cbfn;
	void *cbfn_param;
};

/* schedule paging request */
int paging_request(struct gsm_network *network, struct bsc_subscr *bsub,
		   int type, gsm_cbfn *cbfn, void *data);
int paging_request_bts(struct gsm_bts *bts, struct bsc_subscr *bsub,
		       int type, gsm_cbfn *cbfn, void *data);

/* stop paging requests */
void paging_request_stop(struct llist_head *bts_list,
			 struct gsm_bts *_bts, struct bsc_subscr *bsub,
			 struct gsm_subscriber_connection *conn,
			 struct msgb *msg);

/* update paging load */
void paging_update_buffer_space(struct gsm_bts *bts, uint16_t);

/* pending paging requests */
unsigned int paging_pending_requests_nr(struct gsm_bts *bts);

void *paging_get_data(struct gsm_bts *bts, struct bsc_subscr *bsub);

#endif
