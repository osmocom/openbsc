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

#include <stdlib.h>
#include <string.h>

#include <osmocore/linuxlist.h>
#include "gsm_data.h"
#include "gsm_subscriber.h"
#include <osmocore/timer.h>

/* call once for every gsm_bts... */
void paging_init(struct gsm_bts *bts);

/* schedule paging request */
int paging_request(struct gsm_network *network, struct gsm_subscriber *subscr,
		   int type, gsm_cbfn *cbfn, void *data);

/* stop paging requests */
void paging_request_stop(struct gsm_bts *bts, struct gsm_subscriber *subscr,
			 struct gsm_subscriber_connection *conn);

/* update paging load */
void paging_update_buffer_space(struct gsm_bts *bts, u_int16_t);

#endif
