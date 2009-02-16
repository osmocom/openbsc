/* Generic signalling/notification infrastructure */
/* (C) 2009 by Holger Hans Peter Freyther <zecke@selfish.org>
 * (C) 2009 by Harald Welte <laforge@gnumonks.org>
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

#ifndef OPENBSC_SIGNAL_H
#define OPENBSC_SIGNAL_H

#include <stdlib.h>
#include <errno.h>

#include <openbsc/gsm_data.h>
#include <openbsc/gsm_subscriber.h>


/*
 * Signalling subsystems
 */
#define SS_PAGING	0x0001
#define SS_SMS		0x0002

/* SS_PAGING signals */
enum signal_paging {
	S_PAGING_COMPLETED,
};

typedef int signal_cbfn(unsigned int subsys, unsigned int signal,
			void *handler_data, void *signal_data);

struct paging_signal_data {
	struct gsm_subscriber *subscr;
	struct gsm_bts *bts;

	/* NULL in case the paging didn't work */
	struct gsm_lchan *lchan;
};

/* Management */
int register_signal_handler(unsigned int subsys, signal_cbfn *cbfn, void *data);
void unregister_signal_handler(unsigned int subsys, signal_cbfn *cbfn, void *data);

/* Dispatch */
void dispatch_signal(unsigned int subsys, unsigned int signal, void *signal_data);


#endif
