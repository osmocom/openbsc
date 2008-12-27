/*
 * (C) 2008 by Holger Hans Peter Freyther <zecke@selfish.org>
 * (C) 2008 by Stefan Schmidt <stefan@datenfreihafen.org>
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

#ifndef _CALL_HANDLING_H
#define _CALL_HANDLING_H

#include "linuxlist.h"
#include "gsm_subscriber.h"
#include "timer.h"

/*
 * State transitions to be seen from the outside
 */
#define CALL_STATE_NULL				0
#define CALL_STATE_SETUP			1
#define CALL_STATE_PROCEED 			2
#define CALL_STATE_ALERT			3
#define CALL_STATE_CONNECT			4
#define CALL_STATE_ACTIVE			5
#define CALL_STATE_RELEASE			6

struct call_data {
	struct llist_head entry;
	void (*state_change_cb)(int oldstate, int newstate, int event, void *data);
	void *data;
	char *destination_number;

	/* Internal */
	int state;
	char tmsi[GSM_TMSI_LENGTH];
	struct timer_list t30x; /* to be added for... */
};


int call_initiate(struct call_data *call, char *tmsi);
void call_abort(struct call_data *call);

/**
 * Get notified about new incoming calls. The call_data is owned
 * and managed by the internal call handling.
 */
void call_set_callback(void (*cb)(struct call_data *call, void *data), void* data);
void call_proceed(struct call_data *call_data);
void call_connect(struct call_data *call_data);

#endif /* _CALL_HANDLING_H */
