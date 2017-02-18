/*
 * (C) 2010-2013 by Holger Hans Peter Freyther <zecke@selfish.org>
 * (C) 2010-2013 by On-Waves
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

#ifndef OSMO_BSC_GRACE_H
#define OSMO_BSC_GRACE_H

#include <openbsc/gsm_data.h>
#include <openbsc/signal.h>

struct bsc_msc_data;

int bsc_grace_allow_new_connection(struct gsm_network *net, struct gsm_bts *bts);
int bsc_grace_paging_request(enum signal_rf rf_policy,
			     struct bsc_subscr *subscr,
			     int chan_needed,
			     struct bsc_msc_data *msc);

#endif
