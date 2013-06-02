/* Management functions to allocate/release struct gsm_lchan */
/* (C) 2008 by Harald Welte <laforge@gnumonks.org>
 * (C) 2009 by Holger Hans Peter Freyther <zecke@selfish.org>
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
#ifndef _CHAN_ALLOC_H
#define _CHAN_ALLOC_H

#include "gsm_data.h"

struct gsm_subscriber_connection;

/* Special allocator for C0 of BTS */
struct gsm_bts_trx_ts *ts_c0_alloc(struct gsm_bts *bts,
				   enum gsm_phys_chan_config pchan);

/* Regular physical channel allocator */
struct gsm_bts_trx_ts *ts_alloc(struct gsm_bts *bts,
				enum gsm_phys_chan_config pchan);

/* Regular physical channel (TS) */
void ts_free(struct gsm_bts_trx_ts *ts);

/* Count number of free TS of given pchan type */
int lc_count_bts(struct gsm_bts *bts, enum gsm_phys_chan_config pchan);

/* Find an allocated channel for a specified subscriber */
struct gsm_subscriber_connection *connection_for_subscr(struct gsm_subscriber *subscr);

/* Allocate a logical channel (SDCCH, TCH, ...) */
struct gsm_lchan *lchan_alloc(struct gsm_bts *bts, enum gsm_chan_t type, int allow_bigger);

/* Free a logical channel (SDCCH, TCH, ...) */
void lchan_free(struct gsm_lchan *lchan);
void lchan_reset(struct gsm_lchan *lchan);

/* Release the given lchan */
int lchan_release(struct gsm_lchan *lchan, int sacch_deact, enum rsl_rel_mode release_mode);

struct load_counter {
	unsigned int total;
	unsigned int used;
};

struct pchan_load {
	struct load_counter pchan[GSM_PCHAN_UNKNOWN];
};

void bts_chan_load(struct pchan_load *cl, const struct gsm_bts *bts);
void network_chan_load(struct pchan_load *pl, struct gsm_network *net);

int ts_is_usable(struct gsm_bts_trx_ts *ts);
int trx_is_usable(struct gsm_bts_trx *trx);

#endif /* _CHAN_ALLOC_H */
