/* Radio Resource LCS (Location) Protocol, GMS TS 04.31 */

/* (C) 2009 by Harald Welte <laforge@gnumonks.org>
 *
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


#include <sys/types.h>

#include <openbsc/gsm_04_08.h>
#include <openbsc/signal.h>
#include <openbsc/gsm_subscriber.h>
#include <openbsc/chan_alloc.h>

/* RRLP msPositionReq, nsBased,
 *	Accuracy=60, Method=gps, ResponseTime=2, oneSet */
static const u_int8_t ms_based_pos_req[] = { 0x40, 0x01, 0x78, 0xa8 };

/* RRLP msPositionReq, msBasedPref,
	Accuracy=60, Method=gpsOrEOTD, ResponseTime=5, multipleSets */
static const u_int8_t ms_pref_pos_req[]  = { 0x40, 0x02, 0x79, 0x50 };

/* RRLP msPositionReq, msAssistedPref,
	Accuracy=60, Method=gpsOrEOTD, ResponseTime=5, multipleSets */
static const u_int8_t ass_pref_pos_req[] = { 0x40, 0x03, 0x79, 0x50 };

static int send_rrlp_req(struct gsm_lchan *lchan)
{
	struct gsm_network *net = lchan->ts->trx->bts->network;
	const u_int8_t *req;

	switch (net->rrlp.mode) {
	case RRLP_MODE_MS_BASED:
		req = ms_based_pos_req;
		break;
	case RRLP_MODE_MS_PREF:
		req = ms_pref_pos_req;
		break;
	case RRLP_MODE_ASS_PREF:
		req = ass_pref_pos_req;
		break;
	case RRLP_MODE_NONE:
	default:
		return 0;
	}

	return gsm48_send_rr_app_info(lchan, 0x00,
				      sizeof(ms_based_pos_req), req);
}

static int subscr_sig_cb(unsigned int subsys, unsigned int signal,
			 void *handler_data, void *signal_data)
{
	struct gsm_subscriber *subscr;
	struct gsm_lchan *lchan;

	switch (signal) {
	case S_SUBSCR_ATTACHED:
		/* A subscriber has attached. */
		subscr = signal_data;
		lchan = lchan_for_subscr(subscr);
		if (!lchan)
			break;
		send_rrlp_req(lchan);
		break;
	}
	return 0;
}

static int paging_sig_cb(unsigned int subsys, unsigned int signal,
			 void *handler_data, void *signal_data)
{
	struct paging_signal_data *psig_data = signal_data;

	switch (signal) {
	case S_PAGING_COMPLETED:
		/* paging might have "completed' unsucessfully,
		 * in this case we don't have a lchan */
		if (!psig_data->lchan)
			break;
		/* A subscriber has attached. */
		send_rrlp_req(psig_data->lchan);
		break;
	}
	return 0;
}

void on_dso_load_rrlp(void)
{
	register_signal_handler(SS_SUBSCR, subscr_sig_cb, NULL);
	register_signal_handler(SS_PAGING, paging_sig_cb, NULL);
}
