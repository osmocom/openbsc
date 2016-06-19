/* Radio Resource LCS (Location) Protocol, GMS TS 04.31 */

/* (C) 2009 by Harald Welte <laforge@gnumonks.org>
 *
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



#include <openbsc/gsm_04_08.h>
#include <openbsc/signal.h>
#include <openbsc/gsm_subscriber.h>
#include <openbsc/chan_alloc.h>

/* RRLP msPositionReq, nsBased,
 *	Accuracy=60, Method=gps, ResponseTime=2, oneSet */
static const uint8_t ms_based_pos_req[] = { 0x40, 0x01, 0x78, 0xa8 };

/* RRLP msPositionReq, msBasedPref,
	Accuracy=60, Method=gpsOrEOTD, ResponseTime=5, multipleSets */
static const uint8_t ms_pref_pos_req[]  = { 0x40, 0x02, 0x79, 0x50 };

/* RRLP msPositionReq, msAssistedPref,
	Accuracy=60, Method=gpsOrEOTD, ResponseTime=5, multipleSets */
static const uint8_t ass_pref_pos_req[] = { 0x40, 0x03, 0x79, 0x50 };

static int send_rrlp_req(struct gsm_subscriber_connection *conn)
{
	struct gsm_network *net = conn->network;
	const uint8_t *req;

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

	return gsm48_send_rr_app_info(conn, 0x00,
				      sizeof(ms_based_pos_req), req);
}

static int subscr_sig_cb(unsigned int subsys, unsigned int signal,
			 void *handler_data, void *signal_data)
{
	struct vlr_subscr *vsub;
	struct gsm_subscriber_connection *conn;

	switch (signal) {
	case S_SUBSCR_ATTACHED:
		/* A subscriber has attached. */
		vsub = signal_data;
		conn = connection_for_subscr(vsub);
		if (!conn)
			break;
		send_rrlp_req(conn);
		break;
	}
	return 0;
}

static int paging_sig_cb(unsigned int subsys, unsigned int signal,
			 void *handler_data, void *signal_data)
{
	struct paging_signal_data *psig_data = signal_data;

	switch (signal) {
	case S_PAGING_SUCCEEDED:
		/* A subscriber has attached. */
		send_rrlp_req(psig_data->conn);
		break;
	case S_PAGING_EXPIRED:
		break;
	}
	return 0;
}

void on_dso_load_rrlp(void)
{
	osmo_signal_register_handler(SS_SUBSCR, subscr_sig_cb, NULL);
	osmo_signal_register_handler(SS_PAGING, paging_sig_cb, NULL);
}
