/* Implementations for receiving or sending MM|CC|... messages from/to the
 * BSC|RNC direction, regardless of which particular external interface is
 * actually involved (A or IuCS). */

/* (C) 2016 by sysmocom s.m.f.c GmbH <info@sysmocom.de>
 *
 * Based on parts of osmo_msc.c:
 * (C) 2010,2013 by Holger Hans Peter Freyther <zecke@selfish.org>
 * (C) 2010 by On-Waves
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
 */

#include <osmocom/core/logging.h>

#include <openbsc/debug.h>

#include <openbsc/msc_api.h>
#include <openbsc/gsm_data.h>
#include <openbsc/transaction.h>

int msc_compl_l3(struct gsm_subscriber_connection *conn, struct msgb *msg,
		 uint16_t chosen_channel)
{
	gsm0408_new_conn(conn);
	gsm0408_dispatch(conn, msg);

	/*
	 * If this is a silent call we want the channel to remain open as long as
	 * possible and this is why we accept this connection regardless of any
	 * pending transaction or ongoing operation.
	 */
	if (conn->silent_call)
		return MSC_CONN_ACCEPT;
	if (conn->loc_operation || conn->sec_operation || conn->anch_operation)
		return MSC_CONN_ACCEPT;
	if (trans_has_conn(conn))
		return MSC_CONN_ACCEPT;

	LOGP(DRR, LOGL_INFO, "MSC Complete L3: Rejecting connection.\n");
	return MSC_CONN_REJECT;
}

