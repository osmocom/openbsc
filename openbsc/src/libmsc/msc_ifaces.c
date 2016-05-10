/* Implementation for MSC decisions which interface to send messages out on. */

/* (C) 2016 by sysmocom s.m.f.c GmbH <info@sysmocom.de>
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
#include <openbsc/gsm_data.h>
#include <openbsc/msc_ifaces.h>

static int msc_tx(struct gsm_subscriber_connection *conn, struct msgb *msg)
{
	switch (conn->via_iface) {
	case IFACE_A:
		msg->dst = conn;
		return a_tx(msg);

	case IFACE_IU:
		msg->dst = conn->iu.ue_ctx;
		return iu_tx(msg, 0);

	default:
		LOGP(DMSC, LOGL_ERROR,
		     "msc_tx(): conn->via_iface invalid (%d)\n",
		     conn->via_iface);
		return -1;
	}
}


int msc_tx_dtap(struct gsm_subscriber_connection *conn,
		struct msgb *msg)
{
	return msc_tx(conn, msg);
}
