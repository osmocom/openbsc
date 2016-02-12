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

static int tx_dummy_a(struct msgb *msg, uint8_t sapi)
{
	LOGP(DMSC, LOGL_ERROR,
	     "attempt to send message via uninitialized A-interface\n");
	return -1
}

static int tx_dummy_iu_cs(struct msgb *msg, uint8_t sapi)
{
	LOGP(DMSC, LOGL_ERROR,
	     "attempt to send message via uninitialized IuCS-interface\n");
	return -1
}

struct msc_ifaces *global_msc_ifaces = {
	.a = {
		.tx = tx_dummy_a,
	},
	.iu_cs = {
		.tx = tx_dummy_iu_cs,
	}
};


static int msc_tx(struct msc_ifaces *ifaces,
		  struct gsm_subscriber_connection *conn,
		  struct msgb *msg)
{
	switch (conn->via_iface) {
	case IFACE_A:
		/* TODO: msg->dst = <A-iface token> */
		return ifaces->a.tx(msg, 0);

	case IFACE_IUCS:
		msg->dst = conn->iu.ue_ctx;
		return ifaces->iu_cs.tx(msg, 0);

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
	msc_tx(global_msc_ifaces, conn, msg);
}

