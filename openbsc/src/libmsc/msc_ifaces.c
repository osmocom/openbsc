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
#include <openbsc/iu.h>
#include <openbsc/gsm_subscriber.h>

#include "../../bscconfig.h"

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


/* 9.2.5 CM service accept */
int msc_gsm48_tx_mm_serv_ack(struct gsm_subscriber_connection *conn)
{
	struct msgb *msg = gsm48_msgb_alloc_name("GSM 04.08 SERV ACC");
	struct gsm48_hdr *gh = (struct gsm48_hdr *) msgb_put(msg, sizeof(*gh));

	gh->proto_discr = GSM48_PDISC_MM;
	gh->msg_type = GSM48_MT_MM_CM_SERV_ACC;

	DEBUGP(DMM, "-> CM SERVICE ACCEPT\n");

	return msc_tx_dtap(conn, msg);
}

/* 9.2.6 CM service reject */
int msc_gsm48_tx_mm_serv_rej(struct gsm_subscriber_connection *conn,
			     enum gsm48_reject_value value)
{
	struct msgb *msg;

	msg = gsm48_create_mm_serv_rej(value);
	if (!msg) {
		LOGP(DMM, LOGL_ERROR, "Failed to allocate CM Service Reject.\n");
		return -1;
	}

	DEBUGP(DMM, "-> CM SERVICE Reject cause: %d\n", value);

	return msc_tx_dtap(conn, msg);
}

int msc_tx_common_id(struct gsm_subscriber_connection *conn)
{
	/* Common ID is only sent over IuCS */
	if (conn->via_iface != IFACE_IU)
		return 0;

#ifdef BUILD_IU
	return iu_tx_common_id(conn->iu.ue_ctx, conn->subscr->imsi);
#else
	LOGP(DMM, LOGL_ERROR,
	     "Cannot send CommonID: IFACE_IU but IuCS support not built\n");
	return -ENOTSUP;
#endif
}
