/* Code to manage MSC subscriber connections over IuCS interface */

/*
 * (C) 2016,2017 by sysmocom s.f.m.c. GmbH <info@sysmocom.de>
 *
 * Author: Neels Hofmeyr <nhofmeyr@sysmocom.de>
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

#include <inttypes.h>

#include <osmocom/core/logging.h>
#include <openbsc/debug.h>

#include <openbsc/gsm_data.h>
#include <openbsc/iu.h>
#include <openbsc/gsm_subscriber.h>
#include <openbsc/osmo_msc.h>
#include <openbsc/vlr.h>

/* For A-interface see libbsc/bsc_api.c subscr_con_allocate() */
static struct gsm_subscriber_connection *subscr_conn_allocate_iu(struct gsm_network *network,
								 struct ue_conn_ctx *ue,
								 uint16_t lac)
{
	struct gsm_subscriber_connection *conn;

	DEBUGP(DIUCS, "Allocating IuCS subscriber conn: lac %d, conn_id %" PRIx32 "\n",
	       lac, ue->conn_id);

	conn = talloc_zero(network, struct gsm_subscriber_connection);
	if (!conn)
		return NULL;

	conn->network = network;
	conn->via_ran = RAN_UTRAN_IU;
	conn->iu.ue_ctx = ue;
	conn->iu.ue_ctx->rab_assign_addr_enc = network->iu.rab_assign_addr_enc;
	conn->lac = lac;

	llist_add_tail(&conn->entry, &network->subscr_conns);
	return conn;
}

static int same_ue_conn(struct ue_conn_ctx *a, struct ue_conn_ctx *b)
{
	if (a == b)
		return 1;
	return (a->conn_id == b->conn_id);
}

static inline void log_subscribers(struct gsm_network *network)
{
	if (!log_check_level(DIUCS, LOGL_DEBUG))
		return;

	struct gsm_subscriber_connection *conn;
	int i = 0;
	llist_for_each_entry(conn, &network->subscr_conns, entry) {
		DEBUGP(DIUCS, "%3d: %s", i, vlr_subscr_name(conn->vsub));
		switch (conn->via_ran) {
		case RAN_UTRAN_IU:
			DEBUGPC(DIUCS, " Iu");
			if (conn->iu.ue_ctx) {
				DEBUGPC(DIUCS, " conn_id %d",
					conn->iu.ue_ctx->conn_id
				       );
			}
			break;
		case RAN_GERAN_A:
			DEBUGPC(DIUCS, " A");
			/* TODO log A-interface connection details */
			break;
		case RAN_UNKNOWN:
			DEBUGPC(DIUCS, " ?");
			break;
		default:
			DEBUGPC(DIUCS, " invalid");
			break;
		}
		DEBUGPC(DIUCS, "\n");
		i++;
	}
	DEBUGP(DIUCS, "subscribers registered: %d\n", i);
}

/* Return an existing IuCS subscriber connection record for the given
 * connection IDs, or return NULL if not found. */
struct gsm_subscriber_connection *subscr_conn_lookup_iu(
						struct gsm_network *network,
						struct ue_conn_ctx *ue)
{
	struct gsm_subscriber_connection *conn;

	DEBUGP(DIUCS, "Looking for IuCS subscriber: conn_id %" PRIx32 "\n",
	       ue->conn_id);
	log_subscribers(network);

	llist_for_each_entry(conn, &network->subscr_conns, entry) {
		if (conn->via_ran != RAN_UTRAN_IU)
			continue;
		if (!same_ue_conn(conn->iu.ue_ctx, ue))
			continue;
		DEBUGP(DIUCS, "Found IuCS subscriber for conn_id %" PRIx32 "\n",
		       ue->conn_id);
		return conn;
	}
	DEBUGP(DIUCS, "No IuCS subscriber found for conn_id %" PRIx32 "\n",
	       ue->conn_id);
	return NULL;
}

/* Receive MM/CC/... message from IuCS (SCCP user SAP).
 * msg->dst must reference a struct ue_conn_ctx, which identifies the peer that
 * sent the msg.
 *
 * For A-interface see libbsc/bsc_api.c gsm0408_rcvmsg(). */
int gsm0408_rcvmsg_iucs(struct gsm_network *network, struct msgb *msg,
			uint16_t *lac)
{
	int rc;
	struct ue_conn_ctx *ue_ctx;
	struct gsm_subscriber_connection *conn;

	ue_ctx = (struct ue_conn_ctx*)msg->dst;

	/* TODO: are there message types that could allow us to skip this
	 * search? */
	conn = subscr_conn_lookup_iu(network, ue_ctx);

	if (conn && lac && (conn->lac != *lac)) {
		LOGP(DIUCS, LOGL_ERROR, "IuCS subscriber has changed LAC"
		     " within the same connection, discarding connection:"
		     " %s from LAC %d to %d\n",
		     vlr_subscr_name(conn->vsub), conn->lac, *lac);
		/* Deallocate conn with previous LAC */
		msc_subscr_conn_close(conn, GSM_CAUSE_INV_MAND_INFO);
		/* At this point we could be tolerant and allocate a new
		 * connection, but changing the LAC within the same connection
		 * is shifty. Rather cancel everything. */
		return -1;
	}

	if (conn) {
		/* Make sure we don't receive RR over IuCS; otherwise all
		 * messages handled by gsm0408_dispatch() are of interest (CC,
		 * MM, SMS, NS_SS, maybe even MM_GPRS and SM_GPRS). */
		struct gsm48_hdr *gh = msgb_l3(msg);
		uint8_t pdisc = gh->proto_discr & 0x0f;
		OSMO_ASSERT(pdisc != GSM48_PDISC_RR);

		msc_dtap(conn, ue_ctx->conn_id, msg);
		rc = 0;
	} else {
		/* allocate a new connection */

		if (!lac) {
			LOGP(DIUCS, LOGL_ERROR, "New IuCS subscriber"
			     " but no LAC available. Expecting an InitialUE"
			     " message containing a LAI IE."
			     " Dropping connection.\n");
			return -1;
		}

		conn = subscr_conn_allocate_iu(network, ue_ctx, *lac);
		if (!conn)
			abort();

		/* ownership of conn hereby goes to the MSC: */
		rc = msc_compl_l3(conn, msg, 0);
	}

	return rc;
}
