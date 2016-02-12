#include <inttypes.h>

#include <osmocom/core/logging.h>
#include <openbsc/debug.h>

#include <openbsc/gsm_data.h>
#include <openbsc/iu.h>

#include <openbsc/bsc_api.h> /* for BSC_API_CONN_POL_ACCEPT, TODO move that to libmsc */

#include "../libmsc/msc_api.h"

/* For A-interface see libbsc/bsc_api.c subscr_con_allocate() */
struct gsm_subscriber_connection *subscr_conn_allocate_iu(struct gsm_network *network,
							  struct ue_conn_ctx *ue)
{
	struct gsm_subscriber_connection *conn;

	DEBUGP(DIUCS, "Allocating IuCS subscriber conn: link_id %p, conn_id %" PRIx32 "\n",
	       ue->link, ue->conn_id);

	conn = talloc_zero(network, struct gsm_subscriber_connection);
	if (!conn)
		return NULL;

	conn->network = network;
	conn->via_iface = IFACE_IU;
	conn->iu.ue_ctx = ue;

	llist_add_tail(&conn->entry, &network->subscr_conns);
	return conn;
}

static int same_ue_conn(struct ue_conn_ctx *a, struct ue_conn_ctx *b)
{
	if (a == b)
		return 1;
	return (a->link == b->link)
		&& (a->conn_id != b->conn_id);
}

/* Return an existing IuCS subscriber connection record for the given link and
 * connection IDs, or return NULL if not found. */
static struct gsm_subscriber_connection *subscr_conn_lookup_iu(struct gsm_network *network,
							       struct ue_conn_ctx *ue)
{
	struct gsm_subscriber_connection *conn;

	llist_for_each_entry(conn, &network->subscr_conns, entry) {
		if (conn->via_iface != IFACE_IU)
			continue;
		if (!same_ue_conn(conn->iu.ue_ctx, ue))
			continue;
		DEBUGP(DIUCS, "Found IuCS subscriber for link_id %p, conn_id %" PRIx32 "\n",
		       ue->link, ue->conn_id);
		return conn;
	}
	DEBUGP(DIUCS, "No IuCS subscriber found for link_id %p, conn_id %" PRIx32 "\n",
	       ue->link, ue->conn_id);
	return NULL;
}

/* Receive MM/CC/... message from IuCS (SCCP user SAP).
 * msg->dst must reference a struct ue_conn_ctx. link_id identifies the SCTP
 * peer that sent the msg.
 *
 * For A-interface see libbsc/bsc_api.c gsm0408_rcvmsg(). */
int gsm0408_rcvmsg_iucs(struct gsm_network *network, struct msgb *msg)
{
	int rc;
	struct ue_conn_ctx *ue_ctx;
	struct gsm_subscriber_connection *conn;

	ue_ctx = (struct ue_conn_ctx*)msg->dst;

	/* TODO: are there message types that could allow us to skip this
	 * search? */
	conn = subscr_conn_lookup_iu(network, ue_ctx);

	if (conn) {
		/* if we already have a connection, handle DTAP.
		   gsm0408_dispatch() is aka msc_dtap() */

		/* Make sure we don't receive RR over IuCS; otherwise all
		 * messages handled by gsm0408_dispatch() are of interest (CC,
		 * MM, SMS, NS_SS, maybe even MM_GPRS and SM_GPRS). */
		struct gsm48_hdr *gh = msgb_l3(msg);
		uint8_t pdisc = gh->proto_discr & 0x0f;
		OSMO_ASSERT(pdisc != GSM48_PDISC_RR);

		rc = gsm0408_dispatch(conn, msg);
	} else {
		/* allocate a new connection */

		conn = subscr_conn_allocate_iu(network, ue_ctx);
		if (!conn)
			abort();

		rc = msc_compl_l3(conn, msg, 0);
		if (rc != BSC_API_CONN_POL_ACCEPT) {
			subscr_con_free(conn);
			rc = -1;
		}
		else
			rc = 0;
	}

	return rc;
}


