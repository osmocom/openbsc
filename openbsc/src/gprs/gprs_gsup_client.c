/* GPRS Subscriber Update Protocol client */

/* (C) 2014 by Sysmocom s.f.m.c. GmbH
 * All Rights Reserved
 *
 * Author: Jacob Erlbeck
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

#include <openbsc/gprs_gsup_client.h>

#include <osmocom/abis/ipa.h>
#include <osmocom/gsm/protocol/ipaccess.h>
#include <osmocom/core/msgb.h>

#include <openbsc/debug.h>

#include <errno.h>
#include <string.h>

extern void *tall_bsc_ctx;

static int gsup_client_connect(struct gprs_gsup_client *gsupc)
{
	int rc;

	if (gsupc->is_connected)
		return 0;

	if (osmo_timer_pending(&gsupc->connect_timer)) {
		LOGP(DLINP, LOGL_DEBUG,
		     "GSUP connect: connect timer already running\n");
		osmo_timer_del(&gsupc->connect_timer);
	}

	if (ipa_client_conn_clear_queue(gsupc->link) > 0)
		LOGP(DLINP, LOGL_DEBUG, "GSUP connect: discarded stored messages\n");

	rc = ipa_client_conn_open(gsupc->link);

	if (rc >= 0)
		return rc;

	LOGP(DGPRS, LOGL_INFO, "GSUP failed to connect to %s:%d: %s\n",
	     gsupc->link->addr, gsupc->link->port, strerror(-rc));

	if (rc == -EBADF || rc == -ENOTSOCK || rc == -EAFNOSUPPORT ||
	    rc == -EINVAL)
		return rc;

	osmo_timer_schedule(&gsupc->connect_timer, GPRS_GSUP_RECONNECT_INTERVAL, 0);

	return 0;
}

static void connect_timer_cb(void *gsupc_)
{
	struct gprs_gsup_client *gsupc = gsupc_;

	if (gsupc->is_connected)
		return;

	gsup_client_connect(gsupc);
}

static void gsup_client_updown_cb(struct ipa_client_conn *link, int up)
{
	struct gprs_gsup_client *gsupc = link->data;

	LOGP(DGPRS, LOGL_NOTICE, "GSUP link to %s:%d %s\n",
		     link->addr, link->port, up ? "UP" : "DOWN");

	gsupc->is_connected = up;

	if (up) {
		/* TODO: Start ping procedure */

		osmo_timer_del(&gsupc->connect_timer);
	} else {
		/* TODO: Stop ping procedure */

		osmo_timer_schedule(&gsupc->connect_timer,
				    GPRS_GSUP_RECONNECT_INTERVAL, 0);
	}
}

static int gsup_client_read_cb(struct ipa_client_conn *link, struct msgb *msg)
{
	struct ipaccess_head *hh = (struct ipaccess_head *) msg->data;
	struct ipaccess_head_ext *he = (struct ipaccess_head_ext *) msgb_l2(msg);
	struct gprs_gsup_client *gsupc = (struct gprs_gsup_client *)link->data;

	if (hh->proto != IPAC_PROTO_OSMO)
		goto invalid;

	if (!he || msgb_l2len(msg) < sizeof(*he) ||
	    he->proto != IPAC_PROTO_EXT_GSUP)
		goto invalid;

	msg->l2h = &he->data[0];

	OSMO_ASSERT(gsupc->read_cb != NULL);
	gsupc->read_cb(gsupc, msg);

	/* Not freeing msg here, because that must be done by the read_cb. */
	return 0;

invalid:
	LOGP(DGPRS, LOGL_NOTICE,
	     "GSUP received an invalid IPA message from %s:%d, size = %d\n",
	     link->addr, link->port, msgb_length(msg));

	msgb_free(msg);
	return -1;
}

struct gprs_gsup_client *gprs_gsup_client_create(const char *ip_addr,
						 unsigned int tcp_port,
						 gprs_gsup_read_cb_t read_cb)
{
	struct gprs_gsup_client *gsupc;
	int rc;

	gsupc = talloc_zero(tall_bsc_ctx, struct gprs_gsup_client);
	OSMO_ASSERT(gsupc);

	gsupc->link = ipa_client_conn_create(gsupc,
					     /* no e1inp */ NULL,
					     0,
					     ip_addr, tcp_port,
					     gsup_client_updown_cb,
					     gsup_client_read_cb,
					     /* default write_cb */ NULL,
					     gsupc);
	if (!gsupc->link)
		goto failed;

	gsupc->connect_timer.data = gsupc;
	gsupc->connect_timer.cb = &connect_timer_cb;

	rc = gsup_client_connect(gsupc);

	if (rc < 0 && rc != -EINPROGRESS)
		goto failed;

	gsupc->read_cb = read_cb;

	return gsupc;

failed:
	gprs_gsup_client_destroy(gsupc);
	return NULL;
}

void gprs_gsup_client_destroy(struct gprs_gsup_client *gsupc)
{
	osmo_timer_del(&gsupc->connect_timer);

	if (gsupc->link) {
		ipa_client_conn_close(gsupc->link);
		ipa_client_conn_destroy(gsupc->link);
		gsupc->link = NULL;
	}
	talloc_free(gsupc);
}

int gprs_gsup_client_send(struct gprs_gsup_client *gsupc, struct msgb *msg)
{
	if (!gsupc) {
		msgb_free(msg);
		return -ENOTCONN;
	}

	if (!gsupc->is_connected) {
		msgb_free(msg);
		return -EAGAIN;
	}

	ipa_prepend_header_ext(msg, IPAC_PROTO_EXT_GSUP);
	ipa_msg_push_header(msg, IPAC_PROTO_OSMO);
	ipa_client_conn_send(gsupc->link, msg);

	return 0;
}

struct msgb *gprs_gsup_msgb_alloc(void)
{
	return msgb_alloc_headroom(4000, 64, __func__);
}
