/* Generic Subscriber Update Protocol client */

/* (C) 2014-2016 by Sysmocom s.f.m.c. GmbH
 * All Rights Reserved
 *
 * Author: Jacob Erlbeck
 * Author: Neels Hofmeyr
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
#include <osmocom/core/logging.h>

#include <openbsc/debug.h>

#include <errno.h>
#include <string.h>

extern void *tall_bsc_ctx;

static void start_test_procedure(struct gprs_gsup_client *gsupc);

static void gsup_client_send_ping(struct gprs_gsup_client *gsupc)
{
	struct msgb *msg = gprs_gsup_msgb_alloc();

	msg->l2h = msgb_put(msg, 1);
	msg->l2h[0] = IPAC_MSGT_PING;
	ipa_msg_push_header(msg, IPAC_PROTO_IPACCESS);
	ipa_client_conn_send(gsupc->link, msg);
}

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

	if (osmo_timer_pending(&gsupc->ping_timer)) {
		LOGP(DLINP, LOGL_DEBUG,
		     "GSUP connect: ping timer already running\n");
		osmo_timer_del(&gsupc->ping_timer);
	}

	if (ipa_client_conn_clear_queue(gsupc->link) > 0)
		LOGP(DLINP, LOGL_DEBUG, "GSUP connect: discarded stored messages\n");

	rc = ipa_client_conn_open(gsupc->link);

	if (rc >= 0) {
		LOGP(DGPRS, LOGL_INFO, "GSUP connecting to %s:%d\n",
		     gsupc->link->addr, gsupc->link->port);
		return 0;
	}

	LOGP(DGPRS, LOGL_INFO, "GSUP failed to connect to %s:%d: %s\n",
	     gsupc->link->addr, gsupc->link->port, strerror(-rc));

	if (rc == -EBADF || rc == -ENOTSOCK || rc == -EAFNOSUPPORT ||
	    rc == -EINVAL)
		return rc;

	osmo_timer_schedule(&gsupc->connect_timer, GPRS_GSUP_RECONNECT_INTERVAL, 0);

	LOGP(DGPRS, LOGL_INFO, "Scheduled timer to retry GSUP connect to %s:%d\n",
	     gsupc->link->addr, gsupc->link->port);

	return 0;
}

static void connect_timer_cb(void *gsupc_)
{
	struct gprs_gsup_client *gsupc = gsupc_;

	if (gsupc->is_connected)
		return;

	gsup_client_connect(gsupc);
}

static void gsup_client_send(struct gprs_gsup_client *gsupc, int proto_ext, struct msgb *msg_tx)
{
	ipa_prepend_header_ext(msg_tx, proto_ext);
	ipa_msg_push_header(msg_tx, IPAC_PROTO_OSMO);
	ipa_client_conn_send(gsupc->link, msg_tx);
	/* msg_tx is now queued and will be freed. */
}

static void gsup_client_oap_register(struct gprs_gsup_client *gsupc)
{
	struct msgb *msg_tx;
	int rc;
	rc = oap_register(&gsupc->oap_state, &msg_tx);

	if ((rc < 0) || (!msg_tx)) {
		LOGP(DGPRS, LOGL_ERROR, "GSUP OAP set up, but cannot register.\n");
		return;
	}

	gsup_client_send(gsupc, IPAC_PROTO_EXT_OAP, msg_tx);
}

static void gsup_client_updown_cb(struct ipa_client_conn *link, int up)
{
	struct gprs_gsup_client *gsupc = link->data;

	LOGP(DGPRS, LOGL_INFO, "GSUP link to %s:%d %s\n",
		     link->addr, link->port, up ? "UP" : "DOWN");

	gsupc->is_connected = up;

	if (up) {
		start_test_procedure(gsupc);

		if (gsupc->oap_state.state == OAP_INITIALIZED)
			gsup_client_oap_register(gsupc);

		osmo_timer_del(&gsupc->connect_timer);
	} else {
		osmo_timer_del(&gsupc->ping_timer);

		osmo_timer_schedule(&gsupc->connect_timer,
				    GPRS_GSUP_RECONNECT_INTERVAL, 0);
	}
}

static int gsup_client_oap_handle(struct gprs_gsup_client *gsupc, struct msgb *msg_rx)
{
	int rc;
	struct msgb *msg_tx;

	rc = oap_handle(&gsupc->oap_state, msg_rx, &msg_tx);
	msgb_free(msg_rx);
	if (rc < 0)
		return rc;

	if (msg_tx)
		gsup_client_send(gsupc, IPAC_PROTO_EXT_OAP, msg_tx);

	return 0;
}

static int gsup_client_read_cb(struct ipa_client_conn *link, struct msgb *msg)
{
	struct ipaccess_head *hh = (struct ipaccess_head *) msg->data;
	struct ipaccess_head_ext *he = (struct ipaccess_head_ext *) msgb_l2(msg);
	struct gprs_gsup_client *gsupc = (struct gprs_gsup_client *)link->data;
	int rc;
	static struct ipaccess_unit ipa_dev = {
		.unit_name = "SGSN"
	};

	msg->l2h = &hh->data[0];

	rc = ipaccess_bts_handle_ccm(link, &ipa_dev, msg);

	if (rc < 0) {
		LOGP(DGPRS, LOGL_NOTICE,
		     "GSUP received an invalid IPA/CCM message from %s:%d\n",
		     link->addr, link->port);
		/* Link has been closed */
		gsupc->is_connected = 0;
		msgb_free(msg);
		return -1;
	}

	if (rc == 1) {
		uint8_t msg_type = *(msg->l2h);
		/* CCM message */
		if (msg_type == IPAC_MSGT_PONG) {
			LOGP(DGPRS, LOGL_DEBUG, "GSUP receiving PONG\n");
			gsupc->got_ipa_pong = 1;
		}

		msgb_free(msg);
		return 0;
	}

	if (hh->proto != IPAC_PROTO_OSMO)
		goto invalid;

	if (!he || msgb_l2len(msg) < sizeof(*he))
		goto invalid;

	msg->l2h = &he->data[0];

	if (he->proto == IPAC_PROTO_EXT_GSUP) {
		OSMO_ASSERT(gsupc->read_cb != NULL);
		gsupc->read_cb(gsupc, msg);
		/* expecting read_cb() to free msg */
	} else if (he->proto == IPAC_PROTO_EXT_OAP) {
		return gsup_client_oap_handle(gsupc, msg);
		/* gsup_client_oap_handle frees msg */
	} else
		goto invalid;

	return 0;

invalid:
	LOGP(DGPRS, LOGL_NOTICE,
	     "GSUP received an invalid IPA message from %s:%d, size = %d\n",
	     link->addr, link->port, msgb_length(msg));

	msgb_free(msg);
	return -1;
}

static void ping_timer_cb(void *gsupc_)
{
	struct gprs_gsup_client *gsupc = gsupc_;

	LOGP(DGPRS, LOGL_INFO, "GSUP ping callback (%s, %s PONG)\n",
	     gsupc->is_connected ? "connected" : "not connected",
	     gsupc->got_ipa_pong ? "got" : "didn't get");

	if (gsupc->got_ipa_pong) {
		start_test_procedure(gsupc);
		return;
	}

	LOGP(DGPRS, LOGL_NOTICE, "GSUP ping timed out, reconnecting\n");
	ipa_client_conn_close(gsupc->link);
	gsupc->is_connected = 0;

	gsup_client_connect(gsupc);
}

static void start_test_procedure(struct gprs_gsup_client *gsupc)
{
	gsupc->ping_timer.data = gsupc;
	gsupc->ping_timer.cb = &ping_timer_cb;

	gsupc->got_ipa_pong = 0;
	osmo_timer_schedule(&gsupc->ping_timer, GPRS_GSUP_PING_INTERVAL, 0);
	LOGP(DGPRS, LOGL_DEBUG, "GSUP sending PING\n");
	gsup_client_send_ping(gsupc);
}

struct gprs_gsup_client *gprs_gsup_client_create(const char *ip_addr,
						 unsigned int tcp_port,
						 gprs_gsup_read_cb_t read_cb,
						 struct oap_config *oap_config)
{
	struct gprs_gsup_client *gsupc;
	int rc;

	gsupc = talloc_zero(tall_bsc_ctx, struct gprs_gsup_client);
	OSMO_ASSERT(gsupc);

	rc = oap_init(oap_config, &gsupc->oap_state);
	if (rc != 0)
		goto failed;

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

	if (rc < 0)
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
	osmo_timer_del(&gsupc->ping_timer);

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

	gsup_client_send(gsupc, IPAC_PROTO_EXT_GSUP, msg);

	return 0;
}

struct msgb *gprs_gsup_msgb_alloc(void)
{
	return msgb_alloc_headroom(4000, 64, __func__);
}
