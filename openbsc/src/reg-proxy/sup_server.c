/* GSM Subscriber Update Protocol server */

/* (C) 2015 by Ivan Klyuchnikov <kluchnikovi@gmail.com>
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

#include <osmocom/abis/ipa.h>
#include <osmocom/gsm/protocol/ipaccess.h>
#include <osmocom/core/msgb.h>
#include <osmocom/core/utils.h>

#include <openbsc/debug.h>

#include <errno.h>
#include <string.h>
#include <unistd.h>

#include <openbsc/sup_server.h>
#include <openbsc/reg_proxy.h>

static int ipa_sock_server_cb(struct ipa_server_conn *conn, struct msgb *msg)
{
	struct gsm_sup_server *sup_server = conn->data;
	struct ipaccess_head *hh = (struct ipaccess_head *) msg->data;
	struct ipaccess_head_ext *he = (struct ipaccess_head_ext *) msgb_l2(msg);
	int ret;

	msg->l2h = &hh->data[0];	/* Handle IPA PING, PONG and ID_ACK messages. */
	ret = ipa_ccm_rcvmsg_base(msg, &conn->ofd);
	switch(ret) {
	case -1:
		/* error in IPA control message handling */
		goto invalid;
	case 1:
		/* this is an IPA control message, skip further processing */
		return 0;
	case 0:
		/* this is not an IPA control message, continue */
		break;
	default:
		LOGP(DSUP, LOGL_ERROR, "Unexpected return from "
					"ipa_ccm_rcvmsg_base "
					"(ret=%d)\n", ret);
		goto invalid;
	}

	if (hh->proto != IPAC_PROTO_OSMO)
		goto invalid;

	if (!he || msgb_l2len(msg) < sizeof(*he) ||
	    he->proto != IPAC_PROTO_EXT_GSUP)
		goto invalid;

	msg->l2h = &he->data[0];

	OSMO_ASSERT(sup_server->read_cb != NULL);
	sup_server->read_cb(sup_server, msg);

	/* Not freeing msg here, because that must be done by the read_cb. */
	return 0;

invalid:
	LOGP(DSUP, LOGL_NOTICE,
	     "SUP received an invalid IPA message from %s:%d, size = %d\n",
	     sup_server->link->addr, sup_server->link->port, msgb_length(msg));

	msgb_free(msg);
	return -1;

}

static int sup_accept_cb(struct ipa_server_link *link, int fd)
{
	struct gsm_sup_server *sup_server = link->data;
	struct ipa_server_conn *server_conn;


	server_conn = talloc_zero(tall_reg_ctx, struct ipa_server_conn);
	if (server_conn == NULL) {
		LOGP(DSUP, LOGL_ERROR, "cannot allocate memory for "
				       "origin IPA\n");
		close(fd);
		return -ENOMEM;
	}

	server_conn = ipa_server_conn_create(tall_reg_ctx, link, fd,
					   ipa_sock_server_cb, NULL, sup_server);
	if (server_conn == NULL) {
		LOGP(DSUP, LOGL_ERROR, "could not create server peer: %s\n",
			strerror(errno));
		return -ENOMEM;
	}
	sup_server->server_conn = server_conn;
	return 0;
}


struct gsm_sup_server *sup_server_create(const char *ip_addr,
						 unsigned int tcp_port,
						 sup_read_cb_t read_cb,
						 void *app)
{
	struct gsm_sup_server *sup_server;

	sup_server = talloc_zero(tall_reg_ctx, struct gsm_sup_server);
	OSMO_ASSERT(sup_server);

	sup_server->app = app;
	sup_server->read_cb = read_cb;
	sup_server->link = ipa_server_link_create(tall_reg_ctx, NULL,
					          ip_addr, tcp_port,
						  sup_accept_cb, sup_server);
	if (sup_server->link == NULL) {
		LOGP(DSUP, LOGL_ERROR, "cannot create OML "
			"BSC link: %s\n", strerror(errno));
		return NULL;
	}
	if (ipa_server_link_open(sup_server->link) < 0) {
		LOGP(DSUP, LOGL_ERROR, "cannot open OML BSC link: %s\n",
			strerror(errno));
		ipa_server_link_destroy(sup_server->link);
		return NULL;
	}
	return sup_server;
}

int sup_server_send(struct gsm_sup_server *sup_server, struct msgb *msg)
{
	if (!sup_server) {
		msgb_free(msg);
		return -ENOTCONN;
	}

	if (!sup_server->link) {
		msgb_free(msg);
		return -EAGAIN;
	}

	ipa_prepend_header_ext(msg, IPAC_PROTO_EXT_GSUP);
	ipa_msg_push_header(msg, IPAC_PROTO_OSMO);
	ipa_server_conn_send(sup_server->server_conn, msg);

	return 0;
}

struct msgb *sup_msgb_alloc(void)
{
	return msgb_alloc_headroom(4000, 64, __func__);
}

