/* USSD Filter Code */

/*
 * (C) 2010 by Holger Hans Peter Freyther <zecke@selfish.org>
 * (C) 2010 by On-Waves
 * All Rights Reserved
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 */

#include <openbsc/bsc_nat.h>
#include <openbsc/bsc_nat_sccp.h>
#include <openbsc/ipaccess.h>
#include <openbsc/socket.h>

#include <osmocore/protocol/gsm_08_08.h>
#include <osmocore/gsm0480.h>
#include <osmocore/talloc.h>
#include <osmocore/tlv.h>

#include <sys/socket.h>
#include <string.h>
#include <unistd.h>

struct bsc_nat_ussd_con {
	struct write_queue queue;
	struct bsc_nat *nat;
	int authorized;

	struct timer_list auth_timeout;
};

static void ussd_auth_con(struct tlv_parsed *, struct bsc_nat_ussd_con *);

static struct bsc_nat_ussd_con *bsc_nat_ussd_alloc(struct bsc_nat *nat)
{
	struct bsc_nat_ussd_con *con;

	con = talloc_zero(nat, struct bsc_nat_ussd_con);
	if (!con)
		return NULL;

	con->nat = nat;
	return con;
}

static void bsc_nat_ussd_destroy(struct bsc_nat_ussd_con *con)
{
	if (con->nat->ussd_con == con)
		con->nat->ussd_con = NULL;
	close(con->queue.bfd.fd);
	bsc_unregister_fd(&con->queue.bfd);
	bsc_del_timer(&con->auth_timeout);
	write_queue_clear(&con->queue);
	talloc_free(con);
}

static int ussd_read_cb(struct bsc_fd *bfd)
{
	int error;
	struct bsc_nat_ussd_con *conn = bfd->data;
	struct msgb *msg = ipaccess_read_msg(bfd, &error);
	struct ipaccess_head *hh;

	if (!msg) {
		LOGP(DNAT, LOGL_ERROR, "USSD Connection was lost.\n");
		bsc_nat_ussd_destroy(conn);
		return -1;
	}

	LOGP(DNAT, LOGL_NOTICE, "MSG from USSD: %s proto: %d\n",
		hexdump(msg->data, msg->len), msg->l2h[0]);
	hh = (struct ipaccess_head *) msg->data;

	if (hh->proto == IPAC_PROTO_IPACCESS) {
		if (msg->l2h[0] == IPAC_MSGT_ID_RESP) {
			struct tlv_parsed tvp;
			ipaccess_idtag_parse(&tvp,
					     (unsigned char *) msg->l2h + 2,
					     msgb_l2len(msg) - 2);
			if (TLVP_PRESENT(&tvp, IPAC_IDTAG_UNITNAME))
				ussd_auth_con(&tvp, conn);
		}

		msgb_free(msg);
	} else if (hh->proto == IPAC_PROTO_SCCP) {
		LOGP(DNAT, LOGL_ERROR, "USSD SCCP is not handled\n");
		msgb_free(msg);
	} else {
		msgb_free(msg);
	}

	return 0;
}

static void ussd_auth_cb(void *_data)
{
	LOGP(DNAT, LOGL_ERROR, "USSD module didn't authenticate\n");
	bsc_nat_ussd_destroy((struct bsc_nat_ussd_con *) _data);
}

static void ussd_auth_con(struct tlv_parsed *tvp, struct bsc_nat_ussd_con *conn)
{
	const char *token;
	int len;
	if (!conn->nat->ussd_token) {
		LOGP(DNAT, LOGL_ERROR, "No USSD token set. Closing\n");
		bsc_nat_ussd_destroy(conn);
		return;
	}

	token = (const char *) TLVP_VAL(tvp, IPAC_IDTAG_UNITNAME);
 	len = TLVP_LEN(tvp, IPAC_IDTAG_UNITNAME);
	if (strncmp(conn->nat->ussd_token, token, len) != 0) {
		LOGP(DNAT, LOGL_ERROR, "Wrong USSD token by client: %d\n",
			conn->queue.bfd.fd);
		bsc_nat_ussd_destroy(conn);
		return;
	}

	/* it is authenticated now */
	if (conn->nat->ussd_con && conn->nat->ussd_con != conn)
		bsc_nat_ussd_destroy(conn->nat->ussd_con);

	LOGP(DNAT, LOGL_ERROR, "USSD token specified. USSD provider is connected.\n");
	bsc_del_timer(&conn->auth_timeout);
	conn->authorized = 1;
	conn->nat->ussd_con = conn;
}

static void ussd_start_auth(struct bsc_nat_ussd_con *conn)
{
	struct msgb *msg;

	conn->auth_timeout.data = conn;
	conn->auth_timeout.cb = ussd_auth_cb;
	bsc_schedule_timer(&conn->auth_timeout, conn->nat->auth_timeout, 0);

	msg = msgb_alloc_headroom(4096, 128, "auth message");
	if (!msg) {
		LOGP(DNAT, LOGL_ERROR, "Failed to allocate auth msg\n");
		return;
	}

	msgb_v_put(msg, IPAC_MSGT_ID_GET);
	bsc_do_write(&conn->queue, msg, IPAC_PROTO_IPACCESS);
}

static int ussd_listen_cb(struct bsc_fd *bfd, unsigned int what)
{
	struct bsc_nat_ussd_con *conn;
	struct bsc_nat *nat;
	struct sockaddr_in sa;
	socklen_t sa_len = sizeof(sa);
	int fd;

	if (!(what & BSC_FD_READ))
		return 0;

	fd = accept(bfd->fd, (struct sockaddr *) &sa, &sa_len);
	if (fd < 0) {
		perror("accept");
		return fd;
	}

	nat = (struct bsc_nat *) bfd->data;
	counter_inc(nat->stats.ussd.reconn);

	conn = bsc_nat_ussd_alloc(nat);
	if (!conn) {
		LOGP(DNAT, LOGL_ERROR, "Failed to allocate USSD con struct.\n");
		close(fd);
		return -1;
	}

	write_queue_init(&conn->queue, 10);
	conn->queue.bfd.data = conn;
	conn->queue.bfd.fd = fd;
	conn->queue.bfd.when = BSC_FD_READ;
	conn->queue.read_cb = ussd_read_cb;
	conn->queue.write_cb = bsc_write_cb;

	if (bsc_register_fd(&conn->queue.bfd) < 0) {
		LOGP(DNAT, LOGL_ERROR, "Failed to register USSD fd.\n");
		bsc_nat_ussd_destroy(conn);
		return -1;
	}

	LOGP(DNAT, LOGL_NOTICE, "USSD Connection on %d with IP: %s\n",
	     fd, inet_ntoa(sa.sin_addr));

	/* do authentication */
	ussd_start_auth(conn);
	return 0;
}

int bsc_ussd_init(struct bsc_nat *nat)
{
	struct in_addr addr;

	addr.s_addr = INADDR_ANY;
	if (nat->ussd_local)
		inet_aton(nat->ussd_local, &addr);

	nat->ussd_listen.data = nat;
	return make_sock(&nat->ussd_listen, IPPROTO_TCP,
			 ntohl(addr.s_addr), 5001, ussd_listen_cb);
}

int bsc_check_ussd(struct sccp_connections *con, struct bsc_nat_parsed *parsed,
		   struct msgb *msg)
{
	uint32_t len;
	uint8_t msg_type;
	struct gsm48_hdr *hdr48;
	struct bsc_nat_acc_lst *lst;
	struct ussd_request req;

	/*
	 * various checks to avoid the decoding work. Right now we only want to
	 * decode if the connection was created for USSD, we do have a USSD access
	 * list, a query, a IMSI and such...
	 */
	if (con->con_type != NAT_CON_TYPE_SSA)
		return 0;

	if (!con->imsi)
		return 0;

	if (!con->bsc->nat->ussd_lst_name)
		return 0;
	if (!con->bsc->nat->ussd_query)
		return 0;

	if (parsed->bssap != BSSAP_MSG_DTAP)
		return 0;

	if (strlen(con->imsi) > GSM_IMSI_LENGTH)
		return 0;

	hdr48 = bsc_unpack_dtap(parsed, msg, &len);
	if (!hdr48)
		return 0;

	msg_type = hdr48->msg_type & 0xbf;
	if (hdr48->proto_discr != GSM48_PDISC_NC_SS || msg_type != GSM0480_MTYPE_REGISTER)
		return 0;

	/* now check if it is a IMSI we care about */
	lst = bsc_nat_acc_lst_find(con->bsc->nat, con->bsc->nat->ussd_lst_name);
	if (!lst)
		return 0;

	if (bsc_nat_lst_check_allow(lst, con->imsi) != 0)
		return 0;

	/* now decode the message and see if we really want to handle it */
	memset(&req, 0, sizeof(req));
	if (gsm0480_decode_ussd_request(hdr48, len, &req) != 1)
		return 0;
	if (req.text[0] == 0xff)
		return 0;

	if (strcmp(req.text, con->bsc->nat->ussd_query) != 0)
		return 0;

	/* found a USSD query for our subscriber */
	LOGP(DNAT, LOGL_NOTICE, "Found USSD query for %s\n", con->imsi);
	return 1;
}
