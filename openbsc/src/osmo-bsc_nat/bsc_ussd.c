/* USSD Filter Code */

/*
 * (C) 2010-2011 by Holger Hans Peter Freyther <zecke@selfish.org>
 * (C) 2010-2011 by On-Waves
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

#include <openbsc/bsc_nat.h>
#include <openbsc/bsc_nat_sccp.h>
#include <openbsc/ipaccess.h>
#include <openbsc/socket.h>

#include <osmocom/gsm/protocol/gsm_08_08.h>
#include <osmocom/gsm/gsm0480.h>
#include <osmocom/core/talloc.h>
#include <osmocom/gsm/tlv.h>

#include <osmocom/sccp/sccp.h>

#include <osmocom/abis/ipa.h>

#include <sys/socket.h>
#include <string.h>
#include <unistd.h>

#define USSD_LAC_IE	0
#define USSD_CI_IE	1

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
	if (con->nat->ussd_con == con) {
		bsc_close_ussd_connections(con->nat);
		con->nat->ussd_con = NULL;
	}

	close(con->queue.bfd.fd);
	osmo_fd_unregister(&con->queue.bfd);
	osmo_timer_del(&con->auth_timeout);
	osmo_wqueue_clear(&con->queue);
	talloc_free(con);
}

static int forward_sccp(struct bsc_nat *nat, struct msgb *msg)
{
	struct nat_sccp_connection *con;
	struct bsc_nat_parsed *parsed;


	parsed = bsc_nat_parse(msg);
	if (!parsed) {
		LOGP(DNAT, LOGL_ERROR, "Can not parse msg from USSD.\n");
		msgb_free(msg);
		return -1;
	}

	if (!parsed->dest_local_ref) {
		LOGP(DNAT, LOGL_ERROR, "No destination local reference.\n");
		msgb_free(msg);
		return -1;
	}

	con = bsc_nat_find_con_by_bsc(nat, parsed->dest_local_ref);
	if (!con || !con->bsc) {
		LOGP(DNAT, LOGL_ERROR, "No active connection found.\n");
		msgb_free(msg);
		return -1;
	}

	talloc_free(parsed);
	bsc_write_msg(&con->bsc->write_queue, msg);
	return 0;
}

static int ussd_read_cb(struct osmo_fd *bfd)
{
	struct bsc_nat_ussd_con *conn = bfd->data;
	struct msgb *msg;
	struct ipaccess_head *hh;
	int ret;

	ret = ipa_msg_recv(bfd->fd, &msg);
	if (ret <= 0) {
		LOGP(DNAT, LOGL_ERROR, "USSD Connection was lost.\n");
		bsc_nat_ussd_destroy(conn);
		return -1;
	}

	LOGP(DNAT, LOGL_NOTICE, "MSG from USSD: %s proto: %d\n",
		osmo_hexdump(msg->data, msg->len), msg->l2h[0]);
	hh = (struct ipaccess_head *) msg->data;

	if (hh->proto == IPAC_PROTO_IPACCESS) {
		if (msg->l2h[0] == IPAC_MSGT_ID_RESP) {
			struct tlv_parsed tvp;
			int ret;
			ret = ipaccess_idtag_parse(&tvp,
					     (unsigned char *) msg->l2h + 2,
					     msgb_l2len(msg) - 2);
			if (ret < 0) {
				LOGP(DNAT, LOGL_ERROR, "ignoring IPA response "
					"message with malformed TLVs\n");
				return ret;
			}
			if (TLVP_PRESENT(&tvp, IPAC_IDTAG_UNITNAME))
				ussd_auth_con(&tvp, conn);
		}

		msgb_free(msg);
	} else if (hh->proto == IPAC_PROTO_SCCP) {
		forward_sccp(conn->nat, msg);
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

	/* last byte should be a NULL */
	if (strlen(conn->nat->ussd_token) != len - 1)
		goto disconnect;
	/* compare everything including the null byte */
	if (memcmp(conn->nat->ussd_token, token, len) != 0)
		goto disconnect;

	/* it is authenticated now */
	if (conn->nat->ussd_con && conn->nat->ussd_con != conn)
		bsc_nat_ussd_destroy(conn->nat->ussd_con);

	LOGP(DNAT, LOGL_ERROR, "USSD token specified. USSD provider is connected.\n");
	osmo_timer_del(&conn->auth_timeout);
	conn->authorized = 1;
	conn->nat->ussd_con = conn;
	return;

disconnect:
	LOGP(DNAT, LOGL_ERROR, "Wrong USSD token by client: %d\n",
		conn->queue.bfd.fd);
	bsc_nat_ussd_destroy(conn);
}

static void ussd_start_auth(struct bsc_nat_ussd_con *conn)
{
	struct msgb *msg;

	conn->auth_timeout.data = conn;
	conn->auth_timeout.cb = ussd_auth_cb;
	osmo_timer_schedule(&conn->auth_timeout, conn->nat->auth_timeout, 0);

	msg = msgb_alloc_headroom(4096, 128, "auth message");
	if (!msg) {
		LOGP(DNAT, LOGL_ERROR, "Failed to allocate auth msg\n");
		return;
	}

	msgb_v_put(msg, IPAC_MSGT_ID_GET);
	bsc_do_write(&conn->queue, msg, IPAC_PROTO_IPACCESS);
}

static int ussd_listen_cb(struct osmo_fd *bfd, unsigned int what)
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
	osmo_counter_inc(nat->stats.ussd.reconn);

	conn = bsc_nat_ussd_alloc(nat);
	if (!conn) {
		LOGP(DNAT, LOGL_ERROR, "Failed to allocate USSD con struct.\n");
		close(fd);
		return -1;
	}

	osmo_wqueue_init(&conn->queue, 10);
	conn->queue.bfd.data = conn;
	conn->queue.bfd.fd = fd;
	conn->queue.bfd.when = BSC_FD_READ;
	conn->queue.read_cb = ussd_read_cb;
	conn->queue.write_cb = bsc_write_cb;

	if (osmo_fd_register(&conn->queue.bfd) < 0) {
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
			 ntohl(addr.s_addr), 5001, 0, ussd_listen_cb, nat);
}

static int forward_ussd_simple(struct nat_sccp_connection *con, struct msgb *input)
{
	struct msgb *copy;
	struct bsc_nat_ussd_con *ussd;

	if (!con->bsc->nat->ussd_con)
		return -1;

	copy = msgb_alloc_headroom(4096, 128, "forward bts");
	if (!copy) {
		LOGP(DNAT, LOGL_ERROR, "Allocation failed, not forwarding.\n");
		return -1;
	}

	/* copy the data into the copy */
	copy->l2h = msgb_put(copy, msgb_l2len(input));
	memcpy(copy->l2h, input->l2h, msgb_l2len(input));

	/* send it out */
	ussd = con->bsc->nat->ussd_con;
	bsc_do_write(&ussd->queue, copy, IPAC_PROTO_SCCP);
	return 0;
}

static int forward_ussd(struct nat_sccp_connection *con, const struct ussd_request *req,
			struct msgb *input)
{
	struct msgb *msg, *copy;
	struct ipac_msgt_sccp_state *state;
	struct bsc_nat_ussd_con *ussd;
	uint16_t lac, ci;

	if (!con->bsc->nat->ussd_con)
		return -1;

	msg = msgb_alloc_headroom(4096, 128, "forward ussd");
	if (!msg) {
		LOGP(DNAT, LOGL_ERROR, "Allocation failed, not forwarding.\n");
		return -1;
	}

	copy = msgb_alloc_headroom(4096, 128, "forward bts");
	if (!copy) {
		LOGP(DNAT, LOGL_ERROR, "Allocation failed, not forwarding.\n");
		msgb_free(msg);
		return -1;
	}

	copy->l2h = msgb_put(copy, msgb_l2len(input));
	memcpy(copy->l2h, input->l2h, msgb_l2len(input));

	msg->l2h = msgb_put(msg, 1);
	msg->l2h[0] = IPAC_MSGT_SCCP_OLD;

	/* fill out the data */
	state = (struct ipac_msgt_sccp_state *) msgb_put(msg, sizeof(*state));
	state->trans_id = req->transaction_id;
	state->invoke_id = req->invoke_id;
	memcpy(&state->src_ref, &con->remote_ref, sizeof(con->remote_ref));
	memcpy(&state->dst_ref, &con->real_ref, sizeof(con->real_ref));
	memcpy(state->imsi, con->imsi, strlen(con->imsi));

	/* add additional tag/values */
	lac = htons(con->lac);
	ci = htons(con->ci);
	msgb_tv_fixed_put(msg, USSD_LAC_IE, sizeof(lac), (const uint8_t *) &lac);
	msgb_tv_fixed_put(msg, USSD_CI_IE, sizeof(ci), (const uint8_t *) &ci);

	ussd = con->bsc->nat->ussd_con;
	bsc_do_write(&ussd->queue, msg, IPAC_PROTO_IPACCESS);
	bsc_do_write(&ussd->queue, copy, IPAC_PROTO_SCCP);

	return 0;
}

int bsc_check_ussd(struct nat_sccp_connection *con, struct bsc_nat_parsed *parsed,
		   struct msgb *msg)
{
	uint32_t len;
	uint8_t msg_type;
	uint8_t proto;
	uint8_t ti;
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

	/* We have not verified the IMSI yet */
	if (!con->authorized)
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

	proto = hdr48->proto_discr & 0x0f;
	msg_type = hdr48->msg_type & 0xbf;
	ti = (hdr48->proto_discr & 0x70) >> 4;
	if (proto != GSM48_PDISC_NC_SS)
		return 0;

	if (msg_type == GSM0480_MTYPE_REGISTER) {

		/* now check if it is a IMSI we care about */
		lst = bsc_nat_acc_lst_find(con->bsc->nat,
					   con->bsc->nat->ussd_lst_name);
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

		if (regexec(&con->bsc->nat->ussd_query_re,
			    req.text, 0, NULL, 0) == REG_NOMATCH)
			return 0;

		/* found a USSD query for our subscriber */
		LOGP(DNAT, LOGL_NOTICE, "Found USSD query for %s\n", con->imsi);
		con->ussd_ti[ti] = 1;
		if (forward_ussd(con, &req, msg) != 0)
			return 0;
		return 1;
	} else if (msg_type == GSM0480_MTYPE_FACILITY && con->ussd_ti[ti]) {
		LOGP(DNAT, LOGL_NOTICE, "Forwarding message part of TI: %d %s\n",
		     ti, con->imsi);
		if (forward_ussd_simple(con, msg) != 0)
			return 0;
		return 1;
	}

	return 0;
}
