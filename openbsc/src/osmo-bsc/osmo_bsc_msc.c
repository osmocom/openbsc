/*
 * Handle the connection to the MSC. This include ping/timeout/reconnect
 * (C) 2008-2009 by Harald Welte <laforge@gnumonks.org>
 * (C) 2009-2015 by Holger Hans Peter Freyther <zecke@selfish.org>
 * (C) 2009-2015 by On-Waves
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
#include <osmocom/ctrl/control_cmd.h>
#include <osmocom/ctrl/control_if.h>
#include <osmocom/crypt/auth.h>
#include <openbsc/debug.h>
#include <openbsc/gsm_data.h>
#include <openbsc/ipaccess.h>
#include <openbsc/bsc_msc_data.h>
#include <openbsc/signal.h>

#include <osmocom/core/talloc.h>

#include <osmocom/gsm/gsm0808.h>

#include <osmocom/sccp/sccp.h>

#include <osmocom/abis/ipa.h>

#include <sys/socket.h>
#include <netinet/tcp.h>
#include <unistd.h>


static void initialize_if_needed(struct bsc_msc_connection *conn);
static void send_lacs(struct gsm_network *net, struct bsc_msc_connection *conn);
static void send_id_get_response(struct bsc_msc_data *data, int fd, struct msgb *inp);
static void send_ping(struct bsc_msc_data *data);
static void schedule_ping_pong(struct bsc_msc_data *data);

/*
 * MGCP forwarding code
 */
static int mgcp_do_read(struct osmo_fd *fd)
{
	struct bsc_msc_data *data = (struct bsc_msc_data *) fd->data;
	struct msgb *mgcp;
	int ret;

	mgcp = msgb_alloc_headroom(4096, 128, "mgcp_from_gw");
	if (!mgcp) {
		LOGP(DMGCP, LOGL_ERROR, "Failed to allocate MGCP message.\n");
		return -1;
	}

	ret = read(fd->fd, mgcp->data, 4096 - 128);
	if (ret <= 0) {
		LOGP(DMGCP, LOGL_ERROR, "Failed to read: %d/%s\n", errno, strerror(errno));
		msgb_free(mgcp);
		return -1;
	} else if (ret > 4096 - 128) {
		LOGP(DMGCP, LOGL_ERROR, "Too much data: %d\n", ret);
		msgb_free(mgcp);
		return -1;
        }

	mgcp->l2h = msgb_put(mgcp, ret);
	msc_queue_write(data->msc_con, mgcp, IPAC_PROTO_MGCP_OLD);
	return 0;
}

static int mgcp_do_write(struct osmo_fd *fd, struct msgb *msg)
{
	int ret;

	LOGP(DMGCP, LOGL_DEBUG, "Sending msg to MGCP GW size: %u\n", msg->len);

	ret = write(fd->fd, msg->data, msg->len);
	if (ret != msg->len)
		LOGP(DMGCP, LOGL_ERROR, "Failed to forward message to MGCP GW (%s).\n", strerror(errno));

	return ret;
}

static void mgcp_forward(struct bsc_msc_data *data, struct msgb *msg)
{
	struct msgb *mgcp;

	if (msgb_l2len(msg) > 4096) {
		LOGP(DMGCP, LOGL_ERROR, "Can not forward too big message.\n");
		return;
	}

	mgcp = msgb_alloc(4096, "mgcp_to_gw");
	if (!mgcp) {
		LOGP(DMGCP, LOGL_ERROR, "Failed to send message.\n");
		return;
	}

	msgb_put(mgcp, msgb_l2len(msg));
	memcpy(mgcp->data, msg->l2h, mgcp->len);
	if (osmo_wqueue_enqueue(&data->mgcp_agent, mgcp) != 0) {
		LOGP(DMGCP, LOGL_FATAL, "Could not queue message to MGCP GW.\n");
		msgb_free(mgcp);
	}
}

static int mgcp_create_port(struct bsc_msc_data *data)
{
	int on;
	struct sockaddr_in addr;

	data->mgcp_agent.bfd.fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (data->mgcp_agent.bfd.fd < 0) {
		LOGP(DMGCP, LOGL_FATAL, "Failed to create UDP socket errno: %d\n", errno);
		return -1;
	}

	on = 1;
	setsockopt(data->mgcp_agent.bfd.fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));

	/* try to bind the socket */
	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	addr.sin_port = 0;

	if (bind(data->mgcp_agent.bfd.fd, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
		LOGP(DMGCP, LOGL_FATAL, "Failed to bind to any port.\n");
		close(data->mgcp_agent.bfd.fd);
		data->mgcp_agent.bfd.fd = -1;
		return -1;
	}

	/* connect to the remote */
	addr.sin_port = htons(2427);
	if (connect(data->mgcp_agent.bfd.fd, (struct sockaddr *) & addr, sizeof(addr)) < 0) {
		LOGP(DMGCP, LOGL_FATAL, "Failed to connect to local MGCP GW. %s\n", strerror(errno));
		close(data->mgcp_agent.bfd.fd);
		data->mgcp_agent.bfd.fd = -1;
		return -1;
	}

	osmo_wqueue_init(&data->mgcp_agent, 10);
	data->mgcp_agent.bfd.when = BSC_FD_READ;
	data->mgcp_agent.bfd.data = data;
	data->mgcp_agent.read_cb = mgcp_do_read;
	data->mgcp_agent.write_cb = mgcp_do_write;

	if (osmo_fd_register(&data->mgcp_agent.bfd) != 0) {
		LOGP(DMGCP, LOGL_FATAL, "Failed to register BFD\n");
		close(data->mgcp_agent.bfd.fd);
		data->mgcp_agent.bfd.fd = -1;
		return -1;
	}

	return 0;
}

/*
 * Send data to the network
 */
int msc_queue_write(struct bsc_msc_connection *conn, struct msgb *msg, int proto)
{
	ipa_prepend_header(msg, proto);
	if (osmo_wqueue_enqueue(&conn->write_queue, msg) != 0) {
		LOGP(DMSC, LOGL_FATAL, "Failed to queue IPA/%d\n", proto);
		msgb_free(msg);
		return -1;
	}

	return 0;
}

int msc_queue_write_with_ping(struct bsc_msc_connection *conn,
			struct msgb *msg, int proto)
{
	struct bsc_msc_data *data;
	uint8_t val;

	/* prepend the header */
	ipa_prepend_header(msg, proto);
	if (osmo_wqueue_enqueue(&conn->write_queue, msg) != 0) {
		LOGP(DMSC, LOGL_FATAL, "Failed to queue IPA/%d\n", proto);
		msgb_free(msg);
		return -1;
	}

	/* add the ping as the other message */
	val = IPAC_MSGT_PING;
	msgb_l16tv_put(msg, 1, IPAC_PROTO_IPACCESS, &val);

	data = (struct bsc_msc_data *) conn->write_queue.bfd.data;
	schedule_ping_pong(data);
	return 0;
}

static int msc_alink_do_write(struct osmo_fd *fd, struct msgb *msg)
{
	int ret;

	LOGP(DMSC, LOGL_DEBUG, "Sending SCCP to MSC: %u\n", msgb_l2len(msg));
	LOGP(DLMI, LOGL_DEBUG, "MSC TX %s\n", osmo_hexdump(msg->data, msg->len));

	ret = write(fd->fd, msg->data, msg->len);
	if (ret < msg->len)
		perror("MSC: Failed to send SCCP");

	return ret;
}

static void handle_ctrl(struct bsc_msc_data *msc, struct msgb *msg)
{
	int ret;
	struct ctrl_cmd *cmd;

	cmd = ctrl_cmd_parse(msc->msc_con, msg);
	if (!cmd) {
		LOGP(DMSC, LOGL_ERROR, "Failed to parse control message.\n");
		cmd = talloc_zero(msc->msc_con, struct ctrl_cmd);
		if (!cmd) {
			LOGP(DMSC, LOGL_ERROR, "OOM!\n");
			return;
		}
		cmd->type = CTRL_TYPE_ERROR;
		cmd->id = "err";
		cmd->reply = "Failed to parse control message.";

		ctrl_cmd_send(&msc->msc_con->write_queue, cmd);
		talloc_free(cmd);

		return;
	}

	ret = ctrl_cmd_handle(msc->network->ctrl, cmd, msc->network);
	if (ret != CTRL_CMD_HANDLED)
		ctrl_cmd_send(&msc->msc_con->write_queue, cmd);
	talloc_free(cmd);
}

static void osmo_ext_handle(struct bsc_msc_data *msc, struct msgb *msg)
{
	struct ipaccess_head *hh;
	struct ipaccess_head_ext *hh_ext;

	hh = (struct ipaccess_head *) msg->data;
	hh_ext = (struct ipaccess_head_ext *) hh->data;
	if (msg->len < sizeof(*hh) + sizeof(*hh_ext)) {
		LOGP(DMSC, LOGL_ERROR, "Packet too short for extended header.\n");
		return;
	}

	msg->l2h = hh_ext->data;
	if (hh_ext->proto == IPAC_PROTO_EXT_MGCP)
		mgcp_forward(msc, msg);
	else if (hh_ext->proto == IPAC_PROTO_EXT_LAC)
		send_lacs(msc->network, msc->msc_con);
	else if (hh_ext->proto == IPAC_PROTO_EXT_CTRL)
		handle_ctrl(msc, msg);
}

static int ipaccess_a_fd_cb(struct osmo_fd *bfd)
{
	struct msgb *msg = NULL;
	struct ipaccess_head *hh;
	struct bsc_msc_data *data = (struct bsc_msc_data *) bfd->data;
	int ret;

	ret = ipa_msg_recv_buffered(bfd->fd, &msg, &data->msc_con->pending_msg);
	if (ret <= 0) {
		if (ret == -EAGAIN)
			return 0;
		if (ret == 0) {
			LOGP(DMSC, LOGL_ERROR, "The connection to the MSC was lost.\n");
			bsc_msc_lost(data->msc_con);
			return -1;
		}

		LOGP(DMSC, LOGL_ERROR, "Failed to parse ip access message: %d\n", ret);
		return -1;
	}

	LOGP(DLMI, LOGL_DEBUG, "From MSC: %s proto: %d\n", osmo_hexdump(msg->data, msg->len), msg->l2h[0]);

	/* handle base message handling */
	hh = (struct ipaccess_head *) msg->data;

	/* initialize the networking. This includes sending a GSM08.08 message */
	msg->cb[0] = (unsigned long) data;
	if (hh->proto == IPAC_PROTO_IPACCESS) {
		ipa_ccm_rcvmsg_base(msg, bfd);
		if (msg->l2h[0] == IPAC_MSGT_ID_ACK)
			initialize_if_needed(data->msc_con);
		else if (msg->l2h[0] == IPAC_MSGT_ID_GET) {
			send_id_get_response(data, bfd->fd, msg);
		} else if (msg->l2h[0] == IPAC_MSGT_PONG) {
			osmo_timer_del(&data->pong_timer);
		}
	} else if (hh->proto == IPAC_PROTO_SCCP) {
		sccp_system_incoming_ctx(msg, data->msc_con);
	} else if (hh->proto == IPAC_PROTO_MGCP_OLD) {
		mgcp_forward(data, msg);
	} else if (hh->proto == IPAC_PROTO_OSMO) {
		osmo_ext_handle(data, msg);
	}

	msgb_free(msg);
	return 0;
}

static void send_ping(struct bsc_msc_data *data)
{
	struct msgb *msg;

	msg = msgb_alloc_headroom(4096, 128, "ping");
	if (!msg) {
		LOGP(DMSC, LOGL_ERROR, "Failed to create PING.\n");
		return;
	}

	msg->l2h = msgb_put(msg, 1);
	msg->l2h[0] = IPAC_MSGT_PING;

	msc_queue_write(data->msc_con, msg, IPAC_PROTO_IPACCESS);
}

static void schedule_ping_pong(struct bsc_msc_data *data)
{
	/* send another ping in 20 seconds */
	osmo_timer_schedule(&data->ping_timer, data->ping_timeout, 0);

	/* also start a pong timer */
	osmo_timer_schedule(&data->pong_timer, data->pong_timeout, 0);
}

static void msc_ping_timeout_cb(void *_data)
{
	struct bsc_msc_data *data = (struct bsc_msc_data *) _data;
	if (data->ping_timeout <= 0)
		return;

	send_ping(data);
	schedule_ping_pong(data);
}

static void msc_pong_timeout_cb(void *_data)
{
	struct bsc_msc_data *data = (struct bsc_msc_data *) _data;

	LOGP(DMSC, LOGL_ERROR, "MSC didn't answer PING. Closing connection.\n");
	bsc_msc_lost(data->msc_con);
}

static void msc_connection_connected(struct bsc_msc_connection *con)
{
	struct msc_signal_data sig;
	struct bsc_msc_data *data;
	int ret, on;
	on = 1;
	ret = setsockopt(con->write_queue.bfd.fd, IPPROTO_TCP, TCP_NODELAY, &on, sizeof(on));
	if (ret != 0)
                LOGP(DMSC, LOGL_ERROR, "Failed to set TCP_NODELAY: %s\n", strerror(errno));

	data = (struct bsc_msc_data *) con->write_queue.bfd.data;
	msc_ping_timeout_cb(data);

	sig.data = data;
	osmo_signal_dispatch(SS_MSC, S_MSC_CONNECTED, &sig);
}

/*
 * The connection to the MSC was lost and we will need to free all
 * resources and then attempt to reconnect.
 */
static void msc_connection_was_lost(struct bsc_msc_connection *msc)
{
	struct msc_signal_data sig;
	struct bsc_msc_data *data;

	LOGP(DMSC, LOGL_ERROR, "Lost MSC connection. Freing stuff.\n");

	data = (struct bsc_msc_data *) msc->write_queue.bfd.data;
	osmo_timer_del(&data->ping_timer);
	osmo_timer_del(&data->pong_timer);

	sig.data = data;
	osmo_signal_dispatch(SS_MSC, S_MSC_LOST, &sig);

	msc->is_authenticated = 0;
	bsc_msc_schedule_connect(msc);
}

static void send_lacs(struct gsm_network *net, struct bsc_msc_connection *conn)
{
	struct ipac_ext_lac_cmd *lac;
	struct gsm_bts *bts;
	struct msgb *msg;
	int lacs = 0;

	if (llist_empty(&net->bts_list)) {
		LOGP(DMSC, LOGL_ERROR, "No BTSs configured. Not sending LACs.\n");
		return;
	}

	msg = msgb_alloc_headroom(4096, 128, "LAC Command");
	if (!msg) {
		LOGP(DMSC, LOGL_ERROR, "Failed to create the LAC command.\n");
		return;
	}

	lac = (struct ipac_ext_lac_cmd *) msgb_put(msg, sizeof(*lac));
	lac->add_remove = 1;

	llist_for_each_entry(bts, &net->bts_list, list) {
		if (lacs++ == 0)
			lac->lac = htons(bts->location_area_code);
		else
			msgb_put_u16(msg, htons(bts->location_area_code));
	}

	lac->nr_extra_lacs = lacs - 1;
	ipa_prepend_header_ext(msg, IPAC_PROTO_EXT_LAC);
	msc_queue_write(conn, msg, IPAC_PROTO_OSMO);
}

static void initialize_if_needed(struct bsc_msc_connection *conn)
{
	struct msgb *msg;

	if (!conn->is_authenticated) {
		/* send a gsm 08.08 reset message from here */
		msg = gsm0808_create_reset();
		if (!msg) {
			LOGP(DMSC, LOGL_ERROR, "Failed to create the reset message.\n");
			return;
		}

		sccp_write(msg, &sccp_ssn_bssap, &sccp_ssn_bssap, 0, conn);
		msgb_free(msg);
		conn->is_authenticated = 1;
	}
}

static int answer_challenge(struct bsc_msc_data *data, struct msgb *inp, struct osmo_auth_vector *vec)
{
	int ret;
	struct tlv_parsed tvp;
	const uint8_t *mrand;
	uint8_t mrand_len;
	struct osmo_sub_auth_data auth = {
		.type		= OSMO_AUTH_TYPE_GSM,
		.algo		= OSMO_AUTH_ALG_MILENAGE,
	};

	ret = ipa_ccm_idtag_parse_off(&tvp,
				inp->l2h + 1,
				msgb_l2len(inp) - 1, 1);
	if (ret < 0) {
		LOGP(DMSC, LOGL_ERROR, "ignoring IPA response "
			"message with malformed TLVs: %s\n", osmo_hexdump(inp->l2h + 1,
			msgb_l2len(inp) - 1));
		return 0;
	}

	mrand = TLVP_VAL(&tvp, 0x23);
	mrand_len = TLVP_LEN(&tvp, 0x23);
	if (mrand_len != 16) {
		LOGP(DMSC, LOGL_ERROR,
			"RAND is not 16 bytes. Was %d\n",
			mrand_len);
		return 0;
	}

	/* copy the key */
	memcpy(auth.u.umts.opc, data->bsc_key, 16);
	memcpy(auth.u.umts.k, data->bsc_key, 16);
	memset(auth.u.umts.amf, 0, 2);
	auth.u.umts.sqn = 0;

	/* generate the result */
	memset(vec, 0, sizeof(*vec));
	osmo_auth_gen_vec(vec, &auth, mrand);
	return 1;
}


static void send_id_get_response(struct bsc_msc_data *data, int fd, struct msgb *inp)
{
	struct msc_signal_data sig;
	struct msgb *msg;
	struct osmo_auth_vector vec;
	int valid = 0;

	if (data->bsc_key_present)
		valid = answer_challenge(data, inp, &vec);

	msg = bsc_msc_id_get_resp(valid, data->bsc_token,
			vec.res, valid ? vec.res_len : 0);
	if (!msg)
		return;
	msc_queue_write(data->msc_con, msg, IPAC_PROTO_IPACCESS);

	sig.data = data;
	osmo_signal_dispatch(SS_MSC, S_MSC_AUTHENTICATED, &sig);
}

int osmo_bsc_msc_init(struct bsc_msc_data *data)
{
	if (mgcp_create_port(data) != 0)
		return -1;

	data->msc_con = bsc_msc_create(data, &data->dests);
	if (!data->msc_con) {
		LOGP(DMSC, LOGL_ERROR, "Creating the MSC network connection failed.\n");
		return -1;
	}

	osmo_timer_setup(&data->ping_timer, msc_ping_timeout_cb, data);
	osmo_timer_setup(&data->pong_timer, msc_pong_timeout_cb, data);

	data->msc_con->write_queue.bfd.data = data;
	data->msc_con->connection_loss = msc_connection_was_lost;
	data->msc_con->connected = msc_connection_connected;
	data->msc_con->write_queue.read_cb = ipaccess_a_fd_cb;
	data->msc_con->write_queue.write_cb = msc_alink_do_write;
	bsc_msc_connect(data->msc_con);

	return 0;
}

struct bsc_msc_data *osmo_msc_data_find(struct gsm_network *net, int nr)
{
	struct bsc_msc_data *msc_data;

	llist_for_each_entry(msc_data, &net->bsc_data->mscs, entry)
		if (msc_data->nr == nr)
			return msc_data;
	return NULL;
}

struct bsc_msc_data *osmo_msc_data_alloc(struct gsm_network *net, int nr)
{
	struct bsc_msc_data *msc_data;

	/* check if there is already one */
	msc_data = osmo_msc_data_find(net, nr);
	if (msc_data)
		return msc_data;

	msc_data = talloc_zero(net, struct bsc_msc_data);
	if (!msc_data)
		return NULL;

	llist_add_tail(&msc_data->entry, &net->bsc_data->mscs);

	/* Init back pointer */
	msc_data->network = net;

	INIT_LLIST_HEAD(&msc_data->dests);
	msc_data->ping_timeout = 20;
	msc_data->pong_timeout = 5;
	msc_data->core_mnc = -1;
	msc_data->core_mcc = -1;
	msc_data->core_ci = -1;
	msc_data->core_lac = -1;
	msc_data->rtp_base = 4000;

	msc_data->nr = nr;
	msc_data->allow_emerg = 1;

	/* Defaults for the audio setup */
	msc_data->amr_conf.m5_90 = 1;

	return msc_data;
}
