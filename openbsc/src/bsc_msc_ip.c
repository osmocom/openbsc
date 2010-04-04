/* A hackish minimal BSC (+MSC +HLR) implementation */

/* (C) 2008-2009 by Harald Welte <laforge@gnumonks.org>
 * (C) 2009 by Holger Hans Peter Freyther <zecke@selfish.org>
 * (C) 2009 by On-Waves
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

#include <unistd.h>
#include <time.h>
#include <errno.h>
#include <signal.h>
#include <fcntl.h>
#include <sys/stat.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define _GNU_SOURCE
#include <getopt.h>

#include <openbsc/debug.h>
#include <openbsc/e1_input.h>
#include <openbsc/ipaccess.h>
#include <openbsc/bssap.h>
#include <openbsc/paging.h>
#include <openbsc/signal.h>
#include <openbsc/chan_alloc.h>
#include <openbsc/bsc_msc.h>
#include <openbsc/bsc_nat.h>

#include <osmocore/select.h>
#include <osmocore/talloc.h>
#include <osmocore/write_queue.h>

#include <sccp/sccp.h>

/* SCCP helper */
#define SCCP_IT_TIMER 60

/* MCC and MNC for the Location Area Identifier */
static struct debug_target *stderr_target;
struct gsm_network *bsc_gsmnet = 0;
static const char *config_file = "openbsc.cfg";
static char *msc_address = "127.0.0.1";
static struct bsc_msc_connection *msc_con;
static struct in_addr local_addr;
static LLIST_HEAD(active_connections);
static struct write_queue mgcp_agent;
extern int ipacc_rtp_direct;

extern int bsc_bootstrap_network(int (*layer4)(struct gsm_network *, int, void *), const char *cfg_file);
extern int bsc_shutdown_net(struct gsm_network *net);

struct bss_sccp_connection_data *bss_sccp_create_data()
{
	struct bss_sccp_connection_data *data;

	data = _talloc_zero(tall_bsc_ctx,
			    sizeof(struct bss_sccp_connection_data),
			    "bsc<->msc");
	if (!data)
		return NULL;

	INIT_LLIST_HEAD(&data->sccp_queue);
	INIT_LLIST_HEAD(&data->gsm_queue);
	llist_add_tail(&data->active_connections, &active_connections);
	return data;
}

void bss_sccp_free_data(struct bss_sccp_connection_data *data)
{
	bsc_del_timer(&data->T10);
	bsc_del_timer(&data->sccp_it);
	bsc_free_queued(data->sccp);
	bts_free_queued(data);
	llist_del(&data->active_connections);
	talloc_free(data);
}

static void sccp_it_fired(void *_data)
{
	struct bss_sccp_connection_data *data =
		(struct bss_sccp_connection_data *) _data;

	sccp_connection_send_it(data->sccp);
	bsc_schedule_timer(&data->sccp_it, SCCP_IT_TIMER, 0);
}


/* GSM subscriber drop-ins */
extern struct llist_head *subscr_bsc_active_subscriber(void);
struct gsm_subscriber *find_subscriber(u_int8_t type, const char *mi_string)
{
	struct gsm_subscriber *subscr;
	u_int32_t tmsi = GSM_RESERVED_TMSI;
	if (type == GSM_MI_TYPE_TMSI) {
		tmsi = tmsi_from_string(mi_string);
		if (tmsi == GSM_RESERVED_TMSI) {
			DEBUGP(DMSC, "The TMSI is the reserved one.\n");
			return NULL;
		}
	}

	llist_for_each_entry(subscr, subscr_bsc_active_subscriber(), entry) {
		if (type == GSM_MI_TYPE_TMSI && tmsi == subscr->tmsi) {
			return subscr_get(subscr);
		} else if (type == GSM_MI_TYPE_IMSI && strcmp(mi_string, subscr->imsi) == 0) {
			return subscr_get(subscr);
		}
	}

	DEBUGP(DMSC, "No subscriber has been found.\n");
	return NULL;
}



/* SCCP handling */
void msc_outgoing_sccp_data(struct sccp_connection *conn, struct msgb *msg, unsigned int len)
{
	struct bssmap_header *bs;

	if (len < 1) {
		DEBUGP(DMSC, "The header is too short.\n");
		return;
	}

	switch (msg->l3h[0]) {
	case BSSAP_MSG_BSS_MANAGEMENT:
		msg->l4h = &msg->l3h[sizeof(*bs)];
		msg->lchan = sccp_get_lchan(conn->data_ctx);
		bssmap_rcvmsg_dt1(conn, msg, len - sizeof(*bs));
		break;
	case BSSAP_MSG_DTAP:
		dtap_rcvmsg(sccp_get_lchan(conn->data_ctx), msg, len);
		break;
	default:
		DEBUGPC(DMSC, "Unimplemented msg type: %d\n", msg->l3h[0]);
	}
}

void msc_outgoing_sccp_state(struct sccp_connection *conn, int old_state)
{
	if (conn->connection_state >= SCCP_CONNECTION_STATE_RELEASE_COMPLETE) {
		DEBUGP(DMSC, "Freeing sccp conn: %p state: %d\n", conn, conn->connection_state);
		if (sccp_get_lchan(conn->data_ctx) != NULL) {
			struct gsm_lchan *lchan = sccp_get_lchan(conn->data_ctx);

			DEBUGP(DMSC, "ERROR: The lchan is still associated\n.");

			lchan->msc_data = NULL;
			put_lchan(lchan, 0);
		}

		bss_sccp_free_data((struct bss_sccp_connection_data *)conn->data_ctx);
		sccp_connection_free(conn);
		return;
	} else if (conn->connection_state == SCCP_CONNECTION_STATE_ESTABLISHED) {
		struct bss_sccp_connection_data *con_data;

		DEBUGP(DMSC, "Connection established: %p\n", conn);

		/* start the inactivity test timer */
		con_data = (struct bss_sccp_connection_data *) conn->data_ctx;
		con_data->sccp_it.cb = sccp_it_fired;
		con_data->sccp_it.data = con_data;
		bsc_schedule_timer(&con_data->sccp_it, SCCP_IT_TIMER, 0);

		bsc_send_queued(conn);
	}
}

/*
 * General COMPLETE LAYER3 INFORMATION handling for
 * PAGING RESPONSE, LOCATION UPDATING REQUEST, CM REESTABLISHMENT REQUEST,
 * CM SERVICE REQUEST, IMSI DETACH, IMMEDIATE SETUP.
 *
 * IMMEDIATE SETUP is coming from GROUP CC that is not yet
 * supported...
 */
static int open_sccp_connection(struct msgb *layer3)
{
	struct bss_sccp_connection_data *con_data;
	struct sccp_connection *sccp_connection;
	struct msgb *data;

	/* When not connected to a MSC. We will simply close things down. */
	if (!msc_con->is_connected) {
		LOGP(DMSC, LOGL_ERROR, "Not connected to a MSC. Not forwarding data.\n");
		use_lchan(layer3->lchan);
		put_lchan(layer3->lchan, 0);
		return -1;
	}

	DEBUGP(DMSC, "Opening new layer3 connection\n");
	sccp_connection = sccp_connection_socket();
	if (!sccp_connection) {
		DEBUGP(DMSC, "Failed to allocate memory.\n");
		return -ENOMEM;
	}

	data = bssmap_create_layer3(layer3);
	if (!data) {
		DEBUGP(DMSC, "Failed to allocate complete layer3.\n");
		sccp_connection_free(sccp_connection);
		return -ENOMEM;
	}

	con_data = bss_sccp_create_data();
	if (!con_data) {
		DEBUGP(DMSC, "Failed to allocate bss<->msc data.\n");
		sccp_connection_free(sccp_connection);
		msgb_free(data);
		return -ENOMEM;
	}

	/* initialize the bridge */
	con_data->lchan = layer3->lchan;
	con_data->sccp = sccp_connection;

	sccp_connection->state_cb = msc_outgoing_sccp_state;
	sccp_connection->data_cb = msc_outgoing_sccp_data;
	sccp_connection->data_ctx = con_data;
	layer3->lchan->msc_data = con_data;

	/* FIXME: Use transaction for this */
	use_lchan(layer3->lchan);
	sccp_connection_connect(sccp_connection, &sccp_ssn_bssap, data);
	msgb_free(data);

	return 1;
}

/* figure out if this is the inial layer3 message */
static int send_dtap_or_open_connection(struct msgb *msg)
{
	if (msg->lchan->msc_data) {
		struct msgb *dtap = dtap_create_msg(msg, 0);
		if (!dtap) {
			DEBUGP(DMSC, "Creating a DTAP message failed.\n");
			return -1;
		}

		bsc_queue_connection_write(lchan_get_sccp(msg->lchan), dtap);
		return 1;
	} else {
		return open_sccp_connection(msg);
	}
}

/* Receive a PAGING RESPONSE message from the MS */
static int handle_paging_response(struct msgb *msg)
{
	struct gsm_subscriber *subscr;
	char mi_string[GSM48_MI_SIZE];
	u_int8_t mi_type;

	gsm48_paging_extract_mi(msg, mi_string, &mi_type);
	DEBUGP(DMSC, "PAGING RESPONSE: mi_type=0x%02x MI(%s)\n",
		mi_type, mi_string);

	subscr = find_subscriber(mi_type, mi_string);
	if (!subscr)
		return -EINVAL;

	/* force the paging to stop at every bts */
	subscr->lac = GSM_LAC_RESERVED_ALL_BTS;
	if (gsm48_handle_paging_resp(msg, subscr) != 0) {
		DEBUGP(DMSC, "Paging failed.\n");
		return -1;
	}

	/* open a new transaction and SCCP connection */
	return send_dtap_or_open_connection(msg);
}

/* Receive a CIPHER MODE COMPLETE from the MS */
static int handle_cipher_m_complete(struct msgb *msg)
{
	struct msgb *resp;

	DEBUGP(DMSC, "CIPHER MODE COMPLETE from MS, forwarding to MSC\n");
	resp = bssmap_create_cipher_complete(msg);
	if (!resp) {
		DEBUGP(DMSC, "Creating MSC response failed.\n");
		return -1;
	}


	/* handled this message */
	bts_unblock_queue(msg->lchan->msc_data);
	bsc_queue_connection_write(lchan_get_sccp(msg->lchan), resp);
	return 1;
}

/* Receive a ASSIGNMENT COMPLETE */
static int handle_ass_compl(struct msgb *msg)
{
	struct gsm_lchan *old_chan;
	struct gsm48_hdr *gh = msgb_l3(msg);

	DEBUGP(DMSC, "ASSIGNMENT COMPLETE from MS, forwarding to MSC\n");

	if (!msg->lchan->msc_data) {
		DEBUGP(DMSC, "No MSC data\n");
		put_lchan(msg->lchan, 0);
		return -1;
	}

	if (msg->lchan->msc_data->secondary_lchan != msg->lchan) {
		LOGP(DMSC, LOGL_NOTICE, "Wrong assignment complete.\n");
		put_lchan(msg->lchan, 0);
		return -1;
	}

	if (msgb_l3len(msg) - sizeof(*gh) != 1) {
		DEBUGP(DMSC, "assignment failure invalid: %d\n",
			msgb_l3len(msg) - sizeof(*gh));
		put_lchan(msg->lchan, 0);
		return -1;
	}

	/* swap the channels and release the old */
	old_chan = msg->lchan->msc_data->lchan;
	msg->lchan->msc_data->lchan = msg->lchan;
	msg->lchan->msc_data->secondary_lchan = NULL;
	old_chan->msc_data = NULL;

	/* give up the old channel to not do a SACCH deactivate */
	subscr_put(old_chan->subscr);
	old_chan->subscr = NULL;
	put_lchan(old_chan, 1);

	/* activate audio on it... */
	if (is_ipaccess_bts(msg->lchan->ts->trx->bts) && msg->lchan->tch_mode != GSM48_CMODE_SIGN)
		rsl_ipacc_crcx(msg->lchan);

	gsm0808_send_assignment_compl(msg->lchan, gh->data[0]);
	return 1;
}

/*
 * Receive a ASSIGNMENT FAILURE. If the message is failed
 * to be parsed the T10 timer will send the failure.
 */
static int handle_ass_fail(struct msgb *msg)
{
	struct gsm48_hdr *gh = msgb_l3(msg);

	DEBUGP(DMSC, "ASSIGNMENT FAILURE from MS, forwarding to MSC\n");
	if (!msg->lchan->msc_data) {
		DEBUGP(DMSC, "No MSC data\n");
		put_lchan(msg->lchan, 0);
		return -1;
	}

	if (msg->lchan->msc_data->secondary_lchan != msg->lchan) {
		LOGP(DMSC, LOGL_NOTICE, "Wrong assignment complete.\n");
		put_lchan(msg->lchan, 0);
		return -1;
	}

	if (msgb_l3len(msg) - sizeof(*gh) != 1) {
		DEBUGP(DMSC, "assignment failure invalid: %d\n",
			msgb_l3len(msg) - sizeof(*gh));
		put_lchan(msg->lchan, 0);
		return -1;
	}

	gsm0808_send_assignment_failure(msg->lchan,
		GSM0808_CAUSE_RADIO_INTERFACE_MESSAGE_FAILURE, &gh->data[0]);
	return 1;
}

/*
 * Receive a GSM04.08 MODIFY ACK. Actually we have to check
 * the content to see if this was a success or not.
 */
static int handle_modify_ack(struct msgb *msg)
{
	int rc;

	/* modify RSL */
	rc = gsm48_rx_rr_modif_ack(msg);
	if (rc < 0)
		gsm0808_send_assignment_failure(msg->lchan,
			GSM0808_CAUSE_NO_RADIO_RESOURCE_AVAILABLE, NULL);
	else
		gsm0808_send_assignment_compl(msg->lchan, 0);

	return 1;
}

/* Receive a GSM 04.08 Radio Resource (RR) message */
static int gsm0408_rcv_rr(struct msgb *msg)
{
	struct gsm48_hdr *gh = msgb_l3(msg);
	int rc = 0;

	switch (gh->msg_type) {
	case GSM48_MT_RR_PAG_RESP:
		rc = handle_paging_response(msg);
		break;
	case GSM48_MT_RR_MEAS_REP:
		/* ignore measurement for now */
		rc = -1;
		break;
	case GSM48_MT_RR_CIPH_M_COMPL:
		rc = handle_cipher_m_complete(msg);
		break;
	case GSM48_MT_RR_ASS_COMPL:
		rc = handle_ass_compl(msg);
		break;
	case GSM48_MT_RR_ASS_FAIL:
		rc = handle_ass_fail(msg);
		break;
	case GSM48_MT_RR_CHAN_MODE_MODIF_ACK:
		rc = handle_modify_ack(msg);
		break;
	default:
		break;
	}

	return rc;
}

/* Receive a GSM 04.08 Mobility Management (MM) message */
static int gsm0408_rcv_mm(struct msgb *msg)
{
	struct gsm48_hdr *gh = msgb_l3(msg);
	int rc = 0;

	switch (gh->msg_type & 0xbf) {
	case GSM48_MT_MM_LOC_UPD_REQUEST:
	case GSM48_MT_MM_CM_REEST_REQ:
	case GSM48_MT_MM_CM_SERV_REQ:
	case GSM48_MT_MM_IMSI_DETACH_IND:
		rc = send_dtap_or_open_connection(msg);
		break;
	default:
		break;
	}

	return rc;
}

int gsm0408_rcvmsg(struct msgb *msg, u_int8_t link_id)
{
	struct gsm48_hdr *gh = msgb_l3(msg);
	u_int8_t pdisc = gh->proto_discr & 0x0f;
	int rc = 0;

	switch (pdisc) {
	case GSM48_PDISC_RR:
		rc = gsm0408_rcv_rr(msg);
		break;
	case GSM48_PDISC_MM:
		rc = gsm0408_rcv_mm(msg);
		break;
	default:
		break;
	}

	/*
	 * if we have a sccp connection and didn't handle the message
	 * forward it to the MSC using DTAP
	 */
	if (rc == 0 && msg->lchan->msc_data && lchan_get_sccp(msg->lchan)) {
		struct msgb *dtap = dtap_create_msg(msg, link_id);
		if (!dtap) {
			DEBUGP(DMSC, "Creating a DTAP message failed.\n");
			return -1;
		}

		bsc_queue_connection_write(lchan_get_sccp(msg->lchan), dtap);
	}

	return rc;
}

/* handle ipaccess signals */
static int handle_abisip_signal(unsigned int subsys, unsigned int signal,
				 void *handler_data, void *signal_data)
{
	struct gsm_lchan *lchan = signal_data;
	struct gsm_bts_trx_ts *ts;
	int rc;

	if (subsys != SS_ABISIP)
		return 0;

	ts = lchan->ts;

	switch (signal) {
	case S_ABISIP_CRCX_ACK:
		/* we can ask it to connect now */
		if (lchan->msc_data) {
			DEBUGP(DMSC, "Connecting BTS to port: %d conn: %d\n",
				lchan->msc_data->rtp_port, lchan->abis_ip.conn_id);

			int rtp_payload = ts->trx->bts->network->rtp_payload;
			if (rtp_payload == 0)
				rtp_payload = lchan->abis_ip.rtp_payload2;

			rc = rsl_ipacc_mdcx(lchan, ntohl(local_addr.s_addr),
					    lchan->msc_data->rtp_port,
					    rtp_payload);
			if (rc < 0) {
				DEBUGP(DMSC, "Failed to send connect: %d\n", rc);
				return rc;
			}
		}
		break;
	case S_ABISIP_DLCX_IND:
		break;
	}

	return 0;
}

static void print_usage()
{
	printf("Usage: bsc_hack\n");
}

/*
 * SCCP handling
 */
static int msc_queue_write(struct msgb *msg, int proto)
{
	ipaccess_prepend_header(msg, proto);
	if (write_queue_enqueue(&msc_con->write_queue, msg) != 0) {
		LOGP(DMSC, LOGL_FATAL, "Failed to queue IPA/%d\n", proto);
		msgb_free(msg);
		return -1;
	}

	return 0;
}

static int msc_sccp_do_write(struct bsc_fd *fd, struct msgb *msg)
{
	int ret;

	DEBUGP(DMSC, "Sending SCCP to MSC: %u\n", msgb_l2len(msg));
	DEBUGP(DMI, "MSC TX %s\n", hexdump(msg->l2h, msgb_l2len(msg)));

	ret = write(msc_con->write_queue.bfd.fd, msg->data, msg->len);
	if (ret < msg->len)
		perror("MSC: Failed to send SCCP");

	return ret;
}

static void msc_sccp_write_ipa(struct msgb *msg, void *data)
{
	msc_queue_write(msg, IPAC_PROTO_SCCP);
}

/*
 * mgcp forwarding is below
 */
static int mgcp_do_write(struct bsc_fd *fd, struct msgb *msg)
{
	int ret;

	LOGP(DMGCP, LOGL_DEBUG, "Sending msg to MGCP GW size: %u\n", msg->len);

	ret = write(fd->fd, msg->data, msg->len);
	if (ret != msg->len)
		LOGP(DMGCP, LOGL_ERROR, "Failed to forward message to MGCP GW (%s).\n", strerror(errno));

	return ret;
}

static int mgcp_do_read(struct bsc_fd *fd)
{
	struct msgb *mgcp;
	int ret;

	mgcp = msgb_alloc_headroom(4096, 128, "mgcp_from_gw");
	if (!mgcp) {
		LOGP(DMGCP, LOGL_ERROR, "Failed to allocate MGCP message.\n");
		return -1;
	}

	ret = read(fd->fd, mgcp->data, mgcp->len);
	if (ret <= 0) {
		LOGP(DMGCP, LOGL_ERROR, "Failed to read: %d/%s\n", errno, strerror(errno));
		msgb_free(mgcp);
		return -1;
	} else if (ret > 4096 - 128) {
		LOGP(DMGCP, LOGL_ERROR, "Too much data: %d\n", ret);
		msgb_free(mgcp);
		return -1; 
        }

	msgb_put(mgcp, ret);
	msc_queue_write(mgcp, NAT_IPAC_PROTO_MGCP);
	return 0;
}

static void mgcp_forward(struct msgb *msg)
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
	if (write_queue_enqueue(&mgcp_agent, mgcp) != 0) {
		LOGP(DMGCP, LOGL_FATAL, "Could not queue message to MGCP GW.\n");
		msgb_free(mgcp);
	}
}
static int mgcp_create_port(void)
{
	int on;
	int port;
	struct sockaddr_in addr;

	mgcp_agent.bfd.fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (mgcp_agent.bfd.fd < 0) {
		LOGP(DMGCP, LOGL_FATAL, "Failed to create UDP socket errno: %d\n", errno);
		return -1;
	}

	on = 1;
	setsockopt(mgcp_agent.bfd.fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));

	/* try to bind the socket */
	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

	for (port = 2727; port < 3000; ++port) {
		addr.sin_port = htons(port);
		if (bind(mgcp_agent.bfd.fd, (struct sockaddr *) &addr, sizeof(addr)) == 0)
			break;
		perror("foo");
	}

	if (port >= 3000) {
		LOGP(DMGCP, LOGL_FATAL, "Failed to bind to any port.\n");
		close(mgcp_agent.bfd.fd);
		mgcp_agent.bfd.fd = -1;
		return -1;
	}

	/* connect to the remote */
	addr.sin_port = htons(2427);
	if (connect(mgcp_agent.bfd.fd, (struct sockaddr *) & addr, sizeof(addr)) < 0) {
		LOGP(DMGCP, LOGL_FATAL, "Failed to connect to local MGCP GW. %s\n", strerror(errno));
		close(mgcp_agent.bfd.fd);
		mgcp_agent.bfd.fd = -1;
		return -1;
	}

	write_queue_init(&mgcp_agent, 10);
	mgcp_agent.bfd.when = BSC_FD_READ;
	mgcp_agent.read_cb = mgcp_do_read;
	mgcp_agent.write_cb = mgcp_do_write;

	if (bsc_register_fd(&mgcp_agent.bfd) != 0) {
		LOGP(DMGCP, LOGL_FATAL, "Failed to register BFD\n");
		close(mgcp_agent.bfd.fd);
		mgcp_agent.bfd.fd = -1;
		return -1;
	}


	return 0;
}


static int msc_sccp_accept(struct sccp_connection *connection, void *data)
{
	DEBUGP(DMSC, "Rejecting incoming SCCP connection.\n");
	return -1;
}

static int msc_sccp_read(struct msgb *msgb, unsigned int length, void *data)
{
	struct bssmap_header *bs;

	DEBUGP(DMSC, "Incoming SCCP message ftom MSC: %s\n", hexdump(msgb->l3h, length));

	if (length < sizeof(*bs)) {
		DEBUGP(DMSC, "The header is too short.\n");
		return -1;
	}

	bs = (struct bssmap_header *) msgb->l3h;
	if (bs->length < length - sizeof(*bs))
		return -1;

	switch (bs->type) {
	case BSSAP_MSG_BSS_MANAGEMENT:
		msgb->l4h = &msgb->l3h[sizeof(*bs)];
		bssmap_rcvmsg_udt(bsc_gsmnet, msgb, length - sizeof(*bs));
		break;
	default:
		DEBUGPC(DMSC, "Unimplemented msg type: %d\n", bs->type);
	}

	return 0;
}


/*
 * network initialisation
 */
static void initialize_if_needed(void)
{
	if (!bsc_gsmnet) {
		int rc;
		struct msgb *msg;

		fprintf(stderr, "Bootstraping the network. Sending GSM08.08 reset.\n");
		rc = bsc_bootstrap_network(NULL, config_file);
		if (rc < 0) {
			fprintf(stderr, "Bootstrapping the network failed. exiting.\n");
			exit(1);
		}


		/* send a gsm 08.08 reset message from here */
		msg = bssmap_create_reset();
		if (!msg) {
			DEBUGP(DMSC, "Failed to create the reset message.\n");
			return;
		}

		sccp_write(msg, &sccp_ssn_bssap, &sccp_ssn_bssap, 0);
		msgb_free(msg);
	}
}

static void send_id_get_response(int fd)
{
	struct msgb *msg;
	if (!bsc_gsmnet) {
		LOGP(DMSC, LOGL_ERROR, "The network is not initialized yet.\n");
		return;
	}

	if (!bsc_gsmnet->bsc_token) {
		LOGP(DMSC, LOGL_ERROR, "The bsc token is not set.\n");
		return;
	}

	msg = msgb_alloc_headroom(4096, 128, "id resp");

	msg->l2h = msgb_v_put(msg, IPAC_MSGT_ID_RESP);
	msgb_l16tv_put(msg, strlen(bsc_gsmnet->bsc_token) + 1,
			IPAC_IDTAG_UNITNAME, (u_int8_t *) bsc_gsmnet->bsc_token);
	ipaccess_prepend_header(msg, IPAC_PROTO_IPACCESS);

	if (write(fd, msg->data, msg->len) != msg->len) {
		LOGP(DMSC, LOGL_ERROR, "Short write.\n");
	}

	msgb_free(msg);
}

/*
 * The connection to the MSC was lost and we will need to free all
 * resources and then attempt to reconnect.
 */
static void msc_connection_was_lost(struct bsc_msc_connection *msc)
{
	struct bss_sccp_connection_data *bss, *tmp;

	LOGP(DMSC, LOGL_ERROR, "Lost MSC connection. Freing stuff.\n");

	llist_for_each_entry_safe(bss, tmp, &active_connections, active_connections) {
		if (bss->lchan) {
			bss->lchan->msc_data = NULL;
			put_lchan(bss->lchan, 0);
			bss->lchan = NULL;
		}

		if (bss->secondary_lchan) {
			bss->secondary_lchan->msc_data = NULL;
			put_lchan(bss->secondary_lchan, 0);
			bss->secondary_lchan = NULL;
		}

		/* force the close by poking stuff */
		if (bss->sccp) {
			bss->sccp->connection_state = SCCP_CONNECTION_STATE_REFUSED;
			sccp_connection_free(bss->sccp);
			bss->sccp = NULL;
		}

		bss_sccp_free_data(bss);
	}

	bsc_msc_schedule_connect(msc);
}

/*
 * callback with IP access data
 */
static int ipaccess_a_fd_cb(struct bsc_fd *bfd)
{
	int error;
	struct msgb *msg = ipaccess_read_msg(bfd, &error);
	struct ipaccess_head *hh;

	if (!msg) {
		if (error == 0) {
			LOGP(DMSC, LOGL_ERROR, "The connection to the MSC was lost.\n");
			bsc_msc_lost(msc_con);
			return -1;
		}

		fprintf(stderr, "Failed to parse ip access message: %d\n", error);
		return -1;
	}

	DEBUGP(DMSC, "From MSC: %s proto: %d\n", hexdump(msg->data, msg->len), msg->l2h[0]);

	/* handle base message handling */
	hh = (struct ipaccess_head *) msg->data;
	ipaccess_rcvmsg_base(msg, bfd);

	/* initialize the networking. This includes sending a GSM08.08 message */
	if (hh->proto == IPAC_PROTO_IPACCESS) {
		if (msg->l2h[0] == IPAC_MSGT_ID_ACK)
			initialize_if_needed();
		else if (msg->l2h[0] == IPAC_MSGT_ID_GET) {
			send_id_get_response(bfd->fd);
		}
	} else if (hh->proto == IPAC_PROTO_SCCP) {
		sccp_system_incoming(msg);
	} else if (hh->proto == NAT_IPAC_PROTO_MGCP) {
		mgcp_forward(msg);
	}

	msgb_free(msg);
	return 0;
}

static void print_help()
{
	printf("  Some useful help...\n");
	printf("  -h --help this text\n");
	printf("  -d option --debug=DRLL:DCC:DMM:DRR:DRSL:DNM enable debugging\n");
	printf("  -s --disable-color\n");
	printf("  -c --config-file filename The config file to use.\n");
	printf("  -m --msc=IP. The address of the MSC.\n");
	printf("  -l --local=IP. The local address of the MGCP.\n");
	printf("  -e --log-level number. Set a global loglevel.\n");
}

static void handle_options(int argc, char** argv)
{
	while (1) {
		int option_index = 0, c;
		static struct option long_options[] = {
			{"help", 0, 0, 'h'},
			{"debug", 1, 0, 'd'},
			{"config-file", 1, 0, 'c'},
			{"disable-color", 0, 0, 's'},
			{"timestamp", 0, 0, 'T'},
			{"rtp-proxy", 0, 0, 'P'},
			{"msc", 1, 0, 'm'},
			{"local", 1, 0, 'l'},
			{"log-level", 1, 0, 'e'},
			{0, 0, 0, 0}
		};

		c = getopt_long(argc, argv, "hd:sTPc:m:l:",
				long_options, &option_index);
		if (c == -1)
			break;

		switch (c) {
		case 'h':
			print_usage();
			print_help();
			exit(0);
		case 's':
			debug_set_use_color(stderr_target, 0);
			break;
		case 'd':
			debug_parse_category_mask(stderr_target, optarg);
			break;
		case 'c':
			config_file = strdup(optarg);
			break;
		case 'T':
			debug_set_print_timestamp(stderr_target, 1);
			break;
		case 'P':
			ipacc_rtp_direct = 0;
			break;
		case 'm':
			msc_address = strdup(optarg);
			break;
		case 'l':
			inet_aton(optarg, &local_addr);
			break;
		case 'e':
			debug_set_log_level(stderr_target, atoi(optarg));
			break;
		default:
			/* ignore */
			break;
		}
	}
}

static void signal_handler(int signal)
{
	fprintf(stdout, "signal %u received\n", signal);

	switch (signal) {
	case SIGINT:
		bsc_shutdown_net(bsc_gsmnet);
		sleep(3);
		exit(0);
		break;
	case SIGABRT:
		/* in case of abort, we want to obtain a talloc report
		 * and then return to the caller, who will abort the process */
	case SIGUSR1:
		talloc_report_full(tall_bsc_ctx, stderr);
		break;
	case SIGUSR2:
		bsc_msc_lost(msc_con);
		break;
	default:
		break;
	}
}

static void test_mode()
{
	static const u_int8_t assignment_req[] = { 0x01, 0x0b, 0x03, 0x01, 0x0b, 0x25, 0x01, 0x00, 0x01 };
	struct gsm_lchan lchan;
	struct sccp_connection conn;
	struct bss_sccp_connection_data data;

	struct gsm_bts_trx_ts trx_ts;
	struct gsm_bts_trx trx;
	struct gsm_bts bts;
	int rc;

	/* initialize */
	fprintf(stderr, "Bootstraping the network. Sending GSM08.08 reset.\n");
	rc = bsc_bootstrap_network(NULL, config_file);
	if (rc < 0) {
		fprintf(stderr, "Bootstrapping the network failed. exiting.\n");
		exit(1);
	}

	bts.network = bsc_gsmnet;
	trx.bts = &bts;
	trx_ts.trx = &trx;
	lchan.ts = &trx_ts;

	/* create fake data connection */
	data.lchan = &lchan;
	data.sccp = &conn;
	lchan.msc_data = &data;
	conn.data_ctx = &data;


	struct msgb *msg = msgb_alloc(400, "test-msg");
	msg->lchan = &lchan;

	msg->l4h = msgb_put(msg, ARRAY_SIZE(assignment_req));
	memcpy(msg->l4h, assignment_req, ARRAY_SIZE(assignment_req));
	bssmap_rcvmsg_dt1(&conn, msg, ARRAY_SIZE(assignment_req));
}

extern int bts_model_unknown_init(void);
extern int bts_model_bs11_init(void);
extern int bts_model_nanobts_init(void);

int main(int argc, char **argv)
{
	debug_init();
	tall_bsc_ctx = talloc_named_const(NULL, 1, "openbsc");
	stderr_target = debug_target_create_stderr();
	debug_add_target(stderr_target);

	bts_model_unknown_init();
	bts_model_bs11_init();
	bts_model_nanobts_init();

	/* enable filters */
	debug_set_all_filter(stderr_target, 1);

	/* parse options */
	handle_options(argc, argv);

	/* seed the PRNG */
	srand(time(NULL));

	/* attempt to register the local mgcp forward */
	if (mgcp_create_port() != 0) {
		fprintf(stderr, "Failed to bind local MGCP port\n");
		exit(1);
	}

	/* initialize sccp */
	sccp_system_init(msc_sccp_write_ipa, NULL);
	sccp_connection_set_incoming(&sccp_ssn_bssap, msc_sccp_accept, NULL);
	sccp_set_read(&sccp_ssn_bssap, msc_sccp_read, NULL);

	/* initialize ipaccess handling */
	register_signal_handler(SS_ABISIP, handle_abisip_signal, NULL);


	/* setup MSC Connection handling */
	msc_con = bsc_msc_create(msc_address, 5000);
	if (!msc_con) {
		fprintf(stderr, "Creating a bsc_msc_connection failed.\n");
		exit(1);
	}

	msc_con->connection_loss = msc_connection_was_lost;
	msc_con->write_queue.read_cb = ipaccess_a_fd_cb;
	msc_con->write_queue.write_cb = msc_sccp_do_write;
	bsc_msc_connect(msc_con);


	signal(SIGINT, &signal_handler);
	signal(SIGABRT, &signal_handler);
	signal(SIGUSR1, &signal_handler);
	signal(SIGPIPE, SIG_IGN);

	while (1) {
		bsc_select_main(0);
	}
}
