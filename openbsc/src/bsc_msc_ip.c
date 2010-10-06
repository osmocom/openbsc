/* The BSC Process to handle GSM08.08 (A-Interface) */

/* (C) 2008-2009 by Harald Welte <laforge@gnumonks.org>
 * (C) 2009-2010 by Holger Hans Peter Freyther <zecke@selfish.org>
 * (C) 2009-2010 by On-Waves
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
#include <netinet/tcp.h>
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
#include <openbsc/osmo_bsc_rf.h>
#include <openbsc/osmo_bsc_grace.h>

#include <osmocore/select.h>
#include <osmocore/talloc.h>
#include <osmocore/write_queue.h>
#include <osmocore/gsm0808.h>

#include <osmocom/sccp/sccp.h>

/* SCCP helper */
#define SCCP_IT_TIMER 60

/* MCC and MNC for the Location Area Identifier */
static struct log_target *stderr_target;
struct gsm_network *bsc_gsmnet = 0;
static const char *config_file = "openbsc.cfg";
static char *msc_address = NULL;
static struct in_addr local_addr;
static LLIST_HEAD(active_connections);
static struct write_queue mgcp_agent;
static const char *rf_ctl = NULL;
static int testmode = 0;
extern int ipacc_rtp_direct;

/* msc handling */
static struct timer_list msc_ping_timeout;
static struct timer_list msc_pong_timeout;

extern int bsc_bootstrap_network(int (*layer4)(struct gsm_network *, int, void *), const char *cfg_file);
extern int bsc_shutdown_net(struct gsm_network *net);

struct llist_head *bsc_sccp_connections()
{
	return &active_connections;
}

/*
 * Having a subscriber in the lchan is used to indicate that a SACH DEACTIVATE
 * should be send. We will just introduce a fake subscriber and bind it to the
 * lchan.
 */
static void assign_dummy_subscr(struct gsm_lchan *lchan)
{
	if (!lchan->conn.subscr) {
		lchan->conn.subscr = subscr_get_or_create(bsc_gsmnet, "2323");
		lchan->conn.subscr->lac = 2323;
	}
}

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
	bsc_del_timer(&data->sccp_cc_timeout);
	bsc_del_timer(&data->sccp_it);
	if (data->sccp)
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

/* make sure to stop the T10 timer... bss_sccp_free_data is doing that */
static void bss_close_lchans(struct bss_sccp_connection_data *bss)
{
	if (bss->lchan) {
		bss->lchan->msc_data = NULL;
		bss->lchan->conn.hand_off += 1;
		put_subscr_con(&bss->lchan->conn, 0);
		bss->lchan = NULL;
	}

	if (bss->secondary_lchan) {
		bss->secondary_lchan->msc_data = NULL;
		bss->secondary_lchan->conn.hand_off += 1;
		put_subscr_con(&bss->secondary_lchan->conn, 0);
		bss->secondary_lchan = NULL;
	}
}

static void bss_force_close(struct bss_sccp_connection_data *bss)
{
	bss_close_lchans(bss);

	/* force the close by poking stuff */
	if (bss->sccp) {
		sccp_connection_force_free(bss->sccp);
		bss->sccp = NULL;
	}

	bss_sccp_free_data(bss);
}

/* check if this connection was ever confirmed and then recycle */
static void sccp_check_cc(void *_data)
{
	struct bss_sccp_connection_data *data = _data;

	if (data->sccp->connection_state >= SCCP_CONNECTION_STATE_ESTABLISHED)
		return;

	LOGP(DMSC, LOGL_ERROR, "The connection was never established\n");
	bss_force_close(data);
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
			LOGP(DMSC, LOGL_ERROR, "The TMSI is the reserved one.\n");
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

	LOGP(DMSC, LOGL_ERROR, "No subscriber has been found.\n");
	return NULL;
}



/* SCCP handling */
void msc_outgoing_sccp_data(struct sccp_connection *conn, struct msgb *msg, unsigned int len)
{
	struct gsm_lchan *lchan;
	struct bssmap_header *bs;

	if (len < 1) {
		LOGP(DMSC, LOGL_ERROR, "The header is too short.\n");
		return;
	}

	lchan = sccp_get_lchan(conn->data_ctx);
	if (!lchan) {
		LOGP(DMSC, LOGL_ERROR, "SCCP data without lchan for type: 0x%x\n", msg->l3h[0]);
		return;
	}

	/* that is bad */
	if (!lchan->msc_data) {
		LOGP(DMSC, LOGL_ERROR, "SCCP data for lchan without msc data type: 0x%x\n",
		     msg->l3h[0]);
		return;
	}

	switch (msg->l3h[0]) {
	case BSSAP_MSG_BSS_MANAGEMENT:
		msg->l4h = &msg->l3h[sizeof(*bs)];
		msg->lchan = lchan;
		bssmap_rcvmsg_dt1(conn, msg, len - sizeof(*bs));
		break;
	case BSSAP_MSG_DTAP:
		dtap_rcvmsg(lchan, msg, len);
		break;
	default:
		LOGP(DMSC, LOGL_DEBUG, "Unimplemented msg type: %d\n", msg->l3h[0]);
	}
}

void msc_outgoing_sccp_state(struct sccp_connection *conn, int old_state)
{
	struct bss_sccp_connection_data *con_data;

	if (conn->connection_state >= SCCP_CONNECTION_STATE_RELEASE_COMPLETE) {
		con_data = (struct bss_sccp_connection_data *) conn->data_ctx;

		LOGP(DMSC, LOGL_DEBUG, "Freeing sccp conn: %p state: %d\n", conn, conn->connection_state);
		if (con_data->lchan || con_data->secondary_lchan) {
			LOGP(DMSC, LOGL_ERROR, "ERROR: The lchan is still associated\n.");
			bss_close_lchans(con_data);
		}

		bss_sccp_free_data(con_data);
		sccp_connection_free(conn);
		return;
	} else if (conn->connection_state == SCCP_CONNECTION_STATE_ESTABLISHED) {
		LOGP(DMSC, LOGL_DEBUG, "Connection established: %p\n", conn);

		con_data = (struct bss_sccp_connection_data *) conn->data_ctx;

		/* stop the CC timeout */
		bsc_del_timer(&con_data->sccp_cc_timeout);

		/* start the inactivity test timer */
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
	if (!bsc_gsmnet->msc_con->is_authenticated) {
		LOGP(DMSC, LOGL_ERROR, "Not connected to a MSC. Not forwarding data.\n");
		return -1;
	}

	if (!bsc_grace_allow_new_connection(bsc_gsmnet)) {
		LOGP(DMSC, LOGL_NOTICE, "BSC in grace period. No new connections.\n");
		return -1;
	}

	LOGP(DMSC, LOGL_DEBUG, "Opening new layer3 connection\n");
	sccp_connection = sccp_connection_socket();
	if (!sccp_connection) {
		LOGP(DMSC, LOGL_ERROR, "Failed to allocate memory.\n");
		return -ENOMEM;
	}

	data = bssmap_create_layer3(layer3);
	if (!data) {
		LOGP(DMSC, LOGL_ERROR, "Failed to allocate complete layer3.\n");
		sccp_connection_free(sccp_connection);
		return -ENOMEM;
	}

	con_data = bss_sccp_create_data();
	if (!con_data) {
		LOGP(DMSC, LOGL_ERROR, "Failed to allocate bss<->msc data.\n");
		sccp_connection_free(sccp_connection);
		msgb_free(data);
		return -ENOMEM;
	}

	/* initialize the bridge */
	con_data->lchan = layer3->lchan;
	con_data->sccp = sccp_connection;

	/* assign the outgoing msc connection */
	con_data->msc_con = bsc_gsmnet->msc_con;

	sccp_connection->state_cb = msc_outgoing_sccp_state;
	sccp_connection->data_cb = msc_outgoing_sccp_data;
	sccp_connection->data_ctx = con_data;
	layer3->lchan->msc_data = con_data;

	/* Make sure we open the connection */
	con_data->sccp_cc_timeout.data = con_data;
	con_data->sccp_cc_timeout.cb = sccp_check_cc;
	bsc_schedule_timer(&con_data->sccp_cc_timeout, 10, 0);

	/* FIXME: Use transaction for this */
	/* assign a dummy subscriber */
	assign_dummy_subscr(layer3->lchan);
	use_subscr_con(&layer3->lchan->conn);
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
			LOGP(DMSC, LOGL_ERROR, "Creating a DTAP message failed.\n");
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

	struct gsm48_hdr *hdr;
	struct gsm48_pag_resp *resp;

	hdr = msgb_l3(msg);
	resp = (struct gsm48_pag_resp *) &hdr->data[0];

	gsm48_paging_extract_mi(resp, msgb_l3len(msg) - sizeof(*hdr),
				mi_string, &mi_type);
	LOGP(DMSC, LOGL_DEBUG, "PAGING RESPONSE: mi_type=0x%02x MI(%s)\n",
		mi_type, mi_string);

	subscr = find_subscriber(mi_type, mi_string);
	if (!subscr)
		return -EINVAL;

	/* force the paging to stop at every bts */
	subscr->lac = GSM_LAC_RESERVED_ALL_BTS;
	if (gsm48_handle_paging_resp(msg, subscr) != 0) {
		LOGP(DMSC, LOGL_ERROR, "Paging failed.\n");
		return -1;
	}

	/* open a new transaction and SCCP connection */
	return send_dtap_or_open_connection(msg);
}

/* Receive a CIPHER MODE COMPLETE from the MS */
static int handle_cipher_m_complete(struct msgb *msg)
{
	struct msgb *resp;

	if (!msg->lchan->msc_data) {
		LOGP(DMSC, LOGL_ERROR, "No MSC data for CIPHER MODE COMPLETE.\n");
		return -1;
	}

	LOGP(DMSC, LOGL_DEBUG, "CIPHER MODE COMPLETE from MS, forwarding to MSC\n");
	resp = gsm0808_create_cipher_complete(msg, msg->lchan->encr.alg_id);
	if (!resp) {
		LOGP(DMSC, LOGL_ERROR, "Creating MSC response failed.\n");
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

	LOGP(DMSC, LOGL_DEBUG, "ASSIGNMENT COMPLETE from MS, forwarding to MSC\n");

	if (!msg->lchan->msc_data) {
		LOGP(DMSC, LOGL_ERROR, "No MSC data\n");
		msg->lchan->conn.hand_off += 1;
		put_subscr_con(&msg->lchan->conn, 0);
		return -1;
	}

	if (msg->lchan->msc_data->secondary_lchan != msg->lchan) {
		LOGP(DMSC, LOGL_ERROR, "Wrong assignment complete.\n");
		msg->lchan->conn.hand_off += 1;
		put_subscr_con(&msg->lchan->conn, 0);
		return -1;
	}

	if (msgb_l3len(msg) - sizeof(*gh) != 1) {
		LOGP(DMSC, LOGL_ERROR, "assignment compl invalid: %d\n",
			msgb_l3len(msg) - sizeof(*gh));
		msg->lchan->conn.hand_off += 1;
		put_subscr_con(&msg->lchan->conn, 0);
		return -1;
	}

	/* assign a dummy subscriber */
	assign_dummy_subscr(msg->lchan);

	/* swap the channels and release the old */
	old_chan = msg->lchan->msc_data->lchan;
	if (old_chan) {
		msg->lchan->msc_data->lchan = msg->lchan;
		msg->lchan->msc_data->secondary_lchan = NULL;
		old_chan->msc_data = NULL;

		/* give up the old channel to not do a SACCH deactivate */
		if (old_chan->conn.subscr)
			subscr_put(old_chan->conn.subscr);
		old_chan->conn.subscr = NULL;
		old_chan->conn.hand_off += 1;
		put_subscr_con(&old_chan->conn, 1);
	}

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
	u_int8_t *rr_cause;
	struct gsm48_hdr *gh = msgb_l3(msg);

	LOGP(DMSC, LOGL_ERROR, "ASSIGNMENT FAILURE from MS, forwarding to MSC\n");
	if (!msg->lchan->msc_data) {
		LOGP(DMSC, LOGL_ERROR, "No MSC data\n");
		msg->lchan->conn.hand_off += 1;
		put_subscr_con(&msg->lchan->conn, 0);
		return -1;
	}

	/* assignment failure comes on the old link */
	if (msg->lchan->msc_data->lchan != msg->lchan) {
		LOGP(DMSC, LOGL_NOTICE, "Failure should come on the old link.\n");
		msg->lchan->msc_data = NULL;
		msg->lchan->conn.hand_off += 1;
		put_subscr_con(&msg->lchan->conn, 0);
		return -1;
	}

	/* Giving up the secondary will happen in bssap */
	if (msgb_l3len(msg) - sizeof(*gh) != 1) {
		LOGP(DMSC, LOGL_ERROR, "assignment failure invalid: %d\n",
			msgb_l3len(msg) - sizeof(*gh));
		rr_cause = NULL;
	} else {
		rr_cause = &gh->data[0];
	}

	/* this will also free the secondary channel */
	gsm0808_send_assignment_failure(msg->lchan,
		GSM0808_CAUSE_RADIO_INTERFACE_MESSAGE_FAILURE, rr_cause);
	return 1;
}

/*
 * Receive a GSM04.08 MODIFY ACK. Actually we have to check
 * the content to see if this was a success or not.
 */
static int handle_modify_ack(struct msgb *msg)
{
	int rc;

	if (!msg->lchan->msc_data) {
		LOGP(DMSC, LOGL_ERROR, "No MSC data for modify ack.\n");
		return -1;
	}

	/* modify RSL */
	rc = gsm48_rx_rr_modif_ack(msg);
	if (rc < 0)
		gsm0808_send_assignment_failure(msg->lchan,
			GSM0808_CAUSE_NO_RADIO_RESOURCE_AVAILABLE, NULL);
	else
		gsm0808_send_assignment_compl(msg->lchan, 0);

	return 1;
}

/*
 * Check if the subscriber is coming from our LAC
 */
static void handle_lu(struct msgb *msg)
{
	struct gsm48_hdr *gh;
	struct gsm48_loc_upd_req *lu;
	struct gsm48_loc_area_id lai;
	struct gsm_network *net;

	if (msgb_l3len(msg) < sizeof(*gh) + sizeof(*lu)) {
		LOGP(DMSC, LOGL_ERROR, "LU too small to look at: %u\n", msgb_l3len(msg));
		return;
	}

	if (!msg->lchan->msc_data)
		return;

	net = msg->trx->bts->network;

	gh = msgb_l3(msg);
	lu = (struct gsm48_loc_upd_req *) gh->data;

	gsm48_generate_lai(&lai, net->country_code, net->network_code,
			   msg->trx->bts->location_area_code);

	if (memcmp(&lai, &lu->lai, sizeof(lai)) != 0) {
		LOGP(DMSC, LOGL_DEBUG, "Marking con for welcome USSD.\n");
		msg->lchan->msc_data->new_subscriber = 1;
	}
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
		if ((gh->msg_type & 0xbf) == GSM48_MT_MM_LOC_UPD_REQUEST)
			handle_lu(msg);
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
			LOGP(DMSC, LOGL_ERROR, "Creating a DTAP message failed.\n");
			return -1;
		}

		bsc_queue_connection_write(lchan_get_sccp(msg->lchan), dtap);
	} else if (rc <= 0 && !msg->lchan->msc_data && msg->lchan->conn.use_count == 0) {
		if (msg->lchan->state == LCHAN_S_ACTIVE) {
			LOGP(DMSC, LOGL_NOTICE, "Closing unowned channel.\n");
			msg->lchan->conn.hand_off += 1;
			use_subscr_con(&msg->lchan->conn);
			put_subscr_con(&msg->lchan->conn, 0);
		}
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
			LOGP(DMSC, LOGL_DEBUG, "Connecting BTS to port: %d conn: %d\n",
				lchan->msc_data->rtp_port, lchan->abis_ip.conn_id);

			int rtp_payload = ts->trx->bts->network->rtp_payload;
			if (rtp_payload == 0)
				rtp_payload = lchan->abis_ip.rtp_payload2;

			rc = rsl_ipacc_mdcx(lchan, ntohl(local_addr.s_addr),
					    lchan->msc_data->rtp_port,
					    rtp_payload);
			if (rc < 0) {
				LOGP(DMSC, LOGL_ERROR, "Failed to send connect: %d\n", rc);
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
	printf("Usage: bsc_msc_ip\n");
}

/*
 * SCCP handling
 */
static int msc_queue_write(struct msgb *msg, int proto)
{
	ipaccess_prepend_header(msg, proto);
	if (write_queue_enqueue(&bsc_gsmnet->msc_con->write_queue, msg) != 0) {
		LOGP(DMSC, LOGL_FATAL, "Failed to queue IPA/%d\n", proto);
		msgb_free(msg);
		return -1;
	}

	return 0;
}

static int msc_sccp_do_write(struct bsc_fd *fd, struct msgb *msg)
{
	int ret;

	LOGP(DMSC, LOGL_DEBUG, "Sending SCCP to MSC: %u\n", msgb_l2len(msg));
	LOGP(DMI, LOGL_DEBUG, "MSC TX %s\n", hexdump(msg->l2h, msgb_l2len(msg)));

	ret = write(bsc_gsmnet->msc_con->write_queue.bfd.fd, msg->data, msg->len);
	if (ret < msg->len)
		perror("MSC: Failed to send SCCP");

	return ret;
}

static void msc_sccp_write_ipa(struct sccp_connection *conn, struct msgb *msg, void *data)
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
	addr.sin_port = 0;

	if (bind(mgcp_agent.bfd.fd, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
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
	LOGP(DMSC, LOGL_DEBUG, "Rejecting incoming SCCP connection.\n");
	return -1;
}

static int msc_sccp_read(struct msgb *msgb, unsigned int length, void *data)
{
	struct bssmap_header *bs;

	LOGP(DMSC, LOGL_DEBUG, "Incoming SCCP message ftom MSC: %s\n", hexdump(msgb->l3h, length));

	if (length < sizeof(*bs)) {
		LOGP(DMSC, LOGL_ERROR, "The header is too short.\n");
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
		LOGP(DMSC, LOGL_ERROR, "Unimplemented msg type: %d\n", bs->type);
	}

	return 0;
}


/*
 * network initialisation
 */
static void initialize_if_needed(void)
{
	struct msgb *msg;


	if (!bsc_gsmnet->msc_con->is_authenticated) {
		/* send a gsm 08.08 reset message from here */
		msg = gsm0808_create_reset();
		if (!msg) {
			LOGP(DMSC, LOGL_ERROR, "Failed to create the reset message.\n");
			return;
		}

		sccp_write(msg, &sccp_ssn_bssap, &sccp_ssn_bssap, 0);
		msgb_free(msg);
		bsc_gsmnet->msc_con->is_authenticated = 1;
	}
}

static void send_id_get_response(int fd)
{
	struct msgb *msg;
	if (!bsc_gsmnet) {
		LOGP(DMSC, LOGL_ERROR, "The network is not initialized yet.\n");
		return;
	}

	msg = bsc_msc_id_get_resp(bsc_gsmnet->bsc_token);
	if (!msg)
		return;
	msc_queue_write(msg, IPAC_PROTO_IPACCESS);
}

/*
 * Send some packets to test the MSC.
 */
static void test_msc()
{
	struct msgb *msg;

	if (!testmode)
		return;

	static const uint8_t pag_resp[] = {
		0x01, 0xf3, 0x26, 0x09, 0x02, 0x02, 0x04, 0x02, 0x42,
		0xfe, 0x0f, 0x1f, 0x00, 0x1d, 0x57, 0x05, 0x08, 0x00,
		0x72, 0xf4, 0x80, 0x10, 0x1c, 0x9c, 0x40, 0x17, 0x10,
		0x06, 0x27, 0x02, 0x03, 0x30, 0x18, 0xa0, 0x08, 0x59,
		0x51, 0x30, 0x10, 0x30, 0x32, 0x80, 0x06, 0x00
	};

	msg = msgb_alloc_headroom(4096, 128, "paging response");
	if (!msg)
		return;
	msg->l2h = msgb_put(msg, sizeof(pag_resp));
	memcpy(msg->l2h, pag_resp, sizeof(pag_resp));
	msc_queue_write(msg, IPAC_PROTO_SCCP);
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
		bss_force_close(bss);
	}

	bsc_del_timer(&msc_ping_timeout);
	bsc_del_timer(&msc_pong_timeout);

	msc->is_authenticated = 0;
	bsc_msc_schedule_connect(msc);
}

static void msc_pong_timeout_cb(void *data)
{
	LOGP(DMSC, LOGL_ERROR, "MSC didn't answer PING. Closing connection.\n");
	bsc_msc_lost(bsc_gsmnet->msc_con);
}

static void send_ping(void)
{
	struct msgb *msg;

	msg = msgb_alloc_headroom(4096, 128, "ping");
	if (!msg) {
		LOGP(DMSC, LOGL_ERROR, "Failed to create PING.\n");
		return;
	}

	msg->l2h = msgb_put(msg, 1);
	msg->l2h[0] = IPAC_MSGT_PING;

	msc_queue_write(msg, IPAC_PROTO_IPACCESS);
}

static void msc_ping_timeout_cb(void *data)
{
	if (bsc_gsmnet->ping_timeout < 0)
		return;

	send_ping();

	/* send another ping in 20 seconds */
	bsc_schedule_timer(&msc_ping_timeout, bsc_gsmnet->ping_timeout, 0);

	/* also start a pong timer */
	bsc_schedule_timer(&msc_pong_timeout, bsc_gsmnet->pong_timeout, 0);
}

static void msc_connection_connected(struct bsc_msc_connection *con)
{
	int ret, on;
	on = 1;
	ret = setsockopt(con->write_queue.bfd.fd, IPPROTO_TCP, TCP_NODELAY, &on, sizeof(on));
	if (ret != 0)
                LOGP(DMSC, LOGL_ERROR, "Failed to set TCP_NODELAY: %s\n", strerror(errno));

	msc_ping_timeout_cb(con);
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
			bsc_msc_lost(bsc_gsmnet->msc_con);
			return -1;
		}

		fprintf(stderr, "Failed to parse ip access message: %d\n", error);
		return -1;
	}

	LOGP(DMSC, LOGL_DEBUG, "From MSC: %s proto: %d\n", hexdump(msg->data, msg->len), msg->l2h[0]);

	/* handle base message handling */
	hh = (struct ipaccess_head *) msg->data;
	ipaccess_rcvmsg_base(msg, bfd);

	/* initialize the networking. This includes sending a GSM08.08 message */
	if (hh->proto == IPAC_PROTO_IPACCESS) {
		if (msg->l2h[0] == IPAC_MSGT_ID_ACK)
			initialize_if_needed();
		else if (msg->l2h[0] == IPAC_MSGT_ID_GET) {
			send_id_get_response(bfd->fd);
			test_msc();
		} else if (msg->l2h[0] == IPAC_MSGT_PONG) {
			bsc_del_timer(&msc_pong_timeout);
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
	printf("  -T --timestamp. Print a timestamp in the debug output.\n");
	printf("  -c --config-file filename The config file to use.\n");
	printf("  -m --msc=IP. The address of the MSC.\n");
	printf("  -l --local=IP. The local address of the MGCP.\n");
	printf("  -e --log-level number. Set a global loglevel.\n");
	printf("  -r --rf-ctl NAME. A unix domain socket to listen for cmds.\n");
	printf("  -t --testmode. A special mode to provoke failures at the MSC.\n");
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
			{"msc", 1, 0, 'm'},
			{"local", 1, 0, 'l'},
			{"log-level", 1, 0, 'e'},
			{"rf-ctl", 1, 0, 'r'},
			{"testmode", 0, 0, 't'},
			{0, 0, 0, 0}
		};

		c = getopt_long(argc, argv, "hd:sTc:m:l:e:r:t",
				long_options, &option_index);
		if (c == -1)
			break;

		switch (c) {
		case 'h':
			print_usage();
			print_help();
			exit(0);
		case 's':
			log_set_use_color(stderr_target, 0);
			break;
		case 'd':
			log_parse_category_mask(stderr_target, optarg);
			break;
		case 'c':
			config_file = strdup(optarg);
			break;
		case 'T':
			log_set_print_timestamp(stderr_target, 1);
			break;
		case 'P':
			ipacc_rtp_direct = 0;
			break;
		case 'm':
			msc_address = optarg;
			break;
		case 'l':
			inet_aton(optarg, &local_addr);
			break;
		case 'e':
			log_set_log_level(stderr_target, atoi(optarg));
			break;
		case 'r':
			rf_ctl = optarg;
			break;
		case 't':
			testmode = 1;
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
		if (bsc_gsmnet) {
			bsc_shutdown_net(bsc_gsmnet);
			sleep(3);
		}
		exit(0);
		break;
	case SIGABRT:
		/* in case of abort, we want to obtain a talloc report
		 * and then return to the caller, who will abort the process */
	case SIGUSR1:
		talloc_report_full(tall_bsc_ctx, stderr);
		break;
	case SIGUSR2:
		if (!bsc_gsmnet->msc_con)
			return;
		bsc_msc_lost(bsc_gsmnet->msc_con);
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
	char *msc;
	int rc;

	log_init(&log_info);
	tall_bsc_ctx = talloc_named_const(NULL, 1, "openbsc");
	stderr_target = log_target_create_stderr();
	log_add_target(stderr_target);

	bts_model_unknown_init();
	bts_model_bs11_init();
	bts_model_nanobts_init();

	/* enable filters */
	log_set_all_filter(stderr_target, 1);

	/* parse options */
	handle_options(argc, argv);

	/* seed the PRNG */
	srand(time(NULL));

	signal(SIGINT, &signal_handler);
	signal(SIGABRT, &signal_handler);
	signal(SIGUSR1, &signal_handler);
	signal(SIGUSR2, &signal_handler);
	signal(SIGPIPE, SIG_IGN);

	/* attempt to register the local mgcp forward */
	if (mgcp_create_port() != 0) {
		fprintf(stderr, "Failed to bind local MGCP port\n");
		exit(1);
	}

	/* initialize sccp */
	sccp_set_log_area(DSCCP);
	sccp_system_init(msc_sccp_write_ipa, NULL);
	sccp_connection_set_incoming(&sccp_ssn_bssap, msc_sccp_accept, NULL);
	sccp_set_read(&sccp_ssn_bssap, msc_sccp_read, NULL);

	/* initialize ipaccess handling */
	register_signal_handler(SS_ABISIP, handle_abisip_signal, NULL);

	fprintf(stderr, "Bootstraping the network. Sending GSM08.08 reset.\n");
	rc = bsc_bootstrap_network(NULL, config_file);
	if (rc < 0) {
		fprintf(stderr, "Bootstrapping the network failed. exiting.\n");
		exit(1);
	}

	if (rf_ctl) {
		bsc_gsmnet->rf = osmo_bsc_rf_create(rf_ctl, bsc_gsmnet);
		if (!bsc_gsmnet->rf) {
			fprintf(stderr, "Failed to create the RF service.\n");
			exit(1);
		}
	}

	/* setup MSC Connection handling */
	msc = bsc_gsmnet->msc_ip;
	if (msc_address)
		msc = msc_address;

	bsc_gsmnet->msc_con = bsc_msc_create(msc,
					     bsc_gsmnet->msc_port,
					     bsc_gsmnet->msc_ip_dscp);
	if (!bsc_gsmnet->msc_con) {
		fprintf(stderr, "Creating a bsc_msc_connection failed.\n");
		exit(1);
	}

	msc_ping_timeout.cb = msc_ping_timeout_cb;
	msc_pong_timeout.cb = msc_pong_timeout_cb;

	bsc_gsmnet->msc_con->connection_loss = msc_connection_was_lost;
	bsc_gsmnet->msc_con->connected = msc_connection_connected;
	bsc_gsmnet->msc_con->write_queue.read_cb = ipaccess_a_fd_cb;
	bsc_gsmnet->msc_con->write_queue.write_cb = msc_sccp_do_write;
	bsc_msc_connect(bsc_gsmnet->msc_con);



	while (1) {
		bsc_select_main(0);
	}
}

