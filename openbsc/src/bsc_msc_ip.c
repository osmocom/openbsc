/* A hackish minimal BSC (+MSC +HLR) implementation */

/* (C) 2008-2009 by Harald Welte <laforge@gnumonks.org>
 * (C) 2009 by Holger Hans Peter Freyther <zecke@selfish.org>
 * (C) 2009 by on-waves.com
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

#include <openbsc/select.h>
#include <openbsc/debug.h>
#include <openbsc/e1_input.h>
#include <openbsc/talloc.h>
#include <openbsc/select.h>
#include <openbsc/ipaccess.h>
#include <openbsc/bssap.h>
#include <openbsc/paging.h>
#include <openbsc/signal.h>
#include <openbsc/chan_alloc.h>

#include <sccp/sccp.h>

/* SCCP helper */
#define SCCP_IT_TIMER 60

/* MCC and MNC for the Location Area Identifier */
struct gsm_network *bsc_gsmnet = 0;
static const char *config_file = "openbsc.cfg";
static char *msc_address = "127.0.0.1";
static struct bsc_fd msc_connection;
static struct in_addr local_addr;
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
	return data;
}

void bss_sccp_free_data(struct bss_sccp_connection_data *data)
{
	bsc_del_timer(&data->T10);
	bsc_del_timer(&data->sccp_it);
	bsc_free_queued(data->sccp);
	bts_free_queued(data);
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
			put_lchan(lchan);
		}

		bss_sccp_free_data((struct bss_sccp_connection_data *)conn->data_ctx);
		sccp_connection_free(conn);
		return;
	} else if (conn->connection_state == SCCP_CONNECTION_STATE_ESTABLISHED) {
		DEBUGP(DMSC, "Connection established: %p\n", conn);
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
int open_sccp_connection(struct msgb *layer3)
{
	struct bss_sccp_connection_data *con_data;
	struct sccp_connection *sccp_connection;
	struct msgb *data;

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

	/* start the inactivity test timer */
	con_data->sccp_it.cb = sccp_it_fired;
	con_data->sccp_it.data = con_data;
	bsc_schedule_timer(&con_data->sccp_it, SCCP_IT_TIMER, 0);

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
	bsc_queue_connection_write(lchan_get_sccp(msg->lchan), resp);
	return 1;
}

/* Receive a ASSIGNMENT COMPLETE */
static int handle_ass_compl(struct msgb *msg)
{
	struct gsm48_hdr *gh = msgb_l3(msg);

	DEBUGP(DMSC, "ASSIGNMENT COMPLETE from MS, forwarding to MSC\n");

	if (!msg->lchan->msc_data) {
		DEBUGP(DMSC, "No MSC data\n");
		return -1;
	}

	if (msgb_l3len(msg) - sizeof(*gh) != 1) {
		DEBUGP(DMSC, "assignment failure invalid: %d\n",
			msgb_l3len(msg) - sizeof(*gh));
		return -1;
	}
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
		return -1;
	}

	if (msgb_l3len(msg) - sizeof(*gh) != 1) {
		DEBUGP(DMSC, "assignment failure invalid: %d\n",
			msgb_l3len(msg) - sizeof(*gh));
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
static int msc_sccp_write_ipa(struct msgb *msg, void *data)
{
	int ret;

	DEBUGP(DMSC, "Sending SCCP to MSC: %u\n", msgb_l2len(msg));
	ipaccess_prepend_header(msg, IPAC_PROTO_SCCP);


	DEBUGP(DMI, "MSC TX %s\n", hexdump(msg->l2h, msgb_l2len(msg)));
	ret = write(msc_connection.fd, msg->data, msg->len);

	if (ret <= 0) {
		perror("MSC: Failed to send SCCP");
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

/*
 * callback with IP access data
 */
static int ipaccess_a_fd_cb(struct bsc_fd *bfd, unsigned int what)
{
	int error;
	struct msgb *msg = ipaccess_read_msg(bfd, &error);
	struct ipaccess_head *hh;

	if (!msg) {
		if (error == 0) {
			fprintf(stderr, "The connection to the MSC was lost, exiting\n");
			exit(-2);
		}

		fprintf(stderr, "Failed to parse ip access message: %d\n", error);
		return -1;
	}

	DEBUGP(DMSC, "From MSC: %s proto: %d\n", hexdump(msg->data, msg->len), msg->l2h[0]);

	/* handle base message handling */
	hh = (struct ipaccess_head *) msg->data;
	ipaccess_rcvmsg_base(msg, bfd);

	/* initialize the networking. This includes sending a GSM08.08 message */
	if (hh->proto == IPAC_PROTO_IPACCESS && msg->l2h[0] == IPAC_MSGT_ID_ACK)
		initialize_if_needed();
	else if (hh->proto == IPAC_PROTO_SCCP)
		sccp_system_incoming(msg);

	return 0;
}

/*
 * Connect to the MSC
 */
static int connect_to_msc(const char *ip, int port)
{
	struct sockaddr_in sin;
	int on = 1, ret;

	printf("Attempting to connect MSC at %s:%d\n", ip, port);

	msc_connection.fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	msc_connection.cb = ipaccess_a_fd_cb;
	msc_connection.when = BSC_FD_READ;
	msc_connection.data = NULL;
	msc_connection.priv_nr = 1;

	if (msc_connection.fd < 0) {
		perror("Creating TCP socket failed");
		return msc_connection.fd;
	}


	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_port = htons(port);
        inet_aton(ip, &sin.sin_addr);

	setsockopt(msc_connection.fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
	ret = connect(msc_connection.fd, (struct sockaddr *) &sin, sizeof(sin));

	if (ret < 0) {
		perror("Connection failed");
		return ret;
	}

	ret = bsc_register_fd(&msc_connection);
	if (ret < 0) {
		perror("Registering the fd failed");
		close(msc_connection.fd);
		return ret;
	}

	return ret;
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
			debug_use_color(0);
			break;
		case 'd':
			debug_parse_category_mask(optarg);
			break;
		case 'c':
			config_file = strdup(optarg);
			break;
		case 'T':
			debug_timestamp(1);
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

int main(int argc, char **argv)
{
	int rc;

	tall_bsc_ctx = talloc_named_const(NULL, 1, "openbsc");

	/* parse options */
	handle_options(argc, argv);

	/* seed the PRNG */
	srand(time(NULL));

	/* initialize sccp */
	sccp_system_init(msc_sccp_write_ipa, NULL);
	sccp_connection_set_incoming(&sccp_ssn_bssap, msc_sccp_accept, NULL);
	sccp_set_read(&sccp_ssn_bssap, msc_sccp_read, NULL);

	/* initialize ipaccess handling */
	register_signal_handler(SS_ABISIP, handle_abisip_signal, NULL);

	rc = connect_to_msc(msc_address, 5000);
	if (rc < 0) {
		fprintf(stderr, "Opening the MSC connection failed.\n");
		exit(1);
	}

	signal(SIGINT, &signal_handler);
	signal(SIGABRT, &signal_handler);
	signal(SIGUSR1, &signal_handler);
	signal(SIGPIPE, SIG_IGN);

	while (1) {
		bsc_select_main(0);
	}
}
