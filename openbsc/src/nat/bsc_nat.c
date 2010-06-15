/* BSC Multiplexer/NAT */

/*
 * (C) 2010 by Holger Hans Peter Freyther <zecke@selfish.org>
 * (C) 2010 by on-waves.com
 * (C) 2009 by Harald Welte <laforge@gnumonks.org>
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
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>

#define _GNU_SOURCE
#include <getopt.h>

#include <openbsc/debug.h>
#include <openbsc/msgb.h>
#include <openbsc/bsc_msc.h>
#include <openbsc/bsc_nat.h>
#include <openbsc/bssap.h>
#include <openbsc/ipaccess.h>
#include <openbsc/abis_nm.h>
#include <openbsc/talloc.h>
#include <openbsc/telnet_interface.h>

#include <vty/vty.h>

#include <sccp/sccp.h>

static const char *config_file = "bsc-nat.cfg";
static char *msc_address = "127.0.0.1";
static struct in_addr local_addr;
static struct bsc_fd msc_connection;
static struct bsc_fd bsc_connection;


static struct bsc_nat *nat;

static struct bsc_nat *bsc_nat_alloc(void)
{
	struct bsc_nat *nat = talloc_zero(tall_bsc_ctx, struct bsc_nat);
	if (!nat)
		return NULL;

	INIT_LLIST_HEAD(&nat->sccp_connections);
	INIT_LLIST_HEAD(&nat->bsc_connections);
	INIT_LLIST_HEAD(&nat->bsc_configs);
	return nat;
}

static struct bsc_connection *bsc_connection_alloc(void)
{
	struct bsc_connection *con = talloc_zero(nat, struct bsc_connection);
	if (!con)
		return NULL;

	return con;
}

struct bsc_config *bsc_config_alloc(struct bsc_nat *nat, const char *token, unsigned int lac)
{
	struct bsc_config *conf = talloc_zero(nat, struct bsc_config);
	if (!conf)
		return NULL;

	conf->token = talloc_strdup(conf, token);
	conf->lac = lac;
	conf->nr = nat->num_bsc;
	conf->nat = nat;

	llist_add(&conf->entry, &nat->bsc_configs);
	++nat->num_bsc;

	return conf;
}

struct bsc_config *bsc_config_num(struct bsc_nat *nat, int num)
{
	struct bsc_config *conf;

	llist_for_each_entry(conf, &nat->bsc_configs, entry)
		if (conf->nr == num)
			return conf;

	return NULL;
}

/*
 * below are stubs we need to link
 */
int nm_state_event(enum nm_evt evt, u_int8_t obj_class, void *obj,
		   struct gsm_nm_state *old_state, struct gsm_nm_state *new_state)
{
	return -1;
}

void input_event(int event, enum e1inp_sign_type type, struct gsm_bts_trx *trx)
{}

int gsm0408_rcvmsg(struct msgb *msg, u_int8_t link_id)
{
	return -1;
}

static int send_reset_ack(struct bsc_fd *bfd)
{
	static const u_int8_t gsm_reset_ack[] = {
		0x00, 0x13, 0xfd,
		0x09, 0x00, 0x03, 0x07, 0x0b, 0x04, 0x43, 0x01,
		0x00, 0xfe, 0x04, 0x43, 0x5c, 0x00, 0xfe, 0x03,
		0x00, 0x01, 0x31,
	};

	return write(bfd->fd, gsm_reset_ack, sizeof(gsm_reset_ack));
}

/*
 * SCCP patching below
 */

/* check if we are using this ref for patched already */
static int sccp_ref_is_free(struct sccp_source_reference *ref)
{
	struct sccp_connections *conn;

	llist_for_each_entry(conn, &nat->sccp_connections, list_entry) {
		if (memcmp(ref, &conn->patched_ref, sizeof(*ref)) == 0)
			return -1;
	}

	return 0;
}

/* copied from sccp.c */
static int assign_src_local_reference(struct sccp_source_reference *ref)
{
	static u_int32_t last_ref = 0x50000;
	int wrapped = 0;

	do {
		struct sccp_source_reference reference;
		reference.octet1 = (last_ref >>  0) & 0xff;
		reference.octet2 = (last_ref >>  8) & 0xff;
		reference.octet3 = (last_ref >> 16) & 0xff;

		++last_ref;
		/* do not use the reversed word and wrap around */
		if ((last_ref & 0x00FFFFFF) == 0x00FFFFFF) {
			LOGP(DNAT, LOGL_NOTICE, "Wrapped searching for a free code\n");
			last_ref = 0;
			++wrapped;
		}

		if (sccp_ref_is_free(&reference) == 0) {
			*ref = reference;
			return 0;
		}
	} while (wrapped != 2);

	LOGP(DNAT, LOGL_ERROR, "Finding a free reference failed\n");
	return -1;
}

static int create_sccp_src_ref(struct bsc_connection *bsc, struct msgb *msg, struct bsc_nat_parsed *parsed)
{
	struct sccp_connections *conn;

	conn = talloc_zero(nat, struct sccp_connections);
	if (!conn) {
		LOGP(DNAT, LOGL_ERROR, "Memory allocation failure.\n");
		return -1;
	}

	conn->real_ref = *parsed->src_local_ref;
	if (assign_src_local_reference(&conn->patched_ref) != 0) {
		LOGP(DNAT, LOGL_ERROR, "Failed to assign a ref.\n");
		talloc_free(conn);
		return -1;
	}

	return 0;
}

static void remove_sccp_src_ref(struct bsc_connection *bsc, struct msgb *msg, struct bsc_nat_parsed *parsed)
{
	struct sccp_connections *conn;

	llist_for_each_entry(conn, &nat->sccp_connections, list_entry) {
		if (memcmp(parsed->src_local_ref,
			   &conn->real_ref, sizeof(conn->real_ref)) == 0) {
			if (bsc != conn->bsc) {
				LOGP(DNAT, LOGL_ERROR, "Someone else...\n");
				continue;
			}


			llist_del(&conn->list_entry);
			talloc_free(conn);
			return;
		}
	}

	LOGP(DNAT, LOGL_ERROR, "Unknown connection.\n");
}

static struct bsc_connection *patch_sccp_src_ref_to_bsc(struct msgb *msg, struct bsc_nat_parsed *parsed)
{
	struct sccp_connections *conn;
	llist_for_each_entry(conn, &nat->sccp_connections, list_entry) {
		if (memcmp(parsed->dest_local_ref,
			   &conn->real_ref, sizeof(*parsed->dest_local_ref)) == 0) {
			memcpy(parsed->dest_local_ref,
			       &conn->patched_ref, sizeof(*parsed->dest_local_ref));
			return conn->bsc;
		}
	}

	return NULL;
}

static struct bsc_connection *patch_sccp_src_ref_to_msc(struct msgb *msg, struct bsc_nat_parsed *parsed)
{
	struct sccp_connections *conn;
	llist_for_each_entry(conn, &nat->sccp_connections, list_entry) {
		if (memcmp(parsed->src_local_ref,
			   &conn->real_ref, sizeof(*parsed->src_local_ref)) == 0) {
			memcpy(parsed->src_local_ref,
			       &conn->patched_ref, sizeof(*parsed->src_local_ref));
			return conn->bsc;
		}
	}

	return NULL;
}

/*
 * Below is the handling of messages coming
 * from the MSC and need to be forwarded to
 * a real BSC.
 */
static void initialize_msc_if_needed()
{
	static int init = 0;
	init = 1;

	/* do we need to send a GSM 08.08 message here? */
}

static int forward_sccp_to_bts(struct msgb *msg)
{
	struct bsc_connection *bsc;
	struct bsc_nat_parsed *parsed;
	int rc;

	/* filter, drop, patch the message? */
	parsed = bsc_nat_parse(msg);
	if (!parsed) {
		LOGP(DNAT, LOGL_ERROR, "Can not parse msg from BSC.\n");
		return -1;
	}

	if (bsc_nat_filter_ipa(DIR_BSC, msg, parsed))
		goto exit;

	/* Route and modify the SCCP packet */
	if (parsed->ipa_proto == IPAC_PROTO_SCCP) {
		switch (parsed->sccp_type) {
		case SCCP_MSG_TYPE_UDT:
			/* forward UDT messages to every BSC */
			goto send_to_all;
			break;
		case SCCP_MSG_TYPE_RLSD:
		case SCCP_MSG_TYPE_CREF:
		case SCCP_MSG_TYPE_DT1:
		case SCCP_MSG_TYPE_CC:
			bsc = patch_sccp_src_ref_to_bsc(msg, parsed);
			break;
		case SCCP_MSG_TYPE_CR:
		case SCCP_MSG_TYPE_RLC:
			/* MSC never opens a SCCP connection, fall through */
		default:
			goto exit;
		}
	}

	talloc_free(parsed);
	if (!bsc)
		return -1;
	if (!bsc->authenticated) {
		LOGP(DNAT, LOGL_ERRO, "Selected BSC not authenticated.\n");
		return -1;
	}

	return write(bsc->bsc_fd.fd, msg->data, msg->len);

send_to_all:
	/* currently send this to every BSC connected */
	llist_for_each_entry(bsc, &nat->bsc_connections, list_entry) {
		if (!bsc->authenticated)
			continue;

		rc = write(bsc->bsc_fd.fd, msg->data, msg->len);

		/* try the next one */
		if (rc < msg->len)
			LOGP(DNAT, LOGL_ERROR, "Failed to write message to BTS: %d\n", rc);
	}

exit:
	talloc_free(parsed);
	return 0;
}

static int ipaccess_msc_cb(struct bsc_fd *bfd, unsigned int what)
{
	int error;
	struct msgb *msg = ipaccess_read_msg(bfd, &error);
	struct ipaccess_head *hh;

	if (!msg) {
		if (error == 0) {
			LOGP(DNAT, LOGL_FATAL, "The connection the MSC was lost, exiting\n");
			exit(-2);
		}

		LOGP(DNAT, LOGL_ERROR, "Failed to parse ip access message: %d\n", error);
		return -1;
	}

	LOGP(DNAT, LOGL_DEBUG, "MSG from MSC: %s proto: %d\n", hexdump(msg->data, msg->len), msg->l2h[0]);

	/* handle base message handling */
	hh = (struct ipaccess_head *) msg->data;
	ipaccess_rcvmsg_base(msg, bfd);

	/* initialize the networking. This includes sending a GSM08.08 message */
	if (hh->proto == IPAC_PROTO_IPACCESS && msg->l2h[0] == IPAC_MSGT_ID_ACK)
		initialize_msc_if_needed();
	else if (hh->proto == IPAC_PROTO_SCCP)
		forward_sccp_to_bts(msg);

	return 0;
}

/*
 * Below is the handling of messages coming
 * from the BSC and need to be forwarded to
 * a real BSC.
 */

/*
 * Remove the connection from the connections list,
 * remove it from the patching of SCCP header lists
 * as well. Maybe in the future even close connection..
 */
static void remove_bsc_connection(struct bsc_connection *connection)
{
	struct sccp_connections *sccp_patch, *tmp;
	bsc_unregister_fd(&connection->bsc_fd);
	close(connection->bsc_fd.fd);
	llist_del(&connection->list_entry);

	/* stop the timeout timer */
	bsc_del_timer(&connection->id_timeout);

	/* remove all SCCP connections */
	llist_for_each_entry_safe(sccp_patch, tmp, &nat->sccp_connections, list_entry) {
		if (sccp_patch->bsc != connection)
			continue;

		llist_del(&sccp_patch->list_entry);
		talloc_free(sccp_patch);
	}

	talloc_free(connection);
}

static void ipaccess_close_bsc(void *data)
{
	struct bsc_connection *conn = data;

	LOGP(DNAT, LOGL_ERROR, "BSC didn't respond to identity request. Closing.\n");
	remove_bsc_connection(conn);
}

static void ipaccess_auth_bsc(struct tlv_parsed *tvp, struct bsc_connection *bsc)
{
	struct bsc_config *conf;
	const char* token = (const char *) TLVP_VAL(tvp, IPAC_IDTAG_UNITNAME);

	llist_for_each_entry(conf, &bsc->nat->bsc_configs, entry) {
		if (strcmp(conf->token, token) == 0) {
			bsc->authenticated = 1;
			bsc->lac = conf->lac;
			bsc_del_timer(&bsc->id_timeout);
			break;
		}
	}
}

static int forward_sccp_to_msc(struct bsc_fd *bfd, struct msgb *msg)
{
	struct bsc_connection *bsc;
	struct bsc_connection *found_bsc;
	struct bsc_nat_parsed *parsed;
	int rc = -1;

	bsc = bfd->data;

	/* Parse and filter messages */
	parsed = bsc_nat_parse(msg);
	if (!parsed) {
		LOGP(DNAT, LOGL_ERROR, "Can not parse msg from BSC.\n");
		return -1;
	}

	if (bsc_nat_filter_ipa(DIR_MSC, msg, parsed))
		goto exit;

	/* modify the SCCP entries */
	if (parsed->ipa_proto == IPAC_PROTO_SCCP) {
		switch (parsed->sccp_type) {
		case SCCP_MSG_TYPE_CR:
			if (create_sccp_src_ref(bsc, msg, parsed) != 0)
				goto exit2;
			found_bsc = patch_sccp_src_ref_to_msc(msg, parsed);
			break;
		case SCCP_MSG_TYPE_RLSD:
		case SCCP_MSG_TYPE_CREF:
		case SCCP_MSG_TYPE_DT1:
		case SCCP_MSG_TYPE_CC:
			found_bsc = patch_sccp_src_ref_to_msc(msg, parsed);
			break;
		case SCCP_MSG_TYPE_RLC:
			found_bsc = patch_sccp_src_ref_to_msc(msg, parsed);
			remove_sccp_src_ref(bsc, msg, parsed);
			break;
		case SCCP_MSG_TYPE_UDT:
			/* simply forward everything */
			break;
		default:
			goto exit2;
			break;
		}
	}

	if (found_bsc != bsc) {
		LOGP(DNAT, LOGL_ERROR, "Found the wrong entry.\n");
		goto exit2;
	}

	if (!bsc->authenticated) {
		LOGP(DNAT, LOGL_ERROR, "BSC is not authenticated.\n");
		goto exit2;
	}

	/* send the non-filtered but maybe modified msg */
	rc = write(msc_connection.fd, msg->data, msg->len);
	talloc_free(parsed);
	return rc;

exit:
	/* if we filter out the reset send an ack to the BSC */
	if (parsed->bssap == 0 && parsed->gsm_type == BSS_MAP_MSG_RESET) {
		send_reset_ack(bfd);
		send_reset_ack(bfd);
	} else if (parsed->ipa_proto == IPAC_PROTO_IPACCESS) {
		/* do we know who is handling this? */
		if (msg->l2h[0] == IPAC_MSGT_ID_RESP) {
			struct tlv_parsed tvp;
			ipaccess_idtag_parse(&tvp,
					     (unsigned char *) msg->l2h + 2,
					     msgb_l2len(msg) - 2);
			if (TLVP_PRESENT(&tvp, IPAC_IDTAG_UNITNAME))
				ipaccess_auth_bsc(&tvp, bsc);
		}

		goto exit2;
	}

exit2:
	talloc_free(parsed);
	return rc;
}

static int ipaccess_bsc_cb(struct bsc_fd *bfd, unsigned int what)
{
	int error;
	struct msgb *msg = ipaccess_read_msg(bfd, &error);

	if (!msg) {
		if (error == 0) {
			LOGP(DNAT, LOGL_ERROR,	"The connection to the BSC was lost. Cleaning it\n");
			remove_bsc_connection((struct bsc_connection *) bfd->data);
		} else {
			LOGP(DNAT, LOGL_ERROR, "Failed to parse ip access message: %d\n", error);
		}
		return -1;
	}


	LOGP(DNAT, LOGL_DEBUG, "MSG from BSC: %s proto: %d\n", hexdump(msg->data, msg->len), msg->l2h[0]);

	/* Handle messages from the BSC */
	/* FIXME: Currently no PONG is sent to the BSC */
	/* FIXME: Currently no ID ACK is sent to the BSC */
	forward_sccp_to_msc(bfd, msg);

	return 0;
}

static int ipaccess_listen_bsc_cb(struct bsc_fd *bfd, unsigned int what)
{
	struct bsc_connection *bsc;
	int ret;
	struct sockaddr_in sa;
	socklen_t sa_len = sizeof(sa);

	if (!(what & BSC_FD_READ))
		return 0;

	ret = accept(bfd->fd, (struct sockaddr *) &sa, &sa_len);
	if (ret < 0) {
		perror("accept");
		return ret;
	}

	/* todo... do something with the connection */
	/* todo... use GNUtls to see if we want to trust this as a BTS */

	/*
	 *
	 */
	bsc = bsc_connection_alloc();
	if (!bsc) {
		LOGP(DNAT, LOGL_ERROR, "Failed to allocate BSC struct.\n");
		close(ret);
		return -1;
	}

	bsc->nat = nat;
	bsc->bsc_fd.data = bsc;
	bsc->bsc_fd.fd = ret;
	bsc->bsc_fd.cb = ipaccess_bsc_cb;
	bsc->bsc_fd.when = BSC_FD_READ;
	if (bsc_register_fd(&bsc->bsc_fd) < 0) {
		LOGP(DNAT, LOGL_ERROR, "Failed to register BSC fd.\n");
		close(ret);
		talloc_free(bsc);
		return -2;
	}

	LOGP(DNAT, LOGL_INFO, "Registered new BSC\n");
	llist_add(&bsc->list_entry, &nat->bsc_connections);
	ipaccess_send_id_ack(bsc->bsc_fd.fd);
	ipaccess_send_id_req(ret);

	/*
	 * start the hangup timer
	 */
	bsc->id_timeout.data = bsc;
	bsc->id_timeout.cb = ipaccess_close_bsc;
	bsc_schedule_timer(&bsc->id_timeout, 2, 0);
	return 0;
}

static int listen_for_bsc(struct bsc_fd *bfd, struct in_addr *in_addr, int port)
{
	struct sockaddr_in addr;
	int ret, on = 1;

	bfd->fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	bfd->cb = ipaccess_listen_bsc_cb;
	bfd->when = BSC_FD_READ;

	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);
	addr.sin_addr.s_addr = in_addr->s_addr;

	setsockopt(bfd->fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));

	ret = bind(bfd->fd, (struct sockaddr *) &addr, sizeof(addr));
	if (ret < 0) {
		fprintf(stderr, "Could not bind the BSC socket %s\n",
			strerror(errno));
		return -EIO;
	}

	ret = listen(bfd->fd, 1);
	if (ret < 0) {
		perror("listen");
		return ret;
	}

	ret = bsc_register_fd(bfd);
	if (ret < 0) {
		perror("register_listen_fd");
		return ret;
	}
	return 0;
}

static void print_usage()
{
	printf("Usage: bsc_nat\n");
}

static void print_help()
{
	printf("  Some useful help...\n");
	printf("  -h --help this text\n");
	printf("  -d option --debug=DRLL:DCC:DMM:DRR:DRSL:DNM enable debugging\n");
	printf("  -s --disable-color\n");
	printf("  -c --config-file filename The config file to use.\n");
	printf("  -m --msc=IP. The address of the MSC.\n");
	printf("  -l --local=IP. The local address of this BSC.\n");
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
	switch (signal) {
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

int main(int argc, char** argv)
{
	int rc;

	/* parse options */
	local_addr.s_addr = INADDR_ANY;
	handle_options(argc, argv);

	nat = bsc_nat_alloc();
	if (!nat) {
		fprintf(stderr, "Failed to allocate the BSC nat.\n");
		return -4;
	}

	/* init vty and parse */
	bsc_nat_vty_init(nat);
	telnet_init(NULL, 4244);
	if (vty_read_config_file(config_file) < 0) {
		fprintf(stderr, "Failed to parse the config file: '%s'\n", config_file);
		return -3;
	}

	/* seed the PRNG */
	srand(time(NULL));

	/* connect to the MSC */
	msc_connection.cb = ipaccess_msc_cb;
	rc = connect_to_msc(&msc_connection, msc_address, 5000);
	if (rc < 0) {
		fprintf(stderr, "Opening the MSC connection failed.\n");
		exit(1);
	}

	/* wait for the BSC */
	if (listen_for_bsc(&bsc_connection, &local_addr, 5000) < 0) {
		fprintf(stderr, "Failed to listen for BSC.\n");
		exit(1);
	}

	signal(SIGABRT, &signal_handler);
	signal(SIGUSR1, &signal_handler);
	signal(SIGPIPE, SIG_IGN);

	while (1) {
		bsc_select_main(0);
	}

	return 0;
}
