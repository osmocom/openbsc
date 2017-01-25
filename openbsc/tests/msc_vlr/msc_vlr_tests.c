/* Osmocom MSC+VLR end-to-end tests */

/* (C) 2017 by sysmocom s.f.m.c. GmbH <info@sysmocom.de>
 *
 * All Rights Reserved
 *
 * Author: Neels Hofmeyr <nhofmeyr@sysmocom.de>
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

#include <getopt.h>
#include <stdlib.h>

#include <osmocom/core/logging.h>
#include <osmocom/core/utils.h>
#include <osmocom/core/msgb.h>
#include <osmocom/core/application.h>
#include <osmocom/gsm/protocol/gsm_04_11.h>
#include <osmocom/gsm/gsup.h>
#include <openbsc/gsup_client.h>
#include <openbsc/gsm_04_11.h>
#include <openbsc/bsc_subscriber.h>
#include <openbsc/debug.h>

#include "msc_vlr_tests.h"

bool _log_lines = false;

struct gsm_network *net = NULL;

struct gsm_bts *the_bts;

const char *gsup_tx_expected = NULL;
bool gsup_tx_confirmed;

struct msgb *dtap_tx_expected = NULL;
bool dtap_tx_confirmed;

enum result_sent lu_result_sent;
enum result_sent cm_service_result_sent;
bool auth_request_sent;
const char *auth_request_expect_rand;
const char *auth_request_expect_autn;
bool cipher_mode_cmd_sent;
bool cipher_mode_cmd_sent_with_imeisv;

struct msgb *msgb_from_hex(const char *label, uint16_t size, const char *hex)
{
	struct msgb *msg = msgb_alloc(size, label);
	unsigned char *rc;
	msg->l2h = msg->head;
	rc = msgb_put(msg, osmo_hexparse(hex, msg->head, msgb_tailroom(msg)));
	OSMO_ASSERT(rc == msg->l2h);
	return msg;
}

void dtap_expect_tx(const char *hex)
{
	OSMO_ASSERT(!dtap_tx_expected);
	if (!hex)
		return;
	dtap_tx_expected = msgb_from_hex("dtap_tx_expected", 1024, hex);
	dtap_tx_confirmed = false;
}

void dtap_expect_tx_ussd(char *ussd_text)
{
	uint8_t ussd_enc[128];
	int len;
	/* header */
	char ussd_msg_hex[128] = "8b2a1c27a225020100302002013b301b04010f0416";

	log("expecting USSD:\n  %s", ussd_text);
	/* append encoded USSD text */
	gsm_7bit_encode_n_ussd(ussd_enc, sizeof(ussd_enc), ussd_text,
			       &len);
	strncat(ussd_msg_hex, osmo_hexdump_nospc(ussd_enc, len),
		sizeof(ussd_msg_hex) - strlen(ussd_msg_hex));
	dtap_expect_tx(ussd_msg_hex);
}

int vlr_gsupc_read_cb(struct gsup_client *gsupc, struct msgb *msg);

void gsup_rx(const char *rx_hex, const char *expect_tx_hex)
{
	int rc;
	struct msgb *msg;
	const char *label;

	gsup_expect_tx(expect_tx_hex);

	msg = msgb_from_hex("gsup", 1024, rx_hex);
	label = osmo_gsup_message_type_name(msg->l2h[0]);
	fprintf(stderr, "<-- GSUP rx %s: %s\n", label,
		osmo_hexdump_nospc(msgb_l2(msg), msgb_l2len(msg)));
	rc = vlr_gsupc_read_cb(net->vlr->gsup_client, msg);
	fprintf(stderr, "<-- GSUP rx %s: vlr_gsupc_read_cb() returns %d\n",
		label, rc);
	if (expect_tx_hex)
		OSMO_ASSERT(gsup_tx_confirmed);
	talloc_free(msg);
}

bool conn_exists(struct gsm_subscriber_connection *conn)
{
	struct gsm_subscriber_connection *c;
	llist_for_each_entry(c, &net->subscr_conns, entry) {
		if (c == conn)
			return true;
	}
	return false;
}

enum ran_type rx_from_ran = RAN_GERAN_A;

struct gsm_subscriber_connection *conn_new(void)
{
	struct gsm_subscriber_connection *conn;
	conn = msc_subscr_con_allocate(net);
	conn->bts = the_bts;
	conn->via_ran = rx_from_ran;
	return conn;
}

struct gsm_subscriber_connection *g_conn = NULL;

void rx_from_ms(struct msgb *msg)
{
	int rc;

	struct gsm48_hdr *gh = msgb_l3(msg);
	log("rx from MS: pdisc=0x%02x msg_type=0x%02x",
	    gh->proto_discr, gh->msg_type);

	if (g_conn && !conn_exists(g_conn))
		g_conn = NULL;

	if (!g_conn) {
		log("new conn");
		g_conn = conn_new();
		rc = net->bsc_api->compl_l3(g_conn, msg, 23);
		if (rc == BSC_API_CONN_POL_REJECT) {
			msc_subscr_con_free(g_conn);
			g_conn = NULL;
		}
	} else {
		if ((gsm48_hdr_pdisc(gh) == GSM48_PDISC_RR)
		    && (gsm48_hdr_msg_type(gh) == GSM48_MT_RR_CIPH_M_COMPL))
			net->bsc_api->cipher_mode_compl(g_conn, msg, 0);
		else
			net->bsc_api->dtap(g_conn, 23, msg);
	}

	if (g_conn && !conn_exists(g_conn))
		g_conn = NULL;
}

void ms_sends_msg(const char *hex)
{
	struct msgb *msg;

	msg = msgb_from_hex("ms_sends_msg", 1024, hex);
	msg->l1h = msg->l2h = msg->l3h = msg->data;
	rx_from_ms(msg);
	talloc_free(msg);
}

int ms_sends_msg_fake(uint8_t pdisc, uint8_t msg_type)
{
	int rc;
	struct msgb *msg;
	struct gsm48_hdr *gh;

	msg = msgb_alloc(1024, "ms_sends_msg_fake");
	msg->l1h = msg->l2h = msg->l3h = msg->data;

	gh = (struct gsm48_hdr*)msgb_put(msg, sizeof(*gh));
	gh->proto_discr = pdisc;
	gh->msg_type = msg_type;
	/* some amount of data, whatever */
	msgb_put(msg, 123);

	rc = gsm0408_dispatch(g_conn, msg);

	talloc_free(msg);
	return rc;
}

void thwart_rx_non_initial_requests()
{
	log("requests shall be thwarted");
	OSMO_ASSERT(ms_sends_msg_fake(GSM48_PDISC_CC, GSM48_MT_CC_SETUP) == -EACCES);
	OSMO_ASSERT(ms_sends_msg_fake(GSM48_PDISC_MM, 0x33 /* nonexistent */) == -EACCES);
	OSMO_ASSERT(ms_sends_msg_fake(GSM48_PDISC_RR, GSM48_MT_RR_SYSINFO_1) == -EACCES);
	OSMO_ASSERT(ms_sends_msg_fake(GSM48_PDISC_SMS, GSM411_MT_CP_DATA) == -EACCES);
}

void send_sms(struct vlr_subscr *receiver,
	      struct vlr_subscr *sender,
	      char *str)
{
	struct gsm_sms *sms = sms_from_text(receiver, sender, 0, str);
	gsm411_send_sms_subscr(receiver, sms);
}

unsigned char next_rand_byte = 0;
/* override, requires '-Wl,--wrap=RAND_bytes' */
int __real_RAND_bytes(unsigned char *buf, int num);
int __wrap_RAND_bytes(unsigned char *buf, int num)
{
	int i;
	for (i = 0; i < num; i++)
		buf[i] = next_rand_byte++;
	return 1;
}

/* override, requires '-Wl,--wrap=gsm340_gen_scts' */
void __real_gsm340_gen_scts(uint8_t *scts, time_t time);
void __wrap_gsm340_gen_scts(uint8_t *scts, time_t time)
{
	/* Remove the time to encode for deterministic test results */
	__real_gsm340_gen_scts(scts, 0);
}

const char *paging_expecting_imsi = NULL;
uint32_t paging_expecting_tmsi;
bool paging_sent;
bool paging_stopped;

void paging_expect_imsi(const char *imsi)
{
	paging_expecting_imsi = imsi;
	paging_expecting_tmsi = GSM_RESERVED_TMSI;
}

void paging_expect_tmsi(uint32_t tmsi)
{
	paging_expecting_tmsi = tmsi;
	paging_expecting_imsi = NULL;
}

/* override, requires '-Wl,--wrap=paging_request' */
int __real_paging_request(struct gsm_network *network, struct bsc_subscr *sub,
			  int type, gsm_cbfn *cbfn, void *data);
int __wrap_paging_request(struct gsm_network *network, struct bsc_subscr *sub,
			  int type, gsm_cbfn *cbfn, void *data)
{
	log("BTS/BSC sends out paging request to %s for channel type %d",
	    bsc_subscr_name(sub), type);
	OSMO_ASSERT(paging_expecting_imsi || (paging_expecting_tmsi != GSM_RESERVED_TMSI));
	if (paging_expecting_imsi)
		VERBOSE_ASSERT(strcmp(paging_expecting_imsi, sub->imsi), == 0, "%d");
	if (paging_expecting_tmsi != GSM_RESERVED_TMSI)
		VERBOSE_ASSERT(paging_expecting_tmsi, == sub->tmsi, "0x%08x");
	paging_sent = true;
	paging_stopped = false;
	return 1;
}

/* override, requires '-Wl,--wrap=paging_request_stop' */
void __real_paging_request_stop(struct gsm_bts *_bts,
				struct vlr_subscr *vsub,
				struct gsm_subscriber_connection *conn,
				struct msgb *msg);
void __wrap_paging_request_stop(struct gsm_bts *_bts,
				struct vlr_subscr *vsub,
				struct gsm_subscriber_connection *conn,
				struct msgb *msg)
{
	paging_stopped = true;
}

void clear_vlr()
{
	struct vlr_subscr *vsub, *n;
	llist_for_each_entry_safe(vsub, n, &net->vlr->subscribers, list) {
		vlr_subscr_free(vsub);
	}

	net->authentication_required = false;
	net->a5_encryption = VLR_CIPH_NONE;
	net->vlr->cfg.check_imei_rqd = false;
	net->vlr->cfg.assign_tmsi = false;
	net->vlr->cfg.retrieve_imeisv = false;

	rx_from_ran = RAN_GERAN_A;
	auth_request_sent = false;
	auth_request_expect_rand = NULL;
	auth_request_expect_autn = NULL;

	next_rand_byte = 0;

	osmo_gettimeofday_override = false;
}

static struct log_info_cat test_categories[] = {
	[DMSC] = {
		.name = "DMSC",
		.description = "Mobile Switching Center",
		.enabled = 1, .loglevel = LOGL_DEBUG,
	},
	[DRLL] = {
		.name = "DRLL",
		.description = "A-bis Radio Link Layer (RLL)",
		.enabled = 1, .loglevel = LOGL_DEBUG,
	},
	[DMM] = {
		.name = "DMM",
		.description = "Layer3 Mobility Management (MM)",
		.enabled = 1, .loglevel = LOGL_DEBUG,
	},
	[DRR] = {
		.name = "DRR",
		.description = "Layer3 Radio Resource (RR)",
		.enabled = 1, .loglevel = LOGL_DEBUG,
	},
	[DCC] = {
		.name = "DCC",
		.description = "Layer3 Call Control (CC)",
		.enabled = 1, .loglevel = LOGL_NOTICE,
	},
	[DMM] = {
		.name = "DMM",
		.description = "Layer3 Mobility Management (MM)",
		.enabled = 1, .loglevel = LOGL_DEBUG,
	},
	[DVLR] = {
		.name = "DVLR",
		.description = "Visitor Location Register",
		.enabled = 1, .loglevel = LOGL_DEBUG,
	},
	[DREF] = {
		.name = "DREF",
		.description = "Reference Counting",
		.enabled = 1, .loglevel = LOGL_DEBUG,
	},
};

static struct log_info info = {
	.cat = test_categories,
	.num_cat = ARRAY_SIZE(test_categories),
};

extern void *tall_bsc_ctx;

int fake_mncc_recv(struct gsm_network *net, struct msgb *msg)
{
	fprintf(stderr, "rx MNCC\n");
	return 0;
}

/* override, requires '-Wl,--wrap=gsup_client_create' */
struct gsup_client *
__real_gsup_client_create(const char *ip_addr, unsigned int tcp_port,
			  gsup_client_read_cb_t read_cb,
			  struct oap_client_config *oap_config);
struct gsup_client *
__wrap_gsup_client_create(const char *ip_addr, unsigned int tcp_port,
			  gsup_client_read_cb_t read_cb,
			  struct oap_client_config *oap_config)
{
	struct gsup_client *gsupc;
	gsupc = talloc_zero(tall_bsc_ctx, struct gsup_client);
	OSMO_ASSERT(gsupc);
	return gsupc;
}

/* override, requires '-Wl,--wrap=gsup_client_send' */
int __real_gsup_client_send(struct gsup_client *gsupc, struct msgb *msg);
int __wrap_gsup_client_send(struct gsup_client *gsupc, struct msgb *msg)
{
	const char *is = osmo_hexdump_nospc(msg->data, msg->len);
	fprintf(stderr, "GSUP --> HLR: %s: %s\n",
		osmo_gsup_message_type_name(msg->data[0]), is);

	OSMO_ASSERT(gsup_tx_expected);
	if (strcmp(gsup_tx_expected, is)) {
		fprintf(stderr, "Mismatch! Expected:\n%s\n", gsup_tx_expected);
		abort();
	}

	talloc_free(msg);
	gsup_tx_confirmed = true;
	gsup_tx_expected = NULL;
	return 0;
}

/* override, requires '-Wl,--wrap=gsm0808_submit_dtap' */
int __real_gsm0808_submit_dtap(struct gsm_subscriber_connection *conn,
			       struct msgb *msg, int link_id, int allow_sacch);
int __wrap_gsm0808_submit_dtap(struct gsm_subscriber_connection *conn,
			       struct msgb *msg, int link_id, int allow_sacch)
{
	btw("DTAP --> MS: %s", osmo_hexdump_nospc(msg->data, msg->len));

	OSMO_ASSERT(dtap_tx_expected);
	if (msg->len != dtap_tx_expected->len
	    || memcmp(msg->data, dtap_tx_expected->data, msg->len)) {
		fprintf(stderr, "Mismatch! Expected:\n%s\n",
		       osmo_hexdump_nospc(dtap_tx_expected->data,
					  dtap_tx_expected->len));
		abort();
	}

	btw("DTAP matches expected message");

	talloc_free(msg);
	dtap_tx_confirmed = true;
	talloc_free(dtap_tx_expected);
	dtap_tx_expected = NULL;
	return 0;
}

static int fake_vlr_tx_lu_acc(void *msc_conn_ref, uint32_t send_tmsi)
{
	struct gsm_subscriber_connection *conn = msc_conn_ref;
	if (send_tmsi == GSM_RESERVED_TMSI)
		btw("sending LU Accept for %s", vlr_subscr_name(conn->vsub));
	else
		btw("sending LU Accept for %s, with TMSI 0x%08x",
		    vlr_subscr_name(conn->vsub), send_tmsi);
	lu_result_sent |= RES_ACCEPT;
	return 0;
}

static int fake_vlr_tx_lu_rej(void *msc_conn_ref, uint8_t cause)
{
	struct gsm_subscriber_connection *conn = msc_conn_ref;
	btw("sending LU Reject for %s, cause %u", vlr_subscr_name(conn->vsub), cause);
	lu_result_sent |= RES_REJECT;
	return 0;
}

static int fake_vlr_tx_cm_serv_acc(void *msc_conn_ref)
{
	struct gsm_subscriber_connection *conn = msc_conn_ref;
	btw("sending CM Service Accept for %s", vlr_subscr_name(conn->vsub));
	cm_service_result_sent |= RES_ACCEPT;
	return 0;
}

static int fake_vlr_tx_cm_serv_rej(void *msc_conn_ref,
				   enum vlr_proc_arq_result result)
{
	struct gsm_subscriber_connection *conn = msc_conn_ref;
	btw("sending CM Service Reject for %s, result %s",
	    vlr_subscr_name(conn->vsub),
	    vlr_proc_arq_result_name(result));
	cm_service_result_sent |= RES_REJECT;
	return 0;
}

static int fake_vlr_tx_auth_req(void *msc_conn_ref, struct gsm_auth_tuple *at,
				bool send_autn)
{
	struct gsm_subscriber_connection *conn = msc_conn_ref;
	char *hex;
	bool ok = true;
	btw("sending %s Auth Request for %s: tuple use_count=%d key_seq=%d auth_types=0x%x and...",
	    send_autn? "UMTS" : "GSM", vlr_subscr_name(conn->vsub),
	    at->use_count, at->key_seq, at->vec.auth_types);

	hex = osmo_hexdump_nospc((void*)&at->vec.rand, sizeof(at->vec.rand));
	btw("...rand=%s", hex);
	if (!auth_request_expect_rand
	    || strcmp(hex, auth_request_expect_rand) != 0) {
		ok = false;
		log("FAILURE: expected rand=%s",
		    auth_request_expect_rand ? auth_request_expect_rand : "-");
	}

	if (send_autn) {
		hex = osmo_hexdump_nospc((void*)&at->vec.autn, sizeof(at->vec.autn));
		btw("...autn=%s", hex);
		if (!auth_request_expect_autn
		    || strcmp(hex, auth_request_expect_autn) != 0) {
			ok = false;
			log("FAILURE: expected autn=%s",
			    auth_request_expect_autn ? auth_request_expect_autn : "-");
		}
	} else if (auth_request_expect_autn) {
		ok = false;
		log("FAILURE: no AUTN sent, expected AUTN = %s",
		    auth_request_expect_autn);
	}

	if (send_autn)
		btw("...expecting res=%s",
		    osmo_hexdump_nospc((void*)&at->vec.res, at->vec.res_len));
	else
		btw("...expecting sres=%s",
		    osmo_hexdump_nospc((void*)&at->vec.sres, sizeof(at->vec.sres)));

	auth_request_sent = ok;
	return 0;
}

static int fake_vlr_tx_auth_rej(void *msc_conn_ref)
{
	struct gsm_subscriber_connection *conn = msc_conn_ref;
	btw("sending Auth Reject for %s", vlr_subscr_name(conn->vsub));
	return 0;
}

static int fake_vlr_tx_ciph_mode_cmd(void *msc_conn_ref, enum vlr_ciph ciph,
				     bool retrieve_imeisv)
{
	/* FIXME: we actually would like to see the message bytes checked here,
	 * not possible while msc_vlr_set_ciph_mode() calls
	 * gsm0808_cipher_mode() directly. When the MSCSPLIT is ready, check
	 * the tx bytes in the sense of dtap_expect_tx() above. */
	struct gsm_subscriber_connection *conn = msc_conn_ref;
	btw("sending Ciphering Mode Command for %s: cipher=%s kc=%s"
	    " retrieve_imeisv=%d",
	    vlr_subscr_name(conn->vsub),
	    vlr_ciph_name(conn->network->a5_encryption),
	    osmo_hexdump_nospc(conn->vsub->last_tuple->vec.kc, 8),
	    retrieve_imeisv);
	cipher_mode_cmd_sent = true;
	cipher_mode_cmd_sent_with_imeisv = retrieve_imeisv;
	return 0;
}

const struct timeval fake_time_start_time = { 123, 456 };

void fake_time_start()
{
	osmo_gettimeofday_override_time = fake_time_start_time;
	osmo_gettimeofday_override = true;
	fake_time_passes(0, 0);
}

void check_talloc(void *msgb_ctx, void *tall_bsc_ctx, int expected_blocks)
{
	talloc_report_full(msgb_ctx, stderr);
	fprintf(stderr, "talloc_total_blocks(tall_bsc_ctx) == %zu\n",
		talloc_total_blocks(tall_bsc_ctx));
	if (talloc_total_blocks(tall_bsc_ctx) != expected_blocks)
		talloc_report_full(tall_bsc_ctx, stderr);
	fprintf(stderr, "\n");
}

static struct {
	bool verbose;
	int run_test_nr;
} cmdline_opts = {
	.verbose = false,
	.run_test_nr = -1,
};

static void print_help(const char *program)
{
	printf("Usage:\n"
	       "  %s [-v] [N [N...]]\n"
	       "Options:\n"
	       "  -h --help      show this text.\n"
	       "  -v --verbose   print source file and line numbers\n"
	       "  N              run only the Nth test (first test is N=1)\n",
	       program
	       );
}

static void handle_options(int argc, char **argv)
{
	while (1) {
		int option_index = 0, c;
		static struct option long_options[] = {
			{"help", 0, 0, 'h'},
			{"verbose", 1, 0, 'v'},
			{0, 0, 0, 0}
		};

		c = getopt_long(argc, argv, "hv",
				long_options, &option_index);
		if (c == -1)
			break;

		switch (c) {
		case 'h':
			print_help(argv[0]);
			exit(0);
		case 'v':
			cmdline_opts.verbose = true;
			break;
		default:
			/* catch unknown options *as well as* missing arguments. */
			fprintf(stderr, "Error in command line options. Exiting.\n");
			exit(-1);
			break;
		}
	}
}

void *msgb_ctx = NULL;

void run_tests(int nr)
{
	int test_nr;
	nr --; /* arg's first test is 1, in here it's 0 */
	for (test_nr = 0; msc_vlr_tests[test_nr]; test_nr ++) {
		if (nr >= 0 && test_nr != nr)
			continue;

		if (cmdline_opts.verbose)
			fprintf(stderr, "(test nr %d)\n", test_nr + 1);

		msc_vlr_tests[test_nr]();

		if (cmdline_opts.verbose)
			fprintf(stderr, "(test nr %d)\n", test_nr + 1);

		check_talloc(msgb_ctx, tall_bsc_ctx, 75);
	} while(0);
}

int main(int argc, char **argv)
{
	handle_options(argc, argv);

	tall_bsc_ctx = talloc_named_const(NULL, 0, "subscr_conn_test_ctx");
	msgb_ctx = msgb_talloc_ctx_init(tall_bsc_ctx, 0);
	osmo_init_logging(&info);

	_log_lines = cmdline_opts.verbose;

	OSMO_ASSERT(osmo_stderr_target);
	log_set_use_color(osmo_stderr_target, 0);
	log_set_print_timestamp(osmo_stderr_target, 0);
	log_set_print_filename(osmo_stderr_target, _log_lines? 1 : 0);
	log_set_print_category(osmo_stderr_target, 1);

	net = gsm_network_init(tall_bsc_ctx, 1, 1, fake_mncc_recv);
	bsc_api_init(net, msc_bsc_api());
	the_bts = gsm_bts_alloc(net);
	net->gsup_server_addr_str = talloc_strdup(net, "no_gsup_server");
	net->gsup_server_port = 0;

	osmo_fsm_log_addr(false);
	OSMO_ASSERT(msc_vlr_alloc(net) == 0);
	OSMO_ASSERT(msc_vlr_start(net) == 0);
	OSMO_ASSERT(net->vlr);
	OSMO_ASSERT(net->vlr->gsup_client);
	msc_subscr_conn_init();

	net->vlr->ops.tx_lu_acc = fake_vlr_tx_lu_acc;
	net->vlr->ops.tx_lu_rej = fake_vlr_tx_lu_rej;
	net->vlr->ops.tx_cm_serv_acc = fake_vlr_tx_cm_serv_acc;
	net->vlr->ops.tx_cm_serv_rej = fake_vlr_tx_cm_serv_rej;
	net->vlr->ops.tx_auth_req = fake_vlr_tx_auth_req;
	net->vlr->ops.tx_auth_rej = fake_vlr_tx_auth_rej;
	net->vlr->ops.set_ciph_mode = fake_vlr_tx_ciph_mode_cmd;

	if (optind >= argc)
		run_tests(-1);
	else {
		int arg;
		long int nr;
		for (arg = optind; arg < argc; arg++) {
			nr = strtol(argv[arg], NULL, 10);
			if (errno) {
				fprintf(stderr, "Invalid argument: %s\n",
					argv[arg]);
				exit(1);
			}

			run_tests(nr);
		}
	}

	printf("Done\n");

	talloc_free(the_bts);

	check_talloc(msgb_ctx, tall_bsc_ctx, 9);
	return 0;
}
