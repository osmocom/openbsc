/*
 * BSC NAT Message filtering
 *
 * (C) 2010 by Holger Hans Peter Freyther <zecke@selfish.org>
 * (C) 2010 by On-Waves
 *
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


#include <openbsc/debug.h>
#include <openbsc/gsm_data.h>
#include <openbsc/bsc_nat.h>

#include <osmocore/talloc.h>

#include <stdio.h>

/* test messages for ipa */
static u_int8_t ipa_id[] = {
	0x00, 0x01, 0xfe, 0x06,
};

/* SCCP messages are below */
static u_int8_t gsm_reset[] = {
	0x00, 0x12, 0xfd,
	0x09, 0x00, 0x03, 0x05, 0x07, 0x02, 0x42, 0xfe,
	0x02, 0x42, 0xfe, 0x06, 0x00, 0x04, 0x30, 0x04,
	0x01, 0x20,
};

static const u_int8_t gsm_reset_ack[] = {
	0x00, 0x13, 0xfd,
	0x09, 0x00, 0x03, 0x07, 0x0b, 0x04, 0x43, 0x01,
	0x00, 0xfe, 0x04, 0x43, 0x5c, 0x00, 0xfe, 0x03,
	0x00, 0x01, 0x31,
};

static const u_int8_t gsm_paging[] = {
	0x00, 0x20, 0xfd,
	0x09, 0x00, 0x03, 0x07, 0x0b, 0x04, 0x43, 0x01,
	0x00, 0xfe, 0x04, 0x43, 0x5c, 0x00, 0xfe, 0x10,
	0x00, 0x0e, 0x52, 0x08, 0x08, 0x29, 0x47, 0x10,
	0x02, 0x01, 0x31, 0x97, 0x61, 0x1a, 0x01, 0x06,
};

/* BSC -> MSC connection open */
static const u_int8_t bssmap_cr[] = {
	0x00, 0x2c, 0xfd,
	0x01, 0x01, 0x02, 0x03, 0x02, 0x02, 0x04, 0x02,
	0x42, 0xfe, 0x0f, 0x1f, 0x00, 0x1d, 0x57, 0x05,
	0x08, 0x00, 0x72, 0xf4, 0x80, 0x20, 0x12, 0xc3,
	0x50, 0x17, 0x10, 0x05, 0x24, 0x11, 0x03, 0x33,
	0x19, 0xa2, 0x08, 0x29, 0x47, 0x10, 0x02, 0x01,
	0x31, 0x97, 0x61, 0x00
};

/* MSC -> BSC connection confirm */
static const u_int8_t bssmap_cc[] = {
	0x00, 0x0a, 0xfd,
	0x02, 0x01, 0x02, 0x03, 0x00, 0x00, 0x03, 0x02, 0x01, 0x00,
};

/* MSC -> BSC released */
static const u_int8_t bssmap_released[] = {
	0x00, 0x0e, 0xfd,
	0x04, 0x00, 0x00, 0x03, 0x01, 0x02, 0x03, 0x00, 0x01, 0x0f,
	0x02, 0x23, 0x42, 0x00,
};

/* BSC -> MSC released */
static const u_int8_t bssmap_release_complete[] = {
	0x00, 0x07, 0xfd,
	0x05, 0x01, 0x02, 0x03, 0x00, 0x00, 0x03
};

/* both directions IT timer */
static const u_int8_t connnection_it[] = {
	0x00, 0x0b, 0xfd,
	0x10, 0x01, 0x02, 0x03, 0x01, 0x02, 0x03,
	0x00, 0x00, 0x00, 0x00,
};

/* error in both directions */
static const u_int8_t proto_error[] = {
	0x00, 0x05, 0xfd,
	0x0f, 0x22, 0x33, 0x44, 0x00,
};

/* MGCP wrap... */
static const u_int8_t mgcp_msg[] = {
	0x00, 0x03, 0xfc,
	0x20, 0x20, 0x20,
};

/* location updating request */
static const u_int8_t bss_lu[] = {
	0x00, 0x2e, 0xfd,
	0x01, 0x91, 0x45, 0x14, 0x02, 0x02, 0x04, 0x02,
	0x42, 0xfe, 0x0f, 0x21, 0x00, 0x1f, 0x57, 0x05,
	0x08, 0x00, 0x72, 0xf4, 0x80, 0x20, 0x14, 0xc3,
	0x50, 0x17, 0x12, 0x05, 0x08, 0x70, 0x72, 0xf4,
	0x80, 0xff, 0xfe, 0x30, 0x08, 0x29, 0x44, 0x50,
	0x12, 0x03, 0x24, 0x01, 0x95, 0x00
};

/* paging response */
static const uint8_t pag_resp[] = {
	0x00, 0x2c, 0xfd, 0x01, 0xe5, 0x68,
	0x14, 0x02, 0x02, 0x04, 0x02, 0x42, 0xfe, 0x0f,
	0x1f, 0x00, 0x1d, 0x57, 0x05, 0x08, 0x00, 0x72,
	0xf4, 0x80, 0x20, 0x16, 0xc3, 0x50, 0x17, 0x10,
	0x06, 0x27, 0x01, 0x03, 0x30, 0x18, 0x96, 0x08,
	0x29, 0x26, 0x30, 0x32, 0x11, 0x42, 0x01, 0x19,
	0x00
};

struct filter_result {
	const u_int8_t *data;
	const u_int16_t length;
	const int dir;
	const int result;
};

static const struct filter_result results[] = {
	{
		.data = ipa_id,
		.length = ARRAY_SIZE(ipa_id),
		.dir = DIR_MSC,
		.result = 1,
	},
	{
		.data = gsm_reset,
		.length = ARRAY_SIZE(gsm_reset),
		.dir = DIR_MSC,
		.result = 1,
	},
	{
		.data = gsm_reset_ack,
		.length = ARRAY_SIZE(gsm_reset_ack),
		.dir = DIR_BSC,
		.result = 1,
	},
	{
		.data = gsm_paging,
		.length = ARRAY_SIZE(gsm_paging),
		.dir = DIR_BSC,
		.result = 0,
	},
	{
		.data = bssmap_cr,
		.length = ARRAY_SIZE(bssmap_cr),
		.dir = DIR_MSC,
		.result = 0,
	},
	{
		.data = bssmap_cc,
		.length = ARRAY_SIZE(bssmap_cc),
		.dir = DIR_BSC,
		.result = 0,
	},
	{
		.data = bssmap_released,
		.length = ARRAY_SIZE(bssmap_released),
		.dir = DIR_MSC,
		.result = 0,
	},
	{
		.data = bssmap_release_complete,
		.length = ARRAY_SIZE(bssmap_release_complete),
		.dir = DIR_BSC,
		.result = 0,
	},
	{
		.data = mgcp_msg,
		.length = ARRAY_SIZE(mgcp_msg),
		.dir = DIR_MSC,
		.result = 0,
	},
	{
		.data = connnection_it,
		.length = ARRAY_SIZE(connnection_it),
		.dir = DIR_BSC,
		.result = 0,
	},
	{
		.data = connnection_it,
		.length = ARRAY_SIZE(connnection_it),
		.dir = DIR_MSC,
		.result = 0,
	},
	{
		.data = proto_error,
		.length = ARRAY_SIZE(proto_error),
		.dir = DIR_BSC,
		.result = 0,
	},
	{
		.data = proto_error,
		.length = ARRAY_SIZE(proto_error),
		.dir = DIR_MSC,
		.result = 0,
	},

};

static void test_filter(void)
{
	int i;


	/* start testinh with proper messages */
	fprintf(stderr, "Testing BSS Filtering.\n");
	for (i = 0; i < ARRAY_SIZE(results); ++i) {
		int result;
		struct bsc_nat_parsed *parsed;
		struct msgb *msg = msgb_alloc(4096, "test-message");

		fprintf(stderr, "Going to test item: %d\n", i);
		memcpy(msg->data, results[i].data, results[i].length);
		msg->l2h = msgb_put(msg, results[i].length);

		parsed = bsc_nat_parse(msg);
		if (!parsed) {
			fprintf(stderr, "FAIL: Failed to parse the message\n");
			continue;
		}

		result = bsc_nat_filter_ipa(results[i].dir, msg, parsed);
		if (result != results[i].result) {
			fprintf(stderr, "FAIL: Not the expected result got: %d wanted: %d\n",
				result, results[i].result);
		}

		msgb_free(msg);
	}
}

#include "bsc_data.c"

static void copy_to_msg(struct msgb *msg, const u_int8_t *data, unsigned int length)
{
	msgb_reset(msg);
	msg->l2h = msgb_put(msg, length);
	memcpy(msg->l2h, data, msgb_l2len(msg));
}

#define VERIFY(con_found, con, msg, ver, str) \
	if (!con_found || con_found->bsc != con) { \
		fprintf(stderr, "Failed to find the con: %p\n", con_found); \
		abort(); \
	} \
	if (memcmp(msg->data, ver, sizeof(ver)) != 0) { \
		fprintf(stderr, "Failed to patch the %s msg.\n", str); \
		abort(); \
	}

/* test conn tracking once */
static void test_contrack()
{
	struct bsc_nat *nat;
	struct bsc_connection *con;
	struct sccp_connections *con_found;
	struct sccp_connections *rc_con;
	struct bsc_nat_parsed *parsed;
	struct msgb *msg;

	fprintf(stderr, "Testing connection tracking.\n");
	nat = bsc_nat_alloc();
	con = bsc_connection_alloc(nat);
	con->cfg = bsc_config_alloc(nat, "foo", 23);
	msg = msgb_alloc(4096, "test");

	/* 1.) create a connection */
	copy_to_msg(msg, bsc_cr, sizeof(bsc_cr));
	parsed = bsc_nat_parse(msg);
	con_found = patch_sccp_src_ref_to_msc(msg, parsed, con);
	if (con_found != NULL) {
		fprintf(stderr, "Con should not exist %p\n", con_found);
		abort();
	}
	rc_con = create_sccp_src_ref(con, parsed);
	if (!rc_con) {
		fprintf(stderr, "Failed to create a ref\n");
		abort();
	}
	con_found = patch_sccp_src_ref_to_msc(msg, parsed, con);
	if (!con_found || con_found->bsc != con) {
		fprintf(stderr, "Failed to find the con: %p\n", con_found);
		abort();
	}
	if (con_found != rc_con) {
		fprintf(stderr, "Failed to find the right connection.\n");
		abort();
	}
	if (memcmp(msg->data, bsc_cr_patched, sizeof(bsc_cr_patched)) != 0) {
		fprintf(stderr, "Failed to patch the BSC CR msg.\n");
		abort();
	}
	talloc_free(parsed);

	/* 2.) get the cc */
	copy_to_msg(msg, msc_cc, sizeof(msc_cc));
	parsed = bsc_nat_parse(msg);
	con_found = patch_sccp_src_ref_to_bsc(msg, parsed, nat);
	VERIFY(con_found, con, msg, msc_cc_patched, "MSC CC");
	if (update_sccp_src_ref(con_found, parsed) != 0) {
		fprintf(stderr, "Failed to update the SCCP con.\n");
		abort();
	}

	/* 3.) send some data */
	copy_to_msg(msg, bsc_dtap, sizeof(bsc_dtap));
	parsed = bsc_nat_parse(msg);
	con_found = patch_sccp_src_ref_to_msc(msg, parsed, con);
	VERIFY(con_found, con, msg, bsc_dtap_patched, "BSC DTAP");

	/* 4.) receive some data */
	copy_to_msg(msg, msc_dtap, sizeof(msc_dtap));
	parsed = bsc_nat_parse(msg);
	con_found = patch_sccp_src_ref_to_bsc(msg, parsed, nat);
	VERIFY(con_found, con, msg, msc_dtap_patched, "MSC DTAP");

	/* 5.) close the connection */
	copy_to_msg(msg, msc_rlsd, sizeof(msc_rlsd));
	parsed = bsc_nat_parse(msg);
	con_found = patch_sccp_src_ref_to_bsc(msg, parsed, nat);
	VERIFY(con_found, con, msg, msc_rlsd_patched, "MSC RLSD");

	/* 6.) confirm the connection close */
	copy_to_msg(msg, bsc_rlc, sizeof(bsc_rlc));
	parsed = bsc_nat_parse(msg);
	con_found = patch_sccp_src_ref_to_msc(msg, parsed, con);
	if (!con_found || con_found->bsc != con) {
		fprintf(stderr, "Failed to find the con: %p\n", con_found);
		abort();
	}
	if (memcmp(msg->data, bsc_rlc_patched, sizeof(bsc_rlc_patched)) != 0) {
		fprintf(stderr, "Failed to patch the BSC CR msg.\n");
		abort();
	}
	remove_sccp_src_ref(con, msg, parsed);
	talloc_free(parsed);

	copy_to_msg(msg, bsc_rlc, sizeof(bsc_rlc));
	parsed = bsc_nat_parse(msg);
	con_found = patch_sccp_src_ref_to_msc(msg, parsed, con);

	/* verify that it is gone */
	if (con_found != NULL) {
		fprintf(stderr, "Con should be gone. %p\n", con_found);
		abort();
	}
	talloc_free(parsed);


	talloc_free(nat);
	msgb_free(msg);
}

static void test_paging(void)
{
	int lac;
	struct bsc_nat *nat;
	struct bsc_connection *con;
	struct bsc_nat_parsed *parsed;
	struct bsc_config cfg;
	struct msgb *msg;

	fprintf(stderr, "Testing paging by lac.\n");

	nat = bsc_nat_alloc();
	con = bsc_connection_alloc(nat);
	con->cfg = &cfg;
	cfg.lac = 23;
	con->authenticated = 1;
	llist_add(&con->list_entry, &nat->bsc_connections);
	msg = msgb_alloc(4096, "test");

	/* Test completely bad input */
	copy_to_msg(msg, paging_by_lac_cmd, sizeof(paging_by_lac_cmd));
	if (bsc_nat_find_bsc(nat, msg, &lac) != 0) {
		fprintf(stderr, "Should have not found anything.\n");
		abort();
	}

	/* Test it by not finding it */
	copy_to_msg(msg, paging_by_lac_cmd, sizeof(paging_by_lac_cmd));
	parsed = bsc_nat_parse(msg);
	if (bsc_nat_find_bsc(nat, msg, &lac) != 0) {
		fprintf(stderr, "Should have not found aynthing.\n");
		abort();
	}
	talloc_free(parsed);

	/* Test by finding it */
	cfg.lac = 8213;
	copy_to_msg(msg, paging_by_lac_cmd, sizeof(paging_by_lac_cmd));
	parsed = bsc_nat_parse(msg);
	if (bsc_nat_find_bsc(nat, msg, &lac) != con) {
		fprintf(stderr, "Should have found it.\n");
		abort();
	}
	talloc_free(parsed);
}

static void test_mgcp_ass_tracking(void)
{
	struct bsc_connection *bsc;
	struct bsc_nat *nat;
	struct sccp_connections con;
	struct bsc_nat_parsed *parsed;
	struct msgb *msg;

	fprintf(stderr, "Testing MGCP.\n");
	memset(&con, 0, sizeof(con));

	nat = bsc_nat_alloc();
	nat->bsc_endpoints = talloc_zero_array(nat,
					       struct bsc_endpoint,
					       33);
	bsc = bsc_connection_alloc(nat);
	bsc->cfg = bsc_config_alloc(nat, "foo", 2323);
	con.bsc = bsc;

	msg = msgb_alloc(4096, "foo");
	copy_to_msg(msg, ass_cmd, sizeof(ass_cmd));
	parsed = bsc_nat_parse(msg);
	if (bsc_mgcp_assign(&con, msg) != 0) {
		fprintf(stderr, "Failed to handle assignment.\n");
		abort();
	}

	if (con.msc_timeslot != 21) {
		fprintf(stderr, "Timeslot should be 21.\n");
		abort();
	}

	if (con.bsc_timeslot != 21) {
		fprintf(stderr, "Assigned timeslot should have been 21.\n");
		abort();
	}
	talloc_free(parsed);

	bsc_mgcp_dlcx(&con);
	if (con.bsc_timeslot != -1 || con.msc_timeslot != -1) {
		fprintf(stderr, "Clearing should remove the mapping.\n");
		abort();
	}

	talloc_free(nat);
}

/* test the code to find a given connection */
static void test_mgcp_find(void)
{
	struct bsc_nat *nat;
	struct bsc_connection *con;
	struct sccp_connections *sccp_con;

	fprintf(stderr, "Testing finding of a BSC Connection\n");

	nat = bsc_nat_alloc();
	con = bsc_connection_alloc(nat);
	llist_add(&con->list_entry, &nat->bsc_connections);

	sccp_con = talloc_zero(con, struct sccp_connections);
	sccp_con->msc_timeslot = 12;
	sccp_con->bsc_timeslot = 12;
	sccp_con->bsc = con;
	llist_add(&sccp_con->list_entry, &nat->sccp_connections);

	if (bsc_mgcp_find_con(nat, 11) != NULL) {
		fprintf(stderr, "Found the wrong connection.\n");
		abort();
	}

	if (bsc_mgcp_find_con(nat, 12) != sccp_con) {
		fprintf(stderr, "Didn't find the connection\n");
		abort();
	}

	sccp_con->msc_timeslot = 0;
	sccp_con->bsc_timeslot = 0;
	if (bsc_mgcp_find_con(nat, 1) != sccp_con) {
		fprintf(stderr, "Didn't find the connection\n");
		abort();
	}

	/* free everything */
	talloc_free(nat);
}

static void test_mgcp_rewrite(void)
{
	int i;
	struct msgb *output;
	fprintf(stderr, "Test rewriting MGCP messages.\n");

	for (i = 0; i < ARRAY_SIZE(mgcp_messages); ++i) {
		const char *orig = mgcp_messages[i].orig;
		const char *patc = mgcp_messages[i].patch;
		const char *ip = mgcp_messages[i].ip;
		const int port = mgcp_messages[i].port;

		char *input = strdup(orig);

		output = bsc_mgcp_rewrite(input, strlen(input), ip, port);
		if (msgb_l2len(output) != strlen(patc)) {
			fprintf(stderr, "Wrong sizes for test: %d  %d != %d != %d\n", i, msgb_l2len(output), strlen(patc), strlen(orig));
			fprintf(stderr, "String '%s' vs '%s'\n", (const char *) output->l2h, patc);
			abort();
		}

		if (memcmp(output->l2h, patc, msgb_l2len(output)) != 0) {
			fprintf(stderr, "Broken on %d msg: '%s'\n", i, (const char *) output->l2h);
			abort();
		}

		msgb_free(output);
		free(input);
	}
}

static void test_mgcp_parse(void)
{
	int code, ci;
	char transaction[60];

	fprintf(stderr, "Test MGCP response parsing.\n");

	if (bsc_mgcp_parse_response(crcx_resp, &code, transaction) != 0) {
		fprintf(stderr, "Failed to parse CRCX resp.\n");
		abort();
	}

	if (code != 200) {
		fprintf(stderr, "Failed to parse the CODE properly. Got: %d\n", code);
		abort();
	}

	if (strcmp(transaction, "23265295") != 0) {
		fprintf(stderr, "Failed to parse transaction id: '%s'\n", transaction);
		abort();
	}

	ci = bsc_mgcp_extract_ci(crcx_resp);
	if (ci != 1) {
		fprintf(stderr, "Failed to parse the CI. Got: %d\n", ci);
		abort();
	}
}

struct cr_filter {
	const u_int8_t *data;
	int length;
	int result;
	int contype;

	const char *bsc_imsi_allow;
	const char *bsc_imsi_deny;
	const char *nat_imsi_deny;
};

static struct cr_filter cr_filter[] = {
	{
		.data = bssmap_cr,
		.length = sizeof(bssmap_cr),
		.result = 0,
		.contype = NAT_CON_TYPE_CM_SERV_REQ,
	},
	{
		.data = bss_lu,
		.length = sizeof(bss_lu),
		.result = 0,
		.contype = NAT_CON_TYPE_LU,
	},
	{
		.data = pag_resp,
		.length = sizeof(pag_resp),
		.result = 0,
		.contype = NAT_CON_TYPE_PAG_RESP,
	},
	{
		/* nat deny is before blank/null BSC */
		.data = bss_lu,
		.length = sizeof(bss_lu),
		.result = -3,
		.nat_imsi_deny = "[0-9]*",
		.contype = NAT_CON_TYPE_LU,
	},
	{
		/* BSC allow is before NAT deny */
		.data = bss_lu,
		.length = sizeof(bss_lu),
		.result = 0,
		.nat_imsi_deny = "[0-9]*",
		.bsc_imsi_allow = "2440[0-9]*",
		.contype = NAT_CON_TYPE_LU,
	},
	{
		/* BSC allow is before NAT deny */
		.data = bss_lu,
		.length = sizeof(bss_lu),
		.result = 0,
		.bsc_imsi_allow = "[0-9]*",
		.nat_imsi_deny = "[0-9]*",
		.contype = NAT_CON_TYPE_LU,
	},
	{
		/* filter as deny is first */
		.data = bss_lu,
		.length = sizeof(bss_lu),
		.result = -2,
		.bsc_imsi_deny = "[0-9]*",
		.bsc_imsi_allow = "[0-9]*",
		.nat_imsi_deny = "[0-9]*",
		.contype = NAT_CON_TYPE_LU,
	},

};

static void test_cr_filter()
{
	int i, res, contype;
	struct msgb *msg = msgb_alloc(4096, "test_cr_filter");
	struct bsc_nat_parsed *parsed;
	struct bsc_nat_access_list *nat_lst, *bsc_lst;

	struct bsc_nat *nat = bsc_nat_alloc();
	struct bsc_connection *bsc = bsc_connection_alloc(nat);
	bsc->cfg = bsc_config_alloc(nat, "foo", 1234);
	bsc->cfg->acc_lst_name = "bsc";
	nat->acc_lst_name = "nat";

	for (i = 0; i < ARRAY_SIZE(cr_filter); ++i) {
		msgb_reset(msg);
		copy_to_msg(msg, cr_filter[i].data, cr_filter[i].length);

		nat_lst = bsc_nat_accs_list_get(nat, "nat");
		bsc_lst = bsc_nat_accs_list_get(nat, "bsc");

		bsc_parse_reg(nat_lst, &nat_lst->imsi_deny_re, &nat_lst->imsi_deny,
			      cr_filter[i].nat_imsi_deny ? 1 : 0,
			      &cr_filter[i].nat_imsi_deny);
		bsc_parse_reg(bsc_lst, &bsc_lst->imsi_allow_re, &bsc_lst->imsi_allow,
			      cr_filter[i].bsc_imsi_allow ? 1 : 0,
			      &cr_filter[i].bsc_imsi_allow);
		bsc_parse_reg(bsc_lst, &bsc_lst->imsi_deny_re, &bsc_lst->imsi_deny,
			      cr_filter[i].bsc_imsi_deny ? 1 : 0,
			      &cr_filter[i].bsc_imsi_deny);

		parsed = bsc_nat_parse(msg);
		if (!parsed) {
			fprintf(stderr, "FAIL: Failed to parse the message\n");
			abort();
		}

		res = bsc_nat_filter_sccp_cr(bsc, msg, parsed, &contype);
		if (res != cr_filter[i].result) {
			fprintf(stderr, "FAIL: Wrong result %d for test %d.\n", res, i);
			abort();
		}

		if (contype != cr_filter[i].contype) {
			fprintf(stderr, "FAIL: Wrong contype %d for test %d.\n", res, contype);
			abort();
		}

		talloc_free(parsed);
	}

	msgb_free(msg);
}

int main(int argc, char **argv)
{
	struct debug_target *stderr_target;

	stderr_target = debug_target_create_stderr();
	debug_add_target(stderr_target);
	debug_set_all_filter(stderr_target, 1);

	test_filter();
	test_contrack();
	test_paging();
	test_mgcp_ass_tracking();
	test_mgcp_find();
	test_mgcp_rewrite();
	test_mgcp_parse();
	test_cr_filter();
	return 0;
}

void input_event()
{}
int nm_state_event()
{
	return -1;
}

int gsm0408_rcvmsg(struct msgb *msg, u_int8_t link_id)
{
	return -1;
}
