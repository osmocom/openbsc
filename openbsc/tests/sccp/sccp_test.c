/*
 * SCCP testing code
 *
 * (C) 2009 by Holger Hans Peter Freyther <zecke@selfish.org>
 * (C) 2009 by On-Waves
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

#include <stdio.h>

#include <arpa/inet.h>

#include <openbsc/gsm_data.h>
#include <openbsc/debug.h>
#include <osmocore/msgb.h>

#include <sccp/sccp.h>

#define MIN(x, y) ((x) < (y) ? (x) : (y))

/* BSC -> MSC */
static const u_int8_t bssmap_reset[] = {
	0x09, 0x00, 0x03, 0x05, 0x07, 0x02, 0x42, 0xfe,
	0x02, 0x42, 0xfe, 0x06, 0x00, 0x04, 0x30, 0x04,
	0x01, 0x20,
};

/* MSC -> BSC reset ack */
static const u_int8_t bssmap_reset_ack[] = {
	0x09, 0x00, 0x03, 0x07, 0x0b, 0x04, 0x43, 0x01,
	0x00, 0xfe, 0x04, 0x43, 0x5c, 0x00, 0xfe, 0x03,
	0x00, 0x01, 0x31,
};

/* MSC -> BSC paging, connection less */
static const u_int8_t bssmap_paging[] = {
	0x09, 0x00, 0x03, 0x07, 0x0b, 0x04, 0x43, 0x01,
	0x00, 0xfe, 0x04, 0x43, 0x5c, 0x00, 0xfe, 0x10,
	0x00, 0x0e, 0x52, 0x08, 0x08, 0x29, 0x47, 0x10,
	0x02, 0x01, 0x31, 0x97, 0x61, 0x1a, 0x01, 0x06,
};

/* MSC -> BSC paging, UDT without PC  */
static const u_int8_t bssmap_udt[] = {
	0x09, 0x00, 0x03, 0x05, 0x07, 0x02, 0x42, 0xfe,
	0x02, 0x42, 0xfe, 0x10, 0x00, 0x0e, 0x52, 0x08,
	0x08, 0x29, 0x47, 0x10, 0x02, 0x01, 0x31, 0x97,
	0x61, 0x1a, 0x01, 0x06,
};

/* BSC -> MSC connection open */
static const u_int8_t bssmap_cr[] = {
	0x01, 0x01, 0x02, 0x03, 0x02, 0x02, 0x04, 0x02,
	0x42, 0xfe, 0x0f, 0x1f, 0x00, 0x1d, 0x57, 0x05,
	0x08, 0x00, 0x72, 0xf4, 0x80, 0x20, 0x12, 0xc3,
	0x50, 0x17, 0x10, 0x05, 0x24, 0x11, 0x03, 0x33,
	0x19, 0xa2, 0x08, 0x29, 0x47, 0x10, 0x02, 0x01,
	0x31, 0x97, 0x61, 0x00
};

/* MSC -> BSC connection confirm */
static const u_int8_t bssmap_cc[] = {
	0x02, 0x01, 0x02, 0x03, 0x00, 0x00, 0x03, 0x02, 0x01, 0x00,
};

/* MSC -> BSC DTAP
 *
 * we fake a bit and make it BSC -> MSC... so the
 * payload does not make any sense..
 */
static const u_int8_t bssmap_dtap[] = {
	0x06, 0x00, 0x00, 0x03, 0x00, 0x01, 0x0f, 0x01, 0x00, 0x0c,
	0x03, 0x05, 0x5c, 0x08, 0x11, 0x81, 0x33, 0x66, 0x02, 0x13,
	0x45, 0xf4,
};

/* MSC -> BSC clear command */
static const u_int8_t bssmap_clear[] = {
	0x06, 0x00, 0x00, 0x03, 0x00, 0x01, 0x06, 0x00, 0x04, 0x20,
	0x04, 0x01, 0x09,
};

/* MSC -> BSC released */
static const u_int8_t bssmap_released[] = {
	0x04, 0x00, 0x00, 0x03, 0x01, 0x02, 0x03, 0x00, 0x01, 0x0f,
	0x02, 0x23, 0x42, 0x00,
};

/* BSC -> MSC released */
static const u_int8_t bssmap_release_complete[] = {
	0x05, 0x01, 0x02, 0x03, 0x00, 0x00, 0x03
};

struct test_data {
	int length;
	const u_int8_t *data;
	int payload_start;
	int payload_length;
	u_int8_t first_byte;

        /* in case it should trigger a sccp response */
	int write;
	const u_int8_t  *response;
	int response_length;
};

static const struct test_data test_data[] = {
	{
		.length		= ARRAY_SIZE(bssmap_reset),
		.data		= &bssmap_reset[0],
		.payload_start	= 12,
		.payload_length = ARRAY_SIZE(bssmap_reset) - 12,
		.first_byte	= 0x0,
	},
	{
		.length		= ARRAY_SIZE(bssmap_reset_ack),
		.data		= &bssmap_reset_ack[0],
		.payload_start	= 16,
		.payload_length = ARRAY_SIZE(bssmap_reset_ack) - 16,
		.first_byte	= 0x0,
	},
	{
		.length		= ARRAY_SIZE(bssmap_paging),
		.data		= &bssmap_paging[0],
		.payload_start	= 16,
		.payload_length = ARRAY_SIZE(bssmap_paging) - 16,
		.first_byte	= 0x0,
	},
	{
		.length		= ARRAY_SIZE(bssmap_cr),
		.data		= &bssmap_cr[0],
		.payload_start	= 12,
		/* 0x00 is end of optional data, subtract this byte */
		.payload_length = 31,
		.first_byte	= 0x0,

		/* the connection request should trigger a connection confirm */
		.write		= 1,
		.response	= &bssmap_cc[0],
		.response_length= ARRAY_SIZE(bssmap_cc),
	},
	{
		.length		= ARRAY_SIZE(bssmap_dtap),
		.data		= &bssmap_dtap[0],
		.payload_start	= 7,
		.payload_length = 15,
		.first_byte	= 0x01,
	},
	{
		.length		= ARRAY_SIZE(bssmap_clear),
		.data		= &bssmap_clear[0],
		.payload_start	= 7,
		.payload_length = 6,
		.first_byte	= 0x00,
	},
	{
		.length		= ARRAY_SIZE(bssmap_released),
		.data		= &bssmap_released[0],
		.payload_length = 2,
		.payload_start  = 11,
		.first_byte	= 0x23,

		.write		= 1,
		.response	= &bssmap_release_complete[0],
		.response_length= ARRAY_SIZE(bssmap_release_complete),
	},
};

/* we will send UDTs and verify they look like this */
static const struct test_data send_data[] = {
	{
		.length		= ARRAY_SIZE(bssmap_udt),
		.data		= &bssmap_udt[0],
		.payload_start	= 12,
		.payload_length = ARRAY_SIZE(bssmap_udt) - 12,
		.first_byte	= 0x0,
	},
	{
		.length		= ARRAY_SIZE(bssmap_reset),
		.data		= &bssmap_reset[0],
		.payload_start	= 12,
		.payload_length = ARRAY_SIZE(bssmap_reset) - 12,
		.first_byte	= 0x0,
	},
};

struct connection_test {
	/* should the connection be refused? */
	int refuse;

	int with_data;

	/* on which side to close the connection? */
	int close_side;
	int close_cause;
};

/* sccp connection handling we want to test */
static const struct connection_test connection_tests[] = {
	{
		.refuse	= 1,
	},
	{
		.refuse	= 1,
		.with_data = 1,
	},
	{
		.refuse = 0,
		.close_side = 0,
		.close_cause = 5,
	},
	{
		.refuse = 0,
		.close_side = 0,
		.close_cause = 5,
		.with_data = 1,
	},
	{
		.refuse = 0,
		.close_side = 1,
		.close_cause = 5,
	},
	{
		.refuse = 0,
		.close_side = 1,
		.close_cause = 5,
		.with_data = 1,
	},
};

struct sccp_parse_header_result {
	/* results */
	int msg_type;
	int wanted_len;
	int src_ssn;
	int dst_ssn;

	int has_src_ref, has_dst_ref;
	struct sccp_source_reference src_ref;
	struct sccp_source_reference dst_ref;

	/* the input */
	const u_int8_t *input;
	int input_len;
};

static const u_int8_t it_test[] = {
0x10, 0x01, 0x07, 
0x94, 0x01, 0x04, 0x00, 0x02, 0x00, 0x00, 0x00 };

static const struct sccp_parse_header_result parse_result[] = {
	{
		.msg_type	= SCCP_MSG_TYPE_IT,
		.wanted_len	= 0,
		.src_ssn	= -1,
		.dst_ssn	= -1,
		.has_src_ref	= 1,
		.has_dst_ref	= 1,

		.src_ref	= {
			.octet1 = 0x01,
			.octet2 = 0x04,
			.octet3 = 0x00
		},
		.dst_ref	= {
			.octet1 = 0x01,
			.octet2 = 0x07,
			.octet3 = 0x94,
		},

		.input		= it_test,
		.input_len	= sizeof(it_test),
	},
};


/* testing procedure:
 *	- we will use sccp_write and see what will be set in the
 *	  outgoing callback
 *	- we will call sccp_system_incoming and see which calls
 *	  are made. And then compare it to the ones we expect. We
 *	  want the payload to arrive, or callbacks to be called.
 *	- we will use sccp_connection_socket and sccp_connection_write
 *	  and verify state handling of connections
 */

static int current_test;

/*
 * test state...
 */
static int called  = 0;
static int matched = 0;
static int write_called = 0;

#define FAIL(x, args...) printf("FAILURE in %s:%d: " x, __FILE__, __LINE__, ## args)

/*
 * writing these packets and expecting a result
 */
int sccp_read_cb(struct msgb *data, unsigned len, void *context)
{
	u_int16_t payload_length = test_data[current_test].payload_length;
	const u_int8_t *got, *wanted;
	int i;

	called = 1;

	if (msgb_l3len(data) < len) {
		/* this should never be reached */
		FAIL("Something horrible happened.. invalid packet..\n");
		exit(-1);
	}

	if (len == 0 || len != payload_length) {
		FAIL("length mismatch: got: %d wanted: %d\n", msgb_l3len(data), payload_length);
		return -1;
	}

	if (data->l3h[0] !=  test_data[current_test].first_byte) {
		FAIL("The first bytes of l3 do not match: 0x%x 0x%x\n",
			data->l3h[0], test_data[current_test].first_byte);
		return -1;
	}

	got = &data->l3h[0];
	wanted = test_data[current_test].data + test_data[current_test].payload_start;

	for (i = 0; i < len; ++i) {
		if (got[i] != wanted[i]) {
			FAIL("Failed to compare byte. Got: 0x%x Wanted: 0x%x at %d\n",
			     got[i], wanted[i], i);
			return -1;
		}
	}

	matched = 1;
	return 0;
}

int sccp_write_cb(struct msgb *data, void *ctx)
{
	int i = 0;
	const u_int8_t *got, *wanted;

	if (test_data[current_test].response == NULL) {
		FAIL("Didn't expect write callback\n");
		return -1;
	} else if (test_data[current_test].response_length != msgb_l2len(data)) {
		FAIL("Size does not match. Got: %d Wanted: %d\n",
		     msgb_l2len(data), test_data[current_test].response_length);
	}

	got = &data->l2h[0];
	wanted = test_data[current_test].response;

	for (i = 0; i < msgb_l2len(data); ++i) {
		if (got[i] != wanted[i]) {
			FAIL("Failed to compare byte. Got: 0x%x Wanted: 0x%x at %d\n",
			     got[i], wanted[i], i);
			return -1;
		}
	}

	write_called = 1;
	return 0;
}

void sccp_c_read(struct sccp_connection *connection, struct msgb *msgb, unsigned int len)
{
	sccp_read_cb(msgb, len, connection->data_ctx);
}

void sccp_c_state(struct sccp_connection *connection, int old_state)
{
	if (connection->connection_state >= SCCP_CONNECTION_STATE_RELEASE_COMPLETE)
		sccp_connection_free(connection);
}

int sccp_accept_cb(struct sccp_connection *connection, void *user_data)
{
	called = 1;
	unsigned int ref = 0;
	ref |= connection->destination_local_reference.octet1 << 24;
	ref |= connection->destination_local_reference.octet2 << 16;
	ref |= connection->destination_local_reference.octet3 <<  8;
	ref = ntohl(ref);

	connection->data_cb = sccp_c_read;
	connection->state_cb = sccp_c_state;

	/* accept this */
	return 0;
}

static int sccp_udt_write_cb(struct msgb *data, void *context)
{
	const u_int8_t *got, *wanted;
	int i;

	write_called = 1;

	if (send_data[current_test].length != msgb_l2len(data)) {
		FAIL("Size does not match. Got: %d Wanted: %d\n",
		     msgb_l2len(data), send_data[current_test].length);
		return -1;
	}

	got = &data->l2h[0];
	wanted = send_data[current_test].data;

	for (i = 0; i < msgb_l2len(data); ++i) {
		if (got[i] != wanted[i]) {
			FAIL("Failed to compare byte. Got: 0x%x Wanted: 0x%x at %d\n",
			     got[i], wanted[i], i);
			return -1;
		}
	}

	matched = 1;
	return 0;
}

static void test_sccp_system(void)
{
	sccp_system_init(sccp_write_cb, NULL);
	sccp_set_read(&sccp_ssn_bssap, sccp_read_cb, NULL);
	sccp_connection_set_incoming(&sccp_ssn_bssap, sccp_accept_cb, NULL);

	for (current_test = 0; current_test < ARRAY_SIZE(test_data); ++current_test) {
		unsigned int length = test_data[current_test].length;
		struct msgb *msg = msgb_alloc_headroom(length + 2, 2, __func__);
		msg->l2h = msgb_put(msg, length);
		memcpy(msg->l2h, test_data[current_test].data, length);

		called = matched = write_called = 0;
		printf("Testing packet: %d\n", current_test);
		sccp_system_incoming(msg);

		if (!called || !matched || (test_data[current_test].write != write_called))
			FAIL("current test: %d called: %d matched: %d write: %d\n",
			     current_test, called, matched, write_called);

		msgb_free(msg);
	}
}

/* test sending of udt */
static void test_sccp_send_udt(void)
{
	sccp_system_init(sccp_udt_write_cb, NULL);
	sccp_set_read(NULL, NULL, NULL);
	sccp_connection_set_incoming(NULL, NULL, NULL);

	for (current_test = 0; current_test < ARRAY_SIZE(send_data); ++current_test) {
		const struct test_data *test = &send_data[current_test];

		struct msgb *msg = msgb_alloc(test->payload_length, __func__);
		msg->l3h = msgb_put(msg, test->payload_length);
		memcpy(msg->l3h, test->data + test->payload_start, test->payload_length);

		matched = write_called = 0;
		printf("Testing packet: %d\n", current_test);
		sccp_write(msg, &sccp_ssn_bssap, &sccp_ssn_bssap, 0);

		if (!matched || !write_called)
			FAIL("current test: %d matched: %d write: %d\n",
			     current_test, matched, write_called);

		msgb_free(msg);
	}
}

/* send udt from one end to another */
static unsigned int test_value = 0x2442;
static int sccp_udt_read(struct msgb *data, unsigned int len, void *context)
{
	unsigned int *val;

	if (len != 4) {
		FAIL("Wrong size: %d\n", msgb_l3len(data));
		return -1;
	}

	val = (unsigned int*)data->l3h;
	matched = test_value == *val;

	return 0;
}

static int sccp_write_loop(struct msgb *data, void *context)
{
	/* send it back to us */
	sccp_system_incoming(data);
	return 0;
}

static void test_sccp_udt_communication(void)
{
	struct msgb *data;
	unsigned int *val;

	sccp_system_init(sccp_write_loop, NULL);
	sccp_set_read(&sccp_ssn_bssap, sccp_udt_read, NULL);
	sccp_connection_set_incoming(NULL, NULL, NULL);


	data = msgb_alloc(4, "test data");
	data->l3h = &data->data[0];
	val = (unsigned int *)msgb_put(data, 4);
	*val = test_value;

	matched = 0;
	sccp_write(data, &sccp_ssn_bssap, &sccp_ssn_bssap, 0);

	if (!matched)
	    FAIL("Talking with us didn't work\n");

	msgb_free(data);
}


/* connection testing... open, send, close */
static const struct connection_test *current_con_test;
static struct sccp_connection *outgoing_con;
static struct sccp_connection *incoming_con;
static int outgoing_data, incoming_data, incoming_state, outgoing_state;

static struct msgb *test_data1, *test_data2, *test_data3;

static void sccp_conn_in_state(struct sccp_connection *conn, int old_state)
{
	printf("\tincome: %d -> %d\n", old_state, conn->connection_state);
	if (conn->connection_state >= SCCP_CONNECTION_STATE_RELEASE_COMPLETE) {
		if (conn == incoming_con) {
			sccp_connection_free(conn);
			incoming_con = NULL;
		}
	}
}

static void sccp_conn_in_data(struct sccp_connection *conn, struct msgb *msg, unsigned int len)
{
	/* compare the data */
	++incoming_data;
	printf("\tincoming data: %d\n", len);

	/* compare the data */
	if (len != 4) {
		FAIL("Length of packet is wrong: %u %u\n", msgb_l3len(msg), len);
		return;
	}

	if (incoming_data == 1) {
		if (memcmp(msg->l3h, test_data1->l3h, len) != 0) {
			FAIL("Comparing the data failed: %d\n", incoming_data);
			incoming_state = 0;
			printf("Got:    %s\n", hexdump(msg->l3h, len));
			printf("Wanted: %s\n", hexdump(test_data1->l3h, len));

		}
	} else if (incoming_data == 2) {
		if (memcmp(msg->l3h, test_data2->l3h, len) != 0) {
			FAIL("Comparing the data failed: %d\n", incoming_data);
			incoming_state = 0;
			printf("Got:    %s\n", hexdump(msg->l3h, len));
			printf("Wanted: %s\n", hexdump(test_data2->l3h, len));
		}
	}

	/* sending out data */
	if (incoming_data == 2) {
		printf("\tReturning data3\n");
		sccp_connection_write(conn, test_data3);
	}
}

static int sccp_conn_accept(struct sccp_connection *conn, void *ctx)
{
	printf("\taccept: %p\n", conn);
	conn->state_cb = sccp_conn_in_state;
	conn->data_cb = sccp_conn_in_data;

	if (current_con_test->refuse)
		return -1;

	incoming_con = conn;
	return 0;
}

/* callbacks for the outgoing side */
static void sccp_conn_out_state(struct sccp_connection *conn, int old_state)
{
	printf("\toutgoing: %p %d -> %d\n", conn, old_state, conn->connection_state);

	if (conn->connection_state >= SCCP_CONNECTION_STATE_RELEASE_COMPLETE) {
		if (conn == outgoing_con) {
			sccp_connection_free(conn);
			outgoing_con = NULL;
		}
	}
}

static void sccp_conn_out_data(struct sccp_connection *conn, struct msgb *msg, unsigned int len)
{
	++outgoing_data;
	printf("\toutgoing data: %p %d\n", conn, len);

	if (len != 4)
		FAIL("Length of packet is wrong: %u %u\n", msgb_l3len(msg), len);

	if (outgoing_data == 1) {
		if (memcmp(msg->l3h, test_data3->l3h, len) != 0) {
			FAIL("Comparing the data failed\n");
			outgoing_state = 0;
		}
	}
}

static void do_test_sccp_connection(const struct connection_test *test)
{
	int ret;

	current_con_test = test;
	outgoing_con = incoming_con = 0;

	outgoing_con = sccp_connection_socket();
	if (!outgoing_con) {
		FAIL("Connection is NULL\n");
		return;
	}

	outgoing_con->state_cb = sccp_conn_out_state;
	outgoing_con->data_cb = sccp_conn_out_data;
	outgoing_data = incoming_data = 0;
	incoming_state = outgoing_state = 1;

	/* start testing */
	if (test->with_data) {
		if (sccp_connection_connect(outgoing_con, &sccp_ssn_bssap, test_data1) != 0)
			FAIL("Binding failed\n");
	} else {
		++incoming_data;
		if (sccp_connection_connect(outgoing_con, &sccp_ssn_bssap, NULL) != 0)
			FAIL("Binding failed\n");
	}

	if (test->refuse) {
		if (outgoing_con)
			FAIL("Outgoing connection should have been refused.\n");
	} else {
		if (!incoming_con)
			FAIL("Creating incoming didn't work.\n");

		printf("\tWriting test data2\n");
		sccp_connection_write(outgoing_con, test_data2);
		sccp_connection_send_it(outgoing_con);

		/* closing connection */
		if (test->close_side == 0)
			ret = sccp_connection_close(outgoing_con, 0);
		else
			ret = sccp_connection_close(incoming_con, 0);

		if (ret != 0)
			FAIL("Closing the connection failed\n");
	}

	/* outgoing should be gone now */
	if (outgoing_con)
		FAIL("Outgoing connection was not properly closed\n");

	if (incoming_con)
		FAIL("Incoming connection was not propery closed.\n");

	if (test->refuse == 0) {
		if (outgoing_data != 1 || incoming_data != 2) {
			FAIL("Data sending failed: %d/%d %d/%d\n",
			     outgoing_data, 1,
			     incoming_data, 2);
		}
	}

	if (!incoming_state || !outgoing_state)
		FAIL("Failure with the state transition. %d %d\n",
		     outgoing_state, incoming_state);
}

static void test_sccp_connection(void)
{
	sccp_system_init(sccp_write_loop, NULL);
	sccp_set_read(NULL, NULL, NULL);
	sccp_connection_set_incoming(&sccp_ssn_bssap, sccp_conn_accept, NULL);

	test_data1 = msgb_alloc(4, "data1");
	test_data1->l3h = msgb_put(test_data1, 4);
	*((unsigned int*)test_data1->l3h) = 0x23421122;

	test_data2 = msgb_alloc(4, "data2");
	test_data2->l3h = msgb_put(test_data2, 4);
	*((unsigned int*)test_data2->l3h) = 0x42232211;

	test_data3 = msgb_alloc(4, "data3");
	test_data3->l3h = msgb_put(test_data3, 4);
	*((unsigned int*)test_data3->l3h) = 0x2323ff55;


	for (current_test = 0; current_test < ARRAY_SIZE(connection_tests); ++current_test) {
		printf("Testing %d refuse: %d with_data: %d\n",
			current_test, connection_tests[current_test].refuse,
			connection_tests[current_test].with_data);
		do_test_sccp_connection(&connection_tests[current_test]);
	}

	msgb_free(test_data1);
	msgb_free(test_data2);
	msgb_free(test_data3);
}

/* invalid input */
static void test_sccp_system_crash(void)
{
	printf("trying to provoke a crash with invalid input\n");
	sccp_set_read(&sccp_ssn_bssap, sccp_read_cb, NULL);
	sccp_connection_set_incoming(&sccp_ssn_bssap, sccp_accept_cb, NULL);

	for (current_test = 0; current_test < ARRAY_SIZE(test_data); ++current_test) {
		int original_length = test_data[current_test].length;
		int length = original_length + 2;
		int i;

		printf("Testing packet: %d\n", current_test);

		for (i = length; i >= 0; --i) {
			unsigned int length = MIN(test_data[current_test].length, i);
			struct msgb *msg = msgb_alloc_headroom(length + 2, 2, __func__);
			msg->l2h = msgb_put(msg, length);
			memcpy(msg->l2h, test_data[current_test].data, length);
			sccp_system_incoming(msg);
			msgb_free(msg);
		}
	}

	printf("survived\n");
}

static void test_sccp_parsing(void)
{
	for (current_test = 0; current_test < ARRAY_SIZE(parse_result); ++current_test) {
		struct msgb *msg;
		struct sccp_parse_result result;

		msg = msgb_alloc_headroom(1024, 128, "parse-test");
		msgb_put(msg, 1);
		msg->l2h = msgb_put(msg, parse_result[current_test].input_len);
		memcpy(msg->l2h, parse_result[current_test].input, msgb_l2len(msg));

		memset(&result, 0, sizeof(result));
		if (sccp_parse_header(msg, &result) != 0) {
			fprintf(stderr, "Failed to parse test: %d\n", current_test);
		} else {
			if (parse_result[current_test].wanted_len != result.data_len) {
				fprintf(stderr, "Unexpected data length.\n");
				abort();
			}

			if (parse_result[current_test].has_src_ref) {
				if (memcmp(result.source_local_reference,
					   &parse_result[current_test].src_ref,
					   sizeof(struct sccp_source_reference)) != 0) {
					fprintf(stderr, "SRC REF did not match\n");
					abort();
				}
			}

			if (parse_result[current_test].has_dst_ref) {
				if (memcmp(result.destination_local_reference,
					   &parse_result[current_test].dst_ref,
					   sizeof(struct sccp_source_reference)) != 0) {
					fprintf(stderr, "DST REF did not match\n");
					abort();
				}
			}

			if (parse_result[current_test].src_ssn != -1) {
				fprintf(stderr, "Not implemented.\n");
				abort();
			}

			if (parse_result[current_test].dst_ssn != -1) {
				fprintf(stderr, "Not implemented.\n");
				abort();
			}
		}

		msgb_free(msg);
	}
}


int main(int argc, char **argv)
{
	test_sccp_system();
	test_sccp_send_udt();
	test_sccp_udt_communication();
	test_sccp_connection();
	test_sccp_system_crash();
	test_sccp_parsing();
	return 0;
}

void db_store_counter() {}
