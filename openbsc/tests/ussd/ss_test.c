/* simple test for the gsm0480  */
/*
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
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>

#include <arpa/inet.h>


#include <openbsc/gsm_ussd_map.h>
#include <openbsc/gsm_ussd_map_proto.h>
#include <openbsc/gsm_04_80.h>
#include <openbsc/gsm_subscriber.h>
#include <openbsc/debug.h>
#include <osmocom/core/application.h>

#define COMPARE(result, op, value) \
    if (!((result) op (value))) {\
	fprintf(stderr, "Compare failed. Was %x should be %x in %s:%d\n",result, value, __FILE__, __LINE__); \
	exit(-1); \
    }

#define COMPARE_STR(result, value) \
	if (strcmp(result, value) != 0) { \
		fprintf(stderr, "Compare failed. Was %s should be %s in %s:%d\n",result, value, __FILE__, __LINE__); \
		exit(-1); \
	}

#define DBG(...)

#define VERIFY(res, cmp, wanted)					\
	if (!(res cmp wanted)) {					\
		printf("ASSERT failed: %s:%d Wanted: %d %s %d\n",	\
			__FILE__, __LINE__, res, # cmp, wanted);	\
	}

const uint8_t test_ss_int_01[] = {
0xa1, 0x0e, 0x02, 0x01, 0x00, 0x02, 0x01, 0x0e, 0x30, 0x06, 0x04, 0x01, 0x21, 0x83, 0x01, 0x10
};

const uint8_t test_ss_int_02[] = {
0xa1, 0x0b, 0x02, 0x01, 0x01, 0x02, 0x01, 0x0e, 0x30, 0x03, 0x04, 0x01, 0x21
};

const uint8_t test_ss_int_03[] = {
0xa1, 0x17, 0x02, 0x01, 0x01, 0x02, 0x01, 0x0a, 0x30, 0x0f, 0x04, 0x01, 0x21,
0x83, 0x01, 0x10, 0x84, 0x07, 0x91, 0x52, 0x75, 0x89, 0x46, 0x36, 0x25
};

const uint8_t test_ussd_01[] = {
0xa1, 0x81, 0x83, 0x02, 0x01, 0x01, 0x02, 0x01, 0x3c, 0x30, 0x7b, 0x04, 0x01,
0x0f, 0x04, 0x76, 0xd3, 0x66, 0x50, 0x4a, 0x55, 0xc4, 0x5c, 0x20, 0x6b, 0xda,
0x5c, 0x97, 0xd7, 0xe7, 0xe8, 0x34, 0xc8, 0x9e, 0x0f, 0x83, 0x68, 0x47, 0x50,
0xd2, 0x4d, 0x0f, 0xbb, 0xcb, 0xf4, 0xb4, 0x42, 0xe6, 0x02, 0x59, 0xd3, 0xe6,
0xba, 0xbc, 0x3e, 0x47, 0xa7, 0x41, 0xd6, 0x7c, 0x18, 0x34, 0x6d, 0x06, 0xa9,
0xc9, 0x65, 0x50, 0x31, 0x73, 0x81, 0xac, 0x69, 0x73, 0x5d, 0x5e, 0x9f, 0xa3,
0xd3, 0x20, 0x7b, 0x3e, 0x0c, 0x5a, 0xa7, 0xdb, 0x61, 0x7a, 0x38, 0x6d, 0x0e,
0xbb, 0x14, 0x34, 0x17, 0x68, 0xda, 0x0e, 0xcb, 0xe9, 0xa0, 0x6b, 0xb9, 0xbc,
0x2e, 0xbb, 0xc9, 0x8a, 0x9a, 0x0b, 0xd4, 0x4c, 0xb7, 0xd3, 0x20, 0x77, 0x18,
0x74, 0x2d, 0xdf, 0xcb, 0x20, 0x28, 0xbb, 0x3e, 0x57, 0xd8, 0x5c, 0x20, 0x7d,
0x38, 0x4d, 0x4e, 0x03
};

const uint8_t test_ussd_02[] = {
0xa2, 0x10, 0x02, 0x01, 0x01, 0x30, 0x0b, 0x02, 0x01, 0x3c, 0x30,
0x06, 0x04, 0x01, 0x0f, 0x04, 0x01, 0x34
};

static void test_uss_ser_deser(void)
{
	const uint32_t ref = 1234567890;
	const char* ext = "555333444";
	struct msgb *data = msgb_alloc(4000, "test");
	struct ss_header ssh;

	uint32_t r_ref;
	struct ss_header r_ssh;
	char r_ext_buf[32];

	int rc;
	printf("testing serializing-deserializing\n");

	ssh.component_length = sizeof(test_ussd_01);
	ssh.component_offset = 0;
	ssh.message_type = GSM0480_MTYPE_REGISTER;
	ssh.transaction_id = 0;

	rc = subscr_uss_message(data, &ssh, ext, ref, test_ussd_01);
	OSMO_ASSERT(rc == 0);

	printf("uss len:%d\n", msgb_length(data));

	rc = rx_uss_message_parse(data->data, msgb_length(data), &r_ssh, &r_ref, r_ext_buf, sizeof(r_ext_buf));
	OSMO_ASSERT(rc == 0);
	OSMO_ASSERT(ref == r_ref);
	OSMO_ASSERT(ssh.message_type == r_ssh.message_type);

	rc = strcmp(ext, r_ext_buf);
	printf("orig_ext:%s decoded_ext:%s\n", ext, r_ext_buf);
	OSMO_ASSERT(rc == 0);

	printf("orig_clen:%d decoded_clen:%d\n", ssh.component_length, r_ssh.component_length);
	OSMO_ASSERT(ssh.component_length == r_ssh.component_length);

	rc = memcmp(data->data + r_ssh.component_offset, test_ussd_01, sizeof(test_ussd_01));
	OSMO_ASSERT(rc == 0);


	msgb_reset(data);
	memset(&r_ssh, 0, sizeof(r_ssh));
	printf("testing serializing-deserializing small\n");

	rc = subscr_uss_message(data, &ssh, NULL, ref, NULL);
	OSMO_ASSERT(rc == 0);

	printf("uss len:%d\n", msgb_length(data));

	rc = rx_uss_message_parse(data->data, msgb_length(data), &r_ssh, &r_ref, NULL, 0);
	OSMO_ASSERT(rc == 0);
	OSMO_ASSERT(ref == r_ref);
	OSMO_ASSERT(ssh.message_type == r_ssh.message_type);

}

static void test_parse_ss(void)
{
	struct ss_request ss;
	int rc;
	printf("testing parsing ss\n");

	// mark as uninitialized
	memset(&ss, 0xcc, sizeof(ss));
	rc = gsm0480_parse_ss_facility(test_ussd_01, sizeof(test_ussd_01), &ss);
	OSMO_ASSERT(rc == 1);
	printf("Sample: test_ussd_01  ctype=%02x invoke_id=%02x opcode=%02x\n",
	       ss.component_type, ss.invoke_id, ss.opcode);
	printf("- USSD: len:%d lang:%d\n", ss.ussd_text_len, ss.ussd_text_language);

	// mark as uninitialized
	memset(&ss, 0xcc, sizeof(ss));
	rc = gsm0480_parse_ss_facility(test_ussd_02, sizeof(test_ussd_02), &ss);
	OSMO_ASSERT(rc == 1);
	printf("Sample: test_ussd_02  ctype=%02x invoke_id=%02x opcode=%02x\n",
	       ss.component_type, ss.invoke_id, ss.opcode);

	// mark as uninitialized
	memset(&ss, 0xcc, sizeof(ss));
	rc = gsm0480_parse_ss_facility(test_ss_int_02, sizeof(test_ss_int_02), &ss);
	OSMO_ASSERT(rc == 1);
	printf("Sample: test_ss_int_02 ctype=%02x invoke_id=%02x opcode=%02x\n",
	       ss.component_type, ss.invoke_id, ss.opcode);
	printf("- SS: code:%d\n", ss.ss_code);

	// mark as uninitialized
	memset(&ss, 0xcc, sizeof(ss));
	rc = gsm0480_parse_ss_facility(test_ss_int_01, sizeof(test_ss_int_01), &ss);
	OSMO_ASSERT(rc == 1);
	printf("Sample: test_ss_int_01 ctype=%02x invoke_id=%02x opcode=%02x\n",
	       ss.component_type, ss.invoke_id, ss.opcode);
	printf("- SS: code:%d\n", ss.ss_code);

	// mark as uninitialized
	memset(&ss, 0xcc, sizeof(ss));
	rc = gsm0480_parse_ss_facility(test_ss_int_03, sizeof(test_ss_int_03), &ss);
	OSMO_ASSERT(rc == 1);
	printf("Sample: test_ss_int_01 ctype=%02x invoke_id=%02x opcode=%02x\n",
	       ss.component_type, ss.invoke_id, ss.opcode);
	printf("- SS: code:%d\n", ss.ss_code);

}

int main(int argc, char **argv)
{
	osmo_init_logging(&log_info);
	log_set_log_level(osmo_stderr_target, LOGL_INFO);

	test_uss_ser_deser();
	test_parse_ss();

	printf("Done.\n");
	return EXIT_SUCCESS;
}
