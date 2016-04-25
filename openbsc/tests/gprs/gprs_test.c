#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>

#include <openbsc/gprs_llc.h>
#include <openbsc/gprs_utils.h>

#include <openbsc/gprs_gsup_messages.h>

#include <openbsc/debug.h>

#include <osmocom/core/application.h>

#define ASSERT_FALSE(x) if (x)  { printf("Should have returned false.\n"); abort(); }
#define ASSERT_TRUE(x)  if (!x) { printf("Should have returned true.\n"); abort(); }

#define VERBOSE_FPRINTF(...)

/**
 * GSM 04.64 8.4.2 Receipt of unacknowledged information
 */
static int nu_is_retransmission(uint16_t nu, uint16_t vur)
{
	int ret = gprs_llc_is_retransmit(nu, vur);
	printf("N(U) = %d, V(UR) = %d => %s\n", nu, vur,
	       ret == 1 ? "retransmit" : "new");
	return ret;
}

static void test_8_4_2()
{
	printf("Testing gprs_llc_is_retransmit.\n");

	ASSERT_FALSE(nu_is_retransmission(0, 0));
	ASSERT_TRUE (nu_is_retransmission(0, 1));

	/* expect 1... check for retransmissions */
	ASSERT_TRUE (nu_is_retransmission(0, 1));
	ASSERT_TRUE (nu_is_retransmission(511, 1));
	ASSERT_TRUE (nu_is_retransmission(483, 1));
	ASSERT_TRUE (nu_is_retransmission(482, 1));
	ASSERT_FALSE(nu_is_retransmission(481, 1));

	/* expect 511... check for retransmissions */
	ASSERT_FALSE(nu_is_retransmission(0, 240)); // ahead
	ASSERT_FALSE(nu_is_retransmission(0, 511)); // ahead
	ASSERT_FALSE(nu_is_retransmission(1, 511)); // ahead
	ASSERT_FALSE(nu_is_retransmission(511, 511)); // same
	ASSERT_TRUE (nu_is_retransmission(510, 511)); // behind
	ASSERT_TRUE (nu_is_retransmission(481, 511)); // behind
	ASSERT_FALSE(nu_is_retransmission(479, 511)); // wrapped
}

static void apn_round_trip(const uint8_t *input, size_t len, const char *wanted_output)
{
	char output[len ? len : 1];
	uint8_t encoded[len + 50];
	char *out_str;
	int enc_len;

	/* decode and verify we have what we want */
	out_str = gprs_apn_to_str(output, input, len);
	OSMO_ASSERT(out_str);
	OSMO_ASSERT(out_str == &output[0]);
	OSMO_ASSERT(strlen(out_str) == strlen(wanted_output));
	OSMO_ASSERT(strcmp(out_str, wanted_output) == 0);

	/* encode and verify it */
	if (len != 0) {
		enc_len = gprs_str_to_apn(encoded, ARRAY_SIZE(encoded), wanted_output);
		OSMO_ASSERT(enc_len == len);
		OSMO_ASSERT(memcmp(encoded, input, enc_len) == 0);
	} else {
		enc_len = gprs_str_to_apn(encoded, 0, wanted_output);
		OSMO_ASSERT(enc_len == -1);
	}
}

static void test_gsm_03_03_apn(void)
{

	{
		/* test invalid writes */
		const uint8_t ref[10] = { 0xAB, 0xAC, 0xAD, 0xAE, 0xAF, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF };
		uint8_t output[10];
		int enc_len;

		memcpy(output, ref, ARRAY_SIZE(output));
		enc_len = gprs_str_to_apn(output, 0, "");
		OSMO_ASSERT(enc_len == -1);
		OSMO_ASSERT(memcmp(ref, output, ARRAY_SIZE(ref)) == 0);

		memcpy(output, ref, ARRAY_SIZE(output));
		enc_len = gprs_str_to_apn(output, 0, "foo");
		OSMO_ASSERT(enc_len == -1);
		OSMO_ASSERT(memcmp(ref, output, ARRAY_SIZE(ref)) == 0);

		memcpy(output, ref, ARRAY_SIZE(output));
		enc_len = gprs_str_to_apn(output, 1, "foo");
		OSMO_ASSERT(enc_len == -1);
		OSMO_ASSERT(memcmp(ref + 1, output + 1, ARRAY_SIZE(ref) - 1) == 0);

		memcpy(output, ref, ARRAY_SIZE(output));
		enc_len = gprs_str_to_apn(output, 2, "foo");
		OSMO_ASSERT(enc_len == -1);
		OSMO_ASSERT(memcmp(ref + 2, output + 2, ARRAY_SIZE(ref) - 2) == 0);

		memcpy(output, ref, ARRAY_SIZE(output));
		enc_len = gprs_str_to_apn(output, 3, "foo");
		OSMO_ASSERT(enc_len == -1);
		OSMO_ASSERT(memcmp(ref + 3, output + 3, ARRAY_SIZE(ref) - 3) == 0);
	}

	{
		/* single empty label */
		uint8_t input[] = { 0x0 };
		const char *output = "";
		apn_round_trip(input, ARRAY_SIZE(input), output);
	}

	{
		/* no label */
		uint8_t input[] = { };
		const char *output = "";
		apn_round_trip(input, ARRAY_SIZE(input), output);
	}

	{
		/* single label with A */
		uint8_t input[] = { 0x1, 65 };
		const char *output = "A";
		apn_round_trip(input, ARRAY_SIZE(input), output);
		OSMO_ASSERT(gprs_apn_to_str(NULL, input, ARRAY_SIZE(input) - 1) == NULL);
	}

	{
		uint8_t input[] = { 0x3, 65, 66, 67, 0x2, 90, 122 };
		const char *output = "ABC.Zz";
		char tmp[strlen(output) + 1];
		apn_round_trip(input, ARRAY_SIZE(input), output);
		OSMO_ASSERT(gprs_apn_to_str(tmp, input, ARRAY_SIZE(input) - 1) == NULL);
		OSMO_ASSERT(gprs_apn_to_str(tmp, input, ARRAY_SIZE(input) - 2) == NULL);
		OSMO_ASSERT(gprs_apn_to_str(tmp, input, ARRAY_SIZE(input) - 4) == NULL);
		OSMO_ASSERT(gprs_apn_to_str(tmp, input, ARRAY_SIZE(input) - 5) == NULL);
		OSMO_ASSERT(gprs_apn_to_str(tmp, input, ARRAY_SIZE(input) - 6) == NULL);
	}
}

/* Tests for osmo_gsup_messages.c */

#define TEST_IMSI_IE 0x01, 0x08, 0x21, 0x43, 0x65, 0x87, 0x09, 0x21, 0x43, 0xf5
#define TEST_IMSI_STR "123456789012345"

static void test_gsup_messages_dec_enc(void)
{
	int test_idx;
	int rc;
	uint8_t buf[1024];

	static const uint8_t send_auth_info_req[] = {
		0x08,
		TEST_IMSI_IE
	};

	static const uint8_t send_auth_info_err[] = {
		0x09,
		TEST_IMSI_IE,
		0x02, 0x01, 0x07 /* GPRS no allowed */
	};

	static const uint8_t send_auth_info_res[] = {
		0x0a,
		TEST_IMSI_IE,
		0x03, 0x22, /* Auth tuple */
			0x20, 0x10,
				0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
				0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
			0x21, 0x04,
				0x21, 0x22, 0x23, 0x24,
			0x22, 0x08,
				0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
		0x03, 0x22, /* Auth tuple */
			0x20, 0x10,
				0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88,
				0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f, 0x90,
			0x21, 0x04,
				0xa1, 0xa2, 0xa3, 0xa4,
			0x22, 0x08,
				0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8,
	};

	static const uint8_t update_location_req[] = {
		0x04,
		TEST_IMSI_IE,
	};

	static const uint8_t update_location_err[] = {
		0x05,
		TEST_IMSI_IE,
		0x02, 0x01, 0x07 /* GPRS no allowed */
	};

	static const uint8_t update_location_res[] = {
		0x06,
		TEST_IMSI_IE,
		0x08, 0x07, /* MSISDN of the subscriber */
			0x91, 0x94, 0x61, 0x46, 0x32, 0x24, 0x43,
		0x09, 0x07, /* HLR-Number of the subscriber */
			0x91, 0x83, 0x52, 0x38, 0x48, 0x83, 0x93,
		0x04, 0x00, /* PDP info complete */
		0x05, 0x15,
			0x10, 0x01, 0x01,
			0x11, 0x02, 0xf1, 0x21, /* IPv4 */
			0x12, 0x09, 0x04, 't', 'e', 's', 't', 0x03, 'a', 'p', 'n',
			0x13, 0x01, 0x02,
		0x05, 0x11,
			0x10, 0x01, 0x02,
			0x11, 0x02, 0xf1, 0x21, /* IPv4 */
			0x12, 0x08, 0x03, 'f', 'o', 'o', 0x03, 'a', 'p', 'n',
	};

	static const uint8_t location_cancellation_req[] = {
		0x1c,
		TEST_IMSI_IE,
		0x06, 0x01, 0x00,
	};

	static const uint8_t location_cancellation_err[] = {
		0x1d,
		TEST_IMSI_IE,
		0x02, 0x01, 0x03 /* Illegal MS */
	};

	static const uint8_t location_cancellation_res[] = {
		0x1e,
		TEST_IMSI_IE,
	};

	static const uint8_t purge_ms_req[] = {
		0x0c,
		TEST_IMSI_IE,
	};

	static const uint8_t purge_ms_err[] = {
		0x0d,
		TEST_IMSI_IE,
		0x02, 0x01, 0x03, /* Illegal MS */
	};

	static const uint8_t purge_ms_res[] = {
		0x0e,
		TEST_IMSI_IE,
		0x07, 0x00,
	};

	static const struct test {
		char *name;
		const uint8_t *data;
		size_t data_len;
	} test_messages[] = {
		{"Send Authentication Info Request",
			send_auth_info_req, sizeof(send_auth_info_req)},
		{"Send Authentication Info Error",
			send_auth_info_err, sizeof(send_auth_info_err)},
		{"Send Authentication Info Result",
			send_auth_info_res, sizeof(send_auth_info_res)},
		{"Update Location Request",
			update_location_req, sizeof(update_location_req)},
		{"Update Location Error",
			update_location_err, sizeof(update_location_err)},
		{"Update Location Result",
			update_location_res, sizeof(update_location_res)},
		{"Location Cancellation Request",
			location_cancellation_req, sizeof(location_cancellation_req)},
		{"Location Cancellation Error",
			location_cancellation_err, sizeof(location_cancellation_err)},
		{"Location Cancellation Result",
			location_cancellation_res, sizeof(location_cancellation_res)},
		{"Purge MS Request",
			purge_ms_req, sizeof(purge_ms_req)},
		{"Purge MS Error",
			purge_ms_err, sizeof(purge_ms_err)},
		{"Purge MS Result",
			purge_ms_res, sizeof(purge_ms_res)},
	};

	printf("Test GSUP message decoding/encoding\n");

	for (test_idx = 0; test_idx < ARRAY_SIZE(test_messages); test_idx++) {
		const struct test *t = &test_messages[test_idx];
		struct gprs_gsup_message gm = {0};
		struct msgb *msg = msgb_alloc(4096, "gsup_test");

		printf("  Testing %s\n", t->name);

		rc = gprs_gsup_decode(t->data, t->data_len, &gm);
		OSMO_ASSERT(rc >= 0);

		gprs_gsup_encode(msg, &gm);

		fprintf(stderr, "  generated message: %s\n", msgb_hexdump(msg));
		fprintf(stderr, "  original message:  %s\n", osmo_hexdump(t->data, t->data_len));
		fprintf(stderr, "  IMSI:              %s\n", gm.imsi);
		OSMO_ASSERT(strcmp(gm.imsi, TEST_IMSI_STR) == 0);
		OSMO_ASSERT(msgb_length(msg) == t->data_len);
		OSMO_ASSERT(memcmp(msgb_data(msg), t->data, t->data_len) == 0);

		msgb_free(msg);
	}

	/* simple truncation test */
	for (test_idx = 0; test_idx < ARRAY_SIZE(test_messages); test_idx++) {
		int j;
		const struct test *t = &test_messages[test_idx];
		int ie_end = t->data_len;
		struct gprs_gsup_message gm = {0};
		int counter = 0;
		int parse_err = 0;

		for (j = t->data_len - 1; j >= 0; --j) {
			rc = gprs_gsup_decode(t->data, j, &gm);
			counter += 1;

			VERBOSE_FPRINTF(stderr,
				"  partial message decoding: "
				"orig_len = %d, trunc = %d, rc = %d, ie_end = %d\n",
				t->data_len, j, rc, ie_end);
			if (rc >= 0) {
				VERBOSE_FPRINTF(stderr,
					"    remaing partial message: %s\n",
					osmo_hexdump(t->data + j, ie_end - j));

				OSMO_ASSERT(j <= ie_end - 2);
				OSMO_ASSERT(t->data[j+0] <= GPRS_GSUP_KC_IE);
				OSMO_ASSERT(t->data[j+1] <= ie_end - j - 2);

				ie_end = j;
			} else {
				parse_err += 1;
			}
		}

		fprintf(stderr,
			"  message %d: tested %d truncations, %d parse failures\n",
			test_idx, counter, parse_err);
	}

	/* message modification test (relies on ASAN or valgrind being used) */
	for (test_idx = 0; test_idx < ARRAY_SIZE(test_messages); test_idx++) {
		int j;
		const struct test *t = &test_messages[test_idx];
		struct gprs_gsup_message gm = {0};
		uint8_t val;
		int counter = 0;
		int parse_err = 0;

		OSMO_ASSERT(sizeof(buf) >= t->data_len);

		for (j = t->data_len - 1; j >= 0; --j) {
			memcpy(buf, t->data, t->data_len);
			val = 0;
			do {
				VERBOSE_FPRINTF(stderr,
					"t = %d, len = %d, val = %d\n",
					test_idx, j, val);
				buf[j] = val;
				rc = gprs_gsup_decode(buf, t->data_len, &gm);
				counter += 1;
				if (rc < 0)
					parse_err += 1;

				val += 1;
			} while (val != (uint8_t)256);
		}

		fprintf(stderr,
			"  message %d: tested %d modifications, %d parse failures\n",
			test_idx, counter, parse_err);
	}
}

static void test_gprs_timer_enc_dec(void)
{
	int i, u, secs, tmr;
	const int upper_secs_test_limit = 12000;
	int dec_secs, last_dec_secs = -1;

	printf("Test GPRS timer decoding/encoding\n");

	/* Check gprs_tmr_to_secs with all 256 encoded values */
	for (u = 0; u <= GPRS_TMR_DEACTIVATED; u += 32) {
		fprintf(stderr, "Testing decoding with timer value unit %u\n",
			u / 32);
		for (i = 0; i < 32; i++) {
			switch (u) {
			case GPRS_TMR_2SECONDS:
				OSMO_ASSERT(gprs_tmr_to_secs(u + i) == 2 * i);
				break;

			default:
			case GPRS_TMR_MINUTE:
				OSMO_ASSERT(gprs_tmr_to_secs(u + i) == 60 * i);
				break;

			case GPRS_TMR_6MINUTE:
				OSMO_ASSERT(gprs_tmr_to_secs(u + i) == 360 * i);
				break;

			case GPRS_TMR_DEACTIVATED:
				OSMO_ASSERT(gprs_tmr_to_secs(u + i) == -1);
				break;
			}

			OSMO_ASSERT(gprs_tmr_to_secs(u + i) < upper_secs_test_limit);
		}
	}

	/* Check gprs_secs_to_tmr_floor for secs that can exactly be
	 * represented as GPRS timer values */
	for (i = 0; i < GPRS_TMR_DEACTIVATED; i++) {
		int j;
		secs = gprs_tmr_to_secs(i);
		tmr = gprs_secs_to_tmr_floor(secs);
		OSMO_ASSERT(secs == gprs_tmr_to_secs(tmr));

		/* Check that the highest resolution is used */
		for (j = 0; j < tmr; j++)
			OSMO_ASSERT(secs != gprs_tmr_to_secs(j));
	}
	OSMO_ASSERT(GPRS_TMR_DEACTIVATED == gprs_secs_to_tmr_floor(-1));

	/* Check properties of gprs_secs_to_tmr_floor */
	for (secs = 0; secs <= upper_secs_test_limit; secs++) {
		int tmr = gprs_secs_to_tmr_floor(secs);
		int delta_secs = gprs_tmr_to_secs((tmr & ~0x1f) | 1);
		dec_secs = gprs_tmr_to_secs(tmr);

		/* Check floor */
		OSMO_ASSERT(dec_secs <= secs);
		/* Check monotonicity */
		OSMO_ASSERT(dec_secs >= last_dec_secs);
		/* Check max distance (<= resolution) */
		OSMO_ASSERT(dec_secs - last_dec_secs <= delta_secs);

		last_dec_secs = dec_secs;
	}
}

const struct log_info_cat default_categories[] = {
	[DGPRS] = {
		.name = "DGPRS",
		.description = "GPRS Packet Service",
		.enabled = 0, .loglevel = LOGL_DEBUG,
	},
};

static struct log_info info = {
	.cat = default_categories,
	.num_cat = ARRAY_SIZE(default_categories),
};

int main(int argc, char **argv)
{
	osmo_init_logging(&info);

	test_8_4_2();
	test_gsm_03_03_apn();
	test_gsup_messages_dec_enc();
	test_gprs_timer_enc_dec();

	printf("Done.\n");
	return EXIT_SUCCESS;
}
