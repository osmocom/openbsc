#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>

#include <openbsc/gprs_llc.h>
#include <openbsc/gprs_utils.h>

#define ASSERT_FALSE(x) if (x)  { printf("Should have returned false.\n"); abort(); }
#define ASSERT_TRUE(x)  if (!x) { printf("Should have returned true.\n"); abort(); }

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

/* TODO: Move tlv testing to libosmocore */
static void check_tlv_parse(uint8_t **data, size_t *data_len,
			    uint8_t exp_tag, size_t exp_len, const uint8_t *exp_val)
{
	uint8_t *value;
	size_t value_len;
	uint8_t tag;
	int rc;
	uint8_t *saved_data = *data;
	size_t saved_data_len = *data_len;

	rc = gprs_match_tlv(data, data_len, exp_tag ^ 1, NULL, NULL);
	OSMO_ASSERT(rc == 0);

	rc = gprs_match_tlv(data, data_len, exp_tag, &value, &value_len);
	OSMO_ASSERT(rc == (int)value_len + 2);
	OSMO_ASSERT(value_len == exp_len);
	OSMO_ASSERT(memcmp(value, exp_val, exp_len) == 0);

	/* restore data/data_len */
	*data = saved_data;
	*data_len = saved_data_len;

	rc = gprs_shift_tlv(data, data_len, &tag, &value, &value_len);
	OSMO_ASSERT(rc == (int)value_len + 2);
	OSMO_ASSERT(tag == exp_tag);
	OSMO_ASSERT(value_len == exp_len);
	OSMO_ASSERT(memcmp(value, exp_val, exp_len) == 0);
}

static void check_tv_fixed_match(uint8_t **data, size_t *data_len,
				 uint8_t tag, size_t len, const uint8_t *exp_val)
{
	uint8_t *value;
	int rc;

	rc = gprs_match_tv_fixed(data, data_len, tag ^ 1, len, NULL);
	OSMO_ASSERT(rc == 0);

	rc = gprs_match_tv_fixed(data, data_len, tag, len, &value);
	OSMO_ASSERT(rc == (int)len + 1);
	OSMO_ASSERT(memcmp(value, exp_val, len) == 0);
}

static void check_v_fixed_shift(uint8_t **data, size_t *data_len,
				size_t len, const uint8_t *exp_val)
{
	uint8_t *value;
	int rc;

	rc = gprs_shift_v_fixed(data, data_len, len, &value);
	OSMO_ASSERT(rc == (int)len);
	OSMO_ASSERT(memcmp(value, exp_val, len) == 0);
}

static void check_lv_shift(uint8_t **data, size_t *data_len,
			   size_t exp_len, const uint8_t *exp_val)
{
	uint8_t *value;
	size_t value_len;
	int rc;

	rc = gprs_shift_lv(data, data_len, &value, &value_len);
	OSMO_ASSERT(rc == (int)value_len + 1);
	OSMO_ASSERT(value_len == exp_len);
	OSMO_ASSERT(memcmp(value, exp_val, exp_len) == 0);
}

static void check_tlv_match_data_len(size_t data_len, uint8_t tag, size_t len,
				     const uint8_t *test_data)
{
	uint8_t buf[300] = {0};

	uint8_t *unchanged_ptr = buf - 1;
	size_t unchanged_len = 0xdead;
	size_t tmp_data_len = data_len;
	uint8_t *value = unchanged_ptr;
	size_t value_len = unchanged_len;
	uint8_t *data = buf;

	OSMO_ASSERT(data_len <= sizeof(buf));

	tlv_put(data, tag, len, test_data);
	if (data_len < len + 2) {
		OSMO_ASSERT(-1 == gprs_match_tlv(&data, &tmp_data_len,
					    tag, &value, &value_len));
		OSMO_ASSERT(tmp_data_len == 0);
		OSMO_ASSERT(data == buf + data_len);
		OSMO_ASSERT(value == unchanged_ptr);
		OSMO_ASSERT(value_len == unchanged_len);
	} else {
		OSMO_ASSERT(0 <= gprs_match_tlv(&data, &tmp_data_len,
					   tag, &value, &value_len));
		OSMO_ASSERT(value != unchanged_ptr);
		OSMO_ASSERT(value_len != unchanged_len);
	}
}

static void check_tv_fixed_match_data_len(size_t data_len,
					  uint8_t tag, size_t len,
					  const uint8_t *test_data)
{
	uint8_t buf[300] = {0};

	uint8_t *unchanged_ptr = buf - 1;
	size_t tmp_data_len = data_len;
	uint8_t *value = unchanged_ptr;
	uint8_t *data = buf;

	OSMO_ASSERT(data_len <= sizeof(buf));

	tv_fixed_put(data, tag, len, test_data);

	if (data_len < len + 1) {
		OSMO_ASSERT(-1 == gprs_match_tv_fixed(&data, &tmp_data_len,
						 tag, len, &value));
		OSMO_ASSERT(tmp_data_len == 0);
		OSMO_ASSERT(data == buf + data_len);
		OSMO_ASSERT(value == unchanged_ptr);
	} else {
		OSMO_ASSERT(0 <= gprs_match_tv_fixed(&data, &tmp_data_len,
						tag, len, &value));
		OSMO_ASSERT(value != unchanged_ptr);
	}
}

static void check_v_fixed_shift_data_len(size_t data_len,
					 size_t len, const uint8_t *test_data)
{
	uint8_t buf[300] = {0};

	uint8_t *unchanged_ptr = buf - 1;
	size_t tmp_data_len = data_len;
	uint8_t *value = unchanged_ptr;
	uint8_t *data = buf;

	OSMO_ASSERT(data_len <= sizeof(buf));

	memcpy(data, test_data, len);

	if (data_len < len) {
		OSMO_ASSERT(-1 == gprs_shift_v_fixed(&data, &tmp_data_len,
						len, &value));
		OSMO_ASSERT(tmp_data_len == 0);
		OSMO_ASSERT(data == buf + data_len);
		OSMO_ASSERT(value == unchanged_ptr);
	} else {
		OSMO_ASSERT(0 <= gprs_shift_v_fixed(&data, &tmp_data_len,
					       len, &value));
		OSMO_ASSERT(value != unchanged_ptr);
	}
}

static void check_lv_shift_data_len(size_t data_len,
				    size_t len, const uint8_t *test_data)
{
	uint8_t buf[300] = {0};

	uint8_t *unchanged_ptr = buf - 1;
	size_t unchanged_len = 0xdead;
	size_t tmp_data_len = data_len;
	uint8_t *value = unchanged_ptr;
	size_t value_len = unchanged_len;
	uint8_t *data = buf;

	lv_put(data, len, test_data);
	if (data_len < len + 1) {
		OSMO_ASSERT(-1 == gprs_shift_lv(&data, &tmp_data_len,
					   &value, &value_len));
		OSMO_ASSERT(tmp_data_len == 0);
		OSMO_ASSERT(data == buf + data_len);
		OSMO_ASSERT(value == unchanged_ptr);
		OSMO_ASSERT(value_len == unchanged_len);
	} else {
		OSMO_ASSERT(0 <= gprs_shift_lv(&data, &tmp_data_len,
					  &value, &value_len));
		OSMO_ASSERT(value != unchanged_ptr);
		OSMO_ASSERT(value_len != unchanged_len);
	}
}

static void test_tlv_shift_functions()
{
	uint8_t test_data[1024];
	uint8_t buf[1024];
	uint8_t *data_end;
	unsigned i, len;
	uint8_t *data;
	size_t data_len;
	const uint8_t tag = 0x1a;

	printf("Test shift functions\n");

	for (i = 0; i < ARRAY_SIZE(test_data); i++)
		test_data[i] = (uint8_t)i;

	for (len = 0; len < 256; len++) {
		const unsigned iterations = sizeof(buf) / (len + 2) / 4;

		memset(buf, 0xee, sizeof(buf));
		data_end = data = buf;

		for (i = 0; i < iterations; i++) {
			data_end = tlv_put(data_end, tag, len, test_data);
			data_end = tv_fixed_put(data_end, tag, len, test_data);
			/* v_fixed_put */
			memcpy(data_end, test_data, len);
			data_end += len;
			data_end = lv_put(data_end, len, test_data);
		}

		data_len = data_end - data;
		OSMO_ASSERT(data_len <= sizeof(buf));

		for (i = 0; i < iterations; i++) {
			check_tlv_parse(&data, &data_len, tag, len, test_data);
			check_tv_fixed_match(&data, &data_len, tag, len, test_data);
			check_v_fixed_shift(&data, &data_len, len, test_data);
			check_lv_shift(&data, &data_len, len, test_data);
		}

		OSMO_ASSERT(data == data_end);

		/* Test at end of data */

		OSMO_ASSERT(-1 == gprs_match_tlv(&data, &data_len, tag, NULL, NULL));
		OSMO_ASSERT(-1 == gprs_match_tv_fixed(&data, &data_len, tag, len, NULL));
		OSMO_ASSERT((len ? -1 : 0) == gprs_shift_v_fixed(&data, &data_len, len, NULL));
		OSMO_ASSERT(-1 == gprs_shift_lv(&data, &data_len, NULL, NULL));

		/* Test invalid data_len */
		for (data_len = 0; data_len <= len + 2 + 1; data_len += 1) {
			check_tlv_match_data_len(data_len, tag, len, test_data);
			check_tv_fixed_match_data_len(data_len, tag, len, test_data);
			check_v_fixed_shift_data_len(data_len, len, test_data);
			check_lv_shift_data_len(data_len, len, test_data);
		}
	}
}

int main(int argc, char **argv)
{
	test_8_4_2();
	test_gsm_03_03_apn();
	test_tlv_shift_functions();

	printf("Done.\n");
	return EXIT_SUCCESS;
}
