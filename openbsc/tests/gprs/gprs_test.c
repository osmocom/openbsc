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

int main(int argc, char **argv)
{
	test_8_4_2();
	test_gsm_03_03_apn();

	printf("Done.\n");
	return EXIT_SUCCESS;
}
