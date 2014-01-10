/* simple test for the gsm0408 formatting functions */
/*
 * (C) 2008 by Holger Hans Peter Freyther <zecke@selfish.org>
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

#include <openbsc/gsm_04_08.h>
#include <openbsc/gsm_subscriber.h>
#include <openbsc/debug.h>
#include <openbsc/arfcn_range_encode.h>
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

/*
 * Test Location Area Identifier formatting. Table 10.5.3 of 04.08
 */
static void test_location_area_identifier(void)
{
    struct gsm48_loc_area_id lai48;

    printf("Testing test location area identifier\n");

    /*
     * Test the default/test setup. Coming from
     * bsc_hack.c dumps
     */
    gsm48_generate_lai(&lai48, 1, 1, 1);
    COMPARE(lai48.digits[0], ==, 0x00);
    COMPARE(lai48.digits[1], ==, 0xF1);
    COMPARE(lai48.digits[2], ==, 0x10);
    COMPARE(lai48.lac, ==, htons(0x0001));

    gsm48_generate_lai(&lai48, 602, 1, 15);
    COMPARE(lai48.digits[0], ==, 0x06);
    COMPARE(lai48.digits[1], ==, 0xF2);
    COMPARE(lai48.digits[2], ==, 0x10);
    COMPARE(lai48.lac, ==, htons(0x000f));
}

static void test_mi_functionality(void)
{
	const char *imsi_odd  = "987654321098763";
	const char *imsi_even = "9876543210987654";
	const uint32_t tmsi = 0xfabeacd0;
	uint8_t mi[128];
	unsigned int mi_len;
	char mi_parsed[GSM48_MI_SIZE];

	printf("Testing parsing and generating TMSI/IMSI\n");

	/* tmsi code */
	mi_len = gsm48_generate_mid_from_tmsi(mi, tmsi);
	gsm48_mi_to_string(mi_parsed, sizeof(mi_parsed), mi + 2, mi_len - 2);
	COMPARE((uint32_t)strtoul(mi_parsed, NULL, 10), ==, tmsi);

	/* imsi code */
	mi_len = gsm48_generate_mid_from_imsi(mi, imsi_odd);
	gsm48_mi_to_string(mi_parsed, sizeof(mi_parsed), mi + 2, mi_len -2);
	printf("hex: %s\n", osmo_hexdump(mi, mi_len));
	COMPARE_STR(mi_parsed, imsi_odd);

	mi_len = gsm48_generate_mid_from_imsi(mi, imsi_even);
	gsm48_mi_to_string(mi_parsed, sizeof(mi_parsed), mi + 2, mi_len -2);
	printf("hex: %s\n", osmo_hexdump(mi, mi_len));
	COMPARE_STR(mi_parsed, imsi_even);
}

struct {
	int range;
	int arfcns_num;
	int arfcns[RANGE_ENC_MAX_ARFCNS];
} arfcn_test_ranges[] = {
	{ARFCN_RANGE_512, 12,
		{ 1, 12, 31, 51, 57, 91, 97, 98, 113, 117, 120, 125 }},
	{ARFCN_RANGE_512, 17,
		{ 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17 }},
	{ARFCN_RANGE_512, 18,
		{ 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18 }},
	{ARFCN_RANGE_512, 18,
		{ 1, 17, 31, 45, 58, 79, 81, 97,
		  113, 127, 213, 277, 287, 311, 331, 391,
		  417, 511 }},
	{ARFCN_RANGE_512, 6,
		{ 1, 17, 31, 45, 58, 79 }},
	{ARFCN_RANGE_512, 6,
		{ 10, 17, 31, 45, 58, 79 }},
	{ARFCN_RANGE_1024, 17,
		{ 0, 17, 31, 45, 58, 79, 81, 97,
		  113, 127, 213, 277, 287, 311, 331, 391,
		  1023 }},
	{ARFCN_RANGE_1024, 16,
		{ 17, 31, 45, 58, 79, 81, 97, 113,
		  127, 213, 277, 287, 311, 331, 391, 1023 }},
	{-1}
};

static int test_single_range_encoding(int range, const int *orig_arfcns,
				       int arfcns_num, int silent)
{
	int arfcns[RANGE_ENC_MAX_ARFCNS];
	int w[RANGE_ENC_MAX_ARFCNS];
	int f0_included = 0;
	int rc, f0;
	uint8_t chan_list[16] = {0};
	struct gsm_sysinfo_freq dec_freq[1024] = {{0}};
	int dec_arfcns[RANGE_ENC_MAX_ARFCNS] = {0};
	int dec_arfcns_count = 0;
	int arfcns_used = 0;
	int i;

	arfcns_used = arfcns_num;
	memmove(arfcns, orig_arfcns, sizeof(arfcns));

	f0 = arfcns[0];
	/*
	 * Manipulate the ARFCN list according to the rules in J4 depending
	 * on the selected range.
	 */
	arfcns_used = range_enc_filter_arfcns(range, arfcns, arfcns_used,
					      f0, &f0_included);

	memset(w, 0, sizeof(w));
	rc = range_enc_arfcns(range, arfcns, arfcns_used, w, 0);
	if (rc != 0) {
		printf("Cannot compute range W(k), rc = %d\n", rc);
		return 1;
	}

	if (!silent)
		fprintf(stderr, "range=%d, arfcns_used=%d, f0=%d, f0_included=%d\n",
			range, arfcns_used, f0, f0_included);

	/* Select the range and the amount of bits needed */
	switch (range) {
	case ARFCN_RANGE_128:
		rc = range_enc_range128(chan_list, f0, w);
		break;
	case ARFCN_RANGE_256:
		rc = range_enc_range256(chan_list, f0, w);
		break;
	case ARFCN_RANGE_512:
		rc = range_enc_range512(chan_list, f0, w);
		break;
	case ARFCN_RANGE_1024:
		rc = range_enc_range1024(chan_list, f0, f0_included, w);
		break;
	default:
		return 1;
	};
	if (rc != 0) {
		printf("Cannot encode range, rc = %d\n", rc);
		return 1;
	}

	if (!silent)
		printf("chan_list = %s\n",
		       osmo_hexdump(chan_list, sizeof(chan_list)));

	rc = gsm48_decode_freq_list(dec_freq, chan_list, sizeof(chan_list),
				    0xfe, 1);
	if (rc != 0) {
		printf("Cannot decode freq list, rc = %d\n", rc);
		return 1;
	}

	for (i = 0; i < ARRAY_SIZE(dec_freq); i++) {
		if (dec_freq[i].mask &&
		    dec_arfcns_count < ARRAY_SIZE(dec_arfcns))
			dec_arfcns[dec_arfcns_count++] = i;
	}

	if (!silent) {
		printf("Decoded freqs %d (expected %d)\n",
		       dec_arfcns_count, arfcns_num);
		printf("Decoded: ");
		for (i = 0; i < dec_arfcns_count; i++) {
			printf("%d ", dec_arfcns[i]);
			if (dec_arfcns[i] != orig_arfcns[i])
				printf("(!= %d) ", orig_arfcns[i]);
		}
		printf("\n");
	}

	if (dec_arfcns_count != arfcns_num) {
		printf("Wrong number of arfcns\n");
		return 1;
	}

	if (memcmp(dec_arfcns, orig_arfcns, sizeof(dec_arfcns)) != 0) {
		printf("Decoding error, got wrong freqs\n");
		fprintf(stderr, " w = ");
		for (i = 0; i < ARRAY_SIZE(w); i++)
			fprintf(stderr, "%d ", w[i]);
		fprintf(stderr, "\n");
		return 1;
	}

	return 0;
}

static void test_random_range_encoding(int range, int max_arfcn_num)
{
	int arfcns_num = 0;
	int test_idx;
	int rc, max_count;
	int num_tests = 1024;

	printf("Random range test: range %d, max num ARFCNs %d\n",
	       range, max_arfcn_num);

	srandom(1);

	for (max_count = 1; max_count < max_arfcn_num; max_count++) {
		for (test_idx = 0; test_idx < num_tests; test_idx++) {
			int count;
			int i;
			int min_freq = 0;

			int rnd_arfcns[RANGE_ENC_MAX_ARFCNS] = {0};
			char rnd_arfcns_set[1024] = {0};

			if (range < ARFCN_RANGE_1024)
				min_freq = random() % (1023 - range);

			for (count = max_count; count; ) {
				int arfcn = min_freq + random() % (range + 1);
				OSMO_ASSERT(arfcn < ARRAY_SIZE(rnd_arfcns_set));

				if (!rnd_arfcns_set[arfcn]) {
					rnd_arfcns_set[arfcn] = 1;
					count -= 1;
				}
			}

			arfcns_num = 0;
			for (i = 0; i < ARRAY_SIZE(rnd_arfcns_set); i++)
				if (rnd_arfcns_set[i])
					rnd_arfcns[arfcns_num++] = i;

			rc = test_single_range_encoding(range, rnd_arfcns,
							arfcns_num, 1);
			if (rc != 0) {
				printf("Failed on test %d, range %d, num ARFCNs %d\n",
				       test_idx, range, max_count);
				test_single_range_encoding(range, rnd_arfcns,
							   arfcns_num, 0);
				return;
			}
		}
	}
}

static void test_range_encoding()
{
	int *arfcns;
	int arfcns_num = 0;
	int test_idx;
	int range;

	for (test_idx = 0; arfcn_test_ranges[test_idx].arfcns_num > 0; test_idx++)
	{
		arfcns_num = arfcn_test_ranges[test_idx].arfcns_num;
		arfcns = &arfcn_test_ranges[test_idx].arfcns[0];
		range = arfcn_test_ranges[test_idx].range;

		printf("Range test %d: range %d, num ARFCNs %d\n",
		       test_idx, range, arfcns_num);

		test_single_range_encoding(range, arfcns, arfcns_num, 0);
	}

	test_random_range_encoding(ARFCN_RANGE_128, 29);
	test_random_range_encoding(ARFCN_RANGE_256, 22);
	test_random_range_encoding(ARFCN_RANGE_512, 18);
	test_random_range_encoding(ARFCN_RANGE_1024, 16);
}

int main(int argc, char **argv)
{
	osmo_init_logging(&log_info);
	log_set_log_level(osmo_stderr_target, LOGL_INFO);

	test_location_area_identifier();
	test_mi_functionality();
	test_range_encoding();

	printf("Done.\n");
	return EXIT_SUCCESS;
}
