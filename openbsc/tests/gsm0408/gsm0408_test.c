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
#include <stdbool.h>
#include <arpa/inet.h>

#include <openbsc/common_bsc.h>
#include <openbsc/gsm_04_08.h>
#include <openbsc/gsm_04_11.h>
#include <openbsc/gsm_subscriber.h>
#include <openbsc/gsm_data_shared.h>
#include <openbsc/debug.h>
#include <openbsc/arfcn_range_encode.h>
#include <openbsc/system_information.h>
#include <openbsc/abis_rsl.h>

#include <osmocom/core/application.h>
#include <osmocom/gsm/sysinfo.h>

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
			__FILE__, __LINE__, (int) res, # cmp, (int) wanted);	\
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

static inline void gen(struct gsm_bts *bts, const char *s)
{
	int r;

	bts->si_valid = 0;
	bts->si_valid |= (1 << SYSINFO_TYPE_2quater);

	printf("generating SI2quater for %zu EARFCNs and %zu UARFCNs...\n",
	       si2q_earfcn_count(&bts->si_common.si2quater_neigh_list), bts->si_common.uarfcn_length);

	r = gsm_generate_si(bts, SYSINFO_TYPE_2quater);
	if (r > 0)
		for (bts->si2q_index = 0; bts->si2q_index < bts->si2q_count + 1; bts->si2q_index++)
			printf("generated %s SI2quater [%02u/%02u]: [%d] %s\n",
			       GSM_BTS_HAS_SI(bts, SYSINFO_TYPE_2quater) ? "valid" : "invalid",
			       bts->si2q_index, bts->si2q_count, r,
			       osmo_hexdump((void *)GSM_BTS_SI2Q(bts, bts->si2q_index), GSM_MACBLOCK_LEN));
	else
		printf("%s() failed to generate SI2quater: %s\n", s, strerror(-r));
}

static inline void del_earfcn_b(struct gsm_bts *bts, uint16_t earfcn)
{
	struct osmo_earfcn_si2q *e = &bts->si_common.si2quater_neigh_list;
	int r = osmo_earfcn_del(e, earfcn);
	if (r)
		printf("failed to remove EARFCN %u: %s\n", earfcn, strerror(-r));
	else
		printf("removed EARFCN %u - ", earfcn);

	gen(bts, __func__);
}

static inline void add_earfcn_b(struct gsm_bts *bts, uint16_t earfcn, uint8_t bw)
{
	struct osmo_earfcn_si2q *e = &bts->si_common.si2quater_neigh_list;
	int r = osmo_earfcn_add(e, earfcn, bw);
	if (r)
		printf("failed to add EARFCN %u: %s\n", earfcn, strerror(-r));
	else
		printf("added EARFCN %u - ", earfcn);

	gen(bts, __func__);
}

static inline void _bts_uarfcn_add(struct gsm_bts *bts, uint16_t arfcn, uint16_t scramble, bool diversity)
{
	int r;

	bts->u_offset = 0;

	r = bts_uarfcn_add(bts, arfcn, scramble, diversity);
	if (r < 0)
		printf("failed to add UARFCN to SI2quater: %s\n", strerror(-r));
	else {
		bts->si2q_count = si2q_num(bts) - 1;
		gen(bts, __func__);
	}
}

static inline void test_si2q_segfault(void)
{
	struct gsm_bts *bts;
	struct gsm_network *network = bsc_network_init(tall_bsc_ctx, 1, 1, NULL);
	printf("Test SI2quater UARFCN (same scrambling code and diversity):\n");

	if (!network)
		exit(1);
	bts = gsm_bts_alloc(network);

	_bts_uarfcn_add(bts, 10564, 319, 0);
	_bts_uarfcn_add(bts, 10612, 319, 0);
	gen(bts, __func__);
}

static inline void test_si2q_mu(void)
{
	struct gsm_bts *bts;
	struct gsm_network *network = bsc_network_init(tall_bsc_ctx, 1, 1, NULL);
	printf("Test SI2quater multiple UARFCNs:\n");

	if (!network)
		exit(1);
	bts = gsm_bts_alloc(network);

	_bts_uarfcn_add(bts, 10564, 318, 0);
	_bts_uarfcn_add(bts, 10612, 319, 0);
	_bts_uarfcn_add(bts, 10612, 31, 0);
	_bts_uarfcn_add(bts, 10612, 19, 0);
	_bts_uarfcn_add(bts, 10613, 64, 0);
	_bts_uarfcn_add(bts, 10613, 164, 0);
	_bts_uarfcn_add(bts, 10613, 14, 0);
}

static inline void test_si2q_u(void)
{
	struct gsm_bts *bts;
	struct gsm_network *network = bsc_network_init(NULL, 1, 1, NULL);
	printf("Testing SYSINFO_TYPE_2quater UARFCN generation:\n");

	if (!network)
		exit(1);

	bts = gsm_bts_alloc(network);

	/* first generate invalid SI as no UARFCN added */
	gen(bts, __func__);

	/* subsequent calls should produce valid SI if there's enough memory */
	_bts_uarfcn_add(bts, 1982, 13, 1);
	_bts_uarfcn_add(bts, 1982, 44, 0);
	_bts_uarfcn_add(bts, 1982, 61, 1);
	_bts_uarfcn_add(bts, 1982, 89, 1);
	_bts_uarfcn_add(bts, 1982, 113, 0);
	_bts_uarfcn_add(bts, 1982, 123, 0);
	_bts_uarfcn_add(bts, 1982, 56, 1);
	_bts_uarfcn_add(bts, 1982, 72, 1);
	_bts_uarfcn_add(bts, 1982, 223, 1);
	_bts_uarfcn_add(bts, 1982, 14, 0);
	_bts_uarfcn_add(bts, 1982, 88, 0);
}

static inline void test_si2q_e(void)
{
	struct gsm_bts *bts;
	struct gsm_network *network = bsc_network_init(NULL, 1, 1, NULL);
	printf("Testing SYSINFO_TYPE_2quater EARFCN generation:\n");

	if (!network)
		exit(1);

	bts = gsm_bts_alloc(network);

	bts->si_common.si2quater_neigh_list.arfcn = bts->si_common.data.earfcn_list;
	bts->si_common.si2quater_neigh_list.meas_bw = bts->si_common.data.meas_bw_list;
	bts->si_common.si2quater_neigh_list.length = MAX_EARFCN_LIST;
	bts->si_common.si2quater_neigh_list.thresh_hi = 5;

	osmo_earfcn_init(&bts->si_common.si2quater_neigh_list);

	/* first generate invalid SI as no EARFCN added */
	gen(bts, __func__);

	/* subsequent calls should produce valid SI if there's enough memory and EARFCNs */
	add_earfcn_b(bts, 1917, 5);
	del_earfcn_b(bts, 1917);
	add_earfcn_b(bts, 1917, 1);
	add_earfcn_b(bts, 1932, OSMO_EARFCN_MEAS_INVALID);
	add_earfcn_b(bts, 1937, 2);
	add_earfcn_b(bts, 1945, OSMO_EARFCN_MEAS_INVALID);
	add_earfcn_b(bts, 1965, OSMO_EARFCN_MEAS_INVALID);
	add_earfcn_b(bts, 1967, 4);
	add_earfcn_b(bts, 1982, 3);
}

static inline void test_si2q_long(void)
{
	struct gsm_bts *bts;
	struct gsm_network *network = bsc_network_init(tall_bsc_ctx, 1, 1, NULL);
	printf("Testing SYSINFO_TYPE_2quater combined EARFCN & UARFCN generation:\n");

	if (!network)
		exit(1);

	bts = gsm_bts_alloc(network);

	bts->si_common.si2quater_neigh_list.arfcn = bts->si_common.data.earfcn_list;
	bts->si_common.si2quater_neigh_list.meas_bw = bts->si_common.data.meas_bw_list;
	bts->si_common.si2quater_neigh_list.length = MAX_EARFCN_LIST;
	bts->si_common.si2quater_neigh_list.thresh_hi = 5;

	osmo_earfcn_init(&bts->si_common.si2quater_neigh_list);

	bts_earfcn_add(bts, 1922, 11, 22, 8,32, 8);
	bts_earfcn_add(bts, 1922, 11, 22, 8, 32, 8);
	bts_earfcn_add(bts, 1924, 11, 12, 6, 11, 5);
	bts_earfcn_add(bts, 1923, 11, 12, 6, 11, 5);
	bts_earfcn_add(bts, 1925, 11, 12, 6, 11, 5);
	bts_earfcn_add(bts, 2111, 11, 12, 6, 11, 5);
	bts_earfcn_add(bts, 2112, 11, 12, 6, 11, 4);
	bts_earfcn_add(bts, 2113, 11, 12, 6, 11, 3);
	bts_earfcn_add(bts, 2114, 11, 12, 6, 11, 2);
	bts_earfcn_add(bts, 2131, 11, 12, 6, 11, 5);
	bts_earfcn_add(bts, 2132, 11, 12, 6, 11, 4);
	bts_earfcn_add(bts, 2133, 11, 12, 6, 11, 3);
	bts_earfcn_add(bts, 2134, 11, 12, 6, 11, 2);
	bts_earfcn_add(bts, 2121, 11, 12, 6, 11, 5);
	bts_earfcn_add(bts, 2122, 11, 12, 6, 11, 4);
	bts_earfcn_add(bts, 2123, 11, 12, 6, 11, 3);
	bts_earfcn_add(bts, 2124, 11, 12, 6, 11, 2);
	_bts_uarfcn_add(bts, 1976, 13, 1);
	_bts_uarfcn_add(bts, 1976, 38, 1);
	_bts_uarfcn_add(bts, 1976, 44, 1);
	_bts_uarfcn_add(bts, 1976, 120, 1);
	_bts_uarfcn_add(bts, 1976, 140, 1);
	_bts_uarfcn_add(bts, 1976, 163, 1);
	_bts_uarfcn_add(bts, 1976, 166, 1);
	_bts_uarfcn_add(bts, 1976, 217, 1);
	_bts_uarfcn_add(bts, 1976, 224, 1);
	_bts_uarfcn_add(bts, 1976, 225, 1);
	_bts_uarfcn_add(bts, 1976, 226, 1);
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

	f0 = range == ARFCN_RANGE_1024 ? 0 : arfcns[0];
	/*
	 * Manipulate the ARFCN list according to the rules in J4 depending
	 * on the selected range.
	 */
	arfcns_used = range_enc_filter_arfcns(arfcns, arfcns_used,
					      f0, &f0_included);

	memset(w, 0, sizeof(w));
	range_enc_arfcns(range, arfcns, arfcns_used, w, 0);

	if (!silent)
		fprintf(stderr, "range=%d, arfcns_used=%d, f0=%d, f0_included=%d\n",
			range, arfcns_used, f0, f0_included);

	/* Select the range and the amount of bits needed */
	switch (range) {
	case ARFCN_RANGE_128:
		range_enc_range128(chan_list, f0, w);
		break;
	case ARFCN_RANGE_256:
		range_enc_range256(chan_list, f0, w);
		break;
	case ARFCN_RANGE_512:
		range_enc_range512(chan_list, f0, w);
		break;
	case ARFCN_RANGE_1024:
		range_enc_range1024(chan_list, f0, f0_included, w);
		break;
	default:
		return 1;
	};

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

static int freqs1[] = {
	12, 70, 121, 190, 250, 320, 401, 475, 520, 574, 634, 700, 764, 830, 905, 980
};

static int freqs2[] = {
	402, 460, 1, 67, 131, 197, 272, 347,
};

static int freqs3[] = {
	68, 128, 198, 279, 353, 398, 452,

};

static int w_out[] = {
	122, 2, 69, 204, 75, 66, 60, 70, 83, 3, 24, 67, 54, 64, 70, 9,
};

static int range128[] = {
	1, 1 + 127,
};

static int range256[] = {
	1, 1 + 128,
};

static int range512[] = {
	1, 1+ 511,
};


static void test_arfcn_filter()
{
	int arfcns[50], i, res, f0_included;
	for (i = 0; i < ARRAY_SIZE(arfcns); ++i)
		arfcns[i] = (i + 1) * 2;

	/* check that the arfcn is taken out. f0_included is only set for Range1024 */
	f0_included = 24;
	res = range_enc_filter_arfcns(arfcns, ARRAY_SIZE(arfcns),
			arfcns[0], &f0_included);
	VERIFY(res, ==, ARRAY_SIZE(arfcns) - 1);
	VERIFY(f0_included, ==, 1);
	for (i = 0; i < res; ++i)
		VERIFY(arfcns[i], ==, ((i+2) * 2) - (2+1));

	/* check with range1024, ARFCN 0 is included */
	for (i = 0; i < ARRAY_SIZE(arfcns); ++i)
		arfcns[i] = i * 2;
	res = range_enc_filter_arfcns(arfcns, ARRAY_SIZE(arfcns),
			0, &f0_included);
	VERIFY(res, ==, ARRAY_SIZE(arfcns) - 1);
	VERIFY(f0_included, ==, 1);
	for (i = 0; i < res; ++i)
		VERIFY(arfcns[i], ==, (i + 1) * 2 - 1);

	/* check with range1024, ARFCN 0 not included */
	for (i = 0; i < ARRAY_SIZE(arfcns); ++i)
		arfcns[i] = (i + 1) * 2;
	res = range_enc_filter_arfcns(arfcns, ARRAY_SIZE(arfcns),
			0, &f0_included);
	VERIFY(res, ==, ARRAY_SIZE(arfcns));
	VERIFY(f0_included, ==, 0);
	for (i = 0; i < res; ++i)
		VERIFY(arfcns[i], ==, ((i + 1) * 2) - 1);
}

static void test_print_encoding()
{
	int rc;
	int w[17];
	uint8_t chan_list[16];
	memset(chan_list, 0x23, sizeof(chan_list));

	for (rc = 0; rc < ARRAY_SIZE(w); ++rc)
		switch (rc % 3) {
		case 0:
			w[rc] = 0xAAAA;
			break;
		case 1:
			w[rc] = 0x5555;
			break;
		case 2:
			w[rc] = 0x9696;
			break;
		}

	range_enc_range512(chan_list, (1 << 9) | 0x96, w);

	printf("Range512: %s\n", osmo_hexdump(chan_list, ARRAY_SIZE(chan_list)));
}

static void test_si_range_helpers()
{
	int ws[(sizeof(freqs1)/sizeof(freqs1[0]))];
	int i, f0 = 0xFFFFFF;

	memset(&ws[0], 0x23, sizeof(ws));

	i = range_enc_find_index(1023, freqs1, ARRAY_SIZE(freqs1));
	printf("Element is: %d => freqs[i] = %d\n", i, i >= 0 ? freqs1[i] : -1);
	VERIFY(i, ==, 2);

	i = range_enc_find_index(511, freqs2, ARRAY_SIZE(freqs2));
	printf("Element is: %d => freqs[i] = %d\n", i,  i >= 0 ? freqs2[i] : -1);
	VERIFY(i, ==, 2);

	i = range_enc_find_index(511, freqs3, ARRAY_SIZE(freqs3));
	printf("Element is: %d => freqs[i] = %d\n", i,  i >= 0 ? freqs3[i] : -1);
	VERIFY(i, ==, 0);

	range_enc_arfcns(1023, freqs1, ARRAY_SIZE(freqs1), ws, 0);

	for (i = 0; i < sizeof(freqs1)/sizeof(freqs1[0]); ++i) {
		printf("w[%d]=%d\n", i, ws[i]);
		VERIFY(ws[i], ==, w_out[i]);
	}

	i = range_enc_determine_range(range128, ARRAY_SIZE(range128), &f0);
	VERIFY(i, ==, ARFCN_RANGE_128);
	VERIFY(f0, ==, 1);

	i = range_enc_determine_range(range256, ARRAY_SIZE(range256), &f0);
	VERIFY(i, ==, ARFCN_RANGE_256);
	VERIFY(f0, ==, 1);

	i = range_enc_determine_range(range512, ARRAY_SIZE(range512), &f0);
	VERIFY(i, ==, ARFCN_RANGE_512);
	VERIFY(f0, ==, 1);
}

static void test_gsm411_rp_ref_wrap(void)
{
	struct gsm_subscriber_connection conn;
	int res;

	printf("testing RP-Reference wrap\n");

	memset(&conn, 0, sizeof(conn));
	conn.next_rp_ref = 255;

	res = sms_next_rp_msg_ref(&conn.next_rp_ref);
	printf("Allocated reference: %d\n", res);
	OSMO_ASSERT(res == 255);

	res = sms_next_rp_msg_ref(&conn.next_rp_ref);
	printf("Allocated reference: %d\n", res);
	OSMO_ASSERT(res == 0);

	res = sms_next_rp_msg_ref(&conn.next_rp_ref);
	printf("Allocated reference: %d\n", res);
	OSMO_ASSERT(res == 1);
}

int main(int argc, char **argv)
{
	osmo_init_logging(&log_info);
	log_set_log_level(osmo_stderr_target, LOGL_INFO);

	test_location_area_identifier();
	test_mi_functionality();

	test_si_range_helpers();
	test_arfcn_filter();
	test_print_encoding();
	test_range_encoding();
	test_gsm411_rp_ref_wrap();

	test_si2q_segfault();
	test_si2q_e();
	test_si2q_u();
	test_si2q_mu();
	test_si2q_long();

	printf("Done.\n");

	return EXIT_SUCCESS;
}
