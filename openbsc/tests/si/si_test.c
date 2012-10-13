

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openbsc/arfcn_range_encode.h>

#include <osmocom/core/utils.h>

#define DBG(...)

#define VERIFY(res, cmp, wanted)					\
	if (!(res cmp wanted)) {					\
		printf("ASSERT failed: %s:%d Wanted: %d %s %d\n",	\
			__FILE__, __LINE__, res, # cmp, wanted);	\
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
	res = range_enc_filter_arfcns(ARFCN_RANGE_512, arfcns, ARRAY_SIZE(arfcns),
			arfcns[0], &f0_included);
	VERIFY(res, ==, ARRAY_SIZE(arfcns) - 1);
	VERIFY(f0_included, ==, 0);
	for (i = 0; i < res; ++i)
		VERIFY(arfcns[i], ==, ((i+2) * 2) - (2+1));

	/* check with range1024 */
	for (i = 0; i < ARRAY_SIZE(arfcns); ++i)
		arfcns[i] = (i + 1) * 2;
	res = range_enc_filter_arfcns(ARFCN_RANGE_1024, arfcns, ARRAY_SIZE(arfcns),
			arfcns[0], &f0_included);
	VERIFY(res, ==, ARRAY_SIZE(arfcns) - 1);
	VERIFY(f0_included, ==, 1);
	for (i = 0; i < res; ++i)
		VERIFY(arfcns[i], ==, ((i + 2) * 2) - 1);

	/* check with range1024, not included */
	for (i = 0; i < ARRAY_SIZE(arfcns); ++i)
		arfcns[i] = (i + 1) * 2;
	res = range_enc_filter_arfcns(ARFCN_RANGE_1024, arfcns, ARRAY_SIZE(arfcns),
			11, &f0_included);
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

	rc = range_enc_range512(chan_list, 0x96, w);
	VERIFY(rc, ==, 0);

	printf("Range512: %s\n", osmo_hexdump(chan_list, ARRAY_SIZE(chan_list)));
}

int main(int argc, char **argv)
{
	int ws[(sizeof(freqs1)/sizeof(freqs1[0]))];
	int i, f0 = 0xFFFFFF;

	memset(&ws[0], 0x23, sizeof(ws));

	i = range_enc_find_index(1023, freqs1, ARRAY_SIZE(freqs1));
	printf("Element is: %d => freqs[i] = %d\n", i, freqs1[i]);
	VERIFY(i, ==, 2);

	i = range_enc_find_index(511, freqs2, ARRAY_SIZE(freqs2));
	printf("Element is: %d => freqs[i] = %d\n", i, freqs2[i]);
	VERIFY(i, ==, 2);

	i = range_enc_find_index(511, freqs3, ARRAY_SIZE(freqs3));
	printf("Element is: %d => freqs[i] = %d\n", i, freqs3[i]);
	VERIFY(i, ==, 0);

	i = range_enc_arfcns(1023, freqs1, ARRAY_SIZE(freqs1), ws, 0);
	VERIFY(i, ==, 0);

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


	test_arfcn_filter();
	test_print_encoding();

	return 0;
}
