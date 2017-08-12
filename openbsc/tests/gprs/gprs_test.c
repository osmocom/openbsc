#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>

#include <openbsc/gprs_llc.h>
#include <openbsc/gprs_utils.h>

#include <openbsc/debug.h>

#include <osmocom/core/application.h>
#include <osmocom/gsm/gsup.h>

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
	test_gprs_timer_enc_dec();

	printf("Done.\n");
	return EXIT_SUCCESS;
}
