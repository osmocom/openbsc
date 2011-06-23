#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>

#include <openbsc/gprs_llc.h>

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

int main(int argc, char **argv)
{
	test_8_4_2();

	printf("Done.\n");
	return EXIT_SUCCESS;
}
