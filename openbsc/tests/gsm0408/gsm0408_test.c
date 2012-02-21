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

int main(int argc, char **argv)
{
	test_location_area_identifier();
	test_mi_functionality();

	printf("Done.\n");
	return EXIT_SUCCESS;
}
