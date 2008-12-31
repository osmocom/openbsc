/* simple test for the gsm0408 formatting functions */
/*
 * (C) 2008 by Holger Hans Peter Freyther <zecke@selfish.org>
 * All Rights Reserved
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 */

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>

#include <openbsc/gsm_04_08.h>

#define COMPARE(result, op, value) \
    if (!((result) op (value))) {\
	fprintf(stderr, "Compare failed. Was %x should be %x in %s:%d\n",result, value, __FILE__, __LINE__); \
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
    gsm0408_generate_lai(&lai48, 1, 1, 1);
    COMPARE(lai48.digits[0], ==, 0x00);
    COMPARE(lai48.digits[1], ==, 0xF1);
    COMPARE(lai48.digits[2], ==, 0x10);
    COMPARE(lai48.lac, ==, htons(0x0001));

    gsm0408_generate_lai(&lai48, 602, 1, 15);
    COMPARE(lai48.digits[0], ==, 0x06);
    COMPARE(lai48.digits[1], ==, 0xF2);
    COMPARE(lai48.digits[2], ==, 0x10);
    COMPARE(lai48.lac, ==, htons(0x000f));
}

int main(int argc, char** argv)
{
    test_location_area_identifier();
}



/*
 * Stubs to compile and link
 */
void rsl_data_request(void) {}
void gsm0411_rcv_sms(void) {}
void schedule_timer(void) {}
void del_timer(void) {}
void subscr_get_by_tmsi(void) {}
void subscr_update(void) {}
void db_subscriber_assoc_imei(void) {}
void db_subscriber_alloc_tmsi(void) {}
void db_create_subscriber(void) {}
void rsl_chan_release(void) {}
void msgb_alloc(void) {}
void gsm0411_send_sms(void) {}
