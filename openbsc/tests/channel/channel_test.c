/*
 * (C) 2009 by Holger Hans Peter Freyther <zecke@selfish.org>
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

#include <stdio.h>
#include <stdlib.h>

#include <assert.h>

#include <osmocom/core/application.h>
#include <osmocom/core/select.h>

#include <openbsc/abis_rsl.h>
#include <openbsc/debug.h>
#include <openbsc/gsm_subscriber.h>

static int s_end = 0;
static struct gsm_subscriber_connection s_conn;

/* our handler */
static int subscr_cb(unsigned int hook, unsigned int event, struct msgb *msg, void *data, void *param)
{
	assert(hook == 101);
	assert(event == 200);
	assert(msg == (void*)0x1323L);
	assert(data == &s_conn);
	assert(param == (void*)0x2342L);
	printf("Reached, didn't crash, test passed\n");
	s_end = true;
	return 0;
}

/* mock object for testing, directly invoke the cb... maybe later through the timer */
int paging_request(struct gsm_bts *bts, struct gsm_subscriber *subscriber, int type, gsm_cbfn *cbfn, void *data)
{
	cbfn(101, 200, (void*)0x1323L, &s_conn, data);

	/* claim we have patched */
	return 1;
}


int main(int argc, char **argv)
{
	struct gsm_network *network;
	struct gsm_bts *bts;

	osmo_init_logging(&log_info);

	printf("Testing the gsm_subscriber chan logic\n");

	/* Create a dummy network */
	network = gsm_network_init(1, 1, NULL);
	if (!network)
		exit(1);
	bts = gsm_bts_alloc(network);
	bts->location_area_code = 23;

	/* Create a dummy subscriber */
	struct gsm_subscriber *subscr = subscr_alloc();
	subscr->lac = 23;
	subscr->net = network;

	/* Ask for a channel... */
	subscr_get_channel(subscr, RSL_CHANNEED_TCH_F, subscr_cb, (void*)0x2342L);

	while (!s_end) {
		osmo_select_main(0);
	}

	return EXIT_SUCCESS;
}

void _abis_nm_sendmsg() {}
void sms_alloc() {}
void sms_free() {}
void gsm_net_update_ctype(struct gsm_network *network) {}
void gsm48_secure_channel() {}
void paging_request_stop() {}
void vty_out() {}
void* connection_for_subscr(void) { abort(); return NULL; }


struct tlv_definition nm_att_tlvdef;

