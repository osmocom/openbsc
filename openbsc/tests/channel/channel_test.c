/*
 * (C) 2009 by Holger Hans Peter Freyther <zecke@selfish.org>
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

#include <stdio.h>
#include <stdlib.h>

#include <assert.h>

#include <osmocore/select.h>
#include <openbsc/gsm_subscriber.h>
#include <openbsc/abis_rsl.h>

/* our handler */
static int subscr_cb(unsigned int hook, unsigned int event, struct msgb *msg, void *data, void *param)
{
	assert(hook == 101);
	assert(event == 200);
	assert(msg == (void*)0x1323L);
	assert(data == (void*)0x4242L);
	assert(param == (void*)0x2342L);
	printf("Reached, didn't crash, test passed\n");
	return 0;
}

/* mock object for testing, directly invoke the cb... maybe later through the timer */
void paging_request(struct gsm_bts *bts, struct gsm_subscriber *subscriber, int type, gsm_cbfn *cbfn, void *data)
{
	cbfn(101, 200, (void*)0x1323L, (void*)0x4242L, data);
}


int main(int argc, char **argv)
{
	struct gsm_network *network;
	struct gsm_bts *bts;

	printf("Testing the gsm_subscriber chan logic\n");

	/* Create a dummy network */
	network = gsm_network_init(1, 1, NULL);
	if (!network)
		exit(1);
	bts = gsm_bts_alloc(network, GSM_BTS_TYPE_BS11, 0, 0);
	bts->location_area_code = 23;

	/* Create a dummy subscriber */
	struct gsm_subscriber *subscr = subscr_alloc();
	subscr->lac = 23;
	subscr->net = network;

	/* Ask for a channel... */
	subscr_get_channel(subscr, RSL_CHANNEED_TCH_F, subscr_cb, (void*)0x2342L);

	while (1) {
		bsc_select_main(0);
	}
}

void nm_state_event() {}
void input_event() {}
void sms_alloc() {}
void gsm_net_update_ctype(struct gsm_network *network) {}

struct tlv_definition nm_att_tlvdef;

