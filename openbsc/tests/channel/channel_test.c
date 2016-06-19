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

#include <openbsc/common_bsc.h>
#include <openbsc/abis_rsl.h>
#include <openbsc/debug.h>
#include <openbsc/gsm_subscriber.h>
#include <openbsc/vlr.h>

void test_dyn_ts_subslots(void)
{
	struct gsm_bts_trx_ts ts;

	printf("Testing subslot numbers for pchan types\n");

	ts.pchan = GSM_PCHAN_TCH_F;
	OSMO_ASSERT(ts_subslots(&ts) == 1);

	ts.pchan = GSM_PCHAN_TCH_H;
	OSMO_ASSERT(ts_subslots(&ts) == 2);

	ts.pchan = GSM_PCHAN_PDCH;
	OSMO_ASSERT(ts_subslots(&ts) == 0);

	ts.pchan = GSM_PCHAN_TCH_F_PDCH;
	ts.flags = 0; /* TCH_F mode */
	OSMO_ASSERT(ts_subslots(&ts) == 1);
	ts.flags = TS_F_PDCH_ACTIVE;
	OSMO_ASSERT(ts_subslots(&ts) == 0);

	ts.pchan = GSM_PCHAN_TCH_F_TCH_H_PDCH;
	ts.dyn.pchan_is = GSM_PCHAN_TCH_F;
	OSMO_ASSERT(ts_subslots(&ts) == 1);
	ts.dyn.pchan_is = GSM_PCHAN_TCH_H;
	OSMO_ASSERT(ts_subslots(&ts) == 2);
	ts.dyn.pchan_is = GSM_PCHAN_PDCH;
	OSMO_ASSERT(ts_subslots(&ts) == 0);
}

int main(int argc, char **argv)
{
	osmo_init_logging(&log_info);

	test_dyn_ts_subslots();

	return EXIT_SUCCESS;
}

void _abis_nm_sendmsg() {}
void sms_alloc() {}
void sms_free() {}
void gsm_net_update_ctype(struct gsm_network *network) {}
void gsm48_secure_channel() {}
void paging_request_stop() {}
void vty_out() {}

void ipa_client_conn_clear_queue() {}
void ipa_client_conn_close() {}
void ipa_client_conn_create() {}
void ipa_client_conn_destroy() {}
void ipa_client_conn_open() {}
void ipa_client_conn_send() {}
void ipa_msg_push_header() {}
void ipaccess_bts_handle_ccm() {}

struct tlv_definition nm_att_tlvdef;
