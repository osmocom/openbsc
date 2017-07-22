/* Osmocom MSC+VLR end-to-end tests */

/* (C) 2017 by sysmocom s.f.m.c. GmbH <info@sysmocom.de>
 *
 * All Rights Reserved
 *
 * Author: Neels Hofmeyr <nhofmeyr@sysmocom.de>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include "msc_vlr_tests.h"

void test_reject_2nd_conn()
{
	struct gsm_subscriber_connection *conn1;
	comment_start();

	btw("Location Update Request on one connection");
	lu_result_sent = RES_NONE;
	gsup_expect_tx("04010809710000004026f0");
	ms_sends_msg("050802008168000130089910070000006402");
	OSMO_ASSERT(gsup_tx_confirmed);
	VERBOSE_ASSERT(lu_result_sent, == RES_NONE, "%d");
	EXPECT_CONN_COUNT(1);

	btw("Another Location Update Request from the same subscriber on another connection is rejected");
	conn1 = g_conn;
	g_conn = NULL;
	expect_bssap_clear();
	ms_sends_msg("050802008168000130089910070000006402");
	VERBOSE_ASSERT(bssap_clear_sent, == true, "%d");
	VERBOSE_ASSERT(lu_result_sent, == RES_REJECT, "%d");
	EXPECT_CONN_COUNT(1);


	BTW("The first connection can still complete its LU");
	btw("HLR sends _INSERT_DATA_REQUEST, VLR responds with _INSERT_DATA_RESULT");
	g_conn = conn1;
	lu_result_sent = RES_NONE;
	gsup_rx("10010809710000004026f00804036470f1",
		"12010809710000004026f0");
	VERBOSE_ASSERT(lu_result_sent, == RES_NONE, "%d");

	btw("HLR also sends GSUP _UPDATE_LOCATION_RESULT");
	expect_bssap_clear();
	gsup_rx("06010809710000004026f0", NULL);
	VERBOSE_ASSERT(bssap_clear_sent, == true, "%d");

	btw("LU was successful, and the conn has already been closed");
	VERBOSE_ASSERT(lu_result_sent, == RES_ACCEPT, "%d");
	EXPECT_CONN_COUNT(0);

	clear_vlr();
	comment_end();
}

void _normal_lu_part1()
{
	btw("Location Update Request");
	lu_result_sent = RES_NONE;
	gsup_expect_tx("04010809710000004026f0");
	ms_sends_msg("050802008168000130089910070000006402");
	OSMO_ASSERT(gsup_tx_confirmed);
	VERBOSE_ASSERT(lu_result_sent, == RES_NONE, "%d");
	EXPECT_CONN_COUNT(1);
}

void _normal_lu_part2()
{
	btw("HLR sends _INSERT_DATA_REQUEST, VLR responds with _INSERT_DATA_RESULT");
	lu_result_sent = RES_NONE;
	gsup_rx("10010809710000004026f00804036470f1",
		"12010809710000004026f0");
	VERBOSE_ASSERT(lu_result_sent, == RES_NONE, "%d");

	btw("HLR also sends GSUP _UPDATE_LOCATION_RESULT");
	expect_bssap_clear();
	gsup_rx("06010809710000004026f0", NULL);
	VERBOSE_ASSERT(bssap_clear_sent, == true, "%d");

	btw("LU was successful, and the conn has already been closed");
	VERBOSE_ASSERT(lu_result_sent, == RES_ACCEPT, "%d");
	EXPECT_CONN_COUNT(0);
}

void _normal_lu()
{
	BTW("Subscriber does a normal LU");
	_normal_lu_part1();
	_normal_lu_part2();
}

void _normal_cm_service_req()
{
	BTW("Subscriber does a normal CM Service Request");
	cm_service_result_sent = RES_NONE;
	ms_sends_msg("05247803305886089910070000006402");
	OSMO_ASSERT(g_conn);
	OSMO_ASSERT(g_conn->conn_fsm);
	OSMO_ASSERT(g_conn->vsub);
	VERBOSE_ASSERT(cm_service_result_sent, == RES_ACCEPT, "%d");
	EXPECT_ACCEPTED(true);
}

void _page()
{
	const char *imsi = "901700000004620";
	struct vlr_subscr *vsub;

	BTW("an SMS is sent, MS is paged");
	paging_expect_imsi(imsi);
	paging_sent = false;
	vsub = vlr_subscr_find_by_imsi(net->vlr, imsi);
	OSMO_ASSERT(vsub);
	VERBOSE_ASSERT(llist_count(&vsub->cs.requests), == 0, "%d");

	send_sms(vsub, vsub,
		 "Privacy in residential applications is a desirable"
		 " marketing option.");

	VERBOSE_ASSERT(llist_count(&vsub->cs.requests), == 1, "%d");
	vlr_subscr_put(vsub);
	vsub = NULL;
	VERBOSE_ASSERT(paging_sent, == true, "%d");
	VERBOSE_ASSERT(paging_stopped, == false, "%d");
}

void _paging_resp_part1()
{
	btw("MS replies with Paging Response, we deliver the SMS");
	dtap_expect_tx("09" /* SMS messages */
		       "01" /* CP-DATA */
		       "58" /* length */
		       "01" /* Network to MS */
		       "00" /* reference */
		       /* originator (gsm411_send_sms() hardcodes this weird nr) */
		       "0791" "447758100650" /* 447785016005 */
		       "00" /* dest */
		       /* SMS TPDU */
		       "4c" /* len */
		       "00" /* SMS deliver */
		       "05806470f1" /* originating address 46071 */
		       "00" /* TP-PID */
		       "00" /* GSM default alphabet */
		       "071010" /* Y-M-D (from wrapped gsm340_gen_scts())*/
		       "000000" /* H-M-S */
		       "00" /* GMT+0 */
		       "44" /* data length */
		       "5079da1e1ee7416937485e9ea7c965373d1d6683c270383b3d0e"
		       "d3d36ff71c949e83c22072799e9687c5ec32a81d96afcbf4b4fb"
		       "0c7ac3e9e9b7db05");
	ms_sends_msg("06270703305882089910070000006402");
	VERBOSE_ASSERT(dtap_tx_confirmed, == true, "%d");
	VERBOSE_ASSERT(paging_stopped, == true, "%d");

	btw("conn is still open to wait for SMS ack dance");
	EXPECT_CONN_COUNT(1);
}

void _paging_resp_part2(int expect_conn_count, bool expect_clear)
{
	btw("MS replies with CP-ACK for received SMS");
	ms_sends_msg("8904");
	EXPECT_CONN_COUNT(1);

	btw("MS also sends RP-ACK, MSC in turn sends CP-ACK for that");
	dtap_expect_tx("0904");
	if (expect_clear)
		expect_bssap_clear();
	ms_sends_msg("890106020041020000");
	VERBOSE_ASSERT(dtap_tx_confirmed, == true, "%d");
	if (expect_clear)
		VERBOSE_ASSERT(bssap_clear_sent, == true, "%d");

	btw("SMS is done");
	EXPECT_CONN_COUNT(expect_conn_count);
}

void test_reject_lu_during_lu()
{
	comment_start();

	_normal_lu_part1();

	BTW("Another Location Update Request from the same subscriber on the same conn is dropped silently");
	ms_sends_msg("050802008168000130089910070000006402");
	VERBOSE_ASSERT(lu_result_sent, == RES_NONE, "%d");
	EXPECT_CONN_COUNT(1);

	BTW("The first LU can still complete");
	_normal_lu_part2();

	clear_vlr();
	comment_end();
}

void test_reject_cm_during_lu()
{
	comment_start();

	_normal_lu_part1();

	BTW("A CM Service Request in the middle of a LU is rejected");
	cm_service_result_sent = RES_NONE;
	dtap_expect_tx("052211");
	ms_sends_msg("05247803305886089910070000006402");
	VERBOSE_ASSERT(lu_result_sent, == RES_NONE, "%d");
	VERBOSE_ASSERT(cm_service_result_sent, == RES_NONE, "%d");
	EXPECT_CONN_COUNT(1);

	BTW("The first LU can still complete");
	_normal_lu_part2();

	clear_vlr();
	comment_end();
}

void test_reject_paging_resp_during_lu()
{
	comment_start();

	_normal_lu_part1();

	BTW("An erratic Paging Response is dropped silently");
	ms_sends_msg("06270703305882089910070000006402");
	VERBOSE_ASSERT(lu_result_sent, == RES_NONE, "%d");
	EXPECT_CONN_COUNT(1);

	BTW("The first LU can still complete");
	_normal_lu_part2();

	clear_vlr();
	comment_end();
}

void test_reject_lu_during_cm()
{
	comment_start();

	_normal_lu();
	_normal_cm_service_req();

	btw("A LU request on an open conn is dropped silently");
	/* TODO: accept periodic LU on an already open conn? */
	lu_result_sent = RES_NONE;
	ms_sends_msg("050802008168000130089910070000006402");
	VERBOSE_ASSERT(lu_result_sent, == RES_NONE, "%d");
	EXPECT_CONN_COUNT(1);

	BTW("subscriber detaches");
	expect_bssap_clear();
	ms_sends_msg("050130089910070000006402");
	VERBOSE_ASSERT(bssap_clear_sent, == true, "%d");
	EXPECT_CONN_COUNT(0);

	clear_vlr();
	comment_end();
}

void test_reject_cm_during_cm()
{
	comment_start();

	_normal_lu();
	_normal_cm_service_req();

	btw("A second CM Service Request on the same conn is accepted without another auth dance");
	cm_service_result_sent = RES_NONE;
	ms_sends_msg("05247803305886089910070000006402");
	VERBOSE_ASSERT(cm_service_result_sent, == RES_ACCEPT, "%d");
	EXPECT_CONN_COUNT(1);

	BTW("subscriber detaches");
	expect_bssap_clear();
	ms_sends_msg("050130089910070000006402");
	VERBOSE_ASSERT(bssap_clear_sent, == true, "%d");
	EXPECT_CONN_COUNT(0);

	clear_vlr();
	comment_end();
}

void test_reject_paging_resp_during_cm()
{
	comment_start();

	_normal_lu();
	_normal_cm_service_req();

	BTW("An erratic Paging Response on the same conn is dropped silently");
	ms_sends_msg("06270703305882089910070000006402");
	EXPECT_CONN_COUNT(1);

	BTW("The original CM Service Request can conclude");
	btw("a USSD request is serviced");
	dtap_expect_tx_ussd("Your extension is 46071\r");
	expect_bssap_clear();
	ms_sends_msg("0b3b1c15a11302010002013b300b04010f0406aa510c061b017f0100");
	VERBOSE_ASSERT(bssap_clear_sent, == true, "%d");

	btw("all requests serviced, conn has been released");
	EXPECT_CONN_COUNT(0);

	clear_vlr();
	comment_end();
}

void test_reject_paging_resp_during_paging_resp()
{
	comment_start();

	_normal_lu();
	_page();
	_paging_resp_part1();

	BTW("MS sends another erratic Paging Response which is dropped silently");
	ms_sends_msg("06270703305882089910070000006402");

	_paging_resp_part2(0, true);

	clear_vlr();
	comment_end();
}

void test_reject_lu_during_paging_resp()
{
	comment_start();

	_normal_lu();
	_page();
	_paging_resp_part1();

	BTW("MS sends erratic LU Request, which is dropped silently");
	lu_result_sent = RES_NONE;
	ms_sends_msg("050802008168000130089910070000006402");
	VERBOSE_ASSERT(lu_result_sent, == RES_NONE, "%d");
	EXPECT_CONN_COUNT(1);

	_paging_resp_part2(0, true);

	clear_vlr();
	comment_end();
}

void test_accept_cm_during_paging_resp()
{
	comment_start();

	_normal_lu();
	_page();
	_paging_resp_part1();

	BTW("CM Service Request during open connection is accepted");
	cm_service_result_sent = RES_NONE;
	ms_sends_msg("05247803305886089910070000006402");
	VERBOSE_ASSERT(cm_service_result_sent, == RES_ACCEPT, "%d");
	EXPECT_CONN_COUNT(1);
	VERBOSE_ASSERT(g_conn->received_cm_service_request, == true, "%d");

	_paging_resp_part2(1, false);

	BTW("subscriber detaches");
	expect_bssap_clear();
	ms_sends_msg("050130089910070000006402");
	VERBOSE_ASSERT(bssap_clear_sent, == true, "%d");
	EXPECT_CONN_COUNT(0);

	clear_vlr();
	comment_end();
}

msc_vlr_test_func_t msc_vlr_tests[] = {
	test_reject_2nd_conn,
	test_reject_lu_during_lu,
	test_reject_cm_during_lu,
	test_reject_paging_resp_during_lu,
	test_reject_lu_during_cm,
	test_reject_cm_during_cm,
	test_reject_paging_resp_during_cm,
	test_reject_lu_during_paging_resp,
	test_accept_cm_during_paging_resp,
	test_reject_paging_resp_during_paging_resp,
	NULL
};
