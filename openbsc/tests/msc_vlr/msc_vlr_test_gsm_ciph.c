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

void test_ciph()
{
	struct vlr_subscr *vsub;
	const char *imsi = "901700000004620";

	comment_start();

	/* implicit: net->authentication_required = true; */
	net->a5_encryption = VLR_CIPH_A5_1;

	btw("Location Update request causes a GSUP Send Auth Info request to HLR");
	lu_result_sent = RES_NONE;
	gsup_expect_tx("08010809710000004026f0");
	ms_sends_msg("050802008168000130089910070000006402");
	OSMO_ASSERT(gsup_tx_confirmed);
	VERBOSE_ASSERT(lu_result_sent, == RES_NONE, "%d");

	btw("from HLR, rx _SEND_AUTH_INFO_RESULT; VLR sends Auth Req to MS");
	/* Based on a Ki of 000102030405060708090a0b0c0d0e0f */
	auth_request_sent = false;
	auth_request_expect_rand = "585df1ae287f6e273dce07090d61320b";
	auth_request_expect_autn = NULL;
	gsup_rx("0a"
		/* imsi */
		"0108" "09710000004026f0"
		/* 5 auth vectors... */
		/* TL    TL     rand */
		"0322"  "2010" "585df1ae287f6e273dce07090d61320b"
		/*       TL     sres       TL     kc */
			"2104" "2d8b2c3e" "2208" "61855fb81fc2a800"
		"0322"  "2010" "12aca96fb4ffdea5c985cbafa9b6e18b"
			"2104" "20bde240" "2208" "07fa7502e07e1c00"
		"0322"  "2010" "e7c03ba7cf0e2fde82b2dc4d63077d42"
			"2104" "a29514ae" "2208" "e2b234f807886400"
		"0322"  "2010" "fa8f20b781b5881329d4fea26b1a3c51"
			"2104" "5afc8d72" "2208" "2392f14f709ae000"
		"0322"  "2010" "0fd4cc8dbe8715d1f439e304edfd68dc"
			"2104" "bc8d1c5b" "2208" "da7cdd6bfe2d7000",
		NULL);
	VERBOSE_ASSERT(lu_result_sent, == RES_NONE, "%d");
	VERBOSE_ASSERT(auth_request_sent, == true, "%d");

	btw("MS sends Authen Response, VLR accepts and sends Ciphering Mode Command to MS");
	cipher_mode_cmd_sent = false;
	ms_sends_msg("05542d8b2c3e");
	OSMO_ASSERT(cipher_mode_cmd_sent);
	VERBOSE_ASSERT(lu_result_sent, == RES_NONE, "%d");

	btw("needs ciph, not yet accepted");
	EXPECT_ACCEPTED(false);
	thwart_rx_non_initial_requests();
	VERBOSE_ASSERT(lu_result_sent, == RES_NONE, "%d");

	btw("MS sends Ciphering Mode Complete, VLR accepts and sends GSUP LU Req to HLR");
	gsup_expect_tx("04010809710000004026f0");
	ms_sends_msg("0632");
	VERBOSE_ASSERT(lu_result_sent, == RES_NONE, "%d");

	btw("HLR sends _INSERT_DATA_REQUEST, VLR responds with _INSERT_DATA_RESULT");
	gsup_rx("10010809710000004026f00804036470f1",
		"12010809710000004026f0");
	VERBOSE_ASSERT(lu_result_sent, == RES_NONE, "%d");

	btw("HLR also sends GSUP _UPDATE_LOCATION_RESULT");
	gsup_rx("06010809710000004026f0", NULL);

	btw("LU was successful, and the conn has already been closed");
	VERBOSE_ASSERT(lu_result_sent, == RES_ACCEPT, "%d");
	EXPECT_CONN_COUNT(0);

	BTW("after a while, a new conn sends a CM Service Request. VLR responds with Auth Req, 2nd auth vector");
	cm_service_result_sent = RES_NONE;
	auth_request_sent = false;
	auth_request_expect_rand = "12aca96fb4ffdea5c985cbafa9b6e18b";
	ms_sends_msg("05247803305886089910070000006402");
	OSMO_ASSERT(g_conn);
	OSMO_ASSERT(g_conn->conn_fsm);
	OSMO_ASSERT(g_conn->vsub);
	VERBOSE_ASSERT(auth_request_sent, == true, "%d");
	VERBOSE_ASSERT(cm_service_result_sent, == RES_NONE, "%d");

	btw("needs auth, not yet accepted");
	EXPECT_ACCEPTED(false);
	thwart_rx_non_initial_requests();

	btw("MS sends Authen Response, VLR accepts and requests Ciphering");
	cipher_mode_cmd_sent = false;
	ms_sends_msg("0554" "20bde240" /* 2nd vector's sres, s.a. */);
	VERBOSE_ASSERT(cm_service_result_sent, == RES_NONE, "%d");
	VERBOSE_ASSERT(cipher_mode_cmd_sent, == true, "%d");

	btw("needs ciph, not yet accepted");
	EXPECT_ACCEPTED(false);
	thwart_rx_non_initial_requests();

	btw("MS sends Ciphering Mode Complete, VLR accepts; above Ciphering is an implicit CM Service Accept");
	ms_sends_msg("0632");
	VERBOSE_ASSERT(cm_service_result_sent, == RES_NONE, "%d");

	btw("a USSD request is serviced");
	dtap_expect_tx_ussd("Your extension is 46071\r");
	ms_sends_msg("0b3b1c15a11302010002013b300b04010f0406aa510c061b017f0100");
	OSMO_ASSERT(dtap_tx_confirmed);

	btw("all requests serviced, conn has been released");
	EXPECT_CONN_COUNT(0);

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

	btw("the subscriber and its pending request should remain");
	vsub = vlr_subscr_find_by_imsi(net->vlr, imsi);
	OSMO_ASSERT(vsub);
	VERBOSE_ASSERT(llist_count(&vsub->cs.requests), == 1, "%d");
	vlr_subscr_put(vsub);

	btw("MS replies with Paging Response, and VLR sends Auth Request with third key");
	auth_request_sent = false;
	auth_request_expect_rand = "e7c03ba7cf0e2fde82b2dc4d63077d42";
	ms_sends_msg("06270703305882089910070000006402");
	VERBOSE_ASSERT(auth_request_sent, == true, "%d");

	btw("needs auth, not yet accepted");
	EXPECT_ACCEPTED(false);
	thwart_rx_non_initial_requests();

	btw("MS sends Authen Response, VLR accepts and requests Ciphering");
	cipher_mode_cmd_sent = false;
	ms_sends_msg("0554" "a29514ae" /* 3rd vector's sres, s.a. */);
	VERBOSE_ASSERT(cipher_mode_cmd_sent, == true, "%d");

	btw("needs ciph, not yet accepted");
	EXPECT_ACCEPTED(false);
	thwart_rx_non_initial_requests();

	btw("MS sends Ciphering Mode Complete, VLR accepts and sends pending SMS");
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
	ms_sends_msg("0632");
	VERBOSE_ASSERT(dtap_tx_confirmed, == true, "%d");
	VERBOSE_ASSERT(paging_stopped, == true, "%d");

	btw("SMS was delivered, no requests pending for subscr");
	vsub = vlr_subscr_find_by_imsi(net->vlr, imsi);
	OSMO_ASSERT(vsub);
	VERBOSE_ASSERT(llist_count(&vsub->cs.requests), == 0, "%d");
	vlr_subscr_put(vsub);

	btw("conn is still open to wait for SMS ack dance");
	EXPECT_CONN_COUNT(1);

	btw("MS replies with CP-ACK for received SMS");
	ms_sends_msg("8904");
	EXPECT_CONN_COUNT(1);

	btw("MS also sends RP-ACK, MSC in turn sends CP-ACK for that");
	dtap_expect_tx("0904");
	ms_sends_msg("890106020041020000");
	VERBOSE_ASSERT(dtap_tx_confirmed, == true, "%d");

	btw("SMS is done, conn is gone");
	EXPECT_CONN_COUNT(0);

	BTW("subscriber detaches");
	ms_sends_msg("050130089910070000006402");

	EXPECT_CONN_COUNT(0);
	clear_vlr();
	comment_end();
}

void test_ciph_tmsi()
{
	struct vlr_subscr *vsub;
	const char *imsi = "901700000004620";

	comment_start();

	/* implicit: net->authentication_required = true; */
	net->a5_encryption = VLR_CIPH_A5_1;
	net->vlr->cfg.assign_tmsi = true;

	btw("Location Update request causes a GSUP Send Auth Info request to HLR");
	lu_result_sent = RES_NONE;
	gsup_expect_tx("08010809710000004026f0");
	ms_sends_msg("050802008168000130089910070000006402");
	OSMO_ASSERT(gsup_tx_confirmed);
	VERBOSE_ASSERT(lu_result_sent, == RES_NONE, "%d");

	btw("from HLR, rx _SEND_AUTH_INFO_RESULT; VLR sends Auth Req to MS");
	/* Based on a Ki of 000102030405060708090a0b0c0d0e0f */
	auth_request_sent = false;
	auth_request_expect_rand = "585df1ae287f6e273dce07090d61320b";
	auth_request_expect_autn = NULL;
	gsup_rx("0a"
		/* imsi */
		"0108" "09710000004026f0"
		/* 5 auth vectors... */
		/* TL    TL     rand */
		"0322"  "2010" "585df1ae287f6e273dce07090d61320b"
		/*       TL     sres       TL     kc */
			"2104" "2d8b2c3e" "2208" "61855fb81fc2a800"
		"0322"  "2010" "12aca96fb4ffdea5c985cbafa9b6e18b"
			"2104" "20bde240" "2208" "07fa7502e07e1c00"
		"0322"  "2010" "e7c03ba7cf0e2fde82b2dc4d63077d42"
			"2104" "a29514ae" "2208" "e2b234f807886400"
		"0322"  "2010" "fa8f20b781b5881329d4fea26b1a3c51"
			"2104" "5afc8d72" "2208" "2392f14f709ae000"
		"0322"  "2010" "0fd4cc8dbe8715d1f439e304edfd68dc"
			"2104" "bc8d1c5b" "2208" "da7cdd6bfe2d7000",
		NULL);
	VERBOSE_ASSERT(auth_request_sent, == true, "%d");
	VERBOSE_ASSERT(lu_result_sent, == RES_NONE, "%d");

	btw("MS sends Authen Response, VLR accepts and sends Ciphering Mode Command to MS");
	cipher_mode_cmd_sent = false;
	ms_sends_msg("05542d8b2c3e");
	OSMO_ASSERT(cipher_mode_cmd_sent);
	VERBOSE_ASSERT(lu_result_sent, == RES_NONE, "%d");
	VERBOSE_ASSERT(auth_request_sent, == true, "%d");

	btw("needs ciph, not yet accepted");
	EXPECT_ACCEPTED(false);
	thwart_rx_non_initial_requests();
	VERBOSE_ASSERT(lu_result_sent, == RES_NONE, "%d");

	btw("MS sends Ciphering Mode Complete, VLR accepts and sends GSUP LU Req to HLR");
	gsup_expect_tx("04010809710000004026f0");
	ms_sends_msg("0632");
	VERBOSE_ASSERT(lu_result_sent, == RES_NONE, "%d");

	btw("HLR sends _INSERT_DATA_REQUEST, VLR responds with _INSERT_DATA_RESULT");
	gsup_rx("10010809710000004026f00804036470f1",
		"12010809710000004026f0");
	VERBOSE_ASSERT(lu_result_sent, == RES_NONE, "%d");

	btw("HLR also sends GSUP _UPDATE_LOCATION_RESULT");
	gsup_rx("06010809710000004026f0", NULL);

	btw("a LU Accept with a new TMSI was sent, waiting for TMSI Realloc Compl");
	EXPECT_CONN_COUNT(1);
	VERBOSE_ASSERT(lu_result_sent, == RES_ACCEPT, "%d");
	EXPECT_ACCEPTED(false);
	thwart_rx_non_initial_requests();

	btw("even though the TMSI is not acked, we can already find the subscr with it");
	vsub = vlr_subscr_find_by_tmsi(net->vlr, 0x03020100);
	VERBOSE_ASSERT(vsub != NULL, == true, "%d");
	VERBOSE_ASSERT(strcmp(vsub->imsi, imsi), == 0, "%d");
	VERBOSE_ASSERT(vsub->tmsi_new, == 0x03020100, "0x%08x");
	VERBOSE_ASSERT(vsub->tmsi, == GSM_RESERVED_TMSI, "0x%08x");
	vlr_subscr_put(vsub);

	btw("MS sends TMSI Realloc Complete");
	ms_sends_msg("055b");

	btw("LU was successful, and the conn has already been closed");
	EXPECT_CONN_COUNT(0);

	btw("Subscriber has the new TMSI");
	vsub = vlr_subscr_find_by_imsi(net->vlr, imsi);
	VERBOSE_ASSERT(vsub != NULL, == true, "%d");
	VERBOSE_ASSERT(strcmp(vsub->imsi, imsi), == 0, "%d");
	VERBOSE_ASSERT(vsub->tmsi_new, == GSM_RESERVED_TMSI, "0x%08x");
	VERBOSE_ASSERT(vsub->tmsi, == 0x03020100, "0x%08x");
	vlr_subscr_put(vsub);

	BTW("after a while, a new conn sends a CM Service Request using above TMSI. VLR responds with Auth Req, 2nd auth vector");
	cm_service_result_sent = RES_NONE;
	auth_request_sent = false;
	auth_request_expect_rand = "12aca96fb4ffdea5c985cbafa9b6e18b";
	auth_request_expect_autn = NULL;
	ms_sends_msg("05247803305886" "05f4" "03020100");
	OSMO_ASSERT(g_conn);
	OSMO_ASSERT(g_conn->conn_fsm);
	OSMO_ASSERT(g_conn->vsub);
	VERBOSE_ASSERT(auth_request_sent, == true, "%d");
	VERBOSE_ASSERT(cm_service_result_sent, == RES_NONE, "%d");

	btw("needs auth, not yet accepted");
	EXPECT_ACCEPTED(false);
	thwart_rx_non_initial_requests();

	btw("MS sends Authen Response, VLR accepts and requests Ciphering");
	cipher_mode_cmd_sent = false;
	ms_sends_msg("0554" "20bde240" /* 2nd vector's sres, s.a. */);
	VERBOSE_ASSERT(cm_service_result_sent, == RES_NONE, "%d");
	VERBOSE_ASSERT(cipher_mode_cmd_sent, == true, "%d");

	btw("needs ciph, not yet accepted");
	EXPECT_ACCEPTED(false);
	thwart_rx_non_initial_requests();

	btw("MS sends Ciphering Mode Complete, VLR accepts; above Ciphering is an implicit CM Service Accept");
	ms_sends_msg("0632");
	VERBOSE_ASSERT(cm_service_result_sent, == RES_NONE, "%d");

	btw("a USSD request is serviced");
	dtap_expect_tx_ussd("Your extension is 46071\r");
	ms_sends_msg("0b3b1c15a11302010002013b300b04010f0406aa510c061b017f0100");
	OSMO_ASSERT(dtap_tx_confirmed);

	btw("all requests serviced, conn has been released");
	EXPECT_CONN_COUNT(0);

	BTW("an SMS is sent, MS is paged");
	paging_expect_tmsi(0x03020100);
	paging_sent = false;
	vsub = vlr_subscr_find_by_tmsi(net->vlr, 0x03020100);
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

	btw("the subscriber and its pending request should remain");
	vsub = vlr_subscr_find_by_imsi(net->vlr, imsi);
	OSMO_ASSERT(vsub);
	VERBOSE_ASSERT(llist_count(&vsub->cs.requests), == 1, "%d");
	vlr_subscr_put(vsub);

	btw("MS replies with Paging Response using TMSI, and VLR sends Auth Request with third key");
	auth_request_sent = false;
	auth_request_expect_rand = "e7c03ba7cf0e2fde82b2dc4d63077d42";
	ms_sends_msg("06270703305882" "05f4" "03020100");
	VERBOSE_ASSERT(auth_request_sent, == true, "%d");

	btw("needs auth, not yet accepted");
	EXPECT_ACCEPTED(false);
	thwart_rx_non_initial_requests();

	btw("MS sends Authen Response, VLR accepts and requests Ciphering");
	cipher_mode_cmd_sent = false;
	ms_sends_msg("0554" "a29514ae" /* 3rd vector's sres, s.a. */);
	VERBOSE_ASSERT(cipher_mode_cmd_sent, == true, "%d");

	btw("needs ciph, not yet accepted");
	EXPECT_ACCEPTED(false);
	thwart_rx_non_initial_requests();

	btw("MS sends Ciphering Mode Complete, VLR accepts and sends pending SMS");
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
	ms_sends_msg("0632");
	VERBOSE_ASSERT(dtap_tx_confirmed, == true, "%d");
	VERBOSE_ASSERT(paging_stopped, == true, "%d");

	btw("SMS was delivered, no requests pending for subscr");
	vsub = vlr_subscr_find_by_imsi(net->vlr, imsi);
	OSMO_ASSERT(vsub);
	VERBOSE_ASSERT(llist_count(&vsub->cs.requests), == 0, "%d");
	vlr_subscr_put(vsub);

	btw("conn is still open to wait for SMS ack dance");
	EXPECT_CONN_COUNT(1);

	btw("MS replies with CP-ACK for received SMS");
	ms_sends_msg("8904");
	EXPECT_CONN_COUNT(1);

	btw("MS also sends RP-ACK, MSC in turn sends CP-ACK for that");
	dtap_expect_tx("0904");
	ms_sends_msg("890106020041020000");
	VERBOSE_ASSERT(dtap_tx_confirmed, == true, "%d");

	btw("SMS is done, conn is gone");
	EXPECT_CONN_COUNT(0);

	BTW("subscriber detaches, using TMSI");
	ms_sends_msg("050130" "05f4" "03020100");

	EXPECT_CONN_COUNT(0);
	clear_vlr();
	comment_end();
}

void test_ciph_imei()
{
	struct vlr_subscr *vsub;
	const char *imsi = "901700000004620";

	comment_start();

	/* implicit: net->authentication_required = true; */
	net->a5_encryption = VLR_CIPH_A5_1;
	net->vlr->cfg.check_imei_rqd = true;

	btw("Location Update request causes a GSUP Send Auth Info request to HLR");
	lu_result_sent = RES_NONE;
	gsup_expect_tx("08010809710000004026f0");
	ms_sends_msg("050802008168000130089910070000006402");
	OSMO_ASSERT(gsup_tx_confirmed);
	VERBOSE_ASSERT(lu_result_sent, == RES_NONE, "%d");

	btw("from HLR, rx _SEND_AUTH_INFO_RESULT; VLR sends Auth Req to MS");
	/* Based on a Ki of 000102030405060708090a0b0c0d0e0f */
	auth_request_sent = false;
	auth_request_expect_rand = "585df1ae287f6e273dce07090d61320b";
	auth_request_expect_autn = NULL;
	gsup_rx("0a"
		/* imsi */
		"0108" "09710000004026f0"
		/* 5 auth vectors... */
		/* TL    TL     rand */
		"0322"  "2010" "585df1ae287f6e273dce07090d61320b"
		/*       TL     sres       TL     kc */
			"2104" "2d8b2c3e" "2208" "61855fb81fc2a800"
		"0322"  "2010" "12aca96fb4ffdea5c985cbafa9b6e18b"
			"2104" "20bde240" "2208" "07fa7502e07e1c00"
		"0322"  "2010" "e7c03ba7cf0e2fde82b2dc4d63077d42"
			"2104" "a29514ae" "2208" "e2b234f807886400"
		"0322"  "2010" "fa8f20b781b5881329d4fea26b1a3c51"
			"2104" "5afc8d72" "2208" "2392f14f709ae000"
		"0322"  "2010" "0fd4cc8dbe8715d1f439e304edfd68dc"
			"2104" "bc8d1c5b" "2208" "da7cdd6bfe2d7000",
		NULL);
	VERBOSE_ASSERT(auth_request_sent, == true, "%d");
	VERBOSE_ASSERT(lu_result_sent, == RES_NONE, "%d");

	btw("MS sends Authen Response, VLR accepts and sends Ciphering Mode Command to MS");
	cipher_mode_cmd_sent = false;
	ms_sends_msg("05542d8b2c3e");
	OSMO_ASSERT(cipher_mode_cmd_sent);
	VERBOSE_ASSERT(lu_result_sent, == RES_NONE, "%d");

	btw("needs ciph, not yet accepted");
	EXPECT_ACCEPTED(false);
	thwart_rx_non_initial_requests();
	VERBOSE_ASSERT(lu_result_sent, == RES_NONE, "%d");

	btw("MS sends Ciphering Mode Complete, VLR accepts and sends GSUP LU Req to HLR");
	gsup_expect_tx("04010809710000004026f0");
	ms_sends_msg("0632");
	VERBOSE_ASSERT(lu_result_sent, == RES_NONE, "%d");

	btw("HLR sends _INSERT_DATA_REQUEST, VLR responds with _INSERT_DATA_RESULT");
	gsup_rx("10010809710000004026f00804036470f1",
		"12010809710000004026f0");
	VERBOSE_ASSERT(lu_result_sent, == RES_NONE, "%d");

	btw("HLR also sends GSUP _UPDATE_LOCATION_RESULT, and we send an ID Request for the IMEI to the MS");
	dtap_expect_tx("051802");
	gsup_rx("06010809710000004026f0", NULL);

	btw("We will only do business when the IMEI is known");
	EXPECT_CONN_COUNT(1);
	vsub = vlr_subscr_find_by_imsi(net->vlr, imsi);
	OSMO_ASSERT(vsub);
	VERBOSE_ASSERT(vsub->imei[0], == 0, "%d");
	vlr_subscr_put(vsub);
	EXPECT_ACCEPTED(false);
	thwart_rx_non_initial_requests();

	btw("MS replies with an Identity Response");
	ms_sends_msg("0559084a32244332244332");

	btw("LU was successful, and the conn has already been closed");
	VERBOSE_ASSERT(lu_result_sent, == RES_ACCEPT, "%d");
	EXPECT_CONN_COUNT(0);

	btw("Subscriber has the IMEI");
	vsub = vlr_subscr_find_by_imsi(net->vlr, imsi);
	OSMO_ASSERT(vsub);
	VERBOSE_ASSERT(strcmp(vsub->imei, "423423423423423"), == 0, "%d");
	vlr_subscr_put(vsub);

	BTW("subscriber detaches");
	ms_sends_msg("050130089910070000006402");

	EXPECT_CONN_COUNT(0);
	clear_vlr();
	comment_end();
}

void test_ciph_imeisv()
{
	struct vlr_subscr *vsub;
	const char *imsi = "901700000004620";

	comment_start();

	/* implicit: net->authentication_required = true; */
	net->a5_encryption = VLR_CIPH_A5_1;
	net->vlr->cfg.retrieve_imeisv = true;

	btw("Location Update request causes a GSUP Send Auth Info request to HLR");
	lu_result_sent = RES_NONE;
	gsup_expect_tx("08010809710000004026f0");
	ms_sends_msg("050802008168000130089910070000006402");
	OSMO_ASSERT(gsup_tx_confirmed);
	VERBOSE_ASSERT(lu_result_sent, == RES_NONE, "%d");

	btw("from HLR, rx _SEND_AUTH_INFO_RESULT; VLR sends Auth Req to MS");
	/* Based on a Ki of 000102030405060708090a0b0c0d0e0f */
	auth_request_sent = false;
	auth_request_expect_rand = "585df1ae287f6e273dce07090d61320b";
	auth_request_expect_autn = NULL;
	gsup_rx("0a"
		/* imsi */
		"0108" "09710000004026f0"
		/* 5 auth vectors... */
		/* TL    TL     rand */
		"0322"  "2010" "585df1ae287f6e273dce07090d61320b"
		/*       TL     sres       TL     kc */
			"2104" "2d8b2c3e" "2208" "61855fb81fc2a800"
		"0322"  "2010" "12aca96fb4ffdea5c985cbafa9b6e18b"
			"2104" "20bde240" "2208" "07fa7502e07e1c00"
		"0322"  "2010" "e7c03ba7cf0e2fde82b2dc4d63077d42"
			"2104" "a29514ae" "2208" "e2b234f807886400"
		"0322"  "2010" "fa8f20b781b5881329d4fea26b1a3c51"
			"2104" "5afc8d72" "2208" "2392f14f709ae000"
		"0322"  "2010" "0fd4cc8dbe8715d1f439e304edfd68dc"
			"2104" "bc8d1c5b" "2208" "da7cdd6bfe2d7000",
		NULL);
	VERBOSE_ASSERT(auth_request_sent, == true, "%d");
	VERBOSE_ASSERT(lu_result_sent, == RES_NONE, "%d");

	btw("MS sends Authen Response, VLR accepts and sends Ciphering Mode Command to MS");
	cipher_mode_cmd_sent = false;
	ms_sends_msg("05542d8b2c3e");
	VERBOSE_ASSERT(cipher_mode_cmd_sent, == true, "%d");
	VERBOSE_ASSERT(cipher_mode_cmd_sent_with_imeisv, == true, "%d");
	VERBOSE_ASSERT(lu_result_sent, == RES_NONE, "%d");

	btw("needs ciph, not yet accepted");
	EXPECT_ACCEPTED(false);
	thwart_rx_non_initial_requests();
	VERBOSE_ASSERT(lu_result_sent, == RES_NONE, "%d");

	vsub = vlr_subscr_find_by_imsi(net->vlr, imsi);
	OSMO_ASSERT(vsub);
	VERBOSE_ASSERT(vsub->imeisv[0], == 0, "%d");
	vlr_subscr_put(vsub);

	btw("MS sends Ciphering Mode Complete with IMEISV, VLR accepts and sends GSUP LU Req to HLR");
	gsup_expect_tx("04010809710000004026f0");
	ms_sends_msg("063217094b32244332244332f5");
	VERBOSE_ASSERT(lu_result_sent, == RES_NONE, "%d");

	btw("Subscriber has the IMEISV");
	vsub = vlr_subscr_find_by_imsi(net->vlr, imsi);
	OSMO_ASSERT(vsub);
	VERBOSE_ASSERT(strcmp(vsub->imeisv, "4234234234234235"), == 0, "%d");
	vlr_subscr_put(vsub);

	EXPECT_ACCEPTED(false);
	thwart_rx_non_initial_requests();

	btw("MS replies with an Identity Response");
	ms_sends_msg("0559084a32244332244332");

	btw("HLR sends _INSERT_DATA_REQUEST, VLR responds with _INSERT_DATA_RESULT");
	gsup_rx("10010809710000004026f00804036470f1",
		"12010809710000004026f0");
	VERBOSE_ASSERT(lu_result_sent, == RES_NONE, "%d");

	btw("HLR also sends GSUP _UPDATE_LOCATION_RESULT");
	gsup_rx("06010809710000004026f0", NULL);

	btw("LU was successful, and the conn has already been closed");
	VERBOSE_ASSERT(lu_result_sent, == RES_ACCEPT, "%d");
	EXPECT_CONN_COUNT(0);

	BTW("subscriber detaches");
	ms_sends_msg("050130089910070000006402");

	EXPECT_CONN_COUNT(0);
	clear_vlr();
	comment_end();
}

void test_ciph_tmsi_imei()
{
	struct vlr_subscr *vsub;
	const char *imsi = "901700000004620";

	comment_start();

	/* implicit: net->authentication_required = true; */
	net->a5_encryption = VLR_CIPH_A5_1;
	net->vlr->cfg.assign_tmsi = true;
	net->vlr->cfg.check_imei_rqd = true;

	btw("Location Update request causes a GSUP Send Auth Info request to HLR");
	lu_result_sent = RES_NONE;
	gsup_expect_tx("08010809710000004026f0");
	ms_sends_msg("050802008168000130089910070000006402");
	OSMO_ASSERT(gsup_tx_confirmed);
	VERBOSE_ASSERT(lu_result_sent, == RES_NONE, "%d");

	btw("from HLR, rx _SEND_AUTH_INFO_RESULT; VLR sends Auth Req to MS");
	/* Based on a Ki of 000102030405060708090a0b0c0d0e0f */
	auth_request_sent = false;
	auth_request_expect_rand = "585df1ae287f6e273dce07090d61320b";
	auth_request_expect_autn = NULL;
	gsup_rx("0a"
		/* imsi */
		"0108" "09710000004026f0"
		/* 5 auth vectors... */
		/* TL    TL     rand */
		"0322"  "2010" "585df1ae287f6e273dce07090d61320b"
		/*       TL     sres       TL     kc */
			"2104" "2d8b2c3e" "2208" "61855fb81fc2a800"
		"0322"  "2010" "12aca96fb4ffdea5c985cbafa9b6e18b"
			"2104" "20bde240" "2208" "07fa7502e07e1c00"
		"0322"  "2010" "e7c03ba7cf0e2fde82b2dc4d63077d42"
			"2104" "a29514ae" "2208" "e2b234f807886400"
		"0322"  "2010" "fa8f20b781b5881329d4fea26b1a3c51"
			"2104" "5afc8d72" "2208" "2392f14f709ae000"
		"0322"  "2010" "0fd4cc8dbe8715d1f439e304edfd68dc"
			"2104" "bc8d1c5b" "2208" "da7cdd6bfe2d7000",
		NULL);
	VERBOSE_ASSERT(auth_request_sent, == true, "%d");
	VERBOSE_ASSERT(lu_result_sent, == RES_NONE, "%d");

	btw("MS sends Authen Response, VLR accepts and sends Ciphering Mode Command to MS");
	cipher_mode_cmd_sent = false;
	ms_sends_msg("05542d8b2c3e");
	OSMO_ASSERT(cipher_mode_cmd_sent);
	VERBOSE_ASSERT(lu_result_sent, == RES_NONE, "%d");

	btw("needs ciph, not yet accepted");
	EXPECT_ACCEPTED(false);
	thwart_rx_non_initial_requests();
	VERBOSE_ASSERT(lu_result_sent, == RES_NONE, "%d");

	btw("MS sends Ciphering Mode Complete, VLR accepts and sends GSUP LU Req to HLR");
	gsup_expect_tx("04010809710000004026f0");
	ms_sends_msg("0632");
	VERBOSE_ASSERT(lu_result_sent, == RES_NONE, "%d");

	btw("HLR sends _INSERT_DATA_REQUEST, VLR responds with _INSERT_DATA_RESULT");
	gsup_rx("10010809710000004026f00804036470f1",
		"12010809710000004026f0");
	VERBOSE_ASSERT(lu_result_sent, == RES_NONE, "%d");

	btw("HLR also sends GSUP _UPDATE_LOCATION_RESULT, and we send an ID Request for the IMEI to the MS");
	dtap_expect_tx("051802");
	gsup_rx("06010809710000004026f0", NULL);

	btw("We will only do business when the IMEI is known");
	EXPECT_CONN_COUNT(1);
	vsub = vlr_subscr_find_by_imsi(net->vlr, imsi);
	OSMO_ASSERT(vsub);
	VERBOSE_ASSERT(vsub->imei[0], == 0, "%d");
	vlr_subscr_put(vsub);
	EXPECT_ACCEPTED(false);
	thwart_rx_non_initial_requests();

	btw("MS replies with an Identity Response");
	ms_sends_msg("0559084a32244332244332");

	btw("a LU Accept with a new TMSI was sent, waiting for TMSI Realloc Compl");
	EXPECT_CONN_COUNT(1);
	VERBOSE_ASSERT(lu_result_sent, == RES_ACCEPT, "%d");
	EXPECT_ACCEPTED(false);
	thwart_rx_non_initial_requests();

	btw("even though the TMSI is not acked, we can already find the subscr with it");
	vsub = vlr_subscr_find_by_tmsi(net->vlr, 0x03020100);
	VERBOSE_ASSERT(vsub != NULL, == true, "%d");
	VERBOSE_ASSERT(strcmp(vsub->imsi, imsi), == 0, "%d");
	VERBOSE_ASSERT(vsub->tmsi_new, == 0x03020100, "0x%08x");
	VERBOSE_ASSERT(vsub->tmsi, == GSM_RESERVED_TMSI, "0x%08x");
	vlr_subscr_put(vsub);

	btw("MS sends TMSI Realloc Complete");
	ms_sends_msg("055b");

	btw("LU was successful, and the conn has already been closed");
	EXPECT_CONN_COUNT(0);

	btw("Subscriber has the IMEI and TMSI");
	vsub = vlr_subscr_find_by_imsi(net->vlr, imsi);
	OSMO_ASSERT(vsub);
	VERBOSE_ASSERT(strcmp(vsub->imei, "423423423423423"), == 0, "%d");
	VERBOSE_ASSERT(vsub->tmsi, == 0x03020100, "0x%08x");
	vlr_subscr_put(vsub);

	BTW("subscriber detaches, using TMSI");
	ms_sends_msg("050130" "05f4" "03020100");

	EXPECT_CONN_COUNT(0);
	clear_vlr();
	comment_end();
}

void test_lu_unknown_tmsi()
{
	comment_start();

	btw("Location Update request with unknown TMSI sends ID Request for IMSI");
	lu_result_sent = RES_NONE;
	dtap_expect_tx("051801");
	ms_sends_msg("050802008168000130" "05f4" "23422342");
	VERBOSE_ASSERT(lu_result_sent, == RES_NONE, "%d");

	EXPECT_ACCEPTED(false);
	thwart_rx_non_initial_requests();

	btw("MS tells us the IMSI, causes a GSUP LU request to HLR");
	gsup_expect_tx("04010809710000004026f0");
	ms_sends_msg("0559089910070000006402");
	OSMO_ASSERT(gsup_tx_confirmed);
	VERBOSE_ASSERT(lu_result_sent, == RES_NONE, "%d");

	btw("HLR sends _INSERT_DATA_REQUEST, VLR responds with _INSERT_DATA_RESULT");
	gsup_rx("10010809710000004026f00804036470f1",
		"12010809710000004026f0");
	VERBOSE_ASSERT(lu_result_sent, == RES_NONE, "%d");

	btw("having received subscriber data does not mean acceptance");
	EXPECT_ACCEPTED(false);
	thwart_rx_non_initial_requests();
	VERBOSE_ASSERT(lu_result_sent, == RES_NONE, "%d");

	btw("HLR also sends GSUP _UPDATE_LOCATION_RESULT");
	gsup_rx("06010809710000004026f0", NULL);

	btw("LU was successful, and the conn has already been closed");
	VERBOSE_ASSERT(lu_result_sent, == RES_ACCEPT, "%d");
	EXPECT_CONN_COUNT(0);
	clear_vlr();
	comment_end();
}

msc_vlr_test_func_t msc_vlr_tests[] = {
	test_ciph,
	test_ciph_tmsi,
	test_ciph_imei,
	test_ciph_imeisv,
	test_ciph_tmsi_imei,
	NULL
};
