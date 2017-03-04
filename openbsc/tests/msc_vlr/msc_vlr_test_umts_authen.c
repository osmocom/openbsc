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

void _test_umts_authen(enum ran_type via_ran)
{
	struct vlr_subscr *vsub;
	const char *imsi = "901700000010650";

	net->authentication_required = true;
	rx_from_ran = via_ran;

	btw("Location Update request causes a GSUP Send Auth Info request to HLR");
	lu_result_sent = RES_NONE;
	gsup_expect_tx("080108" "09710000000156f0");
	ms_sends_msg("0508" /* MM LU */
		     "7" /* ciph key seq: no key available */
		     "0" /* LU type: normal */
		     "ffffff" "0000" /* LAI, LAC */
		     "57" /* classmark 1: R99, early classmark, no power lvl */
		     "089910070000106005" /* IMSI */
		     "3303575886" /* classmark 2 */
		     );
	OSMO_ASSERT(gsup_tx_confirmed);
	VERBOSE_ASSERT(lu_result_sent, == RES_NONE, "%d");

	btw("from HLR, rx _SEND_AUTH_INFO_RESULT; VLR sends Auth Req to MS");
	/* based on auc_3g:
	 * K = 'EB215756028D60E3275E613320AEC880',
	 * OPC = 'FB2A3D1B360F599ABAB99DB8669F8308'
	 * SQN = 0
	 */
	auth_request_sent = false;
	auth_request_expect_rand = "39fa2f4e3d523d8619a73b4f65c3e14d";
	auth_request_expect_autn = "8704f5ba55f30000d2ee44b22c8ea919";
	gsup_rx("0a"
		/* imsi */
		"0108" "09710000000156f0"
		/* 5 auth vectors... */
		/* TL    TL     rand */
		"0362"  "2010" "39fa2f4e3d523d8619a73b4f65c3e14d"
		/*       TL     sres       TL     kc */
			"2104" "9b36efdf" "2208" "059a4f668f6fbe39"
		/*       TL     3G IK */
			"2310" "27497388b6cb044648f396aa155b95ef"
		/*       TL     3G CK */
			"2410" "f64735036e5871319c679f4742a75ea1"
		/*       TL     AUTN */
			"2510" "8704f5ba55f30000d2ee44b22c8ea919"
		/*       TL     RES */
			"2708" "e229c19e791f2e41"
		/* TL    TL     rand */
		"0362"  "2010" "c187a53a5e6b9d573cac7c74451fd46d"
			"2104" "85aa3130" "2208" "d3d50a000bf04f6e"
			"2310" "1159ec926a50e98c034a6b7d7c9f418d"
			"2410" "df3a03d9ca5335641efc8e36d76cd20b"
			"2510" "1843a645b98d00005b2d666af46c45d9"
			"2708" "7db47cf7f81e4dc7"
		"0362"  "2010" "efa9c29a9742148d5c9070348716e1bb"
			"2104" "69d5f9fb" "2208" "3df176f0c29f1a3d"
			"2310" "eb50e770ddcc3060101d2f43b6c2b884"
			"2410" "76542abce5ff9345b0e8947f4c6e019c"
			"2510" "f9375e6d41e1000096e7fe4ff1c27e39"
			"2708" "706f996719ba609c"
		"0362"  "2010" "f023d5a3b24726e0631b64b3840f8253"
			"2104" "d570c03f" "2208" "ec011be8919883d6"
			"2310" "c4e58af4ba43f3bcd904e16984f086d7"
			"2410" "0593f65e752e5cb7f473862bda05aa0a"
			"2510" "541ff1f077270000c5ea00d658bc7e9a"
			"2708" "3fd26072eaa2a04d"
		"0362"  "2010" "2f8f90c780d6a9c0c53da7ac57b6707e"
			"2104" "b072446f220823f39f9f425ad6e6"
			"2310" "65af0527fda95b0dc5ae4aa515cdf32f"
			"2410" "537c3b35a3b13b08d08eeb28098f45cc"
			"2510" "4bf4e564f75300009bc796706bc65744"
			"2708" "0edb0eadbea94ac2",
		NULL);
	VERBOSE_ASSERT(auth_request_sent, == true, "%d");
	VERBOSE_ASSERT(lu_result_sent, == RES_NONE, "%d");

	btw("MS sends Authen Response, VLR accepts and sends GSUP LU Req to HLR");
	gsup_expect_tx("04010809710000000156f0");
	ms_sends_msg("0554" "e229c19e" "2104" "791f2e41");
	VERBOSE_ASSERT(lu_result_sent, == RES_NONE, "%d");

	btw("HLR sends _INSERT_DATA_REQUEST, VLR responds with _INSERT_DATA_RESULT");
	gsup_rx("10010809710000000156f00804032443f2",
		"12010809710000000156f0");
	VERBOSE_ASSERT(lu_result_sent, == RES_NONE, "%d");

	btw("HLR also sends GSUP _UPDATE_LOCATION_RESULT");
	gsup_rx("06010809710000000156f0", NULL);

	btw("LU was successful, and the conn has already been closed");
	VERBOSE_ASSERT(lu_result_sent, == RES_ACCEPT, "%d");
	EXPECT_CONN_COUNT(0);

	BTW("after a while, a new conn sends a CM Service Request. VLR responds with Auth Req, 2nd auth vector");
	auth_request_sent = false;
	auth_request_expect_rand = "c187a53a5e6b9d573cac7c74451fd46d";
	auth_request_expect_autn = "1843a645b98d00005b2d666af46c45d9";
	cm_service_result_sent = RES_NONE;
	ms_sends_msg("052478"
		     "03575886" /* classmark 2 */
		     "089910070000106005" /* IMSI */);
	OSMO_ASSERT(g_conn);
	OSMO_ASSERT(g_conn->conn_fsm);
	OSMO_ASSERT(g_conn->vsub);
	VERBOSE_ASSERT(cm_service_result_sent, == RES_NONE, "%d");
	VERBOSE_ASSERT(auth_request_sent, == true, "%d");

	btw("needs auth, not yet accepted");
	EXPECT_ACCEPTED(false);
	thwart_rx_non_initial_requests();

	btw("MS sends Authen Response, VLR accepts with a CM Service Accept");
	gsup_expect_tx(NULL);
	ms_sends_msg("0554" "7db47cf7" "2104" "f81e4dc7"); /* 2nd vector's res, s.a. */
	VERBOSE_ASSERT(cm_service_result_sent, == RES_ACCEPT, "%d");

	btw("a USSD request is serviced");
	dtap_expect_tx_ussd("Your extension is 42342\r");
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
	auth_request_expect_rand = "efa9c29a9742148d5c9070348716e1bb";
	auth_request_expect_autn = "f9375e6d41e1000096e7fe4ff1c27e39";
	ms_sends_msg("062707"
		     "03575886" /* classmark 2 */
		     "089910070000106005" /* IMSI */);
	VERBOSE_ASSERT(auth_request_sent, == true, "%d");

	btw("needs auth, not yet accepted");
	EXPECT_ACCEPTED(false);
	thwart_rx_non_initial_requests();

	btw("MS sends Authen Response, VLR accepts and sends pending SMS");
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
		       "05802443f2" /* originating address 42342 */
		       "00" /* TP-PID */
		       "00" /* GSM default alphabet */
		       "071010" /* Y-M-D (from wrapped gsm340_gen_scts())*/
		       "000000" /* H-M-S */
		       "00" /* GMT+0 */
		       "44" /* data length */
		       "5079da1e1ee7416937485e9ea7c965373d1d6683c270383b3d0e"
		       "d3d36ff71c949e83c22072799e9687c5ec32a81d96afcbf4b4fb"
		       "0c7ac3e9e9b7db05");
	ms_sends_msg("0554" "706f9967" "2104" "19ba609c"); /* 3nd vector's res, s.a. */
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
	ms_sends_msg("050130"
		     "089910070000106005" /* IMSI */);

	EXPECT_CONN_COUNT(0);
	clear_vlr();
}

void test_umts_authen_geran()
{
	comment_start();
	_test_umts_authen(RAN_GERAN_A);
	comment_end();
}

void test_umts_authen_utran()
{
	comment_start();
	_test_umts_authen(RAN_UTRAN_IU);
	comment_end();
}

#define RECALC_AUTS 0

#if RECALC_AUTS
typedef uint8_t u8;
extern int milenage_f2345(const u8 *opc, const u8 *k, const u8 *_rand,
			  u8 *res, u8 *ck, u8 *ik, u8 *ak, u8 *akstar);
extern int milenage_f1(const u8 *opc, const u8 *k, const u8 *_rand,
		       const u8 *sqn, const u8 *amf, u8 *mac_a, u8 *mac_s);
#endif

void _test_umts_authen_resync(enum ran_type via_ran)
{
	net->authentication_required = true;
	rx_from_ran = via_ran;

	btw("Location Update request causes a GSUP Send Auth Info request to HLR");
	lu_result_sent = RES_NONE;
	gsup_expect_tx("080108" "09710000000156f0");
	ms_sends_msg("0508" /* MM LU */
		     "7" /* ciph key seq: no key available */
		     "0" /* LU type: normal */
		     "ffffff" "0000" /* LAI, LAC */
		     "57" /* classmark 1: R99, early classmark, no power lvl */
		     "089910070000106005" /* IMSI */
		     "3303575886" /* classmark 2 */
		     );
	OSMO_ASSERT(gsup_tx_confirmed);
	VERBOSE_ASSERT(lu_result_sent, == RES_NONE, "%d");

	btw("from HLR, rx _SEND_AUTH_INFO_RESULT; VLR sends Auth Req to MS");
	/* based on auc_3g:
	 * K = 'EB215756028D60E3275E613320AEC880',
	 * OPC = 'FB2A3D1B360F599ABAB99DB8669F8308'
	 * SQN = 0
	 */
	auth_request_sent = false;
	auth_request_expect_rand = "39fa2f4e3d523d8619a73b4f65c3e14d";
	auth_request_expect_autn = "8704f5ba55f30000d2ee44b22c8ea919";
	gsup_rx("0a"
		/* imsi */
		"0108" "09710000000156f0"
		/* auth vectors... */
		/* TL    TL     rand */
		"0362"  "2010" "39fa2f4e3d523d8619a73b4f65c3e14d"
		/*       TL     sres       TL     kc */
			"2104" "9b36efdf" "2208" "059a4f668f6fbe39"
		/*       TL     3G IK */
			"2310" "27497388b6cb044648f396aa155b95ef"
		/*       TL     3G CK */
			"2410" "f64735036e5871319c679f4742a75ea1"
		/*       TL     AUTN */
			"2510" "8704f5ba55f30000d2ee44b22c8ea919"
		/*       TL     RES */
			"2708" "e229c19e791f2e41"
		,NULL);
	VERBOSE_ASSERT(auth_request_sent, == true, "%d");
	VERBOSE_ASSERT(lu_result_sent, == RES_NONE, "%d");

	/* The AUTN sent was 8704f5ba55f30000d2ee44b22c8ea919
	 * (see expected error output)
	 * with the first 6 bytes being SQN ^ AK.
	 * K = EB215756028D60E3275E613320AEC880
	 * OPC = FB2A3D1B360F599ABAB99DB8669F8308
	 * RAND = 39fa2f4e3d523d8619a73b4f65c3e14d
	 * --milenage-f5-->
	 * AK = 8704f5ba55f3
	 *
	 * The first six bytes are 8704f5ba55f3,
	 * and 8704f5ba55f3 ^ AK = 0.
	 * --> SQN = 0.
	 *
	 * Say the USIM doesn't like that, let's say it is at SQN 23.
	 * SQN_MS = 000000000017
	 *
	 * AUTS = Conc(SQN_MS) || MAC-S
	 * Conc(SQN_MS) = SQN_MS ⊕ f5*[K](RAND)
	 * MAC-S = f1*[K] (SQN MS || RAND || AMF)
	 *
	 * f5*--> Conc(SQN_MS) = 000000000017 ^ 979498b1f73a
	 *                     = 979498b1f72d
	 * AMF = 0000 (TS 33.102 v7.0.0, 6.3.3)
	 *
	 * MAC-S = f1*[K] (000000000017 || 39fa2f4e3d523d8619a73b4f65c3e14d || 0000)
	 *       = 3e28c59fa2e72f9c
	 *
	 * AUTS = 979498b1f72d || 3e28c59fa2e72f9c
	 */
#if RECALC_AUTS
	uint8_t ak[6];
	uint8_t akstar[6];
	uint8_t opc[16];
	uint8_t k[16];
	uint8_t rand[16];
	osmo_hexparse("EB215756028D60E3275E613320AEC880", k, sizeof(k));
	osmo_hexparse("FB2A3D1B360F599ABAB99DB8669F8308", opc, sizeof(opc));
	osmo_hexparse("39fa2f4e3d523d8619a73b4f65c3e14d", rand, sizeof(rand));
	milenage_f2345(opc, k, rand, NULL, NULL, NULL, ak, akstar);
	btw("ak = %s", osmo_hexdump_nospc(ak, sizeof(ak)));
	btw("akstar = %s", osmo_hexdump_nospc(akstar, sizeof(akstar)));

	uint8_t sqn_ms[6] = { 0, 0, 0, 0, 0, 23 };
	uint8_t amf[2] = { 0 };
	uint8_t mac_s[8];
	milenage_f1(opc, k, rand, sqn_ms, amf, NULL, mac_s);
	btw("mac_s = %s", osmo_hexdump_nospc(mac_s, sizeof(mac_s)));
	/* verify valid AUTS resulting in SQN 23 with:
	   osmo-auc-gen -3 -a milenage -k EB215756028D60E3275E613320AEC880 \
	                -o FB2A3D1B360F599ABAB99DB8669F8308 \
	                -r 39fa2f4e3d523d8619a73b4f65c3e14d \
	                -A 979498b1f72d3e28c59fa2e72f9c
	 */
#endif

	btw("MS sends Authen Failure with Resync cause, VLR sends GSUP to HLR to resync");
	auth_request_sent = false;
	gsup_expect_tx("08" /* OSMO_GSUP_MSGT_SEND_AUTH_INFO_REQUEST */
		       "0108" "09710000000156f0" /* IMSI */
		       "260e" "979498b1f72d3e28c59fa2e72f9c" /* AUTS */
		       "2010" "39fa2f4e3d523d8619a73b4f65c3e14d" /* RAND */);
	ms_sends_msg("051c" /* 05 = MM; 1c = Auth Failure */
		     "15"   /* cause = Synch Failure */
		     "220e" "979498b1f72d3e28c59fa2e72f9c" /* AUTS */);
	VERBOSE_ASSERT(gsup_tx_confirmed, == true, "%d");
	VERBOSE_ASSERT(auth_request_sent, == false, "%d");
	VERBOSE_ASSERT(lu_result_sent, == RES_NONE, "%d");

	btw("HLR replies with new tuples");
	auth_request_sent = false;
	auth_request_expect_rand = "0f1feb1623e1bf626334e37ec448ac18";
	auth_request_expect_autn = "02a83f62e9470000660d51afc75f169d";
	gsup_rx("0a"
		/* imsi */
		"0108" "09710000000156f0"
		/* 1 auth vector */
		/* TL    TL     rand */
		"0362"  "2010" "0f1feb1623e1bf626334e37ec448ac18"
		/*       TL     sres       TL     kc */
			"2104" "efde99da" "2208" "14778c855c523730"
		/*       TL     3G IK */
			"2310" "8a90c769b7272f3bb7a1c1fbb1ea9349"
		/*       TL     3G CK */
			"2410" "43ffc1cf8c89a7fd6ab94bd8d6162cbf"
		/*       TL     AUTN */
			"2510" "02a83f62e9470000660d51afc75f169d"
		/*       TL     RES */
			"2708" "1df5f0b4f22b696e"
		/* TL    TL     rand */
		"0362"  "2010" "ac21d34937b4e1142a2c757af2949319"
		/*       TL     sres       TL     kc */
			"2104" "7818bfdc" "2208" "d175571f41f314a4"
		/*       TL     3G IK */
			"2310" "ff8edbceb6dd24799c77c3b9a6790c10"
		/*       TL     3G CK */
			"2410" "157c39022ca9d885a7f0766a7dfee448"
		/*       TL     AUTN */
			"2510" "8a43b91898e500002cf354c6f5d1f8c3"
		/*       TL     RES */
			"2708" "f748a7078f5018db"
		,NULL);

	VERBOSE_ASSERT(auth_request_sent, == true, "%d");
	VERBOSE_ASSERT(lu_result_sent, == RES_NONE, "%d");

	btw("MS sends Authen Response, VLR accepts and sends GSUP LU Req to HLR");
	gsup_expect_tx("04010809710000000156f0");
	ms_sends_msg("0554" "1df5f0b4" "2104" "f22b696e");
	VERBOSE_ASSERT(lu_result_sent, == RES_NONE, "%d");

	btw("HLR sends _INSERT_DATA_REQUEST, VLR responds with _INSERT_DATA_RESULT");
	gsup_rx("10010809710000000156f00804032443f2",
		"12010809710000000156f0");
	VERBOSE_ASSERT(lu_result_sent, == RES_NONE, "%d");

	btw("HLR also sends GSUP _UPDATE_LOCATION_RESULT");
	gsup_rx("06010809710000000156f0", NULL);

	btw("LU was successful, and the conn has already been closed");
	VERBOSE_ASSERT(lu_result_sent, == RES_ACCEPT, "%d");
	EXPECT_CONN_COUNT(0);

	clear_vlr();
}

void test_umts_authen_resync_geran()
{
	comment_start();
	_test_umts_authen_resync(RAN_GERAN_A);
	comment_end();
}

void test_umts_authen_resync_utran()
{
	comment_start();
	_test_umts_authen_resync(RAN_UTRAN_IU);
	comment_end();
}

msc_vlr_test_func_t msc_vlr_tests[] = {
	test_umts_authen_geran,
	test_umts_authen_utran,
	test_umts_authen_resync_geran,
	test_umts_authen_resync_utran,
	NULL
};
