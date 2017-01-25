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

void test_hlr_rej_auth_info_unknown_imsi()
{
	comment_start();

	net->authentication_required = true;

	btw("Location Update request causes a GSUP Send Auth Info request to HLR");
	lu_result_sent = RES_NONE;
	gsup_expect_tx("08010809710000004026f0");
	ms_sends_msg("050802008168000130089910070000006402");
	OSMO_ASSERT(gsup_tx_confirmed);
	VERBOSE_ASSERT(lu_result_sent, == RES_NONE, "%d");

	btw("HLR sends _SEND_AUTH_INFO_ERROR = unknown IMSI");
	auth_request_sent = false;
	gsup_rx("09" "010809710000004026f0" "020102", NULL);
	VERBOSE_ASSERT(auth_request_sent, == false, "%d");
	VERBOSE_ASSERT(lu_result_sent, == RES_REJECT, "%d");

	EXPECT_CONN_COUNT(0);
	clear_vlr();
	comment_end();
}

void test_hlr_rej_auth_info_net_fail()
{
	comment_start();

	net->authentication_required = true;

	btw("Location Update request causes a GSUP Send Auth Info request to HLR");
	lu_result_sent = RES_NONE;
	gsup_expect_tx("08010809710000004026f0");
	ms_sends_msg("050802008168000130089910070000006402");
	OSMO_ASSERT(gsup_tx_confirmed);
	VERBOSE_ASSERT(lu_result_sent, == RES_NONE, "%d");

	btw("HLR sends _SEND_AUTH_INFO_ERROR = net fail");
	auth_request_sent = false;
	gsup_rx("09" "010809710000004026f0" "020111", NULL);
	VERBOSE_ASSERT(auth_request_sent, == false, "%d");
	VERBOSE_ASSERT(lu_result_sent, == RES_REJECT, "%d");

	EXPECT_CONN_COUNT(0);
	clear_vlr();
	comment_end();
}

void test_hlr_rej_auth_info_net_fail_no_reuse_tuples()
{
	struct vlr_subscr *vsub;
	const char *imsi = "901700000004620";

	comment_start();

	net->authentication_required = true;
	net->vlr->cfg.auth_reuse_old_sets_on_error = false;
	net->vlr->cfg.auth_tuple_max_use_count = 0;

	BTW("Submit a used auth tuple in the VLR");
	btw("Location Update request causes a GSUP Send Auth Info request to HLR");
	lu_result_sent = RES_NONE;
	gsup_expect_tx("08010809710000004026f0");
	ms_sends_msg("050802008168000130089910070000006402");
	OSMO_ASSERT(gsup_tx_confirmed);
	VERBOSE_ASSERT(lu_result_sent, == RES_NONE, "%d");

	btw("from HLR, rx _SEND_AUTH_INFO_RESULT; VLR sends Auth Req to MS");
	auth_request_sent = false;
	auth_request_expect_rand = "585df1ae287f6e273dce07090d61320b";
	auth_request_expect_autn = NULL;
	/* Based on a Ki of 000102030405060708090a0b0c0d0e0f */
	gsup_rx("0a"
		/* imsi */
		"0108" "09710000004026f0"
		/* auth vectors... */
		/* TL    TL     rand */
		"0322"  "2010" "585df1ae287f6e273dce07090d61320b"
		/*       TL     sres       TL     kc */
			"2104" "2d8b2c3e" "2208" "61855fb81fc2a800"
		,NULL);
	VERBOSE_ASSERT(auth_request_sent, == true, "%d");
	VERBOSE_ASSERT(lu_result_sent, == RES_NONE, "%d");

	btw("MS sends Authen Response, VLR accepts and sends GSUP LU Req to HLR");
	gsup_expect_tx("04010809710000004026f0");
	ms_sends_msg("05542d8b2c3e");
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


	BTW("Now one auth tuple is available, but used.");
	vsub = vlr_subscr_find_by_imsi(net->vlr, imsi);
	OSMO_ASSERT(vsub);
	OSMO_ASSERT(vsub->last_tuple);
	VERBOSE_ASSERT(vsub->last_tuple->use_count, == 1, "%d");
	/* no need to look at all auth tuples, the ongoing test would take an
	 * unexpected course if there were more. */
	vlr_subscr_put(vsub);

	BTW("Another LU wants to get new tuples; HLR sends Network Failure, we reject.");

	btw("Location Update request causes a GSUP Send Auth Info request to HLR");
	lu_result_sent = RES_NONE;
	gsup_expect_tx("08010809710000004026f0");
	ms_sends_msg("050802008168000130089910070000006402");
	OSMO_ASSERT(gsup_tx_confirmed);
	VERBOSE_ASSERT(lu_result_sent, == RES_NONE, "%d");

	btw("HLR sends _SEND_AUTH_INFO_ERROR = net fail");
	auth_request_sent = false;
	gsup_rx("09" "010809710000004026f0" "020111", NULL);
	VERBOSE_ASSERT(auth_request_sent, == false, "%d");
	VERBOSE_ASSERT(lu_result_sent, == RES_REJECT, "%d");

	EXPECT_CONN_COUNT(0);
	clear_vlr();
	comment_end();
}

void test_hlr_rej_auth_info_unkown_imsi_no_reuse_tuples()
{
	struct vlr_subscr *vsub;
	const char *imsi = "901700000004620";

	comment_start();

	net->authentication_required = true;
	net->vlr->cfg.auth_reuse_old_sets_on_error = true;
	net->vlr->cfg.auth_tuple_max_use_count = 0;

	BTW("Submit a used auth tuple in the VLR");
	btw("Location Update request causes a GSUP Send Auth Info request to HLR");
	lu_result_sent = RES_NONE;
	gsup_expect_tx("08010809710000004026f0");
	ms_sends_msg("050802008168000130089910070000006402");
	OSMO_ASSERT(gsup_tx_confirmed);
	VERBOSE_ASSERT(lu_result_sent, == RES_NONE, "%d");

	btw("from HLR, rx _SEND_AUTH_INFO_RESULT; VLR sends Auth Req to MS");
	auth_request_sent = false;
	auth_request_expect_rand = "585df1ae287f6e273dce07090d61320b";
	auth_request_expect_autn = NULL;
	/* Based on a Ki of 000102030405060708090a0b0c0d0e0f */
	gsup_rx("0a"
		/* imsi */
		"0108" "09710000004026f0"
		/* auth vectors... */
		/* TL    TL     rand */
		"0322"  "2010" "585df1ae287f6e273dce07090d61320b"
		/*       TL     sres       TL     kc */
			"2104" "2d8b2c3e" "2208" "61855fb81fc2a800"
		,NULL);
	VERBOSE_ASSERT(auth_request_sent, == true, "%d");
	VERBOSE_ASSERT(lu_result_sent, == RES_NONE, "%d");

	btw("MS sends Authen Response, VLR accepts and sends GSUP LU Req to HLR");
	gsup_expect_tx("04010809710000004026f0");
	ms_sends_msg("05542d8b2c3e");
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


	BTW("Now one auth tuple is available, but used.");
	vsub = vlr_subscr_find_by_imsi(net->vlr, imsi);
	OSMO_ASSERT(vsub);
	OSMO_ASSERT(vsub->last_tuple);
	VERBOSE_ASSERT(vsub->last_tuple->use_count, == 1, "%d");
	/* no need to look at all auth tuples, the ongoing test would take an
	 * unexpected course if there were more. */
	vlr_subscr_put(vsub);

	BTW("Another LU wants to get new tuples; HLR sends IMSI Unknown. Even though we would re-use an old tuple, reject the unknown IMSI.");
	VERBOSE_ASSERT(net->vlr->cfg.auth_reuse_old_sets_on_error, == true, "%d");

	btw("Location Update request causes a GSUP Send Auth Info request to HLR");
	lu_result_sent = RES_NONE;
	gsup_expect_tx("08010809710000004026f0");
	ms_sends_msg("050802008168000130089910070000006402");
	OSMO_ASSERT(gsup_tx_confirmed);
	VERBOSE_ASSERT(lu_result_sent, == RES_NONE, "%d");

	btw("HLR sends _SEND_AUTH_INFO_ERROR = unknown IMSI");
	auth_request_sent = false;
	gsup_rx("09" "010809710000004026f0" "020102", NULL);
	VERBOSE_ASSERT(auth_request_sent, == false, "%d");
	VERBOSE_ASSERT(lu_result_sent, == RES_REJECT, "%d");

	EXPECT_CONN_COUNT(0);
	clear_vlr();
	comment_end();
}

void test_hlr_acc_but_no_auth_tuples()
{
	comment_start();

	net->authentication_required = true;
	net->vlr->cfg.auth_reuse_old_sets_on_error = true;
	net->vlr->cfg.auth_tuple_max_use_count = 0;

	btw("Location Update request causes a GSUP Send Auth Info request to HLR");
	lu_result_sent = RES_NONE;
	gsup_expect_tx("08010809710000004026f0");
	ms_sends_msg("050802008168000130089910070000006402");
	OSMO_ASSERT(gsup_tx_confirmed);
	VERBOSE_ASSERT(lu_result_sent, == RES_NONE, "%d");

	btw("from HLR, rx _SEND_AUTH_INFO_RESULT but it lacks auth tuples");
	auth_request_sent = false;
	gsup_rx("0a"
		/* imsi */
		"0108" "09710000004026f0"
		/* NO auth vectors */
		,NULL);
	VERBOSE_ASSERT(auth_request_sent, == false, "%d");
	VERBOSE_ASSERT(lu_result_sent, == RES_REJECT, "%d");

	EXPECT_CONN_COUNT(0);
	clear_vlr();
	comment_end();
}

void test_hlr_rej_auth_info_net_fail_reuse_tuples()
{
	struct vlr_subscr *vsub;
	const char *imsi = "901700000004620";

	comment_start();

	net->authentication_required = true;
	net->vlr->cfg.auth_reuse_old_sets_on_error = true;
	net->vlr->cfg.auth_tuple_max_use_count = 0;

	BTW("Submit a used auth tuple in the VLR");
	btw("Location Update request causes a GSUP Send Auth Info request to HLR");
	lu_result_sent = RES_NONE;
	gsup_expect_tx("08010809710000004026f0");
	ms_sends_msg("050802008168000130089910070000006402");
	OSMO_ASSERT(gsup_tx_confirmed);
	VERBOSE_ASSERT(lu_result_sent, == RES_NONE, "%d");

	btw("from HLR, rx _SEND_AUTH_INFO_RESULT; VLR sends Auth Req to MS");
	auth_request_sent = false;
	auth_request_expect_rand = "585df1ae287f6e273dce07090d61320b";
	auth_request_expect_autn = NULL;
	/* Based on a Ki of 000102030405060708090a0b0c0d0e0f */
	gsup_rx("0a"
		/* imsi */
		"0108" "09710000004026f0"
		/* auth vectors... */
		/* TL    TL     rand */
		"0322"  "2010" "585df1ae287f6e273dce07090d61320b"
		/*       TL     sres       TL     kc */
			"2104" "2d8b2c3e" "2208" "61855fb81fc2a800"
		,NULL);
	VERBOSE_ASSERT(auth_request_sent, == true, "%d");
	VERBOSE_ASSERT(lu_result_sent, == RES_NONE, "%d");

	btw("MS sends Authen Response, VLR accepts and sends GSUP LU Req to HLR");
	gsup_expect_tx("04010809710000004026f0");
	ms_sends_msg("05542d8b2c3e");
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


	BTW("Now one auth tuple is available, but used.");
	vsub = vlr_subscr_find_by_imsi(net->vlr, imsi);
	OSMO_ASSERT(vsub);
	OSMO_ASSERT(vsub->last_tuple);
	VERBOSE_ASSERT(vsub->last_tuple->use_count, == 1, "%d");
	/* no need to look at all auth tuples, the ongoing test would take an
	 * unexpected course if there were more. */
	vlr_subscr_put(vsub);

	BTW("Another LU wants to get new tuples; even though HLR sends Network Failure, we are reusing the old tuples.");

	btw("Location Update request causes a GSUP Send Auth Info request to HLR");
	lu_result_sent = RES_NONE;
	gsup_expect_tx("08010809710000004026f0");
	ms_sends_msg("050802008168000130089910070000006402");
	OSMO_ASSERT(gsup_tx_confirmed);
	VERBOSE_ASSERT(lu_result_sent, == RES_NONE, "%d");

	btw("HLR sends _SEND_AUTH_INFO_ERROR = net fail");
	auth_request_sent = false;
	gsup_rx("09" "010809710000004026f0" "020111", NULL);
	VERBOSE_ASSERT(auth_request_sent, == true, "%d");
	VERBOSE_ASSERT(lu_result_sent, == RES_NONE, "%d");

	btw("MS sends Authen Response, VLR accepts and sends GSUP LU Req to HLR");
	gsup_expect_tx("04010809710000004026f0");
	ms_sends_msg("05542d8b2c3e");
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

	clear_vlr();
	comment_end();
}

void test_hlr_rej_lu()
{
	comment_start();

	btw("Location Update request causes a GSUP LU request to HLR");
	lu_result_sent = RES_NONE;
	gsup_expect_tx("04010809710000004026f0");
	ms_sends_msg("050802008168000130089910070000006402");
	OSMO_ASSERT(gsup_tx_confirmed);
	VERBOSE_ASSERT(lu_result_sent, == RES_NONE, "%d");

	btw("HLR sends UPDATE_LOCATION_ERROR");
	gsup_rx("05" "010809710000004026f0" "020102",
		NULL);
	VERBOSE_ASSERT(lu_result_sent, == RES_REJECT, "%d");
	EXPECT_CONN_COUNT(0);

	clear_vlr();
	comment_end();
}

void test_hlr_no_insert_data()
{
	comment_start();

	btw("Location Update request causes a GSUP LU request to HLR");
	lu_result_sent = RES_NONE;
	gsup_expect_tx("04010809710000004026f0");
	ms_sends_msg("050802008168000130089910070000006402");
	OSMO_ASSERT(gsup_tx_confirmed);
	VERBOSE_ASSERT(lu_result_sent, == RES_NONE, "%d");

	btw("HLR sends only _UPDATE_LOCATION_RESULT, no INSERT DATA");
	gsup_rx("06010809710000004026f0", NULL);

	/* TODO should we wait for OSMO_GSUP_MSGT_INSERT_DATA_REQUEST? */

	btw("LU was successful, and the conn has already been closed");
	VERBOSE_ASSERT(lu_result_sent, == RES_ACCEPT, "%d");

	EXPECT_CONN_COUNT(0);
	clear_vlr();
	comment_end();
}

msc_vlr_test_func_t msc_vlr_tests[] = {
	test_hlr_rej_auth_info_unknown_imsi,
	test_hlr_rej_auth_info_net_fail,
	test_hlr_rej_auth_info_net_fail_reuse_tuples,
	test_hlr_rej_auth_info_net_fail_no_reuse_tuples,
	test_hlr_rej_auth_info_unkown_imsi_no_reuse_tuples,
	test_hlr_acc_but_no_auth_tuples,
	test_hlr_rej_lu,
	test_hlr_no_insert_data,
	NULL
};
