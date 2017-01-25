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

#include <osmocom/core/logging.h>

void test_hlr_timeout_lu_auth_info()
{
	comment_start();

	fake_time_start();

	net->authentication_required = true;

	btw("Location Update request causes a GSUP Send Auth Info request to HLR");
	lu_result_sent = RES_NONE;
	gsup_expect_tx("08010809710000004026f0");
	ms_sends_msg("050802008168000130089910070000006402");
	OSMO_ASSERT(gsup_tx_confirmed);
	VERBOSE_ASSERT(lu_result_sent, == RES_NONE, "%d");

	BTW("HLR never replies");

	btw("At first, we're still waiting");
	fake_time_passes(0, 423);
	EXPECT_CONN_COUNT(1);
	fake_time_passes(1, 235);
	EXPECT_CONN_COUNT(1);
	fake_time_passes(1, 235);
	EXPECT_CONN_COUNT(1);
	fake_time_passes(1, 235);
	EXPECT_CONN_COUNT(1);
	fake_time_passes(1, 235);
	EXPECT_CONN_COUNT(1);
	fake_time_passes(1, 235);
	btw("SUBSCR_CONN_TIMEOUT has passed, conn is gone.");
	EXPECT_CONN_COUNT(0);
	VERBOSE_ASSERT(lu_result_sent, == RES_REJECT, "%d");

	clear_vlr();
	comment_end();
}

void test_hlr_timeout_lu_upd_loc_result()
{
	comment_start();

	fake_time_start();

	btw("Location Update request causes a GSUP LU request to HLR");
	lu_result_sent = RES_NONE;
	gsup_expect_tx("04010809710000004026f0");
	ms_sends_msg("050802008168000130089910070000006402");
	OSMO_ASSERT(gsup_tx_confirmed);
	VERBOSE_ASSERT(lu_result_sent, == RES_NONE, "%d");

	btw("HLR sends _INSERT_DATA_REQUEST, VLR responds with _INSERT_DATA_RESULT");
	gsup_rx("10010809710000004026f00804036470f1",
		"12010809710000004026f0");
	VERBOSE_ASSERT(lu_result_sent, == RES_NONE, "%d");

	BTW("HLR never sends GSUP _UPDATE_LOCATION_RESULT");

	btw("At first, we're still waiting");
	fake_time_passes(0, 423);
	EXPECT_CONN_COUNT(1);
	VERBOSE_ASSERT(lu_result_sent, == RES_NONE, "%d");
	fake_time_passes(1, 235);
	EXPECT_CONN_COUNT(1);
	VERBOSE_ASSERT(lu_result_sent, == RES_NONE, "%d");
	fake_time_passes(1, 235);
	EXPECT_CONN_COUNT(1);
	VERBOSE_ASSERT(lu_result_sent, == RES_NONE, "%d");
	fake_time_passes(1, 235);
	EXPECT_CONN_COUNT(1);
	VERBOSE_ASSERT(lu_result_sent, == RES_NONE, "%d");
	fake_time_passes(1, 235);
	EXPECT_CONN_COUNT(1);
	VERBOSE_ASSERT(lu_result_sent, == RES_NONE, "%d");
	fake_time_passes(1, 235);
	btw("SUBSCR_CONN_TIMEOUT has passed, conn is gone.");
	EXPECT_CONN_COUNT(0);
	VERBOSE_ASSERT(lu_result_sent, == RES_REJECT, "%d");

	clear_vlr();
	comment_end();
}

msc_vlr_test_func_t msc_vlr_tests[] = {
	test_hlr_timeout_lu_auth_info,
	test_hlr_timeout_lu_upd_loc_result,
	NULL
};
