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

#pragma once

#include <stdbool.h>
#include <stdio.h>

#include <openbsc/gsm_data.h>
#include <openbsc/osmo_msc.h>
#include <openbsc/vlr.h>

extern bool _log_lines;
#define _log(fmt, args...) do { \
		if (_log_lines) \
			fprintf(stderr, " %4d:%s: " fmt "\n", \
				__LINE__, __FILE__, ## args ); \
		else \
			fprintf(stderr, fmt "\n", ## args ); \
	} while (false)

/* btw means "by the way", the test tells the log what's happening.
 * BTW() marks a larger section, btw() is the usual logging. */
#define BTW(fmt, args...) _log("---\n- " fmt, ## args )
#define btw(fmt, args...) _log("- " fmt, ## args )
#define log(fmt, args...) _log("  " fmt, ## args )

#define comment_start() fprintf(stderr, "===== %s\n", __func__);
#define comment_end() fprintf(stderr, "===== %s: SUCCESS\n\n", __func__);

extern struct gsm_subscriber_connection *g_conn;
extern struct gsm_network *net;
extern struct gsm_bts *the_bts;
extern void *msgb_ctx;

extern enum ran_type rx_from_ran;

extern const char *gsup_tx_expected;
extern bool gsup_tx_confirmed;

extern struct msgb *dtap_tx_expected;
extern bool dtap_tx_confirmed;

enum result_sent {
	RES_NONE = 0,
	RES_ACCEPT = 1,
	RES_REJECT = 2,
};
extern enum result_sent lu_result_sent;
extern enum result_sent cm_service_result_sent;

extern bool auth_request_sent;
extern const char *auth_request_expect_rand;
extern const char *auth_request_expect_autn;

extern bool cipher_mode_cmd_sent;
extern bool cipher_mode_cmd_sent_with_imeisv;

extern bool paging_sent;
extern bool paging_stopped;

struct msc_vlr_test_cmdline_opts {
	bool verbose;
	int run_test_nr;
};

typedef void (* msc_vlr_test_func_t )(void);
extern msc_vlr_test_func_t msc_vlr_tests[];

struct msgb *msgb_from_hex(const char *label, uint16_t size, const char *hex);

void clear_vlr();
bool conn_exists(struct gsm_subscriber_connection *conn);

void dtap_expect_tx(const char *hex);
void dtap_expect_tx_ussd(char *ussd_text);
void paging_expect_imsi(const char *imsi);
void paging_expect_tmsi(uint32_t tmsi);

void ms_sends_msg(const char *hex);
void ms_sends_security_mode_complete();
void gsup_rx(const char *rx_hex, const char *expect_tx_hex);
void send_sms(struct vlr_subscr *receiver,
	      struct vlr_subscr *sender,
	      char *str);

void thwart_rx_non_initial_requests();

void check_talloc(void *msgb_ctx, void *tall_bsc_ctx, int expected_blocks);

#define EXPECT_ACCEPTED(expect_accepted) do { \
		if (g_conn) \
			OSMO_ASSERT(conn_exists(g_conn)); \
		bool accepted = msc_subscr_conn_is_accepted(g_conn); \
		fprintf(stderr, "msc_subscr_conn_is_accepted() == %s\n", \
			accepted ? "true" : "false"); \
		OSMO_ASSERT(accepted == expect_accepted); \
	} while (false)

#define VERBOSE_ASSERT(val, expect_op, fmt) \
	do { \
		log(#val " == " fmt, (val)); \
		OSMO_ASSERT((val) expect_op); \
	} while (0);

#define EXPECT_CONN_COUNT(N) VERBOSE_ASSERT(llist_count(&net->subscr_conns), == N, "%d")

#define gsup_expect_tx(hex) do \
{ \
	if (gsup_tx_expected) { \
		log("Previous expected GSUP tx was not confirmed!"); \
		OSMO_ASSERT(!gsup_tx_expected); \
	} \
	if (!hex) \
		break; \
	gsup_tx_expected = hex; \
	gsup_tx_confirmed = false; \
} while (0)

void fake_time_start();

/* as macro to get the test file's source line number */
#define fake_time_passes(secs, usecs) do \
{ \
	struct timeval diff; \
	osmo_gettimeofday_override_add(secs, usecs); \
	timersub(&osmo_gettimeofday_override_time, &fake_time_start_time, &diff); \
	btw("Total time passed: %d.%06d s", \
	    (int)diff.tv_sec, (int)diff.tv_usec); \
	osmo_timers_prepare(); \
	osmo_timers_update(); \
} while (0)

extern const struct timeval fake_time_start_time;
