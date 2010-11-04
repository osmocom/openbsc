/* (C) 2009-2010 by Holger Hans Peter Freyther <zecke@selfish.org>
 * (C) 2009-2010 by On-Waves
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

#include <openbsc/osmo_bsc.h>

static void bsc_sapi_n_reject(struct gsm_subscriber_connection *conn, int dlci)
{
}

static void bsc_cipher_mode_compl(struct gsm_subscriber_connection *conn,
				  struct msgb *msg, uint8_t chosen_encr)
{
}

static int bsc_compl_l3(struct gsm_subscriber_connection *conn, struct msgb *msg,
			uint16_t chosen_channel)
{
	return BSC_API_CONN_POL_REJECT;
}

static void bsc_dtap(struct gsm_subscriber_connection *conn, struct msgb *msg)
{
}

static void bsc_assign_compl(struct gsm_subscriber_connection *conn, uint8_t rr_cause)
{
}

static void bsc_assign_fail(struct gsm_subscriber_connection *conn, uint32_t cause)
{
}

static int bsc_clear_request(struct gsm_subscriber_connection *conn, uint32_t cause)
{
	return 0;
}

static void bsc_clear_compl(struct gsm_subscriber_connection *conn)
{
}

static struct bsc_api bsc_handler = {
	.sapi_n_reject = bsc_sapi_n_reject,
	.cipher_mode_compl = bsc_cipher_mode_compl,
	.compl_l3 = bsc_compl_l3,
	.dtap  = bsc_dtap,
	.assign_compl = bsc_assign_compl,
	.assign_fail = bsc_assign_fail,
	.clear_request = bsc_clear_request,
	.clear_compl = bsc_clear_compl,
};

struct bsc_api *osmo_bsc_api()
{
	return &bsc_handler;
}
