/* GSM MS Testing  Layer 3 messages
 * 3GPP TS 44.014 / GSM TS 04.14 */

/* (C) 2017 by Harald Welte <laforge@gnumonks.org>
 *
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
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#include "bscconfig.h"

#include <openbsc/debug.h>
#include <openbsc/gsm_data.h>
#include <openbsc/gsm_subscriber.h>
#include <openbsc/gsm_04_08.h>
#include <openbsc/bsc_api.h>

#include <osmocom/gsm/gsm48.h>
#include <osmocom/gsm/gsm_utils.h>
#include <osmocom/gsm/protocol/gsm_04_14.h>
#include <osmocom/gsm/tlv.h>
#include <osmocom/core/msgb.h>
#include <osmocom/core/talloc.h>
#include <osmocom/core/utils.h>

static struct msgb *create_gsm0414_msg(uint8_t msg_type)
{
	struct msgb *msg = gsm48_msgb_alloc_name("GSM 04.14");
	struct gsm48_hdr *gh;

	gh = (struct gsm48_hdr *) msgb_put(msg, sizeof(*gh) + 1);
	gh->proto_discr = GSM48_PDISC_TEST;
	gh->msg_type = msg_type;
	return msg;
}

static int gsm0414_conn_sendmsg(struct gsm_subscriber_connection *conn, struct msgb *msg)
{
	return gsm0808_submit_dtap(conn, msg, 0, 0);
}

static int gsm0414_tx_simple(struct gsm_subscriber_connection *conn, uint8_t msg_type)
{
	struct msgb *msg = create_gsm0414_msg(msg_type);

	return gsm0414_conn_sendmsg(conn, msg);
}


/* Send a CLOSE_TCH_LOOOP_CMD according to Section 8.1 */
int gsm0414_tx_close_tch_loop_cmd(struct gsm_subscriber_connection *conn,
				  enum gsm414_tch_loop_mode loop_mode)
{
	struct msgb *msg = create_gsm0414_msg(GSM414_MT_CLOSE_TCH_LOOP_CMD);
	uint8_t subch;

	subch = (loop_mode << 1);
	msgb_put_u8(msg, subch);

	msg->lchan = conn->lchan;
	return gsm0414_conn_sendmsg(conn, msg);
}

/* Send a OPEN_LOOP_CMD according to Section 8.3 */
int gsm0414_tx_open_loop_cmd(struct gsm_subscriber_connection *conn)
{
	return gsm0414_tx_simple(conn, GSM414_MT_OPEN_LOOP_CMD);
}

/* Send a ACT_EMMI_CMD according to Section 8.8 */
int gsm0414_tx_act_emmi_cmd(struct gsm_subscriber_connection *conn)
{
	return gsm0414_tx_simple(conn, GSM414_MT_ACT_EMMI_CMD);
}

/* Send a DEACT_EMMI_CMD according to Section 8.10 */
int gsm0414_tx_deact_emmi_cmd(struct gsm_subscriber_connection *conn)
{
	return gsm0414_tx_simple(conn, GSM414_MT_DEACT_EMMI_CMD);
}

/* Send a TEST_INTERFACE according to Section 8.11 */
int gsm0414_tx_test_interface(struct gsm_subscriber_connection *conn,
			      uint8_t tested_devs)
{
	struct msgb *msg = create_gsm0414_msg(GSM414_MT_TEST_INTERFACE);
	msgb_put_u8(msg, tested_devs);
	return gsm0414_conn_sendmsg(conn, msg);
}

/* Send a RESET_MS_POSITION_STORED according to Section 8.11 */
int gsm0414_tx_reset_ms_pos_store(struct gsm_subscriber_connection *conn,
				  uint8_t technology)
{
	struct msgb *msg = create_gsm0414_msg(GSM414_MT_RESET_MS_POS_STORED);
	msgb_put_u8(msg, technology);
	return gsm0414_conn_sendmsg(conn, msg);
}



/* Entry point for incoming GSM48_PDISC_TEST received from MS */
int gsm0414_rcv_test(struct gsm_subscriber_connection *conn,
		     struct msgb *msg)
{
	struct gsm48_hdr *gh = msgb_l3(msg);

	if (msgb_l3len(msg) < sizeof(*gh))
		return -1;

	LOGP(DMM, LOGL_NOTICE, "%s: Received TEST class message '%s'\n", "FIXME",
		get_value_string(gsm414_msgt_names, gh->msg_type));

	return 0;
}
