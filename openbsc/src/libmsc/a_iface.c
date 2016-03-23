/* A-interface implementation, from MSC to BSC */

/* (C) 2016 by sysmocom s.m.f.c GmbH <info@sysmocom.de>
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

#include <osmocom/core/msgb.h>
#include <osmocom/core/logging.h>

#include <openbsc/debug.h>

#include <openbsc/gsm_data.h>
#include <openbsc/msc_ifaces.h>

int a_tx(struct msgb *msg)
{
	LOGP(DMSC, LOGL_ERROR, "message to be sent to BSC, but A-interface"
	     " not implemented.\n%s\n", osmo_hexdump(msg->data, msg->len));
	return -1;
}

int gsm0808_cipher_mode(struct gsm_subscriber_connection *conn, int cipher,
			const uint8_t *key, int len, int include_imeisv)
{
	/* TODO generalize for A- and Iu interfaces, don't name after 08.08 */
	LOGP(DMSC, LOGL_ERROR, "gsm0808_cipher_mode(): message to be sent to"
	     " BSC, but A interface not yet implemented.\n");
	return -1;
}

/* from gsm_04_08_utils.c *****/

/* 9.2.5 CM service accept */
int gsm48_tx_mm_serv_ack(struct gsm_subscriber_connection *conn)
{
	struct msgb *msg = gsm48_msgb_alloc_name("GSM 04.08 SERV ACC");
	struct gsm48_hdr *gh = (struct gsm48_hdr *) msgb_put(msg, sizeof(*gh));

	gh->proto_discr = GSM48_PDISC_MM;
	gh->msg_type = GSM48_MT_MM_CM_SERV_ACC;

	DEBUGP(DMM, "-> CM SERVICE ACCEPT\n");

	return msc_tx_dtap(conn, msg);
}

/* 9.2.6 CM service reject */
int gsm48_tx_mm_serv_rej(struct gsm_subscriber_connection *conn,
			 enum gsm48_reject_value value)
{
	struct msgb *msg;

	msg = gsm48_create_mm_serv_rej(value);
	if (!msg) {
		LOGP(DMM, LOGL_ERROR, "Failed to allocate CM Service Reject.\n");
		return -1;
	}

	DEBUGP(DMM, "-> CM SERVICE Reject cause: %d\n", value);

	return msc_tx_dtap(conn, msg);
}
