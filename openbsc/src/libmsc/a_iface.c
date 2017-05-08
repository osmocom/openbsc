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
#include <openbsc/debug.h>

int a_tx(struct msgb *msg)
{
	LOGP(DMSC, LOGL_ERROR, "message to be sent to BSC, but A-interface"
	     " not implemented.\n%s\n", osmo_hexdump(msg->data, msg->len));
	return -1;
}

int msc_gsm0808_tx_cipher_mode(struct gsm_subscriber_connection *conn, int cipher,
			       const uint8_t *key, int len, int include_imeisv)
{
	/* TODO generalize for A- and Iu interfaces, don't name after 08.08 */
	LOGP(DMSC, LOGL_ERROR, "gsm0808_cipher_mode(): message to be sent to"
	     " BSC, but A interface not yet implemented.\n");
	return -1;
}
