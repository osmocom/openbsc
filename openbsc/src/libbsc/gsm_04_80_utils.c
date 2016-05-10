/* OpenBSC utility functions for 3GPP TS 04.80 */

/* (C) 2016 by sysmocom s.m.f.c. GmbH <info@sysmocom.de>
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

#include <osmocom/gsm/gsm0480.h>
#include <openbsc/bsc_api.h>

int bsc_send_ussd_notify(struct gsm_subscriber_connection *conn, int level,
			 const char *text)
{
	struct msgb *msg = gsm0480_create_ussd_notify(level, text);
	if (!msg)
		return -1;
	return gsm0808_submit_dtap(conn, msg, 0, 0);
}

int bsc_send_ussd_release_complete(struct gsm_subscriber_connection *conn)
{
	struct msgb *msg = gsm0480_create_ussd_release_complete();
	if (!msg)
		return -1;
	return gsm0808_submit_dtap(conn, msg, 0, 0);
}
