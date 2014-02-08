/* Helpers for SMS/GSM 04.11 */
/*
 * (C) 2014 by Holger Hans Peter Freyther
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

#include <openbsc/gsm_data.h>
#include <openbsc/gsm_04_11.h>

uint8_t sms_next_rp_msg_ref(struct gsm_subscriber_connection *conn)
{
	const uint8_t rp_msg_ref = conn->next_rp_ref;
	/*
	 * This should wrap as the valid range is 0 to 255. We only
	 * transfer one SMS at a time so we don't need to check if
	 * the id has been already assigned.
	 */
	conn->next_rp_ref += 1;

	return rp_msg_ref;
}

