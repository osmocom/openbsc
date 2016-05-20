/* Media Gateway Control Protocol Media Gateway: RFC 3435 */
/* Implementations useful both for the MGCP GW as well as MGCP GW clients */

/*
 * (C) 2016 by sysmocom s.m.f.c. GmbH <info@sysmocom.de>
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

#include <errno.h>

#include <osmocom/core/utils.h>
#include <openbsc/mgcp.h>

const struct value_string mgcp_connection_mode_strs[] = {
	{ MGCP_CONN_NONE, "none" },
	{ MGCP_CONN_RECV_SEND, "sendrecv" },
	{ MGCP_CONN_SEND_ONLY, "sendonly" },
	{ MGCP_CONN_RECV_ONLY, "recvonly" },
	{ MGCP_CONN_LOOPBACK, "loopback" },
	{ 0, NULL }
};

/* Ensure that the msg->l2h is NUL terminated. */
int mgcp_msg_terminate_nul(struct msgb *msg)
{
	unsigned char *tail = msg->l2h + msgb_l2len(msg); /* char after l2 data */
	if (tail[-1] == '\0')
		/* nothing to do */;
	else if (msgb_tailroom(msg) > 0)
		tail[0] = '\0';
	else if (tail[-1] == '\r' || tail[-1] == '\n')
		tail[-1] = '\0';
	else {
		LOGP(DMGCP, LOGL_ERROR, "Cannot NUL terminate MGCP message: "
		     "Length: %d, Buffer size: %d\n",
		     msgb_l2len(msg), msg->data_len);
		return -ENOTSUP;
	}
	return 0;
}
