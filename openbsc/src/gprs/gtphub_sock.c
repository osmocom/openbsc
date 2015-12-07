/* GTP Hub Implementation */

/* (C) 2015 by sysmocom s.f.m.c. GmbH <info@sysmocom.de>
 * All Rights Reserved
 *
 * gtphub_sock.c.
 *
 * This file is kept separate so that these functions can be wrapped for
 * gtphub_test.c. When a function and its callers are in the same compilational
 * unit, the wrappability may be optimized away.
 *
 * Author: Neels Hofmeyr
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
 */

#include <openbsc/gtphub.h>
#include <openbsc/debug.h>

/* Convenience makro, note: only within this C file. */
#define LOG(level, fmt, args...) \
	LOGP(DGTPHUB, level, fmt, ##args)

int gtphub_write(const struct osmo_fd *to,
		 const struct osmo_sockaddr *to_addr,
		 const uint8_t *buf, size_t buf_len)
{
	errno = 0;
	ssize_t sent = sendto(to->fd, buf, buf_len, 0,
			      (struct sockaddr*)&to_addr->a, to_addr->l);
	LOG(LOGL_DEBUG, "to %s\n", osmo_sockaddr_to_str(to_addr));

	if (sent == -1) {
		LOG(LOGL_ERROR, "error: %s\n", strerror(errno));
		return -EINVAL;
	}

	if (sent != buf_len)
		LOG(LOGL_ERROR, "sent(%d) != data_len(%d)\n",
		    (int)sent, (int)buf_len);
	else
		LOG(LOGL_DEBUG, "Sent %d: %s%s\n",
		    (int)sent,
		    osmo_hexdump(buf, sent > 1000? 1000 : sent),
		    sent > 1000 ? "..." : "");

	return 0;
}

