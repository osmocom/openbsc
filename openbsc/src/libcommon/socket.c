/* OpenBSC sokcet code, taken from Abis input driver for ip.access */

/* (C) 2009 by Harald Welte <laforge@gnumonks.org>
 * (C) 2010 by Holger Hans Peter Freyther
 * (C) 2010 by On-Waves
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

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <time.h>
#include <sys/fcntl.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>

#include <osmocom/core/select.h>
#include <osmocom/gsm/tlv.h>
#include <osmocom/core/msgb.h>
#include <openbsc/debug.h>
#include <openbsc/gsm_data.h>
#include <osmocom/core/talloc.h>

int make_sock(struct osmo_fd *bfd, int proto,
	      uint32_t ip, uint16_t port, int priv_nr,
	      int (*cb)(struct osmo_fd *fd, unsigned int what), void *data)
{
	struct sockaddr_in addr;
	int ret, on = 1;
	int type = SOCK_STREAM;

	switch (proto) {
	case IPPROTO_TCP:
		type = SOCK_STREAM;
		break;
	case IPPROTO_UDP:
		type = SOCK_DGRAM;
		break;
#ifdef IPPROTO_GRE
	case IPPROTO_GRE:
		type = SOCK_RAW;
		break;
#endif
	default:
		return -EINVAL;
	}

	bfd->fd = socket(AF_INET, type, proto);
	bfd->cb = cb;
	bfd->when = BSC_FD_READ;
	bfd->data = data;
	bfd->priv_nr = priv_nr;

	if (bfd->fd < 0) {
		LOGP(DLINP, LOGL_ERROR, "could not create socket.\n");
		return -EIO;
	}

	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);
	if (ip != INADDR_ANY)
		addr.sin_addr.s_addr = htonl(ip);
	else
		addr.sin_addr.s_addr = INADDR_ANY;

	setsockopt(bfd->fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));

	ret = bind(bfd->fd, (struct sockaddr *) &addr, sizeof(addr));
	if (ret < 0) {
		LOGP(DLINP, LOGL_ERROR, "could not bind socket %s\n",
			strerror(errno));
		close(bfd->fd);
		return -EIO;
	}

	if (proto == IPPROTO_TCP) {
		ret = listen(bfd->fd, 1);
		if (ret < 0) {
			perror("listen");
			close(bfd->fd);
			return ret;
		}
	}

	ret = osmo_fd_register(bfd);
	if (ret < 0) {
		perror("register_listen_fd");
		close(bfd->fd);
		return ret;
	}
	return 0;
}
