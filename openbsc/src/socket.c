/* OpenBSC sokcet code, taken from Abis input driver for ip.access */

/* (C) 2009 by Harald Welte <laforge@gnumonks.org>
 * (C) 2010 by Holger Hans Peter Freyther
 * (C) 2010 by On-Waves
 *
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

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <time.h>
#include <sys/fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>

#include <osmocore/select.h>
#include <osmocore/tlv.h>
#include <osmocore/msgb.h>
#include <openbsc/debug.h>
#include <openbsc/gsm_data.h>
#include <osmocore/talloc.h>

int make_sock(struct bsc_fd *bfd, int proto, u_int16_t port,
	      int (*cb)(struct bsc_fd *fd, unsigned int what))
{
	struct sockaddr_in addr;
	int ret, on = 1;
	int type = SOCK_STREAM;

	if (proto == IPPROTO_UDP)
		type = SOCK_DGRAM;

	bfd->fd = socket(AF_INET, type, proto);
	bfd->cb = cb;
	bfd->when = BSC_FD_READ;
	//bfd->data = line;

	if (bfd->fd < 0) {
		LOGP(DINP, LOGL_ERROR, "could not create TCP socket.\n");
		return -EIO;
	}

	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);
	addr.sin_addr.s_addr = INADDR_ANY;

	setsockopt(bfd->fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));

	ret = bind(bfd->fd, (struct sockaddr *) &addr, sizeof(addr));
	if (ret < 0) {
		LOGP(DINP, LOGL_ERROR, "could not bind l2 socket %s\n",
			strerror(errno));
		close(bfd->fd);
		return -EIO;
	}

	if (proto != IPPROTO_UDP) {
		ret = listen(bfd->fd, 1);
		if (ret < 0) {
			perror("listen");
			return ret;
		}
	}

	ret = bsc_register_fd(bfd);
	if (ret < 0) {
		perror("register_listen_fd");
		close(bfd->fd);
		return ret;
	}
	return 0;
}
