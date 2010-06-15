/* Routines to talk to the MSC using the IPA Protocol */
/*
 * (C) 2010 by Holger Hans Peter Freyther <zecke@selfish.org>
 * (C) 2010 by on-waves.com
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

#include <openbsc/bsc_msc.h>

#include <arpa/inet.h>
#include <sys/socket.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

int connect_to_msc(struct bsc_fd *fd, const char *ip, int port)
{
	struct sockaddr_in sin;
	int on = 1, ret;

	printf("Attempting to connect MSC at %s:%d\n", ip, port);

	fd->fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	fd->when = BSC_FD_READ;
	fd->data = NULL;
	fd->priv_nr = 1;

	if (fd->fd < 0) {
		perror("Creating TCP socket failed");
		return fd->fd;
	}


	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_port = htons(port);
        inet_aton(ip, &sin.sin_addr);

	setsockopt(fd->fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
	ret = connect(fd->fd, (struct sockaddr *) &sin, sizeof(sin));

	if (ret < 0) {
		perror("Connection failed");
		return ret;
	}

	ret = bsc_register_fd(fd);
	if (ret < 0) {
		perror("Registering the fd failed");
		close(fd->fd);
		return ret;
	}

	return ret;
}
