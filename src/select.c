/* select filedescriptor handling, taken from:
 * userspace logging daemon for the iptables ULOG target
 * of the linux 2.4 netfilter subsystem.
 *
 * (C) 2000-2008 by Harald Welte <laforge@gnumonks.org>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2 
 *  as published by the Free Software Foundation
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include <fcntl.h>
#include <openbsc/select.h>
#include <openbsc/linuxlist.h>

static int maxfd = 0;
static LLIST_HEAD(bsc_fds);

int bsc_register_fd(struct bsc_fd *fd)
{
	int flags;

	/* make FD nonblocking */
	flags = fcntl(fd->fd, F_GETFL);
	if (flags < 0)
		return flags;
	flags |= O_NONBLOCK;
	flags = fcntl(fd->fd, F_SETFL, flags);
	if (flags < 0)
		return flags;

	/* Register FD */
	if (fd->fd > maxfd)
		maxfd = fd->fd;

	llist_add_tail(&fd->list, &bsc_fds);

	return 0;
}

void bsc_unregister_fd(struct bsc_fd *fd)
{
	llist_del(&fd->list);
}

int bsc_select_main()
{
	struct bsc_fd *ufd;
	fd_set readset, writeset, exceptset;
	int i;

	FD_ZERO(&readset);
	FD_ZERO(&writeset);
	FD_ZERO(&exceptset);

	/* prepare read and write fdsets */
	llist_for_each_entry(ufd, &bsc_fds, list) {
		if (ufd->when & BSC_FD_READ)
			FD_SET(ufd->fd, &readset);

		if (ufd->when & BSC_FD_WRITE)
			FD_SET(ufd->fd, &writeset);

		if (ufd->when & BSC_FD_EXCEPT)
			FD_SET(ufd->fd, &exceptset);
	}

	i = select(maxfd+1, &readset, &writeset, &exceptset, NULL);
	if (i > 0) {
		/* call registered callback functions */
		llist_for_each_entry(ufd, &bsc_fds, list) {
			int flags = 0;

			if (FD_ISSET(ufd->fd, &readset))
				flags |= BSC_FD_READ;

			if (FD_ISSET(ufd->fd, &writeset))
				flags |= BSC_FD_WRITE;

			if (FD_ISSET(ufd->fd, &exceptset))
				flags |= BSC_FD_EXCEPT;

			if (flags)
				ufd->cb(ufd, flags);
		}
	}
	return i;
}
