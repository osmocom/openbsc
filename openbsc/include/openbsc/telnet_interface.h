/* minimalistic telnet/network interface it might turn into a wire interface */
/* (C) 2009 by Holger Hans Peter Freyther <zecke@selfish.org>
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

#ifndef TELNET_INTERFACE_H
#define TELNET_INTERFACE_H

#include "gsm_data.h"
#include "linuxlist.h"
#include "select.h"

#include <vty/vty.h>

#define TELNET_COMMAND_48	1
#define TELNET_COMMAND_11	2

struct telnet_connection {
	struct llist_head entry;
	struct gsm_network *network;
	struct bsc_fd fd;
	struct vty *vty;

	int bts;

	int command;
	char *imsi;
	char commands[1024];
	int read;
};


void telnet_init(struct gsm_network *network, int port);

int bsc_vty_init(struct gsm_network *net);

#endif
