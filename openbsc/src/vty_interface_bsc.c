/* OpenBSC interface to quagga VTY - BSC options */
/* (C) 2009 by Harald Welte <laforge@gnumonks.org>
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

#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>

#include <vty/command.h>
#include <vty/buffer.h>
#include <vty/vty.h>

#include <openbsc/gsm_data.h>

static struct gsmnet *gsmnet = NULL;

DEFUN(show_bsc, show_bsc_cmd, "show bsc",
	SHOW_STR "Display information about the BSC\n")
{
	vty_out(vty, "BSC... not implemented yet%s", VTY_NEWLINE);
	return CMD_SUCCESS;
}

int bsc_vty_init_extra(struct gsm_network *net)
{
	gsmnet = net;

	/* get runtime information */
	install_element(VIEW_NODE, &show_bsc_cmd);

	return 0;
}
