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
#include <openbsc/bsc_msc.h>
#include <openbsc/vty.h>

#include <sccp/sccp.h>

static struct gsm_network *gsmnet = NULL;

extern struct llist_head *bsc_sccp_connections();

DEFUN(show_bsc, show_bsc_cmd, "show bsc",
	SHOW_STR "Display information about the BSC\n")
{
	struct bss_sccp_connection_data *con;

	vty_out(vty, "BSC Information%s", VTY_NEWLINE);
	llist_for_each_entry(con, bsc_sccp_connections(), active_connections) {
		vty_out(vty, " Connection: LCHAN: %p sec LCHAN: 0x%p SCCP src: 0x%x dest: 0x%x%s",
			con->lchan, con->secondary_lchan,
			con->sccp ? (int) sccp_src_ref_to_int(&con->sccp->source_local_reference) : -1,
			con->sccp ? (int) sccp_src_ref_to_int(&con->sccp->destination_local_reference) : -1,
			VTY_NEWLINE);
	}

	return CMD_SUCCESS;
}

DEFUN(show_stats,
      show_stats_cmd,
      "show statistics",
	SHOW_STR "Display network statistics\n")
{
	struct gsm_network *net = gsmnet;

	openbsc_vty_print_statistics(vty, net);
	return CMD_SUCCESS;
}

DEFUN(show_msc,
      show_msc_cmd,
      "show msc connection",
      SHOW_STR "Show the status of the MSC connection.")
{
	if (!gsmnet->msc_con) {
		vty_out(vty, "The MSC is not yet configured.\n");
		return CMD_WARNING;
	}

	vty_out(vty, "MSC on %s:%d is connected: %d%s\n",
		gsmnet->msc_con->ip, gsmnet->msc_con->port,
		gsmnet->msc_con->is_connected, VTY_NEWLINE);

	return CMD_SUCCESS;
}


int bsc_vty_init_extra(struct gsm_network *net)
{
	gsmnet = net;

	/* get runtime information */
	install_element(VIEW_NODE, &show_bsc_cmd);
	install_element(VIEW_NODE, &show_stats_cmd);
	install_element(VIEW_NODE, &show_msc_cmd);

	return 0;
}
