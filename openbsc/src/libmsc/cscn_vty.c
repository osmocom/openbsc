/* MSC interface to quagga VTY */
/* (C) 2016 by sysmocom s.m.f.c. GmbH <info@sysmocom.de>
 * Based on OpenBSC interface to quagga VTY (libmsc/vty_interface_layer3.c)
 * (C) 2009 by Harald Welte <laforge@gnumonks.org>
 * (C) 2009-2011 by Holger Hans Peter Freyther
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

/* NOTE: I would have liked to call this the MSC_NODE instead of the CSCN_NODE,
 * but MSC_NODE already exists to configure a remote MSC for osmo-bsc. */

#include <osmocom/vty/command.h>
#include <openbsc/vty.h>

#include <openbsc/gsm_data.h>

static struct cmd_node cscn_node = {
	CSCN_NODE,
	"%s(config-cscn)# ",
	1,
};

DEFUN(cfg_cscn, cfg_cscn_cmd,
      "cscn", "Configure CSCN options")
{
	vty->node = CSCN_NODE;
	return CMD_SUCCESS;
}

DEFUN(cfg_cscn_subscr_create, cfg_cscn_subscr_create_cmd,
      "subscriber-create-on-demand",
      "Make a new record when a subscriber is first seen.\n")
{
	struct gsm_network *gsmnet = gsmnet_from_vty(vty);
	gsmnet->create_subscriber = 1;
	return CMD_SUCCESS;
}

DEFUN(cfg_cscn_no_subscr_create, cfg_cscn_no_subscr_create_cmd,
      "no subscriber-create-on-demand",
      NO_STR "Make a new record when a subscriber is first seen.\n")
{
	struct gsm_network *gsmnet = gsmnet_from_vty(vty);
	gsmnet->create_subscriber = 0;
	return CMD_SUCCESS;
}

DEFUN(cfg_cscn_assign_tmsi, cfg_cscn_assign_tmsi_cmd,
      "assign-tmsi",
      "Assign TMSI during Location Updating.\n")
{
	struct gsm_network *gsmnet = gsmnet_from_vty(vty);
	gsmnet->avoid_tmsi = 0;
	return CMD_SUCCESS;
}

DEFUN(cfg_cscn_no_assign_tmsi, cfg_cscn_no_assign_tmsi_cmd,
      "no assign-tmsi",
      NO_STR "Assign TMSI during Location Updating.\n")
{
	struct gsm_network *gsmnet = gsmnet_from_vty(vty);
	gsmnet->avoid_tmsi = 1;
	return CMD_SUCCESS;
}

static int config_write_cscn(struct vty *vty)
{
	struct gsm_network *gsmnet = gsmnet_from_vty(vty);
	vty_out(vty, "cscn%s", VTY_NEWLINE);
	vty_out(vty, " %ssubscriber-create-on-demand%s",
		gsmnet->create_subscriber ? "" : "no ", VTY_NEWLINE);
	vty_out(vty, " %sassign-tmsi%s",
		gsmnet->avoid_tmsi ? "no " : "", VTY_NEWLINE);
	return CMD_SUCCESS;
}


void cscn_vty_init(void)
{
	install_element(CONFIG_NODE, &cfg_cscn_cmd);
	install_node(&cscn_node, config_write_cscn);
	install_element(CSCN_NODE, &cfg_cscn_subscr_create_cmd);
	install_element(CSCN_NODE, &cfg_cscn_no_subscr_create_cmd);
	install_element(CSCN_NODE, &cfg_cscn_assign_tmsi_cmd);
	install_element(CSCN_NODE, &cfg_cscn_no_assign_tmsi_cmd);
}
