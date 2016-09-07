/* MGCPGW client interface to quagga VTY */
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

#include <inttypes.h>
#include <stdlib.h>
#include <talloc.h>

#include <osmocom/vty/command.h>

#include <openbsc/vty.h>
#include <openbsc/mgcpgw_client.h>

#define MGCPGW_STR "MGCP gateway configuration for RTP streams\n"

struct mgcpgw_client_conf *global_mgcpgw_client_conf = NULL;

DEFUN(cfg_mgcpgw_local_ip, cfg_mgcpgw_local_ip_cmd,
      "mgcpgw local-ip A.B.C.D",
      MGCPGW_STR "local bind to connect to MGCP gateway with\n"
      "local bind IP address\n")
{
	if (!global_mgcpgw_client_conf)
		return CMD_ERR_NOTHING_TODO;
	global_mgcpgw_client_conf->local_addr =
		talloc_strdup(gsmnet_from_vty(vty), argv[0]);
	return CMD_SUCCESS;
}

DEFUN(cfg_mgcpgw_local_port, cfg_mgcpgw_local_port_cmd,
      "mgcpgw local-port <0-65535>",
      MGCPGW_STR "local bind to connect to MGCP gateway with\n"
      "local bind port\n")
{
	if (!global_mgcpgw_client_conf)
		return CMD_ERR_NOTHING_TODO;
	global_mgcpgw_client_conf->local_port = atoi(argv[0]);
	return CMD_SUCCESS;
}

DEFUN(cfg_mgcpgw_remote_ip, cfg_mgcpgw_remote_ip_cmd,
      "mgcpgw remote-ip A.B.C.D",
      MGCPGW_STR "remote bind to connect to MGCP gateway with\n"
      "remote bind IP address\n")
{
	if (!global_mgcpgw_client_conf)
		return CMD_ERR_NOTHING_TODO;
	global_mgcpgw_client_conf->remote_addr =
		talloc_strdup(gsmnet_from_vty(vty), argv[0]);
	return CMD_SUCCESS;
}

DEFUN(cfg_mgcpgw_remote_port, cfg_mgcpgw_remote_port_cmd,
      "mgcpgw remote-port <0-65535>",
      MGCPGW_STR "remote bind to connect to MGCP gateway with\n"
      "remote bind port\n")
{
	if (!global_mgcpgw_client_conf)
		return CMD_ERR_NOTHING_TODO;
	global_mgcpgw_client_conf->remote_port = atoi(argv[0]);
	return CMD_SUCCESS;
}

int mgcpgw_client_config_write(struct vty *vty, const char *indent)
{
	const char *addr;
	int port;

	addr = global_mgcpgw_client_conf->local_addr;
	if (addr)
		vty_out(vty, "%smgcpgw local-ip %s%s", indent, addr,
			VTY_NEWLINE);
	port = global_mgcpgw_client_conf->local_port;
	if (port >= 0)
		vty_out(vty, "%smgcpgw local-port %u%s", indent,
			(uint16_t)port, VTY_NEWLINE);

	addr = global_mgcpgw_client_conf->remote_addr;
	if (addr)
		vty_out(vty, "%smgcpgw remote-ip %s%s", indent, addr,
			VTY_NEWLINE);
	port = global_mgcpgw_client_conf->remote_port;
	if (port >= 0)
		vty_out(vty, "%smgcpgw remote-port %u%s", indent,
			(uint16_t)port, VTY_NEWLINE);

	return CMD_SUCCESS;
}

void mgcpgw_client_vty_init(int node, struct mgcpgw_client_conf *conf)
{
	global_mgcpgw_client_conf = conf;

	install_element(node, &cfg_mgcpgw_local_ip_cmd);
	install_element(node, &cfg_mgcpgw_local_port_cmd);
	install_element(node, &cfg_mgcpgw_remote_ip_cmd);
	install_element(node, &cfg_mgcpgw_remote_port_cmd);
}
