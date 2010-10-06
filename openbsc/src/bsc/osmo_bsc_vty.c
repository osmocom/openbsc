/* Osmo BSC VTY Configuration */
/* (C) 2009-2010 by Holger Hans Peter Freyther
 * (C) 2009-2010 by On-Waves
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

#include <openbsc/gsm_data.h>
#include <openbsc/osmo_msc_data.h>
#include <openbsc/vty.h>

#include <osmocore/talloc.h>

extern struct gsm_network *bsc_gsmnet;

static struct osmo_msc_data *osmo_msc_data(struct vty *vty)
{
	return bsc_gsmnet->msc_data;
}

static struct cmd_node msc_node = {
	MSC_NODE,
	"%s(msc)#",
	1,
};

DEFUN(cfg_net_msc, cfg_net_msc_cmd,
      "msc", "Configure MSC details")
{
	vty->index = bsc_gsmnet;
	vty->node = MSC_NODE;

	return CMD_SUCCESS;
}

static int config_write_msc(struct vty *vty)
{
	struct osmo_msc_data *data = osmo_msc_data(vty);

	vty_out(vty, " msc%s", VTY_NEWLINE);
	if (data->bsc_token)
		vty_out(vty, "  token %s%s", data->bsc_token, VTY_NEWLINE);
	vty_out(vty, "  ip %s%s", data->msc_ip, VTY_NEWLINE);
	vty_out(vty, "  port %d%s", data->msc_port, VTY_NEWLINE);
	vty_out(vty, "  ip-dscp %d%s", data->msc_ip_dscp, VTY_NEWLINE);
	vty_out(vty, "  timeout-ping %d%s", data->ping_timeout, VTY_NEWLINE);
	vty_out(vty, "  timeout-pong %d%s", data->pong_timeout, VTY_NEWLINE);
	if (data->ussd_grace_txt)
		vty_out(vty, "bsc-grace-text %s%s", data->ussd_grace_txt, VTY_NEWLINE);

	return CMD_SUCCESS;
}

DEFUN(cfg_net_msc_token,
      cfg_net_bsc_token_cmd,
      "token TOKEN",
      "A token for the BSC to be sent to the MSC")
{
	struct osmo_msc_data *data = osmo_msc_data(vty);

	if (data->bsc_token)
		talloc_free(data->bsc_token);
	data->bsc_token = talloc_strdup(data, argv[0]);

	return CMD_SUCCESS;
}

DEFUN(cfg_net_msc_ip,
      cfg_net_msc_ip_cmd,
      "ip A.B.C.D", "Set the MSC/MUX IP address.")
{
	struct osmo_msc_data *data = osmo_msc_data(vty);
	if (data->msc_ip)
		talloc_free(data->msc_ip);
	data->msc_ip = talloc_strdup(data, argv[0]);

	return CMD_SUCCESS;
}

DEFUN(cfg_net_msc_port,
      cfg_net_msc_port_cmd,
      "port <1-65000>",
      "Set the MSC/MUX port.")
{
	struct osmo_msc_data *data = osmo_msc_data(vty);
	data->msc_port = atoi(argv[0]);
	return CMD_SUCCESS;
}


DEFUN(cfg_net_msc_prio,
      cfg_net_msc_prio_cmd,
      "ip-dscp <0-255>",
      "Set the IP_TOS socket attribite")
{
	struct osmo_msc_data *data = osmo_msc_data(vty);
	data->msc_ip_dscp = atoi(argv[0]);
	return CMD_SUCCESS;
}

DEFUN(cfg_net_msc_ping_time,
      cfg_net_msc_ping_time_cmd,
      "timeout-ping NR",
      "Set the PING interval, negative for not sending PING")
{
	struct osmo_msc_data *data = osmo_msc_data(vty);
	data->ping_timeout = atoi(argv[0]);
	return CMD_SUCCESS;
}

DEFUN(cfg_net_msc_pong_time,
      cfg_net_msc_pong_time_cmd,
      "timeout-pong NR",
      "Set the time to wait for a PONG.")
{
	struct osmo_msc_data *data = osmo_msc_data(vty);
	data->pong_timeout = atoi(argv[0]);
	return CMD_SUCCESS;
}

DEFUN(cfg_net_msc_grace_ussd,
      cfg_net_msc_grace_ussd_cmd,
      "bsc-grace-text .TEXT",
      "Set the USSD notifcation to be send.\n" "Text to be sent\n")
{
	struct osmo_msc_data *data = osmo_msc_data(vty);
	char *txt = argv_concat(argv, argc, 1);
	if (!txt)
		return CMD_WARNING;

	if (data->ussd_grace_txt)
		talloc_free(data->ussd_grace_txt);
	data->ussd_grace_txt = talloc_strdup(data, txt);
	talloc_free(txt);
	return CMD_SUCCESS;
}

int bsc_vty_init_extra(void)
{
	install_element(GSMNET_NODE, &cfg_net_msc_cmd);
	install_node(&msc_node, config_write_msc);
	install_default(MSC_NODE);
	install_element(MSC_NODE, &cfg_net_bsc_token_cmd);
	install_element(MSC_NODE, &cfg_net_msc_ip_cmd);
	install_element(MSC_NODE, &cfg_net_msc_port_cmd);
	install_element(MSC_NODE, &cfg_net_msc_prio_cmd);
	install_element(MSC_NODE, &cfg_net_msc_ping_time_cmd);
	install_element(MSC_NODE, &cfg_net_msc_pong_time_cmd);
	install_element(MSC_NODE, &cfg_net_msc_grace_ussd_cmd);

	return 0;
}
