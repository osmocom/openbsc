/*
 * (C) 2010 by Harald Welte <laforge@gnumonks.org>
 * (C) 2010 by On-Waves
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

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <osmocore/talloc.h>

#include <openbsc/debug.h>
#include <openbsc/gb_proxy.h>
#include <openbsc/gprs_ns.h>
#include <openbsc/vty.h>

#include <vty/command.h>
#include <vty/vty.h>

static struct gbproxy_config *g_cfg = NULL;

/*
 * vty code for mgcp below
 */
static struct cmd_node gbproxy_node = {
	GBPROXY_NODE,
	"%s(gbproxy)#",
	1,
};

static int config_write_gbproxy(struct vty *vty)
{
	struct in_addr ia;

	vty_out(vty, "gbproxy%s", VTY_NEWLINE);

	if (g_cfg->nsip_listen_ip) {
		ia.s_addr = htonl(g_cfg->nsip_listen_ip);
		vty_out(vty, " nsip bss local ip %s%s", inet_ntoa(ia),
			VTY_NEWLINE);
	}
	vty_out(vty, " nsip bss local port %u%s", g_cfg->nsip_listen_port,
		VTY_NEWLINE);
	ia.s_addr = htonl(g_cfg->nsip_sgsn_ip);
	vty_out(vty, " nsip sgsn remote ip %s%s", inet_ntoa(ia),
		VTY_NEWLINE);
	vty_out(vty, " nsip sgsn remote port %u%s", g_cfg->nsip_sgsn_port,
		VTY_NEWLINE);
	vty_out(vty, " nsip sgsn nsei %u%s", g_cfg->nsip_sgsn_nsei,
		VTY_NEWLINE);
	vty_out(vty, " nsip sgsn nsvci %u%s", g_cfg->nsip_sgsn_nsvci,
		VTY_NEWLINE);

	return CMD_SUCCESS;
}

DEFUN(cfg_gbproxy,
      cfg_gbproxy_cmd,
      "gbproxy",
      "Configure the Gb proxy")
{
	vty->node = GBPROXY_NODE;
	return CMD_SUCCESS;
}

DEFUN(cfg_nsip_bss_local_ip,
      cfg_nsip_bss_local_ip_cmd,
      "nsip bss local ip A.B.C.D",
      "Set the IP address on which we listen for BSS connects")
{
	struct in_addr ia;

	inet_aton(argv[0], &ia);
	g_cfg->nsip_listen_ip = ntohl(ia.s_addr);

	return CMD_SUCCESS;
}

DEFUN(cfg_nsip_bss_local_port,
      cfg_nsip_bss_local_port_cmd,
      "nsip bss local port <0-65534>",
      "Set the UDP port on which we listen for BSS connects")
{
	unsigned int port = atoi(argv[0]);

	g_cfg->nsip_listen_port = port;
	return CMD_SUCCESS;
}


DEFUN(cfg_nsip_sgsn_ip,
      cfg_nsip_sgsn_ip_cmd,
      "nsip sgsn remote ip A.B.C.D",
      "Set the IP of the SGSN to which the proxy shall connect")
{
	struct in_addr ia;

	inet_aton(argv[0], &ia);
	g_cfg->nsip_sgsn_ip = ntohl(ia.s_addr);

	return CMD_SUCCESS;
}

DEFUN(cfg_nsip_sgsn_port,
      cfg_nsip_sgsn_port_cmd,
      "nsip sgsn remote port <0-65534>",
      "Set the UDP port of the SGSN to which the proxy shall connect")
{
	unsigned int port = atoi(argv[0]);

	g_cfg->nsip_sgsn_port = port;
	return CMD_SUCCESS;
}

DEFUN(cfg_nsip_sgsn_nsei,
      cfg_nsip_sgsn_nsei_cmd,
      "nsip sgsn nsei <0-65534>",
      "Set the NSEI to be used in the connection with the SGSN")
{
	unsigned int port = atoi(argv[0]);

	g_cfg->nsip_sgsn_nsei = port;
	return CMD_SUCCESS;
}

DEFUN(cfg_nsip_sgsn_nsvci,
      cfg_nsip_sgsn_nsvci_cmd,
      "nsip sgsn nsvci <0-65534>",
      "Set the NSVCI to be used in the connection with the SGSN")
{
	unsigned int port = atoi(argv[0]);

	g_cfg->nsip_sgsn_nsvci = port;
	return CMD_SUCCESS;
}

int gbproxy_vty_init(void)
{
	install_element_ve(&show_gbproxy_cmd);

	install_element(CONFIG_NODE, &cfg_gbproxy_cmd);
	install_node(&gbproxy_node, config_write_gbproxy);
	install_default(GBPROXY_NODE);
	install_element(GBPROXY_NODE, &ournode_exit_cmd);
	install_element(GBPROXY_NODE, &ournode_end_cmd);
	install_element(GBPROXY_NODE, &cfg_nsip_bss_local_ip_cmd);
	install_element(GBPROXY_NODE, &cfg_nsip_bss_local_port_cmd);
	install_element(GBPROXY_NODE, &cfg_nsip_sgsn_ip_cmd);
	install_element(GBPROXY_NODE, &cfg_nsip_sgsn_port_cmd);
	install_element(GBPROXY_NODE, &cfg_nsip_sgsn_nsei_cmd);
	install_element(GBPROXY_NODE, &cfg_nsip_sgsn_nsvci_cmd);

	return 0;
}

int gbproxy_parse_config(const char *config_file, struct gbproxy_config *cfg)
{
	int rc;

	g_cfg = cfg;
	rc = vty_read_config_file(config_file, NULL);
	if (rc < 0) {
		fprintf(stderr, "Failed to parse the config file: '%s'\n", config_file);
		return rc;
	}

	return 0;
}

