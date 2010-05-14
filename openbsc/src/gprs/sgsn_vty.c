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
#include <openbsc/sgsn.h>
#include <openbsc/gprs_ns.h>
#include <openbsc/vty.h>

#include <vty/command.h>
#include <vty/vty.h>

static struct sgsn_config *g_cfg = NULL;

static struct cmd_node sgsn_node = {
	SGSN_NODE,
	"%s(sgsn)#",
	1,
};

static int config_write_sgsn(struct vty *vty)
{
	struct in_addr ia;

	vty_out(vty, "sgsn%s", VTY_NEWLINE);

	if (g_cfg->nsip_listen_ip) {
		ia.s_addr = htonl(g_cfg->nsip_listen_ip);
		vty_out(vty, "  nsip local ip %s%s", inet_ntoa(ia),
			VTY_NEWLINE);
	}
	vty_out(vty, "  nsip local port %u%s", g_cfg->nsip_listen_port,
		VTY_NEWLINE);

	return CMD_SUCCESS;
}

DEFUN(show_sgsn, show_sgsn_cmd, "show sgsn",
      SHOW_STR "Display information about the SGSN")
{
	/* FIXME: iterate over list of NS-VC's and display their state */
	struct gprs_ns_inst *nsi = g_cfg->nsi;
	struct gprs_nsvc *nsvc;

	llist_for_each_entry(nsvc, &nsi->gprs_nsvcs, list) {
		vty_out(vty, "NSEI %5u, NS-VC %5u, %s-mode, %s %s%s",
			nsvc->nsei, nsvc->nsvci,
			nsvc->remote_end_is_sgsn ? "BSS" : "SGSN",
			nsvc->state & NSE_S_ALIVE ? "ALIVE" : "DEAD",
			nsvc->state & NSE_S_BLOCKED ? "BLOCKED" : "UNBLOCKED",
			VTY_NEWLINE);
		if (nsvc->nsi->ll == GPRS_NS_LL_UDP)
			vty_out(vty, "  remote peer %s:%u%s",
				inet_ntoa(nsvc->ip.bts_addr.sin_addr),
				ntohs(nsvc->ip.bts_addr.sin_port), VTY_NEWLINE);
	}

	return CMD_SUCCESS;
}

DEFUN(cfg_sgsn,
      cfg_sgsn_cmd,
      "sgsn",
      "Configure the SGSN")
{
	vty->node = SGSN_NODE;
	return CMD_SUCCESS;
}


DEFUN(cfg_nsip_local_ip,
      cfg_nsip_local_ip_cmd,
      "nsip local ip A.B.C.D",
      "Set the IP address on which we listen for BSS connects")
{
	struct in_addr ia;

	inet_aton(argv[0], &ia);
	g_cfg->nsip_listen_ip = ntohl(ia.s_addr);

	return CMD_SUCCESS;
}

DEFUN(cfg_nsip_local_port,
      cfg_nsip_local_port_cmd,
      "nsip local port <0-65534>",
      "Set the UDP port on which we listen for BSS connects")
{
	unsigned int port = atoi(argv[0]);

	g_cfg->nsip_listen_port = port;
	return CMD_SUCCESS;
}




int sgsn_vty_init(void)
{
	install_element(VIEW_NODE, &show_sgsn_cmd);

	install_element(CONFIG_NODE, &cfg_sgsn_cmd);
	install_node(&sgsn_node, config_write_sgsn);
	install_default(SGSN_NODE);
	install_element(SGSN_NODE, &ournode_exit_cmd);
	install_element(SGSN_NODE, &ournode_end_cmd);
	install_element(SGSN_NODE, &cfg_nsip_local_ip_cmd);
	install_element(SGSN_NODE, &cfg_nsip_local_port_cmd);

	return 0;
}

int sgsn_parse_config(const char *config_file, struct sgsn_config *cfg)
{
	int rc;

	g_cfg = cfg;
	rc = vty_read_config_file(config_file);
	if (rc < 0) {
		fprintf(stderr, "Failed to parse the config file: '%s'\n", config_file);
		return rc;
	}

	return 0;
}
