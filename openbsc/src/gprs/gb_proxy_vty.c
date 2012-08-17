/*
 * (C) 2010 by Harald Welte <laforge@gnumonks.org>
 * (C) 2010 by On-Waves
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

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <osmocom/core/talloc.h>

#include <osmocom/gprs/gprs_ns.h>

#include <openbsc/debug.h>
#include <openbsc/gb_proxy.h>
#include <openbsc/vty.h>

#include <osmocom/vty/command.h>
#include <osmocom/vty/vty.h>

static struct gbproxy_config *g_cfg = NULL;

/*
 * vty code for mgcp below
 */
static struct cmd_node gbproxy_node = {
	GBPROXY_NODE,
	"%s(config-gbproxy)# ",
	1,
};

static int config_write_gbproxy(struct vty *vty)
{
	vty_out(vty, "gbproxy%s", VTY_NEWLINE);

	vty_out(vty, " sgsn nsei %u%s", g_cfg->nsip_sgsn_nsei,
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

DEFUN(cfg_nsip_sgsn_nsei,
      cfg_nsip_sgsn_nsei_cmd,
      "sgsn nsei <0-65534>",
      "SGSN information\n"
      "NSEI to be used in the connection with the SGSN\n"
      "The NSEI\n")
{
	unsigned int port = atoi(argv[0]);

	g_cfg->nsip_sgsn_nsei = port;
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
	install_element(GBPROXY_NODE, &cfg_nsip_sgsn_nsei_cmd);

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

