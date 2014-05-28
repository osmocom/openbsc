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

static const struct value_string patch_modes[] = {
	{GBPROX_PATCH_DEFAULT, "default"},
	{GBPROX_PATCH_BSSGP, "bssgp"},
	{GBPROX_PATCH_LLC_ATTACH_REQ, "llc-attach-req"},
	{GBPROX_PATCH_LLC_ATTACH, "llc-attach"},
	{GBPROX_PATCH_LLC_GMM, "llc-gmm"},
	{GBPROX_PATCH_LLC, "llc"},
	{0, NULL}
};

static int config_write_gbproxy(struct vty *vty)
{
	vty_out(vty, "gbproxy%s", VTY_NEWLINE);

	vty_out(vty, " sgsn nsei %u%s", g_cfg->nsip_sgsn_nsei,
		VTY_NEWLINE);

	if (g_cfg->core_mcc > 0)
		vty_out(vty, " core-mobile-country-code %d%s",
			g_cfg->core_mcc, VTY_NEWLINE);
	if (g_cfg->core_mnc > 0)
		vty_out(vty, " core-mobile-network-code %d%s",
			g_cfg->core_mnc, VTY_NEWLINE);

	if (g_cfg->patch_mode != GBPROX_PATCH_DEFAULT)
		vty_out(vty, " patch-mode %s%s",
			get_value_string(patch_modes, g_cfg->patch_mode),
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

#define GBPROXY_CORE_MNC_STR "Use this network code for the backbone\n"

DEFUN(cfg_gbproxy_core_mnc,
      cfg_gbproxy_core_mnc_cmd,
      "core-mobile-network-code <1-999>",
      GBPROXY_CORE_MNC_STR "NCC value\n")
{
	g_cfg->core_mnc = atoi(argv[0]);
	return CMD_SUCCESS;
}

DEFUN(cfg_gbproxy_no_core_mnc,
      cfg_gbproxy_no_core_mnc_cmd,
      "no core-mobile-network-code",
      NO_STR GBPROXY_CORE_MNC_STR)
{
	g_cfg->core_mnc = 0;
	return CMD_SUCCESS;
}

#define GBPROXY_CORE_MCC_STR "Use this country code for the backbone\n"

DEFUN(cfg_gbproxy_core_mcc,
      cfg_gbproxy_core_mcc_cmd,
      "core-mobile-country-code <1-999>",
      GBPROXY_CORE_MCC_STR "MCC value\n")
{
	g_cfg->core_mcc = atoi(argv[0]);
	return CMD_SUCCESS;
}

DEFUN(cfg_gbproxy_no_core_mcc,
      cfg_gbproxy_no_core_mcc_cmd,
      "no core-mobile-country-code",
      NO_STR GBPROXY_CORE_MCC_STR)
{
	g_cfg->core_mcc = 0;
	return CMD_SUCCESS;
}

DEFUN(cfg_gbproxy_patch_mode,
      cfg_gbproxy_patch_mode_cmd,
      "patch-mode (default|bssgp|llc-attach-req|llc-attach|llc)",
      "Set patch mode\n"
      "Use build-in default (at least llc-attach-req)\n"
      "Only patch BSSGP headers\n"
      "Patch BSSGP headers and LLC Attach Request messages\n"
      "Patch BSSGP headers and LLC Attach Request/Accept messages\n"
      "Patch BSSGP headers and all supported GMM LLC messages\n"
      )
{
	int val = get_string_value(patch_modes, argv[0]);
	OSMO_ASSERT(val >= 0);
	g_cfg->patch_mode = val;
	return CMD_SUCCESS;
}



int gbproxy_vty_init(void)
{
	install_element_ve(&show_gbproxy_cmd);

	install_element(ENABLE_NODE, &delete_gb_bvci_cmd);
	install_element(ENABLE_NODE, &delete_gb_nsei_cmd);

	install_element(CONFIG_NODE, &cfg_gbproxy_cmd);
	install_node(&gbproxy_node, config_write_gbproxy);
	vty_install_default(GBPROXY_NODE);
	install_element(GBPROXY_NODE, &cfg_nsip_sgsn_nsei_cmd);
	install_element(GBPROXY_NODE, &cfg_gbproxy_core_mcc_cmd);
	install_element(GBPROXY_NODE, &cfg_gbproxy_core_mnc_cmd);
	install_element(GBPROXY_NODE, &cfg_gbproxy_no_core_mcc_cmd);
	install_element(GBPROXY_NODE, &cfg_gbproxy_no_core_mnc_cmd);
	install_element(GBPROXY_NODE, &cfg_gbproxy_patch_mode_cmd);

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

