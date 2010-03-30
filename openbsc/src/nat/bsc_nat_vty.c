/* OpenBSC NAT interface to quagga VTY */
/* (C) 2010 by Holger Hans Peter Freyther
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

#include <vty/command.h>
#include <vty/buffer.h>
#include <vty/vty.h>

#include <openbsc/bsc_nat.h>
#include <openbsc/gsm_04_08.h>

#include <osmocore/talloc.h>

#include <sccp/sccp.h>

#include <stdlib.h>

static struct bsc_nat *_nat;

static struct cmd_node nat_node = {
	NAT_NODE,
	"%s(nat)#",
	1,
};

static struct cmd_node bsc_node = {
	BSC_NODE,
	"%s(bsc)#",
	1,
};

static int config_write_nat(struct vty *vty)
{
	vty_out(vty, "nat%s", VTY_NEWLINE);
	return CMD_SUCCESS;
}

static void config_write_bsc_single(struct vty *vty, struct bsc_config *bsc)
{
	vty_out(vty, " bsc %u%s", bsc->nr, VTY_NEWLINE);
	vty_out(vty, "  token %s%s", bsc->token, VTY_NEWLINE);
	vty_out(vty, "  lac %u%s", bsc->lac, VTY_NEWLINE);
}

static int config_write_bsc(struct vty *vty)
{
	struct bsc_config *bsc;

	llist_for_each_entry(bsc, &_nat->bsc_configs, entry)
		config_write_bsc_single(vty, bsc);
	return CMD_SUCCESS;
}


DEFUN(show_sccp, show_sccp_cmd, "show connections sccp",
      SHOW_STR "Display information about current SCCP connections")
{
	struct sccp_connections *con;
	llist_for_each_entry(con, &_nat->sccp_connections, list_entry) {
		vty_out(vty, "SCCP for BSC: %d BSC ref: %u Local ref: %u%s",
			con->bsc->lac,
			sccp_src_ref_to_int(&con->real_ref),
			sccp_src_ref_to_int(&con->patched_ref), VTY_NEWLINE);
	}

	return CMD_SUCCESS;
}

DEFUN(show_bsc, show_bsc_cmd, "show connections bsc",
      SHOW_STR "Display information about current BSCs")
{
	struct bsc_connection *con;
	llist_for_each_entry(con, &_nat->bsc_connections, list_entry) {
		vty_out(vty, "BSC lac: %d auth: %d fd: %d%s",
			con->lac, con->authenticated, con->write_queue.bfd.fd, VTY_NEWLINE);
	}

	return CMD_SUCCESS;
}

DEFUN(show_bsc_cfg, show_bsc_cfg_cmd, "show bsc config",
      SHOW_STR "Display information about known BSC configs")
{
	struct bsc_config *conf;
	llist_for_each_entry(conf, &_nat->bsc_configs, entry) {
		vty_out(vty, "BSC token: '%s' lac: %u nr: %u%s",
			conf->token, conf->lac, conf->nr, VTY_NEWLINE);
	}

	return CMD_SUCCESS;
}


DEFUN(cfg_nat, cfg_nat_cmd, "nat", "Configute the NAT")
{
	vty->index = _nat;
	vty->node = NAT_NODE;

	return CMD_SUCCESS;
}

/* per BSC configuration */
DEFUN(cfg_bsc, cfg_bsc_cmd, "bsc BSC_NR", "Select a BSC to configure\n")
{
	int bsc_nr = atoi(argv[0]);
	struct bsc_config *bsc;

	if (bsc_nr > _nat->num_bsc) {
		vty_out(vty, "%% The next unused BSC number is %u%s",
			_nat->num_bsc, VTY_NEWLINE);
		return CMD_WARNING;
	} else if (bsc_nr == _nat->num_bsc) {
		/* allocate a new one */
		bsc = bsc_config_alloc(_nat, "unknown", 0);
	} else
		bsc = bsc_config_num(_nat, bsc_nr);

	if (!bsc)
		return CMD_WARNING;

	vty->index = bsc;
	vty->node = BSC_NODE;

	return CMD_SUCCESS;
}

DEFUN(cfg_bsc_token, cfg_bsc_token_cmd, "token TOKEN", "Set the token")
{
	struct bsc_config *conf = vty->index;

	if (conf->token)
	    talloc_free(conf->token);
	conf->token = talloc_strdup(conf, argv[0]);
	return CMD_SUCCESS;
}

DEFUN(cfg_bsc_lac, cfg_bsc_lac_cmd, "location_area_code <0-65535>",
      "Set the Location Area Code (LAC) of this BSC\n")
{
	struct bsc_config *tmp;
	struct bsc_config *conf = vty->index;

	int lac = atoi(argv[0]);

	if (lac < 0 || lac > 0xffff) {
		vty_out(vty, "%% LAC %d is not in the valid range (0-65535)%s",
			lac, VTY_NEWLINE);
		return CMD_WARNING;
	}

	if (lac == GSM_LAC_RESERVED_DETACHED || lac == GSM_LAC_RESERVED_ALL_BTS) {
		vty_out(vty, "%% LAC %d is reserved by GSM 04.08%s",
			lac, VTY_NEWLINE);
		return CMD_WARNING;
	}

	/* verify that the LACs are unique */
	llist_for_each_entry(tmp, &_nat->bsc_configs, entry) {
		if (tmp->lac == lac) {
			vty_out(vty, "%% LAC %d is already used.%s", lac, VTY_NEWLINE);
			return CMD_ERR_INCOMPLETE;
		}
	}

	conf->lac = lac;

	return CMD_SUCCESS;
}

int bsc_nat_vty_init(struct bsc_nat *nat)
{
	_nat = nat;

	cmd_init(1);
	vty_init();

	/* show commands */
	install_element(VIEW_NODE, &show_sccp_cmd);
	install_element(VIEW_NODE, &show_bsc_cmd);
	install_element(VIEW_NODE, &show_bsc_cfg_cmd);

	/* nat group */
	install_element(CONFIG_NODE, &cfg_nat_cmd);
	install_node(&nat_node, config_write_nat);
	install_default(NAT_NODE);

	/* BSC subgroups */
	install_element(NAT_NODE, &cfg_bsc_cmd);
	install_node(&bsc_node, config_write_bsc);
	install_default(BSC_NODE);
	install_element(BSC_NODE, &cfg_bsc_token_cmd);
	install_element(BSC_NODE, &cfg_bsc_lac_cmd);

	return 0;
}


/* called by the telnet interface... we have our own init above */
void bsc_vty_init()
{}
