/* VTY interface for A-bis OM2000 */

/* (C) 2010-2011 by Harald Welte <laforge@gnumonks.org>
 *
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

#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <stdint.h>

#include <arpa/inet.h>

#include <openbsc/gsm_data.h>
#include <osmocore/msgb.h>
#include <osmocore/tlv.h>
#include <osmocore/talloc.h>
#include <openbsc/debug.h>
#include <openbsc/signal.h>
#include <openbsc/abis_om2000.h>
#include <openbsc/vty.h>

#include <osmocom/vty/vty.h>
#include <osmocom/vty/command.h>
#include <osmocom/vty/logging.h>
#include <osmocom/vty/telnet_interface.h>

extern struct gsm_network *bsc_gsmnet;

static struct cmd_node om2k_node = {
	OM2K_NODE,
	"%s(oml)# ",
	1,
};

struct oml_node_state {
	struct gsm_bts *bts;
	struct abis_om2k_mo mo;
};

static int dummy_config_write(struct vty *v)
{
	return CMD_SUCCESS;
}

/* FIXME: auto-generate those strings from the value_string lists */
#define OM2K_OBJCLASS_VTY "(trxc|ts|tf|is|con|dp|cf|tx|rx)"
#define OM2K_OBJCLASS_VTY_HELP "FIXME"

DEFUN(om2k_class_inst, om2k_class_inst_cmd,
	"bts <0-255> om2000 class " OM2K_OBJCLASS_VTY
					" <0-255> <0-255> <0-255>",
	"BTS related commands\n" "BTS Number\n"
	"Manipulate the OM2000 managed objects\n"
	"Object Class\n" 	OM2K_OBJCLASS_VTY_HELP
	"BTS Number\n" "Associated SO Instance\n" "Instance Number\n")
{
	struct gsm_bts *bts;
	struct oml_node_state *oms;
	int bts_nr = atoi(argv[0]);

	bts = gsm_bts_num(bsc_gsmnet, bts_nr);
	if (!bts) {
		vty_out(vty, "%% No such BTS (%d)%s", bts_nr, VTY_NEWLINE);
		return CMD_WARNING;
	}

	if (bts->type != GSM_BTS_TYPE_RBS2000) {
		vty_out(vty, "%% BTS %d not an Ericsson RBS%s",
			bts_nr, VTY_NEWLINE);
		return CMD_WARNING;
	}

	oms = talloc_zero(tall_bsc_ctx, struct oml_node_state);
	if (!oms)
		return CMD_WARNING;

	oms->bts = bts;
	oms->mo.class = get_string_value(om2k_mo_class_short_vals, argv[1]);
	oms->mo.bts = atoi(argv[2]);
	oms->mo.assoc_so = atoi(argv[3]);
	oms->mo.inst = atoi(argv[4]);

	vty->index = oms;
	vty->node = OM2K_NODE;

	return CMD_SUCCESS;

}

DEFUN(om2k_classnum_inst, om2k_classnum_inst_cmd,
	"bts <0-255> om2000 class <0-255> <0-255> <0-255> <0-255>",
	"BTS related commands\n" "BTS Number\n"
	"Manipulate the OML managed objects\n"
	"Object Class\n" "Object Class\n"
	"BTS Number\n" "Associated SO Instance\n" "Instance Number\n")
{
	struct gsm_bts *bts;
	struct oml_node_state *oms;
	int bts_nr = atoi(argv[0]);

	bts = gsm_bts_num(bsc_gsmnet, bts_nr);
	if (!bts) {
		vty_out(vty, "%% No such BTS (%d)%s", bts_nr, VTY_NEWLINE);
		return CMD_WARNING;
	}

	oms = talloc_zero(tall_bsc_ctx, struct oml_node_state);
	if (!oms)
		return CMD_WARNING;

	oms->bts = bts;
	oms->mo.class = atoi(argv[1]);
	oms->mo.bts = atoi(argv[2]);
	oms->mo.assoc_so = atoi(argv[3]);
	oms->mo.inst = atoi(argv[4]);

	vty->index = oms;
	vty->node = OM2K_NODE;

	return CMD_SUCCESS;
}

DEFUN(om2k_reset, om2k_reset_cmd,
	"reset-command",
	"Reset the MO\n")
{
	struct oml_node_state *oms = vty->index;

	abis_om2k_tx_reset_cmd(oms->bts, &oms->mo);
	return CMD_SUCCESS;
}

DEFUN(om2k_start, om2k_start_cmd,
	"start-request",
	"Start the MO\n")
{
	struct oml_node_state *oms = vty->index;

	abis_om2k_tx_start_req(oms->bts, &oms->mo);
	return CMD_SUCCESS;
}

DEFUN(om2k_status, om2k_status_cmd,
	"status-request",
	"Get the MO Status\n")
{
	struct oml_node_state *oms = vty->index;

	abis_om2k_tx_status_req(oms->bts, &oms->mo);
	return CMD_SUCCESS;
}

int abis_om2k_vty_init(void)
{
	install_element(ENABLE_NODE, &om2k_class_inst_cmd);
	install_element(ENABLE_NODE, &om2k_classnum_inst_cmd);
	install_node(&om2k_node, dummy_config_write);

	install_default(OM2K_NODE);
	install_element(OM2K_NODE, &ournode_exit_cmd);
	install_element(OM2K_NODE, &om2k_reset_cmd);
	install_element(OM2K_NODE, &om2k_start_cmd);
	install_element(OM2K_NODE, &om2k_status_cmd);

	return 0;
}
