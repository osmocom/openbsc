/* VTY interface for A-bis OML (Netowrk Management) */

/* (C) 2009-2010 by Harald Welte <laforge@gnumonks.org>
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

#include <osmocom/gsm/abis_nm.h>

#include <openbsc/gsm_data.h>
#include <osmocom/core/msgb.h>
#include <osmocom/gsm/tlv.h>
#include <osmocom/core/talloc.h>
#include <openbsc/debug.h>
#include <openbsc/signal.h>
#include <openbsc/abis_nm.h>
#include <openbsc/vty.h>

#include <osmocom/vty/vty.h>
#include <osmocom/vty/command.h>
#include <osmocom/vty/logging.h>
#include <osmocom/vty/telnet_interface.h>

extern struct gsm_network *bsc_gsmnet;

static struct cmd_node oml_node = {
	OML_NODE,
	"%s(oml)# ",
	1,
};

struct oml_node_state {
	struct gsm_bts *bts;
	uint8_t obj_class;
	uint8_t obj_inst[3];
};

static int dummy_config_write(struct vty *v)
{
	return CMD_SUCCESS;
}

/* FIXME: auto-generate those strings from the value_string lists */
#define NM_OBJCLASS_VTY "(site-manager|bts|radio-carrier|baseband-transceiver|channel|adjc|handover|power-contorl|btse|rack|test|envabtse|bport|gprs-nse|gprs-cell|gprs-nsvc|siemenshw)"
#define NM_OBJCLASS_VTY_HELP	"Site Manager Object\n"			\
				"BTS Object\n"				\
				"Radio Carrier Object\n"		\
				"Baseband Transceiver Object\n"		\
				"Channel (Timeslot) Object\n"		\
				"Adjacent Object (Siemens)\n"		\
				"Handover Object (Siemens)\n"		\
				"Power Control Object (Siemens)\n"	\
				"BTSE Object (Siemens)\n"		\
				"Rack Object (Siemens)\n"		\
				"Test Object (Siemens)\n"		\
				"ENVABTSE Object (Siemens)\n"		\
				"BPORT Object (Siemens)\n"		\
				"GPRS NSE Object (ip.access/osmo-bts)\n"	\
				"GPRS Cell Object (ip.acecss/osmo-bts)\n"	\
				"GPRS NSVC Object (ip.acecss/osmo-bts)\n"	\
				"SIEMENSHW Object (Siemens)\n"


DEFUN(oml_class_inst, oml_class_inst_cmd,
	"bts <0-255> oml class " NM_OBJCLASS_VTY
					" instance <0-255> <0-255> <0-255>",
	"BTS related commands\n" "BTS Number\n"
	"Manipulate the OML managed objects\n"
	"Object Class\n" 	NM_OBJCLASS_VTY_HELP
	"Object Instance\n" "BTS Number\n" "TRX Number\n" "TS Number\n")
{
	struct gsm_bts *bts;
	struct oml_node_state *oms;
	int bts_nr = atoi(argv[0]);

	bts = gsm_bts_num(gsmnet_from_vty(vty), bts_nr);
	if (!bts) {
		vty_out(vty, "%% No such BTS (%d)%s", bts_nr, VTY_NEWLINE);
		return CMD_WARNING;
	}

	oms = talloc_zero(tall_bsc_ctx, struct oml_node_state);
	if (!oms)
		return CMD_WARNING;

	oms->bts = bts;
	oms->obj_class = get_string_value(abis_nm_obj_class_names, argv[1]);
	oms->obj_inst[0] = atoi(argv[2]);
	oms->obj_inst[1] = atoi(argv[3]);
	oms->obj_inst[2] = atoi(argv[4]);

	vty->index = oms;
	vty->node = OML_NODE;

	return CMD_SUCCESS;

}

DEFUN(oml_classnum_inst, oml_classnum_inst_cmd,
	"bts <0-255> oml class <0-255> instance <0-255> <0-255> <0-255>",
	"BTS related commands\n" "BTS Number\n"
	"Manipulate the OML managed objects\n"
	"Object Class\n" "Object Class\n"
	"Object Instance\n" "BTS Number\n" "TRX Number\n" "TS Number\n")
{
	struct gsm_bts *bts;
	struct oml_node_state *oms;
	int bts_nr = atoi(argv[0]);

	bts = gsm_bts_num(gsmnet_from_vty(vty), bts_nr);
	if (!bts) {
		vty_out(vty, "%% No such BTS (%d)%s", bts_nr, VTY_NEWLINE);
		return CMD_WARNING;
	}

	oms = talloc_zero(tall_bsc_ctx, struct oml_node_state);
	if (!oms)
		return CMD_WARNING;

	oms->bts = bts;
	oms->obj_class = atoi(argv[1]);
	oms->obj_inst[0] = atoi(argv[2]);
	oms->obj_inst[1] = atoi(argv[3]);
	oms->obj_inst[2] = atoi(argv[4]);

	vty->index = oms;
	vty->node = OML_NODE;

	return CMD_SUCCESS;
}

DEFUN(oml_chg_adm_state, oml_chg_adm_state_cmd,
	"change-adm-state (locked|unlocked|shutdown|null)",
	"Change the Administrative State\n"
	"Locked\n" "Unlocked\n" "Shutdown\n" "NULL\n")
{
	struct oml_node_state *oms = vty->index;
	enum abis_nm_adm_state state;

	state = get_string_value(abis_nm_adm_state_names, argv[0]);

	abis_nm_chg_adm_state(oms->bts, oms->obj_class, oms->obj_inst[0],
			      oms->obj_inst[1], oms->obj_inst[2], state);

	return CMD_SUCCESS;
}

DEFUN(oml_opstart, oml_opstart_cmd,
	"opstart", "Send an OPSTART message to the object")
{
	struct oml_node_state *oms = vty->index;

	abis_nm_opstart(oms->bts, oms->obj_class, oms->obj_inst[0],
			oms->obj_inst[1], oms->obj_inst[2]);

	return CMD_SUCCESS;
}

int abis_nm_vty_init(void)
{
	install_element(ENABLE_NODE, &oml_class_inst_cmd);
	install_element(ENABLE_NODE, &oml_classnum_inst_cmd);
	install_node(&oml_node, dummy_config_write);

	vty_install_default(OML_NODE);
	install_element(OML_NODE, &oml_chg_adm_state_cmd);
	install_element(OML_NODE, &oml_opstart_cmd);

	return 0;
}
