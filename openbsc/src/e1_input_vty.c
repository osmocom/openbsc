/* OpenBSC E1 vty interface */
/* (C) 2011 by Harald Welte <laforge@gnumonks.org>
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
#include <sys/types.h>

#include <osmocom/vty/command.h>
#include <osmocom/vty/buffer.h>
#include <osmocom/vty/vty.h>
#include <osmocom/vty/logging.h>
#include <osmocom/vty/telnet_interface.h>

#include <osmocore/linuxlist.h>
#include <openbsc/gsm_data.h>
#include <openbsc/e1_input.h>
#include <osmocore/utils.h>
#include <osmocore/gsm_utils.h>
#include <osmocore/talloc.h>
#include <openbsc/vty.h>
#include <openbsc/debug.h>

#include "../bscconfig.h"

#define E1_DRIVER_NAMES		"(misdn)"
#define E1_DRIVER_HELP		"mISDN supported E1 Card\n"

DEFUN(cfg_e1line_driver, cfg_e1_line_driver_cmd,
	"e1_line <0-255> driver " E1_DRIVER_NAMES,
	"Configure E1/T1/J1 Line\n" "Line Number\n" "Set driver for this line\n"
	E1_DRIVER_HELP)
{
	struct e1inp_line *line;
	int e1_nr = atoi(argv[0]);

	line = e1inp_line_get(e1_nr);
	if (line) {
		vty_out(vty, "%% Line %d already exists%s", e1_nr, VTY_NEWLINE);
		return CMD_WARNING;
	}
	line = e1inp_line_create(e1_nr, argv[1]);
	if (!line) {
		vty_out(vty, "%% Error creating line %d%s", e1_nr, VTY_NEWLINE);
		return CMD_WARNING;
	}

	return CMD_SUCCESS;
}

DEFUN(cfg_e1inp, cfg_e1inp_cmd,
	"e1_input",
	"Configure E1/T1/J1 TDM input\n")
{
	vty->node = E1INP_NODE;

	return CMD_SUCCESS;
}

static int e1inp_config_write(struct vty *vty)
{
	struct e1inp_line *line;

	llist_for_each_entry(line, &e1inp_line_list, list) {
		vty_out(vty, " e1_line %u driver %s%s", line->num,
			line->driver->name, VTY_NEWLINE);
	}
	return CMD_SUCCESS;
}

struct cmd_node e1inp_node = {
	E1INP_NODE,
	"%s(e1_input)#",
	1,
};

int e1inp_vty_init(void)
{
	install_element(CONFIG_NODE, &cfg_e1inp_cmd);
	install_node(&e1inp_node, e1inp_config_write);
	install_element(E1INP_NODE, &cfg_e1_line_driver_cmd);

	return 0;
}
