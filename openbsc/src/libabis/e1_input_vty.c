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

#include <osmocom/core/linuxlist.h>
#include <osmocom/core/talloc.h>
#include <osmocom/core/utils.h>
#include <osmocom/gsm/gsm_utils.h>

#include <osmocom/vty/command.h>
#include <osmocom/vty/buffer.h>
#include <osmocom/vty/vty.h>
#include <osmocom/vty/logging.h>
#include <osmocom/vty/misc.h>
#include <osmocom/vty/telnet_interface.h>

#include <openbsc/gsm_data.h>
#include <openbsc/e1_input.h>
#include <openbsc/vty.h>
#include <openbsc/debug.h>

#include "../../bscconfig.h"

/* CONFIG */

#define E1_DRIVER_NAMES		"(misdn|dahdi)"
#define E1_DRIVER_HELP		"mISDN supported E1 Card\n" \
				"DAHDI supported E1/T1/J1 Card\n"

#define E1_LINE_HELP		"Configure E1/T1/J1 Line\n" "Line Number\n"

DEFUN(cfg_e1line_driver, cfg_e1_line_driver_cmd,
	"e1_line <0-255> driver " E1_DRIVER_NAMES,
	E1_LINE_HELP "Set driver for this line\n"
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

DEFUN(cfg_e1line_name, cfg_e1_line_name_cmd,
	"e1_line <0-255> name .LINE",
	E1_LINE_HELP "Set name for this line\n" "Human readable name\n")
{
	struct e1inp_line *line;
	int e1_nr = atoi(argv[0]);

	line = e1inp_line_get(e1_nr);
	if (!line) {
		vty_out(vty, "%% Line %d doesn't exist%s", e1_nr, VTY_NEWLINE);
		return CMD_WARNING;
	}
	if (line->name) {
		talloc_free((void *)line->name);
		line->name = NULL;
	}
	line->name = talloc_strdup(line, argv[1]);

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

	if (llist_empty(&e1inp_line_list))
		return CMD_SUCCESS;

	vty_out(vty, "e1_input%s", VTY_NEWLINE);

	llist_for_each_entry(line, &e1inp_line_list, list) {
		vty_out(vty, " e1_line %u driver %s%s", line->num,
			line->driver->name, VTY_NEWLINE);
		if (line->name)
			vty_out(vty, " e1_line %u name %s%s", line->num,
				line->name, VTY_NEWLINE);
	}
	return CMD_SUCCESS;
}

/* SHOW */

static void e1drv_dump_vty(struct vty *vty, struct e1inp_driver *drv)
{
	vty_out(vty, "E1 Input Driver %s%s", drv->name, VTY_NEWLINE);
}

DEFUN(show_e1drv,
      show_e1drv_cmd,
      "show e1_driver",
	SHOW_STR "Display information about available E1 drivers\n")
{
	struct e1inp_driver *drv;

	llist_for_each_entry(drv, &e1inp_driver_list, list)
		e1drv_dump_vty(vty, drv);

	return CMD_SUCCESS;
}

static void e1line_dump_vty(struct vty *vty, struct e1inp_line *line,
			    int stats)
{
	vty_out(vty, "E1 Line Number %u, Name %s, Driver %s%s",
		line->num, line->name ? line->name : "",
		line->driver->name, VTY_NEWLINE);
	if (stats)
		vty_out_rate_ctr_group(vty, " ", line->rate_ctr);
}

DEFUN(show_e1line,
      show_e1line_cmd,
      "show e1_line [line_nr] [stats]",
	SHOW_STR "Display information about a E1 line\n"
	"E1 Line Number\n")
{
	struct e1inp_line *line;
	int stats = 0;

	if (argc >= 1 && strcmp(argv[0], "stats")) {
		int num = atoi(argv[0]);
		if (argc >= 2)
			stats = 1;
		llist_for_each_entry(line, &e1inp_line_list, list) {
			if (line->num == num) {
				e1line_dump_vty(vty, line, stats);
				return CMD_SUCCESS;
			}
		}
		return CMD_WARNING;
	}

	if (argc >= 1 && !strcmp(argv[0], "stats"))
		stats = 1;

	llist_for_each_entry(line, &e1inp_line_list, list)
		e1line_dump_vty(vty, line, stats);

	return CMD_SUCCESS;
}

static void e1ts_dump_vty(struct vty *vty, struct e1inp_ts *ts)
{
	if (ts->type == E1INP_TS_TYPE_NONE)
		return;
	vty_out(vty, "E1 Timeslot %2u of Line %u is Type %s%s",
		ts->num, ts->line->num, e1inp_tstype_name(ts->type),
		VTY_NEWLINE);
}

DEFUN(show_e1ts,
      show_e1ts_cmd,
      "show e1_timeslot [line_nr] [ts_nr]",
	SHOW_STR "Display information about a E1 timeslot\n"
	"E1 Line Number\n" "E1 Timeslot Number\n")
{
	struct e1inp_line *line = NULL;
	struct e1inp_ts *ts;
	int ts_nr;

	if (argc == 0) {
		llist_for_each_entry(line, &e1inp_line_list, list) {
			for (ts_nr = 0; ts_nr < NUM_E1_TS; ts_nr++) {
				ts = &line->ts[ts_nr];
				e1ts_dump_vty(vty, ts);
			}
		}
		return CMD_SUCCESS;
	}
	if (argc >= 1) {
		int num = atoi(argv[0]);
		struct e1inp_line *l;
		llist_for_each_entry(l, &e1inp_line_list, list) {
			if (l->num == num) {
				line = l;
				break;
			}
		}
		if (!line) {
			vty_out(vty, "E1 line %s is invalid%s",
				argv[0], VTY_NEWLINE);
			return CMD_WARNING;
		}
	}
	if (argc >= 2) {
		ts_nr = atoi(argv[1]);
		if (ts_nr >= NUM_E1_TS) {
			vty_out(vty, "E1 timeslot %s is invalid%s",
				argv[1], VTY_NEWLINE);
			return CMD_WARNING;
		}
		ts = &line->ts[ts_nr];
		e1ts_dump_vty(vty, ts);
		return CMD_SUCCESS;
	} else {
		for (ts_nr = 0; ts_nr < NUM_E1_TS; ts_nr++) {
			ts = &line->ts[ts_nr];
			e1ts_dump_vty(vty, ts);
		}
		return CMD_SUCCESS;
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
	install_element(E1INP_NODE, &cfg_e1_line_name_cmd);

	install_element_ve(&show_e1drv_cmd);
	install_element_ve(&show_e1line_cmd);
	install_element_ve(&show_e1ts_cmd);

	return 0;
}
