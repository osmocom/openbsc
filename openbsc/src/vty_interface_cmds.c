/* OpenBSC logging helper for the VTY */
/* (C) 2009-2010 by Harald Welte <laforge@gnumonks.org>
 * (C) 2009-2010 by Holger Hans Peter Freyther
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

#include <openbsc/vty.h>
#include <openbsc/telnet_interface.h>

#include <osmocore/talloc.h>

#include <vty/command.h>
#include <vty/buffer.h>
#include <vty/vty.h>

#include <stdlib.h>

static void _vty_output(struct log_target *tgt, const char *line)
{
	struct vty *vty = tgt->tgt_vty.vty;
	vty_out(vty, "%s", line);
	/* This is an ugly hack, but there is no easy way... */
	if (strchr(line, '\n'))
		vty_out(vty, "\r");
}

struct log_target *log_target_create_vty(struct vty *vty)
{
	struct log_target *target;

	target = log_target_create();
	if (!target)
		return NULL;

	target->tgt_vty.vty = vty;
	target->output = _vty_output;
	return target;
}

DEFUN(enable_logging,
      enable_logging_cmd,
      "logging enable",
      "Enables logging to this vty\n")
{
	struct telnet_connection *conn;

	conn = (struct telnet_connection *) vty->priv;
	if (conn->dbg) {
		vty_out(vty, "Logging already enabled.%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	conn->dbg = log_target_create_vty(vty);
	if (!conn->dbg)
		return CMD_WARNING;

	log_add_target(conn->dbg);
	return CMD_SUCCESS;
}

DEFUN(logging_fltr_imsi,
      logging_fltr_imsi_cmd,
      "logging filter imsi IMSI",
      "Print all messages related to a IMSI\n")
{
	struct telnet_connection *conn;

	conn = (struct telnet_connection *) vty->priv;
	if (!conn->dbg) {
		vty_out(vty, "Logging was not enabled.%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	log_set_imsi_filter(conn->dbg, argv[0]);
	return CMD_SUCCESS;
}

DEFUN(logging_fltr_all,
      logging_fltr_all_cmd,
      "logging filter all <0-1>",
      "Print all messages to the console\n")
{
	struct telnet_connection *conn;

	conn = (struct telnet_connection *) vty->priv;
	if (!conn->dbg) {
		vty_out(vty, "Logging was not enabled.%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	log_set_all_filter(conn->dbg, atoi(argv[0]));
	return CMD_SUCCESS;
}

DEFUN(logging_use_clr,
      logging_use_clr_cmd,
      "logging color <0-1>",
      "Use color for printing messages\n")
{
	struct telnet_connection *conn;

	conn = (struct telnet_connection *) vty->priv;
	if (!conn->dbg) {
		vty_out(vty, "Logging was not enabled.%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	log_set_use_color(conn->dbg, atoi(argv[0]));
	return CMD_SUCCESS;
}

DEFUN(logging_prnt_timestamp,
      logging_prnt_timestamp_cmd,
      "logging timestamp <0-1>",
      "Print the timestamp of each message\n")
{
	struct telnet_connection *conn;

	conn = (struct telnet_connection *) vty->priv;
	if (!conn->dbg) {
		vty_out(vty, "Logging was not enabled.%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	log_set_print_timestamp(conn->dbg, atoi(argv[0]));
	return CMD_SUCCESS;
}

/* FIXME: those have to be kept in sync with the log levels and categories */
#define VTY_DEBUG_CATEGORIES "(rll|cc|mm|rr|rsl|nm|sms|pag|mncc|inp|mi|mib|mux|meas|sccp|msc|mgcp|ho|db|ref)"
#define VTY_DEBUG_LEVELS "(everything|debug|info|notice|error|fatal)"
DEFUN(logging_level,
      logging_level_cmd,
      "logging level " VTY_DEBUG_CATEGORIES " " VTY_DEBUG_LEVELS,
      "Set the log level for a specified category\n")
{
	struct telnet_connection *conn;
	int category = log_parse_category(argv[0]);
	int level = log_parse_level(argv[1]);

	conn = (struct telnet_connection *) vty->priv;
	if (!conn->dbg) {
		vty_out(vty, "Logging was not enabled.%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	if (category < 0) {
		vty_out(vty, "Invalid category `%s'%s", argv[0], VTY_NEWLINE);
		return CMD_WARNING;
	}

	if (level < 0) {
		vty_out(vty, "Invalid level `%s'%s", argv[1], VTY_NEWLINE);
		return CMD_WARNING;
	}

	conn->dbg->categories[category].enabled = 1;
	conn->dbg->categories[category].loglevel = level;

	return CMD_SUCCESS;
}

DEFUN(logging_set_category_mask,
      logging_set_category_mask_cmd,
      "logging set log mask MASK",
      "Decide which categories to output.\n")
{
	struct telnet_connection *conn;

	conn = (struct telnet_connection *) vty->priv;
	if (!conn->dbg) {
		vty_out(vty, "Logging was not enabled.%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	log_parse_category_mask(conn->dbg, argv[0]);
	return CMD_SUCCESS;
}

DEFUN(logging_set_log_level,
      logging_set_log_level_cmd,
      "logging set log level <0-8>",
      "Set the global log level. The value 0 implies no filtering.\n")
{
	struct telnet_connection *conn;

	conn = (struct telnet_connection *) vty->priv;
	if (!conn->dbg) {
		vty_out(vty, "Logging was not enabled.%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	log_set_log_level(conn->dbg, atoi(argv[0]));
	return CMD_SUCCESS;
}

DEFUN(diable_logging,
      disable_logging_cmd,
      "logging disable",
      "Disables logging to this vty\n")
{
	struct telnet_connection *conn;

	conn = (struct telnet_connection *) vty->priv;
	if (!conn->dbg) {
		vty_out(vty, "Logging was not enabled.%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	log_del_target(conn->dbg);
	talloc_free(conn->dbg);
	conn->dbg = NULL;
	return CMD_SUCCESS;
}

void openbsc_vty_print_statistics(struct vty *vty, struct gsm_network *net)
{
	vty_out(vty, "Channel Requests        : %lu total, %lu no channel%s",
		counter_get(net->stats.chreq.total),
		counter_get(net->stats.chreq.no_channel), VTY_NEWLINE);
	vty_out(vty, "Paging                  : %lu attempted, %lu complete, %lu expired%s",
		counter_get(net->stats.paging.attempted),
		counter_get(net->stats.paging.completed),
		counter_get(net->stats.paging.expired), VTY_NEWLINE);
}

void openbsc_vty_add_cmds()
{
	install_element(VIEW_NODE, &enable_logging_cmd);
	install_element(VIEW_NODE, &disable_logging_cmd);
	install_element(VIEW_NODE, &logging_fltr_imsi_cmd);
	install_element(VIEW_NODE, &logging_fltr_all_cmd);
	install_element(VIEW_NODE, &logging_use_clr_cmd);
	install_element(VIEW_NODE, &logging_prnt_timestamp_cmd);
	install_element(VIEW_NODE, &logging_set_category_mask_cmd);
	install_element(VIEW_NODE, &logging_level_cmd);
	install_element(VIEW_NODE, &logging_set_log_level_cmd);

}
