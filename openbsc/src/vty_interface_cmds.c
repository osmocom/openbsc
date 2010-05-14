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

#define LOGGING_STR	"Configure log message to this terminal\n"

static void _vty_output(struct log_target *tgt, const char *line)
{
	struct vty *vty = tgt->tgt_vty.vty;
	vty_out(vty, "%s", line);
	/* This is an ugly hack, but there is no easy way... */
	if (strchr(line, '\n'))
		vty_out(vty, "\r");
}

struct buffer *vty_argv_to_buffer(int argc, const char *argv[], int base)
{
	struct buffer *b = buffer_new(NULL, 1024);
	int i;

	if (!b)
		return NULL;

	for (i = base; i < argc; i++) {
		buffer_putstr(b, argv[i]);
		buffer_putc(b, ' ');
	}
	buffer_putc(b, '\0');

	return b;
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
	LOGGING_STR
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
	LOGGING_STR
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
	LOGGING_STR
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
	LOGGING_STR
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
	LOGGING_STR
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
#define VTY_DEBUG_CATEGORIES "(rll|cc|mm|rr|rsl|nm|sms|pag|mncc|inp|mi|mib|mux|meas|sccp|msc|mgcp|ho|db|ref|gprs|ns|bssgp|llc|sndcp|all)"
#define CATEGORIES_HELP	\
	"A-bis Radio Link Layer (RLL)\n"			\
	"Layer3 Call Control (CC)\n"				\
	"Layer3 Mobility Management (MM)\n"			\
	"Layer3 Radio Resource (RR)\n"				\
	"A-bis Radio Signalling Link (RSL)\n"			\
	"A-bis Network Management / O&M (NM/OML)\n"		\
	"Layer3 Short Messagaging Service (SMS)\n"		\
	"Paging Subsystem\n"					\
	"MNCC API for Call Control application\n"		\
	"A-bis Input Subsystem\n"				\
	"A-bis Input Driver for Signalling\n"			\
	"A-bis Input Driver for B-Channel (voice data)\n"	\
	"A-bis B-Channel / Sub-channel Multiplexer\n"		\
	"Radio Measurements\n"					\
	"SCCP\n"						\
	"Mobile Switching Center\n"				\
	"Media Gateway Control Protocol\n"			\
	"Hand-over\n"						\
	"Database Layer\n"					\
	"Reference Counting\n"					\
	"GPRS Core\n"						\
	"GPRS Network Service (NS)\n"				\
	"GPRS BSS Gateway Protocol (BSSGP)\n"			\
	"GPRS Logical Link Control Protocol (LLC)\n"		\
	"GPRS Sub-Network Dependent Control Protocol (SNDCP)\n"	\
	"Global setting for all subsytems\n"

#define VTY_DEBUG_LEVELS "(everything|debug|info|notice|error|fatal)"
#define LEVELS_HELP	\
	"Log simply everything\n"				\
	"Log debug messages and higher levels\n"		\
	"Log informational messages and higher levels\n"	\
	"Log noticable messages and higher levels\n"		\
	"Log error messages and higher levels\n"		\
	"Log only fatal messages\n"
DEFUN(logging_level,
      logging_level_cmd,
      "logging level " VTY_DEBUG_CATEGORIES " " VTY_DEBUG_LEVELS,
      LOGGING_STR
      "Set the log level for a specified category\n"
      CATEGORIES_HELP
      LEVELS_HELP)
{
	struct telnet_connection *conn;
	int category = log_parse_category(argv[0]);
	int level = log_parse_level(argv[1]);

	conn = (struct telnet_connection *) vty->priv;
	if (!conn->dbg) {
		vty_out(vty, "Logging was not enabled.%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	if (level < 0) {
		vty_out(vty, "Invalid level `%s'%s", argv[1], VTY_NEWLINE);
		return CMD_WARNING;
	}

	/* Check for special case where we want to set global log level */
	if (!strcmp(argv[0], "all")) {
		log_set_log_level(conn->dbg, level);
		return CMD_SUCCESS;
	}

	if (category < 0) {
		vty_out(vty, "Invalid category `%s'%s", argv[0], VTY_NEWLINE);
		return CMD_WARNING;
	}

	conn->dbg->categories[category].enabled = 1;
	conn->dbg->categories[category].loglevel = level;

	return CMD_SUCCESS;
}

DEFUN(logging_set_category_mask,
      logging_set_category_mask_cmd,
      "logging set log mask MASK",
	LOGGING_STR
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

DEFUN(diable_logging,
      disable_logging_cmd,
      "logging disable",
	LOGGING_STR
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

static void vty_print_logtarget(struct vty *vty, const struct log_info *info,
				const struct log_target *tgt)
{
	unsigned int i;

	vty_out(vty, " Global Loglevel: %s%s",
		log_level_str(tgt->loglevel), VTY_NEWLINE);
	vty_out(vty, " Use color: %s, Print Timestamp: %s%s",
		tgt->use_color ? "On" : "Off",
		tgt->print_timestamp ? "On" : "Off", VTY_NEWLINE);

	vty_out(vty, " Log Level specific information:%s", VTY_NEWLINE);

	for (i = 0; i < info->num_cat; i++) {
		const struct log_category *cat = &tgt->categories[i];
		vty_out(vty, "  %-10s %-10s %-8s %s%s",
			info->cat[i].name+1, log_level_str(cat->loglevel),
			cat->enabled ? "Enabled" : "Disabled",
 			info->cat[i].description,
			VTY_NEWLINE);
	}
}

#define SHOW_LOG_STR "Show current logging configuration\n"

DEFUN(show_logging_vty,
      show_logging_vty_cmd,
      "show logging vty",
	SHOW_STR SHOW_LOG_STR
	"Show current logging configuration for this vty\n")
{
	struct telnet_connection *conn;

	conn = (struct telnet_connection *) vty->priv;
	if (!conn->dbg) {
		vty_out(vty, "Logging was not enabled.%s", VTY_NEWLINE);
		return CMD_WARNING;
	}
	vty_print_logtarget(vty, &log_info, conn->dbg);

	return CMD_SUCCESS;
}

gDEFUN(cfg_description, cfg_description_cmd,
	"description .TEXT",
	"Save human-readable decription of the object\n")
{
	char **dptr = vty->index_sub;
	struct buffer *b;

	if (!dptr) {
		vty_out(vty, "vty->index_sub == NULL%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	b = vty_argv_to_buffer(argc, argv, 0);
	if (!b)
		return CMD_WARNING;

	if (*dptr)
		talloc_free(*dptr);

	*dptr = talloc_strdup(NULL, buffer_getstr(b));

	buffer_free(b);

	return CMD_SUCCESS;
}

gDEFUN(cfg_no_description, cfg_no_description_cmd,
	"no description",
	NO_STR
	"Remove description of the object\n")
{
	char **dptr = vty->index_sub;

	if (!dptr) {
		vty_out(vty, "vty->index_sub == NULL%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	if (*dptr) {
		talloc_free(*dptr);
		*dptr = NULL;
	}

	return CMD_SUCCESS;
}

void openbsc_vty_print_statistics(struct vty *vty, struct gsm_network *net)
{
	vty_out(vty, "Channel Requests        : %lu total, %lu no channel%s",
		counter_get(net->stats.chreq.total),
		counter_get(net->stats.chreq.no_channel), VTY_NEWLINE);
	vty_out(vty, "Channel Failures        : %lu rf_failures, %lu rll failures%s",
		counter_get(net->stats.chan.rf_fail),
		counter_get(net->stats.chan.rll_err), VTY_NEWLINE);
	vty_out(vty, "Paging                  : %lu attempted, %lu complete, %lu expired%s",
		counter_get(net->stats.paging.attempted),
		counter_get(net->stats.paging.completed),
		counter_get(net->stats.paging.expired), VTY_NEWLINE);
	vty_out(vty, "BTS failures            : %lu OML, %lu RSL%s",
		counter_get(net->stats.bts.oml_fail),
		counter_get(net->stats.bts.rsl_fail), VTY_NEWLINE);
}

void openbsc_vty_add_cmds()
{
	install_element_ve(&enable_logging_cmd);
	install_element_ve(&disable_logging_cmd);
	install_element_ve(&logging_fltr_imsi_cmd);
	install_element_ve(&logging_fltr_all_cmd);
	install_element_ve(&logging_use_clr_cmd);
	install_element_ve(&logging_prnt_timestamp_cmd);
	install_element_ve(&logging_set_category_mask_cmd);
	install_element_ve(&logging_level_cmd);
	install_element_ve(&show_logging_vty_cmd);
}
