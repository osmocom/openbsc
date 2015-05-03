/* (C) 2010-2015 by Holger Hans Peter Freyther
 * (C) 2010-2013 by On-Waves
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

#include <openbsc/bsc_msg_filter.h>
#include <openbsc/gsm_data.h>
#include <openbsc/vty.h>

#include <osmocom/vty/misc.h>

static struct llist_head *_acc_lst;
static void *_ctx;

DEFUN(cfg_lst_no,
      cfg_lst_no_cmd,
      "no access-list NAME",
      NO_STR "Remove an access-list by name\n"
      "The access-list to remove\n")
{
	struct bsc_msg_acc_lst *acc;
	acc = bsc_msg_acc_lst_find(_acc_lst, argv[0]);
	if (!acc)
		return CMD_WARNING;

	bsc_msg_acc_lst_delete(acc);
	return CMD_SUCCESS;
}

DEFUN(show_acc_lst,
      show_acc_lst_cmd,
      "show access-list NAME",
      SHOW_STR "IMSI access list\n" "Name of the access list\n")
{
	struct bsc_msg_acc_lst *acc;
	acc = bsc_msg_acc_lst_find(_acc_lst, argv[0]);
	if (!acc)
		return CMD_WARNING;

	vty_out(vty, "access-list %s%s", acc->name, VTY_NEWLINE);
	vty_out_rate_ctr_group(vty, " ", acc->stats);

	return CMD_SUCCESS;
}

DEFUN(cfg_lst_imsi_allow,
      cfg_lst_imsi_allow_cmd,
      "access-list NAME imsi-allow [REGEXP]",
      "Access list commands\n"
      "Name of the access list\n"
      "Add allowed IMSI to the list\n"
      "Regexp for IMSIs\n")
{
	struct bsc_msg_acc_lst *acc;
	struct bsc_msg_acc_lst_entry *entry;

	acc = bsc_msg_acc_lst_get(_ctx, _acc_lst, argv[0]);
	if (!acc)
		return CMD_WARNING;

	entry = bsc_msg_acc_lst_entry_create(acc);
	if (!entry)
		return CMD_WARNING;

	if (gsm_parse_reg(acc, &entry->imsi_allow_re, &entry->imsi_allow, argc - 1, &argv[1]) != 0)
		return CMD_WARNING;
	return CMD_SUCCESS;
}

DEFUN(cfg_lst_imsi_deny,
      cfg_lst_imsi_deny_cmd,
      "access-list NAME imsi-deny [REGEXP] (<0-256>) (<0-256>)",
      "Access list commands\n"
      "Name of the access list\n"
      "Add denied IMSI to the list\n"
      "Regexp for IMSIs\n"
      "CM Service Reject reason\n"
      "LU Reject reason\n")
{
	struct bsc_msg_acc_lst *acc;
	struct bsc_msg_acc_lst_entry *entry;

	acc = bsc_msg_acc_lst_get(_ctx, _acc_lst, argv[0]);
	if (!acc)
		return CMD_WARNING;

	entry = bsc_msg_acc_lst_entry_create(acc);
	if (!entry)
		return CMD_WARNING;

	if (gsm_parse_reg(acc, &entry->imsi_deny_re, &entry->imsi_deny, argc - 1, &argv[1]) != 0)
		return CMD_WARNING;
	if (argc >= 3)
		entry->cm_reject_cause = atoi(argv[2]);
	if (argc >= 4)
		entry->lu_reject_cause = atoi(argv[3]);
	return CMD_SUCCESS;
}

void bsc_msg_acc_lst_write(struct vty *vty, struct bsc_msg_acc_lst *lst)
{
	struct bsc_msg_acc_lst_entry *entry;

	llist_for_each_entry(entry, &lst->fltr_list, list) {
		if (entry->imsi_allow)
			vty_out(vty, " access-list %s imsi-allow %s%s",
				lst->name, entry->imsi_allow, VTY_NEWLINE);
		if (entry->imsi_deny)
			vty_out(vty, " access-list %s imsi-deny %s %d %d%s",
				lst->name, entry->imsi_deny,
				entry->cm_reject_cause, entry->lu_reject_cause,
				VTY_NEWLINE);
	}
}

void bsc_msg_lst_vty_init(void *ctx, struct llist_head *lst, int node)
{
	_ctx = ctx;
	_acc_lst = lst;
	install_element_ve(&show_acc_lst_cmd);

	/* access-list */
	install_element(node, &cfg_lst_imsi_allow_cmd);
	install_element(node, &cfg_lst_imsi_deny_cmd);
	install_element(node, &cfg_lst_no_cmd);
}
