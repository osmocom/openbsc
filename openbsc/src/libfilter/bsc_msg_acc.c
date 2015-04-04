/*
 * (C) 2010-2015 by Holger Hans Peter Freyther <zecke@selfish.org>
 * (C) 2010-2011 by On-Waves
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
#include <openbsc/bsc_nat.h>

#include <osmocom/core/rate_ctr.h>

#include <string.h>

static const struct rate_ctr_desc acc_list_ctr_description[] = {
	[ACC_LIST_BSC_FILTER]	= { "access-list.bsc-filter", "Rejected by rule for BSC"},
	[ACC_LIST_NAT_FILTER]	= { "access-list.nat-filter", "Rejected by rule for NAT"},
};

static const struct rate_ctr_group_desc bsc_cfg_acc_list_desc = {
	.group_name_prefix = "nat.filter",
	.group_description = "NAT Access-List Statistics",
	.num_ctr = ARRAY_SIZE(acc_list_ctr_description),
	.ctr_desc = acc_list_ctr_description,
};


int bsc_nat_lst_check_allow(struct bsc_nat_acc_lst *lst, const char *mi_string)
{
	struct bsc_nat_acc_lst_entry *entry;

	llist_for_each_entry(entry, &lst->fltr_list, list) {
		if (!entry->imsi_allow)
			continue;
		if (regexec(&entry->imsi_allow_re, mi_string, 0, NULL, 0) == 0)
			return 0;
	}

	return 1;
}

struct bsc_nat_acc_lst *bsc_nat_acc_lst_find(struct bsc_nat *nat, const char *name)
{
	struct bsc_nat_acc_lst *lst;

	if (!name)
		return NULL;

	llist_for_each_entry(lst, &nat->access_lists, list)
		if (strcmp(lst->name, name) == 0)
			return lst;

	return NULL;
}

struct bsc_nat_acc_lst *bsc_nat_acc_lst_get(struct bsc_nat *nat, const char *name)
{
	struct bsc_nat_acc_lst *lst;

	lst = bsc_nat_acc_lst_find(nat, name);
	if (lst)
		return lst;

	lst = talloc_zero(nat, struct bsc_nat_acc_lst);
	if (!lst) {
		LOGP(DNAT, LOGL_ERROR, "Failed to allocate access list");
		return NULL;
	}

	/* TODO: get the index right */
	lst->stats = rate_ctr_group_alloc(lst, &bsc_cfg_acc_list_desc, 0);
	if (!lst->stats) {
		talloc_free(lst);
		return NULL;
	}

	INIT_LLIST_HEAD(&lst->fltr_list);
	lst->name = talloc_strdup(lst, name);
	llist_add_tail(&lst->list, &nat->access_lists);
	return lst;
}

void bsc_nat_acc_lst_delete(struct bsc_nat_acc_lst *lst)
{
	llist_del(&lst->list);
	rate_ctr_group_free(lst->stats);
	talloc_free(lst);
}

struct bsc_nat_acc_lst_entry *bsc_nat_acc_lst_entry_create(struct bsc_nat_acc_lst *lst)
{
	struct bsc_nat_acc_lst_entry *entry;

	entry = talloc_zero(lst, struct bsc_nat_acc_lst_entry);
	if (!entry)
		return NULL;

	entry->cm_reject_cause = GSM48_REJECT_PLMN_NOT_ALLOWED;
	entry->lu_reject_cause = GSM48_REJECT_PLMN_NOT_ALLOWED;
	llist_add_tail(&entry->list, &lst->fltr_list);
	return entry;
}

