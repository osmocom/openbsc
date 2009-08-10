/* GSM 04.07 Transaction handling */

/* (C) 2009 by Harald Welte <laforge@gnumonks.org>
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

#include <openbsc/transaction.h>
#include <openbsc/gsm_data.h>
#include <openbsc/mncc.h>
#include <openbsc/debug.h>
#include <openbsc/talloc.h>
#include <openbsc/gsm_subscriber.h>
#include <openbsc/gsm_04_08.h>
#include <openbsc/mncc.h>
#include <openbsc/paging.h>

static void *tall_trans_ctx;

void _gsm48_cc_trans_free(struct gsm_trans *trans);

struct gsm_trans *trans_find_by_id(struct gsm_subscriber *subscr,
				   u_int8_t proto, u_int8_t trans_id)
{
	struct gsm_trans *trans;
	struct gsm_network *net = subscr->net;

	llist_for_each_entry(trans, &net->trans_list, entry) {
		if (trans->subscr == subscr &&
		    trans->protocol == proto &&
		    trans->transaction_id == trans_id)
			return trans;
	}
	return NULL;
}

struct gsm_trans *trans_find_by_callref(struct gsm_network *net,
					u_int32_t callref)
{
	struct gsm_trans *trans;

	llist_for_each_entry(trans, &net->trans_list, entry) {
		if (trans->callref == callref)
			return trans;
	}
	return NULL;
}

struct gsm_trans *trans_alloc(struct gsm_subscriber *subscr,
			      u_int8_t protocol, u_int8_t trans_id,
			      u_int32_t callref)
{
	struct gsm_trans *trans;

	DEBUGP(DCC, "subscr=%p, subscr->net=%p\n", subscr, subscr->net);

	trans = talloc_zero(tall_trans_ctx, struct gsm_trans);
	if (!trans)
		return NULL;

	trans->subscr = subscr;
	subscr_get(trans->subscr);

	trans->protocol = protocol;
	trans->transaction_id = trans_id;
	trans->callref = callref;

	llist_add_tail(&trans->entry, &subscr->net->trans_list);

	return trans;
}

void trans_free(struct gsm_trans *trans)
{
	struct gsm_bts *bts;

	switch (trans->protocol) {
	case GSM48_PDISC_CC:
		_gsm48_cc_trans_free(trans);
		break;
	}

	if (trans->lchan)
		put_lchan(trans->lchan);

	if (!trans->lchan && trans->subscr && trans->subscr->net) {
		/* Stop paging on all bts' */
		bts = NULL;
		do {
			bts = gsm_bts_by_lac(trans->subscr->net,
					     trans->subscr->lac, bts);
			if (!bts)
				break;
			/* Stop paging */
			paging_request_stop(bts, trans->subscr, NULL);
		} while (1);
	}

	if (trans->subscr)
		subscr_put(trans->subscr);

	llist_del(&trans->entry);

	talloc_free(trans);
}

/* allocate an unused transaction ID for the given subscriber
 * in the given protocol using the ti_flag specified */
int trans_assign_trans_id(struct gsm_subscriber *subscr,
			  u_int8_t protocol, u_int8_t ti_flag)
{
	struct gsm_network *net = subscr->net;
	struct gsm_trans *trans;
	unsigned int used_tid_bitmask = 0;
	int i;

	if (ti_flag)
		ti_flag = 0x8;

	/* generate bitmask of already-used TIDs for this (subscr,proto) */
	llist_for_each_entry(trans, &net->trans_list, entry) {
		if (trans->subscr != subscr ||
		    trans->protocol != protocol ||
		    trans->transaction_id == 0xff)
			continue;
		used_tid_bitmask |= (1 << trans->transaction_id);
	}

	for (i = 0; i <= 7; i++) {
		if ((used_tid_bitmask & (1 << (i | ti_flag))) == 0)
			return i | ti_flag;
	}

	return -1;
}
