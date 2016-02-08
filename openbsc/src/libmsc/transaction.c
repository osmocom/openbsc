/* GSM 04.07 Transaction handling */

/* (C) 2009 by Harald Welte <laforge@gnumonks.org>
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

#include <openbsc/transaction.h>
#include <openbsc/gsm_data.h>
#include <openbsc/mncc.h>
#include <openbsc/debug.h>
#include <osmocom/core/talloc.h>
#include <openbsc/gsm_subscriber.h>
#include <openbsc/gsm_04_08.h>
#include <openbsc/mncc.h>
#include <openbsc/paging.h>
#include <openbsc/osmo_msc.h>

void *tall_trans_ctx;

void _gsm48_cc_trans_free(struct gsm_trans *trans);

struct gsm_trans *trans_find_by_id(struct gsm_subscriber_connection *conn,
				   uint8_t proto, uint8_t trans_id)
{
	struct gsm_trans *trans;
	struct gsm_network *net = conn->network;
	struct gsm_subscriber *subscr = conn->subscr;

	llist_for_each_entry(trans, &net->trans_list, entry) {
		if (trans->subscr == subscr &&
		    trans->protocol == proto &&
		    trans->transaction_id == trans_id)
			return trans;
	}
	return NULL;
}

struct gsm_trans *trans_find_by_callref(struct gsm_network *net,
					uint32_t callref)
{
	struct gsm_trans *trans;

	llist_for_each_entry(trans, &net->trans_list, entry) {
		if (trans->callref == callref)
			return trans;
	}
	return NULL;
}

struct gsm_trans *trans_alloc(struct gsm_network *net,
			      struct gsm_subscriber *subscr,
			      uint8_t protocol, uint8_t trans_id,
			      uint32_t callref)
{
	struct gsm_trans *trans;

	DEBUGP(DCC, "subscr=%p, net=%p\n", subscr, net);

	trans = talloc_zero(tall_trans_ctx, struct gsm_trans);
	if (!trans)
		return NULL;

	trans->subscr = subscr;
	subscr_get(trans->subscr);

	trans->protocol = protocol;
	trans->transaction_id = trans_id;
	trans->callref = callref;

	trans->net = net;
	llist_add_tail(&trans->entry, &net->trans_list);

	return trans;
}

void trans_free(struct gsm_trans *trans)
{
	switch (trans->protocol) {
	case GSM48_PDISC_CC:
		_gsm48_cc_trans_free(trans);
		break;
	case GSM48_PDISC_SMS:
		_gsm411_sms_trans_free(trans);
		break;
	}

	if (trans->paging_request) {
		subscr_remove_request(trans->paging_request);
		trans->paging_request = NULL;
	}

	if (trans->subscr) {
		subscr_put(trans->subscr);
		trans->subscr = NULL;
	}

	llist_del(&trans->entry);

	if (trans->conn)
		msc_release_connection(trans->conn);

	trans->conn = NULL;
	talloc_free(trans);
}

/* allocate an unused transaction ID for the given subscriber
 * in the given protocol using the ti_flag specified */
int trans_assign_trans_id(struct gsm_network *net, struct gsm_subscriber *subscr,
			  uint8_t protocol, uint8_t ti_flag)
{
	struct gsm_trans *trans;
	unsigned int used_tid_bitmask = 0;
	int i, j, h;

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

	/* find a new one, trying to go in a 'circular' pattern */
	for (h = 6; h > 0; h--)
		if (used_tid_bitmask & (1 << (h | ti_flag)))
			break;
	for (i = 0; i < 7; i++) {
		j = ((h + i) % 7) | ti_flag;
		if ((used_tid_bitmask & (1 << j)) == 0)
			return j;
	}

	return -1;
}

int trans_has_conn(const struct gsm_subscriber_connection *conn)
{
	struct gsm_trans *trans;

	llist_for_each_entry(trans, &conn->network->trans_list, entry)
		if (trans->conn == conn)
			return 1;

	return 0;
}
