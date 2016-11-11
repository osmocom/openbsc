/* OpenBSC allocation contexts initialization code */
/* (C) 2011-2016 by sysmocom s.f.m.c. GmbH <info@sysmocom.de>
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

#include <osmocom/core/talloc.h>
#include <osmocom/core/msgb.h>

extern void *tall_bsc_ctx;
extern void *tall_fle_ctx;
extern void *tall_locop_ctx;
extern void *tall_authciphop_ctx;
extern void *tall_gsms_ctx;
extern void *tall_subscr_ctx;
extern void *tall_sub_req_ctx;
extern void *tall_call_ctx;
extern void *tall_paging_ctx;
extern void *tall_sigh_ctx;
extern void *tall_tqe_ctx;
extern void *tall_trans_ctx;
extern void *tall_map_ctx;
extern void *tall_upq_ctx;
extern void *tall_ctr_ctx;

void talloc_ctx_init(void *ctx_root)
{
	msgb_talloc_ctx_init(ctx_root, 0);
	tall_fle_ctx = talloc_named_const(ctx_root, 0, "bs11_file_list_entry");
	tall_locop_ctx = talloc_named_const(ctx_root, 0, "loc_updating_oper");
	tall_authciphop_ctx = talloc_named_const(ctx_root, 0, "auth_ciph_oper");
	tall_gsms_ctx = talloc_named_const(ctx_root, 0, "sms");
	tall_subscr_ctx = talloc_named_const(ctx_root, 0, "subscriber");
	tall_sub_req_ctx = talloc_named_const(ctx_root, 0, "subscr_request");
	tall_call_ctx = talloc_named_const(ctx_root, 0, "gsm_call");
	tall_paging_ctx = talloc_named_const(ctx_root, 0, "paging_request");
	tall_sigh_ctx = talloc_named_const(ctx_root, 0, "signal_handler");
	tall_tqe_ctx = talloc_named_const(ctx_root, 0, "subch_txq_entry");
	tall_trans_ctx = talloc_named_const(ctx_root, 0, "transaction");
	tall_map_ctx = talloc_named_const(ctx_root, 0, "trau_map_entry");
	tall_upq_ctx = talloc_named_const(ctx_root, 0, "trau_upq_entry");
	tall_ctr_ctx = talloc_named_const(ctx_root, 0, "counter");
}
