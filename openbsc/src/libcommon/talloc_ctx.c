#include <osmocom/core/talloc.h>
#include <openbsc/gsm_data.h>

extern void *tall_msgb_ctx;
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

void talloc_ctx_init(void)
{
	tall_msgb_ctx = talloc_named_const(tall_bsc_ctx, 0, "msgb");
	tall_fle_ctx = talloc_named_const(tall_bsc_ctx, 0,
					  "bs11_file_list_entry");
	tall_locop_ctx = talloc_named_const(tall_bsc_ctx, 0, "loc_updating_oper");
	tall_authciphop_ctx = talloc_named_const(tall_bsc_ctx, 0, "auth_ciph_oper");
	tall_gsms_ctx = talloc_named_const(tall_bsc_ctx, 0, "sms");
	tall_subscr_ctx = talloc_named_const(tall_bsc_ctx, 0, "subscriber");
	tall_sub_req_ctx = talloc_named_const(tall_bsc_ctx, 0, "subscr_request");
	tall_call_ctx = talloc_named_const(tall_bsc_ctx, 0, "gsm_call");
	tall_paging_ctx = talloc_named_const(tall_bsc_ctx, 0, "paging_request");
	tall_sigh_ctx = talloc_named_const(tall_bsc_ctx, 0, "signal_handler");
	tall_tqe_ctx = talloc_named_const(tall_bsc_ctx, 0, "subch_txq_entry");
	tall_trans_ctx = talloc_named_const(tall_bsc_ctx, 0, "transaction");
	tall_map_ctx = talloc_named_const(tall_bsc_ctx, 0, "trau_map_entry");
	tall_upq_ctx = talloc_named_const(tall_bsc_ctx, 0, "trau_upq_entry");
	tall_ctr_ctx = talloc_named_const(tall_bsc_ctx, 0, "counter");
}
