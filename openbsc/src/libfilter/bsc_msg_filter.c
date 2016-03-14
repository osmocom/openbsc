/*
 * Access filtering
 */
/*
 * (C) 2010-2015 by Holger Hans Peter Freyther <zecke@selfish.org>
 * (C) 2010-2012 by On-Waves
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
#include <openbsc/bsc_msc.h>
#include <openbsc/gsm_data.h>
#include <openbsc/debug.h>
#include <openbsc/ipaccess.h>

#include <osmocom/core/talloc.h>
#include <osmocom/gsm/gsm0808.h>

#include <osmocom/gsm/protocol/gsm_08_08.h>
#include <osmocom/gsm/protocol/gsm_04_11.h>

int bsc_filter_barr_find(struct rb_root *root, const char *imsi, int *cm, int *lu)
{
	struct bsc_filter_barr_entry *n;
	n = rb_entry(root->rb_node, struct bsc_filter_barr_entry, node);

	while (n) {
		int rc = strcmp(imsi, n->imsi);
		if (rc == 0) {
			*cm = n->cm_reject_cause;
			*lu = n->lu_reject_cause;
			return 1;
		}

		n = rb_entry(
			(rc < 0) ? n->node.rb_left : n->node.rb_right,
			struct bsc_filter_barr_entry, node);
	};

	return 0;
}

static int insert_barr_node(struct bsc_filter_barr_entry *entry, struct rb_root *root)
{
	struct rb_node **new = &root->rb_node, *parent = NULL;

	while (*new) {
		int rc;
		struct bsc_filter_barr_entry *this;
		this = rb_entry(*new, struct bsc_filter_barr_entry, node);
		parent = *new;

		rc = strcmp(entry->imsi, this->imsi);
		if (rc < 0)
			new = &((*new)->rb_left);
		else if (rc > 0)
			new = &((*new)->rb_right);
		else {
			LOGP(DFILTER, LOGL_ERROR,
				"Duplicate entry for IMSI(%s)\n", entry->imsi);
			talloc_free(entry);
			return -1;
		}
	}

	rb_link_node(&entry->node, parent, new);
	rb_insert_color(&entry->node, root);
	return 0;
}

int bsc_filter_barr_adapt(void *ctx, struct rb_root *root,
			const struct osmo_config_list *list)
{
	struct osmo_config_entry *cfg_entry;
	int err = 0;

	/* free the old data */
	while (!RB_EMPTY_ROOT(root)) {
		struct rb_node *node = rb_first(root);
		rb_erase(node, root);
		talloc_free(node);
	}

	if (!list)
		return 0;

	/* now adapt the new list */
	llist_for_each_entry(cfg_entry, &list->entry, list) {
		struct bsc_filter_barr_entry *entry;
		entry = talloc_zero(ctx, struct bsc_filter_barr_entry);
		if (!entry) {
			LOGP(DFILTER, LOGL_ERROR,
				"Allocation of the barr entry failed.\n");
			continue;
		}

		entry->imsi = talloc_strdup(entry, cfg_entry->mcc);
		entry->cm_reject_cause = atoi(cfg_entry->mnc);
		entry->lu_reject_cause = atoi(cfg_entry->option);
		err |= insert_barr_node(entry, root);
	}

	return err;
}


static int lst_check_deny(struct bsc_msg_acc_lst *lst, const char *mi_string,
			int *cm_cause, int *lu_cause)
{
	struct bsc_msg_acc_lst_entry *entry;

	llist_for_each_entry(entry, &lst->fltr_list, list) {
		if (!entry->imsi_deny)
			continue;
		if (regexec(&entry->imsi_deny_re, mi_string, 0, NULL, 0) == 0) {
			*cm_cause = entry->cm_reject_cause;
			*lu_cause = entry->lu_reject_cause;
			return 0;
		}
	}

	return 1;
}

/* apply white/black list */
static int auth_imsi(struct bsc_filter_request *req,
		const char *imsi,
		struct bsc_filter_reject_cause *cause)
{
	/*
	 * Now apply blacklist/whitelist of the BSC and the NAT.
	 * 1.) Check the global IMSI barr list
	 * 2.) Allow directly if the IMSI is allowed at the BSC
	 * 3.) Reject if the IMSI is not allowed at the BSC
	 * 4.) Reject if the IMSI not allowed at the global level.
	 * 5.) Allow directly if the IMSI is allowed at the global level
	 */
	int cm, lu;
	struct bsc_msg_acc_lst *nat_lst = NULL;
	struct bsc_msg_acc_lst *bsc_lst = NULL;

	/* 1. global check for barred imsis */
	if (req->black_list && bsc_filter_barr_find(req->black_list, imsi, &cm, &lu)) {
		cause->cm_reject_cause = cm;
		cause->lu_reject_cause = lu;
		LOGP(DFILTER, LOGL_DEBUG,
			"Blocking subscriber IMSI %s with CM: %d LU: %d\n",
			imsi, cm, lu);
		return -4;
	}


	bsc_lst = bsc_msg_acc_lst_find(req->access_lists, req->local_lst_name);
	nat_lst = bsc_msg_acc_lst_find(req->access_lists, req->global_lst_name);


	if (bsc_lst) {
		/* 2. BSC allow */
		if (bsc_msg_acc_lst_check_allow(bsc_lst, imsi) == 0)
			return 1;

		/* 3. BSC deny */
		if (lst_check_deny(bsc_lst, imsi, &cm, &lu) == 0) {
			LOGP(DFILTER, LOGL_ERROR,
			     "Filtering %s by imsi_deny on config nr: %d.\n", imsi, req->bsc_nr);
			rate_ctr_inc(&bsc_lst->stats->ctr[ACC_LIST_LOCAL_FILTER]);
			cause->cm_reject_cause = cm;
			cause->lu_reject_cause = lu;
			return -2;
		}

	}

	/* 4. NAT deny */
	if (nat_lst) {
		if (lst_check_deny(nat_lst, imsi, &cm, &lu) == 0) {
			LOGP(DFILTER, LOGL_ERROR,
			     "Filtering %s global imsi_deny on bsc nr: %d.\n", imsi, req->bsc_nr);
			rate_ctr_inc(&nat_lst->stats->ctr[ACC_LIST_GLOBAL_FILTER]);
			cause->cm_reject_cause = cm;
			cause->lu_reject_cause = lu;
			return -3;
		}
	}

	return 1;
}

static int _cr_check_loc_upd(void *ctx,
			     uint8_t *data, unsigned int length,
			     char **imsi)
{
	uint8_t mi_type;
	struct gsm48_loc_upd_req *lu;
	char mi_string[GSM48_MI_SIZE];

	if (length < sizeof(*lu)) {
		LOGP(DFILTER, LOGL_ERROR,
		     "LU does not fit. Length is %d \n", length);
		return -1;
	}

	lu = (struct gsm48_loc_upd_req *) data;
	mi_type = lu->mi[0] & GSM_MI_TYPE_MASK;

	/*
	 * We can only deal with the IMSI. This will fail for a phone that
	 * will send the TMSI of a previous network to us.
	 */
	if (mi_type != GSM_MI_TYPE_IMSI)
		return 0;

	gsm48_mi_to_string(mi_string, sizeof(mi_string), lu->mi, lu->mi_len);
	*imsi = talloc_strdup(ctx, mi_string);
	return 1;
}

static int _cr_check_cm_serv_req(void *ctx,
				 uint8_t *data, unsigned int length,
				 int *con_type, char **imsi)
{
	static const uint32_t classmark_offset =
				offsetof(struct gsm48_service_request, classmark);

	char mi_string[GSM48_MI_SIZE];
	uint8_t mi_type;
	int rc;
	struct gsm48_service_request *req;

	/* unfortunately in Phase1 the classmark2 length is variable */

	if (length < sizeof(*req)) {
		LOGP(DFILTER, LOGL_ERROR,
		     "CM Serv Req does not fit. Length is %d\n", length);
		return -1;
	}

	req = (struct gsm48_service_request *) data;
	if (req->cm_service_type == 0x8)
		*con_type = FLT_CON_TYPE_SSA;
	rc = gsm48_extract_mi((uint8_t *) &req->classmark,
			      length - classmark_offset, mi_string, &mi_type);
	if (rc < 0) {
		LOGP(DFILTER, LOGL_ERROR, "Failed to parse the classmark2/mi. error: %d\n", rc);
		return -1;
	}

	/* we have to let the TMSI or such pass */
	if (mi_type != GSM_MI_TYPE_IMSI)
		return 0;

	*imsi = talloc_strdup(ctx, mi_string);
	return 1;
}

static int _cr_check_pag_resp(void *ctx,
			      uint8_t *data, unsigned int length, char **imsi)
{
	struct gsm48_pag_resp *resp;
	char mi_string[GSM48_MI_SIZE];
	uint8_t mi_type;

	if (length < sizeof(*resp)) {
		LOGP(DFILTER, LOGL_ERROR, "PAG RESP does not fit. Length was %d.\n", length);
		return -1;
	}

	resp = (struct gsm48_pag_resp *) data;
	if (gsm48_paging_extract_mi(resp, length, mi_string, &mi_type) < 0) {
		LOGP(DFILTER, LOGL_ERROR, "Failed to extract the MI.\n");
		return -1;
	}

	/* we need to let it pass for now */
	if (mi_type != GSM_MI_TYPE_IMSI)
		return 0;

	*imsi = talloc_strdup(ctx, mi_string);
	return 1;
}

static int _dt_check_id_resp(struct bsc_filter_request *req,
			     uint8_t *data, unsigned int length,
			     struct bsc_filter_state *state,
			     struct bsc_filter_reject_cause *cause)
{
	char mi_string[GSM48_MI_SIZE];
	uint8_t mi_type;

	if (length < 2) {
		LOGP(DFILTER, LOGL_ERROR, "mi does not fit.\n");
		return -1;
	}

	if (data[0] < length - 1) {
		LOGP(DFILTER, LOGL_ERROR, "mi length too big.\n");
		return -2;
	}

	mi_type = data[1] & GSM_MI_TYPE_MASK;
	gsm48_mi_to_string(mi_string, sizeof(mi_string), &data[1], data[0]);

	if (mi_type != GSM_MI_TYPE_IMSI)
		return 0;

	state->imsi_checked = 1;
	state->imsi = talloc_strdup(req->ctx, mi_string);
	return auth_imsi(req, mi_string, cause);
}


/* Filter out CR data... */
int bsc_msg_filter_initial(struct gsm48_hdr *hdr48, size_t hdr48_len,
			struct bsc_filter_request *req,
			int *con_type,
			char **imsi, struct bsc_filter_reject_cause *cause)
{
	int ret = 0;
	uint8_t msg_type, proto;

	*con_type = FLT_CON_TYPE_NONE;
	cause->cm_reject_cause = GSM48_REJECT_PLMN_NOT_ALLOWED;
	cause->lu_reject_cause = GSM48_REJECT_PLMN_NOT_ALLOWED;
	*imsi = NULL;

	proto = gsm48_hdr_pdisc(hdr48);
	msg_type = gsm48_hdr_msg_type(hdr48);
	if (proto == GSM48_PDISC_MM &&
	    msg_type == GSM48_MT_MM_LOC_UPD_REQUEST) {
		*con_type = FLT_CON_TYPE_LU;
		ret = _cr_check_loc_upd(req->ctx, &hdr48->data[0],
					hdr48_len - sizeof(*hdr48), imsi);
	} else if (proto == GSM48_PDISC_MM &&
		   msg_type == GSM48_MT_MM_CM_SERV_REQ) {
		*con_type = FLT_CON_TYPE_CM_SERV_REQ;
		ret = _cr_check_cm_serv_req(req->ctx, &hdr48->data[0],
					     hdr48_len - sizeof(*hdr48),
					     con_type, imsi);
	} else if (proto == GSM48_PDISC_RR &&
		   msg_type == GSM48_MT_RR_PAG_RESP) {
		*con_type = FLT_CON_TYPE_PAG_RESP;
		ret = _cr_check_pag_resp(req->ctx, &hdr48->data[0],
					hdr48_len - sizeof(*hdr48), imsi);
	} else {
		/* We only want to filter the above, let other things pass */
		*con_type = FLT_CON_TYPE_OTHER;
		return 0;
	}

	/* check if we are done */
	if (ret != 1)
		return ret;

	/* the memory allocation failed */
	if (!*imsi)
		return -1;

	/* now check the imsi */
	return auth_imsi(req, *imsi, cause);
}

int bsc_msg_filter_data(struct gsm48_hdr *hdr48, size_t len,
		struct bsc_filter_request *req,
		struct bsc_filter_state *state,
		struct bsc_filter_reject_cause *cause)
{
	uint8_t msg_type, proto;

	cause->cm_reject_cause = GSM48_REJECT_PLMN_NOT_ALLOWED;
	cause->lu_reject_cause = GSM48_REJECT_PLMN_NOT_ALLOWED;

	if (state->imsi_checked)
		return 0;

	proto = gsm48_hdr_pdisc(hdr48);
	msg_type = gsm48_hdr_msg_type(hdr48);
	if (proto != GSM48_PDISC_MM || msg_type != GSM48_MT_MM_ID_RESP)
		return 0;

	return _dt_check_id_resp(req, &hdr48->data[0],
					len - sizeof(*hdr48), state, cause);
}
