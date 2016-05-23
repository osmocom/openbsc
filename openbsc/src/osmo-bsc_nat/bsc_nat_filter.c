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

#include <openbsc/bsc_nat.h>
#include <openbsc/bsc_nat_sccp.h>
#include <openbsc/bsc_msg_filter.h>
#include <openbsc/debug.h>

#include <osmocom/gsm/gsm0808.h>

#include <osmocom/gsm/protocol/gsm_08_08.h>
#include <osmocom/gsm/protocol/gsm_04_11.h>

#include <osmocom/sccp/sccp.h>

/* Filter out CR data... */
int bsc_nat_filter_sccp_cr(struct bsc_connection *bsc, struct msgb *msg,
			struct bsc_nat_parsed *parsed, int *con_type,
			char **imsi, struct bsc_filter_reject_cause *cause)
{
	struct bsc_filter_request req;
	struct tlv_parsed tp;
	struct gsm48_hdr *hdr48;
	int hdr48_len;
	int len;

	*con_type = FLT_CON_TYPE_NONE;
	cause->cm_reject_cause = GSM48_REJECT_PLMN_NOT_ALLOWED;
	cause->lu_reject_cause = GSM48_REJECT_PLMN_NOT_ALLOWED;
	*imsi = NULL;

	if (parsed->gsm_type != BSS_MAP_MSG_COMPLETE_LAYER_3) {
		LOGP(DNAT, LOGL_ERROR,
		     "Rejecting CR message due wrong GSM Type %d\n", parsed->gsm_type);
		return -1;
	}

	/* the parsed has had some basic l3 length check */
	len = msg->l3h[1];
	if (msgb_l3len(msg) - 3 < len) {
		LOGP(DNAT, LOGL_ERROR,
		     "The CR Data has not enough space...\n");
		return -1;
	}

	msg->l4h = &msg->l3h[3];
	len -= 1;

	tlv_parse(&tp, gsm0808_att_tlvdef(), msg->l4h, len, 0, 0);

	if (!TLVP_PRESENT(&tp, GSM0808_IE_LAYER_3_INFORMATION)) {
		LOGP(DNAT, LOGL_ERROR, "CR Data does not contain layer3 information.\n");
		return -1;
	}

	hdr48_len = TLVP_LEN(&tp, GSM0808_IE_LAYER_3_INFORMATION);

	if (hdr48_len < sizeof(*hdr48)) {
		LOGP(DNAT, LOGL_ERROR, "GSM48 header does not fit.\n");
		return -1;
	}

	hdr48 = (struct gsm48_hdr *) TLVP_VAL(&tp, GSM0808_IE_LAYER_3_INFORMATION);
	req.ctx = bsc;
	req.black_list = &bsc->nat->imsi_black_list;
	req.access_lists = &bsc->nat->access_lists;
	req.local_lst_name = bsc->cfg->acc_lst_name;
	req.global_lst_name = bsc->nat->acc_lst_name;
	req.bsc_nr = bsc->cfg->nr;
	return bsc_msg_filter_initial(hdr48, hdr48_len, &req, con_type, imsi, cause);
}

int bsc_nat_filter_dt(struct bsc_connection *bsc, struct msgb *msg,
		struct nat_sccp_connection *con, struct bsc_nat_parsed *parsed,
		struct bsc_filter_reject_cause *cause)
{
	uint32_t len;
	struct gsm48_hdr *hdr48;
	struct bsc_filter_request req;

	cause->cm_reject_cause = GSM48_REJECT_PLMN_NOT_ALLOWED;
	cause->lu_reject_cause = GSM48_REJECT_PLMN_NOT_ALLOWED;

	if (con->filter_state.imsi_checked)
		return 0;

	/* only care about DTAP messages */
	if (parsed->bssap != BSSAP_MSG_DTAP)
		return 0;

	hdr48 = bsc_unpack_dtap(parsed, msg, &len);
	if (!hdr48)
		return -1;

	req.ctx = con;
	req.black_list = &bsc->nat->imsi_black_list;
	req.access_lists = &bsc->nat->access_lists;
	req.local_lst_name = bsc->cfg->acc_lst_name;
	req.global_lst_name = bsc->nat->acc_lst_name;
	req.bsc_nr = bsc->cfg->nr;
	return bsc_msg_filter_data(hdr48, len, &req, &con->filter_state, cause);
}
