
/* BSC Multiplexer/NAT Utilities */

/*
 * (C) 2010-2011 by Holger Hans Peter Freyther <zecke@selfish.org>
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

#include <openbsc/bsc_nat.h>
#include <openbsc/bsc_nat_sccp.h>
#include <openbsc/bsc_msc.h>
#include <openbsc/gsm_data.h>
#include <openbsc/debug.h>
#include <openbsc/ipaccess.h>
#include <openbsc/vty.h>

#include <osmocom/core/linuxlist.h>
#include <osmocom/core/talloc.h>
#include <osmocom/gsm/gsm0808.h>

#include <osmocom/gsm/protocol/gsm_08_08.h>
#include <osmocom/gsm/protocol/gsm_04_11.h>

#include <osmocom/sccp/sccp.h>

#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

static const struct rate_ctr_desc bsc_cfg_ctr_description[] = {
	[BCFG_CTR_SCCP_CONN]     = { "sccp.conn",      "SCCP Connections         "},
	[BCFG_CTR_SCCP_CALLS]    = { "sccp.calls",     "SCCP Assignment Commands "},
	[BCFG_CTR_NET_RECONN]    = { "net.reconnects", "Network reconnects       "},
	[BCFG_CTR_DROPPED_SCCP]  = { "dropped.sccp",   "Dropped SCCP connections."},
	[BCFG_CTR_DROPPED_CALLS] = { "dropped.calls",  "Dropped active calls.    "},
	[BCFG_CTR_REJECTED_CR]   = { "rejected.cr",    "Rejected CR due filter   "},
	[BCFG_CTR_REJECTED_MSG]  = { "rejected.msg",   "Rejected MSG due filter  "},
	[BCFG_CTR_ILL_PACKET]    = { "rejected.ill",   "Rejected due parse error "},
	[BCFG_CTR_CON_TYPE_LU]   = { "conn.lu",        "Conn Location Update     "},
	[BCFG_CTR_CON_CMSERV_RQ] = { "conn.rq",        "Conn CM Service Req      "},
	[BCFG_CTR_CON_PAG_RESP]  = { "conn.pag",       "Conn Paging Response     "},
	[BCFG_CTR_CON_SSA]       = { "conn.ssa",       "Conn USSD                "},
	[BCFG_CTR_CON_OTHER]     = { "conn.other",     "Conn Other               "},
};

static const struct rate_ctr_group_desc bsc_cfg_ctrg_desc = {
	.group_name_prefix = "nat.bsc",
	.group_description = "NAT BSC Statistics",
	.num_ctr = ARRAY_SIZE(bsc_cfg_ctr_description),
	.ctr_desc = bsc_cfg_ctr_description,
};

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

struct bsc_nat *bsc_nat_alloc(void)
{
	struct bsc_nat *nat = talloc_zero(tall_bsc_ctx, struct bsc_nat);
	if (!nat)
		return NULL;

	nat->main_dest = talloc_zero(nat, struct bsc_msc_dest);
	if (!nat->main_dest) {
		talloc_free(nat);
		return NULL;
	}

	INIT_LLIST_HEAD(&nat->sccp_connections);
	INIT_LLIST_HEAD(&nat->bsc_connections);
	INIT_LLIST_HEAD(&nat->paging_groups);
	INIT_LLIST_HEAD(&nat->bsc_configs);
	INIT_LLIST_HEAD(&nat->access_lists);
	INIT_LLIST_HEAD(&nat->dests);
	INIT_LLIST_HEAD(&nat->num_rewr);
	INIT_LLIST_HEAD(&nat->smsc_rewr);
	INIT_LLIST_HEAD(&nat->tpdest_match);
	INIT_LLIST_HEAD(&nat->sms_clear_tp_srr);
	INIT_LLIST_HEAD(&nat->sms_num_rewr);

	nat->stats.sccp.conn = osmo_counter_alloc("nat.sccp.conn");
	nat->stats.sccp.calls = osmo_counter_alloc("nat.sccp.calls");
	nat->stats.bsc.reconn = osmo_counter_alloc("nat.bsc.conn");
	nat->stats.bsc.auth_fail = osmo_counter_alloc("nat.bsc.auth_fail");
	nat->stats.msc.reconn = osmo_counter_alloc("nat.msc.conn");
	nat->stats.ussd.reconn = osmo_counter_alloc("nat.ussd.conn");
	nat->auth_timeout = 2;
	nat->ping_timeout = 20;
	nat->pong_timeout = 5;

	llist_add(&nat->main_dest->list, &nat->dests);
	nat->main_dest->ip = talloc_strdup(nat, "127.0.0.1");
	nat->main_dest->port = 5000;

	return nat;
}

void bsc_nat_set_msc_ip(struct bsc_nat *nat, const char *ip)
{
	bsc_replace_string(nat, &nat->main_dest->ip, ip);
}

struct bsc_connection *bsc_connection_alloc(struct bsc_nat *nat)
{
	struct bsc_connection *con = talloc_zero(nat, struct bsc_connection);
	if (!con)
		return NULL;

	con->nat = nat;
	osmo_wqueue_init(&con->write_queue, 100);
	INIT_LLIST_HEAD(&con->cmd_pending);
	return con;
}

struct bsc_config *bsc_config_alloc(struct bsc_nat *nat, const char *token)
{
	struct bsc_config *conf = talloc_zero(nat, struct bsc_config);
	if (!conf)
		return NULL;

	conf->token = talloc_strdup(conf, token);
	conf->nr = nat->num_bsc;
	conf->nat = nat;
	conf->max_endpoints = 32;
	conf->paging_group = PAGIN_GROUP_UNASSIGNED;

	INIT_LLIST_HEAD(&conf->lac_list);

	llist_add_tail(&conf->entry, &nat->bsc_configs);
	++nat->num_bsc;

	conf->stats.ctrg = rate_ctr_group_alloc(conf, &bsc_cfg_ctrg_desc, conf->nr);
	if (!conf->stats.ctrg) {
		talloc_free(conf);
		return NULL;
	}

	return conf;
}

void bsc_config_free(struct bsc_config *cfg)
{
	rate_ctr_group_free(cfg->stats.ctrg);
}

static void _add_lac(void *ctx, struct llist_head *list, int _lac)
{
	struct bsc_lac_entry *lac;

	llist_for_each_entry(lac, list, entry)
		if (lac->lac == _lac)
			return;

	lac = talloc_zero(ctx, struct bsc_lac_entry);
	if (!lac) {
		LOGP(DNAT, LOGL_ERROR, "Failed to allocate.\n");
		return;
	}

	lac->lac = _lac;
	llist_add_tail(&lac->entry, list);
}

static void _del_lac(struct llist_head *list, int _lac)
{
	struct bsc_lac_entry *lac;

	llist_for_each_entry(lac, list, entry)
		if (lac->lac == _lac) {
			llist_del(&lac->entry);
			talloc_free(lac);
			return;
		}
}

void bsc_config_add_lac(struct bsc_config *cfg, int _lac)
{
	_add_lac(cfg, &cfg->lac_list, _lac);
}

void bsc_config_del_lac(struct bsc_config *cfg, int _lac)
{
	_del_lac(&cfg->lac_list, _lac);
}

struct bsc_nat_paging_group *bsc_nat_paging_group_create(struct bsc_nat *nat, int group)
{
	struct bsc_nat_paging_group *pgroup;

	pgroup = talloc_zero(nat, struct bsc_nat_paging_group);
	if (!pgroup) {
		LOGP(DNAT, LOGL_ERROR, "Failed to allocate a paging group.\n");
		return NULL;
	}

	pgroup->nr = group;
	INIT_LLIST_HEAD(&pgroup->lists);
	llist_add_tail(&pgroup->entry, &nat->paging_groups);
	return pgroup;
}

void bsc_nat_paging_group_delete(struct bsc_nat_paging_group *pgroup)
{
	llist_del(&pgroup->entry);
	talloc_free(pgroup);
}

struct bsc_nat_paging_group *bsc_nat_paging_group_num(struct bsc_nat *nat, int group)
{
	struct bsc_nat_paging_group *pgroup;

	llist_for_each_entry(pgroup, &nat->paging_groups, entry)
		if (pgroup->nr == group)
			return pgroup;

	return NULL;
}

void bsc_nat_paging_group_add_lac(struct bsc_nat_paging_group *pgroup, int lac)
{
	_add_lac(pgroup, &pgroup->lists, lac);
}

void bsc_nat_paging_group_del_lac(struct bsc_nat_paging_group *pgroup, int lac)
{
	_del_lac(&pgroup->lists, lac);
}

int bsc_config_handles_lac(struct bsc_config *cfg, int lac_nr)
{
	struct bsc_nat_paging_group *pgroup;
	struct bsc_lac_entry *entry;

	llist_for_each_entry(entry, &cfg->lac_list, entry)
		if (entry->lac == lac_nr)
			return 1;

	/* now lookup the paging group */
	pgroup = bsc_nat_paging_group_num(cfg->nat, cfg->paging_group);
	if (!pgroup)
		return 0;

	llist_for_each_entry(entry, &pgroup->lists, entry)
		if (entry->lac == lac_nr)
			return 1;

	return 0;
}

void sccp_connection_destroy(struct sccp_connections *conn)
{
	LOGP(DNAT, LOGL_DEBUG, "Destroy 0x%x <-> 0x%x mapping for con %p\n",
	     sccp_src_ref_to_int(&conn->real_ref),
	     sccp_src_ref_to_int(&conn->patched_ref), conn->bsc);
	bsc_mgcp_dlcx(conn);
	llist_del(&conn->list_entry);
	talloc_free(conn);
}


int bsc_nat_find_paging(struct msgb *msg,
			const uint8_t **out_data, int *out_leng)
{
	int data_length;
	const uint8_t *data;
	struct tlv_parsed tp;

	if (!msg->l3h || msgb_l3len(msg) < 3) {
		LOGP(DNAT, LOGL_ERROR, "Paging message is too short.\n");
		return -1;
	}

	tlv_parse(&tp, gsm0808_att_tlvdef(), msg->l3h + 3, msgb_l3len(msg) - 3, 0, 0);
	if (!TLVP_PRESENT(&tp, GSM0808_IE_CELL_IDENTIFIER_LIST)) {
		LOGP(DNAT, LOGL_ERROR, "No CellIdentifier List inside paging msg.\n");
		return -2;
	}

	data_length = TLVP_LEN(&tp, GSM0808_IE_CELL_IDENTIFIER_LIST);
	data = TLVP_VAL(&tp, GSM0808_IE_CELL_IDENTIFIER_LIST);

	/* No need to try a different BSS */
	if (data[0] == CELL_IDENT_BSS) {
		return -3;
	} else if (data[0] != CELL_IDENT_LAC) {
		LOGP(DNAT, LOGL_ERROR, "Unhandled cell ident discrminator: %d\n", data[0]);
		return -4;
	}

	*out_data = &data[1];
	*out_leng = data_length - 1;
	return 0;
}

int bsc_write_mgcp(struct bsc_connection *bsc, const uint8_t *data, unsigned int length)
{
	struct msgb *msg;

	if (length > 4096 - 128) {
		LOGP(DLINP, LOGL_ERROR, "Can not send message of that size.\n");
		return -1;
	}

	msg = msgb_alloc_headroom(4096, 128, "to-bsc");
	if (!msg) {
		LOGP(DLINP, LOGL_ERROR, "Failed to allocate memory for BSC msg.\n");
		return -1;
	}

	/* copy the data */
	msg->l3h = msgb_put(msg, length);
	memcpy(msg->l3h, data, length);

        return bsc_write(bsc, msg, IPAC_PROTO_MGCP_OLD);
}

int bsc_write(struct bsc_connection *bsc, struct msgb *msg, int proto)
{
	return bsc_do_write(&bsc->write_queue, msg, proto);
}

int bsc_do_write(struct osmo_wqueue *queue, struct msgb *msg, int proto)
{
	/* prepend the header */
	ipaccess_prepend_header(msg, proto);
	return bsc_write_msg(queue, msg);
}

int bsc_write_msg(struct osmo_wqueue *queue, struct msgb *msg)
{
	if (osmo_wqueue_enqueue(queue, msg) != 0) {
		LOGP(DLINP, LOGL_ERROR, "Failed to enqueue the write.\n");
		msgb_free(msg);
		return -1;
	}

	return 0;
}

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

static int lst_check_deny(struct bsc_nat_acc_lst *lst, const char *mi_string)
{
	struct bsc_nat_acc_lst_entry *entry;

	llist_for_each_entry(entry, &lst->fltr_list, list) {
		if (!entry->imsi_deny)
			continue;
		if (regexec(&entry->imsi_deny_re, mi_string, 0, NULL, 0) == 0)
			return 0;
	}

	return 1;
}

/* apply white/black list */
static int auth_imsi(struct bsc_connection *bsc, const char *mi_string)
{
	/*
	 * Now apply blacklist/whitelist of the BSC and the NAT.
	 * 1.) Allow directly if the IMSI is allowed at the BSC
	 * 2.) Reject if the IMSI is not allowed at the BSC
	 * 3.) Reject if the IMSI not allowed at the global level.
	 * 4.) Allow directly if the IMSI is allowed at the global level
	 */
	struct bsc_nat_acc_lst *nat_lst = NULL;
	struct bsc_nat_acc_lst *bsc_lst = NULL;

	bsc_lst = bsc_nat_acc_lst_find(bsc->nat, bsc->cfg->acc_lst_name);
	nat_lst = bsc_nat_acc_lst_find(bsc->nat, bsc->nat->acc_lst_name);


	if (bsc_lst) {
		/* 1. BSC allow */
		if (bsc_nat_lst_check_allow(bsc_lst, mi_string) == 0)
			return 1;

		/* 2. BSC deny */
		if (lst_check_deny(bsc_lst, mi_string) == 0) {
			LOGP(DNAT, LOGL_ERROR,
			     "Filtering %s by imsi_deny on bsc nr: %d.\n", mi_string, bsc->cfg->nr);
			rate_ctr_inc(&bsc_lst->stats->ctr[ACC_LIST_BSC_FILTER]);
			return -2;
		}

	}

	/* 3. NAT deny */
	if (nat_lst) {
		if (lst_check_deny(nat_lst, mi_string) == 0) {
			LOGP(DNAT, LOGL_ERROR,
			     "Filtering %s by nat imsi_deny on bsc nr: %d.\n", mi_string, bsc->cfg->nr);
			rate_ctr_inc(&nat_lst->stats->ctr[ACC_LIST_NAT_FILTER]);
			return -3;
		}
	}

	return 1;
}

static int _cr_check_loc_upd(struct bsc_connection *bsc,
			     uint8_t *data, unsigned int length,
			     char **imsi)
{
	uint8_t mi_type;
	struct gsm48_loc_upd_req *lu;
	char mi_string[GSM48_MI_SIZE];

	if (length < sizeof(*lu)) {
		LOGP(DNAT, LOGL_ERROR,
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
	*imsi = talloc_strdup(bsc, mi_string);
	return auth_imsi(bsc, mi_string);
}

static int _cr_check_cm_serv_req(struct bsc_connection *bsc,
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
		LOGP(DNAT, LOGL_ERROR,
		     "CM Serv Req does not fit. Length is %d\n", length);
		return -1;
	}

	req = (struct gsm48_service_request *) data;
	if (req->cm_service_type == 0x8)
		*con_type = NAT_CON_TYPE_SSA;
	rc = gsm48_extract_mi((uint8_t *) &req->classmark,
			      length - classmark_offset, mi_string, &mi_type);
	if (rc < 0) {
		LOGP(DNAT, LOGL_ERROR, "Failed to parse the classmark2/mi. error: %d\n", rc);
		return -1;
	}

	/* we have to let the TMSI or such pass */
	if (mi_type != GSM_MI_TYPE_IMSI)
		return 0;

	*imsi = talloc_strdup(bsc, mi_string);
	return auth_imsi(bsc, mi_string);
}

static int _cr_check_pag_resp(struct bsc_connection *bsc,
			      uint8_t *data, unsigned int length,
			      char **imsi)
{
	struct gsm48_pag_resp *resp;
	char mi_string[GSM48_MI_SIZE];
	uint8_t mi_type;

	if (length < sizeof(*resp)) {
		LOGP(DNAT, LOGL_ERROR, "PAG RESP does not fit. Length was %d.\n", length);
		return -1;
	}

	resp = (struct gsm48_pag_resp *) data;
	if (gsm48_paging_extract_mi(resp, length, mi_string, &mi_type) < 0) {
		LOGP(DNAT, LOGL_ERROR, "Failed to extract the MI.\n");
		return -1;
	}

	/* we need to let it pass for now */
	if (mi_type != GSM_MI_TYPE_IMSI)
		return 0;

	*imsi = talloc_strdup(bsc, mi_string);
	return auth_imsi(bsc, mi_string);
}

static int _dt_check_id_resp(struct bsc_connection *bsc,
			     uint8_t *data, unsigned int length,
			     struct sccp_connections *con)
{
	char mi_string[GSM48_MI_SIZE];
	uint8_t mi_type;
	int ret;

	if (length < 2) {
		LOGP(DNAT, LOGL_ERROR, "mi does not fit.\n");
		return -1;
	}

	if (data[0] < length - 1) {
		LOGP(DNAT, LOGL_ERROR, "mi length too big.\n");
		return -2;
	}

	mi_type = data[1] & GSM_MI_TYPE_MASK;
	gsm48_mi_to_string(mi_string, sizeof(mi_string), &data[1], data[0]);

	if (mi_type != GSM_MI_TYPE_IMSI)
		return 0;

	ret = auth_imsi(bsc, mi_string);
	con->imsi_checked = 1;
	con->imsi = talloc_strdup(con, mi_string);
	return ret;
}

/* Filter out CR data... */
int bsc_nat_filter_sccp_cr(struct bsc_connection *bsc, struct msgb *msg,
			   struct bsc_nat_parsed *parsed, int *con_type,
			   char **imsi)
{
	struct tlv_parsed tp;
	struct gsm48_hdr *hdr48;
	int hdr48_len;
	int len;
	uint8_t msg_type, proto;

	*con_type = NAT_CON_TYPE_NONE;
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

	proto = hdr48->proto_discr & 0x0f;
	msg_type = hdr48->msg_type & 0xbf;
	if (proto == GSM48_PDISC_MM &&
	    msg_type == GSM48_MT_MM_LOC_UPD_REQUEST) {
		*con_type = NAT_CON_TYPE_LU;
		return _cr_check_loc_upd(bsc, &hdr48->data[0], hdr48_len - sizeof(*hdr48), imsi);
	} else if (proto == GSM48_PDISC_MM &&
		  msg_type == GSM48_MT_MM_CM_SERV_REQ) {
		*con_type = NAT_CON_TYPE_CM_SERV_REQ;
		return _cr_check_cm_serv_req(bsc, &hdr48->data[0],
					     hdr48_len - sizeof(*hdr48),
					     con_type, imsi);
	} else if (proto == GSM48_PDISC_RR &&
		   msg_type == GSM48_MT_RR_PAG_RESP) {
		*con_type = NAT_CON_TYPE_PAG_RESP;
		return _cr_check_pag_resp(bsc, &hdr48->data[0], hdr48_len - sizeof(*hdr48), imsi);
	} else {
		/* We only want to filter the above, let other things pass */
		*con_type = NAT_CON_TYPE_OTHER;
		return 0;
	}
}

struct gsm48_hdr *bsc_unpack_dtap(struct bsc_nat_parsed *parsed,
				  struct msgb *msg, uint32_t *len)
{
	/* gsm_type is actually the size of the dtap */
	*len = parsed->gsm_type;
	if (*len < msgb_l3len(msg) - 3) {
		LOGP(DNAT, LOGL_ERROR, "Not enough space for DTAP.\n");
		return NULL;
	}

	if (msgb_l3len(msg) - 3 < msg->l3h[2]) {
		LOGP(DNAT, LOGL_ERROR,
		     "GSM48 payload does not fit: %d %d\n",
		     msg->l3h[2], msgb_l3len(msg) - 3);
		return NULL;
	}

	msg->l4h = &msg->l3h[3];
	return (struct gsm48_hdr *) msg->l4h;
}

int bsc_nat_filter_dt(struct bsc_connection *bsc, struct msgb *msg,
		      struct sccp_connections *con, struct bsc_nat_parsed *parsed)
{
	uint32_t len;
	uint8_t msg_type, proto;
	struct gsm48_hdr *hdr48;

	if (con->imsi_checked)
		return 0;

	/* only care about DTAP messages */
	if (parsed->bssap != BSSAP_MSG_DTAP)
		return 0;

	hdr48 = bsc_unpack_dtap(parsed, msg, &len);
	if (!hdr48)
		return -1;

	proto = hdr48->proto_discr & 0x0f;
	msg_type = hdr48->msg_type & 0xbf;
	if (proto == GSM48_PDISC_MM &&
	    msg_type == GSM48_MT_MM_ID_RESP) {
		return _dt_check_id_resp(bsc, &hdr48->data[0], len - sizeof(*hdr48), con);
	} else {
		return 0;
	}
}

static const char *con_types [] = {
	[NAT_CON_TYPE_NONE] = "n/a",
	[NAT_CON_TYPE_LU] = "Location Update",
	[NAT_CON_TYPE_CM_SERV_REQ] = "CM Serv Req",
	[NAT_CON_TYPE_PAG_RESP] = "Paging Response",
	[NAT_CON_TYPE_SSA] = "Supplementar Service Activation",
	[NAT_CON_TYPE_LOCAL_REJECT] = "Local Reject",
	[NAT_CON_TYPE_OTHER] = "Other",
};

const char *bsc_con_type_to_string(int type)
{
	return con_types[type];
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

	llist_add_tail(&entry->list, &lst->fltr_list);
	return entry;
}

int bsc_nat_msc_is_connected(struct bsc_nat *nat)
{
	return nat->msc_con->is_connected;
}

static const int con_to_ctr[] = {
	[NAT_CON_TYPE_NONE]		= -1,
	[NAT_CON_TYPE_LU]		= BCFG_CTR_CON_TYPE_LU,
	[NAT_CON_TYPE_CM_SERV_REQ]	= BCFG_CTR_CON_CMSERV_RQ,
	[NAT_CON_TYPE_PAG_RESP]		= BCFG_CTR_CON_PAG_RESP,
	[NAT_CON_TYPE_SSA]		= BCFG_CTR_CON_SSA,
	[NAT_CON_TYPE_LOCAL_REJECT]	= -1,
	[NAT_CON_TYPE_OTHER]		= BCFG_CTR_CON_OTHER,
};

int bsc_conn_type_to_ctr(struct sccp_connections *conn)
{
	return con_to_ctr[conn->con_type];
}

int bsc_write_cb(struct osmo_fd *bfd, struct msgb *msg)
{
	int rc;

	rc = write(bfd->fd, msg->data, msg->len);
	if (rc != msg->len)
		LOGP(DNAT, LOGL_ERROR, "Failed to write message to the BSC.\n");

	return rc;
}

static char *match_and_rewrite_number(void *ctx, const char *number,
				      const char *imsi,
				      struct llist_head *list)
{
	struct bsc_nat_num_rewr_entry *entry;
	char *new_number = NULL;

	/* need to find a replacement and then fix it */
	llist_for_each_entry(entry, list, list) {
		regmatch_t matches[2];

		/* check the IMSI match */
		if (regexec(&entry->msisdn_reg, imsi, 0, NULL, 0) != 0)
			continue;

		/* this regexp matches... */
		if (regexec(&entry->num_reg, number, 2, matches, 0) == 0 &&
		    matches[1].rm_eo != -1)
			new_number = talloc_asprintf(ctx, "%s%s",
					entry->replace,
					&number[matches[1].rm_so]);
		if (new_number)
			break;
	}

	return new_number;
}

static char *rewrite_non_international(struct bsc_nat *nat, void *ctx, const char *imsi,
				       struct gsm_mncc_number *called)
{
	if (llist_empty(&nat->num_rewr))
		return NULL;

	if (called->plan != 1)
		return NULL;
	if (called->type == 1)
		return NULL;

	return match_and_rewrite_number(ctx, called->number,
					imsi, &nat->num_rewr);
}


/**
 * Rewrite non global numbers... according to rules based on the IMSI
 */
static struct msgb *rewrite_setup(struct bsc_nat *nat, struct msgb *msg,
				  struct bsc_nat_parsed *parsed, const char *imsi,
				  struct gsm48_hdr *hdr48, const uint32_t len)
{
	struct tlv_parsed tp;
	unsigned int payload_len;
	struct gsm_mncc_number called;
	struct msgb *out;
	char *new_number = NULL;
	uint8_t *outptr;
	const uint8_t *msgptr;
	int sec_len;

	/* decode and rewrite the message */
	payload_len = len - sizeof(*hdr48);
	tlv_parse(&tp, &gsm48_att_tlvdef, hdr48->data, payload_len, 0, 0);

	/* no number, well let us ignore it */
	if (!TLVP_PRESENT(&tp, GSM48_IE_CALLED_BCD))
		return NULL;

	memset(&called, 0, sizeof(called));
	gsm48_decode_called(&called,
			    TLVP_VAL(&tp, GSM48_IE_CALLED_BCD) - 1);

	/* check if it looks international and stop */
	new_number = rewrite_non_international(nat, msg, imsi, &called);

	if (!new_number) {
		LOGP(DNAT, LOGL_DEBUG, "No IMSI match found, returning message.\n");
		return NULL;
	}

	if (strlen(new_number) > sizeof(called.number)) {
		LOGP(DNAT, LOGL_ERROR, "Number is too long for structure.\n");
		talloc_free(new_number);
		return NULL;
	}

	/*
	 * Need to create a new message now based on the old onew
	 * with a new number. We can sadly not patch this in place
	 * so we will need to regenerate it.
	 */

	out = msgb_alloc_headroom(4096, 128, "changed-setup");
	if (!out) {
		LOGP(DNAT, LOGL_ERROR, "Failed to allocate.\n");
		talloc_free(new_number);
		return NULL;
	}

	/* copy the header */
	outptr = msgb_put(out, sizeof(*hdr48));
	memcpy(outptr, hdr48, sizeof(*hdr48));

	/* copy everything up to the number */
	sec_len = TLVP_VAL(&tp, GSM48_IE_CALLED_BCD) - 2 - &hdr48->data[0];
	outptr = msgb_put(out, sec_len);
	memcpy(outptr, &hdr48->data[0], sec_len);

	/* create the new number */
	if (strncmp(new_number, "00", 2) == 0) {
		called.type = 1;
		strncpy(called.number, new_number + 2, sizeof(called.number));
	} else {
		strncpy(called.number, new_number, sizeof(called.number));
	}
	gsm48_encode_called(out, &called);

	/* copy thre rest */
	msgptr = TLVP_VAL(&tp, GSM48_IE_CALLED_BCD) +
		 TLVP_LEN(&tp, GSM48_IE_CALLED_BCD);
	sec_len = payload_len - (msgptr - &hdr48->data[0]);
	outptr = msgb_put(out, sec_len);
	memcpy(outptr, msgptr, sec_len);

	talloc_free(new_number);
	return out;
}

/**
 * Find a new SMSC address, returns an allocated string that needs to be
 * freed or is NULL.
 */
static char *find_new_smsc(struct bsc_nat *nat, void *ctx, const char *imsi,
			   const char *smsc_addr, const char *dest_nr)
{
	struct bsc_nat_num_rewr_entry *entry;
	char *new_number = NULL;
	uint8_t dest_match = llist_empty(&nat->tpdest_match);

	/* We will find a new number now */
	llist_for_each_entry(entry, &nat->smsc_rewr, list) {
		regmatch_t matches[2];

		/* check the IMSI match */
		if (regexec(&entry->msisdn_reg, imsi, 0, NULL, 0) != 0)
			continue;

		/* this regexp matches... */
		if (regexec(&entry->num_reg, smsc_addr, 2, matches, 0) == 0 &&
		    matches[1].rm_eo != -1)
			new_number = talloc_asprintf(ctx, "%s%s",
					entry->replace,
					&smsc_addr[matches[1].rm_so]);
		if (new_number)
			break;
	}

	if (!new_number)
		return NULL;

	/*
	 * now match the number against another list
	 */
	llist_for_each_entry(entry, &nat->tpdest_match, list) {
		/* check the IMSI match */
		if (regexec(&entry->msisdn_reg, imsi, 0, NULL, 0) != 0)
			continue;

		if (regexec(&entry->num_reg, dest_nr, 0, NULL, 0) == 0) {
			dest_match = 1;
			break;
		}
	}

	if (!dest_match) {
		talloc_free(new_number);
		return NULL;
	}

	return new_number;
}

/**
 * Clear the TP-SRR from the TPDU header
 */
static uint8_t sms_new_tpdu_hdr(struct bsc_nat *nat, const char *imsi,
				const char *dest_nr, uint8_t hdr)
{
	struct bsc_nat_num_rewr_entry *entry;

	/* We will find a new number now */
	llist_for_each_entry(entry, &nat->sms_clear_tp_srr, list) {
		/* check the IMSI match */
		if (regexec(&entry->msisdn_reg, imsi, 0, NULL, 0) != 0)
			continue;
		if (regexec(&entry->num_reg, dest_nr, 0, NULL, 0) != 0)
			continue;

		/* matched phone number and imsi */
		return hdr & ~0x20;
	}

	return hdr;
}

/**
 * Check if we need to rewrite the number. For this SMS.
 */
static char *sms_new_dest_nr(struct bsc_nat *nat, void *ctx,
			     const char *imsi, const char *dest_nr)
{
	return match_and_rewrite_number(ctx, dest_nr, imsi,
					&nat->sms_num_rewr);
}

/**
 * This is a helper for GSM 04.11 8.2.5.2 Destination address element
 */
void sms_encode_addr_element(struct msgb *out, const char *new_number,
			     int format, int tp_data)
{
	uint8_t new_addr_len;
	uint8_t new_addr[26];

	/*
	 * Copy the new number. We let libosmocore encode it, then set
	 * the extension followed after the length. Depending on if
	 * we want to write RP we will let the TLV code add the
	 * length for us or we need to use strlen... This is not very clear
	 * as of 03.40 and 04.11.
	 */
	new_addr_len = gsm48_encode_bcd_number(new_addr, ARRAY_SIZE(new_addr),
					       1, new_number);
	new_addr[1] = format;
	if (tp_data) {
		uint8_t *data = msgb_put(out, new_addr_len);
		memcpy(data, new_addr, new_addr_len);
		data[0] = strlen(new_number);
	} else {
		msgb_lv_put(out, new_addr_len - 1, new_addr + 1);
	}
}

static struct msgb *sms_create_new(uint8_t type, uint8_t ref,
				   struct gsm48_hdr *old_hdr48,
				   const uint8_t *orig_addr_ptr,
				   int orig_addr_len, const char *new_number,
				   const uint8_t *data_ptr, int data_len,
				   uint8_t tpdu_first_byte,
				   const int old_dest_len, const char *new_dest_nr)
{
	struct gsm48_hdr *new_hdr48;
	struct msgb *out;

	/*
	 * We need to re-create the patched structure. This is why we have
	 * saved the above pointers.
	 */
	out = msgb_alloc_headroom(4096, 128, "changed-smsc");
	if (!out) {
		LOGP(DNAT, LOGL_ERROR, "Failed to allocate.\n");
		return NULL;
	}

	out->l2h = out->data;
	msgb_v_put(out, GSM411_MT_RP_DATA_MO);
	msgb_v_put(out, ref);
	msgb_lv_put(out, orig_addr_len, orig_addr_ptr);

	sms_encode_addr_element(out, new_number, 0x91, 0);


	/* Patch the TPDU from here on */

	/**
	 * Do we need to put a new TP-Destination-Address (TP-DA) here or
	 * can we copy the old thing? For the TP-DA we need to find out the
	 * new size.
	 */
	if (new_dest_nr) {
		uint8_t *data, *new_size;

		/* reserve the size and write the header */
		new_size = msgb_put(out, 1);
		out->l3h = new_size + 1;
		msgb_v_put(out, tpdu_first_byte);
		msgb_v_put(out, data_ptr[1]);

		/* encode the new number and put it */
		if (strncmp(new_dest_nr, "00", 2) == 0)
			sms_encode_addr_element(out, new_dest_nr + 2, 0x91, 1);
		else
			sms_encode_addr_element(out, new_dest_nr, 0x81, 1);

		/* Copy the rest after the TP-DS */
		data = msgb_put(out, data_len - 2 - 1 - old_dest_len);
		memcpy(data, &data_ptr[2 + 1 + old_dest_len], data_len - 2 - 1 - old_dest_len);

		/* fill in the new size */
		new_size[0] = msgb_l3len(out);
	} else {
		msgb_v_put(out, data_len);
		msgb_tv_fixed_put(out, tpdu_first_byte, data_len - 1, &data_ptr[1]);
	}

	/* prepend GSM 04.08 header */
	new_hdr48 = (struct gsm48_hdr *) msgb_push(out, sizeof(*new_hdr48) + 1);
	memcpy(new_hdr48, old_hdr48, sizeof(*old_hdr48));
	new_hdr48->data[0] = msgb_l2len(out);

	return out;
}

/**
 * Parse the SMS and check if it needs to be rewritten
 */
static struct msgb *rewrite_sms(struct bsc_nat *nat, struct msgb *msg,
				struct bsc_nat_parsed *parsed, const char *imsi,
				struct gsm48_hdr *hdr48, const uint32_t len)
{
	unsigned int payload_len;
	unsigned int cp_len;

	uint8_t ref;
	uint8_t orig_addr_len, *orig_addr_ptr;
	uint8_t dest_addr_len, *dest_addr_ptr;
	uint8_t data_len, *data_ptr;
	char smsc_addr[30];


	uint8_t dest_len, orig_dest_len;
	char _dest_nr[30];
	char *dest_nr;
	char *new_dest_nr;

	char *new_number = NULL;
	uint8_t tpdu_hdr;
	struct msgb *out;

	payload_len = len - sizeof(*hdr48);
	if (payload_len < 1) {
		LOGP(DNAT, LOGL_ERROR, "SMS too short for things. %d\n", payload_len);
		return NULL;
	}

	cp_len = hdr48->data[0];
	if (payload_len + 1 < cp_len) {
		LOGP(DNAT, LOGL_ERROR, "SMS RPDU can not fit in: %d %d\n", cp_len, payload_len);
		return NULL;
	}

	if (hdr48->data[1] != GSM411_MT_RP_DATA_MO)
		return NULL;

	if (cp_len < 5) {
		LOGP(DNAT, LOGL_ERROR, "RD-DATA can not fit in the CP len: %d\n", cp_len);
		return NULL;
	}

	/* RP */
	ref = hdr48->data[2];
	orig_addr_len = hdr48->data[3];
	orig_addr_ptr = &hdr48->data[4];

	/* the +1 is for checking if the following element has some space */
	if (cp_len < 3 + orig_addr_len + 1) {
		LOGP(DNAT, LOGL_ERROR, "RP-Originator addr does not fit: %d\n", orig_addr_len);
		return NULL;
	}

	dest_addr_len = hdr48->data[3 + orig_addr_len + 1];
	dest_addr_ptr = &hdr48->data[3 + orig_addr_len + 2];

	if (cp_len < 3 + orig_addr_len + 1 + dest_addr_len + 1) {
		LOGP(DNAT, LOGL_ERROR, "RP-Destination addr does not fit: %d\n", dest_addr_len);
		return NULL;
	}
	gsm48_decode_bcd_number(smsc_addr, ARRAY_SIZE(smsc_addr), dest_addr_ptr - 1, 1);

	data_len = hdr48->data[3 + orig_addr_len + 1 + dest_addr_len + 1];
	data_ptr = &hdr48->data[3 + orig_addr_len + 1 + dest_addr_len + 2];

	if (cp_len < 3 + orig_addr_len + 1 + dest_addr_len + 1 + data_len) {
		LOGP(DNAT, LOGL_ERROR, "RP-Data does not fit: %d\n", data_len);
		return NULL;
	}

	if (data_len < 3) {
		LOGP(DNAT, LOGL_ERROR, "SMS-SUBMIT is too short.\n");
		return NULL;
	}

	/* TP-PDU starts here */
	if ((data_ptr[0] & 0x03) != GSM340_SMS_SUBMIT_MS2SC)
		return NULL;

	/*
	 * look into the phone number. The length is in semi-octets, we will
	 * need to add the byte for the number type as well.
	 */
	orig_dest_len = data_ptr[2];
	dest_len = ((orig_dest_len + 1) / 2) + 1;
	if (data_len < dest_len + 3 || dest_len < 2) {
		LOGP(DNAT, LOGL_ERROR, "SMS-SUBMIT can not have TP-DestAddr.\n");
		return NULL;
	}

	if ((data_ptr[3] & 0x80) == 0) {
		LOGP(DNAT, LOGL_ERROR, "TP-DestAddr has extension. Not handled.\n");
		return NULL;
	}

	if ((data_ptr[3] & 0x0F) == 0) {
		LOGP(DNAT, LOGL_ERROR, "TP-DestAddr is of unknown type.\n");
		return NULL;
	}

	/**
	 * Besides of what I think I read in GSM 03.40 and 04.11 the TP-DA
	 * contains the semi-octets as length (strlen), change it to the
	 * the number of bytes, but then change it back.
	 */
	data_ptr[2] = dest_len;
	gsm48_decode_bcd_number(_dest_nr + 2, ARRAY_SIZE(_dest_nr) - 2,
				&data_ptr[2], 1);
	data_ptr[2] = orig_dest_len;
	if ((data_ptr[3] & 0x70) == 0x10) {
		_dest_nr[0] = _dest_nr[1] = '0';
		dest_nr = &_dest_nr[0];
	} else {
		dest_nr = &_dest_nr[2];
	}

	/**
	 * Call functions to rewrite the data
	 */
	tpdu_hdr = sms_new_tpdu_hdr(nat, imsi, dest_nr, data_ptr[0]);
	new_number = find_new_smsc(nat, msg, imsi, smsc_addr, dest_nr);
	new_dest_nr = sms_new_dest_nr(nat, msg, imsi, dest_nr);

	if (tpdu_hdr == data_ptr[0] && !new_number && !new_dest_nr)
		return NULL;

	out = sms_create_new(GSM411_MT_RP_DATA_MO, ref, hdr48,
			orig_addr_ptr, orig_addr_len,
			new_number ? new_number : smsc_addr,
			data_ptr, data_len, tpdu_hdr,
			dest_len, new_dest_nr);
	talloc_free(new_number);
	talloc_free(new_dest_nr);
	return out;
}

struct msgb *bsc_nat_rewrite_msg(struct bsc_nat *nat, struct msgb *msg, struct bsc_nat_parsed *parsed, const char *imsi)
{
	struct gsm48_hdr *hdr48;
	uint32_t len;
	uint8_t msg_type, proto;
	struct msgb *new_msg = NULL, *sccp;
	uint8_t link_id;

	if (!imsi || strlen(imsi) < 5)
		return msg;

	/* only care about DTAP messages */
	if (parsed->bssap != BSSAP_MSG_DTAP)
		return msg;
	if (!parsed->dest_local_ref)
		return msg;

	hdr48 = bsc_unpack_dtap(parsed, msg, &len);
	if (!hdr48)
		return msg;

	link_id = msg->l3h[1];
	proto = hdr48->proto_discr & 0x0f;
	msg_type = hdr48->msg_type & 0xbf;

	if (proto == GSM48_PDISC_CC && msg_type == GSM48_MT_CC_SETUP)
		new_msg = rewrite_setup(nat, msg, parsed, imsi, hdr48, len);
	else if (proto == GSM48_PDISC_SMS && msg_type == GSM411_MT_CP_DATA)
		new_msg = rewrite_sms(nat, msg, parsed, imsi, hdr48, len);

	if (!new_msg)
		return msg;

	/* wrap with DTAP, SCCP, then IPA. TODO: Stop copying */
	gsm0808_prepend_dtap_header(new_msg, link_id);
	sccp = sccp_create_dt1(parsed->dest_local_ref, new_msg->data, new_msg->len);
	talloc_free(new_msg);

	if (!sccp) {
		LOGP(DNAT, LOGL_ERROR, "Failed to allocate.\n");
		return msg;
	}

	ipaccess_prepend_header(sccp, IPAC_PROTO_SCCP);

	/* the parsed hangs off from msg but it needs to survive */
	talloc_steal(sccp, parsed);
	msgb_free(msg);
	return sccp;
}

static void num_rewr_free_data(struct bsc_nat_num_rewr_entry *entry)
{
	regfree(&entry->msisdn_reg);
	regfree(&entry->num_reg);
	talloc_free(entry->replace);
}

void bsc_nat_num_rewr_entry_adapt(void *ctx, struct llist_head *head,
				  const struct osmo_config_list *list)
{
	struct bsc_nat_num_rewr_entry *entry, *tmp;
	struct osmo_config_entry *cfg_entry;

	/* free the old data */
	llist_for_each_entry_safe(entry, tmp, head, list) {
		num_rewr_free_data(entry);
		llist_del(&entry->list);
		talloc_free(entry);
	}


	if (!list)
		return;

	llist_for_each_entry(cfg_entry, &list->entry, list) {
		char *regexp;
		if (cfg_entry->text[0] == '+') {
			LOGP(DNAT, LOGL_ERROR,
				"Plus is not allowed in the number\n");
			continue;
		}

		entry = talloc_zero(ctx, struct bsc_nat_num_rewr_entry);
		if (!entry) {
			LOGP(DNAT, LOGL_ERROR,
				"Allication of the num_rewr entry failed.\n");
			continue;
		}

		entry->replace = talloc_strdup(entry, cfg_entry->text);
		if (!entry->replace) {
			LOGP(DNAT, LOGL_ERROR,
				"Failed to copy the replacement text.\n");
			talloc_free(entry);
			continue;
		}

		/* we will now build a regexp string */
		if (cfg_entry->mcc[0] == '^') {
			regexp = talloc_strdup(entry, cfg_entry->mcc);
		} else {
			regexp = talloc_asprintf(entry, "^%s%s",
					cfg_entry->mcc[0] == '*' ?
						"[0-9][0-9][0-9]" : cfg_entry->mcc,
					cfg_entry->mnc[0] == '*' ?
						"[0-9][0-9]" : cfg_entry->mnc);
		}

		if (!regexp) {
			LOGP(DNAT, LOGL_ERROR, "Failed to create a regexp string.\n");
			talloc_free(entry);
			continue;
		}

		if (regcomp(&entry->msisdn_reg, regexp, 0) != 0) {
			LOGP(DNAT, LOGL_ERROR,
				"Failed to compile regexp '%s'\n", regexp);
			talloc_free(regexp);
			talloc_free(entry);
			continue;
		}

		talloc_free(regexp);
		if (regcomp(&entry->num_reg, cfg_entry->option, REG_EXTENDED) != 0) {
			LOGP(DNAT, LOGL_ERROR,
				"Failed to compile regexp '%s'\n", cfg_entry->option);
			regfree(&entry->msisdn_reg);
			talloc_free(entry);
			continue;
		}

		/* we have copied the number */
		llist_add_tail(&entry->list, head);
	}
}
