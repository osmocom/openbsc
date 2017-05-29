
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
#include <openbsc/bsc_msg_filter.h>
#include <openbsc/bsc_msc.h>
#include <openbsc/gsm_data.h>
#include <openbsc/debug.h>
#include <openbsc/ipaccess.h>
#include <openbsc/vty.h>

#include <osmocom/core/linuxlist.h>
#include <osmocom/core/talloc.h>
#include <osmocom/core/stats.h>
#include <osmocom/gsm/gsm0808.h>
#include <osmocom/gsm/ipa.h>

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
	.class_id = OSMO_STATS_CLASS_PEER,
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
	INIT_LLIST_HEAD(&nat->num_rewr_post);
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

void bsc_nat_free(struct bsc_nat *nat)
{
	struct bsc_config *cfg, *tmp;
	struct bsc_msg_acc_lst *lst, *tmp_lst;

	llist_for_each_entry_safe(cfg, tmp, &nat->bsc_configs, entry)
		bsc_config_free(cfg);
	llist_for_each_entry_safe(lst, tmp_lst, &nat->access_lists, list)
		bsc_msg_acc_lst_delete(lst);

	bsc_nat_num_rewr_entry_adapt(nat, &nat->num_rewr, NULL);
	bsc_nat_num_rewr_entry_adapt(nat, &nat->num_rewr_post, NULL);
	bsc_nat_num_rewr_entry_adapt(nat, &nat->sms_clear_tp_srr, NULL);
	bsc_nat_num_rewr_entry_adapt(nat, &nat->sms_num_rewr, NULL);
	bsc_nat_num_rewr_entry_adapt(nat, &nat->tpdest_match, NULL);

	osmo_counter_free(nat->stats.sccp.conn);
	osmo_counter_free(nat->stats.sccp.calls);
	osmo_counter_free(nat->stats.bsc.reconn);
	osmo_counter_free(nat->stats.bsc.auth_fail);
	osmo_counter_free(nat->stats.msc.reconn);
	osmo_counter_free(nat->stats.ussd.reconn);
	talloc_free(nat->mgcp_cfg);
	talloc_free(nat);
}

void bsc_nat_set_msc_ip(struct bsc_nat *nat, const char *ip)
{
	osmo_talloc_replace_string(nat, &nat->main_dest->ip, ip);
}

struct bsc_connection *bsc_connection_alloc(struct bsc_nat *nat)
{
	struct bsc_connection *con = talloc_zero(nat, struct bsc_connection);
	if (!con)
		return NULL;

	con->nat = nat;
	osmo_wqueue_init(&con->write_queue, 100);
	INIT_LLIST_HEAD(&con->cmd_pending);
	INIT_LLIST_HEAD(&con->pending_dlcx);
	return con;
}

struct bsc_config *bsc_config_alloc(struct bsc_nat *nat, const char *token,
				    unsigned int number)
{
	struct bsc_config *conf = talloc_zero(nat, struct bsc_config);
	if (!conf)
		return NULL;

	conf->token = talloc_strdup(conf, token);
	conf->nr = number;
	conf->nat = nat;
	conf->max_endpoints = 32;
	conf->paging_group = PAGIN_GROUP_UNASSIGNED;

	INIT_LLIST_HEAD(&conf->lac_list);

	llist_add_tail(&conf->entry, &nat->bsc_configs);
	++nat->num_bsc;

	conf->stats.ctrg = rate_ctr_group_alloc(conf, &bsc_cfg_ctrg_desc, conf->nr);
	if (!conf->stats.ctrg) {
		llist_del(&conf->entry);
		talloc_free(conf);
		return NULL;
	}

	return conf;
}

struct bsc_config *bsc_config_by_token(struct bsc_nat *nat, const char *token, int len)
{
	struct bsc_config *conf;

	llist_for_each_entry(conf, &nat->bsc_configs, entry) {
		/*
		 * Add the '\0' of the token for the memcmp, the IPA messages
		 * for some reason added null termination.
		 */
		const int token_len = strlen(conf->token) + 1;

		if (token_len == len && memcmp(conf->token, token, token_len) == 0)
			return conf;
	}

	return NULL;
}

void bsc_config_free(struct bsc_config *cfg)
{
	llist_del(&cfg->entry);
	rate_ctr_group_free(cfg->stats.ctrg);
	cfg->nat->num_bsc--;
	OSMO_ASSERT(cfg->nat->num_bsc >= 0)
	talloc_free(cfg);
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

void sccp_connection_destroy(struct nat_sccp_connection *conn)
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
	ipa_prepend_header(msg, proto);
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

static const char *con_types [] = {
	[FLT_CON_TYPE_NONE] = "n/a",
	[FLT_CON_TYPE_LU] = "Location Update",
	[FLT_CON_TYPE_CM_SERV_REQ] = "CM Serv Req",
	[FLT_CON_TYPE_PAG_RESP] = "Paging Response",
	[FLT_CON_TYPE_SSA] = "Supplementar Service Activation",
	[FLT_CON_TYPE_LOCAL_REJECT] = "Local Reject",
	[FLT_CON_TYPE_OTHER] = "Other",
};

const char *bsc_con_type_to_string(int type)
{
	return con_types[type];
}

int bsc_nat_msc_is_connected(struct bsc_nat *nat)
{
	return nat->msc_con->is_connected;
}

static const int con_to_ctr[] = {
	[FLT_CON_TYPE_NONE]		= -1,
	[FLT_CON_TYPE_LU]		= BCFG_CTR_CON_TYPE_LU,
	[FLT_CON_TYPE_CM_SERV_REQ]	= BCFG_CTR_CON_CMSERV_RQ,
	[FLT_CON_TYPE_PAG_RESP]		= BCFG_CTR_CON_PAG_RESP,
	[FLT_CON_TYPE_SSA]		= BCFG_CTR_CON_SSA,
	[FLT_CON_TYPE_LOCAL_REJECT]	= -1,
	[FLT_CON_TYPE_OTHER]		= BCFG_CTR_CON_OTHER,
};

int bsc_conn_type_to_ctr(struct nat_sccp_connection *conn)
{
	return con_to_ctr[conn->filter_state.con_type];
}

int bsc_write_cb(struct osmo_fd *bfd, struct msgb *msg)
{
	int rc;

	rc = write(bfd->fd, msg->data, msg->len);
	if (rc != msg->len)
		LOGP(DNAT, LOGL_ERROR, "Failed to write message to the BSC.\n");

	return rc;
}

static void extract_lac(const uint8_t *data, uint16_t *lac, uint16_t *ci)
{
	memcpy(lac, &data[0], sizeof(*lac));
	memcpy(ci, &data[2], sizeof(*ci));

	*lac = ntohs(*lac);
	*ci = ntohs(*ci);
}

int bsc_nat_extract_lac(struct bsc_connection *bsc,
			struct nat_sccp_connection *con,
			struct bsc_nat_parsed *parsed, struct msgb *msg)
{
	int data_length;
	const uint8_t *data;
	struct tlv_parsed tp;
	uint16_t lac, ci;

	if (parsed->gsm_type != BSS_MAP_MSG_COMPLETE_LAYER_3) {
		LOGP(DNAT, LOGL_ERROR, "Can only extract LAC from Complete Layer3\n");
		return -1;
	}

	if (!msg->l3h || msgb_l3len(msg) < 3) {
		LOGP(DNAT, LOGL_ERROR, "Complete Layer3 mssage is too short.\n");
		return -1;
	}

	tlv_parse(&tp, gsm0808_att_tlvdef(), msg->l3h + 3, msgb_l3len(msg) - 3, 0, 0);
	if (!TLVP_PRESENT(&tp, GSM0808_IE_CELL_IDENTIFIER)) {
		LOGP(DNAT, LOGL_ERROR, "No CellIdentifier List inside paging msg.\n");
		return -2;
	}

	data_length = TLVP_LEN(&tp, GSM0808_IE_CELL_IDENTIFIER);
	data = TLVP_VAL(&tp, GSM0808_IE_CELL_IDENTIFIER);

	/* Attemt to get the LAC/CI from it */
	if (data[0] == CELL_IDENT_WHOLE_GLOBAL) {
		if (data_length != 8) {
			LOGP(DNAT, LOGL_ERROR,
				"Ident too short: %d\n", data_length);
			return -3;
		}
		extract_lac(&data[1 + 3], &lac, &ci);
	} else if (data[0] == CELL_IDENT_LAC_AND_CI) {
		if (data_length != 5) {
			LOGP(DNAT, LOGL_ERROR,
				"Ident too short: %d\n", data_length);
			return -3;
		}
		extract_lac(&data[1], &lac, &ci);
	} else {
		LOGP(DNAT, LOGL_ERROR,
			"Unhandled cell identifier: %d\n", data[0]);
		return -1;
	}

	con->lac = lac;
	con->ci = ci;
	return 0;
}
