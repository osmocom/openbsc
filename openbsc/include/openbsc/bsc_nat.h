/*
 * (C) 2010-2012 by Holger Hans Peter Freyther <zecke@selfish.org>
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

#ifndef BSC_NAT_H
#define BSC_NAT_H

#include "mgcp.h"


#include <osmocom/core/select.h>
#include <osmocom/core/msgb.h>
#include <osmocom/core/msgfile.h>
#include <osmocom/core/timer.h>
#include <osmocom/core/write_queue.h>
#include <osmocom/core/rate_ctr.h>
#include <osmocom/core/statistics.h>
#include <osmocom/gsm/protocol/gsm_04_08.h>

#include <regex.h>

#define DIR_BSC 1
#define DIR_MSC 2

#define PAGIN_GROUP_UNASSIGNED -1

struct sccp_source_reference;
struct nat_sccp_connection;
struct bsc_nat_parsed;
struct bsc_nat;
struct bsc_nat_ussd_con;
struct nat_rewrite_rule;

enum {
	NAT_CON_TYPE_NONE,
	NAT_CON_TYPE_LU,
	NAT_CON_TYPE_CM_SERV_REQ,
	NAT_CON_TYPE_PAG_RESP,
	NAT_CON_TYPE_SSA,
	NAT_CON_TYPE_LOCAL_REJECT,
	NAT_CON_TYPE_OTHER,
};

/*
 * Is this terminated to the MSC, to the local machine (release
 * handling for IMSI filtering) or to a USSD provider?
 */
enum {
	NAT_CON_END_MSC,
	NAT_CON_END_LOCAL,
	NAT_CON_END_USSD,
};

/*
 * Pending command entry
 */
struct bsc_cmd_list {
	struct llist_head list_entry;

	struct osmo_timer_list timeout;

	/* The NATed ID used on the bsc_con*/
	int nat_id;

	/* The control connection from which the command originated */
	struct ctrl_connection *ccon;

	/* The command from the control connection */
	struct ctrl_cmd *cmd;
};

/*
 * Per BSC data structure
 */
struct bsc_connection {
	struct llist_head list_entry;

	/* do we know anything about this BSC? */
	int authenticated;

	/* the fd we use to communicate */
	struct osmo_wqueue write_queue;

	/* the BSS associated */
	struct bsc_config *cfg;

	/* a timeout node */
	struct osmo_timer_list id_timeout;

	/* pong timeout */
	struct osmo_timer_list ping_timeout;
	struct osmo_timer_list pong_timeout;

	/* mgcp related code */
	char *_endpoint_status;
	int number_multiplexes;
	int max_endpoints;
	int last_endpoint;
	int next_transaction;
	uint32_t pending_dlcx_count;
	struct llist_head pending_dlcx;

	/* track the pending commands for this BSC */
	struct llist_head cmd_pending;
	int last_id;

	/* a back pointer */
	struct bsc_nat *nat;
};

/**
 * Stats per BSC
 */
struct bsc_config_stats {
	struct rate_ctr_group *ctrg;
};

enum bsc_cfg_ctr {
	BCFG_CTR_SCCP_CONN,
	BCFG_CTR_SCCP_CALLS,
	BCFG_CTR_NET_RECONN,
	BCFG_CTR_DROPPED_SCCP,
	BCFG_CTR_DROPPED_CALLS,
	BCFG_CTR_REJECTED_CR,
	BCFG_CTR_REJECTED_MSG,
	BCFG_CTR_ILL_PACKET,
	BCFG_CTR_CON_TYPE_LU,
	BCFG_CTR_CON_CMSERV_RQ,
	BCFG_CTR_CON_PAG_RESP,
	BCFG_CTR_CON_SSA,
	BCFG_CTR_CON_OTHER,
};

/**
 * One BSC entry in the config
 */
struct bsc_config {
	struct llist_head entry;

	char *token;
	int nr;

	char *description;

	/* imsi white and blacklist */
	char *acc_lst_name;

	int forbid_paging;
	int paging_group;

	/* audio handling */
	int max_endpoints;

	/* backpointer */
	struct bsc_nat *nat;

	struct bsc_config_stats stats;

	struct llist_head lac_list;
};

struct bsc_lac_entry {
	struct llist_head entry;
	uint16_t lac;
};

struct bsc_nat_paging_group {
	struct llist_head entry;

	/* list of lac entries */
	struct llist_head lists;
	int nr;
};

/**
 * BSCs point of view of endpoints
 */
struct bsc_endpoint {
	/* the operation that is carried out */
	int transaction_state;
	/* the pending transaction id */
	char *transaction_id;
	/* the bsc we are talking to */
	struct bsc_connection *bsc;
};

/**
 * Statistic for the nat.
 */
struct bsc_nat_statistics {
	struct {
		struct osmo_counter *conn;
		struct osmo_counter *calls;
	} sccp;

	struct {
		struct osmo_counter *reconn;
                struct osmo_counter *auth_fail;
	} bsc;

	struct {
		struct osmo_counter *reconn;
	} msc;

	struct {
		struct osmo_counter *reconn;
	} ussd;
};

enum bsc_nat_acc_ctr {
	ACC_LIST_BSC_FILTER,
	ACC_LIST_NAT_FILTER,
};

struct bsc_nat_acc_lst {
	struct llist_head list;

	/* counter */
	struct rate_ctr_group *stats;

	/* the name of the list */
	const char *name;
	struct llist_head fltr_list;
};

struct bsc_nat_acc_lst_entry {
	struct llist_head list;

	/* the filter */
	char *imsi_allow;
	regex_t imsi_allow_re;
	char *imsi_deny;
	regex_t imsi_deny_re;
};

/**
 * the structure of the "nat" network
 */
struct bsc_nat {
	/* active SCCP connections that need patching */
	struct llist_head sccp_connections;

	/* active BSC connections that need patching */
	struct llist_head bsc_connections;

	/* access lists */
	struct llist_head access_lists;

	/* paging groups */
	struct llist_head paging_groups;

	/* known BSC's */
	struct llist_head bsc_configs;
	int num_bsc;
	int bsc_ip_dscp;

	/* MGCP config */
	struct mgcp_config *mgcp_cfg;
	uint8_t mgcp_msg[4096];
	int mgcp_length;
	int mgcp_ipa;

	/* msc things */
	struct llist_head dests;
	struct bsc_msc_dest *main_dest;
	struct bsc_msc_connection *msc_con;
	char *token;

	/* timeouts */
	int auth_timeout;
	int ping_timeout;
	int pong_timeout;

	struct bsc_endpoint *bsc_endpoints;

	/* filter */
	char *acc_lst_name;

	/* Barring of subscribers with a rb tree */
	struct rb_root imsi_black_list;
	char *imsi_black_list_fn;

	/* number rewriting */
	char *num_rewr_name;
	struct llist_head num_rewr;

	char *smsc_rewr_name;
	struct llist_head smsc_rewr;
	char *tpdest_match_name;
	struct llist_head tpdest_match;
	char *sms_clear_tp_srr_name;
	struct llist_head sms_clear_tp_srr;
	char *sms_num_rewr_name;
	struct llist_head sms_num_rewr;

	/* more rewriting */
	char *num_rewr_trie_name;
	struct nat_rewrite *num_rewr_trie;

	/* USSD messages  we want to match */
	char *ussd_lst_name;
	char *ussd_query;
	regex_t ussd_query_re;
	char *ussd_token;
	char *ussd_local;
	struct osmo_fd ussd_listen;
	struct bsc_nat_ussd_con *ussd_con;

	/* for maintainenance */
	int blocked;

	/* statistics */
	struct bsc_nat_statistics stats;

	/* control interface */
	struct ctrl_handle *ctrl;
};

struct bsc_nat_ussd_con {
	struct osmo_wqueue queue;
	struct bsc_nat *nat;
	int authorized;

	struct osmo_timer_list auth_timeout;
};

struct bsc_nat_reject_cause {
	int lu_reject_cause;
	int cm_reject_cause;
};

/* create and init the structures */
struct bsc_config *bsc_config_alloc(struct bsc_nat *nat, const char *token);
struct bsc_config *bsc_config_num(struct bsc_nat *nat, int num);
void bsc_config_free(struct bsc_config *);
void bsc_config_add_lac(struct bsc_config *cfg, int lac);
void bsc_config_del_lac(struct bsc_config *cfg, int lac);
int bsc_config_handles_lac(struct bsc_config *cfg, int lac);

struct bsc_nat *bsc_nat_alloc(void);
struct bsc_connection *bsc_connection_alloc(struct bsc_nat *nat);
void bsc_nat_set_msc_ip(struct bsc_nat *bsc, const char *ip);

void sccp_connection_destroy(struct nat_sccp_connection *);
void bsc_close_connection(struct bsc_connection *);

const char *bsc_con_type_to_string(int type);

/**
 * parse the given message into the above structure
 */
struct bsc_nat_parsed *bsc_nat_parse(struct msgb *msg);

/**
 * filter based on IP Access header in both directions
 */
int bsc_nat_filter_ipa(int direction, struct msgb *msg, struct bsc_nat_parsed *parsed);
int bsc_nat_vty_init(struct bsc_nat *nat);
int bsc_nat_find_paging(struct msgb *msg, const uint8_t **,int *len);

/**
 * Content filtering.
 */
int bsc_nat_filter_sccp_cr(struct bsc_connection *bsc, struct msgb *msg,
			struct bsc_nat_parsed *, int *con_type, char **imsi,
			struct bsc_nat_reject_cause *cause);
int bsc_nat_filter_dt(struct bsc_connection *bsc, struct msgb *msg,
			struct nat_sccp_connection *con, struct bsc_nat_parsed *parsed,
			struct bsc_nat_reject_cause *cause);

/**
 * SCCP patching and handling
 */
struct nat_sccp_connection *create_sccp_src_ref(struct bsc_connection *bsc, struct bsc_nat_parsed *parsed);
int update_sccp_src_ref(struct nat_sccp_connection *sccp, struct bsc_nat_parsed *parsed);
void remove_sccp_src_ref(struct bsc_connection *bsc, struct msgb *msg, struct bsc_nat_parsed *parsed);
struct nat_sccp_connection *patch_sccp_src_ref_to_bsc(struct msgb *, struct bsc_nat_parsed *, struct bsc_nat *);
struct nat_sccp_connection *patch_sccp_src_ref_to_msc(struct msgb *, struct bsc_nat_parsed *, struct bsc_connection *);
struct nat_sccp_connection *bsc_nat_find_con_by_bsc(struct bsc_nat *, struct sccp_source_reference *);

/**
 * MGCP/Audio handling
 */
int bsc_mgcp_nr_multiplexes(int max_endpoints);
int bsc_write_mgcp(struct bsc_connection *bsc, const uint8_t *data, unsigned int length);
int bsc_mgcp_assign_patch(struct nat_sccp_connection *, struct msgb *msg);
void bsc_mgcp_init(struct nat_sccp_connection *);
void bsc_mgcp_dlcx(struct nat_sccp_connection *);
void bsc_mgcp_free_endpoints(struct bsc_nat *nat);
int bsc_mgcp_nat_init(struct bsc_nat *nat);

struct nat_sccp_connection *bsc_mgcp_find_con(struct bsc_nat *, int endpoint_number);
struct msgb *bsc_mgcp_rewrite(char *input, int length, int endp, const char *ip, int port);
void bsc_mgcp_forward(struct bsc_connection *bsc, struct msgb *msg);

void bsc_mgcp_clear_endpoints_for(struct bsc_connection *bsc);
int bsc_mgcp_parse_response(const char *str, int *code, char transaction[60]);
uint32_t bsc_mgcp_extract_ci(const char *resp);


int bsc_write(struct bsc_connection *bsc, struct msgb *msg, int id);
int bsc_do_write(struct osmo_wqueue *queue, struct msgb *msg, int id);
int bsc_write_msg(struct osmo_wqueue *queue, struct msgb *msg);
int bsc_write_cb(struct osmo_fd *bfd, struct msgb *msg);

/* IMSI allow/deny handling */
struct bsc_nat_acc_lst *bsc_nat_acc_lst_find(struct bsc_nat *nat, const char *name);
struct bsc_nat_acc_lst *bsc_nat_acc_lst_get(struct bsc_nat *nat, const char *name);
void bsc_nat_acc_lst_delete(struct bsc_nat_acc_lst *lst);

struct bsc_nat_acc_lst_entry *bsc_nat_acc_lst_entry_create(struct bsc_nat_acc_lst *);
int bsc_nat_lst_check_allow(struct bsc_nat_acc_lst *lst, const char *imsi);

int bsc_nat_msc_is_connected(struct bsc_nat *nat);

int bsc_conn_type_to_ctr(struct nat_sccp_connection *conn);

struct gsm48_hdr *bsc_unpack_dtap(struct bsc_nat_parsed *parsed, struct msgb *msg, uint32_t *len);

/** USSD filtering */
int bsc_ussd_init(struct bsc_nat *nat);
int bsc_check_ussd(struct nat_sccp_connection *con, struct bsc_nat_parsed *parsed, struct msgb *msg);
int bsc_close_ussd_connections(struct bsc_nat *nat);

struct msgb *bsc_nat_rewrite_msg(struct bsc_nat *nat, struct msgb *msg, struct bsc_nat_parsed *, const char *imsi);

/** paging group handling */
struct bsc_nat_paging_group *bsc_nat_paging_group_num(struct bsc_nat *nat, int group);
struct bsc_nat_paging_group *bsc_nat_paging_group_create(struct bsc_nat *nat, int group);
void bsc_nat_paging_group_delete(struct bsc_nat_paging_group *);
void bsc_nat_paging_group_add_lac(struct bsc_nat_paging_group *grp, int lac);
void bsc_nat_paging_group_del_lac(struct bsc_nat_paging_group *grp, int lac);

/**
 * Number rewriting support below
 */
struct bsc_nat_num_rewr_entry {
	struct llist_head list;

	regex_t msisdn_reg;
	regex_t num_reg;

	char *replace;
	uint8_t is_prefix_lookup;
};

void bsc_nat_num_rewr_entry_adapt(void *ctx, struct llist_head *head, const struct osmo_config_list *);

struct bsc_nat_barr_entry {
	struct rb_node node;

	char *imsi;
	int cm_reject_cause;
	int lu_reject_cause;
};

int bsc_nat_barr_adapt(void *ctx, struct rb_root *rbtree, const struct osmo_config_list *);
int bsc_nat_barr_find(struct rb_root *root, const char *imsi, int *cm, int *lu);

void bsc_nat_send_mgcp_to_msc(struct bsc_nat *bsc_nat, struct msgb *msg);
void bsc_nat_handle_mgcp(struct bsc_nat *bsc, struct msgb *msg);

struct ctrl_handle *bsc_nat_controlif_setup(struct bsc_nat *nat, int port);
void bsc_nat_ctrl_del_pending(struct bsc_cmd_list *pending);
int bsc_nat_handle_ctrlif_msg(struct bsc_connection *bsc, struct msgb *msg);

int bsc_nat_extract_lac(struct bsc_connection *bsc, struct nat_sccp_connection *con,
				struct bsc_nat_parsed *parsed, struct msgb *msg);

#endif
