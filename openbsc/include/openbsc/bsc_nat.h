/*
 * (C) 2010 by Holger Hans Peter Freyther <zecke@selfish.org>
 * (C) 2010 by On-Waves
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

#ifndef BSC_NAT_H
#define BSC_NAT_H

#include "mgcp.h"

#include <sys/types.h>
#include <sccp/sccp_types.h>

#include <osmocore/select.h>
#include <osmocore/msgb.h>
#include <osmocore/timer.h>
#include <osmocore/write_queue.h>
#include <osmocore/rate_ctr.h>
#include <osmocore/statistics.h>

#include <regex.h>

#define DIR_BSC 1
#define DIR_MSC 2

#define NAT_IPAC_PROTO_MGCP	0xfc

struct bsc_nat;

enum {
	NAT_CON_TYPE_NONE,
	NAT_CON_TYPE_LU,
	NAT_CON_TYPE_CM_SERV_REQ,
	NAT_CON_TYPE_PAG_RESP,
	NAT_CON_TYPE_LOCAL_REJECT,
	NAT_CON_TYPE_OTHER,
};

/*
 * For the NAT we will need to analyze and later patch
 * the received message. This would require us to parse
 * the IPA and SCCP header twice. Instead of doing this
 * we will have one analyze structure and have the patching
 * and filter operate on the same structure.
 */
struct bsc_nat_parsed {
	/* ip access prototype */
	int ipa_proto;

	/* source local reference */
	struct sccp_source_reference *src_local_ref;

	/* destination local reference */
	struct sccp_source_reference *dest_local_ref;

	/* called ssn number */
	int called_ssn;

	/* calling ssn number */
	int calling_ssn;

	/* sccp message type */
	int sccp_type;

	/* bssap type, e.g. 0 for BSS Management */
	int bssap;

	/* the gsm0808 message type */
	int gsm_type;
};

/*
 * Per BSC data structure
 */
struct bsc_connection {
	struct llist_head list_entry;

	/* do we know anything about this BSC? */
	int authenticated;

	/* the fd we use to communicate */
	struct write_queue write_queue;

	/* the BSS associated */
	struct bsc_config *cfg;

	/* a timeout node */
	struct timer_list id_timeout;

	/* pong timeout */
	struct timer_list ping_timeout;
	struct timer_list pong_timeout;

	/* a back pointer */
	struct bsc_nat *nat;
};

/*
 * Per SCCP source local reference patch table. It needs to
 * be updated on new SCCP connections, connection confirm and reject,
 * and on the loss of the BSC connection.
 */
struct sccp_connections {
	struct llist_head list_entry;

	struct bsc_connection *bsc;

	struct sccp_source_reference real_ref;
	struct sccp_source_reference patched_ref;
	struct sccp_source_reference remote_ref;
	int has_remote_ref;

	/* status */
	int con_type;
	int con_local;

	/* GSM audio handling. That is 32 * multiplex + ts */
	int crcx;
	int msc_timeslot;
	int bsc_timeslot;

	/* timeout handling */
	struct timespec creation_time;
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
};

/**
 * One BSC entry in the config
 */
struct bsc_config {
	struct llist_head entry;

	char *token;
	unsigned int lac;
	int nr;

	char *description;

	/* imsi white and blacklist */
	char *acc_lst_name;

	int forbid_paging;

	/* backpointer */
	struct bsc_nat *nat;

	struct bsc_config_stats stats;
};

/**
 * BSCs point of view of endpoints
 */
struct bsc_endpoint {
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
		struct counter *conn;
		struct counter *calls;
	} sccp;

	struct {
		struct counter *reconn;
                struct counter *auth_fail;
	} bsc;

	struct {
		struct counter *reconn;
	} msc;
};

struct bsc_nat_acc_lst {
	struct llist_head list;

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

	/* known BSC's */
	struct llist_head bsc_configs;
	int num_bsc;
	int bsc_ip_tos;

	/* MGCP config */
	struct mgcp_config *mgcp_cfg;
	struct write_queue mgcp_queue;
	u_int8_t mgcp_msg[4096];
	int mgcp_length;

	/* msc things */
	char *msc_ip;
	int msc_port;
	int first_contact;
	struct bsc_msc_connection *msc_con;
	char *token;

	/* timeouts */
	int auth_timeout;
	int ping_timeout;
	int pong_timeout;

	struct bsc_endpoint *bsc_endpoints;

	/* filter */
	char *acc_lst_name;

	/* statistics */
	struct bsc_nat_statistics stats;
};

/* create and init the structures */
struct bsc_config *bsc_config_alloc(struct bsc_nat *nat, const char *token, unsigned int lac);
struct bsc_config *bsc_config_num(struct bsc_nat *nat, int num);
struct bsc_nat *bsc_nat_alloc(void);
struct bsc_connection *bsc_connection_alloc(struct bsc_nat *nat);
void bsc_nat_set_msc_ip(struct bsc_nat *bsc, const char *ip);

void sccp_connection_destroy(struct sccp_connections *);
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
struct bsc_connection *bsc_nat_find_bsc(struct bsc_nat *nat, struct msgb *msg, int *_lac);

/**
 * Content filtering.
 */
int bsc_nat_filter_sccp_cr(struct bsc_connection *bsc, struct msgb *msg,
			   struct bsc_nat_parsed *, int *con_type);

/**
 * SCCP patching and handling
 */
struct sccp_connections *create_sccp_src_ref(struct bsc_connection *bsc, struct bsc_nat_parsed *parsed);
int update_sccp_src_ref(struct sccp_connections *sccp, struct bsc_nat_parsed *parsed);
void remove_sccp_src_ref(struct bsc_connection *bsc, struct msgb *msg, struct bsc_nat_parsed *parsed);
struct sccp_connections *patch_sccp_src_ref_to_bsc(struct msgb *, struct bsc_nat_parsed *, struct bsc_nat *);
struct sccp_connections *patch_sccp_src_ref_to_msc(struct msgb *, struct bsc_nat_parsed *, struct bsc_connection *);

/**
 * MGCP/Audio handling
 */
int bsc_write_mgcp(struct bsc_connection *bsc, const u_int8_t *data, unsigned int length);
int bsc_mgcp_assign(struct sccp_connections *, struct msgb *msg);
void bsc_mgcp_init(struct sccp_connections *);
void bsc_mgcp_dlcx(struct sccp_connections *);
void bsc_mgcp_free_endpoints(struct bsc_nat *nat);
int bsc_mgcp_nat_init(struct bsc_nat *nat);

struct sccp_connections *bsc_mgcp_find_con(struct bsc_nat *, int endpoint_number);
struct msgb *bsc_mgcp_rewrite(char *input, int length, const char *ip, int port);
void bsc_mgcp_forward(struct bsc_connection *bsc, struct msgb *msg);

void bsc_mgcp_clear_endpoints_for(struct bsc_connection *bsc);
int bsc_mgcp_parse_response(const char *str, int *code, char transaction[60]);
int bsc_mgcp_extract_ci(const char *resp);


int bsc_write(struct bsc_connection *bsc, struct msgb *msg, int id);

/* IMSI allow/deny handling */
void bsc_parse_reg(void *ctx, regex_t *reg, char **imsi, int argc, const char **argv);
struct bsc_nat_acc_lst *bsc_nat_acc_lst_find(struct bsc_nat *nat, const char *name);
struct bsc_nat_acc_lst *bsc_nat_acc_lst_get(struct bsc_nat *nat, const char *name);
void bsc_nat_acc_lst_delete(struct bsc_nat_acc_lst *lst);

struct bsc_nat_acc_lst_entry *bsc_nat_acc_lst_entry_create(struct bsc_nat_acc_lst *);

#endif
