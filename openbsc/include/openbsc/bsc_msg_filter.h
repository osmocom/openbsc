#pragma once

#include <osmocom/core/msgb.h>
#include <osmocom/core/msgfile.h>
#include <osmocom/core/linuxrbtree.h>
#include <osmocom/core/linuxlist.h>

#include <regex.h>

/* TODO: remove */
struct bsc_nat_parsed;
struct bsc_connection;
struct nat_sccp_connection;

struct bsc_nat_reject_cause {
	int lu_reject_cause;
	int cm_reject_cause;
};

struct bsc_nat_barr_entry {
	struct rb_node node;

	char *imsi;
	int cm_reject_cause;
	int lu_reject_cause;
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

	/* reject reasons for the access lists */
	int cm_reject_cause;
	int lu_reject_cause;
};


int bsc_nat_barr_adapt(void *ctx, struct rb_root *rbtree, const struct osmo_config_list *);
int bsc_nat_barr_find(struct rb_root *root, const char *imsi, int *cm, int *lu);

/**
 * Content filtering.
 */
int bsc_nat_filter_sccp_cr(struct bsc_connection *bsc, struct msgb *msg,
			struct bsc_nat_parsed *, int *con_type, char **imsi,
			struct bsc_nat_reject_cause *cause);
int bsc_nat_filter_dt(struct bsc_connection *bsc, struct msgb *msg,
			struct nat_sccp_connection *con, struct bsc_nat_parsed *parsed,
			struct bsc_nat_reject_cause *cause);

