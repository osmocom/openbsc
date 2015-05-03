#pragma once

#include <osmocom/core/msgb.h>
#include <osmocom/core/msgfile.h>
#include <osmocom/core/linuxrbtree.h>
#include <osmocom/core/linuxlist.h>

#include <regex.h>

struct vty;
struct gsm48_hdr;

struct bsc_filter_reject_cause {
	int lu_reject_cause;
	int cm_reject_cause;
};

struct bsc_filter_barr_entry {
	struct rb_node node;

	char *imsi;
	int cm_reject_cause;
	int lu_reject_cause;
};

enum bsc_filter_acc_ctr {
	ACC_LIST_LOCAL_FILTER,
	ACC_LIST_GLOBAL_FILTER,
};

struct bsc_msg_acc_lst {
	struct llist_head list;

	/* counter */
	struct rate_ctr_group *stats;

	/* the name of the list */
	const char *name;
	struct llist_head fltr_list;
};

struct bsc_msg_acc_lst_entry {
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

enum {
	FLT_CON_TYPE_NONE,
	FLT_CON_TYPE_LU,
	FLT_CON_TYPE_CM_SERV_REQ,
	FLT_CON_TYPE_PAG_RESP,
	FLT_CON_TYPE_SSA,
	FLT_CON_TYPE_LOCAL_REJECT,
	FLT_CON_TYPE_OTHER,
};


struct bsc_filter_state {
	char *imsi;
	int imsi_checked;
	int con_type;
};

struct bsc_filter_request {
	void *ctx;
	struct rb_root *black_list;
	struct llist_head *access_lists;
	const char *local_lst_name;
	const char *global_lst_name;
	int bsc_nr;
};


int bsc_filter_barr_adapt(void *ctx, struct rb_root *rbtree, const struct osmo_config_list *);
int bsc_filter_barr_find(struct rb_root *root, const char *imsi, int *cm, int *lu);

/**
 * Content filtering.
 */
int bsc_msg_filter_initial(struct gsm48_hdr *hdr, size_t size,
			struct bsc_filter_request *req,
			int *con_type, char **imsi,
			struct bsc_filter_reject_cause *cause);
int bsc_msg_filter_data(struct gsm48_hdr *hdr, size_t size,
			struct bsc_filter_request *req,
			struct bsc_filter_state *state,
			struct bsc_filter_reject_cause *cause);

/* IMSI allow/deny handling */
struct bsc_msg_acc_lst *bsc_msg_acc_lst_find(struct llist_head *lst, const char *name);
struct bsc_msg_acc_lst *bsc_msg_acc_lst_get(void *ctx, struct llist_head *lst, const char *name);
void bsc_msg_acc_lst_delete(struct bsc_msg_acc_lst *lst);

struct bsc_msg_acc_lst_entry *bsc_msg_acc_lst_entry_create(struct bsc_msg_acc_lst *);
int bsc_msg_acc_lst_check_allow(struct bsc_msg_acc_lst *lst, const char *imsi);

void bsc_msg_lst_vty_init(void *ctx, struct llist_head *lst, int node);
void bsc_msg_acc_lst_write(struct vty *vty, struct bsc_msg_acc_lst *lst);
