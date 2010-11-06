/* OpenBSC BSC code */

#ifndef OSMO_BSC_H
#define OSMO_BSC_H

#include "bsc_api.h"

struct sccp_connection;

struct osmo_bsc_sccp_con {
	struct llist_head entry;

	/* SCCP connection realted */
	struct sccp_connection *sccp;
	struct bsc_msc_connection *msc_con;
	struct timer_list sccp_it_timeout;
	struct timer_list sccp_cc_timeout;

	struct gsm_subscriber_connection *conn;
	uint8_t new_subscriber;
};

struct bsc_api *osmo_bsc_api();

int bsc_queue_for_msc(struct gsm_subscriber_connection *conn, struct msgb *msg);
int bsc_open_connection(struct osmo_bsc_sccp_con *sccp, struct msgb *msg);
int bsc_create_new_connection(struct gsm_subscriber_connection *conn);
int bsc_delete_connection(struct osmo_bsc_sccp_con *sccp);

int bsc_scan_bts_msg(struct gsm_subscriber_connection *conn, struct msgb *msg);
int bsc_scan_msc_msg(struct gsm_subscriber_connection *conn, struct msgb *msg);

#endif
