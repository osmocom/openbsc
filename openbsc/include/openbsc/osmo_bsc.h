/* OpenBSC BSC code */

#ifndef OSMO_BSC_H
#define OSMO_BSC_H

#include "bsc_api.h"

#define BSS_SEND_USSD 1

struct sccp_connection;
struct osmo_msc_data;
struct bsc_msc_connection;

struct osmo_bsc_sccp_con {
	struct llist_head entry;

	int ciphering_handled;
	int rtp_port;

	/* SCCP connection realted */
	struct sccp_connection *sccp;
	struct osmo_msc_data *msc;
	struct osmo_timer_list sccp_it_timeout;
	struct osmo_timer_list sccp_cc_timeout;

	struct llist_head sccp_queue;
	unsigned int sccp_queue_size;

	struct gsm_subscriber_connection *conn;
	uint8_t new_subscriber;
};

struct bsc_api *osmo_bsc_api();

int bsc_queue_for_msc(struct osmo_bsc_sccp_con *conn, struct msgb *msg);
int bsc_open_connection(struct osmo_bsc_sccp_con *sccp, struct msgb *msg);
int bsc_create_new_connection(struct gsm_subscriber_connection *conn,
			      struct osmo_msc_data *msc);
int bsc_delete_connection(struct osmo_bsc_sccp_con *sccp);

struct osmo_msc_data *bsc_find_msc(struct gsm_subscriber_connection *conn, struct msgb *);
int bsc_scan_bts_msg(struct gsm_subscriber_connection *conn, struct msgb *msg);
int bsc_scan_msc_msg(struct gsm_subscriber_connection *conn, struct msgb *msg);
int bsc_send_welcome_ussd(struct gsm_subscriber_connection *conn);

int bsc_handle_udt(struct osmo_msc_data *msc, struct msgb *msg, unsigned int length);
int bsc_handle_dt1(struct osmo_bsc_sccp_con *conn, struct msgb *msg, unsigned int len);

int bsc_ctrl_cmds_install();

#endif
