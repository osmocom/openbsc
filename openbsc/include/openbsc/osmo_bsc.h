/* OpenBSC BSC code */

#ifndef OSMO_BSC_H
#define OSMO_BSC_H

#include "bsc_api.h"

struct osmo_bsc_sccp_con {
	uint8_t new_subscriber;
};

struct bsc_api *osmo_bsc_api();

int bsc_queue_for_msc(struct gsm_subscriber_connection *conn, struct msgb *msg);
int bsc_open_connection(struct gsm_subscriber_connection *conn, struct msgb *msg);
int bsc_create_new_connection(struct gsm_subscriber_connection *conn);
int bsc_delete_connection(struct gsm_subscriber_connection *conn);

int bsc_scan_bts_msg(struct gsm_subscriber_connection *conn, struct msgb *msg);
int bsc_scan_msc_msg(struct gsm_subscriber_connection *conn, struct msgb *msg);

#endif
