/* OpenBSC BSC code */

#ifndef OSMO_BSC_H
#define OSMO_BSC_H

#include "bsc_api.h"

struct bsc_api *osmo_bsc_api();

int bsc_queue_for_msc(struct gsm_subscriber_connection *conn, struct msgb *msg);
int bsc_create_new_connection(struct gsm_subscriber_connection *conn,
			      struct msgb *msg, uint16_t chosen_channel);

int bsc_scan_bts_msg(struct gsm_subscriber_connection *conn, struct msgb *msg);

#endif
