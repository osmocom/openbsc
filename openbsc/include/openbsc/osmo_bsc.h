/* OpenBSC BSC code */

#ifndef OSMO_BSC_H
#define OSMO_BSC_H

#include "bsc_api.h"

struct bsc_api *osmo_bsc_api();

int bsc_queue_for_msc(struct gsm_subscriber_connection *conn, struct msgb *msg);

#endif
