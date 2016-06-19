/* Routines for the MSC handling */

#ifndef OSMO_MSC_H
#define OSMO_MSC_H

#include "bsc_api.h"

struct bsc_api *msc_bsc_api();
struct gsm_subscriber_connection *subscr_con_get(struct gsm_subscriber_connection *conn);
void subscr_con_put(struct gsm_subscriber_connection *conn);

#endif
