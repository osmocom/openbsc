/* Routines for the MSC handling */

#ifndef OSMO_MSC_H
#define OSMO_MSC_H

#include "bsc_api.h"

struct bsc_api *msc_bsc_api();
void msc_release_connection(struct gsm_subscriber_connection *conn);

#endif
