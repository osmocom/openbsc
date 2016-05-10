/* Routines for the MSC handling */

#ifndef OSMO_MSC_H
#define OSMO_MSC_H

#include "bsc_api.h"

enum {
	MSC_CONN_ACCEPT = 0,
	MSC_CONN_REJECT = 1,
};

struct bsc_api *msc_bsc_api();

int msc_compl_l3(struct gsm_subscriber_connection *conn, struct msgb *msg,
		 uint16_t chosen_channel);
void msc_release_connection(struct gsm_subscriber_connection *conn);

#endif
