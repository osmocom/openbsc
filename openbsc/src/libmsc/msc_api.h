#pragma once

/* These functions receive or send MM|CC|... messages from/to the BSC|RNC
 * direction, while they are not concerned with which particular external
 * interface is actually involved (A or IuCS).
 *
 * For the interface specific decisions see msc_iface.[hc] */

#include <stdint.h>

struct gsm_subscriber_connection;
struct msgb;

enum {
	MSC_CONN_ACCEPT = 0,
	MSC_CONN_REJECT = 1,
};

/* receive a Level 3 Complete message and return MSC_CONN_ACCEPT or
 * MSC_CONN_REJECT */
int msc_compl_l3(struct gsm_subscriber_connection *conn, struct msgb *msg,
		 uint16_t chosen_channel);
/* TODO: is chosen_channel NITB legacy? */

