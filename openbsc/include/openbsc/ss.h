#ifndef _SS_H
#define _SS_H

/* Handler function for mobile-originated SS messages */

#include <osmocom/core/msgb.h>

int handle_rcv_ss(struct gsm_subscriber_connection *conn, struct msgb *msg);

#endif
