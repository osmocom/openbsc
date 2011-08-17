#ifndef _USSD_H
#define _USSD_H

/* Handler function for mobile-originated USSD messages */

#include <osmocom/core/msgb.h>

int handle_rcv_ussd(struct gsm_subscriber_connection *conn, struct msgb *msg);

#endif
