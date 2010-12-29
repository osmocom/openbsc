#ifndef _USSD_H
#define _USSD_H

/* Handler function for mobile-originated USSD messages */

#include <osmocore/msgb.h>

struct vty;

int handle_rcv_ussd(struct gsm_subscriber_connection *conn, struct msgb *msg);

/* reply with custom L3 messages */
int ussd_parse_mapping(const char *number, const uint8_t *msg, int len);
int ussd_clear_mapping(const char *number);
int ussd_dump_mapping(struct vty *vty);


int ussd_call_reroute(struct gsm_subscriber_connection *conn, struct msgb *msg);
int ussd_call_rx(struct gsm_subscriber_connection *conn, struct msgb *msg);

#endif
