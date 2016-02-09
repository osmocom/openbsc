#ifndef _USSD_H
#define _USSD_H

/* Handler function for mobile-originated USSD messages */

#include <osmocom/core/msgb.h>

#define USSD_MO 1
#define USSD_MT 0

int handle_rcv_ussd(struct gsm_subscriber_connection *conn, struct msgb *msg);


int on_ussd_response(struct gsm_network *net,
		     uint32_t ref,
		     struct ss_header *reqhdr,
		     const uint8_t *component,
		     const char* extention);


void _ussd_trans_free(struct gsm_trans *trans);

#endif
