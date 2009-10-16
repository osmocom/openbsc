#ifndef _USSD_H
#define _USSD_H

/* Handler function for mobile-originated USSD messages */

#include <openbsc/msgb.h>

int handle_rcv_ussd(struct msgb *msg);

#endif
