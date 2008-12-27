#ifndef _GSM_SUBSCR_H
#define _GSM_SUBSCR_H

#include <sys/types.h>
#include "gsm_data.h"

#define GSM_IMEI_LENGTH 17
#define GSM_IMSI_LENGTH 17
#define GSM_TMSI_LENGTH 17
#define GSM_NAME_LENGTH 128

struct gsm_subscriber {
	u_int64_t id;
	char imsi[GSM_IMSI_LENGTH];
	char tmsi[GSM_TMSI_LENGTH];
	u_int16_t lac;
	char name[GSM_NAME_LENGTH];
	int authorized;
};

enum gsm_subscriber_field {
	GSM_SUBSCRIBER_IMSI,
	GSM_SUBSCRIBER_TMSI,
};

#endif /* _GSM_SUBSCR_H */
