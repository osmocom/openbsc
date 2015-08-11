#ifndef _GSM_SUP_H
#define _GSM_SUP_H

#include <openbsc/debug.h>
#include <openbsc/gsm_subscriber.h>

#define LOGGSUBSCRP(level, subscr, fmt, args...) \
	LOGP(DSUP, level, "SUBSCR(%s) " fmt, \
	     (subscr) ? (subscr)->imsi : "---", \
	     ## args)

int subscr_query_auth_info(struct gsm_subscriber *subscr);
int subscr_location_update(struct gsm_subscriber *subscr);
int sup_init(struct gsm_network *net);

#endif /* _GSM_SUP_H */
