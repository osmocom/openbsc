#ifndef _GSM_SUP_H
#define _GSM_SUP_H

#include <openbsc/debug.h>
#include <openbsc/gsm_subscriber.h>
#include <osmocom/gsm/gsm0480.h>
#include <osmocom/gsm/protocol/gsm_04_11.h>

#define LOGGSUBSCRP(level, subscr, fmt, args...) \
	LOGP(DSUP, level, "SUBSCR(%s) " fmt, \
	     (subscr) ? (subscr)->imsi : "---", \
	     ## args)

/* Callback for both HLR/auth and USSD SUP sockets */
int sup_read_cb(struct gprs_gsup_client *sup_client, struct msgb *msg);

int subscr_query_auth_info(struct gsm_subscriber *subscr);
int subscr_location_update(struct gsm_subscriber *subscr);

int subscr_tx_sms_message(struct gsm_subscriber *subscr,
                          struct gsm411_rp_hdr *rph);

#endif /* _GSM_SUP_H */
