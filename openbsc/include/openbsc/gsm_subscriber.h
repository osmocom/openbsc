#ifndef _GSM_SUBSCR_H
#define _GSM_SUBSCR_H

#include <stdbool.h>

#include <osmocom/core/linuxlist.h>
#include <osmocom/gsm/protocol/gsm_23_003.h>

#include <openbsc/gsm_data.h>

#define GSM_NAME_LENGTH 160

#define GSM_EXTENSION_LENGTH 15 /* MSISDN can only be 15 digits length */
#define GSM_MIN_EXTEN 20000
#define GSM_MAX_EXTEN 49999

#define GSM_SUBSCRIBER_FIRST_CONTACT	0x00000001
/* gprs_sgsn.h defines additional flags including and above bit 16 (0x10000) */

#define GSM_SUBSCRIBER_NO_EXPIRATION	0x0

struct subscr_request;

enum gsm_subscriber_field {
	GSM_SUBSCRIBER_IMSI,
	GSM_SUBSCRIBER_TMSI,
	GSM_SUBSCRIBER_EXTENSION,
	GSM_SUBSCRIBER_ID,
};

enum gsm_subscriber_update_reason {
	GSM_SUBSCRIBER_UPDATE_ATTACHED,
	GSM_SUBSCRIBER_UPDATE_DETACHED,
	GSM_SUBSCRIBER_UPDATE_EQUIPMENT,
};

int subscr_update(struct vlr_subscr *vsub, struct gsm_bts *bts, int reason);

/*
 * Paging handling with authentication
 */
struct subscr_request *subscr_request_channel(struct vlr_subscr *vsub,
					      int channel_type,
					      gsm_cbfn *cbfn, void *param);
void subscr_remove_request(struct subscr_request *req);

int subscr_paging_dispatch(unsigned int hooknum, unsigned int event,
			   struct msgb *msg, void *data, void *param);

#endif /* _GSM_SUBSCR_H */
