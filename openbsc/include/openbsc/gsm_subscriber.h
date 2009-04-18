#ifndef _GSM_SUBSCR_H
#define _GSM_SUBSCR_H

#include <sys/types.h>
#include "gsm_data.h"
#include "linuxlist.h"

#define GSM_IMEI_LENGTH 17
#define GSM_IMSI_LENGTH 17
#define GSM_TMSI_LENGTH 17
#define GSM_NAME_LENGTH 128
#define GSM_EXTENSION_LENGTH 128

struct gsm_subscriber {
	long long unsigned int id;
	char imsi[GSM_IMSI_LENGTH];
	char tmsi[GSM_TMSI_LENGTH];
	u_int16_t lac;
	char name[GSM_NAME_LENGTH];
	char extension[GSM_EXTENSION_LENGTH];
	int authorized;

	/* for internal management */
	int use_count;
	struct llist_head entry;

	/* those are properties of the equipment, but they
	 * are applicable to the subscriber at the moment */
	struct gsm48_classmark1 classmark1;
	u_int8_t classmark2_len;
	u_int8_t classmark2[3];
	u_int8_t classmark3_len;
	u_int8_t classmark3[14];

	/* pending requests */
	int in_callback;
	struct llist_head requests;
};

enum gsm_subscriber_field {
	GSM_SUBSCRIBER_IMSI,
	GSM_SUBSCRIBER_TMSI,
	GSM_SUBSCRIBER_EXTENSION,
};

enum gsm_subscriber_update_reason {
	GSM_SUBSCRIBER_UPDATE_ATTACHED,
	GSM_SUBSCRIBER_UPDATE_DETACHED,
};

struct gsm_subscriber *subscr_get(struct gsm_subscriber *subscr);
struct gsm_subscriber *subscr_put(struct gsm_subscriber *subscr);
struct gsm_subscriber *subscr_get_by_tmsi(const char *tmsi);
struct gsm_subscriber *subscr_get_by_imsi(const char *imsi);
struct gsm_subscriber *subscr_get_by_extension(const char *ext);
int subscr_update(struct gsm_subscriber *s, struct gsm_bts *bts, int reason);
void subscr_put_channel(struct gsm_lchan *lchan);
void subscr_get_channel(struct gsm_subscriber *subscr,
                        struct gsm_network *network, int type,
		        gsm_cbfn *cbfn, void *param);

/* internal */
struct gsm_subscriber *subscr_alloc(void);

#endif /* _GSM_SUBSCR_H */
