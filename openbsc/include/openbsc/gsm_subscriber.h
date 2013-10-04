#ifndef _GSM_SUBSCR_H
#define _GSM_SUBSCR_H

#include "gsm_data.h"
#include <osmocom/core/linuxlist.h>

#define GSM_IMEI_LENGTH 17
#define GSM_IMSI_LENGTH 17
#define GSM_NAME_LENGTH 160

#define GSM_EXTENSION_LENGTH 15 /* MSISDN can only be 15 digits length */
#define GSM_MIN_EXTEN 20000
#define GSM_MAX_EXTEN 49999

#define GSM_SUBSCRIBER_FIRST_CONTACT	0x00000001
#define tmsi_from_string(str) strtoul(str, NULL, 10)

#define GSM_SUBSCRIBER_NO_EXPIRATION	0x0

struct vty;

struct gsm_equipment {
	long long unsigned int id;
	char imei[GSM_IMEI_LENGTH];
	char name[GSM_NAME_LENGTH];

	struct gsm48_classmark1 classmark1;
	uint8_t classmark2_len;
	uint8_t classmark2[3];
	uint8_t classmark3_len;
	uint8_t classmark3[14];
};

struct gsm_subscriber {
	struct gsm_network *net;
	long long unsigned int id;
	char imsi[GSM_IMSI_LENGTH];
	uint32_t tmsi;
	uint16_t lac;
	char name[GSM_NAME_LENGTH];
	char extension[GSM_EXTENSION_LENGTH];
	int authorized;
	time_t expire_lu;

	/* Temporary field which is not stored in the DB/HLR */
	uint32_t flags;

	/* Every user can only have one equipment in use at any given
	 * point in time */
	struct gsm_equipment equipment;

	/* for internal management */
	int use_count;
	struct llist_head entry;

	/* pending requests */
	int in_callback;
	struct llist_head requests;
};

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

struct gsm_subscriber *subscr_get(struct gsm_subscriber *subscr);
struct gsm_subscriber *subscr_put(struct gsm_subscriber *subscr);
struct gsm_subscriber *subscr_create_subscriber(struct gsm_network *net,
						const char *imsi);
struct gsm_subscriber *subscr_get_by_tmsi(struct gsm_network *net,
					  uint32_t tmsi);
struct gsm_subscriber *subscr_get_by_imsi(struct gsm_network *net,
					  const char *imsi);
struct gsm_subscriber *subscr_get_by_extension(struct gsm_network *net,
					       const char *ext);
struct gsm_subscriber *subscr_get_by_id(struct gsm_network *net,
					unsigned long long id);
struct gsm_subscriber *subscr_get_or_create(struct gsm_network *net,
					const char *imsi);
int subscr_update(struct gsm_subscriber *s, struct gsm_bts *bts, int reason);
void subscr_put_channel(struct gsm_subscriber *subscr);
void subscr_get_channel(struct gsm_subscriber *subscr,
                        int type, gsm_cbfn *cbfn, void *param);
struct gsm_subscriber *subscr_active_by_tmsi(struct gsm_network *net,
					     uint32_t tmsi);
struct gsm_subscriber *subscr_active_by_imsi(struct gsm_network *net,
					     const char *imsi);

int subscr_pending_requests(struct gsm_subscriber *subscr);
int subscr_pending_clear(struct gsm_subscriber *subscr);
int subscr_pending_dump(struct gsm_subscriber *subscr, struct vty *vty);
int subscr_pending_kick(struct gsm_subscriber *subscr);

char *subscr_name(struct gsm_subscriber *subscr);

int subscr_purge_inactive(struct gsm_network *net);
void subscr_update_from_db(struct gsm_subscriber *subscr);
void subscr_expire(struct gsm_network *net);
int subscr_update_expire_lu(struct gsm_subscriber *subscr, struct gsm_bts *bts);

/* internal */
struct gsm_subscriber *subscr_alloc(void);
extern struct llist_head active_subscribers;

#endif /* _GSM_SUBSCR_H */
