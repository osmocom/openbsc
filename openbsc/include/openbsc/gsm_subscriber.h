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

struct vty;
struct sgsn_mm_ctx;
struct sgsn_subscriber_data;

struct subscr_request;

struct gsm_subscriber_group {
	struct gsm_network *net;

	int keep_subscr;
};

struct gsm_equipment {
	long long unsigned int id;
	char imei[GSM23003_IMEISV_NUM_DIGITS+1];
	char name[GSM_NAME_LENGTH];

	struct gsm48_classmark1 classmark1;
	uint8_t classmark2_len;
	uint8_t classmark2[3];
	uint8_t classmark3_len;
	uint8_t classmark3[14];
};

struct gsm_subscriber {
	struct gsm_subscriber_group *group;
	long long unsigned int id;
	char imsi[GSM23003_IMSI_MAX_DIGITS+1];
	uint32_t tmsi;
	uint16_t lac;
	char name[GSM_NAME_LENGTH];
	char extension[GSM_EXTENSION_LENGTH];
	int authorized;
	time_t expire_lu;

	/* Don't delete subscribers even if group->keep_subscr is not set */
	int keep_in_ram;

	/* Temporary field which is not stored in the DB/HLR */
	uint32_t flags;

	/* Every user can only have one equipment in use at any given
	 * point in time */
	struct gsm_equipment equipment;

	/* for internal management */
	int use_count;
	struct llist_head entry;

	/* pending requests */
	int is_paging;
	struct llist_head requests;

	/* GPRS/SGSN related fields */
	struct sgsn_subscriber_data *sgsn_data;
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
struct gsm_subscriber *subscr_create_subscriber(struct gsm_subscriber_group *sgrp,
						const char *imsi);
struct gsm_subscriber *subscr_get_by_tmsi(struct gsm_subscriber_group *sgrp,
					  uint32_t tmsi);
struct gsm_subscriber *subscr_get_by_imsi(struct gsm_subscriber_group *sgrp,
					  const char *imsi);
struct gsm_subscriber *subscr_get_by_extension(struct gsm_subscriber_group *sgrp,
					       const char *ext);
struct gsm_subscriber *subscr_get_by_id(struct gsm_subscriber_group *sgrp,
					unsigned long long id);
struct gsm_subscriber *subscr_get_or_create(struct gsm_subscriber_group *sgrp,
					const char *imsi);
int subscr_update(struct gsm_subscriber *s, struct gsm_bts *bts, int reason);
struct gsm_subscriber *subscr_active_by_tmsi(struct gsm_subscriber_group *sgrp,
					     uint32_t tmsi);
struct gsm_subscriber *subscr_active_by_imsi(struct gsm_subscriber_group *sgrp,
					     const char *imsi);

char *subscr_name(struct gsm_subscriber *subscr);

int subscr_purge_inactive(struct gsm_subscriber_group *sgrp);
void subscr_update_from_db(struct gsm_subscriber *subscr);
void subscr_expire(struct gsm_subscriber_group *sgrp);
int subscr_update_expire_lu(struct gsm_subscriber *subscr, struct gsm_bts *bts);

/*
 * Paging handling with authentication
 */
struct subscr_request *subscr_request_channel(struct gsm_subscriber *subscr,
                        int type, gsm_cbfn *cbfn, void *param);
void subscr_remove_request(struct subscr_request *req);

/* internal */
struct gsm_subscriber *subscr_alloc(void);
extern struct llist_head active_subscribers;

#endif /* _GSM_SUBSCR_H */
