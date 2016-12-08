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
#define tmsi_from_string(str) strtoul(str, NULL, 10)

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
	/* VLR work in progress: the long term aim is to completely eliminate
	 * gsm_subscriber; in libmsc, to replace it with vlr_subscriber, in
	 * libbsc in the osmo-bsc case to not have any gsm_subscriber at all,
	 * and in the osmo-nitb case to have a pointer to the vlr_subscriber
	 * for logging and debugging that is left NULL in osmo-bsc. But to be
	 * able to move there in small increments, I'm first keeping
	 * gsm_subscriber and merely point at the "future real" vlr_subscriber
	 * from here. To completely replace gsm_subscriber, these things need
	 * to be resolved:
	 * - provide id in vlr_subscriber for libmsc's VTY 'subscriber id N';
	 * - refactor libmsc paging to remember the paging requests with cb in
	 *   vlr_subscriber -- see 'requests' below, subscr_request_channel()
	 *   and paging.c;
	 * - in libbsc paging, don't reference the subscriber in a paging
	 *   request, simply pass a MI (TMSI or IMSI) to the paging API;
	 * - in libbsc, store IMSI, TMSI and LAC in the subscriber_conn (?);
	 * - use vlr_sub_name() instead of subscr_name() in various logging;
	 * - in libbsc, log the subscriber info only when available;
	 * - move classmark info to subscriber_conn ('equipment' below);
	 * - in the SGSN, use vsub->ps.* instead
	 */
	struct vlr_subscriber *vsub;

	/* AFAICT we always keep only one global group and never use it for
	 * anything. */
	struct gsm_subscriber_group *group;

	/* VTY: 'subscriber id N' */
	long long unsigned int id;

	/* use vsub->imsi instead, if at all this is a copy */
	char imsi[GSM23003_IMSI_MAX_DIGITS+1];
	/* use vsub->tmsi instead, if at all this is a copy */
	uint32_t tmsi;
	/* use vsub->lac instead, if at all this is a copy */
	uint16_t lac;
	/* use vsub->name instead, if at all this is a copy */
	char name[GSM_NAME_LENGTH];
	/* use vsub->msisdn instead, if at all this is a copy */
	char extension[GSM_EXTENSION_LENGTH];
	/* use vsub->authorized instead, if at all this is a copy */
	int authorized;
	/* use vsub->expire_lu instead, if at all this is a copy */
	time_t expire_lu;

	/* AFAICT this is only set to 1 by the SGSN VTY's 'update subscriber
	 * <imsi> create' command and a unit test.  "Don't delete subscribers
	 * even if group->keep_subscr is not set" */
	int keep_in_ram;

	/* Used in libmsc only for GSM_SUBSCRIBER_FIRST_CONTACT to send a
	 * token, set by db.c; used extensively in osmo-sgsn, see
	 * GPRS_SUBSCRIBER_* flags. TODO: set GSM_SUBSCRIBER_FIRST_CONTACT from
	 * HLR via VLR? */
	uint32_t flags;

	/* Every user can only have one equipment in use at any given
	 * point in time */
	struct gsm_equipment equipment;

	/* use vsub->use_count instead?? */
	int use_count;
	struct llist_head entry;

	/* use vsub->cs.is_paging instead */
	int is_paging;
	/* use vsub->cs.requests instead */
	struct llist_head requests;

	/* use vsub->ps.* instead */
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
