/* GPRS subscriber details for use in SGSN land */
#pragma once

#include <stdint.h>

#include <osmocom/core/linuxlist.h>
#include <osmocom/gsm/protocol/gsm_23_003.h>

extern struct llist_head * const gprs_subscribers;

struct gprs_subscr {
	struct llist_head entry;
	int use_count;

	char imsi[GSM23003_IMSI_MAX_DIGITS+1];
	uint32_t tmsi;
	char imei[GSM23003_IMEISV_NUM_DIGITS+1];
	bool authorized;
	bool keep_in_ram;
	uint32_t flags;
	uint16_t lac;

	struct sgsn_subscriber_data *sgsn_data;
};

struct gprs_subscr *_gprs_subscr_get(struct gprs_subscr *gsub,
				     const char *file, int line);
struct gprs_subscr *_gprs_subscr_put(struct gprs_subscr *gsub,
				     const char *file, int line);
#define gprs_subscr_get(gsub) _gprs_subscr_get(gsub, __BASE_FILE__, __LINE__)
#define gprs_subscr_put(gsub) _gprs_subscr_put(gsub, __BASE_FILE__, __LINE__)
