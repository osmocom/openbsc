/* GSM subscriber details for use in BSC land */

#pragma once

#include <stdint.h>

#include <osmocom/core/linuxlist.h>
#include <osmocom/gsm/protocol/gsm_23_003.h>

struct log_target;

struct bsc_subscr {
	struct llist_head entry;
	int use_count;

	char imsi[GSM23003_IMSI_MAX_DIGITS+1];
	uint32_t tmsi;
	uint16_t lac;
};

const char *bsc_subscr_name(struct bsc_subscr *bsub);

struct bsc_subscr *bsc_subscr_find_or_create_by_imsi(struct llist_head *list,
						     const char *imsi);
struct bsc_subscr *bsc_subscr_find_or_create_by_tmsi(struct llist_head *list,
						     uint32_t tmsi);

struct bsc_subscr *bsc_subscr_find_by_imsi(struct llist_head *list,
					   const char *imsi);
struct bsc_subscr *bsc_subscr_find_by_tmsi(struct llist_head *list,
					   uint32_t tmsi);

void bsc_subscr_set_imsi(struct bsc_subscr *bsub, const char *imsi);

struct bsc_subscr *_bsc_subscr_get(struct bsc_subscr *bsub,
				   const char *file, int line);
struct bsc_subscr *_bsc_subscr_put(struct bsc_subscr *bsub,
				   const char *file, int line);
#define bsc_subscr_get(bsub) _bsc_subscr_get(bsub, __BASE_FILE__, __LINE__)
#define bsc_subscr_put(bsub) _bsc_subscr_put(bsub, __BASE_FILE__, __LINE__)

void log_set_filter_bsc_subscr(struct log_target *target,
			       struct bsc_subscr *bsub);
