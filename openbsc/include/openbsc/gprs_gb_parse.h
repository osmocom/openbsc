#pragma once

#include <openbsc/gprs_llc.h>

#include <sys/types.h>

struct gprs_gb_parse_context {
	/* Pointer to protocol specific parts */
	struct gsm48_hdr *g48_hdr;
	struct bssgp_normal_hdr *bgp_hdr;
	struct bssgp_ud_hdr *bud_hdr;
	uint8_t *bssgp_data;
	size_t bssgp_data_len;
	uint8_t *llc;
	size_t llc_len;

	/* Extracted information */
	struct gprs_llc_hdr_parsed llc_hdr_parsed;
	struct tlv_parsed bssgp_tp;
	int to_bss;
	uint8_t *tlli_enc;
	uint8_t *old_tlli_enc;
	uint8_t *imsi;
	size_t imsi_len;
	uint8_t *apn_ie;
	size_t apn_ie_len;
	uint8_t *ptmsi_enc;
	uint8_t *new_ptmsi_enc;
	uint8_t *raid_enc;
	uint8_t *old_raid_enc;
	uint8_t *bssgp_raid_enc;
	uint8_t *bssgp_ptmsi_enc;

	/* General info */
	const char *llc_msg_name;
	int invalidate_tlli;
	int await_reattach;
	int need_decryption;
	uint32_t tlli;
	int pdu_type;
	int old_raid_is_foreign;
	int peer_nsei;
};

int gprs_gb_parse_dtap(uint8_t *data, size_t data_len,
		       struct gprs_gb_parse_context *parse_ctx);

int gprs_gb_parse_llc(uint8_t *llc, size_t llc_len,
		      struct gprs_gb_parse_context *parse_ctx);

int gprs_gb_parse_bssgp(uint8_t *bssgp, size_t bssgp_len,
			struct gprs_gb_parse_context *parse_ctx);

const char *gprs_gb_message_name(const struct gprs_gb_parse_context *parse_ctx,
				 const char *default_msg_name);

void gprs_gb_log_parse_context(int log_level,
			       struct gprs_gb_parse_context *parse_ctx,
			       const char *default_msg_name);
