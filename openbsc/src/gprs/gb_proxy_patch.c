/* Gb-proxy message patching */

/* (C) 2014 by On-Waves
 * All Rights Reserved
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include <openbsc/gb_proxy.h>

#include <openbsc/gprs_utils.h>
#include <openbsc/gprs_gb_parse.h>

#include <openbsc/gsm_data.h>
#include <openbsc/debug.h>

#include <osmocom/gprs/protocol/gsm_08_18.h>
#include <osmocom/core/rate_ctr.h>
#include <osmocom/gsm/apn.h>

/* patch RA identifier in place */
static void gbproxy_patch_raid(uint8_t *raid_enc, struct gbproxy_peer *peer,
			       int to_bss, const char *log_text)
{
	struct gbproxy_patch_state *state = &peer->patch_state;
	int old_mcc;
	int old_mnc;
	struct gprs_ra_id raid;
	enum gbproxy_peer_ctr counter =
		to_bss ?
		GBPROX_PEER_CTR_RAID_PATCHED_SGSN :
		GBPROX_PEER_CTR_RAID_PATCHED_BSS;

	if (!state->local_mcc || !state->local_mnc)
		return;

	gsm48_parse_ra(&raid, raid_enc);

	old_mcc = raid.mcc;
	old_mnc = raid.mnc;

	if (!to_bss) {
		/* BSS -> SGSN */
		if (state->local_mcc)
			raid.mcc = peer->cfg->core_mcc;

		if (state->local_mnc)
			raid.mnc = peer->cfg->core_mnc;
	} else {
		/* SGSN -> BSS */
		if (state->local_mcc)
			raid.mcc = state->local_mcc;

		if (state->local_mnc)
			raid.mnc = state->local_mnc;
	}

	LOGP(DGPRS, LOGL_DEBUG,
	     "Patching %s to %s: "
	     "%d-%d-%d-%d -> %d-%d-%d-%d\n",
	     log_text,
	     to_bss ? "BSS" : "SGSN",
	     old_mcc, old_mnc, raid.lac, raid.rac,
	     raid.mcc, raid.mnc, raid.lac, raid.rac);

	gsm48_construct_ra(raid_enc, &raid);
	rate_ctr_inc(&peer->ctrg->ctr[counter]);
}

static void gbproxy_patch_apn_ie(struct msgb *msg,
				 uint8_t *apn_ie, size_t apn_ie_len,
				 struct gbproxy_peer *peer,
				 size_t *new_apn_ie_len, const char *log_text)
{
	struct apn_ie_hdr {
		uint8_t iei;
		uint8_t apn_len;
		uint8_t apn[0];
	} *hdr = (void *)apn_ie;

	size_t apn_len = hdr->apn_len;
	uint8_t *apn = hdr->apn;

	OSMO_ASSERT(apn_ie_len == apn_len + sizeof(struct apn_ie_hdr));
	OSMO_ASSERT(apn_ie_len > 2 && apn_ie_len <= 102);

	if (peer->cfg->core_apn_size == 0) {
		char str1[110];
		/* Remove the IE */
		LOGP(DGPRS, LOGL_DEBUG,
		     "Patching %s to SGSN: Removing APN '%s'\n",
		     log_text,
		     osmo_apn_to_str(str1, apn, apn_len));

		*new_apn_ie_len = 0;
		gprs_msgb_resize_area(msg, apn_ie, apn_ie_len, 0);
	} else {
		/* Resize the IE */
		char str1[110];
		char str2[110];

		OSMO_ASSERT(peer->cfg->core_apn_size <= 100);

		LOGP(DGPRS, LOGL_DEBUG,
		     "Patching %s to SGSN: "
		     "Replacing APN '%s' -> '%s'\n",
		     log_text,
		     osmo_apn_to_str(str1, apn, apn_len),
		     osmo_apn_to_str(str2, peer->cfg->core_apn,
				       peer->cfg->core_apn_size));

		*new_apn_ie_len = peer->cfg->core_apn_size + 2;
		gprs_msgb_resize_area(msg, apn, apn_len, peer->cfg->core_apn_size);
		memcpy(apn, peer->cfg->core_apn, peer->cfg->core_apn_size);
		hdr->apn_len = peer->cfg->core_apn_size;
	}

	rate_ctr_inc(&peer->ctrg->ctr[GBPROX_PEER_CTR_APN_PATCHED]);
}

static int gbproxy_patch_tlli(uint8_t *tlli_enc,
			      struct gbproxy_peer *peer,
			      uint32_t new_tlli,
			      int to_bss, const char *log_text)
{
	uint32_t tlli_be;
	uint32_t tlli;
	enum gbproxy_peer_ctr counter =
		to_bss ?
		GBPROX_PEER_CTR_TLLI_PATCHED_SGSN :
		GBPROX_PEER_CTR_TLLI_PATCHED_BSS;

	memcpy(&tlli_be, tlli_enc, sizeof(tlli_be));
	tlli = ntohl(tlli_be);

	if (tlli == new_tlli)
		return 0;

	LOGP(DGPRS, LOGL_DEBUG,
	     "Patching %ss: "
	     "Replacing %08x -> %08x\n",
	     log_text, tlli, new_tlli);

	tlli_be = htonl(new_tlli);
	memcpy(tlli_enc, &tlli_be, sizeof(tlli_be));

	rate_ctr_inc(&peer->ctrg->ctr[counter]);

	return 1;
}

static int gbproxy_patch_ptmsi(uint8_t *ptmsi_enc,
			       struct gbproxy_peer *peer,
			       uint32_t new_ptmsi,
			       int to_bss, const char *log_text)
{
	uint32_t ptmsi_be;
	uint32_t ptmsi;
	enum gbproxy_peer_ctr counter =
		to_bss ?
		GBPROX_PEER_CTR_PTMSI_PATCHED_SGSN :
		GBPROX_PEER_CTR_PTMSI_PATCHED_BSS;
	memcpy(&ptmsi_be, ptmsi_enc, sizeof(ptmsi_be));
	ptmsi = ntohl(ptmsi_be);

	if (ptmsi == new_ptmsi)
		return 0;

	LOGP(DGPRS, LOGL_DEBUG,
	     "Patching %ss: "
	     "Replacing %08x -> %08x\n",
	     log_text, ptmsi, new_ptmsi);

	ptmsi_be = htonl(new_ptmsi);
	memcpy(ptmsi_enc, &ptmsi_be, sizeof(ptmsi_be));

	rate_ctr_inc(&peer->ctrg->ctr[counter]);

	return 1;
}

int gbproxy_patch_llc(struct msgb *msg, uint8_t *llc, size_t llc_len,
		     struct gbproxy_peer *peer,
		     struct gbproxy_link_info *link_info, int *len_change,
		     struct gprs_gb_parse_context *parse_ctx)
{
	struct gprs_llc_hdr_parsed *ghp = &parse_ctx->llc_hdr_parsed;
	int have_patched = 0;
	int fcs;
	struct gbproxy_config *cfg = peer->cfg;

	if (parse_ctx->ptmsi_enc && link_info &&
	    !parse_ctx->old_raid_is_foreign && peer->cfg->patch_ptmsi) {
		uint32_t ptmsi;
		if (parse_ctx->to_bss)
			ptmsi = link_info->tlli.ptmsi;
		else
			ptmsi = link_info->sgsn_tlli.ptmsi;

		if (ptmsi != GSM_RESERVED_TMSI) {
			if (gbproxy_patch_ptmsi(parse_ctx->ptmsi_enc, peer,
						ptmsi, parse_ctx->to_bss, "P-TMSI"))
				have_patched = 1;
		} else {
			/* TODO: invalidate old RAI if present (see below) */
		}
	}

	if (parse_ctx->new_ptmsi_enc && link_info && cfg->patch_ptmsi) {
		uint32_t ptmsi;
		if (parse_ctx->to_bss)
			ptmsi = link_info->tlli.ptmsi;
		else
			ptmsi = link_info->sgsn_tlli.ptmsi;

		OSMO_ASSERT(ptmsi);
		if (gbproxy_patch_ptmsi(parse_ctx->new_ptmsi_enc, peer,
					ptmsi, parse_ctx->to_bss, "new P-TMSI"))
			have_patched = 1;
	}

	if (parse_ctx->raid_enc) {
		gbproxy_patch_raid(parse_ctx->raid_enc, peer, parse_ctx->to_bss,
				   parse_ctx->llc_msg_name);
		have_patched = 1;
	}

	if (parse_ctx->old_raid_enc && !parse_ctx->old_raid_is_foreign) {
		/* TODO: Patch to invalid if P-TMSI unknown. */
		gbproxy_patch_raid(parse_ctx->old_raid_enc, peer, parse_ctx->to_bss,
				   parse_ctx->llc_msg_name);
		have_patched = 1;
	}

	if (parse_ctx->apn_ie &&
	    cfg->core_apn &&
	    !parse_ctx->to_bss &&
	    gbproxy_imsi_matches(cfg, GBPROX_MATCH_PATCHING, link_info) &&
	    cfg->core_apn) {
		size_t new_len;
		gbproxy_patch_apn_ie(msg,
				     parse_ctx->apn_ie, parse_ctx->apn_ie_len,
				     peer, &new_len, parse_ctx->llc_msg_name);
		*len_change += (int)new_len - (int)parse_ctx->apn_ie_len;

		have_patched = 1;
	}

	if (have_patched) {
		llc_len += *len_change;
		ghp->crc_length += *len_change;

		/* Fix FCS */
		fcs = gprs_llc_fcs(llc, ghp->crc_length);
		LOGP(DLLC, LOGL_DEBUG, "Updated LLC message, CRC: %06x -> %06x\n",
		     ghp->fcs, fcs);

		llc[llc_len - 3] = fcs & 0xff;
		llc[llc_len - 2] = (fcs >> 8) & 0xff;
		llc[llc_len - 1] = (fcs >> 16) & 0xff;
	}

	return have_patched;
}

/* patch BSSGP message to use core_mcc/mnc on the SGSN side */
void gbproxy_patch_bssgp(struct msgb *msg, uint8_t *bssgp, size_t bssgp_len,
			 struct gbproxy_peer *peer,
			 struct gbproxy_link_info *link_info, int *len_change,
			 struct gprs_gb_parse_context *parse_ctx)
{
	const char *err_info = NULL;
	int err_ctr = -1;

	if (parse_ctx->bssgp_raid_enc)
		gbproxy_patch_raid(parse_ctx->bssgp_raid_enc, peer,
				   parse_ctx->to_bss, "BSSGP");

	if (parse_ctx->need_decryption &&
	    (peer->cfg->patch_ptmsi || peer->cfg->core_apn)) {
		/* Patching LLC messages has been requested
		 * explicitly, but the message (including the
		 * type) is encrypted, so we possibly fail to
		 * patch the LLC part of the message. */
		err_ctr = GBPROX_PEER_CTR_PATCH_CRYPT_ERR;
		err_info = "GMM message is encrypted";
		goto patch_error;
	}

	if (!link_info && parse_ctx->tlli_enc && parse_ctx->to_bss) {
		/* Happens with unknown (not cached) TLLI coming from
		 * the SGSN */
		/* TODO: What shall be done with the message in this case? */
		err_ctr = GBPROX_PEER_CTR_TLLI_UNKNOWN;
		err_info = "TLLI sent by the SGSN is unknown";
		goto patch_error;
	}

	if (!link_info)
		return;

	if (parse_ctx->tlli_enc && peer->cfg->patch_ptmsi) {
		uint32_t tlli = gbproxy_map_tlli(parse_ctx->tlli,
						 link_info, parse_ctx->to_bss);

		if (tlli) {
			gbproxy_patch_tlli(parse_ctx->tlli_enc, peer, tlli,
					   parse_ctx->to_bss, "TLLI");
			parse_ctx->tlli = tlli;
		} else {
			/* Internal error */
			err_ctr = GBPROX_PEER_CTR_PATCH_ERR;
			err_info = "Replacement TLLI is 0";
			goto patch_error;
		}
	}

	if (parse_ctx->bssgp_ptmsi_enc && peer->cfg->patch_ptmsi) {
		uint32_t ptmsi;
		if (parse_ctx->to_bss)
			ptmsi = link_info->tlli.ptmsi;
		else
			ptmsi = link_info->sgsn_tlli.ptmsi;

		if (ptmsi != GSM_RESERVED_TMSI)
			gbproxy_patch_ptmsi(
				parse_ctx->bssgp_ptmsi_enc, peer,
				ptmsi, parse_ctx->to_bss, "BSSGP P-TMSI");
	}

	if (parse_ctx->llc) {
		uint8_t *llc = parse_ctx->llc;
		size_t llc_len = parse_ctx->llc_len;
		int llc_len_change = 0;

		gbproxy_patch_llc(msg, llc, llc_len, peer, link_info,
				  &llc_len_change, parse_ctx);
		/* Note that the APN might have been resized here, but no
		 * pointer int the parse_ctx will refer to an adress after the
		 * APN. So it's possible to patch first and do the TLLI
		 * handling afterwards. */

		if (llc_len_change) {
			llc_len += llc_len_change;

			/* Fix LLC IE len */
			/* TODO: This is a kludge, but the a pointer to the
			 * start of the IE is not available here */
			if (llc[-2] == BSSGP_IE_LLC_PDU && llc[-1] & 0x80) {
				/* most probably a one byte length */
				if (llc_len > 127) {
					err_info = "Cannot increase size";
					err_ctr = GBPROX_PEER_CTR_PATCH_ERR;
					goto patch_error;
				}
				llc[-1] = llc_len | 0x80;
			} else {
				llc[-2] = (llc_len >> 8) & 0x7f;
				llc[-1] = llc_len & 0xff;
			}
			*len_change += llc_len_change;
		}
		/* Note that the tp struct might contain invalid pointers here
		 * if the LLC field has changed its size */
		parse_ctx->llc_len = llc_len;
	}
	return;

patch_error:
	OSMO_ASSERT(err_ctr >= 0);
	rate_ctr_inc(&peer->ctrg->ctr[err_ctr]);
	LOGP(DGPRS, LOGL_ERROR,
	     "NSEI=%u(%s) failed to patch BSSGP message as requested: %s.\n",
	     msgb_nsei(msg), parse_ctx->to_bss ? "SGSN" : "BSS",
	     err_info);
}

void gbproxy_clear_patch_filter(struct gbproxy_match *match)
{
	if (match->enable) {
		regfree(&match->re_comp);
		match->enable = 0;
	}
	talloc_free(match->re_str);
	match->re_str = NULL;
}

int gbproxy_set_patch_filter(struct gbproxy_match *match, const char *filter,
		const char **err_msg)
{
	static char err_buf[300];
	int rc;

	gbproxy_clear_patch_filter(match);

	if (!filter)
		return 0;

	rc = regcomp(&match->re_comp, filter,
		     REG_EXTENDED | REG_NOSUB | REG_ICASE);

	if (rc == 0) {
		match->enable = 1;
		match->re_str = talloc_strdup(tall_bsc_ctx, filter);
		return 0;
	}

	if (err_msg) {
		regerror(rc, &match->re_comp,
			 err_buf, sizeof(err_buf));
		*err_msg = err_buf;
	}

	return -1;
}

int gbproxy_check_imsi(struct gbproxy_match *match,
		       const uint8_t *imsi, size_t imsi_len)
{
	char mi_buf[200];
	int rc;

	if (!match->enable)
		return 1;

	rc = gprs_is_mi_imsi(imsi, imsi_len);
	if (rc > 0)
		rc = gsm48_mi_to_string(mi_buf, sizeof(mi_buf), imsi, imsi_len);
	if (rc <= 0) {
		LOGP(DGPRS, LOGL_NOTICE, "Invalid IMSI %s\n",
		     osmo_hexdump(imsi, imsi_len));
		return -1;
	}

	LOGP(DGPRS, LOGL_DEBUG, "Checking IMSI '%s' (%d)\n", mi_buf, rc);

	rc = regexec(&match->re_comp, mi_buf, 0, NULL, 0);
	if (rc == REG_NOMATCH) {
		LOGP(DGPRS, LOGL_INFO,
		       "IMSI '%s' doesn't match pattern '%s'\n",
		       mi_buf, match->re_str);
		return 0;
	}

	return 1;
}

