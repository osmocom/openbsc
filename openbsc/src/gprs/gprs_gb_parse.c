/* GPRS Gb message parser */

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

#include <osmocom/gsm/gsm48.h>

#include <openbsc/gprs_gb_parse.h>

#include <openbsc/gprs_utils.h>

#include <openbsc/gsm_04_08_gprs.h>
#include <openbsc/debug.h>

#include <osmocom/gprs/gprs_bssgp.h>

/* TODO: Move shift functions to libosmocore */

int v_fixed_shift(uint8_t **data, size_t *data_len,
		  size_t len, uint8_t **value)
{
	if (len > *data_len)
		goto fail;

	if (value)
		*value = *data;

	*data += len;
	*data_len -= len;

	return len;

fail:
	*data += *data_len;
	*data_len = 0;
	return -1;
}

int tv_fixed_match(uint8_t **data, size_t *data_len,
		   uint8_t tag, size_t len,
		   uint8_t **value)
{
	size_t ie_len;

	if (*data_len == 0)
		goto fail;

	if ((*data)[0] != tag)
		return 0;

	if (len > *data_len - 1)
		goto fail;

	if (value)
		*value = *data + 1;

	ie_len = len + 1;
	*data += ie_len;
	*data_len -= ie_len;

	return ie_len;

fail:
	*data += *data_len;
	*data_len = 0;
	return -1;
}

int tlv_match(uint8_t **data, size_t *data_len,
	      uint8_t tag, uint8_t **value, size_t *value_len)
{
	size_t len;
	size_t ie_len;

	if (*data_len < 2)
		goto fail;

	if ((*data)[0] != tag)
		return 0;

	len = (*data)[1];
	if (len > *data_len - 2)
		goto fail;

	if (value)
		*value = *data + 2;
	if (value_len)
		*value_len = len;

	ie_len = len + 2;

	*data += ie_len;
	*data_len -= ie_len;

	return ie_len;

fail:
	*data += *data_len;
	*data_len = 0;
	return -1;
}

int lv_shift(uint8_t **data, size_t *data_len,
	     uint8_t **value, size_t *value_len)
{
	size_t len;
	size_t ie_len;

	if (*data_len < 1)
		goto fail;

	len = (*data)[0];
	if (len > *data_len - 1)
		goto fail;

	if (value)
		*value = *data + 1;
	if (value_len)
		*value_len = len;

	ie_len = len + 1;
	*data += ie_len;
	*data_len -= ie_len;

	return ie_len;

fail:
	*data += *data_len;
	*data_len = 0;
	return -1;
}

static int gprs_gb_parse_gmm_attach_req(uint8_t *data, size_t data_len,
					struct gprs_gb_parse_context *parse_ctx)
{
	uint8_t *value;
	size_t value_len;

	parse_ctx->llc_msg_name = "ATTACH_REQ";

	/* Skip MS network capability */
	if (lv_shift(&data, &data_len, NULL, &value_len) <= 0 ||
	    value_len < 1 || value_len > 2)
		/* invalid */
		return 0;;

	/* Skip Attach type */
	/* Skip Ciphering key sequence number */
	/* Skip DRX parameter */
	v_fixed_shift(&data, &data_len, 3, NULL);

	/* Get Mobile identity */
	if (lv_shift(&data, &data_len, &value, &value_len) <= 0 ||
	    value_len < 5 || value_len > 8)
		/* invalid */
		return 0;

	if (gprs_is_mi_tmsi(value, value_len)) {
		parse_ctx->ptmsi_enc = value;
	} else if (gprs_is_mi_imsi(value, value_len)) {
		parse_ctx->imsi = value;
		parse_ctx->imsi_len = value_len;
	}

	if (v_fixed_shift(&data, &data_len, 6, &value) <= 0)
		return 0;

	parse_ctx->old_raid_enc = value;

	return 1;
}

static int gprs_gb_parse_gmm_attach_ack(uint8_t *data, size_t data_len,
					struct gprs_gb_parse_context *parse_ctx)
{
	uint8_t *value;
	size_t value_len;

	parse_ctx->llc_msg_name = "ATTACH_ACK";

	/* Skip Attach result */
	/* Skip Force to standby */
	/* Skip Periodic RA update timer */
	/* Skip Radio priority for SMS */
	/* Skip Spare half octet */
	v_fixed_shift(&data, &data_len, 3, NULL);

	if (v_fixed_shift(&data, &data_len, 6, &value) <= 0)
		return 0;

	parse_ctx->raid_enc = value;

	/* Skip P-TMSI signature (P-TMSI signature, opt, TV, length 4) */
	tv_fixed_match(&data, &data_len, GSM48_IE_GMM_PTMSI_SIG, 3, NULL);

	/* Skip Negotiated READY timer value (GPRS timer, opt, TV, length 2) */
	tv_fixed_match(&data, &data_len, GSM48_IE_GMM_TIMER_READY, 1, NULL);

	/* Allocated P-TMSI (Mobile identity, opt, TLV, length 7) */
	if (tlv_match(&data, &data_len, GSM48_IE_GMM_ALLOC_PTMSI,
		      &value, &value_len) > 0 &&
	    gprs_is_mi_tmsi(value, value_len))
		parse_ctx->new_ptmsi_enc = value;
	return 1;
}

static int gprs_gb_parse_gmm_detach_req(uint8_t *data, size_t data_len,
					struct gprs_gb_parse_context *parse_ctx)
{
	uint8_t *value;
	size_t value_len;
	int power_off;

	parse_ctx->llc_msg_name = "DETACH_REQ";

	/* Skip spare half octet */
	/* Get Detach type */
	if (v_fixed_shift(&data, &data_len, 1, &value) <= 0)
		/* invalid */
		return 0;

	power_off = *value & 0x08 ? 1 : 0;

	if (!parse_ctx->to_bss) {
		/* Mobile originated */

		if (power_off)
			parse_ctx->invalidate_tlli = 1;

		/* Get P-TMSI (Mobile identity), see GSM 24.008, 9.4.5.2 */
		if (tlv_match(&data, &data_len,
			      GSM48_IE_GMM_ALLOC_PTMSI, &value, &value_len) > 0)
		{
			if (gprs_is_mi_tmsi(value, value_len))
				parse_ctx->ptmsi_enc = value;
		}
	}

	return 1;
}

static int gprs_gb_parse_gmm_ra_upd_req(uint8_t *data, size_t data_len,
					struct gprs_gb_parse_context *parse_ctx)
{
	uint8_t *value;

	parse_ctx->llc_msg_name = "RA_UPD_REQ";

	/* Skip Update type */
	/* Skip GPRS ciphering key sequence number */
	v_fixed_shift(&data, &data_len, 1, NULL);

	if (v_fixed_shift(&data, &data_len, 6, &value) <= 0)
		return 0;

	parse_ctx->old_raid_enc = value;

	return 1;
}

static int gprs_gb_parse_gmm_ra_upd_ack(uint8_t *data, size_t data_len,
					struct gprs_gb_parse_context *parse_ctx)
{
	uint8_t *value;
	size_t value_len;

	parse_ctx->llc_msg_name = "RA_UPD_ACK";

	/* Skip Force to standby */
	/* Skip Update result */
	/* Skip Periodic RA update timer */
	v_fixed_shift(&data, &data_len, 2, NULL);

	if (v_fixed_shift(&data, &data_len, 6, &value) <= 0)
		return 0;

	parse_ctx->raid_enc = value;

	/* Skip P-TMSI signature (P-TMSI signature, opt, TV, length 4) */
	tv_fixed_match(&data, &data_len, GSM48_IE_GMM_PTMSI_SIG, 3, NULL);

	/* Allocated P-TMSI (Mobile identity, opt, TLV, length 7) */
	if (tlv_match(&data, &data_len, GSM48_IE_GMM_ALLOC_PTMSI,
		      &value, &value_len) > 0 &&
	    gprs_is_mi_tmsi(value, value_len))
		parse_ctx->new_ptmsi_enc = value;

	return 1;
}

static int gprs_gb_parse_gmm_ptmsi_reall_cmd(uint8_t *data, size_t data_len,
					     struct gprs_gb_parse_context *parse_ctx)
{
	uint8_t *value;
	size_t value_len;

	parse_ctx->llc_msg_name = "PTMSI_REALL_CMD";

	LOGP(DLLC, LOGL_NOTICE,
	     "Got P-TMSI Reallocation Command which is not covered by unit tests yet.\n");

	/* Allocated P-TMSI */
	if (lv_shift(&data, &data_len, &value, &value_len) > 0 &&
	    gprs_is_mi_tmsi(value, value_len))
		parse_ctx->new_ptmsi_enc = value;

	if (v_fixed_shift(&data, &data_len, 6, &value) <= 0)
		return 0;

	parse_ctx->raid_enc = value;

	return 1;
}

static int gprs_gb_parse_gmm_id_resp(uint8_t *data, size_t data_len,
				     struct gprs_gb_parse_context *parse_ctx)
{
	uint8_t *value;
	size_t value_len;

	parse_ctx->llc_msg_name = "ID_RESP";

	/* Mobile identity, Mobile identity 10.5.1.4, M LV 2-10 */
	if (lv_shift(&data, &data_len, &value, &value_len) <= 0 ||
	    value_len < 1 || value_len > 9)
		/* invalid */
		return 0;

	if (gprs_is_mi_tmsi(value, value_len)) {
		parse_ctx->ptmsi_enc = value;
	} else if (gprs_is_mi_imsi(value, value_len)) {
		parse_ctx->imsi = value;
		parse_ctx->imsi_len = value_len;
	}

	return 1;
}

static int gprs_gb_parse_gsm_act_pdp_req(uint8_t *data, size_t data_len,
					 struct gprs_gb_parse_context *parse_ctx)
{
	ssize_t old_len;
	uint8_t *value;
	size_t value_len;

	parse_ctx->llc_msg_name = "ACT_PDP_REQ";

	/* Skip Requested NSAPI */
	/* Skip Requested LLC SAPI */
	v_fixed_shift(&data, &data_len, 2, NULL);

	/* Skip Requested QoS (support 04.08 and 24.008) */
	if (lv_shift(&data, &data_len, NULL, &value_len) <= 0 ||
	    value_len < 4 || value_len > 14)
		/* invalid */
		return 0;;

	/* Skip Requested PDP address */
	if (lv_shift(&data, &data_len, NULL, &value_len) <= 0 ||
	    value_len < 2 || value_len > 18)
		/* invalid */
		return 0;

	/* Access point name */
	old_len = tlv_match(&data, &data_len,
			    GSM48_IE_GSM_APN, &value, &value_len);

	if (old_len > 0 && value_len >=1 && value_len <= 100) {
		parse_ctx->apn_ie = data - old_len;
		parse_ctx->apn_ie_len = old_len;
	}

	return 1;
}

int gprs_gb_parse_dtap(uint8_t *data, size_t data_len,
		       struct gprs_gb_parse_context *parse_ctx)
{
	struct gsm48_hdr *g48h;

	if (v_fixed_shift(&data, &data_len, sizeof(*g48h), (uint8_t **)&g48h) <= 0)
		return 0;

	parse_ctx->g48_hdr = g48h;

	if ((g48h->proto_discr & 0x0f) != GSM48_PDISC_MM_GPRS &&
	    (g48h->proto_discr & 0x0f) != GSM48_PDISC_SM_GPRS)
		return 1;

	switch (g48h->msg_type) {
	case GSM48_MT_GMM_ATTACH_REQ:
		return gprs_gb_parse_gmm_attach_req(data, data_len, parse_ctx);

	case GSM48_MT_GMM_ATTACH_ACK:
		return gprs_gb_parse_gmm_attach_ack(data, data_len, parse_ctx);

	case GSM48_MT_GMM_RA_UPD_REQ:
		return gprs_gb_parse_gmm_ra_upd_req(data, data_len, parse_ctx);

	case GSM48_MT_GMM_RA_UPD_ACK:
		return gprs_gb_parse_gmm_ra_upd_ack(data, data_len, parse_ctx);

	case GSM48_MT_GMM_PTMSI_REALL_CMD:
		return gprs_gb_parse_gmm_ptmsi_reall_cmd(data, data_len, parse_ctx);

	case GSM48_MT_GSM_ACT_PDP_REQ:
		return gprs_gb_parse_gsm_act_pdp_req(data, data_len, parse_ctx);

	case GSM48_MT_GMM_ID_RESP:
		return gprs_gb_parse_gmm_id_resp(data, data_len, parse_ctx);

	case GSM48_MT_GMM_DETACH_REQ:
		return gprs_gb_parse_gmm_detach_req(data, data_len, parse_ctx);

	case GSM48_MT_GMM_DETACH_ACK:
		parse_ctx->llc_msg_name = "DETACH_ACK";
		parse_ctx->invalidate_tlli = 1;
		break;

	default:
		break;
	};

	return 1;
}

int gprs_gb_parse_llc(uint8_t *llc, size_t llc_len,
		      struct gprs_gb_parse_context *parse_ctx)
{
	struct gprs_llc_hdr_parsed *ghp = &parse_ctx->llc_hdr_parsed;
	int rc;
	int fcs;

	/* parse LLC */
	rc = gprs_llc_hdr_parse(ghp, llc, llc_len);
	gprs_llc_hdr_dump(ghp);
	if (rc != 0) {
		LOGP(DLLC, LOGL_NOTICE, "Error during LLC header parsing\n");
		return 0;
	}

	fcs = gprs_llc_fcs(llc, ghp->crc_length);
	LOGP(DLLC, LOGL_DEBUG, "Got LLC message, CRC: %06x (computed %06x)\n",
	     ghp->fcs, fcs);

	if (!ghp->data)
		return 0;

	if (ghp->sapi != GPRS_SAPI_GMM)
		return 1;

	if (ghp->cmd != GPRS_LLC_UI)
		return 1;

	if (ghp->is_encrypted) {
		parse_ctx->need_decryption = 1;
		return 0;
	}

	return gprs_gb_parse_dtap(ghp->data, ghp->data_len, parse_ctx);
}

int gprs_gb_parse_bssgp(uint8_t *bssgp, size_t bssgp_len,
			struct gprs_gb_parse_context *parse_ctx)
{
	struct bssgp_normal_hdr *bgph;
	struct bssgp_ud_hdr *budh = NULL;
	struct tlv_parsed *tp = &parse_ctx->bssgp_tp;
	uint8_t pdu_type;
	uint8_t *data;
	size_t data_len;
	int rc;

	if (bssgp_len < sizeof(struct bssgp_normal_hdr))
		return 0;

	bgph = (struct bssgp_normal_hdr *)bssgp;
	pdu_type = bgph->pdu_type;

	if (pdu_type == BSSGP_PDUT_UL_UNITDATA ||
	    pdu_type == BSSGP_PDUT_DL_UNITDATA) {
		if (bssgp_len < sizeof(struct bssgp_ud_hdr))
			return 0;
		budh = (struct bssgp_ud_hdr *)bssgp;
		bgph = NULL;
		data = budh->data;
		data_len = bssgp_len - sizeof(*budh);
	} else {
		data = bgph->data;
		data_len = bssgp_len - sizeof(*bgph);
	}

	if (bssgp_tlv_parse(tp, data, data_len) < 0)
		return 0;

	parse_ctx->pdu_type = pdu_type;
	parse_ctx->bud_hdr = budh;
	parse_ctx->bgp_hdr = bgph;
	parse_ctx->bssgp_data = data;
	parse_ctx->bssgp_data_len = data_len;

	if (budh)
		parse_ctx->tlli_enc = (uint8_t *)&budh->tlli;

	if (TLVP_PRESENT(tp, BSSGP_IE_ROUTEING_AREA))
		parse_ctx->bssgp_raid_enc = (uint8_t *)TLVP_VAL(tp, BSSGP_IE_ROUTEING_AREA);

	if (TLVP_PRESENT(tp, BSSGP_IE_CELL_ID))
		parse_ctx->bssgp_raid_enc = (uint8_t *)TLVP_VAL(tp, BSSGP_IE_CELL_ID);

	if (TLVP_PRESENT(tp, BSSGP_IE_IMSI)) {
		parse_ctx->imsi = (uint8_t *)TLVP_VAL(tp, BSSGP_IE_IMSI);
		parse_ctx->imsi_len = TLVP_LEN(tp, BSSGP_IE_IMSI);
	}

	if (TLVP_PRESENT(tp, BSSGP_IE_TLLI)) {
		if (parse_ctx->tlli_enc)
			/* This is TLLI old, don't confuse it with TLLI current */
			parse_ctx->old_tlli_enc = (uint8_t *)TLVP_VAL(tp, BSSGP_IE_TLLI);
		else
			parse_ctx->tlli_enc = (uint8_t *)TLVP_VAL(tp, BSSGP_IE_TLLI);
	}

	if (TLVP_PRESENT(tp, BSSGP_IE_TMSI) && pdu_type == BSSGP_PDUT_PAGING_PS)
		parse_ctx->ptmsi_enc = (uint8_t *)TLVP_VAL(tp, BSSGP_IE_TMSI);

	if (TLVP_PRESENT(tp, BSSGP_IE_LLC_PDU)) {
		uint8_t *llc = (uint8_t *)TLVP_VAL(tp, BSSGP_IE_LLC_PDU);
		size_t llc_len = TLVP_LEN(tp, BSSGP_IE_LLC_PDU);

		rc = gprs_gb_parse_llc(llc, llc_len, parse_ctx);
		if (!rc)
			return 0;

		parse_ctx->llc = llc;
		parse_ctx->llc_len = llc_len;
	}

	if (parse_ctx->tlli_enc) {
		uint32_t tmp_tlli;
		memcpy(&tmp_tlli, parse_ctx->tlli_enc, sizeof(tmp_tlli));
		parse_ctx->tlli = ntohl(tmp_tlli);
	}

	return 1;
}

void gprs_gb_log_parse_context(struct gprs_gb_parse_context *parse_ctx,
			       const char *default_msg_name)
{
	const char *msg_name = default_msg_name;
	const char *sep = "";

	if (!parse_ctx->tlli_enc &&
	    !parse_ctx->ptmsi_enc &&
	    !parse_ctx->new_ptmsi_enc &&
	    !parse_ctx->imsi)
		return;

	if (parse_ctx->llc_msg_name)
		msg_name = parse_ctx->llc_msg_name;

	LOGP(DGPRS, LOGL_DEBUG, "%s: Got", msg_name);

	if (parse_ctx->tlli_enc) {
		LOGP(DGPRS, LOGL_DEBUG, "%s TLLI %08x", sep, parse_ctx->tlli);
		sep = ",";
	}

	if (parse_ctx->old_tlli_enc) {
		LOGP(DGPRS, LOGL_DEBUG, "%s old TLLI %02x%02x%02x%02x", sep,
		     parse_ctx->old_tlli_enc[0],
		     parse_ctx->old_tlli_enc[1],
		     parse_ctx->old_tlli_enc[2],
		     parse_ctx->old_tlli_enc[3]);
		sep = ",";
	}

	if (parse_ctx->bssgp_raid_enc) {
		struct gprs_ra_id raid;
		gsm48_parse_ra(&raid, parse_ctx->bssgp_raid_enc);
		LOGP(DGPRS, LOGL_DEBUG, "%s BSSGP RAID %u-%u-%u-%u", sep,
		     raid.mcc, raid.mnc, raid.lac, raid.rac);
		sep = ",";
	}

	if (parse_ctx->raid_enc) {
		struct gprs_ra_id raid;
		gsm48_parse_ra(&raid, parse_ctx->raid_enc);
		LOGP(DGPRS, LOGL_DEBUG, "%s RAID %u-%u-%u-%u", sep,
		     raid.mcc, raid.mnc, raid.lac, raid.rac);
		sep = ",";
	}

	if (parse_ctx->old_raid_enc) {
		struct gprs_ra_id raid;
		gsm48_parse_ra(&raid, parse_ctx->old_raid_enc);
		LOGP(DGPRS, LOGL_DEBUG, "%s old RAID %u-%u-%u-%u", sep,
		     raid.mcc, raid.mnc, raid.lac, raid.rac);
		sep = ",";
	}

	if (parse_ctx->ptmsi_enc) {
		uint32_t ptmsi = GSM_RESERVED_TMSI;
		int ok;
		ok = gprs_parse_mi_tmsi(parse_ctx->ptmsi_enc, GSM48_TMSI_LEN, &ptmsi);
		LOGP(DGPRS, LOGL_DEBUG, "%s PTMSI %08x%s",
		     sep, ptmsi, ok ? "" : " (parse error)");
		sep = ",";
	}

	if (parse_ctx->new_ptmsi_enc) {
		uint32_t new_ptmsi = GSM_RESERVED_TMSI;
		int ok;
		ok = gprs_parse_mi_tmsi(parse_ctx->new_ptmsi_enc, GSM48_TMSI_LEN,
					&new_ptmsi);
		LOGP(DGPRS, LOGL_DEBUG, "%s new PTMSI %08x%s",
		     sep, new_ptmsi, ok ? "" : " (parse error)");
		sep = ",";
	}

	if (parse_ctx->imsi) {
		char mi_buf[200];
		mi_buf[0] = '\0';
		gsm48_mi_to_string(mi_buf, sizeof(mi_buf),
				   parse_ctx->imsi, parse_ctx->imsi_len);
		LOGP(DGPRS, LOGL_DEBUG, "%s IMSI %s",
		     sep, mi_buf);
		sep = ",";
	}
	if (parse_ctx->invalidate_tlli) {
		LOGP(DGPRS, LOGL_DEBUG, "%s invalidate", sep);
		sep = ",";
	}

	LOGP(DGPRS, LOGL_DEBUG, "\n");
}

