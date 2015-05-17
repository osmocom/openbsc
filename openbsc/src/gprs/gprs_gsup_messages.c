/* GPRS Subscriber Update Protocol message encoder/decoder */

/*
 * (C) 2014 by Sysmocom s.f.m.c. GmbH
 * (C) 2015 by Holger Hans Peter Freyther
 * All Rights Reserved
 *
 * Author: Jacob Erlbeck
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

#include <openbsc/gprs_gsup_messages.h>

#include <openbsc/debug.h>
#include <openbsc/gprs_utils.h>

#include <osmocom/gsm/tlv.h>
#include <osmocom/core/msgb.h>

#include <stdint.h>


static uint64_t decode_big_endian(const uint8_t *data, size_t data_len)
{
	uint64_t value = 0;

	while (data_len > 0) {
		value = (value << 8) + *data;
		data += 1;
		data_len -= 1;
	}

	return value;
}

static uint8_t *encode_big_endian(uint64_t value, size_t data_len)
{
	static uint8_t buf[sizeof(uint64_t)];
	int idx;

	OSMO_ASSERT(data_len <= ARRAY_SIZE(buf));

	for (idx = data_len - 1; idx >= 0; idx--) {
		buf[idx] = (uint8_t)value;
		value = value >> 8;
	}

	return buf;
}

static int decode_pdp_info(uint8_t *data, size_t data_len,
			  struct gprs_gsup_pdp_info *pdp_info)
{
	int rc;
	uint8_t tag;
	uint8_t *value;
	size_t value_len;

	/* specific parts */
	while (data_len > 0) {
		enum gprs_gsup_iei iei;

		rc = gprs_shift_tlv(&data, &data_len, &tag, &value, &value_len);
		if (rc < 0)
			return -GMM_CAUSE_PROTO_ERR_UNSPEC;

		iei = tag;

		switch (iei) {
		case GPRS_GSUP_PDP_CONTEXT_ID_IE:
			pdp_info->context_id = decode_big_endian(value, value_len);
			break;

		case GPRS_GSUP_PDP_TYPE_IE:
			pdp_info->pdp_type =
				decode_big_endian(value, value_len) & 0x0fff;
			break;

		case GPRS_GSUP_ACCESS_POINT_NAME_IE:
			pdp_info->apn_enc = value;
			pdp_info->apn_enc_len = value_len;
			break;

		case GPRS_GSUP_PDP_QOS_IE:
			pdp_info->qos_enc = value;
			pdp_info->qos_enc_len = value_len;
			break;

		default:
			LOGP(DGPRS, LOGL_ERROR,
			     "GSUP IE type %d not expected in PDP info\n", iei);
			continue;
		}
	}

	return 0;
}

static int decode_auth_info(uint8_t *data, size_t data_len,
			   struct gsm_auth_tuple *auth_tuple)
{
	int rc;
	uint8_t tag;
	uint8_t *value;
	size_t value_len;
	enum gprs_gsup_iei iei;

	/* specific parts */
	while (data_len > 0) {
		rc = gprs_shift_tlv(&data, &data_len, &tag, &value, &value_len);
		if (rc < 0)
			return -GMM_CAUSE_PROTO_ERR_UNSPEC;

		iei = tag;

		switch (iei) {
		case GPRS_GSUP_RAND_IE:
			if (value_len != sizeof(auth_tuple->rand))
				goto parse_error;

			memcpy(auth_tuple->rand, value, value_len);
			break;

		case GPRS_GSUP_SRES_IE:
			if (value_len != sizeof(auth_tuple->sres))
				goto parse_error;

			memcpy(auth_tuple->sres, value, value_len);
			break;

		case GPRS_GSUP_KC_IE:
			if (value_len != sizeof(auth_tuple->kc))
				goto parse_error;

			memcpy(auth_tuple->kc, value, value_len);
			break;

		default:
			LOGP(DGPRS, LOGL_ERROR,
			     "GSUP IE type %d not expected in PDP info\n", iei);
			continue;
		}
	}

	return 0;

parse_error:
	LOGP(DGPRS, LOGL_ERROR,
	     "GSUP IE type %d, length %zu invalid in PDP info\n", iei, value_len);

	return -1;
}

int gprs_gsup_decode(const uint8_t *const_data, size_t data_len,
		     struct gprs_gsup_message *gsup_msg)
{
	int rc;
	uint8_t tag;
	/* the shift/match functions expect non-const pointers, but we'll
	 * either copy the data or cast pointers back to const before returning
	 * them
	 */
	uint8_t *data = (uint8_t *)const_data;
	uint8_t *value;
	size_t value_len;
	static const struct gprs_gsup_pdp_info empty_pdp_info = {0};
	static const struct gsm_auth_tuple empty_auth_info = {0};
	static const struct gprs_gsup_message empty_gsup_message = {0};

	*gsup_msg = empty_gsup_message;

	/* generic part */
	rc = gprs_shift_v_fixed(&data, &data_len, 1, &value);
	if (rc < 0)
		return -GMM_CAUSE_INV_MAND_INFO;

	gsup_msg->message_type = decode_big_endian(value, 1);

	rc = gprs_match_tlv(&data, &data_len, GPRS_GSUP_IMSI_IE,
			    &value, &value_len);

	if (rc <= 0)
		return -GMM_CAUSE_INV_MAND_INFO;

	if (value_len * 2 + 1 > sizeof(gsup_msg->imsi))
		return -GMM_CAUSE_INV_MAND_INFO;

	/* Note that gsm48_decode_bcd_number expects the number of encoded IMSI
	 * octets in the first octet. By coincidence (the TLV encoding) the byte
	 * before the value part already contains this length so we can use it
	 * here.
	 */
	OSMO_ASSERT(value[-1] == value_len);
	gsm48_decode_bcd_number(gsup_msg->imsi, sizeof(gsup_msg->imsi),
				value - 1, 0);

	/* specific parts */
	while (data_len > 0) {
		enum gprs_gsup_iei iei;
		struct gprs_gsup_pdp_info pdp_info;
		struct gsm_auth_tuple auth_info;

		rc = gprs_shift_tlv(&data, &data_len, &tag, &value, &value_len);
		if (rc < 0)
			return -GMM_CAUSE_PROTO_ERR_UNSPEC;

		iei = tag;

		switch (iei) {
		case GPRS_GSUP_IMSI_IE:
		case GPRS_GSUP_PDP_TYPE_IE:
		case GPRS_GSUP_ACCESS_POINT_NAME_IE:
		case GPRS_GSUP_RAND_IE:
		case GPRS_GSUP_SRES_IE:
		case GPRS_GSUP_KC_IE:
			LOGP(DGPRS, LOGL_NOTICE,
			     "GSUP IE type %d not expected (ignored)\n", iei);
			continue;

		case GPRS_GSUP_CAUSE_IE:
			gsup_msg->cause = decode_big_endian(value, value_len);
			break;

		case GPRS_GSUP_CANCEL_TYPE_IE:
			gsup_msg->cancel_type =
				decode_big_endian(value, value_len) + 1;
			break;

		case GPRS_GSUP_PDP_INFO_COMPL_IE:
			gsup_msg->pdp_info_compl = 1;
			break;

		case GPRS_GSUP_FREEZE_PTMSI_IE:
			gsup_msg->freeze_ptmsi = 1;
			break;

		case GPRS_GSUP_PDP_CONTEXT_ID_IE:
			/* When these IE appear in the top-level part of the
			 * message, they are used by Delete Subscr Info to delete
			 * single entries. We don't have an extra list for
			 * these but use the PDP info list instead */

			/* fall through */

		case GPRS_GSUP_PDP_INFO_IE:
			if (gsup_msg->num_pdp_infos >= GPRS_GSUP_MAX_NUM_PDP_INFO) {
				LOGP(DGPRS, LOGL_ERROR,
				     "GSUP IE type %d (PDP_INFO) max exceeded\n",
				     iei);
				return -GMM_CAUSE_COND_IE_ERR;
			}

			pdp_info = empty_pdp_info;

			if (iei == GPRS_GSUP_PDP_INFO_IE) {
				rc = decode_pdp_info(value, value_len, &pdp_info);
				if (rc < 0)
					return rc;
				pdp_info.have_info = 1;
			} else {
				pdp_info.context_id =
					decode_big_endian(value, value_len);
			}

			gsup_msg->pdp_infos[gsup_msg->num_pdp_infos++] =
				pdp_info;
			break;

		case GPRS_GSUP_AUTH_TUPLE_IE:
			if (gsup_msg->num_auth_tuples >= GPRS_GSUP_MAX_NUM_AUTH_INFO) {
				LOGP(DGPRS, LOGL_ERROR,
				     "GSUP IE type %d (AUTH_INFO) max exceeded\n",
				     iei);
				return -GMM_CAUSE_INV_MAND_INFO;
			}

			auth_info = empty_auth_info;
			auth_info.key_seq = gsup_msg->num_auth_tuples;

			rc = decode_auth_info(value, value_len, &auth_info);
			if (rc < 0)
				return rc;

			gsup_msg->auth_tuples[gsup_msg->num_auth_tuples++] =
				auth_info;
			break;

		case GPRS_GSUP_MSISDN_IE:
			gsup_msg->msisdn_enc = value;
			gsup_msg->msisdn_enc_len = value_len;
			break;

		case GPRS_GSUP_HLR_NUMBER_IE:
			gsup_msg->hlr_enc = value;
			gsup_msg->hlr_enc_len = value_len;
			break;

		default:
			LOGP(DGPRS, LOGL_NOTICE,
			     "GSUP IE type %d unknown\n", iei);
			continue;
		}
	}

	return 0;
}

static void encode_pdp_info(struct msgb *msg, enum gprs_gsup_iei iei,
			    const struct gprs_gsup_pdp_info *pdp_info)
{
	uint8_t *len_field;
	size_t old_len;
	uint8_t u8;

	len_field = msgb_tlv_put(msg, iei, 0, NULL) - 1;
	old_len = msgb_length(msg);

	u8 = pdp_info->context_id;
	msgb_tlv_put(msg, GPRS_GSUP_PDP_CONTEXT_ID_IE, sizeof(u8), &u8);

	if (pdp_info->pdp_type) {
		msgb_tlv_put(msg, GPRS_GSUP_PDP_TYPE_IE,
			     GPRS_GSUP_PDP_TYPE_SIZE,
			     encode_big_endian(pdp_info->pdp_type | 0xf000,
					       GPRS_GSUP_PDP_TYPE_SIZE));
	}

	if (pdp_info->apn_enc) {
		msgb_tlv_put(msg, GPRS_GSUP_ACCESS_POINT_NAME_IE,
			     pdp_info->apn_enc_len, pdp_info->apn_enc);
	}

	if (pdp_info->qos_enc) {
		msgb_tlv_put(msg, GPRS_GSUP_PDP_QOS_IE,
				pdp_info->qos_enc_len, pdp_info->qos_enc);
	}

	/* Update length field */
	*len_field = msgb_length(msg) - old_len;
}

static void encode_auth_info(struct msgb *msg, enum gprs_gsup_iei iei,
			     const struct gsm_auth_tuple *auth_tuple)
{
	uint8_t *len_field;
	size_t old_len;

	len_field = msgb_tlv_put(msg, iei, 0, NULL) - 1;
	old_len = msgb_length(msg);

	msgb_tlv_put(msg, GPRS_GSUP_RAND_IE,
		     sizeof(auth_tuple->rand), auth_tuple->rand);

	msgb_tlv_put(msg, GPRS_GSUP_SRES_IE,
		     sizeof(auth_tuple->sres), auth_tuple->sres);

	msgb_tlv_put(msg, GPRS_GSUP_KC_IE,
		     sizeof(auth_tuple->kc), auth_tuple->kc);

	/* Update length field */
	*len_field = msgb_length(msg) - old_len;
}

void gprs_gsup_encode(struct msgb *msg, const struct gprs_gsup_message *gsup_msg)
{
	uint8_t u8;
	int idx;
	uint8_t bcd_buf[GSM48_MI_SIZE] = {0};
	size_t bcd_len;

	/* generic part */
	OSMO_ASSERT(gsup_msg->message_type);
	msgb_v_put(msg, gsup_msg->message_type);

	bcd_len = gsm48_encode_bcd_number(bcd_buf, sizeof(bcd_buf), 0,
					  gsup_msg->imsi);

	OSMO_ASSERT(bcd_len > 1);

	/* Note that gsm48_encode_bcd_number puts the length into the first
	 * octet. Since msgb_tlv_put will add this length byte, we'll have to
	 * skip it */
	msgb_tlv_put(msg, GPRS_GSUP_IMSI_IE, bcd_len - 1, &bcd_buf[1]);

	/* specific parts */
	if (gsup_msg->msisdn_enc)
		msgb_tlv_put(msg, GPRS_GSUP_MSISDN_IE,
				gsup_msg->msisdn_enc_len, gsup_msg->msisdn_enc);
	if (gsup_msg->hlr_enc)
		msgb_tlv_put(msg, GPRS_GSUP_HLR_NUMBER_IE,
				gsup_msg->hlr_enc_len, gsup_msg->hlr_enc);

	if ((u8 = gsup_msg->cause))
		msgb_tlv_put(msg, GPRS_GSUP_CAUSE_IE, sizeof(u8), &u8);

	if ((u8 = gsup_msg->cancel_type)) {
		u8 -= 1;
		msgb_tlv_put(msg, GPRS_GSUP_CANCEL_TYPE_IE, sizeof(u8), &u8);
	}

	if (gsup_msg->pdp_info_compl)
		msgb_tlv_put(msg, GPRS_GSUP_PDP_INFO_COMPL_IE, 0, &u8);

	if (gsup_msg->freeze_ptmsi)
		msgb_tlv_put(msg, GPRS_GSUP_FREEZE_PTMSI_IE, 0, &u8);

	for (idx = 0; idx < gsup_msg->num_pdp_infos; idx++) {
		const struct gprs_gsup_pdp_info *pdp_info;

		pdp_info = &gsup_msg->pdp_infos[idx];

		if (pdp_info->context_id == 0)
			continue;

		if (pdp_info->have_info) {
			encode_pdp_info(msg, GPRS_GSUP_PDP_INFO_IE, pdp_info);
		} else {
			u8 = pdp_info->context_id;
			msgb_tlv_put(msg, GPRS_GSUP_PDP_CONTEXT_ID_IE,
				     sizeof(u8), &u8);
		}
	}

	for (idx = 0; idx < gsup_msg->num_auth_tuples; idx++) {
		const struct gsm_auth_tuple *auth_info;

		auth_info = &gsup_msg->auth_tuples[idx];

		if (auth_info->key_seq == GSM_KEY_SEQ_INVAL)
			continue;

		encode_auth_info(msg, GPRS_GSUP_AUTH_TUPLE_IE, auth_info);
	}
}
