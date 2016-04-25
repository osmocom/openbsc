/* Osmocom Authentication Protocol message encoder/decoder */

/* (C) 2015 by Sysmocom s.f.m.c. GmbH
 * All Rights Reserved
 *
 * Author: Neels Hofmeyr
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

#include <osmocom/core/utils.h>
#include <openbsc/oap_messages.h>

#include <openbsc/debug.h>
#include <openbsc/gprs_utils.h>

#include <osmocom/gsm/tlv.h>
#include <osmocom/core/msgb.h>

#include <stdint.h>


int oap_decode(const uint8_t *const_data, size_t data_len,
	       struct oap_message *oap_msg)
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

	memset(oap_msg, 0, sizeof(*oap_msg));

	/* message type */
	rc = osmo_shift_v_fixed(&data, &data_len, 1, &value);
	if (rc < 0)
		return -GMM_CAUSE_INV_MAND_INFO;
	oap_msg->message_type = osmo_decode_big_endian(value, 1);

	/* specific parts */
	while (data_len > 0) {
		enum oap_iei iei;

		rc = osmo_shift_tlv(&data, &data_len, &tag, &value, &value_len);
		if (rc < 0)
			return -GMM_CAUSE_PROTO_ERR_UNSPEC;

		iei = tag;

		switch (iei) {
		case OAP_CLIENT_ID_IE:
			if (value_len != 2) {
				LOGP(DGPRS, LOGL_NOTICE,
				     "OAP IE type client ID (%d) should be 2 octets, but has %d\n",
				     (int)iei, (int)value_len);
				return -GMM_CAUSE_PROTO_ERR_UNSPEC;
			}

			oap_msg->client_id = osmo_decode_big_endian(value, value_len);

			if (oap_msg->client_id == 0) {
				LOGP(DGPRS, LOGL_NOTICE,
				     "OAP IE type client ID (%d): client ID must be nonzero.\n",
				     (int)iei);
				return -GMM_CAUSE_PROTO_ERR_UNSPEC;
			}
			break;

		case OAP_AUTN_IE:
			if (value_len != sizeof(oap_msg->autn)) {
				LOGP(DGPRS, LOGL_NOTICE,
				     "OAP IE type AUTN (%d) should be %d octets, but has %d\n",
				     (int)iei, (int)sizeof(oap_msg->autn), (int)value_len);
				return -GMM_CAUSE_PROTO_ERR_UNSPEC;
			}
			memcpy(oap_msg->autn, value, value_len);
			oap_msg->autn_present = value_len;
			break;

		case OAP_RAND_IE:
			if (value_len != sizeof(oap_msg->rand)) {
				LOGP(DGPRS, LOGL_NOTICE,
				     "OAP IE type RAND (%d) should be %d octets, but has %d\n",
				     (int)iei, (int)sizeof(oap_msg->rand), (int)value_len);
				return -GMM_CAUSE_PROTO_ERR_UNSPEC;
			}
			memcpy(oap_msg->rand, value, value_len);
			oap_msg->rand_present = value_len;
			break;

		case OAP_XRES_IE:
			if (value_len != sizeof(oap_msg->xres)) {
				LOGP(DGPRS, LOGL_NOTICE,
				     "OAP IE type XRES (%d) should be %d octets, but has %d\n",
				     (int)iei, (int)sizeof(oap_msg->xres), (int)value_len);
				return -GMM_CAUSE_PROTO_ERR_UNSPEC;
			}
			memcpy(oap_msg->xres, value, value_len);
			oap_msg->xres_present = value_len;
			break;

		case OAP_AUTS_IE:
			if (value_len != sizeof(oap_msg->auts)) {
				LOGP(DGPRS, LOGL_NOTICE,
				     "OAP IE type AUTS (%d) should be %d octets, but has %d\n",
				     (int)iei, (int)sizeof(oap_msg->auts), (int)value_len);
				return -GMM_CAUSE_PROTO_ERR_UNSPEC;
			}
			memcpy(oap_msg->auts, value, value_len);
			oap_msg->auts_present = value_len;
			break;

		case OAP_CAUSE_IE:
			if (value_len > 1) {
				LOGP(DGPRS, LOGL_ERROR,
				     "OAP cause may not exceed one octet, is %d", (int)value_len);
				return -GMM_CAUSE_PROTO_ERR_UNSPEC;
			}
			oap_msg->cause = *value;
			break;

		default:
			LOGP(DGPRS, LOGL_NOTICE,
			     "OAP IE type %d unknown\n", iei);
			continue;
		}
	}

	return 0;
}

void oap_encode(struct msgb *msg, const struct oap_message *oap_msg)
{
	uint8_t u8;

	/* generic part */
	OSMO_ASSERT(oap_msg->message_type);
	msgb_v_put(msg, (uint8_t)oap_msg->message_type);

	/* specific parts */
	if ((u8 = oap_msg->cause))
		msgb_tlv_put(msg, OAP_CAUSE_IE, sizeof(u8), &u8);

	if (oap_msg->client_id > 0)
		msgb_tlv_put(msg, OAP_CLIENT_ID_IE, sizeof(oap_msg->client_id),
			     osmo_encode_big_endian(oap_msg->client_id,
						    sizeof(oap_msg->client_id)));

	if (oap_msg->rand_present)
		msgb_tlv_put(msg, OAP_RAND_IE, sizeof(oap_msg->rand), oap_msg->rand);

	if (oap_msg->autn_present)
		msgb_tlv_put(msg, OAP_AUTN_IE, sizeof(oap_msg->autn), oap_msg->autn);

	if (oap_msg->auts_present)
		msgb_tlv_put(msg, OAP_AUTS_IE, sizeof(oap_msg->auts), oap_msg->auts);

	if (oap_msg->xres_present)
		msgb_tlv_put(msg, OAP_XRES_IE, sizeof(oap_msg->xres), oap_msg->xres);

	msg->l2h = msg->data;
}

