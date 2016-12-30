/* GSM USSD external MAP protocol on pseudo TCAP */

/* (C) 2015 by Sergey Kostanbaev <sergey.kostanbaev@gmail.com>
 *
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

#include <openbsc/gsm_ussd_map.h>
#include <openbsc/gsm_ussd_map_proto.h>
#include <openbsc/gsm_subscriber.h>
#include <openbsc/gsm_04_08.h>
#include <openbsc/debug.h>
#include <openbsc/db.h>
#include <openbsc/chan_alloc.h>
#include <osmocom/gsm/protocol/gsm_04_08_gprs.h>
#include <osmocom/gsm/gsup.h>
#include <openbsc/osmo_msc.h>
#include <openbsc/gprs_utils.h>
#include <openbsc/ussd.h>

/*
* 0 - OSMO_GSUP_MSGT_USSD_MAP constant
* 1 - LEN
* 2 - message_type [ REGISTER / FACILITY / RELEASE COMPLETE ]
* 3,4,5,6 - tid          ID associated with the session
* 7 - FMAP_MSISDN constant
* 8 - extention_len
* 9..x -  extention
* x+1 .. original MAP message
*/

int subscr_uss_message(struct msgb *msg,
		       struct ss_header *req,
		       const char* extension,
		       uint32_t ref,
		       const uint8_t* component_data)
{
	uint8_t bcd_lvlen;
	uint8_t offset = 0;
	uint8_t *gsup_indicator;

	gsup_indicator = msgb_put(msg, 7);

	/* First byte should always be OSMO_GSUP_MSGT_USSD_MAP */
	gsup_indicator[offset++] = OSMO_GSUP_MSGT_USSD_MAP;
	gsup_indicator[offset++] = 0; // Total length
	gsup_indicator[offset++] = req->message_type;

	gsup_indicator[offset++] = ref >> 24;
	gsup_indicator[offset++] = ref >> 16;
	gsup_indicator[offset++] = ref >> 8;
	gsup_indicator[offset++] = ref;

	if (extension) {
		gsup_indicator[offset++] = FMAP_MSISDN;
		bcd_lvlen = gsm48_encode_bcd_number(gsup_indicator + offset,
						    32, 0, extension);

		offset += bcd_lvlen;
		msgb_put(msg, bcd_lvlen + 1);
	}

	if (component_data) {
		msgb_put(msg, req->component_length);
		memcpy(gsup_indicator + offset, component_data, req->component_length);
	}

	gsup_indicator[1] = offset + req->component_length - 2; //except OSMO_GSUP_MSGT_USSD_MAP and length field
	return 0;
#if 0
	gsup_indicator[6] = req->component_type;

	/* invokeId */
	msgb_tlv_put(msg, GSM0480_COMPIDTAG_INVOKE_ID, 1, &req->invoke_id);

	/* opCode */
	msgb_tlv_put(msg, GSM0480_OPERATION_CODE, 1, &req->opcode);

	if (req->ussd_text_len > 0) {
		msgb_tlv_put(msg, ASN1_OCTET_STRING_TAG, req->ussd_text_len + 1, &req->ussd_text_language);
	}

	if (extension) {
		uint8_t bcd_buf[32];
		bcd_len = gsm48_encode_bcd_number(bcd_buf, sizeof(bcd_buf), 0,
						  extension);
		msgb_tlv_put(msg, FMAP_MSISDN, bcd_len - 1, &bcd_buf[1]);
	}

	/* fill actual length */
	gsup_indicator[7] = 3 + 3 + (req->ussd_text_len + 1 + 2) + (bcd_len + 2);;

	/* wrap with GSM0480_CTYPE_INVOKE */
	// gsm0480_wrap_invoke(msg, req->opcode, invoke_id);
	// gsup_indicator = msgb_push(msgb, 1);
	// gsup_indicator[0] = OSMO_GSUP_MSGT_MAP;
	return 0;
#endif
}



int rx_uss_message_parse(const uint8_t* data,
			 size_t len,
			 struct ss_header *ss,
			 uint32_t *pref,
			 char* extention,
			 size_t extention_len)
{
	uint8_t ext_len;
	const uint8_t* const_data = data + 1; // Skip constant
	uint32_t ref;
	int total_len;

	if (len < 7)
		return -1;

	/* skip OSMO_GSUP_MSGT_MAP */
	total_len        = *(const_data++);
	ss->message_type = *(const_data++);

	ref = ((uint32_t)(*(const_data++))) << 24;
	ref |= ((uint32_t)(*(const_data++))) << 16;
	ref |= ((uint32_t)(*(const_data++))) << 8;
	ref |= ((uint32_t)(*(const_data++)));
	if (pref)
		*pref = ref;

	total_len -= 4 + 1; // ref + sizeof(len)

	if (*const_data == FMAP_MSISDN) {
		ext_len = *(++const_data);
		if (extention) {
			gsm48_decode_bcd_number(extention,
						extention_len,
						const_data,
						0);
		}
		const_data += ext_len + 1;
		total_len -= ext_len + 2; // tag FMAP_MSISDN + sizeof(len)
	}

	ss->component_offset = const_data - data;
	ss->component_length = total_len; //data[ss->component_offset + 1];

	return 0;
#if 0
	ss->component_type = *(++const_data);

	/* skip full len and move to component id */
	const_data += 2;

	if (*const_data != GSM0480_COMPIDTAG_INVOKE_ID) {
		return -1;
	}
	const_data += 2;
	ss->invoke_id = *const_data;
	const_data++;

	//
	if (*const_data != GSM0480_OPERATION_CODE) {
		return -1;
	}
	const_data += 2;
	ss->opcode = *const_data;
	const_data++;


	while (const_data - data < len) {
		uint8_t len;
		switch (*const_data) {
		case ASN1_OCTET_STRING_TAG:
			ss->ussd_text_len = len = (*(++const_data) - 1);
			ss->ussd_text_language = *(++const_data);
			memcpy(ss->ussd_text,
				++const_data,
				(len > MAX_LEN_USSD_STRING) ? MAX_LEN_USSD_STRING : len);
			const_data += len;
			break;

		case FMAP_MSISDN:
			len = *(++const_data);
			gsm48_decode_bcd_number(extention,
						extention_len,
						const_data,
						0);
			const_data += len + 1;
			break;
		default:
			DEBUGP(DSS, "Unknown code: %d\n", *const_data);
			return -1;
		}
	}

	return 0;
#endif
}
