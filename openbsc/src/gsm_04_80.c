/* GSM Mobile Radio Interface Layer 3 messages on the A-bis interface
 * 3GPP TS 04.08 version 7.21.0 Release 1998 / ETSI TS 100 940 V7.21.0 */

/* (C) 2008-2009 by Harald Welte <laforge@gnumonks.org>
 * (C) 2008, 2009, 2010 by Holger Hans Peter Freyther <zecke@selfish.org>
 * (C) 2009 by Mike Haben <michael.haben@btinternet.com>
 *
 * All Rights Reserved
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 */


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include <osmocore/msgb.h>
#include <osmocore/tlv.h>
#include <openbsc/debug.h>
#include <openbsc/gsm_data.h>
#include <osmocore/gsm_utils.h>
#include <openbsc/gsm_04_08.h>
#include <openbsc/gsm_04_80.h>
#include <openbsc/bsc_api.h>

/* Forward declarations */
static int parse_ussd(u_int8_t *ussd, struct ussd_request *req);
static int parse_ussd_info_elements(u_int8_t *ussd_ie,
					struct ussd_request *req);
static int parse_facility_ie(u_int8_t *facility_ie, u_int8_t length,
					struct ussd_request *req);
static int parse_ss_invoke(u_int8_t *invoke_data, u_int8_t length,
					struct ussd_request *req);
static int parse_process_uss_req(u_int8_t *uss_req_data, u_int8_t length,
					struct ussd_request *req);

static inline unsigned char *msgb_wrap_with_TL(struct msgb *msgb, u_int8_t tag)
{
	msgb->data -= 2;
	msgb->data[0] = tag;
	msgb->data[1] = msgb->len;
	msgb->len += 2;
	return msgb->data;
}

static inline unsigned char *msgb_push_TLV1(struct msgb *msgb, u_int8_t tag,
					    u_int8_t value)
{
	msgb->data -= 3;
	msgb->len += 3;
	msgb->data[0] = tag;
	msgb->data[1] = 1;
	msgb->data[2] = value;
	return msgb->data;
}


/* Decode a mobile-originated USSD-request message */
int gsm0480_decode_ussd_request(const struct msgb *msg, struct ussd_request *req)
{
	int rc = 0;
	u_int8_t *parse_ptr = msgb_l3(msg);

	if ((*parse_ptr & 0x0F) == GSM48_PDISC_NC_SS) {
		req->transaction_id = *parse_ptr & 0x70;
		rc = parse_ussd(parse_ptr+1, req);
	}

	if (!rc)
		DEBUGP(DMM, "Error occurred while parsing received USSD!\n");

	return rc;
}

static int parse_ussd(u_int8_t *ussd, struct ussd_request *req)
{
	int rc = 1;
	u_int8_t msg_type = ussd[0] & 0xBF;  /* message-type - section 3.4 */

	switch (msg_type) {
	case GSM0480_MTYPE_RELEASE_COMPLETE:
		DEBUGP(DMM, "USS Release Complete\n");
		/* could also parse out the optional Cause/Facility data */
		req->text[0] = 0xFF;
		break;
	case GSM0480_MTYPE_REGISTER:
	case GSM0480_MTYPE_FACILITY:
		rc &= parse_ussd_info_elements(ussd+1, req);
		break;
	default:
		fprintf(stderr, "Unknown GSM 04.80 message-type field 0x%02x\n",
			ussd[0]);
		rc = 0;
		break;
	}

	return rc;
}

static int parse_ussd_info_elements(u_int8_t *ussd_ie, struct ussd_request *req)
{
	int rc = -1;
	/* Information Element Identifier - table 3.2 & GSM 04.08 section 10.5 */
	u_int8_t iei = ussd_ie[0];
	u_int8_t iei_length = ussd_ie[1];

	switch (iei) {
	case GSM48_IE_CAUSE:
		break;
	case GSM0480_IE_FACILITY:
		rc = parse_facility_ie(ussd_ie+2, iei_length, req);
		break;
	case GSM0480_IE_SS_VERSION:
		break;
	default:
		fprintf(stderr, "Unhandled GSM 04.08 or 04.80 IEI 0x%02x\n",
			iei);
		rc = 0;
		break;
	}

	return rc;
}

static int parse_facility_ie(u_int8_t *facility_ie, u_int8_t length,
						struct ussd_request *req)
{
	int rc = 1;
	u_int8_t offset = 0;

	do {
		/* Component Type tag - table 3.7 */
		u_int8_t component_type = facility_ie[offset];
		u_int8_t component_length = facility_ie[offset+1];

		switch (component_type) {
		case GSM0480_CTYPE_INVOKE:
			rc &= parse_ss_invoke(facility_ie+2,
						component_length,
						req);
			break;
		case GSM0480_CTYPE_RETURN_RESULT:
			break;
		case GSM0480_CTYPE_RETURN_ERROR:
			break;
		case GSM0480_CTYPE_REJECT:
			break;
		default:
			fprintf(stderr, "Unknown GSM 04.80 Facility "
				"Component Type 0x%02x\n", component_type);
			rc = 0;
			break;
		}
		offset += (component_length+2);
	} while (offset < length);

	return rc;
}

/* Parse an Invoke component - see table 3.3 */
static int parse_ss_invoke(u_int8_t *invoke_data, u_int8_t length,
						struct ussd_request *req)
{
	int rc = 1;
	u_int8_t offset;

	/* mandatory part */
	if (invoke_data[0] != GSM0480_COMPIDTAG_INVOKE_ID) {
		fprintf(stderr, "Unexpected GSM 04.80 Component-ID tag "
			"0x%02x (expecting Invoke ID tag)\n", invoke_data[0]);
	}

	offset = invoke_data[1] + 2;
	req->invoke_id = invoke_data[2];

	/* optional part */
	if (invoke_data[offset] == GSM0480_COMPIDTAG_LINKED_ID)
		offset += invoke_data[offset+1] + 2;  /* skip over it */

	/* mandatory part */
	if (invoke_data[offset] == GSM0480_OPERATION_CODE) {
		u_int8_t operation_code = invoke_data[offset+2];
		switch (operation_code) {
		case GSM0480_OP_CODE_PROCESS_USS_REQ:
			rc = parse_process_uss_req(invoke_data + offset + 3,
						   length - offset - 3,
						   req);
			break;
		default:
			fprintf(stderr, "GSM 04.80 operation code 0x%02x "
				"is not yet handled\n", operation_code);
			rc = 0;
			break;
		}
	} else {
		fprintf(stderr, "Unexpected GSM 04.80 Component-ID tag 0x%02x "
			"(expecting Operation Code tag)\n",
			invoke_data[0]);
		rc = 0;
	}

	return rc;
}

/* Parse the parameters of a Process UnstructuredSS Request */
static int parse_process_uss_req(u_int8_t *uss_req_data, u_int8_t length,
					struct ussd_request *req)
{
	int rc = 0;
	int num_chars;
	u_int8_t dcs;

	if (uss_req_data[0] == GSM_0480_SEQUENCE_TAG) {
		if (uss_req_data[2] == ASN1_OCTET_STRING_TAG) {
			dcs = uss_req_data[4];
			if ((dcs == 0x0F) &&
			    (uss_req_data[5] == ASN1_OCTET_STRING_TAG)) {
				num_chars = (uss_req_data[6] * 8) / 7;
				/* Prevent a mobile-originated buffer-overrun! */
				if (num_chars > MAX_LEN_USSD_STRING)
					num_chars = MAX_LEN_USSD_STRING;
				gsm_7bit_decode(req->text,
						&(uss_req_data[7]), num_chars);
				/* append null-terminator */
				req->text[num_chars+1] = 0;
				rc = 1;
			}
		}
	}
	return rc;
}

struct msgb *gsm0480_create_notifySS(const char *text)
{
	struct msgb *msg;
	uint8_t *data, *tmp_len;
	uint8_t *seq_len_ptr, *cal_len_ptr, *opt_len_ptr, *nam_len_ptr;
	int len;

	len = strlen(text);
	if (len < 1 || len > 160)
		return NULL;

	msg = gsm48_msgb_alloc();
	if (!msg)
		return NULL;

	msgb_put_u8(msg, GSM_0480_SEQUENCE_TAG);
	seq_len_ptr = msgb_put(msg, 1);


	/* nameIndicator { */
	msgb_put_u8(msg, 0xB4);
	nam_len_ptr = msgb_put(msg, 1);

	/* callingName { */
	msgb_put_u8(msg, 0xA0);
	opt_len_ptr = msgb_put(msg, 1);
	msgb_put_u8(msg, 0xA0);
	cal_len_ptr = msgb_put(msg, 1);

	/* namePresentationAllowed { */
	/* add the DCS value */
	msgb_put_u8(msg, 0x80);
	msgb_put_u8(msg, 1);
	msgb_put_u8(msg, 0x0F);

	/* add the lengthInCharacters */
	msgb_put_u8(msg, 0x81);
	msgb_put_u8(msg, 1);
	msgb_put_u8(msg, strlen(text));

	/* add the actual string */
	msgb_put_u8(msg, 0x82);
	tmp_len = msgb_put(msg, 1);
	data = msgb_put(msg, 0);
	len = gsm_7bit_encode(data, text);
	tmp_len[0] = len;
	msgb_put(msg, len);

	/* }; namePresentationAllowed */

	cal_len_ptr[0] = 3 + 3 + 2 + len;
	opt_len_ptr[0] = cal_len_ptr[0] + 2;
	/* }; callingName */

	nam_len_ptr[0] = opt_len_ptr[0] + 2;
	/* ); nameIndicator */

	/* write the lengths... */
	seq_len_ptr[0] = nam_len_ptr[0] + 2;

	return msg;
}

/* Send response to a mobile-originated ProcessUnstructuredSS-Request */
int gsm0480_send_ussd_response(struct gsm_subscriber_connection *conn,
			       const struct msgb *in_msg, const char *response_text,
			       const struct ussd_request *req)
{
	struct msgb *msg = gsm48_msgb_alloc();
	struct gsm48_hdr *gh;
	u_int8_t *ptr8;
	int response_len;

	response_len = (strlen(response_text) * 7) / 8;
	if (((strlen(response_text) * 7) % 8) != 0)
		response_len += 1;

	/* First put the payload text into the message */
	ptr8 = msgb_put(msg, response_len);
	gsm_7bit_encode(ptr8, response_text);

	/* Then wrap it as an Octet String */
	msgb_wrap_with_TL(msg, ASN1_OCTET_STRING_TAG);

	/* Pre-pend the DCS octet string */
	msgb_push_TLV1(msg, ASN1_OCTET_STRING_TAG, 0x0F);

	/* Then wrap these as a Sequence */
	msgb_wrap_with_TL(msg, GSM_0480_SEQUENCE_TAG);

	/* Pre-pend the operation code */
	msgb_push_TLV1(msg, GSM0480_OPERATION_CODE,
			GSM0480_OP_CODE_PROCESS_USS_REQ);

	/* Wrap the operation code and IA5 string as a sequence */
	msgb_wrap_with_TL(msg, GSM_0480_SEQUENCE_TAG);

	/* Pre-pend the invoke ID */
	msgb_push_TLV1(msg, GSM0480_COMPIDTAG_INVOKE_ID, req->invoke_id);

	/* Wrap this up as a Return Result component */
	msgb_wrap_with_TL(msg, GSM0480_CTYPE_RETURN_RESULT);

	/* Wrap the component in a Facility message */
	msgb_wrap_with_TL(msg, GSM0480_IE_FACILITY);

	/* And finally pre-pend the L3 header */
	gh = (struct gsm48_hdr *) msgb_push(msg, sizeof(*gh));
	gh->proto_discr = GSM48_PDISC_NC_SS | req->transaction_id
					| (1<<7);  /* TI direction = 1 */
	gh->msg_type = GSM0480_MTYPE_RELEASE_COMPLETE;

	return gsm0808_submit_dtap(conn, msg, 0);
}

/* wrap an invoke around it... the other way around
 *
 * 1.) Invoke Component tag
 * 2.) Invoke ID Tag
 * 3.) Operation
 * 4.) Data
 */
int gsm0480_wrap_invoke(struct msgb *msg, int op, int link_id)
{
	/* 3. operation */
	msgb_push_TLV1(msg, GSM0480_OPERATION_CODE, op);

	/* 2. invoke id tag */
	msgb_push_TLV1(msg, GSM0480_COMPIDTAG_INVOKE_ID, link_id);

	/* 1. component tag */
	msgb_wrap_with_TL(msg, GSM0480_CTYPE_INVOKE);

	return 0;
}

int gsm0480_send_ussd_reject(struct gsm_subscriber_connection *conn,
			     const struct msgb *in_msg,
			     const struct ussd_request *req)
{
	struct msgb *msg = gsm48_msgb_alloc();
	struct gsm48_hdr *gh;

	/* First insert the problem code */
	msgb_push_TLV1(msg, GSM_0480_PROBLEM_CODE_TAG_GENERAL,
			GSM_0480_GEN_PROB_CODE_UNRECOGNISED);

	/* Before it insert the invoke ID */
	msgb_push_TLV1(msg, GSM0480_COMPIDTAG_INVOKE_ID, req->invoke_id);

	/* Wrap this up as a Reject component */
	msgb_wrap_with_TL(msg, GSM0480_CTYPE_REJECT);

	/* Wrap the component in a Facility message */
	msgb_wrap_with_TL(msg, GSM0480_IE_FACILITY);

	/* And finally pre-pend the L3 header */
	gh = (struct gsm48_hdr *) msgb_push(msg, sizeof(*gh));
	gh->proto_discr = GSM48_PDISC_NC_SS;
	gh->proto_discr |= req->transaction_id | (1<<7);  /* TI direction = 1 */
	gh->msg_type = GSM0480_MTYPE_RELEASE_COMPLETE;

	return gsm0808_submit_dtap(conn, msg, 0);
}
