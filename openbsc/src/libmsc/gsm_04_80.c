/* GSM Mobile Radio Interface Layer 3 messages on the A-bis interface
 * 3GPP TS 04.08 version 7.21.0 Release 1998 / ETSI TS 100 940 V7.21.0 */

/* (C) 2008-2009 by Harald Welte <laforge@gnumonks.org>
 * (C) 2008, 2009, 2010 by Holger Hans Peter Freyther <zecke@selfish.org>
 * (C) 2009 by Mike Haben <michael.haben@btinternet.com>
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


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include <openbsc/debug.h>
#include <openbsc/gsm_data.h>
#include <openbsc/gsm_04_08.h>
#include <openbsc/gsm_04_80.h>
#include <openbsc/bsc_api.h>

#include <osmocom/gsm/gsm0480.h>
#include <osmocom/gsm/gsm_utils.h>
#include <osmocom/core/msgb.h>
#include <osmocom/gsm/tlv.h>

/* This function can handle ASN1 length up to 255 which is enough for USSD */
static inline unsigned char *msgb_wrap_with_ASN1_TL(struct msgb *msgb, uint8_t tag)
{
	uint16_t origlen = msgb->len;
	uint8_t *data = msgb_push(msgb, (origlen > 0x7f) ? 3 : 2);
	data[0] = tag;
	if (origlen > 0x7f) {
		data[1] = 0x81;
		data[2] = origlen;
	} else {
		data[1] = origlen;
	}
	return data;
}


static inline unsigned char *msgb_wrap_with_TL(struct msgb *msgb, uint8_t tag)
{
	uint8_t *data = msgb_push(msgb, 2);

	data[0] = tag;
	data[1] = msgb->len - 2;
	return data;
}

static inline unsigned char *msgb_push_TLV1(struct msgb *msgb, uint8_t tag,
					    uint8_t value)
{
	uint8_t *data = msgb_push(msgb, 3);

	data[0] = tag;
	data[1] = 1;
	data[2] = value;
	return data;
}

static inline unsigned char *msgb_wrap_with_L(struct msgb *msgb)
{
	uint8_t *data = msgb_push(msgb, 1);

	data[0] = msgb->len - 1;
	return data;
}

/* Compose universial USSD packet invoke/return_result payload */
struct msgb *gsm0480_compose_ussd_component(struct ss_request* req)
{
	struct msgb *msg = gsm48_msgb_alloc_name("GSM 04.08 USSD RSP");
	uint8_t *ptr8;

	/* First put the payload text into the message */
	ptr8 = msgb_put(msg, 0);

	memcpy(ptr8, req->ussd_text, req->ussd_text_len);
	msgb_put(msg, req->ussd_text_len);

	/* Then wrap it as an Octet String */
	msgb_wrap_with_ASN1_TL(msg, ASN1_OCTET_STRING_TAG);

	/* Pre-pend the DCS octet string */
	msgb_push_TLV1(msg, ASN1_OCTET_STRING_TAG, req->ussd_text_language);

	/* Then wrap these as a Sequence */
	msgb_wrap_with_ASN1_TL(msg, GSM_0480_SEQUENCE_TAG);

	if (req->component_type == GSM0480_CTYPE_RETURN_RESULT) {
		/* Pre-pend the operation code */
		msgb_push_TLV1(msg, GSM0480_OPERATION_CODE, req->opcode);

		/* Wrap the operation code and IA5 string as a sequence */
		msgb_wrap_with_ASN1_TL(msg, GSM_0480_SEQUENCE_TAG);

		/* Pre-pend the invoke ID */
		msgb_push_TLV1(msg, GSM0480_COMPIDTAG_INVOKE_ID, req->invoke_id);
	} else if (req->component_type == GSM0480_CTYPE_INVOKE) {
		/* Pre-pend the operation code */
		msgb_push_TLV1(msg, GSM0480_OPERATION_CODE, req->opcode);

		/* Pre-pend the invoke ID */
		msgb_push_TLV1(msg, GSM0480_COMPIDTAG_INVOKE_ID, req->invoke_id);
	} else {
		abort();
	}

	/* Wrap this up as an Invoke or a Return Result component */
	msgb_wrap_with_ASN1_TL(msg, req->component_type);
	return msg;
}

#ifndef NO_GSM0480_SEND_FUNC

int gsm0480_send_component(struct gsm_subscriber_connection *conn,
			   struct msgb *msg,
			   struct ss_header* reqhdr)
{
#if 0
	struct msgb *msg = gsm48_msgb_alloc();
	struct gsm48_hdr *gh;
	uint8_t *ptr8;

	ptr8 = msgb_put(msg, 0);

	memcpy(ptr8, component, reqhdr->component_length);
	msgb_put(msg, reqhdr->component_length);
#endif
	struct gsm48_hdr *gh;

	if (reqhdr->message_type == GSM0480_MTYPE_REGISTER ||
		reqhdr->message_type == GSM0480_MTYPE_RELEASE_COMPLETE) {
		/* Wrap the component in a Facility message, it's not ASN1 */
		msgb_wrap_with_TL(msg, GSM0480_IE_FACILITY);
	} else if (reqhdr->message_type == GSM0480_MTYPE_FACILITY) {
		/* For GSM0480_MTYPE_FACILITY it's LV not TLV */
		msgb_wrap_with_L(msg);
	} else {
		abort();
	}

	/* And finally pre-pend the L3 header */
	gh = (struct gsm48_hdr *) msgb_push(msg, sizeof(*gh));
	gh->proto_discr = GSM48_PDISC_NC_SS | reqhdr->transaction_id
					| (1<<7);  /* TI direction = 1 */
	gh->msg_type = reqhdr->message_type;

	DEBUGP(DSS, "Sending SS to mobile: %s\n", msgb_hexdump(msg));

	return gsm0808_submit_dtap(conn, msg, 0, 0);
}

#if 0
/* Compose universial SS packet except Reject opcodes */
int gsm0480_send_ussd(struct gsm_subscriber_connection *conn,
		      struct ss_request* req)
{
	struct msgb *msg = gsm48_msgb_alloc();
	struct gsm48_hdr *gh;
	uint8_t *ptr8;

	/* First put the payload text into the message */
	ptr8 = msgb_put(msg, 0);

	memcpy(ptr8, req->ussd_text, req->ussd_text_len);
	msgb_put(msg, req->ussd_text_len);

	/* Then wrap it as an Octet String */
	msgb_wrap_with_ASN1_TL(msg, ASN1_OCTET_STRING_TAG);

	/* Pre-pend the DCS octet string */
	msgb_push_TLV1(msg, ASN1_OCTET_STRING_TAG, req->ussd_text_language);

	/* Then wrap these as a Sequence */
	msgb_wrap_with_ASN1_TL(msg, GSM_0480_SEQUENCE_TAG);

	if (req->component_type == GSM0480_CTYPE_RETURN_RESULT) {
		/* Pre-pend the operation code */
		msgb_push_TLV1(msg, GSM0480_OPERATION_CODE, req->opcode);

		/* Wrap the operation code and IA5 string as a sequence */
		msgb_wrap_with_ASN1_TL(msg, GSM_0480_SEQUENCE_TAG);

		/* Pre-pend the invoke ID */
		msgb_push_TLV1(msg, GSM0480_COMPIDTAG_INVOKE_ID, req->invoke_id);
	} else if (req->component_type == GSM0480_CTYPE_INVOKE) {
		/* Pre-pend the operation code */
		msgb_push_TLV1(msg, GSM0480_OPERATION_CODE, req->opcode);

		/* Pre-pend the invoke ID */
		msgb_push_TLV1(msg, GSM0480_COMPIDTAG_INVOKE_ID, req->invoke_id);
	} else {
		abort();
	}

	/* Wrap this up as an Invoke or a Return Result component */
	msgb_wrap_with_ASN1_TL(msg, req->component_type);

	if (req->message_type == GSM0480_MTYPE_REGISTER ||
		req->message_type == GSM0480_MTYPE_RELEASE_COMPLETE) {
		/* Wrap the component in a Facility message, it's not ASN1 */
		msgb_wrap_with_TL(msg, GSM0480_IE_FACILITY);
	} else if (req->message_type == GSM0480_MTYPE_FACILITY) {
		/* For GSM0480_MTYPE_FACILITY it's LV not TLV */
		msgb_wrap_with_L(msg);
	} else {
		abort();
	}

	/* And finally pre-pend the L3 header */
	gh = (struct gsm48_hdr *) msgb_push(msg, sizeof(*gh));
	gh->proto_discr = GSM48_PDISC_NC_SS | req->transaction_id
					| (1<<7);  /* TI direction = 1 */
	gh->msg_type = req->message_type;

	DEBUGP(DSS, "Sending USSD to mobile: %s\n", msgb_hexdump(msg));

	return gsm0808_submit_dtap(conn, msg, 0, 0);
}
#endif

int gsm0480_send_ussd_reject(struct gsm_subscriber_connection *conn,
			     uint8_t invoke_id,
			     uint8_t transaction_id)
{
	struct msgb *msg = gsm48_msgb_alloc_name("GSM 04.08 USSD REJ");
	struct ss_header ssh;

	/* First insert the problem code */
	msgb_push_TLV1(msg, GSM_0480_PROBLEM_CODE_TAG_GENERAL,
			GSM_0480_GEN_PROB_CODE_UNRECOGNISED);

	/* Before it insert the invoke ID */
	msgb_push_TLV1(msg, GSM0480_COMPIDTAG_INVOKE_ID, invoke_id);

	/* Wrap this up as a Reject component */
	msgb_wrap_with_ASN1_TL(msg, GSM0480_CTYPE_REJECT);

	/* Prepare data for L3 header */
	ssh.transaction_id = transaction_id;
	ssh.message_type = GSM0480_MTYPE_RELEASE_COMPLETE;
	return gsm0480_send_component(conn, msg, &ssh);
#if 0
	/* Wrap the component in a Facility message */
	msgb_wrap_with_TL(msg, GSM0480_IE_FACILITY);

	/* And finally pre-pend the L3 header */
	gh = (struct gsm48_hdr *) msgb_push(msg, sizeof(*gh));
	gh->proto_discr = GSM48_PDISC_NC_SS;
	gh->proto_discr |= transaction_id | (1<<7);  /* TI direction = 1 */
	gh->msg_type = GSM0480_MTYPE_RELEASE_COMPLETE;

	return gsm0808_submit_dtap(conn, msg, 0, 0);
#endif
}

int msc_send_ussd_notify(struct gsm_subscriber_connection *conn, int level, const char *text)
{
	struct msgb *msg = gsm0480_create_ussd_notify(level, text);
	if (!msg)
		return -1;
	return gsm0808_submit_dtap(conn, msg, 0, 0);
}

int msc_send_ussd_release_complete(struct gsm_subscriber_connection *conn)
{
	struct msgb *msg = gsm0480_create_ussd_release_complete();
	if (!msg)
		return -1;
	return gsm0808_submit_dtap(conn, msg, 0, 0);
}

#endif
