/* Network-specific handling of mobile-originated SSs. */

/* (C) 2008-2009 by Harald Welte <laforge@gnumonks.org>
 * (C) 2008, 2009 by Holger Hans Peter Freyther <zecke@selfish.org>
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

/* This module defines the network-specific handling of mobile-originated
   SS messages. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include <openbsc/db.h>
#include <openbsc/gsm_04_80.h>
#include <openbsc/gsm_subscriber.h>
#include <openbsc/debug.h>
#include <openbsc/osmo_msc.h>

/* Declarations of USSD strings to be recognised */
const char USSD_TEXT_OWN_NUMBER[] = "*#100#";

/* Forward declarations of network-specific handler functions */
static int send_own_number(struct gsm_subscriber_connection *conn, const struct msgb *msg, const struct ss_request *req);
static int change_ss_activation(struct gsm_subscriber_connection *conn, uint8_t activate, const struct ss_request *req);
static int interrogate_ss(struct gsm_subscriber_connection *conn, const struct ss_request *req);

/* Entrypoint - handler function common to all mobile-originated SS */
int handle_rcv_ss(struct gsm_subscriber_connection *conn, struct msgb *msg)
{
	int rc;
	struct ss_request req;
	struct gsm48_hdr *gh;
	uint8_t activate;

	memset(&req, 0, sizeof(req));
	gh = msgb_l3(msg);
	rc = gsm0480_decode_ss_request(gh, msgb_l3len(msg), &req);

	if (rc == 1) {

		switch (req.opcode) {
		case GSM0480_OP_CODE_PROCESS_USS_REQ:

			if (req.ussd_text[0] == 0xFF)  /* Release-Complete */
				return 0;

			if (!strcmp(USSD_TEXT_OWN_NUMBER,
				   (const char *)req.ussd_text)) {
				DEBUGP(DMM, "USSD: Own number requested\n");
				rc = send_own_number(conn, msg, &req);
			} else {
				DEBUGP(DMM, "Unhandled USSD %s\n", req.ussd_text);
				rc = gsm0480_send_ss_reject(conn, &req,
							    GSM_0480_PROBLEM_CODE_TAG_INVOKE,
							    GSM_0480_INVOKE_PROB_CODE_UNRECOGNISED_OPERATION);
			}

			break;

		case GSM0480_OP_CODE_ACTIVATE_SS:
		case GSM0480_OP_CODE_DEACTIVATE_SS:
			activate = (req.opcode == GSM0480_OP_CODE_ACTIVATE_SS);
			rc = change_ss_activation(conn, activate, &req);
			break;
		case GSM0480_OP_CODE_INTERROGATE_SS:
			rc = interrogate_ss(conn, &req);
			break;
		default:
			DEBUGP(DMM, "Unhandled SS opcode %d\n", req.opcode);
			rc = gsm0480_send_ss_reject(conn, &req,
						    GSM_0480_PROBLEM_CODE_TAG_GENERAL,
						    GSM_0480_GEN_PROB_CODE_UNRECOGNISED);
			break;
		}

	} else {
		rc = gsm0480_send_ss_reject(conn, &req,
					    GSM_0480_PROBLEM_CODE_TAG_GENERAL,
					    GSM_0480_GEN_PROB_CODE_BAD_STRUCTURE);
	}

	/* check if we can release it */
	msc_release_connection(conn);
	return rc;
}

/* A network-specific handler function */
static int send_own_number(struct gsm_subscriber_connection *conn, const struct msgb *msg, const struct ss_request *req)
{
	char *own_number = conn->subscr->extension;
	char response_string[GSM_EXTENSION_LENGTH + 20];

	/* Need trailing CR as EOT character */
	snprintf(response_string, sizeof(response_string), "Your extension is %s\r", own_number);
	return gsm0480_send_ussd_response(conn, response_string, req);
}

static int change_ss_activation(struct gsm_subscriber_connection *conn, uint8_t activate, const struct ss_request *req)
{
	struct msgb *msg;
	uint8_t ss_status;
	int rc = db_ss_interrogate_status(conn->subscr,
					  req->ss_code,
					  GSM0902_TS_CODE_TELEPHONY,
					  &ss_status);

	if(rc < 0 || !(ss_status & GSM0902_SS_STATUS_P_BIT)) {
		DEBUGP(DMM, "SS 0x%02X not provisioned\n", req->ss_code);
		return gsm0480_send_ss_return_error(conn, req,
                                                    GSM0480_ERR_CODE_SS_SUBSCRIPTION_VIOLATION,
                                                    NULL);
	}

	ss_status &= ~GSM0902_SS_STATUS_A_BIT;
	ss_status |= (activate ? GSM0902_SS_STATUS_A_BIT : 0);

	rc = db_ss_set_status(conn->subscr, req->ss_code,
			      GSM0902_TS_CODE_TELEPHONY, ss_status);
	if(rc < 0)
		return gsm0480_send_ss_reject(conn, req,
					      GSM_0480_PROBLEM_CODE_TAG_INVOKE,
					      GSM_0480_INVOKE_PROB_CODE_RESOURCE_LIMITATION);

	msg = gsm48_msgb_alloc();
	/* First put the payload into the message */
	msgb_push_TLV1(msg, GSM0902_SS_DATA_SS_STATUS_TAG, ss_status);
	/* Then wrap it as a Sequence of type SS-Data */
	msgb_wrap_with_TL(msg, GSM0902_SS_INFO_SS_DATA_TAG);

	return gsm0480_send_ss_return_result(conn, req, msg);
}

static int interrogate_ss(struct gsm_subscriber_connection *conn, const struct ss_request *req)
{
	struct msgb *msg;
	uint8_t ss_status;
	int rc = db_ss_interrogate_status(conn->subscr,
					  req->ss_code,
					  GSM0902_TS_CODE_TELEPHONY,
					  &ss_status);

	if(rc < 0 || !(ss_status & GSM0902_SS_STATUS_P_BIT)) {
		DEBUGP(DMM, "SS 0x%02X not provisioned\n", req->ss_code);
		return gsm0480_send_ss_return_error(conn, req,
                                                    GSM0480_ERR_CODE_SS_SUBSCRIPTION_VIOLATION,
                                                    NULL);
	}

	msg = gsm48_msgb_alloc();
	/* Put the payload into the message */
	msgb_push_TLV1(msg, GSM0902_SS_INTERR_SS_RES_SS_STATUS_TAG, ss_status);

	return gsm0480_send_ss_return_result(conn, req, msg);
}
