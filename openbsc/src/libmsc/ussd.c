/* Network-specific handling of mobile-originated USSDs. */

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
   USSD messages. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include <openbsc/gsm_04_80.h>
#include <openbsc/gsm_subscriber.h>
#include <openbsc/debug.h>
#include <openbsc/osmo_msc.h>
#include <openbsc/gsm_sup.h>
#include <openbsc/ussd.h>
#include <osmocom/gsm/gsm0480.h>

struct gsm_ussd {
	struct llist_head ussqueue;

	uint8_t uniq_id;   /**<  System wide uniq ID */

	uint8_t invoke_id;
	uint8_t transaction_id;

	uint8_t current_transaction_id;

	struct gsm_subscriber_connection *conn;
};

static uint64_t s_uniq_ussd_sessiod_id = 0;
static LLIST_HEAD(s_active_ussd_sessions);

static struct llist_head *get_active_ussd_sessions(void)
{
	return &s_active_ussd_sessions;
}


static struct gsm_ussd* ussd_session_alloc(struct gsm_subscriber_connection* conn)
{
	struct gsm_network* net = conn->bts->network;
	struct gsm_ussd* m = talloc_zero(net, struct gsm_ussd);
	if (!m)
		return NULL;

	m->conn = conn;
	m->uniq_id = s_uniq_ussd_sessiod_id++;

	INIT_LLIST_HEAD(&m->ussqueue);
	llist_add_tail(&m->ussqueue, &s_active_ussd_sessions);

	DEBUGP(DMM, "Alloc USSD session: %d\n", m->uniq_id);
	return m;
}

static void ussd_session_free(struct gsm_ussd* s)
{
	DEBUGP(DMM, "Free USSD session: %d\n", s->uniq_id);
	llist_del(&s->ussqueue);
	talloc_free(s);
}

static struct gsm_ussd* get_by_uniq_id(uint8_t invoke_id)
{
	struct gsm_ussd* c;
	llist_for_each_entry(c, get_active_ussd_sessions(), ussqueue) {
		if (c->uniq_id == invoke_id) {
			DEBUGP(DMM, "uniq invoke_id %d has %s extention\n",
			       invoke_id, c->conn->subscr->extension);
			return c;
		}
	}

	DEBUGP(DMM, "uniq invoke_id %d hasn't been found\n", invoke_id);
	return NULL;
}

static struct gsm_ussd* get_by_id(struct gsm_subscriber_connection *conn, uint8_t invoke_id)
{
	struct gsm_ussd* c;
	llist_for_each_entry(c, get_active_ussd_sessions(), ussqueue) {
		if (c->conn == conn && c->invoke_id == invoke_id) {
			DEBUGP(DMM, "invoke_id %d has %s extention\n",
			       invoke_id, c->conn->subscr->extension);
			return c;
		}
	}

	DEBUGP(DMM, "invoke_id %d hasn't been found\n", invoke_id);
	return NULL;
}

int on_ussd_response(const struct ss_request *req, const char *extention)
{
	struct ussd_request ussd_req;
	struct gsm_ussd* ussdq = get_by_uniq_id(req->invoke_id);
	memset(&ussd_req, 0, sizeof(ussd_req));
	int rc;
	uint8_t mtype;

	switch (req->opcode) {
	case GSM0480_OP_CODE_USS_NOTIFY:
		DEBUGP(DMM, "Network originated USSD Notify is not supported yet!\n");

		if (!ussdq) {
			mtype = GSM0480_MTYPE_REGISTER;
		} else {
			mtype = GSM0480_MTYPE_FACILITY;
		}

		return -ENOTSUP;
	case GSM0480_OP_CODE_PROCESS_USS_REQ:
		if (!ussdq) {
			DEBUGP(DMM, "Network originated Process USSD Request is not supported yet!\n");
			// TODO SUP Reject
			return -ENOTSUP;
		}

		mtype = GSM0480_MTYPE_RELEASE_COMPLETE;
		ussd_req.transaction_id = ussdq->transaction_id;
		break;
	case GSM0480_OP_CODE_USS_REQUEST:
		if (!ussdq) {
			DEBUGP(DMM, "No session was found for invoke_id: %d\n", req->invoke_id);
			return -EINVAL;
		}

		mtype = GSM0480_MTYPE_FACILITY;
		ussd_req.transaction_id = ussdq->current_transaction_id;
		break;
	default:
		// TODO SUP Reject
		return -EINVAL;
	}

	ussd_req.invoke_id = ussdq->invoke_id;

	if (req->ussd_text[0]) {
		rc = gsm0480_send_ussd_response(ussdq->conn,
						NULL,
						(const char *)req->ussd_text,
						&ussd_req,
						req->opcode,
						req->component_type,
						mtype);
	} else {
		rc = gsm0480_send_ussd_reject(ussdq->conn, NULL, &ussd_req);
	}
	if (rc || mtype == GSM0480_MTYPE_RELEASE_COMPLETE) {
		ussd_session_free(ussdq);
		msc_release_connection(ussdq->conn);
	}

	return rc;
}

/* Entrypoint - handler function common to all mobile-originated USSDs */
int handle_rcv_ussd(struct gsm_subscriber_connection *conn, struct msgb *msg)
{
	int rc;
	struct gsm48_hdr *gh;
	struct ss_request req;
	struct gsm_ussd* ussdq = NULL;
	struct ussd_request ussd_req;

	memset(&req, 0, sizeof(req));
	memset(&ussd_req, 0, sizeof(ussd_req));

	DEBUGP(DMM, "handle ussd: %s\n", msgb_hexdump(msg));

	gh = msgb_l3(msg);
	rc = gsm0480_decode_ss_request(gh, msgb_l3len(msg), &req);

	//if (req.ussd_text[0] == 0xFF)
	//	req.ussd_text[0] = '\0';

	if (!rc) {
		DEBUGP(DMM, "Unhandled SS\n");
		goto failed;
	}

	ussdq = get_by_id(conn, req.invoke_id);

	// TODO FIXME !!!! Replace by message_type
	switch (req.opcode) {
	case GSM0480_OP_CODE_PROCESS_USS_REQ:
		if (ussdq) {
			/* new session with the same id as an open session, destroy both */
			DEBUGP(DMM, "Duplicate session? invoke_id: %d\n", req.invoke_id);
			goto failed;
		}

		if (req.component_type != GSM0480_CTYPE_INVOKE) {
			DEBUGP(DMM, "processUSS with component_type 0x%02x\n", req.component_type);
			goto failed;
		}

		ussdq = ussd_session_alloc(conn);
		if (!ussdq) {
			DEBUGP(DMM, "Failed to create new session\n");
			goto failed;
		}

		ussdq->conn = conn;
		ussdq->invoke_id = req.invoke_id;
		ussdq->transaction_id = req.transaction_id;
		break;

	case GSM0480_OP_CODE_USS_REQUEST:
		if (!ussdq) {
			DEBUGP(DMM, "no session found for USS_REQUEST with invoke_id=%d\n", req.invoke_id);
			goto failed;
		}
		if (req.component_type != GSM0480_CTYPE_RETURN_RESULT) {
			DEBUGP(DMM, "USS with component_type 0x%02x\n", req.component_type);
			goto failed;
		}

		ussdq->current_transaction_id = req.transaction_id;
		break;

	default:
		DEBUGP(DMM, "Unhandled opcode: 0x%02x, component_type: 0x%02x, text: %s\n",
		       req.opcode, req.component_type, req.ussd_text);
		goto failed;
	}

	// ACHTUNG! FIXME!! FIXME!! Introduce transaction ID instead
	// Override Invoke ID
	req.invoke_id = ussdq->uniq_id;
	rc = subscr_tx_uss_message(&req, conn->subscr);
	if (rc) {
		DEBUGP(DMM, "Unable tp send uss over sup reason: %d\n", rc);
		goto failed;
	}

	return 0;

#if 0
	struct ussd_request req;
	struct gsm48_hdr *gh;

	memset(&req, 0, sizeof(req));
	gh = msgb_l3(msg);
	rc = gsm0480_decode_ussd_request(gh, msgb_l3len(msg), &req);
	if (!rc) {
		DEBUGP(DMM, "Unhandled SS\n");
		rc = gsm0480_send_ussd_reject(conn, msg, &req);
		msc_release_connection(conn);
		return rc;
	}

	/* Release-Complete */
	if (req.text[0] == '\0')
		return 0;

	if (!strcmp(USSD_TEXT_OWN_NUMBER, (const char *)req.text)) {
		DEBUGP(DMM, "USSD: Own number requested\n");
		rc = send_own_number(conn, msg, &req);
	} else {
		rc = subscr_tx_uss_message(req, conn->subscr);


		//TODO:
	}
#endif

failed:
	// TODO handle error on SUP end
	if (ussdq) {
		ussd_session_free(ussdq);
	}

	ussd_req.invoke_id = req.invoke_id;
	ussd_req.transaction_id = req.transaction_id;
	gsm0480_send_ussd_reject(conn, msg, &ussd_req);
	/* check if we can release it */
	msc_release_connection(conn);
	return rc;
}

#if 0

/* Declarations of USSD strings to be recognised */
const char USSD_TEXT_OWN_NUMBER[] = "*#100#";

/* Forward declarations of network-specific handler functions */
static int send_own_number(struct gsm_subscriber_connection *conn, const struct msgb *msg, const struct ussd_request *req);


/* A network-specific handler function */
static int send_own_number(struct gsm_subscriber_connection *conn, const struct msgb *msg, const struct ussd_request *req)
{
	char *own_number = conn->subscr->extension;
	char response_string[GSM_EXTENSION_LENGTH + 20];

	/* Need trailing CR as EOT character */
	snprintf(response_string, sizeof(response_string), "Your extension is %s\r", own_number);
	return gsm0480_send_ussd_response(conn, msg, response_string, req);
}
#endif
