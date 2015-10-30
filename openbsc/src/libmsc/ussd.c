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

	uint8_t mobile_originated;

	struct gsm_subscriber_connection *conn;
};

static unsigned s_ussd_open_sessions = 0;
static uint64_t s_uniq_ussd_sessiod_id = 0;
static LLIST_HEAD(s_active_ussd_sessions);

static struct llist_head *get_active_ussd_sessions(void)
{
	return &s_active_ussd_sessions;
}


static struct gsm_ussd* ussd_session_alloc(struct gsm_subscriber_connection* conn,
					   uint8_t tid,
					   uint8_t mo)
{
	struct gsm_network* net = conn->bts->network;
	struct gsm_ussd* m = talloc_zero(net, struct gsm_ussd);
	if (!m)
		return NULL;

	m->conn = conn;
	m->uniq_id = s_uniq_ussd_sessiod_id++;
	m->transaction_id = tid;
	m->mobile_originated = mo;
	++s_ussd_open_sessions;

	INIT_LLIST_HEAD(&m->ussqueue);
	llist_add_tail(&m->ussqueue, &s_active_ussd_sessions);

	DEBUGP(DMM, "Alloc USSD session: %d (open: %d)\n", m->uniq_id, s_ussd_open_sessions);
	return m;
}

static void ussd_session_free(struct gsm_ussd* s)
{
	--s_ussd_open_sessions;
	DEBUGP(DMM, "Free USSD session: %d (open: %d)\n", s->uniq_id, s_ussd_open_sessions);
	llist_del(&s->ussqueue);
	talloc_free(s);
}

static struct gsm_ussd* get_by_uniq_id(uint8_t uniq_id)
{
	struct gsm_ussd* c;
	llist_for_each_entry(c, get_active_ussd_sessions(), ussqueue) {
		if (c->uniq_id == uniq_id) {
			DEBUGP(DMM, "uniq_id %d has %s extention\n",
			       uniq_id, c->conn->subscr->extension);
			return c;
		}
	}

	DEBUGP(DMM, "uniq_id %d hasn't been found\n", uniq_id);
	return NULL;
}

static struct gsm_ussd* get_by_iid(struct gsm_subscriber_connection *conn, uint8_t invoke_id)
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

static struct gsm_ussd* get_by_tid(struct gsm_subscriber_connection *conn, uint8_t transaction_id)
{
	struct gsm_ussd* c;
	llist_for_each_entry(c, get_active_ussd_sessions(), ussqueue) {
		if (c->conn == conn && c->transaction_id == transaction_id) {
			DEBUGP(DMM, "transaction_id %d has %s extention\n",
			       transaction_id, c->conn->subscr->extension);
			return c;
		}
	}

	DEBUGP(DMM, "transaction_id %d hasn't been found\n", transaction_id);
	return NULL;
}

// From SUP
int on_ussd_response(const struct ss_request *req, const char *extention)
{
	struct ussd_request ussd_req;
	struct gsm_ussd* ussdq;
	memset(&ussd_req, 0, sizeof(ussd_req));
	int rc = 0;

	switch (req->message_type) {
	case GSM0480_MTYPE_REGISTER:
		DEBUGP(DMM, "Network originated USSD messages isn't supported yet!\n");

		//TODO Send to sup rejection
		return 0;

	case GSM0480_MTYPE_FACILITY:
	case GSM0480_MTYPE_RELEASE_COMPLETE:
		// FIXME add uinq_id field
		ussdq = get_by_uniq_id(req->invoke_id);
		if (!ussdq) {
			DEBUGP(DMM, "No session was found for uniq_id: %d!\n",
			       req->invoke_id);
			// TODO SUP Reject
			return 0;
		}
		break;
	default:
		DEBUGP(DMM, "Unknown message type 0x%02x\n", req->message_type);
		// TODO SUP Reject
		return 0;
	}

	ussd_req.transaction_id = ussdq->transaction_id;
	ussd_req.invoke_id = ussdq->invoke_id;

	if (req->component_type != GSM0480_CTYPE_REJECT) {
		rc = gsm0480_send_ussd_response(ussdq->conn,
						NULL,
						(req->ussd_text_language == 0x80) ? -1 : req->ussd_text_len,
						req->ussd_text_language,
						(const char *)req->ussd_text,
						&ussd_req,
						req->opcode,
						req->component_type,
						req->message_type);
	} else {
		rc = gsm0480_send_ussd_reject(ussdq->conn, NULL, &ussd_req);
	}

	if (req->message_type == GSM0480_MTYPE_RELEASE_COMPLETE) {
		msc_release_connection(ussdq->conn);
		ussd_session_free(ussdq);
	}

	return rc;
}

static int ussd_sup_send_reject(struct gsm_subscriber_connection *conn,
				uint8_t uniq_id, uint8_t opcode)
{
	struct ss_request rej;
	rej.message_type = GSM0480_MTYPE_RELEASE_COMPLETE;
	rej.component_type = GSM0480_CTYPE_REJECT;
	rej.invoke_id = uniq_id;
	rej.opcode = opcode;
	rej.ussd_text_len = 0;

	return subscr_tx_uss_message(&rej, conn->subscr);
}

/* Entrypoint - handler function common to all mobile-originated USSDs */
int handle_rcv_ussd(struct gsm_subscriber_connection *conn, struct msgb *msg)
{
	int rc = 0;
	struct gsm48_hdr *gh;
	struct ss_request req;
	struct gsm_ussd* ussdq = NULL;
	struct ussd_request ussd_req;

	memset(&req, 0, sizeof(req));
	memset(&ussd_req, 0, sizeof(ussd_req));

	DEBUGP(DMM, "handle ussd: %s\n", msgb_hexdump(msg));

	gh = msgb_l3(msg);
	rc = gsm0480_decode_ss_request(gh, msgb_l3len(msg), &req);
	if (!rc) {
		DEBUGP(DMM, "Unhandled SS\n");
		ussdq = get_by_tid(conn, req.transaction_id);
		if (ussdq) {
			ussd_sup_send_reject(conn, ussdq->uniq_id, 0);
			goto failed_transaction;
		}

		goto transaction_not_found;
	}

	switch (req.message_type) {
	case GSM0480_MTYPE_REGISTER:
		ussdq = ussd_session_alloc(conn, req.transaction_id, USSD_MO);
		if (!ussdq) {
			DEBUGP(DMM, "Failed to create new session\n");
			goto transaction_not_found;
		}
		ussdq->invoke_id = req.invoke_id;
		break;
	case GSM0480_MTYPE_FACILITY:
		ussdq = get_by_tid(conn, req.transaction_id);
		if (!ussdq) {
			ussdq = get_by_iid(conn, req.invoke_id);
			if (!ussdq) {
				DEBUGP(DMM, "no session found invoke_id=%d tid=%d\n",
				       req.invoke_id, req.transaction_id);
				goto transaction_not_found;
			}
		}
		break;

	case GSM0480_MTYPE_RELEASE_COMPLETE:
		// FIXME handle parsing in libosmocore
		ussdq = get_by_tid(conn, req.transaction_id);
		if (!ussdq) {
			DEBUGP(DMM, "RELEASE_COMPLETE to non-existing transaction!\n");
			goto release_conn;
		}

		ussd_session_free(ussdq);
		ussd_sup_send_reject(conn, ussdq->uniq_id, req.opcode);
		goto release_conn;
	}

	req.invoke_id = ussdq->uniq_id;
	rc = subscr_tx_uss_message(&req, conn->subscr);
	if (rc) {
		DEBUGP(DMM, "Unable tp send uss over sup reason: %d\n", rc);
		goto failed_transaction;
	}
	return 0;

failed_transaction:
	ussd_session_free(ussdq);

transaction_not_found:
	ussd_req.invoke_id = req.invoke_id;
	ussd_req.transaction_id = req.transaction_id;
	gsm0480_send_ussd_reject(conn, msg, &ussd_req);

release_conn:
	msc_release_connection(conn);
	return rc;

#if 0
	ussdq = get_by_iid(conn, req.invoke_id);

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
#endif
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
#if 0
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
#endif
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
