/* SMPP 3.4 interface, SMSC-side implementation */
/* (C) 2012 by Harald Welte <laforge@gnumonks.org>
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
 */


#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <limits.h>

#include <sys/socket.h>
#include <netinet/in.h>

#include <smpp34.h>
#include <smpp34_structs.h>
#include <smpp34_params.h>

#include <osmocom/core/utils.h>
#include <osmocom/core/socket.h>
#include <osmocom/core/msgb.h>
#include <osmocom/core/logging.h>
#include <osmocom/core/write_queue.h>
#include <osmocom/core/talloc.h>

#include "smpp_smsc.h"

#include <openbsc/debug.h>
#include <openbsc/gsm_data.h>

/*! \brief Ugly wrapper. libsmpp34 should do this itself! */
#define SMPP34_UNPACK(rc, type, str, data, len)		\
	memset(str, 0, sizeof(*str));			\
	rc = smpp34_unpack(type, str, data, len)

enum emse_bind {
	ESME_BIND_RX = 0x01,
	ESME_BIND_TX = 0x02,
};

const struct value_string smpp_status_strs[] = {
	{ ESME_ROK,		"No Error" },
	{ ESME_RINVMSGLEN,	"Message Length is invalid" },
	{ ESME_RINVCMDLEN,	"Command Length is invalid" },
	{ ESME_RINVCMDID,	"Invalid Command ID" },
	{ ESME_RINVBNDSTS,	"Incorrect BIND Status for given command" },
	{ ESME_RALYBND,		"ESME Already in Bound State" },
	{ ESME_RINVPRTFLG,	"Invalid Priority Flag" },
	{ ESME_RINVREGDLVFLG,	"Invalid Registered Delivery Flag" },
	{ ESME_RSYSERR,		"System Error" },
	{ ESME_RINVSRCADR,	"Invalid Source Address" },
	{ ESME_RINVDSTADR,	"Invalid Destination Address" },
	{ ESME_RINVMSGID,	"Message ID is invalid" },
	{ ESME_RBINDFAIL,	"Bind failed" },
	{ ESME_RINVPASWD,	"Invalid Password" },
	{ ESME_RINVSYSID,	"Invalid System ID" },
	{ ESME_RCANCELFAIL,	"Cancel SM Failed" },
	{ ESME_RREPLACEFAIL,	"Replace SM Failed" },
	{ ESME_RMSGQFUL,	"Message Queue Full" },
	{ ESME_RINVSERTYP,	"Invalid Service Type" },
	{ ESME_RINVNUMDESTS,	"Invalid number of destinations" },
	{ ESME_RINVDLNAME,	"Invalid Distribution List name" },
	{ ESME_RINVDESTFLAG,	"Destination flag is invalid" },
	{ ESME_RINVSUBREP,	"Invalid submit with replace request" },
	{ ESME_RINVESMCLASS,	"Invalid esm_class field data" },
	{ ESME_RCNTSUBDL,	"Cannot Submit to Distribution List" },
	{ ESME_RSUBMITFAIL,	"submit_sm or submit_multi failed" },
	{ ESME_RINVSRCTON,	"Invalid Source address TON" },
	{ ESME_RINVSRCNPI,	"Invalid Sourec address NPI" },
	{ ESME_RINVDSTTON,	"Invalid Destination address TON" },
	{ ESME_RINVDSTNPI,	"Invalid Desetination address NPI" },
	{ ESME_RINVSYSTYP,	"Invalid system_type field" },
	{ ESME_RINVREPFLAG,	"Invalid replace_if_present field" },
	{ ESME_RINVNUMMSGS,	"Invalid number of messages" },
	{ ESME_RTHROTTLED,	"Throttling error (ESME has exceeded message limits)" },
	{ ESME_RINVSCHED,	"Invalid Scheduled Delivery Time" },
	{ ESME_RINVEXPIRY,	"Invalid message validity period (Expiry time)" },
	{ ESME_RINVDFTMSGID,	"Predefined Message Invalid or Not Found" },
	{ ESME_RX_T_APPN,	"ESME Receiver Temporary App Error Code" },
	{ ESME_RX_P_APPN,	"ESME Receiver Permanent App Error Code" },
	{ ESME_RX_R_APPN,	"ESME Receiver Reject Message Error Code" },
	{ ESME_RQUERYFAIL,	"query_sm request failed" },
	{ ESME_RINVOPTPARSTREAM,"Error in the optional part of the PDU Body" },
	{ ESME_ROPTPARNOTALLWD,	"Optional Parameter not allowed" },
	{ ESME_RINVPARLEN,	"Invalid Parameter Length" },
	{ ESME_RMISSINGOPTPARAM,"Expected Optional Parameter missing" },
	{ ESME_RINVOPTPARAMVAL,	"Invalid Optional Parameter Value" },
	{ ESME_RDELIVERYFAILURE,"Delivery Failure (used for data_sm_resp)" },
	{ ESME_RUNKNOWNERR,	"Unknown Error" },
	{ 0, NULL }
};

/*! \brief compare if two SMPP addresses are equal */
int smpp_addr_eq(const struct osmo_smpp_addr *a,
		 const struct osmo_smpp_addr *b)
{
	if (a->ton == b->ton &&
	    a->npi == b->npi &&
	    !strcmp(a->addr, b->addr))
		return 1;

	return 0;
}


struct osmo_smpp_acl *smpp_acl_by_system_id(struct smsc *smsc,
					    const char *sys_id)
{
	struct osmo_smpp_acl *acl;

	llist_for_each_entry(acl, &smsc->acl_list, list) {
		if (!strcmp(acl->system_id, sys_id))
			return acl;
	}

	return NULL;
}

struct osmo_smpp_acl *smpp_acl_alloc(struct smsc *smsc, const char *sys_id)
{
	struct osmo_smpp_acl *acl;

	if (strlen(sys_id) > SMPP_SYS_ID_LEN)
		return NULL;

	if (smpp_acl_by_system_id(smsc, sys_id))
		return NULL;

	acl = talloc_zero(smsc, struct osmo_smpp_acl);
	if (!acl)
		return NULL;

	acl->smsc = smsc;
	strcpy(acl->system_id, sys_id);
	INIT_LLIST_HEAD(&acl->route_list);

	llist_add_tail(&acl->list, &smsc->acl_list);

	return acl;
}

void smpp_acl_delete(struct osmo_smpp_acl *acl)
{
	struct osmo_smpp_route *r, *r2;

	llist_del(&acl->list);

	/* kill any active ESMEs */
	if (acl->esme) {
		struct osmo_esme *esme = acl->esme;
		osmo_fd_unregister(&esme->wqueue.bfd);
		close(esme->wqueue.bfd.fd);
		esme->wqueue.bfd.fd = -1;
		esme->acl = NULL;
		smpp_esme_put(esme);
	}

	/* delete all routes for this ACL */
	llist_for_each_entry_safe(r, r2, &acl->route_list, list) {
		llist_del(&r->list);
		llist_del(&r->global_list);
		talloc_free(r);
	}

	talloc_free(acl);
}

static struct osmo_smpp_route *route_alloc(struct osmo_smpp_acl *acl)
{
	struct osmo_smpp_route *r;

	r = talloc_zero(acl, struct osmo_smpp_route);
	if (!r)
		return NULL;

	llist_add_tail(&r->list, &acl->route_list);
	llist_add_tail(&r->global_list, &acl->smsc->route_list);

	return r;
}

int smpp_route_pfx_add(struct osmo_smpp_acl *acl,
			const struct osmo_smpp_addr *pfx)
{
	struct osmo_smpp_route *r;

	llist_for_each_entry(r, &acl->route_list, list) {
		if (r->type == SMPP_ROUTE_PREFIX &&
		    smpp_addr_eq(&r->u.prefix, pfx))
			return -EEXIST;
	}

	r = route_alloc(acl);
	if (!r)
		return -ENOMEM;
	r->type = SMPP_ROUTE_PREFIX;
	r->acl = acl;
	memcpy(&r->u.prefix, pfx, sizeof(r->u.prefix));

	return 0;
}

int smpp_route_pfx_del(struct osmo_smpp_acl *acl,
		       const struct osmo_smpp_addr *pfx)
{
	struct osmo_smpp_route *r, *r2;

	llist_for_each_entry_safe(r, r2, &acl->route_list, list) {
		if (r->type == SMPP_ROUTE_PREFIX &&
		    smpp_addr_eq(&r->u.prefix, pfx)) {
			llist_del(&r->list);
			talloc_free(r);
			return 0;
		}
	}

	return -ENODEV;
}


/*! \brief increaes the use/reference count */
void smpp_esme_get(struct osmo_esme *esme)
{
	esme->use++;
}

static void esme_destroy(struct osmo_esme *esme)
{
	osmo_wqueue_clear(&esme->wqueue);
	if (esme->wqueue.bfd.fd >= 0) {
		osmo_fd_unregister(&esme->wqueue.bfd);
		close(esme->wqueue.bfd.fd);
	}
	smpp_cmd_flush_pending(esme);
	llist_del(&esme->list);
	talloc_free(esme);
}

static uint32_t esme_inc_seq_nr(struct osmo_esme *esme)
{
	esme->own_seq_nr++;
	if (esme->own_seq_nr > 0x7fffffff)
		esme->own_seq_nr = 1;

	return esme->own_seq_nr;
}

/*! \brief decrease the use/reference count, free if it is 0 */
void smpp_esme_put(struct osmo_esme *esme)
{
	esme->use--;
	if (esme->use <= 0)
		esme_destroy(esme);
}

/*! \brief try to find a SMPP route (ESME) for given destination */
int smpp_route(const struct smsc *smsc, const struct osmo_smpp_addr *dest, struct osmo_esme **pesme)
{
	struct osmo_smpp_route *r;
	struct osmo_smpp_acl *acl = NULL;

	DEBUGP(DSMPP, "Looking up route for (%u/%u/%s)\n",
		dest->ton, dest->npi, dest->addr);

	/* search for a specific route */
	llist_for_each_entry(r, &smsc->route_list, global_list) {
		switch (r->type) {
		case SMPP_ROUTE_PREFIX:
			DEBUGP(DSMPP, "Checking prefix route (%u/%u/%s)->%s\n",
				r->u.prefix.ton, r->u.prefix.npi, r->u.prefix.addr,
				r->acl->system_id);
			if (r->u.prefix.ton == dest->ton &&
			    r->u.prefix.npi == dest->npi &&
			    !strncmp(r->u.prefix.addr, dest->addr,
				     strlen(r->u.prefix.addr))) {
				DEBUGP(DSMPP, "Found prefix route ACL\n");
				acl = r->acl;
			}
			break;
		default:
			break;
		}

		if (acl)
			break;
	}

	if (!acl) {
		/* check for default route */
		if (smsc->def_route) {
			DEBUGP(DSMPP, "Using existing default route\n");
			acl = smsc->def_route;
		}
	}

	if (acl && acl->esme) {
		struct osmo_esme *esme;
		DEBUGP(DSMPP, "ACL even has ESME, we can route to it!\n");
		esme = acl->esme;
		if (esme->bind_flags & ESME_BIND_RX) {
			*pesme = esme;
			return 0;
		} else
			LOGP(DSMPP, LOGL_NOTICE, "[%s] is matching route, "
			     "but not bound for Rx, discarding MO SMS\n",
				     esme->system_id);
	}

	*pesme = NULL;
	if (acl)
		return GSM48_CC_CAUSE_NETWORK_OOO;
	else
		return GSM48_CC_CAUSE_UNASSIGNED_NR;
}


/*! \brief initialize the libsmpp34 data structure for a response */
#define INIT_RESP(type, resp, req) 		{ \
	memset((resp), 0, sizeof(*(resp)));	  \
	(resp)->command_length	= 0;		  \
	(resp)->command_id	= type;		  \
	(resp)->command_status	= ESME_ROK;	  \
	(resp)->sequence_number	= (req)->sequence_number;	\
}

/*! \brief pack a libsmpp34 data strcutrure and send it to the ESME */
#define PACK_AND_SEND(esme, ptr)	pack_and_send(esme, (ptr)->command_id, ptr)
static int pack_and_send(struct osmo_esme *esme, uint32_t type, void *ptr)
{
	struct msgb *msg = msgb_alloc(4096, "SMPP_Tx");
	int rc, rlen;
	if (!msg)
		return -ENOMEM;

	rc = smpp34_pack(type, msg->tail, msgb_tailroom(msg), &rlen, ptr);
	if (rc != 0) {
		LOGP(DSMPP, LOGL_ERROR, "[%s] Error during smpp34_pack(): %s\n",
		     esme->system_id, smpp34_strerror);
		msgb_free(msg);
		return -EINVAL;
	}
	msgb_put(msg, rlen);

	if (osmo_wqueue_enqueue(&esme->wqueue, msg) != 0) {
		LOGP(DSMPP, LOGL_ERROR, "[%s] Write queue full. Dropping message\n",
		     esme->system_id);
		msgb_free(msg);
		return -EAGAIN;
	}
	return 0;
}

/*! \brief transmit a generic NACK to a remote ESME */
static int smpp_tx_gen_nack(struct osmo_esme *esme, uint32_t seq, uint32_t status)
{
	struct generic_nack_t nack;
	char buf[SMALL_BUFF];

	nack.command_length = 0;
	nack.command_id = GENERIC_NACK;
	nack.sequence_number = seq;
	nack.command_status = status;

	LOGP(DSMPP, LOGL_ERROR, "[%s] Tx GENERIC NACK: %s\n",
	     esme->system_id, str_command_status(status, buf));

	return PACK_AND_SEND(esme, &nack);
}

/*! \brief retrieve SMPP command ID from a msgb */
static inline uint32_t smpp_msgb_cmdid(struct msgb *msg)
{
	uint8_t *tmp = msgb_data(msg) + 4;
	return ntohl(*(uint32_t *)tmp);
}

/*! \brief retrieve SMPP sequence number from a msgb */
static inline uint32_t smpp_msgb_seq(struct msgb *msg)
{
	uint8_t *tmp = msgb_data(msg);
	return ntohl(*(uint32_t *)tmp);
}

/*! \brief handle an incoming SMPP generic NACK */
static int smpp_handle_gen_nack(struct osmo_esme *esme, struct msgb *msg)
{
	struct generic_nack_t nack;
	char buf[SMALL_BUFF];
	int rc;

	SMPP34_UNPACK(rc, GENERIC_NACK, &nack, msgb_data(msg),
			 msgb_length(msg));
	if (rc < 0) {
		LOGP(DSMPP, LOGL_ERROR, "[%s] Error in smpp34_unpack():%s\n",
			esme->system_id, smpp34_strerror);
		return rc;
	}

	LOGP(DSMPP, LOGL_ERROR, "[%s] Rx GENERIC NACK: %s\n",
	     esme->system_id, str_command_status(nack.command_status, buf));

	return 0;
}

static int _process_bind(struct osmo_esme *esme, uint8_t if_version,
			 uint32_t bind_flags, const char *sys_id,
			 const char *passwd)
{
	struct osmo_smpp_acl *acl;

	if (if_version != SMPP_VERSION)
		return ESME_RSYSERR;

	if (esme->bind_flags)
		return ESME_RALYBND;

	esme->smpp_version = if_version;
	snprintf(esme->system_id, sizeof(esme->system_id), "%s", sys_id);

	acl = smpp_acl_by_system_id(esme->smsc, esme->system_id);
	if (!esme->smsc->accept_all) {
		if (!acl) {
			/* This system is unknown */
			return ESME_RINVSYSID;
		} else {
			if (strlen(acl->passwd) &&
			    strcmp(acl->passwd, passwd)) {
				return ESME_RINVPASWD;
			}
		}
	}
	if (acl) {
		esme->acl = acl;
		acl->esme = esme;
	}

	esme->bind_flags = bind_flags;

	return ESME_ROK;
}


/*! \brief handle an incoming SMPP BIND RECEIVER */
static int smpp_handle_bind_rx(struct osmo_esme *esme, struct msgb *msg)
{
	struct bind_receiver_t bind;
	struct bind_receiver_resp_t bind_r;
	int rc;

	SMPP34_UNPACK(rc, BIND_RECEIVER, &bind, msgb_data(msg),
			   msgb_length(msg));
	if (rc < 0) {
		LOGP(DSMPP, LOGL_ERROR, "[%s] Error in smpp34_unpack():%s\n",
			esme->system_id, smpp34_strerror);
		return rc;
	}

	INIT_RESP(BIND_TRANSMITTER_RESP, &bind_r, &bind);

	LOGP(DSMPP, LOGL_INFO, "[%s] Rx BIND Rx from (Version %02x)\n",
		bind.system_id, bind.interface_version);

	rc = _process_bind(esme, bind.interface_version, ESME_BIND_RX,
			   (const char *)bind.system_id, (const char *)bind.password);
	bind_r.command_status = rc;

	return PACK_AND_SEND(esme, &bind_r);
}

/*! \brief handle an incoming SMPP BIND TRANSMITTER */
static int smpp_handle_bind_tx(struct osmo_esme *esme, struct msgb *msg)
{
	struct bind_transmitter_t bind;
	struct bind_transmitter_resp_t bind_r;
	struct tlv_t tlv;
	int rc;

	SMPP34_UNPACK(rc, BIND_TRANSMITTER, &bind, msgb_data(msg),
			   msgb_length(msg));
	if (rc < 0) {
		LOGP(DSMPP, LOGL_ERROR, "[%s] Error in smpp34_unpack():%s\n",
			esme->system_id, smpp34_strerror);
		return rc;
	}

	INIT_RESP(BIND_TRANSMITTER_RESP, &bind_r, &bind);

	LOGP(DSMPP, LOGL_INFO, "[%s] Rx BIND Tx (Version %02x)\n",
		bind.system_id, bind.interface_version);

	rc = _process_bind(esme, bind.interface_version, ESME_BIND_TX,
			   (const char *)bind.system_id, (const char *)bind.password);
	bind_r.command_status = rc;

	/* build response */
	snprintf((char *)bind_r.system_id, sizeof(bind_r.system_id), "%s",
		 esme->smsc->system_id);

	/* add interface version TLV */
	tlv.tag = TLVID_sc_interface_version;
	tlv.length = sizeof(uint8_t);
	tlv.value.val16 = esme->smpp_version;
	build_tlv(&bind_r.tlv, &tlv);

	return PACK_AND_SEND(esme, &bind_r);
}

/*! \brief handle an incoming SMPP BIND TRANSCEIVER */
static int smpp_handle_bind_trx(struct osmo_esme *esme, struct msgb *msg)
{
	struct bind_transceiver_t bind;
	struct bind_transceiver_resp_t bind_r;
	int rc;

	SMPP34_UNPACK(rc, BIND_TRANSCEIVER, &bind, msgb_data(msg),
			   msgb_length(msg));
	if (rc < 0) {
		LOGP(DSMPP, LOGL_ERROR, "[%s] Error in smpp34_unpack():%s\n",
			esme->system_id, smpp34_strerror);
		return rc;
	}

	INIT_RESP(BIND_TRANSCEIVER_RESP, &bind_r, &bind);

	LOGP(DSMPP, LOGL_INFO, "[%s] Rx BIND Trx (Version %02x)\n",
		bind.system_id, bind.interface_version);

	rc = _process_bind(esme, bind.interface_version, ESME_BIND_RX|ESME_BIND_TX,
			   (const char *)bind.system_id, (const char *)bind.password);
	bind_r.command_status = rc;

	return PACK_AND_SEND(esme, &bind_r);
}

/*! \brief handle an incoming SMPP UNBIND */
static int smpp_handle_unbind(struct osmo_esme *esme, struct msgb *msg)
{
	struct unbind_t unbind;
	struct unbind_resp_t unbind_r;
	int rc;

	SMPP34_UNPACK(rc, UNBIND, &unbind, msgb_data(msg),
			   msgb_length(msg));
	if (rc < 0) {
		LOGP(DSMPP, LOGL_ERROR, "[%s] Error in smpp34_unpack():%s\n",
			esme->system_id, smpp34_strerror);
		return rc;
	}

	INIT_RESP(UNBIND_RESP, &unbind_r, &unbind);

	LOGP(DSMPP, LOGL_INFO, "[%s] Rx UNBIND\n", esme->system_id);

	if (esme->bind_flags == 0) {
		unbind_r.command_status = ESME_RINVBNDSTS;
		goto err;
	}

	esme->bind_flags = 0;
err:
	return PACK_AND_SEND(esme, &unbind_r);
}

/*! \brief handle an incoming SMPP ENQUIRE LINK */
static int smpp_handle_enq_link(struct osmo_esme *esme, struct msgb *msg)
{
	struct enquire_link_t enq;
	struct enquire_link_resp_t enq_r;
	int rc;

	SMPP34_UNPACK(rc, ENQUIRE_LINK, &enq, msgb_data(msg),
			   msgb_length(msg));
	if (rc < 0) {
		LOGP(DSMPP, LOGL_ERROR, "[%s] Error in smpp34_unpack():%s\n",
			esme->system_id, smpp34_strerror);
		return rc;
	}

	LOGP(DSMPP, LOGL_DEBUG, "[%s] Rx Enquire Link\n", esme->system_id);

	INIT_RESP(ENQUIRE_LINK_RESP, &enq_r, &enq);

	LOGP(DSMPP, LOGL_DEBUG, "[%s] Tx Enquire Link Response\n", esme->system_id);

	return PACK_AND_SEND(esme, &enq_r);
}

/*! \brief send a SUBMIT-SM RESPONSE to a remote ESME */
int smpp_tx_submit_r(struct osmo_esme *esme, uint32_t sequence_nr,
		     uint32_t command_status, char *msg_id)
{
	struct submit_sm_resp_t submit_r;

	memset(&submit_r, 0, sizeof(submit_r));
	submit_r.command_length	= 0;
	submit_r.command_id	= SUBMIT_SM_RESP;
	submit_r.command_status	= command_status;
	submit_r.sequence_number= sequence_nr;
	snprintf((char *) submit_r.message_id, sizeof(submit_r.message_id), "%s", msg_id);

	return PACK_AND_SEND(esme, &submit_r);
}

static const struct value_string smpp_avail_strs[] = {
	{ 0,	"Available" },
	{ 1,	"Denied" },
	{ 2,	"Unavailable" },
	{ 0,	NULL }
};

/*! \brief send an ALERT_NOTIFICATION to a remote ESME */
int smpp_tx_alert(struct osmo_esme *esme, uint8_t ton, uint8_t npi,
		  const char *addr, uint8_t avail_status)
{
	struct alert_notification_t alert;
	struct tlv_t tlv;

	memset(&alert, 0, sizeof(alert));
	alert.command_length	= 0;
	alert.command_id	= ALERT_NOTIFICATION;
	alert.command_status	= ESME_ROK;
	alert.sequence_number	= esme_inc_seq_nr(esme);
	alert.source_addr_ton 	= ton;
	alert.source_addr_npi	= npi;
	snprintf((char *)alert.source_addr, sizeof(alert.source_addr), "%s", addr);

	tlv.tag = TLVID_ms_availability_status;
	tlv.length = sizeof(uint8_t);
	tlv.value.val08 = avail_status;
	build_tlv(&alert.tlv, &tlv);

	LOGP(DSMPP, LOGL_DEBUG, "[%s] Tx ALERT_NOTIFICATION (%s/%u/%u): %s\n",
		esme->system_id, alert.source_addr, alert.source_addr_ton,
		alert.source_addr_npi,
		get_value_string(smpp_avail_strs, avail_status));

	return PACK_AND_SEND(esme, &alert);
}

/* \brief send a DELIVER-SM message to given ESME */
int smpp_tx_deliver(struct osmo_esme *esme, struct deliver_sm_t *deliver)
{
	deliver->sequence_number = esme_inc_seq_nr(esme);

	LOGP(DSMPP, LOGL_DEBUG, "[%s] Tx DELIVER-SM (from %s)\n",
		esme->system_id, deliver->source_addr);

	return PACK_AND_SEND(esme, deliver);
}

/*! \brief handle an incoming SMPP DELIVER-SM RESPONSE */
static int smpp_handle_deliver_resp(struct osmo_esme *esme, struct msgb *msg)
{
	struct deliver_sm_resp_t deliver_r;
	struct osmo_smpp_cmd *cmd;
	int rc;

	memset(&deliver_r, 0, sizeof(deliver_r));
	SMPP34_UNPACK(rc, DELIVER_SM_RESP, &deliver_r, msgb_data(msg),
			   msgb_length(msg));
	if (rc < 0) {
		LOGP(DSMPP, LOGL_ERROR, "[%s] Error in smpp34_unpack():%s\n",
			esme->system_id, smpp34_strerror);
		return rc;
	}

	cmd = smpp_cmd_find_by_seqnum(esme, deliver_r.sequence_number);
	if (!cmd) {
		LOGP(DSMPP, LOGL_ERROR, "[%s] Rx DELIVER-SM RESP !? (%s)\n",
			esme->system_id, get_value_string(smpp_status_strs,
						  deliver_r.command_status));
		return -1;
	}

	if (deliver_r.command_status == ESME_ROK)
		smpp_cmd_ack(cmd);
	else
		smpp_cmd_err(cmd, deliver_r.command_status);

	LOGP(DSMPP, LOGL_INFO, "[%s] Rx DELIVER-SM RESP (%s)\n",
		esme->system_id, get_value_string(smpp_status_strs,
						  deliver_r.command_status));

	return 0;
}

/*! \brief handle an incoming SMPP SUBMIT-SM */
static int smpp_handle_submit(struct osmo_esme *esme, struct msgb *msg)
{
	struct submit_sm_t submit;
	struct submit_sm_resp_t submit_r;
	int rc;

	memset(&submit, 0, sizeof(submit));
	SMPP34_UNPACK(rc, SUBMIT_SM, &submit, msgb_data(msg),
			   msgb_length(msg));
	if (rc < 0) {
		LOGP(DSMPP, LOGL_ERROR, "[%s] Error in smpp34_unpack():%s\n",
			esme->system_id, smpp34_strerror);
		return rc;
	}

	INIT_RESP(SUBMIT_SM_RESP, &submit_r, &submit);

	if (!(esme->bind_flags & ESME_BIND_TX)) {
		submit_r.command_status = ESME_RINVBNDSTS;
		return PACK_AND_SEND(esme, &submit_r);
	}

	LOGP(DSMPP, LOGL_INFO, "[%s] Rx SUBMIT-SM (%s/%u/%u)\n",
		esme->system_id, submit.destination_addr,
		submit.dest_addr_ton, submit.dest_addr_npi);

	INIT_RESP(SUBMIT_SM_RESP, &submit_r, &submit);

	rc = handle_smpp_submit(esme, &submit, &submit_r);
	if (rc == 0)
		return PACK_AND_SEND(esme, &submit_r);

	return rc;
}

/*! \brief one complete SMPP PDU from the ESME has been received */
static int smpp_pdu_rx(struct osmo_esme *esme, struct msgb *msg __uses)
{
	uint32_t cmd_id = smpp_msgb_cmdid(msg);
	int rc = 0;

	LOGP(DSMPP, LOGL_DEBUG, "[%s] smpp_pdu_rx(%s)\n", esme->system_id,
	     osmo_hexdump(msgb_data(msg), msgb_length(msg)));

	switch (cmd_id) {
	case GENERIC_NACK:
		rc = smpp_handle_gen_nack(esme, msg);
		break;
	case BIND_RECEIVER:
		rc = smpp_handle_bind_rx(esme, msg);
		break;
	case BIND_TRANSMITTER:
		rc = smpp_handle_bind_tx(esme, msg);
		break;
	case BIND_TRANSCEIVER:
		rc = smpp_handle_bind_trx(esme, msg);
		break;
	case UNBIND:
		rc = smpp_handle_unbind(esme, msg);
		break;
	case ENQUIRE_LINK:
		rc = smpp_handle_enq_link(esme, msg);
		break;
	case SUBMIT_SM:
		rc = smpp_handle_submit(esme, msg);
		break;
	case DELIVER_SM_RESP:
		rc = smpp_handle_deliver_resp(esme, msg);
		break;
	case DELIVER_SM:
		break;
	case DATA_SM:
		break;
	case CANCEL_SM:
	case QUERY_SM:
	case REPLACE_SM:
	case SUBMIT_MULTI:
		LOGP(DSMPP, LOGL_NOTICE, "[%s] Unimplemented PDU Command "
		     "0x%08x\n", esme->system_id, cmd_id);
		break;
	default:
		LOGP(DSMPP, LOGL_ERROR, "[%s] Unknown PDU Command 0x%08x\n",
		     esme->system_id, cmd_id);
		rc = smpp_tx_gen_nack(esme, smpp_msgb_seq(msg), ESME_RINVCMDID);
		break;
	}

	return rc;
}

/* This macro should be called after a call to read() in the read_cb of an
 * osmo_fd to properly check for errors.
 * rc is the return value of read, err_label is the label to jump to in case of
 * an error. The code there should handle closing the connection.
 * FIXME: This code should go in libosmocore utils.h so it can be used by other
 * projects as well.
 * */
#define OSMO_FD_CHECK_READ(rc, err_label) \
	if (rc < 0) { \
		/* EINTR is a non-fatal error, just try again */ \
		if (errno == EINTR) \
			return 0; \
		goto err_label; \
	} else if (rc == 0) { \
		goto err_label; \
	}

/* !\brief call-back when per-ESME TCP socket has some data to be read */
static int esme_link_read_cb(struct osmo_fd *ofd)
{
	struct osmo_esme *esme = ofd->data;
	uint32_t len;
	uint8_t *lenptr = (uint8_t *) &len;
	uint8_t *cur;
	struct msgb *msg;
	ssize_t rdlen, rc;

	switch (esme->read_state) {
	case READ_ST_IN_LEN:
		rdlen = sizeof(uint32_t) - esme->read_idx;
		rc = read(ofd->fd, lenptr + esme->read_idx, rdlen);
		if (rc < 0)
			LOGP(DSMPP, LOGL_ERROR, "[%s] read returned %zd (%s)\n",
					esme->system_id, rc, strerror(errno));
		OSMO_FD_CHECK_READ(rc, dead_socket);

		esme->read_idx += rc;

		if (esme->read_idx >= sizeof(uint32_t)) {
			esme->read_len = ntohl(len);
			if (esme->read_len < 8 || esme->read_len > UINT16_MAX) {
				LOGP(DSMPP, LOGL_ERROR, "[%s] length invalid %u\n",
						esme->system_id, esme->read_len);
				goto dead_socket;
			}

			msg = msgb_alloc(esme->read_len, "SMPP Rx");
			if (!msg)
				return -ENOMEM;
			esme->read_msg = msg;
			cur = msgb_put(msg, sizeof(uint32_t));
			memcpy(cur, lenptr, sizeof(uint32_t));
			esme->read_state = READ_ST_IN_MSG;
			esme->read_idx = sizeof(uint32_t);
		}
		break;
	case READ_ST_IN_MSG:
		msg = esme->read_msg;
		rdlen = esme->read_len - esme->read_idx;
		rc = read(ofd->fd, msg->tail, OSMO_MIN(rdlen, msgb_tailroom(msg)));
		if (rc < 0)
			LOGP(DSMPP, LOGL_ERROR, "[%s] read returned %zd (%s)\n",
					esme->system_id, rc, strerror(errno));
		OSMO_FD_CHECK_READ(rc, dead_socket);

		esme->read_idx += rc;
		msgb_put(msg, rc);

		if (esme->read_idx >= esme->read_len) {
			rc = smpp_pdu_rx(esme, esme->read_msg);
			msgb_free(esme->read_msg);
			esme->read_msg = NULL;
			esme->read_idx = 0;
			esme->read_len = 0;
			esme->read_state = READ_ST_IN_LEN;
		}
		break;
	}

	return 0;
dead_socket:
	msgb_free(esme->read_msg);
	osmo_fd_unregister(&esme->wqueue.bfd);
	close(esme->wqueue.bfd.fd);
	esme->wqueue.bfd.fd = -1;
	smpp_esme_put(esme);

	return 0;
}

/* call-back of write queue once it wishes to write a message to the socket */
static int esme_link_write_cb(struct osmo_fd *ofd, struct msgb *msg)
{
	struct osmo_esme *esme = ofd->data;
	int rc;

	rc = write(ofd->fd, msgb_data(msg), msgb_length(msg));
	if (rc == 0) {
		osmo_fd_unregister(&esme->wqueue.bfd);
		close(esme->wqueue.bfd.fd);
		esme->wqueue.bfd.fd = -1;
		smpp_esme_put(esme);
	} else if (rc < msgb_length(msg)) {
		LOGP(DSMPP, LOGL_ERROR, "[%s] Short write\n", esme->system_id);
		return -1;
	}

	return 0;
}

/* callback for already-accepted new TCP socket */
static int link_accept_cb(struct smsc *smsc, int fd,
			  struct sockaddr_storage *s, socklen_t s_len)
{
	struct osmo_esme *esme = talloc_zero(smsc, struct osmo_esme);
	if (!esme) {
		close(fd);
		return -ENOMEM;
	}

	INIT_LLIST_HEAD(&esme->smpp_cmd_list);
	smpp_esme_get(esme);
	esme->own_seq_nr = rand();
	esme_inc_seq_nr(esme);
	esme->smsc = smsc;
	osmo_wqueue_init(&esme->wqueue, 10);
	esme->wqueue.bfd.fd = fd;
	esme->wqueue.bfd.data = esme;
	esme->wqueue.bfd.when = BSC_FD_READ;

	if (osmo_fd_register(&esme->wqueue.bfd) != 0) {
		close(fd);
		talloc_free(esme);
		return -EIO;
	}

	esme->wqueue.read_cb = esme_link_read_cb;
	esme->wqueue.write_cb = esme_link_write_cb;

	esme->sa_len = OSMO_MIN(sizeof(esme->sa), s_len);
	memcpy(&esme->sa, s, esme->sa_len);

	llist_add_tail(&esme->list, &smsc->esme_list);

	return 0;
}

/* callback of listening TCP socket */
static int smsc_fd_cb(struct osmo_fd *ofd, unsigned int what)
{
	int rc;
	struct sockaddr_storage sa;
	socklen_t sa_len = sizeof(sa);

	rc = accept(ofd->fd, (struct sockaddr *)&sa, &sa_len);
	if (rc < 0) {
		LOGP(DSMPP, LOGL_ERROR, "Accept returns %d (%s)\n",
		     rc, strerror(errno));
		return rc;
	}
	return link_accept_cb(ofd->data, rc, &sa, sa_len);
}

/*! \brief allocate and initialize an smsc struct from talloc context ctx. */
struct smsc *smpp_smsc_alloc_init(void *ctx)
{
	struct smsc *smsc = talloc_zero(ctx, struct smsc);

	INIT_LLIST_HEAD(&smsc->esme_list);
	INIT_LLIST_HEAD(&smsc->acl_list);
	INIT_LLIST_HEAD(&smsc->route_list);

	smsc->listen_ofd.data = smsc;
	smsc->listen_ofd.cb = smsc_fd_cb;

	return smsc;
}

/*! \brief Set the SMPP address and port without binding. */
int smpp_smsc_conf(struct smsc *smsc, const char *bind_addr, uint16_t port)
{
	talloc_free((void*)smsc->bind_addr);
	smsc->bind_addr = NULL;
	if (bind_addr) {
		smsc->bind_addr = talloc_strdup(smsc, bind_addr);
		if (!smsc->bind_addr)
			return -ENOMEM;
	}
	smsc->listen_port = port;
	return 0;
}

/*! \brief Bind to given address and port and accept connections.
 * \param[in] bind_addr Local IP address, may be NULL for any.
 * \param[in] port TCP port number, may be 0 for default SMPP (2775).
 */
int smpp_smsc_start(struct smsc *smsc, const char *bind_addr, uint16_t port)
{
	int rc;

	/* default port for SMPP */
	if (!port)
		port = 2775;

	smpp_smsc_stop(smsc);

	LOGP(DSMPP, LOGL_NOTICE, "SMPP at %s %d\n",
	     bind_addr? bind_addr : "0.0.0.0", port);

	rc = osmo_sock_init_ofd(&smsc->listen_ofd, AF_UNSPEC, SOCK_STREAM,
				IPPROTO_TCP, bind_addr, port,
				OSMO_SOCK_F_BIND);
	if (rc < 0)
		return rc;

	/* store new address and port */
	rc = smpp_smsc_conf(smsc, bind_addr, port);
	if (rc)
		smpp_smsc_stop(smsc);
	return rc;
}

/*! \brief Change a running connection to a different address/port, and upon
 * error switch back to the running configuration. */
int smpp_smsc_restart(struct smsc *smsc, const char *bind_addr, uint16_t port)
{
	int rc;

	rc = smpp_smsc_start(smsc, bind_addr, port);
	if (rc)
		/* if there is an error, try to re-bind to the old port */
		return smpp_smsc_start(smsc, smsc->bind_addr, smsc->listen_port);
	return 0;
}

/*! /brief Close SMPP connection. */
void smpp_smsc_stop(struct smsc *smsc)
{
	if (smsc->listen_ofd.fd > 0) {
		close(smsc->listen_ofd.fd);
		smsc->listen_ofd.fd = 0;
		osmo_fd_unregister(&smsc->listen_ofd);
	}
}
