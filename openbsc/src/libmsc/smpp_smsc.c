/* SMPP 3.4 interface, SMSC-side implementation */
/* (C) 2012 by Harald Welte <laforge@gnumonks.org>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */


#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>

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

/*! \brief Ugly wrapper. libsmpp34 should do this itself! */
#define SMPP34_UNPACK(rc, type, str, data, len)		\
	memset(str, 0, sizeof(*str));			\
	rc = smpp34_unpack(type, str, data, len)

enum emse_bind {
	ESME_BIND_RX = 0x01,
	ESME_BIND_TX = 0x02,
};

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
	llist_del(&esme->list);
	talloc_free(esme);
}

/*! \brief decrease the use/reference count, free if it is 0 */
void smpp_esme_put(struct osmo_esme *esme)
{
	esme->use--;
	if (esme->use <= 0)
		esme_destroy(esme);
}

static struct osmo_esme *
esme_by_system_id(const struct smsc *smsc, char *system_id)
{
	struct osmo_esme *e;

	llist_for_each_entry(e, &smsc->esme_list, list) {
		if (!strcmp(e->system_id, system_id))
			return e;
	}
	return NULL;
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
		LOGP(DSMPP, LOGL_ERROR, "Error during smpp34_pack(): %s\n",
		     smpp34_strerror);
		msgb_free(msg);
		return -EINVAL;
	}
	msgb_put(msg, rlen);

	return osmo_wqueue_enqueue(&esme->wqueue, msg);
}

/*! \brief transmit a generic NACK to a remote ESME */
static int smpp_tx_gen_nack(struct osmo_esme *esme, uint32_t seq, uint32_t status)
{
	struct generic_nack_t nack;

	nack.command_length = 0;
	nack.command_id = GENERIC_NACK;
	nack.sequence_number = seq;
	nack.command_status = status;

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
	if (rc < 0)
		return rc;

	LOGP(DSMPP, LOGL_ERROR, "%s: GENERIC NACK: %s\n", esme->system_id,
	     str_command_status(nack.command_status, buf));

	return 0;
}

/*! \brief handle an incoming SMPP BIND RECEIVER */
static int smpp_handle_bind_rx(struct osmo_esme *esme, struct msgb *msg)
{
	struct bind_receiver_t bind;
	struct bind_receiver_resp_t bind_r;
	int rc;

	SMPP34_UNPACK(rc, BIND_RECEIVER, &bind, msgb_data(msg),
			   msgb_length(msg));
	if (rc < 0)
		return rc;

	INIT_RESP(BIND_TRANSMITTER_RESP, &bind_r, &bind);

	LOGP(DSMPP, LOGL_INFO, "%s: BIND Rx from (Version %02x)\n",
		bind.system_id, bind.interface_version);

	if (bind.interface_version != SMPP_VERSION) {
		bind_r.command_status = ESME_RSYSERR;
		goto err;
	}

	if (esme->bind_flags) {
		bind_r.command_status = ESME_RALYBND;
		goto err;
	}

	esme->smpp_version = bind.interface_version;
	snprintf(esme->system_id, sizeof(esme->system_id), "%s",
		 bind.system_id);
	esme->bind_flags = ESME_BIND_RX;

	/* FIXME */
err:
	return 0;
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
		printf("error during unpack: %s\n", smpp34_strerror);
		return rc;
	}

	INIT_RESP(BIND_TRANSMITTER_RESP, &bind_r, &bind);

	LOGP(DSMPP, LOGL_INFO, "%s: BIND Tx (Version %02x)\n",
		bind.system_id, bind.interface_version);

	if (bind.interface_version != SMPP_VERSION) {
		bind_r.command_status = ESME_RSYSERR;
		goto err;
	}

	if (esme->bind_flags) {
		bind_r.command_status = ESME_RALYBND;
		goto err;
	}

	esme->smpp_version = bind.interface_version;
	snprintf(esme->system_id, sizeof(esme->system_id), "%s", bind.system_id);
	esme->bind_flags = ESME_BIND_TX;

	/* build response */
	snprintf((char *)bind_r.system_id, sizeof(bind_r.system_id), "%s",
		 esme->smsc->system_id);

	/* add interface version TLV */
	tlv.tag = TLVID_sc_interface_version;
	tlv.length = sizeof(uint8_t);
	tlv.value.val16 = esme->smpp_version;
	build_tlv(&bind_r.tlv, &tlv);

err:
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
	if (rc < 0)
		return rc;

	INIT_RESP(BIND_TRANSMITTER_RESP, &bind_r, &bind);

	LOGP(DSMPP, LOGL_INFO, "%s: BIND Trx (Version %02x)\n",
		bind.system_id, bind.interface_version);

	if (bind.interface_version != SMPP_VERSION) {
		bind_r.command_status = ESME_RSYSERR;
		goto err;
	}

	if (esme->bind_flags) {
		bind_r.command_status = ESME_RALYBND;
		goto err;
	}

	esme->smpp_version = bind.interface_version;
	snprintf(esme->system_id, sizeof(esme->system_id), "%s", bind.system_id);
	esme->bind_flags |= ESME_BIND_TX | ESME_BIND_RX;

	/* FIXME */
err:
	return 0;
}

/*! \brief handle an incoming SMPP UNBIND */
static int smpp_handle_unbind(struct osmo_esme *esme, struct msgb *msg)
{
	struct unbind_t unbind;
	struct unbind_resp_t unbind_r;
	int rc;

	SMPP34_UNPACK(rc, UNBIND, &unbind, msgb_data(msg),
			   msgb_length(msg));
	if (rc < 0)
		return rc;

	INIT_RESP(UNBIND_RESP, &unbind_r, &unbind);

	LOGP(DSMPP, LOGL_INFO, "%s: UNBIND\n", esme->system_id);

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
	if (rc < 0)
		return rc;

	LOGP(DSMPP, LOGL_DEBUG, "%s: Enquire Link\n", esme->system_id);

	INIT_RESP(ENQUIRE_LINK_RESP, &enq_r, &enq);

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
	alert.sequence_number	= esme->own_seq_nr++;
	alert.source_addr_ton 	= ton;
	alert.source_addr_npi	= npi;
	snprintf(alert.source_addr, sizeof(alert.source_addr), "%s", addr);

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

/*! \brief handle an incoming SMPP SUBMIT-SM */
static int smpp_handle_submit(struct osmo_esme *esme, struct msgb *msg)
{
	struct submit_sm_t submit;
	struct submit_sm_resp_t submit_r;
	int rc;

	memset(&submit, 0, sizeof(submit));
	SMPP34_UNPACK(rc, SUBMIT_SM, &submit, msgb_data(msg),
			   msgb_length(msg));
	if (rc < 0)
		return rc;

	INIT_RESP(SUBMIT_SM_RESP, &submit_r, &submit);

	if (!(esme->bind_flags & ESME_BIND_TX)) {
		submit_r.command_status = ESME_RINVBNDSTS;
		return PACK_AND_SEND(esme, &submit_r);
	}

	LOGP(DSMPP, LOGL_INFO, "%s: SUBMIT-SM(%s)\n", esme->system_id,
	     submit.service_type);

	INIT_RESP(SUBMIT_SM_RESP, &submit_r, &submit);

	rc = handle_smpp_submit(esme, &submit, &submit_r);
	if (rc == 0)
		return PACK_AND_SEND(esme, &submit_r);

	return rc;
}

/*! \brief one complete SMPP PDU from the ESME has been received */
static int smpp_pdu_rx(struct osmo_esme *esme, struct msgb *msg)
{
	uint32_t cmd_id = smpp_msgb_cmdid(msg);
	int rc = 0;

	LOGP(DSMPP, LOGL_DEBUG, "%s: smpp_pdu_rx(%s)\n", esme->system_id,
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
	case DELIVER_SM:
		break;
	case DATA_SM:
		break;
	case CANCEL_SM:
	case QUERY_SM:
	case REPLACE_SM:
	case SUBMIT_MULTI:
		LOGP(DSMPP, LOGL_NOTICE, "%s: Unimplemented PDU Commmand "
		     "0x%08x\n", esme->system_id, cmd_id);
		break;
	default:
		LOGP(DSMPP, LOGL_ERROR, "%s: Unknown PDU Command 0x%08x\n",
		     esme->system_id, cmd_id);
		rc = smpp_tx_gen_nack(esme, smpp_msgb_seq(msg), ESME_RINVCMDID);
		break;
	}

	return rc;
}

/* !\brief call-back when per-ESME TCP socket has some data to be read */
static int esme_link_read_cb(struct osmo_fd *ofd)
{
	struct osmo_esme *esme = ofd->data;
	uint32_t len;
	uint8_t *lenptr = (uint8_t *) &len;
	uint8_t *cur;
	struct msgb *msg;
	int rdlen;
	int rc;

	switch (esme->read_state) {
	case READ_ST_IN_LEN:
		rdlen = sizeof(uint32_t) - esme->read_idx;
		rc = read(ofd->fd, lenptr + esme->read_idx, rdlen);
		if (rc < 0) {
			LOGP(DSMPP, LOGL_ERROR, "read returned %d\n", rc);
		} else if (rc == 0) {
			goto dead_socket;
		} else
			esme->read_idx += rc;
		if (esme->read_idx >= sizeof(uint32_t)) {
			esme->read_len = ntohl(len);
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
		if (rc < 0) {
			LOGP(DSMPP, LOGL_ERROR, "read returned %d\n", rc);
		} else if (rc == 0) {
			goto dead_socket;
		} else {
			esme->read_idx += rc;
			msgb_put(msg, rc);
		}

		if (esme->read_idx >= esme->read_len) {
			rc = smpp_pdu_rx(esme, esme->read_msg);
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
static void esme_link_write_cb(struct osmo_fd *ofd, struct msgb *msg)
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
		LOGP(DSMPP, LOGL_ERROR, "%s: Short write\n", esme->system_id);
		return;
	}
}

/* callback for already-accepted new TCP socket */
static int link_accept_cb(struct smsc *smsc, int fd,
			  struct sockaddr_storage *s, socklen_t s_len)
{
	struct osmo_esme *esme = talloc_zero(smsc, struct osmo_esme);
	if (!esme)
		return -ENOMEM;

	smpp_esme_get(esme);
	esme->own_seq_nr = rand();
	esme->smsc = smsc;
	osmo_wqueue_init(&esme->wqueue, 10);
	esme->wqueue.bfd.fd = fd;
	esme->wqueue.bfd.data = esme;
	esme->wqueue.bfd.when = BSC_FD_READ;
	osmo_fd_register(&esme->wqueue.bfd);

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

/*! \brief Initialize the SMSC-side SMPP implementation */
int smpp_smsc_init(struct smsc *smsc, uint16_t port)
{
	int rc;

	INIT_LLIST_HEAD(&smsc->esme_list);
	smsc->listen_ofd.data = smsc;
	smsc->listen_ofd.cb = smsc_fd_cb;
	rc = osmo_sock_init_ofd(&smsc->listen_ofd, AF_UNSPEC, SOCK_STREAM,
				IPPROTO_TCP, NULL, port, OSMO_SOCK_F_BIND);

	return rc;
}
