/* OpenBSC SMPP 3.4 interface, SMSC-side implementation */

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

#include <smpp34.h>
#include <smpp34_structs.h>
#include <smpp34_params.h>

#include <osmocom/core/utils.h>
#include <osmocom/core/msgb.h>
#include <osmocom/core/logging.h>
#include <osmocom/core/talloc.h>
#include <osmocom/gsm/protocol/gsm_04_11.h>

#include <openbsc/gsm_subscriber.h>
#include <openbsc/debug.h>
#include <openbsc/db.h>
#include <openbsc/gsm_04_11.h>
#include <openbsc/gsm_data.h>
#include <openbsc/signal.h>

#include "smpp_smsc.h"

/*! \brief find gsm_subscriber for a given SMPP NPI/TON/Address */
static struct gsm_subscriber *subscr_by_dst(struct gsm_network *net,
					    uint8_t npi, uint8_t ton, const char *addr)
{
	struct gsm_subscriber *subscr = NULL;

	switch (npi) {
	case NPI_Land_Mobile_E212:
		subscr = subscr_get_by_imsi(net, addr);
		break;
	case NPI_ISDN_E163_E164:
	case NPI_Private:
		subscr = subscr_get_by_extension(net, addr);
		break;
	default:
		LOGP(DSMPP, LOGL_NOTICE, "Unsupported NPI: %u\n", npi);
		break;
	}

	return subscr;
}

/*! \brief find a TLV with given tag in list of libsmpp34 TLVs */
static struct tlv_t *find_tlv(struct tlv_t *head, uint16_t tag)
{
	struct tlv_t *t;

	for (t = head; t != NULL; t = t->next) {
		if (t->tag == tag)
			return t;
	}
	return NULL;
}

/*! \brief convert from submit_sm_t to gsm_sms */
static int submit_to_sms(struct gsm_sms **psms, struct gsm_network *net,
			 const struct submit_sm_t *submit)
{
	struct gsm_subscriber *dest;
	struct gsm_sms *sms;
	struct tlv_t *t;
	const uint8_t *sms_msg;
	unsigned int sms_msg_len;

	dest = subscr_by_dst(net, submit->dest_addr_npi,
			     submit->dest_addr_ton,
			     (const char *)submit->destination_addr);
	if (!dest) {
		LOGP(DSMS, LOGL_NOTICE, "SMPP SUBMIT-SM for unknown subscriber: "
		     "%s (NPI=%u)\n", submit->destination_addr,
		     submit->dest_addr_npi);
		return ESME_RINVDSTADR;
	}

	t = find_tlv(submit->tlv, TLVID_message_payload);
	if (t) {
		if (submit->sm_length) {
			/* ERROR: we cannot have botH! */
			LOGP(DSMS, LOGL_ERROR, "SMPP Cannot have payload in "
				"TLV _and_ in the header\n");
			return ESME_ROPTPARNOTALLWD;
		}
		sms_msg = t->value.octet;
		sms_msg_len = t->length;
	} else if (submit->short_message && submit->sm_length) {
		sms_msg = submit->short_message;
		sms_msg_len = submit->sm_length;
	} else {
		sms_msg = NULL;
		sms_msg_len = 0;
	}

	sms = sms_alloc();
	sms->source = SMS_SOURCE_SMPP;
	sms->smpp.sequence_nr = submit->sequence_number;

	/* fill in the destination address */
	sms->receiver = dest;
	sms->dst.ton = submit->dest_addr_ton;
	sms->dst.npi = submit->dest_addr_npi;
	strncpy(sms->dst.addr, dest->extension, sizeof(sms->dst.addr)-1);

	/* fill in the source address */
	sms->sender = subscr_get_by_id(net, 1);
	sms->src.ton = submit->source_addr_ton;
	sms->src.npi = submit->source_addr_npi;
	strncpy(sms->src.addr, (char *)submit->source_addr, sizeof(sms->src.addr)-1);

	if (submit->esm_class & 0x40)
		sms->ud_hdr_ind = 1;

	if (submit->esm_class & 0x80) {
		sms->reply_path_req = 1;
#warning Implement reply path
	}

	if (submit->data_coding == 0x00 ||	/* SMSC default */
	    submit->data_coding == 0x01 ||	/* GSM default alphabet */
	    (submit->data_coding & 0xFC) == 0xF0) { /* 03.38 DCS default */
		uint8_t ud_len = 0;
		sms->data_coding_scheme = GSM338_DCS_1111_7BIT;
		if (sms->ud_hdr_ind) {
			ud_len = *sms_msg + 1;
			printf("copying %u bytes user data...\n", ud_len);
			memcpy(sms->user_data, sms_msg,
				OSMO_MIN(ud_len, sizeof(sms->user_data)));
			sms_msg += ud_len;
			sms_msg_len -= ud_len;
		}
		strncpy(sms->text, (char *)sms_msg,
			OSMO_MIN(sizeof(sms->text)-1, sms_msg_len));
		printf("encoding 7bit to offset %u text(%s)\n", ud_len, sms->text);
		sms->user_data_len = gsm_7bit_encode(sms->user_data+ud_len, sms->text);
	} else if (submit->data_coding == 0x02 ||
		   submit->data_coding == 0x04 ||
		   (submit->data_coding & 0xFC) == 0xF4) { /* 03.38 DCS 8bit */
		/* 8-bit binary */
		sms->data_coding_scheme = GSM338_DCS_1111_8BIT_DATA;
		memcpy(sms->user_data, sms_msg, sms_msg_len);
		sms->user_data_len = sms_msg_len;
	} else if (submit->data_coding == 0x80) {
		/* UCS-2 */
		sms->data_coding_scheme = (2 << 2);
		memcpy(sms->user_data, sms_msg, submit->sm_length);
		sms->user_data_len = sms_msg_len;
	} else {
		sms_free(sms);
		LOGP(DSMS, LOGL_ERROR, "SMPP Unknown Data Coding 0x%02x\n",
			submit->data_coding);
		return ESME_RUNKNOWNERR;
	}

	*psms = sms;
	return ESME_ROK;
}

/*! \brief handle incoming libsmpp34 ssubmit_sm_t from remote ESME */
int handle_smpp_submit(struct osmo_esme *esme, struct submit_sm_t *submit,
		       struct submit_sm_resp_t *submit_r)
{
	struct gsm_sms *sms;
	int rc = -1;

	rc = submit_to_sms(&sms, esme->smsc->priv, submit);
	if (rc != ESME_ROK) {
		submit_r->command_status = rc;
		return 0;
	}
	smpp_esme_get(esme);
	sms->smpp.esme = esme;
	sms->protocol_id = submit->protocol_id;

	switch (submit->esm_class & 3) {
	case 0: /* default */
	case 1: /* datagram */
	case 3: /* store-and-forward */
		rc = db_sms_store(sms);
		if (rc < 0) {
			LOGP(DSMS, LOGL_ERROR, "SMPP SUBMIT-SM: Unable to "
				"store SMS in database\n");
			sms_free(sms);
			submit_r->command_status = ESME_RSYSERR;
			return 0;
		}
		strcpy((char *)submit_r->message_id, "msg_id_not_implemented");
		LOGP(DSMS, LOGL_INFO, "SMPP SUBMIT-SM: Stored in DB\n");
		rc = 0;
		break;
	case 2: /* forward (i.e. transaction) mode */
		LOGP(DSMS, LOGL_DEBUG, "SMPP SUBMIT-SM: Forwarding in "
			"real time (Transaction/Forward mode)\n");
		sms->smpp.transaction_mode = 1;
		gsm411_send_sms_subscr(sms->receiver, sms);
		rc = 1; /* don't send any response yet */
		break;
	}
	return rc;
}

/*! \brief signal handler for status of attempted SMS deliveries */
static int smpp_sms_cb(unsigned int subsys, unsigned int signal,
			void *handler_data, void *signal_data)
{
	struct sms_signal_data *sig_sms = signal_data;
	struct gsm_sms *sms = sig_sms->sms;
	int rc = 0;

	if (!sms)
		return 0;

	if (sms->source != SMS_SOURCE_SMPP)
		return 0;

	switch (signal) {
	case S_SMS_UNKNOWN_ERROR:
		if (sms->smpp.transaction_mode) {
			/* Send back the SUBMIT-SM response with apropriate error */
			LOGP(DSMS, LOGL_INFO, "SMPP SUBMIT-SM: Error\n");
			rc = smpp_tx_submit_r(sms->smpp.esme,
					      sms->smpp.sequence_nr,
					      ESME_RDELIVERYFAILURE,
					      sms->smpp.msg_id);
		}
		break;
	case S_SMS_DELIVERED:
		/* SMS layer tells us the delivery has been completed */
		if (sms->smpp.transaction_mode) {
			/* Send back the SUBMIT-SM response */
			LOGP(DSMS, LOGL_INFO, "SMPP SUBMIT-SM: Success\n");
			rc = smpp_tx_submit_r(sms->smpp.esme,
					      sms->smpp.sequence_nr,
					      ESME_ROK, sms->smpp.msg_id);
		}
		break;
	}

	return rc;
}

/*! \brief signal handler for subscriber related signals */
static int smpp_subscr_cb(unsigned int subsys, unsigned int signal,
			  void *handler_data, void *signal_data)
{
	struct gsm_subscriber *subscr = signal_data;
	struct smsc *smsc = handler_data;
	struct osmo_esme *esme;
	uint8_t smpp_avail_status;

	/* determine the smpp_avail_status depending on attach/detach */
	switch (signal) {
	case S_SUBSCR_ATTACHED:
		smpp_avail_status = 0;
		break;
	case S_SUBSCR_DETACHED:
		smpp_avail_status = 2;
		break;
	default:
		return 0;
	}

	llist_for_each_entry(esme, &smsc->esme_list, list) {
		/* we currently send an alert notification to each ESME that is
		 * connected, and do not require a (non-existant) delivery
		 * pending flag to be set before,  FIXME: make this VTY
		 * configurable */
		smpp_tx_alert(esme, TON_Subscriber_Number,
				NPI_Land_Mobile_E212, subscr->imsi,
				smpp_avail_status);
	}

	return 0;
}

static int deliver_to_esme(struct osmo_esme *esme, struct gsm_sms *sms)
{
	struct deliver_sm_t deliver;
	uint8_t dcs;

	memset(&deliver, 0, sizeof(deliver));
	deliver.command_length	= 0;
	deliver.command_id	= DELIVER_SM;
	deliver.command_status	= ESME_ROK;

	strcpy((char *)deliver.service_type, "CMT");
	if (esme->acl && esme->acl->deliver_src_imsi) {
		deliver.source_addr_ton	= TON_Subscriber_Number;
		deliver.source_addr_npi = NPI_Land_Mobile_E212;
		snprintf((char *)deliver.source_addr,
			sizeof(deliver.source_addr), "%s",
			sms->sender->imsi);
	} else {
		deliver.source_addr_ton = TON_Network_Specific;
		deliver.source_addr_npi = NPI_ISDN_E163_E164;
		snprintf((char *)deliver.source_addr,
			 sizeof(deliver.source_addr), "%s",
			 sms->sender->extension);
	}

	deliver.dest_addr_ton	= sms->dst.ton;
	deliver.dest_addr_npi	= sms->dst.npi;
	memcpy(deliver.destination_addr, sms->dst.addr,
		sizeof(deliver.destination_addr));

	deliver.esm_class	= 1;	/* datagram mode */
	if (sms->ud_hdr_ind)
		deliver.esm_class |= 0x40;
	if (sms->reply_path_req)
		deliver.esm_class |= 0x80;

	deliver.protocol_id 	= sms->protocol_id;
	deliver.priority_flag	= 0;
	deliver.registered_delivery = 0;

	dcs = sms->data_coding_scheme;
	if (dcs == GSM338_DCS_1111_7BIT ||
	   ((dcs & 0xE0000000) == 0 && (dcs & 0xC) == 0)) {
		uint8_t *src = sms->user_data;
		uint8_t *dst = deliver.short_message;
		uint8_t src_byte_len = sms->user_data_len;

		/* SMPP has this strange notion of putting 7bit SMS in
		 * an octet-aligned mode */
		deliver.data_coding = 0x01;
		if (sms->ud_hdr_ind) {
			uint8_t udh_len = sms->user_data[0];
			src += udh_len + 1;
			dst += udh_len + 1;
			src_byte_len -= udh_len + 1;
			memcpy(dst, sms->user_data, udh_len + 1);
			deliver.sm_length = udh_len + 1;
		}
		deliver.sm_length += gsm_7bit_decode((char *)dst, src, src_byte_len);
	} else if (dcs == GSM338_DCS_1111_8BIT_DATA ||
		   ((dcs & 0xE0000000) == 0 && (dcs & 0xC) == 4)) {
		deliver.data_coding = 0x02;
		deliver.sm_length = sms->user_data_len;
		memcpy(deliver.short_message, sms->user_data, deliver.sm_length);
	} else if ((dcs & 0xE0000000) == 0 && (dcs & 0xC) == 8) {
		deliver.data_coding = 0x08;	/* UCS-2 */
		deliver.sm_length = sms->user_data_len;
		memcpy(deliver.short_message, sms->user_data, deliver.sm_length);
	}

	return smpp_tx_deliver(esme, &deliver);
}

static struct smsc *g_smsc;

int smpp_try_deliver(struct gsm_sms *sms)
{
	struct osmo_esme *esme;
	struct osmo_smpp_addr dst;

	memset(&dst, 0, sizeof(dst));
	dst.ton = sms->dst.ton;
	dst.npi = sms->dst.npi;
	memcpy(dst.addr, sms->dst.addr, sizeof(dst.addr));

	esme = smpp_route(g_smsc, &dst);
	if (!esme)
		return 1; /* unknown subscriber */

	return deliver_to_esme(esme, sms);
}

struct smsc *smsc_from_vty(struct vty *v)
{
	/* FIXME: this is ugly */
	return g_smsc;
}

/*! \brief Initialize the OpenBSC SMPP interface */
int smpp_openbsc_init(struct gsm_network *net, uint16_t port)
{
	struct smsc *smsc = talloc_zero(net, struct smsc);
	int rc;

	smsc->priv = net;

	rc = smpp_smsc_init(smsc, port);
	if (rc < 0)
		talloc_free(smsc);

	osmo_signal_register_handler(SS_SMS, smpp_sms_cb, net);
	osmo_signal_register_handler(SS_SUBSCR, smpp_subscr_cb, smsc);

	g_smsc = smsc;

	smpp_vty_init();

	return rc;
}
