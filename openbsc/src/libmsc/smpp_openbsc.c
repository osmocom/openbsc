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

struct tlv_t *find_tlv(struct tlv_t *head, uint16_t tag)
{
	struct tlv_t *t;

	for (t = head; t != NULL; t = t->next) {
		if (t->tag == tag)
			return t;
	}
	return NULL;
}

/* convert from submit_sm_t to gsm_sms */
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
	sms->receiver = subscr_get(dest);
	strncpy(sms->dest_addr, dest->extension, sizeof(sms->dest_addr)-1);
	sms->sender = subscr_get_by_id(net, 1);

	if (submit->esm_class & 0x40)
		sms->ud_hdr_ind = 1;

	if (submit->esm_class & 0x80) {
		sms->reply_path_req = 1;
#warning Implement reply path
	}

	switch (submit->data_coding) {
	case 0x00:
	case 0x01: /* GSM default alphabet */
		sms->data_coding_scheme = GSM338_DCS_1111_7BIT;
		strncpy(sms->text, (char *)sms_msg,
			OSMO_MIN(sizeof(sms->text)-1, sms_msg_len));
		sms->user_data_len = gsm_7bit_encode(sms->user_data, sms->text);
		break;
	case 0x02:
	case 0x04: /* 8-bit binary */
		sms->data_coding_scheme = GSM338_DCS_1111_8BIT_DATA;
		memcpy(sms->user_data, sms_msg, sms_msg_len);
		sms->user_data_len = sms_msg_len;
		break;
	case 0x80: /* UCS-2 */
		sms->data_coding_scheme = (2 << 2);
		memcpy(sms->user_data, sms_msg, submit->sm_length);
		sms->user_data_len = sms_msg_len;
		break;
		/* FIXME */
	default:
		sms_free(sms);
		return ESME_RUNKNOWNERR;
	}

	*psms = sms;
	return ESME_ROK;
}

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
	sms->smpp.esme = esme;
	/* FIXME: TP-PID */

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
		sms->smpp.transaction_mode = 1;
		gsm411_send_sms_subscr(sms->receiver, sms);
		rc = 1; /* don't send any response yet */
		break;
	}
	return rc;
}

static int smpp_sms_cb(unsigned int subsys, unsigned int signal,
			void *handler_data, void *signal_data)
{
	struct gsm_network *network = handler_data;
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


int smpp_openbsc_init(struct gsm_network *net, uint16_t port)
{
	struct smsc *smsc = talloc_zero(net, struct smsc);
	int rc;

	smsc->priv = net;

	rc = smpp_smsc_init(smsc, port);
	if (rc < 0)
		talloc_free(smsc);

	osmo_signal_register_handler(SS_SMS, smpp_sms_cb, net);

	return rc;
}

