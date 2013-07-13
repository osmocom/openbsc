/* OpenBSC SMPP 3.4 interface, SMSC-side implementation */

/* (C) 2012-2013 by Harald Welte <laforge@gnumonks.org>
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

#include <smpp34.h>
#include <smpp34_structs.h>
#include <smpp34_params.h>

#include <osmocom/core/utils.h>
#include <osmocom/core/msgb.h>
#include <osmocom/core/logging.h>
#include <osmocom/core/talloc.h>
#include <osmocom/gsm/protocol/gsm_04_11.h>
#include <osmocom/gsm/protocol/smpp34_osmocom.h>

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
	int mode;

	dest = subscr_by_dst(net, submit->dest_addr_npi,
			     submit->dest_addr_ton,
			     (const char *)submit->destination_addr);
	if (!dest) {
		LOGP(DLSMS, LOGL_NOTICE, "SMPP SUBMIT-SM for unknown subscriber: "
		     "%s (NPI=%u)\n", submit->destination_addr,
		     submit->dest_addr_npi);
		return ESME_RINVDSTADR;
	}

	t = find_tlv(submit->tlv, TLVID_message_payload);
	if (t) {
		if (submit->sm_length) {
			/* ERROR: we cannot have botH! */
			LOGP(DLSMS, LOGL_ERROR, "SMPP Cannot have payload in "
				"TLV _and_ in the header\n");
			return ESME_ROPTPARNOTALLWD;
		}
		sms_msg = t->value.octet;
		sms_msg_len = t->length;
	} else if (submit->sm_length) {
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
	    submit->data_coding == 0x01) {	/* GSM default alphabet */
		sms->data_coding_scheme = GSM338_DCS_1111_7BIT;
		mode = MODE_7BIT;
	} else if ((submit->data_coding & 0xFC) == 0xF0) { /* 03.38 DCS default */
		/* pass DCS 1:1 through from SMPP to GSM */
		sms->data_coding_scheme = submit->data_coding;
		mode = MODE_7BIT;
	} else if (submit->data_coding == 0x02 ||
		   submit->data_coding == 0x04) {
		/* 8-bit binary */
		sms->data_coding_scheme = GSM338_DCS_1111_8BIT_DATA;
		mode = MODE_8BIT;
	} else if ((submit->data_coding & 0xFC) == 0xF4) { /* 03.38 DCS 8bit */
		/* pass DCS 1:1 through from SMPP to GSM */
		sms->data_coding_scheme = submit->data_coding;
		mode = MODE_8BIT;
	} else if (submit->data_coding == 0x80) {
		/* UCS-2 */
		sms->data_coding_scheme = (2 << 2);
		mode = MODE_8BIT;
	} else {
		sms_free(sms);
		LOGP(DLSMS, LOGL_ERROR, "SMPP Unknown Data Coding 0x%02x\n",
			submit->data_coding);
		return ESME_RUNKNOWNERR;
	}

	if (mode == MODE_7BIT) {
		uint8_t ud_len = 0, padbits = 0;
		sms->data_coding_scheme = GSM338_DCS_1111_7BIT;
		if (sms->ud_hdr_ind) {
			ud_len = *sms_msg + 1;
			printf("copying %u bytes user data...\n", ud_len);
			memcpy(sms->user_data, sms_msg,
				OSMO_MIN(ud_len, sizeof(sms->user_data)));
			sms_msg += ud_len;
			sms_msg_len -= ud_len;
			padbits = 7 - (ud_len % 7);
		}
		gsm_septets2octets(sms->user_data+ud_len, sms_msg,
				   sms_msg_len, padbits);
		sms->user_data_len = (ud_len*8 + padbits)/7 + sms_msg_len;/* SEPTETS */
		/* FIXME: sms->text */
	} else {
		memcpy(sms->user_data, sms_msg, sms_msg_len);
		sms->user_data_len = sms_msg_len;
	}

	*psms = sms;
	return ESME_ROK;
}

/*! \brief handle incoming libsmpp34 ssubmit_sm_t from remote ESME */
int handle_smpp_submit(struct osmo_esme *esme, struct submit_sm_t *submit,
		       struct submit_sm_resp_t *submit_r)
{
	struct gsm_sms *sms;
	struct gsm_network *net = esme->smsc->priv;
	struct sms_signal_data sig;
	int rc = -1;

	rc = submit_to_sms(&sms, net, submit);
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
		sms_free(sms);
		sms = NULL;
		if (rc < 0) {
			LOGP(DLSMS, LOGL_ERROR, "SMPP SUBMIT-SM: Unable to "
				"store SMS in database\n");
			submit_r->command_status = ESME_RSYSERR;
			return 0;
		}
		strcpy((char *)submit_r->message_id, "msg_id_not_implemented");
		LOGP(DLSMS, LOGL_INFO, "SMPP SUBMIT-SM: Stored in DB\n");

		memset(&sig, 0, sizeof(sig));
		osmo_signal_dispatch(SS_SMS, S_SMS_SUBMITTED, &sig);
		rc = 0;
		break;
	case 2: /* forward (i.e. transaction) mode */
		LOGP(DLSMS, LOGL_DEBUG, "SMPP SUBMIT-SM: Forwarding in "
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
			LOGP(DLSMS, LOGL_INFO, "SMPP SUBMIT-SM: Error\n");
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
			LOGP(DLSMS, LOGL_INFO, "SMPP SUBMIT-SM: Success\n");
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

/* GSM 03.38 6.2.1 Character expanding (no decode!) */
static int gsm_7bit_expand(char *text, const uint8_t *user_data, uint8_t septet_l, uint8_t ud_hdr_ind)
{
	int i = 0;
	int shift = 0;
	uint8_t c;

	/* skip the user data header */
	if (ud_hdr_ind) {
		/* get user data header length + 1 (for the 'user data header length'-field) */
		shift = ((user_data[0] + 1) * 8) / 7;
		if ((((user_data[0] + 1) * 8) % 7) != 0)
			shift++;
		septet_l = septet_l - shift;
	}

	for (i = 0; i < septet_l; i++) {
		c =
			((user_data[((i + shift) * 7 + 7) >> 3] <<
			  (7 - (((i + shift) * 7 + 7) & 7))) |
			 (user_data[((i + shift) * 7) >> 3] >>
			  (((i + shift) * 7) & 7))) & 0x7f;

		*(text++) = c;
	}

	*text = '\0';

	return i;
}


/* FIXME: libsmpp34 helpers, they should  be part of libsmpp34! */
void append_tlv(tlv_t **req_tlv, uint16_t tag,
	        const uint8_t *data, uint16_t len)
{
	tlv_t tlv;

	memset(&tlv, 0, sizeof(tlv));
	tlv.tag = tag;
	tlv.length = len;
	memcpy(tlv.value.octet, data, tlv.length);
	build_tlv(req_tlv, &tlv);
}
void append_tlv_u8(tlv_t **req_tlv, uint16_t tag, uint8_t val)
{
	tlv_t tlv;

	memset(&tlv, 0, sizeof(tlv));
	tlv.tag = tag;
	tlv.length = 1;
	tlv.value.val08 = val;
	build_tlv(req_tlv, &tlv);
}
void append_tlv_u16(tlv_t **req_tlv, uint16_t tag, uint16_t val)
{
	tlv_t tlv;

	memset(&tlv, 0, sizeof(tlv));
	tlv.tag = tag;
	tlv.length = 2;
	tlv.value.val16 = htons(val);
	build_tlv(req_tlv, &tlv);
}

/* Append the Osmocom vendor-specific additional TLVs to a SMPP msg */
static void append_osmo_tlvs(tlv_t **req_tlv, const struct gsm_lchan *lchan)
{
	int idx = calc_initial_idx(ARRAY_SIZE(lchan->meas_rep),
				   lchan->meas_rep_idx, 1);
	const struct gsm_meas_rep *mr = &lchan->meas_rep[idx];
	const struct gsm_meas_rep_unidir *ul_meas = &mr->ul;
	const struct gsm_meas_rep_unidir *dl_meas = &mr->dl;

	/* Osmocom vendor-specific SMPP34 extensions */
	append_tlv_u16(req_tlv, TLVID_osmo_arfcn, lchan->ts->trx->arfcn);
	if (mr->flags & MEAS_REP_F_MS_L1) {
		uint8_t ms_dbm;
		append_tlv_u8(req_tlv, TLVID_osmo_ta, mr->ms_l1.ta);
		ms_dbm = ms_pwr_dbm(lchan->ts->trx->bts->band, mr->ms_l1.pwr);
		append_tlv_u8(req_tlv, TLVID_osmo_ms_l1_txpwr, ms_dbm);
	} else if (mr->flags & MEAS_REP_F_MS_TO)
		append_tlv_u8(req_tlv, TLVID_osmo_ta, mr->ms_timing_offset);

	append_tlv_u16(req_tlv, TLVID_osmo_rxlev_ul,
		       rxlev2dbm(ul_meas->full.rx_lev));
	append_tlv_u8(req_tlv, TLVID_osmo_rxqual_ul, ul_meas->full.rx_qual);

	if (mr->flags & MEAS_REP_F_DL_VALID) {
		append_tlv_u16(req_tlv, TLVID_osmo_rxlev_dl,
			       rxlev2dbm(dl_meas->full.rx_lev));
		append_tlv_u8(req_tlv, TLVID_osmo_rxqual_dl,
			      dl_meas->full.rx_qual);
	}

	if (lchan->conn && lchan->conn->subscr) {
		struct gsm_subscriber *subscr = lchan->conn->subscr;
		size_t imei_len = strlen(subscr->equipment.imei);
		if (imei_len)
			append_tlv(req_tlv, TLVID_osmo_imei,
				   (uint8_t *)subscr->equipment.imei, imei_len+1);
	}
}

static int deliver_to_esme(struct osmo_esme *esme, struct gsm_sms *sms,
			   struct gsm_subscriber_connection *conn)
{
	struct deliver_sm_t deliver;
	uint8_t dcs;
	int mode;

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

	/* Figure out SMPP DCS from TP-DCS */
	dcs = sms->data_coding_scheme;
	if (smpp_determine_scheme(dcs, &deliver.data_coding, &mode) == -1)
		return -1;

	/* Transparently pass on DCS via SMPP if requested */
	if (esme->acl && esme->acl->dcs_transparent)
		deliver.data_coding = dcs;

	if (mode == MODE_7BIT) {
		uint8_t *dst = deliver.short_message;

		/* SMPP has this strange notion of putting 7bit SMS in
		 * an octet-aligned mode */
		if (sms->ud_hdr_ind) {
			/* length (bytes) of UDH inside UD */
			uint8_t udh_len = sms->user_data[0] + 1;

			/* copy over the UDH */
			memcpy(dst, sms->user_data, udh_len);
			dst += udh_len;
			deliver.sm_length = udh_len;
		}
		/* add decoded text */
		deliver.sm_length += gsm_7bit_expand((char *)dst, sms->user_data, sms->user_data_len, sms->ud_hdr_ind);
	} else {
		deliver.sm_length = sms->user_data_len;
		memcpy(deliver.short_message, sms->user_data, deliver.sm_length);
		deliver.sm_length = sms->user_data_len;
		memcpy(deliver.short_message, sms->user_data, deliver.sm_length);
	}

	if (esme->acl && esme->acl->osmocom_ext && conn && conn->lchan)
		append_osmo_tlvs(&deliver.tlv, conn->lchan);

	return smpp_tx_deliver(esme, &deliver);
}

static struct smsc *g_smsc;

int smpp_try_deliver(struct gsm_sms *sms, struct gsm_subscriber_connection *conn)
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

	return deliver_to_esme(esme, sms, conn);
}

struct smsc *smsc_from_vty(struct vty *v)
{
	/* FIXME: this is ugly */
	return g_smsc;
}

/*! \brief Initialize the OpenBSC SMPP interface */
int smpp_openbsc_init(void *ctx, uint16_t port)
{
	struct smsc *smsc = talloc_zero(ctx, struct smsc);
	int rc;

	rc = smpp_smsc_init(smsc, port);
	if (rc < 0)
		talloc_free(smsc);

	osmo_signal_register_handler(SS_SMS, smpp_sms_cb, smsc);
	osmo_signal_register_handler(SS_SUBSCR, smpp_subscr_cb, smsc);

	g_smsc = smsc;

	smpp_vty_init();

	return rc;
}

void smpp_openbsc_set_net(struct gsm_network *net)
{
	g_smsc->priv = net;
}
