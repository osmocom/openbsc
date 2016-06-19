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
#include <openbsc/transaction.h>
#include <openbsc/gsm_subscriber.h>
#include <openbsc/chan_alloc.h>
#include <openbsc/vlr.h>

#include "smpp_smsc.h"

/*! \brief find vlr_subscr for a given SMPP NPI/TON/Address */
static struct vlr_subscr *subscr_by_dst(struct gsm_network *net,
					    uint8_t npi, uint8_t ton,
					    const char *addr)
{
	struct vlr_subscr *vsub = NULL;

	switch (npi) {
	case NPI_Land_Mobile_E212:
		vsub = vlr_subscr_find_by_imsi(net->vlr, addr);
		break;
	case NPI_ISDN_E163_E164:
	case NPI_Private:
		vsub = vlr_subscr_find_by_msisdn(net->vlr, addr);
		break;
	default:
		LOGP(DSMPP, LOGL_NOTICE, "Unsupported NPI: %u\n", npi);
		break;
	}

	log_set_context(LOG_CTX_VLR_SUBSCR, vsub);
	return vsub;
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
	struct vlr_subscr *dest;
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
			/* ERROR: we cannot have both! */
			LOGP(DLSMS, LOGL_ERROR, "SMPP Cannot have payload in "
				"TLV _and_ in the header\n");
			vlr_subscr_put(dest);
			return ESME_ROPTPARNOTALLWD;
		}
		sms_msg = t->value.octet;
		sms_msg_len = t->length;
	} else if (submit->sm_length > 0 && submit->sm_length < 255) {
		sms_msg = submit->short_message;
		sms_msg_len = submit->sm_length;
	} else {
		LOGP(DLSMS, LOGL_ERROR,
			"SMPP neither message payload nor valid sm_length.\n");
		vlr_subscr_put(dest);
		return ESME_RINVPARLEN;
	}

	sms = sms_alloc();
	sms->source = SMS_SOURCE_SMPP;
	sms->smpp.sequence_nr = submit->sequence_number;

	/* fill in the destination address */
	sms->receiver = dest;
	sms->dst.ton = submit->dest_addr_ton;
	sms->dst.npi = submit->dest_addr_npi;
	osmo_strlcpy(sms->dst.addr, dest->msisdn, sizeof(sms->dst.addr));

	/* fill in the source address */
	sms->src.ton = submit->source_addr_ton;
	sms->src.npi = submit->source_addr_npi;
	osmo_strlcpy(sms->src.addr, (char *)submit->source_addr,
		     sizeof(sms->src.addr));

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
	} else if (submit->data_coding == 0x08) {
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

static void alert_all_esme(struct smsc *smsc, struct vlr_subscr *vsub,
			   uint8_t smpp_avail_status)
{
	struct osmo_esme *esme;

	llist_for_each_entry(esme, &smsc->esme_list, list) {
		/* we currently send an alert notification to each ESME that is
		 * connected, and do not require a (non-existant) delivery
		 * pending flag to be set before,  FIXME: make this VTY
		 * configurable */
		if (esme->acl && esme->acl->deliver_src_imsi) {
			smpp_tx_alert(esme, TON_Subscriber_Number,
				      NPI_Land_Mobile_E212,
				      vsub->imsi, smpp_avail_status);
		} else {
			smpp_tx_alert(esme, TON_Network_Specific,
				      NPI_ISDN_E163_E164,
				      vsub->msisdn, smpp_avail_status);
		}
	}
}


/*! \brief signal handler for status of attempted SMS deliveries */
static int smpp_sms_cb(unsigned int subsys, unsigned int signal,
			void *handler_data, void *signal_data)
{
	struct sms_signal_data *sig_sms = signal_data;
	struct gsm_sms *sms = sig_sms->sms;
	struct smsc *smsc = handler_data;
	int rc = 0;

	if (!sms)
		return 0;

	if (sms->source != SMS_SOURCE_SMPP)
		return 0;

	switch (signal) {
	case S_SMS_MEM_EXCEEDED:
		/* fall-through: There is no ESME_Rxxx result code to
		 * indicate a MEMORY EXCEEDED in transaction mode back
		 * to the ESME */
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
	case S_SMS_SMMA:
		if (!sig_sms->trans || !sig_sms->trans->vsub) {
			/* SMMA without a subscriber? strange... */
			LOGP(DLSMS, LOGL_NOTICE, "SMMA without subscriber?\n");
			break;
		}

		/* There's no real 1:1 match for SMMA in SMPP.  However,
		 * an ALERT NOTIFICATION seems to be the most logical
		 * choice */
		alert_all_esme(smsc, sig_sms->trans->vsub, 0);
		break;
	}

	return rc;
}

/*! \brief signal handler for subscriber related signals */
static int smpp_subscr_cb(unsigned int subsys, unsigned int signal,
			  void *handler_data, void *signal_data)
{
	struct vlr_subscr *vsub = signal_data;
	struct smsc *smsc = handler_data;
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

	alert_all_esme(smsc, vsub, smpp_avail_status);

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
	} else if (mr->flags & MEAS_REP_F_MS_TO) /* Save Timing Offset field = MS Timing Offset + 63 */
		append_tlv_u8(req_tlv, TLVID_osmo_ta, mr->ms_timing_offset + 63);

	append_tlv_u16(req_tlv, TLVID_osmo_rxlev_ul,
		       rxlev2dbm(ul_meas->full.rx_lev));
	append_tlv_u8(req_tlv, TLVID_osmo_rxqual_ul, ul_meas->full.rx_qual);

	if (mr->flags & MEAS_REP_F_DL_VALID) {
		append_tlv_u16(req_tlv, TLVID_osmo_rxlev_dl,
			       rxlev2dbm(dl_meas->full.rx_lev));
		append_tlv_u8(req_tlv, TLVID_osmo_rxqual_dl,
			      dl_meas->full.rx_qual);
	}

	if (lchan->conn && lchan->conn->vsub) {
		struct vlr_subscr *vsub = lchan->conn->vsub;
		size_t imei_len = strlen(vsub->imei);
		if (imei_len)
			append_tlv(req_tlv, TLVID_osmo_imei,
				   (uint8_t *)vsub->imei, imei_len+1);
	}
}

struct {
	uint32_t smpp_status_code;
	uint8_t gsm411_cause;
} smpp_to_gsm411_err_array[] = {

	/* Seems like most phones don't care about the failure cause,
	 * although some will display a different notification for
	 * GSM411_RP_CAUSE_MO_NUM_UNASSIGNED
	 * Some provoke a display of "Try again later"
	 * while others a more definitive "Message sending failed"
	 */

	{ ESME_RSYSERR, 	GSM411_RP_CAUSE_MO_DEST_OUT_OF_ORDER	},
	{ ESME_RINVDSTADR,	GSM411_RP_CAUSE_MO_NUM_UNASSIGNED	},
	{ ESME_RMSGQFUL,	GSM411_RP_CAUSE_MO_CONGESTION		},
	{ ESME_RINVSRCADR,	GSM411_RP_CAUSE_MO_SMS_REJECTED		},
	{ ESME_RINVMSGID,	GSM411_RP_CAUSE_INV_TRANS_REF		}
};

static int smpp_to_gsm411_err(uint32_t smpp_status_code, int *gsm411_cause)
{
	int i;
	for (i = 0; i < ARRAY_SIZE(smpp_to_gsm411_err_array); i++) {
		if (smpp_to_gsm411_err_array[i].smpp_status_code != smpp_status_code)
			continue;
		*gsm411_cause = smpp_to_gsm411_err_array[i].gsm411_cause;
		return 0;
	}
	return -1;
}

static void smpp_cmd_free(struct osmo_smpp_cmd *cmd)
{
	osmo_timer_del(&cmd->response_timer);
	llist_del(&cmd->list);
	vlr_subscr_put(cmd->vsub);
	sms_free(cmd->sms);
	talloc_free(cmd);
}

void smpp_cmd_flush_pending(struct osmo_esme *esme)
{
	struct osmo_smpp_cmd *cmd, *next;

	llist_for_each_entry_safe(cmd, next, &esme->smpp_cmd_list, list)
		smpp_cmd_free(cmd);
}

void smpp_cmd_ack(struct osmo_smpp_cmd *cmd)
{
	struct gsm_subscriber_connection *conn;
	struct gsm_trans *trans;

	conn = connection_for_subscr(cmd->vsub);
	if (!conn) {
		LOGP(DSMPP, LOGL_ERROR, "No connection to subscriber anymore\n");
		return;
	}

	trans = trans_find_by_id(conn, GSM48_PDISC_SMS,
				 cmd->sms->gsm411.transaction_id);
	if (!trans) {
		LOGP(DSMPP, LOGL_ERROR, "GSM transaction %u is gone\n",
		     cmd->sms->gsm411.transaction_id);
		return;
	}

	gsm411_send_rp_ack(trans, cmd->sms->gsm411.msg_ref);
	smpp_cmd_free(cmd);
}

void smpp_cmd_err(struct osmo_smpp_cmd *cmd, uint32_t status)
{
	struct gsm_subscriber_connection *conn;
	struct gsm_trans *trans;
	int gsm411_cause;

	conn = connection_for_subscr(cmd->vsub);
	if (!conn) {
		LOGP(DSMPP, LOGL_ERROR, "No connection to subscriber anymore\n");
		return;
	}

	trans = trans_find_by_id(conn, GSM48_PDISC_SMS,
				 cmd->sms->gsm411.transaction_id);
	if (!trans) {
		LOGP(DSMPP, LOGL_ERROR, "GSM transaction %u is gone\n",
		     cmd->sms->gsm411.transaction_id);
		return;
	}

	if (smpp_to_gsm411_err(status, &gsm411_cause) < 0)
		gsm411_cause = GSM411_RP_CAUSE_MO_NET_OUT_OF_ORDER;

	gsm411_send_rp_error(trans, cmd->sms->gsm411.msg_ref, gsm411_cause);

	smpp_cmd_free(cmd);
}

static void smpp_deliver_sm_cb(void *data)
{
	smpp_cmd_err(data, ESME_RSYSERR);
}

static int smpp_cmd_enqueue(struct osmo_esme *esme,
			    struct vlr_subscr *vsub, struct gsm_sms *sms,
			    uint32_t sequence_number, bool *deferred)
{
	struct osmo_smpp_cmd *cmd;

	cmd = talloc_zero(esme, struct osmo_smpp_cmd);
	if (!cmd)
		return -1;

	cmd->sequence_nr	= sequence_number;
	cmd->sms		= sms;
	cmd->vsub		= vlr_subscr_get(vsub);

	/* FIXME: No predefined value for this response_timer as specified by
	 * SMPP 3.4 specs, section 7.2. Make this configurable? Don't forget
	 * lchan keeps busy until we get a reply to this SMPP command. Too high
	 * value may exhaust resources.
	 */
	osmo_timer_setup(&cmd->response_timer, smpp_deliver_sm_cb, cmd);
	osmo_timer_schedule(&cmd->response_timer, 5, 0);
	llist_add_tail(&cmd->list, &esme->smpp_cmd_list);
	*deferred = true;

	return 0;
}

struct osmo_smpp_cmd *smpp_cmd_find_by_seqnum(struct osmo_esme *esme,
					      uint32_t sequence_nr)
{
	struct osmo_smpp_cmd *cmd;

	llist_for_each_entry(cmd, &esme->smpp_cmd_list, list) {
		if (cmd->sequence_nr == sequence_nr)
			return cmd;
	}
	return NULL;
}

static int deliver_to_esme(struct osmo_esme *esme, struct gsm_sms *sms,
			   struct gsm_subscriber_connection *conn,
			   bool *deferred)
{
	struct deliver_sm_t deliver;
	int mode, ret;
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
			conn->vsub->imsi);
	} else {
		deliver.source_addr_ton = TON_Network_Specific;
		deliver.source_addr_npi = NPI_ISDN_E163_E164;
		snprintf((char *)deliver.source_addr,
			 sizeof(deliver.source_addr), "%s",
			 conn->vsub->msisdn);
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

	if (esme->acl && esme->acl->osmocom_ext && conn->lchan)
		append_osmo_tlvs(&deliver.tlv, conn->lchan);

	ret = smpp_tx_deliver(esme, &deliver);
	if (ret < 0)
		return ret;

	return smpp_cmd_enqueue(esme, conn->vsub, sms,
				deliver.sequence_number, deferred);
}

static struct smsc *g_smsc;

int smpp_route_smpp_first(struct gsm_sms *sms, struct gsm_subscriber_connection *conn)
{
	return g_smsc->smpp_first;
}

int smpp_try_deliver(struct gsm_sms *sms,
		     struct gsm_subscriber_connection *conn, bool *deferred)
{
	struct osmo_esme *esme;
	struct osmo_smpp_addr dst;

	memset(&dst, 0, sizeof(dst));
	dst.ton = sms->dst.ton;
	dst.npi = sms->dst.npi;
	memcpy(dst.addr, sms->dst.addr, sizeof(dst.addr));

	esme = smpp_route(g_smsc, &dst);
	if (!esme)
		return GSM411_RP_CAUSE_MO_NUM_UNASSIGNED;

	return deliver_to_esme(esme, sms, conn, deferred);
}

struct smsc *smsc_from_vty(struct vty *v)
{
	/* FIXME: this is ugly */
	return g_smsc;
}

/*! \brief Allocate the OpenBSC SMPP interface struct and init VTY. */
int smpp_openbsc_alloc_init(void *ctx)
{
	g_smsc = smpp_smsc_alloc_init(ctx);
	if (!g_smsc) {
		LOGP(DSMPP, LOGL_FATAL, "Cannot allocate smsc struct\n");
		return -1;
	}
	return smpp_vty_init();
}

/*! \brief Launch the OpenBSC SMPP interface with the parameters set from VTY.
 */
int smpp_openbsc_start(struct gsm_network *net)
{
	int rc;
	g_smsc->priv = net;

	/* If a VTY configuration has taken place, the values have been stored
	 * in the smsc struct. Otherwise, use the defaults (NULL -> any, 0 ->
	 * default SMPP port, see smpp_smsc_bind()). */
	rc = smpp_smsc_start(g_smsc, g_smsc->bind_addr, g_smsc->listen_port);
	if (rc < 0)
		return rc;

	rc = osmo_signal_register_handler(SS_SMS, smpp_sms_cb, g_smsc);
	if (rc < 0)
		return rc;
	rc = osmo_signal_register_handler(SS_SUBSCR, smpp_subscr_cb, g_smsc);
	if (rc < 0)
		return rc;

	return 0;
}

