/* GSM 08.08 BSSMAP handling						*/
/* (C) 2009-2012 by Holger Hans Peter Freyther <zecke@selfish.org>
 * (C) 2009-2012 by On-Waves
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

#include <openbsc/osmo_bsc.h>
#include <openbsc/osmo_bsc_grace.h>
#include <openbsc/osmo_bsc_rf.h>
#include <openbsc/bsc_msc_data.h>
#include <openbsc/debug.h>
#include <openbsc/bsc_subscriber.h>
#include <openbsc/mgcp.h>
#include <openbsc/paging.h>

#include <osmocom/gsm/protocol/gsm_08_08.h>
#include <osmocom/gsm/gsm0808.h>

/*
 * helpers for the assignment command
 */
enum gsm0808_permitted_speech audio_support_to_gsm88(struct gsm_audio_support *audio)
{
	if (audio->hr) {
		switch (audio->ver) {
		case 1:
			return GSM0808_PERM_HR1;
			break;
		case 2:
			return GSM0808_PERM_HR2;
			break;
		case 3:
			return GSM0808_PERM_HR3;
			break;
		default:
			    LOGP(DMSC, LOGL_ERROR, "Wrong speech mode: %d\n", audio->ver);
			    return GSM0808_PERM_FR1;
		}
	} else {
		switch (audio->ver) {
		case 1:
			return GSM0808_PERM_FR1;
			break;
		case 2:
			return GSM0808_PERM_FR2;
			break;
		case 3:
			return GSM0808_PERM_FR3;
			break;
		default:
			LOGP(DMSC, LOGL_ERROR, "Wrong speech mode: %d\n", audio->ver);
			return GSM0808_PERM_HR1;
		}
	}
}

enum gsm48_chan_mode gsm88_to_chan_mode(enum gsm0808_permitted_speech speech)
{
	switch (speech) {
	case GSM0808_PERM_HR1:
	case GSM0808_PERM_FR1:
		return GSM48_CMODE_SPEECH_V1;
		break;
	case GSM0808_PERM_HR2:
	case GSM0808_PERM_FR2:
		return GSM48_CMODE_SPEECH_EFR;
		break;
	case GSM0808_PERM_HR3:
	case GSM0808_PERM_FR3:
		return GSM48_CMODE_SPEECH_AMR;
		break;
	}

	LOGP(DMSC, LOGL_FATAL, "Should not be reached.\n");
	return GSM48_CMODE_SPEECH_AMR;
}

static int bssmap_handle_reset_ack(struct bsc_msc_data *msc,
				   struct msgb *msg, unsigned int length)
{
	LOGP(DMSC, LOGL_NOTICE, "Reset ACK from MSC\n");
	return 0;
}

/* GSM 08.08 § 3.2.1.19 */
static int bssmap_handle_paging(struct bsc_msc_data *msc,
				struct msgb *msg, unsigned int payload_length)
{
	struct bsc_subscr *subscr;
	struct tlv_parsed tp;
	char mi_string[GSM48_MI_SIZE];
	uint32_t tmsi = GSM_RESERVED_TMSI;
	unsigned int lac = GSM_LAC_RESERVED_ALL_BTS;
	uint8_t data_length;
	const uint8_t *data;
	uint8_t chan_needed = RSL_CHANNEED_ANY;

	tlv_parse(&tp, gsm0808_att_tlvdef(), msg->l4h + 1, payload_length - 1, 0, 0);

	if (!TLVP_PRESENT(&tp, GSM0808_IE_IMSI)) {
		LOGP(DMSC, LOGL_ERROR, "Mandatory IMSI not present.\n");
		return -1;
	} else if ((TLVP_VAL(&tp, GSM0808_IE_IMSI)[0] & GSM_MI_TYPE_MASK) != GSM_MI_TYPE_IMSI) {
		LOGP(DMSC, LOGL_ERROR, "Wrong content in the IMSI\n");
		return -1;
	}

	if (!TLVP_PRESENT(&tp, GSM0808_IE_CELL_IDENTIFIER_LIST)) {
		LOGP(DMSC, LOGL_ERROR, "Mandatory CELL IDENTIFIER LIST not present.\n");
		return -1;
	}

	if (TLVP_PRESENT(&tp, GSM0808_IE_TMSI) &&
	    TLVP_LEN(&tp, GSM0808_IE_TMSI) == 4) {
		tmsi = ntohl(tlvp_val32_unal(&tp, GSM0808_IE_TMSI));
	}

	/*
	 * parse the IMSI
	 */
	gsm48_mi_to_string(mi_string, sizeof(mi_string),
			   TLVP_VAL(&tp, GSM0808_IE_IMSI), TLVP_LEN(&tp, GSM0808_IE_IMSI));

	/*
	 * parse the cell identifier list
	 */
	data_length = TLVP_LEN(&tp, GSM0808_IE_CELL_IDENTIFIER_LIST);
	data = TLVP_VAL(&tp, GSM0808_IE_CELL_IDENTIFIER_LIST);

	/*
	 * Support paging to all network or one BTS at one LAC
	 */
	if (data_length == 3 && data[0] == CELL_IDENT_LAC) {
		lac = osmo_load16be(&data[1]);
	} else if (data_length > 1 || (data[0] & 0x0f) != CELL_IDENT_BSS) {
		LOGP(DMSC, LOGL_ERROR, "Unsupported Cell Identifier List: %s\n", osmo_hexdump(data, data_length));
		return -1;
	}

	if (TLVP_PRESENT(&tp, GSM0808_IE_CHANNEL_NEEDED) && TLVP_LEN(&tp, GSM0808_IE_CHANNEL_NEEDED) == 1)
		chan_needed = TLVP_VAL(&tp, GSM0808_IE_CHANNEL_NEEDED)[0] & 0x03;

	if (TLVP_PRESENT(&tp, GSM0808_IE_EMLPP_PRIORITY)) {
		LOGP(DMSC, LOGL_ERROR, "eMLPP is not handled\n");
	}

	subscr = bsc_subscr_find_or_create_by_imsi(msc->network->bsc_subscribers,
						   mi_string);
	if (!subscr) {
		LOGP(DMSC, LOGL_ERROR, "Failed to allocate a subscriber for %s\n", mi_string);
		return -1;
	}

	subscr->lac = lac;
	subscr->tmsi = tmsi;

	LOGP(DMSC, LOGL_INFO, "Paging request from MSC IMSI: '%s' TMSI: '0x%x/%u' LAC: 0x%x\n", mi_string, tmsi, tmsi, lac);
	bsc_grace_paging_request(msc->network->bsc_data->rf_ctrl->policy,
				 subscr, chan_needed, msc);
	return 0;
}

/*
 * GSM 08.08 § 3.1.9.1 and 3.2.1.21...
 * release our gsm_subscriber_connection and send message
 */
static int bssmap_handle_clear_command(struct osmo_bsc_sccp_con *conn,
				       struct msgb *msg, unsigned int payload_length)
{
	struct msgb *resp;

	/* TODO: handle the cause of this package */

	if (conn->conn) {
		LOGP(DMSC, LOGL_INFO, "Releasing all transactions on %p\n", conn);
		gsm0808_clear(conn->conn);
		bsc_subscr_con_free(conn->conn);
		conn->conn = NULL;
	}

	/* send the clear complete message */
	resp = gsm0808_create_clear_complete();
	if (!resp) {
		LOGP(DMSC, LOGL_ERROR, "Sending clear complete failed.\n");
		return -1;
	}

	bsc_queue_for_msc(conn, resp);
	return 0;
}

/*
 * GSM 08.08 § 3.4.7 cipher mode handling. We will have to pick
 * the cipher to be used for this. In case we are already using
 * a cipher we will have to send cipher mode reject to the MSC,
 * otherwise we will have to pick something that we and the MS
 * is supporting. Currently we are doing it in a rather static
 * way by picking one ecnryption or no encrytpion.
 */
static int bssmap_handle_cipher_mode(struct osmo_bsc_sccp_con *conn,
				     struct msgb *msg, unsigned int payload_length)
{
	uint16_t len;
	struct gsm_network *network = NULL;
	const uint8_t *data;
	struct tlv_parsed tp;
	struct msgb *resp;
	int reject_cause = -1;
	int include_imeisv = 1;

	if (!conn->conn) {
		LOGP(DMSC, LOGL_ERROR, "No lchan/msc_data in cipher mode command.\n");
		goto reject;
	}

	if (conn->ciphering_handled) {
		LOGP(DMSC, LOGL_ERROR, "Already seen ciphering command. Protocol Error.\n");
		goto reject;
	}

	conn->ciphering_handled = 1;

	tlv_parse(&tp, gsm0808_att_tlvdef(), msg->l4h + 1, payload_length - 1, 0, 0);
	if (!TLVP_PRESENT(&tp, GSM0808_IE_ENCRYPTION_INFORMATION)) {
		LOGP(DMSC, LOGL_ERROR, "IE Encryption Information missing.\n");
		goto reject;
	}

	/*
	 * check if our global setting is allowed
	 *  - Currently we check for A5/0 and A5/1
	 *  - Copy the key if that is necessary
	 *  - Otherwise reject
	 */
	len = TLVP_LEN(&tp, GSM0808_IE_ENCRYPTION_INFORMATION);
	if (len < 1) {
		LOGP(DMSC, LOGL_ERROR, "IE Encryption Information is too short.\n");
		goto reject;
	}

	network = conn->conn->bts->network;
	data = TLVP_VAL(&tp, GSM0808_IE_ENCRYPTION_INFORMATION);

	if (TLVP_PRESENT(&tp, GSM0808_IE_CIPHER_RESPONSE_MODE))
		include_imeisv = TLVP_VAL(&tp, GSM0808_IE_CIPHER_RESPONSE_MODE)[0] & 0x1;

	if (network->a5_encryption == 0 && (data[0] & 0x1) == 0x1) {
		gsm0808_cipher_mode(conn->conn, 0, NULL, 0, include_imeisv);
	} else if (network->a5_encryption != 0 && (data[0] & 0x2) == 0x2) {
		gsm0808_cipher_mode(conn->conn, 1, &data[1], len - 1, include_imeisv);
	} else {
		LOGP(DMSC, LOGL_ERROR, "Can not select encryption...\n");
		goto reject;
	}

	return 0;

reject:
	resp = gsm0808_create_cipher_reject(reject_cause);
	if (!resp) {
		LOGP(DMSC, LOGL_ERROR, "Sending the cipher reject failed.\n");
		return -1;
	}

	bsc_queue_for_msc(conn, resp);
	return -1;
}

/*
 * Handle the assignment request message.
 *
 * See §3.2.1.1 for the message type
 */
static int bssmap_handle_assignm_req(struct osmo_bsc_sccp_con *conn,
				     struct msgb *msg, unsigned int length)
{
	struct msgb *resp;
	struct bsc_msc_data *msc;
	struct tlv_parsed tp;
	uint8_t *data;
	uint8_t timeslot;
	uint8_t multiplex;
	enum gsm48_chan_mode chan_mode = GSM48_CMODE_SIGN;
	int i, supported, port, full_rate = -1;

	if (!conn->conn) {
		LOGP(DMSC, LOGL_ERROR, "No lchan/msc_data in cipher mode command.\n");
		return -1;
	}

	tlv_parse(&tp, gsm0808_att_tlvdef(), msg->l4h + 1, length - 1, 0, 0);

	if (!TLVP_PRESENT(&tp, GSM0808_IE_CHANNEL_TYPE)) {
		LOGP(DMSC, LOGL_ERROR, "Mandatory channel type not present.\n");
		goto reject;
	}

	if (!TLVP_PRESENT(&tp, GSM0808_IE_CIRCUIT_IDENTITY_CODE)) {
		LOGP(DMSC, LOGL_ERROR, "Identity code missing. Audio routing will not work.\n");
		goto reject;
	}

	conn->cic = osmo_load16be(TLVP_VAL(&tp, GSM0808_IE_CIRCUIT_IDENTITY_CODE));
	timeslot = conn->cic & 0x1f;
	multiplex = (conn->cic & ~0x1f) >> 5;

	/*
	 * Currently we only support a limited subset of all
	 * possible channel types. The limitation ends by not using
	 * multi-slot, limiting the channel coding, speech...
	 */
	if (TLVP_LEN(&tp, GSM0808_IE_CHANNEL_TYPE) < 3) {
		LOGP(DMSC, LOGL_ERROR, "ChannelType len !=3 not supported: %d\n",
			TLVP_LEN(&tp, GSM0808_IE_CHANNEL_TYPE));
		goto reject;
	}

	/*
	 * Try to figure out if we support the proposed speech codecs. For
	 * now we will always pick the full rate codecs.
	 */

	data = (uint8_t *) TLVP_VAL(&tp, GSM0808_IE_CHANNEL_TYPE);
	if ((data[0] & 0xf) != 0x1) {
		LOGP(DMSC, LOGL_ERROR, "ChannelType != speech: %d\n", data[0]);
		goto reject;
	}

	/*
	 * go through the list of preferred codecs of our gsm network
	 * and try to find it among the permitted codecs. If we found
	 * it we will send chan_mode to the right mode and break the
	 * inner loop. The outer loop will exit due chan_mode having
	 * the correct value.
	 */
	full_rate = 0;
	msc = conn->msc;
	for (supported = 0;
		chan_mode == GSM48_CMODE_SIGN && supported < msc->audio_length;
		++supported) {

		int perm_val = audio_support_to_gsm88(msc->audio_support[supported]);
		for (i = 2; i < TLVP_LEN(&tp, GSM0808_IE_CHANNEL_TYPE); ++i) {
			if ((data[i] & 0x7f) == perm_val) {
				chan_mode = gsm88_to_chan_mode(perm_val);
				full_rate = (data[i] & 0x4) == 0;
				break;
			} else if ((data[i] & 0x80) == 0x00) {
				break;
			}
		}
	}

	if (chan_mode == GSM48_CMODE_SIGN) {
		LOGP(DMSC, LOGL_ERROR, "No supported audio type found.\n");
		goto reject;
	}

	/* map it to a MGCP Endpoint and a RTP port */
	port = mgcp_timeslot_to_endpoint(multiplex, timeslot);
	conn->rtp_port = rtp_calculate_port(port, msc->rtp_base);

	return gsm0808_assign_req(conn->conn, chan_mode, full_rate);

reject:
	resp = gsm0808_create_assignment_failure(GSM0808_CAUSE_NO_RADIO_RESOURCE_AVAILABLE, NULL);
	if (!resp) {
		LOGP(DMSC, LOGL_ERROR, "Channel allocation failure.\n");
		return -1;
	}

	bsc_queue_for_msc(conn, resp);
	return -1;
}

static int bssmap_rcvmsg_udt(struct bsc_msc_data *msc,
			     struct msgb *msg, unsigned int length)
{
	int ret = 0;

	if (length < 1) {
		LOGP(DMSC, LOGL_ERROR, "Not enough room: %d\n", length);
		return -1;
	}

	LOGP(DMSC, LOGL_INFO, "Rx MSC UDT BSSMAP %s\n",
		gsm0808_bssmap_name(msg->l4h[0]));

	switch (msg->l4h[0]) {
	case BSS_MAP_MSG_RESET_ACKNOWLEDGE:
		ret = bssmap_handle_reset_ack(msc, msg, length);
		break;
	case BSS_MAP_MSG_PAGING:
		ret = bssmap_handle_paging(msc, msg, length);
		break;
	}

	return ret;
}

static int bssmap_rcvmsg_dt1(struct osmo_bsc_sccp_con *conn,
			     struct msgb *msg, unsigned int length)
{
	int ret = 0;

	if (length < 1) {
		LOGP(DMSC, LOGL_ERROR, "Not enough room: %d\n", length);
		return -1;
	}

	LOGP(DMSC, LOGL_INFO, "Rx MSC DT1 BSSMAP %s\n",
		gsm0808_bssmap_name(msg->l4h[0]));

	switch (msg->l4h[0]) {
	case BSS_MAP_MSG_CLEAR_CMD:
		ret = bssmap_handle_clear_command(conn, msg, length);
		break;
	case BSS_MAP_MSG_CIPHER_MODE_CMD:
		ret = bssmap_handle_cipher_mode(conn, msg, length);
		break;
	case BSS_MAP_MSG_ASSIGMENT_RQST:
		ret = bssmap_handle_assignm_req(conn, msg, length);
		break;
	default:
		LOGP(DMSC, LOGL_NOTICE, "Unimplemented msg type: %s\n",
			gsm0808_bssmap_name(msg->l4h[0]));
		break;
	}

	return ret;
}

static int dtap_rcvmsg(struct osmo_bsc_sccp_con *conn,
		       struct msgb *msg, unsigned int length)
{
	struct dtap_header *header;
	struct msgb *gsm48;
	uint8_t *data;
	int rc, dtap_rc;

	LOGP(DMSC, LOGL_DEBUG, "Rx MSC DTAP: %s\n",
		osmo_hexdump(msg->l3h, length));

	if (!conn->conn) {
		LOGP(DMSC, LOGL_ERROR, "No subscriber connection available\n");
		return -1;
	}

	header = (struct dtap_header *) msg->l3h;
	if (sizeof(*header) >= length) {
		LOGP(DMSC, LOGL_ERROR, "The DTAP header does not fit. Wanted: %zu got: %u\n", sizeof(*header), length);
                LOGP(DMSC, LOGL_ERROR, "hex: %s\n", osmo_hexdump(msg->l3h, length));
                return -1;
	}

	if (header->length > length - sizeof(*header)) {
		LOGP(DMSC, LOGL_ERROR, "The DTAP l4 information does not fit: header: %u length: %u\n", header->length, length);
                LOGP(DMSC, LOGL_ERROR, "hex: %s\n", osmo_hexdump(msg->l3h, length));
		return -1;
	}

	LOGP(DMSC, LOGL_INFO, "Rx MSC DTAP, SAPI: %u CHAN: %u\n", header->link_id & 0x07, header->link_id & 0xC0);

	/* forward the data */
	gsm48 = gsm48_msgb_alloc_name("GSM 04.08 DTAP RCV");
	if (!gsm48) {
		LOGP(DMSC, LOGL_ERROR, "Allocation of the message failed.\n");
		return -1;
	}

	gsm48->l3h = gsm48->data;
	data = msgb_put(gsm48, length - sizeof(*header));
	memcpy(data, msg->l3h + sizeof(*header), length - sizeof(*header));

	/* pass it to the filter for extra actions */
	rc = bsc_scan_msc_msg(conn->conn, gsm48);
	dtap_rc = gsm0808_submit_dtap(conn->conn, gsm48, header->link_id, 1);
	if (rc == BSS_SEND_USSD)
		bsc_send_welcome_ussd(conn->conn);
	return dtap_rc;
}

int bsc_handle_udt(struct bsc_msc_data *msc,
		   struct msgb *msgb, unsigned int length)
{
	struct bssmap_header *bs;

	LOGP(DMSC, LOGL_DEBUG, "Rx MSC UDT: %s\n",
		osmo_hexdump(msgb->l3h, length));

	if (length < sizeof(*bs)) {
		LOGP(DMSC, LOGL_ERROR, "The header is too short.\n");
		return -1;
	}

	bs = (struct bssmap_header *) msgb->l3h;
	if (bs->length < length - sizeof(*bs))
		return -1;

	switch (bs->type) {
	case BSSAP_MSG_BSS_MANAGEMENT:
		msgb->l4h = &msgb->l3h[sizeof(*bs)];
		bssmap_rcvmsg_udt(msc, msgb, length - sizeof(*bs));
		break;
	default:
		LOGP(DMSC, LOGL_NOTICE, "Unimplemented msg type: %s\n",
			gsm0808_bssmap_name(bs->type));
	}

	return 0;
}

int bsc_handle_dt1(struct osmo_bsc_sccp_con *conn,
		   struct msgb *msg, unsigned int len)
{
	if (len < sizeof(struct bssmap_header)) {
		LOGP(DMSC, LOGL_ERROR, "The header is too short.\n");
	}

	switch (msg->l3h[0]) {
	case BSSAP_MSG_BSS_MANAGEMENT:
		msg->l4h = &msg->l3h[sizeof(struct bssmap_header)];
		bssmap_rcvmsg_dt1(conn, msg, len - sizeof(struct bssmap_header));
		break;
	case BSSAP_MSG_DTAP:
		dtap_rcvmsg(conn, msg, len);
		break;
	default:
		LOGP(DMSC, LOGL_NOTICE, "Unimplemented BSSAP msg type: %s\n",
			gsm0808_bssap_name(msg->l3h[0]));
	}

	return -1;
}
