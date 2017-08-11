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
#include <osmocom/gsm/gsm0808_utils.h>
#include <openbsc/osmo_bsc_sigtran.h>
#include <openbsc/a_reset.h>
#include <osmocom/core/byteswap.h>

#define IP_V4_ADDR_LEN 4

/*
 * helpers for the assignment command
 */

/* Helper function for match_codec_pref(), looks up a matching permitted speech
 * value for a given msc audio codec pref */
enum gsm0808_permitted_speech audio_support_to_gsm88(struct gsm_audio_support
						     *audio)
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
			LOGP(DMSC, LOGL_ERROR, "Wrong speech mode: %d\n",
			     audio->ver);
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
			LOGP(DMSC, LOGL_ERROR, "Wrong speech mode: %d\n",
			     audio->ver);
			return GSM0808_PERM_HR1;
		}
	}
}

/* Helper function for match_codec_pref(), looks up a matching chan mode for
 * a given permitted speech value */
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
	default:
		LOGP(DMSC, LOGL_FATAL,
		     "Unsupported permitted speech selected, assuming AMR as channel mode...\n");
		return GSM48_CMODE_SPEECH_AMR;
	}
}

/* Helper function for match_codec_pref(), tests if a given audio support
 * matches one of the permitted speech settings of the channel type element.
 * The matched permitted speech value is then also compared against the
 * speech codec list. (optional, only relevant for AoIP) */
static bool test_codec_pref(const struct gsm0808_channel_type *ct,
			    const struct gsm0808_speech_codec_list *scl,
			    uint8_t perm_spch)
{
	unsigned int i;
	bool match = false;
	struct gsm0808_speech_codec sc;
	int rc;

	/* Try to finde the given permitted speech value in the
	 * codec list of the channel type element */
	for (i = 0; i < ct->perm_spch_len; i++) {
		if (ct->perm_spch[i] == perm_spch) {
			match = true;
			break;
		}
	}

	/* If we do not have a speech codec list to test against,
	 * we just exit early (will be always the case in non-AoIP networks) */
	if (!scl)
		return match;

	/* If we failed to match until here, there is no
	 * point in testing further */
	if (match == false)
		return false;

	/* Extrapolate speech codec data */
	rc = gsm0808_speech_codec_from_chan_type(&sc, perm_spch);
	if (rc < 0)
		return false;

	/* Try to find extrapolated speech codec data in
	 * the speech codec list */
	for (i = 0; i < scl->len; i++) {
		if (memcmp(&sc, &scl->codec[i], sizeof(sc)) == 0)
			return true;
	}

	return false;
}

/* Helper function for bssmap_handle_assignm_req(), matches the codec
 * preferences from the MSC with the codec preferences */
static int match_codec_pref(int *full_rate, enum gsm48_chan_mode *chan_mode,
			    const struct gsm0808_channel_type *ct,
			    const struct gsm0808_speech_codec_list *scl,
			    const struct bsc_msc_data *msc)
{
	unsigned int i;
	uint8_t perm_spch;
	bool match = false;

	for (i = 0; i < msc->audio_length; i++) {
		perm_spch = audio_support_to_gsm88(msc->audio_support[i]);
		if (test_codec_pref(ct, scl, perm_spch)) {
			match = true;
			break;
		}
	}

	/* Exit without result, in case no match can be deteched */
	if (!match) {
		*full_rate = -1;
		*chan_mode = GSM48_CMODE_SIGN;
		return -1;
	}

	/* Check if the result is a half or full rate codec */
	if (perm_spch == GSM0808_PERM_HR1 || perm_spch == GSM0808_PERM_HR2
	    || perm_spch == GSM0808_PERM_HR3 || perm_spch == GSM0808_PERM_HR4
	    || perm_spch == GSM0808_PERM_HR6)
		*full_rate = 0;
	else
		*full_rate = 1;

	/* Lookup a channel mode for the selected codec */
	*chan_mode = gsm88_to_chan_mode(perm_spch);

	return 0;
}

static int bssmap_handle_reset_ack(struct bsc_msc_data *msc,
				   struct msgb *msg, unsigned int length)
{
	LOGP(DMSC, LOGL_NOTICE, "RESET ACK from MSC: %s\n",
	     osmo_sccp_addr_name(osmo_ss7_instance_find(msc->a.cs7_instance),
				 &msc->a.msc_addr));

	/* Inform the FSM that controls the RESET/RESET-ACK procedure
	 * that we have successfully received the reset-ack message */
	a_reset_ack_confirm(msc->a.reset);

	return 0;
}

/* Handle MSC sided reset */
static int bssmap_handle_reset(struct bsc_msc_data *msc,
			       struct msgb *msg, unsigned int length)
{
	LOGP(DMSC, LOGL_NOTICE, "RESET from MSC: %s\n",
	     osmo_sccp_addr_name(osmo_ss7_instance_find(msc->a.cs7_instance),
				 &msc->a.msc_addr));

	/* Instruct the bsc to close all open sigtran connections and to
	 * close all active channels on the BTS side as well */
	osmo_bsc_sigtran_reset(msc);

	/* Inform the MSC that we have received the reset request and
	 * that we acted accordingly */
	osmo_bsc_sigtran_tx_reset_ack(msc);

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

	osmo_bsc_sigtran_send(conn, resp);
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

	osmo_bsc_sigtran_send(conn, resp);
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
	uint8_t timeslot = 0;
	uint8_t multiplex = 0;
	enum gsm48_chan_mode chan_mode = GSM48_CMODE_SIGN;
	int port, full_rate = -1;
	bool aoip = false;
	struct sockaddr_storage rtp_addr;
	struct sockaddr_in *rtp_addr_in;
	struct gsm0808_channel_type ct;
	struct gsm0808_speech_codec_list scl;
	struct gsm0808_speech_codec_list *scl_ptr = NULL;
	int rc;
	const uint8_t *data;
	char len;

	if (!conn->conn) {
		LOGP(DMSC, LOGL_ERROR,
		     "No lchan/msc_data in cipher mode command.\n");
		return -1;
	}

	msc = conn->msc;

	tlv_parse(&tp, gsm0808_att_tlvdef(), msg->l4h + 1, length - 1, 0, 0);

	/* Check for channel type element, if its missing, immediately reject */
	if (!TLVP_PRESENT(&tp, GSM0808_IE_CHANNEL_TYPE)) {
		LOGP(DMSC, LOGL_ERROR, "Mandatory channel type not present.\n");
		goto reject;
	}

	/* Detect if a CIC code is present, if so, we use the classic ip.access
	 * method to calculate the RTP port */
	if (TLVP_PRESENT(&tp, GSM0808_IE_CIRCUIT_IDENTITY_CODE)) {
		conn->cic =
		    osmo_load16be(TLVP_VAL
				  (&tp, GSM0808_IE_CIRCUIT_IDENTITY_CODE));
		timeslot = conn->cic & 0x1f;
		multiplex = (conn->cic & ~0x1f) >> 5;
	} else if (TLVP_PRESENT(&tp, GSM0808_IE_AOIP_TRASP_ADDR)) {
		/* Decode AoIP transport address element */
		data = TLVP_VAL(&tp, GSM0808_IE_AOIP_TRASP_ADDR);
		len = TLVP_LEN(&tp, GSM0808_IE_AOIP_TRASP_ADDR);
		rc = gsm0808_dec_aoip_trasp_addr(&rtp_addr, data, len);
		if (rc < 0) {
			LOGP(DMSC, LOGL_ERROR,
			     "Unable to decode aoip transport address.\n");
			goto reject;
		}
		aoip = true;
	} else {
		LOGP(DMSC, LOGL_ERROR,
		     "transport address missing. Audio routing will not work.\n");
		goto reject;
	}

	/* Decode speech codec list (AoIP) */
	if (aoip) {
		/* Check for speech codec list element */
		if (!TLVP_PRESENT(&tp, GSM0808_IE_SPEECH_CODEC_LIST)) {
			LOGP(DMSC, LOGL_ERROR,
			     "Mandatory speech codec list not present.\n");
			goto reject;
		}

		/* Decode Speech Codec list */
		data = TLVP_VAL(&tp, GSM0808_IE_SPEECH_CODEC_LIST);
		len = TLVP_LEN(&tp, GSM0808_IE_SPEECH_CODEC_LIST);
		rc = gsm0808_dec_speech_codec_list(&scl, data, len);
		if (rc < 0) {
			LOGP(DMSC, LOGL_ERROR,
			     "Unable to decode speech codec list\n");
			goto reject;
		}
		scl_ptr = &scl;
	}

	/* Decode Channel Type element */
	data = TLVP_VAL(&tp, GSM0808_IE_CHANNEL_TYPE);
	len = TLVP_LEN(&tp, GSM0808_IE_CHANNEL_TYPE);
	rc = gsm0808_dec_channel_type(&ct, data, len);
	if (rc < 0) {
		LOGP(DMSC, LOGL_ERROR, "unable to decode channel type.\n");
		goto reject;
	}

	/* Currently we only support a limited subset of all
	 * possible channel types. The limitation ends by not using
	 * multi-slot, limiting the channel coding to speech */
	if (ct.ch_indctr != GSM0808_CHAN_SPEECH) {
		LOGP(DMSC, LOGL_ERROR,
		     "Unsupported channel type, currently only speech is supported!\n");
		goto reject;
	}

	/* Match codec information from the assignment command against the
	 * local preferences of the BSC */
	rc = match_codec_pref(&full_rate, &chan_mode, &ct, scl_ptr, msc);
	if (rc < 0) {
		LOGP(DMSC, LOGL_ERROR, "No supported audio type found.\n");
		goto reject;
	}

	if (aoip == false) {
		/* map it to a MGCP Endpoint and a RTP port */
		port = mgcp_timeslot_to_endpoint(multiplex, timeslot);
		conn->rtp_port = rtp_calculate_port(port, msc->rtp_base);
		conn->rtp_ip = 0;
	} else {
		/* use address / port supplied with the AoIP
		 * transport address element */
		if (rtp_addr.ss_family == AF_INET) {
			rtp_addr_in = (struct sockaddr_in *)&rtp_addr;
			conn->rtp_port = osmo_ntohs(rtp_addr_in->sin_port);
			memcpy(&conn->rtp_ip, &rtp_addr_in->sin_addr.s_addr,
			       IP_V4_ADDR_LEN);
			conn->rtp_ip = osmo_ntohl(conn->rtp_ip);
		} else {
			LOGP(DMSC, LOGL_ERROR,
			     "Unsopported addressing scheme. (supports only IPV4)\n");
			goto reject;
		}
	}

	return gsm0808_assign_req(conn->conn, chan_mode, full_rate);

reject:
	resp =
	    gsm0808_create_assignment_failure
	    (GSM0808_CAUSE_NO_RADIO_RESOURCE_AVAILABLE, NULL);
	if (!resp) {
		LOGP(DMSC, LOGL_ERROR, "Channel allocation failure.\n");
		return -1;
	}

	osmo_bsc_sigtran_send(conn, resp);
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
	case BSS_MAP_MSG_RESET:
		ret = bssmap_handle_reset(msc, msg, length);
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

int bsc_handle_dt(struct osmo_bsc_sccp_con *conn,
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
