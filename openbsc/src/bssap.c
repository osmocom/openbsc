/* GSM 08.08 BSSMAP handling						*/
/* (C) 2009 by Holger Hans Peter Freyther <zecke@selfish.org>
 * (C) 2009 by On-Waves
 * All Rights Reserved
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 */

#include <openbsc/bssap.h>
#include <openbsc/bsc_rll.h>
#include <openbsc/gsm_04_08.h>
#include <openbsc/gsm_subscriber.h>
#include <openbsc/debug.h>
#include <openbsc/mgcp.h>
#include <openbsc/signal.h>
#include <openbsc/paging.h>
#include <openbsc/chan_alloc.h>

#include <osmocore/gsm0808.h>

#include <sccp/sccp.h>

#include <arpa/inet.h>
#include <assert.h>


#define BSSMAP_MSG_SIZE 512
#define BSSMAP_MSG_HEADROOM 128

#define LINK_ID_CB 0

static void bts_queue_send(struct msgb *msg, int link_id);
static void bssmap_free_secondary(struct bss_sccp_connection_data *data);

static uint32_t read_data32(const uint8_t *data)
{
	uint32_t res;

	memcpy(&res, data, sizeof(res));
	return res;
}

static u_int16_t get_network_code_for_msc(struct gsm_network *net)
{
	if (net->core_network_code > 0)
		return net->core_network_code;
	return net->network_code;
}

static u_int16_t get_country_code_for_msc(struct gsm_network *net)
{
	if (net->core_country_code > 0)
		return net->core_country_code;
	return net->country_code;
}

static int bssmap_paging_cb(unsigned int hooknum, unsigned int event, struct msgb *msg, void *data, void *param)
{
	LOGP(DPAG, LOGL_DEBUG, "Paging is complete.\n");
	return 0;
}

static int bssmap_handle_reset_ack(struct gsm_network *net, struct msgb *msg, unsigned int length)
{
	LOGP(DMSC, LOGL_NOTICE, "Reset ACK from MSC\n");

	return 0;
}

/* GSM 08.08 § 3.2.1.19 */
static int bssmap_handle_paging(struct gsm_network *net, struct msgb *msg, unsigned int payload_length)
{
	struct tlv_parsed tp;
	char mi_string[GSM48_MI_SIZE];
	u_int32_t tmsi = GSM_RESERVED_TMSI;
	unsigned int lac = GSM_LAC_RESERVED_ALL_BTS;
	u_int8_t data_length;
	const u_int8_t *data;
	struct gsm_subscriber *subscr;
	u_int8_t chan_needed = RSL_CHANNEED_ANY;
	int paged;

	tlv_parse(&tp, gsm0808_att_tlvdef(), msg->l4h + 1, payload_length - 1, 0, 0);

	if (!TLVP_PRESENT(&tp, GSM0808_IE_IMSI)) {
		LOGP(DMSC, LOGL_ERROR, "Mandantory IMSI not present.\n");
		return -1;
	} else if ((TLVP_VAL(&tp, GSM0808_IE_IMSI)[0] & GSM_MI_TYPE_MASK) != GSM_MI_TYPE_IMSI) {
		LOGP(DMSC, LOGL_ERROR, "Wrong content in the IMSI\n");
		return -1;
	}

	if (!TLVP_PRESENT(&tp, GSM0808_IE_CELL_IDENTIFIER_LIST)) {
		LOGP(DMSC, LOGL_ERROR, "Mandantory CELL IDENTIFIER LIST not present.\n");
		return -1;
	}

	if (TLVP_PRESENT(&tp, GSM0808_IE_TMSI)) {
		gsm48_mi_to_string(mi_string, sizeof(mi_string),
			   TLVP_VAL(&tp, GSM0808_IE_TMSI), TLVP_LEN(&tp, GSM0808_IE_TMSI));
		tmsi = strtoul(mi_string, NULL, 10);
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
		lac = ntohs(read_data32(&data[1]));
	} else if (data_length > 1 || (data[0] & 0x0f) != CELL_IDENT_BSS) {
		LOGP(DMSC, LOGL_ERROR, "Unsupported Cell Identifier List: %s\n", hexdump(data, data_length));
		return -1;
	}

	if (TLVP_PRESENT(&tp, GSM0808_IE_CHANNEL_NEEDED) && TLVP_LEN(&tp, GSM0808_IE_CHANNEL_NEEDED) == 1)
		chan_needed = TLVP_VAL(&tp, GSM0808_IE_CHANNEL_NEEDED)[0] & 0x03;

	if (TLVP_PRESENT(&tp, GSM0808_IE_EMLPP_PRIORITY)) {
		LOGP(DMSC, LOGL_ERROR, "eMLPP is not handled\n");
	}

	LOGP(DMSC, LOGL_DEBUG, "Paging request from MSC IMSI: '%s' TMSI: '0x%x/%u' LAC: 0x%x\n", mi_string, tmsi, tmsi, lac);
	subscr = subscr_get_or_create(net, mi_string);
	if (!subscr)
		return -1;

	/* reassign the tmsi, trust the net over our internal state */
	subscr->tmsi = tmsi;
	subscr->lac = lac;
	paged = paging_request(net, subscr, chan_needed, bssmap_paging_cb, subscr);
	LOGP(DPAG, LOGL_DEBUG, "Paged IMSI: '%s' TMSI: '0x%x/%u' LAC: 0x%x on #bts: %d\n", mi_string, tmsi, tmsi, lac, paged);

	subscr_put(subscr);
	return -1;
}

/* GSM 08.08 § 3.1.9.1 and 3.2.1.21... release our gsm_lchan and send message */
static int bssmap_handle_clear_command(struct sccp_connection *conn,
				       struct msgb *msg, unsigned int payload_length)
{
	struct msgb *resp;

	/* TODO: handle the cause of this package */

	if (msg->lchan) {
		LOGP(DMSC, LOGL_DEBUG, "Releasing all transactions on %p\n", conn);
		bsc_del_timer(&msg->lchan->msc_data->T10);
		msg->lchan->msc_data->lchan = NULL;

		/* we might got killed during an assignment */
		bssmap_free_secondary(msg->lchan->msc_data);

		msg->lchan->msc_data = NULL;
		msg->lchan->conn.hand_off += 1;
		put_subscr_con(&msg->lchan->conn, 0);
	}

	/* send the clear complete message */
	resp = gsm0808_create_clear_complete();
	if (!resp) {
		LOGP(DMSC, LOGL_ERROR, "Sending clear complete failed.\n");
		return -1;
	}

	bsc_queue_connection_write(conn, resp);
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
static int bssmap_handle_cipher_mode(struct sccp_connection *conn,
				     struct msgb *msg, unsigned int payload_length)
{
	u_int16_t len;
	struct gsm_network *network = NULL;
	const u_int8_t *data;
	struct tlv_parsed tp;
	struct msgb *resp;
	int reject_cause = -1;
	int include_imeisv = 1;

	if (!msg->lchan || !msg->lchan->msc_data) {
		LOGP(DMSC, LOGL_ERROR, "No lchan/msc_data in cipher mode command.\n");
		goto reject;
	}

	if (msg->lchan->msc_data->ciphering_handled) {
		LOGP(DMSC, LOGL_ERROR, "Already seen ciphering command. Protocol Error.\n");
		goto reject;
	}

	msg->lchan->msc_data->ciphering_handled = 1;
	msg->lchan->msc_data->block_gsm = 1;

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

	network = msg->lchan->ts->trx->bts->network;
	data = TLVP_VAL(&tp, GSM0808_IE_ENCRYPTION_INFORMATION);

	if (network->a5_encryption == 0 && (data[0] & 0x1) == 0x1) {
		msg->lchan->encr.alg_id = RSL_ENC_ALG_A5(0);
	} else if (network->a5_encryption != 0 && (data[0] & 0x2) == 0x2) {
		msg->lchan->encr.alg_id = RSL_ENC_ALG_A5(1);
		msg->lchan->encr.key_len = len - 1;
		memcpy(msg->lchan->encr.key, &data[1], len - 1);
	} else {
		LOGP(DMSC, LOGL_ERROR, "Can not select encryption...\n");
		goto reject;
	}

	if (TLVP_PRESENT(&tp, GSM0808_IE_CIPHER_RESPONSE_MODE)) {
		include_imeisv = TLVP_VAL(&tp, GSM0808_IE_CIPHER_RESPONSE_MODE)[0] & 0x1;
	}

	return gsm48_send_rr_ciph_mode(msg->lchan, include_imeisv);

reject:
	if (msg->lchan && msg->lchan->msc_data)
		msg->lchan->msc_data->block_gsm = 0;

	resp = gsm0808_create_cipher_reject(reject_cause);
	if (!resp) {
		LOGP(DMSC, LOGL_ERROR, "Sending the cipher reject failed.\n");
		return -1;
	}

	bsc_queue_connection_write(conn, resp);
	return -1;
}

/*
 * handle network failures... and free the secondary lchan
 */
static void bssmap_free_secondary(struct bss_sccp_connection_data *data)
{
	struct gsm_lchan *lchan;

	if (!data || !data->secondary_lchan)
		return;

	lchan = data->secondary_lchan;
	if (lchan->msc_data != data) {
		LOGP(DMSC, LOGL_ERROR, "MSC data does not match on lchan and cb.\n");
		data->secondary_lchan = NULL;
	}

	/* give up additional data */
	lchan->msc_data->secondary_lchan = NULL;
	if (lchan->msc_data->lchan == lchan)
		lchan->msc_data->lchan = NULL;
	lchan->msc_data = NULL;

	/* give up the new channel to not do a SACCH deactivate */
	if (lchan->conn.subscr)
		subscr_put(lchan->conn.subscr);
	lchan->conn.subscr = NULL;
	lchan->conn.hand_off += 1;
	put_subscr_con(&lchan->conn, 1);
}

/*
 * Handle the network configurable T10 parameter
 */
static void bssmap_t10_fired(void *_conn)
{
	struct bss_sccp_connection_data *msc_data;
	struct sccp_connection *conn = (struct sccp_connection *) _conn;
	struct msgb *resp;

	LOGP(DMSC, LOGL_ERROR, "T10 fired, assignment failed: %p\n", conn);

	/* free the secondary channel if we have one */
	msc_data = conn->data_ctx;
	bssmap_free_secondary(msc_data);

	resp = gsm0808_create_assignment_failure(
		GSM0808_CAUSE_NO_RADIO_RESOURCE_AVAILABLE, NULL);
	if (!resp) {
		LOGP(DMSC, LOGL_ERROR, "Allocation failure: %p\n", conn);
		return;
	}

	bsc_queue_connection_write(conn, resp);
}

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

	assert(0);
}

/*
 * The assignment request has started T10. We need to be faster than this
 * or an assignment failure will be sent...
 *
 *  1.) allocate a new lchan
 *  2.) copy the encryption key and other data from the
 *      old to the new channel.
 *  3.) RSL Channel Activate this channel and wait
 *
 * -> Signal handler for the LCHAN
 *  4.) Send GSM 04.08 assignment command to the MS
 *
 * -> Assignment Complete
 *  5.) Release the SDCCH, continue signalling on the new link
 */
static int handle_new_assignment(struct msgb *msg, int full_rate, int chan_mode)
{
	struct bss_sccp_connection_data *msc_data;
	struct gsm_bts *bts;
	struct gsm_lchan *new_lchan;
	int chan_type;

	msc_data = msg->lchan->msc_data;
	bts = msg->lchan->ts->trx->bts;
	chan_type = full_rate ? GSM_LCHAN_TCH_F : GSM_LCHAN_TCH_H;

	new_lchan = lchan_alloc(bts, chan_type, 0);

	if (!new_lchan) {
		LOGP(DMSC, LOGL_NOTICE, "No free channel.\n");
		return -1;
	}

	/* copy old data to the new channel */
	memcpy(&new_lchan->encr, &msg->lchan->encr, sizeof(new_lchan->encr));
	new_lchan->ms_power = msg->lchan->ms_power;
	new_lchan->bs_power = msg->lchan->bs_power;
	if (msg->lchan->conn.subscr)
		new_lchan->conn.subscr = subscr_get(msg->lchan->conn.subscr);

	/* copy new data to it */
	use_subscr_con(&new_lchan->conn);
	new_lchan->tch_mode = chan_mode;
	new_lchan->rsl_cmode = RSL_CMOD_SPD_SPEECH;

	/* handle AMR correctly */
	if (chan_mode == GSM48_CMODE_SPEECH_AMR) {
		new_lchan->mr_conf.ver = 1;
		new_lchan->mr_conf.icmi = 1;
		new_lchan->mr_conf.m5_90 = 1;
	}

	if (rsl_chan_activate_lchan(new_lchan, 0x1, 0, 0) < 0) {
		LOGP(DHO, LOGL_ERROR, "could not activate channel\n");
		lchan_free(new_lchan);
		return -1;
	}

	rsl_lchan_set_state(new_lchan, LCHAN_S_ACT_REQ);
	msc_data->secondary_lchan = new_lchan;
	new_lchan->msc_data = msc_data;
	return 0;
}

/*
 * Any failure will be caught with the T10 timer ticking...
 */
static void continue_new_assignment(struct gsm_lchan *new_lchan)
{
	if (!new_lchan->msc_data) {
		LOGP(DMSC, LOGL_ERROR, "No BSS data found.\n");
		new_lchan->conn.hand_off += 1;
		put_subscr_con(&new_lchan->conn, 0);
		return;
	}

	if (new_lchan->msc_data->secondary_lchan != new_lchan) {
		LOGP(DMSC, LOGL_ERROR, "This is not the secondary channel?\n");
		new_lchan->msc_data = NULL;
		new_lchan->conn.hand_off += 1;
		put_subscr_con(&new_lchan->conn, 0);
		return;
	}

	LOGP(DMSC, LOGL_NOTICE, "Sending assignment on chan: %p\n", new_lchan);
	gsm48_send_rr_ass_cmd(new_lchan->msc_data->lchan, new_lchan, 0x3);
}

/*
 * Handle the assignment request message.
 *
 * See §3.2.1.1 for the message type
 */
static int bssmap_handle_assignm_req(struct sccp_connection *conn,
				     struct msgb *msg, unsigned int length)
{
	struct gsm_network *network;
	struct tlv_parsed tp;
	struct bss_sccp_connection_data *msc_data;
	u_int8_t *data;
	u_int16_t cic;
	u_int8_t timeslot;
	u_int8_t multiplex;
	enum gsm48_chan_mode chan_mode = GSM48_CMODE_SIGN;
	int i, supported, port, full_rate = -1;

	if (!msg->lchan || !msg->lchan->msc_data) {
		LOGP(DMSC, LOGL_ERROR, "No lchan/msc_data in cipher mode command.\n");
		return -1;
	}

	msc_data = msg->lchan->msc_data;
	network = msg->lchan->ts->trx->bts->network;
	tlv_parse(&tp, gsm0808_att_tlvdef(), msg->l4h + 1, length - 1, 0, 0);

	if (!TLVP_PRESENT(&tp, GSM0808_IE_CHANNEL_TYPE)) {
		LOGP(DMSC, LOGL_ERROR, "Mandantory channel type not present.\n");
		goto reject;
	}

	if (!TLVP_PRESENT(&tp, GSM0808_IE_CIRCUIT_IDENTITY_CODE)) {
		LOGP(DMSC, LOGL_ERROR, "Identity code missing. Audio routing will not work.\n");
		goto reject;
	}

	cic = ntohs(*(u_int16_t *)TLVP_VAL(&tp, GSM0808_IE_CIRCUIT_IDENTITY_CODE));
	timeslot = cic & 0x1f;
	multiplex = (cic & ~0x1f) >> 5;

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

	data = (u_int8_t *) TLVP_VAL(&tp, GSM0808_IE_CHANNEL_TYPE);
	if ((data[0] & 0xf) != 0x1) {
		LOGP(DMSC, LOGL_ERROR, "ChannelType != speech: %d\n", data[0]);
		goto reject;
	}

	if (data[1] != GSM0808_SPEECH_FULL_PREF && data[1] != GSM0808_SPEECH_HALF_PREF) {
		LOGP(DMSC, LOGL_ERROR, "ChannelType full not allowed: %d\n", data[1]);
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
	for (supported = 0;
		chan_mode == GSM48_CMODE_SIGN && supported < network->audio_length;
		++supported) {

		int perm_val = audio_support_to_gsm88(network->audio_support[supported]);
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

	/* modify the channel now */
	msc_data->T10.cb = bssmap_t10_fired;
	msc_data->T10.data = conn;
	bsc_schedule_timer(&msc_data->T10, GSM0808_T10_VALUE);

	/* the mgcp call agent starts counting at one. a bit of a weird mapping */
	port = mgcp_timeslot_to_endpoint(multiplex, timeslot);
	msc_data->rtp_port = rtp_calculate_port(port,
						network->rtp_base_port);

	if (msg->lchan->type == GSM_LCHAN_SDCCH) {
		/* start to assign a new channel, if it works */
		if (handle_new_assignment(msg, full_rate, chan_mode) == 0)
			return 0;
		else
			goto reject;
	} else {
		LOGP(DMSC, LOGL_ERROR, "Sending ChanModify for speech on: sccp: %p mode: 0x%x on port %d %d/0x%x port: %u\n",
			conn, chan_mode, port, multiplex, timeslot, msc_data->rtp_port);

		if (chan_mode == GSM48_CMODE_SPEECH_AMR) {
			msg->lchan->mr_conf.ver = 1;
			msg->lchan->mr_conf.icmi = 1;
			msg->lchan->mr_conf.m5_90 = 1;
		}

		return gsm48_lchan_modify(msg->lchan, chan_mode);
	}

reject:
	gsm0808_send_assignment_failure(msg->lchan,
					GSM0808_CAUSE_NO_RADIO_RESOURCE_AVAILABLE, NULL);
	return -1;
}

int bssmap_rcvmsg_udt(struct gsm_network *net, struct msgb *msg, unsigned int length)
{
	int ret = 0;

	if (length < 1) {
		LOGP(DMSC, LOGL_ERROR, "Not enough room: %d\n", length);
		return -1;
	}

	switch (msg->l4h[0]) {
	case BSS_MAP_MSG_RESET_ACKNOWLEDGE:
		ret = bssmap_handle_reset_ack(net, msg, length);
		break;
	case BSS_MAP_MSG_PAGING:
		ret = bssmap_handle_paging(net, msg, length);
		break;
	}

	return ret;
}

int bssmap_rcvmsg_dt1(struct sccp_connection *conn, struct msgb *msg, unsigned int length)
{
	int ret = 0;

	if (length < 1) {
		LOGP(DMSC, LOGL_ERROR, "Not enough room: %d\n", length);
		return -1;
	}

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
		LOGP(DMSC, LOGL_DEBUG, "Unimplemented msg type: %d\n", msg->l4h[0]);
		break;
	}

	return ret;
}

int dtap_rcvmsg(struct gsm_lchan *lchan, struct msgb *msg, unsigned int length)
{
	struct dtap_header *header;
	struct msgb *gsm48;
	u_int8_t *data;
	u_int8_t link_id;

	if (!lchan) {
		LOGP(DMSC, LOGL_ERROR, "No lchan available\n");
		return -1;
	}

	header = (struct dtap_header *) msg->l3h;
	if (sizeof(*header) >= length) {
		LOGP(DMSC, LOGL_ERROR, "The DTAP header does not fit. Wanted: %u got: %u\n", sizeof(*header), length);
                LOGP(DMSC, LOGL_ERROR, "hex: %s\n", hexdump(msg->l3h, length));
                return -1;
	}

	if (header->length > length - sizeof(*header)) {
		LOGP(DMSC, LOGL_ERROR, "The DTAP l4 information does not fit: header: %u length: %u\n", header->length, length);
                LOGP(DMSC, LOGL_ERROR, "hex: %s\n", hexdump(msg->l3h, length));
		return -1;
	}

	LOGP(DMSC, LOGL_DEBUG, "DTAP message: SAPI: %u CHAN: %u\n", header->link_id & 0x07, header->link_id & 0xC0);

	/* forward the data */
	gsm48 = gsm48_msgb_alloc();
	if (!gsm48) {
		LOGP(DMSC, LOGL_ERROR, "Allocation of the message failed.\n");
		return -1;
	}

	gsm48->lchan = lchan;
	gsm48->trx = gsm48->lchan->ts->trx;
	gsm48->l3h = gsm48->data;
	data = msgb_put(gsm48, length - sizeof(*header));
	memcpy(data, msg->l3h + sizeof(*header), length - sizeof(*header));

	/*
	 * This is coming from the network. We need to regenerate the
	 * LAI for the Location Update Accept packet and maybe more
	 * as well.
	 */
	if (gsm48->trx->bts->network->core_network_code > 0 ||
	    gsm48->trx->bts->network->core_country_code > 0) {
		if (msgb_l3len(gsm48) >= sizeof(struct gsm48_loc_area_id) + 1) {
			struct gsm48_hdr *gh = (struct gsm48_hdr *)gsm48->l3h;
			if (gh->msg_type == GSM48_MT_MM_LOC_UPD_ACCEPT) {
				struct gsm_network *net = gsm48->trx->bts->network;
				struct gsm48_loc_area_id *lai = (struct gsm48_loc_area_id *) &gh->data[0];
				gsm48_generate_lai(lai, net->country_code,
						   net->network_code,
						   gsm48->trx->bts->location_area_code);
			}
		}
	}

	link_id = header->link_id;

	/* If we are on a TCH and need to submit a SMS (on SAPI=3) we need to use the SACH */
	if ((lchan->type == GSM_LCHAN_TCH_F ||
	     lchan->type == GSM_LCHAN_TCH_H) && (link_id & 0x7) != 0)
		link_id |= 0x40;

	bts_queue_send(gsm48, link_id);
	return 0;
}

/* Create messages */
struct msgb *bssmap_create_layer3(struct msgb *msg_l3)
{
	struct gsm_bts *bts = msg_l3->lchan->ts->trx->bts;
	u_int16_t network_code = get_network_code_for_msc(bts->network);
	u_int16_t country_code = get_country_code_for_msc(bts->network);

	return gsm0808_create_layer3(msg_l3, network_code, country_code,
				     bts->location_area_code, bts->cell_identity);
}

static u_int8_t chan_mode_to_speech(struct gsm_lchan *lchan)
{
	int mode = 0;

	switch (lchan->tch_mode) {
	case GSM48_CMODE_SPEECH_V1:
		mode = 1;
		break;
	case GSM48_CMODE_SPEECH_EFR:
		mode = 0x11;
		break;
	case GSM48_CMODE_SPEECH_AMR:
		mode = 0x21;
		break;
	case GSM48_CMODE_SIGN:
	case GSM48_CMODE_DATA_14k5:
	case GSM48_CMODE_DATA_12k0:
	case GSM48_CMODE_DATA_6k0:
	case GSM48_CMODE_DATA_3k6:
	default:
		LOGP(DMSC, LOGL_ERROR, "Using non speech mode: %d\n", mode);
		return 0;
		break;
	}

	/* assume to always do AMR HR on any TCH type */
	if (lchan->type == GSM_LCHAN_TCH_H ||
	    lchan->tch_mode == GSM48_CMODE_SPEECH_AMR)
		mode |= 0x4;

        return mode;
}

/* 3.2.2.33 */
static u_int8_t lchan_to_chosen_channel(struct gsm_lchan *lchan)
{
	u_int8_t channel_mode = 0, channel = 0;

	switch (lchan->tch_mode) {
	case GSM48_CMODE_SPEECH_V1:
	case GSM48_CMODE_SPEECH_EFR:
	case GSM48_CMODE_SPEECH_AMR:
		channel_mode = 0x9;
		break;
	case GSM48_CMODE_SIGN:
		channel_mode = 0x8;
		break;
	case GSM48_CMODE_DATA_14k5:
		channel_mode = 0xe;
		break;
	case GSM48_CMODE_DATA_12k0:
		channel_mode = 0xb;
		break;
	case GSM48_CMODE_DATA_6k0:
		channel_mode = 0xc;
		break;
	case GSM48_CMODE_DATA_3k6:
		channel_mode = 0xd;
		break;
	}

	switch (lchan->type) {
	case GSM_LCHAN_NONE:
		channel = 0x0;
		break;
	case GSM_LCHAN_SDCCH:
		channel = 0x1;
		break;
	case GSM_LCHAN_TCH_F:
		channel = 0x8;
		break;
	case GSM_LCHAN_TCH_H:
		channel = 0x9;
		break;
	case GSM_LCHAN_UNKNOWN:
		LOGP(DMSC, LOGL_ERROR, "Unknown lchan type: %p\n", lchan);
		break;
	}

	return channel_mode << 4 | channel;
}

struct msgb *bssmap_create_assignment_completed(struct gsm_lchan *lchan, u_int8_t rr_cause)
{
	return gsm0808_create_assignment_completed(rr_cause,
						   lchan_to_chosen_channel(lchan),
						   lchan->encr.alg_id,
						   chan_mode_to_speech(lchan));
}

struct msgb *dtap_create_msg(struct msgb *msg_l3, u_int8_t link_id)
{
	struct dtap_header *header;
	u_int8_t *data;
	struct msgb *msg = msgb_alloc_headroom(BSSMAP_MSG_SIZE, BSSMAP_MSG_HEADROOM,
					       "dtap");
	if (!msg)
		return NULL;

	/* DTAP header */
	msg->l3h = msgb_put(msg, sizeof(*header));
	header = (struct dtap_header *) &msg->l3h[0];
	header->type = BSSAP_MSG_DTAP;
	header->link_id = link_id;
	header->length = msgb_l3len(msg_l3);

	/* Payload */
	data = msgb_put(msg, header->length);
	memcpy(data, msg_l3->l3h, header->length);

	return msg;
}

static int bssap_handle_lchan_signal(unsigned int subsys, unsigned int signal,
				     void *handler_data, void *signal_data)
{
	struct msgb *msg;
	struct gsm_lchan *lchan;
	struct sccp_connection *conn;

	/*
	 * If we have a SCCP Connection we need to inform the MSC about
         * the resource error and then drop the lchan<->sccp association.
	 */
	switch (subsys) {
	case SS_LCHAN:
		lchan = (struct gsm_lchan *)signal_data;

		if (!lchan || !lchan->msc_data)
			return 0;
		switch (signal) {
		case S_LCHAN_UNEXPECTED_RELEASE:
			/* handle this through the T10 timeout */
			if (lchan->msc_data->lchan != lchan) {
				if (lchan->msc_data->secondary_lchan == lchan) {
					LOGP(DMSC, LOGL_NOTICE, "Setting secondary to NULL.\n");
					lchan->msc_data->secondary_lchan = NULL;
					lchan->msc_data = NULL;
				}
				return 0;
			}

			bsc_del_timer(&lchan->msc_data->T10);
			conn = lchan->msc_data->sccp;
			lchan->msc_data->lchan = NULL;
			lchan->msc_data = NULL;

			msg = msgb_alloc(30, "sccp: clear request");
			if (!msg) {
				LOGP(DMSC, LOGL_ERROR, "Failed to allocate clear request.\n");
				return 0;
			}

			msg->l3h = msgb_put(msg, 2 + 4);
			msg->l3h[0] = BSSAP_MSG_BSS_MANAGEMENT;
			msg->l3h[1] = 4;

			msg->l3h[2] = BSS_MAP_MSG_CLEAR_RQST;
			msg->l3h[3] = GSM0808_IE_CAUSE;
			msg->l3h[4] = 1;
			msg->l3h[5] = GSM0808_CAUSE_RADIO_INTERFACE_FAILURE;

			LOGP(DMSC, LOGL_NOTICE, "Sending clear request on unexpected channel release.\n");
			bsc_queue_connection_write(conn, msg);
			break;
		case S_LCHAN_ACTIVATE_ACK:
			continue_new_assignment(lchan);
			break;
		case S_LCHAN_ACTIVATE_NACK:
			if (lchan->msc_data && lchan->msc_data->secondary_lchan == lchan) {
				LOGP(DMSC, LOGL_ERROR, "Activating a secondary lchan failed.\n");

				/*
				 * The channel will be freed, so let us forget about it, T10 will
				 * fire and we will send the assignment failure to the network. We
				 * do not give up the refcount so we will get another unexpected
				 * release... but that will be handled just fine.
				 */
				lchan->msc_data->secondary_lchan = NULL;
				lchan->msc_data = NULL;
			}
			break;
		}
		break;
	}

	return 0;
}

/*
 * queue handling for BSS AP
 */
void bsc_queue_connection_write(struct sccp_connection *conn, struct msgb *msg)
{
	struct bss_sccp_connection_data *data;

	data = (struct bss_sccp_connection_data *)conn->data_ctx;

	if (conn->connection_state > SCCP_CONNECTION_STATE_ESTABLISHED) {
		LOGP(DMSC, LOGL_ERROR, "Connection closing, dropping packet on: %p\n", conn);
		msgb_free(msg);
	} else if (conn->connection_state == SCCP_CONNECTION_STATE_ESTABLISHED
		   && data->sccp_queue_size == 0) {
		sccp_connection_write(conn, msg);
		msgb_free(msg);
	} else if (data->sccp_queue_size > 10) {
		LOGP(DMSC, LOGL_ERROR, "Dropping packet on %p due queue overflow\n", conn);
		msgb_free(msg);
	} else {
		LOGP(DMSC, LOGL_DEBUG, "Queuing packet on %p. Queue size: %d\n", conn, data->sccp_queue_size);
		++data->sccp_queue_size;
		msgb_enqueue(&data->sccp_queue, msg);
	}
}

void bsc_free_queued(struct sccp_connection *conn)
{
	struct bss_sccp_connection_data *data;
	struct msgb *msg;

	data = (struct bss_sccp_connection_data *)conn->data_ctx;
	while (!llist_empty(&data->sccp_queue)) {
		/* this is not allowed to fail */
		msg = msgb_dequeue(&data->sccp_queue);
		msgb_free(msg);
	}

	data->sccp_queue_size = 0;
}

void bsc_send_queued(struct sccp_connection *conn)
{
	struct bss_sccp_connection_data *data;
	struct msgb *msg;

	data = (struct bss_sccp_connection_data *)conn->data_ctx;

	while (!llist_empty(&data->sccp_queue)) {
		/* this is not allowed to fail */
		msg = msgb_dequeue(&data->sccp_queue);
		sccp_connection_write(conn, msg);
		msgb_free(msg);
		--data->sccp_queue_size;
	}
}

/* RLL callback */
static void rll_ind_cb(struct gsm_lchan *lchan, u_int8_t link_id,
		       void *_data, enum bsc_rllr_ind rllr_ind)
{
	struct sccp_source_reference ref = sccp_src_ref_from_int((u_int32_t) _data);
	struct bss_sccp_connection_data *data = lchan->msc_data;

	if (!data || !data->sccp) {
		LOGP(DMSC, LOGL_ERROR, "Time-out/Establish after sccp release? Ind: %d lchan: %p\n",
		       rllr_ind, lchan);
		return;
	}

	if (memcmp(&data->sccp->source_local_reference, &ref, sizeof(ref)) != 0) {
		LOGP(DMSC, LOGL_ERROR, "Wrong SCCP connection. Not handling RLL callback: %u %u\n",
			sccp_src_ref_to_int(&ref),
			sccp_src_ref_to_int(&data->sccp->source_local_reference));
		return;
	}

	switch (rllr_ind) {
	case BSC_RLLR_IND_EST_CONF:
		/* nothing to do */
		bts_send_queued(data);
		break;
	case BSC_RLLR_IND_REL_IND:
	case BSC_RLLR_IND_ERR_IND:
	case BSC_RLLR_IND_TIMEOUT: {
		/* reject  queued messages */
		struct msgb *sapi_reject;

		bts_free_queued(data);
		sapi_reject = gsm0808_create_sapi_reject(link_id);
		if (!sapi_reject){
			LOGP(DMSC, LOGL_ERROR, "Failed to create SAPI reject\n");
			return;
		}

		bsc_queue_connection_write(data->sccp, sapi_reject);
		break;
	}
	}
}

/* decide if we need to queue because of SAPI != 0 */
static void bts_queue_send(struct msgb *msg, int link_id)
{

	struct bss_sccp_connection_data *data;

	if (!msg->lchan || !msg->lchan->msc_data) {
		LOGP(DMSC, LOGL_ERROR, "BAD: Wrongly configured lchan: %p\n", msg->lchan);
		msgb_free(msg);
	}

	data = msg->lchan->msc_data;

	if (!data->block_gsm && data->gsm_queue_size == 0) {
		if (msg->lchan->sapis[link_id & 0x7] != LCHAN_SAPI_UNUSED) {
			rsl_data_request(msg, link_id);
		} else {
			msg->cb[LINK_ID_CB] = link_id;
			msgb_enqueue(&data->gsm_queue, msg);
			++data->gsm_queue_size;

			/* establish link */
			rll_establish(msg->lchan, link_id & 0x7,
				      rll_ind_cb,
				      (void *)sccp_src_ref_to_int(&data->sccp->source_local_reference));
		}
	} else if (data->gsm_queue_size == 10) {
		LOGP(DMSC, LOGL_ERROR, "Queue full on %p. Dropping GSM0408.\n", data->sccp);
		msgb_free(msg);
	} else {
		LOGP(DMSC, LOGL_DEBUG, "Queueing GSM0408 message on %p. Queue size: %d\n",
		       data->sccp, data->gsm_queue_size + 1);

		msg->cb[LINK_ID_CB] = link_id;
		msgb_enqueue(&data->gsm_queue, msg);
		++data->gsm_queue_size;
	}
}

void bts_free_queued(struct bss_sccp_connection_data *data)
{
	struct msgb *msg;

	while (!llist_empty(&data->gsm_queue)) {
		/* this is not allowed to fail */
		msg = msgb_dequeue(&data->gsm_queue);
		msgb_free(msg);
	}

	data->gsm_queue_size = 0;
}

void bts_send_queued(struct bss_sccp_connection_data *data)
{
	struct msgb *msg;

	while (!llist_empty(&data->gsm_queue)) {
		/* this is not allowed to fail */
		msg = msgb_dequeue(&data->gsm_queue);
		rsl_data_request(msg, msg->cb[LINK_ID_CB]);
	}

	data->gsm_queue_size = 0;
}

void bts_unblock_queue(struct bss_sccp_connection_data *data)
{
	struct msgb *msg;
	LLIST_HEAD(head);

	/* move the messages to a new list */
	data->block_gsm = 0;
	data->gsm_queue_size = 0;
	while (!llist_empty(&data->gsm_queue)) {
		msg = msgb_dequeue(&data->gsm_queue);
		msgb_enqueue(&head, msg);
	}

	/* now queue them again to send RSL establish and such */
	while (!llist_empty(&head)) {
		msg = msgb_dequeue(&head);
		bts_queue_send(msg, msg->cb[LINK_ID_CB]);
	}
}

void gsm0808_send_assignment_failure(struct gsm_lchan *lchan, u_int8_t cause, u_int8_t *rr_value)
{
	struct msgb *resp;

	bsc_del_timer(&lchan->msc_data->T10);
	bssmap_free_secondary(lchan->msc_data);
	resp = gsm0808_create_assignment_failure(cause, rr_value);
	if (!resp) {
		LOGP(DMSC, LOGL_ERROR, "Allocation failure: %p\n", lchan_get_sccp(lchan));
		return;
	}

	bsc_queue_connection_write(lchan_get_sccp(lchan), resp);
}

void gsm0808_send_assignment_compl(struct gsm_lchan *lchan, u_int8_t rr_cause)
{
	struct msgb *resp;

	bsc_del_timer(&lchan->msc_data->T10);
	resp = bssmap_create_assignment_completed(lchan, rr_cause);
	if (!resp) {
		LOGP(DMSC, LOGL_ERROR, "Creating MSC response failed: %p\n", lchan_get_sccp(lchan));
		return;
	}

	bsc_queue_connection_write(lchan_get_sccp(lchan), resp);
}

static __attribute__((constructor)) void on_dso_load_bssap(void)
{
	register_signal_handler(SS_LCHAN, bssap_handle_lchan_signal, NULL);
}
