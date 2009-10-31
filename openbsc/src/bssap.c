/* GSM 08.08 BSSMAP handling						*/
/* (C) 2009 by Holger Hans Peter Freyther <zecke@selfish.org>
 * (C) 2009 by on-waves.com
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
#include <openbsc/tlv.h>
#include <openbsc/paging.h>

#include <sccp/sccp.h>

#include <arpa/inet.h>


#define BSSMAP_MSG_SIZE 512
#define BSSMAP_MSG_HEADROOM 128


static const struct tlv_definition bss_att_tlvdef = {
	.def = {
		[GSM0808_IE_IMSI]		    = { TLV_TYPE_TLV },
		[GSM0808_IE_TMSI]		    = { TLV_TYPE_TLV },
		[GSM0808_IE_CELL_IDENTIFIER_LIST]   = { TLV_TYPE_TLV },
		[GSM0808_IE_CHANNEL_NEEDED]	    = { TLV_TYPE_TV },
		[GSM0808_IE_EMLPP_PRIORITY]	    = { TLV_TYPE_TV },
		[GSM0808_IE_CHANNEL_TYPE]	    = { TLV_TYPE_TLV },
		[GSM0808_IE_PRIORITY]		    = { TLV_TYPE_TLV },
		[GSM0808_IE_CIRCUIT_IDENTITY_CODE]  = { TLV_TYPE_TV },
		[GSM0808_IE_DOWNLINK_DTX_FLAG]	    = { TLV_TYPE_TV },
		[GSM0808_IE_INTERFERENCE_BAND_TO_USE] = { TLV_TYPE_TV },
		[GSM0808_IE_CLASSMARK_INFORMATION_T2] = { TLV_TYPE_TLV },
		[GSM0808_IE_GROUP_CALL_REFERENCE]   = { TLV_TYPE_TLV },
		[GSM0808_IE_TALKER_FLAG]	    = { TLV_TYPE_T },
		[GSM0808_IE_CONFIG_EVO_INDI]	    = { TLV_TYPE_TV },
		[GSM0808_IE_LSA_ACCESS_CTRL_SUPPR]  = { TLV_TYPE_TV },
		[GSM0808_IE_SERVICE_HANDOVER]	    = { TLV_TYPE_TV},
	},
};


static int bssmap_paging_cb(unsigned int hooknum, unsigned int event, struct msgb *msg, void *data, void *param)
{
	DEBUGP(DMSC, "Paging is complete.\n");
	return 0;
}

static int bssmap_handle_reset_ack(struct gsm_network *net, struct msgb *msg, unsigned int length)
{
	DEBUGP(DMSC, "Reset ACK from MSC\n");

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

	tlv_parse(&tp, &bss_att_tlvdef, msg->l4h + 1, payload_length - 1, 0, 0);

	if (!TLVP_PRESENT(&tp, GSM0808_IE_IMSI)) {
		DEBUGP(DMSC, "Mandantory IMSI not present.\n");
		return -1;
	} else if ((TLVP_VAL(&tp, GSM0808_IE_IMSI)[0] & GSM_MI_TYPE_MASK) != GSM_MI_TYPE_IMSI) {
		DEBUGP(DMSC, "Wrong content in the IMSI\n");
		return -1;
	}

	if (!TLVP_PRESENT(&tp, GSM0808_IE_CELL_IDENTIFIER_LIST)) {
		DEBUGP(DMSC, "Mandantory CELL IDENTIFIER LIST not present.\n");
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
		unsigned int *_lac = (unsigned int *)&data[1];
		lac = ntohs(*_lac);
	} else if (data_length > 1 || (data[0] & 0x0f) != CELL_IDENT_BSS) {
		DEBUGPC(DMSC, "Unsupported Cell Identifier List: %s\n", hexdump(data, data_length));
		return -1;
	}

	if (TLVP_PRESENT(&tp, GSM0808_IE_CHANNEL_NEEDED) && TLVP_LEN(&tp, GSM0808_IE_CHANNEL_NEEDED) == 1)
		chan_needed = TLVP_VAL(&tp, GSM0808_IE_CHANNEL_NEEDED)[0] & 0x03;

	if (TLVP_PRESENT(&tp, GSM0808_IE_EMLPP_PRIORITY)) {
		DEBUGP(DMSC, "eMLPP is not handled\n");
	}

	DEBUGP(DMSC, "Paging request from MSC IMSI: '%s' TMSI: '0x%x/%u' LAC: 0x%x\n", mi_string, tmsi, tmsi, lac);
	subscr = subscr_get_or_create(net, mi_string);
	if (!subscr)
		return -1;

	/* reassign the tmsi, trust the net over our internal state */
	subscr->tmsi = tmsi;
	subscr->lac = lac;
	paged = paging_request(net, subscr, chan_needed, bssmap_paging_cb, subscr);
	DEBUGP(DMSC, "Paged IMSI: '%s' TMSI: '0x%x/%u' LAC: 0x%x on #bts: %d\n", mi_string, tmsi, tmsi, lac, paged);

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
		DEBUGP(DMSC, "Releasing all transactions on %p\n", conn);
		bsc_del_timer(&msg->lchan->msc_data->T10);
		msg->lchan->msc_data->lchan = NULL;
		msg->lchan->msc_data = NULL;
		put_lchan(msg->lchan);
	}

	/* send the clear complete message */
	resp = bssmap_create_clear_complete();
	if (!resp) {
		DEBUGP(DMSC, "Sending clear complete failed.\n");
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
	struct msgb *resp;
	int reject_cause = -1;

	/* HACK: Sending A5/0 to the MS */
	if (!msg->lchan || !msg->lchan->msc_data) {
		DEBUGP(DMSC, "No lchan/msc_data in cipher mode command.\n");
		goto reject;
	}

	if (msg->lchan->msc_data->ciphering_handled) {
		DEBUGP(DMSC, "Already seen ciphering command. Protocol Error.\n");
		goto reject;
	}

	msg->lchan->msc_data->ciphering_handled = 1;

	/* FIXME: parse the message. TLVP */
#warning "Need to handle cipher mode properly"

	return gsm48_send_rr_ciph_mode(msg->lchan, 1);

reject:
	resp = bssmap_create_cipher_reject(reject_cause);
	if (!resp) {
		DEBUGP(DMSC, "Sending the cipher reject failed.\n");
		return -1;
	}

	bsc_queue_connection_write(conn, resp);
	return -1;
}

/*
 * Handle the network configurable T10 parameter
 */
static void bssmap_t10_fired(void *_conn)
{
	struct sccp_connection *conn = (struct sccp_connection *) _conn;
	struct msgb *resp;

	DEBUGP(DMSC, "T10 fired, assignment failed: %p\n", conn);
	resp = bssmap_create_assignment_failure(
		GSM0808_CAUSE_NO_RADIO_RESOURCE_AVAILABLE, NULL);
	if (!resp) {
		DEBUGP(DMSC, "Allocation failure: %p\n", conn);
		return;
	}

	bsc_queue_connection_write(conn, resp);
}

/*
 * Handle the assignment request message.
 *
 * See §3.2.1.1 for the message type
 */
static int bssmap_handle_assignm_req(struct sccp_connection *conn,
				     struct msgb *msg, unsigned int length)
{
	struct tlv_parsed tp;
	struct bss_sccp_connection_data *msc_data;
	u_int8_t *data;
	u_int8_t multiplex;
	int i, found = 0;

	if (!msg->lchan || !msg->lchan->msc_data) {
		DEBUGP(DMSC, "No lchan/msc_data in cipher mode command.\n");
		goto reject;
	}

	msc_data = msg->lchan->msc_data;
	tlv_parse(&tp, &bss_att_tlvdef, msg->l4h + 1, length - 1, 0, 0);

	if (!TLVP_PRESENT(&tp, GSM0808_IE_CHANNEL_TYPE)) {
		DEBUGP(DMSC, "Mandantory channel type not present.\n");
		goto reject;
	}

	if (!TLVP_PRESENT(&tp, GSM0808_IE_CIRCUIT_IDENTITY_CODE)) {
		DEBUGP(DMSC, "Identity code missing. Audio routing will not work.\n");
		goto reject;
	}

	multiplex = TLVP_VAL(&tp, GSM0808_IE_CIRCUIT_IDENTITY_CODE)[1] & 0x1f;

	/*
	 * Currently we only support a limited subset of all
	 * possible channel types. The limitation ends by not using
	 * multi-slot, limiting the channel coding, speech...
	 */
	if (TLVP_LEN(&tp, GSM0808_IE_CHANNEL_TYPE) < 3) {
		DEBUGP(DMSC, "ChannelType len !=3 not supported: %d\n",
			TLVP_LEN(&tp, GSM0808_IE_CHANNEL_TYPE));
		goto reject;
	}

	/*
	 * Try to figure out if we support the proposed speech codecs. For
	 * now we will always pick the full rate codecs.
	 */

	data = (u_int8_t *) TLVP_VAL(&tp, GSM0808_IE_CHANNEL_TYPE);
	if ((data[0] & 0xf) != 0x1) {
		DEBUGP(DMSC, "ChannelType != speech: %d\n", data[0]);
		goto reject;
	}

	if (data[1] != GSM0808_SPEECH_FULL_PREF && data[1] != GSM0808_SPEECH_HALF_PREF) {
		DEBUGP(DMSC, "ChannelType full not allowed: %d\n", data[1]);
		goto reject;
	}

	/* go through the list of permitted codecs */
	for (i = 2; i < TLVP_LEN(&tp, GSM0808_IE_CHANNEL_TYPE); ++i) {
		if ((data[i] & 0x7f) == GSM0808_PERM_FR2) {
			found = 1;
			break;
		}

		/* last octet, stop */
		if ((data[i] & 0x80) == 0x00)
			break;
	}

	if (!found) {
		DEBUGP(DMSC, "ChannelType FR2 not supported\n");
		goto reject;
	}

	/* modify the channel now */
	msc_data->T10.cb = bssmap_t10_fired;
	msc_data->T10.data = conn;
	bsc_schedule_timer(&msc_data->T10, GSM0808_T10_VALUE);

	msc_data->rtp_port = rtp_calculate_port(multiplex, rtp_base_port);
	DEBUGP(DMSC, "Sending ChanModify for speech on: sccp: %p\n", conn);
	return gsm48_lchan_modify(msg->lchan, GSM48_CMODE_SPEECH_EFR);

reject:
	gsm0808_send_assignment_failure(msg->lchan,
					GSM0808_CAUSE_NO_RADIO_RESOURCE_AVAILABLE, NULL);
	return -1;
}

int bssmap_rcvmsg_udt(struct gsm_network *net, struct msgb *msg, unsigned int length)
{
	int ret = 0;

	if (length < 1) {
		DEBUGP(DMSC, "Not enough room: %d\n", length);
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
		DEBUGP(DMSC, "Not enough room: %d\n", length);
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
		DEBUGP(DMSC, "Unimplemented msg type: %d\n", msg->l4h[0]);
		break;
	}

	return ret;
}

int dtap_rcvmsg(struct gsm_lchan *lchan, struct msgb *msg, unsigned int length)
{
	struct dtap_header *header;
	struct msgb *gsm48;
	u_int8_t *data;

	if (!lchan) {
		DEBUGP(DMSC, "No lchan available\n");
		return -1;
	}

	header = (struct dtap_header *) msg->l3h;
	if (sizeof(*header) >= length) {
		DEBUGP(DMSC, "The DTAP header does not fit. Wanted: %u got: %u\n", sizeof(*header), length);
                DEBUGP(DMSC, "hex: %s\n", hexdump(msg->l3h, length));
                return -1;
	}

	if (header->length > length - sizeof(*header)) {
		DEBUGP(DMSC, "The DTAP l4 information does not fit: header: %u length: %u\n", header->length, length);
                DEBUGP(DMSC, "hex: %s\n", hexdump(msg->l3h, length));
		return -1;
	}

	DEBUGP(DMSC, "DTAP message: SAPI: %u CHAN: %u\n", header->link_id & 0x07, header->link_id & 0xC0);

	/* forward the data */
	gsm48 = gsm48_msgb_alloc();
	if (!gsm48) {
		DEBUGP(DMSC, "Allocation of the message failed.\n");
		return -1;
	}

	gsm48->lchan = lchan;
	gsm48->trx = gsm48->lchan->ts->trx;
	gsm48->l3h = gsm48->data;
	data = msgb_put(gsm48, length - sizeof(*header));
	memcpy(data, msg->l3h + sizeof(*header), length - sizeof(*header));

	bts_queue_send(gsm48, header->link_id);
	return 0;
}

/* Create messages */
struct msgb *bssmap_create_layer3(struct msgb *msg_l3)
{
	u_int8_t *data;
	u_int16_t *ci;
	struct msgb* msg;
	struct gsm48_loc_area_id *lai;
	struct gsm_bts *bts = msg_l3->lchan->ts->trx->bts;

	msg  = msgb_alloc_headroom(BSSMAP_MSG_SIZE, BSSMAP_MSG_HEADROOM,
				   "bssmap cmpl l3");
	if (!msg)
		return NULL;


	/* create the bssmap header */
	msg->l3h = msgb_put(msg, 2);
	msg->l3h[0] = 0x0;

	/* create layer 3 header */
	data = msgb_put(msg, 1);
	data[0] = BSS_MAP_MSG_COMPLETE_LAYER_3;

	/* create the cell header */
	data = msgb_put(msg, 3);
	data[0] = GSM0808_IE_CELL_IDENTIFIER;
	data[1] = 1 + sizeof(*lai) + 2;
	data[2] = CELL_IDENT_WHOLE_GLOBAL;

	lai = (struct gsm48_loc_area_id *) msgb_put(msg, sizeof(*lai));
	gsm0408_generate_lai(lai, bts->network->country_code,
			     bts->network->network_code, bts->location_area_code);

	ci = (u_int16_t *) msgb_put(msg, 2);
	*ci = htons(bts->cell_identity);

	/* copy the layer3 data */
	data = msgb_put(msg, msgb_l3len(msg_l3) + 2);
	data[0] = GSM0808_IE_LAYER_3_INFORMATION;
	data[1] = msgb_l3len(msg_l3);
	memcpy(&data[2], msg_l3->l3h, data[1]);

	/* update the size */
	msg->l3h[1] = msgb_l3len(msg) - 2;

	return msg;
}

struct msgb *bssmap_create_reset(void)
{
	struct msgb *msg = msgb_alloc(30, "bssmap: reset");
	if (!msg)
		return NULL;

	msg->l3h = msgb_put(msg, 6);
	msg->l3h[0] = BSSAP_MSG_BSS_MANAGEMENT;
	msg->l3h[1] = 0x04;
	msg->l3h[2] = 0x30;
	msg->l3h[3] = 0x04;
	msg->l3h[4] = 0x01;
	msg->l3h[5] = 0x20;
	return msg;
}

struct msgb *bssmap_create_clear_complete(void)
{
	struct msgb *msg = msgb_alloc(30, "bssmap: clear complete");
	if (!msg)
		return NULL;

	msg->l3h = msgb_put(msg, 3);
	msg->l3h[0] = BSSAP_MSG_BSS_MANAGEMENT;
	msg->l3h[1] = 1;
	msg->l3h[2] = BSS_MAP_MSG_CLEAR_COMPLETE;

	return msg;
}

struct msgb *bssmap_create_cipher_complete(struct msgb *layer3)
{
	struct msgb *msg = msgb_alloc_headroom(BSSMAP_MSG_SIZE, BSSMAP_MSG_HEADROOM,
					       "cipher-complete");
	if (!msg)
		return NULL;

        /* send response with BSS override for A5/1... cheating */
	msg->l3h = msgb_put(msg, 3);
	msg->l3h[0] = BSSAP_MSG_BSS_MANAGEMENT;
	msg->l3h[1] = 0xff;
	msg->l3h[2] = BSS_MAP_MSG_CIPHER_MODE_COMPLETE;

	/* include layer3 in case we have at least two octets */
	if (layer3 && msgb_l3len(layer3) > 2) {
		msg->l4h = msgb_put(msg, msgb_l3len(layer3) + 2);
		msg->l4h[0] = GSM0808_IE_LAYER_3_MESSAGE_CONTENTS;
		msg->l4h[1] = msgb_l3len(layer3);
		memcpy(&msg->l4h[2], layer3->l3h, msgb_l3len(layer3));
	}

	/* and the optional BSS message */
	msg->l4h = msgb_put(msg, 2);
	msg->l4h[0] = GSM0808_IE_CHOSEN_ENCR_ALG;
	msg->l4h[1] = layer3->lchan->encr.alg_id;

	/* update the size */
	msg->l3h[1] = msgb_l3len(msg) - 2;
	return msg;
}

struct msgb *bssmap_create_cipher_reject(u_int8_t cause)
{
	struct msgb *msg = msgb_alloc(30, "bssmap: clear complete");
	if (!msg)
		return NULL;

	msg->l3h = msgb_put(msg, 3);
	msg->l3h[0] = BSSAP_MSG_BSS_MANAGEMENT;
	msg->l3h[1] = 2;
	msg->l3h[2] = BSS_MAP_MSG_CIPHER_MODE_REJECT;
	msg->l3h[3] = cause;

	return msg;
}

struct msgb *bssmap_create_sapi_reject(u_int8_t link_id)
{
	struct msgb *msg = msgb_alloc(30, "bssmap: sapi 'n' reject");
	if (!msg)
		return NULL;

	msg->l3h = msgb_put(msg, 5);
	msg->l3h[0] = BSSAP_MSG_BSS_MANAGEMENT;
	msg->l3h[1] = 3;
	msg->l3h[2] = BSS_MAP_MSG_SAPI_N_REJECT;
	msg->l3h[3] = link_id;
	msg->l3h[4] = GSM0808_CAUSE_BSS_NOT_EQUIPPED;

	return msg;
}

static u_int8_t chan_mode_to_speech(enum gsm48_chan_mode mode)
{
	switch (mode) {
	case GSM48_CMODE_SPEECH_V1:
		return 1;
		break;
	case GSM48_CMODE_SPEECH_EFR:
		return 0x11;
		break;
	case GSM48_CMODE_SPEECH_AMR:
		return 0x21;
		break;
	case GSM48_CMODE_SIGN:
	case GSM48_CMODE_DATA_14k5:
	case GSM48_CMODE_DATA_12k0:
	case GSM48_CMODE_DATA_6k0:
	case GSM48_CMODE_DATA_3k6:
	default:
		DEBUGP(DMSC, "Using non speech mode: %d\n", mode);
		return 0;
		break;
	}
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
		DEBUGP(DMSC, "Unknown lchan type: %p\n", lchan);
		break;
	}

	return channel_mode << 4 | channel;
}

struct msgb *bssmap_create_assignment_completed(struct gsm_lchan *lchan, u_int8_t rr_cause)
{
	u_int8_t *data;
	u_int8_t speech_mode;

	struct msgb *msg = msgb_alloc(35, "bssmap: ass compl");
	if (!msg)
		return NULL;

	msg->l3h = msgb_put(msg, 3);
	msg->l3h[0] = BSSAP_MSG_BSS_MANAGEMENT;
	msg->l3h[1] = 0xff;
	msg->l3h[2] = BSS_MAP_MSG_ASSIGMENT_COMPLETE;

	/* write 3.2.2.22 */
	data = msgb_put(msg, 2);
	data[0] = GSM0808_IE_RR_CAUSE;
	data[1] = rr_cause;

	/* write cirtcuit identity  code 3.2.2.2 */
	/* write cell identifier 3.2.2.17 */
	/* write chosen channel 3.2.2.33 when BTS picked it */
	data = msgb_put(msg, 2);
	data[0] = GSM0808_IE_CHOSEN_CHANNEL;
	data[1] = lchan_to_chosen_channel(lchan);

	/* write chosen encryption algorithm 3.2.2.44 */
	data = msgb_put(msg, 2);
	data[0] = GSM0808_IE_CHOSEN_ENCR_ALG;
	data[1] = lchan->encr.alg_id;

	/* write circuit pool 3.2.2.45 */
	/* write speech version chosen: 3.2.2.51 when BTS picked it */
	speech_mode = chan_mode_to_speech(lchan->tch_mode);
	if (speech_mode != 0) {
		data = msgb_put(msg, 2);
		data[0] = GSM0808_IE_SPEECH_VERSION;
		data[1] = speech_mode;
	}

	/* write LSA identifier 3.2.2.15 */


	/* update the size */
	msg->l3h[1] = msgb_l3len(msg) - 2;
	return msg;
}

struct msgb *bssmap_create_assignment_failure(u_int8_t cause, u_int8_t *rr_cause)
{
	u_int8_t *data;
	struct msgb *msg = msgb_alloc(35, "bssmap: ass fail");
	if (!msg)
		return NULL;

	msg->l3h = msgb_put(msg, 6);
	msg->l3h[0] = BSSAP_MSG_BSS_MANAGEMENT;
	msg->l3h[1] = 0xff;
	msg->l3h[2] = BSS_MAP_MSG_ASSIGMENT_FAILURE;
	msg->l3h[3] = GSM0808_IE_CAUSE;
	msg->l3h[4] = 1;
	msg->l3h[5] = cause;

	/* RR cause 3.2.2.22 */
	if (rr_cause) {
		data = msgb_put(msg, 2);
		data[0] = GSM0808_IE_RR_CAUSE;
		data[1] = *rr_cause;
	}

	/* Circuit pool 3.22.45 */
	/* Circuit pool list 3.2.2.46 */

	/* update the size */
	msg->l3h[1] = msgb_l3len(msg) - 2;
	return msg;
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

	if (subsys != SS_LCHAN || signal != S_LCHAN_UNEXPECTED_RELEASE)
		return 0;

	/*
	 * If we have a SCCP Connection we need to inform the MSC about
         * the resource error and then drop the lchan<->sccp association.
	 */
	lchan = (struct gsm_lchan *)signal_data;

	if (!lchan || !lchan->msc_data)
		return 0;

	bsc_del_timer(&lchan->msc_data->T10);
	conn = lchan->msc_data->sccp;
	lchan->msc_data->lchan = NULL;
	lchan->msc_data = NULL;

	msg = msgb_alloc(30, "sccp: clear request");
	if (!msg) {
		DEBUGP(DMSC, "Failed to allocate clear request.\n");
		return 0;
	}

	msg->l3h = msgb_put(msg, 2 + 4);
	msg->l3h[0] = BSSAP_MSG_BSS_MANAGEMENT;
	msg->l3h[1] = 4;

	msg->l3h[2] = BSS_MAP_MSG_CLEAR_RQST;
	msg->l3h[3] = GSM0808_IE_CAUSE;
	msg->l3h[4] = 1;
	msg->l3h[5] = GSM0808_CAUSE_RADIO_INTERFACE_FAILURE;

	DEBUGP(DMSC, "Sending clear request on unexpected channel release.\n");
	bsc_queue_connection_write(conn, msg);

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
		DEBUGP(DMSC, "Connection closing, dropping packet on: %p\n", conn);
		msgb_free(msg);
	} else if (conn->connection_state == SCCP_CONNECTION_STATE_ESTABLISHED
		   && data->sccp_queue_size == 0) {
		sccp_connection_write(conn, msg);
		msgb_free(msg);
	} else if (data->sccp_queue_size > 10) {
		DEBUGP(DMSC, "Dropping packet on %p due queue overflow\n", conn);
		msgb_free(msg);
	} else {
		DEBUGP(DMSC, "Queuing packet on %p. Queue size: %d\n", conn, data->sccp_queue_size);
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
		DEBUGP(DMSC, "Time-out/Establish after sccp release? Ind: %d lchan: %p\n",
		       rllr_ind, lchan);
		return;
	}

	if (memcmp(&data->sccp->source_local_reference, &ref, sizeof(ref)) != 0) {
		DEBUGP(DMSC, "Wrong SCCP connection. Not handling RLL callback: %u %u\n",
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
		sapi_reject = bssmap_create_sapi_reject(link_id);
		if (!sapi_reject){
			DEBUGP(DMSC, "Failed to create SAPI reject\n");
			return;
		}

		bsc_queue_connection_write(data->sccp, sapi_reject);
		break;
	}
	}
}

/* decide if we need to queue because of SAPI != 0 */
void bts_queue_send(struct msgb *msg, int link_id)
{
	struct bss_sccp_connection_data *data = msg->lchan->msc_data;

	if (data->gsm_queue_size == 0) {
		if (msg->lchan->sapis[link_id & 0x7] != LCHAN_SAPI_UNUSED) {
			rsl_data_request(msg, link_id);
		} else {
			msg->smsh = (unsigned char*) link_id;
			msgb_enqueue(&data->gsm_queue, msg);
			++data->gsm_queue_size;

			/* establish link */
			rll_establish(msg->lchan, link_id & 0x7,
				      rll_ind_cb,
				      (void *)sccp_src_ref_to_int(&data->sccp->source_local_reference));
		}
	} else if (data->gsm_queue_size == 10) {
		DEBUGP(DMSC, "Queue full on %p. Dropping GSM0408.\n", data->sccp);
	} else {
		DEBUGP(DMSC, "Queueing GSM0408 message on %p. Queue size: %d\n",
		       data->sccp, data->gsm_queue_size + 1);

		msg->smsh = (unsigned char*) link_id;
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
		rsl_data_request(msg, (int) msg->smsh);
	}

	data->gsm_queue_size = 0;
}

void gsm0808_send_assignment_failure(struct gsm_lchan *lchan, u_int8_t cause, u_int8_t *rr_value)
{
	struct msgb *resp;

	bsc_del_timer(&lchan->msc_data->T10);
	resp = bssmap_create_assignment_failure(cause, rr_value);
	if (!resp) {
		DEBUGP(DMSC, "Allocation failure: %p\n", lchan_get_sccp(lchan));
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
		DEBUGP(DMSC, "Creating MSC response failed: %p\n", lchan_get_sccp(lchan));
		return;
	}

	bsc_queue_connection_write(lchan_get_sccp(lchan), resp);
}

static __attribute__((constructor)) void on_dso_load_bssap(void)
{
	register_signal_handler(SS_LCHAN, bssap_handle_lchan_signal, NULL);
}
