/* GSM 08.08 BSSMAP handling						*/
/* (C) 2009-2010 by Holger Hans Peter Freyther <zecke@selfish.org>
 * (C) 2009-2010 by On-Waves
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

#include <openbsc/osmo_bsc.h>
#include <openbsc/osmo_bsc_grace.h>
#include <openbsc/debug.h>

#include <osmocore/gsm0808.h>
#include <osmocore/protocol/gsm_08_08.h>

#include <arpa/inet.h>

static uint16_t read_data16(const uint8_t *data)
{
	uint16_t res;

	memcpy(&res, data, sizeof(res));
	return res;
}

static int bssmap_handle_reset_ack(struct gsm_network *net,
				   struct msgb *msg, unsigned int length)
{
	LOGP(DMSC, LOGL_NOTICE, "Reset ACK from MSC\n");
	return 0;
}

/* GSM 08.08 § 3.2.1.19 */
static int bssmap_handle_paging(struct gsm_network *net,
				struct msgb *msg, unsigned int payload_length)
{
	struct tlv_parsed tp;
	char mi_string[GSM48_MI_SIZE];
	uint32_t tmsi = GSM_RESERVED_TMSI;
	unsigned int lac = GSM_LAC_RESERVED_ALL_BTS;
	uint8_t data_length;
	const uint8_t *data;
	uint8_t chan_needed = RSL_CHANNEED_ANY;

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
		lac = ntohs(read_data16(&data[1]));
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
	LOGP(DMSC, LOGL_ERROR, "Paging is not implemented...\n");
	return -1;
}

static int bssmap_rcvmsg_udt(struct gsm_network *net,
			     struct msgb *msg, unsigned int length)
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
		if (bsc_grace_allow_new_connection(net))
			ret = bssmap_handle_paging(net, msg, length);
		break;
	}

	return ret;
}

static int bssmap_rcvmsg_dt1(struct osmo_bsc_sccp_con *conn,
			     struct msgb *msg, unsigned int length)
{
	return -1;
}

static int dtap_rcvmsg(struct osmo_bsc_sccp_con *conn,
		       struct msgb *msg, unsigned int length)
{
	return -1;
}

int bsc_handle_udt(struct gsm_network *network,
		   struct bsc_msc_connection *conn,
		   struct msgb *msgb, unsigned int length)
{
	struct bssmap_header *bs;

	LOGP(DMSC, LOGL_DEBUG, "Incoming SCCP message ftom MSC: %s\n",
		hexdump(msgb->l3h, length));

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
		bssmap_rcvmsg_udt(network, msgb, length - sizeof(*bs));
		break;
	default:
		LOGP(DMSC, LOGL_ERROR, "Unimplemented msg type: %d\n", bs->type);
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
		LOGP(DMSC, LOGL_DEBUG, "Unimplemented msg type: %d\n", msg->l3h[0]);
	}

	return -1;
}
