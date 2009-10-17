/* GPRS BSSGP protocol implementation as per 3GPP TS 08.18 */

/* (C) 2009 by Harald Welte <laforge@gnumonks.org>
 *
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

#include <errno.h>
#include <sys/types.h>

#include <openbsc/msgb.h>
#include <openbsc/tlv.h>
#include <openbsc/debug.h>
#include <openbsc/gprs_bssgp.h>
#include <openbsc/gprs_llc.h>

/* BSSGP has its own weird TLV encoding scheme, where the length
 * can be one or two octet... if the first octet bit 7 is zero,
 * then there is a second octet */
static int bssgp_tlv_parse(struct tlv_parsed *tp, u_int8_t *data, int len)
{
	u_int8_t *cur = data;

	while (cur < data) {
		u_int8_t tag, *val;
		u_int16_t len;

		tag = *cur++;
		if (*cur & 0x80)
			len = *cur++ & 0x7f;
		else
			len = ((*cur++ & 0x7f) << 8) | *cur++;
		val = *cur++;

		tp->lv[tag].len = len;
		tp->lv[tag].val = val;
	}
	return 0;
}

/* Uplink user-data */
static int bssgp_rx_ul_ud(struct msgb *msg, u_int16_t bvci)
{
	struct bssgp_ud_hdr *budh = (struct bssgp_ud_hdr *) msg->l3h;
	int data_len = msgb_l3len(msg) - sizeof(*budh);
	struct tlv_parsed tp;
	int rc;

	rc = bssgp_tlv_parse(&tp, budh->data, data_len);

	/* PDU_LIFETIME and LLC_PDU are the only mandatory IE */
	if (!TLVP_PRESENT(&tp, BSSGP_IE_PDU_LIFETIME) ||
	    !TLVP_PRESENT(&tp, BSSGP_IE_LLC_PDU))
		return -EIO;

	msg->llch = TLVP_VAL(&tp, BSSGP_IE_LLC_PDU);

	return gprs_llc_rcvmsg(msg, &tp);
}

static int bssgp_rx_suspend(struct msgb *msg, u_int16_t bvci)
{
	struct bssgp_normal_hdr *bgph = (struct bssgp_normal_hdr *) msg->l3h;
	int data_len = msgb_l3len(msg) - sizeof(*bgph);
	struct tlv_parsed tp;
	int rc;

	rc = bssgp_tlv_parse(&tp, bgph->data, data_len);
	if (rc < 0)
		return rc;

	if (!TLVP_PRESENT(&tp, BSSGP_IE_TLLI) ||
	    !TLVP_PRESENT(&tp, BSSGP_IE_ROUTEING_AREA))
		return -EIO;

	/* SEND SUSPEND_ACK or SUSPEND_NACK */
	/* FIXME */
}

static int bssgp_rx_resume(struct msgb *msg, u_int16_t bvci)
{
	struct bssgp_normal_hdr *bgph = (struct bssgp_normal_hdr *) msg->l3h;
	int data_len = msgb_l3len(msg) - sizeof(*bgph);
	struct tlv_parsed tp;
	int rc;

	rc = bssgp_tlv_parse(&tp, bgph->data, data_len);
	if (rc < 0)
		return rc;

	if (!TLVP_PRESENT(&tp, BSSGP_IE_TLLI) ||
	    !TLVP_PRESENT(&tp, BSSGP_IE_ROUTEING_AREA) ||
	    !TLVP_PRESENT(&tp, BSSGP_IE_SUSPEND_REF_NR))
		return -EIO;

	/* SEND RESUME_ACK or RESUME_NACK */
	/* FIXME */
}

/* We expect msg->l3h to point to the BSSGP header */
int gprs_bssgp_rcvmsg(struct msgb *msg, u_int16_t bvci)
{
	struct bssgp_normal_hdr *bgph = (struct bssgp_normal_hdr *) msg->l3h;
	u_int8_t pdu_type = bgph->pdu_type;
	int rc;

	switch (pdu_type) {
	case BSSGP_PDUT_UL_UNITDATA:
		/* some LLC data from the MS */
		rc = bssgp_rx_ul_ud(msg, bvci);
		break;
	case BSSGP_PDUT_RA_CAPABILITY:
		/* BSS requests RA capability or IMSI */
		DEBUGP(DGPRS, "RA CAPABILITY UPDATE\n");
		/* FIXME: send RA_CAPA_UPDATE_ACK */
		break;
	case BSSGP_PDUT_RADIO_STATUS:
		DEBUGP(DGPRS, "RADIO STATUS\n");
		/* BSS informs us of some exception */
		break;
	case BSSGP_PDUT_SUSPEND:
		/* MS wants to suspend */
		rc = bssgp_rx_suspend(msg, bvci);
		break;
	case BSSGP_PDUT_RESUME:
		/* MS wants to resume */
		rc = bssgp_rx_resume(msg, bvci);
		break;
	case BSSGP_PDUT_FLUSH_LL:
		/* BSS informs MS has moved to one cell to other cell */
		DEBUGP(DGPRS, "FLUSH LL\n");
		/* Send FLUSH_LL_ACK */
		break;
	case BSSGP_PDUT_LLC_DISCARD:
		/* BSS informs that some LLC PDU's have been discarded */
		DEBUGP(DGPRS, "LLC DISCARDED\n");
		break;
	case BSSGP_PDUT_FLOW_CONTROL_BVC:
		/* BSS informs us of available bandwidth in Gb interface */
		/* Send FLOW_CONTROL_BVC_ACK */
		break;
	case BSSGP_PDUT_FLOW_CONTROL_MS:
		/* BSS informs us of available bandwidth to one MS */
		/* Send FLOW_CONTROL_MS_ACK */
		break;
	case BSSGP_PDUT_BVC_BLOCK:
		/* BSS tells us that BVC shall be blocked */
		/* Send BVC_BLOCK_ACK */
	case BSSGP_PDUT_BVC_UNBLOCK:
		/* BSS tells us that BVC shall be unblocked */
		/* Send BVC_UNBLOCK_ACK */
	case BSSGP_PDUT_BVC_RESET:
		/* BSS tells us that BVC init is required */
		/* Send BVC_RESET_ACK */
	case BSSGP_PDUT_STATUS:
		/* Some exception has occurred */
	case BSSGP_PDUT_DOWNLOAD_BSS_PFC:
	case BSSGP_PDUT_CREATE_BSS_PFC_ACK:
	case BSSGP_PDUT_CREATE_BSS_PFC_NACK:
	case BSSGP_PDUT_MODIFY_BSS_PFC:
	case BSSGP_PDUT_DELETE_BSS_PFC_ACK:
		DEBUGP(DGPRS, "BSSGP PDU type 0x%02x not [yet] implemented\n",
			pdu_type);
		break;
	/* those only exist in the SGSN -> BSS direction */
	case BSSGP_PDUT_DL_UNITDATA:
	case BSSGP_PDUT_PAGING_PS:
	case BSSGP_PDUT_PAGING_CS:
	case BSSGP_PDUT_RA_CAPA_UPDATE_ACK:
	case BSSGP_PDUT_SUSPEND_ACK:
	case BSSGP_PDUT_SUSPEND_NACK:
	case BSSGP_PDUT_RESUME_ACK:
	case BSSGP_PDUT_RESUME_NACK:
	case BSSGP_PDUT_FLUSH_LL_ACK:
	case BSSGP_PDUT_FLOW_CONTROL_BVC_ACK:
	case BSSGP_PDUT_FLOW_CONTROL_MS_ACK:
	case BSSGP_PDUT_BVC_BLOCK_ACK:
	case BSSGP_PDUT_BVC_UNBLOCK_ACK:
	case BSSGP_PDUT_SGSN_INVOKE_TRACE:
		DEBUGP(DGPRS, "BSSGP PDU type 0x%02x only exists in DL\n",
			pdu_type);
		rc = -EINVAL;
		break;
	default:
		DEBUGP(DGPRS, "BSSGP PDU type 0x%02x unknown\n", pdu_type);
		break;
	}

	return rc;
}

static int gprs_bssgp_sendmsg()
{
	
}
