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

#include <netinet/in.h>

#include <openbsc/msgb.h>
#include <openbsc/tlv.h>
#include <openbsc/debug.h>
#include <openbsc/gprs_bssgp.h>
#include <openbsc/gprs_llc.h>

static inline int bssgp_tlv_parse(struct tlv_parsed *tp, u_int8_t *buf, int len)
{
	return tlv_parse(tp, &tvlv_att_def, buf, len, 0, 0);
}

static inline struct msgb *bssgp_msgb_alloc(void)
{
	return msgb_alloc_headroom(4096, 128, "BSSGP");
}

/* Transmit a simple response such as BLOCK/UNBLOCK/RESET ACK/NACK */
static int bssgp_tx_simple_bvci(u_int8_t pdu_type, u_int16_t bvci, u_int16_t ns_bvci)
{
	struct msgb *msg = bssgp_msgb_alloc();
	struct bssgp_normal_hdr *bgph =
			(struct bssgp_normal_hdr *) msgb_put(msg, sizeof(*bgph));
	u_int16_t _bvci;

	bgph->pdu_type = pdu_type;
	_bvci = htons(bvci);
	msgb_tvlv_put(msg, BSSGP_IE_BVCI, 2, (u_int8_t *) &_bvci);

	return gprs_ns_sendmsg(NULL, ns_bvci, msg);
}

/* Chapter 10.4.14: Status */
static int bssgp_tx_status(u_int8_t cause, u_int16_t *bvci, struct msgb *orig_msg)
{
	struct msgb *msg = bssgp_msgb_alloc();
	struct bssgp_normal_hdr *bgph =
			(struct bssgp_normal_hdr *) msgb_put(msg, sizeof(*bgph));

	bgph->pdu_type = BSSGP_PDUT_STATUS;
	msgb_tvlv_put(msg, BSSGP_IE_CAUSE, 1, &cause);
	if (bvci) {
		u_int16_t _bvci = htons(*bvci);
		msgb_tvlv_put(msg, BSSGP_IE_BVCI, 2, (u_int8_t *) &_bvci);
	}
	if (orig_msg)
		msgb_tvlv_put(msg, BSSGP_IE_PDU_IN_ERROR,
			      msgb_l3len(orig_msg), orig_msg->l3h);

	return gprs_ns_sendmsg(NULL, 0, msg);
}

/* Uplink user-data */
static int bssgp_rx_ul_ud(struct msgb *msg, u_int16_t bvci)
{
	struct bssgp_ud_hdr *budh = (struct bssgp_ud_hdr *) msg->l3h;
	int data_len = msgb_l3len(msg) - sizeof(*budh);
	struct tlv_parsed tp;
	int rc;

	DEBUGP(DGPRS, "BSSGP UL-UD\n");

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

	DEBUGP(DGPRS, "BSSGP SUSPEND\n");

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

	DEBUGP(DGPRS, "BSSGP RESUME\n");

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
int gprs_bssgp_rcvmsg(struct msgb *msg, u_int16_t ns_bvci)
{
	struct bssgp_normal_hdr *bgph = (struct bssgp_normal_hdr *) msg->l3h;
	struct tlv_parsed tp;
	u_int8_t pdu_type = bgph->pdu_type;
	int data_len = msgb_l3len(msg) - sizeof(*bgph);
	u_int16_t bvci;
	int rc;

	if (pdu_type != BSSGP_PDUT_UL_UNITDATA &&
	    pdu_type != BSSGP_PDUT_DL_UNITDATA)
		rc = bssgp_tlv_parse(&tp, bgph->data, data_len);

	switch (pdu_type) {
	case BSSGP_PDUT_UL_UNITDATA:
		/* some LLC data from the MS */
		rc = bssgp_rx_ul_ud(msg, ns_bvci);
		break;
	case BSSGP_PDUT_RA_CAPABILITY:
		/* BSS requests RA capability or IMSI */
		DEBUGP(DGPRS, "BSSGP RA CAPABILITY UPDATE\n");
		/* FIXME: send RA_CAPA_UPDATE_ACK */
		break;
	case BSSGP_PDUT_RADIO_STATUS:
		DEBUGP(DGPRS, "BSSGP RADIO STATUS\n");
		/* BSS informs us of some exception */
		break;
	case BSSGP_PDUT_SUSPEND:
		/* MS wants to suspend */
		rc = bssgp_rx_suspend(msg, ns_bvci);
		break;
	case BSSGP_PDUT_RESUME:
		/* MS wants to resume */
		rc = bssgp_rx_resume(msg, ns_bvci);
		break;
	case BSSGP_PDUT_FLUSH_LL:
		/* BSS informs MS has moved to one cell to other cell */
		DEBUGP(DGPRS, "BSSGP FLUSH LL\n");
		/* Send FLUSH_LL_ACK */
		break;
	case BSSGP_PDUT_LLC_DISCARD:
		/* BSS informs that some LLC PDU's have been discarded */
		DEBUGP(DGPRS, "BSSGP LLC DISCARDED\n");
		break;
	case BSSGP_PDUT_FLOW_CONTROL_BVC:
		/* BSS informs us of available bandwidth in Gb interface */
		DEBUGP(DGPRS, "BSSGP FC BVC\n");
		/* Send FLOW_CONTROL_BVC_ACK */
		break;
	case BSSGP_PDUT_FLOW_CONTROL_MS:
		/* BSS informs us of available bandwidth to one MS */
		DEBUGP(DGPRS, "BSSGP FC MS\n");
		/* Send FLOW_CONTROL_MS_ACK */
		break;
	case BSSGP_PDUT_BVC_BLOCK:
		/* BSS tells us that BVC shall be blocked */
		DEBUGP(DGPRS, "BSSGP BVC BLOCK\n");
		if (!TLVP_PRESENT(&tp, BSSGP_IE_BVCI))
			goto err_mand_ie;
		bvci = ntohs(*(u_int16_t *)TLVP_VAL(&tp, BSSGP_IE_BVCI));
		rc = bssgp_tx_simple_bvci(BSSGP_PDUT_BVC_BLOCK_ACK,
					  bvci, ns_bvci);
		break;
	case BSSGP_PDUT_BVC_UNBLOCK:
		/* BSS tells us that BVC shall be unblocked */
		DEBUGP(DGPRS, "BSSGP BVC UNBLOCK\n");
		if (!TLVP_PRESENT(&tp, BSSGP_IE_BVCI))
			goto err_mand_ie;
		bvci = ntohs(*(u_int16_t *)TLVP_VAL(&tp, BSSGP_IE_BVCI));
		rc = bssgp_tx_simple_bvci(BSSGP_PDUT_BVC_UNBLOCK_ACK,
					  bvci, ns_bvci);
		break;
	case BSSGP_PDUT_BVC_RESET:
		/* BSS tells us that BVC init is required */
		DEBUGP(DGPRS, "BSSGP BVC RESET\n");
		if (!TLVP_PRESENT(&tp, BSSGP_IE_BVCI) ||
		    !TLVP_PRESENT(&tp, BSSGP_IE_CAUSE))
			goto err_mand_ie;
		bvci = ntohs(*(u_int16_t *)TLVP_VAL(&tp, BSSGP_IE_BVCI));
		rc = bssgp_tx_simple_bvci(BSSGP_PDUT_BVC_RESET_ACK,
					  bvci, ns_bvci);
		break;
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
err_mand_ie:
	DEBUGP(DGPRS, "BSSGP: Missing mandatory IE\n");
	return bssgp_tx_status(BSSGP_CAUSE_MISSING_MAND_IE, NULL, msg);
}

static int gprs_bssgp_sendmsg()
{
	
}
