/* GPRS Layer 3 protocol implementation as per 3GPP TS 08.18 */

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
#include <openbsc/gprs_bssgp.h>

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

/* Downlink user-data */
static int bssgp_rx_dl_ud(struct msgb *msg, u_int16_t bvci)
{

}

/* Uplink user-data */
static int bssgp_rx_ul_ud(struct msgb *msg, u_int16_t bvci)
{
	struct bssgp_ud_hdr *budh = msg->l3h;
	struct tlv_parsed tp;
	int data_len = msgb_l3len(msg) - sizeof(*budh);
	int rc;

	rc = bssgp_tlv_parse(&tp, budh->data, data_len);

	/* PDU_LIFETIME and LLC_PDU are the only mandatory IE */
	if (!TLVP_PRESENT(&tp, BSSGP_IE_PDU_LIFETIME) ||
	    !TLVP_PRESENT(&tp, BSSGP_IE_LLC_PDU))
		return -EIO;


}

/* We expect msg->l3h to point to the BSSGP header */
int gprs_bssgp_rcvmsg(struct msgb *msg, u_int16_t bvci)
{
	struct bssgp_normal_hdr *bgph = msg->l3h;
	u_int8_t pdu_type = bgph->pdu_type;
	int rc;

	switch (pdu_type) {
	case BSSGP_PDUT_DL_UNITDATA:
		rc = bssgp_rx_dl_ud(msg, bvci);
		break;
	case BSSGP_PDUT_UL_UNITDATA:
		rc = bssgp_rx_ul_ud(msg, bvci);
		break;
	}
}

static int gprs_bssgp_sendmsg()
{
	
}
