/* GPRS LLC protocol implementation as per 3GPP TS 04.64 */

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

#include <openbsc/gsm_data.h>
#include <openbsc/msgb.h>
#include <openbsc/debug.h>
#include <openbsc/linuxlist.h>
#include <openbsc/timer.h>
#include <openbsc/gprs_bssgp.h>
#include <openbsc/gprs_llc.h>

/* Section 4.5.2 Logical Link States + Annex C.2 */
enum gprs_llc_ll_state {
	GPRS_LLS_UNASSIGNED	= 1,	/* No TLLI yet */
	GPRS_LLS_ASSIGNED_ADM	= 2,	/* TLLI assigned */
	GPRS_LLS_LOCAL_EST	= 3,	/* Local Establishment */
	GPRS_LLS_REMOTE_EST	= 4,	/* Remote Establishment */
	GPRS_LLS_ABM		= 5,
	GPRS_LLS_LOCAL_REL	= 6,	/* Local Release */
	GPRS_LLS_TIMER_REC 	= 7,	/* Timer Recovery */
};

/* Section 4.7 LLC Layer Structure */
enum gprs_sapi {
	GPRS_SAPI_GMM		= 1,
	GPRS_SAPI_TOM2		= 2,
	GPRS_SAPI_SNDCP3	= 3,
	GPRS_SAPI_SNDCP5	= 5,
	GPRS_SAPI_SMS		= 7,
	GPRS_SAPI_TOM8		= 8,
	GPRS_SAPI_SNDCP9	= 9,
	GPRS_SAPI_SNDCP11	= 11,
};

/* Section 4.7.1: Logical Link Entity: One per DLCI (TLLI + SAPI) */
struct gprs_llc_lle {
	struct llist_head list;
	struct timer_list t200;
	struct timer_list t201;	/* wait for acknowledgement */

	enum gprs_llc_ll_state state;

	u_int32_t tlli;
	u_int32_t sapi;

	u_int8_t v_sent;
	u_int8_t v_ack;
	u_int8_t v_recv;

	unsigned int n200;
	unsigned int retrans_ctr;
};

enum gprs_llc_cmd {
	GPRS_LLC_RR,
	GPRS_LLC_ACK,
	GPRS_LLC_RNR,
	GPRS_LLC_SACK,
	GPRS_LLC_DM,
	GPRS_LLC_DISC,
	GPRS_LLC_UA,
	GPRS_LLC_SABM,
	GPRS_LLC_FRMR,
	GPRS_LLC_XID,
	GPRS_LLC_NULL,
};

struct gprs_llc_hdr_parsed {
	u_int8_t sapi;
	u_int8_t is_cmd;
	u_int8_t ack_req;
	u_int32_t seq_rx;
	u_int32_t seq_tx;
	u_int8_t *data;
	enum gprs_llc_cmd cmd;
};

#define LLC_ALLOC_SIZE 16384

/* transmit a simple U frame */
static int gprs_llc_tx_u()
{
	struct msgb *msg = msgb_alloc(LLC_ALLOC_SIZE, "GPRS/LLC");

	if (!msg)
		return -ENOMEM;



	/* transmit the frame via BSSGP->NS->... */
}

static void t200_expired(void *data)
{
	struct gprs_llc_lle *lle = data;

	/* 8.5.1.3: Expiry of T200 */

	if (lle->retrans_ctr >= lle->n200) {
		/* FIXME: LLGM-STATUS-IND, LL-RELEASE-IND/CNF */
		lle->state = GPRS_LLS_ASSIGNED_ADM;
	}

	switch (lle->state) {
	case GPRS_LLS_LOCAL_EST:
		/* retransmit SABM */
		/* re-start T200 */
		lle->retrans_ctr++;
		break;
	case GPRS_LLS_LOCAL_REL:
		/* retransmit DISC */
		/* re-start T200 */
		lle->retrans_ctr++;
		break;
	}

}

static void t201_expired(void *data)
{
	struct gprs_llc_lle *lle = data;

	if (lle->retrans_ctr < lle->n200) {
		/* transmit apropriate supervisory frame (8.6.4.1) */
		/* set timer T201 */
		lle->retrans_ctr++;
	}
}

static int gprs_llc_hdr_rx(struct gprs_llc_hdr_parsed *gph,
			   struct gprs_llc_lle *lle)
{
	switch (gph->cmd) {
	case GPRS_LLC_SABM: /* Section 6.4.1.1 */
		lle->v_sent = lle->v_ack = lle->v_recv = 0;
		if (lle->state == GPRS_LLS_ASSIGNED_ADM) {
			/* start re-establishment (8.7.1) */
		}
		lle->state = GPRS_LLS_REMOTE_EST;
		/* FIXME: Send UA */
		lle->state = GPRS_LLS_ABM;
		/* FIXME: process data */
		break;
	case GPRS_LLC_DISC: /* Section 6.4.1.2 */
		/* FIXME: Send UA */
		/* terminate ABM */
		lle->state = GPRS_LLS_ASSIGNED_ADM;
		break;
	case GPRS_LLC_UA: /* Section 6.4.1.3 */
		if (lle->state == GPRS_LLS_LOCAL_EST)
			lle->state = GPRS_LLS_ABM;
		break;
	case GPRS_LLC_DM: /* Section 6.4.1.4: ABM cannot be performed */
		if (lle->state == GPRS_LLS_LOCAL_EST)
			lle->state = GPRS_LLS_ASSIGNED_ADM;
		break;
	case GPRS_LLC_FRMR: /* Section 6.4.1.5 */
		break;
	case GPRS_LLC_XID: /* Section 6.4.1.6 */
		break;
	}
}

/* parse a GPRS LLC header, also check for invalid frames */
static int gprs_llc_hdr_parse(struct gprs_llc_hdr_parsed *ghp,
			      const u_int8_t *llc_hdr)
{
	u_int8_t *ctrl = llc_hdr+1;
	int is_sack = 0;

	ghp->ack_req = 0;

	/* Section 6.2.1: invalid PD field */
	if (llc_hdr[0] & 0x80)
		return -EIO;

	ghp->is_cmd = llc_hdr[0] & 0x40;
	ghp->sapi = llc_hdr[0] & 0xf;

	/* Section 6.2.3: check for reserved SAPI */
	switch (ghp->sapi) {
	case 0:
	case 4:
	case 6:
	case 0xa:
	case 0xc:
	case 0xd:
	case 0xf:
		return -EINVAL;
	}

	if ((ctrl[0] & 0x80) == 0) {
		/* I format */
		if (ctrl[0] & 0x40)
			ghp->ack_req = 1;

		ghp->seq_tx  = (ctrl[0] & 0x1f) << 4;
		ghp->seq_tx |= (ctrl[1] >> 4);

		ghp->seq_rx  = (ctrl[1] & 0x7) << 6;
		ghp->seq_rx |= (ctrl[2] >> 2);

		switch (ctrl[2] & 0x03) {
		case 0:
			ghp->cmd = GPRS_LLC_RR;
			break;
		case 1:
			ghp->cmd = GPRS_LLC_ACK;
			break;
		case 2:
			ghp->cmd = GPRS_LLC_RNR;
			break;
		case 3:
			ghp->cmd = GPRS_LLC_SACK;
			break;
		}
	} else if ((ctrl[0] & 0xc0) == 0x80) {
		/* S format */
		if (ctrl[0] & 0x20)
			ghp->ack_req = 1;
		ghp->seq_rx  = (ctrl[0] & 0x7) << 6;
		ghp->seq_rx |= (ctrl[1] >> 2);

		ghp->data = ctrl + 2;

		switch (ctrl[1] & 0x03) {
		case 0:
			ghp->cmd = GPRS_LLC_RR;
			break;
		case 1:
			ghp->cmd = GPRS_LLC_ACK;
			break;
		case 2:
			ghp->cmd = GPRS_LLC_RNR;
			break;
		case 3:
			ghp->cmd = GPRS_LLC_SACK;
			//ghp->data += FIXME;
			break;
		}
	} else if ((ctrl[0] & 0xe0) == 0xc0) {
		/* UI format */
		ghp->seq_tx  = (ctrl[0] & 0x7) << 6;
		ghp->seq_tx |= (ctrl[1] >> 2);
		ghp->data = ctrl + 2;
		if (ctrl[1] & 0x02) {
			/* FIXME: encryption */
		}
		if (ctrl[1] & 0x01) {
			/* FIXME: FCS over hdr + all inf fields */
		} else {
			/* FIXME: FCS over hdr + N202 octets (4) */
		}
	} else {
		/* U format: 1 1 1 P/F M4 M3 M2 M1 */
		ghp->data = NULL;
		switch (ctrl[0] & 0xf) {
		case 0:
			ghp->cmd = GPRS_LLC_NULL;
			break;
		case 0x1:
			ghp->cmd = GPRS_LLC_DM;
			break;
		case 0x4:
			ghp->cmd = GPRS_LLC_DISC;
			break;
		case 0x6:
			ghp->cmd = GPRS_LLC_UA;
			break;
		case 0x7:
			ghp->cmd = GPRS_LLC_SABM;
			break;
		case 0x8:
			ghp->cmd = GPRS_LLC_FRMR;
			break;
		case 0xb:
			ghp->cmd = GPRS_LLC_XID;
			break;
		default:
			return -EIO;
		}
	}

	/* FIXME: parse sack frame */
}

/* receive an incoming LLC PDU */
int gprs_llc_rcvmsg(struct msgb *msg, struct tlv_parsed *tv)
{
	struct bssgp_ud_hdr *udh = (struct bssgp_ud_hdr *) msg->l3h;
	struct gprs_llc_hdr *lh = msg->llch;
	u_int32_t tlli = ntohl(udh->tlli);
	struct gprs_llc_hdr_parsed llhp;
	struct gprs_llc_entity *lle;
	int rc;

	rc = gprs_llc_hdr_parse(&llhp, lh);

	/* FIXME: find LLC Entity */

	gprs_llc_hdr_rx(&llhp, lle);
	return 0;
}
