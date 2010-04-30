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
#include <osmocore/msgb.h>
#include <openbsc/debug.h>
#include <osmocore/linuxlist.h>
#include <osmocore/timer.h>
#include <openbsc/gprs_bssgp.h>
#include <openbsc/gprs_llc.h>
#include <openbsc/crc24.h>

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
	GPRS_LLC_NULL,
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
};

struct gprs_llc_hdr_parsed {
	u_int8_t sapi;
	u_int8_t is_cmd:1,
		 ack_req:1,
		 is_encrypted:1;
	u_int32_t seq_rx;
	u_int32_t seq_tx;
	u_int32_t fcs;
	u_int32_t fcs_calc;
	u_int8_t *data;
	enum gprs_llc_cmd cmd;
};

#define LLC_ALLOC_SIZE 16384
#define UI_HDR_LEN	3
#define N202		4
#define CRC24_LENGTH	3

static int gprs_llc_fcs(u_int8_t *data, unsigned int len)
{
	u_int32_t fcs_calc;

	fcs_calc = crc24_calc(INIT_CRC24, data, len);
	fcs_calc = ~fcs_calc;
	fcs_calc &= 0xffffff;

	return fcs_calc;
}

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

/* Transmit a UI frame over the given SAPI */
int gprs_llc_tx_ui(struct msgb *msg, u_int8_t sapi, int command)
{
	u_int8_t *fcs, *llch;
	u_int8_t addr, ctrl[2];
	u_int32_t fcs_calc;
	u_int16_t nu = 0;

	/* Address Field */
	addr = sapi & 0xf;
	if (command)
		addr |= 0x40;

	/* Control Field */
	ctrl[0] = 0xc0;
	ctrl[0] |= nu >> 6;
	ctrl[1] = (nu << 2) & 0xfc;
	ctrl[1] |= 0x01; /* Protected Mode */

	/* prepend LLC UI header */
	llch = msgb_push(msg, 3);
	llch[0] = addr;
	llch[1] = ctrl[0];
	llch[2] = ctrl[1];

	/* append FCS to end of frame */
	fcs = msgb_put(msg, 3);
	fcs_calc = gprs_llc_fcs(llch, fcs - llch);
	fcs[0] = fcs_calc & 0xff;
	fcs[1] = (fcs_calc >> 8) & 0xff;
	fcs[2] = (fcs_calc >> 16) & 0xff;

	return gprs_bssgp_tx_dl_ud(msg);
}

static int gprs_llc_hdr_dump(struct gprs_llc_hdr_parsed *gph)
{
	DEBUGP(DGPRS, "LLC SAPI=%u %c %c FCS=0x%06x(%s) ",
		gph->sapi, gph->is_cmd ? 'C' : 'R', gph->ack_req ? 'A' : ' ',
		gph->fcs, gph->fcs_calc == gph->fcs ? "correct" : "WRONG");

	if (gph->cmd)
		DEBUGPC(DGPRS, "CMD=%u ", gph->cmd);

	if (gph->data)
		DEBUGPC(DGPRS, "DATA ");

	DEBUGPC(DGPRS, "\n");
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

	return 0;
}

/* parse a GPRS LLC header, also check for invalid frames */
static int gprs_llc_hdr_parse(struct gprs_llc_hdr_parsed *ghp,
			      const u_int8_t *llc_hdr, int len)
{
	u_int8_t *ctrl = llc_hdr+1;
	int is_sack = 0;
	unsigned int crc_length;
	u_int32_t fcs_calc;

	if (len <= CRC24_LENGTH)
		return -EIO;

	crc_length = len - CRC24_LENGTH;

	ghp->ack_req = 0;

	/* Section 5.5: FCS */
	ghp->fcs = *(llc_hdr + len - 3);
	ghp->fcs |= *(llc_hdr + len - 2) << 8;
	ghp->fcs |= *(llc_hdr + len - 1) << 16;

	/* Section 6.2.1: invalid PD field */
	if (llc_hdr[0] & 0x80)
		return -EIO;

	/* This only works for the MS->SGSN direction */
	if (llc_hdr[0] & 0x40)
		ghp->is_cmd = 0;
	else
		ghp->is_cmd = 1;

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
		/* I (Information transfer + Supervisory) format */
		u_int8_t k;

		ghp->data = ctrl + 3;

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
			k = ctrl[3] & 0x1f;
			ghp->data += 1 + k;
			break;
		}
	} else if ((ctrl[0] & 0xc0) == 0x80) {
		/* S (Supervisory) format */
		ghp->data = NULL;

		if (ctrl[0] & 0x20)
			ghp->ack_req = 1;
		ghp->seq_rx  = (ctrl[0] & 0x7) << 6;
		ghp->seq_rx |= (ctrl[1] >> 2);

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
			break;
		}
	} else if ((ctrl[0] & 0xe0) == 0xc0) {
		/* UI (Unconfirmed Inforamtion) format */
		ghp->data = ctrl + 2;

		ghp->seq_tx  = (ctrl[0] & 0x7) << 6;
		ghp->seq_tx |= (ctrl[1] >> 2);
		if (ctrl[1] & 0x02) {
			ghp->is_encrypted = 1;
			/* FIXME: encryption */
		}
		if (ctrl[1] & 0x01) {
			/* FCS over hdr + all inf fields */
		} else {
			/* FCS over hdr + N202 octets (4) */
			if (crc_length > UI_HDR_LEN + N202)
				crc_length = UI_HDR_LEN + N202;
		}
	} else {
		/* U (Unnumbered) format: 1 1 1 P/F M4 M3 M2 M1 */
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

	/* calculate what FCS we expect */
	ghp->fcs_calc = gprs_llc_fcs(llc_hdr, crc_length);

	/* FIXME: parse sack frame */
}

/* receive an incoming LLC PDU */
int gprs_llc_rcvmsg(struct msgb *msg, struct tlv_parsed *tv)
{
	struct bssgp_ud_hdr *udh = (struct bssgp_ud_hdr *) msg->l3h;
	struct gprs_llc_hdr *lh = msgb_llch(msg);
	struct gprs_llc_hdr_parsed llhp;
	struct gprs_llc_entity *lle;
	int rc;

	rc = gprs_llc_hdr_parse(&llhp, lh, TLVP_LEN(tv, BSSGP_IE_LLC_PDU));

	/* FIXME: find LLC Entity */

	gprs_llc_hdr_dump(&llhp);
	rc = gprs_llc_hdr_rx(&llhp, lle);

	if (llhp.data) {
		msgb_gmmh(msg) = llhp.data;
		switch (llhp.sapi) {
		case GPRS_SAPI_GMM:
			rc = gsm0408_gprs_rcvmsg(msg);
		}
	}

	return 0;
}
