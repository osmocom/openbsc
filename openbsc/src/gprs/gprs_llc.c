/* GPRS LLC protocol implementation as per 3GPP TS 04.64 */

/* (C) 2009-2010 by Harald Welte <laforge@gnumonks.org>
 *
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

#include <errno.h>
#include <stdint.h>

#include <osmocom/core/msgb.h>
#include <osmocom/core/linuxlist.h>
#include <osmocom/core/timer.h>
#include <osmocom/core/talloc.h>
#include <osmocom/gprs/gprs_bssgp.h>

#include <openbsc/gsm_data.h>
#include <openbsc/debug.h>
#include <openbsc/gprs_sgsn.h>
#include <openbsc/gprs_gmm.h>
#include <openbsc/gprs_llc.h>
#include <openbsc/crc24.h>
#include <openbsc/sgsn.h>

static struct gprs_llc_llme *llme_alloc(uint32_t tlli);

/* If the TLLI is foreign, return its local version */
static inline uint32_t tlli_foreign2local(uint32_t tlli)
{
	uint32_t new_tlli;

	if (gprs_tlli_type(tlli) == TLLI_FOREIGN) {
		new_tlli = tlli | 0x40000000;
		LOGP(DLLC, LOGL_NOTICE, "TLLI 0x%08x is foreign, converting to "
			"local TLLI 0x%08x\n", tlli, new_tlli);
	} else
		new_tlli = tlli;

	return new_tlli;
}

/* Entry function from upper level (LLC), asking us to transmit a BSSGP PDU
 * to a remote MS (identified by TLLI) at a BTS identified by its BVCI and NSEI */
static int _bssgp_tx_dl_ud(struct msgb *msg, struct sgsn_mm_ctx *mmctx)
{
	struct bssgp_dl_ud_par dup;
	const uint8_t qos_profile_default[3] = { 0x00, 0x00, 0x20 };

	memset(&dup, 0, sizeof(dup));
	/* before we have received some identity from the MS, we might
	 * not yet have a MMC context (e.g. XID negotiation of primarly
	 * LLC connection fro GMM sapi). */
	if (mmctx) {
		/* make sure we only send it to the right llme */
		if (msgb_tlli(msg) != mmctx->llme->tlli &&
		    msgb_tlli(msg) != mmctx->llme->old_tlli &&
		    tlli_foreign2local(msgb_tlli(msg)) != mmctx->llme->tlli &&
		    tlli_foreign2local(msgb_tlli(msg)) != mmctx->llme->old_tlli)
		{
			LOGP(DLLC, LOGL_ERROR,
			     "MM context TLLI mismatch when sending DL unitdata, "
			     "msg TLLI = %08x, ctx TLLI = %08x, "
			     "ctx old TLLI = %08x. "
			     "Using default values for IMSI, DRX, RA CAP\n",
			     msgb_tlli(msg),
			     mmctx->llme->tlli,
			     mmctx->llme->old_tlli);
			osmo_log_backtrace(DLLC, LOGL_INFO);
		} else {
			dup.imsi = mmctx->imsi;
			dup.drx_parms = mmctx->drx_parms;
			dup.ms_ra_cap.len = mmctx->ms_radio_access_capa.len;
			dup.ms_ra_cap.v = mmctx->ms_radio_access_capa.buf;
		}
	}
	memcpy(&dup.qos_profile, qos_profile_default,
		sizeof(qos_profile_default));

	return bssgp_tx_dl_ud(msg, 1000, &dup);
}


/* Section 8.9.9 LLC layer parameter default values */
static const struct gprs_llc_params llc_default_params[NUM_SAPIS] = {
	[1] = {
		.t200_201	= 5,
		.n200		= 3,
		.n201_u		= 400,
	},
	[2] = {
		.t200_201	= 5,
		.n200		= 3,
		.n201_u		= 270,
	},
	[3] = {
		.iov_i_exp	= 27,
		.t200_201	= 5,
		.n200		= 3,
		.n201_u		= 500,
		.n201_i		= 1503,
		.mD		= 1520,
		.mU		= 1520,
		.kD		= 16,
		.kU		= 16,
	},
	[5] = {
		.iov_i_exp	= 27,
		.t200_201	= 10,
		.n200		= 3,
		.n201_u		= 500,
		.n201_i		= 1503,
		.mD		= 760,
		.mU		= 760,
		.kD		= 8,
		.kU		= 8,
	},
	[7] = {
		.t200_201	= 20,
		.n200		= 3,
		.n201_u		= 270,
	},
	[8] = {
		.t200_201	= 20,
		.n200		= 3,
		.n201_u		= 270,
	},
	[9] = {
		.iov_i_exp	= 27,
		.t200_201	= 20,
		.n200		= 3,
		.n201_u		= 500,
		.n201_i		= 1503,
		.mD		= 380,
		.mU		= 380,
		.kD		= 4,
		.kU		= 4,
	},
	[11] = {
		.iov_i_exp	= 27,
		.t200_201	= 40,
		.n200		= 3,
		.n201_u		= 500,
		.n201_i		= 1503,
		.mD		= 190,
		.mU		= 190,
		.kD		= 2,
		.kU		= 2,
	},
};

LLIST_HEAD(gprs_llc_llmes);
void *llc_tall_ctx;

/* lookup LLC Entity based on DLCI (TLLI+SAPI tuple) */
static struct gprs_llc_lle *lle_by_tlli_sapi(const uint32_t tlli, uint8_t sapi)
{
	struct gprs_llc_llme *llme;

	llist_for_each_entry(llme, &gprs_llc_llmes, list) {
		if (llme->tlli == tlli || llme->old_tlli == tlli)
			return &llme->lle[sapi];
	}
	return NULL;
}

struct gprs_llc_lle *gprs_lle_get_or_create(const uint32_t tlli, uint8_t sapi)
{
	struct gprs_llc_llme *llme;
	struct gprs_llc_lle *lle;

	lle = lle_by_tlli_sapi(tlli, sapi);
	if (lle)
		return lle;

	lle = lle_by_tlli_sapi(tlli_foreign2local(tlli), sapi);
	if (lle)
		return lle;

	LOGP(DLLC, LOGL_NOTICE, "LLC: unknown TLLI 0x%08x, "
		"creating LLME on the fly\n", tlli);
	llme = llme_alloc(tlli);
	lle = &llme->lle[sapi];
	return lle;
}

struct llist_head *gprs_llme_list(void)
{
	return &gprs_llc_llmes;
}

/* lookup LLC Entity for RX based on DLCI (TLLI+SAPI tuple) */
static struct gprs_llc_lle *lle_for_rx_by_tlli_sapi(const uint32_t tlli,
					uint8_t sapi, enum gprs_llc_cmd cmd)
{
	struct gprs_llc_lle *lle;

	/* We already know about this TLLI */
	lle = lle_by_tlli_sapi(tlli, sapi);
	if (lle)
		return lle;

	/* Maybe it is a routing area update but we already know this sapi? */
	if (gprs_tlli_type(tlli) == TLLI_FOREIGN) {
		lle = lle_by_tlli_sapi(tlli_foreign2local(tlli), sapi);
		if (lle) {
			LOGP(DLLC, LOGL_NOTICE,
				"LLC RX: Found a local entry for TLLI 0x%08x\n",
				tlli);
			return lle;
		}
	}

	/* 7.2.1.1 LLC belonging to unassigned TLLI+SAPI shall be discarded,
	 * except UID and XID frames with SAPI=1 */
	if (sapi == GPRS_SAPI_GMM &&
		    (cmd == GPRS_LLC_XID || cmd == GPRS_LLC_UI)) {
		struct gprs_llc_llme *llme;
		/* FIXME: don't use the TLLI but the 0xFFFF unassigned? */
		llme = llme_alloc(tlli);
		LOGP(DLLC, LOGL_NOTICE, "LLC RX: unknown TLLI 0x%08x, "
			"creating LLME on the fly\n", tlli);
		lle = &llme->lle[sapi];
		return lle;
	}
	
	LOGP(DLLC, LOGL_NOTICE,
		"unknown TLLI(0x%08x)/SAPI(%d): Silently dropping\n",
		tlli, sapi);
	return NULL;
}

static void lle_init(struct gprs_llc_llme *llme, uint8_t sapi)
{
	struct gprs_llc_lle *lle = &llme->lle[sapi];

	lle->llme = llme;
	lle->sapi = sapi;
	lle->state = GPRS_LLES_UNASSIGNED;

	/* Initialize according to parameters */
	memcpy(&lle->params, &llc_default_params[sapi], sizeof(lle->params));
}

static struct gprs_llc_llme *llme_alloc(uint32_t tlli)
{
	struct gprs_llc_llme *llme;
	uint32_t i;

	llme = talloc_zero(llc_tall_ctx, struct gprs_llc_llme);
	if (!llme)
		return NULL;

	llme->tlli = tlli;
	llme->old_tlli = 0xffffffff;
	llme->state = GPRS_LLMS_UNASSIGNED;
	llme->age_timestamp = GPRS_LLME_RESET_AGE;

	for (i = 0; i < ARRAY_SIZE(llme->lle); i++)
		lle_init(llme, i);

	llist_add(&llme->list, &gprs_llc_llmes);

	return llme;
}

static void llme_free(struct gprs_llc_llme *llme)
{
	llist_del(&llme->list);
	talloc_free(llme);
}

#if 0
/* FIXME: Unused code... */
static void t200_expired(void *data)
{
	struct gprs_llc_lle *lle = data;

	/* 8.5.1.3: Expiry of T200 */

	if (lle->retrans_ctr >= lle->params.n200) {
		/* FIXME: LLGM-STATUS-IND, LL-RELEASE-IND/CNF */
		lle->state = GPRS_LLES_ASSIGNED_ADM;
	}

	switch (lle->state) {
	case GPRS_LLES_LOCAL_EST:
		/* FIXME: retransmit SABM */
		/* FIXME: re-start T200 */
		lle->retrans_ctr++;
		break;
	case GPRS_LLES_LOCAL_REL:
		/* FIXME: retransmit DISC */
		/* FIXME: re-start T200 */
		lle->retrans_ctr++;
		break;
	default:
		LOGP(DLLC, LOGL_ERROR, "LLC unhandled state: %d\n", lle->state);
		break;
	}

}

static void t201_expired(void *data)
{
	struct gprs_llc_lle *lle = data;

	if (lle->retrans_ctr < lle->params.n200) {
		/* FIXME: transmit apropriate supervisory frame (8.6.4.1) */
		/* FIXME: set timer T201 */
		lle->retrans_ctr++;
	}
}
#endif

int gprs_llc_tx_u(struct msgb *msg, uint8_t sapi, int command,
		  enum gprs_llc_u_cmd u_cmd, int pf_bit)
{
	uint8_t *fcs, *llch;
	uint8_t addr, ctrl;
	uint32_t fcs_calc;

	/* Identifiers from UP: (TLLI, SAPI) + (BVCI, NSEI) */

	/* Address Field */
	addr = sapi & 0xf;
	if (command)
		addr |= 0x40;

	/* 6.3 Figure 8 */
	ctrl = 0xe0 | u_cmd;
	if (pf_bit)
		ctrl |= 0x10;

	/* prepend LLC UI header */
	llch = msgb_push(msg, 2);
	llch[0] = addr;
	llch[1] = ctrl;

	/* append FCS to end of frame */
	fcs = msgb_put(msg, 3);
	fcs_calc = gprs_llc_fcs(llch, fcs - llch);
	fcs[0] = fcs_calc & 0xff;
	fcs[1] = (fcs_calc >> 8) & 0xff;
	fcs[2] = (fcs_calc >> 16) & 0xff;

	/* Identifiers passed down: (BVCI, NSEI) */

	/* Send BSSGP-DL-UNITDATA.req */
	return _bssgp_tx_dl_ud(msg, NULL);
}

/* Send XID response to LLE */
static int gprs_llc_tx_xid(struct gprs_llc_lle *lle, struct msgb *msg,
			   int command)
{
	/* copy identifiers from LLE to ensure lower layers can route */
	msgb_tlli(msg) = lle->llme->tlli;
	msgb_bvci(msg) = lle->llme->bvci;
	msgb_nsei(msg) = lle->llme->nsei;

	return gprs_llc_tx_u(msg, lle->sapi, command, GPRS_LLC_U_XID, 1);
}

/* Transmit a UI frame over the given SAPI */
int gprs_llc_tx_ui(struct msgb *msg, uint8_t sapi, int command,
		   void *mmctx)
{
	struct gprs_llc_lle *lle;
	uint8_t *fcs, *llch;
	uint8_t addr, ctrl[2];
	uint32_t fcs_calc;
	uint16_t nu = 0;
	uint32_t oc;

	/* Identifiers from UP: (TLLI, SAPI) + (BVCI, NSEI) */

	/* look-up or create the LL Entity for this (TLLI, SAPI) tuple */
	lle = gprs_lle_get_or_create(msgb_tlli(msg), sapi);

	if (msg->len > lle->params.n201_u) {
		LOGP(DLLC, LOGL_ERROR, "Cannot Tx %u bytes (N201-U=%u)\n",
			msg->len, lle->params.n201_u);
		msgb_free(msg);
		return -EFBIG;
	}

	/* Update LLE's (BVCI, NSEI) tuple */
	lle->llme->bvci = msgb_bvci(msg);
	lle->llme->nsei = msgb_nsei(msg);

	/* Obtain current values for N(u) and OC */
	nu = lle->vu_send;
	oc = lle->oc_ui_send;
	/* Increment V(U) */
	lle->vu_send = (lle->vu_send + 1) % 512;
	/* Increment Overflow Counter, if needed */
	if ((lle->vu_send + 1) / 512)
		lle->oc_ui_send += 512;

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

	/* encrypt information field + FCS, if needed! */
	if (lle->llme->algo != GPRS_ALGO_GEA0) {
		uint32_t iov_ui = 0; /* FIXME: randomly select for TLLI */
		uint16_t crypt_len = (fcs + 3) - (llch + 3);
		uint8_t cipher_out[GSM0464_CIPH_MAX_BLOCK];
		uint32_t iv;
		int rc, i;
		uint64_t kc = *(uint64_t *)&lle->llme->kc;

		/* Compute the 'Input' Paraemeter */
		iv = gprs_cipher_gen_input_ui(iov_ui, sapi, nu, oc);

		/* Compute the keystream that we need to XOR with the data */
		rc = gprs_cipher_run(cipher_out, crypt_len, lle->llme->algo,
				     kc, iv, GPRS_CIPH_SGSN2MS);
		if (rc < 0) {
			LOGP(DLLC, LOGL_ERROR, "Error crypting UI frame: %d\n", rc);
			msgb_free(msg);
			return rc;
		}

		/* XOR the cipher output with the information field + FCS */
		for (i = 0; i < crypt_len; i++)
			*(llch + 3 + i) ^= cipher_out[i];

		/* Mark frame as encrypted */
		ctrl[1] |= 0x02;
	}

	/* Identifiers passed down: (BVCI, NSEI) */

	/* Send BSSGP-DL-UNITDATA.req */
	return _bssgp_tx_dl_ud(msg, mmctx);
}

/* According to 6.4.1.6 / Figure 11 */
static int msgb_put_xid_par(struct msgb *msg, uint8_t type, uint8_t length, uint8_t *data)
{
	uint8_t header_len = 1;
	uint8_t *cur;

	/* type is a 5-bit field... */
	if (type > 0x1f)
		return -EINVAL;

	if (length > 3)
		header_len = 2;

	cur = msgb_put(msg, length + header_len);

	/* build the header without or with XL bit */
	if (length <= 3) {
		*cur++ = (type << 2) | (length & 3);
	} else {
		*cur++ = 0x80 | (type << 2) | (length >> 6);
		*cur++ = (length << 2);
	}

	/* copy over the payload of the parameter*/
	memcpy(cur, data, length);

	return length + header_len;
}

static void rx_llc_xid(struct gprs_llc_lle *lle,
			struct gprs_llc_hdr_parsed *gph)
{
	/* FIXME: 8.5.3.3: check if XID is invalid */
	if (gph->is_cmd) {
		/* FIXME: implement XID negotiation using SNDCP */
		struct msgb *resp;
		uint8_t *xid;
		resp = msgb_alloc_headroom(4096, 1024, "LLC_XID");
		xid = msgb_put(resp, gph->data_len);
		memcpy(xid, gph->data, gph->data_len);
		gprs_llc_tx_xid(lle, resp, 0);
	} else {
		/* FIXME: if we had sent a XID reset, send
		 * LLGMM-RESET.conf to GMM */
		/* FIXME: implement XID negotiation using SNDCP */
	}
}

static int gprs_llc_hdr_rx(struct gprs_llc_hdr_parsed *gph,
			   struct gprs_llc_lle *lle)
{
	switch (gph->cmd) {
	case GPRS_LLC_SABM: /* Section 6.4.1.1 */
		lle->v_sent = lle->v_ack = lle->v_recv = 0;
		if (lle->state == GPRS_LLES_ASSIGNED_ADM) {
			/* start re-establishment (8.7.1) */
		}
		lle->state = GPRS_LLES_REMOTE_EST;
		/* FIXME: Send UA */
		lle->state = GPRS_LLES_ABM;
		/* FIXME: process data */
		break;
	case GPRS_LLC_DISC: /* Section 6.4.1.2 */
		/* FIXME: Send UA */
		/* terminate ABM */
		lle->state = GPRS_LLES_ASSIGNED_ADM;
		break;
	case GPRS_LLC_UA: /* Section 6.4.1.3 */
		if (lle->state == GPRS_LLES_LOCAL_EST)
			lle->state = GPRS_LLES_ABM;
		break;
	case GPRS_LLC_DM: /* Section 6.4.1.4: ABM cannot be performed */
		if (lle->state == GPRS_LLES_LOCAL_EST)
			lle->state = GPRS_LLES_ASSIGNED_ADM;
		break;
	case GPRS_LLC_FRMR: /* Section 6.4.1.5 */
		break;
	case GPRS_LLC_XID: /* Section 6.4.1.6 */
		rx_llc_xid(lle, gph);
		break;
	case GPRS_LLC_UI:
		if (gprs_llc_is_retransmit(gph->seq_tx, lle->vu_recv)) {
			LOGP(DLLC, LOGL_NOTICE,
				"TLLI=%08x dropping UI, N(U=%d) not in window V(URV(UR:%d).\n",
				lle->llme ? lle->llme->tlli : -1,
				gph->seq_tx, lle->vu_recv);

			/* HACK: non-standard recovery handling.  If remote LLE
			 * is re-transmitting the same sequence number for
			 * three times, don't discard the frame but pass it on
			 * and 'learn' the new sequence number */
			if (gph->seq_tx != lle->vu_recv_last) {
				lle->vu_recv_last = gph->seq_tx;
				lle->vu_recv_duplicates = 0;
			} else {
				lle->vu_recv_duplicates++;
				if (lle->vu_recv_duplicates < 3)
					return -EIO;
				LOGP(DLLC, LOGL_NOTICE, "TLLI=%08x recovering "
				     "N(U=%d) after receiving %u duplicates\n",
					lle->llme ? lle->llme->tlli : -1,
					gph->seq_tx, lle->vu_recv_duplicates);
			}
		}
		/* Increment the sequence number that we expect in the next frame */
		lle->vu_recv = (gph->seq_tx + 1) % 512;
		/* Increment Overflow Counter */
		if ((gph->seq_tx + 1) / 512)
			lle->oc_ui_recv += 512;
		break;
	default:
		LOGP(DLLC, LOGL_NOTICE, "Unhandled command: %d\n", gph->cmd);
		break;
	}

	return 0;
}

/* receive an incoming LLC PDU (BSSGP-UL-UNITDATA-IND, 7.2.4.2) */
int gprs_llc_rcvmsg(struct msgb *msg, struct tlv_parsed *tv)
{
	struct gprs_llc_hdr *lh = (struct gprs_llc_hdr *) msgb_llch(msg);
	struct gprs_llc_hdr_parsed llhp;
	struct gprs_llc_lle *lle;
	int rc = 0;

	/* Identifiers from DOWN: NSEI, BVCI, TLLI */

	memset(&llhp, 0, sizeof(llhp));
	rc = gprs_llc_hdr_parse(&llhp, (uint8_t *) lh, TLVP_LEN(tv, BSSGP_IE_LLC_PDU));
	gprs_llc_hdr_dump(&llhp);
	if (rc < 0) {
		LOGP(DLLC, LOGL_NOTICE, "Error during LLC header parsing\n");
		return rc;
	}

	switch (gprs_tlli_type(msgb_tlli(msg))) {
	case TLLI_LOCAL:
	case TLLI_FOREIGN:
	case TLLI_RANDOM:
	case TLLI_AUXILIARY:
		break;
	default:
		LOGP(DLLC, LOGL_ERROR,
			"Discarding frame with strange TLLI type\n");
		break;
	}

	/* find the LLC Entity for this TLLI+SAPI tuple */
	lle = lle_for_rx_by_tlli_sapi(msgb_tlli(msg), llhp.sapi, llhp.cmd);
	if (!lle) {
		switch (llhp.sapi) {
		case GPRS_SAPI_SNDCP3:
		case GPRS_SAPI_SNDCP5:
		case GPRS_SAPI_SNDCP9:
		case GPRS_SAPI_SNDCP11:
			/* Ask an upper layer for help. */
			return sgsn_force_reattach_oldmsg(msg);
		default:
			break;
		}
		return 0;
	}

	/* reset age computation */
	lle->llme->age_timestamp = GPRS_LLME_RESET_AGE;

	/* decrypt information field + FCS, if needed! */
	if (llhp.is_encrypted) {
		uint32_t iov_ui = 0; /* FIXME: randomly select for TLLI */
		uint16_t crypt_len = llhp.data_len + 3;
		uint8_t cipher_out[GSM0464_CIPH_MAX_BLOCK];
		uint32_t iv;
		uint64_t kc = *(uint64_t *)&lle->llme->kc;
		int rc, i;

		if (lle->llme->algo == GPRS_ALGO_GEA0) {
			LOGP(DLLC, LOGL_NOTICE, "encrypted frame for LLC that "
				"has no KC/Algo! Dropping.\n");
			return 0;
		}

		iv = gprs_cipher_gen_input_ui(iov_ui, lle->sapi, llhp.seq_tx,
						lle->oc_ui_recv);
		rc = gprs_cipher_run(cipher_out, crypt_len, lle->llme->algo,
				     kc, iv, GPRS_CIPH_MS2SGSN);
		if (rc < 0) {
			LOGP(DLLC, LOGL_ERROR, "Error decrypting frame: %d\n",
			     rc);
			return rc;
		}

		/* XOR the cipher output with the information field + FCS */
		for (i = 0; i < crypt_len; i++)
			*(llhp.data + i) ^= cipher_out[i];
	} else {
		if (lle->llme->algo != GPRS_ALGO_GEA0) {
			LOGP(DLLC, LOGL_NOTICE, "unencrypted frame for LLC "
				"that is supposed to be encrypted. Dropping.\n");
			return 0;
		}
	}

	/* We have to do the FCS check _after_ decryption */
	llhp.fcs_calc = gprs_llc_fcs((uint8_t *)lh, llhp.crc_length);
	if (llhp.fcs != llhp.fcs_calc) {
		LOGP(DLLC, LOGL_INFO, "Dropping frame with invalid FCS\n");
		return -EIO;
	}

	/* Update LLE's (BVCI, NSEI) tuple */
	lle->llme->bvci = msgb_bvci(msg);
	lle->llme->nsei = msgb_nsei(msg);

	/* Receive and Process the actual LLC frame */
	rc = gprs_llc_hdr_rx(&llhp, lle);
	if (rc < 0)
		return rc;

	/* llhp.data is only set when we need to send LL_[UNIT]DATA_IND up */
	if (llhp.data) {
		msgb_gmmh(msg) = llhp.data;
		switch (llhp.sapi) {
		case GPRS_SAPI_GMM:
			/* send LL_UNITDATA_IND to GMM */
			rc = gsm0408_gprs_rcvmsg(msg, lle->llme);
			break;
		case GPRS_SAPI_SNDCP3:
		case GPRS_SAPI_SNDCP5:
		case GPRS_SAPI_SNDCP9:
		case GPRS_SAPI_SNDCP11:
			/* send LL_DATA_IND/LL_UNITDATA_IND to SNDCP */
			rc = sndcp_llunitdata_ind(msg, lle, llhp.data, llhp.data_len);
			break;
		case GPRS_SAPI_SMS:
			/* FIXME */
		case GPRS_SAPI_TOM2:
		case GPRS_SAPI_TOM8:
			/* FIXME: send LL_DATA_IND/LL_UNITDATA_IND to TOM */
		default:
			LOGP(DLLC, LOGL_NOTICE, "Unsupported SAPI %u\n", llhp.sapi);
			rc = -EINVAL;
			break;
		}
	}

	return rc;
}

/* 04.64 Chapter 7.2.1.1 LLGMM-ASSIGN */
int gprs_llgmm_assign(struct gprs_llc_llme *llme,
		      uint32_t old_tlli, uint32_t new_tlli,
		      enum gprs_ciph_algo alg, const uint8_t *kc)
{
	unsigned int i;

	/* Update the crypto parameters */
	llme->algo = alg;
	if (alg != GPRS_ALGO_GEA0)
		memcpy(llme->kc, kc, sizeof(llme->kc));

	if (old_tlli == 0xffffffff && new_tlli != 0xffffffff) {
		/* TLLI Assignment 8.3.1 */
		/* New TLLI shall be assigned and used when (re)transmitting LLC frames */
		/* If old TLLI != 0xffffffff was assigned to LLME, then TLLI
		 * old is unassigned.  Only TLLI new shall be accepted when
		 * received from peer. */
		if (llme->old_tlli != 0xffffffff) {
			llme->old_tlli = 0xffffffff;
			llme->tlli = new_tlli;
		} else {
			/* If TLLI old == 0xffffffff was assigned to LLME, then this is
			 * TLLI assignmemt according to 8.3.1 */
			llme->old_tlli = 0xffffffff;
			llme->tlli = new_tlli;
			llme->state = GPRS_LLMS_ASSIGNED;
			/* 8.5.3.1 For all LLE's */
			for (i = 0; i < ARRAY_SIZE(llme->lle); i++) {
				struct gprs_llc_lle *l = &llme->lle[i];
				l->vu_send = l->vu_recv = 0;
				l->retrans_ctr = 0;
				l->state = GPRS_LLES_ASSIGNED_ADM;
				/* FIXME Set parameters according to table 9 */
			}
		}
	} else if (old_tlli != 0xffffffff && new_tlli != 0xffffffff) {
		/* TLLI Change 8.3.2 */
		/* Both TLLI Old and TLLI New are assigned; use New when
		 * (re)transmitting.  Accept both Old and New on Rx */
		llme->old_tlli = old_tlli;
		llme->tlli = new_tlli;
		llme->state = GPRS_LLMS_ASSIGNED;
	} else if (old_tlli != 0xffffffff && new_tlli == 0xffffffff) {
		/* TLLI Unassignment 8.3.3) */
		llme->tlli = llme->old_tlli = 0;
		llme->state = GPRS_LLMS_UNASSIGNED;
		for (i = 0; i < ARRAY_SIZE(llme->lle); i++) {
			struct gprs_llc_lle *l = &llme->lle[i];
			l->state = GPRS_LLES_UNASSIGNED;
		}
		llme_free(llme);
	} else
		return -EINVAL;

	return 0;
}

/* Chapter 7.2.1.2 LLGMM-RESET.req */
int gprs_llgmm_reset(struct gprs_llc_llme *llme)
{
	struct msgb *msg = msgb_alloc_headroom(4096, 1024, "LLC_XID");
	int random = rand();
	struct gprs_llc_lle *lle = &llme->lle[1];

	/* First XID component must be RESET */
	msgb_put_xid_par(msg, GPRS_LLC_XID_T_RESET, 0, NULL);
	/* randomly select new IOV-UI */
	msgb_put_xid_par(msg, GPRS_LLC_XID_T_IOV_UI, 4, (uint8_t *) &random);

	/* Reset some of the LLC parameters. See GSM 04.64, 8.5.3.1 */
	lle->vu_recv = 0;
	lle->vu_send = 0;
	lle->oc_ui_send = 0;
	lle->oc_ui_recv = 0;

	/* FIXME: Start T200, wait for XID response */
	return gprs_llc_tx_xid(lle, msg, 1);
}

int gprs_llgmm_reset_oldmsg(struct msgb* oldmsg, uint8_t sapi)
{
	struct msgb *msg = msgb_alloc_headroom(4096, 1024, "LLC_XID");
	int random = rand();

	/* First XID component must be RESET */
	msgb_put_xid_par(msg, GPRS_LLC_XID_T_RESET, 0, NULL);
	/* randomly select new IOV-UI */
	msgb_put_xid_par(msg, GPRS_LLC_XID_T_IOV_UI, 4, (uint8_t *) &random);

	/* FIXME: Start T200, wait for XID response */

	msgb_tlli(msg) = msgb_tlli(oldmsg);
	msgb_bvci(msg) = msgb_bvci(oldmsg);
	msgb_nsei(msg) = msgb_nsei(oldmsg);

	return gprs_llc_tx_u(msg, sapi, 1, GPRS_LLC_U_XID, 1);
}

int gprs_llc_init(const char *cipher_plugin_path)
{
	return gprs_cipher_load(cipher_plugin_path);
}
