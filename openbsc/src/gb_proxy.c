/* NS-over-IP proxy */

/* (C) 2010 by Harald Welte <laforge@gnumonks.org>
 * (C) 2010 by On Waves
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

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <errno.h>
#include <sys/fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <osmocore/talloc.h>
#include <osmocore/select.h>

#include <openbsc/signal.h>
#include <openbsc/debug.h>
#include <openbsc/gprs_ns.h>
#include <openbsc/gprs_bssgp.h>

struct gbprox_peer {
	struct llist_head list;

	/* NS-VC over which we send/receive data to this BVC */
	struct gprs_nsvc *nsvc;

	/* BVCI used for Point-to-Point to this peer */
	uint16_t bvci;

	/* Routeing Area that this peer is part of (raw 04.08 encoding) */
	uint8_t ra[6];
};

/* Linked list of all Gb peers (except SGSN) */
static LLIST_HEAD(gbprox_bts_peers);

/* Pointer to the SGSN peer */
struct gbprox_peer *gbprox_peer_sgsn;

/* The NS protocol stack instance we're using */
extern struct gprs_ns_inst *gbprox_nsi;

/* Find the gbprox_peer by its BVCI */
static struct gbprox_peer *peer_by_bvci(uint16_t bvci)
{
	struct gbprox_peer *peer;
	llist_for_each_entry(peer, &gbprox_bts_peers, list) {
		if (peer->bvci == bvci)
			return peer;
	}
	return NULL;
}

static struct gbprox_peer *peer_by_nsvc(struct gprs_nsvc *nsvc)
{
	struct gbprox_peer *peer;
	llist_for_each_entry(peer, &gbprox_bts_peers, list) {
		if (peer->nsvc == nsvc)
			return peer;
	}
	return NULL;
}

/* look-up a peer by its Routeing Area Code (RAC) */
static struct gbprox_peer *peer_by_rac(const uint8_t *ra)
{
	struct gbprox_peer *peer;
	llist_for_each_entry(peer, &gbprox_bts_peers, list) {
		if (!memcmp(&peer->ra, ra, 6))
			return peer;
	}
	return NULL;
}

/* look-up a peer by its Location Area Code (LAC) */
static struct gbprox_peer *peer_by_lac(const uint8_t *la)
{
	struct gbprox_peer *peer;
	llist_for_each_entry(peer, &gbprox_bts_peers, list) {
		if (!memcmp(&peer->ra, la, 5))
			return peer;
	}
	return NULL;
}

static struct gbprox_peer *peer_alloc(uint16_t bvci)
{
	struct gbprox_peer *peer;

	peer = talloc_zero(tall_bsc_ctx, struct gbprox_peer);
	if (!peer)
		return NULL;

	peer->bvci = bvci;
	llist_add(&peer->list, &gbprox_bts_peers);

	return peer;
}

static void peer_free(struct gbprox_peer *peer)
{
	llist_del(&peer->list);
	talloc_free(peer);
}

/* feed a message down the NS-VC associated with the specified peer */
static int gbprox_tx2peer(struct msgb *msg, struct gbprox_peer *peer,
			  uint16_t ns_bvci)
{
	msgb_bvci(msg) = ns_bvci;
	msgb_nsei(msg) = peer->nsvc->nsei;

	return gprs_ns_sendmsg(gbprox_nsi, msg);
}

/* Send a message to a peer identified by ptp_bvci but using ns_bvci
 * in the NS hdr */
static int gbprox_tx2bvci(struct msgb *msg, uint16_t ptp_bvci,
			  uint16_t ns_bvci)
{
	struct gbprox_peer *peer;

	peer = peer_by_bvci(ptp_bvci);
	if (!peer)
		return -ENOENT;

	return gbprox_tx2peer(msg, peer, ns_bvci);
}

/* Receive an incoming signalling message from a BSS-side NS-VC */
static int gbprox_rx_sig_from_bss(struct msgb *msg, struct gprs_nsvc *nsvc,
				  uint16_t ns_bvci)
{
	struct bssgp_normal_hdr *bgph = (struct bssgp_normal_hdr *) msg->l3h;
	struct tlv_parsed tp;
	uint8_t pdu_type = bgph->pdu_type;
	int data_len = msgb_l3len(msg) - sizeof(*bgph);
	struct gbprox_peer *from_peer;
	struct gprs_ra_id raid;

	if (ns_bvci != 0) {
		LOGP(DGPRS, LOGL_NOTICE, "BVCI %u is not signalling\n", ns_bvci);
		return -EINVAL;
	}

	/* we actually should never see those two for BVCI == 0, but double-check
	 * just to make sure  */
	if (pdu_type == BSSGP_PDUT_UL_UNITDATA ||
	    pdu_type == BSSGP_PDUT_DL_UNITDATA) {
		LOGP(DGPRS, LOGL_NOTICE, "UNITDATA not allowed in signalling\n");
		return -EINVAL;
	}

	bssgp_tlv_parse(&tp, bgph->data, data_len);

	switch (pdu_type) {
	case BSSGP_PDUT_SUSPEND:
	case BSSGP_PDUT_RESUME:
		/* We implement RAC snooping during SUSPEND/RESUME, since
		 * it establishes a relationsip between BVCI/peer and the
		 * routeing area code.  The snooped information is then
		 * used for routing the {SUSPEND,RESUME}_[N]ACK back to
		 * the correct BSSGP */
		if (!TLVP_PRESENT(&tp, BSSGP_IE_ROUTEING_AREA))
			goto err_mand_ie;
		from_peer = peer_by_nsvc(nsvc);
		if (!from_peer)
			goto err_no_peer;
		memcpy(&from_peer->ra, TLVP_VAL(&tp, BSSGP_IE_ROUTEING_AREA),
			sizeof(&from_peer->ra));
		gsm48_parse_ra(&raid, &from_peer->ra);
		DEBUGP(DGPRS, "RAC snooping: RAC %u/%u/%u/%u behind BVCI=%u, "
			"NSVCI=%u, NSEI=%u\n", raid.mcc, raid.mnc, raid.lac,
			raid.rac , from_peer->bvci, nsvc->nsvci, nsvc->nsei);
		/* FIXME: This only supports one BSS per RA */
		break;
	}

	/* Normally, we can simply pass on all signalling messages from BSS to SGSN */
	return gbprox_tx2peer(msg, gbprox_peer_sgsn, ns_bvci);
err_no_peer:
err_mand_ie:
	/* FIXME: do something */
	;
}

/* Receive paging request from SGSN, we need to relay to proper BSS */
static int gbprox_rx_paging(struct msgb *msg, struct tlv_parsed *tp,
			    struct gprs_nsvc *nsvc, uint16_t ns_bvci)
{
	struct gbprox_peer *peer;

	if (TLVP_PRESENT(tp, BSSGP_IE_BVCI)) {
		uint16_t bvci = ntohs(*(uint16_t *)TLVP_VAL(tp, BSSGP_IE_BVCI));
		return gbprox_tx2bvci(msg, bvci, ns_bvci);
	} else if (TLVP_PRESENT(tp, BSSGP_IE_ROUTEING_AREA)) {
		peer = peer_by_rac(TLVP_VAL(tp, BSSGP_IE_ROUTEING_AREA));
		return gbprox_tx2peer(msg, peer, ns_bvci);
	} else if (TLVP_PRESENT(tp, BSSGP_IE_LOCATION_AREA)) {
		peer = peer_by_lac(TLVP_VAL(tp, BSSGP_IE_LOCATION_AREA));
		return gbprox_tx2peer(msg, peer, ns_bvci);
	} else
		return -EINVAL;
}

/* Receive an incoming signalling message from the SGSN-side NS-VC */
static int gbprox_rx_sig_from_sgsn(struct msgb *msg, struct gprs_nsvc *nsvc,
				   uint16_t ns_bvci)
{
	struct bssgp_normal_hdr *bgph = (struct bssgp_normal_hdr *) msg->l3h;
	struct tlv_parsed tp;
	uint8_t pdu_type = bgph->pdu_type;
	int data_len = msgb_l3len(msg) - sizeof(*bgph);
	struct gbprox_peer *peer;
	uint16_t bvci;
	int rc = 0;

	if (ns_bvci != 0) {
		LOGP(DGPRS, LOGL_NOTICE, "BVCI %u is not signalling\n", ns_bvci);
		return -EINVAL;
	}

	/* we actually should never see those two for BVCI == 0, but double-check
	 * just to make sure  */
	if (pdu_type == BSSGP_PDUT_UL_UNITDATA ||
	    pdu_type == BSSGP_PDUT_DL_UNITDATA) {
		LOGP(DGPRS, LOGL_NOTICE, "UNITDATA not allowed in signalling\n");
		return -EINVAL;
	}

	rc = bssgp_tlv_parse(&tp, bgph->data, data_len);

	switch (pdu_type) {
	case BSSGP_PDUT_FLUSH_LL:
	case BSSGP_PDUT_BVC_BLOCK_ACK:
	case BSSGP_PDUT_BVC_UNBLOCK_ACK:
	case BSSGP_PDUT_BVC_RESET:
	case BSSGP_PDUT_BVC_RESET_ACK:
		/* simple case: BVCI IE is mandatory */
		if (!TLVP_PRESENT(&tp, BSSGP_IE_BVCI))
			goto err_mand_ie;
		bvci = ntohs(*(uint16_t *)TLVP_VAL(&tp, BSSGP_IE_BVCI));
		rc = gbprox_tx2bvci(msg, bvci, ns_bvci);
		break;
	case BSSGP_PDUT_PAGING_PS:
	case BSSGP_PDUT_PAGING_CS:
		/* process the paging request (LAC/RAC lookup) */
		rc = gbprox_rx_paging(msg, &tp, nsvc, ns_bvci);
		break;
	case BSSGP_PDUT_STATUS:
		/* FIXME: Some exception has occurred */
		LOGP(DGPRS, LOGL_NOTICE, "STATUS not implemented yet\n");
		break;
	/* those only exist in the SGSN -> BSS direction */
	case BSSGP_PDUT_SUSPEND_ACK:
	case BSSGP_PDUT_SUSPEND_NACK:
	case BSSGP_PDUT_RESUME_ACK:
	case BSSGP_PDUT_RESUME_NACK:
		/* RAC IE is mandatory */
		if (!TLVP_PRESENT(&tp, BSSGP_IE_ROUTEING_AREA))
			goto err_mand_ie;
		peer = peer_by_rac(TLVP_VAL(&tp, BSSGP_IE_ROUTEING_AREA));
		if (!peer)
			goto err_no_peer;
		rc = gbprox_tx2peer(msg, peer, ns_bvci);
		break;
	case BSSGP_PDUT_SGSN_INVOKE_TRACE:
		LOGP(DGPRS, LOGL_ERROR, "SGSN INVOKE TRACE not supported\n");
		break;
	default:
		DEBUGP(DGPRS, "BSSGP PDU type 0x%02x unknown\n", pdu_type);
		break;
	}

	return rc;
err_mand_ie:
	; /* FIXME: this would pull gprs_bssgp.c in, which in turn has dependencies */
	//return bssgp_tx_status(BSSGP_CAUSE_MISSING_MAND_IE, NULL, msg);
err_no_peer:
	; /* FIXME */
}

/* Main input function for Gb proxy */
int gbprox_rcvmsg(struct msgb *msg, struct gprs_nsvc *nsvc, uint16_t ns_bvci)
{
	struct gbprox_peer *peer;

	/* Only BVCI=0 messages need special treatment */
	if (ns_bvci == 0 || ns_bvci == 1) {
		if (nsvc->remote_end_is_sgsn)
			return gbprox_rx_sig_from_sgsn(msg, nsvc, ns_bvci);
		else
			return gbprox_rx_sig_from_bss(msg, nsvc, ns_bvci);
	}

	/* All other BVCI are PTP and thus can be simply forwarded */
	peer = peer_by_bvci(ns_bvci);
	if (!peer) {
		if (!nsvc->remote_end_is_sgsn) {
			LOGP(DGPRS, LOGL_NOTICE, "Allocationg new peer for "
			     "BVCI=%u via NSVC=%u/NSEI=%u\n", ns_bvci,
			     nsvc->nsvci, nsvc->nsei);
			peer = peer_alloc(ns_bvci);
			peer->nsvc = nsvc;
		} else {
			LOGP(DGPRS, LOGL_ERROR, "Couldn't find peer for "
			     "BVCI %u\n", ns_bvci);
			/* FIXME: do we really have to free the message here? */
			msgb_free(msg);
			return -EIO;
		}
	}

	return gbprox_tx2peer(msg, peer, ns_bvci);
}
