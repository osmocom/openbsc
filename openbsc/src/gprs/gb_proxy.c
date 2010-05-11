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
#include <openbsc/gb_proxy.h>

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

/* strip off the NS header */
static void strip_ns_hdr(struct msgb *msg)
{
	int strip_len = msgb_bssgph(msg) - msg->data;
	msgb_pull(msg, strip_len);
}

/* feed a message down the NS-VC associated with the specified peer */
static int gbprox_relay2sgsn(struct msgb *msg, uint16_t ns_bvci)
{
	DEBUGP(DGPRS, "NSEI=%u proxying to SGSN (NS_BVCI=%u, NSEI=%u)\n",
		msgb_nsei(msg), ns_bvci, gbcfg.nsip_sgsn_nsei);

	msgb_bvci(msg) = ns_bvci;
	msgb_nsei(msg) = gbcfg.nsip_sgsn_nsei;

	strip_ns_hdr(msg);

	return gprs_ns_sendmsg(bssgp_nsi, msg);
}

/* feed a message down the NS-VC associated with the specified peer */
static int gbprox_relay2peer(struct msgb *msg, struct gbprox_peer *peer,
			  uint16_t ns_bvci)
{
	DEBUGP(DGPRS, "NSEI=%u proxying to BSS (NS_BVCI=%u, NSEI=%u)\n",
		msgb_nsei(msg), ns_bvci, peer->nsvc->nsei);

	msgb_bvci(msg) = ns_bvci;
	msgb_nsei(msg) = peer->nsvc->nsei;

	strip_ns_hdr(msg);

	return gprs_ns_sendmsg(bssgp_nsi, msg);
}

/* Send a message to a peer identified by ptp_bvci but using ns_bvci
 * in the NS hdr */
static int gbprox_relay2bvci(struct msgb *msg, uint16_t ptp_bvci,
			  uint16_t ns_bvci)
{
	struct gbprox_peer *peer;

	peer = peer_by_bvci(ptp_bvci);
	if (!peer) {
		LOGP(DGPRS, LOGL_ERROR, "Cannot find BSS for BVCI %u\n",
			ptp_bvci);
		return -ENOENT;
	}

	return gbprox_relay2peer(msg, peer, ns_bvci);
}

/* Receive an incoming signalling message from a BSS-side NS-VC */
static int gbprox_rx_sig_from_bss(struct msgb *msg, struct gprs_nsvc *nsvc,
				  uint16_t ns_bvci)
{
	struct bssgp_normal_hdr *bgph = (struct bssgp_normal_hdr *) msgb_bssgph(msg);
	struct tlv_parsed tp;
	uint8_t pdu_type = bgph->pdu_type;
	int data_len = msgb_bssgp_len(msg) - sizeof(*bgph);
	struct gbprox_peer *from_peer;
	struct gprs_ra_id raid;

	if (ns_bvci != 0) {
		LOGP(DGPRS, LOGL_NOTICE, "NSEI=%u BVCI %u is not signalling\n",
			nsvc->nsei, ns_bvci);
		return -EINVAL;
	}

	/* we actually should never see those two for BVCI == 0, but double-check
	 * just to make sure  */
	if (pdu_type == BSSGP_PDUT_UL_UNITDATA ||
	    pdu_type == BSSGP_PDUT_DL_UNITDATA) {
		LOGP(DGPRS, LOGL_NOTICE, "NSEI=%u UNITDATA not allowed in "
			"signalling\n", nsvc->nsei);
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
		DEBUGP(DGPRS, "NSEI=%u RAC snooping: RAC %u/%u/%u/%u behind BVCI=%u, "
			"NSVCI=%u\n", nsvc->nsei, raid.mcc, raid.mnc, raid.lac,
			raid.rac , from_peer->bvci, nsvc->nsvci);
		/* FIXME: This only supports one BSS per RA */
		break;
	case BSSGP_PDUT_BVC_RESET:
		/* If we receive a BVC reset on the signalling endpoint, we
		 * don't want the SGSN to reset, as the signalling endpoint
		 * is common for all point-to-point BVCs (and thus all BTS) */
		if (TLVP_PRESENT(&tp, BSSGP_IE_BVCI)) {
			uint16_t bvci = ntohs(*(uint16_t *)TLVP_VAL(&tp, BSSGP_IE_BVCI));
			if (bvci == 0) {
				/* FIXME: only do this if SGSN is alive! */
				LOGP(DGPRS, LOGL_INFO, "NSEI=%u Sending fake "
					"BVC RESET ACK of BVCI=0\n", nsvc->nsei);
				return bssgp_tx_simple_bvci(BSSGP_PDUT_BVC_RESET_ACK,
							    nsvc->nsei, 0, ns_bvci);
			} else if (!peer_by_bvci(bvci)) {
				/* if a PTP-BVC is reset, and we don't know that
				 * PTP-BVCI yet, we should allocate a new peer */
				LOGP(DGPRS, LOGL_INFO, "Allocationg new peer for "
				     "BVCI=%u via NSVCI=%u/NSEI=%u\n", bvci,
				     nsvc->nsvci, nsvc->nsei);
				from_peer = peer_alloc(bvci);
				from_peer->nsvc = nsvc;
			}
		}
		break;
	}

	/* Normally, we can simply pass on all signalling messages from BSS to SGSN */
	return gbprox_relay2sgsn(msg, ns_bvci);
err_no_peer:
	LOGP(DGPRS, LOGL_ERROR, "NSEI=%u(BSS) cannot find peer based on RAC\n",
		nsvc->nsei);
	return bssgp_tx_status(BSSGP_CAUSE_UNKNOWN_BVCI, NULL, msg);
err_mand_ie:
	LOGP(DGPRS, LOGL_ERROR, "NSEI=%u(BSS) missing mandatory RA IE\n",
		nsvc->nsei);
	return bssgp_tx_status(BSSGP_CAUSE_MISSING_MAND_IE, NULL, msg);
}

/* Receive paging request from SGSN, we need to relay to proper BSS */
static int gbprox_rx_paging(struct msgb *msg, struct tlv_parsed *tp,
			    struct gprs_nsvc *nsvc, uint16_t ns_bvci)
{
	struct gbprox_peer *peer;

	if (TLVP_PRESENT(tp, BSSGP_IE_BVCI)) {
		uint16_t bvci = ntohs(*(uint16_t *)TLVP_VAL(tp, BSSGP_IE_BVCI));
		return gbprox_relay2bvci(msg, bvci, ns_bvci);
	} else if (TLVP_PRESENT(tp, BSSGP_IE_ROUTEING_AREA)) {
		peer = peer_by_rac(TLVP_VAL(tp, BSSGP_IE_ROUTEING_AREA));
		return gbprox_relay2peer(msg, peer, ns_bvci);
	} else if (TLVP_PRESENT(tp, BSSGP_IE_LOCATION_AREA)) {
		peer = peer_by_lac(TLVP_VAL(tp, BSSGP_IE_LOCATION_AREA));
		return gbprox_relay2peer(msg, peer, ns_bvci);
	} else
		return -EINVAL;
}

/* Receive an incoming BVC-RESET message from the SGSN */
static int rx_reset_from_sgsn(struct msgb *msg, struct tlv_parsed *tp,
			      struct gprs_nsvc *nsvc, uint16_t ns_bvci)
{
	struct gbprox_peer *peer;
	uint16_t ptp_bvci;

	if (!TLVP_PRESENT(tp, BSSGP_IE_BVCI)) {
		return bssgp_tx_status(BSSGP_CAUSE_MISSING_MAND_IE,
				       NULL, msg);
	}
	ptp_bvci = ntohs(*(uint16_t *)TLVP_VAL(tp, BSSGP_IE_BVCI));

	if (ptp_bvci >= 2) {
		/* A reset for a PTP BVC was received, forward it to its
		 * respective peer */
		peer = peer_by_bvci(ptp_bvci);
		if (!peer) {
			LOGP(DGPRS, LOGL_ERROR, "Cannot find BSS for BVCI %u\n",
				ptp_bvci);
			return bssgp_tx_status(BSSGP_CAUSE_UNKNOWN_BVCI,
					       NULL, msg);
		}
		return gbprox_relay2peer(msg, peer, ns_bvci);
	}

	/* A reset for the Signalling entity has been received
	 * from the SGSN.  As the signalling BVCI is shared
	 * among all the BSS's that we multiplex, it needs to
	 * be relayed  */
	llist_for_each_entry(peer, &gbprox_bts_peers, list)
		gbprox_relay2peer(msg, peer, ns_bvci);

	return 0;
}

/* Receive an incoming signalling message from the SGSN-side NS-VC */
static int gbprox_rx_sig_from_sgsn(struct msgb *msg, struct gprs_nsvc *nsvc,
				   uint16_t ns_bvci)
{
	struct bssgp_normal_hdr *bgph = (struct bssgp_normal_hdr *) msgb_bssgph(msg);
	struct tlv_parsed tp;
	uint8_t pdu_type = bgph->pdu_type;
	int data_len = msgb_bssgp_len(msg) - sizeof(*bgph);
	struct gbprox_peer *peer;
	uint16_t bvci;
	int rc = 0;

	if (ns_bvci != 0) {
		LOGP(DGPRS, LOGL_NOTICE, "NSEI=%u(SGSN) BVCI %u is not "
			"signalling\n", nsvc->nsei, ns_bvci);
		/* FIXME: Send proper error message */
		return -EINVAL;
	}

	/* we actually should never see those two for BVCI == 0, but double-check
	 * just to make sure  */
	if (pdu_type == BSSGP_PDUT_UL_UNITDATA ||
	    pdu_type == BSSGP_PDUT_DL_UNITDATA) {
		LOGP(DGPRS, LOGL_NOTICE, "NSEI=%u(SGSN) UNITDATA not allowed in "
			"signalling\n", nsvc->nsei);
		return bssgp_tx_status(BSSGP_CAUSE_PROTO_ERR_UNSPEC, NULL, msg);
	}

	rc = bssgp_tlv_parse(&tp, bgph->data, data_len);

	switch (pdu_type) {
	case BSSGP_PDUT_BVC_RESET:
		rc = rx_reset_from_sgsn(msg, &tp, nsvc, ns_bvci);
		break;
	case BSSGP_PDUT_FLUSH_LL:
	case BSSGP_PDUT_BVC_BLOCK_ACK:
	case BSSGP_PDUT_BVC_UNBLOCK_ACK:
	case BSSGP_PDUT_BVC_RESET_ACK:
		/* simple case: BVCI IE is mandatory */
		if (!TLVP_PRESENT(&tp, BSSGP_IE_BVCI))
			goto err_mand_ie;
		bvci = ntohs(*(uint16_t *)TLVP_VAL(&tp, BSSGP_IE_BVCI));
		rc = gbprox_relay2bvci(msg, bvci, ns_bvci);
		break;
	case BSSGP_PDUT_PAGING_PS:
	case BSSGP_PDUT_PAGING_CS:
		/* process the paging request (LAC/RAC lookup) */
		rc = gbprox_rx_paging(msg, &tp, nsvc, ns_bvci);
		break;
	case BSSGP_PDUT_STATUS:
		/* Some exception has occurred */
		LOGP(DGPRS, LOGL_NOTICE,
			"NSEI=%u(SGSN) STATUS ", nsvc->nsei);
		if (!TLVP_PRESENT(&tp, BSSGP_IE_CAUSE)) {
			LOGPC(DGPRS, LOGL_NOTICE, "\n");
			goto err_mand_ie;
		}
		LOGPC(DGPRS, LOGL_NOTICE,
			"cause=0x%02x(%s) ", *TLVP_VAL(&tp, BSSGP_IE_CAUSE),
			bssgp_cause_str(*TLVP_VAL(&tp, BSSGP_IE_CAUSE)));
		if (TLVP_PRESENT(&tp, BSSGP_IE_BVCI)) {
			uint16_t *bvci = TLVP_VAL(&tp, BSSGP_IE_BVCI);
			LOGPC(DGPRS, LOGL_NOTICE,
				"BVCI=%u\n", ntohs(*bvci));
		} else
			LOGPC(DGPRS, LOGL_NOTICE, "\n");
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
		rc = gbprox_relay2peer(msg, peer, ns_bvci);
		break;
	case BSSGP_PDUT_SGSN_INVOKE_TRACE:
		LOGP(DGPRS, LOGL_ERROR,
		     "NSEI=%u(SGSN) INVOKE TRACE not supported\n", nsvc->nsei);
		rc = bssgp_tx_status(BSSGP_CAUSE_PDU_INCOMP_FEAT, NULL, msg);
		break;
	default:
		DEBUGP(DGPRS, "BSSGP PDU type 0x%02x unknown\n", pdu_type);
		rc = bssgp_tx_status(BSSGP_CAUSE_PROTO_ERR_UNSPEC, NULL, msg);
		break;
	}

	return rc;
err_mand_ie:
	LOGP(DGPRS, LOGL_ERROR, "NSEI=%u(SGSN) missing mandatory IE\n",
		nsvc->nsei);
	return bssgp_tx_status(BSSGP_CAUSE_MISSING_MAND_IE, NULL, msg);
err_no_peer:
	LOGP(DGPRS, LOGL_ERROR, "NSEI=%u(SGSN) cannot find peer based on RAC\n",
		nsvc->nsei);
	return bssgp_tx_status(BSSGP_CAUSE_UNKNOWN_BVCI, NULL, msg);
}

/* Main input function for Gb proxy */
int gbprox_rcvmsg(struct msgb *msg, struct gprs_nsvc *nsvc, uint16_t ns_bvci)
{
	int rc;

	/* Only BVCI=0 messages need special treatment */
	if (ns_bvci == 0 || ns_bvci == 1) {
		if (nsvc->remote_end_is_sgsn)
			rc = gbprox_rx_sig_from_sgsn(msg, nsvc, ns_bvci);
		else
			rc = gbprox_rx_sig_from_bss(msg, nsvc, ns_bvci);
	} else {
		/* All other BVCI are PTP and thus can be simply forwarded */
		if (!nsvc->remote_end_is_sgsn) {
			rc = gbprox_relay2sgsn(msg, ns_bvci);
		} else {
			struct gbprox_peer *peer = peer_by_bvci(ns_bvci);
			if (!peer) {
				LOGP(DGPRS, LOGL_NOTICE, "Allocationg new peer for "
				     "BVCI=%u via NSVC=%u/NSEI=%u\n", ns_bvci,
				     nsvc->nsvci, nsvc->nsei);
				peer = peer_alloc(ns_bvci);
				peer->nsvc = nsvc;
			}
			rc = gbprox_relay2peer(msg, peer, ns_bvci);
		}
	}

	return rc;
}

/* Signal handler for signals from NS layer */
int gbprox_signal(unsigned int subsys, unsigned int signal,
		  void *handler_data, void *signal_data)
{
	struct ns_signal_data *nssd = signal_data;
	struct gprs_nsvc *nsvc = nssd->nsvc;
	struct gbprox_peer *peer;

	if (subsys != SS_NS)
		return 0;

	/* We currently only care about signals from the SGSN */
	if (!nsvc->remote_end_is_sgsn)
		return 0;

	/* iterate over all BTS peers and send the respective PDU */
	llist_for_each_entry(peer, &gbprox_bts_peers, list) {
		switch (signal) {
		case S_NS_RESET:
			gprs_ns_tx_reset(peer->nsvc, nssd->cause);
			break;
		case S_NS_BLOCK:
			gprs_ns_tx_block(peer->nsvc, nssd->cause);
			break;
		case S_NS_UNBLOCK:
			gprs_ns_tx_unblock(peer->nsvc);
			break;
		}
	}
	return 0;
}


#include <vty/command.h>

gDEFUN(show_gbproxy, show_gbproxy_cmd, "show gbproxy",
       SHOW_STR "Display information about the Gb proxy")
{
	struct gbprox_peer *peer;

	llist_for_each_entry(peer, &gbprox_bts_peers, list) {
		struct gprs_nsvc *nsvc = peer->nsvc;
		struct gprs_ra_id raid;
		gsm48_parse_ra(&raid, &peer->ra);

		vty_out(vty, "NSEI %5u, NS-VC %5u, PTP-BVCI %u, "
			"RAC %u-%u-%u-%u%s",
			nsvc->nsei, nsvc->nsvci, peer->bvci,
			raid.mcc, raid.mnc, raid.lac, raid.rac, VTY_NEWLINE);
		if (nsvc->nsi->ll == GPRS_NS_LL_UDP)
			vty_out(vty, "  remote address %s:%u%s",
				inet_ntoa(nsvc->ip.bts_addr.sin_addr),
				ntohs(nsvc->ip.bts_addr.sin_port), VTY_NEWLINE);
	}
	return CMD_SUCCESS;
}
