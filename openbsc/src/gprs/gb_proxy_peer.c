/* Gb proxy peer handling */

/* (C) 2010 by Harald Welte <laforge@gnumonks.org>
 * (C) 2010-2013 by On-Waves
 * (C) 2013 by Holger Hans Peter Freyther
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

#include <openbsc/gb_proxy.h>

#include <openbsc/gsm_data.h>
#include <openbsc/gsm_data_shared.h>
#include <openbsc/debug.h>

#include <osmocom/gprs/protocol/gsm_08_18.h>
#include <osmocom/core/rate_ctr.h>
#include <osmocom/core/stats.h>
#include <osmocom/core/talloc.h>

#include <string.h>

static const struct rate_ctr_desc peer_ctr_description[] = {
	{ "blocked",	   "BVC Block                       " },
	{ "unblocked",	   "BVC Unblock                     " },
	{ "dropped",	   "BVC blocked, dropped packet     " },
	{ "inv-nsei",	   "NSEI mismatch                   " },
	{ "tx-err",	   "NS Transmission error           " },
	{ "raid-mod.bss",  "RAID patched              (BSS )" },
	{ "raid-mod.sgsn", "RAID patched              (SGSN)" },
	{ "apn-mod.sgsn",  "APN patched                     " },
	{ "tlli-mod.bss",  "TLLI patched              (BSS )" },
	{ "tlli-mod.sgsn", "TLLI patched              (SGSN)" },
	{ "ptmsi-mod.bss", "P-TMSI patched            (BSS )" },
	{ "ptmsi-mod.sgsn","P-TMSI patched            (SGSN)" },
	{ "mod-crypt-err", "Patch error: encrypted          " },
	{ "mod-err",	   "Patch error: other              " },
	{ "attach-reqs",   "Attach Request count            " },
	{ "attach-rejs",   "Attach Reject count             " },
	{ "attach-acks",   "Attach Accept count             " },
	{ "attach-cpls",   "Attach Completed count          " },
	{ "ra-upd-reqs",   "RoutingArea Update Request count" },
	{ "ra-upd-rejs",   "RoutingArea Update Reject count " },
	{ "ra-upd-acks",   "RoutingArea Update Accept count " },
	{ "ra-upd-cpls",   "RoutingArea Update Compltd count" },
	{ "gmm-status",    "GMM Status count           (BSS)" },
	{ "gmm-status",    "GMM Status count          (SGSN)" },
	{ "detach-reqs",   "Detach Request count            " },
	{ "detach-acks",   "Detach Accept count             " },
	{ "pdp-act-reqs",  "PDP Activation Request count    " },
	{ "pdp-act-rejs",  "PDP Activation Reject count     " },
	{ "pdp-act-acks",  "PDP Activation Accept count     " },
	{ "pdp-deact-reqs","PDP Deactivation Request count  " },
	{ "pdp-deact-acks","PDP Deactivation Accept count   " },
	{ "tlli-unknown",  "TLLI from SGSN unknown          " },
	{ "tlli-cache",    "TLLI cache size                 " },
};

osmo_static_assert(ARRAY_SIZE(peer_ctr_description) == GBPROX_PEER_CTR_LAST, everything_described);

static const struct rate_ctr_group_desc peer_ctrg_desc = {
	.group_name_prefix = "gbproxy.peer",
	.group_description = "GBProxy Peer Statistics",
	.num_ctr = ARRAY_SIZE(peer_ctr_description),
	.ctr_desc = peer_ctr_description,
	.class_id = OSMO_STATS_CLASS_PEER,
};


/* Find the gbprox_peer by its BVCI */
struct gbproxy_peer *gbproxy_peer_by_bvci(struct gbproxy_config *cfg, uint16_t bvci)
{
	struct gbproxy_peer *peer;
	llist_for_each_entry(peer, &cfg->bts_peers, list) {
		if (peer->bvci == bvci)
			return peer;
	}
	return NULL;
}

/* Find the gbprox_peer by its NSEI */
struct gbproxy_peer *gbproxy_peer_by_nsei(struct gbproxy_config *cfg,
					  uint16_t nsei)
{
	struct gbproxy_peer *peer;
	llist_for_each_entry(peer, &cfg->bts_peers, list) {
		if (peer->nsei == nsei)
			return peer;
	}
	return NULL;
}

/* look-up a peer by its Routeing Area Identification (RAI) */
struct gbproxy_peer *gbproxy_peer_by_rai(struct gbproxy_config *cfg,
					 const uint8_t *ra)
{
	struct gbproxy_peer *peer;
	llist_for_each_entry(peer, &cfg->bts_peers, list) {
		if (!memcmp(peer->ra, ra, 6))
			return peer;
	}
	return NULL;
}

/* look-up a peer by its Location Area Identification (LAI) */
struct gbproxy_peer *gbproxy_peer_by_lai(struct gbproxy_config *cfg,
					 const uint8_t *la)
{
	struct gbproxy_peer *peer;
	llist_for_each_entry(peer, &cfg->bts_peers, list) {
		if (!memcmp(peer->ra, la, 5))
			return peer;
	}
	return NULL;
}

/* look-up a peer by its Location Area Code (LAC) */
struct gbproxy_peer *gbproxy_peer_by_lac(struct gbproxy_config *cfg,
					 const uint8_t *la)
{
	struct gbproxy_peer *peer;
	llist_for_each_entry(peer, &cfg->bts_peers, list) {
		if (!memcmp(peer->ra + 3, la + 3, 2))
			return peer;
	}
	return NULL;
}

struct gbproxy_peer *gbproxy_peer_by_bssgp_tlv(struct gbproxy_config *cfg,
					       struct tlv_parsed *tp)
{
	if (TLVP_PRESENT(tp, BSSGP_IE_BVCI)) {
		uint16_t bvci;

		bvci = ntohs(tlvp_val16_unal(tp, BSSGP_IE_BVCI));
		if (bvci >= 2)
			return gbproxy_peer_by_bvci(cfg, bvci);
	}

	if (TLVP_PRESENT(tp, BSSGP_IE_ROUTEING_AREA)) {
		uint8_t *rai = (uint8_t *)TLVP_VAL(tp, BSSGP_IE_ROUTEING_AREA);
		/* Only compare LAC part, since MCC/MNC are possibly patched.
		 * Since the LAC of different BSS must be different when
		 * MCC/MNC are patched, collisions shouldn't happen. */
		return gbproxy_peer_by_lac(cfg, rai);
	}

	if (TLVP_PRESENT(tp, BSSGP_IE_LOCATION_AREA)) {
		uint8_t *lai = (uint8_t *)TLVP_VAL(tp, BSSGP_IE_LOCATION_AREA);
		return gbproxy_peer_by_lac(cfg, lai);
	}

	return NULL;
}


struct gbproxy_peer *gbproxy_peer_alloc(struct gbproxy_config *cfg, uint16_t bvci)
{
	struct gbproxy_peer *peer;

	peer = talloc_zero(tall_bsc_ctx, struct gbproxy_peer);
	if (!peer)
		return NULL;

	peer->bvci = bvci;
	peer->ctrg = rate_ctr_group_alloc(peer, &peer_ctrg_desc, bvci);
	if (!peer->ctrg) {
		talloc_free(peer);
		return NULL;
	}
	peer->cfg = cfg;

	llist_add(&peer->list, &cfg->bts_peers);

	INIT_LLIST_HEAD(&peer->patch_state.logical_links);

	return peer;
}

void gbproxy_peer_free(struct gbproxy_peer *peer)
{
	llist_del(&peer->list);

	gbproxy_delete_link_infos(peer);

	rate_ctr_group_free(peer->ctrg);
	peer->ctrg = NULL;

	talloc_free(peer);
}

int gbproxy_cleanup_peers(struct gbproxy_config *cfg, uint16_t nsei, uint16_t bvci)
{
	int counter = 0;
	struct gbproxy_peer *peer, *tmp;

	llist_for_each_entry_safe(peer, tmp, &cfg->bts_peers, list) {
		if (peer->nsei != nsei)
			continue;
		if (bvci && peer->bvci != bvci)
			continue;

		gbproxy_peer_free(peer);
		counter += 1;
	}

	return counter;
}

