/* Gb-proxy TLLI state handling */

/* (C) 2014 by On-Waves
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

#include <osmocom/gsm/gsm48.h>

#include <openbsc/gb_proxy.h>

#include <openbsc/gprs_utils.h>
#include <openbsc/gprs_gb_parse.h>

#include <openbsc/debug.h>

#include <osmocom/gsm/gsm_utils.h>

#include <osmocom/core/rate_ctr.h>
#include <osmocom/core/talloc.h>

struct gbproxy_link_info *gbproxy_link_info_by_tlli(struct gbproxy_peer *peer,
					    uint32_t tlli)
{
	struct gbproxy_link_info *link_info;
	struct gbproxy_patch_state *state = &peer->patch_state;

	if (!tlli)
		return NULL;

	llist_for_each_entry(link_info, &state->logical_links, list)
		if (link_info->tlli.current == tlli ||
		    link_info->tlli.assigned == tlli)
			return link_info;

	return NULL;
}

struct gbproxy_link_info *gbproxy_link_info_by_ptmsi(
	struct gbproxy_peer *peer,
	uint32_t ptmsi)
{
	struct gbproxy_link_info *link_info;
	struct gbproxy_patch_state *state = &peer->patch_state;

	if (ptmsi == GSM_RESERVED_TMSI)
		return NULL;

	llist_for_each_entry(link_info, &state->logical_links, list)
		if (link_info->tlli.ptmsi == ptmsi)
			return link_info;

	return NULL;
}

struct gbproxy_link_info *gbproxy_link_info_by_any_sgsn_tlli(
	struct gbproxy_peer *peer,
	uint32_t tlli)
{
	struct gbproxy_link_info *link_info;
	struct gbproxy_patch_state *state = &peer->patch_state;

	if (!tlli)
		return NULL;

	/* Don't care about the NSEI */
	llist_for_each_entry(link_info, &state->logical_links, list)
		if (link_info->sgsn_tlli.current == tlli ||
		     link_info->sgsn_tlli.assigned == tlli)
			return link_info;

	return NULL;
}

struct gbproxy_link_info *gbproxy_link_info_by_sgsn_tlli(
	struct gbproxy_peer *peer,
	uint32_t tlli, uint32_t sgsn_nsei)
{
	struct gbproxy_link_info *link_info;
	struct gbproxy_patch_state *state = &peer->patch_state;

	if (!tlli)
		return NULL;

	llist_for_each_entry(link_info, &state->logical_links, list)
		if ((link_info->sgsn_tlli.current == tlli ||
		     link_info->sgsn_tlli.assigned == tlli) &&
		    link_info->sgsn_nsei == sgsn_nsei)
			return link_info;

	return NULL;
}

struct gbproxy_link_info *gbproxy_link_info_by_imsi(
	struct gbproxy_peer *peer,
	const uint8_t *imsi,
	size_t imsi_len)
{
	struct gbproxy_link_info *link_info;
	struct gbproxy_patch_state *state = &peer->patch_state;

	if (!gprs_is_mi_imsi(imsi, imsi_len))
		return NULL;

	llist_for_each_entry(link_info, &state->logical_links, list) {
		if (link_info->imsi_len != imsi_len)
			continue;
		if (memcmp(link_info->imsi, imsi, imsi_len) != 0)
			continue;

		return link_info;
	}

	return NULL;
}

void gbproxy_link_info_discard_messages(struct gbproxy_link_info *link_info)
{
	struct msgb *msg, *nxt;

	llist_for_each_entry_safe(msg, nxt, &link_info->stored_msgs, list) {
		llist_del(&msg->list);
		msgb_free(msg);
	}
}

void gbproxy_delete_link_info(struct gbproxy_peer *peer,
			 struct gbproxy_link_info *link_info)
{
	struct gbproxy_patch_state *state = &peer->patch_state;

	gbproxy_link_info_discard_messages(link_info);

	llist_del(&link_info->list);
	talloc_free(link_info);
	state->logical_link_count -= 1;

	peer->ctrg->ctr[GBPROX_PEER_CTR_TLLI_CACHE_SIZE].current =
		state->logical_link_count;
}

void gbproxy_delete_link_infos(struct gbproxy_peer *peer)
{
	struct gbproxy_link_info *link_info, *nxt;
	struct gbproxy_patch_state *state = &peer->patch_state;

	llist_for_each_entry_safe(link_info, nxt, &state->logical_links, list)
		gbproxy_delete_link_info(peer, link_info);

	OSMO_ASSERT(state->logical_link_count == 0);
	OSMO_ASSERT(llist_empty(&state->logical_links));
}

void gbproxy_attach_link_info(struct gbproxy_peer *peer, time_t now,
			      struct gbproxy_link_info *link_info)
{
	struct gbproxy_patch_state *state = &peer->patch_state;

	link_info->timestamp = now;
	llist_add(&link_info->list, &state->logical_links);
	state->logical_link_count += 1;

	peer->ctrg->ctr[GBPROX_PEER_CTR_TLLI_CACHE_SIZE].current =
		state->logical_link_count;
}

int gbproxy_remove_stale_link_infos(struct gbproxy_peer *peer, time_t now)
{
	struct gbproxy_patch_state *state = &peer->patch_state;
	int exceeded_max_len = 0;
	int deleted_count = 0;
	int check_for_age;

	if (peer->cfg->tlli_max_len > 0)
		exceeded_max_len =
			state->logical_link_count - peer->cfg->tlli_max_len;

	check_for_age = peer->cfg->tlli_max_age > 0;

	for (; exceeded_max_len > 0; exceeded_max_len--) {
		struct gbproxy_link_info *link_info;
		OSMO_ASSERT(!llist_empty(&state->logical_links));
		link_info = llist_entry(state->logical_links.prev,
					struct gbproxy_link_info,
					list);
		LOGP(DGPRS, LOGL_INFO,
		     "Removing TLLI %08x from list "
		     "(stale, length %d, max_len exceeded)\n",
		     link_info->tlli.current, state->logical_link_count);

		gbproxy_delete_link_info(peer, link_info);
		deleted_count += 1;
	}

	while (check_for_age && !llist_empty(&state->logical_links)) {
		time_t age;
		struct gbproxy_link_info *link_info;
		link_info = llist_entry(state->logical_links.prev,
					struct gbproxy_link_info,
					list);
		age = now - link_info->timestamp;
		/* age < 0 only happens after system time jumps, discard entry */
		if (age <= peer->cfg->tlli_max_age && age >= 0) {
			check_for_age = 0;
			continue;
		}

		LOGP(DGPRS, LOGL_INFO,
		     "Removing TLLI %08x from list "
		     "(stale, age %d, max_age exceeded)\n",
		     link_info->tlli.current, (int)age);

		gbproxy_delete_link_info(peer, link_info);
		deleted_count += 1;
	}

	return deleted_count;
}

struct gbproxy_link_info *gbproxy_link_info_alloc( struct gbproxy_peer *peer)
{
	struct gbproxy_link_info *link_info;

	link_info = talloc_zero(peer, struct gbproxy_link_info);
	link_info->tlli.ptmsi = GSM_RESERVED_TMSI;
	link_info->sgsn_tlli.ptmsi = GSM_RESERVED_TMSI;

	link_info->vu_gen_tx_bss = GBPROXY_INIT_VU_GEN_TX;

	INIT_LLIST_HEAD(&link_info->stored_msgs);

	return link_info;
}

void gbproxy_detach_link_info(
	struct gbproxy_peer *peer,
	struct gbproxy_link_info *link_info)
{
	struct gbproxy_patch_state *state = &peer->patch_state;

	llist_del(&link_info->list);
	OSMO_ASSERT(state->logical_link_count > 0);
	state->logical_link_count -= 1;

	peer->ctrg->ctr[GBPROX_PEER_CTR_TLLI_CACHE_SIZE].current =
		state->logical_link_count;
}

void gbproxy_update_link_info(struct gbproxy_link_info *link_info,
			      const uint8_t *imsi, size_t imsi_len)
{
	if (!gprs_is_mi_imsi(imsi, imsi_len))
		return;

	link_info->imsi_len = imsi_len;
	link_info->imsi =
		talloc_realloc_size(link_info, link_info->imsi, imsi_len);
	OSMO_ASSERT(link_info->imsi != NULL);
	memcpy(link_info->imsi, imsi, imsi_len);
}

void gbproxy_reassign_tlli(struct gbproxy_tlli_state *tlli_state,
			   struct gbproxy_peer *peer, uint32_t new_tlli)
{
	if (new_tlli == tlli_state->current)
		return;

	LOGP(DGPRS, LOGL_INFO,
	     "The TLLI has been reassigned from %08x to %08x\n",
	     tlli_state->current, new_tlli);

	/* Remember assigned TLLI */
	tlli_state->assigned = new_tlli;
	tlli_state->bss_validated = 0;
	tlli_state->net_validated = 0;
}

uint32_t gbproxy_map_tlli(uint32_t other_tlli,
			  struct gbproxy_link_info *link_info, int to_bss)
{
	uint32_t tlli = 0;
	struct gbproxy_tlli_state *src, *dst;
	if (to_bss) {
		src = &link_info->sgsn_tlli;
		dst = &link_info->tlli;
	} else {
		src = &link_info->tlli;
		dst = &link_info->sgsn_tlli;
	}
	if (src->current == other_tlli)
		tlli = dst->current;
	else if (src->assigned == other_tlli)
		tlli = dst->assigned;

	return tlli;
}

static void gbproxy_validate_tlli(struct gbproxy_tlli_state *tlli_state,
				  uint32_t tlli, int to_bss)
{
	LOGP(DGPRS, LOGL_DEBUG,
	     "%s({current = %08x, assigned = %08x, net_vld = %d, bss_vld = %d}, %08x)\n",
	     __func__, tlli_state->current, tlli_state->assigned,
	     tlli_state->net_validated, tlli_state->bss_validated, tlli);

	if (!tlli_state->assigned || tlli_state->assigned != tlli)
		return;

	/* TODO: Is this ok? Check spec */
	if (gprs_tlli_type(tlli) != TLLI_LOCAL)
		return;

	/* See GSM 04.08, 4.7.1.5 */
	if (to_bss)
		tlli_state->net_validated = 1;
	else
		tlli_state->bss_validated = 1;

	if (!tlli_state->bss_validated || !tlli_state->net_validated)
		return;

	LOGP(DGPRS, LOGL_INFO,
	     "The TLLI %08x has been validated (was %08x)\n",
	     tlli_state->assigned, tlli_state->current);

	tlli_state->current = tlli;
	tlli_state->assigned = 0;
}

static void gbproxy_touch_link_info(struct gbproxy_peer *peer,
				    struct gbproxy_link_info *link_info,
				    time_t now)
{
	gbproxy_detach_link_info(peer, link_info);
	gbproxy_attach_link_info(peer, now, link_info);
}

static int gbproxy_unregister_link_info(struct gbproxy_peer *peer,
					 struct gbproxy_link_info *link_info)
{
	if (!link_info)
		return 1;

	if (link_info->tlli.ptmsi == GSM_RESERVED_TMSI && !link_info->imsi_len) {
		LOGP(DGPRS, LOGL_INFO,
		     "Removing TLLI %08x from list (P-TMSI or IMSI are not set)\n",
		     link_info->tlli.current);
		gbproxy_delete_link_info(peer, link_info);
		return 1;
	}

	link_info->tlli.current = 0;
	link_info->tlli.assigned = 0;
	link_info->sgsn_tlli.current = 0;
	link_info->sgsn_tlli.assigned = 0;

	link_info->is_deregistered = 1;

	gbproxy_reset_link(link_info);

	return 0;
}

int gbproxy_imsi_matches(struct gbproxy_config *cfg,
			 enum gbproxy_match_id match_id,
			 struct gbproxy_link_info *link_info)
{
	struct gbproxy_match *match;
	OSMO_ASSERT(match_id >= 0 && match_id < ARRAY_SIZE(cfg->matches));

	match = &cfg->matches[match_id];
	if (!match->enable)
		return 1;

	return link_info != NULL && link_info->is_matching[match_id];
}

void gbproxy_assign_imsi(struct gbproxy_peer *peer,
			 struct gbproxy_link_info *link_info,
			 struct gprs_gb_parse_context *parse_ctx)
{
	int imsi_matches;
	struct gbproxy_link_info *other_link_info;
	enum gbproxy_match_id match_id;

	/* Make sure that there is a second entry with the same IMSI */
	other_link_info = gbproxy_link_info_by_imsi(
		peer, parse_ctx->imsi, parse_ctx->imsi_len);

	if (other_link_info && other_link_info != link_info) {
		char mi_buf[200];
		mi_buf[0] = '\0';
		gsm48_mi_to_string(mi_buf, sizeof(mi_buf),
				   parse_ctx->imsi, parse_ctx->imsi_len);
		LOGP(DGPRS, LOGL_INFO,
		     "Removing TLLI %08x from list (IMSI %s re-used)\n",
		     other_link_info->tlli.current, mi_buf);
		gbproxy_delete_link_info(peer, other_link_info);
	}

	/* Update the IMSI field */
	gbproxy_update_link_info(link_info,
				 parse_ctx->imsi, parse_ctx->imsi_len);

	/* Check, whether the IMSI matches */
	OSMO_ASSERT(ARRAY_SIZE(link_info->is_matching) ==
		    ARRAY_SIZE(peer->cfg->matches));
	for (match_id = 0; match_id < ARRAY_SIZE(link_info->is_matching);
	     ++match_id) {
		imsi_matches = gbproxy_check_imsi(
			&peer->cfg->matches[match_id],
			parse_ctx->imsi, parse_ctx->imsi_len);
		if (imsi_matches >= 0)
			link_info->is_matching[match_id] = imsi_matches;
	}
}

static int gbproxy_tlli_match(const struct gbproxy_tlli_state *a,
			      const struct gbproxy_tlli_state *b)
{
	if (a->current && a->current == b->current)
		return 1;

	if (a->assigned && a->assigned == b->assigned)
		return 1;

	if (a->ptmsi != GSM_RESERVED_TMSI && a->ptmsi == b->ptmsi)
		return 1;

	return 0;
}

static void gbproxy_remove_matching_link_infos(
	struct gbproxy_peer *peer, struct gbproxy_link_info *link_info)
{
	struct gbproxy_link_info *info, *nxt;
	struct gbproxy_patch_state *state = &peer->patch_state;

	/* Make sure that there is no second entry with the same P-TMSI or TLLI */
	llist_for_each_entry_safe(info, nxt, &state->logical_links, list) {
		if (info == link_info)
			continue;

		if (!gbproxy_tlli_match(&link_info->tlli, &info->tlli) &&
		    (link_info->sgsn_nsei != info->sgsn_nsei ||
		     !gbproxy_tlli_match(&link_info->sgsn_tlli, &info->sgsn_tlli)))
			continue;

		LOGP(DGPRS, LOGL_INFO,
		     "Removing TLLI %08x from list (P-TMSI/TLLI re-used)\n",
		     info->tlli.current);
		gbproxy_delete_link_info(peer, info);
	}
}

static struct gbproxy_link_info *gbproxy_get_link_info_ul(
	struct gbproxy_peer *peer,
	int *tlli_is_valid,
	struct gprs_gb_parse_context *parse_ctx)
{
	struct gbproxy_link_info *link_info = NULL;

	if (parse_ctx->tlli_enc) {
		link_info = gbproxy_link_info_by_tlli(peer, parse_ctx->tlli);

		if (link_info) {
			*tlli_is_valid = 1;
			return link_info;
		}
	}

	*tlli_is_valid = 0;

	if (!link_info && parse_ctx->imsi) {
		link_info = gbproxy_link_info_by_imsi(
			peer, parse_ctx->imsi, parse_ctx->imsi_len);
	}

	if (!link_info && parse_ctx->ptmsi_enc && !parse_ctx->old_raid_is_foreign) {
		uint32_t bss_ptmsi;
		gprs_parse_tmsi(parse_ctx->ptmsi_enc, &bss_ptmsi);
		link_info = gbproxy_link_info_by_ptmsi(peer, bss_ptmsi);
	}

	if (!link_info)
		return NULL;

	link_info->is_deregistered = 0;

	return link_info;
}

struct gbproxy_link_info *gbproxy_update_link_state_ul(
	struct gbproxy_peer *peer,
	time_t now,
	struct gprs_gb_parse_context *parse_ctx)
{
	struct gbproxy_link_info *link_info;
	int tlli_is_valid;

	link_info = gbproxy_get_link_info_ul(peer, &tlli_is_valid, parse_ctx);

	if (parse_ctx->tlli_enc && parse_ctx->llc) {
		uint32_t sgsn_tlli;

		if (!link_info) {
			LOGP(DGPRS, LOGL_INFO, "Adding TLLI %08x to list\n",
			    parse_ctx->tlli);
			link_info = gbproxy_link_info_alloc(peer);
			gbproxy_attach_link_info(peer, now, link_info);

			/* Setup TLLIs */
			sgsn_tlli = gbproxy_make_sgsn_tlli(peer, link_info,
							   parse_ctx->tlli);
			link_info->sgsn_tlli.current = sgsn_tlli;
			link_info->tlli.current = parse_ctx->tlli;
		} else if (!tlli_is_valid) {
			/* New TLLI (info found by IMSI or P-TMSI) */
			link_info->tlli.current = parse_ctx->tlli;
			link_info->tlli.assigned = 0;
			link_info->sgsn_tlli.current =
				gbproxy_make_sgsn_tlli(peer, link_info,
						       parse_ctx->tlli);
			link_info->sgsn_tlli.assigned = 0;
			gbproxy_touch_link_info(peer, link_info, now);
		} else {
			sgsn_tlli = gbproxy_map_tlli(parse_ctx->tlli, link_info, 0);
			if (!sgsn_tlli)
				sgsn_tlli = gbproxy_make_sgsn_tlli(peer, link_info,
								   parse_ctx->tlli);

			gbproxy_validate_tlli(&link_info->tlli,
					      parse_ctx->tlli, 0);
			gbproxy_validate_tlli(&link_info->sgsn_tlli,
					      sgsn_tlli, 0);
			gbproxy_touch_link_info(peer, link_info, now);
		}
	} else if (link_info) {
		gbproxy_touch_link_info(peer, link_info, now);
	}

	if (parse_ctx->imsi && link_info && link_info->imsi_len == 0)
		gbproxy_assign_imsi(peer, link_info, parse_ctx);

	return link_info;
}

static struct gbproxy_link_info *gbproxy_get_link_info_dl(
	struct gbproxy_peer *peer,
	struct gprs_gb_parse_context *parse_ctx)
{
	struct gbproxy_link_info *link_info = NULL;

	/* Which key to use depends on its availability only, if that fails, do
	 * not retry it with another key (e.g. IMSI). */
	if (parse_ctx->tlli_enc)
		link_info = gbproxy_link_info_by_sgsn_tlli(peer, parse_ctx->tlli,
							   parse_ctx->peer_nsei);

	/* TODO: Get link_info by (SGSN) P-TMSI if that is available (see
	 * GSM 08.18, 7.2) instead of using the IMSI as key. */
	else if (parse_ctx->imsi)
		link_info = gbproxy_link_info_by_imsi(
			peer, parse_ctx->imsi, parse_ctx->imsi_len);

	if (link_info)
		link_info->is_deregistered = 0;

	return link_info;
}

struct gbproxy_link_info *gbproxy_update_link_state_dl(
	struct gbproxy_peer *peer,
	time_t now,
	struct gprs_gb_parse_context *parse_ctx)
{
	struct gbproxy_link_info *link_info = NULL;

	link_info = gbproxy_get_link_info_dl(peer, parse_ctx);

	if (parse_ctx->tlli_enc && parse_ctx->new_ptmsi_enc && link_info) {
		/* A new P-TMSI has been signalled in the message,
		 * register new TLLI */
		uint32_t new_sgsn_ptmsi;
		uint32_t new_bss_ptmsi = GSM_RESERVED_TMSI;
		gprs_parse_tmsi(parse_ctx->new_ptmsi_enc, &new_sgsn_ptmsi);

		if (link_info->sgsn_tlli.ptmsi == new_sgsn_ptmsi)
			new_bss_ptmsi = link_info->tlli.ptmsi;

		if (new_bss_ptmsi == GSM_RESERVED_TMSI)
			new_bss_ptmsi = gbproxy_make_bss_ptmsi(peer, new_sgsn_ptmsi);

		LOGP(DGPRS, LOGL_INFO,
		     "Got new PTMSI %08x from SGSN, using %08x for BSS\n",
		     new_sgsn_ptmsi, new_bss_ptmsi);
		/* Setup PTMSIs */
		link_info->sgsn_tlli.ptmsi = new_sgsn_ptmsi;
		link_info->tlli.ptmsi = new_bss_ptmsi;
	} else if (parse_ctx->tlli_enc && parse_ctx->new_ptmsi_enc && !link_info &&
		   !peer->cfg->patch_ptmsi) {
		/* A new P-TMSI has been signalled in the message with an unknown
		 * TLLI, create a new link_info */
		/* TODO: Add a test case for this branch */
		uint32_t new_ptmsi;
		gprs_parse_tmsi(parse_ctx->new_ptmsi_enc, &new_ptmsi);

		LOGP(DGPRS, LOGL_INFO,
		     "Adding TLLI %08x to list (SGSN, new P-TMSI is %08x)\n",
		     parse_ctx->tlli, new_ptmsi);

		link_info = gbproxy_link_info_alloc(peer);
		link_info->sgsn_tlli.current = parse_ctx->tlli;
		link_info->tlli.current = parse_ctx->tlli;
		link_info->sgsn_tlli.ptmsi = new_ptmsi;
		link_info->tlli.ptmsi = new_ptmsi;
		gbproxy_attach_link_info(peer, now, link_info);
	} else if (parse_ctx->tlli_enc && parse_ctx->llc && !link_info &&
		   !peer->cfg->patch_ptmsi) {
		/* Unknown SGSN TLLI, create a new link_info */
		uint32_t new_ptmsi;
		link_info = gbproxy_link_info_alloc(peer);
		LOGP(DGPRS, LOGL_INFO, "Adding TLLI %08x to list (SGSN)\n",
		     parse_ctx->tlli);

		gbproxy_attach_link_info(peer, now, link_info);

		/* Setup TLLIs */
		link_info->sgsn_tlli.current = parse_ctx->tlli;
		link_info->tlli.current = parse_ctx->tlli;

		if (!parse_ctx->new_ptmsi_enc)
			return link_info;
		/* A new P-TMSI has been signalled in the message */

		gprs_parse_tmsi(parse_ctx->new_ptmsi_enc, &new_ptmsi);
		LOGP(DGPRS, LOGL_INFO,
		     "Assigning new P-TMSI %08x\n", new_ptmsi);
		/* Setup P-TMSIs */
		link_info->sgsn_tlli.ptmsi = new_ptmsi;
		link_info->tlli.ptmsi = new_ptmsi;
	} else if (parse_ctx->tlli_enc && parse_ctx->llc && link_info) {
		uint32_t bss_tlli = gbproxy_map_tlli(parse_ctx->tlli,
						     link_info, 1);
		gbproxy_validate_tlli(&link_info->sgsn_tlli, parse_ctx->tlli, 1);
		gbproxy_validate_tlli(&link_info->tlli, bss_tlli, 1);
		gbproxy_touch_link_info(peer, link_info, now);
	} else if (link_info) {
		gbproxy_touch_link_info(peer, link_info, now);
	}

	if (parse_ctx->imsi && link_info && link_info->imsi_len == 0)
		gbproxy_assign_imsi(peer, link_info, parse_ctx);

	return link_info;
}

int gbproxy_update_link_state_after(
	struct gbproxy_peer *peer,
	struct gbproxy_link_info *link_info,
	time_t now,
	struct gprs_gb_parse_context *parse_ctx)
{
	int rc = 0;
	if (parse_ctx->invalidate_tlli && link_info) {
		int keep_info =
			peer->cfg->keep_link_infos == GBPROX_KEEP_ALWAYS ||
			(peer->cfg->keep_link_infos == GBPROX_KEEP_REATTACH &&
			 parse_ctx->await_reattach) ||
			(peer->cfg->keep_link_infos == GBPROX_KEEP_IDENTIFIED &&
			 link_info->imsi_len > 0);
		if (keep_info) {
			LOGP(DGPRS, LOGL_INFO, "Unregistering TLLI %08x\n",
			     link_info->tlli.current);
			rc = gbproxy_unregister_link_info(peer, link_info);
		} else {
			LOGP(DGPRS, LOGL_INFO, "Removing TLLI %08x from list\n",
			     link_info->tlli.current);
			gbproxy_delete_link_info(peer, link_info);
			rc = 1;
		}
	} else if (parse_ctx->to_bss && parse_ctx->tlli_enc &&
		   parse_ctx->new_ptmsi_enc && link_info) {
		/* A new PTMSI has been signaled in the message,
		 * register new TLLI */
		uint32_t new_sgsn_ptmsi = link_info->sgsn_tlli.ptmsi;
		uint32_t new_bss_ptmsi = link_info->tlli.ptmsi;
		uint32_t new_sgsn_tlli;
		uint32_t new_bss_tlli = 0;

		new_sgsn_tlli = gprs_tmsi2tlli(new_sgsn_ptmsi, TLLI_LOCAL);
		if (new_bss_ptmsi != GSM_RESERVED_TMSI)
			new_bss_tlli = gprs_tmsi2tlli(new_bss_ptmsi, TLLI_LOCAL);
		LOGP(DGPRS, LOGL_INFO,
		     "Assigning new TLLI %08x to SGSN, %08x to BSS\n",
		     new_sgsn_tlli, new_bss_tlli);

		gbproxy_reassign_tlli(&link_info->sgsn_tlli,
				      peer, new_sgsn_tlli);
		gbproxy_reassign_tlli(&link_info->tlli,
				      peer, new_bss_tlli);
		gbproxy_remove_matching_link_infos(peer, link_info);
	}

	gbproxy_remove_stale_link_infos(peer, now);

	return rc;
}


