/* NS-over-IP proxy */

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

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <errno.h>
#include <sys/fcntl.h>
#include <sys/stat.h>
#include <arpa/inet.h>
#include <time.h>

#include <osmocom/core/talloc.h>
#include <osmocom/core/select.h>
#include <osmocom/core/rate_ctr.h>

#include <osmocom/vty/misc.h>

#include <osmocom/gprs/gprs_ns.h>
#include <osmocom/gprs/gprs_bssgp.h>

#include <osmocom/gsm/gsm_utils.h>

#include <openbsc/signal.h>
#include <openbsc/debug.h>
#include <openbsc/gb_proxy.h>

#include <openbsc/gprs_llc.h>
#include <openbsc/gsm_04_08.h>
#include <openbsc/gsm_04_08_gprs.h>

enum gbprox_global_ctr {
	GBPROX_GLOB_CTR_INV_BVCI,
	GBPROX_GLOB_CTR_INV_LAI,
	GBPROX_GLOB_CTR_INV_RAI,
	GBPROX_GLOB_CTR_INV_NSEI,
	GBPROX_GLOB_CTR_PROTO_ERR_BSS,
	GBPROX_GLOB_CTR_PROTO_ERR_SGSN,
	GBPROX_GLOB_CTR_NOT_SUPPORTED_BSS,
	GBPROX_GLOB_CTR_NOT_SUPPORTED_SGSN,
	GBPROX_GLOB_CTR_RESTART_RESET_SGSN,
	GBPROX_GLOB_CTR_TX_ERR_SGSN,
	GBPROX_GLOB_CTR_OTHER_ERR,
	GBPROX_GLOB_CTR_PATCH_PEER_ERR,
};

static const struct rate_ctr_desc global_ctr_description[] = {
	{ "inv-bvci",	    "Invalid BVC Identifier          " },
	{ "inv-lai",	    "Invalid Location Area Identifier" },
	{ "inv-rai",	    "Invalid Routing Area Identifier " },
	{ "inv-nsei",	    "No BVC established for NSEI     " },
	{ "proto-err.bss",  "BSSGP protocol error      (BSS )" },
	{ "proto-err.sgsn", "BSSGP protocol error      (SGSN)" },
	{ "not-supp.bss",   "Feature not supported     (BSS )" },
	{ "not-supp.sgsn",  "Feature not supported     (SGSN)" },
	{ "restart.sgsn",   "Restarted RESET procedure (SGSN)" },
	{ "tx-err.sgsn",    "NS Transmission error     (SGSN)" },
	{ "error",          "Other error                     " },
	{ "mod-peer-err",   "Patch error: no peer            " },
};

static const struct rate_ctr_group_desc global_ctrg_desc = {
	.group_name_prefix = "gbproxy.global",
	.group_description = "GBProxy Global Statistics",
	.num_ctr = ARRAY_SIZE(global_ctr_description),
	.ctr_desc = global_ctr_description,
};

static struct rate_ctr_group *global_ctrg = NULL;

static struct rate_ctr_group *get_global_ctrg()
{
	if (global_ctrg)
		return global_ctrg;

	global_ctrg = rate_ctr_group_alloc(tall_bsc_ctx, &global_ctrg_desc, 0);
	return global_ctrg;
}

enum gbprox_peer_ctr {
	GBPROX_PEER_CTR_BLOCKED,
	GBPROX_PEER_CTR_UNBLOCKED,
	GBPROX_PEER_CTR_DROPPED,
	GBPROX_PEER_CTR_INV_NSEI,
	GBPROX_PEER_CTR_TX_ERR,
	GBPROX_PEER_CTR_RAID_PATCHED_BSS,
	GBPROX_PEER_CTR_RAID_PATCHED_SGSN,
	GBPROX_PEER_CTR_APN_PATCHED,
	GBPROX_PEER_CTR_PATCH_CRYPT_ERR,
	GBPROX_PEER_CTR_PATCH_ERR,
};

static const struct rate_ctr_desc peer_ctr_description[] = {
	{ "blocked",	   "BVC Block                       " },
	{ "unblocked",	   "BVC Unblock                     " },
	{ "dropped",	   "BVC blocked, dropped packet     " },
	{ "inv-nsei",	   "NSEI mismatch                   " },
	{ "tx-err",	   "NS Transmission error           " },
	{ "raid-mod.bss",  "RAID patched              (BSS )" },
	{ "raid-mod.sgsn", "RAID patched              (SGSN)" },
	{ "apn-mod.sgsn",  "APN patched                     " },
	{ "mod-crypt-err", "Patch error: encrypted          " },
	{ "mod-err",	   "Patch error: other              " },
};

static const struct rate_ctr_group_desc peer_ctrg_desc = {
	.group_name_prefix = "gbproxy.peer",
	.group_description = "GBProxy Peer Statistics",
	.num_ctr = ARRAY_SIZE(peer_ctr_description),
	.ctr_desc = peer_ctr_description,
};

struct {
	int check_imsi;
	regex_t imsi_re_comp;
} gbprox_global_patch_state = {0,};

struct gbprox_patch_state {
	int local_mnc;
	int local_mcc;

	/* List of TLLIs for which patching is enabled */
	struct llist_head enabled_tllis;
	int enabled_tllis_count;
};

struct gbprox_peer {
	struct llist_head list;

	/* NSEI of the peer entity */
	uint16_t nsei;

	/* BVCI used for Point-to-Point to this peer */
	uint16_t bvci;
	int blocked;

	/* Routeing Area that this peer is part of (raw 04.08 encoding) */
	uint8_t ra[6];

	/* Counter */
	struct rate_ctr_group *ctrg;

	struct gbprox_patch_state patch_state;
};

/* Linked list of all Gb peers (except SGSN) */
static LLIST_HEAD(gbprox_bts_peers);

static void gbprox_delete_tllis(struct gbprox_peer *peer);

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

/* Find the gbprox_peer by its NSEI */
static struct gbprox_peer *peer_by_nsei(uint16_t nsei)
{
	struct gbprox_peer *peer;
	llist_for_each_entry(peer, &gbprox_bts_peers, list) {
		if (peer->nsei == nsei)
			return peer;
	}
	return NULL;
}

/* look-up a peer by its Routeing Area Identification (RAI) */
static struct gbprox_peer *peer_by_rai(const uint8_t *ra)
{
	struct gbprox_peer *peer;
	llist_for_each_entry(peer, &gbprox_bts_peers, list) {
		if (!memcmp(peer->ra, ra, 6))
			return peer;
	}
	return NULL;
}

/* look-up a peer by its Location Area Identification (LAI) */
static struct gbprox_peer *peer_by_lai(const uint8_t *la)
{
	struct gbprox_peer *peer;
	llist_for_each_entry(peer, &gbprox_bts_peers, list) {
		if (!memcmp(peer->ra, la, 5))
			return peer;
	}
	return NULL;
}

/* look-up a peer by its Location Area Code (LAC) */
static struct gbprox_peer *peer_by_lac(const uint8_t *la)
{
	struct gbprox_peer *peer;
	llist_for_each_entry(peer, &gbprox_bts_peers, list) {
		if (!memcmp(peer->ra + 3, la + 3, 2))
			return peer;
	}
	return NULL;
}


static int check_peer_nsei(struct gbprox_peer *peer, uint16_t nsei)
{
	if (peer->nsei != nsei) {
		LOGP(DGPRS, LOGL_NOTICE, "Peer entry doesn't match current NSEI "
		     "BVCI=%u via NSEI=%u (expected NSEI=%u)\n",
		     peer->bvci, nsei, peer->nsei);
		rate_ctr_inc(&peer->ctrg->ctr[GBPROX_PEER_CTR_INV_NSEI]);
		return 0;
	}

	return 1;
}

static struct gbprox_peer *peer_alloc(uint16_t bvci)
{
	struct gbprox_peer *peer;

	peer = talloc_zero(tall_bsc_ctx, struct gbprox_peer);
	if (!peer)
		return NULL;

	peer->bvci = bvci;
	peer->ctrg = rate_ctr_group_alloc(peer, &peer_ctrg_desc, bvci);

	llist_add(&peer->list, &gbprox_bts_peers);

	INIT_LLIST_HEAD(&peer->patch_state.enabled_tllis);

	return peer;
}

static void peer_free(struct gbprox_peer *peer)
{
	rate_ctr_group_free(peer->ctrg);
	llist_del(&peer->list);

	gbprox_delete_tllis(peer);

	talloc_free(peer);
}

/* FIXME: this needs to go to libosmocore/msgb.c */
static struct msgb *msgb_copy(const struct msgb *msg, const char *name)
{
	struct libgb_msgb_cb *old_cb, *new_cb;
	struct msgb *new_msg;

	new_msg = msgb_alloc(msg->data_len, name);
	if (!new_msg)
		return NULL;

	/* copy data */
	memcpy(new_msg->_data, msg->_data, new_msg->data_len);

	/* copy header */
	new_msg->len = msg->len;
	new_msg->data += msg->data - msg->_data;
	new_msg->head += msg->head - msg->_data;
	new_msg->tail += msg->tail - msg->_data;

	new_msg->l1h = new_msg->_data + (msg->l1h - msg->_data);
	new_msg->l2h = new_msg->_data + (msg->l2h - msg->_data);
	new_msg->l3h = new_msg->_data + (msg->l3h - msg->_data);
	new_msg->l4h = new_msg->_data + (msg->l4h - msg->_data);

	/* copy GB specific data */
	old_cb = LIBGB_MSGB_CB(msg);
	new_cb = LIBGB_MSGB_CB(new_msg);

	new_cb->bssgph = new_msg->_data + (old_cb->bssgph - msg->_data);
	new_cb->llch = new_msg->_data + (old_cb->llch - msg->_data);

	/* bssgp_cell_id is a pointer into the old msgb, so we need to make
	 * it a pointer into the new msgb */
	new_cb->bssgp_cell_id = new_msg->_data + (old_cb->bssgp_cell_id - msg->_data);
	new_cb->nsei = old_cb->nsei;
	new_cb->bvci = old_cb->bvci;
	new_cb->tlli = old_cb->tlli;

	return new_msg;
}

/* strip off the NS header */
static void strip_ns_hdr(struct msgb *msg)
{
	int strip_len = msgb_bssgph(msg) - msg->data;
	msgb_pull(msg, strip_len);
}

/* TODO: Move this to libosmocore/msgb.c */
static int msgb_resize_area(struct msgb *msg, uint8_t *area,
			    size_t old_size, size_t new_size)
{
	int rc;
	uint8_t *rest = area + old_size;
	int rest_len = msg->len - old_size - (area - msg->data);
	int delta_size = (int)new_size - (int)old_size;

	if (delta_size == 0)
		return 0;

	if (delta_size > 0) {
		rc = msgb_trim(msg, msg->len + delta_size);
		if (rc < 0)
			return rc;
	}

	memmove(area + new_size, area + old_size, rest_len);

	if (msg->l1h >= rest)
		msg->l1h += delta_size;
	if (msg->l2h >= rest)
		msg->l2h += delta_size;
	if (msg->l3h >= rest)
		msg->l3h += delta_size;
	if (msg->l4h >= rest)
		msg->l4h += delta_size;

	if (delta_size < 0)
		msgb_trim(msg, msg->len + delta_size);

	return 0;
}

/* TODO: Move these conversion functions to a utils file. */
char * gbprox_apn_to_str(char *out_str, const uint8_t *apn_enc, size_t rest_chars)
{
	char *str = out_str;

	while (rest_chars > 0 && apn_enc[0]) {
		size_t label_size = apn_enc[0];
		if (label_size + 1 > rest_chars)
			return NULL;

		memmove(str, apn_enc + 1, label_size);
		str += label_size;
		rest_chars -= label_size + 1;
		apn_enc += label_size + 1;

		if (rest_chars)
			*(str++) = '.';
	}
	str[0] = '\0';

	return out_str;
}

int gbprox_str_to_apn(uint8_t *apn_enc, const char *str, size_t max_chars)
{
	uint8_t *last_len_field = apn_enc;
	int len = 1;
	apn_enc += 1;

	while (str[0]) {
		if (str[0] == '.') {
			*last_len_field = (apn_enc - last_len_field) - 1;
			last_len_field = apn_enc;
		} else {
			*apn_enc = str[0];
		}
		apn_enc += 1;
		str += 1;
		len += 1;
		if (len > max_chars)
			return -1;
	}

	*last_len_field = (apn_enc - last_len_field) - 1;

	return len;
}

struct gbprox_tlli_info {
	struct llist_head list;

	uint32_t tlli;
	time_t timestamp;
	uint8_t *mi_data;
	size_t mi_data_len;
};

static struct gbprox_tlli_info *gbprox_find_tlli(struct gbprox_peer *peer,
						 uint32_t tlli)
{
	struct gbprox_tlli_info *tlli_info;
	struct gbprox_patch_state *state = &peer->patch_state;

	llist_for_each_entry(tlli_info, &state->enabled_tllis, list)
		if (tlli_info->tlli == tlli)
			return tlli_info;

	return NULL;
}

static struct gbprox_tlli_info *gbprox_find_tlli_by_mi(
	struct gbprox_peer *peer,
	const uint8_t *mi_data,
	size_t mi_data_len)
{
	struct gbprox_tlli_info *tlli_info;
	struct gbprox_patch_state *state = &peer->patch_state;

	llist_for_each_entry(tlli_info, &state->enabled_tllis, list) {
		if (tlli_info->mi_data_len != mi_data_len)
			continue;
		if (memcmp(tlli_info->mi_data, mi_data, mi_data_len) != 0)
			continue;

		return tlli_info;
	}

	return NULL;
}

static void gbprox_delete_tlli(struct gbprox_peer *peer,
			       struct gbprox_tlli_info *tlli_info)
{
	struct gbprox_patch_state *state = &peer->patch_state;

	llist_del(&tlli_info->list);
	talloc_free(tlli_info);
	state->enabled_tllis_count -= 1;
}

static void gbprox_delete_tllis(struct gbprox_peer *peer)
{
	struct gbprox_tlli_info *tlli_info, *nxt;
	struct gbprox_patch_state *state = &peer->patch_state;

	llist_for_each_entry_safe(tlli_info, nxt, &state->enabled_tllis, list) {
		llist_del(&tlli_info->list);
		talloc_free(tlli_info);
	}

	OSMO_ASSERT(llist_empty(&state->enabled_tllis));
}

int gbprox_set_patch_filter(const char *filter, const char **err_msg)
{
	static char err_buf[300];
	int rc;

	if (gbprox_global_patch_state.check_imsi) {
		regfree(&gbprox_global_patch_state.imsi_re_comp);
		gbprox_global_patch_state.check_imsi = 0;
	}

	if (!filter)
		return 0;

	rc = regcomp(&gbprox_global_patch_state.imsi_re_comp, filter,
		     REG_EXTENDED | REG_NOSUB | REG_ICASE);

	if (rc == 0) {
		gbprox_global_patch_state.check_imsi = 1;
		return 0;
	}

	if (err_msg) {
		regerror(rc, &gbprox_global_patch_state.imsi_re_comp,
			 err_buf, sizeof(err_buf));
		*err_msg = err_buf;
	}

	return -1;
}

static int gbprox_check_imsi(struct gbprox_peer *peer,
			     const uint8_t *imsi, size_t imsi_len)
{
	char mi_buf[200];
	int rc;

	if (!gbprox_global_patch_state.check_imsi)
		return 1;

	rc = gsm48_mi_to_string(mi_buf, sizeof(mi_buf), imsi, imsi_len);
	if (rc < 1) {
		LOGP(DGPRS, LOGL_NOTICE, "Invalid IMSI %s\n",
		     osmo_hexdump(imsi, imsi_len));
		return -1;
	}

	LOGP(DGPRS, LOGL_DEBUG, "Checking IMSI '%s' (%d)\n", mi_buf, rc);

	rc = regexec(&gbprox_global_patch_state.imsi_re_comp, mi_buf, 0, NULL, 0);
	if (rc == REG_NOMATCH) {
		LOGP(DGPRS, LOGL_INFO,
		       "IMSI '%s' doesn't match pattern '%s'\n",
		       mi_buf, gbcfg.match_re);
		return 0;
	}

	return 1;
}

static int gbprox_remove_stale_ttlis(struct gbprox_peer *peer, time_t now)
{
	struct gbprox_patch_state *state = &peer->patch_state;
	struct gbprox_tlli_info *tlli_info = NULL, *nxt;
	int count = 0;
	int deleted_count = 0;

	llist_for_each_entry_safe(tlli_info, nxt, &state->enabled_tllis, list) {
		int is_stale = 0;
		time_t age = now - tlli_info->timestamp;

		count += 1;

		if (gbcfg.tlli_max_len > 0)
			is_stale = is_stale || count > gbcfg.tlli_max_len;

		if (gbcfg.tlli_max_age > 0)
			is_stale = is_stale || age > gbcfg.tlli_max_age;

		if (!is_stale)
			continue;

		LOGP(DGPRS, LOGL_INFO,
		     "Removing TLLI %08x from list (stale)\n",
		     tlli_info->tlli);

		gbprox_delete_tlli(peer, tlli_info);
		tlli_info = NULL;

		deleted_count += 1;
	}

	return deleted_count;
}

static void gbprox_register_tlli(struct gbprox_peer *peer, uint32_t tlli,
				 const uint8_t *imsi, size_t imsi_len)
{
	struct gbprox_patch_state *state = &peer->patch_state;
	struct gbprox_tlli_info *tlli_info;
	int enable_patching;
	time_t now = 0;

	if (gprs_tlli_type(tlli) != TLLI_LOCAL)
		return;

	if (!imsi || (imsi[0] & GSM_MI_TYPE_MASK) != GSM_MI_TYPE_IMSI)
		return;

	if (!gbprox_global_patch_state.check_imsi)
		return;

	tlli_info = gbprox_find_tlli(peer, tlli);

#ifdef ENABLE_SAME_IMSI_OPTIMIZATION
	/* Optimization: Check whether the binary representation of the
	 * IMSI didn't change. If it didn't change, assume patching is enabled.
	 */
	/* TODO: This duplicates code and only avoids the IMSI lookup and the
	 * realloc/memcpy() below. It's probably not worth the effort. */
	if (tlli_info &&
	    imsi_len == tlli_info->mi_data_len &&
	    memcmp(imsi, tlli_info->mi_data, imsi_len) == 0) {
		/* Move the entry to the start of the list */
		llist_del(&tlli_info->list);
		llist_add(&tlli_info->list, &state->enabled_tllis);
		tlli_info->timestamp = time(NULL);
		return;
	}
#endif

	/* Check, whether the IMSI matches */
	enable_patching = gbprox_check_imsi(peer, imsi, imsi_len);

	if (enable_patching < 0)
		return;

	if (!tlli_info) {
		tlli_info = gbprox_find_tlli_by_mi(peer, imsi, imsi_len);

		if (tlli_info) {
			/* TLLI has changed somehow, adjust it */
			LOGP(DGPRS, LOGL_INFO,
			     "The TLLI has changed from %08x to %08x\n",
			     tlli_info->tlli, tlli);
			tlli_info->tlli = tlli;
		}
	}

	if (!tlli_info) {
		if (!enable_patching)
			return;

		LOGP(DGPRS, LOGL_INFO, "Adding TLLI %08x to list\n", tlli);
		tlli_info = talloc_zero(peer, struct gbprox_tlli_info);
		tlli_info->tlli = tlli;
	} else {
		llist_del(&tlli_info->list);
		OSMO_ASSERT(state->enabled_tllis_count > 0);
		state->enabled_tllis_count -= 1;
	}

	OSMO_ASSERT(tlli_info != NULL);

	if (enable_patching) {
		now = time(NULL);

		tlli_info->timestamp = now;
		llist_add(&tlli_info->list, &state->enabled_tllis);
		state->enabled_tllis_count += 1;

		gbprox_remove_stale_ttlis(peer, now);

		if (tlli_info != llist_entry(state->enabled_tllis.next,
					     struct gbprox_tlli_info, list)) {
			LOGP(DGPRS, LOGL_ERROR,
			     "Unexpectedly removed new TLLI entry as stale, "
			     "TLLI %08x\n", tlli);
			tlli_info = NULL;
		}
	} else {
		LOGP(DGPRS, LOGL_INFO,
		     "Removing TLLI %08x from list (patching no longer enabled)\n",
		     tlli);
		talloc_free(tlli_info);
		tlli_info = NULL;
	}

	if (tlli_info) {
		tlli_info->mi_data_len = imsi_len;
		tlli_info->mi_data =
			talloc_realloc_size(tlli_info, tlli_info->mi_data, imsi_len);
		OSMO_ASSERT(tlli_info->mi_data != NULL);
		memcpy(tlli_info->mi_data, imsi, imsi_len);
	}
}

static void gbprox_unregister_tlli(struct gbprox_peer *peer, uint32_t tlli)
{
	struct gbprox_tlli_info *tlli_info;

	tlli_info = gbprox_find_tlli(peer, tlli);
	if (tlli_info) {
		LOGP(DGPRS, LOGL_INFO,
		     "Removing TLLI %08x from list\n",
		     tlli);
		llist_del(&tlli_info->list);
		talloc_free(tlli_info);
	}
}

static int gbprox_check_tlli(struct gbprox_peer *peer, uint32_t tlli)
{
	LOGP(DGPRS, LOGL_INFO, "Checking TLLI %08x, class: %d\n",
	     tlli, gprs_tlli_type(tlli));
	if (gprs_tlli_type(tlli) != TLLI_LOCAL)
		return 0;

	return !gbprox_global_patch_state.check_imsi ||
		gbprox_find_tlli(peer, tlli) != NULL;
}

/* patch RA identifier in place, update peer accordingly */
static void gbprox_patch_raid(uint8_t *raid_enc, struct gbprox_peer *peer,
			      int to_bss, const char *log_text)
{
	struct gbprox_patch_state *state = &peer->patch_state;
	int old_local_mcc = state->local_mcc;
	int old_local_mnc = state->local_mnc;
	int old_mcc;
	int old_mnc;
	struct gprs_ra_id raid;

	gsm48_parse_ra(&raid, raid_enc);

	old_mcc = raid.mcc;
	old_mnc = raid.mnc;

	if (!to_bss) {
		/* BSS -> SGSN */
		/* save BSS side MCC/MNC */
		if (!gbcfg.core_mcc || raid.mcc == gbcfg.core_mcc) {
			state->local_mcc = 0;
		} else {
			state->local_mcc = raid.mcc;
			raid.mcc = gbcfg.core_mcc;
		}

		if (!gbcfg.core_mnc || raid.mnc == gbcfg.core_mnc) {
			state->local_mnc = 0;
		} else {
			state->local_mnc = raid.mnc;
			raid.mnc = gbcfg.core_mnc;
		}
	} else {
		/* SGSN -> BSS */
		if (state->local_mcc)
			raid.mcc = state->local_mcc;

		if (state->local_mnc)
			raid.mnc = state->local_mnc;
	}

	if (old_local_mcc != state->local_mcc ||
	    old_local_mnc != state->local_mnc)
		LOGP(DGPRS, LOGL_NOTICE,
		     "Patching RAID %sactivated, msg: %s, "
		     "local: %d-%d, core: %d-%d, to %s\n",
		     state->local_mcc || state->local_mnc ?
		     "" : "de",
		     log_text,
		     state->local_mcc, state->local_mnc,
		     gbcfg.core_mcc, gbcfg.core_mnc,
		     to_bss ? "BSS" : "SGSN");

	if (state->local_mcc || state->local_mnc) {
		enum gbprox_peer_ctr counter =
			to_bss ?
			GBPROX_PEER_CTR_RAID_PATCHED_SGSN :
			GBPROX_PEER_CTR_RAID_PATCHED_BSS;

		LOGP(DGPRS, LOGL_DEBUG,
		       "Patching %s to %s: "
		       "%d-%d-%d-%d -> %d-%d-%d-%d\n",
		       log_text,
		       to_bss ? "BSS" : "SGSN",
		       old_mcc, old_mnc, raid.lac, raid.rac,
		       raid.mcc, raid.mnc, raid.lac, raid.rac);

		gsm48_construct_ra(raid_enc, &raid);
		rate_ctr_inc(&peer->ctrg->ctr[counter]);
	}
}

static void gbprox_patch_apn_ie(struct msgb *msg,
				uint8_t *apn_ie, size_t apn_ie_len,
				struct gbprox_peer *peer,
				size_t *new_apn_ie_len, const char *log_text)
{
	struct apn_ie_hdr {
		uint8_t iei;
		uint8_t apn_len;
		uint8_t apn[0];
	} *hdr = (void *)apn_ie;

	size_t apn_len = hdr->apn_len;
	uint8_t *apn = hdr->apn;

	OSMO_ASSERT(apn_ie_len == apn_len + sizeof(struct apn_ie_hdr));
	OSMO_ASSERT(apn_ie_len > 2 && apn_ie_len <= 102);

	if (gbcfg.core_apn_size == 0) {
		char str1[110];
		/* Remove the IE */
		LOGP(DGPRS, LOGL_DEBUG,
		     "Patching %s to SGSN: Removing APN '%s'\n",
		     log_text,
		     gbprox_apn_to_str(str1, apn, apn_len));

		*new_apn_ie_len = 0;
		msgb_resize_area(msg, apn_ie, apn_ie_len, 0);
	} else {
		/* Resize the IE */
		char str1[110];
		char str2[110];

		OSMO_ASSERT(gbcfg.core_apn_size <= 100);

		LOGP(DGPRS, LOGL_DEBUG,
		     "Patching %s to SGSN: "
		     "Replacing APN '%s' -> '%s'\n",
		     log_text,
		     gbprox_apn_to_str(str1, apn, apn_len),
		     gbprox_apn_to_str(str2, gbcfg.core_apn,
				       gbcfg.core_apn_size));

		*new_apn_ie_len = gbcfg.core_apn_size + 2;
		msgb_resize_area(msg, apn, apn_len, gbcfg.core_apn_size);
		memcpy(apn, gbcfg.core_apn, gbcfg.core_apn_size);
		hdr->apn_len = gbcfg.core_apn_size;
	}

	rate_ctr_inc(&peer->ctrg->ctr[GBPROX_PEER_CTR_APN_PATCHED]);
}

static int gbprox_patch_gmm_attach_req(struct msgb *msg,
				       uint8_t *data, size_t data_len,
				       struct gbprox_peer *peer,
				       int to_bss, int *len_change)
{
	/* Check minimum length, always includes the RAI */
	if (data_len < 23)
		return 0;

	/* Skip MS network capability */
	if (data[0] < 1 || data[0] > 2)
		/* invalid */
		return 0;
	data_len -= data[0] + 1;
	data += data[0] + 1;

	/* Skip Attach type */
	/* Skip Ciphering key sequence number */
	/* Skip DRX parameter */
	data_len -= 3;
	data += 3;

	/* Skip Mobile identity */
	if (data[0] < 5 || data[0] > 8)
		/* invalid */
		return 0;
	data_len -= data[0] + 1;
	data += data[0] + 1;

	gbprox_patch_raid(data, peer, to_bss, "LLC/ATTACH_REQ");

	return 1;
}

static int gbprox_patch_gmm_attach_ack(struct msgb *msg,
				       uint8_t *data, size_t data_len,
				       struct gbprox_peer *peer,
				       int to_bss, int *len_change)
{
	/* Check minimum length, always includes the RAI */
	if (data_len < 9)
		return 0;;

	/* Skip Attach result */
	/* Skip Force to standby */
	/* Skip Periodic RA update timer */
	/* Skip Radio priority for SMS */
	/* Skip Spare half octet */
	data_len -= 3;
	data += 3;

	gbprox_patch_raid(data, peer, to_bss, "LLC/ATTACH_ACK");

	return 1;
}

static int gbprox_patch_gmm_ra_upd_req(struct msgb *msg,
				       uint8_t *data, size_t data_len,
				       struct gbprox_peer *peer,
				       int to_bss, int *len_change)
{
	/* Check minimum length, always includes the RAI */
	if (data_len < 13)
		return 0;;

	/* Skip Update type */
	/* Skip GPRS ciphering key sequence number */
	data_len -= 1;
	data += 1;

	gbprox_patch_raid(data, peer, to_bss, "LLC/RA_UPD_REQ");

	return 1;
}

static int gbprox_patch_gmm_ra_upd_ack(struct msgb *msg,
				       uint8_t *data, size_t data_len,
				       struct gbprox_peer *peer,
				       int to_bss, int *len_change)
{
	/* Check minimum length, always includes the RAI */
	if (data_len < 8)
		return 0;;

	/* Skip Force to standby */
	/* Skip Update result */
	/* Skip Periodic RA update timer */
	data_len -= 2;
	data += 2;

	gbprox_patch_raid(data, peer, to_bss, "LLC/RA_UPD_ACK");

	return 1;
}

static int gbprox_patch_gmm_ptmsi_reall_cmd(struct msgb *msg,
					    uint8_t *data, size_t data_len,
					    struct gbprox_peer *peer,
					    int to_bss, int *len_change)
{
	/* Check minimum length, always includes the RAI */
	if (data_len < 12)
		return 0;;

	/* Skip Allocated P-TMSI */
	if (data[0] != 5)
		/* invalid */
		return 0;;
	data_len -= 6;
	data += 6;

	gbprox_patch_raid(data, peer, to_bss, "LLC/PTMSI_REALL_CMD");

	return 1;
}

static int gbprox_patch_gsm_act_pdp_req(struct msgb *msg,
					uint8_t *data, size_t data_len,
					struct gbprox_peer *peer,
					int to_bss, int *len_change)
{
	size_t new_len, old_len;

	/* Check minimum length, always contains length field of
	 * Requested QoS */
	if (data_len < 9)
		return 0;

	/* Skip Requested NSAPI */
	/* Skip Requested LLC SAPI */
	data_len -= 2;
	data += 2;

	/* Skip Requested QoS (support 04.08 and 24.008) */
	if (data[0] < 4 || data[0] > 14 ||
	    data_len - (data[0] + 1) < 0)
		/* invalid */
		return 0;
	data_len -= data[0] + 1;
	data += data[0] + 1;

	/* Skip Requested PDP address */
	if (data_len < 1 ||
	    data[0] < 2 || data[0] > 18 ||
	    data_len - (data[0] + 1) < 0)
		/* invalid */
		return 0;
	data_len -= data[0] + 1;
	data += data[0] + 1;

	/* Access point name */
	if (data_len < 2 || data[0] != GSM48_IE_GSM_APN)
		return 0;

	if (data[1] < 1 || data[1] > 100 ||
	    data_len - (data[1] + 2) < 0)
		/* invalid */
		return 0;

	old_len = data[1] + 2;

	gbprox_patch_apn_ie(msg, data, old_len, peer, &new_len, "LLC/ACT_PDP_REQ");

	*len_change += (int)new_len - (int)old_len;
	data_len -= old_len;
	data += new_len;

	return 1;
}

struct gbprox_peer *peer_by_bssgp_tlv(struct tlv_parsed *tp)
{
	if (TLVP_PRESENT(tp, BSSGP_IE_BVCI)) {
		uint16_t bvci;

		bvci = ntohs(tlvp_val16_unal(tp, BSSGP_IE_BVCI));
		if (bvci >= 2)
			return peer_by_bvci(bvci);
	}

	if (TLVP_PRESENT(tp, BSSGP_IE_ROUTEING_AREA)) {
		uint8_t *rai = (uint8_t *)TLVP_VAL(tp, BSSGP_IE_ROUTEING_AREA);
		return peer_by_lac(rai);
	}

	if (TLVP_PRESENT(tp, BSSGP_IE_LOCATION_AREA)) {
		uint8_t *lai = (uint8_t *)TLVP_VAL(tp, BSSGP_IE_LOCATION_AREA);
		return peer_by_lac(lai);
	}

	return NULL;
}

static int gbprox_patch_dtap(struct msgb *msg, uint8_t *data, size_t data_len,
			     struct gbprox_peer *peer,
			     enum gbproxy_patch_mode patch_mode, int to_bss,
			     uint32_t tlli,
			     int *len_change)
{
	struct gsm48_hdr *g48h;

	*len_change = 0;

	if (data_len < 2)
		return 0;

	g48h = (struct gsm48_hdr *)data;

	data += sizeof(struct gsm48_hdr);
	data_len -= sizeof(struct gsm48_hdr);

	if ((g48h->proto_discr & 0x0f) != GSM48_PDISC_MM_GPRS &&
	    (g48h->proto_discr & 0x0f) != GSM48_PDISC_SM_GPRS)
		return 0;

	switch (g48h->msg_type) {
	case GSM48_MT_GMM_ATTACH_REQ:
		return gbprox_patch_gmm_attach_req(msg, data, data_len,
						   peer, to_bss, len_change);

	case GSM48_MT_GMM_ATTACH_ACK:
		if (patch_mode < GBPROX_PATCH_LLC_ATTACH)
			break;
		return gbprox_patch_gmm_attach_ack(msg, data, data_len,
						   peer, to_bss, len_change);

	case GSM48_MT_GMM_RA_UPD_REQ:
		if (patch_mode < GBPROX_PATCH_LLC_GMM)
			break;
		return gbprox_patch_gmm_ra_upd_req(msg, data, data_len,
						   peer, to_bss, len_change);

	case GSM48_MT_GMM_RA_UPD_ACK:
		if (patch_mode < GBPROX_PATCH_LLC_GMM)
			break;
		return gbprox_patch_gmm_ra_upd_ack(msg, data, data_len,
						   peer, to_bss, len_change);

	case GSM48_MT_GMM_PTMSI_REALL_CMD:
		if (patch_mode < GBPROX_PATCH_LLC_GMM)
			break;
		return gbprox_patch_gmm_ptmsi_reall_cmd(msg, data, data_len,
							peer, to_bss, len_change);

	case GSM48_MT_GSM_ACT_PDP_REQ:
		if (patch_mode < GBPROX_PATCH_LLC_GSM)
			break;
		if (gbcfg.core_apn == NULL)
			break;
		if (!gbprox_check_tlli(peer, tlli))
			break;
		return gbprox_patch_gsm_act_pdp_req(msg, data, data_len,
						    peer, to_bss, len_change);

	case GSM48_MT_GMM_DETACH_ACK:
	case GSM48_MT_GMM_DETACH_REQ:
		gbprox_unregister_tlli(peer, tlli);
		break;

	default:
		break;
	};

	return 0;
}

static void gbprox_patch_llc(struct msgb *msg, uint8_t *llc, size_t llc_len,
			     struct gbprox_peer *peer,
			     enum gbproxy_patch_mode patch_mode, int to_bss,
			     struct bssgp_ud_hdr *budh,
			     struct tlv_parsed *bssgp_tp)
{
	struct gprs_llc_hdr_parsed ghp = {0};
	int rc;
	uint8_t *data;
	size_t data_len;
	int fcs;
	int len_change = 0;
	const char *err_info = NULL;
	int err_ctr = -1;
	uint32_t tlli = budh ? ntohl(budh->tlli) : 0;

	/* parse LLC */
	rc = gprs_llc_hdr_parse(&ghp, llc, llc_len);
	gprs_llc_hdr_dump(&ghp);
	if (rc != 0) {
		LOGP(DLLC, LOGL_NOTICE, "Error during LLC header parsing\n");
		return;
	}

	fcs = gprs_llc_fcs(llc, ghp.crc_length);
	LOGP(DLLC, LOGL_DEBUG, "Got LLC message, CRC: %06x (computed %06x)\n",
	     ghp.fcs, fcs);

	if (!ghp.data)
		return;

	if (ghp.sapi != GPRS_SAPI_GMM)
		return;

	if (gbcfg.core_apn && to_bss && tlli &&
	    TLVP_PRESENT(bssgp_tp, BSSGP_IE_IMSI))
		gbprox_register_tlli(peer, tlli,
				     TLVP_VAL(bssgp_tp, BSSGP_IE_IMSI),
				     TLVP_LEN(bssgp_tp, BSSGP_IE_IMSI));

	if (ghp.cmd != GPRS_LLC_UI)
		return;

	if (ghp.is_encrypted) {
		if (gbcfg.patch_mode > GBPROX_PATCH_LLC_ATTACH_REQ) {
			/* LLC patch (GMM) has been requested explicitely */
			err_info = "GMM message is encrypted";
			err_ctr = GBPROX_PEER_CTR_PATCH_CRYPT_ERR;
			goto patch_error;
		}

		return;
	}

	/* fix DTAP GMM/GSM */
	data = ghp.data;
	data_len = ghp.data_len;

	rc = gbprox_patch_dtap(msg, data, data_len, peer, patch_mode, to_bss,
			       tlli, &len_change);

	if (rc > 0) {
		llc_len += len_change;
		ghp.crc_length += len_change;

		/* Fix LLC IE len */
		if (llc[-2] == BSSGP_IE_LLC_PDU && llc[-1] & 0x80) {
			/* most probably a one byte length */
			if (llc_len > 127) {
				err_info = "Cannot increase size";
				err_ctr = GBPROX_PEER_CTR_PATCH_ERR;
				goto patch_error;
			}
			llc[-1] = llc_len | 0x80;
		} else {
			llc[-2] = (llc_len >> 8) & 0x7f;
			llc[-1] = llc_len & 0xff;
		}

		/* Fix FCS */
		fcs = gprs_llc_fcs(llc, ghp.crc_length);
		LOGP(DLLC, LOGL_DEBUG, "Updated LLC message, CRC: %06x -> %06x\n",
		     ghp.fcs, fcs);

		llc[llc_len - 3] = fcs & 0xff;
		llc[llc_len - 2] = (fcs >> 8) & 0xff;
		llc[llc_len - 1] = (fcs >> 16) & 0xff;
	}

	return;

patch_error:
	OSMO_ASSERT(err_ctr >= 0);
	rate_ctr_inc(&peer->ctrg->ctr[err_ctr]);
	LOGP(DGPRS, LOGL_ERROR,
	     "Failed to patch BSSGP/GMM message as requested: %s.\n", err_info);

	return;
}

/* patch BSSGP message to use core_mcc/mnc on the SGSN side */
static void gbprox_patch_bssgp_message(struct msgb *msg,
				       struct gbprox_peer *peer, int to_bss)
{
	struct bssgp_normal_hdr *bgph;
	struct bssgp_ud_hdr *budh = NULL;
	struct tlv_parsed tp;
	uint8_t pdu_type;
	uint8_t *data;
	size_t data_len;
	enum gbproxy_patch_mode patch_mode;

	if (!gbcfg.core_mcc && !gbcfg.core_mnc && !gbcfg.core_apn)
		return;

	bgph = (struct bssgp_normal_hdr *) msgb_bssgph(msg);
	pdu_type = bgph->pdu_type;
	patch_mode = gbcfg.patch_mode;
	if (patch_mode == GBPROX_PATCH_DEFAULT)
		patch_mode = GBPROX_PATCH_LLC;

	if (pdu_type == BSSGP_PDUT_UL_UNITDATA ||
	    pdu_type == BSSGP_PDUT_DL_UNITDATA) {
		budh = (struct bssgp_ud_hdr *) msgb_bssgph(msg);
		bgph = NULL;
		data = budh->data;
		data_len = msgb_bssgp_len(msg) - sizeof(*budh);
	} else {
		data = bgph->data;
		data_len = msgb_bssgp_len(msg) - sizeof(*bgph);
	}

	/* fix BSSGP */
	bssgp_tlv_parse(&tp, data, data_len);

	if (!peer && msgb_bvci(msg) >= 2)
		peer = peer_by_bvci(msgb_bvci(msg));

	if (!peer && !to_bss)
		peer = peer_by_nsei(msgb_nsei(msg));

	if (!peer)
		peer = peer_by_bssgp_tlv(&tp);

	if (!peer) {
		LOGP(DLLC, LOGL_INFO,
		     "NSEI=%d(%s) patching: didn't find peer for message, "
		     "PDU %d\n",
		     msgb_nsei(msg), to_bss ? "SGSN" : "BSS", pdu_type);
		/* Increment counter */
		rate_ctr_inc(&get_global_ctrg()->ctr[GBPROX_GLOB_CTR_PATCH_PEER_ERR]);
		return;
	}

	if (TLVP_PRESENT(&tp, BSSGP_IE_ROUTEING_AREA)) {
		gbprox_patch_raid((uint8_t *)TLVP_VAL(&tp, BSSGP_IE_ROUTEING_AREA),
				  peer, to_bss, "ROUTING_AREA");
	}

	if (TLVP_PRESENT(&tp, BSSGP_IE_CELL_ID))
		gbprox_patch_raid((uint8_t *)TLVP_VAL(&tp, BSSGP_IE_CELL_ID),
				  peer, to_bss, "CELL_ID");

	if (TLVP_PRESENT(&tp, BSSGP_IE_LLC_PDU) &&
	    patch_mode >= GBPROX_PATCH_LLC_ATTACH_REQ) {
		uint8_t *llc = (uint8_t *)TLVP_VAL(&tp, BSSGP_IE_LLC_PDU);
		size_t llc_len = TLVP_LEN(&tp, BSSGP_IE_LLC_PDU);
		gbprox_patch_llc(msg, llc, llc_len, peer, patch_mode,
				 to_bss, budh, &tp);
		/* Note that the tp struct might contain invalid pointers here
		 * if the LLC field has changed its size */
	}
}

/* feed a message down the NS-VC associated with the specified peer */
static int gbprox_relay2sgsn(struct msgb *old_msg,
			     struct gbprox_peer *peer, uint16_t ns_bvci)
{
	/* create a copy of the message so the old one can
	 * be free()d safely when we return from gbprox_rcvmsg() */
	struct msgb *msg = msgb_copy(old_msg, "msgb_relay2sgsn");
	int rc;

	gbprox_patch_bssgp_message(msg, peer, 0);

	DEBUGP(DGPRS, "NSEI=%u proxying BTS->SGSN (NS_BVCI=%u, NSEI=%u)\n",
		msgb_nsei(msg), ns_bvci, gbcfg.nsip_sgsn_nsei);

	msgb_bvci(msg) = ns_bvci;
	msgb_nsei(msg) = gbcfg.nsip_sgsn_nsei;

	strip_ns_hdr(msg);

	rc = gprs_ns_sendmsg(bssgp_nsi, msg);
	if (rc < 0)
		rate_ctr_inc(&get_global_ctrg()->ctr[GBPROX_GLOB_CTR_TX_ERR_SGSN]);

	return rc;
}

/* feed a message down the NS-VC associated with the specified peer */
static int gbprox_relay2peer(struct msgb *old_msg, struct gbprox_peer *peer,
			  uint16_t ns_bvci)
{
	/* create a copy of the message so the old one can
	 * be free()d safely when we return from gbprox_rcvmsg() */
	struct msgb *msg = msgb_copy(old_msg, "msgb_relay2peer");
	int rc;

	DEBUGP(DGPRS, "NSEI=%u proxying SGSN->BSS (NS_BVCI=%u, NSEI=%u)\n",
		msgb_nsei(msg), ns_bvci, peer->nsei);

	msgb_bvci(msg) = ns_bvci;
	msgb_nsei(msg) = peer->nsei;

	/* Strip the old NS header, it will be replaced with a new one */
	strip_ns_hdr(msg);

	rc = gprs_ns_sendmsg(bssgp_nsi, msg);
	if (rc < 0)
		rate_ctr_inc(&peer->ctrg->ctr[GBPROX_PEER_CTR_TX_ERR]);

	return rc;
}

static int block_unblock_peer(uint16_t ptp_bvci, uint8_t pdu_type)
{
	struct gbprox_peer *peer;

	peer = peer_by_bvci(ptp_bvci);
	if (!peer) {
		LOGP(DGPRS, LOGL_ERROR, "BVCI=%u: Cannot find BSS\n",
			ptp_bvci);
		rate_ctr_inc(&get_global_ctrg()->ctr[GBPROX_GLOB_CTR_INV_BVCI]);
		return -ENOENT;
	}

	switch (pdu_type) {
	case BSSGP_PDUT_BVC_BLOCK_ACK:
		peer->blocked = 1;
		rate_ctr_inc(&peer->ctrg->ctr[GBPROX_PEER_CTR_BLOCKED]);
		break;
	case BSSGP_PDUT_BVC_UNBLOCK_ACK:
		peer->blocked = 0;
		rate_ctr_inc(&peer->ctrg->ctr[GBPROX_PEER_CTR_UNBLOCKED]);
		break;
	default:
		break;
	}
	return 0;
}

/* Send a message to a peer identified by ptp_bvci but using ns_bvci
 * in the NS hdr */
static int gbprox_relay2bvci(struct msgb *msg, uint16_t ptp_bvci,
			  uint16_t ns_bvci)
{
	struct gbprox_peer *peer;

	peer = peer_by_bvci(ptp_bvci);
	if (!peer) {
		LOGP(DGPRS, LOGL_ERROR, "BVCI=%u: Cannot find BSS\n",
			ptp_bvci);
		rate_ctr_inc(&get_global_ctrg()->ctr[GBPROX_GLOB_CTR_INV_BVCI]);
		return -ENOENT;
	}

	return gbprox_relay2peer(msg, peer, ns_bvci);
}

int bssgp_prim_cb(struct osmo_prim_hdr *oph, void *ctx)
{
	return 0;
}

/* Receive an incoming signalling message from a BSS-side NS-VC */
static int gbprox_rx_sig_from_bss(struct msgb *msg, uint16_t nsei,
				  uint16_t ns_bvci)
{
	struct bssgp_normal_hdr *bgph = (struct bssgp_normal_hdr *) msgb_bssgph(msg);
	struct tlv_parsed tp;
	uint8_t pdu_type = bgph->pdu_type;
	int data_len = msgb_bssgp_len(msg) - sizeof(*bgph);
	struct gbprox_peer *from_peer = NULL;
	struct gprs_ra_id raid;

	if (ns_bvci != 0 && ns_bvci != 1) {
		LOGP(DGPRS, LOGL_NOTICE, "NSEI=%u BVCI=%u is not signalling\n",
			nsei, ns_bvci);
		return -EINVAL;
	}

	/* we actually should never see those two for BVCI == 0, but double-check
	 * just to make sure  */
	if (pdu_type == BSSGP_PDUT_UL_UNITDATA ||
	    pdu_type == BSSGP_PDUT_DL_UNITDATA) {
		LOGP(DGPRS, LOGL_NOTICE, "NSEI=%u UNITDATA not allowed in "
			"signalling\n", nsei);
		return -EINVAL;
	}

	bssgp_tlv_parse(&tp, bgph->data, data_len);

	switch (pdu_type) {
	case BSSGP_PDUT_SUSPEND:
	case BSSGP_PDUT_RESUME:
		/* We implement RAI snooping during SUSPEND/RESUME, since it
		 * establishes a relationsip between BVCI/peer and the routeing
		 * area identification.  The snooped information is then used
		 * for routing the {SUSPEND,RESUME}_[N]ACK back to the correct
		 * BSSGP */
		if (!TLVP_PRESENT(&tp, BSSGP_IE_ROUTEING_AREA))
			goto err_mand_ie;
		from_peer = peer_by_nsei(nsei);
		if (!from_peer)
			goto err_no_peer;
		memcpy(from_peer->ra, TLVP_VAL(&tp, BSSGP_IE_ROUTEING_AREA),
			sizeof(from_peer->ra));
		gsm48_parse_ra(&raid, from_peer->ra);
		LOGP(DGPRS, LOGL_INFO, "NSEI=%u BSSGP SUSPEND/RESUME "
			"RAI snooping: RAI %u-%u-%u-%u behind BVCI=%u\n",
			nsei, raid.mcc, raid.mnc, raid.lac,
			raid.rac , from_peer->bvci);
		/* FIXME: This only supports one BSS per RA */
		break;
	case BSSGP_PDUT_BVC_RESET:
		/* If we receive a BVC reset on the signalling endpoint, we
		 * don't want the SGSN to reset, as the signalling endpoint
		 * is common for all point-to-point BVCs (and thus all BTS) */
		if (TLVP_PRESENT(&tp, BSSGP_IE_BVCI)) {
			uint16_t bvci = ntohs(tlvp_val16_unal(&tp, BSSGP_IE_BVCI));
			LOGP(DGPRS, LOGL_INFO, "NSEI=%u Rx BVC RESET (BVCI=%u)\n",
				nsei, bvci);
			if (bvci == 0) {
				/* FIXME: only do this if SGSN is alive! */
				LOGP(DGPRS, LOGL_INFO, "NSEI=%u Tx fake "
					"BVC RESET ACK of BVCI=0\n", nsei);
				return bssgp_tx_simple_bvci(BSSGP_PDUT_BVC_RESET_ACK,
							    nsei, 0, ns_bvci);
			}
			from_peer = peer_by_bvci(bvci);
			if (!from_peer) {
				/* if a PTP-BVC is reset, and we don't know that
				 * PTP-BVCI yet, we should allocate a new peer */
				LOGP(DGPRS, LOGL_INFO, "Allocationg new peer for "
				     "BVCI=%u via NSEI=%u\n", bvci, nsei);
				from_peer = peer_alloc(bvci);
				from_peer->nsei = nsei;
			}

			if (!check_peer_nsei(from_peer, nsei))
				from_peer->nsei = nsei;

			if (TLVP_PRESENT(&tp, BSSGP_IE_CELL_ID)) {
				struct gprs_ra_id raid;
				/* We have a Cell Identifier present in this
				 * PDU, this means we can extend our local
				 * state information about this particular cell
				 * */
				memcpy(from_peer->ra,
					TLVP_VAL(&tp, BSSGP_IE_CELL_ID),
					sizeof(from_peer->ra));
				gsm48_parse_ra(&raid, from_peer->ra);
				LOGP(DGPRS, LOGL_INFO, "NSEI=%u/BVCI=%u "
				     "Cell ID %u-%u-%u-%u\n", nsei,
				     bvci, raid.mcc, raid.mnc, raid.lac,
				     raid.rac);
			}
		}
		break;
	}

	/* Normally, we can simply pass on all signalling messages from BSS to
	 * SGSN */
	return gbprox_relay2sgsn(msg, from_peer, ns_bvci);
err_no_peer:
	LOGP(DGPRS, LOGL_ERROR, "NSEI=%u(BSS) cannot find peer based on NSEI\n",
		nsei);
	rate_ctr_inc(&get_global_ctrg()->ctr[GBPROX_GLOB_CTR_INV_NSEI]);
	return bssgp_tx_status(BSSGP_CAUSE_UNKNOWN_BVCI, NULL, msg);
err_mand_ie:
	LOGP(DGPRS, LOGL_ERROR, "NSEI=%u(BSS) missing mandatory RA IE\n",
		nsei);
	rate_ctr_inc(&get_global_ctrg()->ctr[GBPROX_GLOB_CTR_PROTO_ERR_BSS]);
	return bssgp_tx_status(BSSGP_CAUSE_MISSING_MAND_IE, NULL, msg);
}

/* Receive paging request from SGSN, we need to relay to proper BSS */
static int gbprox_rx_paging(struct msgb *msg, struct tlv_parsed *tp,
			    uint32_t nsei, uint16_t ns_bvci)
{
	struct gbprox_peer *peer = NULL;
	int errctr = GBPROX_GLOB_CTR_PROTO_ERR_SGSN;

	LOGP(DGPRS, LOGL_INFO, "NSEI=%u(SGSN) BSSGP PAGING ",
		nsei);
	if (TLVP_PRESENT(tp, BSSGP_IE_BVCI)) {
		uint16_t bvci = ntohs(tlvp_val16_unal(tp, BSSGP_IE_BVCI));
		LOGPC(DGPRS, LOGL_INFO, "routing by BVCI to peer BVCI=%u\n",
			bvci);
		errctr = GBPROX_GLOB_CTR_OTHER_ERR;
	} else if (TLVP_PRESENT(tp, BSSGP_IE_ROUTEING_AREA)) {
		peer = peer_by_rai(TLVP_VAL(tp, BSSGP_IE_ROUTEING_AREA));
		LOGPC(DGPRS, LOGL_INFO, "routing by RAI to peer BVCI=%u\n",
			peer ? peer->bvci : -1);
		errctr = GBPROX_GLOB_CTR_INV_RAI;
	} else if (TLVP_PRESENT(tp, BSSGP_IE_LOCATION_AREA)) {
		peer = peer_by_lai(TLVP_VAL(tp, BSSGP_IE_LOCATION_AREA));
		LOGPC(DGPRS, LOGL_INFO, "routing by LAI to peer BVCI=%u\n",
			peer ? peer->bvci : -1);
		errctr = GBPROX_GLOB_CTR_INV_LAI;
	} else
		LOGPC(DGPRS, LOGL_INFO, "\n");

	if (!peer) {
		LOGP(DGPRS, LOGL_ERROR, "NSEI=%u(SGSN) BSSGP PAGING: "
			"unable to route, missing IE\n", nsei);
		rate_ctr_inc(&get_global_ctrg()->ctr[errctr]);
		return -EINVAL;
	}
	return gbprox_relay2peer(msg, peer, ns_bvci);
}

/* Receive an incoming BVC-RESET message from the SGSN */
static int rx_reset_from_sgsn(struct msgb *msg, struct tlv_parsed *tp,
			      uint32_t nsei, uint16_t ns_bvci)
{
	struct gbprox_peer *peer;
	uint16_t ptp_bvci;

	if (!TLVP_PRESENT(tp, BSSGP_IE_BVCI)) {
		rate_ctr_inc(&get_global_ctrg()->
			     ctr[GBPROX_GLOB_CTR_PROTO_ERR_SGSN]);
		return bssgp_tx_status(BSSGP_CAUSE_MISSING_MAND_IE,
				       NULL, msg);
	}
	ptp_bvci = ntohs(tlvp_val16_unal(tp, BSSGP_IE_BVCI));

	if (ptp_bvci >= 2) {
		/* A reset for a PTP BVC was received, forward it to its
		 * respective peer */
		peer = peer_by_bvci(ptp_bvci);
		if (!peer) {
			LOGP(DGPRS, LOGL_ERROR, "NSEI=%u BVCI=%u: Cannot find BSS\n",
				nsei, ptp_bvci);
			rate_ctr_inc(&get_global_ctrg()->
				     ctr[GBPROX_GLOB_CTR_INV_BVCI]);
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
static int gbprox_rx_sig_from_sgsn(struct msgb *msg, uint32_t nsei,
				   uint16_t ns_bvci)
{
	struct bssgp_normal_hdr *bgph = (struct bssgp_normal_hdr *) msgb_bssgph(msg);
	struct tlv_parsed tp;
	uint8_t pdu_type = bgph->pdu_type;
	int data_len = msgb_bssgp_len(msg) - sizeof(*bgph);
	struct gbprox_peer *peer;
	uint16_t bvci;
	int rc = 0;

	if (ns_bvci != 0 && ns_bvci != 1) {
		LOGP(DGPRS, LOGL_NOTICE, "NSEI=%u(SGSN) BVCI=%u is not "
			"signalling\n", nsei, ns_bvci);
		/* FIXME: Send proper error message */
		return -EINVAL;
	}

	/* we actually should never see those two for BVCI == 0, but double-check
	 * just to make sure  */
	if (pdu_type == BSSGP_PDUT_UL_UNITDATA ||
	    pdu_type == BSSGP_PDUT_DL_UNITDATA) {
		LOGP(DGPRS, LOGL_NOTICE, "NSEI=%u(SGSN) UNITDATA not allowed in "
			"signalling\n", nsei);
		return bssgp_tx_status(BSSGP_CAUSE_PROTO_ERR_UNSPEC, NULL, msg);
	}

	rc = bssgp_tlv_parse(&tp, bgph->data, data_len);

	switch (pdu_type) {
	case BSSGP_PDUT_BVC_RESET:
		rc = rx_reset_from_sgsn(msg, &tp, nsei, ns_bvci);
		break;
	case BSSGP_PDUT_FLUSH_LL:
	case BSSGP_PDUT_BVC_RESET_ACK:
		/* simple case: BVCI IE is mandatory */
		if (!TLVP_PRESENT(&tp, BSSGP_IE_BVCI))
			goto err_mand_ie;
		bvci = ntohs(tlvp_val16_unal(&tp, BSSGP_IE_BVCI));
		rc = gbprox_relay2bvci(msg, bvci, ns_bvci);
		break;
	case BSSGP_PDUT_PAGING_PS:
	case BSSGP_PDUT_PAGING_CS:
		/* process the paging request (LAI/RAI lookup) */
		rc = gbprox_rx_paging(msg, &tp, nsei, ns_bvci);
		break;
	case BSSGP_PDUT_STATUS:
		/* Some exception has occurred */
		LOGP(DGPRS, LOGL_NOTICE,
			"NSEI=%u(SGSN) BSSGP STATUS ", nsei);
		if (!TLVP_PRESENT(&tp, BSSGP_IE_CAUSE)) {
			LOGPC(DGPRS, LOGL_NOTICE, "\n");
			goto err_mand_ie;
		}
		LOGPC(DGPRS, LOGL_NOTICE,
			"cause=0x%02x(%s) ", *TLVP_VAL(&tp, BSSGP_IE_CAUSE),
			bssgp_cause_str(*TLVP_VAL(&tp, BSSGP_IE_CAUSE)));
		if (TLVP_PRESENT(&tp, BSSGP_IE_BVCI)) {
			uint16_t bvci = tlvp_val16_unal(&tp, BSSGP_IE_BVCI);
			LOGPC(DGPRS, LOGL_NOTICE,
				"BVCI=%u\n", ntohs(bvci));
		} else
			LOGPC(DGPRS, LOGL_NOTICE, "\n");
		break;
	/* those only exist in the SGSN -> BSS direction */
	case BSSGP_PDUT_SUSPEND_ACK:
	case BSSGP_PDUT_SUSPEND_NACK:
	case BSSGP_PDUT_RESUME_ACK:
	case BSSGP_PDUT_RESUME_NACK:
		/* RAI IE is mandatory */
		if (!TLVP_PRESENT(&tp, BSSGP_IE_ROUTEING_AREA))
			goto err_mand_ie;
		peer = peer_by_rai(TLVP_VAL(&tp, BSSGP_IE_ROUTEING_AREA));
		if (!peer)
			goto err_no_peer;
		rc = gbprox_relay2peer(msg, peer, ns_bvci);
		break;
	case BSSGP_PDUT_BVC_BLOCK_ACK:
	case BSSGP_PDUT_BVC_UNBLOCK_ACK:
		if (!TLVP_PRESENT(&tp, BSSGP_IE_BVCI))
			goto err_mand_ie;
		bvci = ntohs(tlvp_val16_unal(&tp, BSSGP_IE_BVCI));
		if (bvci == 0) {
			LOGP(DGPRS, LOGL_NOTICE, "NSEI=%u(SGSN) BSSGP "
			     "%sBLOCK_ACK for signalling BVCI ?!?\n", nsei,
			     pdu_type == BSSGP_PDUT_BVC_UNBLOCK_ACK ? "UN":"");
			/* should we send STATUS ? */
			rate_ctr_inc(&get_global_ctrg()->
				     ctr[GBPROX_GLOB_CTR_INV_BVCI]);
		} else {
			/* Mark BVC as (un)blocked */
			block_unblock_peer(bvci, pdu_type);
		}
		rc = gbprox_relay2bvci(msg, bvci, ns_bvci);
		break;
	case BSSGP_PDUT_SGSN_INVOKE_TRACE:
		LOGP(DGPRS, LOGL_ERROR,
		     "NSEI=%u(SGSN) BSSGP INVOKE TRACE not supported\n",nsei);
		rate_ctr_inc(&get_global_ctrg()->
			     ctr[GBPROX_GLOB_CTR_NOT_SUPPORTED_SGSN]);
		rc = bssgp_tx_status(BSSGP_CAUSE_PDU_INCOMP_FEAT, NULL, msg);
		break;
	default:
		LOGP(DGPRS, LOGL_NOTICE, "BSSGP PDU type 0x%02x unknown\n",
			pdu_type);
		rate_ctr_inc(&get_global_ctrg()->
			     ctr[GBPROX_GLOB_CTR_PROTO_ERR_SGSN]);
		rc = bssgp_tx_status(BSSGP_CAUSE_PROTO_ERR_UNSPEC, NULL, msg);
		break;
	}

	return rc;
err_mand_ie:
	LOGP(DGPRS, LOGL_ERROR, "NSEI=%u(SGSN) missing mandatory IE\n",
		nsei);
	rate_ctr_inc(&get_global_ctrg()->
		     ctr[GBPROX_GLOB_CTR_PROTO_ERR_SGSN]);
	return bssgp_tx_status(BSSGP_CAUSE_MISSING_MAND_IE, NULL, msg);
err_no_peer:
	LOGP(DGPRS, LOGL_ERROR, "NSEI=%u(SGSN) cannot find peer based on RAI\n",
		nsei);
	rate_ctr_inc(&get_global_ctrg()-> ctr[GBPROX_GLOB_CTR_INV_RAI]);
	return bssgp_tx_status(BSSGP_CAUSE_UNKNOWN_BVCI, NULL, msg);
}

/* Main input function for Gb proxy */
int gbprox_rcvmsg(struct msgb *msg, uint16_t nsei, uint16_t ns_bvci, uint16_t nsvci)
{
	int rc;
	struct gbprox_peer *peer;
	int remote_end_is_sgsn = nsei == gbcfg.nsip_sgsn_nsei;

	if (remote_end_is_sgsn)
		gbprox_patch_bssgp_message(msg, NULL, 1);

	/* Only BVCI=0 messages need special treatment */
	if (ns_bvci == 0 || ns_bvci == 1) {
		if (remote_end_is_sgsn)
			rc = gbprox_rx_sig_from_sgsn(msg, nsei, ns_bvci);
		else
			rc = gbprox_rx_sig_from_bss(msg, nsei, ns_bvci);
	} else {
		peer = peer_by_bvci(ns_bvci);

		/* All other BVCI are PTP and thus can be simply forwarded */
		if (!remote_end_is_sgsn) {
			if (peer)
				check_peer_nsei(peer, nsei);
			return gbprox_relay2sgsn(msg, peer, ns_bvci);
		}

		/* else: SGSN -> BSS direction */
		if (!peer) {
			LOGP(DGPRS, LOGL_INFO, "Didn't find peer for "
			     "BVCI=%u for message from NSVC=%u/NSEI=%u (SGSN)\n",
			     ns_bvci, nsvci, nsei);
			rate_ctr_inc(&get_global_ctrg()->
				     ctr[GBPROX_GLOB_CTR_INV_BVCI]);
			return bssgp_tx_status(BSSGP_CAUSE_UNKNOWN_BVCI,
					       &ns_bvci, msg);
		}
		if (peer->blocked) {
			LOGP(DGPRS, LOGL_NOTICE, "Dropping PDU for "
			     "blocked BVCI=%u via NSVC=%u/NSEI=%u\n",
			     ns_bvci, nsvci, nsei);
			rate_ctr_inc(&peer->ctrg->ctr[GBPROX_PEER_CTR_DROPPED]);
			return bssgp_tx_status(BSSGP_CAUSE_BVCI_BLOCKED, NULL, msg);
		}
		rc = gbprox_relay2peer(msg, peer, ns_bvci);
	}

	return rc;
}

int gbprox_reset_persistent_nsvcs(struct gprs_ns_inst *nsi)
{
	struct gprs_nsvc *nsvc;

	llist_for_each_entry(nsvc, &nsi->gprs_nsvcs, list) {
		if (!nsvc->persistent)
			continue;
		gprs_nsvc_reset(nsvc, NS_CAUSE_OM_INTERVENTION);
	}
	return 0;
}

/* Signal handler for signals from NS layer */
int gbprox_signal(unsigned int subsys, unsigned int signal,
		  void *handler_data, void *signal_data)
{
	struct ns_signal_data *nssd = signal_data;
	struct gprs_nsvc *nsvc = nssd->nsvc;
	struct gbprox_peer *peer;

	if (subsys != SS_L_NS)
		return 0;

	if (signal == S_NS_RESET && nsvc->nsei == gbcfg.nsip_sgsn_nsei) {
		/* We have received a NS-RESET from the NSEI and NSVC
		 * of the SGSN.  This might happen with SGSN that start
		 * their own NS-RESET procedure without waiting for our
		 * NS-RESET */
		nsvc->remote_end_is_sgsn = 1;
	}

	if (signal == S_NS_ALIVE_EXP && nsvc->remote_end_is_sgsn) {
		LOGP(DGPRS, LOGL_NOTICE, "Tns alive expired too often, "
			"re-starting RESET procedure\n");
		rate_ctr_inc(&get_global_ctrg()->
			     ctr[GBPROX_GLOB_CTR_RESTART_RESET_SGSN]);
		gprs_ns_nsip_connect(nsvc->nsi, &nsvc->ip.bts_addr,
				  nsvc->nsei, nsvc->nsvci);
	}

	if (!nsvc->remote_end_is_sgsn) {
		/* from BSS to SGSN */
		peer = peer_by_nsei(nsvc->nsei);
		if (!peer) {
			LOGP(DGPRS, LOGL_NOTICE, "signal %u for unknown peer "
			     "NSEI=%u/NSVCI=%u\n", signal, nsvc->nsei,
			     nsvc->nsvci);
			return 0;
		}
		switch (signal) {
		case S_NS_RESET:
		case S_NS_BLOCK:
			if (!peer->blocked)
				break;
			LOGP(DGPRS, LOGL_NOTICE, "Converting NS_RESET from "
			     "NSEI=%u/NSVCI=%u into BSSGP_BVC_BLOCK to SGSN\n",
			     nsvc->nsei, nsvc->nsvci);
			bssgp_tx_simple_bvci(BSSGP_PDUT_BVC_BLOCK, nsvc->nsei,
					     peer->bvci, 0);
			break;
		}
	} else {
		/* Forward this message to all NS-VC to BSS */
		struct gprs_ns_inst *nsi = gbcfg.nsi;
		struct gprs_nsvc *next_nsvc;

		llist_for_each_entry(next_nsvc, &nsi->gprs_nsvcs, list) {
			if (next_nsvc->remote_end_is_sgsn)
				continue;

			/* Note that the following does not start the full
			 * procedures including timer based retransmissions. */
			switch (signal) {
			case S_NS_RESET:
				gprs_ns_tx_reset(next_nsvc, nssd->cause);
				break;
			case S_NS_BLOCK:
				gprs_ns_tx_block(next_nsvc, nssd->cause);
				break;
			case S_NS_UNBLOCK:
				gprs_ns_tx_unblock(next_nsvc);
				break;
			}
		}
	}
	return 0;
}

int gbprox_dump_global(FILE *stream, int indent, int verbose)
{
	unsigned int i;
	const struct rate_ctr_group_desc *desc;
	int rc;

	rc = fprintf(stream, "%*sGbproxy global:\n", indent, "");
	if (rc < 0)
		return rc;

	if (!verbose)
		return 0;

	desc = get_global_ctrg()->desc;

	for (i = 0; i < desc->num_ctr; i++) {
		struct rate_ctr *ctr = &get_global_ctrg()->ctr[i];
		if (ctr->current) {
			rc = fprintf(stream, "%*s    %s: %llu\n",
				     indent, "",
				     desc->ctr_desc[i].description,
				     (long long)ctr->current);

			if (rc < 0)
				return rc;
		}
	}

	return 0;
}

int gbprox_dump_peers(FILE *stream, int indent, int verbose)
{
	struct gbprox_peer *peer;
	struct gprs_ra_id raid;
	unsigned int i;
	const struct rate_ctr_group_desc *desc;
	int rc;

	rc = fprintf(stream, "%*sPeers:\n", indent, "");
	if (rc < 0)
		return rc;

	llist_for_each_entry(peer, &gbprox_bts_peers, list) {
		gsm48_parse_ra(&raid, peer->ra);

		rc = fprintf(stream, "%*s  NSEI %u, BVCI %u, %sblocked, "
			     "RAI %u-%u-%u-%u\n",
			     indent, "",
			     peer->nsei, peer->bvci,
			     peer->blocked ? "" : "not ",
			     raid.mcc, raid.mnc, raid.lac, raid.rac);

		if (rc < 0)
			return rc;

		if (!verbose)
			continue;

		desc = peer->ctrg->desc;

		for (i = 0; i < desc->num_ctr; i++) {
			struct rate_ctr *ctr = &peer->ctrg->ctr[i];
			if (ctr->current) {
				rc = fprintf(stream, "%*s    %s: %llu\n",
					     indent, "",
					     desc->ctr_desc[i].description,
					     (long long)ctr->current);

				if (rc < 0)
					return rc;
			}
		}
	}

	return 0;
}

void gbprox_reset()
{
	struct gbprox_peer *peer, *tmp;

	llist_for_each_entry_safe(peer, tmp, &gbprox_bts_peers, list)
		peer_free(peer);

	rate_ctr_group_free(global_ctrg);
	global_ctrg = NULL;
}

static int gbprox_cleanup_peers(uint16_t nsei, uint16_t bvci)
{
	int counter = 0;
	struct gbprox_peer *peer, *tmp;

	llist_for_each_entry_safe(peer, tmp, &gbprox_bts_peers, list) {
		if (peer->nsei != nsei)
			continue;
		if (bvci && peer->bvci != bvci)
			continue;

		peer_free(peer);
		counter += 1;
	}

	return counter;
}

#include <osmocom/vty/command.h>

static void gbprox_vty_print_peer(struct vty *vty, struct gbprox_peer *peer)
{
	struct gprs_ra_id raid;
	gsm48_parse_ra(&raid, peer->ra);

	vty_out(vty, "NSEI %5u, PTP-BVCI %5u, "
		"RAI %u-%u-%u-%u",
		peer->nsei, peer->bvci,
		raid.mcc, raid.mnc, raid.lac, raid.rac);
	if (peer->blocked)
		vty_out(vty, " [BVC-BLOCKED]");

	vty_out(vty, "%s", VTY_NEWLINE);
}

gDEFUN(show_gbproxy, show_gbproxy_cmd, "show gbproxy [stats]",
       SHOW_STR "Display information about the Gb proxy\n" "Show statistics\n")
{
	struct gbprox_peer *peer;
	int show_stats = argc >= 1;

	if (show_stats)
		vty_out_rate_ctr_group(vty, "", get_global_ctrg());

	llist_for_each_entry(peer, &gbprox_bts_peers, list) {
		gbprox_vty_print_peer(vty, peer);

		if (show_stats)
			vty_out_rate_ctr_group(vty, "  ", peer->ctrg);
	}
	return CMD_SUCCESS;
}

gDEFUN(delete_gb_bvci, delete_gb_bvci_cmd,
	"delete-gbproxy-peer <0-65534> bvci <2-65534>",
	"Delete a GBProxy peer by NSEI and optionally BVCI\n"
	"NSEI number\n"
	"Only delete peer with a matching BVCI\n"
	"BVCI number\n")
{
	const uint16_t nsei = atoi(argv[0]);
	const uint16_t bvci = atoi(argv[1]);
	int counter;

	counter = gbprox_cleanup_peers(nsei, bvci);

	if (counter == 0) {
		vty_out(vty, "BVC not found%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	return CMD_SUCCESS;
}

gDEFUN(delete_gb_nsei, delete_gb_nsei_cmd,
	"delete-gbproxy-peer <0-65534> (only-bvc|only-nsvc|all) [dry-run]",
	"Delete a GBProxy peer by NSEI and optionally BVCI\n"
	"NSEI number\n"
	"Only delete BSSGP connections (BVC)\n"
	"Only delete dynamic NS connections (NS-VC)\n"
	"Delete BVC and dynamic NS connections\n"
	"Show what would be deleted instead of actually deleting\n"
	)
{
	const uint16_t nsei = atoi(argv[0]);
	const char *mode = argv[1];
	int dry_run = argc > 2;
	int delete_bvc = 0;
	int delete_nsvc = 0;
	int counter;

	if (strcmp(mode, "only-bvc") == 0)
		delete_bvc = 1;
	else if (strcmp(mode, "only-nsvc") == 0)
		delete_nsvc = 1;
	else
		delete_bvc = delete_nsvc = 1;

	if (delete_bvc) {
		if (!dry_run)
			counter = gbprox_cleanup_peers(nsei, 0);
		else {
			struct gbprox_peer *peer;
			counter = 0;
			llist_for_each_entry(peer, &gbprox_bts_peers, list) {
				if (peer->nsei != nsei)
					continue;

				vty_out(vty, "BVC: ");
				gbprox_vty_print_peer(vty, peer);
				counter += 1;
			}
		}
		vty_out(vty, "%sDeleted %d BVC%s",
			dry_run ? "Not " : "", counter, VTY_NEWLINE);
	}

	if (delete_nsvc) {
		struct gprs_ns_inst *nsi = gbcfg.nsi;
		struct gprs_nsvc *nsvc, *nsvc2;

		counter = 0;
		llist_for_each_entry_safe(nsvc, nsvc2, &nsi->gprs_nsvcs, list) {
			if (nsvc->nsei != nsei)
				continue;
			if (nsvc->persistent)
				continue;

			if (!dry_run)
				gprs_nsvc_delete(nsvc);
			else
				vty_out(vty, "NS-VC: NSEI %5u, NS-VCI %5u, "
					"remote %s%s",
					nsvc->nsei, nsvc->nsvci,
					gprs_ns_ll_str(nsvc), VTY_NEWLINE);
			counter += 1;
		}
		vty_out(vty, "%sDeleted %d NS-VC%s",
			dry_run ? "Not " : "", counter, VTY_NEWLINE);
	}

	return CMD_SUCCESS;
}
