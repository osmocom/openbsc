/*
 * (C) 2010 by Harald Welte <laforge@gnumonks.org>
 * (C) 2010 by On-Waves
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

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <time.h>

#include <osmocom/core/talloc.h>
#include <osmocom/core/rate_ctr.h>

#include <openbsc/gsm_04_08.h>
#include <osmocom/gprs/gprs_ns.h>

#include <openbsc/debug.h>
#include <openbsc/gb_proxy.h>
#include <openbsc/gprs_utils.h>
#include <openbsc/vty.h>

#include <osmocom/vty/command.h>
#include <osmocom/vty/vty.h>
#include <osmocom/vty/misc.h>

static struct gbproxy_config *g_cfg = NULL;

/*
 * vty code for mgcp below
 */
static struct cmd_node gbproxy_node = {
	GBPROXY_NODE,
	"%s(config-gbproxy)# ",
	1,
};

static const struct value_string keep_modes[] = {
	{GBPROX_KEEP_NEVER, "never"},
	{GBPROX_KEEP_REATTACH, "re-attach"},
	{GBPROX_KEEP_IDENTIFIED, "identified"},
	{GBPROX_KEEP_ALWAYS, "always"},
	{0, NULL}
};

static const struct value_string match_ids[] = {
	{GBPROX_MATCH_PATCHING, "patching"},
	{GBPROX_MATCH_ROUTING, "routing"},
	{0, NULL}
};

static void gbprox_vty_print_peer(struct vty *vty, struct gbproxy_peer *peer)
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

static int config_write_gbproxy(struct vty *vty)
{
	enum gbproxy_match_id match_id;

	vty_out(vty, "gbproxy%s", VTY_NEWLINE);

	vty_out(vty, " sgsn nsei %u%s", g_cfg->nsip_sgsn_nsei,
		VTY_NEWLINE);

	if (g_cfg->core_mcc > 0)
		vty_out(vty, " core-mobile-country-code %d%s",
			g_cfg->core_mcc, VTY_NEWLINE);
	if (g_cfg->core_mnc > 0)
		vty_out(vty, " core-mobile-network-code %d%s",
			g_cfg->core_mnc, VTY_NEWLINE);

	for (match_id = 0; match_id < ARRAY_SIZE(g_cfg->matches); ++match_id) {
		struct gbproxy_match *match = &g_cfg->matches[match_id];
		if (match->re_str)
			vty_out(vty, " match-imsi %s %s%s",
				get_value_string(match_ids, match_id),
				match->re_str, VTY_NEWLINE);
	}

	if (g_cfg->core_apn != NULL) {
	       if (g_cfg->core_apn_size > 0) {
		       char str[500] = {0};
		       vty_out(vty, " core-access-point-name %s%s",
			       gprs_apn_to_str(str, g_cfg->core_apn,
						 g_cfg->core_apn_size),
			       VTY_NEWLINE);
	       } else {
		       vty_out(vty, " core-access-point-name none%s",
			       VTY_NEWLINE);
	       }
	}

	if (g_cfg->route_to_sgsn2)
		vty_out(vty, " secondary-sgsn nsei %u%s", g_cfg->nsip_sgsn2_nsei,
			VTY_NEWLINE);

	if (g_cfg->tlli_max_age > 0)
		vty_out(vty, " link-list max-age %d%s",
			g_cfg->tlli_max_age, VTY_NEWLINE);
	if (g_cfg->tlli_max_len > 0)
		vty_out(vty, " link-list max-length %d%s",
			g_cfg->tlli_max_len, VTY_NEWLINE);
	vty_out(vty, " link-list keep-mode %s%s",
		get_value_string(keep_modes, g_cfg->keep_link_infos),
		VTY_NEWLINE);


	return CMD_SUCCESS;
}

DEFUN(cfg_gbproxy,
      cfg_gbproxy_cmd,
      "gbproxy",
      "Configure the Gb proxy")
{
	vty->node = GBPROXY_NODE;
	return CMD_SUCCESS;
}

DEFUN(cfg_nsip_sgsn_nsei,
      cfg_nsip_sgsn_nsei_cmd,
      "sgsn nsei <0-65534>",
      "SGSN information\n"
      "NSEI to be used in the connection with the SGSN\n"
      "The NSEI\n")
{
	unsigned int nsei = atoi(argv[0]);

	if (g_cfg->route_to_sgsn2 && g_cfg->nsip_sgsn2_nsei == nsei) {
		vty_out(vty, "SGSN NSEI %d conflicts with secondary SGSN NSEI%s",
			nsei, VTY_NEWLINE);
		return CMD_WARNING;
	}

	g_cfg->nsip_sgsn_nsei = nsei;
	return CMD_SUCCESS;
}

#define GBPROXY_CORE_MNC_STR "Use this network code for the core network\n"

DEFUN(cfg_gbproxy_core_mnc,
      cfg_gbproxy_core_mnc_cmd,
      "core-mobile-network-code <1-999>",
      GBPROXY_CORE_MNC_STR "NCC value\n")
{
	g_cfg->core_mnc = atoi(argv[0]);
	return CMD_SUCCESS;
}

DEFUN(cfg_gbproxy_no_core_mnc,
      cfg_gbproxy_no_core_mnc_cmd,
      "no core-mobile-network-code",
      NO_STR GBPROXY_CORE_MNC_STR)
{
	g_cfg->core_mnc = 0;
	return CMD_SUCCESS;
}

#define GBPROXY_CORE_MCC_STR "Use this country code for the core network\n"

DEFUN(cfg_gbproxy_core_mcc,
      cfg_gbproxy_core_mcc_cmd,
      "core-mobile-country-code <1-999>",
      GBPROXY_CORE_MCC_STR "MCC value\n")
{
	g_cfg->core_mcc = atoi(argv[0]);
	return CMD_SUCCESS;
}

DEFUN(cfg_gbproxy_no_core_mcc,
      cfg_gbproxy_no_core_mcc_cmd,
      "no core-mobile-country-code",
      NO_STR GBPROXY_CORE_MCC_STR)
{
	g_cfg->core_mcc = 0;
	return CMD_SUCCESS;
}

#define GBPROXY_MATCH_IMSI_STR "Restrict actions to certain IMSIs\n"

DEFUN(cfg_gbproxy_match_imsi,
      cfg_gbproxy_match_imsi_cmd,
      "match-imsi (patching|routing) .REGEXP",
      GBPROXY_MATCH_IMSI_STR
      "Patch MS related information elements on match only\n"
      "Route to the secondary SGSN on match only\n"
      "Regular expression for the IMSI match\n")
{
	const char *filter = argv[1];
	const char *err_msg = NULL;
	struct gbproxy_match *match;
	enum gbproxy_match_id match_id = get_string_value(match_ids, argv[0]);

	OSMO_ASSERT(match_id >= GBPROX_MATCH_PATCHING &&
		    match_id < GBPROX_MATCH_LAST);
	match = &g_cfg->matches[match_id];

	if (gbproxy_set_patch_filter(match, filter, &err_msg) != 0) {
		vty_out(vty, "Match expression invalid: %s%s",
			err_msg, VTY_NEWLINE);
		return CMD_WARNING;
	}

	g_cfg->acquire_imsi = 1;

	return CMD_SUCCESS;
}

DEFUN(cfg_gbproxy_no_match_imsi,
      cfg_gbproxy_no_match_imsi_cmd,
      "no match-imsi",
      NO_STR GBPROXY_MATCH_IMSI_STR)
{
	enum gbproxy_match_id match_id;

	for (match_id = 0; match_id < ARRAY_SIZE(g_cfg->matches); ++match_id)
		gbproxy_clear_patch_filter(&g_cfg->matches[match_id]);

	g_cfg->acquire_imsi = 0;

	return CMD_SUCCESS;
}

#define GBPROXY_CORE_APN_STR "Use this access point name (APN) for the backbone\n"
#define GBPROXY_CORE_APN_ARG_STR "Replace APN by this string\n" "Remove APN\n"

static int set_core_apn(struct vty *vty, const char *apn)
{
	int apn_len;

	if (!apn) {
		talloc_free(g_cfg->core_apn);
		g_cfg->core_apn = NULL;
		g_cfg->core_apn_size = 0;
		return CMD_SUCCESS;
	}

	apn_len = strlen(apn);

	if (apn_len >= 100) {
		vty_out(vty, "APN string too long (max 99 chars)%s",
			VTY_NEWLINE);
		return CMD_WARNING;
	}

	if (apn_len == 0) {
		talloc_free(g_cfg->core_apn);
		/* TODO: replace NULL */
		g_cfg->core_apn = talloc_zero_size(NULL, 2);
		g_cfg->core_apn_size = 0;
	} else {
		/* TODO: replace NULL */
		g_cfg->core_apn =
			talloc_realloc_size(NULL, g_cfg->core_apn, apn_len + 1);
		g_cfg->core_apn_size =
			gprs_str_to_apn(g_cfg->core_apn, apn_len + 1, apn);
	}

	return CMD_SUCCESS;
}

DEFUN(cfg_gbproxy_core_apn,
      cfg_gbproxy_core_apn_cmd,
      "core-access-point-name (APN|none)",
      GBPROXY_CORE_APN_STR GBPROXY_CORE_APN_ARG_STR)
{
	if (strcmp(argv[0], "none") == 0)
		return set_core_apn(vty, "");
	else
		return set_core_apn(vty, argv[0]);
}

DEFUN(cfg_gbproxy_no_core_apn,
      cfg_gbproxy_no_core_apn_cmd,
      "no core-access-point-name",
      NO_STR GBPROXY_CORE_APN_STR)
{
	return set_core_apn(vty, NULL);
}

/* TODO: Remove the patch-ptmsi command, since P-TMSI patching is enabled
 * automatically when needed. This command is only left for manual testing
 * (e.g. doing P-TMSI patching without using a secondary SGSN)
 */
#define GBPROXY_PATCH_PTMSI_STR "Patch P-TMSI/TLLI\n"

DEFUN(cfg_gbproxy_patch_ptmsi,
      cfg_gbproxy_patch_ptmsi_cmd,
      "patch-ptmsi",
      GBPROXY_PATCH_PTMSI_STR)
{
	g_cfg->patch_ptmsi = 1;

	return CMD_SUCCESS;
}

DEFUN(cfg_gbproxy_no_patch_ptmsi,
      cfg_gbproxy_no_patch_ptmsi_cmd,
      "no patch-ptmsi",
      NO_STR GBPROXY_PATCH_PTMSI_STR)
{
	g_cfg->patch_ptmsi = 0;

	return CMD_SUCCESS;
}

/* TODO: Remove the acquire-imsi command, since that feature is enabled
 * automatically when IMSI matching is enabled. This command is only left for
 * manual testing (e.g. doing IMSI acquisition without IMSI based patching)
 */
#define GBPROXY_ACQUIRE_IMSI_STR "Acquire the IMSI before establishing a LLC connection (Experimental)\n"

DEFUN(cfg_gbproxy_acquire_imsi,
      cfg_gbproxy_acquire_imsi_cmd,
      "acquire-imsi",
      GBPROXY_ACQUIRE_IMSI_STR)
{
	g_cfg->acquire_imsi = 1;

	return CMD_SUCCESS;
}

DEFUN(cfg_gbproxy_no_acquire_imsi,
      cfg_gbproxy_no_acquire_imsi_cmd,
      "no acquire-imsi",
      NO_STR GBPROXY_ACQUIRE_IMSI_STR)
{
	g_cfg->acquire_imsi = 0;

	return CMD_SUCCESS;
}

#define GBPROXY_SECOND_SGSN_STR "Route matching LLC connections to a second SGSN (Experimental)\n"

DEFUN(cfg_gbproxy_secondary_sgsn,
      cfg_gbproxy_secondary_sgsn_cmd,
      "secondary-sgsn nsei <0-65534>",
      GBPROXY_SECOND_SGSN_STR
      "NSEI to be used in the connection with the SGSN\n"
      "The NSEI\n")
{
	unsigned int nsei = atoi(argv[0]);

	if (g_cfg->nsip_sgsn_nsei == nsei) {
		vty_out(vty, "Secondary SGSN NSEI %d conflicts with primary SGSN NSEI%s",
			nsei, VTY_NEWLINE);
		return CMD_WARNING;
	}

	g_cfg->route_to_sgsn2 = 1;
	g_cfg->nsip_sgsn2_nsei = nsei;

	g_cfg->patch_ptmsi = 1;

	return CMD_SUCCESS;
}

DEFUN(cfg_gbproxy_no_secondary_sgsn,
      cfg_gbproxy_no_secondary_sgsn_cmd,
      "no secondary-sgsn",
      NO_STR GBPROXY_SECOND_SGSN_STR)
{
	g_cfg->route_to_sgsn2 = 0;
	g_cfg->nsip_sgsn2_nsei = 0xFFFF;

	g_cfg->patch_ptmsi = 0;

	return CMD_SUCCESS;
}

#define GBPROXY_LINK_LIST_STR "Set TLLI list parameters\n"
#define GBPROXY_MAX_AGE_STR "Limit maximum age\n"

DEFUN(cfg_gbproxy_link_list_max_age,
      cfg_gbproxy_link_list_max_age_cmd,
      "link-list max-age <1-999999>",
      GBPROXY_LINK_LIST_STR GBPROXY_MAX_AGE_STR
      "Maximum age in seconds\n")
{
	g_cfg->tlli_max_age = atoi(argv[0]);

	return CMD_SUCCESS;
}

DEFUN(cfg_gbproxy_link_list_no_max_age,
      cfg_gbproxy_link_list_no_max_age_cmd,
      "no link-list max-age",
      NO_STR GBPROXY_LINK_LIST_STR GBPROXY_MAX_AGE_STR)
{
	g_cfg->tlli_max_age = 0;

	return CMD_SUCCESS;
}

#define GBPROXY_MAX_LEN_STR "Limit list length\n"

DEFUN(cfg_gbproxy_link_list_max_len,
      cfg_gbproxy_link_list_max_len_cmd,
      "link-list max-length <1-99999>",
      GBPROXY_LINK_LIST_STR GBPROXY_MAX_LEN_STR
      "Maximum number of logical links in the list\n")
{
	g_cfg->tlli_max_len = atoi(argv[0]);

	return CMD_SUCCESS;
}

DEFUN(cfg_gbproxy_link_list_no_max_len,
      cfg_gbproxy_link_list_no_max_len_cmd,
      "no link-list max-length",
      NO_STR GBPROXY_LINK_LIST_STR GBPROXY_MAX_LEN_STR)
{
	g_cfg->tlli_max_len = 0;

	return CMD_SUCCESS;
}

DEFUN(cfg_gbproxy_link_list_keep_mode,
      cfg_gbproxy_link_list_keep_mode_cmd,
      "link-list keep-mode (never|re-attach|identified|always)",
      GBPROXY_LINK_LIST_STR "How to keep entries for detached logical links\n"
      "Discard entry immediately after detachment\n"
      "Keep entry if a re-attachment has be requested\n"
      "Keep entry if it associated with an IMSI\n"
      "Don't discard entries after detachment\n")
{
	int val = get_string_value(keep_modes, argv[0]);
	OSMO_ASSERT(val >= GBPROX_KEEP_NEVER && val <= GBPROX_KEEP_ALWAYS);
	g_cfg->keep_link_infos = val;

	return CMD_SUCCESS;
}


DEFUN(show_gbproxy, show_gbproxy_cmd, "show gbproxy [stats]",
       SHOW_STR "Display information about the Gb proxy\n" "Show statistics\n")
{
	struct gbproxy_peer *peer;
	int show_stats = argc >= 1;

	if (show_stats)
		vty_out_rate_ctr_group(vty, "", g_cfg->ctrg);

	llist_for_each_entry(peer, &g_cfg->bts_peers, list) {
		gbprox_vty_print_peer(vty, peer);

		if (show_stats)
			vty_out_rate_ctr_group(vty, "  ", peer->ctrg);
	}
	return CMD_SUCCESS;
}

DEFUN(show_gbproxy_links, show_gbproxy_links_cmd, "show gbproxy links",
       SHOW_STR "Display information about the Gb proxy\n" "Show logical links\n")
{
	struct gbproxy_peer *peer;
	char mi_buf[200];
	time_t now;
	struct timespec ts = {0,};

	clock_gettime(CLOCK_MONOTONIC, &ts);
	now = ts.tv_sec;

	llist_for_each_entry(peer, &g_cfg->bts_peers, list) {
		struct gbproxy_link_info *link_info;
		struct gbproxy_patch_state *state = &peer->patch_state;

		gbprox_vty_print_peer(vty, peer);

		llist_for_each_entry(link_info, &state->logical_links, list) {
			time_t age = now - link_info->timestamp;
			int stored_msgs = 0;
			struct llist_head *iter;
			llist_for_each(iter, &link_info->stored_msgs)
				stored_msgs++;

			if (link_info->imsi > 0) {
				snprintf(mi_buf, sizeof(mi_buf), "(invalid)");
				gsm48_mi_to_string(mi_buf, sizeof(mi_buf),
						   link_info->imsi,
						   link_info->imsi_len);
			} else {
				snprintf(mi_buf, sizeof(mi_buf), "(none)");
			}
			vty_out(vty, "  TLLI %08x, IMSI %s, AGE %d",
				link_info->tlli.current, mi_buf, (int)age);

			if (stored_msgs)
				vty_out(vty, ", STORED %d", stored_msgs);

			if (g_cfg->route_to_sgsn2)
				vty_out(vty, ", SGSN NSEI %d",
					link_info->sgsn_nsei);

			if (link_info->is_deregistered)
				vty_out(vty, ", DE-REGISTERED");

			vty_out(vty, "%s", VTY_NEWLINE);
		}
	}
	return CMD_SUCCESS;
}

DEFUN(delete_gb_bvci, delete_gb_bvci_cmd,
	"delete-gbproxy-peer <0-65534> bvci <2-65534>",
	"Delete a GBProxy peer by NSEI and optionally BVCI\n"
	"NSEI number\n"
	"Only delete peer with a matching BVCI\n"
	"BVCI number\n")
{
	const uint16_t nsei = atoi(argv[0]);
	const uint16_t bvci = atoi(argv[1]);
	int counter;

	counter = gbproxy_cleanup_peers(g_cfg, nsei, bvci);

	if (counter == 0) {
		vty_out(vty, "BVC not found%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	return CMD_SUCCESS;
}

DEFUN(delete_gb_nsei, delete_gb_nsei_cmd,
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
			counter = gbproxy_cleanup_peers(g_cfg, nsei, 0);
		else {
			struct gbproxy_peer *peer;
			counter = 0;
			llist_for_each_entry(peer, &g_cfg->bts_peers, list) {
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
		struct gprs_ns_inst *nsi = g_cfg->nsi;
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

#define GBPROXY_DELETE_LINK_STR \
	"Delete a GBProxy logical link entry by NSEI and identification\nNSEI number\n"

DEFUN(delete_gb_link_by_id, delete_gb_link_by_id_cmd,
	"delete-gbproxy-link <0-65534> (tlli|imsi|sgsn-nsei) IDENT",
	GBPROXY_DELETE_LINK_STR
	"Delete entries with a matching TLLI (hex)\n"
	"Delete entries with a matching IMSI\n"
	"Delete entries with a matching SGSN NSEI\n"
	"Identification to match\n")
{
	const uint16_t nsei = atoi(argv[0]);
	enum {MATCH_TLLI = 't', MATCH_IMSI = 'i', MATCH_SGSN = 's'} match;
	uint32_t ident = 0;
	const char *imsi = NULL;
	struct gbproxy_peer *peer = 0;
	struct gbproxy_link_info *link_info, *nxt;
	struct gbproxy_patch_state *state;
	char mi_buf[200];
	int found = 0;

	match = argv[1][0];

	switch (match) {
	case MATCH_TLLI: ident = strtoll(argv[2], NULL, 16); break;
	case MATCH_IMSI: imsi = argv[2]; break;
	case MATCH_SGSN: ident = strtoll(argv[2], NULL, 0); break;
	};

	peer = gbproxy_peer_by_nsei(g_cfg, nsei);
	if (!peer) {
		vty_out(vty, "Didn't find peer with NSEI %d%s",
			nsei, VTY_NEWLINE);
		return CMD_WARNING;
	}

	state = &peer->patch_state;

	llist_for_each_entry_safe(link_info, nxt, &state->logical_links, list) {
		switch (match) {
		case MATCH_TLLI:
			if (link_info->tlli.current != ident)
				continue;
			break;
		case MATCH_SGSN:
			if (link_info->sgsn_nsei != ident)
				continue;
			break;
		case MATCH_IMSI:
			if (!link_info->imsi)
				continue;
			mi_buf[0] = '\0';
			gsm48_mi_to_string(mi_buf, sizeof(mi_buf),
					   link_info->imsi,
					   link_info->imsi_len);

			if (strcmp(mi_buf, imsi) != 0)
				continue;
			break;
		}

		vty_out(vty, "Deleting link with TLLI %08x%s", link_info->tlli.current,
			VTY_NEWLINE);
		gbproxy_delete_link_info(peer, link_info);
		found += 1;
	}

	if (!found && argc >= 2) {
		vty_out(vty, "Didn't find link entry with %s %s%s",
			argv[1], argv[2], VTY_NEWLINE);
	}

	return CMD_SUCCESS;
}

DEFUN(delete_gb_link, delete_gb_link_cmd,
	"delete-gbproxy-link <0-65534> (stale|de-registered)",
	GBPROXY_DELETE_LINK_STR
	"Delete stale entries\n"
	"Delete de-registered entries\n")
{
	const uint16_t nsei = atoi(argv[0]);
	enum {MATCH_STALE = 's', MATCH_DEREGISTERED = 'd'} match;
	struct gbproxy_peer *peer = 0;
	struct gbproxy_link_info *link_info, *nxt;
	struct gbproxy_patch_state *state;
	time_t now;
	struct timespec ts = {0,};

	int found = 0;

	match = argv[1][0];

	peer = gbproxy_peer_by_nsei(g_cfg, nsei);
	if (!peer) {
		vty_out(vty, "Didn't find peer with NSEI %d%s",
			nsei, VTY_NEWLINE);
		return CMD_WARNING;
	}

	state = &peer->patch_state;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	now = ts.tv_sec;

	if (match == MATCH_STALE) {
		found = gbproxy_remove_stale_link_infos(peer, now);
		if (found)
			vty_out(vty, "Deleted %d stale logical link%s%s",
				found, found == 1 ? "" : "s", VTY_NEWLINE);
	} else {
		llist_for_each_entry_safe(link_info, nxt,
					  &state->logical_links, list) {
			if (!link_info->is_deregistered)
				continue;

			gbproxy_delete_link_info(peer, link_info);
			found += 1;
		}
	}

	if (found)
		vty_out(vty, "Deleted %d %s logical link%s%s",
			found, argv[1], found == 1 ? "" : "s", VTY_NEWLINE);

	return CMD_SUCCESS;
}

/*
 * legacy commands to provide an upgrade path from "broken" releases
 * or pre-releases
 */
DEFUN_DEPRECATED(cfg_gbproxy_broken_apn_match,
      cfg_gbproxy_broken_apn_match_cmd,
      "core-access-point-name none match-imsi .REGEXP",
      GBPROXY_CORE_APN_STR GBPROXY_MATCH_IMSI_STR "Remove APN\n"
      "Patch MS related information elements on match only\n"
      "Route to the secondary SGSN on match only\n"
      "Regular expression for the IMSI match\n")
{
	const char *filter = argv[0];
	const char *err_msg = NULL;
	struct gbproxy_match *match;
	enum gbproxy_match_id match_id = get_string_value(match_ids, "patching");

	/* apply APN none */
	set_core_apn(vty, "");

	/* do the matching... with copy and paste */
	OSMO_ASSERT(match_id >= GBPROX_MATCH_PATCHING &&
		    match_id < GBPROX_MATCH_LAST);
	match = &g_cfg->matches[match_id];

	if (gbproxy_set_patch_filter(match, filter, &err_msg) != 0) {
		vty_out(vty, "Match expression invalid: %s%s",
			err_msg, VTY_NEWLINE);
		return CMD_WARNING;
	}

	g_cfg->acquire_imsi = 1;

	return CMD_SUCCESS;
}

#define GBPROXY_TLLI_LIST_STR "Set TLLI list parameters\n"
#define GBPROXY_MAX_LEN_STR "Limit list length\n"
DEFUN_DEPRECATED(cfg_gbproxy_depr_tlli_list_max_len,
      cfg_gbproxy_depr_tlli_list_max_len_cmd,
      "tlli-list max-length <1-99999>",
      GBPROXY_TLLI_LIST_STR GBPROXY_MAX_LEN_STR
      "Maximum number of TLLIs in the list\n")
{
	g_cfg->tlli_max_len = atoi(argv[0]);

	return CMD_SUCCESS;
}

int gbproxy_vty_init(void)
{
	install_element_ve(&show_gbproxy_cmd);
	install_element_ve(&show_gbproxy_links_cmd);

	install_element(ENABLE_NODE, &delete_gb_bvci_cmd);
	install_element(ENABLE_NODE, &delete_gb_nsei_cmd);
	install_element(ENABLE_NODE, &delete_gb_link_by_id_cmd);
	install_element(ENABLE_NODE, &delete_gb_link_cmd);

	install_element(CONFIG_NODE, &cfg_gbproxy_cmd);
	install_node(&gbproxy_node, config_write_gbproxy);
	vty_install_default(GBPROXY_NODE);
	install_element(GBPROXY_NODE, &cfg_nsip_sgsn_nsei_cmd);
	install_element(GBPROXY_NODE, &cfg_gbproxy_core_mcc_cmd);
	install_element(GBPROXY_NODE, &cfg_gbproxy_core_mnc_cmd);
	install_element(GBPROXY_NODE, &cfg_gbproxy_match_imsi_cmd);
	install_element(GBPROXY_NODE, &cfg_gbproxy_core_apn_cmd);
	install_element(GBPROXY_NODE, &cfg_gbproxy_secondary_sgsn_cmd);
	install_element(GBPROXY_NODE, &cfg_gbproxy_patch_ptmsi_cmd);
	install_element(GBPROXY_NODE, &cfg_gbproxy_acquire_imsi_cmd);
	install_element(GBPROXY_NODE, &cfg_gbproxy_link_list_max_age_cmd);
	install_element(GBPROXY_NODE, &cfg_gbproxy_link_list_max_len_cmd);
	install_element(GBPROXY_NODE, &cfg_gbproxy_link_list_keep_mode_cmd);
	install_element(GBPROXY_NODE, &cfg_gbproxy_no_core_mcc_cmd);
	install_element(GBPROXY_NODE, &cfg_gbproxy_no_core_mnc_cmd);
	install_element(GBPROXY_NODE, &cfg_gbproxy_no_match_imsi_cmd);
	install_element(GBPROXY_NODE, &cfg_gbproxy_no_core_apn_cmd);
	install_element(GBPROXY_NODE, &cfg_gbproxy_no_secondary_sgsn_cmd);
	install_element(GBPROXY_NODE, &cfg_gbproxy_no_patch_ptmsi_cmd);
	install_element(GBPROXY_NODE, &cfg_gbproxy_no_acquire_imsi_cmd);
	install_element(GBPROXY_NODE, &cfg_gbproxy_link_list_no_max_age_cmd);
	install_element(GBPROXY_NODE, &cfg_gbproxy_link_list_no_max_len_cmd);

	/* broken or deprecated to allow an upgrade path */
	install_element(GBPROXY_NODE, &cfg_gbproxy_broken_apn_match_cmd);
	install_element(GBPROXY_NODE, &cfg_gbproxy_depr_tlli_list_max_len_cmd);

	return 0;
}

int gbproxy_parse_config(const char *config_file, struct gbproxy_config *cfg)
{
	int rc;

	g_cfg = cfg;
	rc = vty_read_config_file(config_file, NULL);
	if (rc < 0) {
		fprintf(stderr, "Failed to parse the config file: '%s'\n", config_file);
		return rc;
	}

	return 0;
}

