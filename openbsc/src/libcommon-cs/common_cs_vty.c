/* Code used by both libbsc and libmsc (common_cs means "BSC or MSC").
 *
 * (C) 2016 by sysmocom s.m.f.c. <info@sysmocom.de>
 * (C) 2008-2010 by Harald Welte <laforge@gnumonks.org>
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

#include <osmocom/core/utils.h>

#include <osmocom/vty/command.h>
#include <osmocom/vty/logging.h>
#include <osmocom/vty/stats.h>

#include <openbsc/vty.h>

#include <openbsc/gsm_data.h>
#include <openbsc/gsm_subscriber.h>

struct cmd_node net_node = {
	GSMNET_NODE,
	"%s(config-net)# ",
	1,
};

#define NETWORK_STR "Configure the GSM network\n"
#define CODE_CMD_STR "Code commands\n"
#define NAME_CMD_STR "Name Commands\n"
#define NAME_STR "Name to use\n"

DEFUN(cfg_net,
      cfg_net_cmd,
      "network", NETWORK_STR)
{
	vty->index = gsmnet_from_vty(vty);
	vty->node = GSMNET_NODE;

	return CMD_SUCCESS;
}

DEFUN(cfg_net_ncc,
      cfg_net_ncc_cmd,
      "network country code <1-999>",
      "Set the GSM network country code\n"
      "Country commands\n"
      CODE_CMD_STR
      "Network Country Code to use\n")
{
	struct gsm_network *gsmnet = gsmnet_from_vty(vty);

	gsmnet->country_code = atoi(argv[0]);

	return CMD_SUCCESS;
}

DEFUN(cfg_net_mnc,
      cfg_net_mnc_cmd,
      "mobile network code <0-999>",
      "Set the GSM mobile network code\n"
      "Network Commands\n"
      CODE_CMD_STR
      "Mobile Network Code to use\n")
{
	struct gsm_network *gsmnet = gsmnet_from_vty(vty);

	gsmnet->network_code = atoi(argv[0]);

	return CMD_SUCCESS;
}

DEFUN(cfg_net_name_short,
      cfg_net_name_short_cmd,
      "short name NAME",
      "Set the short GSM network name\n" NAME_CMD_STR NAME_STR)
{
	struct gsm_network *gsmnet = gsmnet_from_vty(vty);

	osmo_talloc_replace_string(gsmnet, &gsmnet->name_short, argv[0]);
	return CMD_SUCCESS;
}

DEFUN(cfg_net_name_long,
      cfg_net_name_long_cmd,
      "long name NAME",
      "Set the long GSM network name\n" NAME_CMD_STR NAME_STR)
{
	struct gsm_network *gsmnet = gsmnet_from_vty(vty);

	osmo_talloc_replace_string(gsmnet, &gsmnet->name_long, argv[0]);
	return CMD_SUCCESS;
}

DEFUN(cfg_net_auth_policy,
      cfg_net_auth_policy_cmd,
      "auth policy (closed|accept-all|regexp|token)",
	"Authentication (not cryptographic)\n"
	"Set the GSM network authentication policy\n"
	"Require the MS to be activated in HLR\n"
	"Accept all MS, whether in HLR or not\n"
	"Use regular expression for IMSI authorization decision\n"
	"Use SMS-token based authentication\n")
{
	enum gsm_auth_policy policy = gsm_auth_policy_parse(argv[0]);
	struct gsm_network *gsmnet = gsmnet_from_vty(vty);

	gsmnet->auth_policy = policy;

	return CMD_SUCCESS;
}

DEFUN(cfg_net_authorize_regexp, cfg_net_authorize_regexp_cmd,
      "authorized-regexp REGEXP",
      "Set regexp for IMSI which will be used for authorization decision\n"
      "Regular expression, IMSIs matching it are allowed to use the network\n")
{
	struct gsm_network *gsmnet = gsmnet_from_vty(vty);
	if (gsm_parse_reg(gsmnet, &gsmnet->authorized_regexp,
			  &gsmnet->authorized_reg_str, argc, argv) != 0) {
		vty_out(vty, "%%Failed to parse the authorized-regexp: '%s'%s",
			argv[0], VTY_NEWLINE);
		return CMD_WARNING;
	}

	return CMD_SUCCESS;
}

DEFUN(cfg_net_reject_cause,
      cfg_net_reject_cause_cmd,
      "location updating reject cause <2-111>",
      "Set the reject cause of location updating reject\n"
      "Set the reject cause of location updating reject\n"
      "Set the reject cause of location updating reject\n"
      "Set the reject cause of location updating reject\n"
      "Cause Value as Per GSM TS 04.08\n")
{
	struct gsm_network *gsmnet = gsmnet_from_vty(vty);

	gsmnet->reject_cause = atoi(argv[0]);

	return CMD_SUCCESS;
}

DEFUN(cfg_net_encryption,
      cfg_net_encryption_cmd,
      "encryption a5 (0|1|2|3)",
	"Encryption options\n"
	"A5 encryption\n" "A5/0: No encryption\n"
	"A5/1: Encryption\n" "A5/2: Export-grade Encryption\n"
	"A5/3: 'New' Secure Encryption\n")
{
	struct gsm_network *gsmnet = gsmnet_from_vty(vty);

	gsmnet->a5_encryption = atoi(argv[0]);

	return CMD_SUCCESS;
}

DEFUN(cfg_net_rrlp_mode, cfg_net_rrlp_mode_cmd,
      "rrlp mode (none|ms-based|ms-preferred|ass-preferred)",
	"Radio Resource Location Protocol\n"
	"Set the Radio Resource Location Protocol Mode\n"
	"Don't send RRLP request\n"
	"Request MS-based location\n"
	"Request any location, prefer MS-based\n"
	"Request any location, prefer MS-assisted\n")
{
	struct gsm_network *gsmnet = gsmnet_from_vty(vty);

	gsmnet->rrlp.mode = rrlp_mode_parse(argv[0]);

	return CMD_SUCCESS;
}

DEFUN(cfg_net_mm_info, cfg_net_mm_info_cmd,
      "mm info (0|1)",
	"Mobility Management\n"
	"Send MM INFO after LOC UPD ACCEPT\n"
	"Disable\n" "Enable\n")
{
	struct gsm_network *gsmnet = gsmnet_from_vty(vty);

	gsmnet->send_mm_info = atoi(argv[0]);

	return CMD_SUCCESS;
}

DEFUN(cfg_net_dyn_ts_allow_tch_f,
      cfg_net_dyn_ts_allow_tch_f_cmd,
      "dyn_ts_allow_tch_f (0|1)",
      "Allow or disallow allocating TCH/F on TCH_F_TCH_H_PDCH timeslots\n"
      "Disallow TCH/F on TCH_F_TCH_H_PDCH (default)\n"
      "Allow TCH/F on TCH_F_TCH_H_PDCH\n")
{
	struct gsm_network *gsmnet = gsmnet_from_vty(vty);
	gsmnet->dyn_ts_allow_tch_f = atoi(argv[0]) ? true : false;
	return CMD_SUCCESS;
}

DEFUN(cfg_net_subscr_keep,
      cfg_net_subscr_keep_cmd,
      "subscriber-keep-in-ram (0|1)",
      "Keep unused subscribers in RAM.\n"
      "Delete unused subscribers\n" "Keep unused subscribers\n")
{
	struct gsm_network *gsmnet = gsmnet_from_vty(vty);
	gsmnet->subscr_group->keep_subscr = atoi(argv[0]);
	return CMD_SUCCESS;
}

DEFUN(cfg_net_timezone,
      cfg_net_timezone_cmd,
      "timezone <-19-19> (0|15|30|45)",
      "Set the Timezone Offset of the network\n"
      "Timezone offset (hours)\n"
      "Timezone offset (00 minutes)\n"
      "Timezone offset (15 minutes)\n"
      "Timezone offset (30 minutes)\n"
      "Timezone offset (45 minutes)\n"
      )
{
	struct gsm_network *net = vty->index;
	int tzhr = atoi(argv[0]);
	int tzmn = atoi(argv[1]);

	net->tz.hr = tzhr;
	net->tz.mn = tzmn;
	net->tz.dst = 0;
	net->tz.override = 1;

	return CMD_SUCCESS;
}

DEFUN(cfg_net_timezone_dst,
      cfg_net_timezone_dst_cmd,
      "timezone <-19-19> (0|15|30|45) <0-2>",
      "Set the Timezone Offset of the network\n"
      "Timezone offset (hours)\n"
      "Timezone offset (00 minutes)\n"
      "Timezone offset (15 minutes)\n"
      "Timezone offset (30 minutes)\n"
      "Timezone offset (45 minutes)\n"
      "DST offset (hours)\n"
      )
{
	struct gsm_network *net = vty->index;
	int tzhr = atoi(argv[0]);
	int tzmn = atoi(argv[1]);
	int tzdst = atoi(argv[2]);

	net->tz.hr = tzhr;
	net->tz.mn = tzmn;
	net->tz.dst = tzdst;
	net->tz.override = 1;

	return CMD_SUCCESS;
}

DEFUN(cfg_net_no_timezone,
      cfg_net_no_timezone_cmd,
      "no timezone",
      NO_STR
      "Disable network timezone override, use system tz\n")
{
	struct gsm_network *net = vty->index;

	net->tz.override = 0;

	return CMD_SUCCESS;
}

static struct gsm_network *vty_global_gsm_network = NULL;

/* initialize VTY elements used in both BSC and MSC */
int common_cs_vty_init(struct gsm_network *network,
                 int (* config_write_net )(struct vty *))
{
	OSMO_ASSERT(vty_global_gsm_network == NULL);
	vty_global_gsm_network = network;

	install_element(CONFIG_NODE, &cfg_net_cmd);
	install_node(&net_node, config_write_net);
	vty_install_default(GSMNET_NODE);
	install_element(GSMNET_NODE, &cfg_net_ncc_cmd);
	install_element(GSMNET_NODE, &cfg_net_mnc_cmd);
	install_element(GSMNET_NODE, &cfg_net_name_short_cmd);
	install_element(GSMNET_NODE, &cfg_net_name_long_cmd);
	install_element(GSMNET_NODE, &cfg_net_auth_policy_cmd);
	install_element(GSMNET_NODE, &cfg_net_authorize_regexp_cmd);
	install_element(GSMNET_NODE, &cfg_net_reject_cause_cmd);
	install_element(GSMNET_NODE, &cfg_net_encryption_cmd);
	install_element(GSMNET_NODE, &cfg_net_rrlp_mode_cmd);
	install_element(GSMNET_NODE, &cfg_net_mm_info_cmd);
	install_element(GSMNET_NODE, &cfg_net_subscr_keep_cmd);
	install_element(GSMNET_NODE, &cfg_net_timezone_cmd);
	install_element(GSMNET_NODE, &cfg_net_timezone_dst_cmd);
	install_element(GSMNET_NODE, &cfg_net_no_timezone_cmd);
	install_element(GSMNET_NODE, &cfg_net_dyn_ts_allow_tch_f_cmd);

	return CMD_SUCCESS;
}

struct gsm_network *gsmnet_from_vty(struct vty *v)
{
	/* It can't hurt to force callers to continue to pass the vty instance
	 * to this function, in case we'd like to retrieve the global
	 * gsm_network instance from the vty at some point in the future. But
	 * until then, just return the global pointer, which should have been
	 * initialized by common_cs_vty_init().
	 */
	OSMO_ASSERT(vty_global_gsm_network);
	return vty_global_gsm_network;
}
