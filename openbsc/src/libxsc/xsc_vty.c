/* Code used by both libbsc and libmsc (xsc means "BSC or MSC").
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

/* FIXME parts of the gsm_network VTY commands are BSC specific and don't
 * belong here. */

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

struct gsm_network *vty_global_gsm_network = 0;

struct gsm_network *gsmnet_from_vty(struct vty *v)
{
	/* In case we read from the config file, the vty->priv cannot
	 * point to a struct telnet_connection, and thus conn->priv
	 * will not point to the gsm_network structure.
	 * It can't hurt to force callers to continue to pass the vty instance
	 * to this function, in case we'd like to retrieve the global
	 * gsm_network instance from the vty at some point in the future. But
	 * until then, just return the global pointer, which should have been
	 * initialized by bsc_vty_init().
	 */
	OSMO_ASSERT(vty_global_gsm_network);
	return vty_global_gsm_network;
}

static void net_dump_vty(struct vty *vty, struct gsm_network *net)
{
	vty_out(vty, "BSC is on Country Code %u, Network Code %u "
		"and has %u BTS%s", net->country_code, net->network_code,
		net->num_bts, VTY_NEWLINE);
	vty_out(vty, "  Long network name: '%s'%s",
		net->name_long, VTY_NEWLINE);
	vty_out(vty, "  Short network name: '%s'%s",
		net->name_short, VTY_NEWLINE);
	vty_out(vty, "  Authentication policy: %s%s",
		gsm_auth_policy_name(net->auth_policy), VTY_NEWLINE);
	vty_out(vty, "  Location updating reject cause: %u%s",
		net->reject_cause, VTY_NEWLINE);
	vty_out(vty, "  Encryption: A5/%u%s", net->a5_encryption,
		VTY_NEWLINE);
	vty_out(vty, "  NECI (TCH/H): %u%s", net->neci,
		VTY_NEWLINE);
	vty_out(vty, "  Use TCH for Paging any: %d%s", net->pag_any_tch,
		VTY_NEWLINE);
	vty_out(vty, "  RRLP Mode: %s%s", rrlp_mode_name(net->rrlp.mode),
		VTY_NEWLINE);
	vty_out(vty, "  MM Info: %s%s", net->send_mm_info ? "On" : "Off",
		VTY_NEWLINE);
	vty_out(vty, "  Handover: %s%s", net->handover.active ? "On" : "Off",
		VTY_NEWLINE);
#if BEFORE_MSCSPLIT
	struct pchan_load pl;
	network_chan_load(&pl, net);
	vty_out(vty, "  Current Channel Load:%s", VTY_NEWLINE);
	dump_pchan_load_vty(vty, "    ", &pl);

	/* show rf */
	if (net->bsc_data)
		vty_out(vty, "  Last RF Command: %s%s",
			net->bsc_data->rf_ctrl->last_state_command,
			VTY_NEWLINE);
	if (net->bsc_data)
		vty_out(vty, "  Last RF Lock Command: %s%s",
			net->bsc_data->rf_ctrl->last_rf_lock_ctrl_command,
			VTY_NEWLINE);
#endif
}

DEFUN(show_net, show_net_cmd, "show network",
	SHOW_STR "Display information about a GSM NETWORK\n")
{
	struct gsm_network *net = gsmnet_from_vty(vty);
	net_dump_vty(vty, net);

	return CMD_SUCCESS;
}

static int config_write_net(struct vty *vty)
{
	struct gsm_network *gsmnet = gsmnet_from_vty(vty);

	vty_out(vty, "network%s", VTY_NEWLINE);
	vty_out(vty, " network country code %u%s", gsmnet->country_code, VTY_NEWLINE);
	vty_out(vty, " mobile network code %u%s", gsmnet->network_code, VTY_NEWLINE);
	vty_out(vty, " short name %s%s", gsmnet->name_short, VTY_NEWLINE);
	vty_out(vty, " long name %s%s", gsmnet->name_long, VTY_NEWLINE);
	vty_out(vty, " auth policy %s%s", gsm_auth_policy_name(gsmnet->auth_policy), VTY_NEWLINE);
	vty_out(vty, " location updating reject cause %u%s",
		gsmnet->reject_cause, VTY_NEWLINE);
	vty_out(vty, " encryption a5 %u%s", gsmnet->a5_encryption, VTY_NEWLINE);
	vty_out(vty, " neci %u%s", gsmnet->neci, VTY_NEWLINE);
	vty_out(vty, " paging any use tch %d%s", gsmnet->pag_any_tch, VTY_NEWLINE);
	vty_out(vty, " rrlp mode %s%s", rrlp_mode_name(gsmnet->rrlp.mode),
		VTY_NEWLINE);
	vty_out(vty, " mm info %u%s", gsmnet->send_mm_info, VTY_NEWLINE);
	vty_out(vty, " handover %u%s", gsmnet->handover.active, VTY_NEWLINE);
	vty_out(vty, " handover window rxlev averaging %u%s",
		gsmnet->handover.win_rxlev_avg, VTY_NEWLINE);
	vty_out(vty, " handover window rxqual averaging %u%s",
		gsmnet->handover.win_rxqual_avg, VTY_NEWLINE);
	vty_out(vty, " handover window rxlev neighbor averaging %u%s",
		gsmnet->handover.win_rxlev_avg_neigh, VTY_NEWLINE);
	vty_out(vty, " handover power budget interval %u%s",
		gsmnet->handover.pwr_interval, VTY_NEWLINE);
	vty_out(vty, " handover power budget hysteresis %u%s",
		gsmnet->handover.pwr_hysteresis, VTY_NEWLINE);
	vty_out(vty, " handover maximum distance %u%s",
		gsmnet->handover.max_distance, VTY_NEWLINE);
	vty_out(vty, " timer t3101 %u%s", gsmnet->T3101, VTY_NEWLINE);
	vty_out(vty, " timer t3103 %u%s", gsmnet->T3103, VTY_NEWLINE);
	vty_out(vty, " timer t3105 %u%s", gsmnet->T3105, VTY_NEWLINE);
	vty_out(vty, " timer t3107 %u%s", gsmnet->T3107, VTY_NEWLINE);
	vty_out(vty, " timer t3109 %u%s", gsmnet->T3109, VTY_NEWLINE);
	vty_out(vty, " timer t3111 %u%s", gsmnet->T3111, VTY_NEWLINE);
	vty_out(vty, " timer t3113 %u%s", gsmnet->T3113, VTY_NEWLINE);
	vty_out(vty, " timer t3115 %u%s", gsmnet->T3115, VTY_NEWLINE);
	vty_out(vty, " timer t3117 %u%s", gsmnet->T3117, VTY_NEWLINE);
	vty_out(vty, " timer t3119 %u%s", gsmnet->T3119, VTY_NEWLINE);
	vty_out(vty, " timer t3122 %u%s", gsmnet->T3122, VTY_NEWLINE);
	vty_out(vty, " timer t3141 %u%s", gsmnet->T3141, VTY_NEWLINE);
	vty_out(vty, " dtx-used %u%s", gsmnet->dtx_enabled, VTY_NEWLINE);
	vty_out(vty, " subscriber-keep-in-ram %d%s",
		gsmnet->subscr_group->keep_subscr, VTY_NEWLINE);
	if (gsmnet->tz.override != 0) {
		if (gsmnet->tz.dst)
			vty_out(vty, " timezone %d %d %d%s",
				gsmnet->tz.hr, gsmnet->tz.mn, gsmnet->tz.dst,
				VTY_NEWLINE);
		else
			vty_out(vty, " timezone %d %d%s",
				gsmnet->tz.hr, gsmnet->tz.mn, VTY_NEWLINE);
	}

	if (gsmnet->t3212 == 0)
		vty_out(vty, " no periodic location update%s", VTY_NEWLINE);
	else
		vty_out(vty, " periodic location update %u%s",
			gsmnet->t3212 * 6, VTY_NEWLINE);


	return CMD_SUCCESS;
}

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

	bsc_replace_string(gsmnet, &gsmnet->name_short, argv[0]);
	return CMD_SUCCESS;
}

DEFUN(cfg_net_name_long,
      cfg_net_name_long_cmd,
      "long name NAME",
      "Set the long GSM network name\n" NAME_CMD_STR NAME_STR)
{
	struct gsm_network *gsmnet = gsmnet_from_vty(vty);

	bsc_replace_string(gsmnet, &gsmnet->name_long, argv[0]);
	return CMD_SUCCESS;
}

DEFUN(cfg_net_auth_policy,
      cfg_net_auth_policy_cmd,
      "auth policy (closed|accept-all|token)",
	"Authentication (not cryptographic)\n"
	"Set the GSM network authentication policy\n"
	"Require the MS to be activated in HLR\n"
	"Accept all MS, whether in HLR or not\n"
	"Use SMS-token based authentication\n")
{
	enum gsm_auth_policy policy = gsm_auth_policy_parse(argv[0]);
	struct gsm_network *gsmnet = gsmnet_from_vty(vty);

	gsmnet->auth_policy = policy;

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

	gsmnet->a5_encryption= atoi(argv[0]);

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

#define HANDOVER_STR	"Handover Options\n"

DEFUN(cfg_net_handover, cfg_net_handover_cmd,
      "handover (0|1)",
	HANDOVER_STR
	"Don't perform in-call handover\n"
	"Perform in-call handover\n")
{
	int enable = atoi(argv[0]);
	struct gsm_network *gsmnet = gsmnet_from_vty(vty);

#if BEFORE_MSCSPLIT
	if (enable && ipacc_rtp_direct) {
		vty_out(vty, "%% Cannot enable handover unless RTP Proxy mode "
			"is enabled by using the -P command line option%s",
			VTY_NEWLINE);
		return CMD_WARNING;
	}
#endif
	gsmnet->handover.active = enable;

	return CMD_SUCCESS;
}

#define HO_WIN_STR HANDOVER_STR "Measurement Window\n"
#define HO_WIN_RXLEV_STR HO_WIN_STR "Received Level Averaging\n"
#define HO_WIN_RXQUAL_STR HO_WIN_STR "Received Quality Averaging\n"
#define HO_PBUDGET_STR HANDOVER_STR "Power Budget\n"
#define HO_AVG_COUNT_STR "Amount to use for Averaging\n"

DEFUN(cfg_net_ho_win_rxlev_avg, cfg_net_ho_win_rxlev_avg_cmd,
      "handover window rxlev averaging <1-10>",
	HO_WIN_RXLEV_STR
	"How many RxLev measurements are used for averaging\n"
	HO_AVG_COUNT_STR)
{
	struct gsm_network *gsmnet = gsmnet_from_vty(vty);
	gsmnet->handover.win_rxlev_avg = atoi(argv[0]);
	return CMD_SUCCESS;
}

DEFUN(cfg_net_ho_win_rxqual_avg, cfg_net_ho_win_rxqual_avg_cmd,
      "handover window rxqual averaging <1-10>",
	HO_WIN_RXQUAL_STR
	"How many RxQual measurements are used for averaging\n"
	HO_AVG_COUNT_STR)
{
	struct gsm_network *gsmnet = gsmnet_from_vty(vty);
	gsmnet->handover.win_rxqual_avg = atoi(argv[0]);
	return CMD_SUCCESS;
}

DEFUN(cfg_net_ho_win_rxlev_neigh_avg, cfg_net_ho_win_rxlev_avg_neigh_cmd,
      "handover window rxlev neighbor averaging <1-10>",
	HO_WIN_RXLEV_STR "Neighbor\n"
	"How many RxQual measurements are used for averaging\n"
	HO_AVG_COUNT_STR)
{
	struct gsm_network *gsmnet = gsmnet_from_vty(vty);
	gsmnet->handover.win_rxlev_avg_neigh = atoi(argv[0]);
	return CMD_SUCCESS;
}

DEFUN(cfg_net_ho_pwr_interval, cfg_net_ho_pwr_interval_cmd,
      "handover power budget interval <1-99>",
	HO_PBUDGET_STR
	"How often to check if we have a better cell (SACCH frames)\n"
	"Interval\n" "Number\n")
{
	struct gsm_network *gsmnet = gsmnet_from_vty(vty);
	gsmnet->handover.pwr_interval = atoi(argv[0]);
	return CMD_SUCCESS;
}

DEFUN(cfg_net_ho_pwr_hysteresis, cfg_net_ho_pwr_hysteresis_cmd,
      "handover power budget hysteresis <0-999>",
	HO_PBUDGET_STR
	"How many dB does a neighbor to be stronger to become a HO candidate\n"
	"Hysteresis\n" "Number\n")
{
	struct gsm_network *gsmnet = gsmnet_from_vty(vty);
	gsmnet->handover.pwr_hysteresis = atoi(argv[0]);
	return CMD_SUCCESS;
}

DEFUN(cfg_net_ho_max_distance, cfg_net_ho_max_distance_cmd,
      "handover maximum distance <0-9999>",
	HANDOVER_STR
	"How big is the maximum timing advance before HO is forced\n"
	"Distance\n" "Number\n")
{
	struct gsm_network *gsmnet = gsmnet_from_vty(vty);
	gsmnet->handover.max_distance = atoi(argv[0]);
	return CMD_SUCCESS;
}

#define DECLARE_TIMER(number, doc) \
    DEFUN(cfg_net_T##number,					\
      cfg_net_T##number##_cmd,					\
      "timer t" #number  " <0-65535>",				\
      "Configure GSM Timers\n"					\
      doc "Timer Value in seconds\n")				\
{								\
	struct gsm_network *gsmnet = gsmnet_from_vty(vty);	\
	int value = atoi(argv[0]);				\
								\
	if (value < 0 || value > 65535) {			\
		vty_out(vty, "Timer value %s out of range.%s",	\
		        argv[0], VTY_NEWLINE);			\
		return CMD_WARNING;				\
	}							\
								\
	gsmnet->T##number = value;				\
	return CMD_SUCCESS;					\
}

DECLARE_TIMER(3101, "Set the timeout value for IMMEDIATE ASSIGNMENT.\n")
DECLARE_TIMER(3103, "Set the timeout value for HANDOVER.\n")
DECLARE_TIMER(3105, "Set the timer for repetition of PHYSICAL INFORMATION.\n")
DECLARE_TIMER(3107, "Currently not used.\n")
DECLARE_TIMER(3109, "Set the RSL SACCH deactivation timeout.\n")
DECLARE_TIMER(3111, "Set the RSL timeout to wait before releasing the RF Channel.\n")
DECLARE_TIMER(3113, "Set the time to try paging a subscriber.\n")
DECLARE_TIMER(3115, "Currently not used.\n")
DECLARE_TIMER(3117, "Currently not used.\n")
DECLARE_TIMER(3119, "Currently not used.\n")
DECLARE_TIMER(3122, "Waiting time (seconds) after IMM ASS REJECT\n")
DECLARE_TIMER(3141, "Currently not used.\n")

DEFUN(cfg_net_dtx,
      cfg_net_dtx_cmd,
      "dtx-used (0|1)",
      "Enable the usage of DTX.\n"
      "DTX is disabled\n" "DTX is enabled\n")
{
	struct gsm_network *gsmnet = gsmnet_from_vty(vty);
	gsmnet->dtx_enabled = atoi(argv[0]);
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


int gsmnet_vty_init(struct gsm_network *network)
{
	vty_global_gsm_network = network;

	install_element_ve(&show_net_cmd);

	install_element(CONFIG_NODE, &cfg_net_cmd);
	install_node(&net_node, config_write_net);
	vty_install_default(GSMNET_NODE);
	install_element(GSMNET_NODE, &cfg_net_ncc_cmd);
	install_element(GSMNET_NODE, &cfg_net_mnc_cmd);
	install_element(GSMNET_NODE, &cfg_net_name_short_cmd);
	install_element(GSMNET_NODE, &cfg_net_name_long_cmd);
	install_element(GSMNET_NODE, &cfg_net_auth_policy_cmd);
	install_element(GSMNET_NODE, &cfg_net_reject_cause_cmd);
	install_element(GSMNET_NODE, &cfg_net_encryption_cmd);
	install_element(GSMNET_NODE, &cfg_net_rrlp_mode_cmd);
	install_element(GSMNET_NODE, &cfg_net_mm_info_cmd);
	install_element(GSMNET_NODE, &cfg_net_handover_cmd);
	install_element(GSMNET_NODE, &cfg_net_ho_win_rxlev_avg_cmd);
	install_element(GSMNET_NODE, &cfg_net_ho_win_rxqual_avg_cmd);
	install_element(GSMNET_NODE, &cfg_net_ho_win_rxlev_avg_neigh_cmd);
	install_element(GSMNET_NODE, &cfg_net_ho_pwr_interval_cmd);
	install_element(GSMNET_NODE, &cfg_net_ho_pwr_hysteresis_cmd);
	install_element(GSMNET_NODE, &cfg_net_ho_max_distance_cmd);
	install_element(GSMNET_NODE, &cfg_net_T3101_cmd);
	install_element(GSMNET_NODE, &cfg_net_T3103_cmd);
	install_element(GSMNET_NODE, &cfg_net_T3105_cmd);
	install_element(GSMNET_NODE, &cfg_net_T3107_cmd);
	install_element(GSMNET_NODE, &cfg_net_T3109_cmd);
	install_element(GSMNET_NODE, &cfg_net_T3111_cmd);
	install_element(GSMNET_NODE, &cfg_net_T3113_cmd);
	install_element(GSMNET_NODE, &cfg_net_T3115_cmd);
	install_element(GSMNET_NODE, &cfg_net_T3117_cmd);
	install_element(GSMNET_NODE, &cfg_net_T3119_cmd);
	install_element(GSMNET_NODE, &cfg_net_T3122_cmd);
	install_element(GSMNET_NODE, &cfg_net_T3141_cmd);
	install_element(GSMNET_NODE, &cfg_net_dtx_cmd);
	install_element(GSMNET_NODE, &cfg_net_subscr_keep_cmd);
	install_element(GSMNET_NODE, &cfg_net_timezone_cmd);
	install_element(GSMNET_NODE, &cfg_net_timezone_dst_cmd);
	install_element(GSMNET_NODE, &cfg_net_no_timezone_cmd);

	return CMD_SUCCESS;
}

/* VTY elements used in both BSC and MSC */
int xsc_vty_init(struct gsm_network *network)
{
	osmo_stats_vty_add_cmds();

	gsmnet_vty_init(network);
	return CMD_SUCCESS;
}
