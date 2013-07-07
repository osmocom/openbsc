/* OpenBSC interface to quagga VTY */
/* (C) 2009-2010 by Harald Welte <laforge@gnumonks.org>
 *     2013 by Andreas Eversberg <jolly@eversberg.eu>
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

#include <stdlib.h>
#include <unistd.h>

#include <osmocom/vty/command.h>
#include <osmocom/vty/buffer.h>
#include <osmocom/vty/vty.h>
#include <osmocom/vty/logging.h>
#include <osmocom/vty/telnet_interface.h>
#include <osmocom/vty/misc.h>

#include <openbsc/gsm_data.h>
#include <openbsc/vty.h>
#include <openbsc/handover_decision.h>

void bts_dump_vty_handover(struct vty *vty, struct gsm_bts *bts)
{
	int algorithm = bts->network->ho_algorithm;

	if (algorithm == 1 || algorithm == 2)
		vty_out(vty, "  Handover: %s%s",
			bts->handover.ho_active ? "On" : "Off", VTY_NEWLINE);
	if (algorithm == 2)
		vty_out(vty, "  Assignment: %s%s",
			bts->handover.as_active ? "On" : "Off", VTY_NEWLINE);
}

void config_write_bts_handover(struct vty *vty, struct gsm_bts *bts)
{
	int algorithm = bts->network->ho_algorithm;

	if (algorithm == 1 || algorithm == 2)
		vty_out(vty, "  handover enable handover %u%s",
			bts->handover.ho_active, VTY_NEWLINE);
	if (algorithm == 2) {
		vty_out(vty, "  handover enable assignment %u%s",
			bts->handover.as_active, VTY_NEWLINE);
		vty_out(vty, "  handover set %s%s",
			(bts->handover.full) ? "full" : "sub", VTY_NEWLINE);
		vty_out(vty, "  handover min rxlev %d%s",
			bts->handover.min_rxlev, VTY_NEWLINE);
	}
	if (algorithm == 1 || algorithm == 2) {
		vty_out(vty, "  handover window rxlev averaging %u%s",
			bts->handover.win_rxlev_avg, VTY_NEWLINE);
		vty_out(vty, "  handover window rxlev neighbor averaging %u%s",
			bts->handover.win_rxlev_avg_neigh, VTY_NEWLINE);
		vty_out(vty, "  handover power budget hysteresis %u%s",
			bts->handover.pwr_hysteresis, VTY_NEWLINE);
		vty_out(vty, "  handover power budget interval %u%s",
			bts->handover.pwr_interval, VTY_NEWLINE);
	}
	if (algorithm == 2) {
		vty_out(vty, "  handover afs rxlev improvement %u%s",
			bts->handover.afs_rxlev_improve, VTY_NEWLINE);
		vty_out(vty, "  handover min rxqual %u%s",
			bts->handover.min_rxqual, VTY_NEWLINE);
		vty_out(vty, "  handover window rxqual averaging %u%s",
			bts->handover.win_rxqual_avg, VTY_NEWLINE);
		vty_out(vty, "  handover afs rxqual improvement %u%s",
			bts->handover.afs_rxqual_improve, VTY_NEWLINE);
	}
	if (algorithm == 1 || algorithm == 2)
		vty_out(vty, "  handover maximum distance %u%s",
			bts->handover.max_distance, VTY_NEWLINE);
	if (algorithm == 2) {
		vty_out(vty, "  handover min free tch-f %u%s",
			bts->handover.min_free_tchf, VTY_NEWLINE);
		vty_out(vty, "  handover min free tch-h %u%s",
			bts->handover.min_free_tchh, VTY_NEWLINE);
		vty_out(vty, "  handover max unsync handovers %u%s",
			bts->handover.max_unsync_ho, VTY_NEWLINE);
		vty_out(vty, "  handover penalty max distance %u%s",
			bts->handover.penalty_max_dist, VTY_NEWLINE);
		vty_out(vty, "  handover penalty handover failure %u%s",
			bts->handover.penalty_ho_fail, VTY_NEWLINE);
		vty_out(vty, "  handover penalty assignment failure %u%s",
			bts->handover.penalty_as_fail, VTY_NEWLINE);
	}
}

void config_write_net_handover(struct vty *vty)
{
	struct gsm_network *gsmnet = gsmnet_from_vty(vty);
	int algorithm = gsmnet->ho_algorithm;

	if (algorithm == 1 || algorithm == 2)
		vty_out(vty, " handover algorithm %d%s", gsmnet->ho_algorithm,
			VTY_NEWLINE);
	if (algorithm == 2)
		vty_out(vty, " handover congestion-check-timer %u%s",
			gsmnet->ho_congest_timeout, VTY_NEWLINE);
}

/* check if given algorithm is set, otherwise reject command */
int is_cmd_for_algorithm(struct vty *vty, int for_1, int for_2)
{
	struct gsm_network *gsmnet = gsmnet_from_vty(vty);
	int algorithm = gsmnet->ho_algorithm;

	switch (algorithm) {
	case 1:
		if (for_1)
			break;
		vty_out(vty, "%% Given command is not allowed for selected "
			"handover algorithm 1%s\n", VTY_NEWLINE);
		return -EINVAL;
	case 2:
		if (for_2)
			break;
		vty_out(vty, "%% Given command is not allowed for selected "
			"handover algorithm 2%s\n", VTY_NEWLINE);
		return -EINVAL;
	default:
		vty_out(vty, "%% Please define handover algorithm before "
			"giving handover config command%s\n", VTY_NEWLINE);
		return -EINVAL;
	}

	return 0;
}

/* Per network configuration */
#define NET_HO_STR "Global handover settings.\n"
DEFUN(cfg_net_ho_algorithm,
      cfg_net_ho_algorithm_cmd,
      "handover algorithm (1|2)",
      NET_HO_STR
      "Handover algorithm selection\n"
      "Algorithm 1\nAlgorithm 2")
{
	struct gsm_network *gsmnet = gsmnet_from_vty(vty);

	gsmnet->ho_algorithm = atoi(argv[0]);
	switch (gsmnet->ho_algorithm) {
	case 1:
		init_ho_1();
		break;
	case 2:
//		init_ho_2();
		break;
	}
	return CMD_SUCCESS;
}

DEFUN(cfg_net_ho_congest_timer,
      cfg_net_ho_congest_timer_cmd,
      "handover congestion-check-timer <0-60>",
      NET_HO_STR
      "Handover congestion check timer\n"
      "Time in seconds for congestion check interval (0 to disable)\n")
{
	struct gsm_network *gsmnet = gsmnet_from_vty(vty);

	if (is_cmd_for_algorithm(vty, 0, 1))
		return CMD_WARNING;
	gsmnet->ho_congest_timeout = atoi(argv[0]);
	switch (gsmnet->ho_algorithm) {
	case 2:
//		init_ho_timer_2();
		break;
	}
	return CMD_SUCCESS;
}

/* Per BTS configuration */
#define HANDOVER_STR	"Handover Options\n"
#define HO_ENABLE_STR HANDOVER_STR "Enable or disable handover/assignment\n"

DEFUN(cfg_bts_ho_handover, cfg_bts_ho_handover_cmd,
      "handover enable handover (0|1)",
	HO_ENABLE_STR
	"Enable or disable handover\n"
	"Don't perform in-call handover\n"
	"Perform in-call handover\n")
{
	int enable = atoi(argv[0]);
	struct gsm_bts *bts = vty->index;

	if (is_cmd_for_algorithm(vty, 1, 1))
		return CMD_WARNING;
	if (enable && ipacc_rtp_direct) {
		vty_out(vty, "%% Cannot enable handover unless RTP Proxy mode "
			"is enabled by using the -P command line option%s",
			VTY_NEWLINE);
		return CMD_WARNING;
	}
	bts->handover.ho_active = enable;

	return CMD_SUCCESS;
}

DEFUN(cfg_bts_ho_assignment, cfg_bts_ho_assignment_cmd,
      "handover enable assignment (0|1)",
	HO_ENABLE_STR
	"Enable or disable assignment\n"
	"Don't perform in-call assignment\n"
	"Perform in-call assignment\n")
{
	int enable = atoi(argv[0]);
	struct gsm_bts *bts = vty->index;

	if (is_cmd_for_algorithm(vty, 0, 1))
		return CMD_WARNING;
	if (enable && ipacc_rtp_direct) {
		vty_out(vty, "%% Cannot enable assignment unless RTP Proxy mode "
			"is enabled by using the -P command line option%s",
			VTY_NEWLINE);
		return CMD_WARNING;
	}
	bts->handover.as_active = enable;

	return CMD_SUCCESS;
}

DEFUN(cfg_bts_ho_set, cfg_bts_ho_set_cmd,
      "handover set (full|sub)",
	HANDOVER_STR
	"Define measuement set of TDMA frames\n"
	"Full set of 102/104 TDMA frames\n"
	"Sub set of 4 TDMA frames (SACCH)")
{
	struct gsm_bts *bts = vty->index;

	if (is_cmd_for_algorithm(vty, 0, 1))
		return CMD_WARNING;
	bts->handover.full = (argv[0][0]=='f');
	return CMD_SUCCESS;
}

#define HO_MIN_STR HANDOVER_STR "Minimum Values\n"
#define HO_MAX_STR HANDOVER_STR "Maximum Values\n"
#define HO_MIN_FREE_STR HO_MIN_STR "Minimum free Slots\n"
#define HO_WIN_STR HANDOVER_STR "Measurement Window\n"
#define HO_WIN_RXLEV_STR HO_WIN_STR "Received Level Averaging\n"
#define HO_WIN_RXQUAL_STR HO_WIN_STR "Received Quality Averaging\n"
#define HO_PBUDGET_STR HANDOVER_STR "Power Budget\n"
#define HO_AFS_STR HANDOVER_STR "AMR on TCH/F\n"
#define HO_PENALTY_STR HANDOVER_STR "Penalty Time\n"
#define HO_AVG_COUNT_STR "Amount to use for Averaging\n"

DEFUN(cfg_bts_ho_min_rxlev, cfg_bts_ho_min_rxlev_cmd,
      "handover min rxlev <-110-50>",
	HO_MIN_STR
	"The minimum RxLev allowed in this cell\n"
	"Minimum RxLev in dBm")
{
	struct gsm_bts *bts = vty->index;

	if (is_cmd_for_algorithm(vty, 0, 1))
		return CMD_WARNING;
	bts->handover.min_rxlev = atoi(argv[0]);
	return CMD_SUCCESS;
}

DEFUN(cfg_bts_ho_win_rxlev_avg, cfg_bts_ho_win_rxlev_avg_cmd,
      "handover window rxlev averaging <1-10>",
	HO_WIN_RXLEV_STR
	"How many RxLev measurements are used for averaging\n"
	HO_AVG_COUNT_STR)
{
	struct gsm_bts *bts = vty->index;

	if (is_cmd_for_algorithm(vty, 1, 1))
		return CMD_WARNING;
	bts->handover.win_rxlev_avg = atoi(argv[0]);
	return CMD_SUCCESS;
}

DEFUN(cfg_bts_ho_win_rxlev_neigh_avg, cfg_bts_ho_win_rxlev_avg_neigh_cmd,
      "handover window rxlev neighbor averaging <1-10>",
	HO_WIN_RXLEV_STR "Neighbor\n"
	"How many RxQual measurements are used for averaging\n"
	HO_AVG_COUNT_STR)
{
	struct gsm_bts *bts = vty->index;

	if (is_cmd_for_algorithm(vty, 1, 1))
		return CMD_WARNING;
	bts->handover.win_rxlev_avg_neigh = atoi(argv[0]);
	return CMD_SUCCESS;
}

DEFUN(cfg_bts_ho_pwr_hysteresis, cfg_bts_ho_pwr_hysteresis_cmd,
      "handover power budget hysteresis <0-999>",
	HO_PBUDGET_STR
	"How many dB does a neighbor to be stronger to become a HO candidate\n"
	"Hysteresis\n" "Number\n")
{
	struct gsm_bts *bts = vty->index;

	if (is_cmd_for_algorithm(vty, 1, 1))
		return CMD_WARNING;
	bts->handover.pwr_hysteresis = atoi(argv[0]);
	return CMD_SUCCESS;
}

DEFUN(cfg_bts_ho_pwr_interval, cfg_bts_ho_pwr_interval_cmd,
      "handover power budget interval <1-99>",
	HO_PBUDGET_STR
	"How often to check if we have a better cell (SACCH frames)\n"
	"Interval\n" "Number\n")
{
	struct gsm_bts *bts = vty->index;

	if (is_cmd_for_algorithm(vty, 1, 1))
		return CMD_WARNING;
	bts->handover.pwr_interval = atoi(argv[0]);
	return CMD_SUCCESS;
}

DEFUN(cfg_bts_ho_afs_rxlev_improve, cfg_bts_ho_afs_rxlev_improve_cmd,
      "handover afs rxlev improvement <0-20>",
	HO_AFS_STR
	"RxLev\n"
	"Improvement of RxLev over other codecs\n"
	"RxLev in dB")
{
	struct gsm_bts *bts = vty->index;

	if (is_cmd_for_algorithm(vty, 0, 1))
		return CMD_WARNING;
	bts->handover.afs_rxlev_improve = atoi(argv[0]);
	return CMD_SUCCESS;
}

DEFUN(cfg_bts_ho_min_rxqual, cfg_bts_ho_min_rxqual_cmd,
      "handover min rxqual <0-7>",
	HO_MIN_STR
	"The minimum RxQual allowed in this cell\n"
	"Minimum RxQual in dBm")
{
	struct gsm_bts *bts = vty->index;

	if (is_cmd_for_algorithm(vty, 0, 1))
		return CMD_WARNING;
	bts->handover.min_rxqual = atoi(argv[0]);
	return CMD_SUCCESS;
}

DEFUN(cfg_bts_ho_win_rxqual_avg, cfg_bts_ho_win_rxqual_avg_cmd,
      "handover window rxqual averaging <1-10>",
	HO_WIN_RXQUAL_STR
	"How many RxQual measurements are used for averaging\n"
	HO_AVG_COUNT_STR)
{
	struct gsm_bts *bts = vty->index;

	if (is_cmd_for_algorithm(vty, 0, 1))
		return CMD_WARNING;
	bts->handover.win_rxqual_avg = atoi(argv[0]);
	return CMD_SUCCESS;
}

DEFUN(cfg_bts_ho_afs_rxqual_improve, cfg_bts_ho_afs_rxqual_improve_cmd,
      "handover afs rxqual improvement <0-7>",
	HO_AFS_STR
	"RxQual\n"
	"Improvement of RxQual over other codecs\n"
	"RxQual in dB")
{
	struct gsm_bts *bts = vty->index;

	if (is_cmd_for_algorithm(vty, 0, 1))
		return CMD_WARNING;
	bts->handover.afs_rxqual_improve = atoi(argv[0]);
	return CMD_SUCCESS;
}

DEFUN(cfg_bts_ho_max_distance, cfg_bts_ho_max_distance_cmd,
      "handover maximum distance <0-9999>",
	HANDOVER_STR
	"How big is the maximum timing advance before HO is forced\n"
	"Distance\n" "Number\n")
{
	struct gsm_bts *bts = vty->index;

	if (is_cmd_for_algorithm(vty, 1, 1))
		return CMD_WARNING;
	bts->handover.max_distance = atoi(argv[0]);
	return CMD_SUCCESS;
}

DEFUN(cfg_bts_ho_min_free_tchf, cfg_bts_ho_min_free_tchf_cmd,
      "handover min free tch-f <0-9999>",
	HO_MIN_FREE_STR
	"Minimum free TCH/F timeslots before cell is congeted\n"
	"Slots\n")
{
	struct gsm_bts *bts = vty->index;

	if (is_cmd_for_algorithm(vty, 0, 1))
		return CMD_WARNING;
	bts->handover.min_free_tchf = atoi(argv[0]);
	return CMD_SUCCESS;
}

DEFUN(cfg_bts_ho_min_free_tchh, cfg_bts_ho_min_free_tchh_cmd,
      "handover min free tch-h <0-9999>",
	HO_MIN_FREE_STR
	"Minimum free TCH/H timeslots before cell is congeted\n"
	"Slots\n")
{
	struct gsm_bts *bts = vty->index;

	if (is_cmd_for_algorithm(vty, 0, 1))
		return CMD_WARNING;
	bts->handover.min_free_tchh = atoi(argv[0]);
	return CMD_SUCCESS;
}

DEFUN(cfg_bts_ho_max_unsync_ho, cfg_bts_ho_max_unsync_ho_cmd,
      "handover max unsync handovers <0-9999>",
	HO_MAX_STR
	"Maximum unsynchronous handovers\n"
	"Handovers\nNumber\n")
{
	struct gsm_bts *bts = vty->index;

	if (is_cmd_for_algorithm(vty, 0, 1))
		return CMD_WARNING;
	bts->handover.max_unsync_ho = atoi(argv[0]);
	return CMD_SUCCESS;
}

DEFUN(cfg_bts_ho_penalty_max_dist, cfg_bts_ho_penalty_max_dist_cmd,
      "handover penalty max distance <0-99999>",
	HO_PENALTY_STR
	"After leaving this cell due to exceeding the maximum allowed distance\n"
	"Distance\nTime in Seconds\n")
{
	struct gsm_bts *bts = vty->index;

	if (is_cmd_for_algorithm(vty, 0, 1))
		return CMD_WARNING;
	bts->handover.penalty_max_dist = atoi(argv[0]);
	return CMD_SUCCESS;
}

DEFUN(cfg_bts_ho_penalty_ho_fail, cfg_bts_ho_penalty_ho_fail_cmd,
      "handover penalty handover failure <0-99999>",
	HO_PENALTY_STR
	"After handover failure to this cell\n"
	"Failure\nTime in Seconds\n")
{
	struct gsm_bts *bts = vty->index;

	if (is_cmd_for_algorithm(vty, 0, 1))
		return CMD_WARNING;
	bts->handover.penalty_ho_fail = atoi(argv[0]);
	return CMD_SUCCESS;
}

DEFUN(cfg_bts_ho_penalty_as_fail, cfg_bts_ho_penalty_as_fail_cmd,
      "handover penalty assignment failure <0-99999>",
	HO_PENALTY_STR
	"After assignment failure in this cell\n"
	"Failure\nTime in Seconds\n")
{
	struct gsm_bts *bts = vty->index;

	if (is_cmd_for_algorithm(vty, 0, 1))
		return CMD_WARNING;
	bts->handover.penalty_as_fail = atoi(argv[0]);
	return CMD_SUCCESS;
}

void bsc_vty_init_handover(void)
{
	install_element(GSMNET_NODE, &cfg_net_ho_algorithm_cmd);
	install_element(GSMNET_NODE, &cfg_net_ho_congest_timer_cmd);
	install_element(BTS_NODE, &cfg_bts_ho_handover_cmd);
	install_element(BTS_NODE, &cfg_bts_ho_assignment_cmd);
	install_element(BTS_NODE, &cfg_bts_ho_set_cmd);
	install_element(BTS_NODE, &cfg_bts_ho_min_rxlev_cmd);
	install_element(BTS_NODE, &cfg_bts_ho_win_rxlev_avg_cmd);
	install_element(BTS_NODE, &cfg_bts_ho_win_rxlev_avg_neigh_cmd);
	install_element(BTS_NODE, &cfg_bts_ho_pwr_hysteresis_cmd);
	install_element(BTS_NODE, &cfg_bts_ho_pwr_interval_cmd);
	install_element(BTS_NODE, &cfg_bts_ho_afs_rxlev_improve_cmd);
	install_element(BTS_NODE, &cfg_bts_ho_min_rxqual_cmd);
	install_element(BTS_NODE, &cfg_bts_ho_win_rxqual_avg_cmd);
	install_element(BTS_NODE, &cfg_bts_ho_afs_rxqual_improve_cmd);
	install_element(BTS_NODE, &cfg_bts_ho_max_distance_cmd);
	install_element(BTS_NODE, &cfg_bts_ho_min_free_tchf_cmd);
	install_element(BTS_NODE, &cfg_bts_ho_min_free_tchh_cmd);
	install_element(BTS_NODE, &cfg_bts_ho_max_unsync_ho_cmd);
	install_element(BTS_NODE, &cfg_bts_ho_penalty_max_dist_cmd);
	install_element(BTS_NODE, &cfg_bts_ho_penalty_ho_fail_cmd);
	install_element(BTS_NODE, &cfg_bts_ho_penalty_as_fail_cmd);
}

