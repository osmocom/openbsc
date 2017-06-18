/* OpenBSC interface to quagga VTY */
/* (C) 2009-2010 by Harald Welte <laforge@gnumonks.org>
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
#include <stdbool.h>
#include <unistd.h>

#include <osmocom/vty/command.h>
#include <osmocom/vty/buffer.h>
#include <osmocom/vty/vty.h>
#include <osmocom/vty/logging.h>
#include <osmocom/vty/stats.h>
#include <osmocom/vty/telnet_interface.h>
#include <osmocom/vty/misc.h>
#include <osmocom/gsm/protocol/gsm_04_08.h>
#include <osmocom/gsm/gsm0502.h>

#include <arpa/inet.h>

#include <osmocom/core/linuxlist.h>
#include <openbsc/gsm_data.h>
#include <osmocom/abis/e1_input.h>
#include <openbsc/abis_nm.h>
#include <openbsc/abis_om2000.h>
#include <osmocom/core/utils.h>
#include <osmocom/gsm/gsm_utils.h>
#include <osmocom/gsm/abis_nm.h>
#include <openbsc/chan_alloc.h>
#include <openbsc/meas_rep.h>
#include <openbsc/db.h>
#include <openbsc/vty.h>
#include <osmocom/gprs/gprs_ns.h>
#include <openbsc/system_information.h>
#include <openbsc/debug.h>
#include <openbsc/paging.h>
#include <openbsc/ipaccess.h>
#include <openbsc/abis_rsl.h>
#include <openbsc/bsc_msc_data.h>
#include <openbsc/osmo_bsc_rf.h>
#include <openbsc/pcu_if.h>

#include <openbsc/common_cs.h>

#include <inttypes.h>

#include "../../bscconfig.h"


#define LCHAN_NR_STR "Logical Channel Number\n"


/* FIXME: this should go to some common file */
static const struct value_string gprs_ns_timer_strs[] = {
	{ 0, "tns-block" },
	{ 1, "tns-block-retries" },
	{ 2, "tns-reset" },
	{ 3, "tns-reset-retries" },
	{ 4, "tns-test" },
	{ 5, "tns-alive" },
	{ 6, "tns-alive-retries" },
	{ 0, NULL }
};

static const struct value_string gprs_bssgp_cfg_strs[] = {
	{ 0,	"blocking-timer" },
	{ 1,	"blocking-retries" },
	{ 2,	"unblocking-retries" },
	{ 3,	"reset-timer" },
	{ 4,	"reset-retries" },
	{ 5,	"suspend-timer" },
	{ 6,	"suspend-retries" },
	{ 7,	"resume-timer" },
	{ 8,	"resume-retries" },
	{ 9,	"capability-update-timer" },
	{ 10,	"capability-update-retries" },
	{ 0,	NULL }
};

static const struct value_string bts_neigh_mode_strs[] = {
	{ NL_MODE_AUTOMATIC, "automatic" },
	{ NL_MODE_MANUAL, "manual" },
	{ NL_MODE_MANUAL_SI5SEP, "manual-si5" },
	{ 0, NULL }
};

const struct value_string bts_loc_fix_names[] = {
	{ BTS_LOC_FIX_INVALID,	"invalid" },
	{ BTS_LOC_FIX_2D,	"fix2d" },
	{ BTS_LOC_FIX_3D,	"fix3d" },
	{ 0, NULL }
};

struct cmd_node bts_node = {
	BTS_NODE,
	"%s(config-net-bts)# ",
	1,
};

struct cmd_node trx_node = {
	TRX_NODE,
	"%s(config-net-bts-trx)# ",
	1,
};

struct cmd_node ts_node = {
	TS_NODE,
	"%s(config-net-bts-trx-ts)# ",
	1,
};

static int dummy_config_write(struct vty *v)
{
	return CMD_SUCCESS;
}

static void net_dump_nmstate(struct vty *vty, struct gsm_nm_state *nms)
{
	vty_out(vty,"Oper '%s', Admin '%s', Avail '%s'%s",
		abis_nm_opstate_name(nms->operational),
		get_value_string(abis_nm_adm_state_names, nms->administrative),
		abis_nm_avail_name(nms->availability), VTY_NEWLINE);
}

static void dump_pchan_load_vty(struct vty *vty, char *prefix,
				const struct pchan_load *pl)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(pl->pchan); i++) {
		const struct load_counter *lc = &pl->pchan[i];
		unsigned int percent;

		if (lc->total == 0)
			continue;

		percent = (lc->used * 100) / lc->total;

		vty_out(vty, "%s%20s: %3u%% (%u/%u)%s", prefix,
			gsm_pchan_name(i), percent, lc->used, lc->total,
			VTY_NEWLINE);
	}
}

static void net_dump_vty(struct vty *vty, struct gsm_network *net)
{
	struct pchan_load pl;

	vty_out(vty, "BSC is on Country Code %u, Network Code %u "
		"and has %u BTS%s", net->country_code, net->network_code,
		net->num_bts, VTY_NEWLINE);
	vty_out(vty, "  Long network name: '%s'%s",
		net->name_long, VTY_NEWLINE);
	vty_out(vty, "  Short network name: '%s'%s",
		net->name_short, VTY_NEWLINE);
	vty_out(vty, "  Authentication policy: %s",
		gsm_auth_policy_name(net->auth_policy));
	if (net->authorized_reg_str)
		vty_out(vty, ", authorized regexp: %s", net->authorized_reg_str);
	vty_out(vty, "%s", VTY_NEWLINE);
	vty_out(vty, "  Auto create subscriber: %s%s",
		net->auto_create_subscr ? "yes" : "no", VTY_NEWLINE);
	vty_out(vty, "  Auto assign extension: %s%s",
		net->auto_assign_exten ? "yes" : "no", VTY_NEWLINE);
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
}

DEFUN(bsc_show_net, bsc_show_net_cmd, "show network",
	SHOW_STR "Display information about a GSM NETWORK\n")
{
	struct gsm_network *net = gsmnet_from_vty(vty);
	net_dump_vty(vty, net);

	return CMD_SUCCESS;
}

static void e1isl_dump_vty(struct vty *vty, struct e1inp_sign_link *e1l)
{
	struct e1inp_line *line;

	if (!e1l) {
		vty_out(vty, "   None%s", VTY_NEWLINE);
		return;
	}

	line = e1l->ts->line;

	vty_out(vty, "    E1 Line %u, Type %s: Timeslot %u, Mode %s%s",
		line->num, line->driver->name, e1l->ts->num,
		e1inp_signtype_name(e1l->type), VTY_NEWLINE);
	vty_out(vty, "    E1 TEI %u, SAPI %u%s",
		e1l->tei, e1l->sapi, VTY_NEWLINE);
}

static void bts_dump_vty(struct vty *vty, struct gsm_bts *bts)
{
	struct pchan_load pl;

	vty_out(vty, "BTS %u is of %s type in band %s, has CI %u LAC %u, "
		"BSIC %u (NCC=%u, BCC=%u) and %u TRX%s",
		bts->nr, btstype2str(bts->type), gsm_band_name(bts->band),
		bts->cell_identity,
		bts->location_area_code, bts->bsic,
		bts->bsic >> 3, bts->bsic & 7,
		bts->num_trx, VTY_NEWLINE);
	vty_out(vty, "Description: %s%s",
		bts->description ? bts->description : "(null)", VTY_NEWLINE);
	if (strnlen(bts->pcu_version, MAX_VERSION_LENGTH))
		vty_out(vty, "PCU version %s connected%s", bts->pcu_version,
			VTY_NEWLINE);
	vty_out(vty, "MS Max power: %u dBm%s", bts->ms_max_power, VTY_NEWLINE);
	vty_out(vty, "Minimum Rx Level for Access: %i dBm%s",
		rxlev2dbm(bts->si_common.cell_sel_par.rxlev_acc_min),
		VTY_NEWLINE);
	vty_out(vty, "Cell Reselection Hysteresis: %u dBm%s",
		bts->si_common.cell_sel_par.cell_resel_hyst*2, VTY_NEWLINE);
	vty_out(vty, "RACH TX-Integer: %u%s", bts->si_common.rach_control.tx_integer,
		VTY_NEWLINE);
	vty_out(vty, "RACH Max transmissions: %u%s",
		rach_max_trans_raw2val(bts->si_common.rach_control.max_trans),
		VTY_NEWLINE);
	if (bts->si_common.rach_control.cell_bar)
		vty_out(vty, "  CELL IS BARRED%s", VTY_NEWLINE);
	if (bts->dtxu != GSM48_DTX_SHALL_NOT_BE_USED)
		vty_out(vty, "Uplink DTX: %s%s",
			(bts->dtxu != GSM48_DTX_SHALL_BE_USED) ?
			"enabled" : "forced", VTY_NEWLINE);
	else
		vty_out(vty, "Uplink DTX: not enabled%s", VTY_NEWLINE);
	vty_out(vty, "Downlink DTX: %senabled%s", bts->dtxd ? "" : "not ",
		VTY_NEWLINE);
	vty_out(vty, "Channel Description Attachment: %s%s",
		(bts->si_common.chan_desc.att) ? "yes" : "no", VTY_NEWLINE);
	vty_out(vty, "Channel Description BS-PA-MFRMS: %u%s",
		bts->si_common.chan_desc.bs_pa_mfrms + 2, VTY_NEWLINE);
	vty_out(vty, "Channel Description BS-AG_BLKS-RES: %u%s",
		bts->si_common.chan_desc.bs_ag_blks_res, VTY_NEWLINE);
	vty_out(vty, "System Information present: 0x%08x, static: 0x%08x%s",
		bts->si_valid, bts->si_mode_static, VTY_NEWLINE);
	vty_out(vty, "Early Classmark Sending: %s%s",
		bts->early_classmark_allowed ? "allowed" : "forbidden",
		VTY_NEWLINE);
	if (bts->pcu_sock_path)
		vty_out(vty, "PCU Socket Path: %s%s", bts->pcu_sock_path, VTY_NEWLINE);
	if (is_ipaccess_bts(bts))
		vty_out(vty, "  Unit ID: %u/%u/0, OML Stream ID 0x%02x%s",
			bts->ip_access.site_id, bts->ip_access.bts_id,
			bts->oml_tei, VTY_NEWLINE);
	else if (bts->type == GSM_BTS_TYPE_NOKIA_SITE)
		vty_out(vty, "  Skip Reset: %d%s",
			bts->nokia.skip_reset, VTY_NEWLINE);
	vty_out(vty, "  NM State: ");
	net_dump_nmstate(vty, &bts->mo.nm_state);
	vty_out(vty, "  Site Mgr NM State: ");
	net_dump_nmstate(vty, &bts->site_mgr.mo.nm_state);
	vty_out(vty, "  GPRS NSE: ");
	net_dump_nmstate(vty, &bts->gprs.nse.mo.nm_state);
	vty_out(vty, "  GPRS CELL: ");
	net_dump_nmstate(vty, &bts->gprs.cell.mo.nm_state);
	vty_out(vty, "  GPRS NSVC0: ");
	net_dump_nmstate(vty, &bts->gprs.nsvc[0].mo.nm_state);
	vty_out(vty, "  GPRS NSVC1: ");
	net_dump_nmstate(vty, &bts->gprs.nsvc[1].mo.nm_state);
	vty_out(vty, "  Paging: %u pending requests, %u free slots%s",
		paging_pending_requests_nr(bts),
		bts->paging.available_slots, VTY_NEWLINE);
	if (is_ipaccess_bts(bts)) {
		vty_out(vty, "  OML Link state: %s.%s",
			bts->oml_link ? "connected" : "disconnected", VTY_NEWLINE);
	} else {
		vty_out(vty, "  E1 Signalling Link:%s", VTY_NEWLINE);
		e1isl_dump_vty(vty, bts->oml_link);
	}

	/* FIXME: chan_desc */
	memset(&pl, 0, sizeof(pl));
	bts_chan_load(&pl, bts);
	vty_out(vty, "  Current Channel Load:%s", VTY_NEWLINE);
	dump_pchan_load_vty(vty, "    ", &pl);
}

DEFUN(show_bts, show_bts_cmd, "show bts [<0-255>]",
	SHOW_STR "Display information about a BTS\n"
		"BTS number")
{
	struct gsm_network *net = gsmnet_from_vty(vty);
	int bts_nr;

	if (argc != 0) {
		/* use the BTS number that the user has specified */
		bts_nr = atoi(argv[0]);
		if (bts_nr >= net->num_bts) {
			vty_out(vty, "%% can't find BTS '%s'%s", argv[0],
				VTY_NEWLINE);
			return CMD_WARNING;
		}
		bts_dump_vty(vty, gsm_bts_num(net, bts_nr));
		return CMD_SUCCESS;
	}
	/* print all BTS's */
	for (bts_nr = 0; bts_nr < net->num_bts; bts_nr++)
		bts_dump_vty(vty, gsm_bts_num(net, bts_nr));

	return CMD_SUCCESS;
}

/* utility functions */
static void parse_e1_link(struct gsm_e1_subslot *e1_link, const char *line,
			  const char *ts, const char *ss)
{
	e1_link->e1_nr = atoi(line);
	e1_link->e1_ts = atoi(ts);
	if (!strcmp(ss, "full"))
		e1_link->e1_ts_ss = 255;
	else
		e1_link->e1_ts_ss = atoi(ss);
}

static void config_write_e1_link(struct vty *vty, struct gsm_e1_subslot *e1_link,
				 const char *prefix)
{
	if (!e1_link->e1_ts)
		return;

	if (e1_link->e1_ts_ss == 255)
		vty_out(vty, "%se1 line %u timeslot %u sub-slot full%s",
			prefix, e1_link->e1_nr, e1_link->e1_ts, VTY_NEWLINE);
	else
		vty_out(vty, "%se1 line %u timeslot %u sub-slot %u%s",
			prefix, e1_link->e1_nr, e1_link->e1_ts,
			e1_link->e1_ts_ss, VTY_NEWLINE);
}


static void config_write_ts_single(struct vty *vty, struct gsm_bts_trx_ts *ts)
{
	vty_out(vty, "   timeslot %u%s", ts->nr, VTY_NEWLINE);
	if (ts->tsc != -1)
		vty_out(vty, "    training_sequence_code %u%s", ts->tsc, VTY_NEWLINE);
	if (ts->pchan != GSM_PCHAN_NONE)
		vty_out(vty, "    phys_chan_config %s%s",
			gsm_pchan_name(ts->pchan), VTY_NEWLINE);
	vty_out(vty, "    hopping enabled %u%s",
		ts->hopping.enabled, VTY_NEWLINE);
	if (ts->hopping.enabled) {
		unsigned int i;
		vty_out(vty, "    hopping sequence-number %u%s",
			ts->hopping.hsn, VTY_NEWLINE);
		vty_out(vty, "    hopping maio %u%s",
			ts->hopping.maio, VTY_NEWLINE);
		for (i = 0; i < ts->hopping.arfcns.data_len*8; i++) {
			if (!bitvec_get_bit_pos(&ts->hopping.arfcns, i))
				continue;
			vty_out(vty, "    hopping arfcn add %u%s",
				i, VTY_NEWLINE);
		}
	}
	config_write_e1_link(vty, &ts->e1_link, "    ");

	if (ts->trx->bts->model->config_write_ts)
		ts->trx->bts->model->config_write_ts(vty, ts);
}

static void config_write_trx_single(struct vty *vty, struct gsm_bts_trx *trx)
{
	int i;

	vty_out(vty, "  trx %u%s", trx->nr, VTY_NEWLINE);
	if (trx->description)
		vty_out(vty, "   description %s%s", trx->description,
			VTY_NEWLINE);
	vty_out(vty, "   rf_locked %u%s",
		trx->mo.nm_state.administrative == NM_STATE_LOCKED ? 1 : 0,
		VTY_NEWLINE);
	vty_out(vty, "   arfcn %u%s", trx->arfcn, VTY_NEWLINE);
	vty_out(vty, "   nominal power %u%s", trx->nominal_power, VTY_NEWLINE);
	vty_out(vty, "   max_power_red %u%s", trx->max_power_red, VTY_NEWLINE);
	config_write_e1_link(vty, &trx->rsl_e1_link, "   rsl ");
	vty_out(vty, "   rsl e1 tei %u%s", trx->rsl_tei, VTY_NEWLINE);

	if (trx->bts->model->config_write_trx)
		trx->bts->model->config_write_trx(vty, trx);

	for (i = 0; i < TRX_NR_TS; i++)
		config_write_ts_single(vty, &trx->ts[i]);
}

static void config_write_bts_gprs(struct vty *vty, struct gsm_bts *bts)
{
	unsigned int i;
	vty_out(vty, "  gprs mode %s%s", bts_gprs_mode_name(bts->gprs.mode),
		VTY_NEWLINE);
	if (bts->gprs.mode == BTS_GPRS_NONE)
		return;

	vty_out(vty, "  gprs 11bit_rach_support_for_egprs %u%s",
		bts->gprs.supports_egprs_11bit_rach, VTY_NEWLINE);

	vty_out(vty, "  gprs routing area %u%s", bts->gprs.rac,
		VTY_NEWLINE);
	vty_out(vty, "  gprs network-control-order nc%u%s",
		bts->gprs.net_ctrl_ord, VTY_NEWLINE);
	if (!bts->gprs.ctrl_ack_type_use_block)
		vty_out(vty, "  gprs control-ack-type-rach%s", VTY_NEWLINE);
	vty_out(vty, "  gprs cell bvci %u%s", bts->gprs.cell.bvci,
		VTY_NEWLINE);
	for (i = 0; i < ARRAY_SIZE(bts->gprs.cell.timer); i++)
		vty_out(vty, "  gprs cell timer %s %u%s",
			get_value_string(gprs_bssgp_cfg_strs, i),
			bts->gprs.cell.timer[i], VTY_NEWLINE);
	vty_out(vty, "  gprs nsei %u%s", bts->gprs.nse.nsei,
		VTY_NEWLINE);
	for (i = 0; i < ARRAY_SIZE(bts->gprs.nse.timer); i++)
		vty_out(vty, "  gprs ns timer %s %u%s",
			get_value_string(gprs_ns_timer_strs, i),
			bts->gprs.nse.timer[i], VTY_NEWLINE);
	for (i = 0; i < ARRAY_SIZE(bts->gprs.nsvc); i++) {
		struct gsm_bts_gprs_nsvc *nsvc =
					&bts->gprs.nsvc[i];
		struct in_addr ia;

		ia.s_addr = htonl(nsvc->remote_ip);
		vty_out(vty, "  gprs nsvc %u nsvci %u%s", i,
			nsvc->nsvci, VTY_NEWLINE);
		vty_out(vty, "  gprs nsvc %u local udp port %u%s", i,
			nsvc->local_port, VTY_NEWLINE);
		vty_out(vty, "  gprs nsvc %u remote udp port %u%s", i,
			nsvc->remote_port, VTY_NEWLINE);
		vty_out(vty, "  gprs nsvc %u remote ip %s%s", i,
			inet_ntoa(ia), VTY_NEWLINE);
	}
}

/* Write the model data if there is one */
static void config_write_bts_model(struct vty *vty, struct gsm_bts *bts)
{
	struct gsm_bts_trx *trx;

	if (!bts->model)
		return;

	if (bts->model->config_write_bts)
		bts->model->config_write_bts(vty, bts);

	llist_for_each_entry(trx, &bts->trx_list, list)
		config_write_trx_single(vty, trx);
}

static void write_amr_modes(struct vty *vty, const char *prefix,
	const char *name, struct amr_mode *modes, int num)
{
	int i;

	vty_out(vty, "  %s threshold %s", prefix, name);
	for (i = 0; i < num - 1; i++)
		vty_out(vty, " %d", modes[i].threshold);
	vty_out(vty, "%s", VTY_NEWLINE);
	vty_out(vty, "  %s hysteresis %s", prefix, name);
	for (i = 0; i < num - 1; i++)
		vty_out(vty, " %d", modes[i].hysteresis);
	vty_out(vty, "%s", VTY_NEWLINE);
}

static void config_write_bts_amr(struct vty *vty, struct gsm_bts *bts,
	struct amr_multirate_conf *mr, int full)
{
	struct gsm48_multi_rate_conf *mr_conf;
	const char *prefix = (full) ? "amr tch-f" : "amr tch-h";
	int i, num;

	if (!(mr->gsm48_ie[1]))
		return;

	mr_conf = (struct gsm48_multi_rate_conf *) mr->gsm48_ie;

	num = 0;
	vty_out(vty, "  %s modes", prefix);
	for (i = 0; i < ((full) ? 8 : 6); i++) {
		if ((mr->gsm48_ie[1] & (1 << i))) {
			vty_out(vty, " %d", i);
			num++;
		}
	}
	vty_out(vty, "%s", VTY_NEWLINE);
	if (num > 4)
		num = 4;
	if (num > 1) {
		write_amr_modes(vty, prefix, "ms", mr->ms_mode, num);
		write_amr_modes(vty, prefix, "bts", mr->bts_mode, num);
	}
	vty_out(vty, "  %s start-mode ", prefix);
	if (mr_conf->icmi) {
		num = 0;
		for (i = 0; i < ((full) ? 8 : 6) && num < 4; i++) {
			if ((mr->gsm48_ie[1] & (1 << i)))
				num++;
			if (mr_conf->smod == num - 1) {
				vty_out(vty, "%d%s", num, VTY_NEWLINE);
				break;
			}
		}
	} else
		vty_out(vty, "auto%s", VTY_NEWLINE);
}

static void config_write_bts_single(struct vty *vty, struct gsm_bts *bts)
{
	int i;
	uint8_t tmp;

	vty_out(vty, " bts %u%s", bts->nr, VTY_NEWLINE);
	vty_out(vty, "  type %s%s", btstype2str(bts->type), VTY_NEWLINE);
	if (bts->description)
		vty_out(vty, "  description %s%s", bts->description, VTY_NEWLINE);
	vty_out(vty, "  band %s%s", gsm_band_name(bts->band), VTY_NEWLINE);
	vty_out(vty, "  cell_identity %u%s", bts->cell_identity, VTY_NEWLINE);
	vty_out(vty, "  location_area_code %u%s", bts->location_area_code,
		VTY_NEWLINE);
	if (bts->dtxu != GSM48_DTX_SHALL_NOT_BE_USED)
		vty_out(vty, "  dtx uplink%s%s",
			(bts->dtxu != GSM48_DTX_SHALL_BE_USED) ? "" : " force",
			VTY_NEWLINE);
	if (bts->dtxd)
		vty_out(vty, "  dtx downlink%s", VTY_NEWLINE);
	vty_out(vty, "  base_station_id_code %u%s", bts->bsic, VTY_NEWLINE);
	vty_out(vty, "  ms max power %u%s", bts->ms_max_power, VTY_NEWLINE);
	vty_out(vty, "  cell reselection hysteresis %u%s",
		bts->si_common.cell_sel_par.cell_resel_hyst*2, VTY_NEWLINE);
	vty_out(vty, "  rxlev access min %u%s",
		bts->si_common.cell_sel_par.rxlev_acc_min, VTY_NEWLINE);

	if (bts->si_common.cell_ro_sel_par.present) {
		struct gsm48_si_selection_params *sp;
		sp = &bts->si_common.cell_ro_sel_par;

		if (sp->cbq)
			vty_out(vty, "  cell bar qualify %u%s",
				sp->cbq, VTY_NEWLINE);

		if (sp->cell_resel_off)
			vty_out(vty, "  cell reselection offset %u%s",
				sp->cell_resel_off*2, VTY_NEWLINE);

		if (sp->temp_offs == 7)
			vty_out(vty, "  temporary offset infinite%s",
				VTY_NEWLINE);
		else if (sp->temp_offs)
			vty_out(vty, "  temporary offset %u%s",
				sp->temp_offs*10, VTY_NEWLINE);

		if (sp->penalty_time == 31)
			vty_out(vty, "  penalty time reserved%s",
				VTY_NEWLINE);
		else if (sp->penalty_time)
			vty_out(vty, "  penalty time %u%s",
				(sp->penalty_time*20)+20, VTY_NEWLINE);
	}

	/* Is periodic LU enabled or disabled? */
	if (bts->si_common.chan_desc.t3212 == 0)
		vty_out(vty, "  no periodic location update%s", VTY_NEWLINE);
	else
		vty_out(vty, "  periodic location update %u%s",
			bts->si_common.chan_desc.t3212 * 6, VTY_NEWLINE);

	if (gsm_bts_get_radio_link_timeout(bts) < 0)
		vty_out(vty, "  radio-link-timeout infinite%s", VTY_NEWLINE);
	else
		vty_out(vty, "  radio-link-timeout %d%s",
			gsm_bts_get_radio_link_timeout(bts), VTY_NEWLINE);
	vty_out(vty, "  channel allocator %s%s",
		bts->chan_alloc_reverse ? "descending" : "ascending",
		VTY_NEWLINE);
	vty_out(vty, "  rach tx integer %u%s",
		bts->si_common.rach_control.tx_integer, VTY_NEWLINE);
	vty_out(vty, "  rach max transmission %u%s",
		rach_max_trans_raw2val(bts->si_common.rach_control.max_trans),
		VTY_NEWLINE);

	vty_out(vty, "  channel-descrption attach %u%s",
		bts->si_common.chan_desc.att, VTY_NEWLINE);
	vty_out(vty, "  channel-descrption bs-pa-mfrms %u%s",
		bts->si_common.chan_desc.bs_pa_mfrms + 2, VTY_NEWLINE);
	vty_out(vty, "  channel-descrption bs-ag-blks-res %u%s",
		bts->si_common.chan_desc.bs_ag_blks_res, VTY_NEWLINE);

	if (bts->rach_b_thresh != -1)
		vty_out(vty, "  rach nm busy threshold %u%s",
			bts->rach_b_thresh, VTY_NEWLINE);
	if (bts->rach_ldavg_slots != -1)
		vty_out(vty, "  rach nm load average %u%s",
			bts->rach_ldavg_slots, VTY_NEWLINE);
	if (bts->si_common.rach_control.cell_bar)
		vty_out(vty, "  cell barred 1%s", VTY_NEWLINE);
	if ((bts->si_common.rach_control.t2 & 0x4) == 0)
		vty_out(vty, "  rach emergency call allowed 1%s", VTY_NEWLINE);
	if ((bts->si_common.rach_control.t3) != 0)
		for (i = 0; i < 8; i++)
			if (bts->si_common.rach_control.t3 & (0x1 << i))
				vty_out(vty, "  rach access-control-class %d barred%s", i, VTY_NEWLINE);
	if ((bts->si_common.rach_control.t2 & 0xfb) != 0)
		for (i = 0; i < 8; i++)
			if ((i != 2) && (bts->si_common.rach_control.t2 & (0x1 << i)))
				vty_out(vty, "  rach access-control-class %d barred%s", i+8, VTY_NEWLINE);
	for (i = SYSINFO_TYPE_1; i < _MAX_SYSINFO_TYPE; i++) {
		if (bts->si_mode_static & (1 << i)) {
			vty_out(vty, "  system-information %s mode static%s",
				get_value_string(osmo_sitype_strs, i), VTY_NEWLINE);
			vty_out(vty, "  system-information %s static %s%s",
				get_value_string(osmo_sitype_strs, i),
				osmo_hexdump_nospc(GSM_BTS_SI(bts, i), GSM_MACBLOCK_LEN),
				VTY_NEWLINE);
		}
	}
	vty_out(vty, "  early-classmark-sending %s%s",
		bts->early_classmark_allowed ? "allowed" : "forbidden", VTY_NEWLINE);
	switch (bts->type) {
	case GSM_BTS_TYPE_NANOBTS:
	case GSM_BTS_TYPE_OSMOBTS:
		vty_out(vty, "  ip.access unit_id %u %u%s",
			bts->ip_access.site_id, bts->ip_access.bts_id, VTY_NEWLINE);
		if (bts->ip_access.rsl_ip) {
			struct in_addr ia;
			ia.s_addr = htonl(bts->ip_access.rsl_ip);
			vty_out(vty, "  ip.access rsl-ip %s%s", inet_ntoa(ia),
				VTY_NEWLINE);
		}
		vty_out(vty, "  oml ip.access stream_id %u line %u%s",
			bts->oml_tei, bts->oml_e1_link.e1_nr, VTY_NEWLINE);
		break;
	case GSM_BTS_TYPE_NOKIA_SITE:
		vty_out(vty, "  nokia_site skip-reset %d%s", bts->nokia.skip_reset, VTY_NEWLINE);
		vty_out(vty, "  nokia_site no-local-rel-conf %d%s",
			bts->nokia.no_loc_rel_cnf, VTY_NEWLINE);
		vty_out(vty, "  nokia_site bts-reset-timer %d%s", bts->nokia.bts_reset_timer_cnf, VTY_NEWLINE);
		/* fall through: Nokia requires "oml e1" parameters also */
	default:
		config_write_e1_link(vty, &bts->oml_e1_link, "  oml ");
		vty_out(vty, "  oml e1 tei %u%s", bts->oml_tei, VTY_NEWLINE);
		break;
	}

	/* if we have a limit, write it */
	if (bts->paging.free_chans_need >= 0)
		vty_out(vty, "  paging free %d%s", bts->paging.free_chans_need, VTY_NEWLINE);

	vty_out(vty, "  neighbor-list mode %s%s",
		get_value_string(bts_neigh_mode_strs, bts->neigh_list_manual_mode), VTY_NEWLINE);
	if (bts->neigh_list_manual_mode != NL_MODE_AUTOMATIC) {
		for (i = 0; i < 1024; i++) {
			if (bitvec_get_bit_pos(&bts->si_common.neigh_list, i))
				vty_out(vty, "  neighbor-list add arfcn %u%s",
					i, VTY_NEWLINE);
		}
	}
	if (bts->neigh_list_manual_mode == NL_MODE_MANUAL_SI5SEP) {
		for (i = 0; i < 1024; i++) {
			if (bitvec_get_bit_pos(&bts->si_common.si5_neigh_list, i))
				vty_out(vty, "  si5 neighbor-list add arfcn %u%s",
					i, VTY_NEWLINE);
		}
	}

	for (i = 0; i < MAX_EARFCN_LIST; i++) {
		struct osmo_earfcn_si2q *e = &bts->si_common.si2quater_neigh_list;
		if (e->arfcn[i] != OSMO_EARFCN_INVALID) {
			vty_out(vty, "  si2quater neighbor-list add earfcn %u "
				"thresh-hi %u", e->arfcn[i], e->thresh_hi);

			vty_out(vty, " thresh-lo %u",
				e->thresh_lo_valid ? e->thresh_lo : 32);

			vty_out(vty, " prio %u",
				e->prio_valid ? e->prio : 8);

			vty_out(vty, " qrxlv %u",
				e->qrxlm_valid ? e->qrxlm : 32);

			tmp = e->meas_bw[i];
			vty_out(vty, " meas %u",
				(tmp != OSMO_EARFCN_MEAS_INVALID) ? tmp : 8);

			vty_out(vty, "%s", VTY_NEWLINE);
		}
	}

	for (i = 0; i < bts->si_common.uarfcn_length; i++) {
		vty_out(vty, "  si2quater neighbor-list add uarfcn %u %u %u%s",
			bts->si_common.data.uarfcn_list[i],
			bts->si_common.data.scramble_list[i] & ~(1 << 9),
			(bts->si_common.data.scramble_list[i] >> 9) & 1,
			VTY_NEWLINE);
	}

	vty_out(vty, "  codec-support fr");
	if (bts->codec.hr)
		vty_out(vty, " hr");
	if (bts->codec.efr)
		vty_out(vty, " efr");
	if (bts->codec.amr)
		vty_out(vty, " amr");
	vty_out(vty, "%s", VTY_NEWLINE);

	config_write_bts_amr(vty, bts, &bts->mr_full, 1);
	config_write_bts_amr(vty, bts, &bts->mr_half, 0);

	config_write_bts_gprs(vty, bts);

	if (bts->excl_from_rf_lock)
		vty_out(vty, "  rf-lock-exclude%s", VTY_NEWLINE);

	vty_out(vty, "  %sforce-combined-si%s",
		bts->force_combined_si ? "" : "no ", VTY_NEWLINE);

	for (i = 0; i < ARRAY_SIZE(bts->depends_on); ++i) {
		int j;

		if (bts->depends_on[i] == 0)
			continue;

		for (j = 0; j < sizeof(bts->depends_on[i]) * 8; ++j) {
			int bts_nr;

			if ((bts->depends_on[i] & (1<<j)) == 0)
				continue;

			bts_nr = (i * sizeof(bts->depends_on[i]) * 8) + j;
			vty_out(vty, "  depends-on-bts %d%s", bts_nr, VTY_NEWLINE);
		}
	}
	if (bts->pcu_sock_path)
		vty_out(vty, "  pcu-socket %s%s", bts->pcu_sock_path, VTY_NEWLINE);

	config_write_bts_model(vty, bts);
}

static int config_write_bts(struct vty *v)
{
	struct gsm_network *gsmnet = gsmnet_from_vty(v);
	struct gsm_bts *bts;

	llist_for_each_entry(bts, &gsmnet->bts_list, list)
		config_write_bts_single(v, bts);

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
	if (gsmnet->authorized_reg_str)
		vty_out(vty, " authorized-regexp %s%s", gsmnet->authorized_reg_str, VTY_NEWLINE);
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
	vty_out(vty, " dyn_ts_allow_tch_f %d%s",
		gsmnet->dyn_ts_allow_tch_f ? 1 : 0, VTY_NEWLINE);
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

	return CMD_SUCCESS;
}

static void trx_dump_vty(struct vty *vty, struct gsm_bts_trx *trx)
{
	vty_out(vty, "TRX %u of BTS %u is on ARFCN %u%s",
		trx->nr, trx->bts->nr, trx->arfcn, VTY_NEWLINE);
	vty_out(vty, "Description: %s%s",
		trx->description ? trx->description : "(null)", VTY_NEWLINE);
	vty_out(vty, "  RF Nominal Power: %d dBm, reduced by %u dB, "
		"resulting BS power: %d dBm%s",
		trx->nominal_power, trx->max_power_red,
		trx->nominal_power - trx->max_power_red, VTY_NEWLINE);
	vty_out(vty, "  NM State: ");
	net_dump_nmstate(vty, &trx->mo.nm_state);
	vty_out(vty, "  Baseband Transceiver NM State: ");
	net_dump_nmstate(vty, &trx->bb_transc.mo.nm_state);
	if (is_ipaccess_bts(trx->bts)) {
		vty_out(vty, "  ip.access stream ID: 0x%02x%s",
			trx->rsl_tei, VTY_NEWLINE);
	} else {
		vty_out(vty, "  E1 Signalling Link:%s", VTY_NEWLINE);
		e1isl_dump_vty(vty, trx->rsl_link);
	}
}

DEFUN(show_trx,
      show_trx_cmd,
      "show trx [<0-255>] [<0-255>]",
	SHOW_STR "Display information about a TRX\n"
	"BTS Number\n"
	"TRX Number\n")
{
	struct gsm_network *net = gsmnet_from_vty(vty);
	struct gsm_bts *bts = NULL;
	struct gsm_bts_trx *trx;
	int bts_nr, trx_nr;

	if (argc >= 1) {
		/* use the BTS number that the user has specified */
		bts_nr = atoi(argv[0]);
		if (bts_nr >= net->num_bts) {
			vty_out(vty, "%% can't find BTS '%s'%s", argv[0],
				VTY_NEWLINE);
			return CMD_WARNING;
		}
		bts = gsm_bts_num(net, bts_nr);
	}
	if (argc >= 2) {
		trx_nr = atoi(argv[1]);
		if (trx_nr >= bts->num_trx) {
			vty_out(vty, "%% can't find TRX '%s'%s", argv[1],
				VTY_NEWLINE);
			return CMD_WARNING;
		}
		trx = gsm_bts_trx_num(bts, trx_nr);
		trx_dump_vty(vty, trx);
		return CMD_SUCCESS;
	}
	if (bts) {
		/* print all TRX in this BTS */
		for (trx_nr = 0; trx_nr < bts->num_trx; trx_nr++) {
			trx = gsm_bts_trx_num(bts, trx_nr);
			trx_dump_vty(vty, trx);
		}
		return CMD_SUCCESS;
	}

	for (bts_nr = 0; bts_nr < net->num_bts; bts_nr++) {
		bts = gsm_bts_num(net, bts_nr);
		for (trx_nr = 0; trx_nr < bts->num_trx; trx_nr++) {
			trx = gsm_bts_trx_num(bts, trx_nr);
			trx_dump_vty(vty, trx);
		}
	}

	return CMD_SUCCESS;
}


static void ts_dump_vty(struct vty *vty, struct gsm_bts_trx_ts *ts)
{
	vty_out(vty, "BTS %u, TRX %u, Timeslot %u, phys cfg %s, TSC %u",
		ts->trx->bts->nr, ts->trx->nr, ts->nr,
		gsm_pchan_name(ts->pchan), gsm_ts_tsc(ts));
	if (ts->pchan == GSM_PCHAN_TCH_F_PDCH)
		vty_out(vty, " (%s mode)",
			ts->flags & TS_F_PDCH_ACTIVE ? "PDCH" : "TCH/F");
	vty_out(vty, "%s", VTY_NEWLINE);
	vty_out(vty, "  NM State: ");
	net_dump_nmstate(vty, &ts->mo.nm_state);
	if (!is_ipaccess_bts(ts->trx->bts))
		vty_out(vty, "  E1 Line %u, Timeslot %u, Subslot %u%s",
			ts->e1_link.e1_nr, ts->e1_link.e1_ts,
			ts->e1_link.e1_ts_ss, VTY_NEWLINE);
}

DEFUN(show_ts,
      show_ts_cmd,
      "show timeslot [<0-255>] [<0-255>] [<0-7>]",
	SHOW_STR "Display information about a TS\n"
	"BTS Number\n" "TRX Number\n" "Timeslot Number\n")
{
	struct gsm_network *net = gsmnet_from_vty(vty);
	struct gsm_bts *bts = NULL;
	struct gsm_bts_trx *trx = NULL;
	struct gsm_bts_trx_ts *ts = NULL;
	int bts_nr, trx_nr, ts_nr;

	if (argc >= 1) {
		/* use the BTS number that the user has specified */
		bts_nr = atoi(argv[0]);
		if (bts_nr >= net->num_bts) {
			vty_out(vty, "%% can't find BTS '%s'%s", argv[0],
				VTY_NEWLINE);
			return CMD_WARNING;
		}
		bts = gsm_bts_num(net, bts_nr);
	}
	if (argc >= 2) {
		trx_nr = atoi(argv[1]);
		if (trx_nr >= bts->num_trx) {
			vty_out(vty, "%% can't find TRX '%s'%s", argv[1],
				VTY_NEWLINE);
			return CMD_WARNING;
		}
		trx = gsm_bts_trx_num(bts, trx_nr);
	}
	if (argc >= 3) {
		ts_nr = atoi(argv[2]);
		if (ts_nr >= TRX_NR_TS) {
			vty_out(vty, "%% can't find TS '%s'%s", argv[2],
				VTY_NEWLINE);
			return CMD_WARNING;
		}
		/* Fully Specified: print and exit */
		ts = &trx->ts[ts_nr];
		ts_dump_vty(vty, ts);
		return CMD_SUCCESS;
	}

	if (bts && trx) {
		/* Iterate over all TS in this TRX */
		for (ts_nr = 0; ts_nr < TRX_NR_TS; ts_nr++) {
			ts = &trx->ts[ts_nr];
			ts_dump_vty(vty, ts);
		}
	} else if (bts) {
		/* Iterate over all TRX in this BTS, TS in each TRX */
		for (trx_nr = 0; trx_nr < bts->num_trx; trx_nr++) {
			trx = gsm_bts_trx_num(bts, trx_nr);
			for (ts_nr = 0; ts_nr < TRX_NR_TS; ts_nr++) {
				ts = &trx->ts[ts_nr];
				ts_dump_vty(vty, ts);
			}
		}
	} else {
		/* Iterate over all BTS, TRX in each BTS, TS in each TRX */
		for (bts_nr = 0; bts_nr < net->num_bts; bts_nr++) {
			bts = gsm_bts_num(net, bts_nr);
			for (trx_nr = 0; trx_nr < bts->num_trx; trx_nr++) {
				trx = gsm_bts_trx_num(bts, trx_nr);
				for (ts_nr = 0; ts_nr < TRX_NR_TS; ts_nr++) {
					ts = &trx->ts[ts_nr];
					ts_dump_vty(vty, ts);
				}
			}
		}
	}

	return CMD_SUCCESS;
}

static void subscr_dump_vty(struct vty *vty, struct gsm_subscriber *subscr)
{
	vty_out(vty, "    ID: %llu, Authorized: %d%s", subscr->id,
		subscr->authorized, VTY_NEWLINE);
	if (strlen(subscr->name))
		vty_out(vty, "    Name: '%s'%s", subscr->name, VTY_NEWLINE);
	if (strlen(subscr->extension))
		vty_out(vty, "    Extension: %s%s", subscr->extension,
			VTY_NEWLINE);
	vty_out(vty, "    IMSI: %s%s", subscr->imsi, VTY_NEWLINE);
	if (subscr->tmsi != GSM_RESERVED_TMSI)
		vty_out(vty, "    TMSI: %08X%s", subscr->tmsi,
			VTY_NEWLINE);

	vty_out(vty, "    Use count: %u%s", subscr->use_count, VTY_NEWLINE);
}

static void bsc_subscr_dump_vty(struct vty *vty, struct bsc_subscr *bsub)
{
	if (strlen(bsub->imsi))
		vty_out(vty, "    IMSI: %s%s", bsub->imsi, VTY_NEWLINE);
	if (bsub->tmsi != GSM_RESERVED_TMSI)
		vty_out(vty, "    TMSI: 0x%08x%s", bsub->tmsi,
			VTY_NEWLINE);
	vty_out(vty, "    Use count: %d%s", bsub->use_count, VTY_NEWLINE);
}

static void meas_rep_dump_uni_vty(struct vty *vty,
				  struct gsm_meas_rep_unidir *mru,
				  const char *prefix,
				  const char *dir)
{
	vty_out(vty, "%s  RXL-FULL-%s: %4d dBm, RXL-SUB-%s: %4d dBm ",
		prefix, dir, rxlev2dbm(mru->full.rx_lev),
			dir, rxlev2dbm(mru->sub.rx_lev));
	vty_out(vty, "RXQ-FULL-%s: %d, RXQ-SUB-%s: %d%s",
		dir, mru->full.rx_qual, dir, mru->sub.rx_qual,
		VTY_NEWLINE);
}

static void meas_rep_dump_vty(struct vty *vty, struct gsm_meas_rep *mr,
			      const char *prefix)
{
	vty_out(vty, "%sMeasurement Report:%s", prefix, VTY_NEWLINE);
	vty_out(vty, "%s  Flags: %s%s%s%s%s", prefix,
			mr->flags & MEAS_REP_F_UL_DTX ? "DTXu " : "",
			mr->flags & MEAS_REP_F_DL_DTX ? "DTXd " : "",
			mr->flags & MEAS_REP_F_FPC ? "FPC " : "",
			mr->flags & MEAS_REP_F_DL_VALID ? " " : "DLinval ",
			VTY_NEWLINE);
	if (mr->flags & MEAS_REP_F_MS_TO)
		vty_out(vty, "%s  MS Timing Offset: %d%s", prefix, mr->ms_timing_offset, VTY_NEWLINE);
	if (mr->flags & MEAS_REP_F_MS_L1)
		vty_out(vty, "%s  L1 MS Power: %u dBm, Timing Advance: %u%s",
			prefix, mr->ms_l1.pwr, mr->ms_l1.ta, VTY_NEWLINE);
	if (mr->flags & MEAS_REP_F_DL_VALID)
		meas_rep_dump_uni_vty(vty, &mr->dl, prefix, "dl");
	meas_rep_dump_uni_vty(vty, &mr->ul, prefix, "ul");
}

/* FIXME: move this to libosmogsm */
static const struct value_string gsm48_cmode_names[] = {
	{ GSM48_CMODE_SIGN,		"signalling" },
	{ GSM48_CMODE_SPEECH_V1,	"FR or HR" },
	{ GSM48_CMODE_SPEECH_EFR,	"EFR" },
	{ GSM48_CMODE_SPEECH_AMR,	"AMR" },
	{ GSM48_CMODE_DATA_14k5,	"CSD(14k5)" },
	{ GSM48_CMODE_DATA_12k0,	"CSD(12k0)" },
	{ GSM48_CMODE_DATA_6k0,		"CSD(6k0)" },
	{ GSM48_CMODE_DATA_3k6,		"CSD(3k6)" },
	{ 0, NULL }
};

/* call vty_out() to print a string like " as TCH/H" for dynamic timeslots.
 * Don't do anything if the ts is not dynamic. */
static void vty_out_dyn_ts_status(struct vty *vty, struct gsm_bts_trx_ts *ts)
{
	switch (ts->pchan) {
	case GSM_PCHAN_TCH_F_TCH_H_PDCH:
		if (ts->dyn.pchan_is == ts->dyn.pchan_want)
			vty_out(vty, " as %s",
				gsm_pchan_name(ts->dyn.pchan_is));
		else
			vty_out(vty, " switching %s -> %s",
				gsm_pchan_name(ts->dyn.pchan_is),
				gsm_pchan_name(ts->dyn.pchan_want));
		break;
	case GSM_PCHAN_TCH_F_PDCH:
		if ((ts->flags & TS_F_PDCH_PENDING_MASK) == 0)
			vty_out(vty, " as %s",
				(ts->flags & TS_F_PDCH_ACTIVE)? "PDCH"
							      : "TCH/F");
		else
			vty_out(vty, " switching %s -> %s",
				(ts->flags & TS_F_PDCH_ACTIVE)? "PDCH"
							      : "TCH/F",
				(ts->flags & TS_F_PDCH_ACT_PENDING)? "PDCH"
								   : "TCH/F");
		break;
	default:
		/* no dyn ts */
		break;
	}
}

static void lchan_dump_full_vty(struct vty *vty, struct gsm_lchan *lchan)
{
	int idx;

	vty_out(vty, "BTS %u, TRX %u, Timeslot %u, Lchan %u: Type %s%s",
		lchan->ts->trx->bts->nr, lchan->ts->trx->nr, lchan->ts->nr,
		lchan->nr, gsm_lchant_name(lchan->type), VTY_NEWLINE);
	/* show dyn TS details, if applicable */
	switch (lchan->ts->pchan) {
	case GSM_PCHAN_TCH_F_TCH_H_PDCH:
		vty_out(vty, "  Osmocom Dyn TS:");
		vty_out_dyn_ts_status(vty, lchan->ts);
		vty_out(vty, VTY_NEWLINE);
		break;
	case GSM_PCHAN_TCH_F_PDCH:
		vty_out(vty, "  IPACC Dyn PDCH TS:");
		vty_out_dyn_ts_status(vty, lchan->ts);
		vty_out(vty, VTY_NEWLINE);
		break;
	default:
		/* no dyn ts */
		break;
	}
	vty_out(vty, "  Connection: %u, State: %s%s%s%s",
		lchan->conn ? 1: 0,
		gsm_lchans_name(lchan->state),
		lchan->state == LCHAN_S_BROKEN ? " Error reason: " : "",
		lchan->state == LCHAN_S_BROKEN ? lchan->broken_reason : "",
		VTY_NEWLINE);
	vty_out(vty, "  BS Power: %u dBm, MS Power: %u dBm%s",
		lchan->ts->trx->nominal_power - lchan->ts->trx->max_power_red
		- lchan->bs_power*2,
		ms_pwr_dbm(lchan->ts->trx->bts->band, lchan->ms_power),
		VTY_NEWLINE);
	vty_out(vty, "  Channel Mode / Codec: %s%s",
		get_value_string(gsm48_cmode_names, lchan->tch_mode),
		VTY_NEWLINE);
	if (lchan->conn && lchan->conn->subscr) {
		vty_out(vty, "  Subscriber:%s", VTY_NEWLINE);
		subscr_dump_vty(vty, lchan->conn->subscr);
	} else
		vty_out(vty, "  No Subscriber%s", VTY_NEWLINE);
	if (is_ipaccess_bts(lchan->ts->trx->bts)) {
		struct in_addr ia;
		ia.s_addr = htonl(lchan->abis_ip.bound_ip);
		vty_out(vty, "  Bound IP: %s Port %u RTP_TYPE2=%u CONN_ID=%u%s",
			inet_ntoa(ia), lchan->abis_ip.bound_port,
			lchan->abis_ip.rtp_payload2, lchan->abis_ip.conn_id,
			VTY_NEWLINE);
	}

	/* we want to report the last measurement report */
	idx = calc_initial_idx(ARRAY_SIZE(lchan->meas_rep),
			       lchan->meas_rep_idx, 1);
	meas_rep_dump_vty(vty, &lchan->meas_rep[idx], "  ");
}

static void lchan_dump_short_vty(struct vty *vty, struct gsm_lchan *lchan)
{
	struct gsm_meas_rep *mr;
	int idx;

	/* we want to report the last measurement report */
	idx = calc_initial_idx(ARRAY_SIZE(lchan->meas_rep),
			       lchan->meas_rep_idx, 1);
	mr =  &lchan->meas_rep[idx];

	vty_out(vty, "BTS %u, TRX %u, Timeslot %u %s",
		lchan->ts->trx->bts->nr, lchan->ts->trx->nr, lchan->ts->nr,
		gsm_pchan_name(lchan->ts->pchan));
	vty_out_dyn_ts_status(vty, lchan->ts);
	vty_out(vty, ", Lchan %u, Type %s, State %s - "
		"L1 MS Power: %u dBm RXL-FULL-dl: %4d dBm RXL-FULL-ul: %4d dBm%s",
		lchan->nr,
		gsm_lchant_name(lchan->type), gsm_lchans_name(lchan->state),
		mr->ms_l1.pwr,
		rxlev2dbm(mr->dl.full.rx_lev),
		rxlev2dbm(mr->ul.full.rx_lev),
		VTY_NEWLINE);
}


static int dump_lchan_trx_ts(struct gsm_bts_trx_ts *ts, struct vty *vty,
			     void (*dump_cb)(struct vty *, struct gsm_lchan *))
{
	int lchan_nr;
	for (lchan_nr = 0; lchan_nr < TS_MAX_LCHAN; lchan_nr++) {
		struct gsm_lchan *lchan = &ts->lchan[lchan_nr];
		if ((lchan->type == GSM_LCHAN_NONE) && (lchan->state == LCHAN_S_NONE))
			continue;
		dump_cb(vty, lchan);
	}

	return CMD_SUCCESS;
}

static int dump_lchan_trx(struct gsm_bts_trx *trx, struct vty *vty,
			  void (*dump_cb)(struct vty *, struct gsm_lchan *))
{
	int ts_nr;

	for (ts_nr = 0; ts_nr < TRX_NR_TS; ts_nr++) {
		struct gsm_bts_trx_ts *ts = &trx->ts[ts_nr];
		dump_lchan_trx_ts(ts, vty, dump_cb);
	}

	return CMD_SUCCESS;
}

static int dump_lchan_bts(struct gsm_bts *bts, struct vty *vty,
			  void (*dump_cb)(struct vty *, struct gsm_lchan *))
{
	int trx_nr;

	for (trx_nr = 0; trx_nr < bts->num_trx; trx_nr++) {
		struct gsm_bts_trx *trx = gsm_bts_trx_num(bts, trx_nr);
		dump_lchan_trx(trx, vty, dump_cb);
	}

	return CMD_SUCCESS;
}

static int lchan_summary(struct vty *vty, int argc, const char **argv,
			 void (*dump_cb)(struct vty *, struct gsm_lchan *))
{
	struct gsm_network *net = gsmnet_from_vty(vty);
	struct gsm_bts *bts;
	struct gsm_bts_trx *trx;
	struct gsm_bts_trx_ts *ts;
	struct gsm_lchan *lchan;
	int bts_nr, trx_nr, ts_nr, lchan_nr;

	if (argc >= 1) {
		/* use the BTS number that the user has specified */
		bts_nr = atoi(argv[0]);
		if (bts_nr >= net->num_bts) {
			vty_out(vty, "%% can't find BTS %s%s", argv[0],
				VTY_NEWLINE);
			return CMD_WARNING;
		}
		bts = gsm_bts_num(net, bts_nr);

		if (argc == 1)
			return dump_lchan_bts(bts, vty, dump_cb);
	}
	if (argc >= 2) {
		trx_nr = atoi(argv[1]);
		if (trx_nr >= bts->num_trx) {
			vty_out(vty, "%% can't find TRX %s%s", argv[1],
				VTY_NEWLINE);
			return CMD_WARNING;
		}
		trx = gsm_bts_trx_num(bts, trx_nr);

		if (argc == 2)
			return dump_lchan_trx(trx, vty, dump_cb);
	}
	if (argc >= 3) {
		ts_nr = atoi(argv[2]);
		if (ts_nr >= TRX_NR_TS) {
			vty_out(vty, "%% can't find TS %s%s", argv[2],
				VTY_NEWLINE);
			return CMD_WARNING;
		}
		ts = &trx->ts[ts_nr];

		if (argc == 3)
			return dump_lchan_trx_ts(ts, vty, dump_cb);
	}
	if (argc >= 4) {
		lchan_nr = atoi(argv[3]);
		if (lchan_nr >= TS_MAX_LCHAN) {
			vty_out(vty, "%% can't find LCHAN %s%s", argv[3],
				VTY_NEWLINE);
			return CMD_WARNING;
		}
		lchan = &ts->lchan[lchan_nr];
		dump_cb(vty, lchan);
		return CMD_SUCCESS;
	}


	for (bts_nr = 0; bts_nr < net->num_bts; bts_nr++) {
		bts = gsm_bts_num(net, bts_nr);
		dump_lchan_bts(bts, vty, dump_cb);
	}

	return CMD_SUCCESS;
}


DEFUN(show_lchan,
      show_lchan_cmd,
      "show lchan [<0-255>] [<0-255>] [<0-7>] [lchan_nr]",
	SHOW_STR "Display information about a logical channel\n"
	"BTS Number\n" "TRX Number\n" "Timeslot Number\n"
	LCHAN_NR_STR)

{
	return lchan_summary(vty, argc, argv, lchan_dump_full_vty);
}

DEFUN(show_lchan_summary,
      show_lchan_summary_cmd,
      "show lchan summary [<0-255>] [<0-255>] [<0-7>] [lchan_nr]",
	SHOW_STR "Display information about a logical channel\n"
        "Short summary\n"
	"BTS Number\n" "TRX Number\n" "Timeslot Number\n"
        LCHAN_NR_STR)
{
	return lchan_summary(vty, argc, argv, lchan_dump_short_vty);
}

static void paging_dump_vty(struct vty *vty, struct gsm_paging_request *pag)
{
	vty_out(vty, "Paging on BTS %u%s", pag->bts->nr, VTY_NEWLINE);
	bsc_subscr_dump_vty(vty, pag->bsub);
}

static void bts_paging_dump_vty(struct vty *vty, struct gsm_bts *bts)
{
	struct gsm_paging_request *pag;

	if (!bts->paging.bts)
		return;

	llist_for_each_entry(pag, &bts->paging.pending_requests, entry)
		paging_dump_vty(vty, pag);
}

DEFUN(show_paging,
      show_paging_cmd,
      "show paging [<0-255>]",
	SHOW_STR "Display information about paging reuqests of a BTS\n"
	"BTS Number\n")
{
	struct gsm_network *net = gsmnet_from_vty(vty);
	struct gsm_bts *bts;
	int bts_nr;

	if (argc >= 1) {
		/* use the BTS number that the user has specified */
		bts_nr = atoi(argv[0]);
		if (bts_nr >= net->num_bts) {
			vty_out(vty, "%% can't find BTS %s%s", argv[0],
				VTY_NEWLINE);
			return CMD_WARNING;
		}
		bts = gsm_bts_num(net, bts_nr);
		bts_paging_dump_vty(vty, bts);
		
		return CMD_SUCCESS;
	}
	for (bts_nr = 0; bts_nr < net->num_bts; bts_nr++) {
		bts = gsm_bts_num(net, bts_nr);
		bts_paging_dump_vty(vty, bts);
	}

	return CMD_SUCCESS;
}

DEFUN(show_paging_group,
      show_paging_group_cmd,
      "show paging-group <0-255> IMSI",
      SHOW_STR "Display the paging group\n"
      "BTS Number\n" "IMSI\n")
{
	struct gsm_network *net = gsmnet_from_vty(vty);
	struct gsm_bts *bts;
	unsigned int page_group;
	int bts_nr = atoi(argv[0]);

	if (bts_nr >= net->num_bts) {
		vty_out(vty, "%% can't find BTS %s%s", argv[0], VTY_NEWLINE);
		return CMD_WARNING;
	}

	bts = gsm_bts_num(net, bts_nr);
	if (!bts) {
		vty_out(vty, "%% can't find BTS %s%s", argv[0], VTY_NEWLINE);
		return CMD_WARNING;
	}

	page_group = gsm0502_calc_paging_group(&bts->si_common.chan_desc,
						str_to_imsi(argv[1]));
	vty_out(vty, "%%Paging group for IMSI %" PRIu64 " on BTS #%d is %u%s",
		str_to_imsi(argv[1]), bts->nr,
		page_group, VTY_NEWLINE);
	return CMD_SUCCESS;
}

DEFUN(cfg_net_neci,
      cfg_net_neci_cmd,
      "neci (0|1)",
	"New Establish Cause Indication\n"
	"Don't set the NECI bit\n" "Set the NECI bit\n")
{
	struct gsm_network *gsmnet = gsmnet_from_vty(vty);

	gsmnet->neci = atoi(argv[0]);
	gsm_net_update_ctype(gsmnet);
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

	if (enable && ipacc_rtp_direct) {
		vty_out(vty, "%% Cannot enable handover unless RTP Proxy mode "
			"is enabled by using the -P command line option%s",
			VTY_NEWLINE);
		return CMD_WARNING;
	}
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

DEFUN(cfg_net_pag_any_tch,
      cfg_net_pag_any_tch_cmd,
      "paging any use tch (0|1)",
      "Assign a TCH when receiving a Paging Any request\n"
      "Any Channel\n" "Use\n" "TCH\n"
      "Do not use TCH for Paging Request Any\n"
      "Do use TCH for Paging Request Any\n")
{
	struct gsm_network *gsmnet = gsmnet_from_vty(vty);
	gsmnet->pag_any_tch = atoi(argv[0]);
	gsm_net_update_ctype(gsmnet);
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

DEFUN_DEPRECATED(cfg_net_dtx,
		 cfg_net_dtx_cmd,
		 "dtx-used (0|1)",
		 ".HIDDEN\n""Obsolete\n""Obsolete\n")
{
	vty_out(vty, "%% 'dtx-used' is now deprecated: use dtx * "
		"configuration options of BTS instead%s", VTY_NEWLINE);
       return CMD_SUCCESS;
}

/* per-BTS configuration */
DEFUN(cfg_bts,
      cfg_bts_cmd,
      "bts <0-255>",
      "Select a BTS to configure\n"
	"BTS Number\n")
{
	struct gsm_network *gsmnet = gsmnet_from_vty(vty);
	int bts_nr = atoi(argv[0]);
	struct gsm_bts *bts;

	if (bts_nr > gsmnet->num_bts) {
		vty_out(vty, "%% The next unused BTS number is %u%s",
			gsmnet->num_bts, VTY_NEWLINE);
		return CMD_WARNING;
	} else if (bts_nr == gsmnet->num_bts) {
		/* allocate a new one */
		bts = gsm_bts_alloc_register(gsmnet, GSM_BTS_TYPE_UNKNOWN,
					     HARDCODED_BSIC);
	} else
		bts = gsm_bts_num(gsmnet, bts_nr);

	if (!bts) {
		vty_out(vty, "%% Unable to allocate BTS %u%s",
			gsmnet->num_bts, VTY_NEWLINE);
		return CMD_WARNING;
	}

	vty->index = bts;
	vty->index_sub = &bts->description;
	vty->node = BTS_NODE;

	return CMD_SUCCESS;
}

DEFUN(cfg_bts_type,
      cfg_bts_type_cmd,
      "type TYPE", /* dynamically created */
      "Set the BTS type\n" "Type\n")
{
	struct gsm_bts *bts = vty->index;
	int rc;

	rc = gsm_set_bts_type(bts, str2btstype(argv[0]));
	if (rc < 0)
		return CMD_WARNING;

	return CMD_SUCCESS;
}

DEFUN(cfg_bts_band,
      cfg_bts_band_cmd,
      "band BAND",
      "Set the frequency band of this BTS\n" "Frequency band\n")
{
	struct gsm_bts *bts = vty->index;
	int band = gsm_band_parse(argv[0]);

	if (band < 0) {
		vty_out(vty, "%% BAND %d is not a valid GSM band%s",
			band, VTY_NEWLINE);
		return CMD_WARNING;
	}

	bts->band = band;

	return CMD_SUCCESS;
}

DEFUN(cfg_bts_dtxu, cfg_bts_dtxu_cmd, "dtx uplink [force]",
      "Configure discontinuous transmission\n"
      "Enable Uplink DTX for this BTS\n"
      "MS 'shall' use DTXu instead of 'may' use (might not be supported by "
      "older phones).\n")
{
	struct gsm_bts *bts = vty->index;

	bts->dtxu = (argc > 0) ? GSM48_DTX_SHALL_BE_USED : GSM48_DTX_MAY_BE_USED;
	if (!is_ipaccess_bts(bts))
		vty_out(vty, "%% DTX enabled on non-IP BTS: this configuration "
			"neither supported nor tested!%s", VTY_NEWLINE);
	return CMD_SUCCESS;
}

DEFUN(cfg_bts_no_dtxu, cfg_bts_no_dtxu_cmd, "no dtx uplink",
      NO_STR
      "Configure discontinuous transmission\n"
      "Disable Uplink DTX for this BTS\n")
{
	struct gsm_bts *bts = vty->index;

	bts->dtxu = GSM48_DTX_SHALL_NOT_BE_USED;

	return CMD_SUCCESS;
}

DEFUN(cfg_bts_dtxd, cfg_bts_dtxd_cmd, "dtx downlink",
      "Configure discontinuous transmission\n"
      "Enable Downlink DTX for this BTS\n")
{
	struct gsm_bts *bts = vty->index;

	bts->dtxd = true;
	if (!is_ipaccess_bts(bts))
		vty_out(vty, "%% DTX enabled on non-IP BTS: this configuration "
			"neither supported nor tested!%s", VTY_NEWLINE);
	return CMD_SUCCESS;
}

DEFUN(cfg_bts_no_dtxd, cfg_bts_no_dtxd_cmd, "no dtx downlink",
      NO_STR
      "Configure discontinuous transmission\n"
      "Disable Downlink DTX for this BTS\n")
{
	struct gsm_bts *bts = vty->index;

	bts->dtxd = false;

	return CMD_SUCCESS;
}

DEFUN(cfg_bts_ci,
      cfg_bts_ci_cmd,
      "cell_identity <0-65535>",
      "Set the Cell identity of this BTS\n" "Cell Identity\n")
{
	struct gsm_bts *bts = vty->index;
	int ci = atoi(argv[0]);

	if (ci < 0 || ci > 0xffff) {
		vty_out(vty, "%% CI %d is not in the valid range (0-65535)%s",
			ci, VTY_NEWLINE);
		return CMD_WARNING;
	}
	bts->cell_identity = ci;

	return CMD_SUCCESS;
}

DEFUN(cfg_bts_lac,
      cfg_bts_lac_cmd,
      "location_area_code <0-65535>",
      "Set the Location Area Code (LAC) of this BTS\n" "LAC\n")
{
	struct gsm_bts *bts = vty->index;
	int lac = atoi(argv[0]);

	if (lac < 0 || lac > 0xffff) {
		vty_out(vty, "%% LAC %d is not in the valid range (0-65535)%s",
			lac, VTY_NEWLINE);
		return CMD_WARNING;
	}

	if (lac == GSM_LAC_RESERVED_DETACHED || lac == GSM_LAC_RESERVED_ALL_BTS) {
		vty_out(vty, "%% LAC %d is reserved by GSM 04.08%s",
			lac, VTY_NEWLINE);
		return CMD_WARNING;
	}

	bts->location_area_code = lac;

	return CMD_SUCCESS;
}


/* compatibility wrapper for old config files */
DEFUN_HIDDEN(cfg_bts_tsc,
      cfg_bts_tsc_cmd,
      "training_sequence_code <0-7>",
      "Set the Training Sequence Code (TSC) of this BTS\n" "TSC\n")
{
	return CMD_SUCCESS;
}

DEFUN(cfg_bts_bsic,
      cfg_bts_bsic_cmd,
      "base_station_id_code <0-63>",
      "Set the Base Station Identity Code (BSIC) of this BTS\n"
      "BSIC of this BTS\n")
{
	struct gsm_bts *bts = vty->index;
	int bsic = atoi(argv[0]);

	if (bsic < 0 || bsic > 0x3f) {
		vty_out(vty, "%% BSIC %d is not in the valid range (0-255)%s",
			bsic, VTY_NEWLINE);
		return CMD_WARNING;
	}
	bts->bsic = bsic;

	return CMD_SUCCESS;
}

DEFUN(cfg_bts_unit_id,
      cfg_bts_unit_id_cmd,
      "ip.access unit_id <0-65534> <0-255>",
      "Abis/IP specific options\n"
      "Set the IPA BTS Unit ID\n"
      "Unit ID (Site)\n"
      "Unit ID (BTS)\n")
{
	struct gsm_bts *bts = vty->index;
	int site_id = atoi(argv[0]);
	int bts_id = atoi(argv[1]);

	if (!is_ipaccess_bts(bts)) {
		vty_out(vty, "%% BTS is not of ip.access type%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	bts->ip_access.site_id = site_id;
	bts->ip_access.bts_id = bts_id;

	return CMD_SUCCESS;
}

DEFUN(cfg_bts_rsl_ip,
      cfg_bts_rsl_ip_cmd,
      "ip.access rsl-ip A.B.C.D",
      "Abis/IP specific options\n"
      "Set the IPA RSL IP Address of the BSC\n"
      "Destination IP address for RSL connection\n")
{
	struct gsm_bts *bts = vty->index;
	struct in_addr ia;

	if (!is_ipaccess_bts(bts)) {
		vty_out(vty, "%% BTS is not of ip.access type%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	inet_aton(argv[0], &ia);
	bts->ip_access.rsl_ip = ntohl(ia.s_addr);

	return CMD_SUCCESS;
}

#define NOKIA_STR "Nokia *Site related commands\n"

DEFUN(cfg_bts_nokia_site_skip_reset,
      cfg_bts_nokia_site_skip_reset_cmd,
      "nokia_site skip-reset (0|1)",
      NOKIA_STR
      "Skip the reset step during bootstrap process of this BTS\n"
      "Do NOT skip the reset\n" "Skip the reset\n")
{
	struct gsm_bts *bts = vty->index;

	if (bts->type != GSM_BTS_TYPE_NOKIA_SITE) {
		vty_out(vty, "%% BTS is not of Nokia *Site type%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	bts->nokia.skip_reset = atoi(argv[0]);

	return CMD_SUCCESS;
}

DEFUN(cfg_bts_nokia_site_no_loc_rel_cnf,
      cfg_bts_nokia_site_no_loc_rel_cnf_cmd,
      "nokia_site no-local-rel-conf (0|1)",
      NOKIA_STR
      "Do not wait for RELease CONFirm message when releasing channel locally\n"
      "Wait for RELease CONFirm\n" "Do not wait for RELease CONFirm\n")
{
	struct gsm_bts *bts = vty->index;

	if (!is_nokia_bts(bts)) {
		vty_out(vty, "%% BTS is not of Nokia *Site type%s",
			VTY_NEWLINE);
		return CMD_WARNING;
	}

	bts->nokia.no_loc_rel_cnf = atoi(argv[0]);

	return CMD_SUCCESS;
}

DEFUN(cfg_bts_nokia_site_bts_reset_timer_cnf,
      cfg_bts_nokia_site_bts_reset_timer_cnf_cmd,
      "nokia_site bts-reset-timer  <15-100>",
      NOKIA_STR
      "The amount of time (in sec.) between BTS_RESET is sent,\n"
      "and the BTS is being bootstrapped.\n")
{
	struct gsm_bts *bts = vty->index;

	if (!is_nokia_bts(bts)) {
		vty_out(vty, "%% BTS is not of Nokia *Site type%s",
			VTY_NEWLINE);
		return CMD_WARNING;
	}

	bts->nokia.bts_reset_timer_cnf = atoi(argv[0]);

	return CMD_SUCCESS;
}
#define OML_STR	"Organization & Maintenance Link\n"
#define IPA_STR "A-bis/IP Specific Options\n"

DEFUN(cfg_bts_stream_id,
      cfg_bts_stream_id_cmd,
      "oml ip.access stream_id <0-255> line E1_LINE",
	OML_STR IPA_STR
      "Set the ip.access Stream ID of the OML link of this BTS\n"
      "Stream Identifier\n" "Virtual E1 Line Number\n" "Virtual E1 Line Number\n")
{
	struct gsm_bts *bts = vty->index;
	int stream_id = atoi(argv[0]), linenr = atoi(argv[1]);

	if (!is_ipaccess_bts(bts)) {
		vty_out(vty, "%% BTS is not of ip.access type%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	bts->oml_tei = stream_id;
	/* This is used by e1inp_bind_ops callback for each BTS model. */
	bts->oml_e1_link.e1_nr = linenr;

	return CMD_SUCCESS;
}

#define OML_E1_STR OML_STR "OML E1/T1 Configuration\n"

DEFUN(cfg_bts_oml_e1,
      cfg_bts_oml_e1_cmd,
      "oml e1 line E1_LINE timeslot <1-31> sub-slot (0|1|2|3|full)",
	OML_E1_STR
      "E1/T1 line number to be used for OML\n"
      "E1/T1 line number to be used for OML\n"
      "E1/T1 timeslot to be used for OML\n"
      "E1/T1 timeslot to be used for OML\n"
      "E1/T1 sub-slot to be used for OML\n"
      "Use E1/T1 sub-slot 0\n"
      "Use E1/T1 sub-slot 1\n"
      "Use E1/T1 sub-slot 2\n"
      "Use E1/T1 sub-slot 3\n"
      "Use full E1 slot 3\n"
      )
{
	struct gsm_bts *bts = vty->index;

	parse_e1_link(&bts->oml_e1_link, argv[0], argv[1], argv[2]);

	return CMD_SUCCESS;
}


DEFUN(cfg_bts_oml_e1_tei,
      cfg_bts_oml_e1_tei_cmd,
      "oml e1 tei <0-63>",
	OML_E1_STR
      "Set the TEI to be used for OML\n"
      "TEI Number\n")
{
	struct gsm_bts *bts = vty->index;

	bts->oml_tei = atoi(argv[0]);

	return CMD_SUCCESS;
}

DEFUN(cfg_bts_challoc, cfg_bts_challoc_cmd,
      "channel allocator (ascending|descending)",
	"Channnel Allocator\n" "Channel Allocator\n"
	"Allocate Timeslots and Transceivers in ascending order\n"
	"Allocate Timeslots and Transceivers in descending order\n")
{
	struct gsm_bts *bts = vty->index;

	if (!strcmp(argv[0], "ascending"))
		bts->chan_alloc_reverse = 0;
	else
		bts->chan_alloc_reverse = 1;

	return CMD_SUCCESS;
}

#define RACH_STR "Random Access Control Channel\n"

DEFUN(cfg_bts_rach_tx_integer,
      cfg_bts_rach_tx_integer_cmd,
      "rach tx integer <0-15>",
	RACH_STR
      "Set the raw tx integer value in RACH Control parameters IE\n"
      "Set the raw tx integer value in RACH Control parameters IE\n"
      "Raw tx integer value in RACH Control parameters IE\n")
{
	struct gsm_bts *bts = vty->index;
	bts->si_common.rach_control.tx_integer = atoi(argv[0]) & 0xf;
	return CMD_SUCCESS;
}

DEFUN(cfg_bts_rach_max_trans,
      cfg_bts_rach_max_trans_cmd,
      "rach max transmission (1|2|4|7)",
	RACH_STR
      "Set the maximum number of RACH burst transmissions\n"
      "Set the maximum number of RACH burst transmissions\n"
      "Maximum number of 1 RACH burst transmissions\n"
      "Maximum number of 2 RACH burst transmissions\n"
      "Maximum number of 4 RACH burst transmissions\n"
      "Maximum number of 7 RACH burst transmissions\n")
{
	struct gsm_bts *bts = vty->index;
	bts->si_common.rach_control.max_trans = rach_max_trans_val2raw(atoi(argv[0]));
	return CMD_SUCCESS;
}

#define CD_STR "Channel Description\n"

DEFUN(cfg_bts_chan_desc_att,
      cfg_bts_chan_desc_att_cmd,
      "channel-descrption attach (0|1)",
	CD_STR
      "Set if attachment is required\n"
      "Attachment is NOT required\n"
      "Attachment is required (standard)\n")
{
	struct gsm_bts *bts = vty->index;
	bts->si_common.chan_desc.att = atoi(argv[0]);
	return CMD_SUCCESS;
}

DEFUN(cfg_bts_chan_desc_bs_pa_mfrms,
      cfg_bts_chan_desc_bs_pa_mfrms_cmd,
      "channel-descrption bs-pa-mfrms <2-9>",
	CD_STR
      "Set number of multiframe periods for paging groups\n"
      "Number of multiframe periods for paging groups\n")
{
	struct gsm_bts *bts = vty->index;
	int bs_pa_mfrms = atoi(argv[0]);

	bts->si_common.chan_desc.bs_pa_mfrms = bs_pa_mfrms - 2;
	return CMD_SUCCESS;
}

DEFUN(cfg_bts_chan_desc_bs_ag_blks_res,
      cfg_bts_chan_desc_bs_ag_blks_res_cmd,
      "channel-descrption bs-ag-blks-res <0-7>",
	CD_STR
      "Set number of blocks reserved for access grant\n"
      "Number of blocks reserved for access grant\n")
{
	struct gsm_bts *bts = vty->index;
	int bs_ag_blks_res = atoi(argv[0]);

	bts->si_common.chan_desc.bs_ag_blks_res = bs_ag_blks_res;
	return CMD_SUCCESS;
}

#define NM_STR "Network Management\n"

DEFUN(cfg_bts_rach_nm_b_thresh,
      cfg_bts_rach_nm_b_thresh_cmd,
      "rach nm busy threshold <0-255>",
	RACH_STR NM_STR
      "Set the NM Busy Threshold\n"
      "Set the NM Busy Threshold\n"
      "NM Busy Threshold in dB")
{
	struct gsm_bts *bts = vty->index;
	bts->rach_b_thresh = atoi(argv[0]);
	return CMD_SUCCESS;
}

DEFUN(cfg_bts_rach_nm_ldavg,
      cfg_bts_rach_nm_ldavg_cmd,
      "rach nm load average <0-65535>",
	RACH_STR NM_STR
      "Set the NM Loadaverage Slots value\n"
      "Set the NM Loadaverage Slots value\n"
      "NM Loadaverage Slots value\n")
{
	struct gsm_bts *bts = vty->index;
	bts->rach_ldavg_slots = atoi(argv[0]);
	return CMD_SUCCESS;
}

DEFUN(cfg_bts_cell_barred, cfg_bts_cell_barred_cmd,
      "cell barred (0|1)",
      "Should this cell be barred from access?\n"
      "Should this cell be barred from access?\n"
      "Cell should NOT be barred\n"
      "Cell should be barred\n")

{
	struct gsm_bts *bts = vty->index;

	bts->si_common.rach_control.cell_bar = atoi(argv[0]);

	return CMD_SUCCESS;
}

DEFUN(cfg_bts_rach_ec_allowed, cfg_bts_rach_ec_allowed_cmd,
      "rach emergency call allowed (0|1)",
      RACH_STR
      "Should this cell allow emergency calls?\n"
      "Should this cell allow emergency calls?\n"
      "Should this cell allow emergency calls?\n"
      "Do NOT allow emergency calls\n"
      "Allow emergency calls\n")
{
	struct gsm_bts *bts = vty->index;

	if (atoi(argv[0]) == 0)
		bts->si_common.rach_control.t2 |= 0x4;
	else
		bts->si_common.rach_control.t2 &= ~0x4;

	return CMD_SUCCESS;
}

DEFUN(cfg_bts_rach_ac_class, cfg_bts_rach_ac_class_cmd,
      "rach access-control-class (0|1|2|3|4|5|6|7|8|9|11|12|13|14|15) (barred|allowed)",
      RACH_STR
      "Set access control class\n"
      "Access control class 0\n"
      "Access control class 1\n"
      "Access control class 2\n"
      "Access control class 3\n"
      "Access control class 4\n"
      "Access control class 5\n"
      "Access control class 6\n"
      "Access control class 7\n"
      "Access control class 8\n"
      "Access control class 9\n"
      "Access control class 11 for PLMN use\n"
      "Access control class 12 for security services\n"
      "Access control class 13 for public utilities (e.g. water/gas suppliers)\n"
      "Access control class 14 for emergency services\n"
      "Access control class 15 for PLMN staff\n"
      "barred to use access control class\n"
      "allowed to use access control class\n")
{
	struct gsm_bts *bts = vty->index;

	uint8_t control_class;
	uint8_t allowed = 0;

	if (strcmp(argv[1], "allowed") == 0)
		allowed = 1;

	control_class = atoi(argv[0]);
	if (control_class < 8)
		if (allowed)
			bts->si_common.rach_control.t3 &= ~(0x1 << control_class);
		else
			bts->si_common.rach_control.t3 |= (0x1 << control_class);
	else
		if (allowed)
			bts->si_common.rach_control.t2 &= ~(0x1 << (control_class - 8));
		else
			bts->si_common.rach_control.t2 |= (0x1 << (control_class - 8));

	return CMD_SUCCESS;
}

DEFUN(cfg_bts_ms_max_power, cfg_bts_ms_max_power_cmd,
      "ms max power <0-40>",
      "MS Options\n"
      "Maximum transmit power of the MS\n"
      "Maximum transmit power of the MS\n"
      "Maximum transmit power of the MS in dBm")
{
	struct gsm_bts *bts = vty->index;

	bts->ms_max_power = atoi(argv[0]);

	return CMD_SUCCESS;
}

#define CELL_STR "Cell Parameters\n"

DEFUN(cfg_bts_cell_resel_hyst, cfg_bts_cell_resel_hyst_cmd,
      "cell reselection hysteresis <0-14>",
      CELL_STR "Cell re-selection parameters\n"
      "Cell Re-Selection Hysteresis in dB\n"
      "Cell Re-Selection Hysteresis in dB")
{
	struct gsm_bts *bts = vty->index;

	bts->si_common.cell_sel_par.cell_resel_hyst = atoi(argv[0])/2;

	return CMD_SUCCESS;
}

DEFUN(cfg_bts_rxlev_acc_min, cfg_bts_rxlev_acc_min_cmd,
      "rxlev access min <0-63>",
      "Minimum RxLev needed for cell access\n"
      "Minimum RxLev needed for cell access\n"
      "Minimum RxLev needed for cell access\n"
      "Minimum RxLev needed for cell access (better than -110dBm)")
{
	struct gsm_bts *bts = vty->index;

	bts->si_common.cell_sel_par.rxlev_acc_min = atoi(argv[0]);

	return CMD_SUCCESS;
}

DEFUN(cfg_bts_cell_bar_qualify, cfg_bts_cell_bar_qualify_cmd,
	"cell bar qualify (0|1)",
	CELL_STR "Cell Bar Qualify\n" "Cell Bar Qualify\n"
	"Set CBQ to 0\n" "Set CBQ to 1\n")
{
	struct gsm_bts *bts = vty->index;

	bts->si_common.cell_ro_sel_par.present = 1;
	bts->si_common.cell_ro_sel_par.cbq = atoi(argv[0]);

	return CMD_SUCCESS;
}

DEFUN(cfg_bts_cell_resel_ofs, cfg_bts_cell_resel_ofs_cmd,
	"cell reselection offset <0-126>",
	CELL_STR "Cell Re-Selection Parameters\n"
	"Cell Re-Selection Offset (CRO) in dB\n"
	"Cell Re-Selection Offset (CRO) in dB\n"
	)
{
	struct gsm_bts *bts = vty->index;

	bts->si_common.cell_ro_sel_par.present = 1;
	bts->si_common.cell_ro_sel_par.cell_resel_off = atoi(argv[0])/2;

	return CMD_SUCCESS;
}

DEFUN(cfg_bts_temp_ofs, cfg_bts_temp_ofs_cmd,
	"temporary offset <0-60>",
	"Cell selection temporary negative offset\n"
	"Cell selection temporary negative offset\n"
	"Cell selection temporary negative offset in dB")
{
	struct gsm_bts *bts = vty->index;

	bts->si_common.cell_ro_sel_par.present = 1;
	bts->si_common.cell_ro_sel_par.temp_offs = atoi(argv[0])/10;

	return CMD_SUCCESS;
}

DEFUN(cfg_bts_temp_ofs_inf, cfg_bts_temp_ofs_inf_cmd,
	"temporary offset infinite",
	"Cell selection temporary negative offset\n"
	"Cell selection temporary negative offset\n"
	"Sets cell selection temporary negative offset to infinity")
{
	struct gsm_bts *bts = vty->index;

	bts->si_common.cell_ro_sel_par.present = 1;
	bts->si_common.cell_ro_sel_par.temp_offs = 7;

	return CMD_SUCCESS;
}

DEFUN(cfg_bts_penalty_time, cfg_bts_penalty_time_cmd,
	"penalty time <20-620>",
	"Cell selection penalty time\n"
	"Cell selection penalty time\n"
	"Cell selection penalty time in seconds (by 20s increments)\n")
{
	struct gsm_bts *bts = vty->index;

	bts->si_common.cell_ro_sel_par.present = 1;
	bts->si_common.cell_ro_sel_par.penalty_time = (atoi(argv[0])-20)/20;

	return CMD_SUCCESS;
}

DEFUN(cfg_bts_penalty_time_rsvd, cfg_bts_penalty_time_rsvd_cmd,
	"penalty time reserved",
	"Cell selection penalty time\n"
	"Cell selection penalty time\n"
	"Set cell selection penalty time to reserved value 31, "
		"(indicate that CELL_RESELECT_OFFSET is subtracted from C2 "
		"and TEMPORARY_OFFSET is ignored)")
{
	struct gsm_bts *bts = vty->index;

	bts->si_common.cell_ro_sel_par.present = 1;
	bts->si_common.cell_ro_sel_par.penalty_time = 31;

	return CMD_SUCCESS;
}

DEFUN(cfg_bts_per_loc_upd, cfg_bts_per_loc_upd_cmd,
      "periodic location update <6-1530>",
      "Periodic Location Updating Interval\n"
      "Periodic Location Updating Interval\n"
      "Periodic Location Updating Interval\n"
      "Periodic Location Updating Interval in Minutes\n")
{
	struct gsm_bts *bts = vty->index;

	bts->si_common.chan_desc.t3212 = atoi(argv[0]) / 6;

	return CMD_SUCCESS;
}

DEFUN(cfg_bts_no_per_loc_upd, cfg_bts_no_per_loc_upd_cmd,
      "no periodic location update",
      NO_STR
      "Periodic Location Updating Interval\n"
      "Periodic Location Updating Interval\n"
      "Periodic Location Updating Interval\n")
{
	struct gsm_bts *bts = vty->index;

	bts->si_common.chan_desc.t3212 = 0;

	return CMD_SUCCESS;
}

DEFUN(cfg_bts_radio_link_timeout, cfg_bts_radio_link_timeout_cmd,
	"radio-link-timeout <4-64>",
	"Radio link timeout criterion (BTS side)\n"
	"Radio link timeout value (lost SACCH block)\n")
{
	struct gsm_bts *bts = vty->index;

	gsm_bts_set_radio_link_timeout(bts, atoi(argv[0]));

	return CMD_SUCCESS;
}

DEFUN(cfg_bts_radio_link_timeout_inf, cfg_bts_radio_link_timeout_inf_cmd,
	"radio-link-timeout infinite",
	"Radio link timeout criterion (BTS side)\n"
	"Infinite Radio link timeout value (use only for BTS RF testing)\n")
{
	struct gsm_bts *bts = vty->index;

	if (bts->type != GSM_BTS_TYPE_OSMOBTS) {
		vty_out(vty, "%% infinite radio link timeout not supported by this BTS%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	vty_out(vty, "%% INFINITE RADIO LINK TIMEOUT, USE ONLY FOR BTS RF TESTING%s", VTY_NEWLINE);
	gsm_bts_set_radio_link_timeout(bts, -1);

	return CMD_SUCCESS;
}

#define GPRS_TEXT	"GPRS Packet Network\n"

DEFUN(cfg_bts_prs_bvci, cfg_bts_gprs_bvci_cmd,
	"gprs cell bvci <2-65535>",
	GPRS_TEXT
	"GPRS Cell Settings\n"
	"GPRS BSSGP VC Identifier\n"
	"GPRS BSSGP VC Identifier")
{
	struct gsm_bts *bts = vty->index;

	if (bts->gprs.mode == BTS_GPRS_NONE) {
		vty_out(vty, "%% GPRS not enabled on this BTS%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	bts->gprs.cell.bvci = atoi(argv[0]);

	return CMD_SUCCESS;
}

DEFUN(cfg_bts_gprs_nsei, cfg_bts_gprs_nsei_cmd,
	"gprs nsei <0-65535>",
	GPRS_TEXT
	"GPRS NS Entity Identifier\n"
	"GPRS NS Entity Identifier")
{
	struct gsm_bts *bts = vty->index;

	if (bts->gprs.mode == BTS_GPRS_NONE) {
		vty_out(vty, "%% GPRS not enabled on this BTS%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	bts->gprs.nse.nsei = atoi(argv[0]);

	return CMD_SUCCESS;
}

#define NSVC_TEXT "Network Service Virtual Connection (NS-VC)\n" \
		"NSVC Logical Number\n"

DEFUN(cfg_bts_gprs_nsvci, cfg_bts_gprs_nsvci_cmd,
	"gprs nsvc <0-1> nsvci <0-65535>",
	GPRS_TEXT NSVC_TEXT
	"NS Virtual Connection Identifier\n"
	"GPRS NS VC Identifier")
{
	struct gsm_bts *bts = vty->index;
	int idx = atoi(argv[0]);

	if (bts->gprs.mode == BTS_GPRS_NONE) {
		vty_out(vty, "%% GPRS not enabled on this BTS%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	bts->gprs.nsvc[idx].nsvci = atoi(argv[1]);

	return CMD_SUCCESS;
}

DEFUN(cfg_bts_gprs_nsvc_lport, cfg_bts_gprs_nsvc_lport_cmd,
	"gprs nsvc <0-1> local udp port <0-65535>",
	GPRS_TEXT NSVC_TEXT
	"GPRS NS Local UDP Port\n"
	"GPRS NS Local UDP Port\n"
	"GPRS NS Local UDP Port\n"
	"GPRS NS Local UDP Port Number\n")
{
	struct gsm_bts *bts = vty->index;
	int idx = atoi(argv[0]);

	if (bts->gprs.mode == BTS_GPRS_NONE) {
		vty_out(vty, "%% GPRS not enabled on this BTS%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	bts->gprs.nsvc[idx].local_port = atoi(argv[1]);

	return CMD_SUCCESS;
}

DEFUN(cfg_bts_gprs_nsvc_rport, cfg_bts_gprs_nsvc_rport_cmd,
	"gprs nsvc <0-1> remote udp port <0-65535>",
	GPRS_TEXT NSVC_TEXT
	"GPRS NS Remote UDP Port\n"
	"GPRS NS Remote UDP Port\n"
	"GPRS NS Remote UDP Port\n"
	"GPRS NS Remote UDP Port Number\n")
{
	struct gsm_bts *bts = vty->index;
	int idx = atoi(argv[0]);

	if (bts->gprs.mode == BTS_GPRS_NONE) {
		vty_out(vty, "%% GPRS not enabled on this BTS%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	bts->gprs.nsvc[idx].remote_port = atoi(argv[1]);

	return CMD_SUCCESS;
}

DEFUN(cfg_bts_gprs_nsvc_rip, cfg_bts_gprs_nsvc_rip_cmd,
	"gprs nsvc <0-1> remote ip A.B.C.D",
	GPRS_TEXT NSVC_TEXT
	"GPRS NS Remote IP Address\n"
	"GPRS NS Remote IP Address\n"
	"GPRS NS Remote IP Address\n")
{
	struct gsm_bts *bts = vty->index;
	int idx = atoi(argv[0]);
	struct in_addr ia;

	if (bts->gprs.mode == BTS_GPRS_NONE) {
		vty_out(vty, "%% GPRS not enabled on this BTS%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	inet_aton(argv[1], &ia);
	bts->gprs.nsvc[idx].remote_ip = ntohl(ia.s_addr);

	return CMD_SUCCESS;
}

DEFUN(cfg_bts_pag_free, cfg_bts_pag_free_cmd,
      "paging free <-1-1024>",
      "Paging options\n"
      "Only page when having a certain amount of free slots\n"
      "amount of required free paging slots. -1 to disable\n")
{
	struct gsm_bts *bts = vty->index;

	bts->paging.free_chans_need = atoi(argv[0]);
	return CMD_SUCCESS;
}

DEFUN(cfg_bts_gprs_ns_timer, cfg_bts_gprs_ns_timer_cmd,
	"gprs ns timer " NS_TIMERS " <0-255>",
	GPRS_TEXT "Network Service\n"
	"Network Service Timer\n"
	NS_TIMERS_HELP "Timer Value\n")
{
	struct gsm_bts *bts = vty->index;
	int idx = get_string_value(gprs_ns_timer_strs, argv[0]);
	int val = atoi(argv[1]);

	if (bts->gprs.mode == BTS_GPRS_NONE) {
		vty_out(vty, "%% GPRS not enabled on this BTS%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	if (idx < 0 || idx >= ARRAY_SIZE(bts->gprs.nse.timer))
		return CMD_WARNING;

	bts->gprs.nse.timer[idx] = val;

	return CMD_SUCCESS;
}

#define BSSGP_TIMERS "(blocking-timer|blocking-retries|unblocking-retries|reset-timer|reset-retries|suspend-timer|suspend-retries|resume-timer|resume-retries|capability-update-timer|capability-update-retries)"
#define BSSGP_TIMERS_HELP	\
	"Tbvc-block timeout\n"			\
	"Tbvc-block retries\n"			\
	"Tbvc-unblock retries\n"		\
	"Tbvcc-reset timeout\n"			\
	"Tbvc-reset retries\n"			\
	"Tbvc-suspend timeout\n"		\
	"Tbvc-suspend retries\n"		\
	"Tbvc-resume timeout\n"			\
	"Tbvc-resume retries\n"			\
	"Tbvc-capa-update timeout\n"		\
	"Tbvc-capa-update retries\n"

DEFUN(cfg_bts_gprs_cell_timer, cfg_bts_gprs_cell_timer_cmd,
	"gprs cell timer " BSSGP_TIMERS " <0-255>",
	GPRS_TEXT "Cell / BSSGP\n"
	"Cell/BSSGP Timer\n"
	BSSGP_TIMERS_HELP "Timer Value\n")
{
	struct gsm_bts *bts = vty->index;
	int idx = get_string_value(gprs_bssgp_cfg_strs, argv[0]);
	int val = atoi(argv[1]);

	if (bts->gprs.mode == BTS_GPRS_NONE) {
		vty_out(vty, "%% GPRS not enabled on this BTS%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	if (idx < 0 || idx >= ARRAY_SIZE(bts->gprs.cell.timer))
		return CMD_WARNING;

	bts->gprs.cell.timer[idx] = val;

	return CMD_SUCCESS;
}

DEFUN(cfg_bts_gprs_rac, cfg_bts_gprs_rac_cmd,
	"gprs routing area <0-255>",
	GPRS_TEXT
	"GPRS Routing Area Code\n"
	"GPRS Routing Area Code\n"
	"GPRS Routing Area Code\n")
{
	struct gsm_bts *bts = vty->index;

	if (bts->gprs.mode == BTS_GPRS_NONE) {
		vty_out(vty, "%% GPRS not enabled on this BTS%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	bts->gprs.rac = atoi(argv[0]);

	return CMD_SUCCESS;
}

DEFUN(cfg_bts_gprs_ctrl_ack, cfg_bts_gprs_ctrl_ack_cmd,
	"gprs control-ack-type-rach", GPRS_TEXT
	"Set GPRS Control Ack Type for PACKET CONTROL ACKNOWLEDGMENT message to "
	"four access bursts format instead of default RLC/MAC control block\n")
{
	struct gsm_bts *bts = vty->index;

	if (bts->gprs.mode == BTS_GPRS_NONE) {
		vty_out(vty, "%% GPRS not enabled on this BTS%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	bts->gprs.ctrl_ack_type_use_block = false;

	return CMD_SUCCESS;
}

DEFUN(cfg_no_bts_gprs_ctrl_ack, cfg_no_bts_gprs_ctrl_ack_cmd,
	"no gprs control-ack-type-rach", NO_STR GPRS_TEXT
	"Set GPRS Control Ack Type for PACKET CONTROL ACKNOWLEDGMENT message to "
	"four access bursts format instead of default RLC/MAC control block\n")
{
	struct gsm_bts *bts = vty->index;

	if (bts->gprs.mode == BTS_GPRS_NONE) {
		vty_out(vty, "%% GPRS not enabled on this BTS%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	bts->gprs.ctrl_ack_type_use_block = true;

	return CMD_SUCCESS;
}

DEFUN(cfg_bts_gprs_net_ctrl_ord, cfg_bts_gprs_net_ctrl_ord_cmd,
	"gprs network-control-order (nc0|nc1|nc2)",
	GPRS_TEXT
	"GPRS Network Control Order\n"
	"MS controlled cell re-selection, no measurement reporting\n"
	"MS controlled cell re-selection, MS sends measurement reports\n"
	"Network controlled cell re-selection, MS sends measurement reports\n")
{
	struct gsm_bts *bts = vty->index;

	if (bts->gprs.mode == BTS_GPRS_NONE) {
		vty_out(vty, "%% GPRS not enabled on this BTS%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	bts->gprs.net_ctrl_ord = atoi(argv[0] + 2);

	return CMD_SUCCESS;
}

DEFUN(cfg_bts_gprs_mode, cfg_bts_gprs_mode_cmd,
	"gprs mode (none|gprs|egprs)",
	GPRS_TEXT
	"GPRS Mode for this BTS\n"
	"GPRS Disabled on this BTS\n"
	"GPRS Enabled on this BTS\n"
	"EGPRS (EDGE) Enabled on this BTS\n")
{
	struct gsm_bts *bts = vty->index;
	enum bts_gprs_mode mode = bts_gprs_mode_parse(argv[0], NULL);

	if (!bts_gprs_mode_is_compat(bts, mode)) {
		vty_out(vty, "This BTS type does not support %s%s", argv[0],
			VTY_NEWLINE);
		return CMD_WARNING;
	}

	bts->gprs.mode = mode;

	return CMD_SUCCESS;
}

DEFUN(cfg_bts_gprs_11bit_rach_support_for_egprs,
	cfg_bts_gprs_11bit_rach_support_for_egprs_cmd,
	"gprs 11bit_rach_support_for_egprs (0|1)",
	GPRS_TEXT "11 bit RACH options\n"
	"Disable 11 bit RACH for EGPRS\n"
	"Enable 11 bit RACH for EGPRS")
{
	struct gsm_bts *bts = vty->index;

	bts->gprs.supports_egprs_11bit_rach = atoi(argv[0]);

	if (bts->gprs.supports_egprs_11bit_rach > 1) {
		vty_out(vty, "Error in RACH type%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	if ((bts->gprs.mode == BTS_GPRS_NONE) &&
		(bts->gprs.supports_egprs_11bit_rach == 1)) {
		vty_out(vty, "Error:gprs mode is none and 11bit rach is"
			" enabled%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	return CMD_SUCCESS;
}

#define SI_TEXT		"System Information Messages\n"
#define SI_TYPE_TEXT "(1|2|3|4|5|6|7|8|9|10|13|16|17|18|19|20|2bis|2ter|2quater|5bis|5ter)"
#define SI_TYPE_HELP 	"System Information Type 1\n"	\
			"System Information Type 2\n"	\
			"System Information Type 3\n"	\
			"System Information Type 4\n"	\
			"System Information Type 5\n"	\
			"System Information Type 6\n"	\
			"System Information Type 7\n"	\
			"System Information Type 8\n"	\
			"System Information Type 9\n"	\
			"System Information Type 10\n"	\
			"System Information Type 13\n"	\
			"System Information Type 16\n"	\
			"System Information Type 17\n"	\
			"System Information Type 18\n"	\
			"System Information Type 19\n"	\
			"System Information Type 20\n"	\
			"System Information Type 2bis\n"	\
			"System Information Type 2ter\n"	\
			"System Information Type 2quater\n"	\
			"System Information Type 5bis\n"	\
			"System Information Type 5ter\n"

DEFUN(cfg_bts_si_mode, cfg_bts_si_mode_cmd,
	"system-information " SI_TYPE_TEXT " mode (static|computed)",
	SI_TEXT SI_TYPE_HELP
	"System Information Mode\n"
	"Static user-specified\n"
	"Dynamic, BSC-computed\n")
{
	struct gsm_bts *bts = vty->index;
	int type;

	type = get_string_value(osmo_sitype_strs, argv[0]);
	if (type < 0) {
		vty_out(vty, "Error SI Type%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	if (!strcmp(argv[1], "static"))
		bts->si_mode_static |= (1 << type);
	else
		bts->si_mode_static &= ~(1 << type);

	return CMD_SUCCESS;
}

DEFUN(cfg_bts_si_static, cfg_bts_si_static_cmd,
	"system-information " SI_TYPE_TEXT " static HEXSTRING",
	SI_TEXT SI_TYPE_HELP
	"Static System Information filling\n"
	"Static user-specified SI content in HEX notation\n")
{
	struct gsm_bts *bts = vty->index;
	int rc, type;

	type = get_string_value(osmo_sitype_strs, argv[0]);
	if (type < 0) {
		vty_out(vty, "Error SI Type%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	if (!(bts->si_mode_static & (1 << type))) {
		vty_out(vty, "SI Type %s is not configured in static mode%s",
			get_value_string(osmo_sitype_strs, type), VTY_NEWLINE);
		return CMD_WARNING;
	}

	/* Fill buffer with padding pattern */
	memset(GSM_BTS_SI(bts, type), 0x2b, GSM_MACBLOCK_LEN);

	/* Parse the user-specified SI in hex format, [partially] overwriting padding */
	rc = osmo_hexparse(argv[1], GSM_BTS_SI(bts, type), GSM_MACBLOCK_LEN);
	if (rc < 0 || rc > GSM_MACBLOCK_LEN) {
		vty_out(vty, "Error parsing HEXSTRING%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	/* Mark this SI as present */
	bts->si_valid |= (1 << type);

	return CMD_SUCCESS;
}

DEFUN(cfg_bts_early_cm, cfg_bts_early_cm_cmd,
	"early-classmark-sending (allowed|forbidden)",
	"Early Classmark Sending\n"
	"Early Classmark Sending is allowed\n"
	"Early Classmark Sending is forbidden\n")
{
	struct gsm_bts *bts = vty->index;

	if (!strcmp(argv[0], "allowed"))
		bts->early_classmark_allowed = true;
	else
		bts->early_classmark_allowed = false;

	return CMD_SUCCESS;
}

DEFUN(cfg_bts_neigh_mode, cfg_bts_neigh_mode_cmd,
	"neighbor-list mode (automatic|manual|manual-si5)",
	"Neighbor List\n" "Mode of Neighbor List generation\n"
	"Automatically from all BTS in this OpenBSC\n" "Manual\n"
	"Manual with different lists for SI2 and SI5\n")
{
	struct gsm_bts *bts = vty->index;
	int mode = get_string_value(bts_neigh_mode_strs, argv[0]);

	switch (mode) {
	case NL_MODE_MANUAL_SI5SEP:
	case NL_MODE_MANUAL:
		/* make sure we clear the current list when switching to
		 * manual mode */
		if (bts->neigh_list_manual_mode == 0)
			memset(&bts->si_common.data.neigh_list, 0,
				sizeof(bts->si_common.data.neigh_list));
		break;
	default:
		break;
	}

	bts->neigh_list_manual_mode = mode;

	return CMD_SUCCESS;
}

DEFUN(cfg_bts_neigh, cfg_bts_neigh_cmd,
	"neighbor-list (add|del) arfcn <0-1023>",
	"Neighbor List\n" "Add to manual neighbor list\n"
	"Delete from manual neighbor list\n" "ARFCN of neighbor\n"
	"ARFCN of neighbor\n")
{
	struct gsm_bts *bts = vty->index;
	struct bitvec *bv = &bts->si_common.neigh_list;
	uint16_t arfcn = atoi(argv[1]);

	if (!bts->neigh_list_manual_mode) {
		vty_out(vty, "%% Cannot configure neighbor list in "
			"automatic mode%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	if (!strcmp(argv[0], "add"))
		bitvec_set_bit_pos(bv, arfcn, 1);
	else
		bitvec_set_bit_pos(bv, arfcn, 0);

	return CMD_SUCCESS;
}

/* help text should be kept in sync with EARFCN_*_INVALID defines */
DEFUN(cfg_bts_si2quater_neigh_add, cfg_bts_si2quater_neigh_add_cmd,
      "si2quater neighbor-list add earfcn <0-65535> thresh-hi <0-31> "
      "thresh-lo <0-32> prio <0-8> qrxlv <0-32> meas <0-8>",
      "SI2quater Neighbor List\n" "SI2quater Neighbor List\n"
      "Add to manual SI2quater neighbor list\n"
      "EARFCN of neighbor\n" "EARFCN of neighbor\n"
      "threshold high bits\n" "threshold high bits\n"
      "threshold low bits\n" "threshold low bits (32 means NA)\n"
      "priority\n" "priority (8 means NA)\n"
      "QRXLEVMIN\n" "QRXLEVMIN (32 means NA)\n"
      "measurement bandwidth\n" "measurement bandwidth (8 means NA)\n")
{
	struct gsm_bts *bts = vty->index;
	struct osmo_earfcn_si2q *e = &bts->si_common.si2quater_neigh_list;
	uint16_t arfcn = atoi(argv[0]);
	uint8_t thresh_hi = atoi(argv[1]), thresh_lo = atoi(argv[2]),
		prio = atoi(argv[3]), qrx = atoi(argv[4]), meas = atoi(argv[5]);
	int r = bts_earfcn_add(bts, arfcn, thresh_hi, thresh_lo, prio, qrx, meas);

	switch (r) {
	case 1:
		vty_out(vty, "Warning: multiple threshold-high are not supported, overriding with %u%s",
			thresh_hi, VTY_NEWLINE);
		break;
	case EARFCN_THRESH_LOW_INVALID:
		vty_out(vty, "Warning: multiple threshold-low are not supported, overriding with %u%s",
			thresh_lo, VTY_NEWLINE);
		break;
	case EARFCN_QRXLV_INVALID + 1:
		vty_out(vty, "Warning: multiple QRXLEVMIN are not supported, overriding with %u%s",
			qrx, VTY_NEWLINE);
		break;
	case EARFCN_PRIO_INVALID:
		vty_out(vty, "Warning: multiple priorities are not supported, overriding with %u%s",
			prio, VTY_NEWLINE);
		break;
	default:
		if (r < 0) {
			vty_out(vty, "Unable to add ARFCN %u: %s%s", arfcn, strerror(-r), VTY_NEWLINE);
			return CMD_WARNING;
		}
	}

	if (si2q_num(bts) <= SI2Q_MAX_NUM)
		return CMD_SUCCESS;

	vty_out(vty, "Warning: not enough space in SI2quater (%u/%u used) for a given EARFCN %u%s",
		bts->si2q_count, SI2Q_MAX_NUM, arfcn, VTY_NEWLINE);
	osmo_earfcn_del(e, arfcn);

	return CMD_WARNING;
}

DEFUN(cfg_bts_si2quater_neigh_del, cfg_bts_si2quater_neigh_del_cmd,
	"si2quater neighbor-list del earfcn <0-65535>",
	"SI2quater Neighbor List\n"
	"SI2quater Neighbor List\n"
	"Delete from SI2quater manual neighbor list\n"
	"EARFCN of neighbor\n"
	"EARFCN\n")
{
	struct gsm_bts *bts = vty->index;
	struct osmo_earfcn_si2q *e = &bts->si_common.si2quater_neigh_list;
	uint16_t arfcn = atoi(argv[0]);
	int r = osmo_earfcn_del(e, arfcn);
	if (r < 0) {
		vty_out(vty, "Unable to delete arfcn %u: %s%s", arfcn,
			strerror(-r), VTY_NEWLINE);
		return CMD_WARNING;
	}

	return CMD_SUCCESS;
}

DEFUN(cfg_bts_si2quater_uarfcn_add, cfg_bts_si2quater_uarfcn_add_cmd,
      "si2quater neighbor-list add uarfcn <0-16383> <0-511> <0-1>",
      "SI2quater Neighbor List\n"
      "SI2quater Neighbor List\n" "Add to manual SI2quater neighbor list\n"
      "UARFCN of neighbor\n" "UARFCN of neighbor\n" "scrambling code\n"
      "diversity bit\n")
{
	struct gsm_bts *bts = vty->index;
	uint16_t arfcn = atoi(argv[0]), scramble = atoi(argv[1]);

	switch(bts_uarfcn_add(bts, arfcn, scramble, atoi(argv[2]))) {
	case -ENOMEM:
		vty_out(vty, "Unable to add UARFCN: max number of UARFCNs (%u) reached%s", MAX_EARFCN_LIST, VTY_NEWLINE);
		return CMD_WARNING;
	case -ENOSPC:
		vty_out(vty, "Warning: not enough space in SI2quater for a given UARFCN (%u, %u)%s",
			arfcn, scramble, VTY_NEWLINE);
		return CMD_WARNING;
	case -EADDRINUSE:
		vty_out(vty, "Unable to add UARFCN: (%u, %u) is already added%s", arfcn, scramble, VTY_NEWLINE);
		return CMD_WARNING;
	}

	return CMD_SUCCESS;
}

DEFUN(cfg_bts_si2quater_uarfcn_del, cfg_bts_si2quater_uarfcn_del_cmd,
      "si2quater neighbor-list del uarfcn <0-16383> <0-511>",
      "SI2quater Neighbor List\n"
      "SI2quater Neighbor List\n"
      "Delete from SI2quater manual neighbor list\n"
      "UARFCN of neighbor\n"
      "UARFCN\n"
      "scrambling code\n")
{
	struct gsm_bts *bts = vty->index;

	if (bts_uarfcn_del(bts, atoi(argv[0]), atoi(argv[1])) < 0) {
		vty_out(vty, "Unable to delete uarfcn: pair not found%s",
			VTY_NEWLINE);
		return CMD_WARNING;
	}

	return CMD_SUCCESS;
}

DEFUN(cfg_bts_si5_neigh, cfg_bts_si5_neigh_cmd,
	"si5 neighbor-list (add|del) arfcn <0-1023>",
	"SI5 Neighbor List\n"
	"SI5 Neighbor List\n" "Add to manual SI5 neighbor list\n"
	"Delete from SI5 manual neighbor list\n" "ARFCN of neighbor\n"
	"ARFCN of neighbor\n")
{
	struct gsm_bts *bts = vty->index;
	struct bitvec *bv = &bts->si_common.si5_neigh_list;
	uint16_t arfcn = atoi(argv[1]);

	if (!bts->neigh_list_manual_mode) {
		vty_out(vty, "%% Cannot configure neighbor list in "
			"automatic mode%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	if (!strcmp(argv[0], "add"))
		bitvec_set_bit_pos(bv, arfcn, 1);
	else
		bitvec_set_bit_pos(bv, arfcn, 0);

	return CMD_SUCCESS;
}

DEFUN(cfg_bts_pcu_sock, cfg_bts_pcu_sock_cmd,
	"pcu-socket PATH",
	"PCU Socket Path for using OsmoPCU co-located with BSC (legacy BTS)\n"
	"Path in the file system for the unix-domain PCU socket\n")
{
	struct gsm_bts *bts = vty->index;
	int rc;

	osmo_talloc_replace_string(bts, &bts->pcu_sock_path, argv[0]);
	pcu_sock_exit(bts);
	rc = pcu_sock_init(bts->pcu_sock_path, bts);
	if (rc < 0) {
		vty_out(vty, "%% Error creating PCU socket `%s' for BTS %u%s",
			bts->pcu_sock_path, bts->nr, VTY_NEWLINE);
		return CMD_WARNING;
	}

	return CMD_SUCCESS;
}

#define EXCL_RFLOCK_STR "Exclude this BTS from the global RF Lock\n"

DEFUN(cfg_bts_excl_rf_lock,
      cfg_bts_excl_rf_lock_cmd,
      "rf-lock-exclude",
      EXCL_RFLOCK_STR)
{
	struct gsm_bts *bts = vty->index;
	bts->excl_from_rf_lock = 1;
	return CMD_SUCCESS;
}

DEFUN(cfg_bts_no_excl_rf_lock,
      cfg_bts_no_excl_rf_lock_cmd,
      "no rf-lock-exclude",
      NO_STR EXCL_RFLOCK_STR)
{
	struct gsm_bts *bts = vty->index;
	bts->excl_from_rf_lock = 0;
	return CMD_SUCCESS;
}

#define FORCE_COMB_SI_STR "Force the generation of a single SI (no ter/bis)\n"

DEFUN(cfg_bts_force_comb_si,
      cfg_bts_force_comb_si_cmd,
      "force-combined-si",
      FORCE_COMB_SI_STR)
{
	struct gsm_bts *bts = vty->index;
	bts->force_combined_si = 1;
	return CMD_SUCCESS;
}

DEFUN(cfg_bts_no_force_comb_si,
      cfg_bts_no_force_comb_si_cmd,
      "no force-combined-si",
      NO_STR FORCE_COMB_SI_STR)
{
	struct gsm_bts *bts = vty->index;
	bts->force_combined_si = 0;
	return CMD_SUCCESS;
}

static void _get_codec_from_arg(struct vty *vty, int argc, const char *argv[])
{
	struct gsm_bts *bts = vty->index;
	struct bts_codec_conf *codec = &bts->codec;
	int i;

	codec->hr = 0;
	codec->efr = 0;
	codec->amr = 0;
	for (i = 0; i < argc; i++) {
		if (!strcmp(argv[i], "hr"))
			codec->hr = 1;
		if (!strcmp(argv[i], "efr"))
			codec->efr = 1;
		if (!strcmp(argv[i], "amr"))
			codec->amr = 1;
	}
}

#define CODEC_PAR_STR	" (hr|efr|amr)"
#define CODEC_HELP_STR	"Half Rate\n" \
			"Enhanced Full Rate\nAdaptive Multirate\n"

DEFUN(cfg_bts_codec0, cfg_bts_codec0_cmd,
	"codec-support fr",
	"Codec Support settings\nFullrate\n")
{
	_get_codec_from_arg(vty, 0, argv);
	return CMD_SUCCESS;
}

DEFUN(cfg_bts_codec1, cfg_bts_codec1_cmd,
	"codec-support fr" CODEC_PAR_STR,
	"Codec Support settings\nFullrate\n"
	CODEC_HELP_STR)
{
	_get_codec_from_arg(vty, 1, argv);
	return CMD_SUCCESS;
}

DEFUN(cfg_bts_codec2, cfg_bts_codec2_cmd,
	"codec-support fr" CODEC_PAR_STR CODEC_PAR_STR,
	"Codec Support settings\nFullrate\n"
	CODEC_HELP_STR CODEC_HELP_STR)
{
	_get_codec_from_arg(vty, 2, argv);
	return CMD_SUCCESS;
}

DEFUN(cfg_bts_codec3, cfg_bts_codec3_cmd,
	"codec-support fr" CODEC_PAR_STR CODEC_PAR_STR CODEC_PAR_STR,
	"Codec Support settings\nFullrate\n"
	CODEC_HELP_STR CODEC_HELP_STR CODEC_HELP_STR)
{
	_get_codec_from_arg(vty, 3, argv);
	return CMD_SUCCESS;
}

DEFUN(cfg_bts_codec4, cfg_bts_codec4_cmd,
	"codec-support fr" CODEC_PAR_STR CODEC_PAR_STR CODEC_PAR_STR CODEC_PAR_STR,
	"Codec Support settings\nFullrate\n"
	CODEC_HELP_STR CODEC_HELP_STR CODEC_HELP_STR CODEC_HELP_STR)
{
	_get_codec_from_arg(vty, 4, argv);
	return CMD_SUCCESS;
}

DEFUN(cfg_bts_depends_on, cfg_bts_depends_on_cmd,
	"depends-on-bts <0-255>",
	"This BTS can only be started if another one is up\n" "BTS Number\n")
{
	struct gsm_bts *bts = vty->index;
	struct gsm_bts *other_bts;
	int dep = atoi(argv[0]);


	if (!is_ipaccess_bts(bts)) {
		vty_out(vty, "This feature is only available for IP systems.%s",
			VTY_NEWLINE);
		return CMD_WARNING;
	}

	other_bts = gsm_bts_num(bts->network, dep);
	if (!other_bts || !is_ipaccess_bts(other_bts)) {
		vty_out(vty, "This feature is only available for IP systems.%s",
			VTY_NEWLINE);
		return CMD_WARNING;
	}

	if (dep >= bts->nr) {
		vty_out(vty, "%%Need to depend on an already declared unit.%s",
			VTY_NEWLINE);
		return CMD_WARNING;
	}

	bts_depend_mark(bts, dep);
	return CMD_SUCCESS;
}

DEFUN(cfg_bts_no_depends_on, cfg_bts_no_depends_on_cmd,
	"depeneds-on-bts <0-255>",
	NO_STR "This BTS can only be started if another one is up\n"
	"BTS Number\n")
{
	struct gsm_bts *bts = vty->index;
	int dep = atoi(argv[0]);

	bts_depend_clear(bts, dep);
	return CMD_SUCCESS;
}

#define AMR_TEXT "Adaptive Multi Rate settings\n"
#define AMR_MODE_TEXT "Codec modes to use with AMR codec\n"
#define AMR_START_TEXT "Initial codec to use with AMR\n" \
	"Automatically\nFirst codec\nSecond codec\nThird codec\nFourth codec\n"
#define AMR_TH_TEXT "AMR threshold between codecs\nMS side\nBTS side\n"
#define AMR_HY_TEXT "AMR hysteresis between codecs\nMS side\nBTS side\n"

static void get_amr_from_arg(struct vty *vty, int argc, const char *argv[], int full)
{
	struct gsm_bts *bts = vty->index;
	struct amr_multirate_conf *mr = (full) ? &bts->mr_full: &bts->mr_half;
	struct gsm48_multi_rate_conf *mr_conf =
				(struct gsm48_multi_rate_conf *) mr->gsm48_ie;
	int i;

	mr->gsm48_ie[1] = 0;
	for (i = 0; i < argc; i++)
		mr->gsm48_ie[1] |= 1 << atoi(argv[i]);
	mr_conf->icmi = 0;
}

static void get_amr_th_from_arg(struct vty *vty, int argc, const char *argv[], int full)
{
	struct gsm_bts *bts = vty->index;
	struct amr_multirate_conf *mr = (full) ? &bts->mr_full: &bts->mr_half;
	struct amr_mode *modes;
	int i;

	modes = argv[0][0]=='m' ? mr->ms_mode : mr->bts_mode;
	for (i = 0; i < argc - 1; i++)
		modes[i].threshold = atoi(argv[i + 1]);
}

static void get_amr_hy_from_arg(struct vty *vty, int argc, const char *argv[], int full)
{
	struct gsm_bts *bts = vty->index;
	struct amr_multirate_conf *mr = (full) ? &bts->mr_full: &bts->mr_half;
	struct amr_mode *modes;
	int i;

	modes = argv[0][0]=='m' ? mr->ms_mode : mr->bts_mode;
	for (i = 0; i < argc - 1; i++)
		modes[i].hysteresis = atoi(argv[i + 1]);
}

static void get_amr_start_from_arg(struct vty *vty, const char *argv[], int full)
{
	struct gsm_bts *bts = vty->index;
	struct amr_multirate_conf *mr = (full) ? &bts->mr_full: &bts->mr_half;
	struct gsm48_multi_rate_conf *mr_conf =
				(struct gsm48_multi_rate_conf *) mr->gsm48_ie;
	int num = 0, i;

	for (i = 0; i < ((full) ? 8 : 6); i++) {
		if ((mr->gsm48_ie[1] & (1 << i))) {
			num++;
		}
	}

	if (argv[0][0] == 'a' || num == 0)
		mr_conf->icmi = 0;
	else {
		mr_conf->icmi = 1;
		if (num < atoi(argv[0]))
			mr_conf->smod = num - 1;
		else
			mr_conf->smod = atoi(argv[0]) - 1;
	}
}

#define AMR_TCHF_PAR_STR " (0|1|2|3|4|5|6|7)"
#define AMR_TCHF_HELP_STR "4,75k\n5,15k\n5,90k\n6,70k\n7,40k\n7,95k\n" \
	"10,2k\n12,2k\n"

#define AMR_TCHH_PAR_STR " (0|1|2|3|4|5)"
#define AMR_TCHH_HELP_STR "4,75k\n5,15k\n5,90k\n6,70k\n7,40k\n7,95k\n"

#define	AMR_TH_HELP_STR "Threshold between codec 1 and 2\n"
#define	AMR_HY_HELP_STR "Hysteresis between codec 1 and 2\n"

DEFUN(cfg_bts_amr_fr_modes1, cfg_bts_amr_fr_modes1_cmd,
	"amr tch-f modes" AMR_TCHF_PAR_STR,
	AMR_TEXT "Full Rate\n" AMR_MODE_TEXT
	AMR_TCHF_HELP_STR)
{
	get_amr_from_arg(vty, 1, argv, 1);
	return CMD_SUCCESS;
}

DEFUN(cfg_bts_amr_fr_modes2, cfg_bts_amr_fr_modes2_cmd,
	"amr tch-f modes" AMR_TCHF_PAR_STR AMR_TCHF_PAR_STR,
	AMR_TEXT "Full Rate\n" AMR_MODE_TEXT
	AMR_TCHF_HELP_STR AMR_TCHF_HELP_STR)
{
	get_amr_from_arg(vty, 2, argv, 1);
	return CMD_SUCCESS;
}

DEFUN(cfg_bts_amr_fr_modes3, cfg_bts_amr_fr_modes3_cmd,
	"amr tch-f modes" AMR_TCHF_PAR_STR AMR_TCHF_PAR_STR AMR_TCHF_PAR_STR,
	AMR_TEXT "Full Rate\n" AMR_MODE_TEXT
	AMR_TCHF_HELP_STR AMR_TCHF_HELP_STR AMR_TCHF_HELP_STR)
{
	get_amr_from_arg(vty, 3, argv, 1);
	return CMD_SUCCESS;
}

DEFUN(cfg_bts_amr_fr_modes4, cfg_bts_amr_fr_modes4_cmd,
	"amr tch-f modes" AMR_TCHF_PAR_STR AMR_TCHF_PAR_STR AMR_TCHF_PAR_STR AMR_TCHF_PAR_STR,
	AMR_TEXT "Full Rate\n" AMR_MODE_TEXT
	AMR_TCHF_HELP_STR AMR_TCHF_HELP_STR AMR_TCHF_HELP_STR AMR_TCHF_HELP_STR)
{
	get_amr_from_arg(vty, 4, argv, 1);
	return CMD_SUCCESS;
}

DEFUN(cfg_bts_amr_fr_start_mode, cfg_bts_amr_fr_start_mode_cmd,
	"amr tch-f start-mode (auto|1|2|3|4)",
	AMR_TEXT "Full Rate\n" AMR_START_TEXT)
{
	get_amr_start_from_arg(vty, argv, 1);
	return CMD_SUCCESS;
}

DEFUN(cfg_bts_amr_fr_thres1, cfg_bts_amr_fr_thres1_cmd,
	"amr tch-f threshold (ms|bts) <0-63>",
	AMR_TEXT "Full Rate\n" AMR_TH_TEXT
	AMR_TH_HELP_STR)
{
	get_amr_th_from_arg(vty, 2, argv, 1);
	return CMD_SUCCESS;
}

DEFUN(cfg_bts_amr_fr_thres2, cfg_bts_amr_fr_thres2_cmd,
	"amr tch-f threshold (ms|bts) <0-63> <0-63>",
	AMR_TEXT "Full Rate\n" AMR_TH_TEXT
	AMR_TH_HELP_STR AMR_TH_HELP_STR)
{
	get_amr_th_from_arg(vty, 3, argv, 1);
	return CMD_SUCCESS;
}

DEFUN(cfg_bts_amr_fr_thres3, cfg_bts_amr_fr_thres3_cmd,
	"amr tch-f threshold (ms|bts) <0-63> <0-63> <0-63>",
	AMR_TEXT "Full Rate\n" AMR_TH_TEXT
	AMR_TH_HELP_STR AMR_TH_HELP_STR AMR_TH_HELP_STR)
{
	get_amr_th_from_arg(vty, 4, argv, 1);
	return CMD_SUCCESS;
}

DEFUN(cfg_bts_amr_fr_hyst1, cfg_bts_amr_fr_hyst1_cmd,
	"amr tch-f hysteresis (ms|bts) <0-15>",
	AMR_TEXT "Full Rate\n" AMR_HY_TEXT
	AMR_HY_HELP_STR)
{
	get_amr_hy_from_arg(vty, 2, argv, 1);
	return CMD_SUCCESS;
}

DEFUN(cfg_bts_amr_fr_hyst2, cfg_bts_amr_fr_hyst2_cmd,
	"amr tch-f hysteresis (ms|bts) <0-15> <0-15>",
	AMR_TEXT "Full Rate\n" AMR_HY_TEXT
	AMR_HY_HELP_STR AMR_HY_HELP_STR)
{
	get_amr_hy_from_arg(vty, 3, argv, 1);
	return CMD_SUCCESS;
}

DEFUN(cfg_bts_amr_fr_hyst3, cfg_bts_amr_fr_hyst3_cmd,
	"amr tch-f hysteresis (ms|bts) <0-15> <0-15> <0-15>",
	AMR_TEXT "Full Rate\n" AMR_HY_TEXT
	AMR_HY_HELP_STR AMR_HY_HELP_STR AMR_HY_HELP_STR)
{
	get_amr_hy_from_arg(vty, 4, argv, 1);
	return CMD_SUCCESS;
}

DEFUN(cfg_bts_amr_hr_modes1, cfg_bts_amr_hr_modes1_cmd,
	"amr tch-h modes" AMR_TCHH_PAR_STR,
	AMR_TEXT "Half Rate\n" AMR_MODE_TEXT
	AMR_TCHH_HELP_STR)
{
	get_amr_from_arg(vty, 1, argv, 0);
	return CMD_SUCCESS;
}

DEFUN(cfg_bts_amr_hr_modes2, cfg_bts_amr_hr_modes2_cmd,
	"amr tch-h modes" AMR_TCHH_PAR_STR AMR_TCHH_PAR_STR,
	AMR_TEXT "Half Rate\n" AMR_MODE_TEXT
	AMR_TCHH_HELP_STR AMR_TCHH_HELP_STR)
{
	get_amr_from_arg(vty, 2, argv, 0);
	return CMD_SUCCESS;
}

DEFUN(cfg_bts_amr_hr_modes3, cfg_bts_amr_hr_modes3_cmd,
	"amr tch-h modes" AMR_TCHH_PAR_STR AMR_TCHH_PAR_STR AMR_TCHH_PAR_STR,
	AMR_TEXT "Half Rate\n" AMR_MODE_TEXT
	AMR_TCHH_HELP_STR AMR_TCHH_HELP_STR AMR_TCHH_HELP_STR)
{
	get_amr_from_arg(vty, 3, argv, 0);
	return CMD_SUCCESS;
}

DEFUN(cfg_bts_amr_hr_modes4, cfg_bts_amr_hr_modes4_cmd,
	"amr tch-h modes" AMR_TCHH_PAR_STR AMR_TCHH_PAR_STR AMR_TCHH_PAR_STR AMR_TCHH_PAR_STR,
	AMR_TEXT "Half Rate\n" AMR_MODE_TEXT
	AMR_TCHH_HELP_STR AMR_TCHH_HELP_STR AMR_TCHH_HELP_STR AMR_TCHH_HELP_STR)
{
	get_amr_from_arg(vty, 4, argv, 0);
	return CMD_SUCCESS;
}

DEFUN(cfg_bts_amr_hr_start_mode, cfg_bts_amr_hr_start_mode_cmd,
	"amr tch-h start-mode (auto|1|2|3|4)",
	AMR_TEXT "Half Rate\n" AMR_START_TEXT)
{
	get_amr_start_from_arg(vty, argv, 0);
	return CMD_SUCCESS;
}

DEFUN(cfg_bts_amr_hr_thres1, cfg_bts_amr_hr_thres1_cmd,
	"amr tch-h threshold (ms|bts) <0-63>",
	AMR_TEXT "Half Rate\n" AMR_TH_TEXT
	AMR_TH_HELP_STR)
{
	get_amr_th_from_arg(vty, 2, argv, 0);
	return CMD_SUCCESS;
}

DEFUN(cfg_bts_amr_hr_thres2, cfg_bts_amr_hr_thres2_cmd,
	"amr tch-h threshold (ms|bts) <0-63> <0-63>",
	AMR_TEXT "Half Rate\n" AMR_TH_TEXT
	AMR_TH_HELP_STR AMR_TH_HELP_STR)
{
	get_amr_th_from_arg(vty, 3, argv, 0);
	return CMD_SUCCESS;
}

DEFUN(cfg_bts_amr_hr_thres3, cfg_bts_amr_hr_thres3_cmd,
	"amr tch-h threshold (ms|bts) <0-63> <0-63> <0-63>",
	AMR_TEXT "Half Rate\n" AMR_TH_TEXT
	AMR_TH_HELP_STR AMR_TH_HELP_STR AMR_TH_HELP_STR)
{
	get_amr_th_from_arg(vty, 4, argv, 0);
	return CMD_SUCCESS;
}

DEFUN(cfg_bts_amr_hr_hyst1, cfg_bts_amr_hr_hyst1_cmd,
	"amr tch-h hysteresis (ms|bts) <0-15>",
	AMR_TEXT "Half Rate\n" AMR_HY_TEXT
	AMR_HY_HELP_STR)
{
	get_amr_hy_from_arg(vty, 2, argv, 0);
	return CMD_SUCCESS;
}

DEFUN(cfg_bts_amr_hr_hyst2, cfg_bts_amr_hr_hyst2_cmd,
	"amr tch-h hysteresis (ms|bts) <0-15> <0-15>",
	AMR_TEXT "Half Rate\n" AMR_HY_TEXT
	AMR_HY_HELP_STR AMR_HY_HELP_STR)
{
	get_amr_hy_from_arg(vty, 3, argv, 0);
	return CMD_SUCCESS;
}

DEFUN(cfg_bts_amr_hr_hyst3, cfg_bts_amr_hr_hyst3_cmd,
	"amr tch-h hysteresis (ms|bts) <0-15> <0-15> <0-15>",
	AMR_TEXT "Half Rate\n" AMR_HY_TEXT
	AMR_HY_HELP_STR AMR_HY_HELP_STR AMR_HY_HELP_STR)
{
	get_amr_hy_from_arg(vty, 4, argv, 0);
	return CMD_SUCCESS;
}

#define TRX_TEXT "Radio Transceiver\n"

/* per TRX configuration */
DEFUN(cfg_trx,
      cfg_trx_cmd,
      "trx <0-255>",
	TRX_TEXT
      "Select a TRX to configure")
{
	int trx_nr = atoi(argv[0]);
	struct gsm_bts *bts = vty->index;
	struct gsm_bts_trx *trx;

	if (trx_nr > bts->num_trx) {
		vty_out(vty, "%% The next unused TRX number in this BTS is %u%s",
			bts->num_trx, VTY_NEWLINE);
		return CMD_WARNING;
	} else if (trx_nr == bts->num_trx) {
		/* we need to allocate a new one */
		trx = gsm_bts_trx_alloc(bts);
	} else
		trx = gsm_bts_trx_num(bts, trx_nr);

	if (!trx)
		return CMD_WARNING;

	vty->index = trx;
	vty->index_sub = &trx->description;
	vty->node = TRX_NODE;

	return CMD_SUCCESS;
}

DEFUN(cfg_trx_arfcn,
      cfg_trx_arfcn_cmd,
      "arfcn <0-1023>",
      "Set the ARFCN for this TRX\n"
      "Absolute Radio Frequency Channel Number\n")
{
	int arfcn = atoi(argv[0]);
	struct gsm_bts_trx *trx = vty->index;

	/* FIXME: check if this ARFCN is supported by this TRX */

	trx->arfcn = arfcn;

	/* FIXME: patch ARFCN into SYSTEM INFORMATION */
	/* FIXME: use OML layer to update the ARFCN */
	/* FIXME: use RSL layer to update SYSTEM INFORMATION */

	return CMD_SUCCESS;
}

DEFUN(cfg_trx_nominal_power,
      cfg_trx_nominal_power_cmd,
      "nominal power <0-100>",
      "Nominal TRX RF Power in dBm\n"
      "Nominal TRX RF Power in dBm\n"
      "Nominal TRX RF Power in dBm\n")
{
	struct gsm_bts_trx *trx = vty->index;

	trx->nominal_power = atoi(argv[0]);

	return CMD_SUCCESS;
}

DEFUN(cfg_trx_max_power_red,
      cfg_trx_max_power_red_cmd,
      "max_power_red <0-100>",
      "Reduction of maximum BS RF Power (relative to nominal power)\n"
      "Reduction of maximum BS RF Power in dB\n")
{
	int maxpwr_r = atoi(argv[0]);
	struct gsm_bts_trx *trx = vty->index;
	int upper_limit = 24;	/* default 12.21 max power red. */

	/* FIXME: check if our BTS type supports more than 12 */
	if (maxpwr_r < 0 || maxpwr_r > upper_limit) {
		vty_out(vty, "%% Power %d dB is not in the valid range%s",
			maxpwr_r, VTY_NEWLINE);
		return CMD_WARNING;
	}
	if (maxpwr_r & 1) {
		vty_out(vty, "%% Power %d dB is not an even value%s",
			maxpwr_r, VTY_NEWLINE);
		return CMD_WARNING;
	}

	trx->max_power_red = maxpwr_r;

	/* FIXME: make sure we update this using OML */

	return CMD_SUCCESS;
}

DEFUN(cfg_trx_rsl_e1,
      cfg_trx_rsl_e1_cmd,
      "rsl e1 line E1_LINE timeslot <1-31> sub-slot (0|1|2|3|full)",
      "RSL Parameters\n"
      "E1/T1 interface to be used for RSL\n"
      "E1/T1 interface to be used for RSL\n"
      "E1/T1 Line Number to be used for RSL\n"
      "E1/T1 Timeslot to be used for RSL\n"
      "E1/T1 Timeslot to be used for RSL\n"
      "E1/T1 Sub-slot to be used for RSL\n"
      "E1/T1 Sub-slot 0 is to be used for RSL\n"
      "E1/T1 Sub-slot 1 is to be used for RSL\n"
      "E1/T1 Sub-slot 2 is to be used for RSL\n"
      "E1/T1 Sub-slot 3 is to be used for RSL\n"
      "E1/T1 full timeslot is to be used for RSL\n")
{
	struct gsm_bts_trx *trx = vty->index;

	parse_e1_link(&trx->rsl_e1_link, argv[0], argv[1], argv[2]);

	return CMD_SUCCESS;
}

DEFUN(cfg_trx_rsl_e1_tei,
      cfg_trx_rsl_e1_tei_cmd,
      "rsl e1 tei <0-63>",
      "RSL Parameters\n"
      "Set the TEI to be used for RSL\n"
      "Set the TEI to be used for RSL\n"
      "TEI to be used for RSL\n")
{
	struct gsm_bts_trx *trx = vty->index;

	trx->rsl_tei = atoi(argv[0]);

	return CMD_SUCCESS;
}

DEFUN(cfg_trx_rf_locked,
      cfg_trx_rf_locked_cmd,
      "rf_locked (0|1)",
      "Set or unset the RF Locking (Turn off RF of the TRX)\n"
      "TRX is NOT RF locked (active)\n"
      "TRX is RF locked (turned off)\n")
{
	int locked = atoi(argv[0]);
	struct gsm_bts_trx *trx = vty->index;

	gsm_trx_lock_rf(trx, locked);
	return CMD_SUCCESS;
}

/* per TS configuration */
DEFUN(cfg_ts,
      cfg_ts_cmd,
      "timeslot <0-7>",
      "Select a Timeslot to configure\n"
      "Timeslot number\n")
{
	int ts_nr = atoi(argv[0]);
	struct gsm_bts_trx *trx = vty->index;
	struct gsm_bts_trx_ts *ts;

	if (ts_nr >= TRX_NR_TS) {
		vty_out(vty, "%% A GSM TRX only has %u Timeslots per TRX%s",
			TRX_NR_TS, VTY_NEWLINE);
		return CMD_WARNING;
	}

	ts = &trx->ts[ts_nr];

	vty->index = ts;
	vty->node = TS_NODE;

	return CMD_SUCCESS;
}

DEFUN(cfg_ts_pchan,
      cfg_ts_pchan_cmd,
      "phys_chan_config PCHAN", /* dynamically generated! */
      "Physical Channel configuration (TCH/SDCCH/...)\n" "Physical Channel\n")
{
	struct gsm_bts_trx_ts *ts = vty->index;
	int pchanc;

	pchanc = gsm_pchan_parse(argv[0]);
	if (pchanc < 0)
		return CMD_WARNING;

	ts->pchan = pchanc;

	return CMD_SUCCESS;
}

/* used for backwards compatibility with old config files that still
 * have uppercase pchan type names */
DEFUN_HIDDEN(cfg_ts_pchan_compat,
      cfg_ts_pchan_compat_cmd,
      "phys_chan_config PCHAN",
      "Physical Channel configuration (TCH/SDCCH/...)\n" "Physical Channel\n")
{
	struct gsm_bts_trx_ts *ts = vty->index;
	int pchanc;

	pchanc = gsm_pchan_parse(argv[0]);
	if (pchanc < 0)
		return CMD_WARNING;

	ts->pchan = pchanc;

	return CMD_SUCCESS;
}



DEFUN(cfg_ts_tsc,
      cfg_ts_tsc_cmd,
      "training_sequence_code <0-7>",
      "Training Sequence Code of the Timeslot\n" "TSC\n")
{
	struct gsm_bts_trx_ts *ts = vty->index;

	if (!gsm_btsmodel_has_feature(ts->trx->bts->model, BTS_FEAT_MULTI_TSC)) {
		vty_out(vty, "%% This BTS does not support a TSC != BCC, "
			"falling back to BCC%s", VTY_NEWLINE);
		ts->tsc = -1;
		return CMD_WARNING;
	}

	ts->tsc = atoi(argv[0]);

	return CMD_SUCCESS;
}

#define HOPPING_STR "Configure frequency hopping\n"

DEFUN(cfg_ts_hopping,
      cfg_ts_hopping_cmd,
      "hopping enabled (0|1)",
	HOPPING_STR "Enable or disable frequency hopping\n"
      "Disable frequency hopping\n" "Enable frequency hopping\n")
{
	struct gsm_bts_trx_ts *ts = vty->index;
	int enabled = atoi(argv[0]);

	if (enabled && !gsm_btsmodel_has_feature(ts->trx->bts->model, BTS_FEAT_HOPPING)) {
		vty_out(vty, "BTS model does not support hopping%s",
			VTY_NEWLINE);
		return CMD_WARNING;
	}

	ts->hopping.enabled = enabled;

	return CMD_SUCCESS;
}

DEFUN(cfg_ts_hsn,
      cfg_ts_hsn_cmd,
      "hopping sequence-number <0-63>",
	HOPPING_STR
      "Which hopping sequence to use for this channel\n"
      "Hopping Sequence Number (HSN)\n")
{
	struct gsm_bts_trx_ts *ts = vty->index;

	ts->hopping.hsn = atoi(argv[0]);

	return CMD_SUCCESS;
}

DEFUN(cfg_ts_maio,
      cfg_ts_maio_cmd,
      "hopping maio <0-63>",
	HOPPING_STR
      "Which hopping MAIO to use for this channel\n"
      "Mobile Allocation Index Offset (MAIO)\n")
{
	struct gsm_bts_trx_ts *ts = vty->index;

	ts->hopping.maio = atoi(argv[0]);

	return CMD_SUCCESS;
}

DEFUN(cfg_ts_arfcn_add,
      cfg_ts_arfcn_add_cmd,
      "hopping arfcn add <0-1023>",
	HOPPING_STR "Configure hopping ARFCN list\n"
      "Add an entry to the hopping ARFCN list\n" "ARFCN\n")
{
	struct gsm_bts_trx_ts *ts = vty->index;
	int arfcn = atoi(argv[0]);

	bitvec_set_bit_pos(&ts->hopping.arfcns, arfcn, 1);

	return CMD_SUCCESS;
}

DEFUN(cfg_ts_arfcn_del,
      cfg_ts_arfcn_del_cmd,
      "hopping arfcn del <0-1023>",
	HOPPING_STR "Configure hopping ARFCN list\n"
      "Delete an entry to the hopping ARFCN list\n" "ARFCN\n")
{
	struct gsm_bts_trx_ts *ts = vty->index;
	int arfcn = atoi(argv[0]);

	bitvec_set_bit_pos(&ts->hopping.arfcns, arfcn, 0);

	return CMD_SUCCESS;
}

DEFUN(cfg_ts_e1_subslot,
      cfg_ts_e1_subslot_cmd,
      "e1 line E1_LINE timeslot <1-31> sub-slot (0|1|2|3|full)",
      "E1/T1 channel connected to this on-air timeslot\n"
      "E1/T1 channel connected to this on-air timeslot\n"
      "E1/T1 line connected to this on-air timeslot\n"
      "E1/T1 timeslot connected to this on-air timeslot\n"
      "E1/T1 timeslot connected to this on-air timeslot\n"
      "E1/T1 sub-slot connected to this on-air timeslot\n"
      "E1/T1 sub-slot 0 connected to this on-air timeslot\n"
      "E1/T1 sub-slot 1 connected to this on-air timeslot\n"
      "E1/T1 sub-slot 2 connected to this on-air timeslot\n"
      "E1/T1 sub-slot 3 connected to this on-air timeslot\n"
      "Full E1/T1 timeslot connected to this on-air timeslot\n")
{
	struct gsm_bts_trx_ts *ts = vty->index;

	parse_e1_link(&ts->e1_link, argv[0], argv[1], argv[2]);

	return CMD_SUCCESS;
}

void openbsc_vty_print_statistics(struct vty *vty, struct gsm_network *net)
{
	vty_out(vty, "Channel Requests        : %lu total, %lu no channel%s",
		net->bsc_ctrs->ctr[BSC_CTR_CHREQ_TOTAL].current,
		net->bsc_ctrs->ctr[BSC_CTR_CHREQ_NO_CHANNEL].current,
		VTY_NEWLINE);
	vty_out(vty, "Channel Failures        : %lu rf_failures, %lu rll failures%s",
		net->bsc_ctrs->ctr[BSC_CTR_CHAN_RF_FAIL].current,
		net->bsc_ctrs->ctr[BSC_CTR_CHAN_RLL_ERR].current,
		VTY_NEWLINE);
	vty_out(vty, "Paging                  : %lu attempted, %lu complete, %lu expired%s",
		net->bsc_ctrs->ctr[BSC_CTR_PAGING_ATTEMPTED].current,
		net->bsc_ctrs->ctr[BSC_CTR_PAGING_COMPLETED].current,
		net->bsc_ctrs->ctr[BSC_CTR_PAGING_EXPIRED].current,
		VTY_NEWLINE);
	vty_out(vty, "BTS failures            : %lu OML, %lu RSL%s",
		net->bsc_ctrs->ctr[BSC_CTR_BTS_OML_FAIL].current,
		net->bsc_ctrs->ctr[BSC_CTR_BTS_RSL_FAIL].current,
		VTY_NEWLINE);
}

DEFUN(drop_bts,
      drop_bts_cmd,
      "drop bts connection <0-65535> (oml|rsl)",
      "Debug/Simulation command to drop Abis/IP BTS\n"
      "Debug/Simulation command to drop Abis/IP BTS\n"
      "Debug/Simulation command to drop Abis/IP BTS\n"
      "BTS NR\n" "Drop OML Connection\n" "Drop RSL Connection\n")
{
	struct gsm_network *gsmnet;
	struct gsm_bts_trx *trx;
	struct gsm_bts *bts;
	unsigned int bts_nr;

	gsmnet = gsmnet_from_vty(vty);

	bts_nr = atoi(argv[0]);
	if (bts_nr >= gsmnet->num_bts) {
		vty_out(vty, "BTS number must be between 0 and %d. It was %d.%s",
			gsmnet->num_bts, bts_nr, VTY_NEWLINE);
		return CMD_WARNING;
	}

	bts = gsm_bts_num(gsmnet, bts_nr);
	if (!bts) {
		vty_out(vty, "BTS Nr. %d could not be found.%s", bts_nr, VTY_NEWLINE);
		return CMD_WARNING;
	}

	if (!is_ipaccess_bts(bts)) {
		vty_out(vty, "This command only works for ipaccess.%s", VTY_NEWLINE);
		return CMD_WARNING;
	}


	/* close all connections */
	if (strcmp(argv[1], "oml") == 0) {
		ipaccess_drop_oml(bts);
	} else if (strcmp(argv[1], "rsl") == 0) {
		/* close all rsl connections */
		llist_for_each_entry(trx, &bts->trx_list, list) {
			ipaccess_drop_rsl(trx);
		}
	} else {
		vty_out(vty, "Argument must be 'oml# or 'rsl'.%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	return CMD_SUCCESS;
}

DEFUN(restart_bts, restart_bts_cmd,
      "restart-bts <0-65535>",
      "Restart ip.access nanoBTS through OML\n"
      "BTS Number\n")
{
	struct gsm_network *gsmnet;
	struct gsm_bts_trx *trx;
	struct gsm_bts *bts;
	unsigned int bts_nr;

	gsmnet = gsmnet_from_vty(vty);

	bts_nr = atoi(argv[0]);
	if (bts_nr >= gsmnet->num_bts) {
		vty_out(vty, "BTS number must be between 0 and %d. It was %d.%s",
			gsmnet->num_bts, bts_nr, VTY_NEWLINE);
		return CMD_WARNING;
	}

	bts = gsm_bts_num(gsmnet, bts_nr);
	if (!bts) {
		vty_out(vty, "BTS Nr. %d could not be found.%s", bts_nr, VTY_NEWLINE);
		return CMD_WARNING;
	}

	if (!is_ipaccess_bts(bts) || is_sysmobts_v2(bts)) {
		vty_out(vty, "This command only works for ipaccess nanoBTS.%s",
			VTY_NEWLINE);
		return CMD_WARNING;
	}

	/* go from last TRX to c0 */
	llist_for_each_entry_reverse(trx, &bts->trx_list, list)
		abis_nm_ipaccess_restart(trx);

	return CMD_SUCCESS;
}

DEFUN(smscb_cmd, smscb_cmd_cmd,
	"bts <0-255> smscb-command <1-4> HEXSTRING",
	"BTS related commands\n" "BTS Number\n"
	"SMS Cell Broadcast\n" "Last Valid Block\n"
	"Hex Encoded SMSCB message (up to 88 octets)\n")
{
	struct gsm_bts *bts;
	int bts_nr = atoi(argv[0]);
	int last_block = atoi(argv[1]);
	struct rsl_ie_cb_cmd_type cb_cmd;
	uint8_t buf[88];
	int rc;

	bts = gsm_bts_num(gsmnet_from_vty(vty), bts_nr);
	if (!bts) {
		vty_out(vty, "%% No such BTS (%d)%s", bts_nr, VTY_NEWLINE);
		return CMD_WARNING;
	}
	rc = osmo_hexparse(argv[2], buf, sizeof(buf));
	if (rc < 0 || rc > sizeof(buf)) {
		vty_out(vty, "Error parsing HEXSTRING%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	cb_cmd.spare = 0;
	cb_cmd.def_bcast = 0;
	cb_cmd.command = RSL_CB_CMD_TYPE_NORMAL;

	switch (last_block) {
	case 1:
		cb_cmd.last_block = RSL_CB_CMD_LASTBLOCK_1;
		break;
	case 2:
		cb_cmd.last_block = RSL_CB_CMD_LASTBLOCK_2;
		break;
	case 3:
		cb_cmd.last_block = RSL_CB_CMD_LASTBLOCK_3;
		break;
	case 4:
		cb_cmd.last_block = RSL_CB_CMD_LASTBLOCK_4;
		break;
	}

	rsl_sms_cb_command(bts, RSL_CHAN_SDCCH4_ACCH, cb_cmd, buf, rc);

	return CMD_SUCCESS;
}

/* resolve a gsm_bts_trx_ts basd on the given numeric identifiers */
static struct gsm_bts_trx_ts *vty_get_ts(struct vty *vty, const char *bts_str, const char *trx_str,
					 const char *ts_str)
{
	int bts_nr = atoi(bts_str);
	int trx_nr = atoi(trx_str);
	int ts_nr = atoi(ts_str);
	struct gsm_bts *bts;
	struct gsm_bts_trx *trx;
	struct gsm_bts_trx_ts *ts;

	bts = gsm_bts_num(gsmnet_from_vty(vty), bts_nr);
	if (!bts) {
		vty_out(vty, "%% No such BTS (%d)%s", bts_nr, VTY_NEWLINE);
		return NULL;
	}

	trx = gsm_bts_trx_num(bts, trx_nr);
	if (!trx) {
		vty_out(vty, "%% No such TRX (%d)%s", trx_nr, VTY_NEWLINE);
		return NULL;
	}

	ts = &trx->ts[ts_nr];

	return ts;
}

DEFUN(pdch_act, pdch_act_cmd,
	"bts <0-255> trx <0-255> timeslot <0-7> pdch (activate|deactivate)",
	"BTS related commands\n" "BTS Number\n" "Transceiver\n" "Transceiver Number\n"
	"TRX Timeslot\n" "Timeslot Number\n" "Packet Data Channel\n"
	"Activate Dynamic PDCH/TCH (-> PDCH mode)\n"
	"Deactivate Dynamic PDCH/TCH (-> TCH mode)\n")
{
	struct gsm_bts_trx_ts *ts;
	int activate;

	ts = vty_get_ts(vty, argv[0], argv[1], argv[2]);
	if (!ts)
		return CMD_WARNING;

	if (!is_ipaccess_bts(ts->trx->bts)) {
		vty_out(vty, "%% This command only works for ipaccess BTS%s",
			VTY_NEWLINE);
		return CMD_WARNING;
	}

	if (ts->pchan != GSM_PCHAN_TCH_F_PDCH) {
		vty_out(vty, "%% Timeslot %u is not in dynamic TCH_F/PDCH "
			"mode%s", ts->nr, VTY_NEWLINE);
		return CMD_WARNING;
	}

	if (!strcmp(argv[3], "activate"))
		activate = 1;
	else
		activate = 0;

	rsl_ipacc_pdch_activate(ts, activate);

	return CMD_SUCCESS;

}

/* determine the logical channel type based on the physical channel type */
static int lchan_type_by_pchan(enum gsm_phys_chan_config pchan)
{
	switch (pchan) {
	case GSM_PCHAN_TCH_F:
		return GSM_LCHAN_TCH_F;
	case GSM_PCHAN_TCH_H:
		return GSM_LCHAN_TCH_H;
	case GSM_PCHAN_SDCCH8_SACCH8C:
	case GSM_PCHAN_SDCCH8_SACCH8C_CBCH:
	case GSM_PCHAN_CCCH_SDCCH4:
	case GSM_PCHAN_CCCH_SDCCH4_CBCH:
		return GSM_LCHAN_SDCCH;
	default:
		return -1;
	}
}

/* configure the lchan for a single AMR mode (as specified) */
static int lchan_set_single_amr_mode(struct gsm_lchan *lchan, uint8_t amr_mode)
{
	struct amr_multirate_conf mr;
	struct gsm48_multi_rate_conf *mr_conf;
	mr_conf = (struct gsm48_multi_rate_conf *) &mr.gsm48_ie;

	if (amr_mode > 7)
		return -1;

	memset(&mr, 0, sizeof(mr));
	mr_conf->ver = 1;
	/* bit-mask of supported modes, only one bit is set. Reflects
	 * Figure 10.5.2.47a where there are no thershold and only a
	 * single mode */
	mr.gsm48_ie[1] = 1 << amr_mode;

	mr.ms_mode[0].mode = amr_mode;
	mr.bts_mode[0].mode = amr_mode;

	/* encode this configuration into the lchan for both uplink and
	 * downlink direction */
	gsm48_multirate_config(lchan->mr_ms_lv, &mr, mr.ms_mode);
	gsm48_multirate_config(lchan->mr_bts_lv, &mr, mr.bts_mode);

	return 0;
}

/* Debug/Measurement command to activate a given logical channel
 * manually in a given mode/codec.  This is useful for receiver
 * performance testing (FER/RBER/...) */
DEFUN(lchan_act, lchan_act_cmd,
	"bts <0-255> trx <0-255> timeslot <0-7> sub-slot <0-7> (activate|deactivate) (hr|fr|efr|amr) [<0-7>]",
	"BTS related commands\n" "BTS Number\n" "Transceiver\n" "Transceiver Number\n"
	"TRX Timeslot\n" "Timeslot Number\n" "Sub-Slot Number\n" "Sub-Slot Number\n"
	"Manual Channel Activation (e.g. for BER test)\n"
	"Manual Channel Deactivation (e.g. for BER test)\n"
	"Half-Rate v1\n" "Full-Rate\n" "Enhanced Full Rate\n" "Adaptive Multi-Rate\n" "AMR Mode\n")
{
	struct gsm_bts_trx_ts *ts;
	struct gsm_lchan *lchan;
	int ss_nr = atoi(argv[3]);
	const char *act_str = argv[4];
	const char *codec_str = argv[5];
	int activate;

	ts = vty_get_ts(vty, argv[0], argv[1], argv[2]);
	if (!ts)
		return CMD_WARNING;

	lchan = &ts->lchan[ss_nr];

	if (!strcmp(act_str, "activate"))
		activate = 1;
	else
		activate = 0;

	if (ss_nr >= ts_subslots(ts)) {
		vty_out(vty, "%% subslot %d >= permitted %d for physical channel %s%s",
			ss_nr, ts_subslots(ts), gsm_pchan_name(ts->pchan), VTY_NEWLINE);
		return CMD_WARNING;
	}

	if (activate) {
		int lchan_t;
		if (lchan->state != LCHAN_S_NONE) {
			vty_out(vty, "%% Cannot activate: Channel busy!%s", VTY_NEWLINE);
			return CMD_WARNING;
		}
		lchan_t = lchan_type_by_pchan(ts->pchan);
		if (lchan_t < 0)
			return CMD_WARNING;
		/* configure the lchan */
		lchan->type = lchan_t;
		lchan->rsl_cmode = RSL_CMOD_SPD_SPEECH;
		if (!strcmp(codec_str, "hr") || !strcmp(codec_str, "fr"))
			lchan->tch_mode = GSM48_CMODE_SPEECH_V1;
		else if (!strcmp(codec_str, "efr"))
			lchan->tch_mode = GSM48_CMODE_SPEECH_EFR;
		else if (!strcmp(codec_str, "amr")) {
			int amr_mode;
			if (argc < 7) {
				vty_out(vty, "%% AMR requires specification of AMR mode%s", VTY_NEWLINE);
				return CMD_WARNING;
			}
			amr_mode = atoi(argv[6]);
			lchan->tch_mode = GSM48_CMODE_SPEECH_AMR;
			lchan_set_single_amr_mode(lchan, amr_mode);
		}
		vty_out(vty, "%% activating lchan %s%s", gsm_lchan_name(lchan), VTY_NEWLINE);
		rsl_chan_activate_lchan(lchan, RSL_ACT_TYPE_INITIAL, 0);
		rsl_ipacc_crcx(lchan);
	} else {
		rsl_direct_rf_release(lchan);
	}

	return CMD_SUCCESS;
}

DEFUN(lchan_mdcx, lchan_mdcx_cmd,
	"bts <0-255> trx <0-255> timeslot <0-7> sub-slot <0-7> mdcx A.B.C.D <0-65535>",
	"BTS related commands\n" "BTS Number\n" "Transceiver\n" "Transceiver Number\n"
	"TRX Timeslot\n" "Timeslot Number\n" "Sub-Slot\n" "Sub-Slot Number\n"
	"Modify RTP Connection\n" "MGW IP Address\n" "MGW UDP Port\n")
{
	struct gsm_bts_trx_ts *ts;
	struct gsm_lchan *lchan;
	int ss_nr = atoi(argv[3]);
	int port = atoi(argv[5]);
	struct in_addr ia;
	inet_aton(argv[4], &ia);

	ts = vty_get_ts(vty, argv[0], argv[1], argv[2]);
	if (!ts)
		return CMD_WARNING;

	lchan = &ts->lchan[ss_nr];

	if (ss_nr >= ts_subslots(ts)) {
		vty_out(vty, "%% subslot %d >= permitted %d for physical channel %s%s",
			ss_nr, ts_subslots(ts), gsm_pchan_name(ts->pchan), VTY_NEWLINE);
		return CMD_WARNING;
	}

	vty_out(vty, "%% connecting RTP of %s to %s:%u%s", gsm_lchan_name(lchan),
		inet_ntoa(ia), port, VTY_NEWLINE);
	rsl_ipacc_mdcx(lchan, ntohl(ia.s_addr), port, 0);
	return CMD_SUCCESS;
}
extern int bsc_vty_init_extra(void);

int bsc_vty_init(struct gsm_network *network)
{
	cfg_ts_pchan_cmd.string =
		vty_cmd_string_from_valstr(tall_bsc_ctx,
					   gsm_pchant_names,
					   "phys_chan_config (", "|", ")",
					   VTY_DO_LOWER);
	cfg_ts_pchan_cmd.doc =
		vty_cmd_string_from_valstr(tall_bsc_ctx,
					   gsm_pchant_descs,
					   "Physical Channel Combination\n",
					   "\n", "", 0);

	cfg_bts_type_cmd.string =
		vty_cmd_string_from_valstr(tall_bsc_ctx,
					   bts_type_names,
					   "type (", "|", ")",
					   VTY_DO_LOWER);
	cfg_bts_type_cmd.doc =
		vty_cmd_string_from_valstr(tall_bsc_ctx,
					   bts_type_descs,
					   "BTS Vendor/Type\n",
					   "\n", "", 0);

	common_cs_vty_init(network, config_write_net);

	install_element_ve(&bsc_show_net_cmd);
	install_element_ve(&show_bts_cmd);
	install_element_ve(&show_trx_cmd);
	install_element_ve(&show_ts_cmd);
	install_element_ve(&show_lchan_cmd);
	install_element_ve(&show_lchan_summary_cmd);

	install_element_ve(&show_paging_cmd);
	install_element_ve(&show_paging_group_cmd);

	logging_vty_add_cmds(NULL);
	osmo_stats_vty_add_cmds();

	install_element(GSMNET_NODE, &cfg_net_neci_cmd);
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
	install_element(GSMNET_NODE, &cfg_net_pag_any_tch_cmd);

	install_element(GSMNET_NODE, &cfg_bts_cmd);
	install_node(&bts_node, config_write_bts);
	vty_install_default(BTS_NODE);
	install_element(BTS_NODE, &cfg_bts_type_cmd);
	install_element(BTS_NODE, &cfg_description_cmd);
	install_element(BTS_NODE, &cfg_no_description_cmd);
	install_element(BTS_NODE, &cfg_bts_band_cmd);
	install_element(BTS_NODE, &cfg_bts_ci_cmd);
	install_element(BTS_NODE, &cfg_bts_dtxu_cmd);
	install_element(BTS_NODE, &cfg_bts_dtxd_cmd);
	install_element(BTS_NODE, &cfg_bts_no_dtxu_cmd);
	install_element(BTS_NODE, &cfg_bts_no_dtxd_cmd);
	install_element(BTS_NODE, &cfg_bts_lac_cmd);
	install_element(BTS_NODE, &cfg_bts_tsc_cmd);
	install_element(BTS_NODE, &cfg_bts_bsic_cmd);
	install_element(BTS_NODE, &cfg_bts_unit_id_cmd);
	install_element(BTS_NODE, &cfg_bts_rsl_ip_cmd);
	install_element(BTS_NODE, &cfg_bts_nokia_site_skip_reset_cmd);
	install_element(BTS_NODE, &cfg_bts_nokia_site_no_loc_rel_cnf_cmd);
	install_element(BTS_NODE, &cfg_bts_nokia_site_bts_reset_timer_cnf_cmd);
	install_element(BTS_NODE, &cfg_bts_stream_id_cmd);
	install_element(BTS_NODE, &cfg_bts_oml_e1_cmd);
	install_element(BTS_NODE, &cfg_bts_oml_e1_tei_cmd);
	install_element(BTS_NODE, &cfg_bts_challoc_cmd);
	install_element(BTS_NODE, &cfg_bts_rach_tx_integer_cmd);
	install_element(BTS_NODE, &cfg_bts_rach_max_trans_cmd);
	install_element(BTS_NODE, &cfg_bts_chan_desc_att_cmd);
	install_element(BTS_NODE, &cfg_bts_chan_desc_bs_pa_mfrms_cmd);
	install_element(BTS_NODE, &cfg_bts_chan_desc_bs_ag_blks_res_cmd);
	install_element(BTS_NODE, &cfg_bts_rach_nm_b_thresh_cmd);
	install_element(BTS_NODE, &cfg_bts_rach_nm_ldavg_cmd);
	install_element(BTS_NODE, &cfg_bts_cell_barred_cmd);
	install_element(BTS_NODE, &cfg_bts_rach_ec_allowed_cmd);
	install_element(BTS_NODE, &cfg_bts_rach_ac_class_cmd);
	install_element(BTS_NODE, &cfg_bts_ms_max_power_cmd);
	install_element(BTS_NODE, &cfg_bts_per_loc_upd_cmd);
	install_element(BTS_NODE, &cfg_bts_no_per_loc_upd_cmd);
	install_element(BTS_NODE, &cfg_bts_cell_resel_hyst_cmd);
	install_element(BTS_NODE, &cfg_bts_rxlev_acc_min_cmd);
	install_element(BTS_NODE, &cfg_bts_cell_bar_qualify_cmd);
	install_element(BTS_NODE, &cfg_bts_cell_resel_ofs_cmd);
	install_element(BTS_NODE, &cfg_bts_temp_ofs_cmd);
	install_element(BTS_NODE, &cfg_bts_temp_ofs_inf_cmd);
	install_element(BTS_NODE, &cfg_bts_penalty_time_cmd);
	install_element(BTS_NODE, &cfg_bts_penalty_time_rsvd_cmd);
	install_element(BTS_NODE, &cfg_bts_radio_link_timeout_cmd);
	install_element(BTS_NODE, &cfg_bts_radio_link_timeout_inf_cmd);
	install_element(BTS_NODE, &cfg_bts_gprs_mode_cmd);
	install_element(BTS_NODE, &cfg_bts_gprs_11bit_rach_support_for_egprs_cmd);
	install_element(BTS_NODE, &cfg_bts_gprs_ns_timer_cmd);
	install_element(BTS_NODE, &cfg_bts_gprs_rac_cmd);
	install_element(BTS_NODE, &cfg_bts_gprs_net_ctrl_ord_cmd);
	install_element(BTS_NODE, &cfg_bts_gprs_ctrl_ack_cmd);
	install_element(BTS_NODE, &cfg_no_bts_gprs_ctrl_ack_cmd);
	install_element(BTS_NODE, &cfg_bts_gprs_bvci_cmd);
	install_element(BTS_NODE, &cfg_bts_gprs_cell_timer_cmd);
	install_element(BTS_NODE, &cfg_bts_gprs_nsei_cmd);
	install_element(BTS_NODE, &cfg_bts_gprs_nsvci_cmd);
	install_element(BTS_NODE, &cfg_bts_gprs_nsvc_lport_cmd);
	install_element(BTS_NODE, &cfg_bts_gprs_nsvc_rport_cmd);
	install_element(BTS_NODE, &cfg_bts_gprs_nsvc_rip_cmd);
	install_element(BTS_NODE, &cfg_bts_pag_free_cmd);
	install_element(BTS_NODE, &cfg_bts_si_mode_cmd);
	install_element(BTS_NODE, &cfg_bts_si_static_cmd);
	install_element(BTS_NODE, &cfg_bts_early_cm_cmd);
	install_element(BTS_NODE, &cfg_bts_neigh_mode_cmd);
	install_element(BTS_NODE, &cfg_bts_neigh_cmd);
	install_element(BTS_NODE, &cfg_bts_si5_neigh_cmd);
	install_element(BTS_NODE, &cfg_bts_si2quater_neigh_add_cmd);
	install_element(BTS_NODE, &cfg_bts_si2quater_neigh_del_cmd);
	install_element(BTS_NODE, &cfg_bts_si2quater_uarfcn_add_cmd);
	install_element(BTS_NODE, &cfg_bts_si2quater_uarfcn_del_cmd);
	install_element(BTS_NODE, &cfg_bts_excl_rf_lock_cmd);
	install_element(BTS_NODE, &cfg_bts_no_excl_rf_lock_cmd);
	install_element(BTS_NODE, &cfg_bts_force_comb_si_cmd);
	install_element(BTS_NODE, &cfg_bts_no_force_comb_si_cmd);
	install_element(BTS_NODE, &cfg_bts_codec0_cmd);
	install_element(BTS_NODE, &cfg_bts_codec1_cmd);
	install_element(BTS_NODE, &cfg_bts_codec2_cmd);
	install_element(BTS_NODE, &cfg_bts_codec3_cmd);
	install_element(BTS_NODE, &cfg_bts_codec4_cmd);
	install_element(BTS_NODE, &cfg_bts_depends_on_cmd);
	install_element(BTS_NODE, &cfg_bts_no_depends_on_cmd);
	install_element(BTS_NODE, &cfg_bts_amr_fr_modes1_cmd);
	install_element(BTS_NODE, &cfg_bts_amr_fr_modes2_cmd);
	install_element(BTS_NODE, &cfg_bts_amr_fr_modes3_cmd);
	install_element(BTS_NODE, &cfg_bts_amr_fr_modes4_cmd);
	install_element(BTS_NODE, &cfg_bts_amr_fr_thres1_cmd);
	install_element(BTS_NODE, &cfg_bts_amr_fr_thres2_cmd);
	install_element(BTS_NODE, &cfg_bts_amr_fr_thres3_cmd);
	install_element(BTS_NODE, &cfg_bts_amr_fr_hyst1_cmd);
	install_element(BTS_NODE, &cfg_bts_amr_fr_hyst2_cmd);
	install_element(BTS_NODE, &cfg_bts_amr_fr_hyst3_cmd);
	install_element(BTS_NODE, &cfg_bts_amr_fr_start_mode_cmd);
	install_element(BTS_NODE, &cfg_bts_amr_hr_modes1_cmd);
	install_element(BTS_NODE, &cfg_bts_amr_hr_modes2_cmd);
	install_element(BTS_NODE, &cfg_bts_amr_hr_modes3_cmd);
	install_element(BTS_NODE, &cfg_bts_amr_hr_modes4_cmd);
	install_element(BTS_NODE, &cfg_bts_amr_hr_thres1_cmd);
	install_element(BTS_NODE, &cfg_bts_amr_hr_thres2_cmd);
	install_element(BTS_NODE, &cfg_bts_amr_hr_thres3_cmd);
	install_element(BTS_NODE, &cfg_bts_amr_hr_hyst1_cmd);
	install_element(BTS_NODE, &cfg_bts_amr_hr_hyst2_cmd);
	install_element(BTS_NODE, &cfg_bts_amr_hr_hyst3_cmd);
	install_element(BTS_NODE, &cfg_bts_amr_hr_start_mode_cmd);
	install_element(BTS_NODE, &cfg_bts_pcu_sock_cmd);

	install_element(BTS_NODE, &cfg_trx_cmd);
	install_node(&trx_node, dummy_config_write);
	vty_install_default(TRX_NODE);
	install_element(TRX_NODE, &cfg_trx_arfcn_cmd);
	install_element(TRX_NODE, &cfg_description_cmd);
	install_element(TRX_NODE, &cfg_no_description_cmd);
	install_element(TRX_NODE, &cfg_trx_nominal_power_cmd);
	install_element(TRX_NODE, &cfg_trx_max_power_red_cmd);
	install_element(TRX_NODE, &cfg_trx_rsl_e1_cmd);
	install_element(TRX_NODE, &cfg_trx_rsl_e1_tei_cmd);
	install_element(TRX_NODE, &cfg_trx_rf_locked_cmd);

	install_element(TRX_NODE, &cfg_ts_cmd);
	install_node(&ts_node, dummy_config_write);
	vty_install_default(TS_NODE);
	install_element(TS_NODE, &cfg_ts_pchan_cmd);
	install_element(TS_NODE, &cfg_ts_pchan_compat_cmd);
	install_element(TS_NODE, &cfg_ts_tsc_cmd);
	install_element(TS_NODE, &cfg_ts_hopping_cmd);
	install_element(TS_NODE, &cfg_ts_hsn_cmd);
	install_element(TS_NODE, &cfg_ts_maio_cmd);
	install_element(TS_NODE, &cfg_ts_arfcn_add_cmd);
	install_element(TS_NODE, &cfg_ts_arfcn_del_cmd);
	install_element(TS_NODE, &cfg_ts_e1_subslot_cmd);

	install_element(ENABLE_NODE, &drop_bts_cmd);
	install_element(ENABLE_NODE, &restart_bts_cmd);
	install_element(ENABLE_NODE, &pdch_act_cmd);
	install_element(ENABLE_NODE, &lchan_act_cmd);
	install_element(ENABLE_NODE, &lchan_mdcx_cmd);
	install_element(ENABLE_NODE, &smscb_cmd_cmd);

	abis_nm_vty_init();
	abis_om2k_vty_init();
	e1inp_vty_init();
	osmo_fsm_vty_add_cmds();

	bsc_vty_init_extra();

	return 0;
}
