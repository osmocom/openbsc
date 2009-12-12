/* OpenBSC interface to quagga VTY */
/* (C) 2009 by Harald Welte <laforge@gnumonks.org>
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

#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>

#include <vty/command.h>
#include <vty/buffer.h>
#include <vty/vty.h>

#include <arpa/inet.h>

#include <openbsc/linuxlist.h>
#include <openbsc/gsm_data.h>
#include <openbsc/e1_input.h>
#include <openbsc/abis_nm.h>
#include <openbsc/gsm_utils.h>
#include <openbsc/db.h>
#include <openbsc/talloc.h>

static struct gsm_network *gsmnet;

struct cmd_node net_node = {
	GSMNET_NODE,
	"%s(network)#",
	1,
};

struct cmd_node bts_node = {
	BTS_NODE,
	"%s(bts)#",
	1,
};

struct cmd_node trx_node = {
	TRX_NODE,
	"%s(trx)#",
	1,
};

struct cmd_node ts_node = {
	TS_NODE,
	"%s(ts)#",
	1,
};

static int dummy_config_write(struct vty *v)
{
	return CMD_SUCCESS;
}

static void net_dump_nmstate(struct vty *vty, struct gsm_nm_state *nms)
{
	vty_out(vty,"Oper '%s', Admin %u, Avail '%s'%s",
		nm_opstate_name(nms->operational), nms->administrative,
		nm_avail_name(nms->availability), VTY_NEWLINE);
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
}

DEFUN(show_net, show_net_cmd, "show network",
	SHOW_STR "Display information about a GSM NETWORK\n")
{
	struct gsm_network *net = gsmnet;
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
	vty_out(vty, "BTS %u is of %s type in band %s, has CI %u LAC %u, "
		"BSIC %u, TSC %u and %u TRX%s",
		bts->nr, btstype2str(bts->type), gsm_band_name(bts->band),
		bts->cell_identity,
		bts->location_area_code, bts->bsic, bts->tsc, 
		bts->num_trx, VTY_NEWLINE);
	vty_out(vty, "MS Max power: %u dBm%s", bts->ms_max_power, VTY_NEWLINE);
	vty_out(vty, "Minimum Rx Level for Access: %u dBm%s",
		rxlev2dbm(bts->si_common.cell_sel_par.rxlev_acc_min),
		VTY_NEWLINE);
	vty_out(vty, "Cell Reselection Hysteresis: %u dBm%s",
		bts->si_common.cell_sel_par.cell_resel_hyst, VTY_NEWLINE);
	if (bts->cell_barred)
		vty_out(vty, "  CELL IS BARRED%s", VTY_NEWLINE);
	if (is_ipaccess_bts(bts))
		vty_out(vty, "  Unit ID: %u/%u/0, OML Stream ID 0x%02x%s",
			bts->ip_access.site_id, bts->ip_access.bts_id,
			bts->oml_tei, VTY_NEWLINE);
	vty_out(vty, "  NM State: ");
	net_dump_nmstate(vty, &bts->nm_state);
	vty_out(vty, "  Site Mgr NM State: ");
	net_dump_nmstate(vty, &bts->site_mgr.nm_state);
	vty_out(vty, "  Paging: FIXME pending requests, %u free slots%s",
		bts->paging.available_slots, VTY_NEWLINE);
	if (!is_ipaccess_bts(bts)) {
		vty_out(vty, "  E1 Signalling Link:%s", VTY_NEWLINE);
		e1isl_dump_vty(vty, bts->oml_link);
	}
	/* FIXME: oml_link, chan_desc */
}

DEFUN(show_bts, show_bts_cmd, "show bts [number]",
	SHOW_STR "Display information about a BTS\n"
		"BTS number")
{
	struct gsm_network *net = gsmnet;
	int bts_nr;

	if (argc != 0) {
		/* use the BTS number that the user has specified */
		bts_nr = atoi(argv[0]);
		if (bts_nr > net->num_bts) {
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
	vty_out(vty, "    timeslot %u%s", ts->nr, VTY_NEWLINE);
	if (ts->pchan != GSM_PCHAN_NONE)
		vty_out(vty, "     phys_chan_config %s%s",
			gsm_pchan_name(ts->pchan), VTY_NEWLINE);
	config_write_e1_link(vty, &ts->e1_link, "     ");
}

static void config_write_trx_single(struct vty *vty, struct gsm_bts_trx *trx)
{
	int i;

	vty_out(vty, "  trx %u%s", trx->nr, VTY_NEWLINE);
	vty_out(vty, "   arfcn %u%s", trx->arfcn, VTY_NEWLINE);
	vty_out(vty, "   max_power_red %u%s", trx->max_power_red, VTY_NEWLINE);
	config_write_e1_link(vty, &trx->rsl_e1_link, "   rsl ");
	vty_out(vty, "   rsl e1 tei %u%s", trx->rsl_tei, VTY_NEWLINE);

	for (i = 0; i < TRX_NR_TS; i++)
		config_write_ts_single(vty, &trx->ts[i]);
}

static void config_write_bts_single(struct vty *vty, struct gsm_bts *bts)
{
	struct gsm_bts_trx *trx;

	vty_out(vty, " bts %u%s", bts->nr, VTY_NEWLINE);
	vty_out(vty, "  type %s%s", btstype2str(bts->type), VTY_NEWLINE);
	vty_out(vty, "  band %s%s", gsm_band_name(bts->band), VTY_NEWLINE);
	vty_out(vty, "  cell_identity %u%s", bts->cell_identity, VTY_NEWLINE);
	vty_out(vty, "  location_area_code %u%s", bts->location_area_code,
		VTY_NEWLINE);
	vty_out(vty, "  training_sequence_code %u%s", bts->tsc, VTY_NEWLINE);
	vty_out(vty, "  base_station_id_code %u%s", bts->bsic, VTY_NEWLINE);
	vty_out(vty, "  ms max power %u%s", bts->ms_max_power, VTY_NEWLINE);
	if (bts->si_common.chan_desc.t3212)
		vty_out(vty, "  periodic location update %u%s",
			bts->si_common.chan_desc.t3212 * 10, VTY_NEWLINE);
	vty_out(vty, "  channel allocator %s%s",
		bts->chan_alloc_reverse ? "descending" : "ascending",
		VTY_NEWLINE);
	if (bts->cell_barred)
		vty_out(vty, "  cell barred 1%s", VTY_NEWLINE);
	if (is_ipaccess_bts(bts)) {
		vty_out(vty, "  ip.access unit_id %u %u%s",
			bts->ip_access.site_id, bts->ip_access.bts_id, VTY_NEWLINE);
		vty_out(vty, "  oml ip.access stream_id %u%s", bts->oml_tei, VTY_NEWLINE);
	} else {
		config_write_e1_link(vty, &bts->oml_e1_link, "  oml ");
		vty_out(vty, "  oml e1 tei %u%s", bts->oml_tei, VTY_NEWLINE);
	}

	llist_for_each_entry(trx, &bts->trx_list, list)
		config_write_trx_single(vty, trx);
}

static int config_write_bts(struct vty *v)
{
	struct gsm_bts *bts;

	llist_for_each_entry(bts, &gsmnet->bts_list, list)
		config_write_bts_single(v, bts);

	return CMD_SUCCESS;
}

static int config_write_net(struct vty *vty)
{
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
	vty_out(vty, " timer t3141 %u%s", gsmnet->T3141, VTY_NEWLINE);

	return CMD_SUCCESS;
}

static void trx_dump_vty(struct vty *vty, struct gsm_bts_trx *trx)
{
	vty_out(vty, "TRX %u of BTS %u is on ARFCN %u%s",
		trx->nr, trx->bts->nr, trx->arfcn, VTY_NEWLINE);
	vty_out(vty, "  RF Nominal Power: %d dBm, reduced by %u dB, "
		"resulting BS power: %d dBm%s",
		trx->nominal_power, trx->max_power_red,
		trx->nominal_power - trx->max_power_red, VTY_NEWLINE);
	vty_out(vty, "  NM State: ");
	net_dump_nmstate(vty, &trx->nm_state);
	vty_out(vty, "  Baseband Transceiver NM State: ");
	net_dump_nmstate(vty, &trx->bb_transc.nm_state);
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
      "show trx [bts_nr] [trx_nr]",
	SHOW_STR "Display information about a TRX\n")
{
	struct gsm_network *net = gsmnet;
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
	vty_out(vty, "Timeslot %u of TRX %u in BTS %u, phys cfg %s%s",
		ts->nr, ts->trx->nr, ts->trx->bts->nr,
		gsm_pchan_name(ts->pchan), VTY_NEWLINE);
	vty_out(vty, "  NM State: ");
	net_dump_nmstate(vty, &ts->nm_state);
	if (!is_ipaccess_bts(ts->trx->bts))
		vty_out(vty, "  E1 Line %u, Timeslot %u, Subslot %u%s",
			ts->e1_link.e1_nr, ts->e1_link.e1_ts,
			ts->e1_link.e1_ts_ss, VTY_NEWLINE);
}

DEFUN(show_ts,
      show_ts_cmd,
      "show timeslot [bts_nr] [trx_nr] [ts_nr]",
	SHOW_STR "Display information about a TS\n")
{
	struct gsm_network *net = gsmnet;
	struct gsm_bts *bts;
	struct gsm_bts_trx *trx;
	struct gsm_bts_trx_ts *ts;
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
		ts = &trx->ts[ts_nr];
		ts_dump_vty(vty, ts);
		return CMD_SUCCESS;
	}
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

	return CMD_SUCCESS;
}

void subscr_dump_vty(struct vty *vty, struct gsm_subscriber *subscr)
{
	vty_out(vty, "    ID: %llu, Authorized: %d%s", subscr->id,
		subscr->authorized, VTY_NEWLINE);
	if (subscr->name)
		vty_out(vty, "    Name: '%s'%s", subscr->name, VTY_NEWLINE);
	if (subscr->extension)
		vty_out(vty, "    Extension: %s%s", subscr->extension,
			VTY_NEWLINE);
	if (subscr->imsi)
		vty_out(vty, "    IMSI: %s%s", subscr->imsi, VTY_NEWLINE);
	if (subscr->tmsi != GSM_RESERVED_TMSI)
		vty_out(vty, "    TMSI: %08X%s", subscr->tmsi,
			VTY_NEWLINE);
	vty_out(vty, "    Use count: %u%s", subscr->use_count, VTY_NEWLINE);
}

static void lchan_dump_vty(struct vty *vty, struct gsm_lchan *lchan)
{
	vty_out(vty, "Lchan %u in Timeslot %u of TRX %u in BTS %u, Type %s%s",
		lchan->nr, lchan->ts->nr, lchan->ts->trx->nr, 
		lchan->ts->trx->bts->nr, gsm_lchan_name(lchan->type),
		VTY_NEWLINE);
	vty_out(vty, "  Use Count: %u%s", lchan->use_count, VTY_NEWLINE);
	vty_out(vty, "  BS Power %u, MS Power %u%s", lchan->bs_power,
		lchan->ms_power, VTY_NEWLINE);
	if (lchan->subscr) {
		vty_out(vty, "  Subscriber:%s", VTY_NEWLINE);
		subscr_dump_vty(vty, lchan->subscr);
	} else
		vty_out(vty, "  No Subscriber%s", VTY_NEWLINE);
	if (is_ipaccess_bts(lchan->ts->trx->bts)) {
		struct in_addr ia;
		ia.s_addr = lchan->abis_ip.bound_ip;
		vty_out(vty, "  Bound IP: %s Port %u RTP_TYPE2=%u CONN_ID=%u%s",
			inet_ntoa(ia), lchan->abis_ip.bound_port,
			lchan->abis_ip.rtp_payload2, lchan->abis_ip.conn_id,
			VTY_NEWLINE);
	}
}

#if 0
TODO: callref and remote callref of call must be resolved to get gsm_trans object
static void call_dump_vty(struct vty *vty, struct gsm_call *call)
{
	vty_out(vty, "Call Type %u, State %u, Transaction ID %u%s",
		call->type, call->state, call->transaction_id, VTY_NEWLINE);

	if (call->local_lchan) {
		vty_out(vty, "Call Local Channel:%s", VTY_NEWLINE);
		lchan_dump_vty(vty, call->local_lchan);
	} else
		vty_out(vty, "Call has no Local Channel%s", VTY_NEWLINE);

	if (call->remote_lchan) {
		vty_out(vty, "Call Remote Channel:%s", VTY_NEWLINE);
		lchan_dump_vty(vty, call->remote_lchan);
	} else
		vty_out(vty, "Call has no Remote Channel%s", VTY_NEWLINE);

	if (call->called_subscr) {
		vty_out(vty, "Called Subscriber:%s", VTY_NEWLINE);
		subscr_dump_vty(vty, call->called_subscr);
	} else
		vty_out(vty, "Call has no Called Subscriber%s", VTY_NEWLINE);
}
#endif

DEFUN(show_lchan,
      show_lchan_cmd,
      "show lchan [bts_nr] [trx_nr] [ts_nr] [lchan_nr]",
	SHOW_STR "Display information about a logical channel\n")
{
	struct gsm_network *net = gsmnet;
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
	}
	if (argc >= 2) {
		trx_nr = atoi(argv[1]);
		if (trx_nr >= bts->num_trx) {
			vty_out(vty, "%% can't find TRX %s%s", argv[1],
				VTY_NEWLINE);
			return CMD_WARNING;
		}
		trx = gsm_bts_trx_num(bts, trx_nr);
	}
	if (argc >= 3) {
		ts_nr = atoi(argv[2]);
		if (ts_nr >= TRX_NR_TS) {
			vty_out(vty, "%% can't find TS %s%s", argv[2],
				VTY_NEWLINE);
			return CMD_WARNING;
		}
		ts = &trx->ts[ts_nr];
	}
	if (argc >= 4) {
		lchan_nr = atoi(argv[3]);
		if (lchan_nr >= TS_MAX_LCHAN) {
			vty_out(vty, "%% can't find LCHAN %s%s", argv[3],
				VTY_NEWLINE);
			return CMD_WARNING;
		}
		lchan = &ts->lchan[lchan_nr];
		lchan_dump_vty(vty, lchan);
		return CMD_SUCCESS;
	}
	for (bts_nr = 0; bts_nr < net->num_bts; bts_nr++) {
		bts = gsm_bts_num(net, bts_nr);
		for (trx_nr = 0; trx_nr < bts->num_trx; trx_nr++) {
			trx = gsm_bts_trx_num(bts, trx_nr);
			for (ts_nr = 0; ts_nr < TRX_NR_TS; ts_nr++) {
				ts = &trx->ts[ts_nr];
				for (lchan_nr = 0; lchan_nr < TS_MAX_LCHAN;
				     lchan_nr++) {
					lchan = &ts->lchan[lchan_nr];
					if (lchan->type == GSM_LCHAN_NONE)
						continue;
					lchan_dump_vty(vty, lchan);
				}
			}
		}
	}

	return CMD_SUCCESS;
}

static void e1drv_dump_vty(struct vty *vty, struct e1inp_driver *drv)
{
	vty_out(vty, "E1 Input Driver %s%s", drv->name, VTY_NEWLINE);
}

DEFUN(show_e1drv,
      show_e1drv_cmd,
      "show e1_driver",
	SHOW_STR "Display information about available E1 drivers\n")
{
	struct e1inp_driver *drv;

	llist_for_each_entry(drv, &e1inp_driver_list, list)
		e1drv_dump_vty(vty, drv);

	return CMD_SUCCESS;
}

static void e1line_dump_vty(struct vty *vty, struct e1inp_line *line)
{
	vty_out(vty, "E1 Line Number %u, Name %s, Driver %s%s",
		line->num, line->name ? line->name : "",
		line->driver->name, VTY_NEWLINE);
}

DEFUN(show_e1line,
      show_e1line_cmd,
      "show e1_line [line_nr]",
	SHOW_STR "Display information about a E1 line\n")
{
	struct e1inp_line *line;

	if (argc >= 1) {
		int num = atoi(argv[0]);
		llist_for_each_entry(line, &e1inp_line_list, list) {
			if (line->num == num) {
				e1line_dump_vty(vty, line);
				return CMD_SUCCESS;
			}
		}
		return CMD_WARNING;
	}	
	
	llist_for_each_entry(line, &e1inp_line_list, list)
		e1line_dump_vty(vty, line);

	return CMD_SUCCESS;
}

static void e1ts_dump_vty(struct vty *vty, struct e1inp_ts *ts)
{
	if (ts->type == E1INP_TS_TYPE_NONE)
		return;
	vty_out(vty, "E1 Timeslot %2u of Line %u is Type %s%s",
		ts->num, ts->line->num, e1inp_tstype_name(ts->type),
		VTY_NEWLINE);
}

DEFUN(show_e1ts,
      show_e1ts_cmd,
      "show e1_timeslot [line_nr] [ts_nr]",
	SHOW_STR "Display information about a E1 timeslot\n")
{
	struct e1inp_line *line = NULL;
	struct e1inp_ts *ts;
	int ts_nr;

	if (argc == 0) {
		llist_for_each_entry(line, &e1inp_line_list, list) {
			for (ts_nr = 0; ts_nr < NUM_E1_TS; ts_nr++) {
				ts = &line->ts[ts_nr];
				e1ts_dump_vty(vty, ts);
			}
		}
		return CMD_SUCCESS;
	}
	if (argc >= 1) {
		int num = atoi(argv[0]);
		llist_for_each_entry(line, &e1inp_line_list, list) {
			if (line->num == num)
				break;
		}
		if (!line || line->num != num) {
			vty_out(vty, "E1 line %s is invalid%s",
				argv[0], VTY_NEWLINE);
			return CMD_WARNING;
		}
	}	
	if (argc >= 2) {
		ts_nr = atoi(argv[1]);
		if (ts_nr > NUM_E1_TS) {
			vty_out(vty, "E1 timeslot %s is invalid%s",
				argv[1], VTY_NEWLINE);
			return CMD_WARNING;
		}
		ts = &line->ts[ts_nr];
		e1ts_dump_vty(vty, ts);
		return CMD_SUCCESS;
	} else {
		for (ts_nr = 0; ts_nr < NUM_E1_TS; ts_nr++) {
			ts = &line->ts[ts_nr];
			e1ts_dump_vty(vty, ts);
		}
		return CMD_SUCCESS;
	}
	return CMD_SUCCESS;
}

static void paging_dump_vty(struct vty *vty, struct gsm_paging_request *pag)
{
	vty_out(vty, "Paging on BTS %u%s", pag->bts->nr, VTY_NEWLINE);
	subscr_dump_vty(vty, pag->subscr);
}

static void bts_paging_dump_vty(struct vty *vty, struct gsm_bts *bts)
{
	struct gsm_paging_request *pag;

	llist_for_each_entry(pag, &bts->paging.pending_requests, entry)
		paging_dump_vty(vty, pag);
}

DEFUN(show_paging,
      show_paging_cmd,
      "show paging [bts_nr]",
	SHOW_STR "Display information about paging reuqests of a BTS\n")
{
	struct gsm_network *net = gsmnet;
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

DEFUN(cfg_net,
      cfg_net_cmd,
      "network",
      "Configure the GSM network")
{
	vty->index = gsmnet;
	vty->node = GSMNET_NODE;

	return CMD_SUCCESS;
}


DEFUN(cfg_net_ncc,
      cfg_net_ncc_cmd,
      "network country code <1-999>",
      "Set the GSM network country code")
{
	gsmnet->country_code = atoi(argv[0]);

	return CMD_SUCCESS;
}

DEFUN(cfg_net_mnc,
      cfg_net_mnc_cmd,
      "mobile network code <1-999>",
      "Set the GSM mobile network code")
{
	gsmnet->network_code = atoi(argv[0]);

	return CMD_SUCCESS;
}

DEFUN(cfg_net_name_short,
      cfg_net_name_short_cmd,
      "short name NAME",
      "Set the short GSM network name")
{
	if (gsmnet->name_short)
		talloc_free(gsmnet->name_short);

	gsmnet->name_short = talloc_strdup(gsmnet, argv[0]);

	return CMD_SUCCESS;
}

DEFUN(cfg_net_name_long,
      cfg_net_name_long_cmd,
      "long name NAME",
      "Set the long GSM network name")
{
	if (gsmnet->name_long)
		talloc_free(gsmnet->name_long);

	gsmnet->name_long = talloc_strdup(gsmnet, argv[0]);

	return CMD_SUCCESS;
}

DEFUN(cfg_net_auth_policy,
      cfg_net_auth_policy_cmd,
      "auth policy (closed|accept-all|token)",
      "Set the GSM network authentication policy\n")
{
	enum gsm_auth_policy policy = gsm_auth_policy_parse(argv[0]);

	gsmnet->auth_policy = policy;

	return CMD_SUCCESS;
}

DEFUN(cfg_net_reject_cause,
      cfg_net_reject_cause_cmd,
      "location updating reject cause <2-111>",
      "Set the reject cause of location updating reject\n")
{
	gsmnet->reject_cause = atoi(argv[0]);

	return CMD_SUCCESS;
}

DEFUN(cfg_net_encryption,
      cfg_net_encryption_cmd,
      "encryption a5 (0|1|2)",
      "Enable or disable encryption (A5) for this network\n")
{
	gsmnet->a5_encryption= atoi(argv[0]);

	return CMD_SUCCESS;
}

DEFUN(cfg_net_neci,
      cfg_net_neci_cmd,
      "neci (0|1)",
      "Set if NECI of cell selection is to be set")
{
	gsmnet->neci = atoi(argv[0]);
	return CMD_SUCCESS;
}

#define DECLARE_TIMER(number) \
    DEFUN(cfg_net_T##number,					\
      cfg_net_T##number##_cmd,					\
      "timer t" #number  " <0-65535>",				\
      "Set the T" #number " value.")				\
{								\
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

DECLARE_TIMER(3101)
DECLARE_TIMER(3103)
DECLARE_TIMER(3105)
DECLARE_TIMER(3107)
DECLARE_TIMER(3109)
DECLARE_TIMER(3111)
DECLARE_TIMER(3113)
DECLARE_TIMER(3115)
DECLARE_TIMER(3117)
DECLARE_TIMER(3119)
DECLARE_TIMER(3141)


/* per-BTS configuration */
DEFUN(cfg_bts,
      cfg_bts_cmd,
      "bts BTS_NR",
      "Select a BTS to configure\n")
{
	int bts_nr = atoi(argv[0]);
	struct gsm_bts *bts;

	if (bts_nr > gsmnet->num_bts) {
		vty_out(vty, "%% The next unused BTS number is %u%s",
			gsmnet->num_bts, VTY_NEWLINE);
		return CMD_WARNING;
	} else if (bts_nr == gsmnet->num_bts) {
		/* allocate a new one */
		bts = gsm_bts_alloc(gsmnet, GSM_BTS_TYPE_UNKNOWN,
				    HARDCODED_TSC, HARDCODED_BSIC);
	} else 
		bts = gsm_bts_num(gsmnet, bts_nr);

	if (!bts)
		return CMD_WARNING;

	vty->index = bts;
	vty->node = BTS_NODE;

	return CMD_SUCCESS;
}

DEFUN(cfg_bts_type,
      cfg_bts_type_cmd,
      "type TYPE",
      "Set the BTS type\n")
{
	struct gsm_bts *bts = vty->index;

	bts->type = parse_btstype(argv[0]);

	if (is_ipaccess_bts(bts)) {
		/* Set the default OML Stream ID to 0xff */
		bts->oml_tei = 0xff;
	}

	return CMD_SUCCESS;
}

DEFUN(cfg_bts_band,
      cfg_bts_band_cmd,
      "band BAND",
      "Set the frequency band of this BTS\n")
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

DEFUN(cfg_bts_ci,
      cfg_bts_ci_cmd,
      "cell_identity <0-65535>",
      "Set the Cell identity of this BTS\n")
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
      "Set the Location Area Code (LAC) of this BTS\n")
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


DEFUN(cfg_bts_tsc,
      cfg_bts_tsc_cmd,
      "training_sequence_code <0-255>",
      "Set the Training Sequence Code (TSC) of this BTS\n")
{
	struct gsm_bts *bts = vty->index;
	int tsc = atoi(argv[0]);

	if (tsc < 0 || tsc > 0xff) {
		vty_out(vty, "%% TSC %d is not in the valid range (0-255)%s",
			tsc, VTY_NEWLINE);
		return CMD_WARNING;
	}
	bts->tsc = tsc;

	return CMD_SUCCESS;
}

DEFUN(cfg_bts_bsic,
      cfg_bts_bsic_cmd,
      "base_station_id_code <0-63>",
      "Set the Base Station Identity Code (BSIC) of this BTS\n")
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
      "Set the ip.access BTS Unit ID of this BTS\n")
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

DEFUN(cfg_bts_stream_id,
      cfg_bts_stream_id_cmd,
      "oml ip.access stream_id <0-255>",
      "Set the ip.access Stream ID of the OML link of this BTS\n")
{
	struct gsm_bts *bts = vty->index;
	int stream_id = atoi(argv[0]);

	if (!is_ipaccess_bts(bts)) {
		vty_out(vty, "%% BTS is not of ip.access type%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	bts->oml_tei = stream_id;

	return CMD_SUCCESS;
}


DEFUN(cfg_bts_oml_e1,
      cfg_bts_oml_e1_cmd,
      "oml e1 line E1_LINE timeslot <1-31> sub-slot (0|1|2|3|full)",
      "E1 interface to be used for OML\n")
{
	struct gsm_bts *bts = vty->index;

	parse_e1_link(&bts->oml_e1_link, argv[0], argv[1], argv[2]);

	return CMD_SUCCESS;
}


DEFUN(cfg_bts_oml_e1_tei,
      cfg_bts_oml_e1_tei_cmd,
      "oml e1 tei <0-63>",
      "Set the TEI to be used for OML")
{
	struct gsm_bts *bts = vty->index;

	bts->oml_tei = atoi(argv[0]);

	return CMD_SUCCESS;
}

DEFUN(cfg_bts_challoc, cfg_bts_challoc_cmd,
      "channel allocator (ascending|descending)",
      "Should the channel allocator allocate in reverse TRX order?")
{
	struct gsm_bts *bts = vty->index;

	if (!strcmp(argv[0], "ascending"))
		bts->chan_alloc_reverse = 0;
	else
		bts->chan_alloc_reverse = 1;

	return CMD_SUCCESS;
}

DEFUN(cfg_bts_cell_barred, cfg_bts_cell_barred_cmd,
      "cell barred (0|1)",
      "Should this cell be barred from access?")
{
	struct gsm_bts *bts = vty->index;

	bts->cell_barred = atoi(argv[0]);

	return CMD_SUCCESS;
}

DEFUN(cfg_bts_ms_max_power, cfg_bts_ms_max_power_cmd,
      "ms max power <0-40>",
      "Maximum transmit power of the MS")
{
	struct gsm_bts *bts = vty->index;

	bts->ms_max_power = atoi(argv[0]);

	return CMD_SUCCESS;
}

DEFUN(cfg_bts_per_loc_upd, cfg_bts_per_loc_upd_cmd,
      "periodic location update <0-1530>",
      "Periodic Location Updating Interval in Minutes")
{
	struct gsm_bts *bts = vty->index;

	bts->si_common.chan_desc.t3212 = atoi(argv[0]) / 10;

	return CMD_SUCCESS;
}


/* per TRX configuration */
DEFUN(cfg_trx,
      cfg_trx_cmd,
      "trx TRX_NR",
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
	vty->node = TRX_NODE;

	return CMD_SUCCESS;
}

DEFUN(cfg_trx_arfcn,
      cfg_trx_arfcn_cmd,
      "arfcn <1-1024>",
      "Set the ARFCN for this TRX\n")
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

DEFUN(cfg_trx_max_power_red,
      cfg_trx_max_power_red_cmd,
      "max_power_red <0-100>",
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
      "E1 interface to be used for RSL\n")
{
	struct gsm_bts_trx *trx = vty->index;

	parse_e1_link(&trx->rsl_e1_link, argv[0], argv[1], argv[2]);

	return CMD_SUCCESS;
}

DEFUN(cfg_trx_rsl_e1_tei,
      cfg_trx_rsl_e1_tei_cmd,
      "rsl e1 tei <0-63>",
      "Set the TEI to be used for RSL")
{
	struct gsm_bts_trx *trx = vty->index;

	trx->rsl_tei = atoi(argv[0]);

	return CMD_SUCCESS;
}

DEFUN(cfg_trx_rf_locked,
      cfg_trx_rf_locked_cmd,
      "rf_locked (0|1)",
      "Turn off RF of the TRX.\n")
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
      "Select a Timeslot to configure")
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
      "phys_chan_config PCHAN",
      "Physical Channel configuration (TCH/SDCCH/...)")
{
	struct gsm_bts_trx_ts *ts = vty->index;
	int pchanc;

	pchanc = gsm_pchan_parse(argv[0]);
	if (pchanc < 0)
		return CMD_WARNING;

	ts->pchan = pchanc;

	return CMD_SUCCESS;
}

DEFUN(cfg_ts_e1_subslot,
      cfg_ts_e1_subslot_cmd,
      "e1 line E1_LINE timeslot <1-31> sub-slot (0|1|2|3|full)",
      "E1 sub-slot connected to this on-air timeslot")
{
	struct gsm_bts_trx_ts *ts = vty->index;

	parse_e1_link(&ts->e1_link, argv[0], argv[1], argv[2]);

	return CMD_SUCCESS;
}

int bsc_vty_init(struct gsm_network *net)
{
	gsmnet = net;

	cmd_init(1);
	vty_init();

	install_element(VIEW_NODE, &show_net_cmd);
	install_element(VIEW_NODE, &show_bts_cmd);
	install_element(VIEW_NODE, &show_trx_cmd);
	install_element(VIEW_NODE, &show_ts_cmd);
	install_element(VIEW_NODE, &show_lchan_cmd);

	install_element(VIEW_NODE, &show_e1drv_cmd);
	install_element(VIEW_NODE, &show_e1line_cmd);
	install_element(VIEW_NODE, &show_e1ts_cmd);

	install_element(VIEW_NODE, &show_paging_cmd);

	install_element(CONFIG_NODE, &cfg_net_cmd);
	install_node(&net_node, config_write_net);
	install_default(GSMNET_NODE);
	install_element(GSMNET_NODE, &cfg_net_ncc_cmd);
	install_element(GSMNET_NODE, &cfg_net_mnc_cmd);
	install_element(GSMNET_NODE, &cfg_net_name_short_cmd);
	install_element(GSMNET_NODE, &cfg_net_name_long_cmd);
	install_element(GSMNET_NODE, &cfg_net_auth_policy_cmd);
	install_element(GSMNET_NODE, &cfg_net_reject_cause_cmd);
	install_element(GSMNET_NODE, &cfg_net_encryption_cmd);
	install_element(GSMNET_NODE, &cfg_net_neci_cmd);
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
	install_element(GSMNET_NODE, &cfg_net_T3141_cmd);

	install_element(GSMNET_NODE, &cfg_bts_cmd);
	install_node(&bts_node, config_write_bts);
	install_default(BTS_NODE);
	install_element(BTS_NODE, &cfg_bts_type_cmd);
	install_element(BTS_NODE, &cfg_bts_band_cmd);
	install_element(BTS_NODE, &cfg_bts_ci_cmd);
	install_element(BTS_NODE, &cfg_bts_lac_cmd);
	install_element(BTS_NODE, &cfg_bts_tsc_cmd);
	install_element(BTS_NODE, &cfg_bts_bsic_cmd);
	install_element(BTS_NODE, &cfg_bts_unit_id_cmd);
	install_element(BTS_NODE, &cfg_bts_stream_id_cmd);
	install_element(BTS_NODE, &cfg_bts_oml_e1_cmd);
	install_element(BTS_NODE, &cfg_bts_oml_e1_tei_cmd);
	install_element(BTS_NODE, &cfg_bts_challoc_cmd);
	install_element(BTS_NODE, &cfg_bts_cell_barred_cmd);
	install_element(BTS_NODE, &cfg_bts_ms_max_power_cmd);
	install_element(BTS_NODE, &cfg_bts_per_loc_upd_cmd);


	install_element(BTS_NODE, &cfg_trx_cmd);
	install_node(&trx_node, dummy_config_write);
	install_default(TRX_NODE);
	install_element(TRX_NODE, &cfg_trx_arfcn_cmd);
	install_element(TRX_NODE, &cfg_trx_max_power_red_cmd);
	install_element(TRX_NODE, &cfg_trx_rsl_e1_cmd);
	install_element(TRX_NODE, &cfg_trx_rsl_e1_tei_cmd);
	install_element(TRX_NODE, &cfg_trx_rf_locked_cmd);

	install_element(TRX_NODE, &cfg_ts_cmd);
	install_node(&ts_node, dummy_config_write);
	install_default(TS_NODE);
	install_element(TS_NODE, &cfg_ts_pchan_cmd);
	install_element(TS_NODE, &cfg_ts_e1_subslot_cmd);

	bsc_vty_init_extra(net);

	return 0;
}
