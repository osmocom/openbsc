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
#include <openbsc/gsm_subscriber.h>
#include <openbsc/gsm_04_11.h>
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

struct cmd_node subscr_node = {
	SUBSCR_NODE,
	"%s(subscriber)#",
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
	vty_out(vty, "BTS %u is of %s type in band %s, has LAC %u, "
		"BSIC %u, TSC %u and %u TRX%s",
		bts->nr, btstype2str(bts->type), gsm_band_name(bts->band),
		bts->location_area_code, bts->bsic, bts->tsc, 
		bts->num_trx, VTY_NEWLINE);
	if (bts->cell_barred)
		vty_out(vty, "  CELL IS BARRED%s", VTY_NEWLINE);
	if (is_ipaccess_bts(bts))
		vty_out(vty, "  Unit ID: %u/%u/0%s",
			bts->ip_access.site_id, bts->ip_access.bts_id,
			VTY_NEWLINE);
	vty_out(vty, "  NM State: ");
	net_dump_nmstate(vty, &bts->nm_state);
	vty_out(vty, "  Site Mgr NM State: ");
	net_dump_nmstate(vty, &bts->site_mgr.nm_state);
	vty_out(vty, "  Paging: FIXME pending requests, %u free slots%s",
		bts->paging.available_slots, VTY_NEWLINE);
	vty_out(vty, "  E1 Signalling Link:%s", VTY_NEWLINE);
	e1isl_dump_vty(vty, bts->oml_link);
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
	vty_out(vty, "  location_area_code %u%s", bts->location_area_code,
		VTY_NEWLINE);
	vty_out(vty, "  training_sequence_code %u%s", bts->tsc, VTY_NEWLINE);
	vty_out(vty, "  base_station_id_code %u%s", bts->bsic, VTY_NEWLINE);
	vty_out(vty, "  channel allocator %s%s",
		bts->chan_alloc_reverse ? "descending" : "ascending",
		VTY_NEWLINE);
	if (bts->cell_barred)
		vty_out(vty, "  cell barred 1%s", VTY_NEWLINE);
	if (is_ipaccess_bts(bts))
		vty_out(vty, "  ip.access unit_id %u %u%s",
			bts->ip_access.site_id, bts->ip_access.bts_id, VTY_NEWLINE);
	else {
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
	vty_out(vty, "  E1 Signalling Link:%s", VTY_NEWLINE);
	e1isl_dump_vty(vty, trx->rsl_link);
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
	struct in_addr ia;

	vty_out(vty, "Timeslot %u of TRX %u in BTS %u, phys cfg %s%s",
		ts->nr, ts->trx->nr, ts->trx->bts->nr,
		gsm_pchan_name(ts->pchan), VTY_NEWLINE);
	vty_out(vty, "  NM State: ");
	net_dump_nmstate(vty, &ts->nm_state);
	if (is_ipaccess_bts(ts->trx->bts)) {
		ia.s_addr = ts->abis_ip.bound_ip;
		vty_out(vty, "  Bound IP: %s Port %u RTP_TYPE2=%u CONN_ID=%u%s",
			inet_ntoa(ia), ts->abis_ip.bound_port,
			ts->abis_ip.rtp_payload2, ts->abis_ip.conn_id,
			VTY_NEWLINE);
	} else {
		vty_out(vty, "  E1 Line %u, Timeslot %u, Subslot %u%s",
			ts->e1_link.e1_nr, ts->e1_link.e1_ts,
			ts->e1_link.e1_ts_ss, VTY_NEWLINE);
	}
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

static void subscr_dump_vty(struct vty *vty, struct gsm_subscriber *subscr)
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
	if (subscr->tmsi)
		vty_out(vty, "    TMSI: %s%s", subscr->tmsi, VTY_NEWLINE);
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
	struct e1inp_line *line;
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

/* per-subscriber configuration */
DEFUN(cfg_subscr,
      cfg_subscr_cmd,
      "subscriber IMSI",
      "Select a Subscriber to configure\n")
{
	const char *imsi = argv[0];
	struct gsm_subscriber *subscr;

	subscr = subscr_get_by_imsi(gsmnet, imsi);
	if (!subscr) {
		vty_out(vty, "%% No subscriber for IMSI %s%s",
			imsi, VTY_NEWLINE);
		return CMD_WARNING;
	}

	vty->index = subscr;
	vty->node = SUBSCR_NODE;

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

DEFUN(cfg_bts_lac,
      cfg_bts_lac_cmd,
      "location_area_code <0-255>",
      "Set the Location Area Code (LAC) of this BTS\n")
{
	struct gsm_bts *bts = vty->index;
	int lac = atoi(argv[0]);

	if (lac < 0 || lac > 0xff) {
		vty_out(vty, "%% LAC %d is not in the valid range (0-255)%s",
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
	int upper_limit = 12;	/* default 12.21 max power red. */

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

/* Subscriber */
DEFUN(show_subscr,
      show_subscr_cmd,
      "show subscriber [IMSI]",
	SHOW_STR "Display information about a subscriber\n")
{
	const char *imsi;
	struct gsm_subscriber *subscr;

	if (argc >= 1) {
		imsi = argv[0];
		subscr = subscr_get_by_imsi(gsmnet, imsi);
		if (!subscr) {
			vty_out(vty, "%% unknown subscriber%s",
				VTY_NEWLINE);
			return CMD_WARNING;
		}
		subscr_dump_vty(vty, subscr);
		
		return CMD_SUCCESS;
	}

	/* FIXME: iterate over all subscribers ? */
	return CMD_WARNING;

	return CMD_SUCCESS;
}

DEFUN(sms_send_pend,
      sms_send_pend_cmd,
      "sms send pending MIN_ID",
      "Send all pending SMS starting from MIN_ID")
{
	struct gsm_sms *sms;

	sms = db_sms_get_unsent(gsmnet, atoi(argv[0])); 
	if (!sms)
		return CMD_WARNING;

	if (!sms->receiver) {
		sms_free(sms);
		return CMD_WARNING;
	}

	gsm411_send_sms_subscr(sms->receiver, sms);

	return CMD_SUCCESS;
}

static struct buffer *argv_to_buffer(int argc, const char *argv[], int base)
{
	struct buffer *b = buffer_new(1024);
	int i;

	if (!b)
		return NULL;

	for (i = base; i < argc; i++) {
		buffer_putstr(b, argv[i]);
		buffer_putc(b, ' ');
	}
	buffer_putc(b, '\0');

	return b;
}

int sms_from_text(struct gsm_subscriber *receiver, const char *text)
{
	struct gsm_sms *sms = sms_alloc();

	if (!sms)
		return CMD_WARNING;

	if (!receiver->lac) {
		/* subscriber currently not attached, store in database? */
		subscr_put(sms->receiver);
		return CMD_WARNING;
	}

	sms->receiver = receiver;
	strncpy(sms->text, text, sizeof(sms->text)-1);

	/* FIXME: don't use ID 1 static */
	sms->sender = subscr_get_by_id(gsmnet, 1);
	sms->reply_path_req = 0;
	sms->status_rep_req = 0;
	sms->ud_hdr_ind = 0;
	sms->protocol_id = 0; /* implicit */
	sms->data_coding_scheme = 0; /* default 7bit */
	strncpy(sms->dest_addr, receiver->extension, sizeof(sms->dest_addr)-1);
	/* Generate user_data */
	sms->user_data_len = gsm_7bit_encode(sms->user_data, sms->text);

	return sms;
}

static int _send_sms_buffer(struct gsm_subscriber *receiver,
			     struct buffer *b)
{
	struct gsm_sms *sms;

	sms = sms_from_text(receiver, buffer_getstr(b));

	gsm411_send_sms_subscr(sms->receiver, sms);

	return CMD_SUCCESS;
}

DEFUN(sms_send_ext,
      sms_send_ext_cmd,
      "sms send extension EXTEN .LINE",
      "Send a message to a subscriber identified by EXTEN")
{
	struct gsm_subscriber *receiver;
	struct buffer *b;
	int rc;

	receiver = subscr_get_by_extension(gsmnet, argv[0]);
	if (!receiver)
		return CMD_WARNING;

	b = argv_to_buffer(argc, argv, 1);
	rc = _send_sms_buffer(receiver, b);
	buffer_free(b);

	return rc;
}

DEFUN(sms_send_imsi,
      sms_send_imsi_cmd,
      "sms send imsi IMSI .LINE",
      "Send a message to a subscriber identified by IMSI")
{
	struct gsm_subscriber *receiver;
	struct buffer *b;
	int rc;

	receiver = subscr_get_by_imsi(gsmnet, argv[0]);
	if (!receiver)
		return CMD_WARNING;

	b = argv_to_buffer(argc, argv, 1);
	rc = _send_sms_buffer(receiver, b);
	buffer_free(b);

	return rc;
}


DEFUN(cfg_subscr_name,
      cfg_subscr_name_cmd,
      "name NAME",
      "Set the name of the subscriber")
{
	const char *name = argv[0];
	struct gsm_subscriber *subscr = vty->index;

	strncpy(subscr->name, name, sizeof(subscr->name));

	db_sync_subscriber(subscr);

	return CMD_SUCCESS;
}

DEFUN(cfg_subscr_extension,
      cfg_subscr_extension_cmd,
      "extension EXTENSION",
      "Set the extension of the subscriber")
{
	const char *name = argv[0];
	struct gsm_subscriber *subscr = vty->index;

	strncpy(subscr->extension, name, sizeof(subscr->extension));

	db_sync_subscriber(subscr);

	return CMD_SUCCESS;
}

DEFUN(cfg_subscr_authorized,
      cfg_subscr_authorized_cmd,
      "auth <0-1>",
      "Set the authorization status of the subscriber")
{
	int auth = atoi(argv[0]);
	struct gsm_subscriber *subscr = vty->index;

	if (auth)
		subscr->authorized = 1;
	else
		subscr->authorized = 0;

	db_sync_subscriber(subscr);

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

	install_element(VIEW_NODE, &show_subscr_cmd);

	install_element(VIEW_NODE, &sms_send_pend_cmd);
	install_element(VIEW_NODE, &sms_send_ext_cmd);
	install_element(VIEW_NODE, &sms_send_imsi_cmd);

	install_element(CONFIG_NODE, &cfg_net_cmd);
	install_node(&net_node, config_write_net);
	install_default(GSMNET_NODE);
	install_element(GSMNET_NODE, &cfg_net_ncc_cmd);
	install_element(GSMNET_NODE, &cfg_net_mnc_cmd);
	install_element(GSMNET_NODE, &cfg_net_name_short_cmd);
	install_element(GSMNET_NODE, &cfg_net_name_long_cmd);
	install_element(GSMNET_NODE, &cfg_net_auth_policy_cmd);

	install_element(GSMNET_NODE, &cfg_bts_cmd);
	install_node(&bts_node, config_write_bts);
	install_default(BTS_NODE);
	install_element(BTS_NODE, &cfg_bts_type_cmd);
	install_element(BTS_NODE, &cfg_bts_band_cmd);
	install_element(BTS_NODE, &cfg_bts_lac_cmd);
	install_element(BTS_NODE, &cfg_bts_tsc_cmd);
	install_element(BTS_NODE, &cfg_bts_bsic_cmd);
	install_element(BTS_NODE, &cfg_bts_unit_id_cmd);
	install_element(BTS_NODE, &cfg_bts_oml_e1_cmd);
	install_element(BTS_NODE, &cfg_bts_oml_e1_tei_cmd);
	install_element(BTS_NODE, &cfg_bts_challoc_cmd);
	install_element(BTS_NODE, &cfg_bts_cell_barred_cmd);


	install_element(BTS_NODE, &cfg_trx_cmd);
	install_node(&trx_node, dummy_config_write);
	install_default(TRX_NODE);
	install_element(TRX_NODE, &cfg_trx_arfcn_cmd);
	install_element(TRX_NODE, &cfg_trx_max_power_red_cmd);
	install_element(TRX_NODE, &cfg_trx_rsl_e1_cmd);
	install_element(TRX_NODE, &cfg_trx_rsl_e1_tei_cmd);

	install_element(TRX_NODE, &cfg_ts_cmd);
	install_node(&ts_node, dummy_config_write);
	install_default(TS_NODE);
	install_element(TS_NODE, &cfg_ts_pchan_cmd);
	install_element(TS_NODE, &cfg_ts_e1_subslot_cmd);

	install_element(CONFIG_NODE, &cfg_subscr_cmd);
	install_node(&subscr_node, dummy_config_write);
	install_default(SUBSCR_NODE);
	install_element(SUBSCR_NODE, &cfg_subscr_name_cmd);
	install_element(SUBSCR_NODE, &cfg_subscr_extension_cmd);
	install_element(SUBSCR_NODE, &cfg_subscr_authorized_cmd);

	return 0;
}
