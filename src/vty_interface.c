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
#include <vty/vty.h>

#include <arpa/inet.h>

#include <openbsc/gsm_data.h>
#include <openbsc/gsm_subscriber.h>
#include <openbsc/e1_input.h>

static struct gsm_network *gsmnet;

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
	vty_out(vty,"Operational %u, Administrative %u, Availability %u%s",
		nms->operational, nms->administrative, nms->availability,
		VTY_NEWLINE);
}

static void net_dump_vty(struct vty *vty, struct gsm_network *net)
{
	vty_out(vty, "BSC is on Country Code %u, Network Code %u "
		"and has %u BTS%s", net->country_code, net->network_code,
		net->num_bts, VTY_NEWLINE);
	vty_out(vty, "  Long network name: %s%s",
		net->name_long, VTY_NEWLINE);
	vty_out(vty, "  Short network name: %s%s",
		net->name_short, VTY_NEWLINE);
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
	vty_out(vty, "    E1 Line %u, Timeslot %u, Type %u%s",
		e1l->ts->line->num, e1l->ts->num, e1l->type, VTY_NEWLINE);
	vty_out(vty, "    E1 TEI %u, SAPI %u%s\n",
		e1l->tei, e1l->sapi, VTY_NEWLINE);
}

static void bts_dump_vty(struct vty *vty, struct gsm_bts *bts)
{
	vty_out(vty, "BTS %u is of %s type, has LAC %u, TSC %u and %u TRX%s",
		bts->nr, btstype2str(bts->type), bts->location_area_code,
		bts->tsc, bts->num_trx, VTY_NEWLINE);
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
			vty_out(vty, "%% can't find BTS %s%s", argv[0],
				VTY_NEWLINE);
			return CMD_WARNING;
		}
		bts_dump_vty(vty, &net->bts[bts_nr]);
		return CMD_SUCCESS;
	}
	/* print all BTS's */
	for (bts_nr = 0; bts_nr < net->num_bts; bts_nr++)
		bts_dump_vty(vty, &net->bts[bts_nr]);

	return CMD_SUCCESS;
}

static void trx_dump_vty(struct vty *vty, struct gsm_bts_trx *trx)
{
	vty_out(vty, "TRX %u of BTS %u is on ARFCN %u%s",
		trx->nr, trx->bts->nr, trx->arfcn, VTY_NEWLINE);
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
			vty_out(vty, "%% can't find BTS %s%s", argv[0],
				VTY_NEWLINE);
			return CMD_WARNING;
		}
		bts = &net->bts[bts_nr];
	}
	if (argc >= 2) {
		trx_nr = atoi(argv[1]);
		if (trx_nr >= bts->num_trx) {
			vty_out(vty, "%% can't find TRX %s%s", argv[1],
				VTY_NEWLINE);
			return CMD_WARNING;
		}
		trx = &bts->trx[trx_nr];
		trx_dump_vty(vty, trx);
		return CMD_SUCCESS;
	}
	if (bts) {
		/* print all TRX in this BTS */
		for (trx_nr = 0; trx_nr < bts->num_trx; trx_nr++) {
			trx = &bts->trx[trx_nr];
			trx_dump_vty(vty, trx);
		}
		return CMD_SUCCESS;
	}

	for (bts_nr = 0; bts_nr < net->num_bts; bts_nr++) {
		bts = &net->bts[bts_nr];
		for (trx_nr = 0; trx_nr < bts->num_trx; trx_nr++) {
			trx = &bts->trx[trx_nr];
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
		vty_out(vty, "  Bound IP: %s Port %u FC=%u F8=%u%s",
			inet_ntoa(ia), ts->abis_ip.bound_port,
			ts->abis_ip.attr_fc, ts->abis_ip.attr_f8,
			VTY_NEWLINE);
	} else {
		vty_out(vty, "  E1 Line %u, Timeslot %u, Subslot %u%s",
			ts->e1_link.e1_nr, ts->e1_link.e1_ts,
			ts->e1_link.e1_ts_ss, VTY_NEWLINE);
	}
}

DEFUN(show_ts,
      show_ts_cmd,
      "show ts [bts_nr] [trx_nr] [ts_nr]",
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
			vty_out(vty, "%% can't find BTS %s%s", argv[0],
				VTY_NEWLINE);
			return CMD_WARNING;
		}
		bts = &net->bts[bts_nr];
	}
	if (argc >= 2) {
		trx_nr = atoi(argv[1]);
		if (trx_nr >= bts->num_trx) {
			vty_out(vty, "%% can't find TRX %s%s", argv[1],
				VTY_NEWLINE);
			return CMD_WARNING;
		}
		trx = &bts->trx[trx_nr];
	}
	if (argc >= 3) {
		ts_nr = atoi(argv[2]);
		if (ts_nr >= TRX_NR_TS) {
			vty_out(vty, "%% can't find TS %s%s", argv[2],
				VTY_NEWLINE);
			return CMD_WARNING;
		}
		ts = &trx->ts[ts_nr];
		ts_dump_vty(vty, ts);
		return CMD_SUCCESS;
	}
	for (bts_nr = 0; bts_nr < net->num_bts; bts_nr++) {
		bts = &net->bts[bts_nr];
		for (trx_nr = 0; trx_nr < bts->num_trx; trx_nr++) {
			trx = &bts->trx[trx_nr];
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
	if (subscr->name)
		vty_out(vty, "    Name: %s%s", subscr->name, VTY_NEWLINE);
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
		bts = &net->bts[bts_nr];
	}
	if (argc >= 2) {
		trx_nr = atoi(argv[1]);
		if (trx_nr >= bts->num_trx) {
			vty_out(vty, "%% can't find TRX %s%s", argv[1],
				VTY_NEWLINE);
			return CMD_WARNING;
		}
		trx = &bts->trx[trx_nr];
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
		bts = &net->bts[bts_nr];
		for (trx_nr = 0; trx_nr < bts->num_trx; trx_nr++) {
			trx = &bts->trx[trx_nr];
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
		
}

static void e1ts_dump_vty(struct vty *vty, struct e1inp_ts *ts)
{
	vty_out(vty, "E1 Timeslot %u of Line %u is Type %u%s",
		ts->num, ts->line->num, ts->type, VTY_NEWLINE);
}

DEFUN(show_e1ts,
      show_e1ts_cmd,
      "show e1_timeslot [line_nr] [ts_nr]",
	SHOW_STR "Display information about a E1 timeslot\n")
{

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
	install_element(VIEW_NODE, &show_e1line_cmd);
	install_element(VIEW_NODE, &show_e1ts_cmd);

#if 0
	install_node(&bts_node, dummy_config_write);
	install_element(BTS_NODE, &show_bts_cmd);
	install_default(BTS_NODE);

	install_node(&trx_node, dummy_config_write);
	install_element(TRX_NODE, &show_trx_cmd);
	install_default(TRX_NODE);

	install_node(&ts_node, dummy_config_write);
	install_element(TS_NODE, &show_ts_cmd);
	install_default(TS_NODE);
#endif

	return 0;
}
