/* OpenBSC VTY common helpers */
/* (C) 2009-2010 by Harald Welte <laforge@gnumonks.org>
 * (C) 2009-2010 by Holger Hans Peter Freyther
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
#include <string.h>

#include <osmocore/talloc.h>

#include <openbsc/vty.h>
#include <openbsc/gsm_data.h>
#include <openbsc/debug.h>
#include <openbsc/gsm_subscriber.h>
#include <openbsc/bsc_nat.h>

#include <osmocom/vty/telnet_interface.h>
#include <osmocom/vty/command.h>
#include <osmocom/vty/buffer.h>
#include <osmocom/vty/vty.h>


enum node_type bsc_vty_go_parent(struct vty *vty)
{
	switch (vty->node) {
	case GSMNET_NODE:
		vty->node = CONFIG_NODE;
		vty->index = NULL;
		break;
	case BTS_NODE:
		vty->node = GSMNET_NODE;
		{
			/* set vty->index correctly ! */
			struct gsm_bts *bts = vty->index;
			vty->index = bts->network;
		}
		break;
	case TRX_NODE:
		vty->node = BTS_NODE;
		{
			/* set vty->index correctly ! */
			struct gsm_bts_trx *trx = vty->index;
			vty->index = trx->bts;
		}
		break;
	case TS_NODE:
		vty->node = TRX_NODE;
		{
			/* set vty->index correctly ! */
			struct gsm_bts_trx_ts *ts = vty->index;
			vty->index = ts->trx;
		}
		break;
	case OML_NODE:
		vty->node = ENABLE_NODE;
		talloc_free(vty->index);
		vty->index = NULL;
		break;
	case NAT_NODE:
		vty->node = CONFIG_NODE;
		vty->index = NULL;
		break;
	case NAT_BSC_NODE:
		vty->node = NAT_NODE;
		{
			struct bsc_config *bsc_config = vty->index;
			vty->index = bsc_config->nat;
		}
		break;
	default:
		vty->node = CONFIG_NODE;
	}

	return vty->node;
}

/* Down vty node level. */
gDEFUN(ournode_exit,
       ournode_exit_cmd, "exit", "Exit current mode and down to previous mode\n")
{
	switch (vty->node) {
	case GSMNET_NODE:
		vty->node = CONFIG_NODE;
		vty->index = NULL;
		break;
	case BTS_NODE:
		vty->node = GSMNET_NODE;
		{
			/* set vty->index correctly ! */
			struct gsm_bts *bts = vty->index;
			vty->index = bts->network;
			vty->index_sub = NULL;
		}
		break;
	case TRX_NODE:
		vty->node = BTS_NODE;
		{
			/* set vty->index correctly ! */
			struct gsm_bts_trx *trx = vty->index;
			vty->index = trx->bts;
			vty->index_sub = &trx->bts->description;
		}
		break;
	case TS_NODE:
		vty->node = TRX_NODE;
		{
			/* set vty->index correctly ! */
			struct gsm_bts_trx_ts *ts = vty->index;
			vty->index = ts->trx;
			vty->index_sub = &ts->trx->description;
		}
		break;
	case NAT_BSC_NODE:
		vty->node = NAT_NODE;
		{
			struct bsc_config *bsc_config = vty->index;
			vty->index = bsc_config->nat;
		}
		break;
	case MGCP_NODE:
	case GBPROXY_NODE:
	case SGSN_NODE:
	case NS_NODE:
	case BSSGP_NODE:
	case NAT_NODE:
		vty->node = CONFIG_NODE;
		vty->index = NULL;
		break;
	case OML_NODE:
		vty->node = ENABLE_NODE;
		talloc_free(vty->index);
		vty->index = NULL;
		break;
	default:
		break;
	}
	return CMD_SUCCESS;
}

/* End of configuration. */
gDEFUN(ournode_end,
       ournode_end_cmd, "end", "End current mode and change to enable mode.")
{
	switch (vty->node) {
	case VIEW_NODE:
	case ENABLE_NODE:
		/* Nothing to do. */
		break;
	case CONFIG_NODE:
	case GSMNET_NODE:
	case BTS_NODE:
	case TRX_NODE:
	case TS_NODE:
	case MGCP_NODE:
	case GBPROXY_NODE:
	case SGSN_NODE:
	case NS_NODE:
	case VTY_NODE:
	case NAT_NODE:
	case NAT_BSC_NODE:
		vty_config_unlock(vty);
		vty->node = ENABLE_NODE;
		vty->index = NULL;
		vty->index_sub = NULL;
		break;
	default:
		break;
	}
	return CMD_SUCCESS;
}

