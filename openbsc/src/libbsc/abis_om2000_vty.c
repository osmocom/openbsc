/* VTY interface for A-bis OM2000 */

/* (C) 2010-2011 by Harald Welte <laforge@gnumonks.org>
 *
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
#include <errno.h>
#include <stdint.h>

#include <arpa/inet.h>

#include <openbsc/gsm_data.h>
#include <osmocom/core/msgb.h>
#include <osmocom/gsm/tlv.h>
#include <osmocom/core/talloc.h>
#include <openbsc/debug.h>
#include <openbsc/signal.h>
#include <openbsc/abis_om2000.h>
#include <openbsc/vty.h>

#include <osmocom/vty/vty.h>
#include <osmocom/vty/command.h>
#include <osmocom/vty/logging.h>
#include <osmocom/vty/telnet_interface.h>

extern struct gsm_network *bsc_gsmnet;

static struct cmd_node om2k_node = {
	OM2K_NODE,
	"%s(om2k)# ",
	1,
};

struct oml_node_state {
	struct gsm_bts *bts;
	struct abis_om2k_mo mo;
};

static int dummy_config_write(struct vty *v)
{
	return CMD_SUCCESS;
}

/* FIXME: auto-generate those strings from the value_string lists */
#define OM2K_OBJCLASS_VTY "(trxc|ts|tf|is|con|dp|cf|tx|rx)"
#define OM2K_OBJCLASS_VTY_HELP 	"TRX Controller\n"	\
				"Timeslot\n"		\
				"Timing Function\n"	\
				"Interface Switch\n"	\
				"Abis Concentrator\n"	\
				"Digital Path\n"	\
				"Central Function\n"	\
				"Transmitter\n"		\
				"Receiver\n"

DEFUN(om2k_class_inst, om2k_class_inst_cmd,
	"bts <0-255> om2000 class " OM2K_OBJCLASS_VTY
					" <0-255> <0-255> <0-255>",
	"BTS related commands\n" "BTS Number\n"
	"Manipulate the OM2000 managed objects\n"
	"Object Class\n" 	OM2K_OBJCLASS_VTY_HELP
	"BTS Number\n" "Associated SO Instance\n" "Instance Number\n")
{
	struct gsm_bts *bts;
	struct oml_node_state *oms;
	int bts_nr = atoi(argv[0]);

	bts = gsm_bts_num(gsmnet_from_vty(vty), bts_nr);
	if (!bts) {
		vty_out(vty, "%% No such BTS (%d)%s", bts_nr, VTY_NEWLINE);
		return CMD_WARNING;
	}

	if (bts->type != GSM_BTS_TYPE_RBS2000) {
		vty_out(vty, "%% BTS %d not an Ericsson RBS%s",
			bts_nr, VTY_NEWLINE);
		return CMD_WARNING;
	}

	oms = talloc_zero(tall_bsc_ctx, struct oml_node_state);
	if (!oms)
		return CMD_WARNING;

	oms->bts = bts;
	oms->mo.class = get_string_value(om2k_mo_class_short_vals, argv[1]);
	oms->mo.bts = atoi(argv[2]);
	oms->mo.assoc_so = atoi(argv[3]);
	oms->mo.inst = atoi(argv[4]);

	vty->index = oms;
	vty->node = OM2K_NODE;

	return CMD_SUCCESS;

}

DEFUN(om2k_classnum_inst, om2k_classnum_inst_cmd,
	"bts <0-255> om2000 class <0-255> <0-255> <0-255> <0-255>",
	"BTS related commands\n" "BTS Number\n"
	"Manipulate the OML managed objects\n"
	"Object Class\n" "Object Class\n"
	"BTS Number\n" "Associated SO Instance\n" "Instance Number\n")
{
	struct gsm_bts *bts;
	struct oml_node_state *oms;
	int bts_nr = atoi(argv[0]);

	bts = gsm_bts_num(gsmnet_from_vty(vty), bts_nr);
	if (!bts) {
		vty_out(vty, "%% No such BTS (%d)%s", bts_nr, VTY_NEWLINE);
		return CMD_WARNING;
	}

	oms = talloc_zero(tall_bsc_ctx, struct oml_node_state);
	if (!oms)
		return CMD_WARNING;

	oms->bts = bts;
	oms->mo.class = atoi(argv[1]);
	oms->mo.bts = atoi(argv[2]);
	oms->mo.assoc_so = atoi(argv[3]);
	oms->mo.inst = atoi(argv[4]);

	vty->index = oms;
	vty->node = OM2K_NODE;

	return CMD_SUCCESS;
}

DEFUN(om2k_reset, om2k_reset_cmd,
	"reset-command",
	"Reset the MO\n")
{
	struct oml_node_state *oms = vty->index;

	abis_om2k_tx_reset_cmd(oms->bts, &oms->mo);
	return CMD_SUCCESS;
}

DEFUN(om2k_start, om2k_start_cmd,
	"start-request",
	"Start the MO\n")
{
	struct oml_node_state *oms = vty->index;

	abis_om2k_tx_start_req(oms->bts, &oms->mo);
	return CMD_SUCCESS;
}

DEFUN(om2k_status, om2k_status_cmd,
	"status-request",
	"Get the MO Status\n")
{
	struct oml_node_state *oms = vty->index;

	abis_om2k_tx_status_req(oms->bts, &oms->mo);
	return CMD_SUCCESS;
}

DEFUN(om2k_connect, om2k_connect_cmd,
	"connect-command",
	"Connect the MO\n")
{
	struct oml_node_state *oms = vty->index;

	abis_om2k_tx_connect_cmd(oms->bts, &oms->mo);
	return CMD_SUCCESS;
}

DEFUN(om2k_disconnect, om2k_disconnect_cmd,
	"disconnect-command",
	"Disconnect the MO\n")
{
	struct oml_node_state *oms = vty->index;

	abis_om2k_tx_disconnect_cmd(oms->bts, &oms->mo);
	return CMD_SUCCESS;
}

DEFUN(om2k_enable, om2k_enable_cmd,
	"enable-request",
	"Enable the MO\n")
{
	struct oml_node_state *oms = vty->index;

	abis_om2k_tx_enable_req(oms->bts, &oms->mo);
	return CMD_SUCCESS;
}

DEFUN(om2k_disable, om2k_disable_cmd,
	"disable-request",
	"Disable the MO\n")
{
	struct oml_node_state *oms = vty->index;

	abis_om2k_tx_disable_req(oms->bts, &oms->mo);
	return CMD_SUCCESS;
}

DEFUN(om2k_op_info, om2k_op_info_cmd,
	"operational-info <0-1>",
	"Set operational information\n"
	"Set operational info to 0 or 1\n")
{
	struct oml_node_state *oms = vty->index;
	int oper = atoi(argv[0]);

	abis_om2k_tx_op_info(oms->bts, &oms->mo, oper);
	return CMD_SUCCESS;
}

DEFUN(om2k_test, om2k_test_cmd,
	"test-request",
	"Test the MO\n")
{
	struct oml_node_state *oms = vty->index;

	abis_om2k_tx_test_req(oms->bts, &oms->mo);
	return CMD_SUCCESS;
}

struct con_conn_group {
	struct llist_head list;

	uint8_t cg;
	uint16_t ccp;
	uint8_t tag;
	uint8_t tei;
};

static void add_con_list(struct gsm_bts *bts, uint8_t cg, uint16_t ccp,
			 uint8_t tag, uint8_t tei)
{
	struct con_conn_group *ent = talloc_zero(bts, struct con_conn_group);

	ent->cg = cg;
	ent->ccp = ccp;
	ent->tag = tag;
	ent->tei = tei;

	llist_add_tail(&ent->list, &bts->rbs2000.con.conn_groups);
}

static int del_con_list(struct gsm_bts *bts, uint8_t cg, uint16_t ccp,
			uint8_t tag, uint8_t tei)
{
	struct con_conn_group *grp, *grp2;

	llist_for_each_entry_safe(grp, grp2, &bts->rbs2000.con.conn_groups, list) {
		if (grp->cg == cg && grp->ccp == ccp && grp->tag == tag
		    && grp->tei == tei) {
			llist_del(&grp->list);
			talloc_free(grp);
			return 0;
		}
	}
	return -ENOENT;
}

#define CON_LIST_HELP	"CON connetiton list\n"			\
			"Add entry to CON list\n"		\
			"Delete entry from CON list\n"		\
			"Connection Group Number\n"		\
			"CON Connection Point\n"		\

DEFUN(om2k_con_list_dec, om2k_con_list_dec_cmd,
	"con-connection-list (add|del) <1-255> <0-1023> deconcentrated",
	CON_LIST_HELP "De-concentrated in/outlet\n")
{
	struct oml_node_state *oms = vty->index;
	struct gsm_bts *bts = oms->bts;
	uint8_t cg = atoi(argv[1]);
	uint16_t ccp = atoi(argv[2]);

	if (!strcmp(argv[0], "add"))
		add_con_list(bts, cg, ccp, 0, 0xff);
	else {
		if (del_con_list(bts, cg, ccp, 0, 0xff) < 0) {
			vty_out(vty, "%% No matching CON list entry%s",
				VTY_NEWLINE);
			return CMD_WARNING;
		}
	}

	return CMD_SUCCESS;
}

DEFUN(om2k_con_list_tei, om2k_con_list_tei_cmd,
	"con-connection-list (add|del) <1-255> <0-1023> tei <0-63>",
	CON_LIST_HELP "Concentrated in/outlet with TEI\n" "TEI Number\n")
{
	struct oml_node_state *oms = vty->index;
	struct gsm_bts *bts = oms->bts;
	uint8_t cg = atoi(argv[1]);
	uint16_t ccp = atoi(argv[2]);
	uint8_t tei = atoi(argv[3]);

	if (!strcmp(argv[0], "add"))
		add_con_list(bts, cg, ccp, cg, tei);
	else {
		if (del_con_list(bts, cg, ccp, cg, tei) < 0) {
			vty_out(vty, "%% No matching CON list entry%s",
				VTY_NEWLINE);
			return CMD_WARNING;
		}
	}

	return CMD_SUCCESS;
}

DEFUN(cfg_bts_is_conn_list, cfg_bts_is_conn_list_cmd,
	"is-connection-list (add|del) <0-2047> <0-2047> <0-255>",
	"Interface Switch Connnection List\n"
	"Add to IS list\n" "Delete from IS list\n"
	"ICP1\n" "ICP2\n" "Contiguity Index\n")
{
	struct gsm_bts *bts = vty->index;
	uint16_t icp1 = atoi(argv[1]);
	uint16_t icp2 = atoi(argv[2]);
	uint8_t ci = atoi(argv[3]);
	struct is_conn_group *grp, *grp2;

	if (!strcmp(argv[0], "add")) {
		grp = talloc_zero(bts, struct is_conn_group);
		grp->icp1 = icp1;
		grp->icp2 = icp2;
		grp->ci = ci;
		llist_add_tail(&grp->list, &bts->rbs2000.is.conn_groups);
	} else {
		llist_for_each_entry_safe(grp, grp2, &bts->rbs2000.is.conn_groups, list) {
			if (grp->icp1 == icp1 && grp->icp2 == icp2
			    && grp->ci == ci) {
				llist_del(&grp->list);
				talloc_free(grp);
				return CMD_SUCCESS;
			}
		}
		vty_out(vty, "%% No matching IS Conn Group found!%s",
			VTY_NEWLINE);
		return CMD_WARNING;
	}

	return CMD_SUCCESS;
}


DEFUN(om2k_conf_req, om2k_conf_req_cmd,
	"configuration-request",
	"Send the configuration request for current MO\n")
{
	struct oml_node_state *oms = vty->index;
	struct gsm_bts *bts = oms->bts;
	struct gsm_bts_trx *trx = NULL;
	struct gsm_bts_trx_ts *ts = NULL;

	switch (oms->mo.class) {
	case OM2K_MO_CLS_IS:
		abis_om2k_tx_is_conf_req(bts);
		break;
	case OM2K_MO_CLS_TS:
		trx = gsm_bts_trx_by_nr(bts, oms->mo.assoc_so);
		if (!trx) {
			vty_out(vty, "%% BTS %u has no TRX %u%s", bts->nr,
				oms->mo.assoc_so, VTY_NEWLINE);
			return CMD_WARNING;
		}
		if (oms->mo.inst >= ARRAY_SIZE(trx->ts)) {
			vty_out(vty, "%% Timeslot %u out of range%s",
				oms->mo.inst, VTY_NEWLINE);
			return CMD_WARNING;
		}
		ts = &trx->ts[oms->mo.inst];
		abis_om2k_tx_ts_conf_req(ts);
		break;
	case OM2K_MO_CLS_RX:
	case OM2K_MO_CLS_TX:
	case OM2K_MO_CLS_TRXC:
		trx = gsm_bts_trx_by_nr(bts, oms->mo.inst);
		if (!trx) {
			vty_out(vty, "%% BTS %u has no TRX %u%s", bts->nr,
				oms->mo.inst, VTY_NEWLINE);
			return CMD_WARNING;
		}
		switch (oms->mo.class) {
		case OM2K_MO_CLS_RX:
			abis_om2k_tx_rx_conf_req(trx);
			break;
		case OM2K_MO_CLS_TX:
			abis_om2k_tx_tx_conf_req(trx);
			break;
		default:
			break;
		}
		break;
	case OM2K_MO_CLS_TF:
		abis_om2k_tx_tf_conf_req(bts);
		break;
	default:
		vty_out(vty, "%% Don't know how to configure MO%s",
			VTY_NEWLINE);
	}

	return CMD_SUCCESS;
}

void abis_om2k_config_write_bts(struct vty *vty, struct gsm_bts *bts)
{
	struct is_conn_group *igrp;
	struct con_conn_group *cgrp;

	llist_for_each_entry(igrp, &bts->rbs2000.is.conn_groups, list)
		vty_out(vty, "  is-connection-list add %u %u %u%s",
			igrp->icp1, igrp->icp2, igrp->ci, VTY_NEWLINE);

	llist_for_each_entry(cgrp, &bts->rbs2000.con.conn_groups, list) {
		vty_out(vty, "  con-connection-list add %u %u ",
			cgrp->cg, cgrp->ccp);
		if (cgrp->tei == 0xff)
			vty_out(vty, "deconcentrated%s", VTY_NEWLINE);
		else
			vty_out(vty, "tei %u%s", cgrp->tei, VTY_NEWLINE);
	}
}

int abis_om2k_vty_init(void)
{
	install_element(ENABLE_NODE, &om2k_class_inst_cmd);
	install_element(ENABLE_NODE, &om2k_classnum_inst_cmd);
	install_node(&om2k_node, dummy_config_write);

	vty_install_default(OM2K_NODE);
	install_element(OM2K_NODE, &om2k_reset_cmd);
	install_element(OM2K_NODE, &om2k_start_cmd);
	install_element(OM2K_NODE, &om2k_status_cmd);
	install_element(OM2K_NODE, &om2k_connect_cmd);
	install_element(OM2K_NODE, &om2k_disconnect_cmd);
	install_element(OM2K_NODE, &om2k_enable_cmd);
	install_element(OM2K_NODE, &om2k_disable_cmd);
	install_element(OM2K_NODE, &om2k_op_info_cmd);
	install_element(OM2K_NODE, &om2k_test_cmd);
	install_element(OM2K_NODE, &om2k_conf_req_cmd);
	install_element(OM2K_NODE, &om2k_con_list_dec_cmd);
	install_element(OM2K_NODE, &om2k_con_list_tei_cmd);

	install_element(BTS_NODE, &cfg_bts_is_conn_list_cmd);

	return 0;
}
