/* MSC interface to quagga VTY */
/* (C) 2016 by sysmocom s.m.f.c. GmbH <info@sysmocom.de>
 * Based on OpenBSC interface to quagga VTY (libmsc/vty_interface_layer3.c)
 * (C) 2009 by Harald Welte <laforge@gnumonks.org>
 * (C) 2009-2011 by Holger Hans Peter Freyther
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

/* NOTE: I would have liked to call this the MSC_NODE instead of the CSCN_NODE,
 * but MSC_NODE already exists to configure a remote MSC for osmo-bsc. */

#include <inttypes.h>

#include <osmocom/vty/command.h>

#include <openbsc/vty.h>
#include <openbsc/gsm_data.h>
#include <openbsc/gsm_subscriber.h>
#include <openbsc/iu.h>

static struct cmd_node cscn_node = {
	CSCN_NODE,
	"%s(config-cscn)# ",
	1,
};

DEFUN(cfg_cscn, cfg_cscn_cmd,
      "cscn", "Configure CSCN options")
{
	vty->node = CSCN_NODE;
	return CMD_SUCCESS;
}

/* Note: limit on the parameter length is set by internal vty code limitations */
DEFUN(cfg_cscn_subscr_random, cfg_cscn_subscr_random_cmd,
      "subscriber-create-on-demand random <1-9999999999> <2-9999999999>",
      "Set random parameters for a new record when a subscriber is first seen.\n"
      "Set random parameters for a new record when a subscriber is first seen.\n"
      "Minimum for subscriber extension\n""Maximum for subscriber extension\n")
{
	struct gsm_network *gsmnet = gsmnet_from_vty(vty);
	uint64_t mi = atoi(argv[0]), ma = atoi(argv[1]);
	gsmnet->auto_create_subscr = true;
	gsmnet->auto_assign_exten = true;
	if (mi >= ma) {
		vty_out(vty, "Incorrect range: %s >= %s, expected MIN < MAX%s",
			argv[0], argv[1], VTY_NEWLINE);
		return CMD_WARNING;
	}
	gsmnet->ext_min = mi;
	gsmnet->ext_max = ma;
        return CMD_SUCCESS;
}

DEFUN(cfg_cscn_subscr_create, cfg_cscn_subscr_create_cmd,
      "subscriber-create-on-demand [no-extension]",
      "Make a new record when a subscriber is first seen.\n"
      "Do not automatically assign extension to created subscribers\n")
{
	struct gsm_network *gsmnet = gsmnet_from_vty(vty);
	gsmnet->auto_create_subscr = true;
	gsmnet->auto_assign_exten = argc ? false : true;
	return CMD_SUCCESS;
}

DEFUN(cfg_cscn_no_subscr_create, cfg_cscn_no_subscr_create_cmd,
      "no subscriber-create-on-demand",
      NO_STR "Make a new record when a subscriber is first seen.\n")
{
	struct gsm_network *gsmnet = gsmnet_from_vty(vty);
	gsmnet->auto_create_subscr = false;
	return CMD_SUCCESS;
}

DEFUN(cfg_cscn_assign_tmsi, cfg_cscn_assign_tmsi_cmd,
      "assign-tmsi",
      "Assign TMSI during Location Updating.\n")
{
	struct gsm_network *gsmnet = gsmnet_from_vty(vty);
	gsmnet->avoid_tmsi = 0;
	return CMD_SUCCESS;
}

DEFUN(cfg_cscn_no_assign_tmsi, cfg_cscn_no_assign_tmsi_cmd,
      "no assign-tmsi",
      NO_STR "Assign TMSI during Location Updating.\n")
{
	struct gsm_network *gsmnet = gsmnet_from_vty(vty);
	gsmnet->avoid_tmsi = 1;
	return CMD_SUCCESS;
}

static int config_write_cscn(struct vty *vty)
{
	struct gsm_network *gsmnet = gsmnet_from_vty(vty);

	vty_out(vty, "cscn%s", VTY_NEWLINE);
	if (!gsmnet->auto_create_subscr)
		vty_out(vty, " no subscriber-create-on-demand%s", VTY_NEWLINE);
	else
		vty_out(vty, " subscriber-create-on-demand%s%s",
			gsmnet->auto_assign_exten ? "" : " no-extension",
			VTY_NEWLINE);

	if (gsmnet->ext_min != GSM_MIN_EXTEN || gsmnet->ext_max != GSM_MAX_EXTEN)
		vty_out(vty, " subscriber-create-on-demand random %"PRIu64" %"
			PRIu64"%s", gsmnet->ext_min, gsmnet->ext_max,
			VTY_NEWLINE);
	vty_out(vty, " %sassign-tmsi%s",
		gsmnet->avoid_tmsi ? "no " : "", VTY_NEWLINE);

	mgcpgw_client_config_write(vty, " ");
	iu_vty_config_write(vty, " ");

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
	vty_out(vty, " rrlp mode %s%s", rrlp_mode_name(gsmnet->rrlp.mode),
		VTY_NEWLINE);
	vty_out(vty, " mm info %u%s", gsmnet->send_mm_info, VTY_NEWLINE);
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

void cscn_vty_init(struct gsm_network *cscn_network)
{
	common_cs_vty_init(cscn_network, config_write_net);

	install_element(CONFIG_NODE, &cfg_cscn_cmd);
	install_node(&cscn_node, config_write_cscn);
	install_element(CSCN_NODE, &cfg_cscn_subscr_create_cmd);
	install_element(CSCN_NODE, &cfg_cscn_subscr_random_cmd);
	install_element(CSCN_NODE, &cfg_cscn_no_subscr_create_cmd);
	install_element(CSCN_NODE, &cfg_cscn_assign_tmsi_cmd);
	install_element(CSCN_NODE, &cfg_cscn_no_assign_tmsi_cmd);
	mgcpgw_client_vty_init(CSCN_NODE, &cscn_network->mgcpgw.conf);
	iu_vty_init(CSCN_NODE, &cscn_network->iu.rab_assign_addr_enc);
}
