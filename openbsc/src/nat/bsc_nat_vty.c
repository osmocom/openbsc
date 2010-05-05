/* OpenBSC NAT interface to quagga VTY */
/* (C) 2010 by Holger Hans Peter Freyther
 * (C) 2010 by On-Waves
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

#include <vty/command.h>
#include <vty/buffer.h>
#include <vty/vty.h>

#include <openbsc/bsc_nat.h>
#include <openbsc/gsm_04_08.h>
#include <openbsc/mgcp.h>
#include <openbsc/vty.h>

#include <osmocore/talloc.h>

#include <sccp/sccp.h>

#include <stdlib.h>

static struct bsc_nat *_nat;

static struct cmd_node nat_node = {
	NAT_NODE,
	"%s(nat)#",
	1,
};

static struct cmd_node bsc_node = {
	BSC_NODE,
	"%s(bsc)#",
	1,
};

static int config_write_nat(struct vty *vty)
{
	vty_out(vty, "nat%s", VTY_NEWLINE);
	if (_nat->imsi_allow)
		vty_out(vty, " imsi allow %s%s", _nat->imsi_allow, VTY_NEWLINE);
	if (_nat->imsi_deny)
		vty_out(vty, " insi deny %s%s", _nat->imsi_deny, VTY_NEWLINE);
	vty_out(vty, " msc ip %s%s", _nat->msc_ip, VTY_NEWLINE);
	vty_out(vty, " msc port %d%s", _nat->msc_port, VTY_NEWLINE);
	vty_out(vty, " timeout auth %d%s", _nat->auth_timeout, VTY_NEWLINE);
	vty_out(vty, " timeout ping %d%s", _nat->ping_timeout, VTY_NEWLINE);
	vty_out(vty, " timeout pong %d%s", _nat->pong_timeout, VTY_NEWLINE);
	return CMD_SUCCESS;
}

static void config_write_bsc_single(struct vty *vty, struct bsc_config *bsc)
{
	vty_out(vty, " bsc %u%s", bsc->nr, VTY_NEWLINE);
	vty_out(vty, "  token %s%s", bsc->token, VTY_NEWLINE);
	vty_out(vty, "  location_area_code %u%s", bsc->lac, VTY_NEWLINE);
	if (bsc->imsi_allow)
		vty_out(vty, "   imsi allow %s%s", bsc->imsi_allow, VTY_NEWLINE);
	if (bsc->imsi_deny)
		vty_out(vty, "   imsi deny %s%s", bsc->imsi_deny, VTY_NEWLINE);
	vty_out(vty, "  paging forbidden %d%s", bsc->forbid_paging, VTY_NEWLINE);
}

static int config_write_bsc(struct vty *vty)
{
	struct bsc_config *bsc;

	llist_for_each_entry(bsc, &_nat->bsc_configs, entry)
		config_write_bsc_single(vty, bsc);
	return CMD_SUCCESS;
}


DEFUN(show_sccp, show_sccp_cmd, "show sccp connections",
      SHOW_STR "Display information about current SCCP connections")
{
	struct sccp_connections *con;
	vty_out(vty, "Listing all opening SCCP connections%s", VTY_NEWLINE);

	llist_for_each_entry(con, &_nat->sccp_connections, list_entry) {
		vty_out(vty, "For BSC Nr: %d lac: %d; BSC ref: 0x%x; MUX ref: 0x%x; Network has ref: %d ref: 0x%x MSC/BSC mux: 0x%x/0x%x%s",
			con->bsc->cfg ? con->bsc->cfg->nr : -1,
			con->bsc->cfg ? con->bsc->cfg->lac : -1,
			sccp_src_ref_to_int(&con->real_ref),
			sccp_src_ref_to_int(&con->patched_ref),
			con->has_remote_ref,
			sccp_src_ref_to_int(&con->remote_ref),
			con->msc_timeslot, con->bsc_timeslot,
			VTY_NEWLINE);
	}

	return CMD_SUCCESS;
}

DEFUN(show_bsc, show_bsc_cmd, "show bsc connections",
      SHOW_STR "Display information about current BSCs")
{
	struct bsc_connection *con;
	struct sockaddr_in sock;
	socklen_t len = sizeof(sock);

	llist_for_each_entry(con, &_nat->bsc_connections, list_entry) {
		getpeername(con->write_queue.bfd.fd, (struct sockaddr *) &sock, &len);
		vty_out(vty, "BSC nr: %d lac: %d auth: %d fd: %d peername: %s%s",
			con->cfg ? con->cfg->nr : -1,
			con->cfg ? con->cfg->lac : -1,
			con->authenticated, con->write_queue.bfd.fd,
			inet_ntoa(sock.sin_addr), VTY_NEWLINE);
	}

	return CMD_SUCCESS;
}

DEFUN(show_bsc_cfg, show_bsc_cfg_cmd, "show bsc config",
      SHOW_STR "Display information about known BSC configs")
{
	struct bsc_config *conf;
	llist_for_each_entry(conf, &_nat->bsc_configs, entry) {
		vty_out(vty, "BSC token: '%s' lac: %u nr: %u%s",
			conf->token, conf->lac, conf->nr, VTY_NEWLINE);
		vty_out(vty, " imsi_allow: '%s' imsi_deny: '%s'%s",
			conf->imsi_allow ? conf->imsi_allow: "any",
			conf->imsi_deny  ? conf->imsi_deny : "none",
			VTY_NEWLINE);
		vty_out(vty, " paging forbidden: %d%s",
			conf->forbid_paging, VTY_NEWLINE);
	}

	return CMD_SUCCESS;
}

DEFUN(show_stats,
      show_stats_cmd,
      "show statistics [NR]",
	SHOW_STR "Display network statistics")
{
	struct bsc_config *conf;

	int nr = -1;

	if (argc == 1)
		nr = atoi(argv[0]);

	vty_out(vty, "NAT statistics%s", VTY_NEWLINE);
	vty_out(vty, " SCCP Connections %lu total, %lu calls%s",
		counter_get(_nat->stats.sccp.conn),
		counter_get(_nat->stats.sccp.calls), VTY_NEWLINE);
	vty_out(vty, " MSC Connections %lu%s",
		counter_get(_nat->stats.msc.reconn), VTY_NEWLINE);
	vty_out(vty, " BSC Connections %lu total, %lu auth failed.%s",
		counter_get(_nat->stats.bsc.reconn),
		counter_get(_nat->stats.bsc.auth_fail), VTY_NEWLINE);

	llist_for_each_entry(conf, &_nat->bsc_configs, entry) {
		if (argc == 1 && nr != conf->nr)
			continue;

		vty_out(vty, " BSC lac: %d nr: %d%s",
			conf->lac, conf->nr, VTY_NEWLINE);
		vty_out(vty, "   SCCP Connnections %lu total, %lu calls%s",
			counter_get(conf->stats.sccp.conn),
			counter_get(conf->stats.sccp.calls), VTY_NEWLINE);
		vty_out(vty, "   BSC Connections %lu total%s",
			counter_get(conf->stats.net.reconn), VTY_NEWLINE);
	}

	return CMD_SUCCESS;
}

DEFUN(close_bsc,
      close_bsc_cmd,
      "close bsc connection BSC_NR",
      "Close the connection with the BSC identified by the config number.")
{
	struct bsc_connection *bsc;
	int bsc_nr = atoi(argv[0]);

	llist_for_each_entry(bsc, &_nat->bsc_connections, list_entry) {
		if (!bsc->cfg || bsc->cfg->nr != bsc_nr)
			continue;
		bsc_close_connection(bsc);
		break;
	}

	return CMD_SUCCESS;
}

DEFUN(cfg_nat, cfg_nat_cmd, "nat", "Configute the NAT")
{
	vty->index = _nat;
	vty->node = NAT_NODE;

	return CMD_SUCCESS;
}

static void parse_reg(void *ctx, regex_t *reg, char **imsi, int argc, const char **argv)
{
	if (*imsi) {
		talloc_free(*imsi);
		*imsi = NULL;
	}
	regfree(reg);

	if (argc > 0) {
		*imsi = talloc_strdup(ctx, argv[0]);
		regcomp(reg, argv[0], 0);
	}
}

DEFUN(cfg_nat_imsi_allow,
      cfg_nat_imsi_allow_cmd,
      "imsi allow [REGEXP]",
      "Allow matching IMSIs to talk to the MSC. "
      "The defualt is to allow everyone.")
{
	parse_reg(_nat, &_nat->imsi_allow_re, &_nat->imsi_allow, argc, argv);
	return CMD_SUCCESS;
}

DEFUN(cfg_nat_imsi_deny,
      cfg_nat_imsi_deny_cmd,
      "imsi deny [REGEXP]",
      "Deny matching IMSIs to talk to the MSC. "
      "The defualt is to not deny.")
{
	parse_reg(_nat, &_nat->imsi_deny_re, &_nat->imsi_deny, argc, argv);
	return CMD_SUCCESS;
}

DEFUN(cfg_nat_msc_ip,
      cfg_nat_msc_ip_cmd,
      "msc ip IP",
      "Set the IP address of the MSC.")
{
	bsc_nat_set_msc_ip(_nat, argv[0]);
	return CMD_SUCCESS;
}

DEFUN(cfg_nat_msc_port,
      cfg_nat_msc_port_cmd,
      "msc port <1-65500>",
      "Set the port of the MSC.")
{
	_nat->msc_port = atoi(argv[0]);
	return CMD_SUCCESS;
}

DEFUN(cfg_nat_auth_time,
      cfg_nat_auth_time_cmd,
      "timeout auth <1-256>",
      "The time to wait for an auth response.")
{
	_nat->auth_timeout = atoi(argv[0]);
	return CMD_SUCCESS;
}

DEFUN(cfg_nat_ping_time,
      cfg_nat_ping_time_cmd,
      "timeout ping NR",
      "Send a ping every NR seconds. Negative to disable.")
{
	_nat->ping_timeout = atoi(argv[0]);
	return CMD_SUCCESS;
}

DEFUN(cfg_nat_pong_time,
      cfg_nat_pong_time_cmd,
      "timeout pong NR",
      "Wait NR seconds for the PONG response. Should be smaller than ping.")
{
	_nat->pong_timeout = atoi(argv[0]);
	return CMD_SUCCESS;
}

/* per BSC configuration */
DEFUN(cfg_bsc, cfg_bsc_cmd, "bsc BSC_NR", "Select a BSC to configure")
{
	int bsc_nr = atoi(argv[0]);
	struct bsc_config *bsc;

	if (bsc_nr > _nat->num_bsc) {
		vty_out(vty, "%% The next unused BSC number is %u%s",
			_nat->num_bsc, VTY_NEWLINE);
		return CMD_WARNING;
	} else if (bsc_nr == _nat->num_bsc) {
		/* allocate a new one */
		bsc = bsc_config_alloc(_nat, "unknown", 0);
	} else
		bsc = bsc_config_num(_nat, bsc_nr);

	if (!bsc)
		return CMD_WARNING;

	vty->index = bsc;
	vty->node = BSC_NODE;

	return CMD_SUCCESS;
}

DEFUN(cfg_bsc_token, cfg_bsc_token_cmd, "token TOKEN", "Set the token")
{
	struct bsc_config *conf = vty->index;

	if (conf->token)
	    talloc_free(conf->token);
	conf->token = talloc_strdup(conf, argv[0]);
	return CMD_SUCCESS;
}

DEFUN(cfg_bsc_lac, cfg_bsc_lac_cmd, "location_area_code <0-65535>",
      "Set the Location Area Code (LAC) of this BSC")
{
	struct bsc_config *tmp;
	struct bsc_config *conf = vty->index;

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

	/* verify that the LACs are unique */
	llist_for_each_entry(tmp, &_nat->bsc_configs, entry) {
		if (tmp->lac == lac) {
			vty_out(vty, "%% LAC %d is already used.%s", lac, VTY_NEWLINE);
			return CMD_ERR_INCOMPLETE;
		}
	}

	conf->lac = lac;

	return CMD_SUCCESS;
}

DEFUN(cfg_bsc_imsi_allow,
      cfg_bsc_imsi_allow_cmd,
      "imsi allow [REGEXP]",
      "Allow IMSIs with the following network to talk to the MSC."
      "The default is to allow everyone)")
{
	struct bsc_config *conf = vty->index;

	parse_reg(conf, &conf->imsi_allow_re, &conf->imsi_allow, argc, argv);
	return CMD_SUCCESS;
}

DEFUN(cfg_bsc_imsi_deny,
      cfg_bsc_imsi_deny_cmd,
      "imsi deny [REGEXP]",
      "Deny IMSIs with the following network to talk to the MSC."
      "The default is to not deny anyone.)")
{
	struct bsc_config *conf = vty->index;

	parse_reg(conf, &conf->imsi_deny_re, &conf->imsi_deny, argc, argv);
	return CMD_SUCCESS;
}

DEFUN(cfg_bsc_paging,
      cfg_bsc_paging_cmd,
      "paging forbidden (0|1)",
      "Forbid sending PAGING REQUESTS to the BSC.")
{
	struct bsc_config *conf = vty->index;

	if (strcmp("1", argv[0]) == 0)
		conf->forbid_paging = 1;
	else
		conf->forbid_paging = 0;

	return CMD_SUCCESS;
}

int bsc_nat_vty_init(struct bsc_nat *nat)
{
	_nat = nat;

	cmd_init(1);
	vty_init();

	/* show commands */
	install_element(VIEW_NODE, &show_sccp_cmd);
	install_element(VIEW_NODE, &show_bsc_cmd);
	install_element(VIEW_NODE, &show_bsc_cfg_cmd);
	install_element(VIEW_NODE, &show_stats_cmd);
	install_element(VIEW_NODE, &close_bsc_cmd);

	openbsc_vty_add_cmds();

	/* nat group */
	install_element(CONFIG_NODE, &cfg_nat_cmd);
	install_node(&nat_node, config_write_nat);
	install_default(NAT_NODE);
	install_element(NAT_NODE, &cfg_nat_imsi_allow_cmd);
	install_element(NAT_NODE, &cfg_nat_imsi_deny_cmd);
	install_element(NAT_NODE, &cfg_nat_msc_ip_cmd);
	install_element(NAT_NODE, &cfg_nat_msc_port_cmd);
	install_element(NAT_NODE, &cfg_nat_auth_time_cmd);
	install_element(NAT_NODE, &cfg_nat_ping_time_cmd);
	install_element(NAT_NODE, &cfg_nat_pong_time_cmd);

	/* BSC subgroups */
	install_element(NAT_NODE, &cfg_bsc_cmd);
	install_node(&bsc_node, config_write_bsc);
	install_default(BSC_NODE);
	install_element(BSC_NODE, &cfg_bsc_token_cmd);
	install_element(BSC_NODE, &cfg_bsc_lac_cmd);
	install_element(BSC_NODE, &cfg_bsc_imsi_allow_cmd);
	install_element(BSC_NODE, &cfg_bsc_imsi_deny_cmd);
	install_element(BSC_NODE, &cfg_bsc_paging_cmd);

	mgcp_vty_init();

	return 0;
}


/* called by the telnet interface... we have our own init above */
void bsc_vty_init()
{}
