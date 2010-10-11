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

#include <openbsc/vty.h>
#include <openbsc/bsc_nat.h>
#include <openbsc/bsc_nat_sccp.h>
#include <openbsc/bsc_msc.h>
#include <openbsc/gsm_04_08.h>
#include <openbsc/mgcp.h>
#include <openbsc/vty.h>

#include <osmocore/talloc.h>
#include <osmocore/rate_ctr.h>
#include <osmocore/utils.h>

#include <osmocom/sccp/sccp.h>

#include <stdlib.h>

static struct bsc_nat *_nat;

static struct cmd_node nat_node = {
	NAT_NODE,
	"%s(nat)#",
	1,
};

static struct cmd_node bsc_node = {
	NAT_BSC_NODE,
	"%s(bsc)#",
	1,
};

static void write_acc_lst(struct vty *vty, struct bsc_nat_acc_lst *lst)
{
	struct bsc_nat_acc_lst_entry *entry;

	llist_for_each_entry(entry, &lst->fltr_list, list) {
		if (entry->imsi_allow)
			vty_out(vty, " access-list %s imsi-allow %s%s",
				lst->name, entry->imsi_allow, VTY_NEWLINE);
		if (entry->imsi_deny)
			vty_out(vty, " access-list %s imsi-deny %s%s",
				lst->name, entry->imsi_deny, VTY_NEWLINE);
	}
}

static int config_write_nat(struct vty *vty)
{
	struct bsc_nat_acc_lst *lst;

	vty_out(vty, "nat%s", VTY_NEWLINE);
	vty_out(vty, " msc ip %s%s", _nat->msc_ip, VTY_NEWLINE);
	vty_out(vty, " msc port %d%s", _nat->msc_port, VTY_NEWLINE);
	vty_out(vty, " timeout auth %d%s", _nat->auth_timeout, VTY_NEWLINE);
	vty_out(vty, " timeout ping %d%s", _nat->ping_timeout, VTY_NEWLINE);
	vty_out(vty, " timeout pong %d%s", _nat->pong_timeout, VTY_NEWLINE);
	if (_nat->token)
		vty_out(vty, " token %s%s", _nat->token, VTY_NEWLINE);
	vty_out(vty, " ip-dscp %d%s", _nat->bsc_ip_dscp, VTY_NEWLINE);
	if (_nat->acc_lst_name)
		vty_out(vty, " access-list-name %s%s", _nat->acc_lst_name, VTY_NEWLINE);
	if (_nat->ussd_lst_name)
		vty_out(vty, " ussd-list-name %s%s", _nat->ussd_lst_name, VTY_NEWLINE);
	if (_nat->ussd_query)
		vty_out(vty, " ussd-query %s%s", _nat->ussd_query, VTY_NEWLINE);

	llist_for_each_entry(lst, &_nat->access_lists, list) {
		write_acc_lst(vty, lst);
	}

	return CMD_SUCCESS;
}

static void dump_lac(struct vty *vty, struct bsc_config *cfg)
{
	struct bsc_lac_entry *lac;
	llist_for_each_entry(lac, &cfg->lac_list, entry)
		vty_out(vty, "  location_area_code %u%s", lac->lac, VTY_NEWLINE);
}

static void config_write_bsc_single(struct vty *vty, struct bsc_config *bsc)
{
	vty_out(vty, " bsc %u%s", bsc->nr, VTY_NEWLINE);
	vty_out(vty, "  token %s%s", bsc->token, VTY_NEWLINE);
	dump_lac(vty, bsc);
	vty_out(vty, "  paging forbidden %d%s", bsc->forbid_paging, VTY_NEWLINE);
	if (bsc->description)
		vty_out(vty, "  description %s%s", bsc->description, VTY_NEWLINE);
	if (bsc->acc_lst_name)
		vty_out(vty, "  access-list-name %s%s", bsc->acc_lst_name, VTY_NEWLINE);
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
	vty_out(vty, "Listing all open SCCP connections%s", VTY_NEWLINE);

	llist_for_each_entry(con, &_nat->sccp_connections, list_entry) {
		vty_out(vty, "For BSC Nr: %d BSC ref: 0x%x; MUX ref: 0x%x; Network has ref: %d ref: 0x%x MSC/BSC mux: 0x%x/0x%x type: %s%s",
			con->bsc->cfg ? con->bsc->cfg->nr : -1,
			sccp_src_ref_to_int(&con->real_ref),
			sccp_src_ref_to_int(&con->patched_ref),
			con->has_remote_ref,
			sccp_src_ref_to_int(&con->remote_ref),
			con->msc_endp, con->bsc_endp,
			bsc_con_type_to_string(con->con_type),
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
		vty_out(vty, "BSC nr: %d auth: %d fd: %d peername: %s%s",
			con->cfg ? con->cfg->nr : -1,
			con->authenticated, con->write_queue.bfd.fd,
			inet_ntoa(sock.sin_addr), VTY_NEWLINE);
	}

	return CMD_SUCCESS;
}

DEFUN(show_bsc_mgcp, show_bsc_mgcp_cmd, "show bsc mgcp NR",
      SHOW_STR "Display the MGCP status for a given BSC")
{
	struct bsc_connection *con;
	int nr = atoi(argv[0]);
	int i;

	llist_for_each_entry(con, &_nat->bsc_connections, list_entry) {
		if (!con->cfg)
			continue;
		if (con->cfg->nr != nr)
			continue;

		vty_out(vty, "MGCP Status for %d%s", con->cfg->nr, VTY_NEWLINE);
		for (i = 1; i < ARRAY_SIZE(con->endpoint_status); ++i)
			vty_out(vty, " Endpoint 0x%x %s%s", i,
				con->endpoint_status[i] == 0 ? "free" : "allocated",
				VTY_NEWLINE);
		break;
	}

	return CMD_SUCCESS;
}

DEFUN(show_bsc_cfg, show_bsc_cfg_cmd, "show bsc config",
      SHOW_STR "Display information about known BSC configs")
{
	struct bsc_config *conf;
	llist_for_each_entry(conf, &_nat->bsc_configs, entry) {
		vty_out(vty, "BSC token: '%s' nr: %u%s",
			conf->token, conf->nr, VTY_NEWLINE);
		if (conf->acc_lst_name)
			vty_out(vty, " access-list: %s%s",
				conf->acc_lst_name, VTY_NEWLINE);
		vty_out(vty, " paging forbidden: %d%s",
			conf->forbid_paging, VTY_NEWLINE);
		if (conf->description)
			vty_out(vty, " description: %s%s", conf->description, VTY_NEWLINE);
		else
			vty_out(vty, " No description.%s", VTY_NEWLINE);

	}

	return CMD_SUCCESS;
}

static void dump_stat_total(struct vty *vty, struct bsc_nat *nat)
{
	vty_out(vty, "NAT statistics%s", VTY_NEWLINE);
	vty_out(vty, " SCCP Connections %lu total, %lu calls%s",
		counter_get(nat->stats.sccp.conn),
		counter_get(nat->stats.sccp.calls), VTY_NEWLINE);
	vty_out(vty, " MSC Connections %lu%s",
		counter_get(nat->stats.msc.reconn), VTY_NEWLINE);
	vty_out(vty, " MSC Connected: %d%s",
		nat->msc_con->is_connected, VTY_NEWLINE);
	vty_out(vty, " BSC Connections %lu total, %lu auth failed.%s",
		counter_get(nat->stats.bsc.reconn),
		counter_get(nat->stats.bsc.auth_fail), VTY_NEWLINE);
}

static void dump_stat_bsc(struct vty *vty, struct bsc_config *conf)
{
	int connected = 0;
	struct bsc_connection *con;

	vty_out(vty, " BSC nr: %d%s",
		conf->nr, VTY_NEWLINE);
	vty_out_rate_ctr_group(vty, " ", conf->stats.ctrg);

	llist_for_each_entry(con, &conf->nat->bsc_connections, list_entry) {
		if (con->cfg != conf)
			continue;
		connected = 1;
		break;
	}

	vty_out(vty, "  Connected: %d%s", connected, VTY_NEWLINE);
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

	dump_stat_total(vty, _nat);
	llist_for_each_entry(conf, &_nat->bsc_configs, entry) {
		if (argc == 1 && nr != conf->nr)
			continue;
		dump_stat_bsc(vty, conf);
	}

	return CMD_SUCCESS;
}

DEFUN(show_stats_lac,
      show_stats_lac_cmd,
      "show statistics-by-lac <0-65535>",
      SHOW_STR "Display network statistics by lac\n"
      "The lac of the BSC\n")
{
	int lac;
	struct bsc_config *conf;

	lac = atoi(argv[0]);

	dump_stat_total(vty, _nat);
	llist_for_each_entry(conf, &_nat->bsc_configs, entry) {
		if (!bsc_config_handles_lac(conf, lac))
			continue;
		dump_stat_bsc(vty, conf);
	}

	return CMD_SUCCESS;
}

DEFUN(show_msc,
      show_msc_cmd,
      "show msc connection",
      SHOW_STR "Show the status of the MSC connection.")
{
	if (!_nat->msc_con) {
		vty_out(vty, "The MSC is not yet configured.\n");
		return CMD_WARNING;
	}

	vty_out(vty, "MSC on %s:%d is connected: %d%s\n",
		_nat->msc_con->ip, _nat->msc_con->port,
		_nat->msc_con->is_connected, VTY_NEWLINE);
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

DEFUN(cfg_nat_msc_ip,
      cfg_nat_msc_ip_cmd,
      "msc ip A.B.C.D",
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

DEFUN(cfg_nat_token, cfg_nat_token_cmd,
      "token TOKEN",
      "Set a token for the NAT")
{
	bsc_replace_string(_nat, &_nat->token, argv[0]);
	return CMD_SUCCESS;
}

DEFUN(cfg_nat_bsc_ip_dscp, cfg_nat_bsc_ip_dscp_cmd,
      "ip-dscp <0-255>",
      "Set the IP DSCP for the BSCs to use\n" "Set the IP_TOS attribute")
{
	_nat->bsc_ip_dscp = atoi(argv[0]);
	return CMD_SUCCESS;
}

ALIAS_DEPRECATED(cfg_nat_bsc_ip_dscp, cfg_nat_bsc_ip_tos_cmd,
      "ip-tos <0-255>",
      "Use ip-dscp in the future.\n" "Set the DSCP\n")


DEFUN(cfg_nat_acc_lst_name,
      cfg_nat_acc_lst_name_cmd,
      "access-list-name NAME",
      "Set the name of the access list to use.\n"
      "The name of the to be used access list.")
{
	bsc_replace_string(_nat, &_nat->acc_lst_name, argv[0]);
	return CMD_SUCCESS;
}

DEFUN(cfg_nat_ussd_lst_name,
      cfg_nat_ussd_lst_name_cmd,
      "ussd-list-name NAME",
      "Set the name of the access list to check for IMSIs for USSD message\n"
      "The name of the access list for HLR USSD handling")
{
	if (_nat->ussd_lst_name)
		talloc_free(_nat->ussd_lst_name);
	_nat->ussd_lst_name = talloc_strdup(_nat, argv[0]);
	return CMD_SUCCESS;
}

DEFUN(cfg_nat_ussd_query,
      cfg_nat_ussd_query_cmd,
      "ussd-query QUERY",
      "Set the USSD query to match with the ussd-list-name\n"
      "The query to match")
{
	if (_nat->ussd_query)
		talloc_free(_nat->ussd_query);
	_nat->ussd_query = talloc_strdup(_nat, argv[0]);
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
		bsc = bsc_config_alloc(_nat, "unknown");
	} else
		bsc = bsc_config_num(_nat, bsc_nr);

	if (!bsc)
		return CMD_WARNING;

	vty->index = bsc;
	vty->node = NAT_BSC_NODE;

	return CMD_SUCCESS;
}

DEFUN(cfg_bsc_token, cfg_bsc_token_cmd, "token TOKEN", "Set the token")
{
	struct bsc_config *conf = vty->index;

	bsc_replace_string(conf, &conf->token, argv[0]);
	return CMD_SUCCESS;
}

DEFUN(cfg_bsc_lac, cfg_bsc_lac_cmd, "location_area_code <0-65535>",
      "Set the Location Area Code (LAC) of this BSC")
{
	struct bsc_config *tmp;
	struct bsc_config *conf = vty->index;

	int lac = atoi(argv[0]);

	if (lac == GSM_LAC_RESERVED_DETACHED || lac == GSM_LAC_RESERVED_ALL_BTS) {
		vty_out(vty, "%% LAC %d is reserved by GSM 04.08%s",
			lac, VTY_NEWLINE);
		return CMD_WARNING;
	}

	/* verify that the LACs are unique */
	llist_for_each_entry(tmp, &_nat->bsc_configs, entry) {
		if (bsc_config_handles_lac(tmp, lac)) {
			vty_out(vty, "%% LAC %d is already used.%s", lac, VTY_NEWLINE);
			return CMD_ERR_INCOMPLETE;
		}
	}

	bsc_config_add_lac(conf, lac);

	return CMD_SUCCESS;
}

DEFUN(cfg_bsc_no_lac, cfg_bsc_no_lac_cmd,
      "no location_area_code <0-65535>",
      NO_STR "Set the Location Area Code (LAC) of this BSC")
{
	int lac = atoi(argv[0]);
	struct bsc_config *conf = vty->index;

	bsc_config_del_lac(conf, lac);
	return CMD_SUCCESS;
}



DEFUN(cfg_lst_imsi_allow,
      cfg_lst_imsi_allow_cmd,
      "access-list NAME imsi-allow [REGEXP]",
      "Allow IMSIs matching the REGEXP\n"
      "The name of the access-list\n"
      "The regexp of allowed IMSIs\n")
{
	struct bsc_nat_acc_lst *acc;
	struct bsc_nat_acc_lst_entry *entry;

	acc = bsc_nat_acc_lst_get(_nat, argv[0]);
	if (!acc)
		return CMD_WARNING;

	entry = bsc_nat_acc_lst_entry_create(acc);
	if (!entry)
		return CMD_WARNING;

	bsc_parse_reg(acc, &entry->imsi_allow_re, &entry->imsi_allow, argc - 1, &argv[1]);
	return CMD_SUCCESS;
}

DEFUN(cfg_lst_imsi_deny,
      cfg_lst_imsi_deny_cmd,
      "access-list NAME imsi-deny [REGEXP]",
      "Allow IMSIs matching the REGEXP\n"
      "The name of the access-list\n"
      "The regexp of to be denied IMSIs\n")
{
	struct bsc_nat_acc_lst *acc;
	struct bsc_nat_acc_lst_entry *entry;

	acc = bsc_nat_acc_lst_get(_nat, argv[0]);
	if (!acc)
		return CMD_WARNING;

	entry = bsc_nat_acc_lst_entry_create(acc);
	if (!entry)
		return CMD_WARNING;

	bsc_parse_reg(acc, &entry->imsi_deny_re, &entry->imsi_deny, argc - 1, &argv[1]);
	return CMD_SUCCESS;
}

/* naming to follow Zebra... */
DEFUN(cfg_lst_no,
      cfg_lst_no_cmd,
      "no access-list NAME",
      NO_STR "Remove an access-list by name\n"
      "The access-list to remove\n")
{
	struct bsc_nat_acc_lst *acc;
	acc = bsc_nat_acc_lst_find(_nat, argv[0]);
	if (!acc)
		return CMD_WARNING;

	bsc_nat_acc_lst_delete(acc);
	return CMD_SUCCESS;
}

DEFUN(show_acc_lst,
      show_acc_lst_cmd,
      "show access-list NAME",
      SHOW_STR "The name of the access list\n")
{
	struct bsc_nat_acc_lst *acc;
	acc = bsc_nat_acc_lst_find(_nat, argv[0]);
	if (!acc)
		return CMD_WARNING;

	vty_out(vty, "access-list %s%s", acc->name, VTY_NEWLINE);
	vty_out_rate_ctr_group(vty, " ", acc->stats);

	return CMD_SUCCESS;
}


DEFUN(cfg_bsc_acc_lst_name,
      cfg_bsc_acc_lst_name_cmd,
      "access-list-name NAME",
      "Set the name of the access list to use.\n"
      "The name of the to be used access list.")
{
	struct bsc_config *conf = vty->index;

	bsc_replace_string(conf, &conf->acc_lst_name, argv[0]);
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

DEFUN(cfg_bsc_desc,
      cfg_bsc_desc_cmd,
      "description DESC",
      "Provide a description for the given BSC.")
{
	struct bsc_config *conf = vty->index;

	bsc_replace_string(conf, &conf->description, argv[0]);
	return CMD_SUCCESS;
}

DEFUN(test_regex, test_regex_cmd,
      "test regex PATTERN STRING",
      "Check if the string is matching the current pattern.")
{
	regex_t reg;
	char *str = NULL;

	memset(&reg, 0, sizeof(reg));
	bsc_parse_reg(_nat, &reg, &str, 1, argv);

	vty_out(vty, "String matches allow pattern: %d%s",
		regexec(&reg, argv[1], 0, NULL, 0) == 0, VTY_NEWLINE);

	talloc_free(str);
	regfree(&reg);
	return CMD_SUCCESS;
}

int bsc_nat_vty_init(struct bsc_nat *nat)
{
	_nat = nat;

	/* show commands */
	install_element_ve(&show_sccp_cmd);
	install_element_ve(&show_bsc_cmd);
	install_element_ve(&show_bsc_cfg_cmd);
	install_element_ve(&show_stats_cmd);
	install_element_ve(&show_stats_lac_cmd);
	install_element_ve(&close_bsc_cmd);
	install_element_ve(&show_msc_cmd);
	install_element_ve(&test_regex_cmd);
	install_element_ve(&show_bsc_mgcp_cmd);
	install_element_ve(&show_acc_lst_cmd);

	/* nat group */
	install_element(CONFIG_NODE, &cfg_nat_cmd);
	install_node(&nat_node, config_write_nat);
	install_default(NAT_NODE);
	install_element(NAT_NODE, &ournode_exit_cmd);
	install_element(NAT_NODE, &ournode_end_cmd);
	install_element(NAT_NODE, &cfg_nat_msc_ip_cmd);
	install_element(NAT_NODE, &cfg_nat_msc_port_cmd);
	install_element(NAT_NODE, &cfg_nat_auth_time_cmd);
	install_element(NAT_NODE, &cfg_nat_ping_time_cmd);
	install_element(NAT_NODE, &cfg_nat_pong_time_cmd);
	install_element(NAT_NODE, &cfg_nat_token_cmd);
	install_element(NAT_NODE, &cfg_nat_bsc_ip_dscp_cmd);
	install_element(NAT_NODE, &cfg_nat_bsc_ip_tos_cmd);
	install_element(NAT_NODE, &cfg_nat_acc_lst_name_cmd);
	install_element(NAT_NODE, &cfg_nat_ussd_lst_name_cmd);
	install_element(NAT_NODE, &cfg_nat_ussd_query_cmd);

	/* access-list */
	install_element(NAT_NODE, &cfg_lst_imsi_allow_cmd);
	install_element(NAT_NODE, &cfg_lst_imsi_deny_cmd);
	install_element(NAT_NODE, &cfg_lst_no_cmd);

	/* BSC subgroups */
	install_element(NAT_NODE, &cfg_bsc_cmd);
	install_node(&bsc_node, config_write_bsc);
	install_default(NAT_BSC_NODE);
	install_element(NAT_BSC_NODE, &ournode_exit_cmd);
	install_element(NAT_BSC_NODE, &ournode_end_cmd);
	install_element(NAT_BSC_NODE, &cfg_bsc_token_cmd);
	install_element(NAT_BSC_NODE, &cfg_bsc_lac_cmd);
	install_element(NAT_BSC_NODE, &cfg_bsc_no_lac_cmd);
	install_element(NAT_BSC_NODE, &cfg_bsc_paging_cmd);
	install_element(NAT_BSC_NODE, &cfg_bsc_desc_cmd);
	install_element(NAT_BSC_NODE, &cfg_bsc_acc_lst_name_cmd);

	mgcp_vty_init();

	return 0;
}


/* called by the telnet interface... we have our own init above */
void bsc_vty_init()
{}
