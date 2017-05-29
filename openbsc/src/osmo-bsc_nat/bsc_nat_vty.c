/* OpenBSC NAT interface to quagga VTY */
/* (C) 2010-2015 by Holger Hans Peter Freyther
 * (C) 2010-2015 by On-Waves
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

#include <openbsc/vty.h>
#include <openbsc/gsm_data.h>
#include <openbsc/bsc_nat.h>
#include <openbsc/bsc_nat_sccp.h>
#include <openbsc/bsc_msg_filter.h>
#include <openbsc/bsc_msc.h>
#include <openbsc/gsm_04_08.h>
#include <openbsc/mgcp.h>
#include <openbsc/vty.h>
#include <openbsc/nat_rewrite_trie.h>

#include <osmocom/core/talloc.h>
#include <osmocom/core/rate_ctr.h>
#include <osmocom/core/utils.h>
#include <osmocom/vty/logging.h>
#include <osmocom/vty/misc.h>
#include <openbsc/osmux.h>

#include <osmocom/sccp/sccp.h>

#include <stdlib.h>
#include <stdbool.h>

static struct bsc_nat *_nat;


#define BSC_STR "Information about BSCs\n"
#define MGCP_STR "MGCP related status\n"
#define PAGING_STR "Paging\n"
#define SMSC_REWRITE "SMSC Rewriting\n"

static struct cmd_node nat_node = {
	NAT_NODE,
	"%s(config-nat)# ",
	1,
};

static struct cmd_node bsc_node = {
	NAT_BSC_NODE,
	"%s(config-nat-bsc)# ",
	1,
};

static struct cmd_node pgroup_node = {
	PGROUP_NODE,
	"%s(config-nat-paging-group)# ",
	1,
};

static int config_write_pgroup(struct vty *vty)
{
	return CMD_SUCCESS;
}

static void dump_lac(struct vty *vty, struct llist_head *head)
{
	struct bsc_lac_entry *lac;
	llist_for_each_entry(lac, head, entry)
		vty_out(vty, "  location_area_code %u%s", lac->lac, VTY_NEWLINE);
}


static void write_pgroup_lst(struct vty *vty, struct bsc_nat_paging_group *pgroup)
{
	vty_out(vty, " paging-group %d%s", pgroup->nr, VTY_NEWLINE);
	dump_lac(vty, &pgroup->lists);
}

static int config_write_nat(struct vty *vty)
{
	struct bsc_msg_acc_lst *lst;
	struct bsc_nat_paging_group *pgroup;

	vty_out(vty, "nat%s", VTY_NEWLINE);
	vty_out(vty, " msc ip %s%s", _nat->main_dest->ip, VTY_NEWLINE);
	vty_out(vty, " msc port %d%s", _nat->main_dest->port, VTY_NEWLINE);
	vty_out(vty, " timeout auth %d%s", _nat->auth_timeout, VTY_NEWLINE);
	vty_out(vty, " timeout ping %d%s", _nat->ping_timeout, VTY_NEWLINE);
	vty_out(vty, " timeout pong %d%s", _nat->pong_timeout, VTY_NEWLINE);
	if (_nat->include_file)
		vty_out(vty, " bscs-config-file %s%s", _nat->include_file, VTY_NEWLINE);
	if (_nat->token)
		vty_out(vty, " token %s%s", _nat->token, VTY_NEWLINE);
	vty_out(vty, " ip-dscp %d%s", _nat->bsc_ip_dscp, VTY_NEWLINE);
	if (_nat->acc_lst_name)
		vty_out(vty, " access-list-name %s%s", _nat->acc_lst_name, VTY_NEWLINE);
	if (_nat->imsi_black_list_fn)
		vty_out(vty, " imsi-black-list-file-name %s%s",
			_nat->imsi_black_list_fn, VTY_NEWLINE);
	if (_nat->ussd_lst_name)
		vty_out(vty, " ussd-list-name %s%s", _nat->ussd_lst_name, VTY_NEWLINE);
	if (_nat->ussd_query)
		vty_out(vty, " ussd-query %s%s", _nat->ussd_query, VTY_NEWLINE);
	if (_nat->ussd_token)
		vty_out(vty, " ussd-token %s%s", _nat->ussd_token, VTY_NEWLINE);
	if (_nat->ussd_local)
		vty_out(vty, " ussd-local-ip %s%s", _nat->ussd_local, VTY_NEWLINE);

	if (_nat->num_rewr_name)
		vty_out(vty, " number-rewrite %s%s", _nat->num_rewr_name, VTY_NEWLINE);
	if (_nat->num_rewr_post_name)
		vty_out(vty, " number-rewrite-post %s%s",
			_nat->num_rewr_post_name, VTY_NEWLINE);

	if (_nat->smsc_rewr_name)
		vty_out(vty, " rewrite-smsc addr %s%s",
			_nat->smsc_rewr_name, VTY_NEWLINE);
	if (_nat->tpdest_match_name)
		vty_out(vty, " rewrite-smsc tp-dest-match %s%s",
			_nat->tpdest_match_name, VTY_NEWLINE);
	if (_nat->sms_clear_tp_srr_name)
		vty_out(vty, " sms-clear-tp-srr %s%s",
			_nat->sms_clear_tp_srr_name, VTY_NEWLINE);
	if (_nat->sms_num_rewr_name)
		vty_out(vty, " sms-number-rewrite %s%s",
			_nat->sms_num_rewr_name, VTY_NEWLINE);
	if (_nat->num_rewr_trie_name)
		vty_out(vty, " prefix-tree %s%s",
			_nat->num_rewr_trie_name, VTY_NEWLINE);

	llist_for_each_entry(lst, &_nat->access_lists, list)
		bsc_msg_acc_lst_write(vty, lst);
	llist_for_each_entry(pgroup, &_nat->paging_groups, entry)
		write_pgroup_lst(vty, pgroup);
	if (_nat->mgcp_ipa)
		vty_out(vty, " use-msc-ipa-for-mgcp%s", VTY_NEWLINE);
	vty_out(vty, " %ssdp-ensure-amr-mode-set%s",
		_nat->sdp_ensure_amr_mode_set ? "" : "no ", VTY_NEWLINE);

	return CMD_SUCCESS;
}

static void config_write_bsc_single(struct vty *vty, struct bsc_config *bsc)
{
	vty_out(vty, " bsc %u%s", bsc->nr, VTY_NEWLINE);
	vty_out(vty, "  token %s%s", bsc->token, VTY_NEWLINE);
	if (bsc->key_present)
		vty_out(vty, "  auth-key %s%s", osmo_hexdump(bsc->key, 16), VTY_NEWLINE);
	dump_lac(vty, &bsc->lac_list);
	if (bsc->description)
		vty_out(vty, "  description %s%s", bsc->description, VTY_NEWLINE);
	if (bsc->acc_lst_name)
		vty_out(vty, "  access-list-name %s%s", bsc->acc_lst_name, VTY_NEWLINE);
	vty_out(vty, "  max-endpoints %d%s", bsc->max_endpoints, VTY_NEWLINE);
	if (bsc->paging_group != -1)
		vty_out(vty, "  paging group %d%s", bsc->paging_group, VTY_NEWLINE);
	vty_out(vty, "  paging forbidden %d%s", bsc->forbid_paging, VTY_NEWLINE);
	switch (bsc->osmux) {
	case OSMUX_USAGE_ON:
		vty_out(vty, "  osmux on%s", VTY_NEWLINE);
		break;
	case OSMUX_USAGE_ONLY:
		vty_out(vty, "  osmux only%s", VTY_NEWLINE);
		break;
	}
}

static int config_write_bsc(struct vty *vty)
{
	struct bsc_config *bsc;

	llist_for_each_entry(bsc, &_nat->bsc_configs, entry)
		config_write_bsc_single(vty, bsc);
	return CMD_SUCCESS;
}

DEFUN(show_bscs, show_bscs_cmd, "show bscs-config",
      SHOW_STR "Show configured BSCs\n"
      "Both from included file and vty\n")
{
	vty_out(vty, "BSCs configuration loaded from %s:%s", _nat->resolved_path,
		VTY_NEWLINE);
	return config_write_bsc(vty);
}

DEFUN(show_sccp, show_sccp_cmd, "show sccp connections",
      SHOW_STR "Display information about SCCP\n"
      "All active connections\n")
{
	struct nat_sccp_connection *con;
	vty_out(vty, "Listing all open SCCP connections%s", VTY_NEWLINE);

	llist_for_each_entry(con, &_nat->sccp_connections, list_entry) {
		vty_out(vty, "For BSC Nr: %d BSC ref: 0x%x; MUX ref: 0x%x; Network has ref: %d ref: 0x%x MSC/BSC mux: 0x%x/0x%x type: %s%s",
			con->bsc->cfg ? con->bsc->cfg->nr : -1,
			sccp_src_ref_to_int(&con->real_ref),
			sccp_src_ref_to_int(&con->patched_ref),
			con->has_remote_ref,
			sccp_src_ref_to_int(&con->remote_ref),
			con->msc_endp, con->bsc_endp,
			bsc_con_type_to_string(con->filter_state.con_type),
			VTY_NEWLINE);
	}

	return CMD_SUCCESS;
}

DEFUN(show_nat_bsc, show_nat_bsc_cmd, "show nat num-bscs-configured",
      SHOW_STR "Display NAT configuration details\n"
      "BSCs-related\n")
{
	vty_out(vty, "%d BSCs configured%s", _nat->num_bsc, VTY_NEWLINE);
	return CMD_SUCCESS;
}

DEFUN(show_bsc, show_bsc_cmd, "show bsc connections",
      SHOW_STR BSC_STR
      "All active connections\n")
{
	struct bsc_connection *con;
	struct sockaddr_in sock;
	socklen_t len = sizeof(sock);

	llist_for_each_entry(con, &_nat->bsc_connections, list_entry) {
		getpeername(con->write_queue.bfd.fd, (struct sockaddr *) &sock, &len);
		vty_out(vty, "BSC nr: %d auth: %d fd: %d peername: %s pending-stats: %u%s",
			con->cfg ? con->cfg->nr : -1,
			con->authenticated, con->write_queue.bfd.fd,
			inet_ntoa(sock.sin_addr), con->pending_dlcx_count,
			VTY_NEWLINE);
	}

	return CMD_SUCCESS;
}

DEFUN(show_bsc_mgcp, show_bsc_mgcp_cmd, "show bsc mgcp NR",
      SHOW_STR BSC_STR MGCP_STR "Identifier of the BSC\n")
{
	struct bsc_connection *con;
	int nr = atoi(argv[0]);
	int i, j, endp;

	llist_for_each_entry(con, &_nat->bsc_connections, list_entry) {
		int max;
		if (!con->cfg)
			continue;
		if (con->cfg->nr != nr)
			continue;

		/* this bsc has no audio endpoints yet */
		if (!con->_endpoint_status)
			continue;

		vty_out(vty, "MGCP Status for %d%s", con->cfg->nr, VTY_NEWLINE);
		max = bsc_mgcp_nr_multiplexes(con->max_endpoints);
		for (i = 0; i < max; ++i) {
			for (j = 1; j < 32; ++j) {
				endp = mgcp_timeslot_to_endpoint(i, j);
				vty_out(vty, " Endpoint 0x%x %s%s", endp,
					con->_endpoint_status[endp] == 0 
						? "free" : "allocated",
				VTY_NEWLINE);
			}
		}
		break;
	}

	return CMD_SUCCESS;
}

DEFUN(show_bsc_cfg, show_bsc_cfg_cmd, "show bsc config",
      SHOW_STR BSC_STR "Configuration of BSCs\n")
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
		osmo_counter_get(nat->stats.sccp.conn),
		osmo_counter_get(nat->stats.sccp.calls), VTY_NEWLINE);
	vty_out(vty, " MSC Connections %lu%s",
		osmo_counter_get(nat->stats.msc.reconn), VTY_NEWLINE);
	vty_out(vty, " MSC Connected: %d%s",
		bsc_nat_msc_is_connected(nat), VTY_NEWLINE);
	vty_out(vty, " BSC Connections %lu total, %lu auth failed.%s",
		osmo_counter_get(nat->stats.bsc.reconn),
		osmo_counter_get(nat->stats.bsc.auth_fail), VTY_NEWLINE);
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
      SHOW_STR "Display network statistics\n"
      "Number of the BSC\n")
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
      SHOW_STR "MSC related information\n"
      "Status of the A-link connection\n")
{
	if (!_nat->msc_con) {
		vty_out(vty, "The MSC is not yet configured.%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	vty_out(vty, "MSC is connected: %d%s",
		bsc_nat_msc_is_connected(_nat), VTY_NEWLINE);
	return CMD_SUCCESS;
}

DEFUN(close_bsc,
      close_bsc_cmd,
      "close bsc connection BSC_NR",
      "Close\n" "A-link\n" "Connection\n" "Identifier of the BSC\n")
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

DEFUN(cfg_nat, cfg_nat_cmd, "nat", "Configure the NAT")
{
	vty->index = _nat;
	vty->node = NAT_NODE;

	return CMD_SUCCESS;
}

DEFUN(cfg_nat_msc_ip,
      cfg_nat_msc_ip_cmd,
      "msc ip A.B.C.D",
      "MSC related configuration\n"
      "Configure the IP address\n" IP_STR)
{
	bsc_nat_set_msc_ip(_nat, argv[0]);
	return CMD_SUCCESS;
}

DEFUN(cfg_nat_msc_port,
      cfg_nat_msc_port_cmd,
      "msc port <1-65500>",
      "MSC related configuration\n"
      "Configure the port\n"
      "Port number\n")
{
	_nat->main_dest->port = atoi(argv[0]);
	return CMD_SUCCESS;
}

DEFUN(cfg_nat_auth_time,
      cfg_nat_auth_time_cmd,
      "timeout auth <1-256>",
      "Timeout configuration\n"
      "Authentication timeout\n"
      "Timeout in seconds\n")
{
	_nat->auth_timeout = atoi(argv[0]);
	return CMD_SUCCESS;
}

DEFUN(cfg_nat_ping_time,
      cfg_nat_ping_time_cmd,
      "timeout ping NR",
      "Timeout configuration\n"
      "Time between two pings\n"
      "Timeout in seconds\n")
{
	_nat->ping_timeout = atoi(argv[0]);
	return CMD_SUCCESS;
}

DEFUN(cfg_nat_pong_time,
      cfg_nat_pong_time_cmd,
      "timeout pong NR",
      "Timeout configuration\n"
      "Waiting for pong timeout\n"
      "Timeout in seconds\n")
{
	_nat->pong_timeout = atoi(argv[0]);
	return CMD_SUCCESS;
}

DEFUN(cfg_nat_token, cfg_nat_token_cmd,
      "token TOKEN",
      "Authentication token configuration\n"
      "Token of the BSC, currently transferred in cleartext\n")
{
	osmo_talloc_replace_string(_nat, &_nat->token, argv[0]);
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
	osmo_talloc_replace_string(_nat, &_nat->acc_lst_name, argv[0]);
	return CMD_SUCCESS;
}

DEFUN(cfg_nat_include,
      cfg_nat_include_cmd,
      "bscs-config-file NAME",
      "Set the filename of the BSC configuration to include.\n"
      "The filename to be included.")
{
	char *path;
	int rc;
	struct bsc_config *cf1, *cf2;
	struct bsc_connection *con1, *con2;

	if ('/' == argv[0][0])
		osmo_talloc_replace_string(_nat, &_nat->resolved_path, argv[0]);
	else {
		path = talloc_asprintf(_nat, "%s/%s", _nat->include_base,
				       argv[0]);
		osmo_talloc_replace_string(_nat, &_nat->resolved_path, path);
		talloc_free(path);
	}

	llist_for_each_entry_safe(cf1, cf2, &_nat->bsc_configs, entry) {
		cf1->remove = true;
		cf1->token_updated = false;
	}

	rc = vty_read_config_file(_nat->resolved_path, NULL);
	if (rc < 0) {
		vty_out(vty, "Failed to parse the config file %s: %s%s",
			_nat->resolved_path, strerror(-rc), VTY_NEWLINE);
		return CMD_WARNING;
	}

	osmo_talloc_replace_string(_nat, &_nat->include_file, argv[0]);

	llist_for_each_entry_safe(con1, con2, &_nat->bsc_connections,
				  list_entry) {
		if (con1->cfg)
			if (con1->cfg->token_updated || con1->cfg->remove)
				bsc_close_connection(con1);
	}

	llist_for_each_entry_safe(cf1, cf2, &_nat->bsc_configs, entry) {
		if (cf1->remove)
			bsc_config_free(cf1);
	}

	return CMD_SUCCESS;
}

DEFUN(cfg_nat_no_acc_lst_name,
      cfg_nat_no_acc_lst_name_cmd,
      "no access-list-name",
      NO_STR "Remove the access list from the NAT.\n")
{
	if (_nat->acc_lst_name) {
		talloc_free(_nat->acc_lst_name);
		_nat->acc_lst_name = NULL;
	}

	return CMD_SUCCESS;
}

DEFUN(cfg_nat_imsi_black_list_fn,
      cfg_nat_imsi_black_list_fn_cmd,
      "imsi-black-list-file-name NAME",
      "IMSI black listing\n" "Filename IMSI and reject-cause\n")
{

	osmo_talloc_replace_string(_nat, &_nat->imsi_black_list_fn, argv[0]);
	if (_nat->imsi_black_list_fn) {
		int rc;
		struct osmo_config_list *rewr = NULL;
		rewr = osmo_config_list_parse(_nat, _nat->imsi_black_list_fn);
		rc = bsc_filter_barr_adapt(_nat, &_nat->imsi_black_list, rewr);
		if (rc != 0) {
			vty_out(vty, "%%There was an error parsing the list."
				" Please see the error log.%s", VTY_NEWLINE);
			return CMD_WARNING;
		}

		return CMD_SUCCESS;
	}

	bsc_filter_barr_adapt(_nat, &_nat->imsi_black_list, NULL);
	return CMD_SUCCESS;
}

DEFUN(cfg_nat_no_imsi_black_list_fn,
      cfg_nat_no_imsi_black_list_fn_cmd,
      "no imsi-black-list-file-name",
      NO_STR "Remove the imsi-black-list\n")
{
	talloc_free(_nat->imsi_black_list_fn);
	_nat->imsi_black_list_fn = NULL;
	bsc_filter_barr_adapt(_nat, &_nat->imsi_black_list, NULL);
	return CMD_SUCCESS;
}

static int replace_rules(struct bsc_nat *nat, char **name,
			 struct llist_head *head, const char *file)
{
	struct osmo_config_list *rewr = NULL;

	osmo_talloc_replace_string(nat, name, file);
	if (*name) {
		rewr = osmo_config_list_parse(nat, *name);
		bsc_nat_num_rewr_entry_adapt(nat, head, rewr);
		talloc_free(rewr);
		return CMD_SUCCESS;
	} else {
		bsc_nat_num_rewr_entry_adapt(nat, head, NULL);
		return CMD_SUCCESS;
	}
}

DEFUN(cfg_nat_number_rewrite,
      cfg_nat_number_rewrite_cmd,
      "number-rewrite FILENAME",
      "Set the file with rewriting rules.\n" "Filename")
{
	return replace_rules(_nat, &_nat->num_rewr_name,
			     &_nat->num_rewr, argv[0]);
}

DEFUN(cfg_nat_no_number_rewrite,
      cfg_nat_no_number_rewrite_cmd,
      "no number-rewrite",
      NO_STR "Set the file with rewriting rules.\n")
{
	talloc_free(_nat->num_rewr_name);
	_nat->num_rewr_name = NULL;

	bsc_nat_num_rewr_entry_adapt(NULL, &_nat->num_rewr, NULL);
	return CMD_SUCCESS;
}

DEFUN(cfg_nat_number_rewrite_post,
      cfg_nat_number_rewrite_post_cmd,
      "number-rewrite-post FILENAME",
      "Set the file with post-routing rewriting rules.\n" "Filename")
{
	return replace_rules(_nat, &_nat->num_rewr_post_name,
			     &_nat->num_rewr_post, argv[0]);
}

DEFUN(cfg_nat_no_number_rewrite_post,
      cfg_nat_no_number_rewrite_post_cmd,
      "no number-rewrite-post",
      NO_STR "Set the file with post-routing rewriting rules.\n")
{
	talloc_free(_nat->num_rewr_post_name);
	_nat->num_rewr_post_name = NULL;

	bsc_nat_num_rewr_entry_adapt(NULL, &_nat->num_rewr_post, NULL);
	return CMD_SUCCESS;
}

DEFUN(cfg_nat_smsc_addr,
      cfg_nat_smsc_addr_cmd,
      "rewrite-smsc addr FILENAME",
      SMSC_REWRITE
      "The SMSC Address to match and replace in RP-DATA\n"
      "File with rules for the SMSC Address replacing\n")
{
	return replace_rules(_nat, &_nat->smsc_rewr_name,
			     &_nat->smsc_rewr, argv[0]);
}

DEFUN(cfg_nat_smsc_tpdest,
      cfg_nat_smsc_tpdest_cmd,
      "rewrite-smsc tp-dest-match FILENAME",
      SMSC_REWRITE
      "Match TP-Destination of a SMS.\n"
      "File with rules for matching MSISDN and TP-DEST\n")
{
	return replace_rules(_nat, &_nat->tpdest_match_name,
			     &_nat->tpdest_match, argv[0]);
}

DEFUN(cfg_nat_sms_clear_tpsrr,
      cfg_nat_sms_clear_tpsrr_cmd,
      "sms-clear-tp-srr FILENAME",
      "SMS TPDU Sender Report Request clearing\n"
      "Files with rules for matching MSISDN\n")
{
	return replace_rules(_nat, &_nat->sms_clear_tp_srr_name,
			     &_nat->sms_clear_tp_srr, argv[0]);
}

DEFUN(cfg_nat_no_sms_clear_tpsrr,
      cfg_nat_no_sms_clear_tpsrr_cmd,
      "no sms-clear-tp-srr",
      NO_STR
      "SMS TPDU Sender Report Request clearing\n")
{
	talloc_free(_nat->sms_clear_tp_srr_name);
	_nat->sms_clear_tp_srr_name = NULL;

	bsc_nat_num_rewr_entry_adapt(NULL, &_nat->sms_clear_tp_srr, NULL);
	return CMD_SUCCESS;
}

DEFUN(cfg_nat_sms_number_rewrite,
      cfg_nat_sms_number_rewrite_cmd,
      "sms-number-rewrite FILENAME",
      "SMS TP-DA Number rewriting\n"
      "Files with rules for matching MSISDN\n")
{
	return replace_rules(_nat, &_nat->sms_num_rewr_name,
			     &_nat->sms_num_rewr, argv[0]);
}

DEFUN(cfg_nat_no_sms_number_rewrite,
      cfg_nat_no_sms_number_rewrite_cmd,
      "no sms-number-rewrite",
      NO_STR "Disable SMS TP-DA rewriting\n")
{
	talloc_free(_nat->sms_num_rewr_name);
	_nat->sms_num_rewr_name = NULL;

	bsc_nat_num_rewr_entry_adapt(NULL, &_nat->sms_num_rewr, NULL);
	return CMD_SUCCESS;
}

DEFUN(cfg_nat_prefix_trie,
      cfg_nat_prefix_trie_cmd,
      "prefix-tree FILENAME",
      "Prefix tree for number rewriting\n" "File to load\n")
{
	/* give up the old data */
	talloc_free(_nat->num_rewr_trie);
	_nat->num_rewr_trie = NULL;

	/* replace the file name */
	osmo_talloc_replace_string(_nat, &_nat->num_rewr_trie_name, argv[0]);
	if (!_nat->num_rewr_trie_name) {
		vty_out(vty, "%% prefix-tree no filename is present.%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	_nat->num_rewr_trie = nat_rewrite_parse(_nat, _nat->num_rewr_trie_name);
	if (!_nat->num_rewr_trie) {
		vty_out(vty, "%% prefix-tree parsing has failed.%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	vty_out(vty, "%% prefix-tree loaded %zu rules.%s",
		_nat->num_rewr_trie->prefixes, VTY_NEWLINE);
	return CMD_SUCCESS;
}

DEFUN(cfg_nat_no_prefix_trie, cfg_nat_no_prefix_trie_cmd,
      "no prefix-tree",
      NO_STR "Prefix tree for number rewriting\n")
{
	talloc_free(_nat->num_rewr_trie);
	_nat->num_rewr_trie = NULL;
	talloc_free(_nat->num_rewr_trie_name);
	_nat->num_rewr_trie_name = NULL;

	return CMD_SUCCESS;
}

DEFUN(show_prefix_tree, show_prefix_tree_cmd,
      "show prefix-tree",
      SHOW_STR "Prefix tree for number rewriting\n")
{
	if (!_nat->num_rewr_trie) {
		vty_out(vty, "%% there is now prefix tree loaded.%s",
			VTY_NEWLINE);
		return CMD_WARNING;
	}

	nat_rewrite_dump_vty(vty, _nat->num_rewr_trie);
	return CMD_SUCCESS;
}

DEFUN(cfg_nat_ussd_lst_name,
      cfg_nat_ussd_lst_name_cmd,
      "ussd-list-name NAME",
      "Set the name of the access list to check for IMSIs for USSD message\n"
      "The name of the access list for HLR USSD handling")
{
	osmo_talloc_replace_string(_nat, &_nat->ussd_lst_name, argv[0]);
	return CMD_SUCCESS;
}

DEFUN(cfg_nat_ussd_query,
      cfg_nat_ussd_query_cmd,
      "ussd-query REGEXP",
      "Set the USSD query to match with the ussd-list-name\n"
      "The query to match")
{
	if (gsm_parse_reg(_nat, &_nat->ussd_query_re, &_nat->ussd_query, argc, argv) != 0)
		return CMD_WARNING;
	return CMD_SUCCESS;
}

DEFUN(cfg_nat_ussd_token,
      cfg_nat_ussd_token_cmd,
      "ussd-token TOKEN",
      "Set the token used to identify the USSD module\n" "Secret key\n")
{
	osmo_talloc_replace_string(_nat, &_nat->ussd_token, argv[0]);
	return CMD_SUCCESS;
}

DEFUN(cfg_nat_ussd_local,
      cfg_nat_ussd_local_cmd,
      "ussd-local-ip A.B.C.D",
      "Set the IP to listen for the USSD Provider\n" "IP Address\n")
{
	osmo_talloc_replace_string(_nat, &_nat->ussd_local, argv[0]);
	return CMD_SUCCESS;
}

DEFUN(cfg_nat_use_ipa_for_mgcp,
      cfg_nat_use_ipa_for_mgcp_cmd,
      "use-msc-ipa-for-mgcp",
      "This needs to be set at start. Handle MGCP messages through "
      "the IPA protocol and not through the UDP socket.\n")
{
	if (_nat->mgcp_cfg->data)
		vty_out(vty,
			"%%the setting will not be applied right now.%s",
			VTY_NEWLINE);
	_nat->mgcp_ipa = 1;
	return CMD_SUCCESS;
}

DEFUN(cfg_nat_sdp_amr_mode_set,
      cfg_nat_sdp_amr_mode_set_cmd,
      "sdp-ensure-amr-mode-set",
      "Ensure that SDP records include a mode-set\n")
{
	_nat->sdp_ensure_amr_mode_set = 1;
	return CMD_SUCCESS;
}

DEFUN(cfg_nat_no_sdp_amr_mode_set,
      cfg_nat_no_sdp_amr_mode_set_cmd,
      "no sdp-ensure-amr-mode-set",
      NO_STR "Ensure that SDP records include a mode-set\n")
{
	_nat->sdp_ensure_amr_mode_set = 0;
	return CMD_SUCCESS;
}

/* per BSC configuration */
DEFUN(cfg_bsc, cfg_bsc_cmd, "bsc BSC_NR",
      "BSC configuration\n" "Identifier of the BSC\n")
{
	int bsc_nr = atoi(argv[0]);
	struct bsc_config *bsc = bsc_config_num(_nat, bsc_nr);

	/* allocate a new one */
	if (!bsc)
		bsc = bsc_config_alloc(_nat, "unknown", bsc_nr);

	if (!bsc)
		return CMD_WARNING;

	bsc->remove = false;
	vty->index = bsc;
	vty->node = NAT_BSC_NODE;

	return CMD_SUCCESS;
}

DEFUN(cfg_bsc_token, cfg_bsc_token_cmd, "token TOKEN",
      "Authentication token configuration\n"
      "Token of the BSC, currently transferred in cleartext\n")
{
	struct bsc_config *conf = vty->index;

	if (strncmp(conf->token, argv[0], 128) != 0)
		conf->token_updated = true;

	osmo_talloc_replace_string(conf, &conf->token, argv[0]);
	return CMD_SUCCESS;
}

DEFUN(cfg_bsc_auth_key, cfg_bsc_auth_key_cmd,
      "auth-key KEY",
      "Authentication (secret) key configuration\n"
      "Non null security key\n")
{
	struct bsc_config *conf = vty->index;

	memset(conf->key, 0, sizeof(conf->key));
	osmo_hexparse(argv[0], conf->key, sizeof(conf->key));
	conf->key_present = 1;
	return CMD_SUCCESS;
}

DEFUN(cfg_bsc_no_auth_key, cfg_bsc_no_auth_key_cmd,
      "no auth-key",
      NO_STR "Authentication (secret) key configuration\n")
{
	struct bsc_config *conf = vty->index;

	memset(conf->key, 0, sizeof(conf->key));
	conf->key_present = 0;
	return CMD_SUCCESS;
}

DEFUN(cfg_bsc_lac, cfg_bsc_lac_cmd, "location_area_code <0-65535>",
      "Add the Location Area Code (LAC) of this BSC\n" "LAC\n")
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
			if (tmp->nr != conf->nr) {
				vty_out(vty, "%% LAC %d is already used.%s", lac,
					VTY_NEWLINE);
				return CMD_ERR_INCOMPLETE;
			}
		}
	}

	bsc_config_add_lac(conf, lac);

	return CMD_SUCCESS;
}

DEFUN(cfg_bsc_no_lac, cfg_bsc_no_lac_cmd,
      "no location_area_code <0-65535>",
      NO_STR "Remove the Location Area Code (LAC) of this BSC\n" "LAC\n")
{
	int lac = atoi(argv[0]);
	struct bsc_config *conf = vty->index;

	bsc_config_del_lac(conf, lac);
	return CMD_SUCCESS;
}

DEFUN(show_bar_lst,
      show_bar_lst_cmd,
      "show imsi-black-list",
      SHOW_STR "IMSIs barred from the network\n")
{
	struct rb_node *node;

	vty_out(vty, "IMSIs barred from the network:%s", VTY_NEWLINE);

	for (node = rb_first(&_nat->imsi_black_list); node; node = rb_next(node)) {
		struct bsc_filter_barr_entry *entry;
		entry = rb_entry(node, struct bsc_filter_barr_entry, node);

		vty_out(vty, " IMSI(%s) CM-Reject-Cause(%d) LU-Reject-Cause(%d)%s",
			entry->imsi, entry->cm_reject_cause, entry->lu_reject_cause,
			VTY_NEWLINE);
	}

	return CMD_SUCCESS;
}


DEFUN(cfg_bsc_acc_lst_name,
      cfg_bsc_acc_lst_name_cmd,
      "access-list-name NAME",
      "Set the name of the access list to use.\n"
      "The name of the to be used access list.")
{
	struct bsc_config *conf = vty->index;

	osmo_talloc_replace_string(conf, &conf->acc_lst_name, argv[0]);
	return CMD_SUCCESS;
}

DEFUN(cfg_bsc_no_acc_lst_name,
      cfg_bsc_no_acc_lst_name_cmd,
      "no access-list-name",
      NO_STR "Do not use an access-list for the BSC.\n")
{
	struct bsc_config *conf = vty->index;

	if (conf->acc_lst_name) {
		talloc_free(conf->acc_lst_name);
		conf->acc_lst_name = NULL;
	}

	return CMD_SUCCESS;
}

DEFUN(cfg_bsc_max_endps, cfg_bsc_max_endps_cmd,
      "max-endpoints <1-1024>",
      "Highest endpoint to use (exclusively)\n" "Number of ports\n")
{
	struct bsc_config *conf = vty->index;

	conf->max_endpoints = atoi(argv[0]);
	return CMD_SUCCESS;
}

DEFUN(cfg_bsc_paging,
      cfg_bsc_paging_cmd,
      "paging forbidden (0|1)",
      PAGING_STR "Forbid sending PAGING REQUESTS to the BSC.\n"
      "Do not forbid\n" "Forbid\n")
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
      "Provide a description for the given BSC.\n" "Description\n")
{
	struct bsc_config *conf = vty->index;

	osmo_talloc_replace_string(conf, &conf->description, argv[0]);
	return CMD_SUCCESS;
}

DEFUN(cfg_bsc_paging_grp,
      cfg_bsc_paging_grp_cmd,
      "paging group <0-1000>",
      PAGING_STR "Use a paging group\n" "Paging Group to use\n")
{
	struct bsc_config *conf = vty->index;
	conf->paging_group = atoi(argv[0]);
	return CMD_SUCCESS;
}

ALIAS_DEPRECATED(cfg_bsc_paging_grp, cfg_bsc_old_grp_cmd,
		 "paging-group <0-1000>",
		 "Use a paging group\n" "Paging Group to use\n")

DEFUN(cfg_bsc_no_paging_grp,
      cfg_bsc_no_paging_grp_cmd,
      "no paging group",
      NO_STR PAGING_STR "Disable the usage of a paging group.\n")
{
	struct bsc_config *conf = vty->index;
	conf->paging_group = PAGIN_GROUP_UNASSIGNED;
	return CMD_SUCCESS;
}

DEFUN(test_regex, test_regex_cmd,
      "test regex PATTERN STRING",
      "Test utilities\n"
      "Regexp testing\n" "The regexp pattern\n"
      "The string to match\n")
{
	regex_t reg;
	char *str = NULL;

	memset(&reg, 0, sizeof(reg));
	if (gsm_parse_reg(_nat, &reg, &str, 1, argv) != 0)
		return CMD_WARNING;

	vty_out(vty, "String matches allow pattern: %d%s",
		regexec(&reg, argv[1], 0, NULL, 0) == 0, VTY_NEWLINE);

	talloc_free(str);
	regfree(&reg);
	return CMD_SUCCESS;
}

DEFUN(set_last_endp, set_last_endp_cmd,
      "set bsc last-used-endpoint <0-9999999999> <0-1024>",
      "Set a value\n" "Operate on a BSC\n"
      "Last used endpoint for an assignment\n" "BSC configuration number\n"
      "Endpoint number used\n")
{
	struct bsc_connection *con;
	int nr = atoi(argv[0]);
	int endp = atoi(argv[1]);


	llist_for_each_entry(con, &_nat->bsc_connections, list_entry) {
		if (!con->cfg)
			continue;
		if (con->cfg->nr != nr)
			continue;

		con->last_endpoint = endp;
		vty_out(vty, "Updated the last endpoint for %d to %d.%s",
			con->cfg->nr, con->last_endpoint, VTY_NEWLINE);
	}

	return CMD_SUCCESS;
}

DEFUN(block_new_conn, block_new_conn_cmd,
      "nat-block (block|unblock)",
      "Block the NAT for new connections\n"
      "Block\n" "Unblock\n")
{
	_nat->blocked = argv[0][0] == 'b';
	vty_out(vty, "%%Going to %s the NAT.%s",
		_nat->blocked ? "block" : "unblock", VTY_NEWLINE);
	return CMD_SUCCESS;
}

/* paging group */
DEFUN(cfg_nat_pgroup, cfg_nat_pgroup_cmd,
      "paging-group <0-1000>",
      "Create a Paging Group\n" "Number of the Group\n")
{
	int group = atoi(argv[0]);
	struct bsc_nat_paging_group *pgroup;
	pgroup = bsc_nat_paging_group_num(_nat, group);
	if (!pgroup)
		pgroup = bsc_nat_paging_group_create(_nat, group);
	if (!pgroup) {
		vty_out(vty, "Failed to create the group.%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	vty->index = pgroup;
	vty->node = PGROUP_NODE;
	return CMD_SUCCESS;
}

DEFUN(cfg_nat_no_pgroup, cfg_nat_no_pgroup_cmd,
      "no paging-group <0-1000>",
      NO_STR "Delete paging-group\n" "Paging-group number\n")
{
	int group = atoi(argv[0]);
	struct bsc_nat_paging_group *pgroup;
	pgroup = bsc_nat_paging_group_num(_nat, group);
	if (!pgroup) {
		vty_out(vty, "No such paging group %d.%s", group, VTY_NEWLINE);
		return CMD_WARNING;
	}

	bsc_nat_paging_group_delete(pgroup);
	return CMD_SUCCESS;
}

DEFUN(cfg_pgroup_lac, cfg_pgroup_lac_cmd,
      "location_area_code <0-65535>",
       "Add the Location Area Code (LAC)\n" "LAC\n")
{
	struct bsc_nat_paging_group *pgroup = vty->index;

	int lac = atoi(argv[0]);
	if (lac == GSM_LAC_RESERVED_DETACHED || lac == GSM_LAC_RESERVED_ALL_BTS) {
		vty_out(vty, "%% LAC %d is reserved by GSM 04.08%s",
			lac, VTY_NEWLINE);
		return CMD_WARNING;
	}

	bsc_nat_paging_group_add_lac(pgroup, lac);
	return CMD_SUCCESS;
}

DEFUN(cfg_pgroup_no_lac, cfg_pgroup_no_lac_cmd,
      "no location_area_code <0-65535>",
      NO_STR "Remove the Location Area Code (LAC)\n" "LAC\n")
{
	int lac = atoi(argv[0]);
	struct bsc_nat_paging_group *pgroup = vty->index;

	bsc_nat_paging_group_del_lac(pgroup, lac);
	return CMD_SUCCESS;
}

DEFUN(show_ussd_connection,
      show_ussd_connection_cmd,
      "show ussd-connection",
      SHOW_STR "USSD connection related information\n")
{
	vty_out(vty, "The USSD side channel provider is %sconnected and %sauthorized.%s",
		_nat->ussd_con ? "" : "not ",
		_nat->ussd_con && _nat->ussd_con->authorized? "" : "not ",
		VTY_NEWLINE);
	return CMD_SUCCESS;
}

#define OSMUX_STR "RTP multiplexing\n"
DEFUN(cfg_bsc_osmux,
      cfg_bsc_osmux_cmd,
      "osmux (on|off|only)",
       OSMUX_STR "Enable OSMUX\n" "Disable OSMUX\n" "Only OSMUX\n")
{
	struct bsc_config *conf = vty->index;
	int old = conf->osmux;

	if (strcmp(argv[0], "on") == 0)
		conf->osmux = OSMUX_USAGE_ON;
	else if (strcmp(argv[0], "off") == 0)
		conf->osmux = OSMUX_USAGE_OFF;
	else if (strcmp(argv[0], "only") == 0)
		conf->osmux = OSMUX_USAGE_ONLY;

	if (old == 0 && conf->osmux > 0 && !conf->nat->mgcp_cfg->osmux_init) {
		LOGP(DMGCP, LOGL_NOTICE, "Setting up OSMUX socket\n");
		if (osmux_init(OSMUX_ROLE_BSC_NAT, conf->nat->mgcp_cfg) < 0) {
			LOGP(DMGCP, LOGL_ERROR, "Cannot init OSMUX\n");
			vty_out(vty, "%% failed to create Osmux socket%s",
				VTY_NEWLINE);
			return CMD_WARNING;
		}
	} else if (old > 0 && conf->osmux == 0) {
		LOGP(DMGCP, LOGL_NOTICE, "Disabling OSMUX socket\n");
		/* Don't stop the socket, we may already have ongoing voice
		 * flows already using Osmux. This just switch indicates that
		 * new upcoming flows should use RTP.
		 */
	}

	return CMD_SUCCESS;
}

int bsc_nat_vty_init(struct bsc_nat *nat)
{
	_nat = nat;

	/* show commands */
	install_element_ve(&show_sccp_cmd);
	install_element_ve(&show_bsc_cmd);
	install_element_ve(&show_nat_bsc_cmd);
	install_element_ve(&show_bsc_cfg_cmd);
	install_element_ve(&show_stats_cmd);
	install_element_ve(&show_stats_lac_cmd);
	install_element_ve(&close_bsc_cmd);
	install_element_ve(&show_msc_cmd);
	install_element_ve(&test_regex_cmd);
	install_element_ve(&show_bsc_mgcp_cmd);
	install_element_ve(&show_bscs_cmd);
	install_element_ve(&show_bar_lst_cmd);
	install_element_ve(&show_prefix_tree_cmd);
	install_element_ve(&show_ussd_connection_cmd);

	install_element(ENABLE_NODE, &set_last_endp_cmd);
	install_element(ENABLE_NODE, &block_new_conn_cmd);

	/* nat group */
	install_element(CONFIG_NODE, &cfg_nat_cmd);
	install_node(&nat_node, config_write_nat);
	vty_install_default(NAT_NODE);
	install_element(NAT_NODE, &cfg_nat_msc_ip_cmd);
	install_element(NAT_NODE, &cfg_nat_msc_port_cmd);
	install_element(NAT_NODE, &cfg_nat_auth_time_cmd);
	install_element(NAT_NODE, &cfg_nat_ping_time_cmd);
	install_element(NAT_NODE, &cfg_nat_pong_time_cmd);
	install_element(NAT_NODE, &cfg_nat_token_cmd);
	install_element(NAT_NODE, &cfg_nat_bsc_ip_dscp_cmd);
	install_element(NAT_NODE, &cfg_nat_bsc_ip_tos_cmd);
	install_element(NAT_NODE, &cfg_nat_acc_lst_name_cmd);
	install_element(NAT_NODE, &cfg_nat_no_acc_lst_name_cmd);
	install_element(NAT_NODE, &cfg_nat_include_cmd);
	install_element(NAT_NODE, &cfg_nat_imsi_black_list_fn_cmd);
	install_element(NAT_NODE, &cfg_nat_no_imsi_black_list_fn_cmd);
	install_element(NAT_NODE, &cfg_nat_ussd_lst_name_cmd);
	install_element(NAT_NODE, &cfg_nat_ussd_query_cmd);
	install_element(NAT_NODE, &cfg_nat_ussd_token_cmd);
	install_element(NAT_NODE, &cfg_nat_ussd_local_cmd);
	install_element(NAT_NODE, &cfg_nat_use_ipa_for_mgcp_cmd);

	bsc_msg_lst_vty_init(nat, &nat->access_lists, NAT_NODE);

	/* number rewriting */
	install_element(NAT_NODE, &cfg_nat_number_rewrite_cmd);
	install_element(NAT_NODE, &cfg_nat_no_number_rewrite_cmd);
	install_element(NAT_NODE, &cfg_nat_number_rewrite_post_cmd);
	install_element(NAT_NODE, &cfg_nat_no_number_rewrite_post_cmd);
	install_element(NAT_NODE, &cfg_nat_smsc_addr_cmd);
	install_element(NAT_NODE, &cfg_nat_smsc_tpdest_cmd);
	install_element(NAT_NODE, &cfg_nat_sms_clear_tpsrr_cmd);
	install_element(NAT_NODE, &cfg_nat_no_sms_clear_tpsrr_cmd);
	install_element(NAT_NODE, &cfg_nat_sms_number_rewrite_cmd);
	install_element(NAT_NODE, &cfg_nat_no_sms_number_rewrite_cmd);
	install_element(NAT_NODE, &cfg_nat_prefix_trie_cmd);
	install_element(NAT_NODE, &cfg_nat_no_prefix_trie_cmd);

	install_element(NAT_NODE, &cfg_nat_sdp_amr_mode_set_cmd);
	install_element(NAT_NODE, &cfg_nat_no_sdp_amr_mode_set_cmd);

	install_element(NAT_NODE, &cfg_nat_pgroup_cmd);
	install_element(NAT_NODE, &cfg_nat_no_pgroup_cmd);
	install_node(&pgroup_node, config_write_pgroup);
	vty_install_default(PGROUP_NODE);
	install_element(PGROUP_NODE, &cfg_pgroup_lac_cmd);
	install_element(PGROUP_NODE, &cfg_pgroup_no_lac_cmd);

	/* BSC subgroups */
	install_element(NAT_NODE, &cfg_bsc_cmd);
	install_node(&bsc_node, NULL);
	vty_install_default(NAT_BSC_NODE);
	install_element(NAT_BSC_NODE, &cfg_bsc_token_cmd);
	install_element(NAT_BSC_NODE, &cfg_bsc_auth_key_cmd);
	install_element(NAT_BSC_NODE, &cfg_bsc_no_auth_key_cmd);
	install_element(NAT_BSC_NODE, &cfg_bsc_lac_cmd);
	install_element(NAT_BSC_NODE, &cfg_bsc_no_lac_cmd);
	install_element(NAT_BSC_NODE, &cfg_bsc_paging_cmd);
	install_element(NAT_BSC_NODE, &cfg_bsc_desc_cmd);
	install_element(NAT_BSC_NODE, &cfg_bsc_acc_lst_name_cmd);
	install_element(NAT_BSC_NODE, &cfg_bsc_no_acc_lst_name_cmd);
	install_element(NAT_BSC_NODE, &cfg_bsc_max_endps_cmd);
	install_element(NAT_BSC_NODE, &cfg_bsc_old_grp_cmd);
	install_element(NAT_BSC_NODE, &cfg_bsc_paging_grp_cmd);
	install_element(NAT_BSC_NODE, &cfg_bsc_no_paging_grp_cmd);
	install_element(NAT_BSC_NODE, &cfg_bsc_osmux_cmd);

	mgcp_vty_init();

	return 0;
}


/* called by the telnet interface... we have our own init above */
int bsc_vty_init(struct gsm_network *network)
{
	logging_vty_add_cmds(NULL);
	return 0;
}
