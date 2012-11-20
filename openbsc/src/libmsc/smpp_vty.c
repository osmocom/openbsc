/* SMPP vty interface */

/* (C) 2012 by Harald Welte <laforge@gnumonks.org>
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

#include <string.h>
#include <netdb.h>
#include <sys/socket.h>

#include <osmocom/vty/command.h>
#include <osmocom/vty/buffer.h>
#include <osmocom/vty/vty.h>

#include <osmocom/core/linuxlist.h>
#include <osmocom/core/utils.h>
#include <osmocom/core/talloc.h>

#include <openbsc/vty.h>

#include "smpp_smsc.h"

struct smsc *smsc_from_vty(struct vty *v);

static struct cmd_node smpp_node = {
	SMPP_NODE,
	"%s(config-smpp)# ",
	1,
};

static struct cmd_node esme_node = {
	SMPP_ESME_NODE,
	"%s(config-smpp-esme)# ",
	1,
};

DEFUN(cfg_smpp, cfg_smpp_cmd,
	"smpp", "Configure SMPP SMS Interface")
{
	vty->node = SMPP_NODE;

	return CMD_SUCCESS;
}

DEFUN(cfg_smpp_port, cfg_smpp_port_cmd,
	"local-tcp-port <1-65535>",
	"Set the local TCP port on which we listen for SMPP\n"
	"TCP port number")
{
	struct smsc *smsc = smsc_from_vty(vty);
	uint16_t port = atoi(argv[0]);
	int rc;

	rc = smpp_smsc_init(smsc, port);
	if (rc < 0) {
		vty_out(vty, "%% Cannot bind to new port %u nor to "
			"old port %u%s", port, smsc->listen_port, VTY_NEWLINE);
		return CMD_WARNING;
	}

	if (port != smsc->listen_port) {
		vty_out(vty, "%% Cannot bind to new port %u, staying on old"
			"port %u%s", port, smsc->listen_port, VTY_NEWLINE);
		return CMD_WARNING;
	}

	return CMD_SUCCESS;
}

DEFUN(cfg_smpp_sys_id, cfg_smpp_sys_id_cmd,
	"system-id ID", "Set the System ID of this SMSC")
{
	struct smsc *smsc = smsc_from_vty(vty);

	if (strlen(argv[0])+1 > sizeof(smsc->system_id))
		return CMD_WARNING;

	strcpy(smsc->system_id, argv[0]);

	return CMD_SUCCESS;
}

DEFUN(cfg_smpp_policy, cfg_smpp_policy_cmd,
	"policy (accept-all|closed)",
	"Set the authentication policy of this SMSC\n"
	"Accept all SMPP connections independeint of system ID / passwd\n"
	"Accept only SMPP connections from ESMEs explicitly configured")
{
	struct smsc *smsc = smsc_from_vty(vty);

	if (!strcmp(argv[0], "accept-all"))
		smsc->accept_all = 1;
	else
		smsc->accept_all = 0;

	return CMD_SUCCESS;
}


static int config_write_smpp(struct vty *vty)
{
	struct smsc *smsc = smsc_from_vty(vty);

	vty_out(vty, "smpp%s", VTY_NEWLINE);
	vty_out(vty, " local-tcp-port %u%s", smsc->listen_port, VTY_NEWLINE);
	vty_out(vty, " system-id %s%s", smsc->system_id, VTY_NEWLINE);
	vty_out(vty, " policy %s%s",
		smsc->accept_all ? "accept-all" : "closed", VTY_NEWLINE);

	return CMD_SUCCESS;
}

DEFUN(cfg_esme, cfg_esme_cmd,
	"esme NAME", "Configure a particular ESME")
{
	struct smsc *smsc = smsc_from_vty(vty);
	struct osmo_smpp_acl *acl;
	const char *id = argv[0];

	if (strlen(id) > 16) {
		vty_out(vty, "%% System ID cannot be more than 16 "
			"characters long%s", VTY_NEWLINE);
		return CMD_WARNING;
	}
	acl = smpp_acl_by_system_id(smsc, id);
	if (!acl) {
		acl = smpp_acl_alloc(smsc, id);
		if (!acl)
			return CMD_WARNING;
	}

	vty->index = acl;
	vty->index_sub = &acl->description;
	vty->node = SMPP_ESME_NODE;

	return CMD_SUCCESS;
}

DEFUN(cfg_no_esme, cfg_no_esme_cmd,
	"no esme NAME", NO_STR "Remove ESME configuration")
{
	struct smsc *smsc = smsc_from_vty(vty);
	struct osmo_smpp_acl *acl;
	const char *id = argv[0];

	acl = smpp_acl_by_system_id(smsc, id);
	if (!acl) {
		vty_out(vty, "%% ESME with system id '%s' unknown%s",
			id, VTY_NEWLINE);
		return CMD_WARNING;
	}

	/* FIXME: close the connection, free data structure, etc. */

	smpp_acl_delete(acl);

	return CMD_SUCCESS;
}


DEFUN(cfg_esme_passwd, cfg_esme_passwd_cmd,
	"password PASSWORD", "Set the password for this ESME")
{
	struct osmo_smpp_acl *acl = vty->index;

	if (strlen(argv[0])+1 > sizeof(acl->passwd))
		return CMD_WARNING;

	strcpy(acl->passwd, argv[0]);

	return CMD_SUCCESS;
}

DEFUN(cfg_esme_no_passwd, cfg_esme_no_passwd_cmd,
	"no password", NO_STR "Set the password for this ESME")
{
	struct osmo_smpp_acl *acl = vty->index;

	memset(acl->passwd, 0, sizeof(acl->passwd));

	return CMD_SUCCESS;
}

DEFUN(cfg_esme_route, cfg_esme_route_cmd,
	"route DESTINATION",
	"Configure a route for MO-SMS to be sent to this ESME\n"
	"Destination phone number")
{
	struct osmo_smpp_acl *acl = vty->index;

	/* FIXME: check if DESTINATION is all-digits */

	return CMD_SUCCESS;
}

DEFUN(cfg_esme_defaultroute, cfg_esme_defaultroute_cmd,
	"default-route",
	"Set this ESME as default-route for all SMS to unknown destinations")
{
	struct osmo_smpp_acl *acl = vty->index;

	acl->default_route = 1;

	return CMD_SUCCESS;
}

DEFUN(cfg_no_esme_defaultroute, cfg_esme_no_defaultroute_cmd,
	"no default-route", NO_STR
	"Set this ESME as default-route for all SMS to unknown destinations")
{
	struct osmo_smpp_acl *acl = vty->index;

	acl->default_route = 0;

	/* remove currently active default route, if it was created by
	 * this ACL */
	if (acl->smsc->def_route && acl->smsc->def_route->acl == acl)
		acl->smsc->def_route = NULL;

	return CMD_SUCCESS;
}

static void dump_one_esme(struct vty *vty, struct osmo_esme *esme)
{
	char host[128], serv[128];

	host[0] = 0;
	serv[0] = 0;
	getnameinfo((const struct sockaddr *) &esme->sa, esme->sa_len,
		    host, sizeof(host), serv, sizeof(serv), NI_NUMERICSERV);

	vty_out(vty, "ESME System ID: %s, Password: %s, SMPP Version %02x%s",
		esme->system_id, esme->acl->passwd, esme->smpp_version, VTY_NEWLINE);
	vty_out(vty, "  Connected from: %s:%s%s", host, serv, VTY_NEWLINE);
}

DEFUN(show_esme, show_esme_cmd,
	"show smpp esme",
	SHOW_STR "SMPP Interface\n" "SMPP Extrenal SMS Entity\n")
{
	struct smsc *smsc = smsc_from_vty(vty);
	struct osmo_esme *esme;

	llist_for_each_entry(esme, &smsc->esme_list, list)
		dump_one_esme(vty, esme);

	return CMD_SUCCESS;
}

static void config_write_esme_single(struct vty *vty, struct osmo_smpp_acl *acl)
{
	vty_out(vty, " esme %s%s", acl->system_id, VTY_NEWLINE);
	if (strlen(acl->passwd))
		vty_out(vty, "  password %s%s", acl->passwd, VTY_NEWLINE);
	if (acl->default_route)
		vty_out(vty, "  default-route%s", VTY_NEWLINE);
}

static int config_write_esme(struct vty *v)
{
	struct smsc *smsc = smsc_from_vty(v);
	struct osmo_smpp_acl *acl;

	llist_for_each_entry(acl, &smsc->acl_list, list)
		config_write_esme_single(v, acl);

	return CMD_SUCCESS;
}

int smpp_vty_init(void)
{
	install_node(&smpp_node, config_write_smpp);
	install_default(SMPP_NODE);
	install_element(CONFIG_NODE, &cfg_smpp_cmd);

	install_element(SMPP_NODE, &cfg_smpp_port_cmd);
	install_element(SMPP_NODE, &cfg_smpp_sys_id_cmd);
	install_element(SMPP_NODE, &cfg_smpp_policy_cmd);
	install_element(SMPP_NODE, &cfg_esme_cmd);
	install_element(SMPP_NODE, &cfg_no_esme_cmd);

	install_node(&esme_node, config_write_esme);
	install_default(SMPP_ESME_NODE);
	install_element(SMPP_ESME_NODE, &cfg_esme_passwd_cmd);
	install_element(SMPP_ESME_NODE, &cfg_esme_no_passwd_cmd);
	install_element(SMPP_ESME_NODE, &cfg_esme_route_cmd);
	install_element(SMPP_ESME_NODE, &cfg_esme_defaultroute_cmd);
	install_element(SMPP_ESME_NODE, &cfg_esme_no_defaultroute_cmd);
	install_element(SMPP_ESME_NODE, &ournode_exit_cmd);

	install_element_ve(&show_esme_cmd);

	return 0;
}
