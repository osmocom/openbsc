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

#include <ctype.h>
#include <string.h>
#include <errno.h>
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

DEFUN(cfg_smpp_first, cfg_smpp_first_cmd,
	"smpp-first",
	"Try SMPP routes before the subscriber DB\n")
{
	struct smsc *smsc = smsc_from_vty(vty);
	smsc->smpp_first = 1;
	return CMD_SUCCESS;
}

DEFUN(cfg_no_smpp_first, cfg_no_smpp_first_cmd,
	"no smpp-first",
	NO_STR "Try SMPP before routes before the subscriber DB\n")
{
	struct smsc *smsc = smsc_from_vty(vty);
	smsc->smpp_first = 0;
	return CMD_SUCCESS;
}

static int smpp_local_tcp(struct vty *vty,
			  const char *bind_addr, uint16_t port)
{
	struct smsc *smsc = smsc_from_vty(vty);
	int is_running = smsc->listen_ofd.fd > 0;
	int same_bind_addr;
	int rc;

	/* If it is not up yet, don't rebind, just set values. */
	if (!is_running) {
		rc = smpp_smsc_conf(smsc, bind_addr, port);
		if (rc < 0) {
			vty_out(vty, "%% Cannot configure new address:port%s",
				VTY_NEWLINE);
			return CMD_WARNING;
		}
		return CMD_SUCCESS;
	}

	rc = smpp_smsc_restart(smsc, bind_addr, port);
	if (rc < 0) {
		vty_out(vty, "%% Cannot bind to new port %s:%u nor to"
			" old port %s:%u%s",
			bind_addr? bind_addr : "0.0.0.0",
			port,
			smsc->bind_addr? smsc->bind_addr : "0.0.0.0",
			smsc->listen_port,
			VTY_NEWLINE);
		return CMD_WARNING;
	}

	same_bind_addr = (bind_addr == smsc->bind_addr)
		|| (bind_addr && smsc->bind_addr
		    && (strcmp(bind_addr, smsc->bind_addr) == 0));

	if (!same_bind_addr || port != smsc->listen_port) {
		vty_out(vty, "%% Cannot bind to new port %s:%u, staying on"
			" old port %s:%u%s",
			bind_addr? bind_addr : "0.0.0.0",
			port,
			smsc->bind_addr? smsc->bind_addr : "0.0.0.0",
			smsc->listen_port,
			VTY_NEWLINE);
		return CMD_WARNING;
	}

	return CMD_SUCCESS;
}

DEFUN(cfg_smpp_port, cfg_smpp_port_cmd,
	"local-tcp-port <1-65535>",
	"Set the local TCP port on which we listen for SMPP\n"
	"TCP port number")
{
	struct smsc *smsc = smsc_from_vty(vty);
	uint16_t port = atoi(argv[0]);
	return smpp_local_tcp(vty, smsc->bind_addr, port);
}

DEFUN(cfg_smpp_addr_port, cfg_smpp_addr_port_cmd,
	"local-tcp-ip A.B.C.D <1-65535>",
	"Set the local IP address and TCP port on which we listen for SMPP\n"
	"Local IP address\n"
	"TCP port number")
{
	const char *bind_addr = argv[0];
	uint16_t port = atoi(argv[1]);
	return smpp_local_tcp(vty, bind_addr, port);
}

DEFUN(cfg_smpp_sys_id, cfg_smpp_sys_id_cmd,
	"system-id ID",
	"Set the System ID of this SMSC\n"
	"Alphanumeric SMSC System ID\n")
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
	if (smsc->bind_addr)
		vty_out(vty, " local-tcp-ip %s %u%s", smsc->bind_addr,
			smsc->listen_port, VTY_NEWLINE);
	else
		vty_out(vty, " local-tcp-port %u%s", smsc->listen_port,
			VTY_NEWLINE);
	if (strlen(smsc->system_id) > 0)
		vty_out(vty, " system-id %s%s", smsc->system_id, VTY_NEWLINE);
	vty_out(vty, " policy %s%s",
		smsc->accept_all ? "accept-all" : "closed", VTY_NEWLINE);
	vty_out(vty, " %ssmpp-first%s",
		smsc->smpp_first ? "" : "no ", VTY_NEWLINE);

	return CMD_SUCCESS;
}

DEFUN(cfg_esme, cfg_esme_cmd,
	"esme NAME",
	"Configure a particular ESME\n"
	"Alphanumeric System ID of the ESME to be configured\n")
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
	"no esme NAME",
	NO_STR "Remove ESME configuration\n"
	"Alphanumeric System ID of the ESME to be removed\n")
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
	"password PASSWORD",
	"Set the password for this ESME\n"
	"Alphanumeric password string\n")
{
	struct osmo_smpp_acl *acl = vty->index;

	if (strlen(argv[0])+1 > sizeof(acl->passwd))
		return CMD_WARNING;

	strcpy(acl->passwd, argv[0]);

	return CMD_SUCCESS;
}

DEFUN(cfg_esme_no_passwd, cfg_esme_no_passwd_cmd,
	"no password",
	NO_STR "Remove the password for this ESME\n")
{
	struct osmo_smpp_acl *acl = vty->index;

	memset(acl->passwd, 0, sizeof(acl->passwd));

	return CMD_SUCCESS;
}

static int osmo_is_digits(const char *str)
{
	int i;
	for (i = 0; i < strlen(str); i++) {
		if (!isdigit(str[i]))
			return 0;
	}
	return 1;
}

static const struct value_string route_errstr[] = {
	{ -EEXIST,	"Route already exists" },
	{ -ENODEV,	"Route does not exist" },
	{ -ENOMEM,	"No memory" },
	{ -EINVAL,	"Invalid" },
	{ 0, NULL }
};

static const struct value_string smpp_ton_str_short[] = {
	{ TON_Unknown,		"unknown" },
	{ TON_International,	"international" },
	{ TON_National,		"national" },
	{ TON_Network_Specific,	"network" },
	{ TON_Subscriber_Number,"subscriber" },
	{ TON_Alphanumeric,	"alpha" },
	{ TON_Abbreviated,	"abbrev" },
	{ 0, NULL }
};

static const struct value_string smpp_npi_str_short[] = {
	{ NPI_Unknown,		"unknown" },
	{ NPI_ISDN_E163_E164,	"isdn" },
	{ NPI_Data_X121,	"x121" },
	{ NPI_Telex_F69,	"f69" },
	{ NPI_Land_Mobile_E212,	"e212" },
	{ NPI_National,		"national" },
	{ NPI_Private,		"private" },
	{ NPI_ERMES,		"ermes" },
	{ NPI_Internet_IP,	"ip" },
	{ NPI_WAP_Client_Id,	"wap" },
	{ 0, NULL }
};


#define SMPP_ROUTE_STR "Configure a route for MO-SMS to be sent to this ESME\n"
#define SMPP_ROUTE_P_STR SMPP_ROUTE_STR "Prefix-match route\n"
#define SMPP_PREFIX_STR "Destination number prefix\n"

#define TON_CMD "(unknown|international|national|network|subscriber|alpha|abbrev)"
#define NPI_CMD "(unknown|isdn|x121|f69|e212|national|private|ermes|ip|wap)"
#define TON_STR "Unknown type-of-number\n"		\
		"International type-of-number\n"	\
		"National type-of-number\n"		\
		"Network specific type-of-number\n"	\
		"Subscriber type-of-number\n"		\
		"Alphanumeric type-of-number\n"		\
		"Abbreviated type-of-number\n"
#define NPI_STR "Unknown numbering plan\n"		\
		"ISDN (E.164) numbering plan\n"		\
		"X.121 numbering plan\n"		\
		"F.69 numbering plan\n"			\
		"E.212 numbering plan\n"		\
		"National numbering plan\n"		\
		"Private numbering plan\n"		\
		"ERMES numbering plan\n"		\
		"IP numbering plan\n"			\
		"WAP numbeing plan\n"

DEFUN(cfg_esme_route_pfx, cfg_esme_route_pfx_cmd,
	"route prefix " TON_CMD " " NPI_CMD " PREFIX",
	SMPP_ROUTE_P_STR TON_STR NPI_STR SMPP_PREFIX_STR)
{
	struct osmo_smpp_acl *acl = vty->index;
	struct osmo_smpp_addr pfx;
	int rc;

	/* check if DESTINATION is all-digits */
	if (!osmo_is_digits(argv[2])) {
		vty_out(vty, "%% PREFIX has to be numeric%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	pfx.ton = get_string_value(smpp_ton_str_short, argv[0]);
	pfx.npi = get_string_value(smpp_npi_str_short, argv[1]);
	snprintf(pfx.addr, sizeof(pfx.addr), "%s", argv[2]);

	rc = smpp_route_pfx_add(acl, &pfx);
	if (rc < 0) {
		vty_out(vty, "%% error adding prefix route: %s%s",
			get_value_string(route_errstr, rc), VTY_NEWLINE);
		return CMD_WARNING;
	}

	return CMD_SUCCESS;
}

DEFUN(cfg_esme_no_route_pfx, cfg_esme_no_route_pfx_cmd,
	"no route prefix " TON_CMD " " NPI_CMD " PREFIX",
	NO_STR SMPP_ROUTE_P_STR TON_STR NPI_STR SMPP_PREFIX_STR)
{
	struct osmo_smpp_acl *acl = vty->index;
	struct osmo_smpp_addr pfx;
	int rc;

	/* check if DESTINATION is all-digits */
	if (!osmo_is_digits(argv[2])) {
		vty_out(vty, "%% PREFIX has to be numeric%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	pfx.ton = get_string_value(smpp_ton_str_short, argv[0]);
	pfx.npi = get_string_value(smpp_npi_str_short, argv[1]);
	snprintf(pfx.addr, sizeof(pfx.addr), "%s", argv[2]);

	rc = smpp_route_pfx_del(acl, &pfx);
	if (rc < 0) {
		vty_out(vty, "%% error removing prefix route: %s%s",
			get_value_string(route_errstr, rc), VTY_NEWLINE);
		return CMD_WARNING;
	}

	return CMD_SUCCESS;

}


DEFUN(cfg_esme_defaultroute, cfg_esme_defaultroute_cmd,
	"default-route",
	"Set this ESME as default-route for all SMS to unknown destinations")
{
	struct osmo_smpp_acl *acl = vty->index;

	acl->default_route = 1;

	if (!acl->smsc->def_route)
		acl->smsc->def_route = acl;

	return CMD_SUCCESS;
}

DEFUN(cfg_no_esme_defaultroute, cfg_esme_no_defaultroute_cmd,
	"no default-route", NO_STR
	"Remove this ESME as default-route for all SMS to unknown destinations")
{
	struct osmo_smpp_acl *acl = vty->index;

	acl->default_route = 0;

	/* remove currently active default route, if it was created by
	 * this ACL */
	if (acl->smsc->def_route && acl->smsc->def_route == acl)
		acl->smsc->def_route = NULL;

	return CMD_SUCCESS;
}

DEFUN(cfg_esme_del_src_imsi, cfg_esme_del_src_imsi_cmd,
	"deliver-src-imsi",
	"Enable the use of IMSI as source address in DELIVER")
{
	struct osmo_smpp_acl *acl = vty->index;

	acl->deliver_src_imsi = 1;

	return CMD_SUCCESS;
}

DEFUN(cfg_esme_no_del_src_imsi, cfg_esme_no_del_src_imsi_cmd,
	"no deliver-src-imsi", NO_STR
	"Disable the use of IMSI as source address in DELIVER")
{
	struct osmo_smpp_acl *acl = vty->index;

	acl->deliver_src_imsi = 0;

	return CMD_SUCCESS;
}

DEFUN(cfg_esme_osmo_ext, cfg_esme_osmo_ext_cmd,
	"osmocom-extensions",
	"Enable the use of Osmocom SMPP Extensions for this ESME")
{
	struct osmo_smpp_acl *acl = vty->index;

	acl->osmocom_ext = 1;

	return CMD_SUCCESS;
}

DEFUN(cfg_esme_no_osmo_ext, cfg_esme_no_osmo_ext_cmd,
	"no osmocom-extensions", NO_STR
	"Disable the use of Osmocom SMPP Extensions for this ESME")
{
	struct osmo_smpp_acl *acl = vty->index;

	acl->osmocom_ext = 0;

	return CMD_SUCCESS;
}

DEFUN(cfg_esme_dcs_transp, cfg_esme_dcs_transp_cmd,
	"dcs-transparent",
	"Enable the transparent pass-through of TP-DCS to SMPP DataCoding")
{
	struct osmo_smpp_acl *acl = vty->index;

	acl->dcs_transparent = 1;

	return CMD_SUCCESS;
}

DEFUN(cfg_esme_no_dcs_transp, cfg_esme_no_dcs_transp_cmd,
	"no dcs-transparent", NO_STR
	"Disable the transparent pass-through of TP-DCS to SMPP DataCoding")
{
	struct osmo_smpp_acl *acl = vty->index;

	acl->dcs_transparent = 0;

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
		esme->system_id, esme->acl ? esme->acl->passwd : "",
		esme->smpp_version, VTY_NEWLINE);
	vty_out(vty, "  Connected from: %s:%s%s", host, serv, VTY_NEWLINE);
	if (esme->smsc->def_route == esme->acl)
		vty_out(vty, "  Is current default route%s", VTY_NEWLINE);
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

static void write_esme_route_single(struct vty *vty, struct osmo_smpp_route *r)
{
	switch (r->type) {
	case SMPP_ROUTE_PREFIX:
		vty_out(vty, "   route prefix %s ",
			get_value_string(smpp_ton_str_short, r->u.prefix.ton));
		vty_out(vty, "%s %s%s",
			get_value_string(smpp_npi_str_short, r->u.prefix.npi),
			r->u.prefix.addr, VTY_NEWLINE);
		break;
	case SMPP_ROUTE_NONE:
		break;
	}
}

static void config_write_esme_single(struct vty *vty, struct osmo_smpp_acl *acl)
{
	struct osmo_smpp_route *r;

	vty_out(vty, " esme %s%s", acl->system_id, VTY_NEWLINE);
	if (strlen(acl->passwd))
		vty_out(vty, "  password %s%s", acl->passwd, VTY_NEWLINE);
	if (acl->default_route)
		vty_out(vty, "  default-route%s", VTY_NEWLINE);
	if (acl->deliver_src_imsi)
		vty_out(vty, "  deliver-src-imsi%s", VTY_NEWLINE);
	if (acl->osmocom_ext)
		vty_out(vty, "  osmocom-extensions%s", VTY_NEWLINE);
	if (acl->dcs_transparent)
		vty_out(vty, "  dcs-transparent%s", VTY_NEWLINE);

	llist_for_each_entry(r, &acl->route_list, list)
		write_esme_route_single(vty, r);
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
	vty_install_default(SMPP_NODE);
	install_element(CONFIG_NODE, &cfg_smpp_cmd);

	install_element(SMPP_NODE, &cfg_smpp_first_cmd);
	install_element(SMPP_NODE, &cfg_no_smpp_first_cmd);
	install_element(SMPP_NODE, &cfg_smpp_port_cmd);
	install_element(SMPP_NODE, &cfg_smpp_addr_port_cmd);
	install_element(SMPP_NODE, &cfg_smpp_sys_id_cmd);
	install_element(SMPP_NODE, &cfg_smpp_policy_cmd);
	install_element(SMPP_NODE, &cfg_esme_cmd);
	install_element(SMPP_NODE, &cfg_no_esme_cmd);

	install_node(&esme_node, config_write_esme);
	vty_install_default(SMPP_ESME_NODE);
	install_element(SMPP_ESME_NODE, &cfg_esme_passwd_cmd);
	install_element(SMPP_ESME_NODE, &cfg_esme_no_passwd_cmd);
	install_element(SMPP_ESME_NODE, &cfg_esme_route_pfx_cmd);
	install_element(SMPP_ESME_NODE, &cfg_esme_no_route_pfx_cmd);
	install_element(SMPP_ESME_NODE, &cfg_esme_defaultroute_cmd);
	install_element(SMPP_ESME_NODE, &cfg_esme_no_defaultroute_cmd);
	install_element(SMPP_ESME_NODE, &cfg_esme_del_src_imsi_cmd);
	install_element(SMPP_ESME_NODE, &cfg_esme_no_del_src_imsi_cmd);
	install_element(SMPP_ESME_NODE, &cfg_esme_osmo_ext_cmd);
	install_element(SMPP_ESME_NODE, &cfg_esme_no_osmo_ext_cmd);
	install_element(SMPP_ESME_NODE, &cfg_esme_dcs_transp_cmd);
	install_element(SMPP_ESME_NODE, &cfg_esme_no_dcs_transp_cmd);

	install_element_ve(&show_esme_cmd);

	return 0;
}
