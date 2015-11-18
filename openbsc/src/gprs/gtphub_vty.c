/* (C) 2015 by sysmocom s.f.m.c. GmbH
 * All Rights Reserved
 *
 * Author: Neels Hofmeyr
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

#include <ares.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <osmocom/core/talloc.h>
#include <osmocom/vty/command.h>

#include <openbsc/vty.h>
#include <openbsc/gtphub.h>

/* TODO split GRX ares from sgsn into a separate struct and allow use without
 * globals. */
#include <openbsc/sgsn.h>
extern struct sgsn_instance *sgsn;

static struct gtphub_cfg *g_cfg = 0;

static struct cmd_node gtphub_node = {
	GTPHUB_NODE,
	"%s(config-gtphub)# ",
	1,
};

#define GTPH_DEFAULT_CONTROL_PORT 2123
#define GTPH_DEFAULT_USER_PORT 2152

static void write_addrs(struct vty *vty, const char *name,
			struct gtphub_cfg_addr *c, struct gtphub_cfg_addr *u)
{
	if ((c->port == GTPH_DEFAULT_CONTROL_PORT)
	    && (u->port == GTPH_DEFAULT_USER_PORT)
	    && (strcmp(c->addr_str, u->addr_str) == 0)) {
		/* Default port numbers and same IP address: write "short"
		 * variant. */
		vty_out(vty, " %s %s%s",
			name,
			c->addr_str,
			VTY_NEWLINE);
		return;
	}

	vty_out(vty, " %s ctrl %s %d user %s %d%s",
		name,
		c->addr_str, (int)c->port,
		u->addr_str, (int)u->port,
		VTY_NEWLINE);

	struct ares_addr_node *server;
	for (server = sgsn->ares_servers; server; server = server->next)
		vty_out(vty, " grx-dns-add %s%s", inet_ntoa(server->addr.addr4), VTY_NEWLINE);
}

static int config_write_gtphub(struct vty *vty)
{
	vty_out(vty, "gtphub%s", VTY_NEWLINE);

	write_addrs(vty, "bind-to-sgsns",
		    &g_cfg->to_sgsns[GTPH_PLANE_CTRL].bind,
		    &g_cfg->to_sgsns[GTPH_PLANE_USER].bind);

	write_addrs(vty, "bind-to-ggsns",
		    &g_cfg->to_ggsns[GTPH_PLANE_CTRL].bind,
		    &g_cfg->to_ggsns[GTPH_PLANE_USER].bind);

	if (g_cfg->ggsn_proxy[GTPH_PLANE_CTRL].addr_str) {
		write_addrs(vty, "ggsn-proxy",
			    &g_cfg->ggsn_proxy[GTPH_PLANE_CTRL],
			    &g_cfg->ggsn_proxy[GTPH_PLANE_USER]);
	}

	return CMD_SUCCESS;
}

DEFUN(cfg_gtphub, cfg_gtphub_cmd,
      "gtphub",
      "Configure the GTP hub")
{
	vty->node = GTPHUB_NODE;
	return CMD_SUCCESS;
}

#define BIND_ARGS  "ctrl ADDR <0-65535> user ADDR <0-65535>"
#define BIND_DOCS  \
	"Set GTP-C bind\n" \
	"GTP-C local IP address (v4 or v6)\n" \
	"GTP-C local port\n" \
	"Set GTP-U bind\n" \
	"GTP-U local IP address (v4 or v6)\n" \
	"GTP-U local port\n"


DEFUN(cfg_gtphub_bind_to_sgsns_short, cfg_gtphub_bind_to_sgsns_short_cmd,
	"bind-to-sgsns ADDR",
	"GTP Hub Parameters\n"
	"Set the local bind address to listen for SGSNs, for both GTP-C and GTP-U\n"
	"Local IP address (v4 or v6)\n"
	)
{
	int i;
	for (i = 0; i < GTPH_PLANE_N; i++)
		g_cfg->to_sgsns[i].bind.addr_str = talloc_strdup(tall_vty_ctx, argv[0]);
	g_cfg->to_sgsns[GTPH_PLANE_CTRL].bind.port = GTPH_DEFAULT_CONTROL_PORT;
	g_cfg->to_sgsns[GTPH_PLANE_USER].bind.port = GTPH_DEFAULT_USER_PORT;
	return CMD_SUCCESS;
}

DEFUN(cfg_gtphub_bind_to_ggsns_short, cfg_gtphub_bind_to_ggsns_short_cmd,
	"bind-to-ggsns ADDR",
	"GTP Hub Parameters\n"
	"Set the local bind address to listen for GGSNs, for both GTP-C and GTP-U\n"
	"Local IP address (v4 or v6)\n"
	)
{
	int i;
	for (i = 0; i < GTPH_PLANE_N; i++)
		g_cfg->to_ggsns[i].bind.addr_str = talloc_strdup(tall_vty_ctx, argv[0]);
	g_cfg->to_ggsns[GTPH_PLANE_CTRL].bind.port = GTPH_DEFAULT_CONTROL_PORT;
	g_cfg->to_ggsns[GTPH_PLANE_USER].bind.port = GTPH_DEFAULT_USER_PORT;
	return CMD_SUCCESS;
}


static int handle_binds(struct gtphub_cfg_bind *b, const char **argv)
{
	b[GTPH_PLANE_CTRL].bind.addr_str = talloc_strdup(tall_vty_ctx, argv[0]);
	b[GTPH_PLANE_CTRL].bind.port = atoi(argv[1]);
	b[GTPH_PLANE_USER].bind.addr_str = talloc_strdup(tall_vty_ctx, argv[2]);
	b[GTPH_PLANE_USER].bind.port = atoi(argv[3]);
	return CMD_SUCCESS;
}

DEFUN(cfg_gtphub_bind_to_sgsns, cfg_gtphub_bind_to_sgsns_cmd,
	"bind-to-sgsns " BIND_ARGS,
	"GTP Hub Parameters\n"
	"Set the local bind addresses and ports to listen for SGSNs\n"
	BIND_DOCS
	)
{
	return handle_binds(g_cfg->to_sgsns, argv);
}

DEFUN(cfg_gtphub_bind_to_ggsns, cfg_gtphub_bind_to_ggsns_cmd,
	"bind-to-ggsns " BIND_ARGS,
	"GTP Hub Parameters\n"
	"Set the local bind addresses and ports to listen for GGSNs\n"
	BIND_DOCS
	)
{
	return handle_binds(g_cfg->to_ggsns, argv);
}

DEFUN(cfg_gtphub_ggsn_proxy_short, cfg_gtphub_ggsn_proxy_short_cmd,
	"ggsn-proxy ADDR",
	"GTP Hub Parameters\n"
	"Redirect all GGSN bound traffic to default ports on this address (another gtphub)\n"
	"Remote IP address (v4 or v6)\n"
	)
{
	g_cfg->ggsn_proxy[GTPH_PLANE_CTRL].addr_str = talloc_strdup(tall_vty_ctx, argv[0]);
	g_cfg->ggsn_proxy[GTPH_PLANE_CTRL].port = GTPH_DEFAULT_CONTROL_PORT;
	g_cfg->ggsn_proxy[GTPH_PLANE_USER].addr_str = talloc_strdup(tall_vty_ctx, argv[0]);
	g_cfg->ggsn_proxy[GTPH_PLANE_USER].port = GTPH_DEFAULT_USER_PORT;
	return CMD_SUCCESS;
}

DEFUN(cfg_gtphub_ggsn_proxy, cfg_gtphub_ggsn_proxy_cmd,
	"ggsn-proxy " BIND_ARGS,
	"GTP Hub Parameters\n"
	"Redirect all GGSN bound traffic to these addresses and ports (another gtphub)\n"
	BIND_DOCS
	)
{
	g_cfg->ggsn_proxy[GTPH_PLANE_CTRL].addr_str = talloc_strdup(tall_vty_ctx, argv[0]);
	g_cfg->ggsn_proxy[GTPH_PLANE_CTRL].port = atoi(argv[1]);
	g_cfg->ggsn_proxy[GTPH_PLANE_USER].addr_str = talloc_strdup(tall_vty_ctx, argv[2]);
	g_cfg->ggsn_proxy[GTPH_PLANE_USER].port = atoi(argv[3]);
	return CMD_SUCCESS;
}

DEFUN(cfg_gtphub_sgsn_proxy_short, cfg_gtphub_sgsn_proxy_short_cmd,
	"sgsn-proxy ADDR",
	"GTP Hub Parameters\n"
	"Redirect all SGSN bound traffic to default ports on this address (another gtphub)\n"
	"Remote IP address (v4 or v6)\n"
	)
{
	g_cfg->sgsn_proxy[GTPH_PLANE_CTRL].addr_str = talloc_strdup(tall_vty_ctx, argv[0]);
	g_cfg->sgsn_proxy[GTPH_PLANE_CTRL].port = GTPH_DEFAULT_CONTROL_PORT;
	g_cfg->sgsn_proxy[GTPH_PLANE_USER].addr_str = talloc_strdup(tall_vty_ctx, argv[0]);
	g_cfg->sgsn_proxy[GTPH_PLANE_USER].port = GTPH_DEFAULT_USER_PORT;
	return CMD_SUCCESS;
}

DEFUN(cfg_gtphub_sgsn_proxy, cfg_gtphub_sgsn_proxy_cmd,
	"sgsn-proxy " BIND_ARGS,
	"GTP Hub Parameters\n"
	"Redirect all SGSN bound traffic to these addresses and ports (another gtphub)\n"
	BIND_DOCS
	)
{
	g_cfg->sgsn_proxy[GTPH_PLANE_CTRL].addr_str = talloc_strdup(tall_vty_ctx, argv[0]);
	g_cfg->sgsn_proxy[GTPH_PLANE_CTRL].port = atoi(argv[1]);
	g_cfg->sgsn_proxy[GTPH_PLANE_USER].addr_str = talloc_strdup(tall_vty_ctx, argv[2]);
	g_cfg->sgsn_proxy[GTPH_PLANE_USER].port = atoi(argv[3]);
	return CMD_SUCCESS;
}


/* Copied from sgsn_vty.h */
DEFUN(cfg_grx_ggsn, cfg_grx_ggsn_cmd,
	"grx-dns-add A.B.C.D",
	"Add DNS server\nIPv4 address\n")
{
	struct ares_addr_node *node = talloc_zero(tall_bsc_ctx, struct ares_addr_node);
	node->family = AF_INET;
	inet_aton(argv[0], &node->addr.addr4);

	node->next = sgsn->ares_servers;
	sgsn->ares_servers = node;
	return CMD_SUCCESS;
}


DEFUN(show_gtphub, show_gtphub_cmd, "show gtphub",
      SHOW_STR "Display information about the GTP hub")
{
	vty_out(vty, "gtphub has nothing to say yet%s", VTY_NEWLINE);
	return CMD_SUCCESS;
}


int gtphub_vty_init(void)
{
	install_element_ve(&show_gtphub_cmd);

	install_element(CONFIG_NODE, &cfg_gtphub_cmd);
	install_node(&gtphub_node, config_write_gtphub);
	vty_install_default(GTPHUB_NODE);

	install_element(GTPHUB_NODE, &cfg_gtphub_bind_to_sgsns_short_cmd);
	install_element(GTPHUB_NODE, &cfg_gtphub_bind_to_sgsns_cmd);
	install_element(GTPHUB_NODE, &cfg_gtphub_bind_to_ggsns_short_cmd);
	install_element(GTPHUB_NODE, &cfg_gtphub_bind_to_ggsns_cmd);
	install_element(GTPHUB_NODE, &cfg_gtphub_ggsn_proxy_short_cmd);
	install_element(GTPHUB_NODE, &cfg_gtphub_ggsn_proxy_cmd);
	install_element(GTPHUB_NODE, &cfg_gtphub_sgsn_proxy_short_cmd);
	install_element(GTPHUB_NODE, &cfg_gtphub_sgsn_proxy_cmd);
	install_element(GTPHUB_NODE, &cfg_grx_ggsn_cmd);

	return 0;
}

int gtphub_cfg_read(struct gtphub_cfg *cfg, const char *config_file)
{
	int rc;

	g_cfg = cfg;

	rc = vty_read_config_file(config_file, NULL);
	if (rc < 0) {
		fprintf(stderr, "Failed to parse the config file: '%s'\n", config_file);
		return rc;
	}

	return 0;
}
