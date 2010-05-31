/* A Media Gateway Control Protocol Media Gateway: RFC 3435 */
/* The protocol implementation */

/*
 * (C) 2009-2010 by Holger Hans Peter Freyther <zecke@selfish.org>
 * (C) 2009-2010 by On-Waves
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

#include <sys/types.h>

#include <osmocore/talloc.h>

#include <openbsc/debug.h>
#include <openbsc/mgcp.h>
#include <openbsc/mgcp_internal.h>

#include <vty/command.h>
#include <vty/vty.h>

#include <string.h>

static struct mgcp_config *g_cfg = NULL;

/*
 * vty code for mgcp below
 */
struct cmd_node mgcp_node = {
	MGCP_NODE,
	"%s(mgcp)#",
	1,
};

static int config_write_mgcp(struct vty *vty)
{
	vty_out(vty, "mgcp%s", VTY_NEWLINE);
	if (g_cfg->local_ip)
		vty_out(vty, "  local ip %s%s", g_cfg->local_ip, VTY_NEWLINE);
	if (g_cfg->bts_ip && strlen(g_cfg->bts_ip) != 0)
		vty_out(vty, "  bts ip %s%s", g_cfg->bts_ip, VTY_NEWLINE);
	vty_out(vty, "  bind ip %s%s", g_cfg->source_addr, VTY_NEWLINE);
	vty_out(vty, "  bind port %u%s", g_cfg->source_port, VTY_NEWLINE);
	vty_out(vty, "  bind early %u%s", !!g_cfg->early_bind, VTY_NEWLINE);
	vty_out(vty, "  rtp base %u%s", g_cfg->rtp_base_port, VTY_NEWLINE);
	vty_out(vty, "  rtp ip-tos %d%s", g_cfg->endp_tos, VTY_NEWLINE);
	if (g_cfg->audio_payload != -1)
		vty_out(vty, "  sdp audio payload number %d%s", g_cfg->audio_payload, VTY_NEWLINE);
	if (g_cfg->audio_name)
		vty_out(vty, "  sdp audio payload name %s%s", g_cfg->audio_name, VTY_NEWLINE);
	vty_out(vty, "  loop %u%s", !!g_cfg->audio_loop, VTY_NEWLINE);
	vty_out(vty, "  number endpoints %u%s", g_cfg->number_endpoints - 1, VTY_NEWLINE);
	if (g_cfg->forward_ip)
		vty_out(vty, "  forward audio ip %s%s", g_cfg->forward_ip, VTY_NEWLINE);
	if (g_cfg->forward_port != 0)
		vty_out(vty, "  forward audio port %d%s", g_cfg->forward_port, VTY_NEWLINE);
	if (g_cfg->call_agent_addr)
		vty_out(vty, "  call agent ip %s%s", g_cfg->call_agent_addr, VTY_NEWLINE);

	return CMD_SUCCESS;
}

DEFUN(show_mcgp, show_mgcp_cmd, "show mgcp",
      SHOW_STR "Display information about the MGCP Media Gateway")
{
	int i;

	vty_out(vty, "MGCP is up and running with %u endpoints:%s", g_cfg->number_endpoints - 1, VTY_NEWLINE);
	for (i = 1; i < g_cfg->number_endpoints; ++i) {
		struct mgcp_endpoint *endp = &g_cfg->endpoints[i];
		vty_out(vty, " Endpoint 0x%.2x: CI: %d net: %u/%u bts: %u/%u on %s traffic received bts: %u  remote: %u%s",
			i, endp->ci,
			ntohs(endp->net_rtp), ntohs(endp->net_rtcp),
			ntohs(endp->bts_rtp), ntohs(endp->bts_rtcp),
			inet_ntoa(endp->bts), endp->in_bts, endp->in_remote,
			VTY_NEWLINE);
	}

	return CMD_SUCCESS;
}

DEFUN(cfg_mgcp,
      cfg_mgcp_cmd,
      "mgcp",
      "Configure the MGCP")
{
	vty->node = MGCP_NODE;
	return CMD_SUCCESS;
}

DEFUN(cfg_mgcp_local_ip,
      cfg_mgcp_local_ip_cmd,
      "local ip A.B.C.D",
      "Set the IP to be used in SDP records")
{
	if (g_cfg->local_ip)
		talloc_free(g_cfg->local_ip);
	g_cfg->local_ip = talloc_strdup(g_cfg, argv[0]);
	return CMD_SUCCESS;
}

DEFUN(cfg_mgcp_bts_ip,
      cfg_mgcp_bts_ip_cmd,
      "bts ip A.B.C.D",
      "Set the IP of the BTS for RTP forwarding")
{
	if (g_cfg->bts_ip)
		talloc_free(g_cfg->bts_ip);
	g_cfg->bts_ip = talloc_strdup(g_cfg, argv[0]);
	inet_aton(g_cfg->bts_ip, &g_cfg->bts_in);
	return CMD_SUCCESS;
}

DEFUN(cfg_mgcp_bind_ip,
      cfg_mgcp_bind_ip_cmd,
      "bind ip A.B.C.D",
      "Bind the MGCP to this local addr")
{
	if (g_cfg->source_addr)
		talloc_free(g_cfg->source_addr);
	g_cfg->source_addr = talloc_strdup(g_cfg, argv[0]);
	return CMD_SUCCESS;
}

DEFUN(cfg_mgcp_bind_port,
      cfg_mgcp_bind_port_cmd,
      "bind port <0-65534>",
      "Bind the MGCP to this port")
{
	unsigned int port = atoi(argv[0]);
	g_cfg->source_port = port;
	return CMD_SUCCESS;
}

DEFUN(cfg_mgcp_bind_early,
      cfg_mgcp_bind_early_cmd,
      "bind early (0|1)",
      "Bind all RTP ports early")
{
	unsigned int bind = atoi(argv[0]);
	g_cfg->early_bind = bind == 1;
	return CMD_SUCCESS;
}

DEFUN(cfg_mgcp_rtp_base_port,
      cfg_mgcp_rtp_base_port_cmd,
      "rtp base <0-65534>",
      "Base port to use")
{
	unsigned int port = atoi(argv[0]);
	g_cfg->rtp_base_port = port;
	return CMD_SUCCESS;
}

DEFUN(cfg_mgcp_rtp_ip_tos,
      cfg_mgcp_rtp_ip_tos_cmd,
      "rtp ip-tos <0-255>",
      "Set the IP_TOS socket attribute on the RTP/RTCP sockets.\n" "The TOS value.")
{
	int tos = atoi(argv[0]);
	g_cfg->endp_tos = tos;
	return CMD_SUCCESS;
}

DEFUN(cfg_mgcp_sdp_payload_number,
      cfg_mgcp_sdp_payload_number_cmd,
      "sdp audio payload number <1-255>",
      "Set the audio codec to use")
{
	unsigned int payload = atoi(argv[0]);
	g_cfg->audio_payload = payload;
	return CMD_SUCCESS;
}

DEFUN(cfg_mgcp_sdp_payload_name,
      cfg_mgcp_sdp_payload_name_cmd,
      "sdp audio payload name NAME",
      "Set the audio name to use")
{
	if (g_cfg->audio_name)
		talloc_free(g_cfg->audio_name);
	g_cfg->audio_name = talloc_strdup(g_cfg, argv[0]);
	return CMD_SUCCESS;
}

DEFUN(cfg_mgcp_loop,
      cfg_mgcp_loop_cmd,
      "loop (0|1)",
      "Loop the audio")
{
	g_cfg->audio_loop = atoi(argv[0]);
	return CMD_SUCCESS;
}

DEFUN(cfg_mgcp_number_endp,
      cfg_mgcp_number_endp_cmd,
      "number endpoints <0-65534>",
      "The number of endpoints to allocate. This is not dynamic.")
{
	/* + 1 as we start counting at one */
	g_cfg->number_endpoints = atoi(argv[0]) + 1;
	return CMD_SUCCESS;
}

DEFUN(cfg_mgcp_forward_ip,
      cfg_mgcp_forward_ip_cmd,
      "forward audio ip A.B.C.D",
      "Forward packets from and to the IP. This disables most of the MGCP feature.")
{
	if (g_cfg->forward_ip)
		talloc_free(g_cfg->forward_ip);
	g_cfg->forward_ip = talloc_strdup(g_cfg, argv[0]);
	return CMD_SUCCESS;
}

DEFUN(cfg_mgcp_forward_port,
      cfg_mgcp_forward_port_cmd,
      "forward audio port <1-15000>",
      "Forward packets from and to the port. This disables most of the MGCP feature.")
{
	g_cfg->forward_port = atoi(argv[0]);
	return CMD_SUCCESS;
}

DEFUN(cfg_mgcp_agent_addr,
      cfg_mgcp_agent_addr_cmd,
      "call agent ip IP",
      "Set the address of the call agent.")
{
	if (g_cfg->call_agent_addr)
		talloc_free(g_cfg->call_agent_addr);
	g_cfg->call_agent_addr = talloc_strdup(g_cfg, argv[0]);
	return CMD_SUCCESS;
}

int mgcp_vty_init(void)
{
	install_element_ve(&show_mgcp_cmd);

	install_element(CONFIG_NODE, &cfg_mgcp_cmd);
	install_node(&mgcp_node, config_write_mgcp);
	install_default(MGCP_NODE);
	install_element(MGCP_NODE, &cfg_mgcp_local_ip_cmd);
	install_element(MGCP_NODE, &cfg_mgcp_bts_ip_cmd);
	install_element(MGCP_NODE, &cfg_mgcp_bind_ip_cmd);
	install_element(MGCP_NODE, &cfg_mgcp_bind_port_cmd);
	install_element(MGCP_NODE, &cfg_mgcp_bind_early_cmd);
	install_element(MGCP_NODE, &cfg_mgcp_rtp_base_port_cmd);
	install_element(MGCP_NODE, &cfg_mgcp_rtp_ip_tos_cmd);
	install_element(MGCP_NODE, &cfg_mgcp_sdp_payload_number_cmd);
	install_element(MGCP_NODE, &cfg_mgcp_sdp_payload_name_cmd);
	install_element(MGCP_NODE, &cfg_mgcp_loop_cmd);
	install_element(MGCP_NODE, &cfg_mgcp_number_endp_cmd);
	install_element(MGCP_NODE, &cfg_mgcp_forward_ip_cmd);
	install_element(MGCP_NODE, &cfg_mgcp_forward_port_cmd);
	install_element(MGCP_NODE, &cfg_mgcp_agent_addr_cmd);
	return 0;
}

int mgcp_parse_config(const char *config_file, struct mgcp_config *cfg)
{
	int i, rc;

	g_cfg = cfg;
	rc = vty_read_config_file(config_file);
	if (rc < 0) {
		fprintf(stderr, "Failed to parse the config file: '%s'\n", config_file);
		return rc;
	}


	if (!g_cfg->bts_ip)
		fprintf(stderr, "No BTS ip address specified. This will allow everyone to connect.\n");

	if (!g_cfg->source_addr) {
		fprintf(stderr, "You need to specify a bind address.\n");
		return -1;
	}

	if (mgcp_endpoints_allocate(g_cfg) != 0) {
		fprintf(stderr, "Failed to allocate endpoints: %d. Quitting.\n", g_cfg->number_endpoints);
		return -1;
	}

	/*
	 * This application supports two modes.
	 *    1.) a true MGCP gateway with support for AUEP, CRCX, MDCX, DLCX
	 *    2.) plain forwarding of RTP packets on the endpoints.
	 * both modes are mutual exclusive
	 */
	if (g_cfg->forward_ip) {
		int port = g_cfg->rtp_base_port;
		if (g_cfg->forward_port != 0)
			port = g_cfg->forward_port;

		if (!g_cfg->early_bind) {
			LOGP(DMGCP, LOGL_NOTICE, "Forwarding requires early bind.\n");
			return -1;
		}

		/*
		 * Store the forward IP and assign a ci. For early bind
		 * the sockets will be created after this.
		 */
		for (i = 1; i < g_cfg->number_endpoints; ++i) {
			struct mgcp_endpoint *endp = &g_cfg->endpoints[i];
			inet_aton(g_cfg->forward_ip, &endp->remote);
			endp->ci = CI_UNUSED + 23;
			endp->net_rtp = htons(rtp_calculate_port(ENDPOINT_NUMBER(endp), port));
			endp->net_rtcp = htons(rtp_calculate_port(ENDPOINT_NUMBER(endp), port) + 1);
		}

		LOGP(DMGCP, LOGL_NOTICE, "Configured for Audio Forwarding.\n");
	}

	/* early bind */
	if (g_cfg->early_bind) {
		for (i = 1; i < g_cfg->number_endpoints; ++i) {
			struct mgcp_endpoint *endp = &g_cfg->endpoints[i];
			int rtp_port;

			rtp_port = rtp_calculate_port(ENDPOINT_NUMBER(endp), g_cfg->rtp_base_port);
			if (mgcp_bind_rtp_port(endp, rtp_port) != 0) {
				LOGP(DMGCP, LOGL_FATAL, "Failed to bind: %d\n", rtp_port);
				return -1;
			}
		}
	}

	return !!g_cfg->forward_ip;
}

