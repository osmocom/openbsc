/* A Media Gateway Control Protocol Media Gateway: RFC 3435 */
/* The protocol implementation */

/*
 * (C) 2009-2011 by Holger Hans Peter Freyther <zecke@selfish.org>
 * (C) 2009-2011 by On-Waves
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


#include <osmocom/core/talloc.h>

#include <openbsc/mgcp.h>
#include <openbsc/mgcp_internal.h>
#include <openbsc/vty.h>

#include <string.h>

#define RTCP_OMIT_STR "Drop RTCP packets in both directions\n"

static struct mgcp_config *g_cfg = NULL;

static struct mgcp_trunk_config *find_trunk(struct mgcp_config *cfg, int nr)
{
	struct mgcp_trunk_config *trunk;

	if (nr == 0)
		trunk = &cfg->trunk;
	else
		trunk = mgcp_trunk_num(cfg, nr);

	return trunk;
}

/*
 * vty code for mgcp below
 */
struct cmd_node mgcp_node = {
	MGCP_NODE,
	"%s(config-mgcp)# ",
	1,
};

struct cmd_node trunk_node = {
	TRUNK_NODE,
	"%s(config-mgcp-trunk)# ",
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

	if (g_cfg->bts_ports.mode == PORT_ALLOC_STATIC)
		vty_out(vty, "  rtp bts-base %u%s", g_cfg->bts_ports.base_port, VTY_NEWLINE);
	else
		vty_out(vty, "  rtp bts-range %u %u%s",
			g_cfg->bts_ports.range_start, g_cfg->bts_ports.range_end, VTY_NEWLINE);

	if (g_cfg->net_ports.mode == PORT_ALLOC_STATIC)
		vty_out(vty, "  rtp net-base %u%s", g_cfg->net_ports.base_port, VTY_NEWLINE);
	else
		vty_out(vty, "  rtp net-range %u %u%s",
			g_cfg->net_ports.range_start, g_cfg->net_ports.range_end, VTY_NEWLINE);

	vty_out(vty, "  rtp ip-dscp %d%s", g_cfg->endp_dscp, VTY_NEWLINE);
	if (g_cfg->trunk.omit_rtcp)
		vty_out(vty, "  rtcp-omit%s", VTY_NEWLINE);
	else
		vty_out(vty, "  no rtcp-omit%s", VTY_NEWLINE);
	if (g_cfg->trunk.audio_payload != -1)
		vty_out(vty, "  sdp audio-payload number %d%s",
			g_cfg->trunk.audio_payload, VTY_NEWLINE);
	if (g_cfg->trunk.audio_name)
		vty_out(vty, "  sdp audio-payload name %s%s",
			g_cfg->trunk.audio_name, VTY_NEWLINE);
	if (g_cfg->trunk.audio_fmtp_extra)
		vty_out(vty, "  sdp audio fmtp-extra %s%s",
			g_cfg->trunk.audio_fmtp_extra, VTY_NEWLINE);
	vty_out(vty, "  loop %u%s", !!g_cfg->trunk.audio_loop, VTY_NEWLINE);
	vty_out(vty, "  number endpoints %u%s", g_cfg->trunk.number_endpoints - 1, VTY_NEWLINE);
	if (g_cfg->call_agent_addr)
		vty_out(vty, "  call-agent ip %s%s", g_cfg->call_agent_addr, VTY_NEWLINE);
	if (g_cfg->transcoder_ip)
		vty_out(vty, "  transcoder-mgw %s%s", g_cfg->transcoder_ip, VTY_NEWLINE);

	if (g_cfg->transcoder_ports.mode == PORT_ALLOC_STATIC)
		vty_out(vty, "  rtp transcoder-base %u%s", g_cfg->transcoder_ports.base_port, VTY_NEWLINE);
	else
		vty_out(vty, "  rtp transcoder-range %u %u%s",
			g_cfg->transcoder_ports.range_start, g_cfg->transcoder_ports.range_end, VTY_NEWLINE);
	vty_out(vty, "  transcoder-remote-base %u%s", g_cfg->transcoder_remote_base, VTY_NEWLINE);

	return CMD_SUCCESS;
}

static void dump_trunk(struct vty *vty, struct mgcp_trunk_config *cfg, int verbose)
{
	int i;

	vty_out(vty, "%s trunk nr %d with %d endpoints:%s",
		cfg->trunk_type == MGCP_TRUNK_VIRTUAL ? "Virtual" : "E1",
		cfg->trunk_nr, cfg->number_endpoints - 1, VTY_NEWLINE);

	if (!cfg->endpoints) {
		vty_out(vty, "No endpoints allocated yet.%s", VTY_NEWLINE);
		return;
	}

	for (i = 1; i < cfg->number_endpoints; ++i) {
		struct mgcp_endpoint *endp = &cfg->endpoints[i];
		vty_out(vty,
			" Endpoint 0x%.2x: CI: %d net: %u/%u bts: %u/%u on %s "
			"traffic received bts: %u  remote: %u transcoder: %u/%u%s",
			i, endp->ci,
			ntohs(endp->net_end.rtp_port), ntohs(endp->net_end.rtcp_port),
			ntohs(endp->bts_end.rtp_port), ntohs(endp->bts_end.rtcp_port),
			inet_ntoa(endp->bts_end.addr),
			endp->bts_end.packets, endp->net_end.packets,
			endp->trans_net.packets, endp->trans_bts.packets,
			VTY_NEWLINE);

		if (verbose)
			vty_out(vty,
				"  Timestamp Errs: BTS %d->%d, Net %d->%d%s",
				endp->bts_state.in_stream.err_ts_counter,
				endp->bts_state.out_stream.err_ts_counter,
				endp->net_state.in_stream.err_ts_counter,
				endp->net_state.out_stream.err_ts_counter,
				VTY_NEWLINE);
	}
}

DEFUN(show_mcgp, show_mgcp_cmd,
      "show mgcp [stats]",
      SHOW_STR
      "Display information about the MGCP Media Gateway\n"
      "Include Statistics\n")
{
	struct mgcp_trunk_config *trunk;
	int show_stats = argc >= 1;

	dump_trunk(vty, &g_cfg->trunk, show_stats);

	llist_for_each_entry(trunk, &g_cfg->trunks, entry)
		dump_trunk(vty, trunk, show_stats);

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
      "Local options for the SDP record\n"
      IP_STR
      "IPv4 Address to use in SDP record\n")
{
	bsc_replace_string(g_cfg, &g_cfg->local_ip, argv[0]);
	return CMD_SUCCESS;
}

DEFUN(cfg_mgcp_bts_ip,
      cfg_mgcp_bts_ip_cmd,
      "bts ip A.B.C.D",
      "BTS Audio source/destination options\n"
      IP_STR
      "IPv4 Address of the BTS\n")
{
	bsc_replace_string(g_cfg, &g_cfg->bts_ip, argv[0]);
	inet_aton(g_cfg->bts_ip, &g_cfg->bts_in);
	return CMD_SUCCESS;
}

#define BIND_STR "Listen/Bind related socket option\n"
DEFUN(cfg_mgcp_bind_ip,
      cfg_mgcp_bind_ip_cmd,
      "bind ip A.B.C.D",
      BIND_STR
      IP_STR
      "IPv4 Address to bind to\n")
{
	bsc_replace_string(g_cfg, &g_cfg->source_addr, argv[0]);
	return CMD_SUCCESS;
}

DEFUN(cfg_mgcp_bind_port,
      cfg_mgcp_bind_port_cmd,
      "bind port <0-65534>",
      BIND_STR
      "Port information\n"
      "UDP port to listen for MGCP messages\n")
{
	unsigned int port = atoi(argv[0]);
	g_cfg->source_port = port;
	return CMD_SUCCESS;
}

DEFUN(cfg_mgcp_bind_early,
      cfg_mgcp_bind_early_cmd,
      "bind early (0|1)",
      BIND_STR
      "Bind local ports on start up\n"
      "Bind on demand\n" "Bind on startup\n")
{
	vty_out(vty, "bind early is deprecated, remove it from the config.\n");
	return CMD_WARNING;
}

static void parse_base(struct mgcp_port_range *range, const char **argv)
{
	unsigned int port = atoi(argv[0]);
	range->mode = PORT_ALLOC_STATIC;
	range->base_port = port;
}

static void parse_range(struct mgcp_port_range *range, const char **argv)
{
	range->mode = PORT_ALLOC_DYNAMIC;
	range->range_start = atoi(argv[0]);
	range->range_end = atoi(argv[1]);
	range->last_port = g_cfg->bts_ports.range_start;
}


#define RTP_STR "RTP configuration\n"
#define BTS_START_STR "First UDP port allocated for the BTS side\n"
#define NET_START_STR "First UDP port allocated for the NET side\n"
#define UDP_PORT_STR "UDP Port number\n"
DEFUN(cfg_mgcp_rtp_bts_base_port,
      cfg_mgcp_rtp_bts_base_port_cmd,
      "rtp bts-base <0-65534>",
      RTP_STR
      BTS_START_STR
      UDP_PORT_STR)
{
	parse_base(&g_cfg->bts_ports, argv);
	return CMD_SUCCESS;
}

#define RANGE_START_STR "Start of the range of ports\n"
#define RANGE_END_STR "End of the range of ports\n"
DEFUN(cfg_mgcp_rtp_bts_range,
      cfg_mgcp_rtp_bts_range_cmd,
      "rtp bts-range <0-65534> <0-65534>",
      RTP_STR "Range of ports to use for the BTS side\n"
      RANGE_START_STR RANGE_END_STR)
{
	parse_range(&g_cfg->bts_ports, argv);
	return CMD_SUCCESS;
}

DEFUN(cfg_mgcp_rtp_net_range,
      cfg_mgcp_rtp_net_range_cmd,
      "rtp net-range <0-65534> <0-65534>",
      RTP_STR "Range of ports to use for the NET side\n"
      RANGE_START_STR RANGE_END_STR)
{
	parse_range(&g_cfg->net_ports, argv);
	return CMD_SUCCESS;
}

DEFUN(cfg_mgcp_rtp_net_base_port,
      cfg_mgcp_rtp_net_base_port_cmd,
      "rtp net-base <0-65534>",
      RTP_STR NET_START_STR UDP_PORT_STR)
{
	parse_base(&g_cfg->net_ports, argv);
	return CMD_SUCCESS;
}

ALIAS_DEPRECATED(cfg_mgcp_rtp_bts_base_port, cfg_mgcp_rtp_base_port_cmd,
      "rtp base <0-65534>",
      RTP_STR BTS_START_STR UDP_PORT_STR)

DEFUN(cfg_mgcp_rtp_transcoder_range,
      cfg_mgcp_rtp_transcoder_range_cmd,
      "rtp transcoder-range <0-65534> <0-65534>",
      RTP_STR "Range of ports to use for the Transcoder\n"
      RANGE_START_STR RANGE_END_STR)
{
	parse_range(&g_cfg->transcoder_ports, argv);
	return CMD_SUCCESS;
}

DEFUN(cfg_mgcp_rtp_transcoder_base,
      cfg_mgcp_rtp_transcoder_base_cmd,
      "rtp transcoder-base <0-65534>",
      RTP_STR "First UDP port allocated for the Transcoder side\n"
      UDP_PORT_STR)
{
	parse_base(&g_cfg->transcoder_ports, argv);
	return CMD_SUCCESS;
}

DEFUN(cfg_mgcp_rtp_ip_dscp,
      cfg_mgcp_rtp_ip_dscp_cmd,
      "rtp ip-dscp <0-255>",
      RTP_STR
      "Apply IP_TOS to the audio stream\n" "The DSCP value\n")
{
	int dscp = atoi(argv[0]);
	g_cfg->endp_dscp = dscp;
	return CMD_SUCCESS;
}

ALIAS_DEPRECATED(cfg_mgcp_rtp_ip_dscp, cfg_mgcp_rtp_ip_tos_cmd,
      "rtp ip-tos <0-255>",
      RTP_STR
      "Apply IP_TOS to the audio stream\n" "The DSCP value\n")

DEFUN(cfg_mgcp_sdp_fmtp_extra,
      cfg_mgcp_sdp_fmtp_extra_cmd,
      "sdp audio fmtp-extra .NAME",
      "Add extra fmtp for the SDP file\n" "Audio\n" "Fmtp-extra\n"
      "Extra Information\n")
{
	char *txt = argv_concat(argv, argc, 0);
	if (!txt)
		return CMD_WARNING;

	bsc_replace_string(g_cfg, &g_cfg->trunk.audio_fmtp_extra, txt);
	talloc_free(txt);
	return CMD_SUCCESS;
}

#define SDP_STR "SDP File related options\n"
#define AUDIO_STR "Audio payload options\n"
DEFUN(cfg_mgcp_sdp_payload_number,
      cfg_mgcp_sdp_payload_number_cmd,
      "sdp audio-payload number <1-255>",
      SDP_STR AUDIO_STR
      "Number\n" "Payload number\n")
{
	unsigned int payload = atoi(argv[0]);
	g_cfg->trunk.audio_payload = payload;
	return CMD_SUCCESS;
}

ALIAS_DEPRECATED(cfg_mgcp_sdp_payload_number, cfg_mgcp_sdp_payload_number_cmd_old,
      "sdp audio payload number <1-255>",
      SDP_STR AUDIO_STR AUDIO_STR "Number\n" "Payload number\n")
      

DEFUN(cfg_mgcp_sdp_payload_name,
      cfg_mgcp_sdp_payload_name_cmd,
      "sdp audio-payload name NAME",
      SDP_STR AUDIO_STR "Name\n" "Payload name\n")
{
	bsc_replace_string(g_cfg, &g_cfg->trunk.audio_name, argv[0]);
	return CMD_SUCCESS;
}

ALIAS_DEPRECATED(cfg_mgcp_sdp_payload_name, cfg_mgcp_sdp_payload_name_cmd_old,
      "sdp audio payload name NAME",
      SDP_STR AUDIO_STR AUDIO_STR "Name\n" "Payload name\n")

DEFUN(cfg_mgcp_loop,
      cfg_mgcp_loop_cmd,
      "loop (0|1)",
      "Loop audio for all endpoints on main trunk\n"
      "Don't Loop\n" "Loop\n")
{
	g_cfg->trunk.audio_loop = atoi(argv[0]);
	return CMD_SUCCESS;
}

DEFUN(cfg_mgcp_number_endp,
      cfg_mgcp_number_endp_cmd,
      "number endpoints <0-65534>",
      "Number options\n" "Endpoints available\n" "Number endpoints\n")
{
	/* + 1 as we start counting at one */
	g_cfg->trunk.number_endpoints = atoi(argv[0]) + 1;
	return CMD_SUCCESS;
}

DEFUN(cfg_mgcp_omit_rtcp,
      cfg_mgcp_omit_rtcp_cmd,
      "rtcp-omit",
      RTCP_OMIT_STR)
{
	g_cfg->trunk.omit_rtcp = 1;
	return CMD_SUCCESS;
}

DEFUN(cfg_mgcp_no_omit_rtcp,
      cfg_mgcp_no_omit_rtcp_cmd,
      "no rtcp-omit",
      NO_STR RTCP_OMIT_STR)
{
	g_cfg->trunk.omit_rtcp = 0;
	return CMD_SUCCESS;
}

#define CALL_AGENT_STR "Callagent information\n"
DEFUN(cfg_mgcp_agent_addr,
      cfg_mgcp_agent_addr_cmd,
      "call-agent ip A.B.C.D",
      CALL_AGENT_STR IP_STR
      "IPv4 Address of the callagent\n")
{
	bsc_replace_string(g_cfg, &g_cfg->call_agent_addr, argv[0]);
	return CMD_SUCCESS;
}

ALIAS_DEPRECATED(cfg_mgcp_agent_addr, cfg_mgcp_agent_addr_cmd_old,
      "call agent ip A.B.C.D",
      CALL_AGENT_STR CALL_AGENT_STR IP_STR
      "IPv4 Address of the callagent\n")
      

DEFUN(cfg_mgcp_transcoder,
      cfg_mgcp_transcoder_cmd,
      "transcoder-mgw A.B.C.D",
      "Use a MGW to detranscoder RTP\n"
      "The IP address of the MGW")
{
	bsc_replace_string(g_cfg, &g_cfg->transcoder_ip, argv[0]);
	inet_aton(g_cfg->transcoder_ip, &g_cfg->transcoder_in);

	return CMD_SUCCESS;
}

DEFUN(cfg_mgcp_no_transcoder,
      cfg_mgcp_no_transcoder_cmd,
      "no transcoder-mgw",
      NO_STR "Disable the transcoding\n")
{
	if (g_cfg->transcoder_ip) {
		LOGP(DMGCP, LOGL_NOTICE, "Disabling transcoding on future calls.\n");
		talloc_free(g_cfg->transcoder_ip);
		g_cfg->transcoder_ip = NULL;
	}

	return CMD_SUCCESS;
}

DEFUN(cfg_mgcp_transcoder_remote_base,
      cfg_mgcp_transcoder_remote_base_cmd,
      "transcoder-remote-base <0-65534>",
      "Set the base port for the transcoder\n" "The RTP base port on the transcoder")
{
	g_cfg->transcoder_remote_base = atoi(argv[0]);
	return CMD_SUCCESS;
}

DEFUN(cfg_mgcp_trunk, cfg_mgcp_trunk_cmd,
      "trunk <1-64>",
      "Configure a SS7 trunk\n" "Trunk Nr\n")
{
	struct mgcp_trunk_config *trunk;
	int index = atoi(argv[0]);

	trunk = mgcp_trunk_num(g_cfg, index);
	if (!trunk)
		trunk = mgcp_trunk_alloc(g_cfg, index);

	if (!trunk) {
		vty_out(vty, "%%Unable to allocate trunk %u.%s",
			index, VTY_NEWLINE);
		return CMD_WARNING;
	}

	vty->node = TRUNK_NODE;
	vty->index = trunk;
	return CMD_SUCCESS;
}

static int config_write_trunk(struct vty *vty)
{
	struct mgcp_trunk_config *trunk;

	llist_for_each_entry(trunk, &g_cfg->trunks, entry) {
		vty_out(vty, " trunk %d%s", trunk->trunk_nr, VTY_NEWLINE);
		vty_out(vty, "  sdp audio-payload number %d%s",
			trunk->audio_payload, VTY_NEWLINE);
		vty_out(vty, "  sdp audio-payload name %s%s",
			trunk->audio_name, VTY_NEWLINE);
		vty_out(vty, "  loop %d%s",
			trunk->audio_loop, VTY_NEWLINE);
		if (trunk->omit_rtcp)
			vty_out(vty, "  rtcp-omit%s", VTY_NEWLINE);
		else
			vty_out(vty, "  no rtcp-omit%s", VTY_NEWLINE);
		if (trunk->audio_fmtp_extra)
			vty_out(vty, "   sdp audio fmtp-extra %s%s",
				trunk->audio_fmtp_extra, VTY_NEWLINE);
	}

	return CMD_SUCCESS;
}

DEFUN(cfg_trunk_sdp_fmtp_extra,
      cfg_trunk_sdp_fmtp_extra_cmd,
      "sdp audio fmtp-extra .NAME",
      "Add extra fmtp for the SDP file\n" "Audio\n" "Fmtp-extra\n"
      "Extra Information\n")
{
	struct mgcp_trunk_config *trunk = vty->index;
	char *txt = argv_concat(argv, argc, 0);
	if (!txt)
		return CMD_WARNING;

	bsc_replace_string(g_cfg, &trunk->audio_fmtp_extra, txt);
	talloc_free(txt);
	return CMD_SUCCESS;
}

DEFUN(cfg_trunk_payload_number,
      cfg_trunk_payload_number_cmd,
      "sdp audio-payload number <1-255>",
      SDP_STR AUDIO_STR "Number\n" "Payload Number\n")
{
	struct mgcp_trunk_config *trunk = vty->index;
	unsigned int payload = atoi(argv[0]);

	trunk->audio_payload = payload;
	return CMD_SUCCESS;
}

ALIAS_DEPRECATED(cfg_trunk_payload_number, cfg_trunk_payload_number_cmd_old,
      "sdp audio payload number <1-255>",
      SDP_STR AUDIO_STR AUDIO_STR "Number\n" "Payload Number\n")

DEFUN(cfg_trunk_payload_name,
      cfg_trunk_payload_name_cmd,
      "sdp audio-payload name NAME",
       SDP_STR AUDIO_STR "Payload\n" "Payload Name\n")
{
	struct mgcp_trunk_config *trunk = vty->index;

	bsc_replace_string(g_cfg, &trunk->audio_name, argv[0]);
	return CMD_SUCCESS;
}

ALIAS_DEPRECATED(cfg_trunk_payload_name, cfg_trunk_payload_name_cmd_old,
      "sdp audio payload name NAME",
       SDP_STR AUDIO_STR AUDIO_STR "Payload\n" "Payload Name\n")


DEFUN(cfg_trunk_loop,
      cfg_trunk_loop_cmd,
      "loop (0|1)",
      "Loop audio for all endpoints on this trunk\n"
      "Don't Loop\n" "Loop\n")
{
	struct mgcp_trunk_config *trunk = vty->index;

	trunk->audio_loop = atoi(argv[0]);
	return CMD_SUCCESS;
}

DEFUN(cfg_trunk_omit_rtcp,
      cfg_trunk_omit_rtcp_cmd,
      "rtcp-omit",
      RTCP_OMIT_STR)
{
	struct mgcp_trunk_config *trunk = vty->index;
	trunk->omit_rtcp = 1;
	return CMD_SUCCESS;
}

DEFUN(cfg_trunk_no_omit_rtcp,
      cfg_trunk_no_omit_rtcp_cmd,
      "no rtcp-omit",
      NO_STR RTCP_OMIT_STR)
{
	struct mgcp_trunk_config *trunk = vty->index;
	trunk->omit_rtcp = 0;
	return CMD_SUCCESS;
}

DEFUN(loop_endp,
      loop_endp_cmd,
      "loop-endpoint <0-64> NAME (0|1)",
      "Loop a given endpoint\n" "Trunk number\n"
      "The name in hex of the endpoint\n" "Disable the loop\n" "Enable the loop\n")
{
	struct mgcp_trunk_config *trunk;
	struct mgcp_endpoint *endp;

	trunk = find_trunk(g_cfg, atoi(argv[0]));
	if (!trunk) {
		vty_out(vty, "%%Trunk %d not found in the config.%s",
			atoi(argv[0]), VTY_NEWLINE);
		return CMD_WARNING;
	}

	if (!trunk->endpoints) {
		vty_out(vty, "%%Trunk %d has no endpoints allocated.%s",
			trunk->trunk_nr, VTY_NEWLINE);
		return CMD_WARNING;
	}

	int endp_no = strtoul(argv[1], NULL, 16);
	if (endp_no < 1 || endp_no >= trunk->number_endpoints) {
		vty_out(vty, "Loopback number %s/%d is invalid.%s",
		argv[1], endp_no, VTY_NEWLINE);
		return CMD_WARNING;
	}


	endp = &trunk->endpoints[endp_no];
	int loop = atoi(argv[2]);

	if (loop)
		endp->conn_mode = MGCP_CONN_LOOPBACK;
	else
		endp->conn_mode = endp->orig_mode;
	endp->allow_patch = 1;

	return CMD_SUCCESS;
}

DEFUN(tap_call,
      tap_call_cmd,
      "tap-call <0-64> ENDPOINT (bts-in|bts-out|net-in|net-out) A.B.C.D <0-65534>",
      "Forward data on endpoint to a different system\n" "Trunk number\n"
      "The endpoint in hex\n"
      "Forward the data coming from the bts\n"
      "Forward the data coming from the bts leaving to the network\n"
      "Forward the data coming from the net\n"
      "Forward the data coming from the net leaving to the bts\n"
      "destination IP of the data\n" "destination port\n")
{
	struct mgcp_rtp_tap *tap;
	struct mgcp_trunk_config *trunk;
	struct mgcp_endpoint *endp;
	int port = 0;

	trunk = find_trunk(g_cfg, atoi(argv[0]));
	if (!trunk) {
		vty_out(vty, "%%Trunk %d not found in the config.%s",
			atoi(argv[0]), VTY_NEWLINE);
		return CMD_WARNING;
	}

	if (!trunk->endpoints) {
		vty_out(vty, "%%Trunk %d has no endpoints allocated.%s",
			trunk->trunk_nr, VTY_NEWLINE);
		return CMD_WARNING;
	}

	int endp_no = strtoul(argv[1], NULL, 16);
	if (endp_no < 1 || endp_no >= trunk->number_endpoints) {
		vty_out(vty, "Endpoint number %s/%d is invalid.%s",
		argv[1], endp_no, VTY_NEWLINE);
		return CMD_WARNING;
	}

	endp = &trunk->endpoints[endp_no];

	if (strcmp(argv[2], "bts-in") == 0) {
		port = MGCP_TAP_BTS_IN;
	} else if (strcmp(argv[2], "bts-out") == 0) {
		port = MGCP_TAP_BTS_OUT;
	} else if (strcmp(argv[2], "net-in") == 0) {
		port = MGCP_TAP_NET_IN;
	} else if (strcmp(argv[2], "net-out") == 0) {
		port = MGCP_TAP_NET_OUT;
	} else {
		vty_out(vty, "Unknown mode... tricked vty?%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	tap = &endp->taps[port];
	memset(&tap->forward, 0, sizeof(tap->forward));
	inet_aton(argv[3], &tap->forward.sin_addr);
	tap->forward.sin_port = htons(atoi(argv[4]));
	tap->enabled = 1;
	return CMD_SUCCESS;
}

DEFUN(free_endp, free_endp_cmd,
      "free-endpoint <0-64> NUMBER",
      "Free the given endpoint\n" "Trunk number\n"
      "Endpoint number in hex.\n")
{
	struct mgcp_trunk_config *trunk;
	struct mgcp_endpoint *endp;

	trunk = find_trunk(g_cfg, atoi(argv[0]));
	if (!trunk) {
		vty_out(vty, "%%Trunk %d not found in the config.%s",
			atoi(argv[0]), VTY_NEWLINE);
		return CMD_WARNING;
	}

	if (!trunk->endpoints) {
		vty_out(vty, "%%Trunk %d has no endpoints allocated.%s",
			trunk->trunk_nr, VTY_NEWLINE);
		return CMD_WARNING;
	}

	int endp_no = strtoul(argv[1], NULL, 16);
	if (endp_no < 1 || endp_no >= trunk->number_endpoints) {
		vty_out(vty, "Endpoint number %s/%d is invalid.%s",
		argv[1], endp_no, VTY_NEWLINE);
		return CMD_WARNING;
	}

	endp = &trunk->endpoints[endp_no];
	mgcp_free_endp(endp);
	return CMD_SUCCESS;
}

DEFUN(reset_endp, reset_endp_cmd,
      "reset-endpoint <0-64> NUMBER",
      "Reset the given endpoint\n" "Trunk number\n"
      "Endpoint number in hex.\n")
{
	struct mgcp_trunk_config *trunk;
	struct mgcp_endpoint *endp;
	int endp_no, rc;

	trunk = find_trunk(g_cfg, atoi(argv[0]));
	if (!trunk) {
		vty_out(vty, "%%Trunk %d not found in the config.%s",
			atoi(argv[0]), VTY_NEWLINE);
		return CMD_WARNING;
	}

	if (!trunk->endpoints) {
		vty_out(vty, "%%Trunk %d has no endpoints allocated.%s",
			trunk->trunk_nr, VTY_NEWLINE);
		return CMD_WARNING;
	}

	endp_no = strtoul(argv[1], NULL, 16);
	if (endp_no < 1 || endp_no >= trunk->number_endpoints) {
		vty_out(vty, "Endpoint number %s/%d is invalid.%s",
		argv[1], endp_no, VTY_NEWLINE);
		return CMD_WARNING;
	}

	endp = &trunk->endpoints[endp_no];
	rc = mgcp_send_reset_ep(endp, ENDPOINT_NUMBER(endp));
	if (rc < 0) {
		vty_out(vty, "Error %d sending reset.%s", rc, VTY_NEWLINE);
		return CMD_WARNING;
	}
	return CMD_SUCCESS;
}

DEFUN(reset_all_endp, reset_all_endp_cmd,
      "reset-all-endpoints",
      "Reset all endpoints\n")
{
	int rc;

	rc = mgcp_send_reset_all(g_cfg);
	if (rc < 0) {
		vty_out(vty, "Error %d during endpoint reset.%s",
			rc, VTY_NEWLINE);
		return CMD_WARNING;
	}
	return CMD_SUCCESS;
}


int mgcp_vty_init(void)
{
	install_element_ve(&show_mgcp_cmd);
	install_element(ENABLE_NODE, &loop_endp_cmd);
	install_element(ENABLE_NODE, &tap_call_cmd);
	install_element(ENABLE_NODE, &free_endp_cmd);
	install_element(ENABLE_NODE, &reset_endp_cmd);
	install_element(ENABLE_NODE, &reset_all_endp_cmd);

	install_element(CONFIG_NODE, &cfg_mgcp_cmd);
	install_node(&mgcp_node, config_write_mgcp);

	vty_install_default(MGCP_NODE);
	install_element(MGCP_NODE, &cfg_mgcp_local_ip_cmd);
	install_element(MGCP_NODE, &cfg_mgcp_bts_ip_cmd);
	install_element(MGCP_NODE, &cfg_mgcp_bind_ip_cmd);
	install_element(MGCP_NODE, &cfg_mgcp_bind_port_cmd);
	install_element(MGCP_NODE, &cfg_mgcp_bind_early_cmd);
	install_element(MGCP_NODE, &cfg_mgcp_rtp_base_port_cmd);
	install_element(MGCP_NODE, &cfg_mgcp_rtp_bts_base_port_cmd);
	install_element(MGCP_NODE, &cfg_mgcp_rtp_net_base_port_cmd);
	install_element(MGCP_NODE, &cfg_mgcp_rtp_bts_range_cmd);
	install_element(MGCP_NODE, &cfg_mgcp_rtp_net_range_cmd);
	install_element(MGCP_NODE, &cfg_mgcp_rtp_transcoder_range_cmd);
	install_element(MGCP_NODE, &cfg_mgcp_rtp_transcoder_base_cmd);
	install_element(MGCP_NODE, &cfg_mgcp_rtp_ip_dscp_cmd);
	install_element(MGCP_NODE, &cfg_mgcp_rtp_ip_tos_cmd);
	install_element(MGCP_NODE, &cfg_mgcp_agent_addr_cmd);
	install_element(MGCP_NODE, &cfg_mgcp_agent_addr_cmd_old);
	install_element(MGCP_NODE, &cfg_mgcp_transcoder_cmd);
	install_element(MGCP_NODE, &cfg_mgcp_no_transcoder_cmd);
	install_element(MGCP_NODE, &cfg_mgcp_transcoder_remote_base_cmd);
	install_element(MGCP_NODE, &cfg_mgcp_sdp_payload_number_cmd);
	install_element(MGCP_NODE, &cfg_mgcp_sdp_payload_name_cmd);
	install_element(MGCP_NODE, &cfg_mgcp_sdp_payload_number_cmd_old);
	install_element(MGCP_NODE, &cfg_mgcp_sdp_payload_name_cmd_old);
	install_element(MGCP_NODE, &cfg_mgcp_loop_cmd);
	install_element(MGCP_NODE, &cfg_mgcp_number_endp_cmd);
	install_element(MGCP_NODE, &cfg_mgcp_omit_rtcp_cmd);
	install_element(MGCP_NODE, &cfg_mgcp_no_omit_rtcp_cmd);
	install_element(MGCP_NODE, &cfg_mgcp_sdp_fmtp_extra_cmd);

	install_element(MGCP_NODE, &cfg_mgcp_trunk_cmd);
	install_node(&trunk_node, config_write_trunk);
	vty_install_default(TRUNK_NODE);
	install_element(TRUNK_NODE, &cfg_trunk_payload_number_cmd);
	install_element(TRUNK_NODE, &cfg_trunk_payload_name_cmd);
	install_element(TRUNK_NODE, &cfg_trunk_payload_number_cmd_old);
	install_element(TRUNK_NODE, &cfg_trunk_payload_name_cmd_old);
	install_element(TRUNK_NODE, &cfg_trunk_loop_cmd);
	install_element(TRUNK_NODE, &cfg_trunk_omit_rtcp_cmd);
	install_element(TRUNK_NODE, &cfg_trunk_no_omit_rtcp_cmd);
	install_element(TRUNK_NODE, &cfg_trunk_sdp_fmtp_extra_cmd);

	return 0;
}

static int allocate_trunk(struct mgcp_trunk_config *trunk)
{
	int i;
	struct mgcp_config *cfg = trunk->cfg;

	if (mgcp_endpoints_allocate(trunk) != 0) {
		LOGP(DMGCP, LOGL_ERROR,
		     "Failed to allocate %d endpoints on trunk %d.\n",
		     trunk->number_endpoints, trunk->trunk_nr);
		return -1;
	}

	/* early bind */
	for (i = 1; i < trunk->number_endpoints; ++i) {
		struct mgcp_endpoint *endp = &trunk->endpoints[i];

		if (cfg->bts_ports.mode == PORT_ALLOC_STATIC) {
			cfg->last_bts_port += 2;
			if (mgcp_bind_bts_rtp_port(endp, cfg->last_bts_port) != 0) {
				LOGP(DMGCP, LOGL_FATAL,
				     "Failed to bind: %d\n", cfg->last_bts_port);
				return -1;
			}
			endp->bts_end.local_alloc = PORT_ALLOC_STATIC;
		}

		if (cfg->net_ports.mode == PORT_ALLOC_STATIC) {
			cfg->last_net_port += 2;
			if (mgcp_bind_net_rtp_port(endp, cfg->last_net_port) != 0) {
				LOGP(DMGCP, LOGL_FATAL,
				     "Failed to bind: %d\n", cfg->last_net_port);
				return -1;
			}
			endp->net_end.local_alloc = PORT_ALLOC_STATIC;
		}

		if (trunk->trunk_type == MGCP_TRUNK_VIRTUAL &&
		    cfg->transcoder_ip && cfg->transcoder_ports.mode == PORT_ALLOC_STATIC) {
			int rtp_port;

			/* network side */
			rtp_port = rtp_calculate_port(ENDPOINT_NUMBER(endp),
						      cfg->transcoder_ports.base_port);
			if (mgcp_bind_trans_net_rtp_port(endp, rtp_port) != 0) {
				LOGP(DMGCP, LOGL_FATAL, "Failed to bind: %d\n", rtp_port);
				return -1;
			}
			endp->trans_net.local_alloc = PORT_ALLOC_STATIC;

			/* bts side */
			rtp_port = rtp_calculate_port(endp_back_channel(ENDPOINT_NUMBER(endp)),
						      cfg->transcoder_ports.base_port);
			if (mgcp_bind_trans_bts_rtp_port(endp, rtp_port) != 0) {
				LOGP(DMGCP, LOGL_FATAL, "Failed to bind: %d\n", rtp_port);
				return -1;
			}
			endp->trans_bts.local_alloc = PORT_ALLOC_STATIC;
		}
	}

	return 0;
}

int mgcp_parse_config(const char *config_file, struct mgcp_config *cfg,
		      enum mgcp_role role)
{
	int rc;
	struct mgcp_trunk_config *trunk;

	g_cfg = cfg;
	rc = vty_read_config_file(config_file, NULL);
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

	/* initialize the last ports */
	g_cfg->last_bts_port = rtp_calculate_port(0, g_cfg->bts_ports.base_port);
	g_cfg->last_net_port = rtp_calculate_port(0, g_cfg->net_ports.base_port);

	if (allocate_trunk(&g_cfg->trunk) != 0) {
		LOGP(DMGCP, LOGL_ERROR, "Failed to initialize the virtual trunk.\n");
		return -1;
	}

	llist_for_each_entry(trunk, &g_cfg->trunks, entry) {
		if (allocate_trunk(trunk) != 0) {
			LOGP(DMGCP, LOGL_ERROR,
			     "Failed to initialize E1 trunk %d.\n", trunk->trunk_nr);
			return -1;
		}
	}
	cfg->role = role;

	return 0;
}

