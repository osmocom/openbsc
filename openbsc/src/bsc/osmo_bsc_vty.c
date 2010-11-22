/* Osmo BSC VTY Configuration */
/* (C) 2009-2010 by Holger Hans Peter Freyther
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

#include <openbsc/gsm_data.h>
#include <openbsc/osmo_msc_data.h>
#include <openbsc/vty.h>

#include <osmocore/talloc.h>


#define IPA_STR "IP.ACCESS specific\n"

extern struct gsm_network *bsc_gsmnet;

static struct osmo_msc_data *osmo_msc_data(struct vty *vty)
{
	return bsc_gsmnet->msc_data;
}

static struct cmd_node msc_node = {
	MSC_NODE,
	"%s(msc)#",
	1,
};

DEFUN(cfg_net_msc, cfg_net_msc_cmd,
      "msc", "Configure MSC details")
{
	vty->index = bsc_gsmnet;
	vty->node = MSC_NODE;

	return CMD_SUCCESS;
}

static int config_write_msc(struct vty *vty)
{
	struct osmo_msc_data *data = osmo_msc_data(vty);

	vty_out(vty, " msc%s", VTY_NEWLINE);
	if (data->bsc_token)
		vty_out(vty, "  token %s%s", data->bsc_token, VTY_NEWLINE);
	if (data->core_ncc != -1)
		vty_out(vty, "  core-mobile-network-code %d%s",
			data->core_ncc, VTY_NEWLINE);
	if (data->core_mcc != -1)
		vty_out(vty, "  core-mobile-country-code %d%s",
			data->core_mcc, VTY_NEWLINE);
	vty_out(vty, "  ip.access rtp-base %d%s", data->rtp_base, VTY_NEWLINE);
	vty_out(vty, "  ip %s%s", data->msc_ip, VTY_NEWLINE);
	vty_out(vty, "  port %d%s", data->msc_port, VTY_NEWLINE);
	vty_out(vty, "  ip-dscp %d%s", data->msc_ip_dscp, VTY_NEWLINE);
	vty_out(vty, "  timeout-ping %d%s", data->ping_timeout, VTY_NEWLINE);
	vty_out(vty, "  timeout-pong %d%s", data->pong_timeout, VTY_NEWLINE);
	if (data->mid_call_txt)
		vty_out(vty, "mid-call-text %s%s", data->mid_call_txt, VTY_NEWLINE);
	vty_out(vty, " mid-call-timeout %d%s", data->mid_call_timeout, VTY_NEWLINE);

	if (data->audio_length != 0) {
		int i;

		vty_out(vty, " codec_list ");
		for (i = 0; i < data->audio_length; ++i) {
			if (i != 0)
				vty_out(vty, ", ");

			if (data->audio_support[i]->hr)
				vty_out(vty, "hr%.1u", data->audio_support[i]->ver);
			else
				vty_out(vty, "fr%.1u", data->audio_support[i]->ver);
		}
		vty_out(vty, "%s", VTY_NEWLINE);

	}

	return CMD_SUCCESS;
}

DEFUN(cfg_net_bsc_token,
      cfg_net_bsc_token_cmd,
      "token TOKEN",
      "A token for the BSC to be sent to the MSC")
{
	struct osmo_msc_data *data = osmo_msc_data(vty);

	bsc_replace_string(data, &data->bsc_token, argv[0]);
	return CMD_SUCCESS;
}

DEFUN(cfg_net_bsc_ncc,
      cfg_net_bsc_ncc_cmd,
      "core-mobile-network-code <0-255>",
      "Use this network code for the backbone\n" "NCC value\n")
{
	struct osmo_msc_data *data = osmo_msc_data(vty);
	data->core_ncc = atoi(argv[0]);
	return CMD_SUCCESS;
}

DEFUN(cfg_net_bsc_mcc,
      cfg_net_bsc_mcc_cmd,
      "core-mobile-country-code <0-255>",
      "Use this country code for the backbone\n" "MCC value\n")
{
	struct osmo_msc_data *data = osmo_msc_data(vty);
	data->core_mcc = atoi(argv[0]);
	return CMD_SUCCESS;
}

DEFUN(cfg_net_bsc_rtp_base,
      cfg_net_bsc_rtp_base_cmd,
      "ip.access rtp-base <1-65000>",
      IPA_STR
      "Set the rtp-base port for the RTP stream\n"
      "Port number\n")
{
	struct osmo_msc_data *data = osmo_msc_data(vty);
	data->rtp_base = atoi(argv[0]);
	return CMD_SUCCESS;
}

DEFUN(cfg_net_bsc_codec_list,
      cfg_net_bsc_codec_list_cmd,
      "codec-list .LIST",
      "Set the allowed audio codecs\n"
      "List of audio codecs\n")
{
	struct osmo_msc_data *data = osmo_msc_data(vty);
	int saw_fr, saw_hr;
	int i;

	saw_fr = saw_hr = 0;

	/* free the old list... if it exists */
	if (data->audio_support) {
		talloc_free(data->audio_support);
		data->audio_support = NULL;
		data->audio_length = 0;
	}

	/* create a new array */
	data->audio_support =
		talloc_zero_array(data, struct gsm_audio_support *, argc);
	data->audio_length = argc;

	for (i = 0; i < argc; ++i) {
		/* check for hrX or frX */
		if (strlen(argv[i]) != 3
				|| argv[i][1] != 'r'
				|| (argv[i][0] != 'h' && argv[i][0] != 'f')
				|| argv[i][2] < 0x30
				|| argv[i][2] > 0x39)
			goto error;

		data->audio_support[i] = talloc_zero(data->audio_support,
				struct gsm_audio_support);
		data->audio_support[i]->ver = atoi(argv[i] + 2);

		if (strncmp("hr", argv[i], 2) == 0) {
			data->audio_support[i]->hr = 1;
			saw_hr = 1;
		} else if (strncmp("fr", argv[i], 2) == 0) {
			data->audio_support[i]->hr = 0;
			saw_fr = 1;
		}

		if (saw_hr && saw_fr) {
			vty_out(vty, "Can not have full-rate and half-rate codec.%s",
					VTY_NEWLINE);
			return CMD_ERR_INCOMPLETE;
		}
	}

	return CMD_SUCCESS;

error:
	vty_out(vty, "Codec name must be hrX or frX. Was '%s'%s",
			argv[i], VTY_NEWLINE);
	return CMD_ERR_INCOMPLETE;
}

DEFUN(cfg_net_msc_ip,
      cfg_net_msc_ip_cmd,
      "ip A.B.C.D", "Set the MSC/MUX IP address.")
{
	struct osmo_msc_data *data = osmo_msc_data(vty);

	bsc_replace_string(data, &data->msc_ip, argv[0]);
	return CMD_SUCCESS;
}

DEFUN(cfg_net_msc_port,
      cfg_net_msc_port_cmd,
      "port <1-65000>",
      "Set the MSC/MUX port.")
{
	struct osmo_msc_data *data = osmo_msc_data(vty);
	data->msc_port = atoi(argv[0]);
	return CMD_SUCCESS;
}


DEFUN(cfg_net_msc_prio,
      cfg_net_msc_prio_cmd,
      "ip-dscp <0-255>",
      "Set the IP_TOS socket attribite")
{
	struct osmo_msc_data *data = osmo_msc_data(vty);
	data->msc_ip_dscp = atoi(argv[0]);
	return CMD_SUCCESS;
}

DEFUN(cfg_net_msc_ping_time,
      cfg_net_msc_ping_time_cmd,
      "timeout-ping NR",
      "Set the PING interval, negative for not sending PING")
{
	struct osmo_msc_data *data = osmo_msc_data(vty);
	data->ping_timeout = atoi(argv[0]);
	return CMD_SUCCESS;
}

DEFUN(cfg_net_msc_pong_time,
      cfg_net_msc_pong_time_cmd,
      "timeout-pong NR",
      "Set the time to wait for a PONG.")
{
	struct osmo_msc_data *data = osmo_msc_data(vty);
	data->pong_timeout = atoi(argv[0]);
	return CMD_SUCCESS;
}

DEFUN(cfg_net_msc_mid_call_text,
      cfg_net_msc_mid_call_text_cmd,
      "mid-call-text .TEXT",
      "Set the USSD notifcation to be send.\n" "Text to be sent\n")
{
	struct osmo_msc_data *data = osmo_msc_data(vty);
	char *txt = argv_concat(argv, argc, 0);
	if (!txt)
		return CMD_WARNING;

	bsc_replace_string(data, &data->mid_call_txt, txt);
	talloc_free(txt);
	return CMD_SUCCESS;
}

DEFUN(cfg_net_msc_mid_call_timeout,
      cfg_net_msc_mid_call_timeout_cmd,
      "mid-call-timeout NR",
      "Switch from Grace to Off in NR seconds.\n" "Timeout in seconds\n")
{
	struct osmo_msc_data *data = osmo_msc_data(vty);
	data->mid_call_timeout = atoi(argv[0]);
	return CMD_SUCCESS;
}


int bsc_vty_init_extra(void)
{
	install_element(GSMNET_NODE, &cfg_net_msc_cmd);
	install_node(&msc_node, config_write_msc);
	install_default(MSC_NODE);
	install_element(MSC_NODE, &cfg_net_bsc_token_cmd);
	install_element(MSC_NODE, &cfg_net_bsc_ncc_cmd);
	install_element(MSC_NODE, &cfg_net_bsc_mcc_cmd);
	install_element(MSC_NODE, &cfg_net_bsc_rtp_base_cmd);
	install_element(MSC_NODE, &cfg_net_bsc_codec_list_cmd);
	install_element(MSC_NODE, &cfg_net_msc_ip_cmd);
	install_element(MSC_NODE, &cfg_net_msc_port_cmd);
	install_element(MSC_NODE, &cfg_net_msc_prio_cmd);
	install_element(MSC_NODE, &cfg_net_msc_ping_time_cmd);
	install_element(MSC_NODE, &cfg_net_msc_pong_time_cmd);
	install_element(MSC_NODE, &cfg_net_msc_mid_call_text_cmd);
	install_element(MSC_NODE, &cfg_net_msc_mid_call_timeout_cmd);

	return 0;
}
