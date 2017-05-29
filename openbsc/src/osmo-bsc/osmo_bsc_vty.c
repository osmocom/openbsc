/* Osmo BSC VTY Configuration */
/* (C) 2009-2015 by Holger Hans Peter Freyther
 * (C) 2009-2014 by On-Waves
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

#include <openbsc/gsm_data.h>
#include <openbsc/osmo_bsc.h>
#include <openbsc/bsc_msc_data.h>
#include <openbsc/vty.h>
#include <openbsc/bsc_subscriber.h>
#include <openbsc/debug.h>
#include <openbsc/bsc_msg_filter.h>

#include <osmocom/core/talloc.h>
#include <osmocom/vty/logging.h>

#include <time.h>


#define IPA_STR "IP.ACCESS specific\n"

extern struct gsm_network *bsc_gsmnet;

static struct osmo_bsc_data *osmo_bsc_data(struct vty *vty)
{
	return bsc_gsmnet->bsc_data;
}

static struct bsc_msc_data *bsc_msc_data(struct vty *vty)
{
	return vty->index;
}

static struct cmd_node bsc_node = {
	BSC_NODE,
	"%s(config-bsc)# ",
	1,
};

static struct cmd_node msc_node = {
	MSC_NODE,
	"%s(config-msc)# ",
	1,
};

DEFUN(cfg_net_msc, cfg_net_msc_cmd,
      "msc [<0-1000>]", "Configure MSC details\n" "MSC connection to configure\n")
{
	int index = argc == 1 ? atoi(argv[0]) : 0;
	struct bsc_msc_data *msc;

	msc = osmo_msc_data_alloc(bsc_gsmnet, index);
	if (!msc) {
		vty_out(vty, "%%Failed to allocate MSC data.%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	vty->index = msc;
	vty->node = MSC_NODE;
	return CMD_SUCCESS;
}

DEFUN(cfg_net_bsc, cfg_net_bsc_cmd,
      "bsc", "Configure BSC\n")
{
	vty->node = BSC_NODE;
	return CMD_SUCCESS;
}

static void write_msc_amr_options(struct vty *vty, struct bsc_msc_data *msc)
{
#define WRITE_AMR(vty, msc, name, var) \
	vty_out(vty, " amr-config %s %s%s", \
		name, msc->amr_conf.var ? "allowed" : "forbidden", \
		VTY_NEWLINE);

	WRITE_AMR(vty, msc, "12_2k", m12_2);
	WRITE_AMR(vty, msc, "10_2k", m10_2);
	WRITE_AMR(vty, msc, "7_95k", m7_95);
	WRITE_AMR(vty, msc, "7_40k", m7_40);
	WRITE_AMR(vty, msc, "6_70k", m6_70);
	WRITE_AMR(vty, msc, "5_90k", m5_90);
	WRITE_AMR(vty, msc, "5_15k", m5_15);
	WRITE_AMR(vty, msc, "4_75k", m4_75);
#undef WRITE_AMR
}

static void write_msc(struct vty *vty, struct bsc_msc_data *msc)
{
	struct bsc_msc_dest *dest;

	vty_out(vty, "msc %d%s", msc->nr, VTY_NEWLINE);
	if (msc->bsc_token)
		vty_out(vty, " token %s%s", msc->bsc_token, VTY_NEWLINE);
	if (msc->bsc_key_present)
		vty_out(vty, " auth-key %s%s",
			osmo_hexdump(msc->bsc_key, sizeof(msc->bsc_key)), VTY_NEWLINE);
	if (msc->core_mnc != -1)
		vty_out(vty, " core-mobile-network-code %d%s",
			msc->core_mnc, VTY_NEWLINE);
	if (msc->core_mcc != -1)
		vty_out(vty, " core-mobile-country-code %d%s",
			msc->core_mcc, VTY_NEWLINE);
	if (msc->core_lac != -1)
		vty_out(vty, " core-location-area-code %d%s",
			msc->core_lac, VTY_NEWLINE);
	if (msc->core_ci != -1)
		vty_out(vty, " core-cell-identity %d%s",
			msc->core_ci, VTY_NEWLINE);
	vty_out(vty, " ip.access rtp-base %d%s", msc->rtp_base, VTY_NEWLINE);

	if (msc->ping_timeout == -1)
		vty_out(vty, " no timeout-ping%s", VTY_NEWLINE);
	else {
		vty_out(vty, " timeout-ping %d%s", msc->ping_timeout, VTY_NEWLINE);
		vty_out(vty, " timeout-pong %d%s", msc->pong_timeout, VTY_NEWLINE);
		if (msc->advanced_ping)
			vty_out(vty, " timeout-ping advanced%s", VTY_NEWLINE);
		else
			vty_out(vty, " no timeout-ping advanced%s", VTY_NEWLINE);
	}

	if (msc->ussd_welcome_txt)
		vty_out(vty, " bsc-welcome-text %s%s", msc->ussd_welcome_txt, VTY_NEWLINE);
	else
		vty_out(vty, " no bsc-welcome-text%s", VTY_NEWLINE);

	if (msc->ussd_msc_lost_txt && msc->ussd_msc_lost_txt[0])
		vty_out(vty, " bsc-msc-lost-text %s%s", msc->ussd_msc_lost_txt, VTY_NEWLINE);
	else
		vty_out(vty, " no bsc-msc-lost-text%s", VTY_NEWLINE);

	if (msc->ussd_grace_txt && msc->ussd_grace_txt[0])
		vty_out(vty, " bsc-grace-text %s%s", msc->ussd_grace_txt, VTY_NEWLINE);
	else
		vty_out(vty, " no bsc-grace-text%s", VTY_NEWLINE);

	if (msc->audio_length != 0) {
		int i;

		vty_out(vty, " codec-list ");
		for (i = 0; i < msc->audio_length; ++i) {
			if (i != 0)
				vty_out(vty, " ");

			if (msc->audio_support[i]->hr)
				vty_out(vty, "hr%.1u", msc->audio_support[i]->ver);
			else
				vty_out(vty, "fr%.1u", msc->audio_support[i]->ver);
		}
		vty_out(vty, "%s", VTY_NEWLINE);

	}

	llist_for_each_entry(dest, &msc->dests, list)
		vty_out(vty, " dest %s %d %d%s", dest->ip, dest->port,
			dest->dscp, VTY_NEWLINE);

	vty_out(vty, " type %s%s", msc->type == MSC_CON_TYPE_NORMAL ?
					"normal" : "local", VTY_NEWLINE);
	vty_out(vty, " allow-emergency %s%s", msc->allow_emerg ?
					"allow" : "deny", VTY_NEWLINE);

	if (msc->local_pref)
		vty_out(vty, " local-prefix %s%s", msc->local_pref, VTY_NEWLINE);

	if (msc->acc_lst_name)
		vty_out(vty, " access-list-name %s%s", msc->acc_lst_name, VTY_NEWLINE);

	/* write amr options */
	write_msc_amr_options(vty, msc);
}

static int config_write_msc(struct vty *vty)
{
	struct bsc_msc_data *msc;
	struct osmo_bsc_data *bsc = osmo_bsc_data(vty);

	llist_for_each_entry(msc, &bsc->mscs, entry)
		write_msc(vty, msc);

	return CMD_SUCCESS;
}

static int config_write_bsc(struct vty *vty)
{
	struct osmo_bsc_data *bsc = osmo_bsc_data(vty);

	vty_out(vty, "bsc%s", VTY_NEWLINE);
	if (bsc->mid_call_txt)
		vty_out(vty, " mid-call-text %s%s", bsc->mid_call_txt, VTY_NEWLINE);
	vty_out(vty, " mid-call-timeout %d%s", bsc->mid_call_timeout, VTY_NEWLINE);
	if (bsc->rf_ctrl_name)
		vty_out(vty, " bsc-rf-socket %s%s",
			bsc->rf_ctrl_name, VTY_NEWLINE);

	if (bsc->auto_off_timeout != -1)
		vty_out(vty, " bsc-auto-rf-off %d%s",
			bsc->auto_off_timeout, VTY_NEWLINE);

	if (bsc->ussd_no_msc_txt && bsc->ussd_no_msc_txt[0])
		vty_out(vty, " missing-msc-text %s%s", bsc->ussd_no_msc_txt, VTY_NEWLINE);
	else
		vty_out(vty, " no missing-msc-text%s", VTY_NEWLINE);
	if (bsc->acc_lst_name)
		vty_out(vty, " access-list-name %s%s", bsc->acc_lst_name, VTY_NEWLINE);

	return CMD_SUCCESS;
}

DEFUN(cfg_net_bsc_token,
      cfg_net_bsc_token_cmd,
      "token TOKEN",
      "A token for the BSC to be sent to the MSC\n" "A token\n")
{
	struct bsc_msc_data *data = bsc_msc_data(vty);

	osmo_talloc_replace_string(osmo_bsc_data(vty), &data->bsc_token, argv[0]);
	return CMD_SUCCESS;
}

DEFUN(cfg_net_bsc_key,
      cfg_net_bsc_key_cmd,
      "auth-key KEY",
      "Authentication (secret) key configuration\n"
      "Security key\n")
{
	struct bsc_msc_data *data = bsc_msc_data(vty);

	osmo_hexparse(argv[0], data->bsc_key, sizeof(data->bsc_key));
	data->bsc_key_present = 1;
	return CMD_SUCCESS;
}

DEFUN(cfg_net_no_bsc_key, cfg_net_bsc_no_key_cmd,
      "no auth-key",
      NO_STR "Authentication (secret) key configuration\n")
{
	struct bsc_msc_data *data = bsc_msc_data(vty);

	memset(data->bsc_key, 0, sizeof(data->bsc_key));
	data->bsc_key_present = 0;
	return CMD_SUCCESS;
}

DEFUN(cfg_net_bsc_ncc,
      cfg_net_bsc_ncc_cmd,
      "core-mobile-network-code <1-999>",
      "Use this network code for the core network\n" "MNC value\n")
{
	struct bsc_msc_data *data = bsc_msc_data(vty);
	data->core_mnc = atoi(argv[0]);
	return CMD_SUCCESS;
}

DEFUN(cfg_net_bsc_mcc,
      cfg_net_bsc_mcc_cmd,
      "core-mobile-country-code <1-999>",
      "Use this country code for the core network\n" "MCC value\n")
{
	struct bsc_msc_data *data = bsc_msc_data(vty);
	data->core_mcc = atoi(argv[0]);
	return CMD_SUCCESS;
}

DEFUN(cfg_net_bsc_lac,
      cfg_net_bsc_lac_cmd,
      "core-location-area-code <0-65535>",
      "Use this location area code for the core network\n" "LAC value\n")
{
	struct bsc_msc_data *data = bsc_msc_data(vty);
	data->core_lac = atoi(argv[0]);
	return CMD_SUCCESS;
}

DEFUN(cfg_net_bsc_ci,
      cfg_net_bsc_ci_cmd,
      "core-cell-identity <0-65535>",
      "Use this cell identity for the core network\n" "CI value\n")
{
	struct bsc_msc_data *data = bsc_msc_data(vty);
	data->core_ci = atoi(argv[0]);
	return CMD_SUCCESS;
}

DEFUN(cfg_net_bsc_rtp_base,
      cfg_net_bsc_rtp_base_cmd,
      "ip.access rtp-base <1-65000>",
      IPA_STR
      "Set the rtp-base port for the RTP stream\n"
      "Port number\n")
{
	struct bsc_msc_data *data = bsc_msc_data(vty);
	data->rtp_base = atoi(argv[0]);
	return CMD_SUCCESS;
}

DEFUN(cfg_net_bsc_codec_list,
      cfg_net_bsc_codec_list_cmd,
      "codec-list .LIST",
      "Set the allowed audio codecs\n"
      "List of audio codecs, e.g. fr3 fr1 hr3\n")
{
	struct bsc_msc_data *data = bsc_msc_data(vty);
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
		talloc_zero_array(osmo_bsc_data(vty), struct gsm_audio_support *, argc);
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

DEFUN(cfg_net_msc_dest,
      cfg_net_msc_dest_cmd,
      "dest A.B.C.D <1-65000> <0-255>",
      "Add a destination to a MUX/MSC\n"
      "IP Address\n" "Port\n" "DSCP\n")
{
	struct bsc_msc_dest *dest;
	struct bsc_msc_data *data = bsc_msc_data(vty);

	dest = talloc_zero(osmo_bsc_data(vty), struct bsc_msc_dest);
	if (!dest) {
		vty_out(vty, "%%Failed to create structure.%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	dest->ip = talloc_strdup(dest, argv[0]);
	if (!dest->ip) {
		vty_out(vty, "%%Failed to copy dest ip.%s", VTY_NEWLINE);
		talloc_free(dest);
		return CMD_WARNING;
	}

	dest->port = atoi(argv[1]);
	dest->dscp = atoi(argv[2]);
	llist_add_tail(&dest->list, &data->dests);
	return CMD_SUCCESS;
}

DEFUN(cfg_net_msc_no_dest,
      cfg_net_msc_no_dest_cmd,
      "no dest A.B.C.D <1-65000> <0-255>",
      NO_STR "Remove a destination to a MUX/MSC\n"
      "IP Address\n" "Port\n" "DSCP\n")
{
	struct bsc_msc_dest *dest, *tmp;
	struct bsc_msc_data *data = bsc_msc_data(vty);

	int port = atoi(argv[1]);
	int dscp = atoi(argv[2]);

	llist_for_each_entry_safe(dest, tmp, &data->dests, list) {
		if (port != dest->port || dscp != dest->dscp
		    || strcmp(dest->ip, argv[0]) != 0)
			continue;

		llist_del(&dest->list);
		talloc_free(dest);
	}

	return CMD_SUCCESS;
}

DEFUN(cfg_net_msc_no_ping_time,
      cfg_net_msc_no_ping_time_cmd,
      "no timeout-ping",
      NO_STR "Disable the ping/pong handling on A-link\n")
{
	struct bsc_msc_data *data = bsc_msc_data(vty);
	data->ping_timeout = -1;
	return CMD_SUCCESS;
}

DEFUN(cfg_net_msc_ping_time,
      cfg_net_msc_ping_time_cmd,
      "timeout-ping <1-2147483647>",
      "Set the PING interval, negative for not sending PING\n"
      "Timeout in seconds\n")
{
	struct bsc_msc_data *data = bsc_msc_data(vty);
	data->ping_timeout = atoi(argv[0]);
	return CMD_SUCCESS;
}

DEFUN(cfg_net_msc_pong_time,
      cfg_net_msc_pong_time_cmd,
      "timeout-pong <1-2147483647>",
      "Set the time to wait for a PONG\n" "Timeout in seconds\n")
{
	struct bsc_msc_data *data = bsc_msc_data(vty);
	data->pong_timeout = atoi(argv[0]);
	return CMD_SUCCESS;
}

DEFUN(cfg_net_msc_advanced_ping,
      cfg_net_msc_advanced_ping_cmd,
      "timeout-ping advanced",
      "Ping timeout handling\nEnable advanced mode during SCCP\n")
{
	struct bsc_msc_data *data = bsc_msc_data(vty);

	if (data->ping_timeout == -1) {
		vty_out(vty, "%%ping handling is disabled. Enable it first.%s",
			VTY_NEWLINE);
		return CMD_WARNING;
	}

	data->advanced_ping = 1;
	return CMD_SUCCESS;
}

DEFUN(cfg_no_net_msc_advanced_ping,
      cfg_no_net_msc_advanced_ping_cmd,
      "no timeout-ping advanced",
      NO_STR "Ping timeout handling\nEnable advanced mode during SCCP\n")
{
	struct bsc_msc_data *data = bsc_msc_data(vty);
	data->advanced_ping = 0;
	return CMD_SUCCESS;
}

DEFUN(cfg_net_msc_welcome_ussd,
      cfg_net_msc_welcome_ussd_cmd,
      "bsc-welcome-text .TEXT",
      "Set the USSD notification to be sent\n" "Text to be sent\n")
{
	struct bsc_msc_data *data = bsc_msc_data(vty);
	char *str = argv_concat(argv, argc, 0);
	if (!str)
		return CMD_WARNING;

	osmo_talloc_replace_string(osmo_bsc_data(vty), &data->ussd_welcome_txt, str);
	talloc_free(str);
	return CMD_SUCCESS;
}

DEFUN(cfg_net_msc_no_welcome_ussd,
      cfg_net_msc_no_welcome_ussd_cmd,
      "no bsc-welcome-text",
      NO_STR "Clear the USSD notification to be sent\n")
{
	struct bsc_msc_data *data = bsc_msc_data(vty);

	talloc_free(data->ussd_welcome_txt);
	data->ussd_welcome_txt = NULL;

	return CMD_SUCCESS;
}

DEFUN(cfg_net_msc_lost_ussd,
      cfg_net_msc_lost_ussd_cmd,
      "bsc-msc-lost-text .TEXT",
      "Set the USSD notification to be sent on MSC connection loss\n" "Text to be sent\n")
{
	struct bsc_msc_data *data = bsc_msc_data(vty);
	char *str = argv_concat(argv, argc, 0);
	if (!str)
		return CMD_WARNING;

	osmo_talloc_replace_string(osmo_bsc_data(vty), &data->ussd_msc_lost_txt, str);
	talloc_free(str);
	return CMD_SUCCESS;
}

DEFUN(cfg_net_msc_no_lost_ussd,
      cfg_net_msc_no_lost_ussd_cmd,
      "no bsc-msc-lost-text",
      NO_STR "Clear the USSD notification to be sent on MSC connection loss\n")
{
	struct bsc_msc_data *data = bsc_msc_data(vty);

	talloc_free(data->ussd_msc_lost_txt);
	data->ussd_msc_lost_txt = 0;

	return CMD_SUCCESS;
}

DEFUN(cfg_net_msc_grace_ussd,
      cfg_net_msc_grace_ussd_cmd,
      "bsc-grace-text .TEXT",
      "Set the USSD notification to be sent when the MSC has entered the grace period\n" "Text to be sent\n")
{
	struct bsc_msc_data *data = bsc_msc_data(vty);
	char *str = argv_concat(argv, argc, 0);
	if (!str)
		return CMD_WARNING;

	osmo_talloc_replace_string(osmo_bsc_data(vty), &data->ussd_grace_txt, str);
	talloc_free(str);
	return CMD_SUCCESS;
}

DEFUN(cfg_net_msc_no_grace_ussd,
      cfg_net_msc_no_grace_ussd_cmd,
      "no bsc-grace-text",
      NO_STR "Clear the USSD notification to be sent when the MSC has entered the grace period\n")
{
	struct bsc_msc_data *data = bsc_msc_data(vty);

	talloc_free(data->ussd_grace_txt);
	data->ussd_grace_txt = NULL;

	return CMD_SUCCESS;
}

DEFUN(cfg_net_bsc_missing_msc_ussd,
      cfg_net_bsc_missing_msc_ussd_cmd,
      "missing-msc-text .TEXT",
      "Set the USSD notification to be send when a MSC has not been found.\n" "Text to be sent\n")
{
	struct osmo_bsc_data *data = osmo_bsc_data(vty);
	char *txt = argv_concat(argv, argc, 0);
	if (!txt)
		return CMD_WARNING;

	osmo_talloc_replace_string(data, &data->ussd_no_msc_txt, txt);
	talloc_free(txt);
	return CMD_SUCCESS;
}

DEFUN(cfg_net_bsc_no_missing_msc_text,
      cfg_net_bsc_no_missing_msc_text_cmd,
      "no missing-msc-text",
      NO_STR "Clear the USSD notification to be send when a MSC has not been found.\n")
{
	struct osmo_bsc_data *data = osmo_bsc_data(vty);

	talloc_free(data->ussd_no_msc_txt);
	data->ussd_no_msc_txt = 0;

	return CMD_SUCCESS;
}


DEFUN(cfg_net_msc_type,
      cfg_net_msc_type_cmd,
      "type (normal|local)",
      "Select the MSC type\n"
      "Plain GSM MSC\n" "Special MSC for local call routing\n")
{
	struct bsc_msc_data *data = bsc_msc_data(vty);

	if (strcmp(argv[0], "normal") == 0)
		data->type = MSC_CON_TYPE_NORMAL;
	else if (strcmp(argv[0], "local") == 0)
		data->type = MSC_CON_TYPE_LOCAL;

	return CMD_SUCCESS;
}

DEFUN(cfg_net_msc_emerg,
      cfg_net_msc_emerg_cmd,
      "allow-emergency (allow|deny)",
      "Allow CM ServiceRequests with type emergency\n"
      "Allow\n" "Deny\n")
{
	struct bsc_msc_data *data = bsc_msc_data(vty);
	data->allow_emerg = strcmp("allow", argv[0]) == 0;
	return CMD_SUCCESS;
}

DEFUN(cfg_net_msc_local_prefix,
      cfg_net_msc_local_prefix_cmd,
      "local-prefix REGEXP",
      "Prefix for local numbers\n" "REGEXP used\n")
{
	struct bsc_msc_data *msc = bsc_msc_data(vty);

	if (gsm_parse_reg(msc, &msc->local_pref_reg, &msc->local_pref, argc, argv) != 0) {
		vty_out(vty, "%%Failed to parse the regexp: '%s'%s",
			argv[0], VTY_NEWLINE);
		return CMD_WARNING;
	}

	return CMD_SUCCESS;
}

#define AMR_CONF_STR "AMR Multirate Configuration\n"
#define AMR_COMMAND(name) \
	DEFUN(cfg_net_msc_amr_##name,					\
	  cfg_net_msc_amr_##name##_cmd,					\
	  "amr-config " #name "k (allowed|forbidden)",			\
	  AMR_CONF_STR "Bitrate\n" "Allowed\n" "Forbidden\n")		\
{									\
	struct bsc_msc_data *msc = bsc_msc_data(vty);			\
									\
	msc->amr_conf.m##name = strcmp(argv[0], "allowed") == 0; 	\
	return CMD_SUCCESS;						\
}

AMR_COMMAND(12_2)
AMR_COMMAND(10_2)
AMR_COMMAND(7_95)
AMR_COMMAND(7_40)
AMR_COMMAND(6_70)
AMR_COMMAND(5_90)
AMR_COMMAND(5_15)
AMR_COMMAND(4_75)

DEFUN(cfg_msc_acc_lst_name,
      cfg_msc_acc_lst_name_cmd,
      "access-list-name NAME",
      "Set the name of the access list to use.\n"
      "The name of the to be used access list.")
{
	struct bsc_msc_data *msc = bsc_msc_data(vty);

	osmo_talloc_replace_string(msc, &msc->acc_lst_name, argv[0]);
	return CMD_SUCCESS;
}

DEFUN(cfg_msc_no_acc_lst_name,
      cfg_msc_no_acc_lst_name_cmd,
      "no access-list-name",
      NO_STR "Remove the access list from the NAT.\n")
{
	struct bsc_msc_data *msc = bsc_msc_data(vty);

	if (msc->acc_lst_name) {
		talloc_free(msc->acc_lst_name);
		msc->acc_lst_name = NULL;
	}

	return CMD_SUCCESS;
}

DEFUN(cfg_net_bsc_mid_call_text,
      cfg_net_bsc_mid_call_text_cmd,
      "mid-call-text .TEXT",
      "Set the USSD notification to be send.\n" "Text to be sent\n")
{
	struct osmo_bsc_data *data = osmo_bsc_data(vty);
	char *txt = argv_concat(argv, argc, 0);
	if (!txt)
		return CMD_WARNING;

	osmo_talloc_replace_string(data, &data->mid_call_txt, txt);
	talloc_free(txt);
	return CMD_SUCCESS;
}

DEFUN(cfg_net_bsc_mid_call_timeout,
      cfg_net_bsc_mid_call_timeout_cmd,
      "mid-call-timeout NR",
      "Switch from Grace to Off in NR seconds.\n" "Timeout in seconds\n")
{
	struct osmo_bsc_data *data = osmo_bsc_data(vty);
	data->mid_call_timeout = atoi(argv[0]);
	return CMD_SUCCESS;
}

DEFUN(cfg_net_rf_socket,
      cfg_net_rf_socket_cmd,
      "bsc-rf-socket PATH",
      "Set the filename for the RF control interface.\n" "RF Control path\n")
{
	struct osmo_bsc_data *data = osmo_bsc_data(vty);

	osmo_talloc_replace_string(data, &data->rf_ctrl_name, argv[0]);
	return CMD_SUCCESS;
}

DEFUN(cfg_net_rf_off_time,
      cfg_net_rf_off_time_cmd,
      "bsc-auto-rf-off <1-65000>",
      "Disable RF on MSC Connection\n" "Timeout\n")
{
	struct osmo_bsc_data *data = osmo_bsc_data(vty);
	data->auto_off_timeout = atoi(argv[0]);
	return CMD_SUCCESS;
}

DEFUN(cfg_net_no_rf_off_time,
      cfg_net_no_rf_off_time_cmd,
      "no bsc-auto-rf-off",
      NO_STR "Disable RF on MSC Connection\n")
{
	struct osmo_bsc_data *data = osmo_bsc_data(vty);
	data->auto_off_timeout = -1;
	return CMD_SUCCESS;
}

DEFUN(cfg_bsc_acc_lst_name,
      cfg_bsc_acc_lst_name_cmd,
      "access-list-name NAME",
      "Set the name of the access list to use.\n"
      "The name of the to be used access list.")
{
	struct osmo_bsc_data *bsc = osmo_bsc_data(vty);

	osmo_talloc_replace_string(bsc, &bsc->acc_lst_name, argv[0]);
	return CMD_SUCCESS;
}

DEFUN(cfg_bsc_no_acc_lst_name,
      cfg_bsc_no_acc_lst_name_cmd,
      "no access-list-name",
      NO_STR "Remove the access list from the BSC\n")
{
	struct osmo_bsc_data *bsc = osmo_bsc_data(vty);

	if (bsc->acc_lst_name) {
		talloc_free(bsc->acc_lst_name);
		bsc->acc_lst_name = NULL;
	}

	return CMD_SUCCESS;
}

DEFUN(show_statistics,
      show_statistics_cmd,
      "show statistics",
      SHOW_STR "Statistics about the BSC\n")
{
	openbsc_vty_print_statistics(vty, bsc_gsmnet);
	return CMD_SUCCESS;
}

DEFUN(show_mscs,
      show_mscs_cmd,
      "show mscs",
      SHOW_STR "MSC Connections and State\n")
{
	struct bsc_msc_data *msc;
	llist_for_each_entry(msc, &bsc_gsmnet->bsc_data->mscs, entry) {
		vty_out(vty, "MSC Nr: %d is connected: %d auth: %d.%s",
			msc->nr,
			msc->msc_con ? msc->msc_con->is_connected : -1,
			msc->msc_con ? msc->msc_con->is_authenticated : -1,
			VTY_NEWLINE);
	}

	return CMD_SUCCESS;
}

DEFUN(show_pos,
      show_pos_cmd,
      "show position",
      SHOW_STR "Position information of the BTS\n")
{
	struct gsm_bts *bts;
	struct bts_location *curloc;
	struct tm time;
	char timestr[50];

	llist_for_each_entry(bts, &bsc_gsmnet->bts_list, list) {
		if (llist_empty(&bts->loc_list)) {
			vty_out(vty, "BTS Nr: %d position invalid%s", bts->nr,
				VTY_NEWLINE);
			continue;
		}
		curloc = llist_entry(bts->loc_list.next, struct bts_location, list);
		if (gmtime_r(&curloc->tstamp, &time) == NULL) {
			vty_out(vty, "Time conversion failed for BTS %d%s", bts->nr,
				VTY_NEWLINE);
			continue;
		}
		if (asctime_r(&time, timestr) == NULL) {
			vty_out(vty, "Time conversion failed for BTS %d%s", bts->nr,
				VTY_NEWLINE);
			continue;
		}
		/* Last character in asctime is \n */
		timestr[strlen(timestr)-1] = 0;

		vty_out(vty, "BTS Nr: %d position: %s time: %s%s", bts->nr,
			get_value_string(bts_loc_fix_names, curloc->valid), timestr,
			VTY_NEWLINE);
		vty_out(vty, " lat: %f lon: %f height: %f%s", curloc->lat, curloc->lon,
			curloc->height, VTY_NEWLINE);
	}
	return CMD_SUCCESS;
}

DEFUN(gen_position_trap,
      gen_position_trap_cmd,
      "generate-location-state-trap <0-255>",
      "Generate location state report\n"
      "BTS to report\n")
{
	int bts_nr;
	struct gsm_bts *bts;
	struct gsm_network *net = bsc_gsmnet;

	bts_nr = atoi(argv[0]);
	if (bts_nr >= net->num_bts) {
		vty_out(vty, "%% can't find BTS '%s'%s", argv[0],
			VTY_NEWLINE);
		return CMD_WARNING;
	}

	bts = gsm_bts_num(net, bts_nr);
	bsc_gen_location_state_trap(bts);
	return CMD_SUCCESS;
}

DEFUN(logging_fltr_imsi,
      logging_fltr_imsi_cmd,
      "logging filter imsi IMSI",
	LOGGING_STR FILTER_STR
      "Filter log messages by IMSI\n" "IMSI to be used as filter\n")
{
	struct bsc_subscr *bsc_subscr;
	struct log_target *tgt = osmo_log_vty2tgt(vty);
	const char *imsi = argv[0];

	bsc_subscr = bsc_subscr_find_by_imsi(bsc_gsmnet->bsc_subscribers, imsi);

	if (!bsc_subscr) {
		vty_out(vty, "%%no subscriber with IMSI(%s)%s",
			imsi, VTY_NEWLINE);
		return CMD_WARNING;
	}

	log_set_filter_bsc_subscr(tgt, bsc_subscr);
	return CMD_SUCCESS;
}

int bsc_vty_init_extra(void)
{
	install_element(CONFIG_NODE, &cfg_net_msc_cmd);
	install_element(CONFIG_NODE, &cfg_net_bsc_cmd);

	install_node(&bsc_node, config_write_bsc);
	vty_install_default(BSC_NODE);
	install_element(BSC_NODE, &cfg_net_bsc_mid_call_text_cmd);
	install_element(BSC_NODE, &cfg_net_bsc_mid_call_timeout_cmd);
	install_element(BSC_NODE, &cfg_net_rf_socket_cmd);
	install_element(BSC_NODE, &cfg_net_rf_off_time_cmd);
	install_element(BSC_NODE, &cfg_net_no_rf_off_time_cmd);
	install_element(BSC_NODE, &cfg_net_bsc_missing_msc_ussd_cmd);
	install_element(BSC_NODE, &cfg_net_bsc_no_missing_msc_text_cmd);
	install_element(BSC_NODE, &cfg_bsc_acc_lst_name_cmd);
	install_element(BSC_NODE, &cfg_bsc_no_acc_lst_name_cmd);

	install_node(&msc_node, config_write_msc);
	vty_install_default(MSC_NODE);
	install_element(MSC_NODE, &cfg_net_bsc_token_cmd);
	install_element(MSC_NODE, &cfg_net_bsc_key_cmd);
	install_element(MSC_NODE, &cfg_net_bsc_no_key_cmd);
	install_element(MSC_NODE, &cfg_net_bsc_ncc_cmd);
	install_element(MSC_NODE, &cfg_net_bsc_mcc_cmd);
	install_element(MSC_NODE, &cfg_net_bsc_lac_cmd);
	install_element(MSC_NODE, &cfg_net_bsc_ci_cmd);
	install_element(MSC_NODE, &cfg_net_bsc_rtp_base_cmd);
	install_element(MSC_NODE, &cfg_net_bsc_codec_list_cmd);
	install_element(MSC_NODE, &cfg_net_msc_dest_cmd);
	install_element(MSC_NODE, &cfg_net_msc_no_dest_cmd);
	install_element(MSC_NODE, &cfg_net_msc_no_ping_time_cmd);
	install_element(MSC_NODE, &cfg_net_msc_ping_time_cmd);
	install_element(MSC_NODE, &cfg_net_msc_pong_time_cmd);
	install_element(MSC_NODE, &cfg_net_msc_advanced_ping_cmd);
	install_element(MSC_NODE, &cfg_no_net_msc_advanced_ping_cmd);
	install_element(MSC_NODE, &cfg_net_msc_welcome_ussd_cmd);
	install_element(MSC_NODE, &cfg_net_msc_no_welcome_ussd_cmd);
	install_element(MSC_NODE, &cfg_net_msc_lost_ussd_cmd);
	install_element(MSC_NODE, &cfg_net_msc_no_lost_ussd_cmd);
	install_element(MSC_NODE, &cfg_net_msc_grace_ussd_cmd);
	install_element(MSC_NODE, &cfg_net_msc_no_grace_ussd_cmd);
	install_element(MSC_NODE, &cfg_net_msc_type_cmd);
	install_element(MSC_NODE, &cfg_net_msc_emerg_cmd);
	install_element(MSC_NODE, &cfg_net_msc_local_prefix_cmd);
	install_element(MSC_NODE, &cfg_net_msc_amr_12_2_cmd);
	install_element(MSC_NODE, &cfg_net_msc_amr_10_2_cmd);
	install_element(MSC_NODE, &cfg_net_msc_amr_7_95_cmd);
	install_element(MSC_NODE, &cfg_net_msc_amr_7_40_cmd);
	install_element(MSC_NODE, &cfg_net_msc_amr_6_70_cmd);
	install_element(MSC_NODE, &cfg_net_msc_amr_5_90_cmd);
	install_element(MSC_NODE, &cfg_net_msc_amr_5_15_cmd);
	install_element(MSC_NODE, &cfg_net_msc_amr_4_75_cmd);
	install_element(MSC_NODE, &cfg_msc_acc_lst_name_cmd);
	install_element(MSC_NODE, &cfg_msc_no_acc_lst_name_cmd);

	install_element_ve(&show_statistics_cmd);
	install_element_ve(&show_mscs_cmd);
	install_element_ve(&show_pos_cmd);
	install_element_ve(&logging_fltr_imsi_cmd);

	install_element(ENABLE_NODE, &gen_position_trap_cmd);

	install_element(CFG_LOG_NODE, &logging_fltr_imsi_cmd);

	return 0;
}
