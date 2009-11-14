/* OpenBSC interface to quagga VTY */
/* (C) 2009 by Harald Welte <laforge@gnumonks.org>
 * (C) 2009 by Holger Hans Peter Freyther
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

#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>

#include <vty/command.h>
#include <vty/buffer.h>
#include <vty/vty.h>

#include <arpa/inet.h>

#include <openbsc/linuxlist.h>
#include <openbsc/gsm_data.h>
#include <openbsc/gsm_subscriber.h>
#include <openbsc/gsm_04_11.h>
#include <openbsc/e1_input.h>
#include <openbsc/abis_nm.h>
#include <openbsc/gsm_utils.h>
#include <openbsc/db.h>
#include <openbsc/talloc.h>
#include <openbsc/signal.h>

/* forward declarations */
void subscr_dump_vty(struct vty *vty, struct gsm_subscriber *subscr);

static struct gsm_network *gsmnet;

struct cmd_node subscr_node = {
	SUBSCR_NODE,
	"%s(subscriber)#",
	1,
};

static int dummy_config_write(struct vty *v)
{
	return CMD_SUCCESS;
}

static struct buffer *argv_to_buffer(int argc, const char *argv[], int base)
{
	struct buffer *b = buffer_new(1024);
	int i;

	if (!b)
		return NULL;

	for (i = base; i < argc; i++) {
		buffer_putstr(b, argv[i]);
		buffer_putc(b, ' ');
	}
	buffer_putc(b, '\0');

	return b;
}

/* per-subscriber configuration */
DEFUN(cfg_subscr,
      cfg_subscr_cmd,
      "subscriber IMSI",
      "Select a Subscriber to configure\n")
{
	const char *imsi = argv[0];
	struct gsm_subscriber *subscr;

	subscr = subscr_get_by_imsi(gsmnet, imsi);
	if (!subscr) {
		vty_out(vty, "%% No subscriber for IMSI %s%s",
			imsi, VTY_NEWLINE);
		return CMD_WARNING;
	}

	/* vty_go_parent should put this subscriber */
	vty->index = subscr;
	vty->node = SUBSCR_NODE;

	return CMD_SUCCESS;
}

/* Subscriber */
DEFUN(show_subscr,
      show_subscr_cmd,
      "show subscriber [IMSI]",
	SHOW_STR "Display information about a subscriber\n")
{
	const char *imsi;
	struct gsm_subscriber *subscr;

	if (argc >= 1) {
		imsi = argv[0];
		subscr = subscr_get_by_imsi(gsmnet, imsi);
		if (!subscr) {
			vty_out(vty, "%% unknown subscriber%s",
				VTY_NEWLINE);
			return CMD_WARNING;
		}
		subscr_dump_vty(vty, subscr);
		subscr_put(subscr);

		return CMD_SUCCESS;
	}

	/* FIXME: iterate over all subscribers ? */
	return CMD_WARNING;

	return CMD_SUCCESS;
}

DEFUN(show_subscr_cache,
      show_subscr_cache_cmd,
      "show subscriber cache",
	SHOW_STR "Display contents of subscriber cache\n")
{
	struct gsm_subscriber *subscr;

	llist_for_each_entry(subscr, &active_subscribers, entry) {
		vty_out(vty, "  Subscriber:%s", VTY_NEWLINE);
		subscr_dump_vty(vty, subscr);
	}

	return CMD_SUCCESS;
}

DEFUN(sms_send_pend,
      sms_send_pend_cmd,
      "sms send pending MIN_ID",
      "Send all pending SMS starting from MIN_ID")
{
	struct gsm_sms *sms;
	int id = atoi(argv[0]);

	while (1) {
		sms = db_sms_get_unsent(gsmnet, id++);
		if (!sms)
			return CMD_WARNING;

		if (!sms->receiver) {
			sms_free(sms);
			continue;
		}

		gsm411_send_sms_subscr(sms->receiver, sms);
	}

	return CMD_SUCCESS;
}

struct gsm_sms *sms_from_text(struct gsm_subscriber *receiver, const char *text)
{
	struct gsm_sms *sms = sms_alloc();

	if (!sms)
		return NULL;

	if (!receiver->lac) {
		/* subscriber currently not attached, store in database? */
		return NULL;
	}

	sms->receiver = subscr_get(receiver);
	strncpy(sms->text, text, sizeof(sms->text)-1);

	/* FIXME: don't use ID 1 static */
	sms->sender = subscr_get_by_id(gsmnet, 1);
	sms->reply_path_req = 0;
	sms->status_rep_req = 0;
	sms->ud_hdr_ind = 0;
	sms->protocol_id = 0; /* implicit */
	sms->data_coding_scheme = 0; /* default 7bit */
	strncpy(sms->dest_addr, receiver->extension, sizeof(sms->dest_addr)-1);
	/* Generate user_data */
	sms->user_data_len = gsm_7bit_encode(sms->user_data, sms->text);

	return sms;
}

static int _send_sms_buffer(struct gsm_subscriber *receiver,
			     struct buffer *b, u_int8_t tp_pid)
{
	struct gsm_sms *sms;

	sms = sms_from_text(receiver, buffer_getstr(b));
	sms->protocol_id = tp_pid;
	gsm411_send_sms_subscr(receiver, sms);

	return CMD_SUCCESS;
}

static struct gsm_subscriber *get_subscr_by_argv(const char *type,
						 const char *id)
{
	if (!strcmp(type, "extension"))
		return subscr_get_by_extension(gsmnet, id);
	else if (!strcmp(type, "imsi"))
		return subscr_get_by_imsi(gsmnet, id);
	else if (!strcmp(type, "tmsi"))
		return subscr_get_by_tmsi(gsmnet, atoi(id));
	else if (!strcmp(type, "id"))
		return subscr_get_by_id(gsmnet, atoi(id));

	return NULL;
}
#define SUBSCR_TYPES "(extension|imsi|tmsi|id)"

DEFUN(subscriber_send_sms,
      subscriber_send_sms_cmd,
      "subscriber " SUBSCR_TYPES " EXTEN sms send .LINE",
      "Select subscriber based on extension")
{
	struct gsm_subscriber *subscr = get_subscr_by_argv(argv[0], argv[1]);
	struct buffer *b;
	int rc;

	if (!subscr)
		return CMD_WARNING;

	b = argv_to_buffer(argc, argv, 2);
	rc = _send_sms_buffer(subscr, b, 0);
	buffer_free(b);

	return rc;
}

DEFUN(subscriber_silent_sms,
      subscriber_silent_sms_cmd,
      "subscriber " SUBSCR_TYPES " EXTEN silent sms send .LINE",
      "Select subscriber based on extension")
{
	struct gsm_subscriber *subscr = get_subscr_by_argv(argv[0], argv[1]);
	struct buffer *b;
	int rc;

	if (!subscr)
		return CMD_WARNING;

	b = argv_to_buffer(argc, argv, 2);
	rc = _send_sms_buffer(subscr, b, 0);
	buffer_free(b);

	return rc;
}

DEFUN(subscriber_silent_call,
      subscriber_silent_call_cmd,
      "subscriber " SUBSCR_TYPES " EXTEN silent call (start|stop)",
      "Send a silent call to a subscriber")
{
	struct gsm_subscriber *subscr = get_subscr_by_argv(argv[0], argv[1]);
	int rc;

	if (!subscr) {
		vty_out(vty, "%% No subscriber found for %s %s%s",
			argv[0], argv[1]);
		return CMD_WARNING;
	}

	if (!strcmp(argv[2], "start")) {
		rc = gsm_silent_call_start(subscr, vty);
		if (rc <= 0) {
			vty_out(vty, "%% Subscriber not attached%s",
				VTY_NEWLINE);
			return CMD_WARNING;
		}
	} else {
		rc = gsm_silent_call_stop(subscr);
		if (rc < 0)
			return CMD_WARNING;
	}

	subscr_put(subscr);

	return CMD_SUCCESS;
}

DEFUN(cfg_subscr_name,
      cfg_subscr_name_cmd,
      "name NAME",
      "Set the name of the subscriber")
{
	const char *name = argv[0];
	struct gsm_subscriber *subscr = vty->index;

	strncpy(subscr->name, name, sizeof(subscr->name));

	db_sync_subscriber(subscr);

	return CMD_SUCCESS;
}

DEFUN(cfg_subscr_extension,
      cfg_subscr_extension_cmd,
      "extension EXTENSION",
      "Set the extension of the subscriber")
{
	const char *name = argv[0];
	struct gsm_subscriber *subscr = vty->index;

	strncpy(subscr->extension, name, sizeof(subscr->extension));

	db_sync_subscriber(subscr);

	return CMD_SUCCESS;
}

DEFUN(cfg_subscr_authorized,
      cfg_subscr_authorized_cmd,
      "auth <0-1>",
      "Set the authorization status of the subscriber")
{
	int auth = atoi(argv[0]);
	struct gsm_subscriber *subscr = vty->index;

	if (auth)
		subscr->authorized = 1;
	else
		subscr->authorized = 0;

	db_sync_subscriber(subscr);

	return CMD_SUCCESS;
}

static int scall_cbfn(unsigned int subsys, unsigned int signal,
			void *handler_data, void *signal_data)
{
	struct scall_signal_data *sigdata = signal_data;
	struct vty *vty = sigdata->data;

	switch (signal) {
	case S_SCALL_SUCCESS:
		vty_out(vty, "%% silent call on ARFCN %u timeslot %u%s",
			sigdata->lchan->ts->trx->arfcn, sigdata->lchan->ts->nr,
			VTY_NEWLINE);
		break;
	case S_SCALL_EXPIRED:
		vty_out(vty, "%% silent call expired paging%s", VTY_NEWLINE);
		break;
	}
	return 0;
}

int bsc_vty_init_extra(struct gsm_network *net)
{
	gsmnet = net;

	register_signal_handler(SS_SCALL, scall_cbfn, NULL);

	install_element(VIEW_NODE, &show_subscr_cmd);
	install_element(VIEW_NODE, &show_subscr_cache_cmd);

	install_element(VIEW_NODE, &sms_send_pend_cmd);

	install_element(VIEW_NODE, &subscriber_send_sms_cmd);
	install_element(VIEW_NODE, &subscriber_silent_sms_cmd);
	install_element(VIEW_NODE, &subscriber_silent_call_cmd);

	install_element(CONFIG_NODE, &cfg_subscr_cmd);
	install_node(&subscr_node, dummy_config_write);

	install_default(SUBSCR_NODE);
	install_element(SUBSCR_NODE, &cfg_subscr_name_cmd);
	install_element(SUBSCR_NODE, &cfg_subscr_extension_cmd);
	install_element(SUBSCR_NODE, &cfg_subscr_authorized_cmd);

	return 0;
}
