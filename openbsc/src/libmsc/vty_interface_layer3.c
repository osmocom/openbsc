/* OpenBSC interface to quagga VTY */
/* (C) 2009 by Harald Welte <laforge@gnumonks.org>
 * (C) 2009 by Holger Hans Peter Freyther
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

#include <stdlib.h>
#include <limits.h>
#include <unistd.h>
#include <sys/types.h>

#include <osmocom/vty/command.h>
#include <osmocom/vty/buffer.h>
#include <osmocom/vty/vty.h>

#include <arpa/inet.h>

#include <osmocore/linuxlist.h>
#include <openbsc/gsm_data.h>
#include <openbsc/gsm_subscriber.h>
#include <openbsc/silent_call.h>
#include <openbsc/gsm_04_11.h>
#include <openbsc/e1_input.h>
#include <openbsc/abis_nm.h>
#include <osmocore/gsm_utils.h>
#include <osmocore/utils.h>
#include <openbsc/db.h>
#include <osmocore/talloc.h>
#include <openbsc/signal.h>
#include <openbsc/debug.h>
#include <openbsc/vty.h>
#include <openbsc/gsm_04_80.h>
#include <openbsc/chan_alloc.h>
#include <openbsc/sms_queue.h>

extern struct gsm_network *gsmnet_from_vty(struct vty *v);

static void subscr_dump_full_vty(struct vty *vty, struct gsm_subscriber *subscr, int pending)
{
	int rc;
	struct gsm_auth_info ainfo;
	struct gsm_auth_tuple atuple;

	vty_out(vty, "    ID: %llu, Authorized: %d%s", subscr->id,
		subscr->authorized, VTY_NEWLINE);
	if (subscr->name)
		vty_out(vty, "    Name: '%s'%s", subscr->name, VTY_NEWLINE);
	if (subscr->extension)
		vty_out(vty, "    Extension: %s%s", subscr->extension,
			VTY_NEWLINE);
	vty_out(vty, "    LAC: %d/0x%x%s",
		subscr->lac, subscr->lac, VTY_NEWLINE);
	if (subscr->imsi)
		vty_out(vty, "    IMSI: %s%s", subscr->imsi, VTY_NEWLINE);
	if (subscr->tmsi != GSM_RESERVED_TMSI)
		vty_out(vty, "    TMSI: %08X%s", subscr->tmsi,
			VTY_NEWLINE);

	rc = db_get_authinfo_for_subscr(&ainfo, subscr);
	if (!rc) {
		vty_out(vty, "    A3A8 algorithm id: %d%s",
			ainfo.auth_algo, VTY_NEWLINE);
		vty_out(vty, "    A3A8 Ki: %s%s",
			hexdump(ainfo.a3a8_ki, ainfo.a3a8_ki_len),
			VTY_NEWLINE);
	}

	rc = db_get_lastauthtuple_for_subscr(&atuple, subscr);
	if (!rc) {
		vty_out(vty, "    A3A8 last tuple (used %d times):%s",
			atuple.use_count, VTY_NEWLINE);
		vty_out(vty, "     seq # : %d%s",
			atuple.key_seq, VTY_NEWLINE);
		vty_out(vty, "     RAND  : %s%s",
			hexdump(atuple.rand, sizeof(atuple.rand)),
			VTY_NEWLINE);
		vty_out(vty, "     SRES  : %s%s",
			hexdump(atuple.sres, sizeof(atuple.sres)),
			VTY_NEWLINE);
		vty_out(vty, "     Kc    : %s%s",
			hexdump(atuple.kc, sizeof(atuple.kc)),
			VTY_NEWLINE);
	}
	if (pending)
		vty_out(vty, "    Pending: %d%s",
			subscr_pending_requests(subscr), VTY_NEWLINE);

	vty_out(vty, "    Use count: %u%s", subscr->use_count, VTY_NEWLINE);
}


/* Subscriber */
DEFUN(show_subscr_cache,
      show_subscr_cache_cmd,
      "show subscriber cache",
	SHOW_STR "Display contents of subscriber cache\n")
{
	struct gsm_subscriber *subscr;

	llist_for_each_entry(subscr, &active_subscribers, entry) {
		vty_out(vty, "  Subscriber:%s", VTY_NEWLINE);
		subscr_dump_full_vty(vty, subscr, 0);
	}

	return CMD_SUCCESS;
}

DEFUN(sms_send_pend,
      sms_send_pend_cmd,
      "sms send pending",
      "Send all pending SMS")
{
	struct gsm_network *gsmnet = gsmnet_from_vty(vty);
	struct gsm_sms *sms;
	int id = 0;

	while (1) {
		sms = db_sms_get_unsent_by_subscr(gsmnet, id, UINT_MAX);
		if (!sms)
			break;

		gsm411_send_sms_subscr(sms->receiver, sms);

		id = sms->receiver->id + 1;
	}

	return CMD_SUCCESS;
}

static int _send_sms_str(struct gsm_subscriber *receiver, char *str,
			 u_int8_t tp_pid)
{
	struct gsm_sms *sms;

	sms = sms_from_text(receiver, 0, str);
	sms->protocol_id = tp_pid;

	/* store in database for the queue */
	if (db_sms_store(sms) != 0) {
		LOGP(DSMS, LOGL_ERROR, "Failed to store SMS in Database\n");
		sms_free(sms);
		return CMD_WARNING;
	}

	sms_free(sms);
	sms_queue_trigger(receiver->net->sms_queue);
	return CMD_SUCCESS;
}

static struct gsm_subscriber *get_subscr_by_argv(struct gsm_network *gsmnet,
						 const char *type,
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
#define SUBSCR_HELP "Operations on a Subscriber\n"			\
	"Identify subscriber by his extension (phone number)\n"		\
	"Identify subscriber by his IMSI\n"				\
	"Identify subscriber by his TMSI\n"				\
	"Identify subscriber by his database ID\n"			\
	"Identifier for the subscriber\n"

DEFUN(show_subscr,
      show_subscr_cmd,
      "show subscriber " SUBSCR_TYPES " ID",
	SHOW_STR SUBSCR_HELP)
{
	struct gsm_network *gsmnet = gsmnet_from_vty(vty);
	struct gsm_subscriber *subscr =
				get_subscr_by_argv(gsmnet, argv[0], argv[1]);

	if (!subscr) {
		vty_out(vty, "%% No subscriber found for %s %s%s",
			argv[0], argv[1], VTY_NEWLINE);
		return CMD_WARNING;
	}

	subscr_dump_full_vty(vty, subscr, 1);

	subscr_put(subscr);

	return CMD_SUCCESS;
}

DEFUN(subscriber_send_pending_sms,
      subscriber_send_pending_sms_cmd,
      "subscriber " SUBSCR_TYPES " ID sms pending send",
	SUBSCR_HELP "SMS Operations\n" "Send pending SMS\n")
{
	struct gsm_network *gsmnet = gsmnet_from_vty(vty);
	struct gsm_subscriber *subscr = get_subscr_by_argv(gsmnet, argv[0], argv[1]);
	struct gsm_sms *sms;

	sms = db_sms_get_unsent_by_subscr(gsmnet, subscr->id, UINT_MAX);
	if (sms)
		gsm411_send_sms_subscr(sms->receiver, sms);

	subscr_put(subscr);

	return CMD_SUCCESS;
}

DEFUN(subscriber_send_sms,
      subscriber_send_sms_cmd,
      "subscriber " SUBSCR_TYPES " ID sms send .LINE",
	SUBSCR_HELP "SMS Operations\n" "Send SMS\n" "Actual SMS Text")
{
	struct gsm_network *gsmnet = gsmnet_from_vty(vty);
	struct gsm_subscriber *subscr = get_subscr_by_argv(gsmnet, argv[0], argv[1]);
	char *str;
	int rc;

	if (!subscr) {
		vty_out(vty, "%% No subscriber found for %s %s%s",
			argv[0], argv[1], VTY_NEWLINE);
		return CMD_WARNING;
	}
	str = argv_concat(argv, argc, 2);
	rc = _send_sms_str(subscr, str, 0);
	talloc_free(str);

	subscr_put(subscr);

	return rc;
}

DEFUN(subscriber_silent_sms,
      subscriber_silent_sms_cmd,
      "subscriber " SUBSCR_TYPES " ID silent-sms send .LINE",
	SUBSCR_HELP
	"Silent SMS Operation\n" "Send Silent SMS\n" "Actual SMS text\n")
{
	struct gsm_network *gsmnet = gsmnet_from_vty(vty);
	struct gsm_subscriber *subscr = get_subscr_by_argv(gsmnet, argv[0], argv[1]);
	char *str;
	int rc;

	if (!subscr) {
		vty_out(vty, "%% No subscriber found for %s %s%s",
			argv[0], argv[1], VTY_NEWLINE);
		return CMD_WARNING;
	}

	str = argv_concat(argv, argc, 2);
	rc = _send_sms_str(subscr, str, 64);
	talloc_free(str);

	subscr_put(subscr);

	return rc;
}

#define CHAN_TYPES "(any|tch/f|tch/any|sdcch)"
#define CHAN_TYPE_HELP 			\
		"Any channel\n"		\
		"TCH/F channel\n"	\
		"Any TCH channel\n"	\
		"SDCCH channel\n"

DEFUN(subscriber_silent_call_start,
      subscriber_silent_call_start_cmd,
      "subscriber " SUBSCR_TYPES " ID silent-call start (any|tch/f|tch/any|sdcch)",
	SUBSCR_HELP "Silent call operation\n" "Start silent call\n"
	CHAN_TYPE_HELP)
{
	struct gsm_network *gsmnet = gsmnet_from_vty(vty);
	struct gsm_subscriber *subscr = get_subscr_by_argv(gsmnet, argv[0], argv[1]);
	int rc, type;

	if (!subscr) {
		vty_out(vty, "%% No subscriber found for %s %s%s",
			argv[0], argv[1], VTY_NEWLINE);
		return CMD_WARNING;
	}

	if (!strcmp(argv[2], "tch/f"))
		type = RSL_CHANNEED_TCH_F;
	else if (!strcmp(argv[2], "tch/any"))
		type = RSL_CHANNEED_TCH_ForH;
	else if (!strcmp(argv[2], "sdcch"))
		type = RSL_CHANNEED_SDCCH;
	else
		type = RSL_CHANNEED_ANY;	/* Defaults to ANY */

	rc = gsm_silent_call_start(subscr, vty, type);
	if (rc <= 0) {
		vty_out(vty, "%% Subscriber not attached%s",
			VTY_NEWLINE);
		subscr_put(subscr);
		return CMD_WARNING;
	}

	subscr_put(subscr);

	return CMD_SUCCESS;
}

DEFUN(subscriber_silent_call_stop,
      subscriber_silent_call_stop_cmd,
      "subscriber " SUBSCR_TYPES " ID silent-call stop",
	SUBSCR_HELP "Silent call operation\n" "Stop silent call\n"
	CHAN_TYPE_HELP)
{
	struct gsm_network *gsmnet = gsmnet_from_vty(vty);
	struct gsm_subscriber *subscr = get_subscr_by_argv(gsmnet, argv[0], argv[1]);
	int rc;

	if (!subscr) {
		vty_out(vty, "%% No subscriber found for %s %s%s",
			argv[0], argv[1], VTY_NEWLINE);
		return CMD_WARNING;
	}

	rc = gsm_silent_call_stop(subscr);
	if (rc < 0) {
		subscr_put(subscr);
		return CMD_WARNING;
	}

	subscr_put(subscr);

	return CMD_SUCCESS;
}

DEFUN(subscriber_ussd_notify,
      subscriber_ussd_notify_cmd,
      "subscriber " SUBSCR_TYPES " ID ussd-notify (0|1|2) .TEXT",
      SUBSCR_HELP "USSD Notify\n"
      "Subscriber ID\n"
      "Alerting Level\n"
      "Text Message to send\n")
{
	char *text;
	struct gsm_subscriber_connection *conn;
	struct gsm_network *gsmnet = gsmnet_from_vty(vty);
	struct gsm_subscriber *subscr = get_subscr_by_argv(gsmnet, argv[0], argv[1]);
	int level;

	if (!subscr) {
		vty_out(vty, "%% No subscriber found for %s %s%s",
			argv[0], argv[1], VTY_NEWLINE);
		return CMD_WARNING;
	}

	level = atoi(argv[2]);
	text = argv_concat(argv, argc, 3);
	if (!text) {
		subscr_put(subscr);
		return CMD_WARNING;
	}

	conn = connection_for_subscr(subscr);
	if (!conn) {
		vty_out(vty, "%% An active connection is required for %s %s%s",
			argv[0], argv[1], VTY_NEWLINE);
		subscr_put(subscr);
		talloc_free(text);
		return CMD_WARNING;
	}

	gsm0480_send_ussdNotify(conn, level, text);
	gsm0480_send_releaseComplete(conn);

	subscr_put(subscr);
	talloc_free(text);
	return CMD_SUCCESS;
}

DEFUN(ena_subscr_authorizde,
      ena_subscr_authorized_cmd,
      "subscriber " SUBSCR_TYPES " ID authorized (0|1)",
	SUBSCR_HELP "(De-)Authorize subscriber in HLR\n"
	"Subscriber should NOT be authorized\n"
	"Subscriber should be authorized\n")
{
	struct gsm_network *gsmnet = gsmnet_from_vty(vty);
	struct gsm_subscriber *subscr =
			get_subscr_by_argv(gsmnet, argv[0], argv[1]);

	if (!subscr) {
		vty_out(vty, "%% No subscriber found for %s %s%s",
			argv[0], argv[1], VTY_NEWLINE);
		return CMD_WARNING;
	}

	subscr->authorized = atoi(argv[2]);
	db_sync_subscriber(subscr);

	subscr_put(subscr);

	return CMD_SUCCESS;
}

DEFUN(ena_subscr_name,
      ena_subscr_name_cmd,
      "subscriber " SUBSCR_TYPES " ID name .NAME",
	SUBSCR_HELP "Set the name of the subscriber\n"
	"Name of the Subscriber\n")
{
	struct gsm_network *gsmnet = gsmnet_from_vty(vty);
	struct gsm_subscriber *subscr =
			get_subscr_by_argv(gsmnet, argv[0], argv[1]);
	char *name;

	if (!subscr) {
		vty_out(vty, "%% No subscriber found for %s %s%s",
			argv[0], argv[1], VTY_NEWLINE);
		return CMD_WARNING;
	}

	name = argv_concat(argv, argc, 2);
	if (!name) {
		subscr_put(subscr);
		return CMD_WARNING;
	}

	strncpy(subscr->name, name, sizeof(subscr->name));
	talloc_free(name);
	db_sync_subscriber(subscr);

	subscr_put(subscr);

	return CMD_SUCCESS;
}

DEFUN(ena_subscr_extension,
      ena_subscr_extension_cmd,
      "subscriber " SUBSCR_TYPES " ID extension EXTENSION",
	SUBSCR_HELP "Set the extension (phone number) of the subscriber\n"
	"Extension (phone number)\n")
{
	struct gsm_network *gsmnet = gsmnet_from_vty(vty);
	struct gsm_subscriber *subscr =
			get_subscr_by_argv(gsmnet, argv[0], argv[1]);
	const char *name = argv[2];

	if (!subscr) {
		vty_out(vty, "%% No subscriber found for %s %s%s",
			argv[0], argv[1], VTY_NEWLINE);
		return CMD_WARNING;
	}

	strncpy(subscr->extension, name, sizeof(subscr->name));
	db_sync_subscriber(subscr);

	subscr_put(subscr);

	return CMD_SUCCESS;
}

DEFUN(ena_subscr_clear,
      ena_subscr_clear_cmd,
      "subscriber " SUBSCR_TYPES " ID clear-requests",
	SUBSCR_HELP "Clear the paging requests for this subscriber\n")
{
	int del;
	struct gsm_network *gsmnet = gsmnet_from_vty(vty);
	struct gsm_subscriber *subscr =
			get_subscr_by_argv(gsmnet, argv[0], argv[1]);

	if (!subscr) {
		vty_out(vty, "%% No subscriber found for %s %s%s",
			argv[0], argv[1], VTY_NEWLINE);
		return CMD_WARNING;
	}

	del = subscr_pending_clear(subscr);
	vty_out(vty, "Cleared %d pending requests.%s", del, VTY_NEWLINE);
	subscr_put(subscr);

	return CMD_SUCCESS;
}

DEFUN(ena_subscr_pend,
      ena_subscr_pend_cmd,
      "subscriber " SUBSCR_TYPES " ID show-pending",
	SUBSCR_HELP "Clear the paging requests for this subscriber\n")
{
	struct gsm_network *gsmnet = gsmnet_from_vty(vty);
	struct gsm_subscriber *subscr =
			get_subscr_by_argv(gsmnet, argv[0], argv[1]);

	if (!subscr) {
		vty_out(vty, "%% No subscriber found for %s %s%s",
			argv[0], argv[1], VTY_NEWLINE);
		return CMD_WARNING;
	}

	subscr_pending_dump(subscr, vty);
	subscr_put(subscr);

	return CMD_SUCCESS;
}

DEFUN(ena_subscr_kick,
      ena_subscr_kick_cmd,
      "subscriber " SUBSCR_TYPES " ID kick-pending",
	SUBSCR_HELP "Clear the paging requests for this subscriber\n")
{
	struct gsm_network *gsmnet = gsmnet_from_vty(vty);
	struct gsm_subscriber *subscr =
			get_subscr_by_argv(gsmnet, argv[0], argv[1]);

	if (!subscr) {
		vty_out(vty, "%% No subscriber found for %s %s%s",
			argv[0], argv[1], VTY_NEWLINE);
		return CMD_WARNING;
	}

	subscr_pending_kick(subscr);
	subscr_put(subscr);

	return CMD_SUCCESS;
}

#define A3A8_ALG_TYPES "(none|xor|comp128v1)"
#define A3A8_ALG_HELP 			\
	"Use No A3A8 algorithm\n"	\
	"Use XOR algorithm\n"		\
	"Use COMP128v1 algorithm\n"

DEFUN(ena_subscr_a3a8,
      ena_subscr_a3a8_cmd,
      "subscriber " SUBSCR_TYPES " ID a3a8 " A3A8_ALG_TYPES " [KI]",
      SUBSCR_HELP "Set a3a8 parameters for the subscriber\n"
      A3A8_ALG_HELP "Encryption Key Ki\n")
{
	struct gsm_network *gsmnet = gsmnet_from_vty(vty);
	struct gsm_subscriber *subscr =
			get_subscr_by_argv(gsmnet, argv[0], argv[1]);
	const char *alg_str = argv[2];
	const char *ki_str = argc == 4 ? argv[3] : NULL;
	struct gsm_auth_info ainfo;
	int rc, minlen, maxlen;

	if (!subscr) {
		vty_out(vty, "%% No subscriber found for %s %s%s",
			argv[0], argv[1], VTY_NEWLINE);
		return CMD_WARNING;
	}

	if (!strcasecmp(alg_str, "none")) {
		ainfo.auth_algo = AUTH_ALGO_NONE;
		minlen = maxlen = 0;
	} else if (!strcasecmp(alg_str, "xor")) {
		ainfo.auth_algo = AUTH_ALGO_XOR;
		minlen = A38_XOR_MIN_KEY_LEN;
		maxlen = A38_XOR_MAX_KEY_LEN;
	} else if (!strcasecmp(alg_str, "comp128v1")) {
		ainfo.auth_algo = AUTH_ALGO_COMP128v1;
		minlen = maxlen = A38_COMP128_KEY_LEN;
	} else {
		/* Unknown method */
		subscr_put(subscr);
		return CMD_WARNING;
	}

	if (ki_str) {
		rc = hexparse(ki_str, ainfo.a3a8_ki, sizeof(ainfo.a3a8_ki));
		if ((rc > maxlen) || (rc < minlen)) {
			subscr_put(subscr);
			return CMD_WARNING;
		}
		ainfo.a3a8_ki_len = rc;
	} else {
		ainfo.a3a8_ki_len = 0;
		if (minlen) {
			subscr_put(subscr);
			return CMD_WARNING;
		}
	}

	rc = db_sync_authinfo_for_subscr(
		ainfo.auth_algo == AUTH_ALGO_NONE ? NULL : &ainfo,
		subscr);

	/* the last tuple probably invalid with the new auth settings */
	db_sync_lastauthtuple_for_subscr(NULL, subscr);
	subscr_put(subscr);

	return rc ? CMD_WARNING : CMD_SUCCESS;
}

DEFUN(subscriber_purge,
      subscriber_purge_cmd,
      "subscriber purge-inactive",
      "Operations on a Subscriber\n" "Purge subscribers with a zero use count.\n")
{
	struct gsm_network *net = gsmnet_from_vty(vty);
	int purged;

	purged = subscr_purge_inactive(net);
	vty_out(vty, "%d subscriber(s) were purged.%s", purged, VTY_NEWLINE);
	return CMD_SUCCESS;
}

DEFUN(subscriber_update,
      subscriber_update_cmd,
      "subscriber " SUBSCR_TYPES " ID update",
      SUBSCR_HELP "Update the subscriber data from the dabase.\n")
{
	struct gsm_network *gsmnet = gsmnet_from_vty(vty);
	struct gsm_subscriber *subscr = get_subscr_by_argv(gsmnet, argv[0], argv[1]);

	if (!subscr) {
		vty_out(vty, "%% No subscriber found for %s %s%s",
			argv[0], argv[1], VTY_NEWLINE);
		return CMD_WARNING;
	}

	subscr_update_from_db(subscr);
	subscr_put(subscr);
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
			sigdata->conn->lchan->ts->trx->arfcn, sigdata->conn->lchan->ts->nr,
			VTY_NEWLINE);
		break;
	case S_SCALL_EXPIRED:
		vty_out(vty, "%% silent call expired paging%s", VTY_NEWLINE);
		break;
	}
	return 0;
}

DEFUN(show_stats,
      show_stats_cmd,
      "show statistics",
	SHOW_STR "Display network statistics\n")
{
	struct gsm_network *net = gsmnet_from_vty(vty);

	openbsc_vty_print_statistics(vty, net);
	vty_out(vty, "Channel Requests        : %lu total, %lu no channel%s",
		counter_get(net->stats.chreq.total),
		counter_get(net->stats.chreq.no_channel), VTY_NEWLINE);
	vty_out(vty, "Location Update         : %lu attach, %lu normal, %lu periodic%s",
		counter_get(net->stats.loc_upd_type.attach),
		counter_get(net->stats.loc_upd_type.normal),
		counter_get(net->stats.loc_upd_type.periodic), VTY_NEWLINE);
	vty_out(vty, "IMSI Detach Indications : %lu%s",
		counter_get(net->stats.loc_upd_type.detach), VTY_NEWLINE);
	vty_out(vty, "Location Update Response: %lu accept, %lu reject%s",
		counter_get(net->stats.loc_upd_resp.accept),
		counter_get(net->stats.loc_upd_resp.reject), VTY_NEWLINE);
	vty_out(vty, "Handover                : %lu attempted, %lu no_channel, %lu timeout, "
		"%lu completed, %lu failed%s",
		counter_get(net->stats.handover.attempted),
		counter_get(net->stats.handover.no_channel),
		counter_get(net->stats.handover.timeout),
		counter_get(net->stats.handover.completed),
		counter_get(net->stats.handover.failed), VTY_NEWLINE);
	vty_out(vty, "SMS MO                  : %lu submitted, %lu no receiver%s",
		counter_get(net->stats.sms.submitted),
		counter_get(net->stats.sms.no_receiver), VTY_NEWLINE);
	vty_out(vty, "SMS MT                  : %lu delivered, %lu no memory, %lu other error%s",
		counter_get(net->stats.sms.delivered),
		counter_get(net->stats.sms.rp_err_mem),
		counter_get(net->stats.sms.rp_err_other), VTY_NEWLINE);
	vty_out(vty, "MO Calls                : %lu setup, %lu connect ack%s",
		counter_get(net->stats.call.mo_setup),
		counter_get(net->stats.call.mo_connect_ack), VTY_NEWLINE);
	vty_out(vty, "MT Calls                : %lu setup, %lu connect%s",
		counter_get(net->stats.call.mt_setup),
		counter_get(net->stats.call.mt_connect), VTY_NEWLINE);
	return CMD_SUCCESS;
}

DEFUN(show_smsqueue,
      show_smsqueue_cmd,
      "show sms-queue",
      SHOW_STR "Display SMSqueue statistics\n")
{
	struct gsm_network *net = gsmnet_from_vty(vty);

	sms_queue_stats(net->sms_queue, vty);
	return CMD_SUCCESS;
}

DEFUN(smsqueue_trigger,
      smsqueue_trigger_cmd,
      "sms-queue trigger",
      "SMS Queue\n" "Trigger sending messages\n")
{
	struct gsm_network *net = gsmnet_from_vty(vty);

	sms_queue_trigger(net->sms_queue);
	return CMD_SUCCESS;
}

DEFUN(smsqueue_max,
      smsqueue_max_cmd,
      "sms-queue max-pending <1-500>",
      "SMS Queue\n" "SMS to attempt to deliver at the same time\n")
{
	struct gsm_network *net = gsmnet_from_vty(vty);

	sms_queue_set_max_pending(net->sms_queue, atoi(argv[0]));
	return CMD_SUCCESS;
}

DEFUN(smsqueue_clear,
      smsqueue_clear_cmd,
      "sms-queue clear",
      "SMS Queue\n" "Clear the queue of pending SMS\n")
{
	struct gsm_network *net = gsmnet_from_vty(vty);

	sms_queue_clear(net->sms_queue);
	return CMD_SUCCESS;
}

DEFUN(smsqueue_fail,
      smsqueue_fail_cmd,
      "sms-queue max-failure <1-500>",
      "SMS Queue\n" "Set maximum amount of failures\n")
{
	struct gsm_network *net = gsmnet_from_vty(vty);

	sms_queue_set_max_failure(net->sms_queue, atoi(argv[0]));
	return CMD_SUCCESS;
}

int bsc_vty_init_extra(void)
{
	register_signal_handler(SS_SCALL, scall_cbfn, NULL);

	install_element_ve(&show_subscr_cmd);
	install_element_ve(&show_subscr_cache_cmd);

	install_element_ve(&sms_send_pend_cmd);

	install_element_ve(&subscriber_send_sms_cmd);
	install_element_ve(&subscriber_silent_sms_cmd);
	install_element_ve(&subscriber_silent_call_start_cmd);
	install_element_ve(&subscriber_silent_call_stop_cmd);
	install_element_ve(&subscriber_ussd_notify_cmd);
	install_element_ve(&subscriber_update_cmd);
	install_element_ve(&show_stats_cmd);
	install_element_ve(&show_smsqueue_cmd);

	install_element(ENABLE_NODE, &ena_subscr_name_cmd);
	install_element(ENABLE_NODE, &ena_subscr_extension_cmd);
	install_element(ENABLE_NODE, &ena_subscr_authorized_cmd);
	install_element(ENABLE_NODE, &ena_subscr_a3a8_cmd);
	install_element(ENABLE_NODE, &ena_subscr_clear_cmd);
	install_element(ENABLE_NODE, &ena_subscr_pend_cmd);
	install_element(ENABLE_NODE, &ena_subscr_kick_cmd);
	install_element(ENABLE_NODE, &subscriber_purge_cmd);
	install_element(ENABLE_NODE, &smsqueue_trigger_cmd);
	install_element(ENABLE_NODE, &smsqueue_max_cmd);
	install_element(ENABLE_NODE, &smsqueue_clear_cmd);
	install_element(ENABLE_NODE, &smsqueue_fail_cmd);
	install_element(ENABLE_NODE, &subscriber_send_pending_sms_cmd);

	return 0;
}
