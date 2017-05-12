/* OpenBSC interface to quagga VTY */
/* (C) 2009 by Harald Welte <laforge@gnumonks.org>
 * (C) 2009-2011 by Holger Hans Peter Freyther
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
#include <stdbool.h>
#include <inttypes.h>
#include <time.h>

#include <osmocom/vty/command.h>
#include <osmocom/vty/buffer.h>
#include <osmocom/vty/vty.h>

#include <arpa/inet.h>

#include <osmocom/core/linuxlist.h>
#include <openbsc/gsm_data.h>
#include <openbsc/gsm_subscriber.h>
#include <openbsc/bsc_subscriber.h>
#include <openbsc/silent_call.h>
#include <openbsc/gsm_04_11.h>
#include <osmocom/abis/e1_input.h>
#include <openbsc/abis_nm.h>
#include <osmocom/gsm/gsm_utils.h>
#include <osmocom/core/utils.h>
#include <openbsc/db.h>
#include <osmocom/core/talloc.h>
#include <openbsc/signal.h>
#include <openbsc/debug.h>
#include <openbsc/vty.h>
#include <openbsc/gsm_04_80.h>
#include <openbsc/chan_alloc.h>
#include <openbsc/sms_queue.h>
#include <openbsc/mncc_int.h>
#include <openbsc/handover.h>

#include <osmocom/vty/logging.h>

#include "meas_feed.h"

extern struct gsm_network *gsmnet_from_vty(struct vty *v);

static void subscr_dump_full_vty(struct vty *vty, struct gsm_subscriber *subscr)
{
	int rc;
	int reqs;
	struct gsm_auth_info ainfo;
	struct gsm_auth_tuple atuple;
	struct llist_head *entry;
	char expire_time[200];

	vty_out(vty, "    ID: %llu, Authorized: %d%s", subscr->id,
		subscr->authorized, VTY_NEWLINE);
	if (strlen(subscr->name))
		vty_out(vty, "    Name: '%s'%s", subscr->name, VTY_NEWLINE);
	if (strlen(subscr->extension))
		vty_out(vty, "    Extension: %s%s", subscr->extension,
			VTY_NEWLINE);
	vty_out(vty, "    LAC: %d/0x%x%s",
		subscr->lac, subscr->lac, VTY_NEWLINE);
	vty_out(vty, "    IMSI: %s%s", subscr->imsi, VTY_NEWLINE);
	if (subscr->tmsi != GSM_RESERVED_TMSI)
		vty_out(vty, "    TMSI: %08X%s", subscr->tmsi,
			VTY_NEWLINE);

	rc = db_get_authinfo_for_subscr(&ainfo, subscr);
	if (!rc) {
		vty_out(vty, "    A3A8 algorithm id: %d%s",
			ainfo.auth_algo, VTY_NEWLINE);
		vty_out(vty, "    A3A8 Ki: %s%s",
			osmo_hexdump(ainfo.a3a8_ki, ainfo.a3a8_ki_len),
			VTY_NEWLINE);
	}

	rc = db_get_lastauthtuple_for_subscr(&atuple, subscr);
	if (!rc) {
		vty_out(vty, "    A3A8 last tuple (used %d times):%s",
			atuple.use_count, VTY_NEWLINE);
		vty_out(vty, "     seq # : %d%s",
			atuple.key_seq, VTY_NEWLINE);
		vty_out(vty, "     RAND  : %s%s",
			osmo_hexdump(atuple.vec.rand, sizeof(atuple.vec.rand)),
			VTY_NEWLINE);
		vty_out(vty, "     SRES  : %s%s",
			osmo_hexdump(atuple.vec.sres, sizeof(atuple.vec.sres)),
			VTY_NEWLINE);
		vty_out(vty, "     Kc    : %s%s",
			osmo_hexdump(atuple.vec.kc, sizeof(atuple.vec.kc)),
			VTY_NEWLINE);
	}

	/* print the expiration time of a subscriber */
	strftime(expire_time, sizeof(expire_time),
			"%a, %d %b %Y %T %z", localtime(&subscr->expire_lu));
	expire_time[sizeof(expire_time) - 1] = '\0';
	vty_out(vty, "    Expiration Time: %s%s", expire_time, VTY_NEWLINE);

	reqs = 0;
	llist_for_each(entry, &subscr->requests)
		reqs += 1;
	vty_out(vty, "    Paging: %s paging Requests: %d%s",
		subscr->is_paging ? "is" : "not", reqs, VTY_NEWLINE);
	vty_out(vty, "    Use count: %u%s", subscr->use_count, VTY_NEWLINE);
}


/* Subscriber */
DEFUN(show_subscr_cache,
      show_subscr_cache_cmd,
      "show subscriber cache",
	SHOW_STR "Show information about subscribers\n"
	"Display contents of subscriber cache\n")
{
	struct gsm_subscriber *subscr;

	llist_for_each_entry(subscr, &active_subscribers, entry) {
		vty_out(vty, "  Subscriber:%s", VTY_NEWLINE);
		subscr_dump_full_vty(vty, subscr);
	}

	return CMD_SUCCESS;
}

DEFUN(sms_send_pend,
      sms_send_pend_cmd,
      "sms send pending",
      "SMS related commands\n" "SMS Sending related commands\n"
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

static int _send_sms_str(struct gsm_subscriber *receiver,
                         struct gsm_subscriber *sender,
                         char *str, uint8_t tp_pid)
{
	struct gsm_sms *sms;

	sms = sms_from_text(receiver, sender, 0, str);
	sms->protocol_id = tp_pid;

	/* store in database for the queue */
	if (db_sms_store(sms) != 0) {
		LOGP(DLSMS, LOGL_ERROR, "Failed to store SMS in Database\n");
		sms_free(sms);
		return CMD_WARNING;
	}
	LOGP(DLSMS, LOGL_DEBUG, "SMS stored in DB\n");

	sms_free(sms);
	sms_queue_trigger(receiver->group->net->sms_queue);
	return CMD_SUCCESS;
}

static struct gsm_subscriber *get_subscr_by_argv(struct gsm_network *gsmnet,
						 const char *type,
						 const char *id)
{
	if (!strcmp(type, "extension"))
		return subscr_get_by_extension(gsmnet->subscr_group, id);
	else if (!strcmp(type, "imsi"))
		return subscr_get_by_imsi(gsmnet->subscr_group, id);
	else if (!strcmp(type, "tmsi"))
		return subscr_get_by_tmsi(gsmnet->subscr_group, atoi(id));
	else if (!strcmp(type, "id"))
		return subscr_get_by_id(gsmnet->subscr_group, atoi(id));

	return NULL;
}
#define SUBSCR_TYPES "(extension|imsi|tmsi|id)"
#define SUBSCR_HELP "Operations on a Subscriber\n"			\
	"Identify subscriber by extension (phone number)\n"		\
	"Identify subscriber by IMSI\n"					\
	"Identify subscriber by TMSI\n"					\
	"Identify subscriber by database ID\n"				\
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

	subscr_dump_full_vty(vty, subscr);

	subscr_put(subscr);

	return CMD_SUCCESS;
}

DEFUN(subscriber_create,
      subscriber_create_cmd,
      "subscriber create imsi ID",
	"Operations on a Subscriber\n" \
	"Create new subscriber\n" \
	"Identify the subscriber by his IMSI\n" \
	"Identifier for the subscriber\n")
{
	struct gsm_network *gsmnet = gsmnet_from_vty(vty);
	struct gsm_subscriber *subscr;

	subscr = subscr_get_by_imsi(gsmnet->subscr_group, argv[0]);
	if (subscr)
		db_sync_subscriber(subscr);
	else {
		subscr = subscr_create_subscriber(gsmnet->subscr_group, argv[0]);

		if (!subscr) {
			vty_out(vty, "%% No subscriber created for IMSI %s%s",
				argv[0], VTY_NEWLINE);
			return CMD_WARNING;
		}
	}

	/* Show info about the created subscriber. */
	subscr_dump_full_vty(vty, subscr);

	subscr_put(subscr);

	return CMD_SUCCESS;
}

DEFUN(subscriber_send_pending_sms,
      subscriber_send_pending_sms_cmd,
      "subscriber " SUBSCR_TYPES " ID sms pending-send",
	SUBSCR_HELP "SMS Operations\n" "Send pending SMS\n")
{
	struct gsm_network *gsmnet = gsmnet_from_vty(vty);
	struct gsm_subscriber *subscr;
	struct gsm_sms *sms;

	subscr = get_subscr_by_argv(gsmnet, argv[0], argv[1]);
	if (!subscr) {
		vty_out(vty, "%% No subscriber found for %s %s%s",
			argv[0], argv[1], VTY_NEWLINE);
		return CMD_WARNING;
	}

	sms = db_sms_get_unsent_by_subscr(gsmnet, subscr->id, UINT_MAX);
	if (sms)
		gsm411_send_sms_subscr(sms->receiver, sms);

	subscr_put(subscr);

	return CMD_SUCCESS;
}

DEFUN(subscriber_send_sms,
      subscriber_send_sms_cmd,
      "subscriber " SUBSCR_TYPES " ID sms sender " SUBSCR_TYPES " SENDER_ID send .LINE",
	SUBSCR_HELP "SMS Operations\n" SUBSCR_HELP "Send SMS\n" "Actual SMS Text\n")
{
	struct gsm_network *gsmnet = gsmnet_from_vty(vty);
	struct gsm_subscriber *subscr = get_subscr_by_argv(gsmnet, argv[0], argv[1]);
	struct gsm_subscriber *sender = get_subscr_by_argv(gsmnet, argv[2], argv[3]);
	char *str;
	int rc;

	if (!subscr) {
		vty_out(vty, "%% No subscriber found for %s %s%s",
			argv[0], argv[1], VTY_NEWLINE);
		rc = CMD_WARNING;
		goto err;
	}

	if (!sender) {
		vty_out(vty, "%% No sender found for %s %s%s",
			argv[2], argv[3], VTY_NEWLINE);
		rc = CMD_WARNING;
		goto err;
	}

	str = argv_concat(argv, argc, 4);
	rc = _send_sms_str(subscr, sender, str, 0);
	talloc_free(str);

err:
	if (sender)
		subscr_put(sender);

	if (subscr)
		subscr_put(subscr);

	return rc;
}

DEFUN(subscriber_silent_sms,
      subscriber_silent_sms_cmd,

      "subscriber " SUBSCR_TYPES " ID silent-sms sender " SUBSCR_TYPES " SENDER_ID send .LINE",
	SUBSCR_HELP "Silent SMS Operations\n" SUBSCR_HELP "Send SMS\n" "Actual SMS Text\n")
{
	struct gsm_network *gsmnet = gsmnet_from_vty(vty);
	struct gsm_subscriber *subscr = get_subscr_by_argv(gsmnet, argv[0], argv[1]);
	struct gsm_subscriber *sender = get_subscr_by_argv(gsmnet, argv[2], argv[3]);
	char *str;
	int rc;

	if (!subscr) {
		vty_out(vty, "%% No subscriber found for %s %s%s",
			argv[0], argv[1], VTY_NEWLINE);
		rc = CMD_WARNING;
		goto err;
	}

	if (!sender) {
		vty_out(vty, "%% No sender found for %s %s%s",
			argv[2], argv[3], VTY_NEWLINE);
		rc = CMD_WARNING;
		goto err;
	}

	str = argv_concat(argv, argc, 4);
	rc = _send_sms_str(subscr, sender, str, 64);
	talloc_free(str);

err:
	if (sender)
		subscr_put(sender);

	if (subscr)
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
      SUBSCR_HELP "Send a USSD notify to the subscriber\n"
      "Alerting Level 0\n"
      "Alerting Level 1\n"
      "Alerting Level 2\n"
      "Text of USSD message to send\n")
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

	msc_send_ussd_notify(conn, level, text);
	msc_send_ussd_release_complete(conn);

	subscr_put(subscr);
	talloc_free(text);
	return CMD_SUCCESS;
}

DEFUN(ena_subscr_delete,
      ena_subscr_delete_cmd,
      "subscriber " SUBSCR_TYPES " ID delete",
	SUBSCR_HELP "Delete subscriber in HLR\n")
{
	int rc;
	struct gsm_network *gsmnet = gsmnet_from_vty(vty);
	struct gsm_subscriber *subscr =
			get_subscr_by_argv(gsmnet, argv[0], argv[1]);

	if (!subscr) {
		vty_out(vty, "%% No subscriber found for %s %s%s",
			argv[0], argv[1], VTY_NEWLINE);
		return CMD_WARNING;
	}

	if (subscr->use_count != 1) {
		vty_out(vty, "Removing active subscriber%s", VTY_NEWLINE);
	}

	rc = db_subscriber_delete(subscr);
	subscr_put(subscr);

	if (rc != 0) {
		vty_out(vty, "Failed to remove subscriber%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	return CMD_SUCCESS;
}

DEFUN(ena_subscr_expire,
      ena_subscr_expire_cmd,
      "subscriber " SUBSCR_TYPES " ID expire",
	SUBSCR_HELP "Expire the subscriber Now\n")
{
	struct gsm_network *gsmnet = gsmnet_from_vty(vty);
	struct gsm_subscriber *subscr =
			get_subscr_by_argv(gsmnet, argv[0], argv[1]);

	if (!subscr) {
		vty_out(vty, "%% No subscriber found for %s %s%s",
			argv[0], argv[1], VTY_NEWLINE);
		return CMD_WARNING;
	}

	subscr->expire_lu = time(0);
	db_sync_subscriber(subscr);
	subscr_put(subscr);

	return CMD_SUCCESS;
}

DEFUN(ena_subscr_authorized,
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

	if (strlen(name) > sizeof(subscr->name)-1) {
		vty_out(vty,
			"%% NAME is too long, max. %zu characters are allowed%s",
			sizeof(subscr->name)-1, VTY_NEWLINE);
		subscr_put(subscr);
		return CMD_WARNING;
	}

	osmo_strlcpy(subscr->name, name, sizeof(subscr->name));
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
	const char *ext = argv[2];

	if (!subscr) {
		vty_out(vty, "%% No subscriber found for %s %s%s",
			argv[0], argv[1], VTY_NEWLINE);
		return CMD_WARNING;
	}

	if (strlen(ext) > sizeof(subscr->extension)-1) {
		vty_out(vty,
			"%% EXTENSION is too long, max. %zu characters are allowed%s",
			sizeof(subscr->extension)-1, VTY_NEWLINE);
		return CMD_WARNING;
	}

	osmo_strlcpy(subscr->extension, ext, sizeof(subscr->extension));
	db_sync_subscriber(subscr);

	subscr_put(subscr);

	return CMD_SUCCESS;
}

DEFUN(ena_subscr_handover,
      ena_subscr_handover_cmd,
      "subscriber " SUBSCR_TYPES " ID handover BTS_NR",
	SUBSCR_HELP "Handover the active connection\n"
	"Number of the BTS to handover to\n")
{
	int ret;
	struct gsm_subscriber_connection *conn;
	struct gsm_bts *bts;
	struct gsm_network *gsmnet = gsmnet_from_vty(vty);
	struct gsm_subscriber *subscr =
			get_subscr_by_argv(gsmnet, argv[0], argv[1]);

	if (!subscr) {
		vty_out(vty, "%% No subscriber found for %s %s.%s",
			argv[0], argv[1], VTY_NEWLINE);
		return CMD_WARNING;
	}

	conn = connection_for_subscr(subscr);
	if (!conn) {
		vty_out(vty, "%% No active connection for subscriber %s %s.%s",
			argv[0], argv[1], VTY_NEWLINE);
		subscr_put(subscr);
		return CMD_WARNING;
	}

	bts = gsm_bts_num(gsmnet, atoi(argv[2]));
	if (!bts) {
		vty_out(vty, "%% BTS with number(%d) could not be found.%s",
			atoi(argv[2]), VTY_NEWLINE);
		subscr_put(subscr);
		return CMD_WARNING;
	}

	/* now start the handover */
	ret = bsc_handover_start(conn->lchan, bts);
	if (ret != 0) {
		vty_out(vty, "%% Handover failed with errno %d.%s",
			ret, VTY_NEWLINE);
	} else {
		vty_out(vty, "%% Handover started from %s",
			gsm_lchan_name(conn->lchan));
		vty_out(vty, " to %s.%s", gsm_lchan_name(conn->ho_lchan),
			VTY_NEWLINE);
	}

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
		vty_out(vty, "%% Unknown auth method %s%s",
				alg_str, VTY_NEWLINE);
		return CMD_WARNING;
	}

	if (ki_str) {
		rc = osmo_hexparse(ki_str, ainfo.a3a8_ki, sizeof(ainfo.a3a8_ki));
		if ((rc > maxlen) || (rc < minlen)) {
			subscr_put(subscr);
			vty_out(vty, "%% Wrong Ki `%s'%s",
				ki_str, VTY_NEWLINE);
			return CMD_WARNING;
		}
		ainfo.a3a8_ki_len = rc;
	} else {
		ainfo.a3a8_ki_len = 0;
		if (minlen) {
			subscr_put(subscr);
			vty_out(vty, "%% Missing Ki argument%s", VTY_NEWLINE);
			return CMD_WARNING;
		}
	}

	rc = db_sync_authinfo_for_subscr(
		ainfo.auth_algo == AUTH_ALGO_NONE ? NULL : &ainfo,
		subscr);

	/* the last tuple probably invalid with the new auth settings */
	db_sync_lastauthtuple_for_subscr(NULL, subscr);
	subscr_put(subscr);

	if (rc) {
		vty_out(vty, "%% Operation has failed%s", VTY_NEWLINE);
		return CMD_WARNING;
	}
	return CMD_SUCCESS;
}

DEFUN(subscriber_purge,
      subscriber_purge_cmd,
      "subscriber purge-inactive",
      "Operations on a Subscriber\n" "Purge subscribers with a zero use count.\n")
{
	struct gsm_network *net = gsmnet_from_vty(vty);
	int purged;

	purged = subscr_purge_inactive(net->subscr_group);
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
	vty_out(vty, "Location Update         : %lu attach, %lu normal, %lu periodic%s",
		net->msc_ctrs->ctr[MSC_CTR_LOC_UPDATE_TYPE_ATTACH].current,
		net->msc_ctrs->ctr[MSC_CTR_LOC_UPDATE_TYPE_NORMAL].current,
		net->msc_ctrs->ctr[MSC_CTR_LOC_UPDATE_TYPE_PERIODIC].current,
		VTY_NEWLINE);
	vty_out(vty, "IMSI Detach Indications : %lu%s",
		net->msc_ctrs->ctr[MSC_CTR_LOC_UPDATE_TYPE_DETACH].current,
		VTY_NEWLINE);
	vty_out(vty, "Location Updating Results: %lu completed, %lu failed%s",
		net->msc_ctrs->ctr[MSC_CTR_LOC_UPDATE_COMPLETED].current,
		net->msc_ctrs->ctr[MSC_CTR_LOC_UPDATE_FAILED].current,
		VTY_NEWLINE);
	vty_out(vty, "Handover                : %lu attempted, %lu no_channel, %lu timeout, "
		"%lu completed, %lu failed%s",
		net->msc_ctrs->ctr[BSC_CTR_HANDOVER_ATTEMPTED].current,
		net->msc_ctrs->ctr[BSC_CTR_HANDOVER_NO_CHANNEL].current,
		net->msc_ctrs->ctr[BSC_CTR_HANDOVER_TIMEOUT].current,
		net->msc_ctrs->ctr[BSC_CTR_HANDOVER_COMPLETED].current,
		net->msc_ctrs->ctr[BSC_CTR_HANDOVER_FAILED].current,
		VTY_NEWLINE);
	vty_out(vty, "SMS MO                  : %lu submitted, %lu no receiver%s",
		net->msc_ctrs->ctr[MSC_CTR_SMS_SUBMITTED].current,
		net->msc_ctrs->ctr[MSC_CTR_SMS_NO_RECEIVER].current,
		VTY_NEWLINE);
	vty_out(vty, "SMS MT                  : %lu delivered, %lu no memory, %lu other error%s",
		net->msc_ctrs->ctr[MSC_CTR_SMS_DELIVERED].current,
		net->msc_ctrs->ctr[MSC_CTR_SMS_RP_ERR_MEM].current,
		net->msc_ctrs->ctr[MSC_CTR_SMS_RP_ERR_OTHER].current,
		VTY_NEWLINE);
	vty_out(vty, "MO Calls                : %lu setup, %lu connect ack%s",
		net->msc_ctrs->ctr[MSC_CTR_CALL_MO_SETUP].current,
		net->msc_ctrs->ctr[MSC_CTR_CALL_MO_CONNECT_ACK].current,
		VTY_NEWLINE);
	vty_out(vty, "MT Calls                : %lu setup, %lu connect%s",
		net->msc_ctrs->ctr[MSC_CTR_CALL_MT_SETUP].current,
		net->msc_ctrs->ctr[MSC_CTR_CALL_MT_CONNECT].current,
		VTY_NEWLINE);
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
      "SMS Queue\n" "SMS to deliver in parallel\n" "Amount\n")
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
      "SMS Queue\n" "Maximum amount of delivery failures\n" "Amount\n")
{
	struct gsm_network *net = gsmnet_from_vty(vty);

	sms_queue_set_max_failure(net->sms_queue, atoi(argv[0]));
	return CMD_SUCCESS;
}


DEFUN(cfg_mncc_int, cfg_mncc_int_cmd,
      "mncc-int", "Configure internal MNCC handler")
{
	vty->node = MNCC_INT_NODE;

	return CMD_SUCCESS;
}

static struct cmd_node mncc_int_node = {
	MNCC_INT_NODE,
	"%s(config-mncc-int)# ",
	1,
};

static const struct value_string tchf_codec_names[] = {
	{ GSM48_CMODE_SPEECH_V1,	"fr" },
	{ GSM48_CMODE_SPEECH_EFR,	"efr" },
	{ GSM48_CMODE_SPEECH_AMR,	"amr" },
	{ 0, NULL }
};

static const struct value_string tchh_codec_names[] = {
	{ GSM48_CMODE_SPEECH_V1,	"hr" },
	{ GSM48_CMODE_SPEECH_AMR,	"amr" },
	{ 0, NULL }
};

static int config_write_mncc_int(struct vty *vty)
{
	uint16_t meas_port;
	char *meas_host;
	const char *meas_scenario;

	meas_feed_cfg_get(&meas_host, &meas_port);
	meas_scenario = meas_feed_scenario_get();

	vty_out(vty, "mncc-int%s", VTY_NEWLINE);
	vty_out(vty, " default-codec tch-f %s%s",
		get_value_string(tchf_codec_names, mncc_int.def_codec[0]),
		VTY_NEWLINE);
	vty_out(vty, " default-codec tch-h %s%s",
		get_value_string(tchh_codec_names, mncc_int.def_codec[1]),
		VTY_NEWLINE);
	if (meas_port)
		vty_out(vty, " meas-feed destination %s %u%s",
			meas_host, meas_port, VTY_NEWLINE);
	if (strlen(meas_scenario) > 0)
		vty_out(vty, " meas-feed scenario %s%s",
			meas_scenario, VTY_NEWLINE);


	return CMD_SUCCESS;
}

DEFUN(mnccint_def_codec_f,
      mnccint_def_codec_f_cmd,
      "default-codec tch-f (fr|efr|amr)",
      "Set default codec\n" "Codec for TCH/F\n"
      "Full-Rate\n" "Enhanced Full-Rate\n" "Adaptive Multi-Rate\n")
{
	mncc_int.def_codec[0] = get_string_value(tchf_codec_names, argv[0]);

	return CMD_SUCCESS;
}

DEFUN(mnccint_def_codec_h,
      mnccint_def_codec_h_cmd,
      "default-codec tch-h (hr|amr)",
      "Set default codec\n" "Codec for TCH/H\n"
      "Half-Rate\n" "Adaptive Multi-Rate\n")
{
	mncc_int.def_codec[1] = get_string_value(tchh_codec_names, argv[0]);

	return CMD_SUCCESS;
}

#define OBSOLETE_MSG "Obsolete\n"
/* this is just for backwards compatibility as the sms code moved into
 * libosmocore and old config files no longer parse... */
DEFUN_DEPRECATED(log_level_sms, log_level_sms_cmd,
	"logging level sms (everything|debug|info|notice|error|fatal)",
	".HIDDEN\n" OBSOLETE_MSG OBSOLETE_MSG OBSOLETE_MSG OBSOLETE_MSG
	OBSOLETE_MSG OBSOLETE_MSG OBSOLETE_MSG OBSOLETE_MSG)
{
	vty_out(vty, "%% 'logging level sms' is now called 'logging level "
		"lsms', please update your config %s", VTY_NEWLINE);

	return CMD_SUCCESS;
}

#define MEAS_STR "Measurement export related\n"
DEFUN(mnccint_meas_feed, mnccint_meas_feed_cmd,
	"meas-feed destination ADDR <0-65535>",
	MEAS_STR "destination\n" "address or hostname\n" "port number\n")
{
	int rc;

	rc = meas_feed_cfg_set(argv[0], atoi(argv[1]));
	if (rc < 0)
		return CMD_WARNING;

	return CMD_SUCCESS;
}

DEFUN(meas_feed_scenario, meas_feed_scenario_cmd,
	"meas-feed scenario NAME",
	MEAS_STR "scenario\n" "Name up to 31 characters included in report\n")
{
	meas_feed_scenario_set(argv[0]);

	return CMD_SUCCESS;
}


DEFUN(logging_fltr_imsi,
      logging_fltr_imsi_cmd,
      "logging filter imsi IMSI",
	LOGGING_STR FILTER_STR
      "Filter log messages by IMSI\n" "IMSI to be used as filter\n")
{
	struct gsm_subscriber *vlr_subscr;
	struct bsc_subscr *bsc_subscr;
	struct gsm_network *gsmnet = gsmnet_from_vty(vty);
	struct log_target *tgt = osmo_log_vty2tgt(vty);
	const char *imsi = argv[0];

	if (!tgt)
		return CMD_WARNING;

	vlr_subscr = subscr_get_by_imsi(gsmnet->subscr_group, imsi);
	bsc_subscr = bsc_subscr_find_by_imsi(gsmnet->bsc_subscribers, imsi);

	if (!vlr_subscr && !bsc_subscr) {
		vty_out(vty, "%%no subscriber with IMSI(%s)%s",
			argv[0], VTY_NEWLINE);
		return CMD_WARNING;
	}

	log_set_filter_vlr_subscr(tgt, vlr_subscr);
	log_set_filter_bsc_subscr(tgt, bsc_subscr);
	return CMD_SUCCESS;
}

static struct cmd_node nitb_node = {
	NITB_NODE,
	"%s(config-nitb)# ",
	1,
};

DEFUN(cfg_nitb, cfg_nitb_cmd,
      "nitb", "Configure NITB options")
{
	vty->node = NITB_NODE;
	return CMD_SUCCESS;
}

/* Note: limit on the parameter length is set by internal vty code limitations */
DEFUN(cfg_nitb_subscr_random, cfg_nitb_subscr_random_cmd,
      "subscriber-create-on-demand random <1-9999999999> <2-9999999999>",
      "Set random parameters for a new record when a subscriber is first seen.\n"
      "Set random parameters for a new record when a subscriber is first seen.\n"
      "Minimum for subscriber extension\n""Maximum for subscriber extension\n")
{
	struct gsm_network *gsmnet = gsmnet_from_vty(vty);
	uint64_t mi = atoll(argv[0]), ma = atoll(argv[1]);
	gsmnet->auto_create_subscr = true;
	gsmnet->auto_assign_exten = true;
	if (mi >= ma) {
		vty_out(vty, "Incorrect range: %s >= %s, expected MIN < MAX%s",
			argv[0], argv[1], VTY_NEWLINE);
		return CMD_WARNING;
	}
	gsmnet->ext_min = mi;
	gsmnet->ext_max = ma;
        return CMD_SUCCESS;
}

DEFUN(cfg_nitb_subscr_create, cfg_nitb_subscr_create_cmd,
      "subscriber-create-on-demand [no-extension]",
      "Make a new record when a subscriber is first seen.\n"
      "Do not automatically assign extension to created subscribers\n")
{
	struct gsm_network *gsmnet = gsmnet_from_vty(vty);
	gsmnet->auto_create_subscr = true;
	gsmnet->auto_assign_exten = argc ? false : true;
	return CMD_SUCCESS;
}

DEFUN(cfg_nitb_no_subscr_create, cfg_nitb_no_subscr_create_cmd,
      "no subscriber-create-on-demand",
      NO_STR "Make a new record when a subscriber is first seen.\n")
{
	struct gsm_network *gsmnet = gsmnet_from_vty(vty);
	gsmnet->auto_create_subscr = false;
	return CMD_SUCCESS;
}

DEFUN(cfg_nitb_assign_tmsi, cfg_nitb_assign_tmsi_cmd,
      "assign-tmsi",
      "Assign TMSI during Location Updating.\n")
{
	struct gsm_network *gsmnet = gsmnet_from_vty(vty);
	gsmnet->avoid_tmsi = 0;
	return CMD_SUCCESS;
}

DEFUN(cfg_nitb_no_assign_tmsi, cfg_nitb_no_assign_tmsi_cmd,
      "no assign-tmsi",
      NO_STR "Assign TMSI during Location Updating.\n")
{
	struct gsm_network *gsmnet = gsmnet_from_vty(vty);
	gsmnet->avoid_tmsi = 1;
	return CMD_SUCCESS;
}

static int config_write_nitb(struct vty *vty)
{
	struct gsm_network *gsmnet = gsmnet_from_vty(vty);

	vty_out(vty, "nitb%s", VTY_NEWLINE);
	if (!gsmnet->auto_create_subscr)
		vty_out(vty, " no subscriber-create-on-demand%s", VTY_NEWLINE);
	else
		vty_out(vty, " subscriber-create-on-demand%s%s",
			gsmnet->auto_assign_exten ? "" : " no-extension",
			VTY_NEWLINE);

	if (gsmnet->ext_min != GSM_MIN_EXTEN || gsmnet->ext_max != GSM_MAX_EXTEN)
		vty_out(vty, " subscriber-create-on-demand random %"PRIu64" %"
			PRIu64"%s", gsmnet->ext_min, gsmnet->ext_max,
			VTY_NEWLINE);
	vty_out(vty, " %sassign-tmsi%s",
		gsmnet->avoid_tmsi ? "no " : "", VTY_NEWLINE);
	return CMD_SUCCESS;
}

int bsc_vty_init_extra(void)
{
	osmo_signal_register_handler(SS_SCALL, scall_cbfn, NULL);

	install_element_ve(&show_subscr_cmd);
	install_element_ve(&show_subscr_cache_cmd);

	install_element_ve(&sms_send_pend_cmd);

	install_element_ve(&subscriber_create_cmd);
	install_element_ve(&subscriber_send_sms_cmd);
	install_element_ve(&subscriber_silent_sms_cmd);
	install_element_ve(&subscriber_silent_call_start_cmd);
	install_element_ve(&subscriber_silent_call_stop_cmd);
	install_element_ve(&subscriber_ussd_notify_cmd);
	install_element_ve(&subscriber_update_cmd);
	install_element_ve(&show_stats_cmd);
	install_element_ve(&show_smsqueue_cmd);
	install_element_ve(&logging_fltr_imsi_cmd);

	install_element(ENABLE_NODE, &ena_subscr_delete_cmd);
	install_element(ENABLE_NODE, &ena_subscr_expire_cmd);
	install_element(ENABLE_NODE, &ena_subscr_name_cmd);
	install_element(ENABLE_NODE, &ena_subscr_extension_cmd);
	install_element(ENABLE_NODE, &ena_subscr_authorized_cmd);
	install_element(ENABLE_NODE, &ena_subscr_a3a8_cmd);
	install_element(ENABLE_NODE, &ena_subscr_handover_cmd);
	install_element(ENABLE_NODE, &subscriber_purge_cmd);
	install_element(ENABLE_NODE, &smsqueue_trigger_cmd);
	install_element(ENABLE_NODE, &smsqueue_max_cmd);
	install_element(ENABLE_NODE, &smsqueue_clear_cmd);
	install_element(ENABLE_NODE, &smsqueue_fail_cmd);
	install_element(ENABLE_NODE, &subscriber_send_pending_sms_cmd);
	install_element(ENABLE_NODE, &meas_feed_scenario_cmd);

	install_element(CONFIG_NODE, &cfg_mncc_int_cmd);
	install_node(&mncc_int_node, config_write_mncc_int);
	vty_install_default(MNCC_INT_NODE);
	install_element(MNCC_INT_NODE, &mnccint_def_codec_f_cmd);
	install_element(MNCC_INT_NODE, &mnccint_def_codec_h_cmd);
	install_element(MNCC_INT_NODE, &mnccint_meas_feed_cmd);
	install_element(MNCC_INT_NODE, &meas_feed_scenario_cmd);

	install_element(CFG_LOG_NODE, &log_level_sms_cmd);
	install_element(CFG_LOG_NODE, &logging_fltr_imsi_cmd);


	install_element(CONFIG_NODE, &cfg_nitb_cmd);
	install_node(&nitb_node, config_write_nitb);
	install_element(NITB_NODE, &cfg_nitb_subscr_create_cmd);
	install_element(NITB_NODE, &cfg_nitb_subscr_random_cmd);
	install_element(NITB_NODE, &cfg_nitb_no_subscr_create_cmd);
	install_element(NITB_NODE, &cfg_nitb_assign_tmsi_cmd);
	install_element(NITB_NODE, &cfg_nitb_no_assign_tmsi_cmd);

	return 0;
}
