/*
 * (C) 2014 by Holger Hans Peter Freyther
 * (C) 2014 by sysmocom s.f.m.c. GmbH
 *
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

#include <osmocom/ctrl/control_cmd.h>
#include <osmocom/core/utils.h>
#include <openbsc/gsm_data.h>
#include <openbsc/gsm_subscriber.h>
#include <openbsc/db.h>
#include <openbsc/debug.h>

#include <stdbool.h>

static bool alg_supported(const char *alg)
{
	/*
	 * TODO: share this with the vty_interface and extend to all
	 * algorithms supported by libosmocore now. Make it table based
	 * as well.
	 */
	if (strcasecmp(alg, "none") == 0)
		return true;
	if (strcasecmp(alg, "xor") == 0)
		return true;
	if (strcasecmp(alg, "comp128v1") == 0)
		return true;
	return false;
}

static int verify_subscriber_modify(struct ctrl_cmd *cmd, const char *value, void *d)
{
	char *tmp, *imsi, *msisdn, *alg, *ki, *saveptr = NULL;
	int rc = 0;

	tmp = talloc_strdup(cmd, value);
	if (!tmp)
		return 1;

	imsi = strtok_r(tmp, ",", &saveptr);
	msisdn = strtok_r(NULL, ",", &saveptr);
	alg = strtok_r(NULL, ",", &saveptr);
	ki = strtok_r(NULL, ",", &saveptr);

	if (!imsi || !msisdn)
		rc = 1;
	else if (strlen(imsi) > GSM23003_IMSI_MAX_DIGITS)
		rc = 1;
	else if (strlen(msisdn) >= GSM_EXTENSION_LENGTH)
		rc = 1;
	else if (alg) {
		if (!alg_supported(alg))
			rc = 1;
		else if (strcasecmp(alg, "none") != 0 && !ki)
			rc = 1;
	}

	talloc_free(tmp);
	return rc;
}

static int set_subscriber_modify(struct ctrl_cmd *cmd, void *data)
{
	struct gsm_network *net = cmd->node;
	char *tmp, *imsi, *msisdn, *alg, *ki, *saveptr = NULL;
	struct gsm_subscriber* subscr;
	int rc;

	tmp = talloc_strdup(cmd, cmd->value);
	if (!tmp)
		return 1;

	imsi = strtok_r(tmp, ",", &saveptr);
	msisdn = strtok_r(NULL, ",", &saveptr);
	alg = strtok_r(NULL, ",", &saveptr);
	ki = strtok_r(NULL, ",", &saveptr);

	subscr = subscr_get_by_imsi(net->subscr_group, imsi);
	if (!subscr)
		subscr = subscr_create_subscriber(net->subscr_group, imsi);
	if (!subscr)
		goto fail;

	subscr->authorized = 1;
	osmo_strlcpy(subscr->extension, msisdn, sizeof(subscr->extension));

	/* put it back to the db */
	rc = db_sync_subscriber(subscr);
	db_subscriber_update(subscr);

	/* handle optional ciphering */
	if (alg) {
		if (strcasecmp(alg, "none") == 0)
			db_sync_authinfo_for_subscr(NULL, subscr);
		else {
			struct gsm_auth_info ainfo = { 0, };
			/* the verify should make sure that this is okay */
			OSMO_ASSERT(alg);
			OSMO_ASSERT(ki);

			if (strcasecmp(alg, "xor") == 0)
				ainfo.auth_algo = AUTH_ALGO_XOR;
			else if (strcasecmp(alg, "comp128v1") == 0)
				ainfo.auth_algo = AUTH_ALGO_COMP128v1;

			rc = osmo_hexparse(ki, ainfo.a3a8_ki, sizeof(ainfo.a3a8_ki));
			if (rc < 0) {
				subscr_put(subscr);
				talloc_free(tmp);
				cmd->reply = "Failed to parse KI";
				return CTRL_CMD_ERROR;
			}

			ainfo.a3a8_ki_len = rc;
			db_sync_authinfo_for_subscr(&ainfo, subscr);
			rc = 0;
		}
		db_sync_lastauthtuple_for_subscr(NULL, subscr);
	}
	subscr_put(subscr);

	talloc_free(tmp);

	if (rc != 0) {
		cmd->reply = "Failed to store the record in the DB";
		return CTRL_CMD_ERROR;
	}

	cmd->reply = "OK";
	return CTRL_CMD_REPLY;

fail:
	talloc_free(tmp);
	cmd->reply = "Failed to create subscriber";
	return CTRL_CMD_ERROR;
}

CTRL_CMD_DEFINE_WO(subscriber_modify, "subscriber-modify-v1");

static int set_subscriber_delete(struct ctrl_cmd *cmd, void *data)
{
	int was_used = 0;
	int rc;
	struct gsm_subscriber *subscr;
	struct gsm_network *net = cmd->node;

	subscr = subscr_get_by_imsi(net->subscr_group, cmd->value);
	if (!subscr) {
		cmd->reply = "Failed to find subscriber";
		return CTRL_CMD_ERROR;
	}

	if (subscr->use_count != 1) {
		LOGP(DCTRL, LOGL_NOTICE, "Going to remove active subscriber.\n");
		was_used = 1;
	}

	rc = db_subscriber_delete(subscr);
	subscr_put(subscr);

	if (rc != 0) {
		cmd->reply = "Failed to remove subscriber";
		return CTRL_CMD_ERROR;
	}

	cmd->reply = was_used ? "Removed active subscriber" : "Removed";
	return CTRL_CMD_REPLY;
}
CTRL_CMD_DEFINE_WO_NOVRF(subscriber_delete, "subscriber-delete-v1");

static void list_cb(struct gsm_subscriber *subscr, void *d)
{
	char **data = (char **) d;
	*data = talloc_asprintf_append(*data, "%s,%s\n",
				subscr->imsi, subscr->extension);
}

static int get_subscriber_list(struct ctrl_cmd *cmd, void *d)
{
	cmd->reply = talloc_strdup(cmd, "");

	db_subscriber_list_active(list_cb, &cmd->reply);
	printf("%s\n", cmd->reply);
	return CTRL_CMD_REPLY;
}
CTRL_CMD_DEFINE_RO(subscriber_list, "subscriber-list-active-v1");

int msc_ctrl_cmds_install(void)
{
	int rc = 0;

	rc |= ctrl_cmd_install(CTRL_NODE_ROOT, &cmd_subscriber_modify);
	rc |= ctrl_cmd_install(CTRL_NODE_ROOT, &cmd_subscriber_delete);
	rc |= ctrl_cmd_install(CTRL_NODE_ROOT, &cmd_subscriber_list);
	return rc;
}
