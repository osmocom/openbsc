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
#include <openbsc/control_cmd.h>
#include <openbsc/gsm_data.h>
#include <openbsc/gsm_subscriber.h>
#include <openbsc/db.h>

static int verify_subscriber_modify(struct ctrl_cmd *cmd, const char *value, void *d)
{
	char *tmp, *imsi, *msisdn, *saveptr = NULL;

	tmp = talloc_strdup(cmd, value);
	if (!tmp)
		return 1;

	imsi = strtok_r(tmp, ",", &saveptr);
	msisdn = strtok_r(NULL, ",", &saveptr);
	talloc_free(tmp);

	if (!imsi || !msisdn)
		return 1;
	if (strlen(imsi) >= GSM_IMSI_LENGTH)
		return 1;
	if (strlen(msisdn) >= GSM_EXTENSION_LENGTH)
		return 1;
	return 0;
}

static int get_subscriber_modify(struct ctrl_cmd *cmd, void *data)
{
	cmd->reply = "Set only attribute";
	return CTRL_CMD_ERROR;
}

static int set_subscriber_modify(struct ctrl_cmd *cmd, void *data)
{
	struct gsm_network *net = cmd->node;
	char *tmp, *imsi, *msisdn, *saveptr = NULL;
	struct gsm_subscriber* subscr;
	int rc;

	tmp = talloc_strdup(cmd, cmd->value);
	if (!tmp)
		return 1;

	imsi = strtok_r(tmp, ",", &saveptr);
	msisdn = strtok_r(NULL, ",", &saveptr);

	subscr = subscr_get_by_imsi(net, imsi);
	if (!subscr)
		subscr = subscr_create_subscriber(net, imsi);
	if (!subscr)
		goto fail;

	subscr->authorized = 1;
	strncpy(subscr->extension, msisdn, GSM_EXTENSION_LENGTH - 1);
	subscr->extension[GSM_EXTENSION_LENGTH-1] = '\0';

	/* put it back to the db */
	rc = db_sync_subscriber(subscr);
	db_subscriber_update(subscr);
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

CTRL_CMD_DEFINE(subscriber_modify, "subscriber-modify-v1");

int msc_ctrl_cmds_install(void)
{
	int rc = 0;

	rc |= ctrl_cmd_install(CTRL_NODE_ROOT, &cmd_subscriber_modify);
	return rc;
}
