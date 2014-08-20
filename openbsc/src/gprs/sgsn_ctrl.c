/* Control Interface Implementation for the SGSN */
/*
 * (C) 2014 by Holger Hans Peter Freyther
 * (C) 2014 by sysmocom s.f.m.c. GmbH
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

#include <osmocom/ctrl/control_if.h>
#include <osmocom/ctrl/control_cmd.h>
#include <openbsc/gsm_data.h>
#include <openbsc/gprs_sgsn.h>
#include <openbsc/sgsn.h>
#include <openbsc/debug.h>

#include <pdp.h>

extern vector ctrl_node_vec;

static int verify_subscriber_list(struct ctrl_cmd *cmd, const char *v, void *d)
{
	return 1;
}

static int set_subscriber_list(struct ctrl_cmd *cmd, void *d)
{
	cmd->reply = "Get only attribute";
	return CTRL_CMD_ERROR;
}

static int get_subscriber_list(struct ctrl_cmd *cmd, void *d)
{
	struct sgsn_mm_ctx *mm;

	cmd->reply = talloc_strdup(cmd, "");
	llist_for_each_entry(mm, &sgsn_mm_ctxts, list) {
		char *addr = NULL;
		struct sgsn_pdp_ctx *pdp;

		if (strlen(mm->imsi) == 0)
			continue;

		llist_for_each_entry(pdp, &mm->pdp_list, list)
			addr = gprs_pdpaddr2str(pdp->lib->eua.v,
						pdp->lib->eua.l);

		cmd->reply = talloc_asprintf_append(
					cmd->reply,
					"%s,%s\n", mm->imsi, addr ? addr : "");
	}

	return CTRL_CMD_REPLY;
}
CTRL_CMD_DEFINE(subscriber_list, "subscriber-list-active-v1");

int sgsn_ctrl_cmds_install(void)
{
	int rc = 0;
	rc |= ctrl_cmd_install(CTRL_NODE_ROOT, &cmd_subscriber_list);
	return rc;
}

static int sgsn_cmd_handle(struct ctrl_cmd *cmd, void *data)
{
	char *request;
	cmd->reply = NULL;
	cmd->node = NULL;
	vector vline, cmdvec, cmds_vec;
	int i, ret;

	ret = CTRL_CMD_ERROR;

	request = talloc_strdup(tall_bsc_ctx, cmd->variable);
	if (!request)
		goto err;

	for (i = 0; i < strlen(request); ++i) {
		if (request[i] == '.')
			request[i] = ' ';
	}

	vline = cmd_make_strvec(request);
	talloc_free(request);
	if (!vline) {
		cmd->reply = "cmd_make_strvec failed.";
		goto err;
	}

	/* If we're here the rest must be the command */
	cmdvec = vector_init(vector_active(vline));
	for (i = 0 ; i < vector_active(vline); ++i) {
		vector_set(cmdvec, vector_slot(vline, i));
	}

	/* Get the command vector of the right node */
	cmds_vec = vector_lookup(ctrl_node_vec, CTRL_NODE_ROOT);

	if (!cmds_vec) {
		cmd->reply = "Command not found.";
		vector_free(cmdvec);
		goto err;
	}

	ret = ctrl_cmd_exec(cmdvec, cmd, cmds_vec, data);

	vector_free(cmdvec);
	cmd_free_strvec(vline);

err:
	if (!cmd->reply) {
		LOGP(DCTRL, LOGL_ERROR, "cmd->reply has not been set.\n");
		if (ret == CTRL_CMD_ERROR)
			cmd->reply = "An error has occured.";
		else
			cmd->reply = "Command has been handled.";
	}

	if (ret == CTRL_CMD_ERROR)
		cmd->type = CTRL_TYPE_ERROR;
	return ret;
}

struct ctrl_handle *sgsn_controlif_setup(struct gsm_network *net, uint16_t port)
{
	return controlif_setup(net, port, sgsn_cmd_handle);
}
