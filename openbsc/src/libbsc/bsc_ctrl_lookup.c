/* SNMP-like status interface. Look-up of BTS/TRX
 *
 * (C) 2010-2011 by Daniel Willmann <daniel@totalueberwachung.de>
 * (C) 2010-2011 by On-Waves
 *
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

#include <openbsc/control_if.h>
#include <openbsc/debug.h>

extern vector ctrl_node_vec;

static int get_num(vector vline, int i, long *num)
{
	char *token, *tmp;

	if (i >= vector_active(vline))
		return 0;
	token = vector_slot(vline, i);

	errno = 0;
	if (token[0] == '\0')
		return 0;

	*num = strtol(token, &tmp, 10);
	if (tmp[0] != '\0' || errno != 0)
		return 0;

	return 1;
}

int bsc_ctrl_cmd_handle(struct ctrl_cmd *cmd, void *data)
{
	char *token, *request;
	long num;
	int i, j, ret, node;

	struct gsm_network *net = data;
	struct gsm_bts *bts = NULL;
	struct gsm_bts_trx *trx = NULL;
	struct gsm_bts_trx_ts *ts = NULL;
	vector vline, cmdvec, cmds_vec;

	ret = CTRL_CMD_ERROR;
	cmd->reply = NULL;
	node = CTRL_NODE_ROOT;
	cmd->node = net;

	request = talloc_strdup(tall_bsc_ctx, cmd->variable);
	if (!request)
		goto err;

	for (i=0;i<strlen(request);i++) {
		if (request[i] == '.')
			request[i] = ' ';
	}

	vline = cmd_make_strvec(request);
	talloc_free(request);
	if (!vline) {
		cmd->reply = "cmd_make_strvec failed.";
		goto err;
	}

	for (i=0;i<vector_active(vline);i++) {
		token = vector_slot(vline, i);
		/* TODO: We need to make sure that the following chars are digits
		 * and/or use strtol to check if number conversion was successful
		 * Right now something like net.bts_stats will not work */
		if (!strcmp(token, "bts")) {
			if (!net)
				goto err_missing;
			i++;
			if (!get_num(vline, i, &num))
				goto err_index;

			bts = gsm_bts_num(net, num);
			if (!bts)
				goto err_missing;
			cmd->node = bts;
			node = CTRL_NODE_BTS;
		} else if (!strcmp(token, "trx")) {
			if (!bts)
				goto err_missing;
			i++;
			if (!get_num(vline, i, &num))
				goto err_index;

			trx = gsm_bts_trx_num(bts, num);
			if (!trx)
				goto err_missing;
			cmd->node = trx;
			node = CTRL_NODE_TRX;
		} else if (!strcmp(token, "ts")) {
			if (!trx)
				goto err_missing;
			i++;
			if (!get_num(vline, i, &num))
				goto err_index;

			if ((num >= 0) && (num < TRX_NR_TS))
				ts = &trx->ts[num];
			if (!ts)
				goto err_missing;
			cmd->node = ts;
			node = CTRL_NODE_TS;
		} else {
			/* If we're here the rest must be the command */
			cmdvec = vector_init(vector_active(vline)-i);
			for (j=i; j<vector_active(vline); j++) {
				vector_set(cmdvec, vector_slot(vline, j));
			}

			/* Get the command vector of the right node */
			cmds_vec = vector_lookup(ctrl_node_vec, node);

			if (!cmds_vec) {
				cmd->reply = "Command not found.";
				vector_free(cmdvec);
				break;
			}

			ret = ctrl_cmd_exec(cmdvec, cmd, cmds_vec, data);

			vector_free(cmdvec);
			break;
		}

		if (i+1 == vector_active(vline))
			cmd->reply = "Command not present.";
	}

	cmd_free_strvec(vline);

err:
	if (!cmd->reply) {
		if (ret == CTRL_CMD_ERROR) {
			cmd->reply = "An error has occured.";
			LOGP(DCTRL, LOGL_NOTICE,
			     "%s: cmd->reply has not been set (ERROR).\n",
			     cmd->variable);
		} else if (ret == CTRL_CMD_REPLY) {
			LOGP(DCTRL, LOGL_NOTICE,
			     "%s: cmd->reply has not been set (type = %d).\n",
			     cmd->variable, cmd->type);
			cmd->reply = "";
		} else {
			cmd->reply = "Command has been handled.";
		}
	}

	if (ret == CTRL_CMD_ERROR)
		cmd->type = CTRL_TYPE_ERROR;
	return ret;

err_missing:
	cmd_free_strvec(vline);
	cmd->type = CTRL_TYPE_ERROR;
	cmd->reply = "Error while resolving object";
	return ret;
err_index:
	cmd_free_strvec(vline);
	cmd->type = CTRL_TYPE_ERROR;
	cmd->reply = "Error while parsing the index.";
	return ret;
}

struct ctrl_handle *bsc_controlif_setup(struct gsm_network *net, uint16_t port)
{
	return controlif_setup(net, port, bsc_ctrl_cmd_handle);
}
