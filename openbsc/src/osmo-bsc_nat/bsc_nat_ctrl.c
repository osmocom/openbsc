/*
 * (C) 2011-2012 by Holger Hans Peter Freyther
 * (C) 2011-2012 by On-Waves
 * (C) 2011 by Daniel Willmann
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

#include <osmocom/ctrl/control_cmd.h>
#include <osmocom/ctrl/control_if.h>
#include <osmocom/ctrl/ports.h>

#include <osmocom/vty/misc.h>

#include <openbsc/ctrl.h>
#include <openbsc/bsc_nat.h>
#include <openbsc/bsc_msg_filter.h>
#include <openbsc/vty.h>
#include <openbsc/gsm_data.h>

#include <unistd.h>
#include <string.h>
#include <errno.h>


#define NAT_MAX_CTRL_ID 65535

static struct bsc_nat *g_nat;

static int bsc_id_unused(int id, struct bsc_connection *bsc)
{
	struct bsc_cmd_list *pending;

	llist_for_each_entry(pending, &bsc->cmd_pending, list_entry) {
		if (pending->nat_id == id)
			return 0;
	}
	return 1;
}

static int get_next_free_bsc_id(struct bsc_connection *bsc)
{
	int new_id, overflow = 0;

	new_id = bsc->last_id;

	do {
		new_id++;
		if (new_id == NAT_MAX_CTRL_ID) {
			new_id = 1;
			overflow++;
		}

		if (bsc_id_unused(new_id, bsc)) {
			bsc->last_id = new_id;
			return new_id;
		}
	} while (overflow != 2);

	return -1;
}

void bsc_nat_ctrl_del_pending(struct bsc_cmd_list *pending)
{
	llist_del(&pending->list_entry);
	osmo_timer_del(&pending->timeout);
	talloc_free(pending->cmd);
	talloc_free(pending);
}

static struct bsc_cmd_list *bsc_get_pending(struct bsc_connection *bsc, char *id_str)
{
	struct bsc_cmd_list *cmd_entry;
	int id = atoi(id_str);
	if (id == 0)
		return NULL;

	llist_for_each_entry(cmd_entry, &bsc->cmd_pending, list_entry) {
		if (cmd_entry->nat_id == id) {
			return cmd_entry;
		}
	}
	return NULL;
}

int bsc_nat_handle_ctrlif_msg(struct bsc_connection *bsc, struct msgb *msg)
{
	struct ctrl_cmd *cmd;
	struct bsc_cmd_list *pending;
	char *var, *id;

	cmd = ctrl_cmd_parse(bsc, msg);
	msgb_free(msg);

	if (!cmd) {
		cmd = talloc_zero(bsc, struct ctrl_cmd);
		if (!cmd) {
			LOGP(DNAT, LOGL_ERROR, "OOM!\n");
			return -ENOMEM;
		}
		cmd->type = CTRL_TYPE_ERROR;
		cmd->id = "err";
		cmd->reply = "Failed to parse command.";
		goto err;
	}

	if (bsc->cfg && !llist_empty(&bsc->cfg->lac_list)) {
		if (cmd->variable) {
			var = talloc_asprintf(cmd, "net.0.bsc.%i.%s", bsc->cfg->nr,
					   cmd->variable);
			if (!var) {
				cmd->type = CTRL_TYPE_ERROR;
				cmd->reply = "OOM";
				goto err;
			}
			talloc_free(cmd->variable);
			cmd->variable = var;
		}

		/* We have to handle TRAPs before matching pending */
		if (cmd->type == CTRL_TYPE_TRAP) {
			ctrl_cmd_send_to_all(bsc->nat->ctrl, cmd);
			talloc_free(cmd);
			return 0;
		}

		/* Find the pending command */
		pending = bsc_get_pending(bsc, cmd->id);
		if (pending) {
			id = talloc_strdup(cmd, pending->cmd->id);
			if (!id) {
				cmd->type = CTRL_TYPE_ERROR;
				cmd->reply = "OOM";
				goto err;
			}
			cmd->id = id;
			ctrl_cmd_send(&pending->ccon->write_queue, cmd);
			bsc_nat_ctrl_del_pending(pending);
		} else {
			/* We need to handle TRAPS here */
			if ((cmd->type != CTRL_TYPE_ERROR) &&
			    (cmd->type != CTRL_TYPE_TRAP)) {
				LOGP(DNAT, LOGL_NOTICE, "Got control message "
					"from BSC without pending entry\n");
				cmd->type = CTRL_TYPE_ERROR;
				cmd->reply = "No request outstanding";
				goto err;
			}
		}
	}
	talloc_free(cmd);
	return 0;
err:
	ctrl_cmd_send(&bsc->write_queue, cmd);
	talloc_free(cmd);
	return 0;
}

static void pending_timeout_cb(void *data)
{
	struct bsc_cmd_list *pending = data;
	LOGP(DNAT, LOGL_ERROR, "Command timed out\n");
	pending->cmd->type = CTRL_TYPE_ERROR;
	pending->cmd->reply = "Command timed out";
	ctrl_cmd_send(&pending->ccon->write_queue, pending->cmd);

	bsc_nat_ctrl_del_pending(pending);
}

static void ctrl_conn_closed_cb(struct ctrl_connection *connection)
{
	struct bsc_connection *bsc;
	struct bsc_cmd_list *pending, *tmp;

	llist_for_each_entry(bsc, &g_nat->bsc_connections, list_entry) {
		llist_for_each_entry_safe(pending, tmp, &bsc->cmd_pending, list_entry) {
			if (pending->ccon == connection)
				bsc_nat_ctrl_del_pending(pending);
		}
	}
}

static int extract_bsc_nr_variable(char *variable, unsigned int *nr, char **bsc_variable)
{
	char *nr_str, *tmp, *saveptr = NULL;

	tmp = strtok_r(variable, ".", &saveptr);
	tmp = strtok_r(NULL, ".", &saveptr);
	tmp = strtok_r(NULL, ".", &saveptr);
	nr_str = strtok_r(NULL, ".", &saveptr);
	if (!nr_str)
		return 0;
	*nr = atoi(nr_str);

	tmp = strtok_r(NULL, "\0", &saveptr);
	if (!tmp)
		return 0;

	*bsc_variable = tmp;
	return 1;
}

static int forward_to_bsc(struct ctrl_cmd *cmd)
{
	int ret = CTRL_CMD_HANDLED;
	struct ctrl_cmd *bsc_cmd = NULL;
	struct bsc_connection *bsc;
	struct bsc_cmd_list *pending;
	unsigned int nr;
	char *bsc_variable;

	/* Skip over the beginning (bsc.) */
	if (!extract_bsc_nr_variable(cmd->variable, &nr, &bsc_variable)) {
		cmd->reply = "command incomplete";
		goto err;
	}


	llist_for_each_entry(bsc, &g_nat->bsc_connections, list_entry) {
		if (!bsc->cfg)
			continue;
		if (!bsc->authenticated)
			continue;
		if (bsc->cfg->nr == nr) {
			/* Add pending command to list */
			pending = talloc_zero(bsc, struct bsc_cmd_list);
			if (!pending) {
				cmd->reply = "OOM";
				goto err;
			}

			pending->nat_id = get_next_free_bsc_id(bsc);
			if (pending->nat_id < 0) {
				cmd->reply = "No free ID found";
				goto err;
			}

			bsc_cmd = ctrl_cmd_cpy(bsc, cmd);
			if (!bsc_cmd) {
				cmd->reply = "Could not forward command";
				goto err;
			}

			talloc_free(bsc_cmd->id);
			bsc_cmd->id = talloc_asprintf(bsc_cmd, "%i", pending->nat_id);
			if (!bsc_cmd->id) {
				cmd->reply = "OOM";
				goto err;
			}

			talloc_free(bsc_cmd->variable);
			bsc_cmd->variable = talloc_strdup(bsc_cmd, bsc_variable);
			if (!bsc_cmd->variable) {
				cmd->reply = "OOM";
				goto err;
			}

			if (ctrl_cmd_send(&bsc->write_queue, bsc_cmd)) {
				cmd->reply = "Sending failed";
				goto err;
			}
			pending->ccon = cmd->ccon;
			pending->ccon->closed_cb = ctrl_conn_closed_cb;
			pending->cmd = cmd;

			/* Setup the timeout */
			osmo_timer_setup(&pending->timeout, pending_timeout_cb,
					 pending);
			/* TODO: Make timeout configurable */
			osmo_timer_schedule(&pending->timeout, 10, 0);
			llist_add_tail(&pending->list_entry, &bsc->cmd_pending);

			goto done;
		}
	}
	/* We end up here if there's no bsc to handle our LAC */
	cmd->reply = "no BSC with this nr";
err:
	ret = CTRL_CMD_ERROR;
done:
	talloc_free(bsc_cmd);
	return ret;

}


CTRL_CMD_DEFINE(fwd_cmd, "net 0 bsc *");
static int get_fwd_cmd(struct ctrl_cmd *cmd, void *data)
{
	return forward_to_bsc(cmd);
}

static int set_fwd_cmd(struct ctrl_cmd *cmd, void *data)
{
	return forward_to_bsc(cmd);
}

static int verify_fwd_cmd(struct ctrl_cmd *cmd, const char *value, void *data)
{
	return 0;
}

static int extract_bsc_cfg_variable(struct ctrl_cmd *cmd, struct bsc_config **cfg,
				char **bsc_variable)
{
	unsigned int nr;

	if (!extract_bsc_nr_variable(cmd->variable, &nr, bsc_variable)) {
		cmd->reply = "command incomplete";
		return 0;
	}

	*cfg = bsc_config_num(g_nat, nr);
	if (!*cfg) {
		cmd->reply = "Unknown BSC";
		return 0;
	}

	return 1;
}

CTRL_CMD_DEFINE(net_cfg_cmd, "net 0 bsc_cfg *");
static int get_net_cfg_cmd(struct ctrl_cmd *cmd, void *data)
{
	char *bsc_variable;
	struct bsc_config *bsc_cfg;

	if (!extract_bsc_cfg_variable(cmd, &bsc_cfg, &bsc_variable))
		return CTRL_CMD_ERROR;

	if (strcmp(bsc_variable, "access-list-name") == 0) {
		cmd->reply = talloc_asprintf(cmd, "%s",
				bsc_cfg->acc_lst_name ? bsc_cfg->acc_lst_name : "");
		return CTRL_CMD_REPLY;
	}

	cmd->reply = "unknown command";
	return CTRL_CMD_ERROR;
}

static int set_net_cfg_cmd(struct ctrl_cmd *cmd, void *data)
{
	char *bsc_variable;
	struct bsc_config *bsc_cfg;

	if (!extract_bsc_cfg_variable(cmd, &bsc_cfg, &bsc_variable))
		return CTRL_CMD_ERROR;

	if (strcmp(bsc_variable, "access-list-name") == 0) {
		osmo_talloc_replace_string(bsc_cfg, &bsc_cfg->acc_lst_name, cmd->value);
		cmd->reply = talloc_asprintf(cmd, "%s",
				bsc_cfg->acc_lst_name ? bsc_cfg->acc_lst_name : "");
		return CTRL_CMD_REPLY;
	} else if (strcmp(bsc_variable, "no-access-list-name") == 0) {
		talloc_free(bsc_cfg->acc_lst_name);
		bsc_cfg->acc_lst_name = NULL;
		cmd->reply = "";
		return CTRL_CMD_REPLY;
	}

	cmd->reply = "unknown command";
	return CTRL_CMD_ERROR;
}

static int verify_net_cfg_cmd(struct ctrl_cmd *cmd, const char *value, void *data)
{
	return 0;
}

CTRL_CMD_DEFINE(net_cfg_acc_cmd, "net 0 add allow access-list *");
static const char *extract_acc_name(const char *var)
{
	char *str;

	str = strstr(var, "net.0.add.allow.access-list.");
	if (!str)
		return NULL;
	str += strlen("net.0.add.allow.access-list.");
	if (strlen(str) == 0)
		return NULL;
	return str;
}

static int get_net_cfg_acc_cmd(struct ctrl_cmd *cmd, void *data)
{
	cmd->reply = "Append only";
	return CTRL_CMD_ERROR;
}

static int set_net_cfg_acc_cmd(struct ctrl_cmd *cmd, void *data)
{
	const char *access_name = extract_acc_name(cmd->variable);
	struct bsc_msg_acc_lst *acc;
	struct bsc_msg_acc_lst_entry *entry;
	const char *value = cmd->value;
	int rc;

	/* Should have been caught by verify_net_cfg_acc_cmd */
	acc = bsc_msg_acc_lst_find(&g_nat->access_lists, access_name);
	if (!acc) {
		cmd->reply = "Access list not found";
		return CTRL_CMD_ERROR;
	}

	entry = bsc_msg_acc_lst_entry_create(acc);
	if (!entry) {
		cmd->reply = "OOM";
		return CTRL_CMD_ERROR;
	}

	rc = gsm_parse_reg(acc, &entry->imsi_allow_re, &entry->imsi_allow, 1, &value);
	if (rc !=  0) {
		cmd->reply = "Failed to compile expression";
		return CTRL_CMD_ERROR;
	}

	cmd->reply = "IMSI allow added to access list";
	return CTRL_CMD_REPLY;
}

static int verify_net_cfg_acc_cmd(struct ctrl_cmd *cmd, const char *value, void *data)
{
	const char *access_name = extract_acc_name(cmd->variable);
	struct bsc_msg_acc_lst *acc = bsc_msg_acc_lst_find(&g_nat->access_lists, access_name);

	if (!acc) {
		cmd->reply = "Access list not known";
		return -1;
	}

	return 0;
}

CTRL_CMD_DEFINE_WO_NOVRF(net_save_cmd, "net 0 save-configuration");

static int set_net_save_cmd(struct ctrl_cmd *cmd, void *data)
{
	int rc = osmo_vty_save_config_file();
	cmd->reply = talloc_asprintf(cmd, "%d", rc);
	if (!cmd->reply) {
		cmd->reply = "OOM";
		return CTRL_CMD_ERROR;
	}

	return CTRL_CMD_REPLY;
}

struct ctrl_handle *bsc_nat_controlif_setup(struct bsc_nat *nat,
					    const char *bind_addr, int port)
{
	struct ctrl_handle *ctrl;
	int rc;


	ctrl = bsc_controlif_setup(NULL, bind_addr, OSMO_CTRL_PORT_BSC_NAT);
	if (!ctrl) {
		fprintf(stderr, "Failed to initialize the control interface. Exiting.\n");
		return NULL;
	}

	rc = ctrl_cmd_install(CTRL_NODE_ROOT, &cmd_fwd_cmd);
	if (rc) {
		fprintf(stderr, "Failed to install the control command. Exiting.\n");
		goto error;
	}
	rc = ctrl_cmd_install(CTRL_NODE_ROOT, &cmd_net_cfg_cmd);
	if (rc) {
		fprintf(stderr, "Failed to install the net cfg command. Exiting.\n");
		goto error;
	}
	rc = ctrl_cmd_install(CTRL_NODE_ROOT, &cmd_net_cfg_acc_cmd);
	if (rc) {
		fprintf(stderr, "Failed to install the net acc command. Exiting.\n");
		goto error;
	}
	rc = ctrl_cmd_install(CTRL_NODE_ROOT, &cmd_net_save_cmd);
	if (rc) {
		fprintf(stderr, "Failed to install the net save command. Exiting.\n");
		goto error;
	}

	g_nat = nat;
	return ctrl;

error:
	osmo_fd_unregister(&ctrl->listen_fd);
	close(ctrl->listen_fd.fd);
	talloc_free(ctrl);
	return NULL;
}

void bsc_nat_inform_reject(struct bsc_connection *conn, const char *imsi)
{
	struct ctrl_cmd *cmd;

	cmd = ctrl_cmd_create(conn, CTRL_TYPE_TRAP);
	if (!cmd) {
		LOGP(DCTRL, LOGL_ERROR, "Failed to create TRAP command.\n");
		return;
	}

	cmd->id = "0";
	cmd->variable = talloc_asprintf(cmd, "net.0.bsc.%d.notification-rejection-v1",
					conn->cfg->nr);
	cmd->reply = talloc_asprintf(cmd, "imsi=%s", imsi);

	ctrl_cmd_send_to_all(conn->cfg->nat->ctrl, cmd);
	talloc_free(cmd);
}
