/* SNMP-like status interface
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

#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <arpa/inet.h>

#include <netinet/tcp.h>

#include <sys/fcntl.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>

#include <openbsc/control_cmd.h>
#include <openbsc/debug.h>
#include <openbsc/gsm_data.h>
#include <openbsc/ipaccess.h>
#include <openbsc/socket.h>
#include <osmocom/abis/subchan_demux.h>

#include <openbsc/abis_rsl.h>
#include <openbsc/abis_nm.h>

#include <osmocom/core/msgb.h>
#include <osmocom/core/rate_ctr.h>
#include <osmocom/core/select.h>
#include <osmocom/core/statistics.h>
#include <osmocom/core/talloc.h>

#include <osmocom/gsm/tlv.h>

#include <osmocom/vty/command.h>
#include <osmocom/vty/vector.h>

#include <osmocom/abis/e1_input.h>
#include <osmocom/abis/ipa.h>

struct ctrl_handle {
	struct ipa_server_link *ipa_link;
	struct gsm_network *gsmnet;
};

vector ctrl_node_vec;

int ctrl_cmd_send(struct ipa_server_conn *ipa_server_conn, struct ctrl_cmd *cmd)
{
	struct msgb *msg;

	msg = ctrl_cmd_make(cmd);
	if (!msg) {
		LOGP(DCTRL, LOGL_ERROR, "Could not generate msg\n");
		return -1;
	}

	ipaccess_prepend_header_ext(msg, IPAC_PROTO_EXT_CTRL);
	ipaccess_prepend_header(msg, IPAC_PROTO_OSMO);

	ipa_server_conn_send(ipa_server_conn, msg);
	return 0;
}

int ctrl_cmd_handle(struct ctrl_cmd *cmd, void *data)
{
	char *token, *request;
	int num, i, j, ret, node;
	struct gsm_network *gsmnet = data;

	struct gsm_network *net = NULL;
	struct gsm_bts *bts = NULL;
	struct gsm_bts_trx *trx = NULL;
	struct gsm_bts_trx_ts *ts = NULL;
	vector vline, cmdvec, cmds_vec;

	ret = CTRL_CMD_ERROR;
	cmd->reply = "Someone forgot to fill in the reply.";
	cmd->node = NULL;
	node = CTRL_NODE_ROOT;

	request = talloc_strdup(tall_bsc_ctx, cmd->variable);
	if (!request)
		goto err;

	for (i=0;i<strlen(request);i++) {
		if (request[i] == '.')
			request[i] = ' ';
	}

	vline = cmd_make_strvec(request);
	talloc_free(request);
	if (!vline)
		goto err;

	for (i=0;i<vector_active(vline);i++) {
		token = vector_slot(vline, i);
		/* TODO: We need to make sure that the following chars are digits
		 * and/or use strtol to check if number conversion was successful
		 * Right now something like net.bts_stats will not work */
		if (!strcmp(token, "net")) {
			net = gsmnet;
			if (!net)
				break;
			cmd->node = net;
			node = CTRL_NODE_NET;
		} else if (!strncmp(token, "bts", 3)) {
			if (!net)
				break;
			num = atoi(&token[3]);
			bts = gsm_bts_num(net, num);
			if (!bts)
				break;
			cmd->node = bts;
			node = CTRL_NODE_BTS;
		} else if (!strncmp(token, "trx", 3)) {
			if (!bts)
				break;
			num = atoi(&token[3]);
			trx = gsm_bts_trx_num(bts, num);
			if (!trx)
				break;
			cmd->node = trx;
			node = CTRL_NODE_TRX;
		} else if (!strncmp(token, "ts", 2)) {
			if (!trx)
				break;
			num = atoi(&token[2]);
			if ((num >= 0) && (num < TRX_NR_TS))
				ts = &trx->ts[num];
			if (!ts)
				break;
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
				cmd->reply = "Command not found";
				vector_free(cmdvec);
				break;
			}

			ret = ctrl_cmd_exec(cmdvec, cmd, cmds_vec, data);

			vector_free(cmdvec);
			break;
		}
	}

	cmd_free_strvec(vline);

err:
	if (ret == CTRL_CMD_ERROR)
		cmd->type = CTRL_TYPE_ERROR;
	return ret;
}

static int
handle_control_read(struct ipa_server_conn *ipa_server_conn, struct msgb *msg)
{
	int ret = -1;
	struct ipaccess_head *iph;
	struct ipaccess_head_ext *iph_ext;
	struct ctrl_cmd *cmd;
	struct ctrl_handle *ctrl = ipa_server_conn->data;

	iph = (struct ipaccess_head *) msg->data;
	if (iph->proto != IPAC_PROTO_OSMO) {
		LOGP(DCTRL, LOGL_ERROR, "Protocol mismatch. We got 0x%x\n", iph->proto);
		goto err;
	}

	iph_ext = (struct ipaccess_head_ext *) iph->data;
	if (iph_ext->proto != IPAC_PROTO_EXT_CTRL) {
		LOGP(DCTRL, LOGL_ERROR, "Extended protocol mismatch. We got 0x%x\n", iph_ext->proto);
		goto err;
	}

	msg->l2h = iph_ext->data;

	cmd = ctrl_cmd_parse(ipa_server_conn, msg);

	if (cmd) {
		cmd->ipa_link = ipa_server_conn;
		if (ctrl_cmd_handle(cmd, ctrl->gsmnet) != CTRL_CMD_HANDLED) {
			ctrl_cmd_send(ipa_server_conn, cmd);
			talloc_free(cmd);
		}
	} else {
		cmd = talloc_zero(ipa_server_conn, struct ctrl_cmd);
		if (!cmd)
			goto err;
		LOGP(DCTRL, LOGL_ERROR, "Command parser error.\n");
		cmd->type = CTRL_TYPE_ERROR;
		cmd->id = "err";
		cmd->reply = "Command parser error.";
		ctrl_cmd_send(ipa_server_conn, cmd);
		talloc_free(cmd);
	}

	msgb_free(msg);
	return 0;

err:
	ipa_server_conn_destroy(ipa_server_conn);
	msgb_free(msg);
	return ret;
}

static int ctrl_accept_cb(struct ipa_server_link *ipa_link, int fd)
{
	int ret, on = 1;
	struct ipa_server_conn *ipa_peer_link;

	ret = setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &on, sizeof(on));
	if (ret != 0) {
		LOGP(DNAT, LOGL_ERROR, "Failed to set TCP_NODELAY: %s\n", strerror(errno));
		close(fd);
		return ret;
	}
	ipa_peer_link = ipa_server_conn_create(tall_bsc_ctx, ipa_link, fd,
						handle_control_read,
						ipa_link->data);
	if (!ipa_peer_link) {
		LOGP(DCTRL, LOGL_ERROR, "Failed to register peer connection.\n");
		return -ENOMEM;
	}

	return 0;
}

static uint64_t get_rate_ctr_value(const struct rate_ctr *ctr, int intv)
{
	if (intv >= RATE_CTR_INTV_NUM)
		return 0;

	/* Absolute value */
	if (intv == -1) {
		return  ctr->current;
	} else {
		return ctr->intv[intv].rate;
	}
}

static char *get_all_rate_ctr_in_group(const struct rate_ctr_group *ctrg, int intv)
{
	int i;
	char *counters = talloc_strdup(tall_bsc_ctx, "");
	if (!counters)
		return NULL;

	for (i=0;i<ctrg->desc->num_ctr;i++) {
		counters = talloc_asprintf_append(counters, "\n%s.%u.%s %"PRIu64,
			ctrg->desc->group_name_prefix, ctrg->idx,
			ctrg->desc->ctr_desc[i].name,
			get_rate_ctr_value(&ctrg->ctr[i], intv));
		if (!counters)
			return NULL;
	}
	return counters;
}

static int get_rate_ctr_group(const char *ctr_group, int intv, struct ctrl_cmd *cmd)
{
	int i;
	char *counters;
	struct rate_ctr_group *ctrg;

	cmd->reply = talloc_asprintf(cmd, "All counters in group %s", ctr_group);
	if (!cmd->reply)
		goto oom;

	for (i=0;;i++) {
		ctrg = rate_ctr_get_group_by_name_idx(ctr_group, i);
		if (!ctrg)
			break;

		counters = get_all_rate_ctr_in_group(ctrg, intv);
		if (!counters)
			goto oom;

		cmd->reply = talloc_asprintf_append(cmd->reply, "%s", counters);
		talloc_free(counters);
		if (!cmd->reply)
			goto oom;
	}

	/* We found no counter group by that name */
	if (i == 0) {
		cmd->reply = talloc_asprintf(cmd, "No counter group with name %s.", ctr_group);
		return CTRL_CMD_ERROR;
	}

	return CTRL_CMD_REPLY;
oom:
	cmd->reply = "OOM.";
	return CTRL_CMD_ERROR;
}

static int get_rate_ctr_group_idx(const struct rate_ctr_group *ctrg, int intv, struct ctrl_cmd *cmd)
{
	char *counters;

	counters = get_all_rate_ctr_in_group(ctrg, intv);
	if (!counters)
		goto oom;

	cmd->reply = talloc_asprintf(cmd, "All counters in %s.%u%s",
			ctrg->desc->group_name_prefix, ctrg->idx, counters);
	talloc_free(counters);
	if (!cmd->reply)
		goto oom;

	return CTRL_CMD_REPLY;
oom:
	cmd->reply = "OOM.";
	return CTRL_CMD_ERROR;
}

/* rate_ctr */
CTRL_CMD_DEFINE(rate_ctr, "rate_ctr *");
static int get_rate_ctr(struct ctrl_cmd *cmd, void *data)
{
	int intv;
	unsigned int idx;
	char *ctr_group, *ctr_idx, *ctr_name, *tmp, *dup, *saveptr, *interval;
	struct rate_ctr_group *ctrg;
	const struct rate_ctr *ctr;

	dup = talloc_strdup(cmd, cmd->variable);
	if (!dup)
		goto oom;

	/* Skip over possible prefixes (net.) */
	tmp = strstr(dup, "rate_ctr");
	if (!tmp) {
		talloc_free(dup);
		cmd->reply = "rate_ctr not a token in rate_ctr command!";
		goto err;
	}

	strtok_r(tmp, ".", &saveptr);
	interval = strtok_r(NULL, ".", &saveptr);
	if (!interval) {
		talloc_free(dup);
		cmd->reply = "Missing interval.";
		goto err;
	}

	if (!strcmp(interval, "abs")) {
		intv = -1;
	} else if (!strcmp(interval, "per_sec")) {
		intv = RATE_CTR_INTV_SEC;
	} else if (!strcmp(interval, "per_min")) {
		intv = RATE_CTR_INTV_MIN;
	} else if (!strcmp(interval, "per_hour")) {
		intv = RATE_CTR_INTV_HOUR;
	} else if (!strcmp(interval, "per_day")) {
		intv = RATE_CTR_INTV_DAY;
	} else {
		talloc_free(dup);
		cmd->reply = "Wrong interval.";
		goto err;
	}

	ctr_group = strtok_r(NULL, ".", &saveptr);
	tmp = strtok_r(NULL, ".", &saveptr);
	if (!ctr_group || !tmp) {
		talloc_free(dup);
		cmd->reply = "Counter group must be of form a.b";
		goto err;
	}
	ctr_group[strlen(ctr_group)] = '.';

	ctr_idx = strtok_r(NULL, ".", &saveptr);
	if (!ctr_idx) {
		talloc_free(dup);
		return get_rate_ctr_group(ctr_group, intv, cmd);
	}
	idx = atoi(ctr_idx);

	ctrg = rate_ctr_get_group_by_name_idx(ctr_group, idx);
	if (!ctrg) {
		talloc_free(dup);
		cmd->reply = "Counter group not found.";
		goto err;
	}

	ctr_name = strtok_r(NULL, "\0", &saveptr);
	if (!ctr_name) {
		talloc_free(dup);
		return get_rate_ctr_group_idx(ctrg, intv, cmd);
	}

	ctr = rate_ctr_get_by_name(ctrg, ctr_name);
	if (!ctr) {
		cmd->reply = "Counter name not found.";
		talloc_free(dup);
		goto err;
	}

	talloc_free(dup);

	cmd->reply = talloc_asprintf(cmd, "%lu", get_rate_ctr_value(ctr, intv));
	if (!cmd->reply)
		goto oom;

	return CTRL_CMD_REPLY;
oom:
	cmd->reply = "OOM";
err:
	return CTRL_CMD_ERROR;
}

static int set_rate_ctr(struct ctrl_cmd *cmd, void *data)
{
	cmd->reply = "Can't set rate counter.";

	return CTRL_CMD_ERROR;
}

static int verify_rate_ctr(struct ctrl_cmd *cmd, const char *value, void *data)
{
	return 0;
}

/* counter */
CTRL_CMD_DEFINE(counter, "counter *");
static int get_counter(struct ctrl_cmd *cmd, void *data)
{
	char *ctr_name, *tmp, *dup, *saveptr;
	struct osmo_counter *counter;

	cmd->reply = "OOM";
	dup = talloc_strdup(cmd, cmd->variable);
	if (!dup)
		goto err;


	tmp = strstr(dup, "counter");
	if (!tmp) {
		talloc_free(dup);
		goto err;
	}

	strtok_r(tmp, ".", &saveptr);
	ctr_name = strtok_r(NULL, "\0", &saveptr);

	if (!ctr_name)
		goto err;

	counter = osmo_counter_get_by_name(ctr_name);
	if (!counter) {
		cmd->reply = "Counter name not found.";
		talloc_free(dup);
		goto err;
	}

	talloc_free(dup);

	cmd->reply = talloc_asprintf(cmd, "%lu", counter->value);
	if (!cmd->reply) {
		cmd->reply = "OOM";
		goto err;
	}

	return CTRL_CMD_REPLY;
err:
	return CTRL_CMD_ERROR;
}

static int set_counter(struct ctrl_cmd *cmd, void *data)
{

	cmd->reply = "Can't set counter.";

	return CTRL_CMD_ERROR;
}

static int verify_counter(struct ctrl_cmd *cmd, const char *value, void *data)
{
	return 0;
}

int controlif_setup(struct gsm_network *gsmnet, uint16_t port)
{
	struct ctrl_handle *ctrl;

	ctrl = talloc_zero(tall_bsc_ctx, struct ctrl_handle);
	if (!ctrl)
		return -ENOMEM;

	ctrl->gsmnet = gsmnet;

	ctrl_node_vec = vector_init(5);
	if (!ctrl_node_vec)
		return -ENOMEM;

	/* Listen for control connections */
	ctrl->ipa_link = ipa_server_link_create(ctrl, NULL,
						"127.0.0.1", port,
						ctrl_accept_cb, ctrl);
	if (!ctrl->ipa_link) {
		talloc_free(ctrl);
		return -ENOMEM;
	}

	if (ipa_server_link_open(ctrl->ipa_link) < 0) {
		talloc_free(ctrl);
		return -EIO;
	}

	ctrl_cmd_install(CTRL_NODE_ROOT, &cmd_rate_ctr);
	ctrl_cmd_install(CTRL_NODE_ROOT, &cmd_counter);

	return 0;
}
