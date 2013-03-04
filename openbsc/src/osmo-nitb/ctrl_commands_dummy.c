/*
 * (C) 2013 by Holger Hans Peter Freyther
 * (C) 2013 by sysmocom s.f.m.c. GmbH
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

int dummy_set(struct ctrl_cmd *cmd, void *data)
{
	cmd->reply = "Dummy implementation";
	return CTRL_CMD_REPLY;
}

int dummy_get(struct ctrl_cmd *cmd, void *data)
{
	cmd->reply = "0";
	return CTRL_CMD_REPLY;
}

int dummy_verify(struct ctrl_cmd *cmd, const char *value, void *data)
{
	return 0;
}

#define DUMMY_COMMAND(name, str) \
	CTRL_CMD_RAW(name, str, dummy_get, dummy_set, dummy_verify)

/* ROOT related commands below here */
DUMMY_COMMAND(net_trap_meas_enable, "trap-measurement-reports-enable");

/* BTS related commands below here */
DUMMY_COMMAND(bts_drop, "drop");
DUMMY_COMMAND(bts_rflock, "rflock");

/* TRX related commands below here */
DUMMY_COMMAND(trx_drop, "drop");
DUMMY_COMMAND(trx_rflock, "rflock");
int bsc_ctrl_cmds_install_dummies(void)
{
	int rc = 0;

	rc |= ctrl_cmd_install(CTRL_NODE_ROOT, &cmd_net_trap_meas_enable);

	rc |= ctrl_cmd_install(CTRL_NODE_BTS, &cmd_bts_drop);
	rc |= ctrl_cmd_install(CTRL_NODE_BTS, &cmd_bts_rflock);

	rc |= ctrl_cmd_install(CTRL_NODE_TRX, &cmd_trx_drop);
	rc |= ctrl_cmd_install(CTRL_NODE_TRX, &cmd_trx_rflock);
	return rc;
}
