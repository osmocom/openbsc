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


CTRL_CMD_DEFINE_RANGE(bts_mnc, "mnc", struct gsm_bts, network_code, 0, 999);
CTRL_CMD_DEFINE_RANGE(bts_mcc, "mcc", struct gsm_bts, country_code, 1, 999);
CTRL_CMD_DEFINE_STRING(bts_short_name, "short-name", struct gsm_bts, name_short);
CTRL_CMD_DEFINE_STRING(bts_long_name, "long-name", struct gsm_bts, name_long);

int bsc_ctrl_cmds_install(void)
{
	int rc = 0;
	rc |= ctrl_cmd_install(CTRL_NODE_BTS, &cmd_bts_mnc);
	rc |= ctrl_cmd_install(CTRL_NODE_BTS, &cmd_bts_mcc);
	rc |= ctrl_cmd_install(CTRL_NODE_BTS, &cmd_bts_short_name);
	rc |= ctrl_cmd_install(CTRL_NODE_BTS, &cmd_bts_long_name);

	return rc;
}
