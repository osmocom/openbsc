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
CTRL_CMD_DEFINE_RO(subscriber_list, "subscriber-list-active-v1");

int sgsn_ctrl_cmds_install(void)
{
	int rc = 0;
	rc |= ctrl_cmd_install(CTRL_NODE_ROOT, &cmd_subscriber_list);
	return rc;
}

struct ctrl_handle *sgsn_controlif_setup(struct gsm_network *net,
					 const char *bind_addr, uint16_t port)
{
	return ctrl_interface_setup_dynip(net, bind_addr, port, NULL);
}
