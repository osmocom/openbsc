/*
 * (C) 2011 by Holger Hans Peter Freyther <zecke@selfish.org>
 * (C) 2011 by On-Waves
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
 */

#include <openbsc/mgcp.h>

#include <osmocore/talloc.h>
#include <string.h>

static struct msgb *create_auep1()
{
	struct msgb *msg;

	msg = msgb_alloc_headroom(4096, 128, "MGCP msg");
	int len = sprintf((char *)msg->data, "AUEP 158663169 ds/e1-1/2@172.16.6.66 MGCP 1.0\r\n");
	msg->l2h = msgb_put(msg, len);
	return msg;
}

static struct msgb *create_auep2()
{
	struct msgb *msg;

	msg = msgb_alloc_headroom(4096, 128, "MGCP msg");
	int len = sprintf((char *)msg->data, "AUEP 18983213 ds/e1-2/1@172.16.6.66 MGCP 1.0\r\n");
	msg->l2h = msgb_put(msg, len);
	return msg;
}

static void test_auep(void)
{
	struct msgb *inp;
	struct msgb *msg;
	struct mgcp_config *cfg = mgcp_config_alloc();
	cfg->trunk.number_endpoints = 64;
	mgcp_endpoints_allocate(cfg);

	inp = create_auep1();
	msg = mgcp_handle_message(cfg, inp);
	msgb_free(inp);
	if (strcmp((char *) msg->data, "200 158663169 OK\r\n") != 0)
		printf("Result1 failed '%s'\n", (char *) msg->data);
	/* Verify that the endpoint is fine */
	msgb_free(msg);

	inp = create_auep2();
	msg = mgcp_handle_message(cfg, inp);
	msgb_free(inp);
	/* Verify that the endpoint is not fine */
	if (strcmp((char *) msg->data, "500 18983213 FAIL\r\n") != 0)
		printf("Result2 failed '%s'\n", (char *) msg->data);
	msgb_free(msg);

	talloc_free(cfg);
}

int main(int argc, char **argv)
{
	struct log_target *stderr_target;
	log_init(&log_info);
	stderr_target = log_target_create_stderr();
	log_add_target(stderr_target);
	log_set_all_filter(stderr_target, 1);

	test_auep();
	return 0;
}
