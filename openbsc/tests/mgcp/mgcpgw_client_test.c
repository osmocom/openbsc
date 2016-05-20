/*
 * (C) 2016 by sysmocom s.f.m.c. GmbH <info@sysmocom.de>
 * All Rights Reserved
 *
 * Author: Neels Hofmeyr
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

#include <string.h>

#include <osmocom/core/msgb.h>
#include <osmocom/core/application.h>
#include <openbsc/mgcp.h>
#include <openbsc/mgcpgw_client.h>

void *ctx;

#define buf_len 4096

#if 0
static struct msgb *from_hex(const char *hex)
{
	struct msgb *msg = msgb_alloc(buf_len, "mgcpgw_test_from_hex");
	unsigned int l = osmo_hexparse(hex, msg->data, buf_len);
	msg->l2h = msgb_put(msg, l);
	return msg;
}

static struct msgb *mgcp_from_str(const char *head, const char *params)
{
	struct msgb *msg = msgb_alloc(buf_len, "mgcp_from_str");
	unsigned int l;
	char *data;
	l = strlen(head);
	msg->l2h = msgb_put(msg, l);
	data = (char*)msgb_l2(msg);
	strncpy(data, head, l);

	data = (char*)msgb_put(msg, 1);
	*data = '\n';

	l = strlen(params);
	data = (char*)msgb_put(msg, l);
	strncpy(data, params, l);

	return msg;
}
#endif

static struct msgb *from_str(const char *str)
{
	struct msgb *msg = msgb_alloc(buf_len, "from_str");
	unsigned int l = strlen(str);
	char *data;
	msg->l2h = msgb_put(msg, l);
	data = (char*)msgb_l2(msg);
	strncpy(data, str, l);
	return msg;
}

static struct mgcpgw_client_conf conf;
struct mgcpgw_client *mgcp = NULL;

static void reply_to(mgcp_trans_id_t trans_id, int code, const char *comment,
		     int conn_id, const char *params)
{
	static char compose[4096 - 128];
	int len;

	len = snprintf(compose, sizeof(compose),
		       "%d %u %s\r\nI: %d\n\n%s",
		       code, trans_id, comment, conn_id, params);
	OSMO_ASSERT(len < sizeof(compose));
	OSMO_ASSERT(len > 0);

	printf("composed response:\n-----\n%s\n-----\n",
	       compose);
	mgcpgw_client_rx(mgcp, from_str(compose));
}

void test_response_cb(struct mgcp_response *response, void *priv)
{
	OSMO_ASSERT(priv == mgcp);
	mgcp_response_parse_params(response);

	printf("response cb received:\n"
	       "  head.response_code = %d\n"
	       "  head.trans_id = %u\n"
	       "  head.comment = %s\n"
	       "  audio_port = %u\n",
	       response->head.response_code,
	       response->head.trans_id,
	       response->head.comment,
	       response->audio_port
	      );
}

mgcp_trans_id_t dummy_mgcp_send(struct msgb *msg)
{
	mgcp_trans_id_t trans_id;
	trans_id = msg->cb[MSGB_CB_MGCP_TRANS_ID];
	char *end;

	OSMO_ASSERT(mgcpgw_client_pending_add(mgcp, trans_id, test_response_cb, mgcp));

	end = (char*)msgb_put(msg, 1);
	*end = '\0';
	printf("composed:\n-----\n%s\n-----\n",
	       (char*)msgb_l2(msg));

	talloc_free(msg);
	return trans_id;
}

void test_crcx(void)
{
	struct msgb *msg;
	mgcp_trans_id_t trans_id;

	printf("\n===== %s =====\n", __func__);

	if (mgcp)
		talloc_free(mgcp);
	mgcp = mgcpgw_client_init(ctx, &conf);

	msg = mgcp_msg_crcx(mgcp, 23, 42, MGCP_CONN_LOOPBACK);
	trans_id = dummy_mgcp_send(msg);

	reply_to(trans_id, 200, "OK", 1,
		"v=0\r\n"
		"o=- 1 23 IN IP4 10.9.1.120\r\n"
		"s=-\r\n"
		"c=IN IP4 10.9.1.120\r\n"
		"t=0 0\r\n"
		"m=audio 16002 RTP/AVP 98\r\n"
		"a=rtpmap:98 AMR/8000\r\n"
		"a=ptime:20\r\n");
}

int main(int argc, char **argv)
{
	ctx = talloc_named_const(NULL, 1, "mgcpgw_client_test");
	msgb_talloc_ctx_init(ctx, 0);
	osmo_init_logging(&log_info);

	mgcpgw_client_conf_init(&conf);

	test_crcx();

	printf("Done\n");
	fprintf(stderr, "Done\n");
	return EXIT_SUCCESS;
}
