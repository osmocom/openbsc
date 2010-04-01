/*
 * (C) 2010 by Holger Hans Peter Freyther <zecke@selfish.org>
 * (C) 2010 by On-Waves
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

#include <openbsc/bsc_nat.h>
#include <openbsc/gsm_data.h>
#include <openbsc/bssap.h>
#include <openbsc/debug.h>
#include <openbsc/mgcp.h>
#include <openbsc/mgcp_internal.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#include <errno.h>
#include <unistd.h>

int bsc_mgcp_assign(struct sccp_connections *con, struct msgb *msg)
{
	struct tlv_parsed tp;
	u_int16_t cic;
	u_int8_t timeslot;
	u_int8_t multiplex;

	if (!msg->l3h) {
		LOGP(DNAT, LOGL_ERROR, "Assignment message should have l3h pointer.\n");
		return -1;
	}

	if (msgb_l3len(msg) < 3) {
		LOGP(DNAT, LOGL_ERROR, "Assignment message has not enough space for GSM0808.\n");
		return -1;
	}

	tlv_parse(&tp, gsm0808_att_tlvdef(), msg->l3h + 3, msgb_l3len(msg) - 3, 0, 0);
	if (!TLVP_PRESENT(&tp, GSM0808_IE_CIRCUIT_IDENTITY_CODE)) {
		LOGP(DNAT, LOGL_ERROR, "Circuit identity code not found in assignment message.\n");
		return -1;
	}

	cic = ntohs(*(u_int16_t *)TLVP_VAL(&tp, GSM0808_IE_CIRCUIT_IDENTITY_CODE));
	timeslot = cic & 0x1f;
	multiplex = (cic & ~0x1f) >> 5;

	con->msc_timeslot = (32 * multiplex) + timeslot;
	con->bsc_timeslot = con->msc_timeslot;
	return 0;
}

void bsc_mgcp_clear(struct sccp_connections *con)
{
	con->msc_timeslot = -1;
	con->bsc_timeslot = -1;
}

void bsc_mgcp_free_endpoints(struct bsc_nat *nat)
{
	int i;

	for (i = 1; i < nat->mgcp_cfg->number_endpoints; ++i)
		mgcp_free_endp(&nat->mgcp_cfg->endpoints[i]);
}

struct bsc_connection *bsc_mgcp_find_con(struct bsc_nat *nat, int endpoint)
{
	struct sccp_connections *sccp;

	llist_for_each_entry(sccp, &nat->sccp_connections, list_entry) {
		if (sccp->msc_timeslot == -1)
			continue;
		if (mgcp_timeslot_to_endpoint(0, sccp->msc_timeslot) != endpoint)
			continue;

		return sccp->bsc;
	}

	LOGP(DMGCP, LOGL_ERROR, "Failed to find the connection.\n");
	return NULL;
}

/* we need to replace some strings... */
struct msgb *bsc_mgcp_rewrite(struct msgb *input, const char *ip, int port)
{
	static const char *ip_str = "c=IN IP4 ";
	static const char *aud_str = "m=audio ";

	char buf[128];
	char *running, *token;
	struct msgb *output;

	if (msgb_l2len(input) > 4096 - 128) {
		LOGP(DMGCP, LOGL_ERROR, "Input is too long.\n");
		return NULL;
	}

	output = msgb_alloc_headroom(4096, 128, "MGCP rewritten");
	if (!output) {
		LOGP(DMGCP, LOGL_ERROR, "Failed to allocate new MGCP msg.\n");
		return NULL;
	}

	running = (char *) input->l2h;
	output->l2h = output->data;
	for (token = strsep(&running, "\n"); token; token = strsep(&running, "\n")) {
		int len = strlen(token);

		/* ignore completely empty lines for now */
		if (len == 0)
			continue;

		if (strncmp(ip_str, token, (sizeof ip_str) - 1) == 0) {
			output->l3h = msgb_put(output, strlen(ip_str));
			memcpy(output->l3h, ip_str, strlen(ip_str));
			output->l3h = msgb_put(output, strlen(ip));
			memcpy(output->l3h, ip, strlen(ip));
			output->l3h = msgb_put(output, 2);
			output->l3h[0] = '\r';
			output->l3h[1] = '\n';
		} else if (strncmp(aud_str, token, (sizeof aud_str) - 1) == 0) {
			int payload;
			if (sscanf(token, "m=audio %*d RTP/AVP %d", &payload) != 1) {
				LOGP(DMGCP, LOGL_ERROR, "Could not parsed audio line.\n");
				msgb_free(output);
				return NULL;
			}

			snprintf(buf, sizeof(buf)-1, "m=audio %d RTP/AVP %d\r\n", port, payload);
			buf[sizeof(buf)-1] = '\0';

			output->l3h = msgb_put(output, strlen(buf));
			memcpy(output->l3h, buf, strlen(buf));
		} else {
			output->l3h = msgb_put(output, len + 1);
			memcpy(output->l3h, token, len);
			output->l3h[len] = '\n';
		}
	}

	return output;
}

static int mgcp_do_read(struct bsc_fd *fd)
{
	struct bsc_nat *nat;
	struct msgb *msg, *resp;
	int rc;

	msg = msgb_alloc(4096, "MGCP GW Read");
	if (!msg) {
		LOGP(DMGCP, LOGL_ERROR, "Failed to create buffer.\n");
		return -1;
	}


	rc = read(fd->fd, msg->data, msg->data_len);
	if (rc <= 0) {
		LOGP(DMGCP, LOGL_ERROR, "Failed to read errno: %d\n", errno);
		msgb_free(msg);
		return -1;
	}

	nat = fd->data;
	msg->l2h = msgb_put(msg, rc);
	resp = mgcp_handle_message(nat->mgcp_cfg, msg);
	msgb_free(msg);

	/* we do have a direct answer... e.g. AUEP */
	if (resp) {
		if (write_queue_enqueue(&nat->mgcp_queue, resp) != 0) {
			LOGP(DMGCP, LOGL_ERROR, "Failed to enqueue msg.\n");
			msgb_free(resp);
		}
	}

	return 0;
}

static int mgcp_do_write(struct bsc_fd *bfd, struct msgb *msg)
{
	int rc;

	rc = write(bfd->fd, msg->data, msg->len);

	if (rc != msg->len) {
		LOGP(DMGCP, LOGL_ERROR, "Failed to write msg to MGCP CallAgent.\n");
		return -1;
	}

	return rc;
}

int bsc_mgcp_init(struct bsc_nat *nat)
{
	int on;
	struct sockaddr_in addr;

	if (!nat->mgcp_cfg->call_agent_addr) {
		LOGP(DMGCP, LOGL_ERROR, "The BSC nat requires the call agent ip to be set.\n");
		return -1;
	}

	nat->mgcp_queue.bfd.fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (nat->mgcp_queue.bfd.fd < 0) {
		LOGP(DMGCP, LOGL_ERROR, "Failed to create MGCP socket. errno: %d\n", errno);
		return -1;
	}

	on = 1;
	setsockopt(nat->mgcp_queue.bfd.fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));

	addr.sin_family = AF_INET;
	addr.sin_port = htons(nat->mgcp_cfg->source_port);
	inet_aton(nat->mgcp_cfg->source_addr, &addr.sin_addr);

	if (bind(nat->mgcp_queue.bfd.fd, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
		LOGP(DMGCP, LOGL_ERROR, "Failed to bind. errno: %d\n", errno);
		close(nat->mgcp_queue.bfd.fd);
		nat->mgcp_queue.bfd.fd = -1;
		return -1;
	}

	addr.sin_port = htons(2727);
	inet_aton(nat->mgcp_cfg->call_agent_addr, &addr.sin_addr);
	if (connect(nat->mgcp_queue.bfd.fd, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
		LOGP(DMGCP, LOGL_ERROR, "Failed to connect to: '%s'. errno: %d\n",
		     nat->mgcp_cfg->call_agent_addr, errno);
		close(nat->mgcp_queue.bfd.fd);
		nat->mgcp_queue.bfd.fd = -1;
		return -1;
	}

	write_queue_init(&nat->mgcp_queue, 10);
	nat->mgcp_queue.bfd.when = BSC_FD_READ;
	nat->mgcp_queue.bfd.data = nat;
	nat->mgcp_queue.read_cb = mgcp_do_read;
	nat->mgcp_queue.write_cb = mgcp_do_write;

	if (bsc_register_fd(&nat->mgcp_queue.bfd) != 0) {
		LOGP(DMGCP, LOGL_ERROR, "Failed to register MGCP fd.\n");
		close(nat->mgcp_queue.bfd.fd);
		nat->mgcp_queue.bfd.fd = -1;
		return -1;
	}

	return 0;
}
