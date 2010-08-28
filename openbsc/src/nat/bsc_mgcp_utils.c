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
#include <openbsc/bsc_nat_sccp.h>
#include <openbsc/gsm_data.h>
#include <openbsc/debug.h>
#include <openbsc/mgcp.h>
#include <openbsc/mgcp_internal.h>

#include <osmocom/sccp/sccp.h>

#include <osmocore/talloc.h>
#include <osmocore/gsm0808.h>
#include <osmocore/protocol/gsm_08_08.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#include <errno.h>
#include <unistd.h>

int bsc_mgcp_assign(struct sccp_connections *con, struct msgb *msg)
{
	struct sccp_connections *mcon;
	struct tlv_parsed tp;
	uint16_t cic;
	uint8_t timeslot;
	uint8_t multiplex;
	int endp;

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

	cic = ntohs(*(uint16_t *)TLVP_VAL(&tp, GSM0808_IE_CIRCUIT_IDENTITY_CODE));
	timeslot = cic & 0x1f;
	multiplex = (cic & ~0x1f) >> 5;


	endp = mgcp_timeslot_to_endpoint(multiplex, timeslot);

	/* find stale connections using that endpoint */
	llist_for_each_entry(mcon, &con->bsc->nat->sccp_connections, list_entry) {
		if (mcon->msc_endp == endp) {
			LOGP(DNAT, LOGL_ERROR,
			     "Endpoint %d was assigned to 0x%x and now 0x%x\n",
			     endp,
			     sccp_src_ref_to_int(&mcon->patched_ref),
			     sccp_src_ref_to_int(&con->patched_ref));
			bsc_mgcp_dlcx(mcon);
		}
	}

	con->msc_endp = endp;
	con->bsc_endp = endp;
	return 0;
}

static void bsc_mgcp_free_endpoint(struct bsc_nat *nat, int i)
{
	if (nat->bsc_endpoints[i].transaction_id) {
		talloc_free(nat->bsc_endpoints[i].transaction_id);
		nat->bsc_endpoints[i].transaction_id = NULL;
	}

	nat->bsc_endpoints[i].transaction_state = 0;
	nat->bsc_endpoints[i].bsc = NULL;
}

void bsc_mgcp_free_endpoints(struct bsc_nat *nat)
{
	int i;

	for (i = 1; i < nat->mgcp_cfg->number_endpoints; ++i){
		bsc_mgcp_free_endpoint(nat, i);
		mgcp_free_endp(&nat->mgcp_cfg->endpoints[i]);
	}
}

/* send a MDCX where we do not want a response */
static void bsc_mgcp_send_mdcx(struct bsc_connection *bsc, struct mgcp_endpoint *endp)
{
	char buf[2096];
	int len;

	len = snprintf(buf, sizeof(buf),
		       "MDCX 23 %x@mgw MGCP 1.0\r\n"
		       "Z: noanswer\r\n"
		       "\r\n"
		       "c=IN IP4 %s\r\n"
		       "m=audio %d RTP/AVP 255\r\n",
		       ENDPOINT_NUMBER(endp),
		       bsc->nat->mgcp_cfg->source_addr,
		       endp->bts_end.local_port);
	if (len < 0) {
		LOGP(DMGCP, LOGL_ERROR, "snprintf for DLCX failed.\n");
		return;
	}
}

static void bsc_mgcp_send_dlcx(struct bsc_connection *bsc, int endpoint)
{
	char buf[2096];
	int len;

	len = snprintf(buf, sizeof(buf),
		       "DLCX 23 %x@mgw MGCP 1.0\r\n"
		       "Z: noanswer\r\n", endpoint);
	if (len < 0) {
		LOGP(DMGCP, LOGL_ERROR, "snprintf for DLCX failed.\n");
		return;
	}

	bsc_write_mgcp(bsc, (uint8_t *) buf, len);
}

void bsc_mgcp_init(struct sccp_connections *con)
{
	con->msc_endp = -1;
	con->bsc_endp = -1;
	con->crcx = 0;
}

void bsc_mgcp_dlcx(struct sccp_connections *con)
{
	/* send a DLCX down the stream */
	if (con->bsc_endp != -1 && con->crcx) {
		bsc_mgcp_send_dlcx(con->bsc, con->bsc_endp);
		bsc_mgcp_free_endpoint(con->bsc->nat, con->msc_endp);
	}

	bsc_mgcp_init(con);
}


struct sccp_connections *bsc_mgcp_find_con(struct bsc_nat *nat, int endpoint)
{
	struct sccp_connections *con = NULL;
	struct sccp_connections *sccp;

	llist_for_each_entry(sccp, &nat->sccp_connections, list_entry) {
		if (sccp->msc_endp == -1)
			continue;
		if (sccp->msc_endp != endpoint)
			continue;

		con = sccp;
	}

	if (con)
		return con;

	LOGP(DMGCP, LOGL_ERROR, "Failed to find the connection.\n");
	return NULL;
}

int bsc_mgcp_policy_cb(struct mgcp_config *cfg, int endpoint, int state, const char *transaction_id)
{
	struct bsc_nat *nat;
	struct bsc_endpoint *bsc_endp;
	struct sccp_connections *sccp;
	struct mgcp_endpoint *mgcp_endp;
	struct msgb *bsc_msg;

	nat = cfg->data;
	bsc_endp = &nat->bsc_endpoints[endpoint];
	mgcp_endp = &nat->mgcp_cfg->endpoints[endpoint];

	if (bsc_endp->transaction_id) {
		LOGP(DMGCP, LOGL_ERROR, "Endpoint 0x%x had pending transaction: '%s'\n",
		     endpoint, bsc_endp->transaction_id);
		talloc_free(bsc_endp->transaction_id);
		bsc_endp->transaction_id = NULL;
		bsc_endp->transaction_state = 0;
	}
	bsc_endp->bsc = NULL;

	sccp = bsc_mgcp_find_con(nat, endpoint);

	if (!sccp) {
		LOGP(DMGCP, LOGL_ERROR, "Did not find BSC for change on endpoint: 0x%x state: %d\n", endpoint, state);

		switch (state) {
		case MGCP_ENDP_CRCX:
			return MGCP_POLICY_REJECT;
			break;
		case MGCP_ENDP_DLCX:
			return MGCP_POLICY_CONT;
			break;
		case MGCP_ENDP_MDCX:
			return MGCP_POLICY_CONT;
			break;
		default:
			LOGP(DMGCP, LOGL_FATAL, "Unhandled state: %d\n", state);
			return MGCP_POLICY_CONT;
			break;
		}
	}

	/* we need to generate a new and patched message */
	bsc_msg = bsc_mgcp_rewrite((char *) nat->mgcp_msg, nat->mgcp_length,
				   nat->mgcp_cfg->source_addr, mgcp_endp->bts_end.local_port);
	if (!bsc_msg) {
		LOGP(DMGCP, LOGL_ERROR, "Failed to patch the msg.\n");
		return MGCP_POLICY_CONT;
	}


	bsc_endp->transaction_id = talloc_strdup(nat, transaction_id);
	bsc_endp->transaction_state = state;
	bsc_endp->bsc = sccp->bsc;

	/* we need to update some bits */
	if (state == MGCP_ENDP_CRCX) {
		struct sockaddr_in sock;
		socklen_t len = sizeof(sock);
		if (getpeername(sccp->bsc->write_queue.bfd.fd, (struct sockaddr *) &sock, &len) != 0) {
			LOGP(DMGCP, LOGL_ERROR, "Can not get the peername...%d/%s\n",
			      errno, strerror(errno));
		} else {
			mgcp_endp->bts_end.addr = sock.sin_addr;
		}

		/* send the message and a fake MDCX to force sending of a dummy packet */
		sccp->crcx = 1;
		bsc_write(sccp->bsc, bsc_msg, NAT_IPAC_PROTO_MGCP);
		bsc_mgcp_send_mdcx(sccp->bsc, mgcp_endp);
		return MGCP_POLICY_DEFER;
	} else if (state == MGCP_ENDP_DLCX) {
		/* we will free the endpoint now and send a DLCX to the BSC */
		msgb_free(bsc_msg);
		bsc_mgcp_dlcx(sccp);
		return MGCP_POLICY_CONT;
	} else {
		bsc_write(sccp->bsc, bsc_msg, NAT_IPAC_PROTO_MGCP);
		return MGCP_POLICY_DEFER;
	}
}

/*
 * We do have a failure, free data downstream..
 */
static void free_chan_downstream(struct mgcp_endpoint *endp, struct bsc_endpoint *bsc_endp,
				 struct bsc_connection *bsc)
{
		LOGP(DMGCP, LOGL_ERROR, "No CI, freeing endpoint 0x%x in state %d\n",
			ENDPOINT_NUMBER(endp), bsc_endp->transaction_state);

		/* if a CRCX failed... send a DLCX down the stream */
		if (bsc_endp->transaction_state == MGCP_ENDP_CRCX) {
			struct sccp_connections *con;
			con = bsc_mgcp_find_con(bsc->nat, ENDPOINT_NUMBER(endp));
			if (!con) {
				LOGP(DMGCP, LOGL_ERROR,
					"No SCCP connection for endp 0x%x\n",
					ENDPOINT_NUMBER(endp));
			} else {
				if (con->bsc == bsc) {
					bsc_mgcp_send_dlcx(bsc, ENDPOINT_NUMBER(endp));
					con->crcx = 0;
				} else {
					LOGP(DMGCP, LOGL_ERROR,
						"Endpoint belongs to a different BSC\n");
				}
			}
		}

		bsc_mgcp_free_endpoint(bsc->nat, ENDPOINT_NUMBER(endp));
		mgcp_free_endp(endp);
}

/*
 * We have received a msg from the BSC. We will see if we know
 * this transaction and if it belongs to the BSC. Then we will
 * need to patch the content to point to the local network and we
 * need to update the I: that was assigned by the BSS.
 */
void bsc_mgcp_forward(struct bsc_connection *bsc, struct msgb *msg)
{
	struct msgb *output;
	struct bsc_endpoint *bsc_endp = NULL;
	struct mgcp_endpoint *endp = NULL;
	int i, code;
	char transaction_id[60];

	/* Some assumption that our buffer is big enough.. and null terminate */
	if (msgb_l2len(msg) > 2000) {
		LOGP(DMGCP, LOGL_ERROR, "MGCP message too long.\n");
		return;
	}

	msg->l2h[msgb_l2len(msg)] = '\0';

	if (bsc_mgcp_parse_response((const char *) msg->l2h, &code, transaction_id) != 0) {
		LOGP(DMGCP, LOGL_ERROR, "Failed to parse response code.\n");
		return;
	}

	for (i = 1; i < bsc->nat->mgcp_cfg->number_endpoints; ++i) {
		if (bsc->nat->bsc_endpoints[i].bsc != bsc)
			continue;
		/* no one listening? a bug? */
		if (!bsc->nat->bsc_endpoints[i].transaction_id)
			continue;
		if (strcmp(transaction_id, bsc->nat->bsc_endpoints[i].transaction_id) != 0)
			continue;

		endp = &bsc->nat->mgcp_cfg->endpoints[i];
		bsc_endp = &bsc->nat->bsc_endpoints[i];
		break;
	}

	if (!bsc_endp) {
		LOGP(DMGCP, LOGL_ERROR, "Could not find active endpoint: %s for msg: '%s'\n",
		     transaction_id, (const char *) msg->l2h);
		return;
	}

	endp->ci = bsc_mgcp_extract_ci((const char *) msg->l2h);
	if (endp->ci == CI_UNUSED) {
		free_chan_downstream(endp, bsc_endp, bsc);
		return;
	}

	/* free some stuff */
	talloc_free(bsc_endp->transaction_id);
	bsc_endp->transaction_id = NULL;
	bsc_endp->transaction_state = 0;

	/*
	 * rewrite the information. In case the endpoint was deleted
	 * there should be nothing for us to rewrite so putting endp->rtp_port
	 * with the value of 0 should be no problem.
	 */
	output = bsc_mgcp_rewrite((char * ) msg->l2h, msgb_l2len(msg),
				  bsc->nat->mgcp_cfg->source_addr, endp->net_end.local_port);

	if (!output) {
		LOGP(DMGCP, LOGL_ERROR, "Failed to rewrite MGCP msg.\n");
		return;
	}

	if (write_queue_enqueue(&bsc->nat->mgcp_queue, output) != 0) {
		LOGP(DMGCP, LOGL_ERROR, "Failed to queue MGCP msg.\n");
		msgb_free(output);
	}
}

int bsc_mgcp_parse_response(const char *str, int *code, char transaction[60])
{
	/* we want to parse two strings */
	return sscanf(str, "%3d %59s\n", code, transaction) != 2;
}

uint32_t bsc_mgcp_extract_ci(const char *str)
{
	unsigned int ci;
	char *res = strstr(str, "I: ");
	if (!res) {
		LOGP(DMGCP, LOGL_ERROR, "No CI in msg '%s'\n", str);
		return CI_UNUSED;
	}

	if (sscanf(res, "I: %u", &ci) != 1) {
		LOGP(DMGCP, LOGL_ERROR, "Failed to parse CI in msg '%s'\n", str);
		return CI_UNUSED;
	}

	return ci;
}

/* we need to replace some strings... */
struct msgb *bsc_mgcp_rewrite(char *input, int length, const char *ip, int port)
{
	static const char *ip_str = "c=IN IP4 ";
	static const char *aud_str = "m=audio ";

	char buf[128];
	char *running, *token;
	struct msgb *output;

	if (length > 4096 - 128) {
		LOGP(DMGCP, LOGL_ERROR, "Input is too long.\n");
		return NULL;
	}

	output = msgb_alloc_headroom(4096, 128, "MGCP rewritten");
	if (!output) {
		LOGP(DMGCP, LOGL_ERROR, "Failed to allocate new MGCP msg.\n");
		return NULL;
	}

	running = input;
	output->l2h = output->data;
	for (token = strsep(&running, "\n"); running; token = strsep(&running, "\n")) {
		int len = strlen(token);
		int cr = len > 0 && token[len - 1] == '\r';

		if (strncmp(ip_str, token, (sizeof ip_str) - 1) == 0) {
			output->l3h = msgb_put(output, strlen(ip_str));
			memcpy(output->l3h, ip_str, strlen(ip_str));
			output->l3h = msgb_put(output, strlen(ip));
			memcpy(output->l3h, ip, strlen(ip));

			if (cr) {
				output->l3h = msgb_put(output, 2);
				output->l3h[0] = '\r';
				output->l3h[1] = '\n';
			} else {
				output->l3h = msgb_put(output, 1);
				output->l3h[0] = '\n';
			}
		} else if (strncmp(aud_str, token, (sizeof aud_str) - 1) == 0) {
			int payload;
			if (sscanf(token, "m=audio %*d RTP/AVP %d", &payload) != 1) {
				LOGP(DMGCP, LOGL_ERROR, "Could not parsed audio line.\n");
				msgb_free(output);
				return NULL;
			}

			snprintf(buf, sizeof(buf)-1, "m=audio %d RTP/AVP %d%s",
				 port, payload, cr ? "\r\n" : "\n");
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

	nat = fd->data;

	rc = read(fd->fd, nat->mgcp_msg, sizeof(nat->mgcp_msg) - 1);
	if (rc <= 0) {
		LOGP(DMGCP, LOGL_ERROR, "Failed to read errno: %d\n", errno);
		return -1;
	}

	nat->mgcp_msg[rc] = '\0';
	nat->mgcp_length = rc;

	msg = msgb_alloc(sizeof(nat->mgcp_msg), "MGCP GW Read");
	if (!msg) {
		LOGP(DMGCP, LOGL_ERROR, "Failed to create buffer.\n");
		return -1;
	}

	msg->l2h = msgb_put(msg, rc);
	memcpy(msg->l2h, nat->mgcp_msg, msgb_l2len(msg));
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

int bsc_mgcp_nat_init(struct bsc_nat *nat)
{
	int on;
	struct sockaddr_in addr;

	if (!nat->mgcp_cfg->call_agent_addr) {
		LOGP(DMGCP, LOGL_ERROR, "The BSC nat requires the call agent ip to be set.\n");
		return -1;
	}

	if (nat->mgcp_cfg->bts_ip) {
		LOGP(DMGCP, LOGL_ERROR, "Do not set the BTS ip for the nat.\n");
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

	/* some more MGCP config handling */
	if (nat->mgcp_cfg->audio_name)
		talloc_free(nat->mgcp_cfg->audio_name);
	nat->mgcp_cfg->audio_name = NULL;

	nat->mgcp_cfg->audio_payload = -1;
	nat->mgcp_cfg->data = nat;
	nat->mgcp_cfg->policy_cb = bsc_mgcp_policy_cb;
	nat->mgcp_cfg->force_realloc = 1;

	if (nat->mgcp_cfg->bts_ip)
		talloc_free(nat->mgcp_cfg->bts_ip);
	nat->mgcp_cfg->bts_ip = "";

	nat->bsc_endpoints = talloc_zero_array(nat,
					       struct bsc_endpoint,
					       nat->mgcp_cfg->number_endpoints + 1);

	return 0;
}

void bsc_mgcp_clear_endpoints_for(struct bsc_connection *bsc)
{
	struct rate_ctr *ctr = NULL;
	int i;

	if (bsc->cfg)
		ctr = &bsc->cfg->stats.ctrg->ctr[BCFG_CTR_DROPPED_CALLS];

	for (i = 1; i < bsc->nat->mgcp_cfg->number_endpoints; ++i) {
		struct bsc_endpoint *bsc_endp = &bsc->nat->bsc_endpoints[i];

		if (bsc_endp->bsc != bsc)
			continue;

		if (ctr)
			rate_ctr_inc(ctr);

		bsc_mgcp_free_endpoint(bsc->nat, i);
		mgcp_free_endp(&bsc->nat->mgcp_cfg->endpoints[i]);
	}
}
