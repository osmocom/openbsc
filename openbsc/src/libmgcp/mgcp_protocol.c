/* A Media Gateway Control Protocol Media Gateway: RFC 3435 */
/* The protocol implementation */

/*
 * (C) 2009-2011 by Holger Hans Peter Freyther <zecke@selfish.org>
 * (C) 2009-2011 by On-Waves
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

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <limits.h>
#include <unistd.h>

#include <osmocom/core/msgb.h>
#include <osmocom/core/talloc.h>
#include <osmocom/core/select.h>

#include <openbsc/mgcp.h>
#include <openbsc/mgcp_internal.h>

#define for_each_line(input, line, save)			\
	for (line = strtok_r(input, "\r\n", &save); line;	\
	     line = strtok_r(NULL, "\r\n", &save))

static void mgcp_rtp_end_reset(struct mgcp_rtp_end *end);

struct mgcp_request {
	char *name;
	struct msgb *(*handle_request) (struct mgcp_config *cfg, struct msgb *msg);
	char *debug_name;
};

#define MGCP_REQUEST(NAME, REQ, DEBUG_NAME) \
	{ .name = NAME, .handle_request = REQ, .debug_name = DEBUG_NAME },

static struct msgb *handle_audit_endpoint(struct mgcp_config *cfg, struct msgb *msg);
static struct msgb *handle_create_con(struct mgcp_config *cfg, struct msgb *msg);
static struct msgb *handle_delete_con(struct mgcp_config *cfg, struct msgb *msg);
static struct msgb *handle_modify_con(struct mgcp_config *cfg, struct msgb *msg);
static struct msgb *handle_rsip(struct mgcp_config *cfg, struct msgb *msg);
static struct msgb *handle_noti_req(struct mgcp_config *cfg, struct msgb *msg);

static void create_transcoder(struct mgcp_endpoint *endp);
static void delete_transcoder(struct mgcp_endpoint *endp);

static uint32_t generate_call_id(struct mgcp_config *cfg)
{
	int i;

	/* use the call id */
	++cfg->last_call_id;

	/* handle wrap around */
	if (cfg->last_call_id == CI_UNUSED)
		++cfg->last_call_id;

	/* callstack can only be of size number_of_endpoints */
	/* verify that the call id is free, e.g. in case of overrun */
	for (i = 1; i < cfg->trunk.number_endpoints; ++i)
		if (cfg->trunk.endpoints[i].ci == cfg->last_call_id)
			return generate_call_id(cfg);

	return cfg->last_call_id;
}

/*
 * array of function pointers for handling various
 * messages. In the future this might be binary sorted
 * for performance reasons.
 */
static const struct mgcp_request mgcp_requests [] = {
	MGCP_REQUEST("AUEP", handle_audit_endpoint, "AuditEndpoint")
	MGCP_REQUEST("CRCX", handle_create_con, "CreateConnection")
	MGCP_REQUEST("DLCX", handle_delete_con, "DeleteConnection")
	MGCP_REQUEST("MDCX", handle_modify_con, "ModifiyConnection")
	MGCP_REQUEST("RQNT", handle_noti_req, "NotificationRequest")

	/* SPEC extension */
	MGCP_REQUEST("RSIP", handle_rsip, "ReSetInProgress")
};

static struct msgb *mgcp_msgb_alloc(void)
{
	struct msgb *msg;
	msg = msgb_alloc_headroom(4096, 128, "MGCP msg");
	if (!msg)
	    LOGP(DMGCP, LOGL_ERROR, "Failed to msgb for MGCP data.\n");

	return msg;
}

static struct msgb *create_resp(int code, const char *txt, const char *msg,
				const char *trans, const char *param,
				const char *sdp)
{
	int len;
	struct msgb *res;

	res = mgcp_msgb_alloc();
	if (!res)
		return NULL;

	len = snprintf((char *) res->data, 2048, "%d %s%s%s\r\n%s",
			code, trans, txt, param ? param : "", sdp ? sdp : "");
	if (len < 0) {
		LOGP(DMGCP, LOGL_ERROR, "Failed to sprintf MGCP response.\n");
		msgb_free(res);
		return NULL;
	}

	res->l2h = msgb_put(res, len);
	LOGP(DMGCP, LOGL_DEBUG, "Sending response: code: %d for '%s'\n", code, res->l2h);
	return res;
}

struct msgb *mgcp_create_response_with_data(int code, const char *txt,
					    const char *msg, const char *trans,
					    const char *data)
{
	return create_resp(code, txt, msg, trans, NULL, data);
}

static struct msgb *create_ok_resp_with_param(int code, const char *msg,
					const char *trans, const char *param)
{
	return create_resp(code, " OK", msg, trans, param, NULL);
}

static struct msgb *create_ok_response(int code, const char *msg, const char *trans)
{
	return create_ok_resp_with_param(code, msg, trans, NULL);
}

static struct msgb *create_err_response(int code, const char *msg, const char *trans)
{
	return mgcp_create_response_with_data(code, " FAIL", msg, trans, NULL);
}

static struct msgb *create_response_with_sdp(struct mgcp_endpoint *endp,
					     const char *msg, const char *trans_id)
{
	const char *addr = endp->cfg->local_ip;
	char sdp_record[4096];

	if (!addr)
		addr = endp->cfg->source_addr;

	snprintf(sdp_record, sizeof(sdp_record) - 1,
			"I: %u\n\n"
			"v=0\r\n"
			"o=- %u 23 IN IP4 %s\r\n"
			"c=IN IP4 %s\r\n"
			"t=0 0\r\n"
			"m=audio %d RTP/AVP %d\r\n"
			"a=rtpmap:%d %s\r\n",
			endp->ci, endp->ci, addr, addr,
			endp->net_end.local_port, endp->bts_end.payload_type,
			endp->bts_end.payload_type, endp->tcfg->audio_name);
	return mgcp_create_response_with_data(200, " OK", msg, trans_id, sdp_record);
}

/*
 * handle incoming messages:
 *   - this can be a command (four letters, space, transaction id)
 *   - or a response (three numbers, space, transaction id)
 */
struct msgb *mgcp_handle_message(struct mgcp_config *cfg, struct msgb *msg)
{
        int code;
	struct msgb *resp = NULL;

	if (msgb_l2len(msg) < 4) {
		LOGP(DMGCP, LOGL_ERROR, "mgs too short: %d\n", msg->len);
		return NULL;
	}

        /* attempt to treat it as a response */
        if (sscanf((const char *)&msg->l2h[0], "%3d %*s", &code) == 1) {
		LOGP(DMGCP, LOGL_DEBUG, "Response: Code: %d\n", code);
	} else {
		int i, handled = 0;
		msg->l3h = &msg->l2h[4];
		for (i = 0; i < ARRAY_SIZE(mgcp_requests); ++i)
			if (strncmp(mgcp_requests[i].name, (const char *) &msg->l2h[0], 4) == 0) {
				handled = 1;
				resp = mgcp_requests[i].handle_request(cfg, msg);
				break;
			}
		if (!handled) {
			LOGP(DMGCP, LOGL_NOTICE, "MSG with type: '%.4s' not handled\n", &msg->l2h[0]);
		}
	}

	return resp;
}

/**
 * We have a null terminated string with the endpoint name here. We only
 * support two kinds. Simple ones as seen on the BSC level and the ones
 * seen on the trunk side.
 */
static struct mgcp_endpoint *find_e1_endpoint(struct mgcp_config *cfg,
					     const char *mgcp)
{
	char *rest = NULL;
	struct mgcp_trunk_config *tcfg;
	int trunk, endp;

	trunk = strtoul(mgcp + 6, &rest, 10);
	if (rest == NULL || rest[0] != '/' || trunk < 1) {
		LOGP(DMGCP, LOGL_ERROR, "Wrong trunk name '%s'\n", mgcp);
		return NULL;
	}

	endp = strtoul(rest + 1, &rest, 10);
	if (rest == NULL || rest[0] != '@') {
		LOGP(DMGCP, LOGL_ERROR, "Wrong endpoint name '%s'\n", mgcp);
		return NULL;
	}

	/* signalling is on timeslot 1 */
	if (endp == 1)
		return NULL;

	tcfg = mgcp_trunk_num(cfg, trunk);
	if (!tcfg) {
		LOGP(DMGCP, LOGL_ERROR, "The trunk %d is not declared.\n", trunk);
		return NULL;
	}

	if (!tcfg->endpoints) {
		LOGP(DMGCP, LOGL_ERROR, "Endpoints of trunk %d not allocated.\n", trunk);
		return NULL;
	}

	if (endp < 1 || endp >= tcfg->number_endpoints) {
		LOGP(DMGCP, LOGL_ERROR, "Failed to find endpoint '%s'\n", mgcp);
		return NULL;
	}

	return &tcfg->endpoints[endp];
}

static struct mgcp_endpoint *find_endpoint(struct mgcp_config *cfg, const char *mgcp)
{
	char *endptr = NULL;
	unsigned int gw = INT_MAX;

	if (strncmp(mgcp, "ds/e1", 5) == 0) {
		return find_e1_endpoint(cfg, mgcp);
	} else {
		gw = strtoul(mgcp, &endptr, 16);
		if (gw > 0 && gw < cfg->trunk.number_endpoints && strcmp(endptr, "@mgw") == 0)
			return &cfg->trunk.endpoints[gw];
	}

	LOGP(DMGCP, LOGL_ERROR, "Not able to find endpoint: '%s'\n", mgcp);
	return NULL;
}

/**
 * @returns 0 when the status line was complete and transaction_id and
 * endp out parameters are set.
 */
static int mgcp_analyze_header(struct mgcp_config *cfg, char *data,
			const char **transaction_id, struct mgcp_endpoint **endp)
{
	int i = 0;
	char *elem, *save;

	*transaction_id = "000000";

	for (elem = strtok_r(data, " ", &save); elem;
	     elem = strtok_r(NULL, " ", &save)) {
		switch (i) {
		case 0:
			*transaction_id = elem;
			break;
		case 1:
			if (endp) {
				*endp = find_endpoint(cfg, elem);
				if (!*endp) {
					LOGP(DMGCP, LOGL_ERROR,
					     "Unable to find Endpoint `%s'\n",
					     elem);
					return -1;
				}
			}
			break;
		case 2:
			if (strcmp("MGCP", elem)) {
				LOGP(DMGCP, LOGL_ERROR,
				     "MGCP header parsing error\n");
				return -1;
			}
			break;
		case 3:
			if (strcmp("1.0", elem)) {
				LOGP(DMGCP, LOGL_ERROR, "MGCP version `%s' "
					"not supported\n", elem);
				return -1;
			}
			break;
		}
		i++;
	}

	if (i != 4) {
		LOGP(DMGCP, LOGL_ERROR, "MGCP status line too short.\n");
		*transaction_id = "000000";
		*endp = NULL;
		return -1;
	}

	return 0;
}

static int verify_call_id(const struct mgcp_endpoint *endp,
			  const char *callid)
{
	if (strcmp(endp->callid, callid) != 0) {
		LOGP(DMGCP, LOGL_ERROR, "CallIDs does not match on 0x%x. '%s' != '%s'\n",
			ENDPOINT_NUMBER(endp), endp->callid, callid);
		return -1;
	}

	return 0;
}

static int verify_ci(const struct mgcp_endpoint *endp,
		     const char *_ci)
{
	uint32_t ci = strtoul(_ci, NULL, 10);

	if (ci != endp->ci) {
		LOGP(DMGCP, LOGL_ERROR, "ConnectionIdentifiers do not match on 0x%x. %u != %s\n",
			ENDPOINT_NUMBER(endp), endp->ci, _ci);
		return -1;
	}

	return 0;
}

static struct msgb *handle_audit_endpoint(struct mgcp_config *cfg, struct msgb *msg)
{
	int found;
	const char *trans_id;
	struct mgcp_endpoint *endp;
	char *data = strtok((char *) msg->l3h, "\r\n");

	found = mgcp_analyze_header(cfg, data, &trans_id, &endp);
	if (found != 0)
		return create_err_response(500, "AUEP", trans_id);
	else
		return create_ok_response(200, "AUEP", trans_id);
}

static int parse_conn_mode(const char *msg, int *conn_mode)
{
	int ret = 0;
	if (strcmp(msg, "recvonly") == 0)
		*conn_mode = MGCP_CONN_RECV_ONLY;
	else if (strcmp(msg, "sendrecv") == 0)
		*conn_mode = MGCP_CONN_RECV_SEND;
	else if (strcmp(msg, "sendonly") == 0)
		*conn_mode = MGCP_CONN_SEND_ONLY;
	else if (strcmp(msg, "loopback") == 0)
		*conn_mode = MGCP_CONN_LOOPBACK;
	else {
		LOGP(DMGCP, LOGL_ERROR, "Unknown connection mode: '%s'\n", msg);
		ret = -1;
	}

	return ret;
}

static int allocate_port(struct mgcp_endpoint *endp, struct mgcp_rtp_end *end,
			 struct mgcp_port_range *range,
			 int (*alloc)(struct mgcp_endpoint *endp, int port))
{
	int i;

	if (range->mode == PORT_ALLOC_STATIC) {
		end->local_alloc = PORT_ALLOC_STATIC;
		return 0;
	}

	/* attempt to find a port */
	for (i = 0; i < 200; ++i) {
		int rc;

		if (range->last_port >= range->range_end)
			range->last_port = range->range_start;

		rc = alloc(endp, range->last_port);

		range->last_port += 2;
		if (rc == 0) {
			end->local_alloc = PORT_ALLOC_DYNAMIC;
			return 0;
		}

	}

	LOGP(DMGCP, LOGL_ERROR, "Allocating a RTP/RTCP port failed 200 times 0x%x.\n",
	     ENDPOINT_NUMBER(endp));
	return -1;
}

static int allocate_ports(struct mgcp_endpoint *endp)
{
	if (allocate_port(endp, &endp->net_end, &endp->cfg->net_ports,
			  mgcp_bind_net_rtp_port) != 0)
		return -1;

	if (allocate_port(endp, &endp->bts_end, &endp->cfg->bts_ports,
			  mgcp_bind_bts_rtp_port) != 0) {
		mgcp_rtp_end_reset(&endp->net_end);
		return -1;
	}

	if (endp->cfg->transcoder_ip && endp->tcfg->trunk_type == MGCP_TRUNK_VIRTUAL) {
		if (allocate_port(endp, &endp->trans_net,
				  &endp->cfg->transcoder_ports,
				  mgcp_bind_trans_net_rtp_port) != 0) {
			mgcp_rtp_end_reset(&endp->net_end);
			mgcp_rtp_end_reset(&endp->bts_end);
			return -1;
		}

		if (allocate_port(endp, &endp->trans_bts,
				  &endp->cfg->transcoder_ports,
				  mgcp_bind_trans_bts_rtp_port) != 0) {
			mgcp_rtp_end_reset(&endp->net_end);
			mgcp_rtp_end_reset(&endp->bts_end);
			mgcp_rtp_end_reset(&endp->trans_net);
			return -1;
		}

		/* remember that we have set up transcoding */
		endp->is_transcoded = 1;
	}

	return 0;
}

static struct msgb *handle_create_con(struct mgcp_config *cfg, struct msgb *msg)
{
	const char *trans_id;
	struct mgcp_trunk_config *tcfg;
	struct mgcp_endpoint *endp;
	int error_code = 400;

	const char *local_options = NULL;
	const char *callid = NULL;
	const char *mode = NULL;
	char *line, *save;

	/* parse CallID C: and LocalParameters L: */
	for_each_line((char *) msg->l3h, line, save) {
		/* skip first line */
		if (line == (char *) msg->l3h) {
			int found = mgcp_analyze_header(cfg, line, &trans_id, &endp);
			if (found != 0)
				return create_err_response(510, "CRCX", trans_id);
			continue;
		}

		switch (line[0]) {
		case 'L':
			local_options = (const char *) line + 3;
			break;
		case 'C':
			callid = (const char *) line + 3;
			break;
		case 'M':
			mode = (const char *) line + 3;
			break;
		default:
			LOGP(DMGCP, LOGL_NOTICE, "Unhandled option: '%c'/%d on 0x%x\n",
				*line, *line, ENDPOINT_NUMBER(endp));
			break;
		}
	}

	tcfg = endp->tcfg;

	/* Check required data */
	if (!callid || !mode) {
		LOGP(DMGCP, LOGL_ERROR, "Missing callid and mode in CRCX on 0x%x\n",
		     ENDPOINT_NUMBER(endp));
		return create_err_response(400, "CRCX", trans_id);
	}

	/* this appears to be a retransmission, maybe check trans id */
	if (endp->allocated &&
	    memcmp(endp->callid, callid, strlen(endp->callid)) == 0)
		return create_response_with_sdp(endp, "CRCX", trans_id);

	if (endp->allocated) {
		if (tcfg->force_realloc) {
			LOGP(DMGCP, LOGL_NOTICE, "Endpoint 0x%x already allocated. Forcing realloc.\n",
			    ENDPOINT_NUMBER(endp));
			mgcp_free_endp(endp);
			if (cfg->realloc_cb)
				cfg->realloc_cb(tcfg, ENDPOINT_NUMBER(endp));
		} else {
			LOGP(DMGCP, LOGL_ERROR, "Endpoint is already used. 0x%x\n",
			     ENDPOINT_NUMBER(endp));
			return create_err_response(400, "CRCX", trans_id);
		}
	}

	/* copy some parameters */
	endp->callid = talloc_strdup(tcfg->endpoints, callid);

	if (local_options)
		endp->local_options = talloc_strdup(tcfg->endpoints, local_options);

	if (parse_conn_mode(mode, &endp->conn_mode) != 0) {
		    error_code = 517;
		    goto error2;
	}

	/* initialize */
	endp->net_end.rtp_port = endp->net_end.rtcp_port = endp->bts_end.rtp_port = endp->bts_end.rtcp_port = 0;

	/* set to zero until we get the info */
	memset(&endp->net_end.addr, 0, sizeof(endp->net_end.addr));

	/* bind to the port now */
	if (allocate_ports(endp) != 0)
		goto error2;

	/* assign a local call identifier or fail */
	endp->ci = generate_call_id(cfg);
	if (endp->ci == CI_UNUSED)
		goto error2;

	endp->allocated = 1;
	endp->bts_end.payload_type = tcfg->audio_payload;

	/* policy CB */
	if (cfg->policy_cb) {
		switch (cfg->policy_cb(tcfg, ENDPOINT_NUMBER(endp), MGCP_ENDP_CRCX, trans_id)) {
		case MGCP_POLICY_REJECT:
			LOGP(DMGCP, LOGL_NOTICE, "CRCX rejected by policy on 0x%x\n",
			     ENDPOINT_NUMBER(endp));
			mgcp_free_endp(endp);
			return create_err_response(400, "CRCX", trans_id);
			break;
		case MGCP_POLICY_DEFER:
			/* stop processing */
			create_transcoder(endp);
			return NULL;
			break;
		case MGCP_POLICY_CONT:
			/* just continue */
			break;
		}
	}

	LOGP(DMGCP, LOGL_DEBUG, "Creating endpoint on: 0x%x CI: %u port: %u/%u\n",
		ENDPOINT_NUMBER(endp), endp->ci,
		endp->net_end.local_port, endp->bts_end.local_port);
	if (cfg->change_cb)
		cfg->change_cb(tcfg, ENDPOINT_NUMBER(endp), MGCP_ENDP_CRCX);

	create_transcoder(endp);
	return create_response_with_sdp(endp, "CRCX", trans_id);
error2:
	mgcp_free_endp(endp);
	LOGP(DMGCP, LOGL_NOTICE, "Resource error on 0x%x\n", ENDPOINT_NUMBER(endp));
	return create_err_response(error_code, "CRCX", trans_id);
}

static struct msgb *handle_modify_con(struct mgcp_config *cfg, struct msgb *msg)
{
	const char *trans_id;
	struct mgcp_endpoint *endp;
	int error_code = 500;
	int silent = 0;
	char *line, *save;

	for_each_line((char *) msg->l3h, line, save) {
		/* skip first line */
		if (line == (char *) msg->l3h) {
			int found = mgcp_analyze_header(cfg, line, &trans_id,
							&endp);
			if (found != 0)
				return create_err_response(510, "MDCX",
							   trans_id);

			if (endp->ci == CI_UNUSED) {
				LOGP(DMGCP, LOGL_ERROR, "Endpoint is not "
				     "holding a connection. 0x%x\n",
				     ENDPOINT_NUMBER(endp));
				return create_err_response(400, "MDCX", trans_id);
			}
		}

		switch (line[0]) {
		case 'C': {
			if (verify_call_id(endp, line + 3) != 0)
				goto error3;
			break;
		}
		case 'I': {
			if (verify_ci(endp, line + 3) != 0)
				goto error3;
			break;
		}
		case 'L':
			/* skip */
			break;
		case 'M':
			if (parse_conn_mode(line + 3, &endp->conn_mode) != 0) {
			    error_code = 517;
			    goto error3;
			}
			endp->orig_mode = endp->conn_mode;
			break;
		case 'Z':
			silent = strcmp("noanswer", line + 3) == 0;
			break;
		case '\0':
			/* SDP file begins */
			break;
		case 'a':
		case 'o':
		case 's':
		case 't':
		case 'v':
			/* skip these SDP attributes */
			break;
		case 'm': {
			int port;
			int payload;

			if (sscanf(line, "m=audio %d RTP/AVP %d", &port, &payload) == 2) {
				endp->net_end.rtp_port = htons(port);
				endp->net_end.rtcp_port = htons(port + 1);
				endp->net_end.payload_type = payload;
			}
			break;
		}
		case 'c': {
			char ipv4[16];

			if (sscanf(line, "c=IN IP4 %15s", ipv4) == 1) {
				inet_aton(ipv4, &endp->net_end.addr);
			}
			break;
		}
		default:
			LOGP(DMGCP, LOGL_NOTICE, "Unhandled option: '%c'/%d on 0x%x\n",
				line[0], line[0], ENDPOINT_NUMBER(endp));
			break;
		}
	}

	/* policy CB */
	if (cfg->policy_cb) {
		switch (cfg->policy_cb(endp->tcfg, ENDPOINT_NUMBER(endp), MGCP_ENDP_MDCX, trans_id)) {
		case MGCP_POLICY_REJECT:
			LOGP(DMGCP, LOGL_NOTICE, "MDCX rejected by policy on 0x%x\n",
			     ENDPOINT_NUMBER(endp));
			if (silent)
				goto out_silent;
			return create_err_response(400, "MDCX", trans_id);
			break;
		case MGCP_POLICY_DEFER:
			/* stop processing */
			return NULL;
			break;
		case MGCP_POLICY_CONT:
			/* just continue */
			break;
		}
	}

	/* modify */
	LOGP(DMGCP, LOGL_DEBUG, "Modified endpoint on: 0x%x Server: %s:%u\n",
		ENDPOINT_NUMBER(endp), inet_ntoa(endp->net_end.addr), ntohs(endp->net_end.rtp_port));
	if (cfg->change_cb)
		cfg->change_cb(endp->tcfg, ENDPOINT_NUMBER(endp), MGCP_ENDP_MDCX);
	if (silent)
		goto out_silent;

	return create_response_with_sdp(endp, "MDCX", trans_id);

error3:
	return create_err_response(error_code, "MDCX", trans_id);


out_silent:
	return NULL;
}

static struct msgb *handle_delete_con(struct mgcp_config *cfg, struct msgb *msg)
{
	const char *trans_id;
	struct mgcp_endpoint *endp;
	int error_code = 400;
	int silent = 0;
	char *line, *save;
	char stats[1048];

	for_each_line((char *) msg->l3h, line, save) {
		/* skip first line */
		if ((char *) msg->l3h == line) {
			int found = mgcp_analyze_header(cfg, line, &trans_id,
							&endp);
			if (found != 0)
				return create_err_response(error_code, "DLCX",
							   trans_id);

			if (!endp->allocated) {
				LOGP(DMGCP, LOGL_ERROR, "Endpoint is not "
				     "used. 0x%x\n", ENDPOINT_NUMBER(endp));
				return create_err_response(400, "DLCX",
							   trans_id);
			}
		}

		switch (line[0]) {
		case 'C':
			if (verify_call_id(endp, line + 3) != 0)
				goto error3;
			break;
		case 'I':
			if (verify_ci(endp, line + 3) != 0)
				goto error3;
			break;
		case 'Z':
			silent = strcmp("noanswer", line + 3) == 0;
			break;
		default:
			LOGP(DMGCP, LOGL_NOTICE, "Unhandled option: '%c'/%d on 0x%x\n",
				line[0], line[0], ENDPOINT_NUMBER(endp));
			break;
		}
	}

	/* policy CB */
	if (cfg->policy_cb) {
		switch (cfg->policy_cb(endp->tcfg, ENDPOINT_NUMBER(endp), MGCP_ENDP_DLCX, trans_id)) {
		case MGCP_POLICY_REJECT:
			LOGP(DMGCP, LOGL_NOTICE, "DLCX rejected by policy on 0x%x\n",
			     ENDPOINT_NUMBER(endp));
			if (silent)
				goto out_silent;
			return create_err_response(400, "DLCX", trans_id);
			break;
		case MGCP_POLICY_DEFER:
			/* stop processing */
			delete_transcoder(endp);
			return NULL;
			break;
		case MGCP_POLICY_CONT:
			/* just continue */
			break;
		}
	}

	/* free the connection */
	LOGP(DMGCP, LOGL_DEBUG, "Deleted endpoint on: 0x%x Server: %s:%u\n",
		ENDPOINT_NUMBER(endp), inet_ntoa(endp->net_end.addr), ntohs(endp->net_end.rtp_port));

	/* save the statistics of the current call */
	mgcp_format_stats(endp, stats, sizeof(stats));

	delete_transcoder(endp);
	mgcp_free_endp(endp);
	if (cfg->change_cb)
		cfg->change_cb(endp->tcfg, ENDPOINT_NUMBER(endp), MGCP_ENDP_DLCX);

	if (silent)
		goto out_silent;
	return create_ok_resp_with_param(250, "DLCX", trans_id, stats);

error3:
	return create_err_response(error_code, "DLCX", trans_id);

out_silent:
	return NULL;
}

static struct msgb *handle_rsip(struct mgcp_config *cfg, struct msgb *msg)
{
	const char *trans_id;
	struct mgcp_endpoint *endp;
	int found;
	char *data = strtok((char *) msg->l3h, "\r\n");

	found = mgcp_analyze_header(cfg, data, &trans_id, &endp);
	if (found != 0) {
		LOGP(DMGCP, LOGL_ERROR, "Failed to find the endpoint.\n");
		return NULL;
	}

	if (cfg->reset_cb)
		cfg->reset_cb(endp->tcfg);
	return NULL;
}

/*
 * This can request like DTMF detection and forward, fax detection... it
 * can also request when the notification should be send and such. We don't
 * do this right now.
 */
static struct msgb *handle_noti_req(struct mgcp_config *cfg, struct msgb *msg)
{
	const char *trans_id;
	struct mgcp_endpoint *endp;
	int found;
	char *data = strtok((char *) msg->l3h, "\r\n");

	found = mgcp_analyze_header(cfg, data, &trans_id, &endp);
	if (found != 0)
		return create_err_response(400, "RQNT", trans_id);

	if (!endp->allocated) {
		LOGP(DMGCP, LOGL_ERROR, "Endpoint is not used. 0x%x\n", ENDPOINT_NUMBER(endp));
		return create_err_response(400, "RQNT", trans_id);
	}
	return create_ok_response(200, "RQNT", trans_id);
}

struct mgcp_config *mgcp_config_alloc(void)
{
	struct mgcp_config *cfg;

	cfg = talloc_zero(NULL, struct mgcp_config);
	if (!cfg) {
		LOGP(DMGCP, LOGL_FATAL, "Failed to allocate config.\n");
		return NULL;
	}

	cfg->source_port = 2427;
	cfg->source_addr = talloc_strdup(cfg, "0.0.0.0");

	cfg->transcoder_remote_base = 4000;

	cfg->bts_ports.base_port = RTP_PORT_DEFAULT;
	cfg->net_ports.base_port = RTP_PORT_NET_DEFAULT;

	/* default trunk handling */
	cfg->trunk.cfg = cfg;
	cfg->trunk.trunk_nr = 0;
	cfg->trunk.trunk_type = MGCP_TRUNK_VIRTUAL;
	cfg->trunk.audio_name = talloc_strdup(cfg, "AMR/8000");
	cfg->trunk.audio_payload = 126;
	cfg->trunk.omit_rtcp = 0;

	INIT_LLIST_HEAD(&cfg->trunks);

	return cfg;
}

struct mgcp_trunk_config *mgcp_trunk_alloc(struct mgcp_config *cfg, int nr)
{
	struct mgcp_trunk_config *trunk;

	trunk = talloc_zero(cfg, struct mgcp_trunk_config);
	if (!trunk) {
		LOGP(DMGCP, LOGL_ERROR, "Failed to allocate.\n");
		return NULL;
	}

	trunk->cfg = cfg;
	trunk->trunk_type = MGCP_TRUNK_E1;
	trunk->trunk_nr = nr;
	trunk->audio_name = talloc_strdup(cfg, "AMR/8000");
	trunk->audio_payload = 126;
	trunk->number_endpoints = 33;
	trunk->omit_rtcp = 0;
	llist_add_tail(&trunk->entry, &cfg->trunks);
	return trunk;
}

struct mgcp_trunk_config *mgcp_trunk_num(struct mgcp_config *cfg, int index)
{
	struct mgcp_trunk_config *trunk;

	llist_for_each_entry(trunk, &cfg->trunks, entry)
		if (trunk->trunk_nr == index)
			return trunk;

	return NULL;
}

static void mgcp_rtp_end_reset(struct mgcp_rtp_end *end)
{
	if (end->local_alloc == PORT_ALLOC_DYNAMIC) {
		mgcp_free_rtp_port(end);
		end->local_port = 0;
	}

	end->packets = 0;
	end->octets = 0;
	memset(&end->addr, 0, sizeof(end->addr));
	end->rtp_port = end->rtcp_port = 0;
	end->payload_type = -1;
	end->local_alloc = -1;
}

static void mgcp_rtp_end_init(struct mgcp_rtp_end *end)
{
	mgcp_rtp_end_reset(end);
	end->rtp.fd = -1;
	end->rtcp.fd = -1;
}

int mgcp_endpoints_allocate(struct mgcp_trunk_config *tcfg)
{
	int i;

	/* Initialize all endpoints */
	tcfg->endpoints = _talloc_zero_array(tcfg->cfg,
				       sizeof(struct mgcp_endpoint),
				       tcfg->number_endpoints, "endpoints");
	if (!tcfg->endpoints)
		return -1;

	for (i = 0; i < tcfg->number_endpoints; ++i) {
		tcfg->endpoints[i].ci = CI_UNUSED;
		tcfg->endpoints[i].cfg = tcfg->cfg;
		tcfg->endpoints[i].tcfg = tcfg;
		mgcp_rtp_end_init(&tcfg->endpoints[i].net_end);
		mgcp_rtp_end_init(&tcfg->endpoints[i].bts_end);
		mgcp_rtp_end_init(&tcfg->endpoints[i].trans_net);
		mgcp_rtp_end_init(&tcfg->endpoints[i].trans_bts);
	}

	return 0;
}

void mgcp_free_endp(struct mgcp_endpoint *endp)
{
	LOGP(DMGCP, LOGL_DEBUG, "Deleting endpoint on: 0x%x\n", ENDPOINT_NUMBER(endp));
	endp->ci = CI_UNUSED;
	endp->allocated = 0;

	if (endp->callid) {
		talloc_free(endp->callid);
		endp->callid = NULL;
	}

	if (endp->local_options) {
		talloc_free(endp->local_options);
		endp->local_options = NULL;
	}

	mgcp_rtp_end_reset(&endp->bts_end);
	mgcp_rtp_end_reset(&endp->net_end);
	mgcp_rtp_end_reset(&endp->trans_net);
	mgcp_rtp_end_reset(&endp->trans_bts);
	endp->is_transcoded = 0;

	memset(&endp->net_state, 0, sizeof(endp->net_state));
	memset(&endp->bts_state, 0, sizeof(endp->bts_state));

	endp->conn_mode = endp->orig_mode = MGCP_CONN_NONE;
	endp->allow_patch = 0;

	memset(&endp->taps, 0, sizeof(endp->taps));
}

static int send_trans(struct mgcp_config *cfg, const char *buf, int len)
{
	struct sockaddr_in addr;

	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr = cfg->transcoder_in;
	addr.sin_port = htons(2427);
	return sendto(cfg->gw_fd.bfd.fd, buf, len, 0,
		      (struct sockaddr *) &addr, sizeof(addr));
}

static void send_msg(struct mgcp_endpoint *endp, int endpoint, int port,
		     const char *msg, const char *mode)
{
	char buf[2096];
	int len;

	/* hardcoded to AMR right now, we do not know the real type at this point */
	len = snprintf(buf, sizeof(buf),
			"%s 42 %x@mgw MGCP 1.0\r\n"
			"C: 4256\r\n"
			"M: %s\r\n"
			"\r\n"
			"c=IN IP4 %s\r\n"
			"m=audio %d RTP/AVP %d\r\n"
			"a=rtpmap:%d %s\r\n",
			msg, endpoint, mode, endp->cfg->source_addr,
			port, endp->tcfg->audio_payload,
			endp->tcfg->audio_payload, endp->tcfg->audio_name);

	if (len < 0)
		return;

	buf[sizeof(buf) - 1] = '\0';

	send_trans(endp->cfg, buf, len);
}

static void send_dlcx(struct mgcp_endpoint *endp, int endpoint)
{
	char buf[2096];
	int len;

	len = snprintf(buf, sizeof(buf),
			"DLCX 43 %x@mgw MGCP 1.0\r\n"
			"C: 4256\r\n"
			, endpoint);

	if (len < 0)
		return;

	buf[sizeof(buf) - 1] = '\0';

	send_trans(endp->cfg, buf, len);
}

static int send_agent(struct mgcp_config *cfg, const char *buf, int len)
{
	return write(cfg->gw_fd.bfd.fd, buf, len);
}

int mgcp_send_reset_all(struct mgcp_config *cfg)
{
	static const char mgcp_reset[] = {
	    "RSIP 1 *@mgw MGCP 1.0\r\n"
	};

	return send_agent(cfg, mgcp_reset, sizeof mgcp_reset -1);
}

int mgcp_send_reset_ep(struct mgcp_endpoint *endp, int endpoint)
{
	char buf[128];
	int len;

	len = snprintf(buf, sizeof(buf),
			"RSIP 39 %x@mgw MGCP 1.0\r\n"
			, endpoint);
	if (len < 0)
		return len;

	buf[sizeof(buf) - 1] = '\0';

	return send_agent(endp->cfg, buf, len);
}

static void create_transcoder(struct mgcp_endpoint *endp)
{
	int port;
	int in_endp = ENDPOINT_NUMBER(endp);
	int out_endp = endp_back_channel(in_endp);

	if (!endp->is_transcoded)
		return;

	send_msg(endp, in_endp, endp->trans_bts.local_port, "CRCX", "sendrecv");
	send_msg(endp, in_endp, endp->trans_bts.local_port, "MDCX", "sendrecv");
	send_msg(endp, out_endp, endp->trans_net.local_port, "CRCX", "sendrecv");
	send_msg(endp, out_endp, endp->trans_net.local_port, "MDCX", "sendrecv");

	port = rtp_calculate_port(in_endp, endp->cfg->transcoder_remote_base);
	endp->trans_bts.rtp_port = htons(port);
	endp->trans_bts.rtcp_port = htons(port + 1);

	port = rtp_calculate_port(out_endp, endp->cfg->transcoder_remote_base);
	endp->trans_net.rtp_port = htons(port);
	endp->trans_net.rtcp_port = htons(port + 1);
}

static void delete_transcoder(struct mgcp_endpoint *endp)
{
	int in_endp = ENDPOINT_NUMBER(endp);
	int out_endp = endp_back_channel(in_endp);

	if (!endp->is_transcoded)
		return;

	send_dlcx(endp, in_endp);
	send_dlcx(endp, out_endp);
}

int mgcp_reset_transcoder(struct mgcp_config *cfg)
{
	if (!cfg->transcoder_ip)
		return 0;

	static const char mgcp_reset[] = {
	    "RSIP 1 13@mgw MGCP 1.0\r\n"
	};

	return send_trans(cfg, mgcp_reset, sizeof mgcp_reset -1);
}

void mgcp_format_stats(struct mgcp_endpoint *endp, char *msg, size_t size)
{
	uint32_t expected, jitter;
	int ploss;
	mgcp_state_calc_loss(&endp->net_state, &endp->net_end,
				&expected, &ploss);
	jitter = mgcp_state_calc_jitter(&endp->net_state);

	snprintf(msg, size, "\r\nP: PS=%u, OS=%u, PR=%u, OR=%u, PL=%d, JI=%d",
			endp->bts_end.packets, endp->bts_end.octets,
			endp->net_end.packets, endp->net_end.octets,
			ploss, jitter);
	msg[size - 1] = '\0';
}
