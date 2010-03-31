/* A Media Gateway Control Protocol Media Gateway: RFC 3435 */
/* The protocol implementation */

/*
 * (C) 2009-2010 by Holger Hans Peter Freyther <zecke@selfish.org>
 * (C) 2009-2010 by On-Waves
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

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <limits.h>
#include <unistd.h>

#include <openbsc/debug.h>
#include <osmocore/msgb.h>
#include <osmocore/talloc.h>
#include <openbsc/gsm_data.h>
#include <osmocore/select.h>
#include <openbsc/mgcp.h>
#include <openbsc/mgcp_internal.h>

enum mgcp_connection_mode {
	MGCP_CONN_NONE = 0,
	MGCP_CONN_RECV_ONLY = 1,
	MGCP_CONN_SEND_ONLY = 2,
	MGCP_CONN_RECV_SEND = MGCP_CONN_RECV_ONLY | MGCP_CONN_SEND_ONLY,
};

/**
 * Macro for tokenizing MGCP messages and SDP in one go.
 *
 */
#define MSG_TOKENIZE_START \
	line_start = 0;						\
	for (i = 0; i < msgb_l3len(msg); ++i) {			\
		/* we have a line end */			\
		if (msg->l3h[i] == '\n') {			\
			/* skip the first line */		\
			if (line_start == 0) {			\
				line_start = i + 1;		\
				continue;			\
			}					\
								\
			/* check if we have a proper param */	\
			if (i - line_start == 1 && msg->l3h[line_start] == '\r') { \
			} else if (i - line_start > 2		\
			    && islower(msg->l3h[line_start])	\
			    && msg->l3h[line_start + 1] == '=') { \
			} else if (i - line_start < 3		\
			    || msg->l3h[line_start + 1] != ':'	\
			    || msg->l3h[line_start + 2] != ' ')	\
				goto error;			\
								\
			msg->l3h[i] = '\0';			\
			if (msg->l3h[i-1] == '\r')		\
				msg->l3h[i-1] = '\0';

#define MSG_TOKENIZE_END \
			line_start = i + 1; \
		}			    \
	}


struct mgcp_msg_ptr {
	unsigned int start;
	unsigned int length;
};

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

static int generate_call_id(struct mgcp_config *cfg)
{
	int i;

	/* use the call id */
	++cfg->last_call_id;

	/* handle wrap around */
	if (cfg->last_call_id == CI_UNUSED)
		++cfg->last_call_id;

	/* callstack can only be of size number_of_endpoints */
	/* verify that the call id is free, e.g. in case of overrun */
	for (i = 1; i < cfg->number_endpoints; ++i)
		if (cfg->endpoints[i].ci == cfg->last_call_id)
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

struct msgb *mgcp_create_response_with_data(int code, const char *msg, const char *trans,
				    const char *data)
{
	int len;
	struct msgb *res;

	res = mgcp_msgb_alloc();
	if (!res)
		return NULL;

	if (data) {
		len = snprintf((char *) res->data, 2048, "%d %s\n%s", code, trans, data);
	} else {
		len = snprintf((char *) res->data, 2048, "%d %s\n", code, trans);
	}

	res->l2h = msgb_put(res, len);
	LOGP(DMGCP, LOGL_DEBUG, "Sending response: code: %d for '%s'\n", code, res->l2h);
	return res;
}

static struct msgb *create_response(int code, const char *msg, const char *trans)
{
	return mgcp_create_response_with_data(code, msg, trans, NULL);
}

static struct msgb *create_response_with_sdp(struct mgcp_endpoint *endp,
					     const char *msg, const char *trans_id)
{
	const char *addr = endp->cfg->local_ip;
	char sdp_record[4096];

	if (!addr)
		addr = endp->cfg->source_addr;

	snprintf(sdp_record, sizeof(sdp_record) - 1,
			"I: %d\n\n"
			"v=0\r\n"
			"c=IN IP4 %s\r\n"
			"m=audio %d RTP/AVP %d\r\n"
			"a=rtpmap:%d %s\r\n",
			endp->ci, addr, endp->rtp_port,
			endp->bts_payload_type, endp->bts_payload_type,
		        endp->cfg->audio_name);
	return mgcp_create_response_with_data(200, msg, trans_id, sdp_record);
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

	if (msg->len < 4) {
		LOGP(DMGCP, LOGL_ERROR, "mgs too short: %d\n", msg->len);
		return NULL;
	}

        /* attempt to treat it as a response */
        if (sscanf((const char *)&msg->data[0], "%3d %*s", &code) == 1) {
		LOGP(DMGCP, LOGL_DEBUG, "Response: Code: %d\n", code);
	} else {
		int i, handled = 0;
		msg->l3h = &msg->l2h[4];
		for (i = 0; i < ARRAY_SIZE(mgcp_requests); ++i)
			if (strncmp(mgcp_requests[i].name, (const char *) &msg->data[0], 4) == 0) {
				handled = 1;
				resp = mgcp_requests[i].handle_request(cfg, msg);
				break;
			}
		if (!handled) {
			LOGP(DMGCP, LOGL_NOTICE, "MSG with type: '%.4s' not handled\n", &msg->data[0]);
		}
	}

	return resp;
}

/* string tokenizer for the poor */
static int find_msg_pointers(struct msgb *msg, struct mgcp_msg_ptr *ptrs, int ptrs_length)
{
	int i, found = 0;

	int whitespace = 1;
	for (i = 0; i < msgb_l3len(msg) && ptrs_length > 0; ++i) {
		/* if we have a space we found an end */
		if (msg->l3h[i]	== ' ' || msg->l3h[i] == '\r' || msg->l3h[i] == '\n') {
			if (!whitespace) {
				++found;
				whitespace = 1;
				ptrs->length = i - ptrs->start - 1;
				++ptrs;
				--ptrs_length;
			} else {
			    /* skip any number of whitespace */
			}

			/* line end... stop */
			if (msg->l3h[i] == '\r' || msg->l3h[i] == '\n')
				break;
		} else if (msg->l3h[i] == '\r' || msg->l3h[i] == '\n') {
			/* line end, be done */
			break;
		} else if (whitespace) {
			whitespace = 0;
			ptrs->start = i;
		}
	}

	if (ptrs_length == 0)
		return -1;
	return found;
}

static struct mgcp_endpoint *find_endpoint(struct mgcp_config *cfg, const char *mgcp)
{
	char *endptr = NULL;
	unsigned int gw = INT_MAX;

	gw = strtoul(mgcp, &endptr, 16);
	if (gw == 0 || gw >= cfg->number_endpoints || strcmp(endptr, "@mgw") != 0) {
		LOGP(DMGCP, LOGL_ERROR, "Not able to find endpoint: '%s'\n", mgcp);
		return NULL;
	}

	return &cfg->endpoints[gw];
}

static int analyze_header(struct mgcp_config *cfg, struct msgb *msg,
			  struct mgcp_msg_ptr *ptr, int size,
			  const char **transaction_id, struct mgcp_endpoint **endp)
{
	int found;

	*transaction_id = "000000";

	if (size < 3) {
		LOGP(DMGCP, LOGL_ERROR, "Not enough space in ptr\n");
		return -1;
	}

	found = find_msg_pointers(msg, ptr, size);

	if (found <= 3) {
		LOGP(DMGCP, LOGL_ERROR, "Gateway: Not enough params. Found: %d\n", found);
		return -1;
	}

	/*
	 * replace the space with \0. the main method gurantess that
	 * we still have + 1 for null termination
	 */
	msg->l3h[ptr[3].start + ptr[3].length + 1] = '\0';
	msg->l3h[ptr[2].start + ptr[2].length + 1] = '\0';
	msg->l3h[ptr[1].start + ptr[1].length + 1] = '\0';
	msg->l3h[ptr[0].start + ptr[0].length + 1] = '\0';

	if (strncmp("1.0", (const char *)&msg->l3h[ptr[3].start], 3) != 0
	    || strncmp("MGCP", (const char *)&msg->l3h[ptr[2].start], 4) != 0) {
		LOGP(DMGCP, LOGL_ERROR, "Wrong MGCP version. Not handling: '%s' '%s'\n",
			(const char *)&msg->l3h[ptr[3].start],
			(const char *)&msg->l3h[ptr[2].start]);
		return -1;
	}

	*transaction_id = (const char *)&msg->l3h[ptr[0].start];
	*endp = find_endpoint(cfg, (const char *)&msg->l3h[ptr[1].start]);
	return *endp == NULL;
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
		     const char *ci)
{
	if (atoi(ci) != endp->ci) {
		LOGP(DMGCP, LOGL_ERROR, "ConnectionIdentifiers do not match on 0x%x. %d != %s\n",
			ENDPOINT_NUMBER(endp), endp->ci, ci);
		return -1;
	}

	return 0;
}

static struct msgb *handle_audit_endpoint(struct mgcp_config *cfg, struct msgb *msg)
{
	struct mgcp_msg_ptr data_ptrs[6];
	int found, response;
	const char *trans_id;
	struct mgcp_endpoint *endp;

	found = analyze_header(cfg, msg, data_ptrs, ARRAY_SIZE(data_ptrs), &trans_id, &endp);
	if (found != 0)
	    response = 500;
	else
	    response = 200;

	return create_response(response, "AUEP", trans_id);
}

static int parse_conn_mode(const char* msg, int *conn_mode)
{
	int ret = 0;
	if (strcmp(msg, "recvonly") == 0)
		*conn_mode = MGCP_CONN_RECV_ONLY;
	else if (strcmp(msg, "sendrecv") == 0)
		*conn_mode = MGCP_CONN_RECV_SEND;
	else {
		LOGP(DMGCP, LOGL_ERROR, "Unknown connection mode: '%s'\n", msg);
		ret = -1;
	}

	return ret;
}

static struct msgb *handle_create_con(struct mgcp_config *cfg, struct msgb *msg)
{
	struct mgcp_msg_ptr data_ptrs[6];
	int found, i, line_start;
	const char *trans_id;
	struct mgcp_endpoint *endp;
	int error_code = 500;
	int port;

	found = analyze_header(cfg, msg, data_ptrs, ARRAY_SIZE(data_ptrs), &trans_id, &endp);
	if (found != 0)
		return create_response(500, "CRCX", trans_id);

	if (endp->ci != CI_UNUSED) {
		LOGP(DMGCP, LOGL_ERROR, "Endpoint is already used. 0x%x\n", ENDPOINT_NUMBER(endp));
		return create_response(500, "CRCX", trans_id);
	}

	/* parse CallID C: and LocalParameters L: */
	MSG_TOKENIZE_START
	switch (msg->l3h[line_start]) {
	case 'L':
		endp->local_options = talloc_strdup(cfg->endpoints,
			(const char *)&msg->l3h[line_start + 3]);
		break;
	case 'C':
		endp->callid = talloc_strdup(cfg->endpoints,
			(const char *)&msg->l3h[line_start + 3]);
		break;
	case 'M':
		if (parse_conn_mode((const char *)&msg->l3h[line_start + 3],
			    &endp->conn_mode) != 0) {
		    error_code = 517;
		    goto error2;
		}
		break;
	default:
		LOGP(DMGCP, LOGL_NOTICE, "Unhandled option: '%c'/%d on 0x%x\n",
			msg->l3h[line_start], msg->l3h[line_start],
			ENDPOINT_NUMBER(endp));
		break;
	}
	MSG_TOKENIZE_END

	/* initialize */
	endp->net_rtp = endp->net_rtcp = endp->bts_rtp = endp->bts_rtcp = 0;

	/* set to zero until we get the info */
	memset(&endp->remote, 0, sizeof(endp->remote));

	/* bind to the port now */
	port = rtp_calculate_port(ENDPOINT_NUMBER(endp), cfg->rtp_base_port);
	if (cfg->early_bind)
		endp->rtp_port = port;
	else if (mgcp_bind_rtp_port(endp, port) != 0)
		goto error2;

	/* assign a local call identifier or fail */
	endp->ci = generate_call_id(cfg);
	if (endp->ci == CI_UNUSED)
		goto error2;

	endp->bts_payload_type = cfg->audio_payload;

	/* policy CB */
	if (cfg->policy_cb) {
		switch (cfg->policy_cb(cfg, ENDPOINT_NUMBER(endp), MGCP_ENDP_CRCX, trans_id)) {
		case MGCP_POLICY_REJECT:
			LOGP(DMGCP, LOGL_NOTICE, "CRCX rejected by policy on 0x%x\n",
			     ENDPOINT_NUMBER(endp));
			mgcp_free_endp(endp);
			return create_response(500, "CRCX", trans_id);
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

	LOGP(DMGCP, LOGL_NOTICE, "Creating endpoint on: 0x%x CI: %u port: %u\n",
		ENDPOINT_NUMBER(endp), endp->ci, endp->rtp_port);
	if (cfg->change_cb)
		cfg->change_cb(cfg, ENDPOINT_NUMBER(endp), MGCP_ENDP_CRCX, endp->rtp_port);

	return create_response_with_sdp(endp, "CRCX", trans_id);
error:
	LOGP(DMGCP, LOGL_ERROR, "Malformed line: %s on 0x%x with: line_start: %d %d\n",
		    hexdump(msg->l3h, msgb_l3len(msg)),
		    ENDPOINT_NUMBER(endp), line_start, i);
	return create_response(error_code, "CRCX", trans_id);

error2:
	LOGP(DMGCP, LOGL_NOTICE, "Resource error on 0x%x\n", ENDPOINT_NUMBER(endp));
	return create_response(error_code, "CRCX", trans_id);
}

static struct msgb *handle_modify_con(struct mgcp_config *cfg, struct msgb *msg)
{
	struct mgcp_msg_ptr data_ptrs[6];
	int found, i, line_start;
	const char *trans_id;
	struct mgcp_endpoint *endp;
	int error_code = 500;

	found = analyze_header(cfg, msg, data_ptrs, ARRAY_SIZE(data_ptrs), &trans_id, &endp);
	if (found != 0)
		return create_response(error_code, "MDCX", trans_id);

	if (endp->ci == CI_UNUSED) {
		LOGP(DMGCP, LOGL_ERROR, "Endpoint is not holding a connection. 0x%x\n", ENDPOINT_NUMBER(endp));
		return create_response(error_code, "MDCX", trans_id);
	}

	MSG_TOKENIZE_START
	switch (msg->l3h[line_start]) {
	case 'C': {
		if (verify_call_id(endp, (const char *)&msg->l3h[line_start + 3]) != 0)
			goto error3;
		break;
	}
	case 'I': {
		if (verify_ci(endp, (const char *)&msg->l3h[line_start + 3]) != 0)
			goto error3;
		break;
	}
	case 'L':
		/* skip */
		break;
	case 'M':
		if (parse_conn_mode((const char *)&msg->l3h[line_start + 3],
			    &endp->conn_mode) != 0) {
		    error_code = 517;
		    goto error3;
		}
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
		const char *param = (const char *)&msg->l3h[line_start];

		if (sscanf(param, "m=audio %d RTP/AVP %d", &port, &payload) == 2) {
			endp->net_rtp = htons(port);
			endp->net_rtcp = htons(port + 1);
			endp->net_payload_type = payload;
		}
		break;
	}
	case 'c': {
		char ipv4[16];
		const char *param = (const char *)&msg->l3h[line_start];

		if (sscanf(param, "c=IN IP4 %15s", ipv4) == 1) {
			inet_aton(ipv4, &endp->remote);
		}
		break;
	}
	default:
		LOGP(DMGCP, LOGL_NOTICE, "Unhandled option: '%c'/%d on 0x%x\n",
			msg->l3h[line_start], msg->l3h[line_start],
			ENDPOINT_NUMBER(endp));
		break;
	}
	MSG_TOKENIZE_END

	/* policy CB */
	if (cfg->policy_cb) {
		switch (cfg->policy_cb(cfg, ENDPOINT_NUMBER(endp), MGCP_ENDP_MDCX, trans_id)) {
		case MGCP_POLICY_REJECT:
			LOGP(DMGCP, LOGL_NOTICE, "MDCX rejected by policy on 0x%x\n",
			     ENDPOINT_NUMBER(endp));
			return create_response(500, "MDCX", trans_id);
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
	LOGP(DMGCP, LOGL_NOTICE, "Modified endpoint on: 0x%x Server: %s:%u\n",
		ENDPOINT_NUMBER(endp), inet_ntoa(endp->remote), ntohs(endp->net_rtp));
	if (cfg->change_cb)
		cfg->change_cb(cfg, ENDPOINT_NUMBER(endp), MGCP_ENDP_MDCX, endp->rtp_port);
	return create_response_with_sdp(endp, "MDCX", trans_id);

error:
	LOGP(DMGCP, LOGL_ERROR, "Malformed line: %s on 0x%x with: line_start: %d %d %d\n",
		    hexdump(msg->l3h, msgb_l3len(msg)),
		    ENDPOINT_NUMBER(endp), line_start, i, msg->l3h[line_start]);
	return create_response(error_code, "MDCX", trans_id);

error3:
	return create_response(error_code, "MDCX", trans_id);
}

static struct msgb *handle_delete_con(struct mgcp_config *cfg, struct msgb *msg)
{
	struct mgcp_msg_ptr data_ptrs[6];
	int found, i, line_start;
	const char *trans_id;
	struct mgcp_endpoint *endp;
	int error_code = 500;

	found = analyze_header(cfg, msg, data_ptrs, ARRAY_SIZE(data_ptrs), &trans_id, &endp);
	if (found != 0)
		return create_response(error_code, "DLCX", trans_id);

	if (endp->ci == CI_UNUSED) {
		LOGP(DMGCP, LOGL_ERROR, "Endpoint is not used. 0x%x\n", ENDPOINT_NUMBER(endp));
		return create_response(error_code, "DLCX", trans_id);
	}

	MSG_TOKENIZE_START
	switch (msg->l3h[line_start]) {
	case 'C': {
		if (verify_call_id(endp, (const char *)&msg->l3h[line_start + 3]) != 0)
			goto error3;
		break;
	}
	case 'I': {
		if (verify_ci(endp, (const char *)&msg->l3h[line_start + 3]) != 0)
			goto error3;
		break;
	}
	default:
		LOGP(DMGCP, LOGL_NOTICE, "Unhandled option: '%c'/%d on 0x%x\n",
			msg->l3h[line_start], msg->l3h[line_start],
			ENDPOINT_NUMBER(endp));
		break;
	}
	MSG_TOKENIZE_END

	/* policy CB */
	if (cfg->policy_cb) {
		switch (cfg->policy_cb(cfg, ENDPOINT_NUMBER(endp), MGCP_ENDP_DLCX, trans_id)) {
		case MGCP_POLICY_REJECT:
			LOGP(DMGCP, LOGL_NOTICE, "DLCX rejected by policy on 0x%x\n",
			     ENDPOINT_NUMBER(endp));
			return create_response(500, "DLCX", trans_id);
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

	/* free the connection */
	mgcp_free_endp(endp);
	if (cfg->change_cb)
		cfg->change_cb(cfg, ENDPOINT_NUMBER(endp), MGCP_ENDP_DLCX, endp->rtp_port);

	return create_response(250, "DLCX", trans_id);

error:
	LOGP(DMGCP, LOGL_ERROR, "Malformed line: %s on 0x%x with: line_start: %d %d\n",
		    hexdump(msg->l3h, msgb_l3len(msg)),
		    ENDPOINT_NUMBER(endp), line_start, i);
	return create_response(error_code, "DLCX", trans_id);

error3:
	return create_response(error_code, "DLCX", trans_id);
}

static struct msgb *handle_rsip(struct mgcp_config *cfg, struct msgb *msg)
{
	if (cfg->reset_cb)
		cfg->reset_cb(cfg);
	return NULL;
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
	cfg->audio_name = talloc_strdup(cfg, "GSM-EFR/8000");
	cfg->audio_payload = 97;
	cfg->rtp_base_port = RTP_PORT_DEFAULT;

	return cfg;
}

int mgcp_endpoints_allocate(struct mgcp_config *cfg)
{
	int i;

	/* Initialize all endpoints */
	cfg->endpoints = _talloc_zero_array(cfg,
				       sizeof(struct mgcp_endpoint),
				       cfg->number_endpoints, "endpoints");
	if (!cfg->endpoints)
		return -1;

	for (i = 0; i < cfg->number_endpoints; ++i) {
		cfg->endpoints[i].local_rtp.fd = -1;
		cfg->endpoints[i].local_rtcp.fd = -1;
		cfg->endpoints[i].ci = CI_UNUSED;
		cfg->endpoints[i].cfg = cfg;
		cfg->endpoints[i].net_payload_type = -1;
		cfg->endpoints[i].bts_payload_type = -1;
	}

	return 0;
}

void mgcp_free_endp(struct mgcp_endpoint *endp)
{
	LOGP(DMGCP, LOGL_DEBUG, "Deleting endpoint on: 0x%x\n", ENDPOINT_NUMBER(endp));
	endp->ci= CI_UNUSED;

	if (endp->callid) {
		talloc_free(endp->callid);
		endp->callid = NULL;
	}

	if (endp->local_options) {
		talloc_free(endp->local_options);
		endp->local_options = NULL;
	}

	if (!endp->cfg->early_bind) {
		bsc_unregister_fd(&endp->local_rtp);
		bsc_unregister_fd(&endp->local_rtcp);
	}

	endp->net_rtp = endp->net_rtcp = endp->bts_rtp = endp->bts_rtcp = 0;
	endp->net_payload_type = endp->bts_payload_type = -1;
}
