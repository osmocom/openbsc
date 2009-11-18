/* A Media Gateway Control Protocol Media Gateway: RFC 3435 */

/*
 * (C) 2009 by Holger Hans Peter Freyther <zecke@selfish.org>
 * (C) 2009 by on-waves.com
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

#include <sys/socket.h>
#include <arpa/inet.h>

#include <openbsc/debug.h>
#include <openbsc/msgb.h>
#include <openbsc/talloc.h>
#include <openbsc/gsm_data.h>
#include <openbsc/select.h>
#include <openbsc/mgcp.h>

#include <vty/command.h>
#include <vty/vty.h>

/* this is here for the vty... it will never be called */
void subscr_put() { abort(); }
void vty_event() { }

#define _GNU_SOURCE
#include <getopt.h>

#warning "Make use of the rtp proxy code"

static int source_port = 2427;
static const char *local_ip = NULL;
static const char *source_addr = "0.0.0.0";
static struct bsc_fd bfd;
static const unsigned int number_endpoints = 32 + 1;
static const char *bts_ip = NULL;
static struct in_addr bts_in;
static int first_request = 1;
static const char *audio_name = "GSM-EFR/8000";
static int audio_payload = 97;
static int audio_loop = 0;
static int early_bind = 0;

static char *config_file = "mgcp.cfg";

/* used by msgb and mgcp */
void *tall_bsc_ctx = NULL;

enum mgcp_connection_mode {
	MGCP_CONN_NONE = 0,
	MGCP_CONN_RECV_ONLY = 1,
	MGCP_CONN_SEND_ONLY = 2,
	MGCP_CONN_RECV_SEND = MGCP_CONN_RECV_ONLY | MGCP_CONN_SEND_ONLY,
};

enum {
	DEST_NETWORK = 0,
	DEST_BTS = 1,
};

enum {
	PROTO_RTP,
	PROTO_RTCP,
};

#define CI_UNUSED 0
static unsigned int last_call_id = 0;

struct mgcp_endpoint {
	int ci;
	char *callid;
	char *local_options;
	int conn_mode;

	/* the local rtp port */
	int rtp_port;

	/*
	 * RTP mangling:
	 *  - we get RTP and RTCP to us and need to forward to the BTS
	 *  - we get RTP and RTCP from the BTS and forward to the network
	 */
	struct bsc_fd local_rtp;
	struct bsc_fd local_rtcp;

	struct in_addr remote;

	/* in network byte order */
	int rtp, rtcp;
	int bts_rtp, bts_rtcp;
};

static struct mgcp_endpoint *endpoints = NULL;
#define ENDPOINT_NUMBER(endp) abs(endp - endpoints)

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
	void (*handle_request) (struct msgb *msg, struct sockaddr_in *source);
	char *debug_name;
};

#define MGCP_REQUEST(NAME, REQ, DEBUG_NAME) \
	{ .name = NAME, .handle_request = REQ, .debug_name = DEBUG_NAME },

static void handle_audit_endpoint(struct msgb *msg, struct sockaddr_in *source);
static void handle_create_con(struct msgb *msg, struct sockaddr_in *source);
static void handle_delete_con(struct msgb *msg, struct sockaddr_in *source);
static void handle_modify_con(struct msgb *msg, struct sockaddr_in *source);

static int generate_call_id()
{
	int i;

	/* use the call id */
	++last_call_id;

	/* handle wrap around */
	if (last_call_id == CI_UNUSED)
		++last_call_id;

	/* callstack can only be of size number_of_endpoints */
	/* verify that the call id is free, e.g. in case of overrun */
	for (i = 1; i < number_endpoints; ++i)
		if (endpoints[i].ci == last_call_id)
			return generate_call_id();

	return last_call_id;
}

/* FIXIME/TODO: need to have a list of pending transactions and check that */
static unsigned int generate_transaction_id()
{
	return abs(rand());
}

static int _send(int fd, struct in_addr *addr, int port, char *buf, int len)
{
	struct sockaddr_in out;
	out.sin_family = AF_INET;
	out.sin_port = port;
	memcpy(&out.sin_addr, addr, sizeof(*addr));

	return sendto(fd, buf, len, 0, (struct sockaddr *)&out, sizeof(out));
}

/*
 * There is data coming. We will have to figure out if it
 * came from the BTS or the MediaGateway of the MSC. On top
 * of that we need to figure out if it was RTP or RTCP.
 *
 * Currently we do not communicate with the BSC so we have
 * no idea where the BTS is listening for RTP and need to
 * do the classic routing trick. Wait for the first packet
 * from the BTS and then go ahead.
 */
static int rtp_data_cb(struct bsc_fd *fd, unsigned int what)
{
	char buf[4096];
	struct sockaddr_in addr;
	socklen_t slen = sizeof(addr);
	struct mgcp_endpoint *endp;
	int rc, dest, proto;

	endp = (struct mgcp_endpoint *) fd->data;

	rc = recvfrom(fd->fd, &buf, sizeof(buf), 0,
			    (struct sockaddr *) &addr, &slen);
	if (rc < 0) {
		DEBUGP(DMGCP, "Failed to receive message on: 0x%x\n",
			ENDPOINT_NUMBER(endp));
		return -1;
	}

	/*
	 * Figure out where to forward it to. This code assumes that we
	 * have received the Connection Modify and know who is a legitimate
	 * partner. According to the spec we could attempt to forward even
	 * after the Create Connection but we will not as we are not really
	 * able to tell if this is legitimate.
	 */
	#warning "Slight spec violation. With connection mode recvonly we should attempt to forward."
	dest = memcmp(&addr.sin_addr, &endp->remote, sizeof(addr.sin_addr)) == 0
			? DEST_BTS : DEST_NETWORK;
	proto = fd == &endp->local_rtp ? PROTO_RTP : PROTO_RTCP;

	/* We have no idea who called us, maybe it is the BTS. */
	if (dest == DEST_NETWORK && endp->bts_rtp == 0) {
		/* it was the BTS... */
		if (memcmp(&addr.sin_addr, &bts_in, sizeof(bts_in)) == 0) {
			if (fd == &endp->local_rtp) {
				endp->bts_rtp = addr.sin_port;
				endp->bts_rtcp = htons(ntohs(addr.sin_port) + 1);
			} else {
				endp->bts_rtp = htons(ntohs(addr.sin_port) - 1);
				endp->bts_rtcp = addr.sin_port;
			}

			DEBUGP(DMGCP, "Found BTS for endpoint: 0x%x on port: %d\n",
				ENDPOINT_NUMBER(endp), ntohs(endp->bts_rtp));
		}
	}

	/* dispatch */
	if (audio_loop)
		dest = !dest;

	if (dest == DEST_NETWORK) {
		return _send(fd->fd, &endp->remote,
			     proto == PROTO_RTP ? endp->rtp : endp->rtcp,
			     buf, rc);
	} else {
		return _send(fd->fd, &bts_in,
			     proto == PROTO_RTP ? endp->bts_rtp : endp->bts_rtcp,
			     buf, rc);
	}
}

static int create_bind(struct bsc_fd *fd, int port)
{
	struct sockaddr_in addr;
	int on = 1;

	fd->fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd->fd < 0)
		return -1;

	setsockopt(fd->fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);
	inet_aton(source_addr, &addr.sin_addr);

	if (bind(fd->fd, (struct sockaddr *) &addr, sizeof(addr)) < 0)
		return -1;

	return 0;
}

static int bind_rtp(struct mgcp_endpoint *endp)
{
	/* set to zero until we get the info */
	memset(&endp->remote, 0, sizeof(endp->remote));
	endp->bts_rtp = endp->bts_rtcp = 0;
	endp->rtp = endp->rtcp = 0;

	if (create_bind(&endp->local_rtp, endp->rtp_port) != 0) {
		DEBUGP(DMGCP, "Failed to create RTP port: %d on 0x%x\n",
		       endp->rtp_port, ENDPOINT_NUMBER(endp));
		goto cleanup0;
	}

	if (create_bind(&endp->local_rtcp, endp->rtp_port + 1) != 0) {
		DEBUGP(DMGCP, "Failed to create RTCP port: %d on 0x%x\n",
		       endp->rtp_port + 1, ENDPOINT_NUMBER(endp));
		goto cleanup1;
	}

	endp->local_rtp.cb = rtp_data_cb;
	endp->local_rtp.data = endp;
	endp->local_rtp.when = BSC_FD_READ;
	if (bsc_register_fd(&endp->local_rtp) != 0) {
		DEBUGP(DMGCP, "Failed to register RTP port %d on 0x%x\n",
			endp->rtp_port, ENDPOINT_NUMBER(endp));
		goto cleanup2;
	}

	endp->local_rtcp.cb = rtp_data_cb;
	endp->local_rtcp.data = endp;
	endp->local_rtcp.when = BSC_FD_READ;
	if (bsc_register_fd(&endp->local_rtcp) != 0) {
		DEBUGP(DMGCP, "Failed to register RTCP port %d on 0x%x\n",
			endp->rtp_port + 1, ENDPOINT_NUMBER(endp));
		goto cleanup3;
	}

	return 0;

cleanup3:
	bsc_unregister_fd(&endp->local_rtp);
cleanup2:
	close(endp->local_rtcp.fd);
	endp->local_rtcp.fd = -1;
cleanup1:
	close(endp->local_rtp.fd);
	endp->local_rtp.fd = -1;
cleanup0:
	return -1;
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
};

static void send_response_with_data(int code, const char *msg, const char *trans,
				    const char *data, struct sockaddr_in *source)
{
	char buf[4096];
	int len;

	if (data) {
		len = snprintf(buf, sizeof(buf), "%d %s\n%s", code, trans, data);
	} else {
		len = snprintf(buf, sizeof(buf), "%d %s\n", code, trans);
	}
	DEBUGP(DMGCP, "Sending response: code: %d for '%s'\n", code, msg);

	sendto(bfd.fd, buf, len, 0, (struct sockaddr *)source, sizeof(*source));
}

static void send_response(int code, const char *msg, const char *trans, struct sockaddr_in *source)
{
	send_response_with_data(code, msg, trans, NULL, source);
}

static void send_with_sdp(struct mgcp_endpoint *endp, const char *msg, const char *trans_id, struct sockaddr_in *source)
{
	const char *addr = local_ip;
	char sdp_record[4096];

	if (!addr)
		addr = source_addr;

	snprintf(sdp_record, sizeof(sdp_record) - 1,
			"I: %d\n\n"
			"v=0\r\n"
			"c=IN IP4 %s\r\n"
			"m=audio %d RTP/AVP %d\r\n"
			"a=rtpmap:%d %s\r\n",
			endp->ci, addr, endp->rtp_port,
			audio_payload, audio_payload, audio_name);
	return send_response_with_data(200, msg, trans_id, sdp_record, source);
}

/* send a static record */
static void send_rsip(struct sockaddr_in *source)
{
	char reset[4096];
	int len, rc;

	len = snprintf(reset, sizeof(reset) - 1,
			"RSIP %u *@mgw MGCP 1.0\n"
			"RM: restart\n", generate_transaction_id());
	rc = sendto(bfd.fd, reset, len, 0, (struct sockaddr *) source, sizeof(*source));
	if (rc < 0) {
		DEBUGP(DMGCP, "Failed to send RSIP: %d\n", rc);
	}
}

/*
 * handle incoming messages:
 *   - this can be a command (four letters, space, transaction id)
 *   - or a response (three numbers, space, transaction id)
 */
static void handle_message(struct msgb *msg, struct sockaddr_in *source)
{
        int code;

	if (msg->len < 4) {
		DEBUGP(DMGCP, "mgs too short: %d\n", msg->len);
		return;
	}

        /* attempt to treat it as a response */
        if (sscanf((const char *)&msg->data[0], "%3d %*s", &code) == 1) {
		DEBUGP(DMGCP, "Response: Code: %d\n", code);
	} else {
		int i, handled = 0;
		msg->l3h = &msg->l2h[4];
		for (i = 0; i < ARRAY_SIZE(mgcp_requests); ++i)
			if (strncmp(mgcp_requests[i].name, (const char *) &msg->data[0], 4) == 0) {
				handled = 1;
				mgcp_requests[i].handle_request(msg, source);
			}
		if (!handled) {
			DEBUGP(DMGCP, "MSG with type: '%.4s' not handled\n", &msg->data[0]);
		}
	}
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

static struct mgcp_endpoint *find_endpoint(const char *mgcp)
{
	char *endptr = NULL;
	unsigned int gw = INT_MAX;

	gw = strtoul(mgcp, &endptr, 16);
	if (gw == 0 || gw >= number_endpoints || strcmp(endptr, "@mgw") != 0) {
		DEBUGP(DMGCP, "Not able to find endpoint: '%s'\n", mgcp);
		return NULL;
	}

	return &endpoints[gw];
}

static int analyze_header(struct msgb *msg, struct mgcp_msg_ptr *ptr, int size,
			  const char **transaction_id, struct mgcp_endpoint **endp)
{
	int found;

	if (size < 3) {
		DEBUGP(DMGCP, "Not enough space in ptr\n");
		return -1;
	}

	found = find_msg_pointers(msg, ptr, size);

	if (found < 3) {
		DEBUGP(DMGCP, "Gateway: Not enough params. Found: %d\n", found);
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
		DEBUGP(DMGCP, "Wrong MGCP version. Not handling: '%s' '%s'\n",
			(const char *)&msg->l3h[ptr[3].start],
			(const char *)&msg->l3h[ptr[2].start]);
		return -1;
	}

	*transaction_id = (const char *)&msg->l3h[ptr[0].start];
	*endp = find_endpoint((const char *)&msg->l3h[ptr[1].start]);
	return *endp == NULL;
}

static int verify_call_id(const struct mgcp_endpoint *endp,
			  const char *callid)
{
	if (strcmp(endp->callid, callid) != 0) {
		DEBUGP(DMGCP, "CallIDs does not match on 0x%x. '%s' != '%s'\n",
			ENDPOINT_NUMBER(endp), endp->callid, callid);
		return -1;
	}

	return 0;
}

static int verify_ci(const struct mgcp_endpoint *endp,
		     const char *ci)
{
	if (atoi(ci) != endp->ci) {
		DEBUGP(DMGCP, "ConnectionIdentifiers do not match on 0x%x. %d != %s\n",
			ENDPOINT_NUMBER(endp), endp->ci, ci);
		return -1;
	}

	return 0;
}

static void handle_audit_endpoint(struct msgb *msg, struct sockaddr_in *source)
{
	struct mgcp_msg_ptr data_ptrs[6];
	int found, response;
	const char *trans_id;
	struct mgcp_endpoint *endp;

	found = analyze_header(msg, data_ptrs, ARRAY_SIZE(data_ptrs), &trans_id, &endp);
	if (found != 0)
	    response = 500;
	else
	    response = 200;

	return send_response(response, "AUEP", trans_id, source);
}

static int parse_conn_mode(const char* msg, int *conn_mode)
{
	int ret = 0;
	if (strcmp(msg, "recvonly") == 0)
		*conn_mode = MGCP_CONN_RECV_ONLY;
	else if (strcmp(msg, "sendrecv") == 0)
		*conn_mode = MGCP_CONN_RECV_SEND;
	else {
		DEBUGP(DMGCP, "Unknown connection mode: '%s'\n", msg);
		ret = -1;
	}

	return ret;
}

static void handle_create_con(struct msgb *msg, struct sockaddr_in *source)
{
	struct mgcp_msg_ptr data_ptrs[6];
	int found, i, line_start;
	const char *trans_id;
	struct mgcp_endpoint *endp;
	int error_code = 500;

	found = analyze_header(msg, data_ptrs, ARRAY_SIZE(data_ptrs), &trans_id, &endp);
	if (found != 0)
		return send_response(500, "CRCX", trans_id, source);

	if (endp->ci != CI_UNUSED) {
		DEBUGP(DMGCP, "Endpoint is already used. 0x%x\n", ENDPOINT_NUMBER(endp));
		return send_response(500, "CRCX", trans_id, source);
	}

	/* parse CallID C: and LocalParameters L: */
	MSG_TOKENIZE_START
	switch (msg->l3h[line_start]) {
	case 'L':
		endp->local_options = talloc_strdup(endpoints,
			(const char *)&msg->l3h[line_start + 3]);
		break;
	case 'C':
		endp->callid = talloc_strdup(endpoints,
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
		DEBUGP(DMGCP, "Unhandled option: '%c'/%d on 0x%x\n",
			msg->l3h[line_start], msg->l3h[line_start],
			ENDPOINT_NUMBER(endp));
		break;
	}
	MSG_TOKENIZE_END


	/* bind to the port now */
	endp->rtp_port = rtp_calculate_port(ENDPOINT_NUMBER(endp), rtp_base_port);
	if (!early_bind && bind_rtp(endp) != 0)
		goto error2;

	/* assign a local call identifier or fail */
	endp->ci = generate_call_id();
	if (endp->ci == CI_UNUSED)
		goto error2;

	DEBUGP(DMGCP, "Creating endpoint on: 0x%x CI: %u port: %u\n",
		ENDPOINT_NUMBER(endp), endp->ci, endp->rtp_port);
	return send_with_sdp(endp, "CRCX", trans_id, source);
error:
	DEBUGP(DMGCP, "Malformed line: %s on 0x%x with: line_start: %d %d\n",
		    hexdump(msg->l3h, msgb_l3len(msg)),
		    ENDPOINT_NUMBER(endp), line_start, i);
	return send_response(error_code, "CRCX", trans_id, source);

error2:
	DEBUGP(DMGCP, "Resource error on 0x%x\n", ENDPOINT_NUMBER(endp));
	return send_response(error_code, "CRCX", trans_id, source);
}

static void handle_modify_con(struct msgb *msg, struct sockaddr_in *source)
{
	struct mgcp_msg_ptr data_ptrs[6];
	int found, i, line_start;
	const char *trans_id;
	struct mgcp_endpoint *endp;
	int error_code = 500;

	found = analyze_header(msg, data_ptrs, ARRAY_SIZE(data_ptrs), &trans_id, &endp);
	if (found != 0)
		return send_response(error_code, "MDCX", trans_id, source);

	if (endp->ci == CI_UNUSED) {
		DEBUGP(DMGCP, "Endpoint is not holding a connection. 0x%x\n", ENDPOINT_NUMBER(endp));
		return send_response(error_code, "MDCX", trans_id, source);
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
		const char *param = (const char *)&msg->l3h[line_start];

		if (sscanf(param, "m=audio %d RTP/AVP %*d", &port) == 1) {
			endp->rtp = htons(port);
			endp->rtcp = htons(port + 1);
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
		DEBUGP(DMGCP, "Unhandled option: '%c'/%d on 0x%x\n",
			msg->l3h[line_start], msg->l3h[line_start],
			ENDPOINT_NUMBER(endp));
		break;
	}
	MSG_TOKENIZE_END

	/* modify */
	DEBUGP(DMGCP, "Modified endpoint on: 0x%x Server: %s:%u\n",
		ENDPOINT_NUMBER(endp), inet_ntoa(endp->remote), endp->rtp);
	return send_with_sdp(endp, "MDCX", trans_id, source);

error:
	DEBUGP(DMGCP, "Malformed line: %s on 0x%x with: line_start: %d %d %d\n",
		    hexdump(msg->l3h, msgb_l3len(msg)),
		    ENDPOINT_NUMBER(endp), line_start, i, msg->l3h[line_start]);
	return send_response(error_code, "MDCX", trans_id, source);

error3:
	return send_response(error_code, "MDCX", trans_id, source);
}

static void handle_delete_con(struct msgb *msg, struct sockaddr_in *source)
{
	struct mgcp_msg_ptr data_ptrs[6];
	int found, i, line_start;
	const char *trans_id;
	struct mgcp_endpoint *endp;
	int error_code = 500;

	found = analyze_header(msg, data_ptrs, ARRAY_SIZE(data_ptrs), &trans_id, &endp);
	if (found != 0)
		return send_response(error_code, "DLCX", trans_id, source);

	if (endp->ci == CI_UNUSED) {
		DEBUGP(DMGCP, "Endpoint is not used. 0x%x\n", ENDPOINT_NUMBER(endp));
		return send_response(error_code, "DLCX", trans_id, source);
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
		DEBUGP(DMGCP, "Unhandled option: '%c'/%d on 0x%x\n",
			msg->l3h[line_start], msg->l3h[line_start],
			ENDPOINT_NUMBER(endp));
		break;
	}
	MSG_TOKENIZE_END


	/* free the connection */
	DEBUGP(DMGCP, "Deleting endpoint on: 0x%x\n", ENDPOINT_NUMBER(endp));
	endp->ci= CI_UNUSED;
	talloc_free(endp->callid);
	talloc_free(endp->local_options);

	if (!early_bind) {
		bsc_unregister_fd(&endp->local_rtp);
		bsc_unregister_fd(&endp->local_rtcp);
	}

	return send_response(250, "DLCX", trans_id, source);

error:
	DEBUGP(DMGCP, "Malformed line: %s on 0x%x with: line_start: %d %d\n",
		    hexdump(msg->l3h, msgb_l3len(msg)),
		    ENDPOINT_NUMBER(endp), line_start, i);
	return send_response(error_code, "DLCX", trans_id, source);

error3:
	return send_response(error_code, "DLCX", trans_id, source);
}

static void print_help()
{
	printf("Some useful help...\n");
	printf(" -h --help is printing this text.\n");
	printf(" -c --config-file filename The config file to use.\n");
}

static void handle_options(int argc, char** argv)
{
	while (1) {
		int option_index = 0, c;
		static struct option long_options[] = {
			{"help", 0, 0, 'h'},
			{"config-file", 1, 0, 'c'},
			{0, 0, 0, 0},
		};

		c = getopt_long(argc, argv, "hc:", long_options, &option_index);

		if (c == -1)
			break;

		switch(c) {
		case 'h':
			print_help();
			exit(0);
			break;
		case 'c':
			config_file = talloc_strdup(tall_bsc_ctx, optarg);
			break;
		default:
			/* ignore */
			break;
		};
	}
}

static int read_call_agent(struct bsc_fd *fd, unsigned int what)
{
	struct sockaddr_in addr;
	socklen_t slen = sizeof(addr);
	struct msgb *msg;

	msg = (struct msgb *) fd->data;

	/* read one less so we can use it as a \0 */
	int rc = recvfrom(bfd.fd, msg->data, msg->data_len - 1, 0,
		(struct sockaddr *) &addr, &slen);
	if (rc < 0) {
		perror("Gateway failed to read");
		return -1;
	} else if (slen > sizeof(addr)) {
		fprintf(stderr, "Gateway received message from outerspace: %d %d\n",
			slen, sizeof(addr));
		return -1;
	}

	if (first_request) {
		first_request = 0;
		send_rsip(&addr);
		return 0;
        }

	/* handle message now */
	msg->l2h = msgb_put(msg, rc);
	handle_message(msg, &addr);
	msgb_reset(msg);
	return 0;
}

/*
 * vty code for mgcp below
 */
struct cmd_node mgcp_node = {
	MGCP_NODE,
	"%s(mgcp)#",
	1,
};

static int config_write_mgcp(struct vty *vty)
{
	vty_out(vty, "mgcp%s", VTY_NEWLINE);
	if (local_ip)
		vty_out(vty, " local ip %s%s", local_ip, VTY_NEWLINE);
	vty_out(vty, "  bts ip %s%s", bts_ip, VTY_NEWLINE);
	vty_out(vty, "  bind ip %s%s", source_addr, VTY_NEWLINE);
	vty_out(vty, "  bind port %u%s", source_port, VTY_NEWLINE);
	vty_out(vty, "  rtp base %u%s", rtp_base_port, VTY_NEWLINE);

	return CMD_SUCCESS;
}

DEFUN(cfg_mgcp,
      cfg_mgcp_cmd,
      "mgcp",
      "Configure the MGCP")
{
	vty->node = MGCP_NODE;
	return CMD_SUCCESS;
}

DEFUN(cfg_mgcp_local_ip,
      cfg_mgcp_local_ip_cmd,
      "local ip IP",
      "Set the IP to be used in SDP records")
{
	local_ip = talloc_strdup(tall_bsc_ctx, argv[0]);
	return CMD_SUCCESS;
}

DEFUN(cfg_mgcp_bts_ip,
      cfg_mgcp_bts_ip_cmd,
      "bts ip IP",
      "Set the IP of the BTS for RTP forwarding")
{
	bts_ip = talloc_strdup(tall_bsc_ctx, argv[0]);
	inet_aton(bts_ip, &bts_in);
	return CMD_SUCCESS;
}

DEFUN(cfg_mgcp_bind_ip,
      cfg_mgcp_bind_ip_cmd,
      "bind ip IP",
      "Bind the MGCP to this local addr")
{
	source_addr = talloc_strdup(tall_bsc_ctx, argv[0]);
	return CMD_SUCCESS;
}

DEFUN(cfg_mgcp_bind_port,
      cfg_mgcp_bind_port_cmd,
      "bind port <0-65534>",
      "Bind the MGCP to this port")
{
	unsigned int port = atoi(argv[0]);
	if (port > 65534) {
		vty_out(vty, "%% wrong bind port '%s'%s", argv[0], VTY_NEWLINE);
		return CMD_WARNING;
	}

	source_port = port;
	return CMD_SUCCESS;
}

DEFUN(cfg_mgcp_bind_early,
      cfg_mgcp_bind_early_cmd,
      "bind early (0|1)",
      "Bind all RTP ports early")
{
	unsigned int bind = atoi(argv[0]);
	if (bind != 0 && bind != 1) {
		vty_out(vty, "%% param must be 0 or 1.%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	early_bind = bind == 1;
	return CMD_SUCCESS;
}

DEFUN(cfg_mgcp_rtp_base_port,
      cfg_mgcp_rtp_base_port_cmd,
      "rtp base <0-65534>",
      "Base port to use")
{
	unsigned int port = atoi(argv[0]);
	if (port > 65534) {
		vty_out(vty, "%% wrong base port '%s'%s", argv[0], VTY_NEWLINE);
		return CMD_WARNING;
	}

	rtp_base_port = port;
	return CMD_SUCCESS;
}

DEFUN(cfg_mgcp_sdp_payload_number,
      cfg_mgcp_sdp_payload_number_cmd,
      "sdp audio payload number <1-255>",
      "Set the audio codec to use")
{
	unsigned int payload = atoi(argv[0]);
	if (payload > 255) {
		vty_out(vty, "%% wrong payload number '%s'%s", argv[0], VTY_NEWLINE);
		return CMD_WARNING;
	}

	audio_payload = payload;
	return CMD_SUCCESS;
}

DEFUN(cfg_mgcp_sdp_payload_name,
      cfg_mgcp_sdp_payload_name_cmd,
      "sdp audio payload name NAME",
      "Set the audio name to use")
{
	audio_name = talloc_strdup(tall_bsc_ctx, argv[0]);
	return CMD_SUCCESS;
}

DEFUN(cfg_mgcp_loop,
      cfg_mgcp_loop_cmd,
      "loop (0|1)",
      "Loop the audio")
{
	audio_loop = atoi(argv[0]);
	return CMD_SUCCESS;
}

static void mgcp_vty_init()
{
	cmd_init(1);
	vty_init();

	install_element(CONFIG_NODE, &cfg_mgcp_cmd);
	install_node(&mgcp_node, config_write_mgcp);
	install_default(MGCP_NODE);
	install_element(MGCP_NODE, &cfg_mgcp_local_ip_cmd);
	install_element(MGCP_NODE, &cfg_mgcp_bts_ip_cmd);
	install_element(MGCP_NODE, &cfg_mgcp_bind_ip_cmd);
	install_element(MGCP_NODE, &cfg_mgcp_bind_port_cmd);
	install_element(MGCP_NODE, &cfg_mgcp_bind_early_cmd);
	install_element(MGCP_NODE, &cfg_mgcp_rtp_base_port_cmd);
	install_element(MGCP_NODE, &cfg_mgcp_sdp_payload_number_cmd);
	install_element(MGCP_NODE, &cfg_mgcp_sdp_payload_name_cmd);
	install_element(MGCP_NODE, &cfg_mgcp_loop_cmd);
}

int main(int argc, char** argv)
{
	struct sockaddr_in addr;
	int on = 1, i, rc;

	tall_bsc_ctx = talloc_named_const(NULL, 1, "mgcp-callagent");
	handle_options(argc, argv);

	mgcp_vty_init();
	rc = vty_read_config_file(config_file);
	if (rc < 0) {
		fprintf(stderr, "Failed to parse the config file: '%s'\n", config_file);
		return rc;
	}


	if (!bts_ip) {
		fprintf(stderr, "Need to specify the BTS ip address for RTP handling.\n");
		return -1;
	}

	endpoints = _talloc_zero_array(tall_bsc_ctx,
				       sizeof(struct mgcp_endpoint),
				       number_endpoints, "endpoints");
	if (!endpoints) {
		fprintf(stderr, "Failed to allocate endpoints: %d. Quitting.\n", number_endpoints);
		return -1;
	}

	/* Initialize all endpoints */
	for (i = 0; i < number_endpoints; ++i) {
		endpoints[i].local_rtp.fd = -1;
		endpoints[i].local_rtcp.fd = -1;
		endpoints[i].ci = CI_UNUSED;
	}

	/* initialize the socket */
	bfd.when = BSC_FD_READ;
	bfd.cb = read_call_agent;
	bfd.fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (bfd.fd < 0) {
		perror("Gateway failed to listen");
		return -1;
	}

	setsockopt(bfd.fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));

	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(source_port);
	inet_aton(source_addr, &addr.sin_addr);

	if (bind(bfd.fd, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
		perror("Gateway failed to bind");
		return -1;
	}

	bfd.data = msgb_alloc(4096, "mgcp-msg");
	if (!bfd.data) {
		fprintf(stderr, "Gateway memory error.\n");
		return -1;
	}


	if (bsc_register_fd(&bfd) != 0) {
		DEBUGP(DMGCP, "Failed to register the fd\n");
		return -1;
	}

	/* initialisation */
	srand(time(NULL));

	/* early bind */
	if (early_bind) {
		for (i = 1; i < number_endpoints; ++i) {
			struct mgcp_endpoint *endp = &endpoints[i];
			endp->rtp_port = rtp_calculate_port(ENDPOINT_NUMBER(endp), rtp_base_port);
			if (bind_rtp(endp) != 0)
				return -1;
		}
	}

	/* main loop */
	while (1) {
		bsc_select_main(0);
	}


	return 0;
}
