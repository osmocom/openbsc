/* A Media Gateway Control Protocol Media Gateway: RFC 3435 */
/* The protocol implementation */

/*
 * (C) 2009-2012 by Holger Hans Peter Freyther <zecke@selfish.org>
 * (C) 2009-2012 by On-Waves
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
#include <time.h>
#include <limits.h>
#include <unistd.h>
#include <errno.h>

#include <osmocom/core/msgb.h>
#include <osmocom/core/talloc.h>
#include <osmocom/core/select.h>

#include <openbsc/mgcp.h>
#include <openbsc/mgcp_internal.h>

#define for_each_non_empty_line(line, save)			\
	for (line = strtok_r(NULL, "\r\n", &save); line;\
	     line = strtok_r(NULL, "\r\n", &save))


static void mgcp_rtp_end_reset(struct mgcp_rtp_end *end);

struct mgcp_request {
	char *name;
	struct msgb *(*handle_request) (struct mgcp_parse_data *data);
	char *debug_name;
};

#define MGCP_REQUEST(NAME, REQ, DEBUG_NAME) \
	{ .name = NAME, .handle_request = REQ, .debug_name = DEBUG_NAME },

static struct msgb *handle_audit_endpoint(struct mgcp_parse_data *data);
static struct msgb *handle_create_con(struct mgcp_parse_data *data);
static struct msgb *handle_delete_con(struct mgcp_parse_data *data);
static struct msgb *handle_modify_con(struct mgcp_parse_data *data);
static struct msgb *handle_rsip(struct mgcp_parse_data *data);
static struct msgb *handle_noti_req(struct mgcp_parse_data *data);

static void create_transcoder(struct mgcp_endpoint *endp);
static void delete_transcoder(struct mgcp_endpoint *endp);

static int setup_rtp_processing(struct mgcp_endpoint *endp);

static int mgcp_analyze_header(struct mgcp_parse_data *parse, char *data);

static int mgcp_check_param(const struct mgcp_endpoint *endp, const char *line)
{
	const size_t line_len = strlen(line);
	if (line[0] != '\0' && line_len < 2) {
		LOGP(DMGCP, LOGL_ERROR,
			"Wrong MGCP option format: '%s' on 0x%x\n",
			line, ENDPOINT_NUMBER(endp));
		return 0;
	}

	return 1;
}

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

static struct msgb *do_retransmission(const struct mgcp_endpoint *endp)
{
	struct msgb *msg = mgcp_msgb_alloc();
	if (!msg)
		return NULL;

	msg->l2h = msgb_put(msg, strlen(endp->last_response));
	memcpy(msg->l2h, endp->last_response, msgb_l2len(msg));
	return msg;
}

static struct msgb *create_resp(struct mgcp_endpoint *endp, int code,
				const char *txt, const char *msg,
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
	LOGP(DMGCP, LOGL_DEBUG, "Generated response: code: %d for '%s'\n", code, res->l2h);

	/*
	 * Remember the last transmission per endpoint.
	 */
	if (endp) {
		struct mgcp_trunk_config *tcfg = endp->tcfg;
		talloc_free(endp->last_response);
		talloc_free(endp->last_trans);
		endp->last_trans = talloc_strdup(tcfg->endpoints, trans);
		endp->last_response = talloc_strndup(tcfg->endpoints,
						(const char *) res->l2h,
						msgb_l2len(res));
	}

	return res;
}

static struct msgb *create_ok_resp_with_param(struct mgcp_endpoint *endp,
					int code, const char *msg,
					const char *trans, const char *param)
{
	return create_resp(endp, code, " OK", msg, trans, param, NULL);
}

static struct msgb *create_ok_response(struct mgcp_endpoint *endp,
					int code, const char *msg, const char *trans)
{
	return create_ok_resp_with_param(endp, code, msg, trans, NULL);
}

static struct msgb *create_err_response(struct mgcp_endpoint *endp,
					int code, const char *msg, const char *trans)
{
	return create_resp(endp, code, " FAIL", msg, trans, NULL, NULL);
}

static int write_response_sdp(struct mgcp_endpoint *endp,
			      char *sdp_record, size_t size, const char *addr)
{
	const char *fmtp_extra;
	const char *audio_name;
	int payload_type;
	int len;
	int nchars;

	endp->cfg->get_net_downlink_format_cb(endp, &payload_type,
					      &audio_name, &fmtp_extra);

	len = snprintf(sdp_record, size,
			"v=0\r\n"
			"o=- %u 23 IN IP4 %s\r\n"
			"s=-\r\n"
			"c=IN IP4 %s\r\n"
			"t=0 0\r\n",
			endp->ci, addr, addr);

	if (len < 0 || len >= size)
		goto buffer_too_small;

	if (payload_type >= 0) {
		nchars = snprintf(sdp_record + len, size - len,
				  "m=audio %d RTP/AVP %d\r\n",
				  endp->net_end.local_port, payload_type);
		if (nchars < 0 || nchars >= size - len)
			goto buffer_too_small;

		len += nchars;

		if (audio_name && endp->tcfg->audio_send_name) {
			nchars = snprintf(sdp_record + len, size - len,
					  "a=rtpmap:%d %s\r\n",
					  payload_type, audio_name);

			if (nchars < 0 || nchars >= size - len)
				goto buffer_too_small;

			len += nchars;
		}

		if (fmtp_extra) {
			nchars = snprintf(sdp_record + len, size - len,
					  "%s\r\n", fmtp_extra);

			if (nchars < 0 || nchars >= size - len)
				goto buffer_too_small;

			len += nchars;
		}
	}
	if (endp->bts_end.packet_duration_ms > 0 && endp->tcfg->audio_send_ptime) {
		nchars = snprintf(sdp_record + len, size - len,
				  "a=ptime:%d\r\n",
				  endp->bts_end.packet_duration_ms);
		if (nchars < 0 || nchars >= size - len)
			goto buffer_too_small;

		len += nchars;
	}

	return len;

buffer_too_small:
	LOGP(DMGCP, LOGL_ERROR, "SDP buffer too small: %zu (needed %d)\n",
	     size, len);
	return -1;
}

static struct msgb *create_response_with_sdp(struct mgcp_endpoint *endp,
					     const char *msg, const char *trans_id)
{
	const char *addr = endp->cfg->local_ip;
	char sdp_record[4096];
	int len;
	int nchars;
	char osmux_extension[strlen("\nX-Osmux: 255") + 1];

	if (!addr)
		addr = mgcp_net_src_addr(endp);

	if (endp->osmux.state == OSMUX_STATE_NEGOTIATING)
		sprintf(osmux_extension, "\nX-Osmux: %u", endp->osmux.cid);
	else
		osmux_extension[0] = '\0';

	len = snprintf(sdp_record, sizeof(sdp_record),
		       "I: %u%s\n\n", endp->ci, osmux_extension);
	if (len < 0)
		return NULL;

	nchars = write_response_sdp(endp, sdp_record + len,
				    sizeof(sdp_record) - len - 1, addr);
	if (nchars < 0)
		return NULL;

	len += nchars;

	sdp_record[sizeof(sdp_record) - 1] = '\0';

	return create_resp(endp, 200, " OK", msg, trans_id, NULL, sdp_record);
}

static void send_dummy(struct mgcp_endpoint *endp)
{
	if (endp->osmux.state != OSMUX_STATE_DISABLED)
		osmux_send_dummy(endp);
	else
		mgcp_send_dummy(endp);
}

/*
 * handle incoming messages:
 *   - this can be a command (four letters, space, transaction id)
 *   - or a response (three numbers, space, transaction id)
 */
struct msgb *mgcp_handle_message(struct mgcp_config *cfg, struct msgb *msg)
{
	struct mgcp_parse_data pdata;
	int i, code, handled = 0;
	struct msgb *resp = NULL;
	char *data;

	if (msgb_l2len(msg) < 4) {
		LOGP(DMGCP, LOGL_ERROR, "msg too short: %d\n", msg->len);
		return NULL;
	}

	if (mgcp_msg_terminate_nul(msg))
		return NULL;

        /* attempt to treat it as a response */
        if (sscanf((const char *)&msg->l2h[0], "%3d %*s", &code) == 1) {
		LOGP(DMGCP, LOGL_DEBUG, "Response: Code: %d\n", code);
		return NULL;
	}

	msg->l3h = &msg->l2h[4];


	/*
	 * Check for a duplicate message and respond.
	 */
	memset(&pdata, 0, sizeof(pdata));
	pdata.cfg = cfg;
	data = strline_r((char *) msg->l3h, &pdata.save);
	pdata.found = mgcp_analyze_header(&pdata, data);
	if (pdata.endp && pdata.trans
			&& pdata.endp->last_trans
			&& strcmp(pdata.endp->last_trans, pdata.trans) == 0) {
		return do_retransmission(pdata.endp);
	}

	for (i = 0; i < ARRAY_SIZE(mgcp_requests); ++i) {
		if (strncmp(mgcp_requests[i].name, (const char *) &msg->l2h[0], 4) == 0) {
			handled = 1;
			resp = mgcp_requests[i].handle_request(&pdata);
			break;
		}
	}

	if (!handled)
		LOGP(DMGCP, LOGL_NOTICE, "MSG with type: '%.4s' not handled\n", &msg->l2h[0]);

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

	if (strncmp(mgcp, "ds/e1", 5) == 0)
		return find_e1_endpoint(cfg, mgcp);

	gw = strtoul(mgcp, &endptr, 16);
	if (gw > 0 && gw < cfg->trunk.number_endpoints && endptr[0] == '@')
		return &cfg->trunk.endpoints[gw];

	LOGP(DMGCP, LOGL_ERROR, "Not able to find the endpoint: '%s'\n", mgcp);
	return NULL;
}

/**
 * @returns 0 when the status line was complete and transaction_id and
 * endp out parameters are set.
 */
static int mgcp_analyze_header(struct mgcp_parse_data *pdata, char *data)
{
	int i = 0;
	char *elem, *save = NULL;

	OSMO_ASSERT(data);
	pdata->trans = "000000";

	for (elem = strtok_r(data, " ", &save); elem;
	     elem = strtok_r(NULL, " ", &save)) {
		switch (i) {
		case 0:
			pdata->trans = elem;
			break;
		case 1:
			pdata->endp = find_endpoint(pdata->cfg, elem);
			if (!pdata->endp) {
				LOGP(DMGCP, LOGL_ERROR,
				     "Unable to find Endpoint `%s'\n", elem);
				return -1;
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
		pdata->trans = "000000";
		pdata->endp = NULL;
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

static struct msgb *handle_audit_endpoint(struct mgcp_parse_data *p)
{
	if (p->found != 0)
		return create_err_response(NULL, 500, "AUEP", p->trans);
	else
		return create_ok_response(p->endp, 200, "AUEP", p->trans);
}

static int parse_conn_mode(const char *msg, struct mgcp_endpoint *endp)
{
	int ret = 0;
	if (strcmp(msg, "recvonly") == 0)
		endp->conn_mode = MGCP_CONN_RECV_ONLY;
	else if (strcmp(msg, "sendrecv") == 0)
		endp->conn_mode = MGCP_CONN_RECV_SEND;
	else if (strcmp(msg, "sendonly") == 0)
		endp->conn_mode = MGCP_CONN_SEND_ONLY;
	else if (strcmp(msg, "loopback") == 0)
		endp->conn_mode = MGCP_CONN_LOOPBACK;
	else {
		LOGP(DMGCP, LOGL_ERROR, "Unknown connection mode: '%s'\n", msg);
		ret = -1;
	}

	endp->net_end.output_enabled =
		endp->conn_mode & MGCP_CONN_SEND_ONLY ? 1 : 0;
	endp->bts_end.output_enabled =
		endp->conn_mode & MGCP_CONN_RECV_ONLY ? 1 : 0;

	LOGP(DMGCP, LOGL_DEBUG, "endpoint %x connection mode '%s' %d output_enabled net %d bts %d\n",
	     ENDPOINT_NUMBER(endp),
	     msg, endp->conn_mode, endp->net_end.output_enabled,
	     endp->bts_end.output_enabled);

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
		endp->type = MGCP_RTP_TRANSCODED;
	}

	return 0;
}

/* Set the LCO from a string (see RFC 3435).
 * The string is stored in the 'string' field. A NULL string is handled excatly
 * like an empty string, the 'string' field is never NULL after this function
 * has been called. */
static void set_local_cx_options(void *ctx, struct mgcp_lco *lco,
				 const char *options)
{
	char *p_opt, *a_opt;
	char codec[9];

	talloc_free(lco->string);
	talloc_free(lco->codec);
	lco->codec = NULL;
	lco->pkt_period_min = lco->pkt_period_max = 0;
	lco->string = talloc_strdup(ctx, options ? options : "");

	p_opt = strstr(lco->string, "p:");
	if (p_opt && sscanf(p_opt, "p:%d-%d",
			    &lco->pkt_period_min, &lco->pkt_period_max) == 1)
		lco->pkt_period_max = lco->pkt_period_min;

	a_opt = strstr(lco->string, "a:");
	if (a_opt && sscanf(a_opt, "a:%8[^,]", codec) == 1)
		lco->codec = talloc_strdup(ctx, codec);
}

void mgcp_rtp_end_config(struct mgcp_endpoint *endp, int expect_ssrc_change,
			 struct mgcp_rtp_end *rtp)
{
	struct mgcp_trunk_config *tcfg = endp->tcfg;

	int patch_ssrc = expect_ssrc_change && tcfg->force_constant_ssrc;

	rtp->force_aligned_timing = tcfg->force_aligned_timing;
	rtp->force_constant_ssrc = patch_ssrc ? 1 : 0;

	LOGP(DMGCP, LOGL_DEBUG,
	     "Configuring RTP endpoint: local port %d%s%s\n",
	     ntohs(rtp->rtp_port),
	     rtp->force_aligned_timing ? ", force constant timing" : "",
	     rtp->force_constant_ssrc ? ", force constant ssrc" : "");
}

uint32_t mgcp_rtp_packet_duration(struct mgcp_endpoint *endp,
				  struct mgcp_rtp_end *rtp)
{
	int f = 0;

	/* Get the number of frames per channel and packet */
	if (rtp->frames_per_packet)
		f = rtp->frames_per_packet;
	else if (rtp->packet_duration_ms && rtp->codec.frame_duration_num) {
		int den = 1000 * rtp->codec.frame_duration_num;
		f = (rtp->packet_duration_ms * rtp->codec.frame_duration_den + den/2)
			/ den;
	}

	return rtp->codec.rate * f * rtp->codec.frame_duration_num / rtp->codec.frame_duration_den;
}

static int mgcp_parse_osmux_cid(const char *line)
{
	int osmux_cid;

	if (sscanf(line + 2, "Osmux: %u", &osmux_cid) != 1)
		return -1;

	if (osmux_cid > OSMUX_CID_MAX) {
		LOGP(DMGCP, LOGL_ERROR, "Osmux ID too large: %u > %u\n",
		     osmux_cid, OSMUX_CID_MAX);
		return -1;
	}
	LOGP(DMGCP, LOGL_DEBUG, "bsc-nat offered Osmux CID %u\n", osmux_cid);

	return osmux_cid;
}

static int mgcp_osmux_setup(struct mgcp_endpoint *endp, const char *line)
{
	if (!endp->cfg->osmux_init) {
		if (osmux_init(OSMUX_ROLE_BSC, endp->cfg) < 0) {
			LOGP(DMGCP, LOGL_ERROR, "Cannot init OSMUX\n");
			return -1;
		}
		LOGP(DMGCP, LOGL_NOTICE, "OSMUX socket has been set up\n");
	}

	return mgcp_parse_osmux_cid(line);
}

static struct msgb *handle_create_con(struct mgcp_parse_data *p)
{
	struct mgcp_trunk_config *tcfg;
	struct mgcp_endpoint *endp = p->endp;
	int error_code = 400;

	const char *local_options = NULL;
	const char *callid = NULL;
	const char *mode = NULL;
	char *line;
	int have_sdp = 0, osmux_cid = -1;

	if (p->found != 0)
		return create_err_response(NULL, 510, "CRCX", p->trans);

	/* parse CallID C: and LocalParameters L: */
	for_each_line(line, p->save) {
		if (!mgcp_check_param(endp, line))
			continue;

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
		case 'X':
			/* Osmux is not enabled in this bsc, ignore it so the
			 * bsc-nat knows that we don't want to use Osmux.
			 */
			if (!p->endp->cfg->osmux)
				break;

			if (strncmp("Osmux: ", line + 2, strlen("Osmux: ")) == 0)
				osmux_cid = mgcp_osmux_setup(endp, line);
			break;
		case '\0':
			have_sdp = 1;
			goto mgcp_header_done;
		default:
			LOGP(DMGCP, LOGL_NOTICE, "Unhandled option: '%c'/%d on 0x%x\n",
				*line, *line, ENDPOINT_NUMBER(endp));
			break;
		}
	}

mgcp_header_done:
	tcfg = p->endp->tcfg;

	/* Check required data */
	if (!callid || !mode) {
		LOGP(DMGCP, LOGL_ERROR, "Missing callid and mode in CRCX on 0x%x\n",
		     ENDPOINT_NUMBER(endp));
		return create_err_response(endp, 400, "CRCX", p->trans);
	}

	if (endp->allocated) {
		if (tcfg->force_realloc) {
			LOGP(DMGCP, LOGL_NOTICE, "Endpoint 0x%x already allocated. Forcing realloc.\n",
			    ENDPOINT_NUMBER(endp));
			mgcp_release_endp(endp);
			if (p->cfg->realloc_cb)
				p->cfg->realloc_cb(tcfg, ENDPOINT_NUMBER(endp));
		} else {
			LOGP(DMGCP, LOGL_ERROR, "Endpoint is already used. 0x%x\n",
			     ENDPOINT_NUMBER(endp));
			return create_err_response(endp, 400, "CRCX", p->trans);
		}
	}

	/* copy some parameters */
	endp->callid = talloc_strdup(tcfg->endpoints, callid);

	set_local_cx_options(endp->tcfg->endpoints, &endp->local_options,
			     local_options);

	if (parse_conn_mode(mode, endp) != 0) {
		    error_code = 517;
		    goto error2;
	}

	/* initialize */
	endp->net_end.rtp_port = endp->net_end.rtcp_port = endp->bts_end.rtp_port = endp->bts_end.rtcp_port = 0;
	mgcp_rtp_end_config(endp, 0, &endp->net_end);
	mgcp_rtp_end_config(endp, 0, &endp->bts_end);

	/* set to zero until we get the info */
	memset(&endp->net_end.addr, 0, sizeof(endp->net_end.addr));

	/* bind to the port now */
	if (allocate_ports(endp) != 0)
		goto error2;

	/* assign a local call identifier or fail */
	endp->ci = generate_call_id(p->cfg);
	if (endp->ci == CI_UNUSED)
		goto error2;

	/* Annotate Osmux circuit ID and set it to negotiating state until this
	 * is fully set up from the dummy load.
	 */
	endp->osmux.state = OSMUX_STATE_DISABLED;
	if (osmux_cid >= 0) {
		endp->osmux.cid = osmux_cid;
		endp->osmux.state = OSMUX_STATE_NEGOTIATING;
	} else if (endp->cfg->osmux == OSMUX_USAGE_ONLY) {
		LOGP(DMGCP, LOGL_ERROR,
			"Osmux only and no osmux offered on 0x%x\n", ENDPOINT_NUMBER(endp));
		goto error2;
	}

	endp->allocated = 1;

	/* set up RTP media parameters */
	mgcp_set_audio_info(p->cfg, &endp->bts_end.codec, tcfg->audio_payload, tcfg->audio_name);
	endp->bts_end.fmtp_extra = talloc_strdup(tcfg->endpoints,
						tcfg->audio_fmtp_extra);
	if (have_sdp)
		mgcp_parse_sdp_data(endp, &endp->net_end, p);
	else if (endp->local_options.codec)
		mgcp_set_audio_info(p->cfg, &endp->net_end.codec,
			       PTYPE_UNDEFINED, endp->local_options.codec);

	if (p->cfg->bts_force_ptime) {
		endp->bts_end.packet_duration_ms = p->cfg->bts_force_ptime;
		endp->bts_end.force_output_ptime = 1;
	}

	if (setup_rtp_processing(endp) != 0)
		goto error2;

	/* policy CB */
	if (p->cfg->policy_cb) {
		int rc;
		rc = p->cfg->policy_cb(tcfg, ENDPOINT_NUMBER(endp),
				MGCP_ENDP_CRCX, p->trans);
		switch (rc) {
		case MGCP_POLICY_REJECT:
			LOGP(DMGCP, LOGL_NOTICE, "CRCX rejected by policy on 0x%x\n",
			     ENDPOINT_NUMBER(endp));
			mgcp_release_endp(endp);
			return create_err_response(endp, 400, "CRCX", p->trans);
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
	if (p->cfg->change_cb)
		p->cfg->change_cb(tcfg, ENDPOINT_NUMBER(endp), MGCP_ENDP_CRCX);

	if (endp->conn_mode & MGCP_CONN_RECV_ONLY && tcfg->keepalive_interval != 0) {
		send_dummy(endp);
	}

	create_transcoder(endp);
	return create_response_with_sdp(endp, "CRCX", p->trans);
error2:
	mgcp_release_endp(endp);
	LOGP(DMGCP, LOGL_NOTICE, "Resource error on 0x%x\n", ENDPOINT_NUMBER(endp));
	return create_err_response(endp, error_code, "CRCX", p->trans);
}

static struct msgb *handle_modify_con(struct mgcp_parse_data *p)
{
	struct mgcp_endpoint *endp = p->endp;
	int error_code = 500;
	int silent = 0;
	int have_sdp = 0;
	char *line;
	const char *local_options = NULL;

	if (p->found != 0)
		return create_err_response(NULL, 510, "MDCX", p->trans);

	if (endp->ci == CI_UNUSED) {
		LOGP(DMGCP, LOGL_ERROR, "Endpoint is not "
			"holding a connection. 0x%x\n", ENDPOINT_NUMBER(endp));
		return create_err_response(endp, 400, "MDCX", p->trans);
	}

	for_each_line(line, p->save) {
		if (!mgcp_check_param(endp, line))
			continue;

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
			local_options = (const char *) line + 3;
			break;
		case 'M':
			if (parse_conn_mode(line + 3, endp) != 0) {
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
			have_sdp = 1;
			mgcp_parse_sdp_data(endp, &endp->net_end, p);
			/* This will exhaust p->save, so the loop will
			 * terminate next time.
			 */
			break;
		default:
			LOGP(DMGCP, LOGL_NOTICE, "Unhandled MGCP option: '%c'/%d on 0x%x\n",
				line[0], line[0], ENDPOINT_NUMBER(endp));
			break;
		}
	}

	set_local_cx_options(endp->tcfg->endpoints, &endp->local_options,
			     local_options);

	if (!have_sdp && endp->local_options.codec)
		mgcp_set_audio_info(p->cfg, &endp->net_end.codec,
			       PTYPE_UNDEFINED, endp->local_options.codec);

	if (setup_rtp_processing(endp) != 0)
		goto error3;

	/* policy CB */
	if (p->cfg->policy_cb) {
		int rc;
		rc = p->cfg->policy_cb(endp->tcfg, ENDPOINT_NUMBER(endp),
						MGCP_ENDP_MDCX, p->trans);
		switch (rc) {
		case MGCP_POLICY_REJECT:
			LOGP(DMGCP, LOGL_NOTICE, "MDCX rejected by policy on 0x%x\n",
			     ENDPOINT_NUMBER(endp));
			if (silent)
				goto out_silent;
			return create_err_response(endp, 400, "MDCX", p->trans);
			break;
		case MGCP_POLICY_DEFER:
			/* stop processing */
			LOGP(DMGCP, LOGL_DEBUG, "endp %x MDCX defer\n",
			     ENDPOINT_NUMBER(endp));
			return NULL;
			break;
		case MGCP_POLICY_CONT:
			/* just continue */
			break;
		}
	}

	mgcp_rtp_end_config(endp, 1, &endp->net_end);
	mgcp_rtp_end_config(endp, 1, &endp->bts_end);

	/* modify */
	LOGP(DMGCP, LOGL_DEBUG, "Modified endpoint on: 0x%x Server: %s:%u\n",
		ENDPOINT_NUMBER(endp), inet_ntoa(endp->net_end.addr), ntohs(endp->net_end.rtp_port));
	if (p->cfg->change_cb)
		p->cfg->change_cb(endp->tcfg, ENDPOINT_NUMBER(endp), MGCP_ENDP_MDCX);

	if (endp->conn_mode & MGCP_CONN_RECV_ONLY &&
	    endp->tcfg->keepalive_interval != 0)
		send_dummy(endp);

	if (silent)
		goto out_silent;

	return create_response_with_sdp(endp, "MDCX", p->trans);

error3:
	return create_err_response(endp, error_code, "MDCX", p->trans);


out_silent:
	LOGP(DMGCP, LOGL_DEBUG, "endp %x Modify endpoint: silent exit\n",
	     ENDPOINT_NUMBER(endp));
	return NULL;
}

static struct msgb *handle_delete_con(struct mgcp_parse_data *p)
{
	struct mgcp_endpoint *endp = p->endp;
	int error_code = 400;
	int silent = 0;
	char *line;
	char stats[1048];

	if (p->found != 0)
		return create_err_response(NULL, error_code, "DLCX", p->trans);

	if (!p->endp->allocated) {
		LOGP(DMGCP, LOGL_ERROR, "Endpoint is not used. 0x%x\n",
			ENDPOINT_NUMBER(endp));
		return create_err_response(endp, 400, "DLCX", p->trans);
	}

	for_each_line(line, p->save) {
		if (!mgcp_check_param(endp, line))
			continue;

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
	if (p->cfg->policy_cb) {
		int rc;
		rc = p->cfg->policy_cb(endp->tcfg, ENDPOINT_NUMBER(endp),
						MGCP_ENDP_DLCX, p->trans);
		switch (rc) {
		case MGCP_POLICY_REJECT:
			LOGP(DMGCP, LOGL_NOTICE, "DLCX rejected by policy on 0x%x\n",
			     ENDPOINT_NUMBER(endp));
			if (silent)
				goto out_silent;
			return create_err_response(endp, 400, "DLCX", p->trans);
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
	mgcp_release_endp(endp);
	if (p->cfg->change_cb)
		p->cfg->change_cb(endp->tcfg, ENDPOINT_NUMBER(endp), MGCP_ENDP_DLCX);

	if (silent)
		goto out_silent;
	return create_ok_resp_with_param(endp, 250, "DLCX", p->trans, stats);

error3:
	return create_err_response(endp, error_code, "DLCX", p->trans);

out_silent:
	return NULL;
}

static struct msgb *handle_rsip(struct mgcp_parse_data *p)
{
	if (p->found != 0) {
		LOGP(DMGCP, LOGL_ERROR, "Failed to find the endpoint.\n");
		return NULL;
	}

	if (p->cfg->reset_cb)
		p->cfg->reset_cb(p->endp->tcfg);
	return NULL;
}

static char extract_tone(const char *line)
{
	const char *str = strstr(line, "D/");
	if (!str)
		return CHAR_MAX;

	return str[2];
}

/*
 * This can request like DTMF detection and forward, fax detection... it
 * can also request when the notification should be send and such. We don't
 * do this right now.
 */
static struct msgb *handle_noti_req(struct mgcp_parse_data *p)
{
	int res = 0;
	char *line;
	char tone = CHAR_MAX;

	if (p->found != 0)
		return create_err_response(NULL, 400, "RQNT", p->trans);

	for_each_line(line, p->save) {
		switch (line[0]) {
		case 'S':
			tone = extract_tone(line);
			break;
		}
	}

	/* we didn't see a signal request with a tone */
	if (tone == CHAR_MAX)
		return create_ok_response(p->endp, 200, "RQNT", p->trans);

	if (p->cfg->rqnt_cb)
		res = p->cfg->rqnt_cb(p->endp, tone);

	return res == 0 ?
		create_ok_response(p->endp, 200, "RQNT", p->trans) :
		create_err_response(p->endp, res, "RQNT", p->trans);
}

static void mgcp_keepalive_timer_cb(void *_tcfg)
{
	struct mgcp_trunk_config *tcfg = _tcfg;
	int i;
	LOGP(DMGCP, LOGL_DEBUG, "Triggered trunk %d keepalive timer.\n",
	     tcfg->trunk_nr);

	if (tcfg->keepalive_interval <= 0)
		return;

	for (i = 1; i < tcfg->number_endpoints; ++i) {
		struct mgcp_endpoint *endp = &tcfg->endpoints[i];
		if (endp->conn_mode == MGCP_CONN_RECV_ONLY)
			send_dummy(endp);
	}

	LOGP(DMGCP, LOGL_DEBUG, "Rescheduling trunk %d keepalive timer.\n",
	     tcfg->trunk_nr);
	osmo_timer_schedule(&tcfg->keepalive_timer, tcfg->keepalive_interval, 0);
}

void mgcp_trunk_set_keepalive(struct mgcp_trunk_config *tcfg, int interval)
{
	tcfg->keepalive_interval = interval;
	osmo_timer_setup(&tcfg->keepalive_timer, mgcp_keepalive_timer_cb, tcfg);

	if (interval <= 0)
		osmo_timer_del(&tcfg->keepalive_timer);
	else
		osmo_timer_schedule(&tcfg->keepalive_timer,
				    tcfg->keepalive_interval, 0);
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
	cfg->osmux_addr = talloc_strdup(cfg, "0.0.0.0");

	cfg->transcoder_remote_base = 4000;

	cfg->bts_ports.base_port = RTP_PORT_DEFAULT;
	cfg->net_ports.base_port = RTP_PORT_NET_DEFAULT;

	cfg->rtp_processing_cb = &mgcp_rtp_processing_default;
	cfg->setup_rtp_processing_cb = &mgcp_setup_rtp_processing_default;

	cfg->get_net_downlink_format_cb = &mgcp_get_net_downlink_format_default;

	/* default trunk handling */
	cfg->trunk.cfg = cfg;
	cfg->trunk.trunk_nr = 0;
	cfg->trunk.trunk_type = MGCP_TRUNK_VIRTUAL;
	cfg->trunk.audio_name = talloc_strdup(cfg, "AMR/8000");
	cfg->trunk.audio_payload = 126;
	cfg->trunk.audio_send_ptime = 1;
	cfg->trunk.audio_send_name = 1;
	cfg->trunk.omit_rtcp = 0;
	mgcp_trunk_set_keepalive(&cfg->trunk, MGCP_KEEPALIVE_ONCE);

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
	trunk->audio_send_ptime = 1;
	trunk->audio_send_name = 1;
	trunk->number_endpoints = 33;
	trunk->omit_rtcp = 0;
	mgcp_trunk_set_keepalive(trunk, MGCP_KEEPALIVE_ONCE);
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

static void mgcp_rtp_codec_reset(struct mgcp_rtp_codec *codec)
{
	codec->payload_type = -1;
	talloc_free(codec->subtype_name);
	codec->subtype_name = NULL;
	talloc_free(codec->audio_name);
	codec->audio_name = NULL;
	codec->frame_duration_num = DEFAULT_RTP_AUDIO_FRAME_DUR_NUM;
	codec->frame_duration_den = DEFAULT_RTP_AUDIO_FRAME_DUR_DEN;
	codec->rate               = DEFAULT_RTP_AUDIO_DEFAULT_RATE;
	codec->channels           = DEFAULT_RTP_AUDIO_DEFAULT_CHANNELS;
}

static void mgcp_rtp_end_reset(struct mgcp_rtp_end *end)
{
	if (end->local_alloc == PORT_ALLOC_DYNAMIC) {
		mgcp_free_rtp_port(end);
		end->local_port = 0;
	}

	end->packets = 0;
	end->octets = 0;
	end->dropped_packets = 0;
	memset(&end->addr, 0, sizeof(end->addr));
	end->rtp_port = end->rtcp_port = 0;
	end->local_alloc = -1;
	talloc_free(end->fmtp_extra);
	end->fmtp_extra = NULL;
	talloc_free(end->rtp_process_data);
	end->rtp_process_data = NULL;

	/* Set default values */
	end->frames_per_packet  = 0; /* unknown */
	end->packet_duration_ms = DEFAULT_RTP_AUDIO_PACKET_DURATION_MS;
	end->output_enabled	= 0;

	mgcp_rtp_codec_reset(&end->codec);
	mgcp_rtp_codec_reset(&end->alt_codec);
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
		tcfg->endpoints[i].osmux.allocated_cid = -1;
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

void mgcp_release_endp(struct mgcp_endpoint *endp)
{
	LOGP(DMGCP, LOGL_DEBUG, "Releasing endpoint on: 0x%x\n", ENDPOINT_NUMBER(endp));
	endp->ci = CI_UNUSED;
	endp->allocated = 0;

	talloc_free(endp->callid);
	endp->callid = NULL;

	talloc_free(endp->local_options.string);
	endp->local_options.string = NULL;
	talloc_free(endp->local_options.codec);
	endp->local_options.codec = NULL;

	mgcp_rtp_end_reset(&endp->bts_end);
	mgcp_rtp_end_reset(&endp->net_end);
	mgcp_rtp_end_reset(&endp->trans_net);
	mgcp_rtp_end_reset(&endp->trans_bts);
	endp->type = MGCP_RTP_DEFAULT;

	memset(&endp->net_state, 0, sizeof(endp->net_state));
	memset(&endp->bts_state, 0, sizeof(endp->bts_state));

	endp->conn_mode = endp->orig_mode = MGCP_CONN_NONE;

	if (endp->osmux.state == OSMUX_STATE_ENABLED)
		osmux_disable_endpoint(endp);

	/* release the circuit ID if it had been allocated */
	osmux_release_cid(endp);

	memset(&endp->taps, 0, sizeof(endp->taps));
}

void mgcp_initialize_endp(struct mgcp_endpoint *endp)
{
	return mgcp_release_endp(endp);
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
	int nchars;

	/* hardcoded to AMR right now, we do not know the real type at this point */
	len = snprintf(buf, sizeof(buf),
			"%s 42 %x@mgw MGCP 1.0\r\n"
			"C: 4256\r\n"
			"M: %s\r\n"
			"\r\n",
			msg, endpoint, mode);

	if (len < 0)
		return;

	nchars = write_response_sdp(endp, buf + len, sizeof(buf) + len - 1, NULL);
	if (nchars < 0)
		return;

	len += nchars;

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

static int setup_rtp_processing(struct mgcp_endpoint *endp)
{
	int rc = 0;
	struct mgcp_config *cfg = endp->cfg;

	if (endp->type != MGCP_RTP_DEFAULT)
		return 0;

	if (endp->conn_mode == MGCP_CONN_LOOPBACK)
		return 0;

	if (endp->conn_mode & MGCP_CONN_SEND_ONLY)
		rc |= cfg->setup_rtp_processing_cb(endp, &endp->net_end, &endp->bts_end);
	else
		rc |= cfg->setup_rtp_processing_cb(endp, &endp->net_end, NULL);

	if (endp->conn_mode & MGCP_CONN_RECV_ONLY)
		rc |= cfg->setup_rtp_processing_cb(endp, &endp->bts_end, &endp->net_end);
	else
		rc |= cfg->setup_rtp_processing_cb(endp, &endp->bts_end, NULL);
	return rc;
}

static void create_transcoder(struct mgcp_endpoint *endp)
{
	int port;
	int in_endp = ENDPOINT_NUMBER(endp);
	int out_endp = endp_back_channel(in_endp);

	if (endp->type != MGCP_RTP_TRANSCODED)
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

	if (endp->type != MGCP_RTP_TRANSCODED)
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
	int nchars;
	mgcp_state_calc_loss(&endp->net_state, &endp->net_end,
				&expected, &ploss);
	jitter = mgcp_state_calc_jitter(&endp->net_state);

	nchars = snprintf(msg, size,
			  "\r\nP: PS=%u, OS=%u, PR=%u, OR=%u, PL=%d, JI=%u",
			  endp->bts_end.packets, endp->bts_end.octets,
			  endp->net_end.packets, endp->net_end.octets,
			  ploss, jitter);
	if (nchars < 0 || nchars >= size)
		goto truncate;

	msg += nchars;
	size -= nchars;

	/* Error Counter */
	nchars = snprintf(msg, size,
			  "\r\nX-Osmo-CP: EC TIS=%u, TOS=%u, TIR=%u, TOR=%u",
			  endp->net_state.in_stream.err_ts_counter,
			  endp->net_state.out_stream.err_ts_counter,
			  endp->bts_state.in_stream.err_ts_counter,
			  endp->bts_state.out_stream.err_ts_counter);
	if (nchars < 0 || nchars >= size)
		goto truncate;

	msg += nchars;
	size -= nchars;

	if (endp->osmux.state == OSMUX_STATE_ENABLED) {
		snprintf(msg, size,
			 "\r\nX-Osmux-ST: CR=%u, BR=%u",
			 endp->osmux.stats.chunks,
			 endp->osmux.stats.octets);
	}
truncate:
	msg[size - 1] = '\0';
}

int mgcp_parse_stats(struct msgb *msg, uint32_t *ps, uint32_t *os,
		uint32_t *pr, uint32_t *_or, int *loss, uint32_t *jitter)
{
	char *line, *save;
	int rc;

	/* initialize with bad values */
	*ps = *os = *pr = *_or = *jitter = UINT_MAX;
	*loss = INT_MAX;


	line = strtok_r((char *) msg->l2h, "\r\n", &save);
	if (!line)
		return -1;

	/* this can only parse the message that is created above... */
	for_each_non_empty_line(line, save) {
		switch (line[0]) {
		case 'P':
			rc = sscanf(line, "P: PS=%u, OS=%u, PR=%u, OR=%u, PL=%d, JI=%u",
					ps, os, pr, _or, loss, jitter);
			return rc == 6 ? 0 : -1;
		}
	}

	return -1;
}
