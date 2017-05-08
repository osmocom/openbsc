/* BSC Multiplexer/NAT */

/*
 * (C) 2010-2013 by Holger Hans Peter Freyther <zecke@selfish.org>
 * (C) 2010-2013 by On-Waves
 * (C) 2009 by Harald Welte <laforge@gnumonks.org>
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
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#include <fcntl.h>
#include <libgen.h>

#define _GNU_SOURCE
#include <getopt.h>

#include <openbsc/debug.h>
#include <openbsc/bsc_msc.h>
#include <openbsc/bsc_nat.h>
#include <openbsc/bsc_nat_sccp.h>
#include <openbsc/bsc_msg_filter.h>
#include <openbsc/ipaccess.h>
#include <openbsc/abis_nm.h>
#include <openbsc/socket.h>
#include <openbsc/vty.h>

#include <osmocom/ctrl/control_cmd.h>
#include <osmocom/ctrl/control_if.h>
#include <osmocom/ctrl/ports.h>
#include <osmocom/ctrl/control_vty.h>

#include <osmocom/crypt/auth.h>

#include <osmocom/core/application.h>
#include <osmocom/core/talloc.h>
#include <osmocom/core/stats.h>

#include <osmocom/gsm/tlv.h>
#include <osmocom/gsm/gsm0808.h>
#include <osmocom/gsm/protocol/gsm_08_08.h>

#include <osmocom/vty/telnet_interface.h>
#include <osmocom/vty/vty.h>
#include <osmocom/vty/logging.h>
#include <osmocom/vty/stats.h>
#include <osmocom/vty/ports.h>

#include <osmocom/sccp/sccp.h>

#include <osmocom/abis/ipa.h>

#include <openssl/rand.h>

#include "../../bscconfig.h"

#define SCCP_CLOSE_TIME 20
#define SCCP_CLOSE_TIME_TIMEOUT 19

static const char *config_file = "bsc-nat.cfg";
static struct in_addr local_addr;
static struct osmo_fd bsc_listen;
static const char *msc_ip = NULL;
static struct osmo_timer_list sccp_close;
static int daemonize = 0;

const char *openbsc_copyright =
	"Copyright (C) 2010 Holger Hans Peter Freyther and On-Waves\r\n"
	"License AGPLv3+: GNU AGPL version 3 or later <http://gnu.org/licenses/agpl-3.0.html>\r\n"
	"This is free software: you are free to change and redistribute it.\r\n"
	"There is NO WARRANTY, to the extent permitted by law.\r\n";

static struct bsc_nat *nat;
static void bsc_send_data(struct bsc_connection *bsc, const uint8_t *data, unsigned int length, int);
static void msc_send_reset(struct bsc_msc_connection *con);
static void bsc_stat_reject(int filter, struct bsc_connection *bsc, int normal);

struct bsc_config *bsc_config_num(struct bsc_nat *nat, int num)
{
	struct bsc_config *conf;

	llist_for_each_entry(conf, &nat->bsc_configs, entry)
		if (conf->nr == num)
			return conf;

	return NULL;
}

static void queue_for_msc(struct bsc_msc_connection *con, struct msgb *msg)
{
	if (!con) {
		LOGP(DLINP, LOGL_ERROR, "No MSC Connection assigned. Check your code.\n");
		msgb_free(msg);
		return;
	}


	if (osmo_wqueue_enqueue(&con->write_queue, msg) != 0) {
		LOGP(DLINP, LOGL_ERROR, "Failed to enqueue the write.\n");
		msgb_free(msg);
	}
}

static void send_reset_ack(struct bsc_connection *bsc)
{
	static const uint8_t gsm_reset_ack[] = {
		0x09, 0x00, 0x03, 0x07, 0x0b, 0x04, 0x43, 0x01,
		0x00, 0xfe, 0x04, 0x43, 0x5c, 0x00, 0xfe, 0x03,
		0x00, 0x01, 0x31,
	};

	bsc_send_data(bsc, gsm_reset_ack, sizeof(gsm_reset_ack), IPAC_PROTO_SCCP);
}

static void send_ping(struct bsc_connection *bsc)
{
	static const uint8_t id_ping[] = {
		IPAC_MSGT_PING,
	};

	bsc_send_data(bsc, id_ping, sizeof(id_ping), IPAC_PROTO_IPACCESS);
}

static void send_pong(struct bsc_connection *bsc)
{
	static const uint8_t id_pong[] = {
		IPAC_MSGT_PONG,
	};

	bsc_send_data(bsc, id_pong, sizeof(id_pong), IPAC_PROTO_IPACCESS);
}

static void bsc_pong_timeout(void *_bsc)
{
	struct bsc_connection *bsc = _bsc;

	LOGP(DNAT, LOGL_ERROR, "BSC Nr: %d PONG timeout.\n", bsc->cfg->nr);
	bsc_close_connection(bsc);
}

static void bsc_ping_timeout(void *_bsc)
{
	struct bsc_connection *bsc = _bsc;

	if (bsc->nat->ping_timeout < 0)
		return;

	send_ping(bsc);

	/* send another ping in 20 seconds */
	osmo_timer_schedule(&bsc->ping_timeout, bsc->nat->ping_timeout, 0);

	/* also start a pong timer */
	osmo_timer_schedule(&bsc->pong_timeout, bsc->nat->pong_timeout, 0);
}

static void start_ping_pong(struct bsc_connection *bsc)
{
	osmo_timer_setup(&bsc->pong_timeout, bsc_pong_timeout, bsc);
	osmo_timer_setup(&bsc->ping_timeout, bsc_ping_timeout, bsc);

	bsc_ping_timeout(bsc);
}

static void send_id_ack(struct bsc_connection *bsc)
{
	static const uint8_t id_ack[] = {
		IPAC_MSGT_ID_ACK
	};

	bsc_send_data(bsc, id_ack, sizeof(id_ack), IPAC_PROTO_IPACCESS);
}

static void send_id_req(struct bsc_nat *nat, struct bsc_connection *bsc)
{
	static const uint8_t s_id_req[] = {
		IPAC_MSGT_ID_GET,
		0x01, IPAC_IDTAG_UNIT,
		0x01, IPAC_IDTAG_MACADDR,
		0x01, IPAC_IDTAG_LOCATION1,
		0x01, IPAC_IDTAG_LOCATION2,
		0x01, IPAC_IDTAG_EQUIPVERS,
		0x01, IPAC_IDTAG_SWVERSION,
		0x01, IPAC_IDTAG_UNITNAME,
		0x01, IPAC_IDTAG_SERNR,
	};

	uint8_t *mrand;
	uint8_t id_req[sizeof(s_id_req) + (2+16)];
	uint8_t *buf = &id_req[sizeof(s_id_req)];

	/* copy the static data */
	memcpy(id_req, s_id_req, sizeof(s_id_req));

	/* put the RAND with length, tag, value */
	buf = v_put(buf, 0x11);
	buf = v_put(buf, 0x23);
	mrand = bsc->last_rand;

	if (RAND_bytes(mrand, 16) != 1)
		goto failed_random;

	memcpy(buf, mrand, 16);
	buf += 16;

	bsc_send_data(bsc, id_req, sizeof(id_req), IPAC_PROTO_IPACCESS);
	return;

failed_random:
	/* the timeout will trigger and close this connection */
	LOGP(DNAT, LOGL_ERROR, "Failed to read from urandom.\n");
	return;
}

static struct msgb *nat_create_rlsd(struct nat_sccp_connection *conn)
{
	struct sccp_connection_released *rel;
	struct msgb *msg;

	msg = msgb_alloc_headroom(4096, 128, "rlsd");
	if (!msg) {
		LOGP(DNAT, LOGL_ERROR, "Failed to allocate released.\n");
		return NULL;
	}

	msg->l2h = msgb_put(msg, sizeof(*rel));
	rel = (struct sccp_connection_released *) msg->l2h;
	rel->type = SCCP_MSG_TYPE_RLSD;
	rel->release_cause = SCCP_RELEASE_CAUSE_SCCP_FAILURE;
	rel->destination_local_reference = conn->remote_ref;
	rel->source_local_reference = conn->patched_ref;

	return msg;
}

static void nat_send_rlsd_ussd(struct bsc_nat *nat, struct nat_sccp_connection *conn)
{
	struct msgb *msg;

	if (!nat->ussd_con)
		return;

	msg = nat_create_rlsd(conn);
	if (!msg)
		return;

	bsc_do_write(&nat->ussd_con->queue, msg, IPAC_PROTO_SCCP);
}

static void nat_send_rlsd_msc(struct nat_sccp_connection *conn)
{
	struct msgb *msg;

	msg = nat_create_rlsd(conn);
	if (!msg)
		return;

	ipa_prepend_header(msg, IPAC_PROTO_SCCP);
	queue_for_msc(conn->msc_con, msg);
}

static void nat_send_rlsd_bsc(struct nat_sccp_connection *conn)
{
	struct msgb *msg;
	struct sccp_connection_released *rel;

	msg = msgb_alloc_headroom(4096, 128, "rlsd");
	if (!msg) {
		LOGP(DNAT, LOGL_ERROR, "Failed to allocate clear command.\n");
		return;
	}

	msg->l2h = msgb_put(msg, sizeof(*rel));
	rel = (struct sccp_connection_released *) msg->l2h;
	rel->type = SCCP_MSG_TYPE_RLSD;
	rel->release_cause = SCCP_RELEASE_CAUSE_SCCP_FAILURE;
	rel->destination_local_reference = conn->real_ref;
	rel->source_local_reference = conn->remote_ref;

	bsc_write(conn->bsc, msg, IPAC_PROTO_SCCP);
}

static struct msgb *nat_creat_clrc(struct nat_sccp_connection *conn, uint8_t cause)
{
	struct msgb *msg;
	struct msgb *sccp;

	msg = gsm0808_create_clear_command(cause);
	if (!msg) {
		LOGP(DNAT, LOGL_ERROR, "Failed to allocate clear command.\n");
		return NULL;
	}

	sccp = sccp_create_dt1(&conn->real_ref, msg->data, msg->len);
	if (!sccp) {
		LOGP(DNAT, LOGL_ERROR, "Failed to allocate SCCP msg.\n");
		msgb_free(msg);
		return NULL;
	}

	msgb_free(msg);
	return sccp;
}

static int nat_send_clrc_bsc(struct nat_sccp_connection *conn)
{
	struct msgb *sccp;

	sccp = nat_creat_clrc(conn, 0x20);
	if (!sccp)
		return -1;
	return bsc_write(conn->bsc, sccp, IPAC_PROTO_SCCP);
}

static void nat_send_rlc(struct bsc_msc_connection *msc_con,
			 struct sccp_source_reference *src,
			 struct sccp_source_reference *dst)
{
	struct sccp_connection_release_complete *rlc;
	struct msgb *msg;

	msg = msgb_alloc_headroom(4096, 128, "rlc");
	if (!msg) {
		LOGP(DNAT, LOGL_ERROR, "Failed to sccp rlc.\n");
		return;
	}

	msg->l2h = msgb_put(msg, sizeof(*rlc));
	rlc = (struct sccp_connection_release_complete *) msg->l2h;
	rlc->type = SCCP_MSG_TYPE_RLC;
	rlc->destination_local_reference = *dst;
	rlc->source_local_reference = *src;

	ipa_prepend_header(msg, IPAC_PROTO_SCCP);

	queue_for_msc(msc_con, msg);
}

static void send_mgcp_reset(struct bsc_connection *bsc)
{
	static const uint8_t mgcp_reset[] = {
	    "RSIP 1 13@mgw MGCP 1.0\r\n"
	};

	bsc_write_mgcp(bsc, mgcp_reset, sizeof mgcp_reset - 1);
}

void bsc_nat_send_mgcp_to_msc(struct bsc_nat *nat, struct msgb *msg)
{
	ipa_prepend_header(msg, IPAC_PROTO_MGCP_OLD);
	queue_for_msc(nat->msc_con, msg);
}

/*
 * Below is the handling of messages coming
 * from the MSC and need to be forwarded to
 * a real BSC.
 */
static void initialize_msc_if_needed(struct bsc_msc_connection *msc_con)
{
	if (msc_con->first_contact)
		return;

	msc_con->first_contact = 1;
	msc_send_reset(msc_con);
}

static void send_id_get_response(struct bsc_msc_connection *msc_con)
{
	struct msgb *msg = bsc_msc_id_get_resp(0, nat->token, NULL, 0);
	if (!msg)
		return;

	ipa_prepend_header(msg, IPAC_PROTO_IPACCESS);
	queue_for_msc(msc_con, msg);
}

/*
 * Currently we are lacking refcounting so we need to copy each message.
 */
static void bsc_send_data(struct bsc_connection *bsc, const uint8_t *data, unsigned int length, int proto)
{
	struct msgb *msg;

	if (length > 4096 - 128) {
		LOGP(DLINP, LOGL_ERROR, "Can not send message of that size.\n");
		return;
	}

	msg = msgb_alloc_headroom(4096, 128, "to-bsc");
	if (!msg) {
		LOGP(DLINP, LOGL_ERROR, "Failed to allocate memory for BSC msg.\n");
		return;
	}

	msg->l2h = msgb_put(msg, length);
	memcpy(msg->data, data, length);

	bsc_write(bsc, msg, proto);
}

/*
 * Update the release statistics
 */
static void bsc_stat_reject(int filter, struct bsc_connection *bsc, int normal)
{
	if (!bsc->cfg) {
		LOGP(DNAT, LOGL_ERROR, "BSC is not authenticated.");
		return;
	}

	if (filter >= 0) {
		LOGP(DNAT, LOGL_ERROR, "Connection was not rejected");
		return;
	}

	if (filter == -1)
		rate_ctr_inc(&bsc->cfg->stats.ctrg->ctr[BCFG_CTR_ILL_PACKET]);
	else if (normal)
		rate_ctr_inc(&bsc->cfg->stats.ctrg->ctr[BCFG_CTR_REJECTED_MSG]);
	else
		rate_ctr_inc(&bsc->cfg->stats.ctrg->ctr[BCFG_CTR_REJECTED_CR]);
}

/*
 * Release an established connection. We will have to release it to the BSC
 * and to the network and we do it the following way.
 * 1.) Give up on the MSC side
 *  1.1) Send a RLSD message, it is a bit non standard but should work, we
 *       ignore the RLC... we might complain about it. Other options would
 *       be to send a Release Request, handle the Release Complete..
 *  1.2) Mark the data structure to be con_local and wait for 2nd
 *
 * 2.) Give up on the BSC side
 *  2.1) Depending on the con type reject the service, or just close it
 */
static void bsc_send_con_release(struct bsc_connection *bsc,
		struct nat_sccp_connection *con,
		struct bsc_filter_reject_cause *cause)
{
	struct msgb *rlsd;
	/* 1. release the network */
	rlsd = sccp_create_rlsd(&con->patched_ref, &con->remote_ref,
				SCCP_RELEASE_CAUSE_END_USER_ORIGINATED);
	if (!rlsd)
		LOGP(DNAT, LOGL_ERROR, "Failed to create RLSD message.\n");
	else {
		ipa_prepend_header(rlsd, IPAC_PROTO_SCCP);
		queue_for_msc(con->msc_con, rlsd);
	}
	con->con_local = NAT_CON_END_LOCAL;
	con->msc_con = NULL;

	/* 2. release the BSC side */
	if (con->filter_state.con_type == FLT_CON_TYPE_LU) {
		struct msgb *payload, *udt;
		payload = gsm48_create_loc_upd_rej(cause->lu_reject_cause);

		if (payload) {
			gsm0808_prepend_dtap_header(payload, 0);
			udt = sccp_create_dt1(&con->real_ref, payload->data, payload->len);
			if (udt)
				bsc_write(bsc, udt, IPAC_PROTO_SCCP);
			else
				LOGP(DNAT, LOGL_ERROR, "Failed to create DT1\n");

			msgb_free(payload);
		} else {
			LOGP(DNAT, LOGL_ERROR, "Failed to allocate LU Reject.\n");
		}
	}

	nat_send_clrc_bsc(con);

	rlsd = sccp_create_rlsd(&con->remote_ref, &con->real_ref,
				SCCP_RELEASE_CAUSE_END_USER_ORIGINATED);
	if (!rlsd) {
		LOGP(DNAT, LOGL_ERROR, "Failed to allocate RLSD for the BSC.\n");
		sccp_connection_destroy(con);
		return;
	}

	con->filter_state.con_type = FLT_CON_TYPE_LOCAL_REJECT;
	bsc_write(bsc, rlsd, IPAC_PROTO_SCCP);
}

static void bsc_send_con_refuse(struct bsc_connection *bsc,
			struct bsc_nat_parsed *parsed, int con_type,
			struct bsc_filter_reject_cause *cause)
{
	struct msgb *payload;
	struct msgb *refuse;

	if (con_type == FLT_CON_TYPE_LU)
		payload = gsm48_create_loc_upd_rej(cause->lu_reject_cause);
	else if (con_type == FLT_CON_TYPE_CM_SERV_REQ || con_type == FLT_CON_TYPE_SSA)
		payload = gsm48_create_mm_serv_rej(cause->cm_reject_cause);
	else {
		LOGP(DNAT, LOGL_ERROR, "Unknown connection type: %d\n", con_type);
		payload = NULL;
	}

	/*
	 * Some BSCs do not handle the payload inside a SCCP CREF msg
	 * so we will need to:
	 * 1.) Allocate a local connection and mark it as local..
	 * 2.) queue data for downstream.. and the RLC should delete everything
	 */
	if (payload) {
		struct msgb *cc, *udt, *clear, *rlsd;
		struct nat_sccp_connection *con;
		con = create_sccp_src_ref(bsc, parsed);
		if (!con)
			goto send_refuse;

		/* declare it local and assign a unique remote_ref */
		con->filter_state.con_type = FLT_CON_TYPE_LOCAL_REJECT;
		con->con_local = NAT_CON_END_LOCAL;
		con->has_remote_ref = 1;
		con->remote_ref = con->patched_ref;

		/* 1. create a confirmation */
		cc = sccp_create_cc(&con->remote_ref, &con->real_ref);
		if (!cc)
			goto send_refuse;

		/* 2. create the DT1 */
		gsm0808_prepend_dtap_header(payload, 0);
		udt = sccp_create_dt1(&con->real_ref, payload->data, payload->len);
		if (!udt) {
			msgb_free(cc);
			goto send_refuse;
		}

		/* 3. send a Clear Command */
		clear = nat_creat_clrc(con, 0x20);
		if (!clear) {
			msgb_free(cc);
			msgb_free(udt);
			goto send_refuse;
		}

		/* 4. send a RLSD */
		rlsd = sccp_create_rlsd(&con->remote_ref, &con->real_ref,
					SCCP_RELEASE_CAUSE_END_USER_ORIGINATED);
		if (!rlsd) {
			msgb_free(cc);
			msgb_free(udt);
			msgb_free(clear);
			goto send_refuse;
		}

		bsc_write(bsc, cc, IPAC_PROTO_SCCP);
		bsc_write(bsc, udt, IPAC_PROTO_SCCP);
		bsc_write(bsc, clear, IPAC_PROTO_SCCP);
		bsc_write(bsc, rlsd, IPAC_PROTO_SCCP);
		msgb_free(payload);
		return;
	}


send_refuse:
	if (payload)
		msgb_free(payload);

	refuse = sccp_create_refuse(parsed->src_local_ref,
				    SCCP_REFUSAL_SCCP_FAILURE, NULL, 0);
	if (!refuse) {
		LOGP(DNAT, LOGL_ERROR,
		     "Creating refuse msg failed for SCCP 0x%x on BSC Nr: %d.\n",
		      sccp_src_ref_to_int(parsed->src_local_ref), bsc->cfg->nr);
		return;
	}

	bsc_write(bsc, refuse, IPAC_PROTO_SCCP);
}

static void bsc_nat_send_paging(struct bsc_connection *bsc, struct msgb *msg)
{
	if (bsc->cfg->forbid_paging) {
		LOGP(DNAT, LOGL_DEBUG, "Paging forbidden for BTS: %d\n", bsc->cfg->nr);
		return;
	}

	bsc_send_data(bsc, msg->l2h, msgb_l2len(msg), IPAC_PROTO_SCCP);
}

static void bsc_nat_handle_paging(struct bsc_nat *nat, struct msgb *msg)
{
	struct bsc_connection *bsc;
	const uint8_t *paging_start;
	int paging_length, i, ret;

	ret = bsc_nat_find_paging(msg, &paging_start, &paging_length);
	if (ret != 0) {
		LOGP(DNAT, LOGL_ERROR, "Could not parse paging message: %d\n", ret);
		return;
	}

	/* This is quite expensive now */
	for (i = 0; i < paging_length; i += 2) {
		unsigned int _lac = ntohs(*(unsigned int *) &paging_start[i]);
		unsigned int paged = 0;
		llist_for_each_entry(bsc, &nat->bsc_connections, list_entry) {
			if (!bsc->cfg)
				continue;
			if (!bsc->authenticated)
				continue;
			if (!bsc_config_handles_lac(bsc->cfg, _lac))
				continue;
			bsc_nat_send_paging(bsc, msg);
			paged += 1;
		}

		/* highlight a possible config issue */
		if (paged == 0)
			LOGP(DNAT, LOGL_ERROR, "No BSC for LAC %d/0x%d\n", _lac, _lac);

	}
}


/*
 * Update the auth status. This can be either a CIPHER MODE COMMAND or
 * a CM Serivce Accept. Maybe also LU Accept or such in the future.
 */
static void update_con_authorize(struct nat_sccp_connection *con,
				 struct bsc_nat_parsed *parsed,
				 struct msgb *msg)
{
	if (!con)
		return;
	if (con->authorized)
		return;

	if (parsed->bssap == BSSAP_MSG_BSS_MANAGEMENT &&
	    parsed->gsm_type == BSS_MAP_MSG_CIPHER_MODE_CMD) {
		con->authorized = 1;
	} else if (parsed->bssap == BSSAP_MSG_DTAP) {
		uint8_t msg_type, proto;
		uint32_t len;
		struct gsm48_hdr *hdr48;
		hdr48 = bsc_unpack_dtap(parsed, msg, &len);
		if (!hdr48)
			return;

		proto = gsm48_hdr_pdisc(hdr48);
		msg_type = gsm48_hdr_msg_type(hdr48);
		if (proto == GSM48_PDISC_MM &&
		    msg_type == GSM48_MT_MM_CM_SERV_ACC)
			con->authorized = 1;
	}
}

static int forward_sccp_to_bts(struct bsc_msc_connection *msc_con, struct msgb *msg)
{
	struct nat_sccp_connection *con = NULL;
	struct bsc_connection *bsc;
	struct bsc_nat_parsed *parsed;
	int proto;

	/* filter, drop, patch the message? */
	parsed = bsc_nat_parse(msg);
	if (!parsed) {
		LOGP(DNAT, LOGL_ERROR, "Can not parse msg from BSC.\n");
		return -1;
	}

	if (bsc_nat_filter_ipa(DIR_BSC, msg, parsed))
		goto exit;

	proto = parsed->ipa_proto;

	/* Route and modify the SCCP packet */
	if (proto == IPAC_PROTO_SCCP) {
		switch (parsed->sccp_type) {
		case SCCP_MSG_TYPE_UDT:
			/* forward UDT messages to every BSC */
			goto send_to_all;
			break;
		case SCCP_MSG_TYPE_RLSD:
		case SCCP_MSG_TYPE_CREF:
		case SCCP_MSG_TYPE_DT1:
		case SCCP_MSG_TYPE_IT:
			con = patch_sccp_src_ref_to_bsc(msg, parsed, nat);
			if (parsed->gsm_type == BSS_MAP_MSG_ASSIGMENT_RQST) {
				osmo_counter_inc(nat->stats.sccp.calls);

				if (con) {
					struct rate_ctr_group *ctrg;
					ctrg = con->bsc->cfg->stats.ctrg;
					rate_ctr_inc(&ctrg->ctr[BCFG_CTR_SCCP_CALLS]);
					if (bsc_mgcp_assign_patch(con, msg) != 0)
						LOGP(DNAT, LOGL_ERROR, "Failed to assign...\n");
				} else
					LOGP(DNAT, LOGL_ERROR, "Assignment command but no BSC.\n");
			} else if (con && con->con_local == NAT_CON_END_USSD &&
				   parsed->gsm_type == BSS_MAP_MSG_CLEAR_CMD) {
				LOGP(DNAT, LOGL_NOTICE, "Clear Command for USSD Connection. Ignoring.\n");
				con = NULL;
			}
			break;
		case SCCP_MSG_TYPE_CC:
			con = patch_sccp_src_ref_to_bsc(msg, parsed, nat);
			if (!con || update_sccp_src_ref(con, parsed) != 0)
				goto exit;
			break;
		case SCCP_MSG_TYPE_RLC:
			LOGP(DNAT, LOGL_ERROR, "Unexpected release complete from MSC.\n");
			goto exit;
			break;
		case SCCP_MSG_TYPE_CR:
			/* MSC never opens a SCCP connection, fall through */
		default:
			goto exit;
		}

		if (!con && parsed->sccp_type == SCCP_MSG_TYPE_RLSD) {
			LOGP(DNAT, LOGL_NOTICE, "Sending fake RLC on RLSD message to network.\n");
			/* Exchange src/dest for the reply */
			nat_send_rlc(msc_con, &parsed->original_dest_ref,
					parsed->src_local_ref);
		} else if (!con)
			LOGP(DNAT, LOGL_ERROR, "Unknown connection for msg type: 0x%x from the MSC.\n", parsed->sccp_type);
	}

	if (!con) {
		talloc_free(parsed);
		return -1;
	}
	if (!con->bsc->authenticated) {
		talloc_free(parsed);
		LOGP(DNAT, LOGL_ERROR, "Selected BSC not authenticated.\n");
		return -1;
	}

	update_con_authorize(con, parsed, msg);
	talloc_free(parsed);

	bsc_send_data(con->bsc, msg->l2h, msgb_l2len(msg), proto);
	return 0;

send_to_all:
	/*
	 * Filter Paging from the network. We do not want to send a PAGING
	 * Command to every BSC in our network. We will analys the PAGING
	 * message and then send it to the authenticated messages...
	 */
	if (parsed->ipa_proto == IPAC_PROTO_SCCP && parsed->gsm_type == BSS_MAP_MSG_PAGING) {
		bsc_nat_handle_paging(nat, msg);
		goto exit;
	}
	/* currently send this to every BSC connected */
	llist_for_each_entry(bsc, &nat->bsc_connections, list_entry) {
		if (!bsc->authenticated)
			continue;

		bsc_send_data(bsc, msg->l2h, msgb_l2len(msg), parsed->ipa_proto);
	}

exit:
	talloc_free(parsed);
	return 0;
}

static void msc_connection_was_lost(struct bsc_msc_connection *con)
{
	struct bsc_connection *bsc, *tmp;

	LOGP(DMSC, LOGL_ERROR, "Closing all connections downstream.\n");
	llist_for_each_entry_safe(bsc, tmp, &nat->bsc_connections, list_entry)
		bsc_close_connection(bsc);

	bsc_mgcp_free_endpoints(nat);
	bsc_msc_schedule_connect(con);
}

static void msc_connection_connected(struct bsc_msc_connection *con)
{
	osmo_counter_inc(nat->stats.msc.reconn);
}

static void msc_send_reset(struct bsc_msc_connection *msc_con)
{
	static const uint8_t reset[] = {
		0x00, 0x12, 0xfd,
		0x09, 0x00, 0x03, 0x05, 0x07, 0x02, 0x42, 0xfe,
		0x02, 0x42, 0xfe, 0x06, 0x00, 0x04, 0x30, 0x04,
		0x01, 0x20
	};

	struct msgb *msg;

	msg = msgb_alloc_headroom(4096, 128, "08.08 reset");
	if (!msg) {
		LOGP(DMSC, LOGL_ERROR, "Failed to allocate reset msg.\n");
		return;
	}

	msg->l2h = msgb_put(msg, sizeof(reset));
	memcpy(msg->l2h, reset, msgb_l2len(msg));

	queue_for_msc(msc_con, msg);

	LOGP(DMSC, LOGL_NOTICE, "Scheduled GSM0808 reset msg for the MSC.\n");
}

static int ipaccess_msc_read_cb(struct osmo_fd *bfd)
{
	struct bsc_msc_connection *msc_con;
	struct msgb *msg = NULL;
	struct ipaccess_head *hh;
	int ret;

	msc_con = (struct bsc_msc_connection *) bfd->data;

	ret = ipa_msg_recv_buffered(bfd->fd, &msg, &msc_con->pending_msg);
	if (ret <= 0) {
		if (ret == -EAGAIN)
			return 0;
		if (ret == 0)
			LOGP(DNAT, LOGL_FATAL,
				"The connection the MSC(%s) was lost, exiting\n",
				msc_con->name);
		else
			LOGP(DNAT, LOGL_ERROR,
				"Failed to parse ip access message on %s: %d\n",
				msc_con->name, ret);

		bsc_msc_lost(msc_con);
		return -1;
	}

	LOGP(DNAT, LOGL_DEBUG,
		"MSG from MSC(%s): %s proto: %d\n", msc_con->name,
		osmo_hexdump(msg->data, msg->len), msg->l2h[0]);

	/* handle base message handling */
	hh = (struct ipaccess_head *) msg->data;

	/* initialize the networking. This includes sending a GSM08.08 message */
	if (hh->proto == IPAC_PROTO_IPACCESS) {
		ipa_ccm_rcvmsg_base(msg, bfd);
		if (msg->l2h[0] == IPAC_MSGT_ID_ACK)
			initialize_msc_if_needed(msc_con);
		else if (msg->l2h[0] == IPAC_MSGT_ID_GET)
			send_id_get_response(msc_con);
	} else if (hh->proto == IPAC_PROTO_SCCP) {
		forward_sccp_to_bts(msc_con, msg);
	} else if (hh->proto == IPAC_PROTO_MGCP_OLD) {
		bsc_nat_handle_mgcp(nat, msg);
	}

	msgb_free(msg);
	return 0;
}

static int ipaccess_msc_write_cb(struct osmo_fd *bfd, struct msgb *msg)
{
	int rc;
	rc = write(bfd->fd, msg->data, msg->len);

	if (rc != msg->len) {
		LOGP(DNAT, LOGL_ERROR, "Failed to write MSG to MSC.\n");
		return -1;
	}

	return rc;
}

/*
 * Below is the handling of messages coming
 * from the BSC and need to be forwarded to
 * a real BSC.
 */

/*
 * Remove the connection from the connections list,
 * remove it from the patching of SCCP header lists
 * as well. Maybe in the future even close connection..
 */
void bsc_close_connection(struct bsc_connection *connection)
{
	struct nat_sccp_connection *sccp_patch, *tmp;
	struct bsc_cmd_list *cmd_entry, *cmd_tmp;
	struct rate_ctr *ctr = NULL;

	/* stop the timeout timer */
	osmo_timer_del(&connection->id_timeout);
	osmo_timer_del(&connection->ping_timeout);
	osmo_timer_del(&connection->pong_timeout);

	if (connection->cfg)
		ctr = &connection->cfg->stats.ctrg->ctr[BCFG_CTR_DROPPED_SCCP];

	/* remove all SCCP connections */
	llist_for_each_entry_safe(sccp_patch, tmp, &nat->sccp_connections, list_entry) {
		if (sccp_patch->bsc != connection)
			continue;

		if (ctr)
			rate_ctr_inc(ctr);
		if (sccp_patch->has_remote_ref) {
			if (sccp_patch->con_local == NAT_CON_END_MSC)
				nat_send_rlsd_msc(sccp_patch);
			else if (sccp_patch->con_local == NAT_CON_END_USSD)
				nat_send_rlsd_ussd(nat, sccp_patch);
		}

		sccp_connection_destroy(sccp_patch);
	}

	/* Reply to all outstanding commands */
	llist_for_each_entry_safe(cmd_entry, cmd_tmp, &connection->cmd_pending, list_entry) {
		cmd_entry->cmd->type = CTRL_TYPE_ERROR;
		cmd_entry->cmd->reply = "BSC closed the connection";
		ctrl_cmd_send(&cmd_entry->ccon->write_queue, cmd_entry->cmd);
		bsc_nat_ctrl_del_pending(cmd_entry);
	}

	/* close endpoints allocated by this BSC */
	bsc_mgcp_clear_endpoints_for(connection);

	osmo_fd_unregister(&connection->write_queue.bfd);
	close(connection->write_queue.bfd.fd);
	osmo_wqueue_clear(&connection->write_queue);
	llist_del(&connection->list_entry);

	if (connection->pending_msg) {
		LOGP(DNAT, LOGL_ERROR, "Dropping partial message on connection %d.\n",
		     connection->cfg ? connection->cfg->nr : -1);
		msgb_free(connection->pending_msg);
		connection->pending_msg = NULL;
	}

	talloc_free(connection);
}

static void bsc_maybe_close(struct bsc_connection *bsc)
{
	struct nat_sccp_connection *sccp;
	if (!bsc->nat->blocked)
		return;

	/* are there any connections left */
	llist_for_each_entry(sccp, &bsc->nat->sccp_connections, list_entry)
		if (sccp->bsc == bsc)
			return;

	/* nothing left, close the BSC */
	LOGP(DNAT, LOGL_NOTICE, "Cleaning up BSC %d in blocking mode.\n",
	     bsc->cfg ? bsc->cfg->nr : -1);
	bsc_close_connection(bsc);
}

static void ipaccess_close_bsc(void *data)
{
	struct sockaddr_in sock;
	socklen_t len = sizeof(sock);
	struct bsc_connection *conn = data;


	getpeername(conn->write_queue.bfd.fd, (struct sockaddr *) &sock, &len);
	LOGP(DNAT, LOGL_ERROR, "BSC on %s didn't respond to identity request. Closing.\n",
	     inet_ntoa(sock.sin_addr));
	bsc_close_connection(conn);
}

static int verify_key(struct bsc_connection *conn, struct bsc_config *conf, const uint8_t *key, const int keylen)
{
	struct osmo_auth_vector vec;

	struct osmo_sub_auth_data auth = {
		.type		= OSMO_AUTH_TYPE_GSM,
		.algo		= OSMO_AUTH_ALG_MILENAGE,
	};

	/* expect a specific keylen */
	if (keylen != 8) {
		LOGP(DNAT, LOGL_ERROR, "Key length is wrong: %d for bsc nr %d\n",
			keylen, conf->nr);
		return 0;
	}

	memcpy(auth.u.umts.opc, conf->key, 16);
	memcpy(auth.u.umts.k, conf->key, 16);
	memset(auth.u.umts.amf, 0, 2);
	auth.u.umts.sqn = 0;

	memset(&vec, 0, sizeof(vec));
	osmo_auth_gen_vec(&vec, &auth, conn->last_rand);

	if (vec.res_len != 8) {
		LOGP(DNAT, LOGL_ERROR, "Res length is wrong: %d for bsc nr %d\n",
			vec.res_len, conf->nr);
		return 0;
	}

	return osmo_constant_time_cmp(vec.res, key, 8) == 0;
}

static void ipaccess_auth_bsc(struct tlv_parsed *tvp, struct bsc_connection *bsc)
{
	struct bsc_config *conf;
	const char *token = (const char *) TLVP_VAL(tvp, IPAC_IDTAG_UNITNAME);
	int len = TLVP_LEN(tvp, IPAC_IDTAG_UNITNAME);
	const uint8_t *xres = TLVP_VAL(tvp, 0x24);
	const int xlen = TLVP_LEN(tvp, 0x24);

	if (bsc->cfg) {
		LOGP(DNAT, LOGL_ERROR, "Reauth on fd %d bsc nr %d\n",
		     bsc->write_queue.bfd.fd, bsc->cfg->nr);
		return;
	}

	if (len <= 0) {
		LOGP(DNAT, LOGL_ERROR, "Token with length zero on fd: %d\n",
			bsc->write_queue.bfd.fd);
		return;
	}

	if (token[len - 1] != '\0') {
		LOGP(DNAT, LOGL_ERROR, "Token not null terminated on fd: %d\n",
			bsc->write_queue.bfd.fd);
		return;
	}

	/*
	 * New systems have fixed the structure of the message but
	 * we need to support old ones too.
	 */
	if (len >= 2 && token[len - 2] == '\0')
		len -= 1;

	conf = bsc_config_by_token(bsc->nat, token, len);
	if (!conf) {
		LOGP(DNAT, LOGL_ERROR,
			"No bsc found for token '%s' len %d on fd: %d.\n", token,
			bsc->write_queue.bfd.fd, len);
		bsc_close_connection(bsc);
		return;
	}

	/* We have set a key and expect it to be present */
	if (conf->key_present && !verify_key(bsc, conf, xres, xlen - 1)) {
		LOGP(DNAT, LOGL_ERROR,
			"Wrong key for bsc nr %d fd: %d.\n", conf->nr,
			bsc->write_queue.bfd.fd);
		bsc_close_connection(bsc);
		return;
	}

	rate_ctr_inc(&conf->stats.ctrg->ctr[BCFG_CTR_NET_RECONN]);
	bsc->authenticated = 1;
	bsc->cfg = conf;
	osmo_timer_del(&bsc->id_timeout);
	LOGP(DNAT, LOGL_NOTICE, "Authenticated bsc nr: %d on fd %d\n",
		conf->nr, bsc->write_queue.bfd.fd);
	start_ping_pong(bsc);
}

static void handle_con_stats(struct nat_sccp_connection *con)
{
	struct rate_ctr_group *ctrg;
	int id = bsc_conn_type_to_ctr(con);

	if (id == -1)
		return;

	if (!con->bsc || !con->bsc->cfg)
		return;

	ctrg = con->bsc->cfg->stats.ctrg;
	rate_ctr_inc(&ctrg->ctr[id]);
}

static int forward_sccp_to_msc(struct bsc_connection *bsc, struct msgb *msg)
{
	int con_filter = 0;
	char *imsi = NULL;
	struct bsc_msc_connection *con_msc = NULL;
	struct bsc_connection *con_bsc = NULL;
	int con_type;
	struct bsc_nat_parsed *parsed;
	struct bsc_filter_reject_cause cause;

	/* Parse and filter messages */
	parsed = bsc_nat_parse(msg);
	if (!parsed) {
		LOGP(DNAT, LOGL_ERROR, "Can not parse msg from BSC.\n");
		msgb_free(msg);
		return -1;
	}

	if (bsc_nat_filter_ipa(DIR_MSC, msg, parsed))
		goto exit;

	/*
	 * check authentication after filtering to not reject auth
	 * responses coming from the BSC. We have to make sure that
	 * nothing from the exit path will forward things to the MSC
	 */
	if (!bsc->authenticated) {
		LOGP(DNAT, LOGL_ERROR, "BSC is not authenticated.\n");
		msgb_free(msg);
		return -1;
	}


	/* modify the SCCP entries */
	if (parsed->ipa_proto == IPAC_PROTO_SCCP) {
		int filter;
		struct nat_sccp_connection *con;
		switch (parsed->sccp_type) {
		case SCCP_MSG_TYPE_CR:
			memset(&cause, 0, sizeof(cause));
			filter = bsc_nat_filter_sccp_cr(bsc, msg, parsed,
						&con_type, &imsi, &cause);
			if (filter < 0) {
				if (imsi)
					bsc_nat_inform_reject(bsc, imsi);
				bsc_stat_reject(filter, bsc, 0);
				goto exit3;
			}

			if (!create_sccp_src_ref(bsc, parsed))
				goto exit2;
			con = patch_sccp_src_ref_to_msc(msg, parsed, bsc);
			OSMO_ASSERT(con);
			con->msc_con = bsc->nat->msc_con;
			con_msc = con->msc_con;
			con->filter_state.con_type = con_type;
			con->filter_state.imsi_checked = filter;
			bsc_nat_extract_lac(bsc, con, parsed, msg);
			if (imsi)
				con->filter_state.imsi = talloc_steal(con, imsi);
			imsi = NULL;
			con_bsc = con->bsc;
			handle_con_stats(con);
			break;
		case SCCP_MSG_TYPE_RLSD:
		case SCCP_MSG_TYPE_CREF:
		case SCCP_MSG_TYPE_DT1:
		case SCCP_MSG_TYPE_CC:
		case SCCP_MSG_TYPE_IT:
			con = patch_sccp_src_ref_to_msc(msg, parsed, bsc);
			if (con) {
				/* only filter non local connections */
				if (!con->con_local) {
					memset(&cause, 0, sizeof(cause));
					filter = bsc_nat_filter_dt(bsc, msg,
							con, parsed, &cause);
					if (filter < 0) {
						if (con->filter_state.imsi)
							bsc_nat_inform_reject(bsc,
								con->filter_state.imsi);
						bsc_stat_reject(filter, bsc, 1);
						bsc_send_con_release(bsc, con, &cause);
						con = NULL;
						goto exit2;
					}

					/* hand data to a side channel */
					if (bsc_ussd_check(con, parsed, msg) == 1) 
						con->con_local = NAT_CON_END_USSD;

					/*
					 * Optionally rewrite setup message. This can
					 * replace the msg and the parsed structure becomes
					 * invalid.
					 */
					msg = bsc_nat_rewrite_msg(bsc->nat, msg, parsed,
									con->filter_state.imsi);
					talloc_free(parsed);
					parsed = NULL;
				} else if (con->con_local == NAT_CON_END_USSD) {
					bsc_ussd_check(con, parsed, msg);
				}

				con_bsc = con->bsc;
				con_msc = con->msc_con;
				con_filter = con->con_local;
			}

			break;
		case SCCP_MSG_TYPE_RLC:
			con = patch_sccp_src_ref_to_msc(msg, parsed, bsc);
			if (con) {
				con_bsc = con->bsc;
				con_msc = con->msc_con;
				con_filter = con->con_local;
			}
			remove_sccp_src_ref(bsc, msg, parsed);
			bsc_maybe_close(bsc);
			break;
		case SCCP_MSG_TYPE_UDT:
			/* simply forward everything */
			con = NULL;
			break;
		default:
			LOGP(DNAT, LOGL_ERROR, "Not forwarding to msc sccp type: 0x%x\n", parsed->sccp_type);
			con = NULL;
			goto exit2;
			break;
		}
        } else if (parsed->ipa_proto == IPAC_PROTO_MGCP_OLD) {
                bsc_mgcp_forward(bsc, msg);
                goto exit2;
	} else {
		LOGP(DNAT, LOGL_ERROR, "Not forwarding unknown stream id: 0x%x\n", parsed->ipa_proto);
		goto exit2;
	}

	if (con_msc && con_bsc != bsc) {
		LOGP(DNAT, LOGL_ERROR, "The connection belongs to a different BTS: input: %d con: %d\n",
		     bsc->cfg->nr, con_bsc->cfg->nr);
		goto exit2;
	}

	/* do not forward messages to the MSC */
	if (con_filter)
		goto exit2;

	if (!con_msc) {
		LOGP(DNAT, LOGL_ERROR, "Not forwarding data bsc_nr: %d ipa: %d type: 0x%x\n",
			bsc->cfg->nr,
			parsed ? parsed->ipa_proto : -1,
			parsed ? parsed->sccp_type : -1);
		goto exit2;
	}

	/* send the non-filtered but maybe modified msg */
	queue_for_msc(con_msc, msg);
	if (parsed)
		talloc_free(parsed);
	return 0;

exit:
	/* if we filter out the reset send an ack to the BSC */
	if (parsed->bssap == 0 && parsed->gsm_type == BSS_MAP_MSG_RESET) {
		send_reset_ack(bsc);
		send_reset_ack(bsc);
	} else if (parsed->ipa_proto == IPAC_PROTO_IPACCESS) {
		/* do we know who is handling this? */
		if (msg->l2h[0] == IPAC_MSGT_ID_RESP && msgb_l2len(msg) > 2) {
			struct tlv_parsed tvp;
			int ret;
			ret = ipa_ccm_idtag_parse_off(&tvp,
					     (unsigned char *) msg->l2h + 2,
					     msgb_l2len(msg) - 2, 0);
			if (ret < 0) {
				LOGP(DNAT, LOGL_ERROR, "ignoring IPA response "
					"message with malformed TLVs\n");
				return ret;
			}
			if (TLVP_PRESENT(&tvp, IPAC_IDTAG_UNITNAME))
				ipaccess_auth_bsc(&tvp, bsc);
		}

		goto exit2;
	}

exit2:
	if (imsi)
		talloc_free(imsi);
	talloc_free(parsed);
	msgb_free(msg);
	return -1;

exit3:
	/* send a SCCP Connection Refused */
	if (imsi)
		talloc_free(imsi);
	bsc_send_con_refuse(bsc, parsed, con_type, &cause);
	talloc_free(parsed);
	msgb_free(msg);
	return -1;
}

static int ipaccess_bsc_read_cb(struct osmo_fd *bfd)
{
	struct bsc_connection *bsc = bfd->data;
	struct msgb *msg = NULL;
	struct ipaccess_head *hh;
	struct ipaccess_head_ext *hh_ext;
	int ret;

	ret = ipa_msg_recv_buffered(bfd->fd, &msg, &bsc->pending_msg);
	if (ret <= 0) {
		if (ret == -EAGAIN)
			return 0;
		if (ret == 0)
			LOGP(DNAT, LOGL_ERROR,
			     "The connection to the BSC Nr: %d was lost. Cleaning it\n",
			     bsc->cfg ? bsc->cfg->nr : -1);
		else
			LOGP(DNAT, LOGL_ERROR,
			     "Stream error on BSC Nr: %d. Failed to parse ip access message: %d (%s)\n",
			     bsc->cfg ? bsc->cfg->nr : -1, ret, strerror(-ret));

		bsc_close_connection(bsc);
		return -1;
	}


	LOGP(DNAT, LOGL_DEBUG, "MSG from BSC: %s proto: %d\n", osmo_hexdump(msg->data, msg->len), msg->l2h[0]);

	/* Handle messages from the BSC */
	hh = (struct ipaccess_head *) msg->data;

	/* stop the pong timeout */
	if (hh->proto == IPAC_PROTO_IPACCESS) {
		if (msg->l2h[0] == IPAC_MSGT_PONG) {
			osmo_timer_del(&bsc->pong_timeout);
			msgb_free(msg);
			return 0;
		} else if (msg->l2h[0] == IPAC_MSGT_PING) {
			send_pong(bsc);
			msgb_free(msg);
			return 0;
		}
	/* Message contains the ipaccess_head_ext header, investigate further */
	} else if (hh->proto == IPAC_PROTO_OSMO &&
		   msg->len > sizeof(*hh) + sizeof(*hh_ext)) {

		hh_ext = (struct ipaccess_head_ext *) hh->data;
		/* l2h is where the actual command data is expected */
		msg->l2h = hh_ext->data;

		if (hh_ext->proto == IPAC_PROTO_EXT_CTRL)
			return bsc_nat_handle_ctrlif_msg(bsc, msg);
	}

	/* FIXME: Currently no PONG is sent to the BSC */
	/* FIXME: Currently no ID ACK is sent to the BSC */
	forward_sccp_to_msc(bsc, msg);

	return 0;
}

static int ipaccess_listen_bsc_cb(struct osmo_fd *bfd, unsigned int what)
{
	struct bsc_connection *bsc;
	int fd, rc, on;
	struct sockaddr_in sa;
	socklen_t sa_len = sizeof(sa);

	if (!(what & BSC_FD_READ))
		return 0;

	fd = accept(bfd->fd, (struct sockaddr *) &sa, &sa_len);
	if (fd < 0) {
		perror("accept");
		return fd;
	}

	/* count the reconnect */
	osmo_counter_inc(nat->stats.bsc.reconn);

	/*
	 * if we are not connected to a msc... just close the socket
	 */
	if (!bsc_nat_msc_is_connected(nat)) {
		LOGP(DNAT, LOGL_NOTICE, "Disconnecting BSC due lack of MSC connection.\n");
		close(fd);
		return 0;
	}

	if (nat->blocked) {
		LOGP(DNAT, LOGL_NOTICE, "Disconnecting BSC due NAT being blocked.\n");
		close(fd);
		return 0;
	}

	on = 1;
	rc = setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &on, sizeof(on));
	if (rc != 0)
                LOGP(DNAT, LOGL_ERROR, "Failed to set TCP_NODELAY: %s\n", strerror(errno));

	rc = setsockopt(fd, IPPROTO_IP, IP_TOS,
			&nat->bsc_ip_dscp, sizeof(nat->bsc_ip_dscp));
	if (rc != 0)
		LOGP(DNAT, LOGL_ERROR, "Failed to set IP_TOS: %s\n", strerror(errno));

	/* todo... do something with the connection */
	/* todo... use GNUtls to see if we want to trust this as a BTS */

	/*
	 *
	 */
	bsc = bsc_connection_alloc(nat);
	if (!bsc) {
		LOGP(DNAT, LOGL_ERROR, "Failed to allocate BSC struct.\n");
		close(fd);
		return -1;
	}

	bsc->write_queue.bfd.data = bsc;
	bsc->write_queue.bfd.fd = fd;
	bsc->write_queue.read_cb = ipaccess_bsc_read_cb;
	bsc->write_queue.write_cb = bsc_write_cb;
	bsc->write_queue.bfd.when = BSC_FD_READ;
	if (osmo_fd_register(&bsc->write_queue.bfd) < 0) {
		LOGP(DNAT, LOGL_ERROR, "Failed to register BSC fd.\n");
		close(fd);
		talloc_free(bsc);
		return -2;
	}

	LOGP(DNAT, LOGL_NOTICE, "BSC connection on %d with IP: %s\n",
		fd, inet_ntoa(sa.sin_addr));

	llist_add(&bsc->list_entry, &nat->bsc_connections);
	bsc->last_id = 0;

	send_id_ack(bsc);
	send_id_req(nat, bsc);
	send_mgcp_reset(bsc);

	/*
	 * start the hangup timer
	 */
	osmo_timer_setup(&bsc->id_timeout, ipaccess_close_bsc, bsc);
	osmo_timer_schedule(&bsc->id_timeout, nat->auth_timeout, 0);
	return 0;
}

static void print_usage()
{
	printf("Usage: bsc_nat\n");
}

static void print_help()
{
	printf("  Some useful help...\n");
	printf("  -h --help this text\n");
	printf("  -d option --debug=DRLL:DCC:DMM:DRR:DRSL:DNM enable debugging\n");
	printf("  -D --daemonize Fork the process into a background daemon\n");
	printf("  -s --disable-color\n");
	printf("  -c --config-file filename The config file to use.\n");
	printf("  -m --msc=IP. The address of the MSC.\n");
	printf("  -l --local=IP. The local address of this BSC.\n");
}

static void handle_options(int argc, char **argv)
{
	while (1) {
		int option_index = 0, c;
		static struct option long_options[] = {
			{"help", 0, 0, 'h'},
			{"debug", 1, 0, 'd'},
			{"daemonize", 0, 0, 'D'},
			{"config-file", 1, 0, 'c'},
			{"disable-color", 0, 0, 's'},
			{"timestamp", 0, 0, 'T'},
			{"msc", 1, 0, 'm'},
			{"local", 1, 0, 'l'},
			{0, 0, 0, 0}
		};

		c = getopt_long(argc, argv, "hd:sTPc:m:l:D",
				long_options, &option_index);
		if (c == -1)
			break;

		switch (c) {
		case 'h':
			print_usage();
			print_help();
			exit(0);
		case 's':
			log_set_use_color(osmo_stderr_target, 0);
			break;
		case 'd':
			log_parse_category_mask(osmo_stderr_target, optarg);
			break;
		case 'D':
			daemonize = 1;
			break;
		case 'c':
			config_file = optarg;
			break;
		case 'T':
			log_set_print_timestamp(osmo_stderr_target, 1);
			break;
		case 'm':
			msc_ip = optarg;
			break;
		case 'l':
			inet_aton(optarg, &local_addr);
			break;
		default:
			/* ignore */
			break;
		}
	}
}

static void signal_handler(int signal)
{
	switch (signal) {
	case SIGABRT:
		/* in case of abort, we want to obtain a talloc report
		 * and then return to the caller, who will abort the process */
	case SIGUSR1:
		talloc_report_full(tall_bsc_ctx, stderr);
		break;
	default:
		break;
	}
}

static void sccp_close_unconfirmed(void *_data)
{
	int destroyed = 0;
	struct bsc_connection *bsc, *bsc_tmp;
	struct nat_sccp_connection *conn, *tmp1;
	struct timespec now;
	clock_gettime(CLOCK_MONOTONIC, &now);

	llist_for_each_entry_safe(conn, tmp1, &nat->sccp_connections, list_entry) {
		if (conn->has_remote_ref)
			continue;

		int diff = (now.tv_sec - conn->creation_time.tv_sec) / 60;
		if (diff < SCCP_CLOSE_TIME_TIMEOUT)
			continue;

		LOGP(DNAT, LOGL_ERROR,
			"SCCP connection 0x%x/0x%x was never confirmed on bsc nr. %d\n",
			sccp_src_ref_to_int(&conn->real_ref),
			sccp_src_ref_to_int(&conn->patched_ref),
			conn->bsc->cfg->nr);
		sccp_connection_destroy(conn);
		destroyed = 1;
	}

	if (!destroyed)
		goto out;

	/* now close out any BSC */
	llist_for_each_entry_safe(bsc, bsc_tmp, &nat->bsc_connections, list_entry)
		bsc_maybe_close(bsc);

out:
	osmo_timer_schedule(&sccp_close, SCCP_CLOSE_TIME, 0);
}

extern void *tall_ctr_ctx;
static void talloc_init_ctx()
{
	tall_bsc_ctx = talloc_named_const(NULL, 0, "nat");
	msgb_talloc_ctx_init(tall_bsc_ctx, 0);
	tall_ctr_ctx = talloc_named_const(tall_bsc_ctx, 0, "counter");
}

extern int bsc_vty_go_parent(struct vty *vty);

static struct vty_app_info vty_info = {
	.name 		= "OsmoBSCNAT",
	.version	= PACKAGE_VERSION,
	.go_parent_cb	= bsc_vty_go_parent,
	.is_config_node	= bsc_vty_is_config_node,
};


int main(int argc, char **argv)
{
	int rc;

	talloc_init_ctx();

	osmo_init_logging(&log_info);

	nat = bsc_nat_alloc();
	if (!nat) {
		fprintf(stderr, "Failed to allocate the BSC nat.\n");
		return -4;
	}

	nat->mgcp_cfg = mgcp_config_alloc();
	if (!nat->mgcp_cfg) {
		fprintf(stderr, "Failed to allocate MGCP cfg.\n");
		return -5;
	}

	/* We need to add mode-set for amr codecs */
	nat->sdp_ensure_amr_mode_set = 1;

	vty_info.copyright = openbsc_copyright;
	vty_init(&vty_info);
	logging_vty_add_cmds(NULL);
	osmo_stats_vty_add_cmds(&log_info);
	bsc_nat_vty_init(nat);
	ctrl_vty_init(tall_bsc_ctx);


	/* parse options */
	local_addr.s_addr = INADDR_ANY;
	handle_options(argc, argv);

	nat->include_base = dirname(talloc_strdup(tall_bsc_ctx, config_file));

	rate_ctr_init(tall_bsc_ctx);
	osmo_stats_init(tall_bsc_ctx);

	/* init vty and parse */
	if (mgcp_parse_config(config_file, nat->mgcp_cfg, MGCP_BSC_NAT) < 0) {
		fprintf(stderr, "Failed to parse the config file: '%s'\n", config_file);
		return -3;
	}

	/* start telnet after reading config for vty_get_bind_addr() */
	if (telnet_init_dynif(tall_bsc_ctx, NULL, vty_get_bind_addr(),
			      OSMO_VTY_PORT_BSC_NAT)) {
		fprintf(stderr, "Creating VTY telnet line failed\n");
		return -5;
	}

	/* over rule the VTY config for MSC IP */
	if (msc_ip)
		bsc_nat_set_msc_ip(nat, msc_ip);

	/* seed the PRNG */
	srand(time(NULL));

	LOGP(DNAT, LOGL_NOTICE, "BSCs configured from %s\n", nat->resolved_path);

	/*
	 * Setup the MGCP code..
	 */
	if (bsc_mgcp_nat_init(nat) != 0)
		return -4;

	/* connect to the MSC */
	nat->msc_con = bsc_msc_create(nat, &nat->dests);
	if (!nat->msc_con) {
		fprintf(stderr, "Creating a bsc_msc_connection failed.\n");
		exit(1);
	}

	/* start control interface after reading config for
	 * ctrl_vty_get_bind_addr() */
	nat->ctrl = bsc_nat_controlif_setup(nat, ctrl_vty_get_bind_addr(),
					    OSMO_CTRL_PORT_BSC_NAT);
	if (!nat->ctrl) {
		fprintf(stderr, "Creating the control interface failed.\n");
		exit(1);
	}

	nat->msc_con->name = "main MSC";
	nat->msc_con->connection_loss = msc_connection_was_lost;
	nat->msc_con->connected = msc_connection_connected;
	nat->msc_con->write_queue.read_cb = ipaccess_msc_read_cb;
	nat->msc_con->write_queue.write_cb = ipaccess_msc_write_cb;;
	nat->msc_con->write_queue.bfd.data = nat->msc_con;
	bsc_msc_connect(nat->msc_con);

	/* wait for the BSC */
	rc = make_sock(&bsc_listen, IPPROTO_TCP, ntohl(local_addr.s_addr),
		       5000, 0, ipaccess_listen_bsc_cb, nat);
	if (rc != 0) {
		fprintf(stderr, "Failed to listen for BSC.\n");
		exit(1);
	}

	rc = bsc_ussd_init(nat);
	if (rc != 0) {
		LOGP(DNAT, LOGL_ERROR, "Failed to bind the USSD socket.\n");
		exit(1);
	}

	signal(SIGABRT, &signal_handler);
	signal(SIGUSR1, &signal_handler);
	osmo_init_ignore_signals();

	if (daemonize) {
		rc = osmo_daemonize();
		if (rc < 0) {
			perror("Error during daemonize");
			exit(1);
		}
	}

	/* recycle timer */
	sccp_set_log_area(DSCCP);
	osmo_timer_setup(&sccp_close, sccp_close_unconfirmed, NULL);
	osmo_timer_schedule(&sccp_close, SCCP_CLOSE_TIME, 0);

	while (1) {
		osmo_select_main(0);
	}

	return 0;
}

/* Close all connections handed out to the USSD module */
int bsc_ussd_close_connections(struct bsc_nat *nat)
{
	struct nat_sccp_connection *con;
	llist_for_each_entry(con, &nat->sccp_connections, list_entry) {
		if (con->con_local != NAT_CON_END_USSD)
			continue;
		if (!con->bsc)
			continue;

		nat_send_clrc_bsc(con);
		nat_send_rlsd_bsc(con);
	}

	return 0;
}
