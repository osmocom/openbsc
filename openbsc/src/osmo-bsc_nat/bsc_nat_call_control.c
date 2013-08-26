/* Local Call-Control Filter Code */
/*
 * (C) 2013 by Holger Hans Peter Freyther <zecke@selfish.org>
 * (C) 2013 by On-Waves
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

#include <openbsc/bsc_nat.h>
#include <openbsc/bsc_nat_sccp.h>
#include <openbsc/bsc_msc.h>
#include <openbsc/ipaccess.h>
#include <openbsc/vty.h>

#include <osmocom/gsm/tlv.h>
#include <osmocom/gsm/gsm48.h>
#include <osmocom/gsm/protocol/gsm_08_08.h>

#include <osmocom/core/talloc.h>

#include <string.h>

void bsc_cc_update_msc_ip(struct bsc_nat *nat, const char *ip)
{
	if (ip) {
		bsc_replace_string(nat, &nat->local_dest->ip, ip);
	} else {
		talloc_free(nat->local_dest->ip);
		nat->local_dest->ip = NULL;
	}

	/* re-connect if the local_conn was already created */
	if (nat->local_conn)
		bsc_msc_lost(nat->local_conn);
}

static void local_connection_connected(struct bsc_msc_connection *con)
{
	struct bsc_nat *nat = con->data;
	osmo_counter_inc(nat->stats.local_cc.reconn);
}

/**
 * In contrast to forward_sccp_to_bts above we only work on already
 * authenticated connections and will only forward parts of the connection.
 * I am not sure how to reduce the copy and paste between the two routines
 * yet!
 */
static int local_forward_sccp_to_bts(struct bsc_msc_connection *local_con,
					struct msgb *msg)
{
	struct nat_sccp_connection *con = NULL;
	struct bsc_nat_parsed *parsed;
	struct bsc_nat *nat;
	int proto;

	nat = local_con->data;

	/* filter, drop, patch the message? */
	parsed = bsc_nat_parse(msg);
	if (!parsed) {
		LOGP(DNAT, LOGL_ERROR, "Can not parse msg from BSC.\n");
		return -1;
	}

	if (bsc_nat_filter_ipa(DIR_BSC, msg, parsed))
		goto exit;

	proto = parsed->ipa_proto;
	if (proto != IPAC_PROTO_SCCP)
		return -1;

	switch (parsed->sccp_type) {
	case SCCP_MSG_TYPE_UDT:
		/* ignore */
		break;
	case SCCP_MSG_TYPE_RLSD:
	case SCCP_MSG_TYPE_CREF:
	case SCCP_MSG_TYPE_DT1:
	case SCCP_MSG_TYPE_IT:
		con = patch_sccp_src_ref_to_bsc(msg, parsed, nat);
		if (parsed->gsm_type == BSS_MAP_MSG_ASSIGMENT_RQST) {
			osmo_counter_inc(nat->stats.local_cc.calls);
#warning "TODO... MGCP handling needs to be defined..."

			if (con) {
				struct rate_ctr_group *ctrg;
				ctrg = con->bsc->cfg->stats.ctrg;
				rate_ctr_inc(&ctrg->ctr[BCFG_CTR_SCCP_LOC_CALLS]);
				if (bsc_mgcp_assign_patch(con, msg) != 0)
					LOGP(DNAT, LOGL_ERROR, "Failed to assign...\n");
			} else
				LOGP(DNAT, LOGL_ERROR, "Assignment command but no BSC.\n");
		}
		break;
	case SCCP_MSG_TYPE_CC:
		/* should not happen */
	case SCCP_MSG_TYPE_RLC:
		/* should not happen */
	case SCCP_MSG_TYPE_CR:
		/* MSC never opens a SCCP connection, fall through */
	default:
		goto exit;
	}

exit:
	talloc_free(parsed);
	return 0;
}

int local_msc_read_cb(struct osmo_fd *bfd)
{
	struct bsc_msc_connection *local_con;
	struct ipaccess_head *hh;
	struct msgb *msg;
	int ret;

	local_con = (struct bsc_msc_connection *) bfd->data;
	ret = bsc_base_msc_read_cb(bfd, &msg);
	if (ret == -1)
		return ret;
	if (ret == 1)
		return 0;

	/* TODO: MGCP handling */
	hh = (struct ipaccess_head *) msg->data;
	if (hh->proto == IPAC_PROTO_SCCP)
		local_forward_sccp_to_bts(local_con, msg);

	msgb_free(msg);
	return 0;
}

static void local_connection_was_lost(struct bsc_msc_connection *con)
{
	struct bsc_nat *nat = con->data;

	LOGP(DMSC, LOGL_ERROR, "Local MSC disconnected. Closing things.\n");

	/* Close local calls */
	bsc_close_connections_by_type(nat, NAT_CON_END_CALL);

	/* Only schedule the reconnect if we still have an IP address */
	if (nat->local_dest->ip)
		bsc_msc_schedule_connect(con);
}

int bsc_cc_initialize(struct bsc_nat *nat)
{
	nat->local_conn = bsc_msc_create(nat, &nat->local_dests);
	if (!nat->local_conn)
		return -1;

	nat->local_conn->name = "local MSC";
	nat->local_conn->connection_loss = local_connection_was_lost;
	nat->local_conn->connected = local_connection_connected;
	nat->local_conn->write_queue.read_cb = local_msc_read_cb;
	nat->local_conn->write_queue.write_cb = bsc_write_cb;
	nat->local_conn->write_queue.bfd.data = nat->local_conn;
	nat->local_conn->data = nat;
	if (nat->local_dest->ip)
		bsc_msc_connect(nat->local_conn);

	return 0;
}

static int cc_new_connection(struct nat_sccp_connection *con, struct msgb *msg)
{
	return 0;
}

static int cc_forward(struct nat_sccp_connection *con, struct msgb *msg)
{
	return 0;
}

int bsc_cc_check(struct nat_sccp_connection *con, struct bsc_nat_parsed *parsed,
			struct msgb *msg)
{
	uint32_t len;
	uint8_t msg_type;
	uint8_t proto;
	uint8_t ti;
	struct gsm48_hdr *hdr48;
	struct gsm_mncc_number called;
	struct tlv_parsed tp;
	unsigned payload_len;

	char _dest_nr[35];

	/* no local number prefix */
	if (!con->bsc->nat->local_prefix)
		return 0;

	/* We have not verified the IMSI yet */
	if (!con->authorized)
		return 0;

	if (parsed->bssap != BSSAP_MSG_DTAP)
		return 0;

	hdr48 = bsc_unpack_dtap(parsed, msg, &len);
	if (!hdr48)
		return 0;

	proto = hdr48->proto_discr & 0x0f;
	msg_type = hdr48->msg_type & 0xbf;
	ti = (hdr48->proto_discr & 0x70) >> 4;

	/* ignore everything not call related */
	if (proto != GSM48_PDISC_CC)
		return 0;

	/* if we know this connection, return quickly */
	if (con->has_cc_ti && con->cc_ti == ti) {
		cc_forward(con, msg);
		return 1;
	}

	/* right now we identify a CC setup and remember things */
	if (msg_type != GSM48_MT_CC_SETUP)
		return 0;

	/* now look into it */
	payload_len = msgb_l3len(msg) - sizeof(*hdr48);

	tlv_parse(&tp, &gsm48_att_tlvdef, hdr48->data, payload_len, 0, 0);
	if (!TLVP_PRESENT(&tp, GSM48_IE_CALLED_BCD)) {
		LOGP(DMSC, LOGL_ERROR, "Called BCD not present in setup.\n");
		return 0;
	}

	memset(&called, 0, sizeof(called));
	gsm48_decode_called(&called,
			    TLVP_VAL(&tp, GSM48_IE_CALLED_BCD) - 1);

	if (called.plan != 1 && called.plan != 0)
		return 0;

	if (called.plan == 1 && called.type == 1) {
		_dest_nr[0] = _dest_nr[1] = '0';
		memcpy(_dest_nr + 2, called.number, sizeof(called.number));
	} else
		memcpy(_dest_nr, called.number, sizeof(called.number));

	/* now we can compare the number... */
	if (regexec(&con->bsc->nat->local_prefix_regexp, _dest_nr, 0, NULL, 0) != 0)
		return 0;

	con->has_cc_ti = 1;
	con->cc_ti = ti;
	cc_new_connection(con, msg);
	return 1;
}
