
/* BSC Multiplexer/NAT Utilities */

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
#include <openbsc/ipaccess.h>

#include <osmocore/linuxlist.h>
#include <osmocore/talloc.h>
#include <osmocore/gsm0808.h>

#include <sccp/sccp.h>

#include <netinet/in.h>
#include <arpa/inet.h>

struct bsc_nat *bsc_nat_alloc(void)
{
	struct bsc_nat *nat = talloc_zero(tall_bsc_ctx, struct bsc_nat);
	if (!nat)
		return NULL;

	INIT_LLIST_HEAD(&nat->sccp_connections);
	INIT_LLIST_HEAD(&nat->bsc_connections);
	INIT_LLIST_HEAD(&nat->bsc_configs);
	nat->stats.sccp.conn = counter_alloc("nat.sccp.conn");
	nat->stats.sccp.calls = counter_alloc("nat.sccp.calls");
	nat->stats.bsc.reconn = counter_alloc("nat.bsc.conn");
	nat->stats.bsc.auth_fail = counter_alloc("nat.bsc.auth_fail");
	nat->stats.msc.reconn = counter_alloc("nat.msc.conn");
	nat->msc_ip = talloc_strdup(nat, "127.0.0.1");
	nat->msc_port = 5000;
	nat->auth_timeout = 2;
	nat->ping_timeout = 20;
	nat->pong_timeout = 5;
	return nat;
}

void bsc_nat_set_msc_ip(struct bsc_nat *nat, const char *ip)
{
	if (nat->msc_ip)
		talloc_free(nat->msc_ip);
	nat->msc_ip = talloc_strdup(nat, ip);
}

struct bsc_connection *bsc_connection_alloc(struct bsc_nat *nat)
{
	struct bsc_connection *con = talloc_zero(nat, struct bsc_connection);
	if (!con)
		return NULL;

	con->nat = nat;
	write_queue_init(&con->write_queue, 100);
	return con;
}

struct bsc_config *bsc_config_alloc(struct bsc_nat *nat, const char *token, unsigned int lac)
{
	struct bsc_config *conf = talloc_zero(nat, struct bsc_config);
	if (!conf)
		return NULL;

	conf->token = talloc_strdup(conf, token);
	conf->lac = lac;
	conf->nr = nat->num_bsc;
	conf->nat = nat;

	llist_add_tail(&conf->entry, &nat->bsc_configs);
	++nat->num_bsc;

	conf->stats.sccp.conn = counter_alloc("nat.bsc.sccp.conn");
	conf->stats.sccp.calls = counter_alloc("nat.bsc.sccp.calls");
	conf->stats.net.reconn = counter_alloc("nat.bsc.net.reconnects");

	return conf;
}

void sccp_connection_destroy(struct sccp_connections *conn)
{
	LOGP(DNAT, LOGL_DEBUG, "Destroy 0x%x <-> 0x%x mapping for con %p\n",
	     sccp_src_ref_to_int(&conn->real_ref),
	     sccp_src_ref_to_int(&conn->patched_ref), conn->bsc);
	bsc_mgcp_dlcx(conn);
	llist_del(&conn->list_entry);
	talloc_free(conn);
}

struct bsc_connection *bsc_nat_find_bsc(struct bsc_nat *nat, struct msgb *msg, int *lac_out)
{
	struct bsc_connection *bsc;
	int data_length;
	const u_int8_t *data;
	struct tlv_parsed tp;
	int i = 0;

	*lac_out = -1;

	if (!msg->l3h || msgb_l3len(msg) < 3) {
		LOGP(DNAT, LOGL_ERROR, "Paging message is too short.\n");
		return NULL;
	}

	tlv_parse(&tp, gsm0808_att_tlvdef(), msg->l3h + 3, msgb_l3len(msg) - 3, 0, 0);
	if (!TLVP_PRESENT(&tp, GSM0808_IE_CELL_IDENTIFIER_LIST)) {
		LOGP(DNAT, LOGL_ERROR, "No CellIdentifier List inside paging msg.\n");
		return NULL;
	}

	data_length = TLVP_LEN(&tp, GSM0808_IE_CELL_IDENTIFIER_LIST);
	data = TLVP_VAL(&tp, GSM0808_IE_CELL_IDENTIFIER_LIST);

	/* No need to try a different BSS */
	if (data[0] == CELL_IDENT_BSS) {
		return NULL;
	} else if (data[0] != CELL_IDENT_LAC) {
		LOGP(DNAT, LOGL_ERROR, "Unhandled cell ident discrminator: %d\n", data[0]);
		return NULL;
	}

	/* Currently we only handle one BSC */
	for (i = 1; i < data_length - 1; i += 2) {
		unsigned int _lac = ntohs(*(unsigned int *) &data[i]);
		*lac_out = _lac;
		llist_for_each_entry(bsc, &nat->bsc_connections, list_entry) {
			if (!bsc->cfg)
				continue;
			if (!bsc->authenticated || _lac != bsc->cfg->lac)
				continue;

			return bsc;
		}
	}

	return NULL;
}

int bsc_write_mgcp(struct bsc_connection *bsc, const u_int8_t *data, unsigned int length)
{
	struct msgb *msg;

	if (length > 4096 - 128) {
		LOGP(DINP, LOGL_ERROR, "Can not send message of that size.\n");
		return -1;
	}

	msg = msgb_alloc_headroom(4096, 128, "to-bsc");
	if (!msg) {
		LOGP(DINP, LOGL_ERROR, "Failed to allocate memory for BSC msg.\n");
		return -1;
	}

	/* copy the data */
	msg->l3h = msgb_put(msg, length);
	memcpy(msg->l3h, data, length);

        return bsc_write(bsc, msg, NAT_IPAC_PROTO_MGCP);
}

int bsc_write(struct bsc_connection *bsc, struct msgb *msg, int proto)
{
	/* prepend the header */
	ipaccess_prepend_header(msg, proto);

	if (write_queue_enqueue(&bsc->write_queue, msg) != 0) {
		LOGP(DINP, LOGL_ERROR, "Failed to enqueue the write.\n");
		msgb_free(msg);
		return -1;
	}

	return 0;
}

/* apply white/black list */
static int auth_imsi(struct bsc_connection *bsc, const char *mi_string)
{
	/*
	 * Now apply blacklist/whitelist of the BSC and the NAT.
	 * 1.) Reject if the IMSI is not allowed at the BSC
	 * 2.) Allow directly if the IMSI is allowed at the BSC
	 * 3.) Reject if the IMSI not allowed at the global level.
	 * 4.) Allow directly if the IMSI is allowed at the global level
	 */

	/* 1. BSC deny */
	if (bsc->cfg->imsi_deny) {
		if (regexec(&bsc->cfg->imsi_deny_re, mi_string, 0, NULL, 0) == 0) {
			LOGP(DNAT, LOGL_ERROR,
			     "Filtering %s by imsi_deny.\n", mi_string);
			return -2;
		}
	}

	/* 2. BSC allow */
	if (bsc->cfg->imsi_allow) {
		if (regexec(&bsc->cfg->imsi_allow_re, mi_string, 0, NULL, 0) == 0)
			return 0;
	}

	/* 3. NAT deny */
	if (bsc->nat->imsi_deny) {
		if (regexec(&bsc->nat->imsi_deny_re, mi_string, 0, NULL, 0) == 0) {
			LOGP(DNAT, LOGL_ERROR,
			     "Filtering %s by nat imsi_deny.\n", mi_string);
			return -3;
		}
	}

	return 0;
}

static int _cr_check_loc_upd(struct bsc_connection *bsc, uint8_t *data, unsigned int length)
{
	u_int8_t mi_type;
	struct gsm48_loc_upd_req *lu;
	char mi_string[GSM48_MI_SIZE];

	if (length < sizeof(*lu)) {
		LOGP(DNAT, LOGL_ERROR,
		     "LU does not fit. Length is %d \n", length);
		return -1;
	}

	lu = (struct gsm48_loc_upd_req *) data;
	mi_type = lu->mi[0] & GSM_MI_TYPE_MASK;

	/*
	 * We can only deal with the IMSI. This will fail for a phone that
	 * will send the TMSI of a previous network to us.
	 */
	if (mi_type != GSM_MI_TYPE_IMSI)
		return 0;

	gsm48_mi_to_string(mi_string, sizeof(mi_string), lu->mi, lu->mi_len);
	return auth_imsi(bsc, mi_string);
}

static int _cr_check_cm_serv_req(struct bsc_connection *bsc, uint8_t *data, unsigned int length)
{
	char mi_string[GSM48_MI_SIZE];
	struct gsm48_service_request *req;

	/* unfortunately in Phase1 the classmark2 length is variable */
	uint8_t classmark2_len;
	uint8_t *classmark2;
	uint8_t mi_len;
	uint8_t *mi;
	uint8_t mi_type;

	if (length < sizeof(*req)) {
		LOGP(DNAT, LOGL_ERROR,
		     "CM Serv Req does not fit. Length is %d\n", length);
		return -1;
	}

	req = (struct gsm48_service_request *) data;
	classmark2_len = ((uint8_t *) &req->classmark)[0];
	if (length < 2 + classmark2_len) {
		LOGP(DNAT, LOGL_ERROR,
		     "Classmark2 does not fit. cml: %d\n", classmark2_len);
		return -1;
	}

	classmark2 = ((uint8_t *) &req->classmark) + 1;
	mi_len = *(classmark2 + classmark2_len);
	if (length < 3 + classmark2_len + mi_len) {
		LOGP(DNAT, LOGL_ERROR,
		    "MI does not fit length: %d vs. %d\n",
		     length, 3 + classmark2_len + mi_len);
		return -1;
	}

	mi = (classmark2 + classmark2_len + 1);
	mi_type = mi[0] & GSM_MI_TYPE_MASK;

	/* we have to let the TMSI or such pass */
	if (mi_type != GSM_MI_TYPE_IMSI)
		return 0;

	gsm48_mi_to_string(mi_string, sizeof(mi_string), mi, mi_len);
	return auth_imsi(bsc, mi_string);
}

static int _cr_check_pag_resp(struct bsc_connection *bsc, uint8_t *data, unsigned int length)
{
	struct gsm48_pag_resp *resp;
	char mi_string[GSM48_MI_SIZE];
	u_int8_t mi_type;

	if (length < sizeof(*resp)) {
		LOGP(DNAT, LOGL_ERROR, "PAG RESP does not fit. Length was %d.\n", length);
		return -1;
	}

	resp = (struct gsm48_pag_resp *) data;
	if (gsm48_paging_extract_mi(resp, length, mi_string, &mi_type) < 0) {
		LOGP(DNAT, LOGL_ERROR, "Failed to extract the MI.\n");
		return -1;
	}

	/* we need to let it pass for now */
	if (mi_type != GSM_MI_TYPE_IMSI)
		return 0;

	return auth_imsi(bsc, mi_string);
}

/* Filter out CR data... */
int bsc_nat_filter_sccp_cr(struct bsc_connection *bsc, struct msgb *msg, struct bsc_nat_parsed *parsed)
{
	struct tlv_parsed tp;
	struct gsm48_hdr *hdr48;
	int hdr48_len;
	int len;

	if (parsed->gsm_type != BSS_MAP_MSG_COMPLETE_LAYER_3) {
		LOGP(DNAT, LOGL_ERROR,
		     "Rejecting CR message due wrong GSM Type %d\n", parsed->gsm_type);
		return -1;
	}

	/* the parsed has had some basic l3 length check */
	len = msg->l3h[1];
	if (msgb_l3len(msg) - 3 < len) {
		LOGP(DNAT, LOGL_ERROR,
		     "The CR Data has not enough space...\n");
		return -1;
	}

	msg->l4h = &msg->l3h[3];
	len -= 1;

	tlv_parse(&tp, gsm0808_att_tlvdef(), msg->l4h, len, 0, 0);

	if (!TLVP_PRESENT(&tp, GSM0808_IE_LAYER_3_INFORMATION)) {
		LOGP(DNAT, LOGL_ERROR, "CR Data does not contain layer3 information.\n");
		return -1;
	}

	hdr48_len = TLVP_LEN(&tp, GSM0808_IE_LAYER_3_INFORMATION);

	if (hdr48_len < sizeof(*hdr48)) {
		LOGP(DNAT, LOGL_ERROR, "GSM48 header does not fit.\n");
		return -1;
	}

	hdr48 = (struct gsm48_hdr *) TLVP_VAL(&tp, GSM0808_IE_LAYER_3_INFORMATION);

	if (hdr48->proto_discr == GSM48_PDISC_MM &&
	    hdr48->msg_type == GSM48_MT_MM_LOC_UPD_REQUEST) {
		return _cr_check_loc_upd(bsc, &hdr48->data[0], hdr48_len - sizeof(*hdr48));
	} else if (hdr48->proto_discr == GSM48_PDISC_MM &&
		  hdr48->msg_type == GSM48_MT_MM_CM_SERV_REQ) {
		return _cr_check_cm_serv_req(bsc, &hdr48->data[0], hdr48_len - sizeof(*hdr48));
	} else if (hdr48->proto_discr == GSM48_PDISC_RR &&
		   hdr48->msg_type == GSM48_MT_RR_PAG_RESP) {
		return _cr_check_pag_resp(bsc, &hdr48->data[0], hdr48_len - sizeof(*hdr48));
	} else {
		LOGP(DNAT, LOGL_ERROR, "Unknown GSM48 content: proto: %d msg: %d\n",
		     hdr48->proto_discr, hdr48->msg_type);
		return -1;
	}
}

void bsc_parse_reg(void *ctx, regex_t *reg, char **imsi, int argc, const char **argv)
{
	if (*imsi) {
		talloc_free(*imsi);
		*imsi = NULL;
	}
	regfree(reg);

	if (argc > 0) {
		*imsi = talloc_strdup(ctx, argv[0]);
		regcomp(reg, argv[0], 0);
	}
}
