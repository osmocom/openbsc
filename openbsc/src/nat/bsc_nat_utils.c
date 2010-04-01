
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
	return nat;
}

struct bsc_connection *bsc_connection_alloc(struct bsc_nat *nat)
{
	struct bsc_connection *con = talloc_zero(nat, struct bsc_connection);
	if (!con)
		return NULL;

	con->nat = nat;
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

	llist_add(&conf->entry, &nat->bsc_configs);
	++nat->num_bsc;

	return conf;
}

void sccp_connection_destroy(struct sccp_connections *conn)
{
	LOGP(DNAT, LOGL_DEBUG, "Destroy 0x%x <-> 0x%x mapping for con %p\n",
	     sccp_src_ref_to_int(&conn->real_ref),
	     sccp_src_ref_to_int(&conn->patched_ref), conn->bsc);
	bsc_mgcp_clear(conn);
	llist_del(&conn->list_entry);
	talloc_free(conn);
}

struct bsc_connection *bsc_nat_find_bsc(struct bsc_nat *nat, struct msgb *msg)
{
	struct bsc_connection *bsc;
	int data_length;
	const u_int8_t *data;
	struct tlv_parsed tp;
	int i = 0;

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
	if (data[0] !=  CELL_IDENT_LAC) {
		LOGP(DNAT, LOGL_ERROR, "Unhandled cell ident discrminator: %c\n", data[0]);
		return NULL;
	}

	/* Currently we only handle one BSC */
	for (i = 1; i < data_length - 1; i += 2) {
		unsigned int _lac = ntohs(*(unsigned int *) &data[i]);
		llist_for_each_entry(bsc, &nat->bsc_connections, list_entry) {
			if (!bsc->authenticated || _lac != bsc->lac)
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

        return bsc_write_mgcp_msg(bsc, msg);
}

int bsc_write_mgcp_msg(struct bsc_connection *bsc, struct msgb *msg)
{
	/* prepend the header */
	ipaccess_prepend_header(msg, NAT_IPAC_PROTO_MGCP);

	if (write_queue_enqueue(&bsc->write_queue, msg) != 0) {
		LOGP(DINP, LOGL_ERROR, "Failed to enqueue the write.\n");
		msgb_free(msg);
		return -1;
	}

	return 0;
}
