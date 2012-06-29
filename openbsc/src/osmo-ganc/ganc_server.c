/* Handling of actual UMA/GAN protocol as per TS 44.318 */

/* (C) 2012 by Harald Welte <laforge@gnumonks.org>
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

#include <unistd.h>
#include <stdio.h>
#include <errno.h>

#include <arpa/inet.h>

#include <osmocom/core/socket.h>
#include <osmocom/core/talloc.h>
#include <osmocom/core/msgb.h>
#include <osmocom/gsm/tlv.h>
#include <osmocom/gsm/protocol/gsm_44_318.h>
#include <osmocom/gsm/gan.h>
#include <osmocom/gsm/gsm48.h>

#include "conn.h"
#include "ganc_data.h"

static struct tlv_definition tlv_att_def;

static void push_rc_csr_hdr(struct msgb *msg, uint8_t pdisc, uint8_t msgt)
{
	struct gan_rc_csr_hdr *gh = 
		(struct gan_rc_csr_hdr *) msgb_push(msg, sizeof(*gh));

	gh->pdisc = pdisc;
	gh->msg_type = msgt;
}

static struct msgb *unc_msgb_alloc(void)
{
	return msgb_alloc_headroom(1024+128, 128, "GANC Tx");
}

static int unc_peer_tx(struct gan_peer *peer, struct msgb *msg)
{
	struct gan_rc_csr_hdr *gh = (struct gan_rc_csr_hdr*) msg->data;

	/* compute and fill-in length */
	msg->l2h = msg->data;
	gh->len = htons(msgb_l2len(msg)-2);

	if (peer->gan_release == 0) {
		/* shomehow old pre-GAN UMA doesn't have RC */
		if (gh->pdisc == GA_PDISC_RC)
			gh->pdisc = GA_PDISC_CSR;
	}
	
	return osmo_conn_enqueue(peer->conn, msg);
}

static uint8_t *msgb_tlv_be16_put(struct msgb *msg, uint8_t tag, uint16_t val)
{
	uint16_t _val = htons(val);
	return msgb_tlv_put(msg, tag, 2, (uint8_t *) &_val);
}

static void build_gan_cch_desc(struct gan_cch_desc_ie *ie, struct ganc_bts *bts)
{
	struct ganc_net *net = bts->net;

	/* properly initialize to zero */
	memset(&ie, 0, sizeof(ie));

	ie->ecmc = 0;	/* Early Classmark allowed */
	ie->nmo = 0;	/* NMO 1 */
	if (net->gprs.mode != 0)
		ie->gprs = 0;
	else
		ie->gprs = 1;	/* No GPRS */
	ie->dtm = 0;	/* No Dual Transfer Mode */
	ie->att = 1;	/* IMSI attach/detach shall be used */
	ie->mscr = 1;	/* Release 99 onwards */
	ie->t3212 = net->timer[T3212];
	ie->rac = bts->routing_area_code;
	ie->sgsnr = 1;	/* Release 99 onwards */
	ie->ecmp = net->emergency_gan_preferred;
	ie->re = 1;	/* No call re-esetablishment */
	ie->pfcfm = 0;	/* No PFC */
	ie->tgecs = 1;	/* Permit UTRAN classmark change */
	if (!net->emergency_gan_preferred)
		ie->access_class[0] |= 0x4; /* No emergency calls */
}

/* FIXME: move to libosmocore */
static void gsm48_cell_desc(struct gsm48_cell_desc *cd, uint8_t bsic, uint16_t arfcn)
{
	cd->ncc = (bsic >> 3) & 0x07;
	cd->bcc = bsic & 0x07;
	cd->arfcn_hi = arfcn >> 8;
	cd->arfcn_lo = arfcn & 0xff;
}

/* 10.1.6: GA-RC REGISTER ACCEPT */
static int tx_unc_reg_acc(struct gan_peer *peer)
{
	struct msgb *msg = unc_msgb_alloc();
	struct gsm48_loc_area_id lai;
	struct gsm48_cell_desc cd;
	struct gan_cch_desc_ie ie;
	struct ganc_bts *bts = peer->bts;
	struct ganc_net *net = bts->net;
	uint8_t gan_band = 0x02; /* GSM 1800 */

	printf("<- GA-RC REGISTER ACCEPT\n");

	if (!msg)
		return -ENOMEM;

	gsm48_cell_desc(&cd, bts->bsic, bts->arfcn);
	gsm48_generate_lai(&lai, net->country_code, net->network_code,
			   bts->location_area_code);
	build_gan_cch_desc(&ie, bts);

	push_rc_csr_hdr(msg, GA_PDISC_RC, GA_MT_RC_REGISTER_ACCEPT);

	msgb_tlv_be16_put(msg, GA_IE_GERAN_CELL_ID, bts->cell_identity);
	msgb_tlv_put(msg, GA_IE_LAC, sizeof(lai), (uint8_t *) &lai);
	msgb_tlv_put(msg, GA_IE_GANC_CTRL_CH_DESC, sizeof(ie), (uint8_t *) &ie);
	msgb_tlv_be16_put(msg, GA_IE_TU3910_TIMER, net->timer[TU3910]);
	msgb_tlv_be16_put(msg, GA_IE_TU3906_TIMER, net->timer[TU3906]);
	msgb_tlv_put(msg, GA_IE_GAN_BAND, 1, &gan_band);
	msgb_tlv_be16_put(msg, GA_IE_TU3920_TIMER, net->timer[TU3920]);
	msgb_tlv_put(msg, GA_IE_GANC_CELL_DESC, sizeof(cd), (uint8_t *) &cd);

	if (net->gprs.mode != 0) {
		msgb_tlv_be16_put(msg, GA_IE_TU4001_TIMER, net->timer[TU4001]);
		msgb_tlv_be16_put(msg, GA_IE_TU4003_TIMER, net->timer[TU4003]);
	}

	return unc_peer_tx(peer, msg);
}

static int push_fqdn_or_ip(struct msgb *msg, const char *host,
			   uint8_t fqdn_att, uint8_t ip_att)
{
	struct in_addr ia;
	int rc;

	rc = inet_aton(host, &ia);
	if (rc == 0) {
		/* it is not an IP address */
		msgb_tlv_put(msg, fqdn_att, strlen(host)+1,
			     (uint8_t *) host);
	} else {
		uint8_t buf[5];

		buf[0] = 0x21; /* Type: IPv4 */
		memcpy(buf+1, &ia, 4);
		msgb_tlv_put(msg, ip_att, sizeof(buf), buf);
	}

	return rc;
}

/* 10.1.3: GA-RC DISCOVERY ACCEPT */
static int tx_unc_disco_acc(struct gan_peer *peer, const char *segw_host,
			    const char *ganc_host)
{
	struct msgb *msg = unc_msgb_alloc();

	printf("<- GA-RC DISCOVERY ACCEPT\n");

	if (!msg)
		return -ENOMEM;

	push_rc_csr_hdr(msg, GA_PDISC_RC, GA_MT_RC_DISCOVERY_ACCEPT);
	push_fqdn_or_ip(msg, segw_host,
			GA_IE_DEF_SEGW_FQDN, GA_IE_DEF_SEGW_IP);
	push_fqdn_or_ip(msg, ganc_host,
			GA_IE_DEF_GANC_FQDN, GA_IE_DEF_GANC_IP);

	return unc_peer_tx(peer, msg);
}

/* 10.1.13 GA-CSR REQUEST ACCEPT */
static int tx_csr_request_acc(struct gan_peer *peer)
{
	struct msgb *msg = unc_msgb_alloc();

	printf("<- GA-CSR REQUEST ACCEPT\n");

	if (!msg)
		return -ENOMEM;

	push_rc_csr_hdr(msg, GA_PDISC_CSR, GA_MT_CSR_REQUEST_ACCEPT);

	peer->csr_state = GA_S_CSR_DEDICATED;

	return unc_peer_tx(peer, msg);
}

/* 10.1.2 GA-RC DISCOVERY REQUEST */
static int rx_rc_discovery_req(struct gan_peer *peer, struct msgb *msg,
				struct tlv_parsed *tp)
{
	if (TLVP_PRESENT(tp, GA_IE_MI)) {
		gsm48_mi_to_string(peer->imsi, sizeof(peer->imsi),
				   TLVP_VAL(tp, GA_IE_MI), TLVP_LEN(tp, GA_IE_MI));
		printf("\tfrom %s\n", peer->imsi);
	}
	if (TLVP_PRESENT(tp, GA_IE_GAN_RELEASE_IND))
		peer->gan_release = *TLVP_VAL(tp, GA_IE_GAN_RELEASE_IND);
	if (TLVP_PRESENT(tp, GA_IE_GAN_CM) && TLVP_LEN(tp, GA_IE_GAN_CM) >=2)
		memcpy(peer->gan_classmark, TLVP_VAL(tp, GA_IE_GAN_CM), 2);

	return tx_unc_disco_acc(peer, "segw.uma.sysmocom.de",
				"laforge.gnumonks.org");
}

/* 10.1.5 GA-RC REGISTER REQUEST */
static int rx_rc_register_req(struct gan_peer *peer, struct msgb *msg,
			      struct tlv_parsed *tp)
{
	if (TLVP_PRESENT(tp, GA_IE_MI)) {
		gsm48_mi_to_string(peer->imsi, sizeof(peer->imsi),
				   TLVP_VAL(tp, GA_IE_MI), TLVP_LEN(tp, GA_IE_MI));
		printf("\tfrom %s\n", peer->imsi);
	}
	if (TLVP_PRESENT(tp, GA_IE_GAN_RELEASE_IND))
		peer->gan_release = *TLVP_VAL(tp, GA_IE_GAN_RELEASE_IND);
	if (TLVP_PRESENT(tp, GA_IE_GAN_CM) && TLVP_LEN(tp, GA_IE_GAN_CM) >=2)
		memcpy(peer->gan_classmark, TLVP_VAL(tp, GA_IE_GAN_CM), 2);

	return tx_unc_reg_acc(peer);
}

/* 10.1.12 GA CSR REQUEST */
static int rx_csr_request(struct gan_peer *peer, struct msgb *msg,
			  struct tlv_parsed *tp)
{
	return tx_csr_request_acc(peer);
}

/* 10.1.37 GA-CSR CLEAR REQUEST */
static int rx_csr_clear_req(struct gan_peer *peer, struct msgb *msg,
			    struct tlv_parsed *tp)
{
	/* FIXME: request core network to release all dedicated resources */
	return 0;
}

/* 10.1.20 GA-CSR RELEASE COMPLETE */
static int rx_csr_rel_compl(struct gan_peer *peer, struct msgb *msg,
			    struct tlv_parsed *tp)
{
	peer->csr_state = GA_S_CSR_IDLE;

	return 0;
}

/* 10.1.9 GA-RC DEREGISTER */
static int rx_rc_deregister(struct gan_peer *peer, struct msgb *msg,
			    struct tlv_parsed *tp)
{
	/* Release all resources, MS will TCP disconnect */
	return 0;
}

/* 10.1.23 GA-CSR UL DIRECT XFER */
static int rx_csr_ul_direct_xfer(struct gan_peer *peer, struct msgb *msg,
				 struct tlv_parsed *tp)
{
	uint8_t sapi = 0;

	if (TLVP_PRESENT(tp, GA_IE_SAPI_ID))
		sapi = *TLVP_VAL(tp, GA_IE_SAPI_ID) & 0x7;

	if (TLVP_PRESENT(tp, GA_IE_L3_MSG))
		printf("\tL3(%u): %s\n", sapi,
		       osmo_hexdump(TLVP_VAL(tp, GA_IE_L3_MSG),
				    TLVP_LEN(tp, GA_IE_L3_MSG)));
	return 0;
}

/* 10.1.27 GA-CSR CLASSMARK CHANGE */
static int rx_csr_cm_chg(struct gan_peer *peer, struct msgb *msg,
			 struct tlv_parsed *tp)
{
	if (TLVP_PRESENT(tp, GA_IE_MS_CLASSMARK2) &&
	    TLVP_LEN(tp, GA_IE_MS_CLASSMARK2) == 3)
		memcpy(peer->cm2, TLVP_VAL(tp, GA_IE_MS_CLASSMARK2), 3);

	if (TLVP_PRESENT(tp, GA_IE_MS_CLASSMARK3)) {
		peer->cm3.len = TLVP_LEN(tp, GA_IE_MS_CLASSMARK3);
		peer->cm3.val = talloc_memdup(peer,
					TLVP_VAL(tp, GA_IE_MS_CLASSMARK3),
					peer->cm3.len);
	}
	return 0;
}

static int rx_unc_rc_csr(struct gan_peer *peer, struct msgb *msg,
			 struct gan_rc_csr_hdr *gh, struct tlv_parsed *tp)
{
	switch (gh->msg_type) {
	case GA_MT_RC_DISCOVERY_REQUEST:
		return rx_rc_discovery_req(peer, msg, tp);
	case GA_MT_RC_REGISTER_REQUEST:
		return rx_rc_register_req(peer, msg, tp);
	case GA_MT_CSR_REQUEST:
		return rx_csr_request(peer, msg, tp);
	case GA_MT_CSR_CLEAR_REQ:
		return rx_csr_clear_req(peer, msg, tp);
	case GA_MT_CSR_RELEASE_COMPL:
		return rx_csr_rel_compl(peer, msg, tp);
	case GA_MT_RC_DEREGISTER:
		return rx_rc_deregister(peer, msg, tp);
	case GA_MT_CSR_UL_DIRECT_XFER:
		return rx_csr_ul_direct_xfer(peer, msg, tp);
	case GA_MT_CSR_CM_CHANGE:
		return rx_csr_cm_chg(peer, msg, tp);
	case GA_MT_RC_KEEPALIVE:
		break;
	default:
		printf("\tunhandled!\n");
		break;
	}

	return 0;
}

static int rx_unc_msg(struct gan_peer *peer, struct msgb *msg)
{
	struct gan_rc_csr_hdr *gh = (struct gan_rc_csr_hdr *) msg->l2h;
	struct tlv_parsed tp;
	int len = ntohs(gh->len);
	int rc;

	printf("-> (%u) %s\n", gh->pdisc, get_value_string(gan_msgt_vals, gh->msg_type));

	if (len > 2) {
		rc = tlv_parse(&tp, &tlv_att_def, gh->data, len - 2, 0, 0);
		if (rc < 0)
			fprintf(stderr, "error %d during tlv_parse\n", rc);
	} else
		memset(&tp, 0, sizeof(tp));

	switch (gh->pdisc) {
	case GA_PDISC_RC:
	case GA_PDISC_CSR:
		return rx_unc_rc_csr(peer, msg, gh, &tp);
	case GA_PDISC_PSR:
	default:
		break;
	}

	return 0;
}

static int unc_read_cb(struct osmo_conn *conn)
{
	struct msgb *msg;
	int rc, len;

	msg = msgb_alloc_headroom(1024 + 128, 128, "UNC Read");
	if (!msg)
		return -ENOMEM;

	rc = read(conn->queue.bfd.fd, msg->data, 2);
	if (rc <= 0) {
		msgb_free(msg);
		osmo_conn_close(conn);
		return rc;
	} else if (rc != 2) {
		msgb_free(msg);
		fprintf(stderr, "unable to read 2 length bytes\n");
		return -EIO;
	}
	msg->l2h = msg->data;
	msgb_put(msg, rc);

	len = ntohs(*(uint16_t *)msg->data);

	rc = read(conn->queue.bfd.fd, msg->data+2, len);
	if (rc < 0) {
		msgb_free(msg);
		osmo_conn_close(conn);
		return rc;
	} else if (rc != len) {
		msgb_free(msg);
		fprintf(stderr, "unable to read %u bytes following len\n", len);
		return -EIO;
	}

	msgb_put(msg, rc);

	return rx_unc_msg(conn->priv, msg);
}

static void unc_accept_cb(struct osmo_conn *conn)
{
	struct gan_peer *peer = talloc_zero(conn, struct gan_peer);
	printf("accepted connection\n");

	/* FIXME: later we may have different BTS with different ARFCN/BSIC/... */
	peer->bts = g_ganc_bts;
	peer->conn = conn;
	conn->priv = peer;
}


int ganc_server_start(const char *host, uint16_t port)
{
	struct osmo_link *link;
	int i;

	for (i = 0; i < ARRAY_SIZE(tlv_att_def.def); i++)
		tlv_att_def.def[i].type = TLV_TYPE_TLV;

	link = osmo_link_create(NULL, host, port, unc_read_cb, 10);
	if (!link)
		return -ENOMEM;

	osmo_link_listen(link, unc_accept_cb);

	return 0;
}
