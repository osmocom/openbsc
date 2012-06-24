
#include <unistd.h>
#include <stdio.h>
#include <errno.h>

#include <arpa/inet.h>

#include <osmocom/core/socket.h>
#include <osmocom/core/talloc.h>
#include <osmocom/core/msgb.h>
#include <osmocom/gsm/tlv.h>
#include <osmocom/gsm/protocol/gsm_44_318.h>
#include <osmocom/gsm/gsm48.h>

#include "conn.h"
#include "ganc_data.h"

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
		/* shomehow old pre-GAN UMA doesn't like RC */
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

static int tx_unc_disco_acc(struct gan_peer *peer, const char *segw_host,
			    const char *ganc_host)
{
	struct msgb *msg = unc_msgb_alloc();

	printf("<- GA-RC DISCOVERY ACCEPT\n");

	if (!msg)
		return -ENOMEM;

	push_rc_csr_hdr(msg, GA_PDISC_RC, GA_MT_RC_DISCOVERY_ACCEPT);

	msgb_tlv_put(msg, GA_IE_DEF_SEGW_FQDN, strlen(segw_host)+1, (uint8_t *) segw_host);
	msgb_tlv_put(msg, GA_IE_DEF_GANC_FQDN, strlen(ganc_host)+1, (uint8_t *) ganc_host);

	return unc_peer_tx(peer, msg);
}

static int rx_unc_discovery_req(struct gan_peer *peer, struct msgb *msg,
				struct gan_rc_csr_hdr *gh)
{
	struct tlv_parsed tp;
	int rc;

	printf("-> GA-RC DISCOVERY REQUEST\n");
	rc = tlv_parse(&tp, &tvlv_att_def, gh->data, htons(gh->len), 0, 0);
	if (rc < 0)
		fprintf(stderr, "error %d during tlv_parse\n", rc);

	if (TLVP_PRESENT(&tp, GA_IE_MI)) {
		char mi_string[32];
		gsm48_mi_to_string(mi_string, sizeof(mi_string),
				   TLVP_VAL(&tp, GA_IE_MI), TLVP_LEN(&tp, GA_IE_MI));

		printf("DISCOVERY from %s\n", mi_string);
	}

	return tx_unc_disco_acc(peer, "segw.uma.sysmocom.de",
				"laforge.gnumonks.org");
}

static int rx_unc_register_req(struct gan_peer *peer, struct msgb *msg,
			       struct gan_rc_csr_hdr *gh)
{
	printf("-> GA-RC REGISTER REQUEST\n");

	return tx_unc_reg_acc(peer);
}

static int rx_unc_rc(struct gan_peer *peer, struct msgb *msg, struct gan_rc_csr_hdr *gh)
{
	switch (gh->msg_type) {
	case GA_MT_RC_DISCOVERY_REQUEST:
		return rx_unc_discovery_req(peer, msg, gh);
	case GA_MT_RC_REGISTER_REQUEST:
		return rx_unc_register_req(peer, msg, gh);
	case GA_MT_RC_DEREGISTER:
		break;
	}

	return 0;
}

static int rx_unc_msg(struct gan_peer *peer, struct msgb *msg)
{
	struct gan_rc_csr_hdr *gh = (struct gan_rc_csr_hdr *) msg->l2h;

	printf("PDISC=%u TYPE=%u\n", gh->pdisc, gh->msg_type);

	switch (gh->pdisc) {
	case GA_PDISC_RC:
	case GA_PDISC_CSR:
		return rx_unc_rc(peer, msg, gh);
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

	link = osmo_link_create(NULL, host, port, unc_read_cb, 10);
	if (!link)
		return -ENOMEM;

	osmo_link_listen(link, unc_accept_cb);

	return 0;
}
