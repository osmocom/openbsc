
#include <unistd.h>
#include <stdio.h>
#include <errno.h>

#include <arpa/inet.h>

#include <osmocom/core/socket.h>
#include <osmocom/core/talloc.h>
#include <osmocom/core/msgb.h>
#include <osmocom/gsm/tlv.h>
#include <osmocom/gsm/protocol/gsm_44_318.h>

#include "conn.h"
#include "ganc_data.h"

static struct msgb *unc_msgb_alloc(void)
{
	return msgb_alloc_headroom(1024+128, 128, "GANC Tx");
}

static int unc_peer_tx(struct gan_peer *peer, struct msgb *msg)
{
	return osmo_conn_enqueue(peer->conn, msg);
}

static int tx_unc_disco_acc(struct gan_peer *peer, const char *segw_host,
			    const char *ganc_host)
{
	struct msgb *msg = unc_msgb_alloc();
	struct gan_rc_csr_hdr *gh = (struct gan_rc_csr_hdr*) msg->l2h;

	if (!msg)
		return -ENOMEM;

	gh->pdisc = GA_PDISC_RC;
	gh->msg_type = GA_MT_RC_DISCOVERY_ACCEPT;

	msgb_tlv_put(msg, GA_IE_DEF_SEGW_FQDN, strlen(segw_host)+1, (uint8_t *) segw_host);
	msgb_tlv_put(msg, GA_IE_DEF_GANC_FQDN, strlen(ganc_host)+1, (uint8_t *) ganc_host);

	return unc_peer_tx(peer, msg);
}

static int rx_unc_discovery_req(struct gan_peer *peer, struct msgb *msg,
				struct gan_rc_csr_hdr *gh)
{
	struct tlv_parsed tp;

	tlv_parse(&tp, &tvlv_att_def, gh->data, msg->len - sizeof(*gh), 0, 0);

	if (TLVP_PRESENT(&tp, GA_IE_MI)) {
		char mi_string[32];
		gsm48_mi_to_string(&mi_string, sizeof(mi_string),
				   TLVP_VAL(&tp, GA_IE_MI), TLVP_LEN(&tp, GA_IE_MI));

		printf("DISCOVERY from %s\n", mi_string);
	}

	return tx_unc_disco_acc(peer, "segw.uma.sysmocom.de",
				"ganc.uma.sysmocom.de");
}

static int rx_unc_rc(struct gan_peer *peer, struct msgb *msg, struct gan_rc_csr_hdr *gh)
{
	switch (gh->msg_type) {
	case GA_MT_RC_DISCOVERY_REQUEST:
		return rx_unc_discovery_req(peer, msg, gh);
	case GA_MT_RC_REGISTER_REQUEST:
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
		return rx_unc_rc(peer, msg, gh);
	case GA_PDISC_CSR:
	case GA_PDISC_PSR:
	default:
		break;
	}

	return 0;
}

static int unc_read_cb(struct osmo_conn *conn)
{
	struct msgb *msg;
	struct gan_rc_csr_hdr *gh;
	int rc;

	msg = msgb_alloc_headroom(1024 + 128, 128, "UNC Read");
	if (!msg)
		return -ENOMEM;

	gh = (struct gan_rc_csr_hdr *) msg->data;
	rc = read(conn->queue.bfd.fd, msg->data, sizeof(gh->len));
	if (rc <= 0) {
		msgb_free(msg);
		return rc;
	} else if (rc != sizeof(gh->len)) {
		msgb_free(msg);
		return -EIO;
	}
	msg->l2h = msg->data;
	msgb_put(msg, rc);

	rc = read(conn->queue.bfd.fd, msg->data, ntohs(gh->len));
	if (rc <= 0)
		return rc;
	else if (rc != ntohs(gh->len)) {
		msgb_free(msg);
		return -EIO;
	}

	msgb_put(msg, rc);

	return rx_unc_msg(conn->priv, msg);
}

static void unc_accept_cb(struct osmo_conn *conn)
{
	struct gan_peer *peer = talloc_zero(conn, struct gan_peer);
	printf("accepted connection\n");

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
