#include <openbsc/reg_proxy.h>
#include <openbsc/sip_client.h>

//#include <osmocom/abis/ipa.h>
//#include <osmocom/gsm/protocol/ipaccess.h>
#include <osmocom/core/msgb.h>

#include <openbsc/debug.h>

#include <errno.h>
#include <string.h>

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <time.h>
#include <sys/fcntl.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>

#include <openbsc/tcp_client.h>

//extern void *tall_reg_ctx;

//static void start_test_procedure(struct gprs_gsup_client *gsupc);

/*
static void gsup_client_send_ping(struct gprs_gsup_client *gsupc)
{
	struct msgb *msg = gprs_gsup_msgb_alloc();

	msg->l2h = msgb_put(msg, 1);
	msg->l2h[0] = IPAC_MSGT_PING;
	ipa_msg_push_header(msg, IPAC_PROTO_IPACCESS);
	ipa_client_conn_send(gsupc->link, msg);
}
*/

static int sip_client_connect(struct sip_client *sip_client)
{
	int rc;

	if (sip_client->is_connected)
		return 0;

	if (osmo_timer_pending(&sip_client->connect_timer)) {
		LOGP(DSUP, LOGL_DEBUG,
		     "SIP connect: connect timer already running\n");
		osmo_timer_del(&sip_client->connect_timer);
	}

	if (tcp_client_conn_clear_queue(sip_client->link) > 0)
		LOGP(DSUP, LOGL_DEBUG, "SIP connect: discarded stored messages\n");

	rc = tcp_client_conn_open(sip_client->link);

	if (rc >= 0) {
		LOGP(DSUP, LOGL_INFO, "SIP connecting to %s:%d\n",
		     sip_client->link->dst_addr, sip_client->link->dst_port);
		return 0;
	}

	LOGP(DSUP, LOGL_INFO, "SIP failed to connect to %s:%d: %s\n",
	     sip_client->link->dst_addr, sip_client->link->dst_port, strerror(-rc));

	if (rc == -EBADF || rc == -ENOTSOCK || rc == -EAFNOSUPPORT ||
	    rc == -EINVAL)
		return rc;

	osmo_timer_schedule(&sip_client->connect_timer, SIP_RECONNECT_INTERVAL, 0);

	LOGP(DSUP, LOGL_INFO, "Scheduled timer to retry SIP connect to %s:%d\n",
	     sip_client->link->dst_addr, sip_client->link->dst_port);

	return 0;
}

static void connect_timer_cb(void *sip_client_)
{
	struct sip_client *sip_client = sip_client_;

	if (sip_client->is_connected)
		return;

	sip_client_connect(sip_client);
}

static void sip_client_updown_cb(struct tcp_client_conn *link, int up)
{
	struct sip_client *sip_client = link->data;

	LOGP(DSUP, LOGL_INFO, "SIP link to %s:%d %s\n",
		     link->dst_addr, link->dst_port, up ? "UP" : "DOWN");

	sip_client->is_connected = up;

	if (up) {
		osmo_timer_del(&sip_client->connect_timer);
	} else {
		osmo_timer_schedule(&sip_client->connect_timer,
				    SIP_RECONNECT_INTERVAL, 0);
	}
}

static int sip_client_read_cb(struct tcp_client_conn *link, struct msgb *msg)
{
	//struct ipaccess_head *hh = (struct ipaccess_head *) msg->data;
	//struct ipaccess_head_ext *he = (struct ipaccess_head_ext *) msgb_l2(msg);
	printf("Recv sip message! len = %d\n", msg->data_len);
    struct sip_client *sip_client = (struct sip_client *)link->data;
	//int rc;

	//msg->l2h = &hh->data[0];

    OSMO_ASSERT(sip_client->read_cb != NULL);
    sip_client->read_cb(sip_client, msg);

	/* Not freeing msg here, because that must be done by the read_cb. */
	return 0;
}

/*
static void ping_timer_cb(void *gsupc_)
{
	struct gprs_gsup_client *gsupc = gsupc_;

	LOGP(DGPRS, LOGL_INFO, "GSUP ping callback (%s, %s PONG)\n",
	     gsupc->is_connected ? "connected" : "not connected",
	     gsupc->got_ipa_pong ? "got" : "didn't get");

	if (gsupc->got_ipa_pong) {
		start_test_procedure(gsupc);
		return;
	}

	LOGP(DGPRS, LOGL_NOTICE, "GSUP ping timed out, reconnecting\n");
	ipa_client_conn_close(gsupc->link);
	gsupc->is_connected = 0;

	gsup_client_connect(gsupc);
}
*/
/*
static void start_test_procedure(struct gprs_gsup_client *gsupc)
{
	gsupc->ping_timer.data = gsupc;
	gsupc->ping_timer.cb = &ping_timer_cb;

	gsupc->got_ipa_pong = 0;
	osmo_timer_schedule(&gsupc->ping_timer, GPRS_GSUP_PING_INTERVAL, 0);
	LOGP(DGPRS, LOGL_DEBUG, "GSUP sending PING\n");
	gsup_client_send_ping(gsupc);
}
*/
/*
int ipa_client_write_cb(struct ipa_client_conn *link)
{
	struct osmo_fd *ofd = link->ofd;
	struct msgb *msg;
	struct llist_head *lh;
	int ret;

	LOGP(DLINP, LOGL_DEBUG, "sending data\n");


	if (llist_empty(&link->tx_queue)) {
		ofd->when &= ~BSC_FD_WRITE;
		return 0;
	}
	lh = link->tx_queue.next;
	llist_del(lh);
	msg = llist_entry(lh, struct msgb, list);

	printf("ipa_client_write_cb sending data... msg->len= %d\n",  msg->len);

	ret = send(link->ofd->fd, msg->data, msg->len, 0);
	if (ret < 0) {
		if (errno == EPIPE || errno == ENOTCONN) {
			ipa_client_conn_close(link);
			if (link->updown_cb)
				link->updown_cb(link, 0);
		}
		LOGP(DLINP, LOGL_ERROR, "error to send\n");
		printf("ipa_client_write_cb error to send!!!! ret = %d errno = %d\n", ret, errno);
	}
	msgb_free(msg);
	printf("ipa_client_write_cb send OK ret = %d\n", ret);
	return 0;
}
*/
struct sip_client *sip_client_create(const char *src_ip, u_int16_t src_port,
                                     const char *dst_ip, u_int16_t dst_port,
                                          sip_read_cb_t read_cb, void *data)
{
	struct sip_client *sip_client;
	int rc;

	sip_client = talloc_zero(tall_reg_ctx, struct sip_client);
	OSMO_ASSERT(sip_client);

	sip_client->link = tcp_client_conn_create(sip_client,
					     0,
					     dst_ip, dst_port,
					     src_ip, src_port,
					     sip_client_updown_cb,
					     sip_client_read_cb,
					     NULL,
					     sip_client);
	if (!sip_client->link)
		goto failed;

	sip_client->connect_timer.data = sip_client;
	sip_client->connect_timer.cb = &connect_timer_cb;
	sip_client->dst_ip = dst_ip;
	sip_client->src_ip = src_ip;
	sip_client->dst_port = dst_port;
	sip_client->src_port = src_port;

	rc = sip_client_connect(sip_client);

	if (rc < 0)
		goto failed;

	sip_client->read_cb = read_cb;
	sip_client->data = data;

	return sip_client;

failed:
	sip_client_destroy(sip_client);
	return NULL;
}

void sip_client_destroy(struct sip_client *sip_client)
{
	osmo_timer_del(&sip_client->connect_timer);

	if (sip_client->link) {
		tcp_client_conn_close(sip_client->link);
		tcp_client_conn_destroy(sip_client->link);
		sip_client->link = NULL;
	}
	talloc_free(sip_client);
}

int sip_client_send(struct sip_client *sip_client, struct msgb *msg)
{
	if (!sip_client) {
		msgb_free(msg);
		return -ENOTCONN;
	}

	if (!sip_client->is_connected) {
		msgb_free(msg);
		return -EAGAIN;
	}

	//ipa_prepend_header_ext(msg, IPAC_PROTO_EXT_GSUP);
	//ipa_msg_push_header(msg, IPAC_PROTO_OSMO);
	printf(" TRY tcp_client_conn_send\n");

	tcp_client_conn_send(sip_client->link, msg);
	
	printf(" DONE tcp_client_conn_send\n");

	return 0;
}

struct msgb *sip_msgb_alloc(void)
{
	return msgb_alloc_headroom(400000, 64, __func__);
}
