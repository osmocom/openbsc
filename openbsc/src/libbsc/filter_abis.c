#include <sys/socket.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

#include <osmocom/core/talloc.h>
#include <osmocom/core/logging.h>
#include <openbsc/filter_abis.h>
#include <openbsc/abis_rsl.h>
#include <openbsc/signal.h>
#include <openbsc/gsm_subscriber.h>
#include <openbsc/silent_call.h>

// copied from abis_rsl.c
#define RSL_ALLOC_SIZE		1024
#define RSL_ALLOC_HEADROOM	128

extern struct gsm_network *bsc_gsmnet;

static void *tall_filter_ctx;
static struct filter_connection *active_connection = NULL;
static struct llist_head tx_msg_list;

static int filter_new_connection(struct osmo_fd *fd, unsigned int what);

static struct osmo_fd server_socket = {
	.when	    = BSC_FD_READ,
	.cb	    = filter_new_connection,
	.priv_nr    = 0,
};

int filter_is_active() {
	//	LOGP(0, LOGL_DEBUG, "filter %sactive\n", (active_connection ? "" : "in"));
	return(active_connection ? 1 : 0);
}

static int silentcall_cbfn(unsigned int subsys, unsigned int signal,
				void *handler_data, void *signal_data)
{
	struct scall_signal_data *sigdata = signal_data;

	LOGP(0, LOGL_DEBUG, "silentcall callback called\n");

        if(!active_connection)
        	return 0;

	struct msgb *newmsg = msgb_alloc_headroom(RSL_ALLOC_SIZE, RSL_ALLOC_HEADROOM, "RSL");
	if (!newmsg)
		return -ENOMEM;

	struct filter_head *fh;
	struct filter_silentcall_resp *fm;

	fh = (struct filter_head *) newmsg->data;
	msgb_put(newmsg, sizeof(*fh));
	fh->len = htons(sizeof(struct filter_silentcall_resp));
	fh->msg_type = FILTER_SILENT_CALL;

	fm = (struct filter_silentcall_resp *) newmsg->tail;
	msgb_put(newmsg, sizeof(*fm));

	fm->state = (uint8_t) signal;
	fm->scall_id = (uint8_t) ((int) sigdata->data & 0xff);

	if(signal == S_SCALL_SUCCESS) {
		fm->priv1 = sigdata->conn->lchan->ts->trx;
		fm->priv2 = sigdata->conn->lchan;
		fm->chan_nr = gsm_lchan2chan_nr(sigdata->conn->lchan);
	}

	msgb_enqueue(&tx_msg_list, newmsg);
	active_connection->fd.when |= BSC_FD_WRITE;

	return 0;
}

int filter_init(void *tall_ctx, void *priv, int port)
{
	struct sockaddr_in sock_addr;
	int fd, rc, on = 1;

	tall_filter_ctx = talloc_named_const(tall_ctx, 1,
					     "filter_connection");

	fd = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);

	if (fd < 0) {
		LOGP(0, LOGL_ERROR, "Filter interface socket creation failed\n");
		return fd;
	}

	setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));

	memset(&sock_addr, 0, sizeof(sock_addr));
	sock_addr.sin_family = AF_INET;
	sock_addr.sin_port = htons(port);
	sock_addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

	rc = bind(fd, (struct sockaddr*)&sock_addr, sizeof(sock_addr));
	if (rc < 0) {
		LOGP(0, LOGL_ERROR, "Filter interface failed to bind\n");
		close(fd);
		return rc;
	}

	rc = listen(fd, 0);
	if (rc < 0) {
		LOGP(0, LOGL_ERROR, "Filter interface failed to listen\n");
		close(fd);
		return rc;
	}

	server_socket.data = priv;
	server_socket.fd = fd;
	osmo_fd_register(&server_socket);

	INIT_LLIST_HEAD(&tx_msg_list);

	osmo_signal_register_handler(SS_SCALL, silentcall_cbfn, NULL);

	//LOGP(0, LOGL_DEBUG, "filter_init done\n");

	return 0;
}

int filter_send_msg(struct msgb *msg, int msg_type) {
	struct msgb *newmsg = msgb_alloc_headroom(RSL_ALLOC_SIZE, RSL_ALLOC_HEADROOM, "RSL");
	struct filter_head *fh;
	struct filter_msg *fm;
	int len = msgb_l2len(msg);

	LOGP(0, LOGL_DEBUG, "filter_send_msg called, msg has %d bytes, type %d\n", len, msg_type);

	if (!newmsg)
		return -ENOMEM;

	if (len < 0 || RSL_ALLOC_SIZE < len + sizeof(*fh)) {
		LOGP(0, LOGL_ERROR, "Can not send this packet. %d avail\n", RSL_ALLOC_SIZE);
		msgb_free(msg);
		msgb_free(newmsg);
		return -EIO;
	}

	fh = (struct filter_head *) newmsg->data;
	msgb_put(newmsg, sizeof(*fh));

	fh->len = htons(len + sizeof(struct filter_msg));
	fh->msg_type = msg_type;

	fm = (struct filter_msg *) newmsg->tail;
	msgb_put(newmsg, sizeof(*fm));
	fm->priv1 = msg->trx;
	fm->priv2 = msg->lchan;

	newmsg->l2h = newmsg->tail;

	memcpy(newmsg->l2h, msg->l2h, len);
	msgb_put(newmsg, len);

	msgb_free(msg);

	msgb_enqueue(&tx_msg_list, newmsg);
	active_connection->fd.when |= BSC_FD_WRITE;

	return 0;
}

static int filter_close_client()
{
	//LOGP(0, LOGL_DEBUG, "filter_close_client called\n");

	if(active_connection) {

		struct filter_connection *conn = active_connection;
		struct osmo_fd *fd = &conn->fd;

		LOGP(0, LOGL_DEBUG, "freeing resources\n");

		active_connection = NULL;

		close(fd->fd);
		osmo_fd_unregister(fd);

		talloc_free(conn);

	}
	return 0;
}

static struct msgb *filter_read_msg_from_socket(struct osmo_fd *bfd, int *error)
{
	struct msgb *msg = msgb_alloc_headroom(RSL_ALLOC_SIZE, RSL_ALLOC_HEADROOM, "RSL");
	struct filter_head *fh;
	int len, ret = 0;

	LOGP(0, LOGL_DEBUG, "filter_read_msg_from_socket called\n");

	if (!msg) {
		*error = -ENOMEM;
		return NULL;
	}

	/* first read our header */
	fh = (struct filter_head *) msg->data;
	ret = recv(bfd->fd, msg->data, sizeof(*fh), 0);
	if (ret == 0) {
		msgb_free(msg);
		*error = ret;
		return NULL;
	} else if (ret != sizeof(*fh)) {
		if (errno != EAGAIN)
			LOGP(0, LOGL_ERROR, "recv error %d %s\n", ret, strerror(errno));
		msgb_free(msg);
		*error = ret;
		return NULL;
	}

	msgb_put(msg, ret);

	/* then read the length as specified in header */
	len = ntohs(fh->len);

	//LOGP(0, LOGL_DEBUG, "msg has %d bytes\n", len);

	if (len < 0 || RSL_ALLOC_SIZE < len + sizeof(*fh)) {
		LOGP(0, LOGL_ERROR, "Can not read this packet. %d avail\n", RSL_ALLOC_SIZE);
		msgb_free(msg);
		*error = -EIO;
		return NULL;
	}

	ret = recv(bfd->fd, msg->tail, len, 0);
	if (ret < len) {
		LOGP(0, LOGL_ERROR, "short read! Got %d from %d\n", ret, len);
		msgb_free(msg);
		*error = -EIO;
		return NULL;
	}

	msgb_put(msg, ret);

	return msg;
}

static int process_silentcall_message(struct filter_silentcall_req *sc_req, struct osmo_fd *fd) {
	int rc = -1;

	LOGP(0, LOGL_DEBUG, "rcvd FILTER_SILENT_CALL msg for ext %s\n", (char *) sc_req->subscr_id);

	struct gsm_subscriber *subscr = subscr_get_by_extension(bsc_gsmnet, (char *) sc_req->subscr_id);
	if (!subscr) {
		LOGP(0, LOGL_ERROR, "subscriber for ext %s not found\n", (char *) sc_req->subscr_id);
		return rc;
	}

	if(sc_req->activate) {
		LOGP(0, LOGL_DEBUG, "starting silent call with id %d\n", sc_req->scall_id);
		rc = gsm_silent_call_start(subscr, (void *) ((int)sc_req->scall_id), sc_req->channel_type);
	} else {
		LOGP(0, LOGL_DEBUG, "stopping silent call\n");
		rc = gsm_silent_call_stop(subscr);
	}

        subscr_put(subscr);

	if (rc <= 0) {
		LOGP(0, LOGL_DEBUG, "silent call failed: %d\n", rc);
		return rc;
	}

	return rc;
}

static int route_message(struct msgb *msg) {
	struct filter_head *fh = (struct filter_head *) msg->data;
	int rc = -1;

	msgb_pull(msg, sizeof(struct filter_head));
	struct filter_msg *fm = (struct filter_msg *) msg->data;
	msg->trx = fm->priv1;
	msg->lchan = fm->priv2;

	// abis_rsl_sendmsg expects msgb->data == msgb->l2h
	msgb_pull(msg, sizeof(struct filter_msg));
	msg->l2h = msg->data;
	
	if(fh->msg_type == FILTER_UPLINK_MSG) {
		LOGP(0, LOGL_DEBUG, "routing uplink msg to _abis_rsl_rcvmsg\n");
		rc = _abis_rsl_rcvmsg(msg);
	} else if(fh->msg_type == FILTER_DOWNLINK_MSG) {
		LOGP(0, LOGL_DEBUG, "routing downlink msg to abis_rsl_sendmsg\n");
		rc = abis_rsl_sendmsg(msg);
	} else {
		LOGP(0, LOGL_ERROR, "unknown msg type %d\n", fh->msg_type);
		msgb_free(msg);
	}

	return rc;
}

static int client_data(struct osmo_fd *fd, unsigned int what)
{
	int rc = 0;

	LOGP(0, LOGL_DEBUG, "client_data called (%08x)\n", what);

	// new data from external application
	if (what & BSC_FD_READ) {

		struct msgb *msg = filter_read_msg_from_socket(fd, &rc);

		if(msg) {
			struct filter_head *fh = (struct filter_head *) msg->data;
			if(fh->msg_type == FILTER_SILENT_CALL) {
				msgb_pull(msg, sizeof(struct filter_head));
				struct filter_silentcall_req *sc_req = (struct filter_silentcall_req *) msg->data;
				msgb_pull(msg, sizeof(struct filter_silentcall_req));
				*(char *)msg->tail = 0;
				rc = process_silentcall_message(sc_req, fd);
				msgb_free(msg);
			} else {
				rc = route_message(msg);
			}
		// if we didn't get a msg _and_ there was an error,
		// assume the connection has been closed
		} else {
			// try to route all msgs that might have been
			// enqueued for sending already to their
			// original recipient
			LOGP(0, LOGL_INFO, "filter app went away, freeing resources\n");
			while((msg = msgb_dequeue(&tx_msg_list))) {
				route_message(msg);
			}
			filter_close_client();
		}
	}

	// send msgs to external app as soon as we can write
	if (what & BSC_FD_WRITE) {

		struct msgb *msg = msgb_dequeue(&tx_msg_list);

		if(msg) {
			//LOGP(0, LOGL_DEBUG, "sending new msg to filter app (len: %d)\n", msg->len);
			rc = send(fd->fd, msg->data, msg->len, 0);
			msgb_free(msg);
			if(rc > 0)
				rc = 0;
		} else {
			//LOGP(0, LOGL_DEBUG, "no more messages to send\n");
			fd->when &= ~BSC_FD_WRITE;
		}

	}

	return rc;
}

static int filter_new_connection(struct osmo_fd *fd, unsigned int what)
{
	struct filter_connection *connection;
	struct sockaddr_in sockaddr;
	socklen_t len = sizeof(sockaddr);
	int new_connection = accept(fd->fd, (struct sockaddr*)&sockaddr, &len);

	LOGP(0, LOGL_DEBUG, "new filter connection\n");

	if (new_connection < 0) {
		LOGP(0, LOGL_ERROR, "filter accept failed\n");
		return new_connection;
	}

	filter_close_client();

	connection = talloc_zero(tall_filter_ctx, struct filter_connection);
	connection->priv = fd->data;
	connection->fd.data = connection;
	connection->fd.fd = new_connection;
	connection->fd.when = BSC_FD_READ | BSC_FD_WRITE;
	connection->fd.cb = client_data;
	osmo_fd_register(&connection->fd);

	active_connection = connection;

	return 0;
}
