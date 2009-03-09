/* OpenBSC Abis input driver for ip.access */

/* (C) 2009 by Harald Welte <laforge@gnumonks.org>
 *
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

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <time.h>
#include <sys/fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>

#include <openbsc/select.h>
#include <openbsc/msgb.h>
#include <openbsc/debug.h>
#include <openbsc/gsm_data.h>
#include <openbsc/abis_nm.h>
#include <openbsc/abis_rsl.h>
#include <openbsc/subchan_demux.h>
#include <openbsc/e1_input.h>
#include <openbsc/ipaccess.h>

/* data structure for one E1 interface with A-bis */
struct ia_e1_handle {
	struct bsc_fd listen_fd;
	struct bsc_fd rsl_listen_fd;
};

#define TS1_ALLOC_SIZE	300

static const u_int8_t pong[] = { 0, 1, IPAC_PROTO_IPACCESS, IPAC_MSGT_PONG };
static const u_int8_t id_ack[] = { 0, 1, IPAC_PROTO_IPACCESS, IPAC_MSGT_ID_ACK };

static int ipaccess_rcvmsg(struct msgb *msg, int fd)
{
	u_int8_t msg_type = *(msg->l2h);
	int ret = 0;

	switch (msg_type) {
	case IPAC_MSGT_PING:
		ret = write(fd, pong, sizeof(pong));
		break;
	case IPAC_MSGT_PONG:
		DEBUGP(DMI, "PONG!\n");
		break;
	case IPAC_MSGT_ID_RESP:
		DEBUGP(DMI, "ID_RESP\n");
		break;
	case IPAC_MSGT_ID_ACK:
		DEBUGP(DMI, "ID_ACK? -> ACK!\n");
		ret = write(fd, id_ack, sizeof(id_ack));
		break;	
	}

	msgb_free(msg);
	return 0;
}

/* FIXME: this is per BTS */
static int oml_up = 0;
static int rsl_up = 0;

static int handle_ts1_read(struct bsc_fd *bfd)
{
	struct e1inp_line *line = bfd->data;
	unsigned int ts_nr = bfd->priv_nr;
	struct e1inp_ts *e1i_ts = &line->ts[ts_nr-1];
	struct e1inp_sign_link *link;
	struct msgb *msg = msgb_alloc(TS1_ALLOC_SIZE);
	struct ipaccess_head *hh;
	int ret;

	if (!msg)
		return -ENOMEM;

	/* first read our 3-byte header */
	hh = (struct ipaccess_head *) msg->data;
	ret = recv(bfd->fd, msg->data, 3, 0);
	if (ret < 0) {
		fprintf(stderr, "recv error  %s\n", strerror(errno));
		return ret;
	}
	if (ret == 0) {
		fprintf(stderr, "BTS disappeared, dead socket\n");
		e1inp_event(e1i_ts, EVT_E1_TEI_DN, 0, IPAC_PROTO_RSL);
		e1inp_event(e1i_ts, EVT_E1_TEI_DN, 0, IPAC_PROTO_OML);
		bsc_unregister_fd(bfd);
		close(bfd->fd);
		bfd->fd = -1;
	}
	msgb_put(msg, ret);

	/* then read te length as specified in header */
	msg->l2h = msg->data + sizeof(*hh);
	ret = recv(bfd->fd, msg->l2h, hh->len, 0);
	if (ret < hh->len) {
		fprintf(stderr, "short read!\n");
		msgb_free(msg);
		return -EIO;
	}
	msgb_put(msg, ret);

	if (hh->proto == IPAC_PROTO_IPACCESS)
		return ipaccess_rcvmsg(msg, bfd->fd);

	DEBUGP(DMI, "RX %u: %s\n", ts_nr, hexdump(msgb_l2(msg), ret));

	link = e1inp_lookup_sign_link(e1i_ts, 0, hh->proto);
	if (!link) {
		printf("no matching signalling link for hh->proto=0x%02x\n", hh->proto);
		msgb_free(msg);
		return -EIO;
	}
	msg->trx = link->trx;

	switch (hh->proto) {
	case IPAC_PROTO_RSL:
		if (!rsl_up) {
			e1inp_event(e1i_ts, EVT_E1_TEI_UP, 0, IPAC_PROTO_RSL);
			rsl_up = 1;
		}
		ret = abis_rsl_rcvmsg(msg);
		break;
	case IPAC_PROTO_OML:
		if (!oml_up) {
			e1inp_event(e1i_ts, EVT_E1_TEI_UP, 0, IPAC_PROTO_OML);
			oml_up = 1;
		}
		ret = abis_nm_rcvmsg(msg);
		break;
	default:
		DEBUGP(DMI, "Unknown IP.access protocol proto=0x%02x\n", hh->proto);
		msgb_free(msg);
		break;
	}
	return ret;
}

static int handle_ts1_write(struct bsc_fd *bfd)
{
	struct e1inp_line *line = bfd->data;
	unsigned int ts_nr = bfd->priv_nr;
	struct e1inp_ts *e1i_ts = &line->ts[ts_nr-1];
	struct e1inp_sign_link *sign_link;
	struct msgb *msg;
	struct ipaccess_head *hh;
	u_int8_t *l2_data;
	int ret;

	/* get the next msg for this timeslot */
	msg = e1inp_tx_ts(e1i_ts, &sign_link);
	if (!msg) {
		bfd->when &= ~BSC_FD_WRITE;
		return 0;
	}

	l2_data = msg->data;

	/* prepend the mISDNhead */
	hh = (struct ipaccess_head *) msgb_push(msg, sizeof(*hh));
	hh->zero = 0;
	hh->len = msg->len - sizeof(*hh);

	switch (sign_link->type) {
	case E1INP_SIGN_OML:
		hh->proto = IPAC_PROTO_OML;
		break;
	case E1INP_SIGN_RSL:
		hh->proto = IPAC_PROTO_RSL;
		break;
	default:
		msgb_free(msg);
		return -EINVAL;
	}

	DEBUGP(DMI, "TX %u: %s\n", ts_nr, hexdump(l2_data, hh->len));

	ret = send(bfd->fd, msg->data, msg->len, 0);
	msgb_free(msg);
	usleep(100000);

	return ret;
}


/* callback from select.c in case one of the fd's can be read/written */
static int ipaccess_fd_cb(struct bsc_fd *bfd, unsigned int what)
{
	struct e1inp_line *line = bfd->data;
	unsigned int ts_nr = bfd->priv_nr;
	unsigned int idx = ts_nr-1;
	struct e1inp_ts *e1i_ts = &line->ts[idx];
	int rc = 0;

	switch (e1i_ts->type) {
	case E1INP_TS_TYPE_SIGN:
		if (what & BSC_FD_READ)
			rc = handle_ts1_read(bfd);
		if (what & BSC_FD_WRITE)
			rc = handle_ts1_write(bfd);
		break;
#if 0
	case E1INP_TS_TYPE_TRAU:
		if (what & BSC_FD_READ)
			rc = handle_tsX_read(bfd);
		/* We never include the mISDN B-Channel FD into the
		 * writeset, since it doesn't support poll() based
		 * write flow control */		
		break;
#endif
	default:
		fprintf(stderr, "unknown E1 TS type %u\n", e1i_ts->type);
		break;
	}

	return rc;
}


static int ts_want_write(struct e1inp_ts *e1i_ts)
{
	/* We never include the mISDN B-Channel FD into the
	 * writeset, since it doesn't support poll() based
	 * write flow control */		
	if (e1i_ts->type == E1INP_TS_TYPE_TRAU)
		return 0;

	e1i_ts->driver.ipaccess.fd.when |= BSC_FD_WRITE;

	return 0;
}

struct e1inp_driver ipaccess_driver = {
	.name = "ip.access",
	.want_write = ts_want_write,
};

static int ia_e1_setup(struct e1inp_line *line)
{
	return 0;
}

static int listen_fd_cb(struct bsc_fd *listen_bfd, unsigned int what)
{
	struct e1inp_line *line = listen_bfd->data;
	int ret;

	if (what & BSC_FD_READ) {
		int idx = 0;
		struct e1inp_ts *e1i_ts = &line->ts[idx];
		struct bsc_fd *bfd = &e1i_ts->driver.ipaccess.fd;
		struct sockaddr_in sa;
		socklen_t sa_len = sizeof(sa);

		if (bfd->fd) {
			printf("dumping old OML fd\n");
			if (bfd->fd != -1) {
				bsc_unregister_fd(bfd);
				close(bfd->fd);
			}
		}
		bfd->fd = accept(listen_bfd->fd, (struct sockaddr *) &sa, &sa_len);
		if (bfd->fd < 0) {
			perror("accept");
			return bfd->fd;
		}
		printf("accept()ed new OML fd\n");
		bfd->data = line;
		bfd->priv_nr = 1;
		bfd->cb = ipaccess_fd_cb;
		bfd->when = BSC_FD_READ;
		ret = bsc_register_fd(bfd);
		if (ret < 0) {
			fprintf(stderr, "could not register FD\n");
			return ret;
		}
	}
	return 0;
}

static int rsl_listen_fd_cb(struct bsc_fd *listen_bfd, unsigned int what)
{
	struct e1inp_line *line = listen_bfd->data;
	int ret;

	if (what & BSC_FD_READ) {
		int idx = 1;
		struct e1inp_ts *e1i_ts = &line->ts[idx];
		struct bsc_fd *bfd = &e1i_ts->driver.ipaccess.fd;
		struct sockaddr_in sa;
		socklen_t sa_len = sizeof(sa);

		if (bfd->fd) {
			printf("dumping old RSL fd\n");
			if (bfd->fd != -1) {
				bsc_unregister_fd(bfd);
				close(bfd->fd);
			}
		}
		bfd->fd = accept(listen_bfd->fd, (struct sockaddr *) &sa, &sa_len);
		if (bfd->fd < 0) {
			perror("accept");
			return bfd->fd;
		}
		printf("accept()ed new RSL fd\n");
		bfd->data = line;
		bfd->priv_nr = 2;
		bfd->cb = ipaccess_fd_cb;
		bfd->when = BSC_FD_READ;
		ret = bsc_register_fd(bfd);
		if (ret < 0) {
			fprintf(stderr, "could not register FD\n");
			return ret;
		}
	}
	return 0;
}

static int make_sock(struct bsc_fd *bfd, u_int16_t port,
		     struct e1inp_line *line,
		     int (*cb)(struct bsc_fd *fd, unsigned int what))
{
	struct sockaddr_in addr;
	int ret, on = 1;
	
	bfd->fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	bfd->cb = cb;
	bfd->when = BSC_FD_READ;
	bfd->data = line;

	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);
	addr.sin_addr.s_addr = INADDR_ANY;

	setsockopt(bfd->fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));

	ret = bind(bfd->fd, (struct sockaddr *) &addr, sizeof(addr));
	if (ret < 0) {
		fprintf(stderr, "could not bind l2 socket %s\n",
			strerror(errno));
		return -EIO;
	}

	ret = listen(bfd->fd, 1);
	if (ret < 0) {
		perror("listen");
		return ret;
	}
	
	ret = bsc_register_fd(bfd);
	if (ret < 0) {
		perror("register_listen_fd");
		return ret;
	}
	return 0;
}

int ipaccess_setup(struct e1inp_line *line)
{
	struct ia_e1_handle *e1h;
	int ret;

	/* register the driver with the core */
	/* FIXME: do this in the plugin initializer function */
	ret = e1inp_driver_register(&ipaccess_driver);
	if (ret)
		return ret;

	/* create the actual line instance */
	/* FIXME: do this independent of driver registration */
	e1h = malloc(sizeof(*e1h));
	memset(e1h, 0, sizeof(*e1h));

	line->driver = &ipaccess_driver;
	line->driver_data = e1h;

	/* Listen for OML connections */
	ret = make_sock(&e1h->listen_fd, 3002, line, listen_fd_cb);

	/* Listen for RSL connections */
	ret = make_sock(&e1h->rsl_listen_fd, 3003, line, rsl_listen_fd_cb);

	ret = ia_e1_setup(line);
	if (ret)
		return ret;

	return e1inp_line_register(line);
}
