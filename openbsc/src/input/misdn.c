/* OpenBSC Abis input driver for mISDNuser */

/* (C) 2008-2009 by Harald Welte <laforge@gnumonks.org>
 * (C) 2009 by Holger Hans Peter Freyther <zecke@selfish.org>
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
#include <mISDNif.h>

//#define AF_COMPATIBILITY_FUNC
//#include <compat_af_isdn.h>
#define AF_ISDN 34
#define PF_ISDN AF_ISDN

#include <openbsc/select.h>
#include <openbsc/msgb.h>
#include <openbsc/debug.h>
#include <openbsc/gsm_data.h>
#include <openbsc/abis_nm.h>
#include <openbsc/abis_rsl.h>
#include <openbsc/subchan_demux.h>
#include <openbsc/e1_input.h>
#include <openbsc/talloc.h>

#define TS1_ALLOC_SIZE	300

struct prim_name {
	unsigned int prim;
	const char *name;
};

const struct prim_name prim_names[] = {
	{ PH_CONTROL_IND, "PH_CONTROL_IND" },
	{ PH_DATA_IND, "PH_DATA_IND" },
	{ PH_DATA_CNF, "PH_DATA_CNF" },
	{ PH_ACTIVATE_IND, "PH_ACTIVATE_IND" },
	{ DL_ESTABLISH_IND, "DL_ESTABLISH_IND" },
	{ DL_ESTABLISH_CNF, "DL_ESTABLISH_CNF" },
	{ DL_RELEASE_IND, "DL_RELEASE_IND" },
	{ DL_RELEASE_CNF, "DL_RELEASE_CNF" },
	{ DL_DATA_IND, "DL_DATA_IND" },
	{ DL_UNITDATA_IND, "DL_UNITDATA_IND" },
	{ DL_INFORMATION_IND, "DL_INFORMATION_IND" },
	{ MPH_ACTIVATE_IND, "MPH_ACTIVATE_IND" },
	{ MPH_DEACTIVATE_IND, "MPH_DEACTIVATE_IND" },
};

const char *get_prim_name(unsigned int prim)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(prim_names); i++) {
		if (prim_names[i].prim == prim)
			return prim_names[i].name;
	}

	return "UNKNOWN";
}

static int handle_ts1_read(struct bsc_fd *bfd)
{
	struct e1inp_line *line = bfd->data;
	unsigned int ts_nr = bfd->priv_nr;
	struct e1inp_ts *e1i_ts = &line->ts[ts_nr-1];
	struct e1inp_sign_link *link;
	struct msgb *msg = msgb_alloc(TS1_ALLOC_SIZE, "mISDN TS1");
	struct sockaddr_mISDN l2addr;
	struct mISDNhead *hh;
	socklen_t alen;
	int ret;

	if (!msg)
		return -ENOMEM;

	hh = (struct mISDNhead *) msg->data;

	alen = sizeof(l2addr);
	ret = recvfrom(bfd->fd, msg->data, 300, 0,
		       (struct sockaddr *) &l2addr, &alen);
	if (ret < 0) {
		fprintf(stderr, "recvfrom error  %s\n", strerror(errno));
		return ret;
	}

	if (alen != sizeof(l2addr)) {
		fprintf(stderr, "%s error len\n", __func__);
		return -EINVAL;
	}

	msgb_put(msg, ret);

	DEBUGP(DMI, "alen =%d, dev(%d) channel(%d) sapi(%d) tei(%d)\n",
		alen, l2addr.dev, l2addr.channel, l2addr.sapi, l2addr.tei);

	DEBUGP(DMI, "<= len = %d, prim(0x%x) id(0x%x): %s\n",
		ret, hh->prim, hh->id, get_prim_name(hh->prim));

	switch (hh->prim) {
	case DL_INFORMATION_IND:
		/* mISDN tells us which channel number is allocated for this
		 * tuple of (SAPI, TEI). */
		DEBUGP(DMI, "DL_INFORMATION_IND: use channel(%d) sapi(%d) tei(%d) for now\n",
			l2addr.channel, l2addr.sapi, l2addr.tei);
		link = e1inp_lookup_sign_link(e1i_ts, l2addr.tei, l2addr.sapi);
		if (!link) {
			DEBUGPC(DMI, "mISDN message for unknown sign_link\n");
			msgb_free(msg);
			return -EINVAL;
		}
		/* save the channel number in the driver private struct */
		link->driver.misdn.channel = l2addr.channel;
		break;
	case DL_ESTABLISH_IND:
		DEBUGP(DMI, "DL_ESTABLISH_IND: channel(%d) sapi(%d) tei(%d)\n",
		l2addr.channel, l2addr.sapi, l2addr.tei);
		ret = e1inp_event(e1i_ts, EVT_E1_TEI_UP, l2addr.tei, l2addr.sapi);
		break;
	case DL_RELEASE_IND:
		DEBUGP(DMI, "DL_RELEASE_IND: channel(%d) sapi(%d) tei(%d)\n",
		l2addr.channel, l2addr.sapi, l2addr.tei);
		ret = e1inp_event(e1i_ts, EVT_E1_TEI_DN, l2addr.tei, l2addr.sapi);
		break;
	case DL_DATA_IND:
	case DL_UNITDATA_IND:
		msg->l2h = msg->data + MISDN_HEADER_LEN;
		DEBUGP(DMI, "RX: %s\n", hexdump(msgb_l2(msg), ret - MISDN_HEADER_LEN));
		ret = e1inp_rx_ts(e1i_ts, msg, l2addr.tei, l2addr.sapi);
		break;
	case PH_ACTIVATE_IND:
		DEBUGP(DMI, "PH_ACTIVATE_IND: channel(%d) sapi(%d) tei(%d)\n",
		l2addr.channel, l2addr.sapi, l2addr.tei);
		break;
	case PH_DEACTIVATE_IND:
		DEBUGP(DMI, "PH_DEACTIVATE_IND: channel(%d) sapi(%d) tei(%d)\n",
		l2addr.channel, l2addr.sapi, l2addr.tei);
		break;
	default:
		break;
	}
	return ret;
}

static int ts_want_write(struct e1inp_ts *e1i_ts)
{
	/* We never include the mISDN B-Channel FD into the
	 * writeset, since it doesn't support poll() based
	 * write flow control */		
	if (e1i_ts->type == E1INP_TS_TYPE_TRAU)
		return 0;

	e1i_ts->driver.misdn.fd.when |= BSC_FD_WRITE;

	return 0;
}

static void timeout_ts1_write(void *data)
{
	struct e1inp_ts *e1i_ts = (struct e1inp_ts *)data;

	/* trigger write of ts1, due to tx delay timer */
	ts_want_write(e1i_ts);
}

static int handle_ts1_write(struct bsc_fd *bfd)
{
	struct e1inp_line *line = bfd->data;
	unsigned int ts_nr = bfd->priv_nr;
	struct e1inp_ts *e1i_ts = &line->ts[ts_nr-1];
	struct e1inp_sign_link *sign_link;
	struct sockaddr_mISDN sa;
	struct msgb *msg;
	struct mISDNhead *hh;
	u_int8_t *l2_data;
	int ret;

	bfd->when &= ~BSC_FD_WRITE;

	/* get the next msg for this timeslot */
	msg = e1inp_tx_ts(e1i_ts, &sign_link);
	if (!msg) {
		/* no message after tx delay timer */
		return 0;
	}

	l2_data = msg->data;

	/* prepend the mISDNhead */
	hh = (struct mISDNhead *) msgb_push(msg, sizeof(*hh));
	hh->prim = DL_DATA_REQ;

	DEBUGP(DMI, "TX TEI(%d) SAPI(%d): %s\n", sign_link->tei,
		sign_link->sapi, hexdump(l2_data, msg->len - MISDN_HEADER_LEN));

	/* construct the sockaddr */
	sa.family = AF_ISDN;
	sa.sapi = sign_link->sapi;
	sa.dev = sign_link->tei;
	sa.channel = sign_link->driver.misdn.channel;

	ret = sendto(bfd->fd, msg->data, msg->len, 0,
		     (struct sockaddr *)&sa, sizeof(sa));
	if (ret < 0)
		fprintf(stderr, "%s sendto failed %d\n", __func__, ret);
	msgb_free(msg);

	/* set tx delay timer for next event */
	e1i_ts->sign.tx_timer.cb = timeout_ts1_write;
	e1i_ts->sign.tx_timer.data = e1i_ts;
	bsc_schedule_timer(&e1i_ts->sign.tx_timer, 0, 50000);

	return ret;
}

#define BCHAN_TX_GRAN	160
/* write to a B channel TS */
static int handle_tsX_write(struct bsc_fd *bfd)
{
	struct e1inp_line *line = bfd->data;
	unsigned int ts_nr = bfd->priv_nr;
	struct e1inp_ts *e1i_ts = &line->ts[ts_nr-1];
	struct mISDNhead *hh;
	u_int8_t tx_buf[BCHAN_TX_GRAN + sizeof(*hh)];
	struct subch_mux *mx = &e1i_ts->trau.mux;
	int ret;

	hh = (struct mISDNhead *) tx_buf;
	hh->prim = PH_DATA_REQ;

	subchan_mux_out(mx, tx_buf+sizeof(*hh), BCHAN_TX_GRAN);

	DEBUGP(DMIB, "BCHAN TX: %s\n",
		hexdump(tx_buf+sizeof(*hh), BCHAN_TX_GRAN));

	ret = send(bfd->fd, tx_buf, sizeof(*hh) + BCHAN_TX_GRAN, 0);
	if (ret < sizeof(*hh) + BCHAN_TX_GRAN)
		DEBUGP(DMIB, "send returns %d instead of %u\n", ret,
			sizeof(*hh) + BCHAN_TX_GRAN);

	return ret;
}

#define TSX_ALLOC_SIZE 4096
/* FIXME: read from a B channel TS */
static int handle_tsX_read(struct bsc_fd *bfd)
{
	struct e1inp_line *line = bfd->data;
	unsigned int ts_nr = bfd->priv_nr;
	struct e1inp_ts *e1i_ts = &line->ts[ts_nr-1];
	struct msgb *msg = msgb_alloc(TSX_ALLOC_SIZE, "mISDN TSx");
	struct mISDNhead *hh;
	int ret;

	if (!msg)
		return -ENOMEM;

	hh = (struct mISDNhead *) msg->data;

	ret = recv(bfd->fd, msg->data, TSX_ALLOC_SIZE, 0);
	if (ret < 0) {
		fprintf(stderr, "recvfrom error  %s\n", strerror(errno));
		return ret;
	}

	msgb_put(msg, ret);

	if (hh->prim != PH_CONTROL_IND)
		DEBUGP(DMIB, "<= BCHAN len = %d, prim(0x%x) id(0x%x): %s\n",
			ret, hh->prim, hh->id, get_prim_name(hh->prim));

	switch (hh->prim) {
	case PH_DATA_IND:
		msg->l2h = msg->data + MISDN_HEADER_LEN;
		DEBUGP(DMIB, "BCHAN RX: %s\n",
			hexdump(msgb_l2(msg), ret - MISDN_HEADER_LEN));
		ret = e1inp_rx_ts(e1i_ts, msg, 0, 0);
		break;
	case PH_ACTIVATE_IND:
	case PH_DATA_CNF:
		/* physical layer indicates that data has been sent,
		 * we thus can send some more data */
		ret = handle_tsX_write(bfd);
	default:
		break;
	}
	/* FIXME: why do we free signalling msgs in the caller, and trau not? */
	msgb_free(msg);

	return ret;
}

/* callback from select.c in case one of the fd's can be read/written */
static int misdn_fd_cb(struct bsc_fd *bfd, unsigned int what)
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
	case E1INP_TS_TYPE_TRAU:
		if (what & BSC_FD_READ)
			rc = handle_tsX_read(bfd);
		/* We never include the mISDN B-Channel FD into the
		 * writeset, since it doesn't support poll() based
		 * write flow control */		
		break;
	default:
		fprintf(stderr, "unknown E1 TS type %u\n", e1i_ts->type);
		break;
	}

	return rc;
}

static int activate_bchan(struct e1inp_line *line, int ts, int act)
{
	struct mISDNhead hh;
	int ret;
	unsigned int idx = ts-1;
	struct e1inp_ts *e1i_ts = &line->ts[idx];
	struct bsc_fd *bfd = &e1i_ts->driver.misdn.fd;

	fprintf(stdout, "activate bchan\n");
	if (act)
		hh.prim = PH_ACTIVATE_REQ;
	else
		hh.prim = PH_DEACTIVATE_REQ;

	hh.id = MISDN_ID_ANY;
	ret = sendto(bfd->fd, &hh, sizeof(hh), 0, NULL, 0);
	if (ret < 0) {
		fprintf(stdout, "could not send ACTIVATE_RQ %s\n",
			strerror(errno));
	}

	return ret;
}

struct e1inp_driver misdn_driver = {
	.name = "mISDNuser",
	.want_write = ts_want_write,
};

static int mi_e1_setup(struct e1inp_line *line, int release_l2)
{
	int ts, ret;

	/* TS0 is CRC4, don't need any fd for it */
	for (ts = 1; ts < NUM_E1_TS; ts++) {
		unsigned int idx = ts-1;
		struct e1inp_ts *e1i_ts = &line->ts[idx];
		struct bsc_fd *bfd = &e1i_ts->driver.misdn.fd;
		struct sockaddr_mISDN addr;

		bfd->data = line;
		bfd->priv_nr = ts;
		bfd->cb = misdn_fd_cb;

		switch (e1i_ts->type) {
		case E1INP_TS_TYPE_NONE:
			continue;
			break;
		case E1INP_TS_TYPE_SIGN:
			bfd->fd = socket(PF_ISDN, SOCK_DGRAM, ISDN_P_LAPD_NT);
			bfd->when = BSC_FD_READ;
			break;
		case E1INP_TS_TYPE_TRAU:
			bfd->fd = socket(PF_ISDN, SOCK_DGRAM, ISDN_P_B_RAW);
			/* We never include the mISDN B-Channel FD into the
	 		* writeset, since it doesn't support poll() based
	 		* write flow control */		
			bfd->when = BSC_FD_READ;
			break;
		}

		if (bfd->fd < 0) {
			fprintf(stderr, "%s could not open socket %s\n",
				__func__, strerror(errno));
			return bfd->fd;
		}

		memset(&addr, 0, sizeof(addr));
		addr.family = AF_ISDN;
		addr.dev = line->num;
		switch (e1i_ts->type) {
		case E1INP_TS_TYPE_SIGN:
			addr.channel = 0;
			/* SAPI not supported yet in kernel */
			//addr.sapi = e1inp_ts->sign.sapi;
			addr.sapi = 0;
			addr.tei = GROUP_TEI;
			break;
		case E1INP_TS_TYPE_TRAU:
			addr.channel = ts;
			break;
		default:
			DEBUGP(DMI, "unsupported E1 TS type: %u\n",
				e1i_ts->type);
			break;
		}

		ret = bind(bfd->fd, (struct sockaddr *) &addr, sizeof(addr));
		if (ret < 0) {
			fprintf(stderr, "could not bind l2 socket %s\n",
				strerror(errno));
			return -EIO;
		}

		if (e1i_ts->type == E1INP_TS_TYPE_SIGN) {
			ret = ioctl(bfd->fd, IMCLEAR_L2, &release_l2);
			if (ret < 0) {
				fprintf(stderr, "could not send IOCTL IMCLEAN_L2 %s\n", strerror(errno));
				return -EIO;
			}
		}

		/* FIXME: only activate B-Channels once we start to
		 * use them to conserve CPU power */
		if (e1i_ts->type == E1INP_TS_TYPE_TRAU)
			activate_bchan(line, ts, 1);

		ret = bsc_register_fd(bfd);
		if (ret < 0) {
			fprintf(stderr, "could not register FD: %s\n",
				strerror(ret));
			return ret;
		}
	}

	return 0;
}

int mi_e1_line_update(struct e1inp_line *line)
{
	struct mISDN_devinfo devinfo;
	int sk, ret, cnt;

	if (!line->driver) {
		/* this must be the first update */
		line->driver = &misdn_driver;
	} else {
		/* this is a subsequent update */
		/* FIXME: first close all sockets */
		fprintf(stderr, "incremental line updates not supported yet\n");
		return 0;
	}

	if (line->driver != &misdn_driver)
		return -EINVAL;

	/* open the ISDN card device */
	sk = socket(PF_ISDN, SOCK_RAW, ISDN_P_BASE);
	if (sk < 0) {
		fprintf(stderr, "%s could not open socket %s\n",
			__func__, strerror(errno));
		return sk;
	}

	ret = ioctl(sk, IMGETCOUNT, &cnt);
	if (ret) {
		fprintf(stderr, "%s error getting interf count: %s\n",
			__func__, strerror(errno));
		close(sk);
		return -ENODEV;
	}
	//DEBUGP(DMI,"%d device%s found\n", cnt, (cnt==1)?"":"s");
	printf("%d device%s found\n", cnt, (cnt==1)?"":"s");
#if 1
	devinfo.id = line->num;
	ret = ioctl(sk, IMGETDEVINFO, &devinfo);
	if (ret < 0) {
		fprintf(stdout, "error getting info for device %d: %s\n",
			line->num, strerror(errno));
		return -ENODEV;
	}
	fprintf(stdout, "        id:             %d\n", devinfo.id);
	fprintf(stdout, "        Dprotocols:     %08x\n", devinfo.Dprotocols);
	fprintf(stdout, "        Bprotocols:     %08x\n", devinfo.Bprotocols);
	fprintf(stdout, "        protocol:       %d\n", devinfo.protocol);
	fprintf(stdout, "        nrbchan:        %d\n", devinfo.nrbchan);
	fprintf(stdout, "        name:           %s\n", devinfo.name);
#endif

	if (!(devinfo.Dprotocols & (1 << ISDN_P_NT_E1))) {
		fprintf(stderr, "error: card is not of type E1 (NT-mode)\n");
		return -EINVAL;
	}

	ret = mi_e1_setup(line, 1);
	if (ret)
		return ret;

	return 0;
}

static __attribute__((constructor)) void on_dso_load_sms(void)
{
	/* register the driver with the core */
	e1inp_driver_register(&misdn_driver);
}
