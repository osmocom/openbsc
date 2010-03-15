/* OpenBSC Abis input driver for DAHDI */

/* (C) 2008-2009 by Harald Welte <laforge@gnumonks.org>
 * (C) 2009 by Holger Hans Peter Freyther <zecke@selfish.org>
 * (C) 2010 by Digium and Matthew Fredrickson <creslin@digium.com>
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
#include <dahdi/user.h>

//#define AF_COMPATIBILITY_FUNC
//#include <compat_af_isdn.h>
#ifndef AF_ISDN
#define AF_ISDN 34
#define PF_ISDN AF_ISDN
#endif

#include <openbsc/select.h>
#include <openbsc/msgb.h>
#include <openbsc/debug.h>
#include <openbsc/gsm_data.h>
#include <openbsc/abis_nm.h>
#include <openbsc/abis_rsl.h>
#include <openbsc/subchan_demux.h>
#include <openbsc/e1_input.h>
#include <openbsc/talloc.h>

#include "lapd.h"

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
	struct msgb *msg = msgb_alloc(TS1_ALLOC_SIZE, "DAHDI TS1");
	struct sockaddr_mISDN l2addr;
	struct mISDNhead ah;
	struct mISDNhead *hh = &ah;
	int ret;

	if (!msg)
		return -ENOMEM;

	hh = (struct mISDNhead *) msg->data;

	ret = read(bfd->fd, msg->data, TS1_ALLOC_SIZE - 16);
	if (ret < 0) {
		perror("read ");
	}
	msgb_put(msg, ret - 2);
	if (ret <= 3) {
		perror("read ");
	}

	l2addr.sapi = msg->data[0] >> 2;
	l2addr.tei = msg->data[1] >> 1;

	DEBUGP(DMI, "<= len = %d, sapi(%d) tei(%d)",
		ret, l2addr.sapi, l2addr.tei);

	int		ilen;
	lapd_mph_type prim;
	uint8_t *idata = lapd_receive(msg->data, msg->len, &ilen, &prim, bfd);

	switch (prim) {
		case 0: break;
		case LAPD_MPH_ACTIVATE_IND: hh->prim = MPH_ACTIVATE_IND; break;
		case LAPD_MPH_DEACTIVATE_IND: hh->prim = MPH_DEACTIVATE_IND; break;
		case LAPD_DL_DATA_IND: hh->prim = DL_DATA_IND; break;
		case LAPD_DL_UNITDATA_IND: hh->prim = DL_UNITDATA_IND; break;
		default: printf("ERROR: unknown prim\n");
	};

	int pass_on = (prim != 0);

	if (!pass_on) {
		return 0;
	};

	//l2addr.sapi = msg->data[0] >> 2;
	//l2addr.tei = msg->data[1] >> 1;
	msgb_pull(msg, 2);

#if 0
	switch (hh->prim) {
	case DL_INFORMATION_IND:
		DEBUGP(DMI, "got DL_INFORMATION_IND\n");
		struct sockaddr_mISDN *sa = NULL;
		char *lstr = "UNKN";

		switch (l2addr.tei) {
		case TEI_OML:
			sa = &e1h->omladdr;
			lstr = "OML";
			break;
		case TEI_RSL:
			sa = &e1h->l2addr;
			lstr = "RSL";
			break;
		default:
			break;
		}
		if (sa) {
			DEBUGP(DMI, "%s use channel(%d) sapi(%d) tei(%d) for now\n",
				lstr, l2addr.channel, l2addr.sapi, l2addr.tei);
			memcpy(sa, &l2addr, sizeof(l2addr));
		}
		break;
	case DL_ESTABLISH_IND:
		DEBUGP(DMI, "got DL_ESTABLISH_IND\n");
		break;
	case DL_ESTABLISH_CNF:
		DEBUGP(DMI, "got DL_ESTABLISH_CNF\n");
		break;
	case DL_RELEASE_IND:
		DEBUGP(DMI, "got DL_RELEASE_IND: E1 Layer 1 disappeared?\n");
		break;
#if 0
	case MPH_ACTIVATE_IND:
		DEBUGP(DMI, "got MPH_ACTIVATE_IND\n");
		printf("tei %d, sapi %d\n", l2addr.tei, l2addr.sapi);
		if (l2addr.tei == TEI_OML && l2addr.sapi == SAPI_OML)
			e1h->cb(EVT_E1_OML_UP, e1h->bts);
		else if (l2addr.tei == TEI_RSL && l2addr.sapi == SAPI_RSL)
			e1h->cb(EVT_E1_RSL_UP, e1h->bts);
		break;
	case MPH_DEACTIVATE_IND:
		DEBUGP(DMI, "got MPH_DEACTIVATE_IND: TEI link closed?\n");
		if (l2addr.tei == TEI_OML && l2addr.sapi == SAPI_OML)
			e1h->cb(EVT_E1_OML_DN, e1h->bts);
		else if (l2addr.tei == TEI_RSL && l2addr.sapi == SAPI_RSL)
			e1h->cb(EVT_E1_RSL_DN, e1h->bts);
		break;
#endif
	case DL_DATA_IND:
		DEBUGP(DMI, "got DL_DATA_IND\n");

		ret = msg->len;
		msg->l2h = msg->data + 2;// + MISDN_HEADER_LEN;

#if 0
		if (debug_mask & DMI) { 
			fprintf(stdout, "RX: ");
			hexdump(msgb_l2(msg), ret - (msg->l2h - msg->data));// - MISDN_HEADER_LEN);
		}
#endif
		switch (l2addr.tei) {
		case TEI_OML:
			ret = abis_nm_rcvmsg(msg);
			break;
		case TEI_RSL:
			ret = abis_rsl_rcvmsg(msg);
			break;
		default:
			fprintf(stderr, "DATA_IND for unknown TEI\n");
			break;
		}
		break;
	default:
		DEBUGP(DMI, "got unexpected 0x%x prim\n", hh->prim);
		break;
	}
#endif



	DEBUGP(DMI, "hh->prim %08x\n", hh->prim);
#if 1
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
	case MPH_ACTIVATE_IND:
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
		if (hh->prim == DL_DATA_IND)
			msg->l2h = msg->data + 2;
		else
			msg->l2h = msg->data + 1;
		DEBUGP(DMI, "RX: %s\n", hexdump(msgb_l2(msg), ret));
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
#endif
	DEBUGP(DMI, "Returned ok\n");
	return ret;
}

static int ts_want_write(struct e1inp_ts *e1i_ts)
{
	/* We never include the mISDN B-Channel FD into the
	 * writeset, since it doesn't support poll() based
	 * write flow control */		
	if (e1i_ts->type == E1INP_TS_TYPE_TRAU) {
		fprintf(stderr, "Trying to write TRAU ts\n");
		return 0;
	}

	e1i_ts->driver.misdn.fd.when |= BSC_FD_WRITE;

	return 0;
}

static void timeout_ts1_write(void *data)
{
	struct e1inp_ts *e1i_ts = (struct e1inp_ts *)data;

	/* trigger write of ts1, due to tx delay timer */
	ts_want_write(e1i_ts);
}

static void dahdi_write_msg(uint8_t *data, int len, void *cbdata)
{
	struct bsc_fd *bfd = cbdata;
	int ret;

	ret = write(bfd->fd, data, len + 2);

	if (ret < 0)
		fprintf(stderr, "%s write failed %d\n", __func__, ret);
}

static int handle_ts1_write(struct bsc_fd *bfd)
{
	struct e1inp_line *line = bfd->data;
	unsigned int ts_nr = bfd->priv_nr;
	struct e1inp_ts *e1i_ts = &line->ts[ts_nr-1];
	struct e1inp_sign_link *sign_link;
	struct msgb *msg;
	//u_int8_t *l2_data;
	//int ret;
	//int no_oml = 0;

	bfd->when &= ~BSC_FD_WRITE;

	/* get the next msg for this timeslot */
	msg = e1inp_tx_ts(e1i_ts, &sign_link);
	if (!msg) {
		/* no message after tx delay timer */
		return 0;
	}

	lapd_transmit(sign_link->tei, msg->data, msg->len, bfd);

	//ret = write(bfd->fd, msg->data, msg->len + 2);

#if 0
	if (ret < 0)
		fprintf(stderr, "%s write failed %d\n", __func__, ret);
#endif
	msgb_free(msg);

	/* set tx delay timer for next event */
	e1i_ts->sign.tx_timer.cb = timeout_ts1_write;
	e1i_ts->sign.tx_timer.data = e1i_ts;
	bsc_schedule_timer(&e1i_ts->sign.tx_timer, 0, 50000);

	return 0;
}


static int invertbits = 1;

static u_int8_t flip_table[256];

static void init_flip_bits(void)
{
        int i,k;

        for (i = 0 ; i < 256 ; i++) {
                u_int8_t sample = 0 ;
                for (k = 0; k<8; k++) {
                        if ( i & 1 << k ) sample |= 0x80 >>  k;
                }
                flip_table[i] = sample;
        }
}

static u_int8_t * flip_buf_bits ( u_int8_t * buf , int len)
{
        int i;
        char * start = buf;

        for (i = 0 ; i < len; i++) {
                buf[i] = flip_table[(u_int8_t)buf[i]];
        }

        return start;
}

#define D_BCHAN_TX_GRAN 1024
/* write to a B channel TS */
static int handle_tsX_write(struct bsc_fd *bfd)
{
	struct e1inp_line *line = bfd->data;
	unsigned int ts_nr = bfd->priv_nr;
	struct e1inp_ts *e1i_ts = &line->ts[ts_nr-1];
	u_int8_t tx_buf[D_BCHAN_TX_GRAN];
	struct subch_mux *mx = &e1i_ts->trau.mux;
	int ret;

	ret = subchan_mux_out(mx, tx_buf, D_BCHAN_TX_GRAN);

	if (ret != D_BCHAN_TX_GRAN) {
		fprintf(stderr, "Huh, got ret of %d\n", ret);
		if (ret < 0)
			return ret;
	}

	DEBUGP(DMIB, "BCHAN TX: %s\n",
		hexdump(tx_buf, D_BCHAN_TX_GRAN));

	if (invertbits) {
		flip_buf_bits(tx_buf, ret);
	}

	ret = write(bfd->fd, tx_buf, ret);
	if (ret < D_BCHAN_TX_GRAN)
		fprintf(stderr, "send returns %d instead of %lu\n", ret,
			D_BCHAN_TX_GRAN);

	return ret;
}

#define D_TSX_ALLOC_SIZE 1024
/* FIXME: read from a B channel TS */
static int handle_tsX_read(struct bsc_fd *bfd)
{
	struct e1inp_line *line = bfd->data;
	unsigned int ts_nr = bfd->priv_nr;
	struct e1inp_ts *e1i_ts = &line->ts[ts_nr-1];
	struct msgb *msg = msgb_alloc(D_TSX_ALLOC_SIZE, "DAHDI TSx");
	int ret;

	if (!msg)
		return -ENOMEM;

	ret = read(bfd->fd, msg->data, D_TSX_ALLOC_SIZE);
	if (ret < 0 || ret != D_TSX_ALLOC_SIZE) {
		fprintf(stderr, "read error  %d %s\n", ret, strerror(errno));
		return ret;
	}

	if (invertbits) {
		flip_buf_bits(msg->data, ret);
	}

	msgb_put(msg, ret);

	msg->l2h = msg->data;
	DEBUGP(DMIB, "BCHAN RX: %s\n",
		hexdump(msgb_l2(msg), ret));
	ret = e1inp_rx_ts(e1i_ts, msg, 0, 0);
	/* physical layer indicates that data has been sent,
	 * we thus can send some more data */
	//ret = handle_tsX_write(bfd);
	msgb_free(msg);

	return ret;
}

/* callback from select.c in case one of the fd's can be read/written */
static int dahdi_fd_cb(struct bsc_fd *bfd, unsigned int what)
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
		if (what & BSC_FD_WRITE)
			rc = handle_tsX_write(bfd);
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

#if 0
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
#endif

struct e1inp_driver dahdi_driver = {
	.name = "DAHDI",
	.want_write = ts_want_write,
};

void dahdi_set_bufinfo(int fd, int as_sigchan)
{
	struct dahdi_bufferinfo bi;
	int x = 0;

	if (ioctl(fd, DAHDI_GET_BUFINFO, &bi)) {
		fprintf(stderr, "Error getting bufinfo\n");
		exit(-1);
	}

	if (as_sigchan) {
		bi.numbufs = 4;
		bi.bufsize = 512;
	} else {
		bi.numbufs = 4;
		bi.bufsize = D_BCHAN_TX_GRAN;
		//bi.txbufpolicy = DAHDI_POLICY_WHEN_FULL;
	}

	if (ioctl(fd, DAHDI_SET_BUFINFO, &bi)) {
		fprintf(stderr, "Error setting bufinfo\n");
		exit(-1);
	}

	if (!as_sigchan) {
		if (ioctl(fd, DAHDI_AUDIOMODE, &x)) {
			fprintf(stderr, "Error setting bufinfo\n");
			exit(-1);
		}
	}

}

static int mi_e1_setup(struct e1inp_line *line, int release_l2)
{
	int ts, ret;

	/* TS0 is CRC4, don't need any fd for it */
	for (ts = 1; ts < NUM_E1_TS; ts++) {
		unsigned int idx = ts-1;
		char openstr[128];
		struct e1inp_ts *e1i_ts = &line->ts[idx];
		struct bsc_fd *bfd = &e1i_ts->driver.misdn.fd;

		bfd->data = line;
		bfd->priv_nr = ts;
		bfd->cb = dahdi_fd_cb;
		snprintf(openstr, sizeof(openstr), "/dev/dahdi/%d", ts);

		switch (e1i_ts->type) {
		case E1INP_TS_TYPE_NONE:
			continue;
			break;
		case E1INP_TS_TYPE_SIGN:
			bfd->fd = open(openstr, O_RDWR | O_NONBLOCK);
			if (bfd->fd == -1) {
				fprintf(stderr, "%s could not open %s %s\n",
					__func__, openstr, strerror(errno));
				exit(-1);
			}
			bfd->when = BSC_FD_READ;
			dahdi_set_bufinfo(bfd->fd, 1);
			break;
		case E1INP_TS_TYPE_TRAU:
			bfd->fd = open(openstr, O_RDWR | O_NONBLOCK);
			if (bfd->fd == -1) {
				fprintf(stderr, "%s could not open %s %s\n",
					__func__, openstr, strerror(errno));
				exit(-1);
			}
			dahdi_set_bufinfo(bfd->fd, 0);
			/* We never include the mISDN B-Channel FD into the
	 		* writeset, since it doesn't support poll() based
	 		* write flow control */		
			bfd->when = BSC_FD_READ | BSC_FD_WRITE;
			break;
		}

		if (bfd->fd < 0) {
			fprintf(stderr, "%s could not open %s %s\n",
				__func__, openstr, strerror(errno));
			return bfd->fd;
		}

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
	//int sk, ret, cnt;
	int ret;

	if (!line->driver) {
		/* this must be the first update */
		line->driver = &dahdi_driver;
	} else {
		/* this is a subsequent update */
		/* FIXME: first close all sockets */
		fprintf(stderr, "incremental line updates not supported yet\n");
		return 0;
	}

	if (line->driver != &dahdi_driver)
		return -EINVAL;

#if 0
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
#endif
	init_flip_bits();

	ret = mi_e1_setup(line, 1);
	if (ret)
		return ret;

	lapd_transmit_cb = dahdi_write_msg;

	return 0;
}

static __attribute__((constructor)) void on_dso_load_sms(void)
{
	/* register the driver with the core */
	e1inp_driver_register(&dahdi_driver);
}
