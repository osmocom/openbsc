/* OpenBSC Abis input driver for DAHDI */

/* (C) 2008-2011 by Harald Welte <laforge@gnumonks.org>
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

#include "../../../bscconfig.h"

#ifdef HAVE_DAHDI_USER_H

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <time.h>
#include <sys/fcntl.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <dahdi/user.h>

#include <osmocom/core/select.h>
#include <osmocom/core/msgb.h>
#include <osmocom/core/rate_ctr.h>

#include <openbsc/debug.h>
#include <openbsc/gsm_data.h>
#include <openbsc/abis_nm.h>
#include <openbsc/abis_rsl.h>
#include <openbsc/subchan_demux.h>
#include <openbsc/e1_input.h>
#include <openbsc/signal.h>
#include <osmocom/core/talloc.h>

#include "lapd.h"

#define TS1_ALLOC_SIZE	300

/* Corresponds to dahdi/user.h, only PRI related events */
static const struct value_string dahdi_evt_names[] = {
	{ DAHDI_EVENT_NONE,		"NONE" },
	{ DAHDI_EVENT_ALARM,		"ALARM" },
	{ DAHDI_EVENT_NOALARM,		"NOALARM" },
	{ DAHDI_EVENT_ABORT,		"HDLC ABORT" },
	{ DAHDI_EVENT_OVERRUN,		"HDLC OVERRUN" },
	{ DAHDI_EVENT_BADFCS,		"HDLC BAD FCS" },
	{ DAHDI_EVENT_REMOVED,		"REMOVED" },
	{ 0, NULL }
};

static void handle_dahdi_exception(struct e1inp_ts *ts)
{
	int rc, evt;
	struct e1inp_line *line = ts->line;
	struct input_signal_data isd;

	rc = ioctl(ts->driver.dahdi.fd.fd, DAHDI_GETEVENT, &evt);
	if (rc < 0)
		return;

	LOGP(DMI, LOGL_NOTICE, "Line %u(%s) / TS %u DAHDI EVENT %s\n",
		ts->line->num, ts->line->name, ts->num,
		get_value_string(dahdi_evt_names, evt));

	isd.line = ts->line;

	switch (evt) {
	case DAHDI_EVENT_ALARM:
		/* we should notify the code that the line is gone */
		osmo_signal_dispatch(SS_INPUT, S_INP_LINE_ALARM, &isd);
		rate_ctr_inc(&line->rate_ctr->ctr[E1I_CTR_ALARM]);
		break;
	case DAHDI_EVENT_NOALARM:
		/* alarm has gone, we should re-start the SABM requests */
		osmo_signal_dispatch(SS_INPUT, S_INP_LINE_NOALARM, &isd);
		break;
	case DAHDI_EVENT_ABORT:
		rate_ctr_inc(&line->rate_ctr->ctr[E1I_CTR_HDLC_ABORT]);
		break;
	case DAHDI_EVENT_OVERRUN:
		rate_ctr_inc(&line->rate_ctr->ctr[E1I_CTR_HDLC_OVERR]);
		break;
	case DAHDI_EVENT_BADFCS:
		rate_ctr_inc(&line->rate_ctr->ctr[E1I_CTR_HDLC_BADFCS]);
		break;
	case DAHDI_EVENT_REMOVED:
		rate_ctr_inc(&line->rate_ctr->ctr[E1I_CTR_REMOVED]);
		break;
	}
}

static int handle_ts1_read(struct osmo_fd *bfd)
{
	struct e1inp_line *line = bfd->data;
	unsigned int ts_nr = bfd->priv_nr;
	struct e1inp_ts *e1i_ts = &line->ts[ts_nr-1];
	struct msgb *msg = msgb_alloc(TS1_ALLOC_SIZE, "DAHDI TS1");
	lapd_mph_type prim;
	unsigned int sapi, tei;
	int ilen, ret, error = 0;
	uint8_t *idata;

	if (!msg)
		return -ENOMEM;

	ret = read(bfd->fd, msg->data, TS1_ALLOC_SIZE - 16);
	if (ret == -1)
		handle_dahdi_exception(e1i_ts);
	else if (ret < 0) {
		perror("read ");
	}
	msgb_put(msg, ret - 2);
	if (ret <= 3) {
		perror("read ");
	}

	sapi = msg->data[0] >> 2;
	tei = msg->data[1] >> 1;

	DEBUGP(DMI, "<= len = %d, sapi(%d) tei(%d)", ret, sapi, tei);

	idata = lapd_receive(e1i_ts->driver.dahdi.lapd, msg->data, msg->len, &ilen, &prim, &error);
	if (!idata) {
		switch(error) {
		case LAPD_ERR_UNKNOWN_TEI:
			/* We don't know about this TEI, probably the BSC
			 * lost local states (it crashed or it was stopped),
			 * notify the driver to see if it can do anything to
			 * recover the existing signalling links with the BTS.
			 */
			e1inp_event(e1i_ts, S_INP_TEI_UNKNOWN, tei, sapi);
			return -EIO;
		}
		if (prim == 0)
			return -EIO;
	}

	msgb_pull(msg, 2);

	DEBUGP(DMI, "prim %08x\n", prim);

	switch (prim) {
	case 0:
		break;
	case LAPD_MPH_ACTIVATE_IND:
		DEBUGP(DMI, "MPH_ACTIVATE_IND: sapi(%d) tei(%d)\n", sapi, tei);
		ret = e1inp_event(e1i_ts, S_INP_TEI_UP, tei, sapi);
		break;
	case LAPD_MPH_DEACTIVATE_IND:
		DEBUGP(DMI, "MPH_DEACTIVATE_IND: sapi(%d) tei(%d)\n", sapi, tei);
		ret = e1inp_event(e1i_ts, S_INP_TEI_DN, tei, sapi);
		break;
	case LAPD_DL_DATA_IND:
	case LAPD_DL_UNITDATA_IND:
		if (prim == LAPD_DL_DATA_IND)
			msg->l2h = msg->data + 2;
		else
			msg->l2h = msg->data + 1;
		DEBUGP(DMI, "RX: %s\n", osmo_hexdump(msgb_l2(msg), ret));
		ret = e1inp_rx_ts(e1i_ts, msg, tei, sapi);
		break;
	default:
		printf("ERROR: unknown prim\n");
		break;
	}

	DEBUGP(DMI, "Returned ok\n");
	return ret;
}

static int ts_want_write(struct e1inp_ts *e1i_ts)
{
	/* We never include the DAHDI B-Channel FD into the
	 * writeset, since it doesn't support poll() based
	 * write flow control */
	if (e1i_ts->type == E1INP_TS_TYPE_TRAU) {
		fprintf(stderr, "Trying to write TRAU ts\n");
		return 0;
	}

	e1i_ts->driver.dahdi.fd.when |= BSC_FD_WRITE;

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
	struct osmo_fd *bfd = cbdata;
	struct e1inp_line *line = bfd->data;
	unsigned int ts_nr = bfd->priv_nr;
	struct e1inp_ts *e1i_ts = &line->ts[ts_nr-1];
	int ret;

	ret = write(bfd->fd, data, len + 2);
	if (ret == -1)
		handle_dahdi_exception(e1i_ts);
	else if (ret < 0)
		LOGP(DMI, LOGL_NOTICE, "%s write failed %d\n", __func__, ret);
}

static int handle_ts1_write(struct osmo_fd *bfd)
{
	struct e1inp_line *line = bfd->data;
	unsigned int ts_nr = bfd->priv_nr;
	struct e1inp_ts *e1i_ts = &line->ts[ts_nr-1];
	struct e1inp_sign_link *sign_link;
	struct msgb *msg;

	bfd->when &= ~BSC_FD_WRITE;

	/* get the next msg for this timeslot */
	msg = e1inp_tx_ts(e1i_ts, &sign_link);
	if (!msg) {
		/* no message after tx delay timer */
		return 0;
	}

	DEBUGP(DMI, "TX: %s\n", osmo_hexdump(msg->data, msg->len));
	lapd_transmit(e1i_ts->driver.dahdi.lapd, sign_link->tei,
		      sign_link->sapi, msg->data, msg->len);
	msgb_free(msg);

	/* set tx delay timer for next event */
	e1i_ts->sign.tx_timer.cb = timeout_ts1_write;
	e1i_ts->sign.tx_timer.data = e1i_ts;
	osmo_timer_schedule(&e1i_ts->sign.tx_timer, 0, 50000);

	return 0;
}


static int invertbits = 1;

static uint8_t flip_table[256];

static void init_flip_bits(void)
{
        int i,k;

        for (i = 0 ; i < 256 ; i++) {
                uint8_t sample = 0 ;
                for (k = 0; k<8; k++) {
                        if ( i & 1 << k ) sample |= 0x80 >>  k;
                }
                flip_table[i] = sample;
        }
}

static uint8_t * flip_buf_bits ( uint8_t * buf , int len)
{
        int i;
        uint8_t * start = buf;

        for (i = 0 ; i < len; i++) {
                buf[i] = flip_table[(uint8_t)buf[i]];
        }

        return start;
}

#define D_BCHAN_TX_GRAN 160
/* write to a B channel TS */
static int handle_tsX_write(struct osmo_fd *bfd)
{
	struct e1inp_line *line = bfd->data;
	unsigned int ts_nr = bfd->priv_nr;
	struct e1inp_ts *e1i_ts = &line->ts[ts_nr-1];
	uint8_t tx_buf[D_BCHAN_TX_GRAN];
	struct subch_mux *mx = &e1i_ts->trau.mux;
	int ret;

	ret = subchan_mux_out(mx, tx_buf, D_BCHAN_TX_GRAN);

	if (ret != D_BCHAN_TX_GRAN) {
		fprintf(stderr, "Huh, got ret of %d\n", ret);
		if (ret < 0)
			return ret;
	}

	DEBUGP(DMIB, "BCHAN TX: %s\n",
		osmo_hexdump(tx_buf, D_BCHAN_TX_GRAN));

	if (invertbits) {
		flip_buf_bits(tx_buf, ret);
	}

	ret = write(bfd->fd, tx_buf, ret);
	if (ret < D_BCHAN_TX_GRAN)
		fprintf(stderr, "send returns %d instead of %d\n", ret,
			D_BCHAN_TX_GRAN);

	return ret;
}

#define D_TSX_ALLOC_SIZE (D_BCHAN_TX_GRAN)
/* FIXME: read from a B channel TS */
static int handle_tsX_read(struct osmo_fd *bfd)
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
		osmo_hexdump(msgb_l2(msg), ret));
	ret = e1inp_rx_ts(e1i_ts, msg, 0, 0);
	/* physical layer indicates that data has been sent,
	 * we thus can send some more data */
	ret = handle_tsX_write(bfd);
	msgb_free(msg);

	return ret;
}

/* callback from select.c in case one of the fd's can be read/written */
static int dahdi_fd_cb(struct osmo_fd *bfd, unsigned int what)
{
	struct e1inp_line *line = bfd->data;
	unsigned int ts_nr = bfd->priv_nr;
	unsigned int idx = ts_nr-1;
	struct e1inp_ts *e1i_ts = &line->ts[idx];
	int rc = 0;

	switch (e1i_ts->type) {
	case E1INP_TS_TYPE_SIGN:
		if (what & BSC_FD_EXCEPT)
			handle_dahdi_exception(e1i_ts);
		if (what & BSC_FD_READ)
			rc = handle_ts1_read(bfd);
		if (what & BSC_FD_WRITE)
			rc = handle_ts1_write(bfd);
		break;
	case E1INP_TS_TYPE_TRAU:
		if (what & BSC_FD_EXCEPT)
			handle_dahdi_exception(e1i_ts);
		if (what & BSC_FD_READ)
			rc = handle_tsX_read(bfd);
		if (what & BSC_FD_WRITE)
			rc = handle_tsX_write(bfd);
		/* We never include the DAHDI B-Channel FD into the
		 * writeset, since it doesn't support poll() based
		 * write flow control */
		break;
	default:
		fprintf(stderr, "unknown E1 TS type %u\n", e1i_ts->type);
		break;
	}

	return rc;
}

static int dahdi_e1_line_update(struct e1inp_line *line);

struct e1inp_driver dahdi_driver = {
	.name = "dahdi",
	.want_write = ts_want_write,
	.line_update = &dahdi_e1_line_update,
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
		bi.numbufs = 8;
		bi.bufsize = D_BCHAN_TX_GRAN;
		bi.txbufpolicy = DAHDI_POLICY_WHEN_FULL;
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
	} else {
		int one = 1;
		ioctl(fd, DAHDI_HDLCFCSMODE, &one);
		/* we cannot reliably check for the ioctl return value here
		 * as this command will fail if the slot _already_ was a
		 * signalling slot before :( */
	}
}

static int dahdi_e1_setup(struct e1inp_line *line)
{
	int ts, ret;

	/* TS0 is CRC4, don't need any fd for it */
	for (ts = 1; ts < NUM_E1_TS; ts++) {
		unsigned int idx = ts-1;
		char openstr[128];
		struct e1inp_ts *e1i_ts = &line->ts[idx];
		struct osmo_fd *bfd = &e1i_ts->driver.dahdi.fd;
		int dev_nr;

		/* DAHDI device names/numbers just keep incrementing
		 * even over multiple boards.  So TS1 of the second
		 * board will be 32 */
		dev_nr = line->num * (NUM_E1_TS-1) + ts;

		bfd->data = line;
		bfd->priv_nr = ts;
		bfd->cb = dahdi_fd_cb;
		snprintf(openstr, sizeof(openstr), "/dev/dahdi/%d", dev_nr);

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
			bfd->when = BSC_FD_READ | BSC_FD_EXCEPT;
			dahdi_set_bufinfo(bfd->fd, 1);
			e1i_ts->driver.dahdi.lapd = lapd_instance_alloc(1, dahdi_write_msg, bfd);
			break;
		case E1INP_TS_TYPE_TRAU:
			bfd->fd = open(openstr, O_RDWR | O_NONBLOCK);
			if (bfd->fd == -1) {
				fprintf(stderr, "%s could not open %s %s\n",
					__func__, openstr, strerror(errno));
				exit(-1);
			}
			dahdi_set_bufinfo(bfd->fd, 0);
			/* We never include the DAHDI B-Channel FD into the
			 * writeset, since it doesn't support poll() based
			 * write flow control */
			bfd->when = BSC_FD_READ | BSC_FD_EXCEPT;// | BSC_FD_WRITE;
			break;
		}

		if (bfd->fd < 0) {
			fprintf(stderr, "%s could not open %s %s\n",
				__func__, openstr, strerror(errno));
			return bfd->fd;
		}

		ret = osmo_fd_register(bfd);
		if (ret < 0) {
			fprintf(stderr, "could not register FD: %s\n",
				strerror(ret));
			return ret;
		}
	}

	return 0;
}

static int dahdi_e1_line_update(struct e1inp_line *line)
{
	if (line->driver != &dahdi_driver)
		return -EINVAL;

	return dahdi_e1_setup(line);
}

int e1inp_dahdi_init(void)
{
	init_flip_bits();

	/* register the driver with the core */
	return e1inp_driver_register(&dahdi_driver);
}

#endif /* HAVE_DAHDI_USER_H */
