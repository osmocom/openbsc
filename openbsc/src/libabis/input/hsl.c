/* OpenBSC Abis input driver for HSL Femto */

/* (C) 2011 by Harald Welte <laforge@gnumonks.org>
 * (C) 2011 by On-Waves
 *
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

/* HSL uses a much more primitive/simplified version of the IPA multiplex.
 *
 * They have taken out the nice parts like the ID_GET / ID_RESP for resolving
 * the UNIT ID, as well as the keepalive ping/pong messages.  Furthermore, the
 * Stream Identifiers are fixed on the BTS side (RSL always 0, OML always 0xff)
 * and both OML+RSL share a single TCP connection.
 *
 * Other oddities include the encapsulation of BSSGP messages in the L3_INFO IE
 * of RSL
 */

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

#include <osmocom/core/select.h>
#include <osmocom/gsm/tlv.h>
#include <osmocom/core/msgb.h>
#include <openbsc/debug.h>
#include <openbsc/gsm_data.h>
#include <openbsc/abis_nm.h>
#include <openbsc/abis_rsl.h>
#include <openbsc/subchan_demux.h>
#include <openbsc/e1_input.h>
#include <openbsc/ipaccess.h>
#include <openbsc/socket.h>
#include <openbsc/signal.h>
#include <osmocom/core/talloc.h>

#define HSL_TCP_PORT	2500
#define HSL_PROTO_DEBUG	0xdd

#define PRIV_OML 1
#define PRIV_RSL 2

/* data structure for one E1 interface with A-bis */
struct hsl_e1_handle {
	struct osmo_fd listen_fd;
	struct gsm_network *gsmnet;
};

static struct hsl_e1_handle *e1h;


#define TS1_ALLOC_SIZE	900

#define OML_UP		0x0001
#define RSL_UP		0x0002

int hsl_drop_oml(struct gsm_bts *bts)
{
	struct gsm_bts_trx *trx;
	struct e1inp_ts *ts;
	struct e1inp_line *line;
	struct osmo_fd *bfd;

	if (!bts || !bts->oml_link)
		return -1;

	/* send OML down */
	ts = bts->oml_link->ts;
	line = ts->line;
	e1inp_event(ts, S_INP_TEI_DN, bts->oml_link->tei, bts->oml_link->sapi);

	bfd = &ts->driver.ipaccess.fd;
	osmo_fd_unregister(bfd);
	close(bfd->fd);
	bfd->fd = -1;

	/* clean up OML and RSL */
	e1inp_sign_link_destroy(bts->oml_link);
	bts->oml_link = NULL;
	e1inp_sign_link_destroy(bts->c0->rsl_link);
	bts->c0->rsl_link = NULL;
	bts->ip_access.flags = 0;

	/* kill the E1 line now... as we have no one left to use it */
	talloc_free(line);

	return -1;
}

static int hsl_drop_ts_fd(struct e1inp_ts *ts, struct osmo_fd *bfd)
{
	struct e1inp_sign_link *link, *link2;
	int bts_nr = -1;

	llist_for_each_entry_safe(link, link2, &ts->sign.sign_links, list) {
		bts_nr = link->trx->bts->bts_nr;
		e1inp_sign_link_destroy(link);
	}

	osmo_fd_unregister(bfd);
	close(bfd->fd);
	bfd->fd = -1;

	talloc_free(ts->line);

	return bts_nr;
}

struct gsm_bts *find_bts_by_serno(struct gsm_network *net, unsigned long serno)
{
	struct gsm_bts *bts;

	llist_for_each_entry(bts, &net->bts_list, list) {
		if (bts->type != GSM_BTS_TYPE_HSL_FEMTO)
			continue;

		if (serno == bts->hsl.serno)
			return bts;
	}

	return NULL;
}


static int process_hsl_rsl(struct msgb *msg, struct e1inp_line *line)
{
	char serno_buf[16];
	uint8_t serno_len;
	unsigned long serno;
	struct gsm_bts *bts;

	switch (msg->l2h[1]) {
	case 0x80:
		/*, contains Serial Number + SW version */
		if (msg->l2h[2] != 0xc0)
			break;
		serno_len = msg->l2h[3];
		if (serno_len > sizeof(serno_buf)-1)
			serno_len = sizeof(serno_buf)-1;
		memcpy(serno_buf, msg->l2h+4, serno_len);
		serno_buf[serno_len] = '\0';
		serno = strtoul(serno_buf, NULL, 10);
		bts = find_bts_by_serno(e1h->gsmnet, serno);
		if (!bts) {
			LOGP(DINP, LOGL_ERROR, "Unable to find BTS config for "
				"serial number %lu(%s)\n", serno, serno_buf);
			return -EIO;
		}

		DEBUGP(DINP, "Identified HSL BTS Serial Number %lu\n", serno);

		/* we shouldn't hardcode it, but HSL femto also hardcodes it... */
		bts->oml_tei = 255;
		bts->c0->rsl_tei = 0;
		bts->oml_link = e1inp_sign_link_create(&line->ts[PRIV_OML - 1],
							E1INP_SIGN_OML, bts->c0,
							bts->oml_tei, 0);
		bts->c0->rsl_link = e1inp_sign_link_create(&line->ts[PRIV_OML - 1],
							E1INP_SIGN_RSL, bts->c0,
							bts->c0->rsl_tei, 0);
		e1inp_event(&line->ts[PRIV_OML-1], S_INP_TEI_UP, 255, 0);
		e1inp_event(&line->ts[PRIV_OML-1], S_INP_TEI_UP, 0, 0);
		bts->ip_access.flags |= OML_UP;
		bts->ip_access.flags |= (RSL_UP << 0);
		msgb_free(msg);
		return 1;	/* == we have taken over the msg */
	case 0x82:
		/* FIXME: do something with BSSGP, i.e. forward it over
		 * NSIP to OsmoSGSN */
		msgb_free(msg);
		return 1;
	}
	return 0;
}

static int handle_ts1_read(struct osmo_fd *bfd)
{
	struct e1inp_line *line = bfd->data;
	unsigned int ts_nr = bfd->priv_nr;
	struct e1inp_ts *e1i_ts = &line->ts[ts_nr-1];
	struct e1inp_sign_link *link;
	struct msgb *msg;
	struct ipaccess_head *hh;
	int ret = 0, error;

	msg = ipaccess_read_msg(bfd, &error);
	if (!msg) {
		if (error == 0) {
			int ret = hsl_drop_ts_fd(e1i_ts, bfd);
			if (ret >= 0)
				LOGP(DINP, LOGL_NOTICE, "BTS %u disappeared, dead socket\n",
					ret);
			else
				LOGP(DINP, LOGL_NOTICE, "unknown BTS disappeared, dead socket\n");
		}
		return error;
	}

	DEBUGP(DMI, "RX %u: %s\n", ts_nr, osmo_hexdump(msgb_l2(msg), msgb_l2len(msg)));

	hh = (struct ipaccess_head *) msg->data;
	if (hh->proto == HSL_PROTO_DEBUG) {
		LOGP(DINP, LOGL_NOTICE, "HSL debug: %s\n", msg->data + sizeof(*hh));
		msgb_free(msg);
		return ret;
	}

	/* HSL proprietary RSL extension */
	if (hh->proto == 0 && (msg->l2h[0] == 0x81 || msg->l2h[0] == 0x80)) {
		ret = process_hsl_rsl(msg, line);
		if (ret < 0) {
			/* FIXME: close connection */
			hsl_drop_ts_fd(e1i_ts, bfd);
			return ret;
		} else if (ret == 1)
			return 0;
		/* else: continue... */
	}
#ifdef HSL_SR_1_0
	/* HSL for whatever reason chose to use 0x81 instead of 0x80 for FOM */
	if (hh->proto == 255 && msg->l2h[0] == (ABIS_OM_MDISC_FOM | 0x01))
		msg->l2h[0] = ABIS_OM_MDISC_FOM;
#endif
	link = e1inp_lookup_sign_link(e1i_ts, hh->proto, 0);
	if (!link) {
		LOGP(DINP, LOGL_ERROR, "no matching signalling link for "
			"hh->proto=0x%02x\n", hh->proto);
		msgb_free(msg);
		return -EIO;
	}
	msg->trx = link->trx;

	switch (link->type) {
	case E1INP_SIGN_RSL:
		if (!(msg->trx->bts->ip_access.flags & (RSL_UP << msg->trx->nr))) {
			e1inp_event(e1i_ts, S_INP_TEI_UP, link->tei, link->sapi);
			msg->trx->bts->ip_access.flags |= (RSL_UP << msg->trx->nr);
		}
		ret = abis_rsl_rcvmsg(msg);
		break;
	case E1INP_SIGN_OML:
		if (!(msg->trx->bts->ip_access.flags & OML_UP)) {
			e1inp_event(e1i_ts, S_INP_TEI_UP, link->tei, link->sapi);
			msg->trx->bts->ip_access.flags |= OML_UP;
		}
		ret = abis_nm_rcvmsg(msg);
		break;
	default:
		LOGP(DINP, LOGL_NOTICE, "Unknown HSL protocol class 0x%02x\n", hh->proto);
		msgb_free(msg);
		break;
	}
	return ret;
}

static int ts_want_write(struct e1inp_ts *e1i_ts)
{
	e1i_ts->driver.ipaccess.fd.when |= BSC_FD_WRITE;

	return 0;
}

static void timeout_ts1_write(void *data)
{
	struct e1inp_ts *e1i_ts = (struct e1inp_ts *)data;

	/* trigger write of ts1, due to tx delay timer */
	ts_want_write(e1i_ts);
}

static int handle_ts1_write(struct osmo_fd *bfd)
{
	struct e1inp_line *line = bfd->data;
	unsigned int ts_nr = bfd->priv_nr;
	struct e1inp_ts *e1i_ts = &line->ts[ts_nr-1];
	struct e1inp_sign_link *sign_link;
	struct msgb *msg;
	uint8_t proto;
	int ret;

	bfd->when &= ~BSC_FD_WRITE;

	/* get the next msg for this timeslot */
	msg = e1inp_tx_ts(e1i_ts, &sign_link);
	if (!msg) {
		/* no message after tx delay timer */
		return 0;
	}

	switch (sign_link->type) {
	case E1INP_SIGN_OML:
		proto = IPAC_PROTO_OML;
#ifdef HSL_SR_1_0
		/* HSL uses 0x81 for FOM for some reason */
		if (msg->data[0] == ABIS_OM_MDISC_FOM)
			msg->data[0] = ABIS_OM_MDISC_FOM | 0x01;
#endif
		break;
	case E1INP_SIGN_RSL:
		proto = IPAC_PROTO_RSL;
		break;
	default:
		msgb_free(msg);
		bfd->when |= BSC_FD_WRITE; /* come back for more msg */
		return -EINVAL;
	}

	msg->l2h = msg->data;
	ipaccess_prepend_header(msg, sign_link->tei);

	DEBUGP(DMI, "TX %u: %s\n", ts_nr, osmo_hexdump(msg->l2h, msgb_l2len(msg)));

	ret = send(bfd->fd, msg->data, msg->len, 0);
	msgb_free(msg);

	/* set tx delay timer for next event */
	e1i_ts->sign.tx_timer.cb = timeout_ts1_write;
	e1i_ts->sign.tx_timer.data = e1i_ts;

	/* Reducing this might break the nanoBTS 900 init. */
	osmo_timer_schedule(&e1i_ts->sign.tx_timer, 0, e1i_ts->sign.delay);

	return ret;
}

/* callback from select.c in case one of the fd's can be read/written */
static int hsl_fd_cb(struct osmo_fd *bfd, unsigned int what)
{
	struct e1inp_line *line = bfd->data;
	unsigned int ts_nr = bfd->priv_nr;
	unsigned int idx = ts_nr-1;
	struct e1inp_ts *e1i_ts;
	int rc = 0;

	/* In case of early RSL we might not yet have a line */

	if (line)
		e1i_ts = &line->ts[idx];

	if (!line || e1i_ts->type == E1INP_TS_TYPE_SIGN) {
		if (what & BSC_FD_READ)
			rc = handle_ts1_read(bfd);
		if (what & BSC_FD_WRITE)
			rc = handle_ts1_write(bfd);
	} else
		LOGP(DINP, LOGL_ERROR, "unknown E1 TS type %u\n", e1i_ts->type);

	return rc;
}

struct e1inp_driver hsl_driver = {
	.name = "HSL",
	.want_write = ts_want_write,
	.default_delay = 0,
};

/* callback of the OML listening filedescriptor */
static int listen_fd_cb(struct osmo_fd *listen_bfd, unsigned int what)
{
	int ret;
	int idx = 0;
	int i;
	struct e1inp_line *line;
	struct e1inp_ts *e1i_ts;
	struct osmo_fd *bfd;
	struct sockaddr_in sa;
	socklen_t sa_len = sizeof(sa);

	if (!(what & BSC_FD_READ))
		return 0;

	ret = accept(listen_bfd->fd, (struct sockaddr *) &sa, &sa_len);
	if (ret < 0) {
		perror("accept");
		return ret;
	}
	LOGP(DINP, LOGL_NOTICE, "accept()ed new HSL link from %s\n",
		inet_ntoa(sa.sin_addr));

	line = talloc_zero(tall_bsc_ctx, struct e1inp_line);
	if (!line) {
		close(ret);
		return -ENOMEM;
	}
	line->driver = &hsl_driver;
	//line->driver_data = e1h;
	/* create virrtual E1 timeslots for signalling */
	e1inp_ts_config(&line->ts[1-1], line, E1INP_TS_TYPE_SIGN);

	/* initialize the fds */
	for (i = 0; i < ARRAY_SIZE(line->ts); ++i)
		line->ts[i].driver.ipaccess.fd.fd = -1;

	e1i_ts = &line->ts[idx];

	bfd = &e1i_ts->driver.ipaccess.fd;
	bfd->fd = ret;
	bfd->data = line;
	bfd->priv_nr = PRIV_OML;
	bfd->cb = hsl_fd_cb;
	bfd->when = BSC_FD_READ;
	ret = osmo_fd_register(bfd);
	if (ret < 0) {
		LOGP(DINP, LOGL_ERROR, "could not register FD\n");
		close(bfd->fd);
		talloc_free(line);
		return ret;
	}

        return ret;
	//return e1inp_line_register(line);
}

int hsl_setup(struct gsm_network *gsmnet)
{
	int ret;

	e1h = talloc_zero(tall_bsc_ctx, struct hsl_e1_handle);
	if (!e1h)
		return -ENOMEM;

	e1h->gsmnet = gsmnet;

	/* Listen for connections */
	ret = make_sock(&e1h->listen_fd, IPPROTO_TCP, INADDR_ANY, HSL_TCP_PORT,
			0, listen_fd_cb, NULL);
	if (ret < 0)
		return ret;

	return 0;
}

void e1inp_hsl_init(void)
{
	e1inp_driver_register(&hsl_driver);
}
