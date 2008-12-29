/* OpenBSC Abis interface to mISDNuser */

/* (C) 2008 by Harald Welte <laforge@gnumonks.org>
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
#include <sys/fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
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

#define NUM_E1_TS	32

/* data structure for one E1 interface with A-bis */
struct mi_e1_handle {
	struct gsm_bts *bts;
	/* The mISDN card number of the card we use */
	int cardnr;
	/* The RSL adress */
	struct sockaddr_mISDN l2addr;
	/* The OML adress */
	struct sockaddr_mISDN omladdr;
	/* list (queue) of to-be-sent msgb's */
	struct llist_head rsl_tx_list;
	struct llist_head oml_tx_list;

	void (*cb)(int event, struct gsm_bts *bts);
	struct bsc_fd fd[NUM_E1_TS];

	int ts2_fd;
};

/* FIXME: this needs to go */
static struct mi_e1_handle *global_e1h;

#define SAPI_L2ML	0
#define SAPI_OML	62
#define SAPI_RSL	0	/* 63 ? */

#define TEI_L2ML	127
#define TEI_OML		25
#define TEI_RSL		1

void hexdump(unsigned char *buf, int len)
{
	int i;
	for (i = 0; i < len; i++) {
		fprintf(stdout, "%02x ", buf[i]);
	}
	fprintf(stdout, "\n");
}

#define TS1_ALLOC_SIZE	300

static int handle_ts1_read(struct bsc_fd *bfd)
{
	struct mi_e1_handle *e1h = bfd->data;
	struct msgb *msg = msgb_alloc(TS1_ALLOC_SIZE);
	struct sockaddr_mISDN l2addr;
	struct mISDNhead *hh;
	socklen_t alen;
	int ret;

	if (!msg)
		return -ENOMEM;

	hh = (struct mISDNhead *) msg->data;

	/* FIXME: Map TEI/SAPI to TRX */
	msg->trx = e1h->bts->c0;

	alen = sizeof(l2addr);
	ret = recvfrom(bfd->fd, msg->data, 300, 0,
		       (struct sockaddr *) &l2addr, &alen);
	if (ret < 0) {
		fprintf(stderr, "recvfrom error  %s\n", strerror(errno));
		return ret;
	}

	if (alen != sizeof(l2addr))
		return -EINVAL;

	msgb_put(msg, ret);

	DEBUGP(DMI, "alen =%d, dev(%d) channel(%d) sapi(%d) tei(%d)\n",
		alen, l2addr.dev, l2addr.channel, l2addr.sapi, l2addr.tei);

	DEBUGP(DMI, "<= len = %d, prim(0x%x) id(0x%x)\n",
		ret, hh->prim, hh->id);

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
	case MPH_ACTIVATE_IND:
		DEBUGP(DMI, "got MPH_ACTIVATE_IND\n");
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
	case DL_DATA_IND:
		DEBUGP(DMI, "got DL_DATA_IND\n");

		msg->l2h = msg->data + MISDN_HEADER_LEN;
		
		fprintf(stdout, "RX: ");
		hexdump(msgb_l2(msg), ret - MISDN_HEADER_LEN);
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
	return ret;
}

static int handle_ts1_write(struct bsc_fd *bfd)
{
	struct mi_e1_handle *e1h = bfd->data;
	struct msgb *msg;
	struct mISDNhead *hh;
	int ret, no_oml = 0;

	msg = msgb_dequeue(&e1h->oml_tx_list);
	if (!msg)
		no_oml = 1;
	else {
		u_int8_t *l2_data = msg->data;

		/* prepend the mISDNhead */
		hh = (struct mISDNhead *) msgb_push(msg, sizeof(*hh));
		hh->prim = DL_DATA_REQ;

		fprintf(stdout, "OML TX: ");
		hexdump(l2_data, msg->len - MISDN_HEADER_LEN);

		ret = sendto(bfd->fd, msg->data, msg->len, 0,
			     (struct sockaddr *)&e1h->omladdr,
			     sizeof(e1h->omladdr));
		msgb_free(msg);
		usleep(100000);
		/* we always dequeue all OML messages */
		return ret;
	}

	msg = msgb_dequeue(&e1h->rsl_tx_list);
	if (!msg) {
		if (no_oml)
			bfd->when &= ~BSC_FD_WRITE;
	} else {
		u_int8_t *l2_data = msg->data;

		/* prepend the mISDNhead */
		hh = (struct mISDNhead *) msgb_push(msg, sizeof(*hh));
		hh->prim = DL_DATA_REQ;

		fprintf(stdout, "RSL TX: ");
		hexdump(l2_data, msg->len - MISDN_HEADER_LEN);

		ret = sendto(bfd->fd, msg->data, msg->len, 0,
			     (struct sockaddr *)&e1h->l2addr,
			     sizeof(e1h->l2addr));
		msgb_free(msg);
		usleep(10000);
		//sleep(1);
	}

	return ret;
}

#define TSX_ALLOC_SIZE 4096

/* FIXME: read from a B channel TS */
static int handle_tsX_read(struct bsc_fd *bfd)
{
	struct mi_e1_handle *e1h = bfd->data;
	struct msgb *msg = msgb_alloc(TSX_ALLOC_SIZE);
	struct mISDNhead *hh;
	int ret;

	if (!msg)
		return -ENOMEM;

	hh = (struct mISDNhead *) msg->data;

	/* FIXME: Map TEI/SAPI to TRX */
	msg->trx = e1h->bts->c0;

	ret = recv(bfd->fd, msg->data, TSX_ALLOC_SIZE, 0);
	if (ret < 0) {
		fprintf(stderr, "recvfrom error  %s\n", strerror(errno));
		return ret;
	}

	msgb_put(msg, ret);

	DEBUGP(DMIB, "<= BCHAN len = %d, prim(0x%x) id(0x%x)\n", ret, hh->prim, hh->id);

	switch (hh->prim) {
	case PH_CONTROL_IND:
		DEBUGP(DMIB, "got PH_CONTROL_IND\n");
		break;
	case PH_DATA_IND:
		DEBUGP(DMIB, "got PH_DATA_IND\n");

		msg->l2h = msg->data + MISDN_HEADER_LEN;
		
#if 0
		fprintf(stdout, "BCHAN RX: ");
		hexdump(msgb_l2(msg), ret - MISDN_HEADER_LEN);
#endif
		if (!e1h->ts2_fd)
			e1h->ts2_fd = open("/tmp/ts2.dump", O_WRONLY|O_APPEND|O_CREAT, 0660);
		
		write(e1h->ts2_fd, msgb_l2(msg), ret - MISDN_HEADER_LEN);

		break;
	default:
		DEBUGP(DMIB, "got unexpected 0x%x prim\n", hh->prim);
		break;
	}
	/* FIXME: don't free it if we still hold reference! */
	msgb_free(msg);

	return ret;
}

static int handle_tsX_write(struct bsc_fd *bfd)
{
	/* FIXME: write to a B channel TS */
	return -1;
}

/* callback from select.c in case one of the fd's can be read/written */
static int misdn_fd_cb(struct bsc_fd *bfd, unsigned int what)
{
	unsigned int e1_ts = bfd->priv_nr;
	int rc = 0;

	switch (e1_ts) {
	case 1:
		if (what & BSC_FD_READ)
			rc = handle_ts1_read(bfd);
		if (what & BSC_FD_WRITE)
			rc = handle_ts1_write(bfd);
		break;
	default:
		if (what & BSC_FD_READ)
			rc = handle_tsX_read(bfd);
		if (what & BSC_FD_WRITE)
			rc = handle_tsX_write(bfd);
		break;
	}

	return rc;
}

int abis_rsl_sendmsg(struct msgb *msg)
{
	struct mi_e1_handle *e1h = global_e1h;

	msg->l2h = msg->data;
	msgb_enqueue(&e1h->rsl_tx_list, msg);
	e1h->fd[0].when |= BSC_FD_WRITE;

	return 0;
}

int _abis_nm_sendmsg(struct msgb *msg)
{
	struct mi_e1_handle *e1h = global_e1h;

	msg->l2h = msg->data;
	msgb_enqueue(&e1h->oml_tx_list, msg);
	e1h->fd[0].when |= BSC_FD_WRITE;

	return 0;
}

static int activate_bchan(struct mi_e1_handle *e1h, int ts)
{
	struct mISDNhead hh;
	int ret;
	struct bsc_fd *bfd = &e1h->fd[ts-1];

	fprintf(stdout, "activate bchan\n");
	hh.prim = PH_ACTIVATE_REQ;
	hh.id = MISDN_ID_ANY;
	ret = sendto(bfd->fd, &hh, sizeof(hh), 0, NULL, 0);
	if (ret < 0) {
		fprintf(stdout, "could not send ACTIVATE_RQ %s\n",
			strerror(errno));
		return 0;
	}

	return ret;
}

static int mi_e1_setup(struct mi_e1_handle *e1h)
{
	int ts, sk, ret, cnt;
	struct mISDN_devinfo devinfo;

	sk = socket(PF_ISDN, SOCK_RAW, ISDN_P_BASE);
	if (sk < 0) {
		fprintf(stderr, "could not open socket %s\n", strerror(errno));
		return sk;
	}

	ret = ioctl(sk, IMGETCOUNT, &cnt);
	if (ret) {
		fprintf(stderr, "error getting interf count: %s\n",
			strerror(errno));
		close(sk);
		return -ENODEV;
	}
	//DEBUGP(DMI,"%d device%s found\n", cnt, (cnt==1)?"":"s");
	printf("%d device%s found\n", cnt, (cnt==1)?"":"s");
#if 1
	devinfo.id = e1h->cardnr;
	ret = ioctl(sk, IMGETDEVINFO, &devinfo);
	if (ret < 0) {
		fprintf(stdout, "error getting info for device %d: %s\n",
			e1h->cardnr, strerror(errno));
		return -ENODEV;
	}
	fprintf(stdout, "        id:             %d\n", devinfo.id);
	fprintf(stdout, "        Dprotocols:     %08x\n", devinfo.Dprotocols);
	fprintf(stdout, "        Bprotocols:     %08x\n", devinfo.Bprotocols);
	fprintf(stdout, "        protocol:       %d\n", devinfo.protocol);
	fprintf(stdout, "        nrbchan:        %d\n", devinfo.nrbchan);
	fprintf(stdout, "        name:           %s\n", devinfo.name);
#endif

	/* TS0 is CRC4, don't need any fd for it */
	for (ts = 1; ts < NUM_E1_TS; ts++) {
		unsigned int idx = ts-1;
		struct bsc_fd *bfd = &e1h->fd[idx];
		struct sockaddr_mISDN addr;

		bfd->data = e1h;
		bfd->priv_nr = ts;
		bfd->cb = misdn_fd_cb;

		if (ts == 1) {
			bfd->fd = socket(PF_ISDN, SOCK_DGRAM, ISDN_P_LAPD_NT);
			bfd->when = BSC_FD_READ;
		} else
			bfd->fd = socket(PF_ISDN, SOCK_DGRAM, ISDN_P_B_RAW);

		if (bfd->fd < 0) {
			fprintf(stderr, "could not open socket %s\n",
				strerror(errno));
			return bfd->fd;
		}

		memset(&addr, 0, sizeof(addr));
		addr.family = AF_ISDN;
		addr.dev = e1h->cardnr;
		if (ts == 1) {
			addr.channel = 0;
			addr.sapi = 0;/* SAPI not supported yet in kernel */
			addr.tei = TEI_L2ML;
		} else
			addr.channel = ts;

		ret = bind(bfd->fd, (struct sockaddr *) &addr, sizeof(addr));
		if (ret < 0) {
			fprintf(stderr, "could not bind l2 socket %s\n",
				strerror(errno));
			return -EIO;
		}

		if (ts == 2) {
			bfd->when = BSC_FD_READ;
			activate_bchan(e1h, ts);
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

int mi_setup(struct gsm_bts *bts, int cardnr, 
	     void (cb)(int event, struct gsm_bts *bts))
{
	struct mi_e1_handle *e1h;

	e1h = malloc(sizeof(*e1h));
	memset(e1h, 0, sizeof(*e1h));

	e1h->cardnr = cardnr;
	e1h->bts = bts;
	e1h->cb = cb;
	INIT_LLIST_HEAD(&e1h->oml_tx_list);
	INIT_LLIST_HEAD(&e1h->rsl_tx_list);

	global_e1h = e1h;

	return mi_e1_setup(e1h);
}
