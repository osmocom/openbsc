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
#include <openbsc/tlv.h>
#include <openbsc/msgb.h>
#include <openbsc/debug.h>
#include <openbsc/gsm_data.h>
#include <openbsc/abis_nm.h>
#include <openbsc/abis_rsl.h>
#include <openbsc/subchan_demux.h>
#include <openbsc/e1_input.h>
#include <openbsc/ipaccess.h>
#include <openbsc/talloc.h>

/* data structure for one E1 interface with A-bis */
struct ia_e1_handle {
	struct bsc_fd listen_fd;
	struct bsc_fd rsl_listen_fd;
	struct gsm_network *gsmnet;
};

static struct ia_e1_handle *e1h;


#define TS1_ALLOC_SIZE	300

static const u_int8_t pong[] = { 0, 1, IPAC_PROTO_IPACCESS, IPAC_MSGT_PONG };
static const u_int8_t id_ack[] = { 0, 1, IPAC_PROTO_IPACCESS, IPAC_MSGT_ID_ACK };
static const u_int8_t id_req[] = { 0, 17, IPAC_PROTO_IPACCESS, IPAC_MSGT_ID_GET,
					0x01, IPAC_IDTAG_UNIT, 
					0x01, IPAC_IDTAG_MACADDR,
					0x01, IPAC_IDTAG_LOCATION1,
					0x01, IPAC_IDTAG_LOCATION2,
					0x01, IPAC_IDTAG_EQUIPVERS,
					0x01, IPAC_IDTAG_SWVERSION,
					0x01, IPAC_IDTAG_UNITNAME,
					0x01, IPAC_IDTAG_SERNR,
				};

static const char *idtag_names[] = {
	[IPAC_IDTAG_SERNR]	= "Serial_Number",
	[IPAC_IDTAG_UNITNAME]	= "Unit_Name",
	[IPAC_IDTAG_LOCATION1]	= "Location_1",
	[IPAC_IDTAG_LOCATION2]	= "Location_2",
	[IPAC_IDTAG_EQUIPVERS]	= "Equipment_Version",
	[IPAC_IDTAG_SWVERSION]	= "Software_Version",
	[IPAC_IDTAG_IPADDR]	= "IP_Address",
	[IPAC_IDTAG_MACADDR]	= "MAC_Address",
	[IPAC_IDTAG_UNIT]	= "Unit_ID",
};

static const char *ipac_idtag_name(int tag)
{
	if (tag >= ARRAY_SIZE(idtag_names))
		return "unknown";

	return idtag_names[tag];
}

static int ipac_idtag_parse(struct tlv_parsed *dec, unsigned char *buf, int len)
{
	u_int8_t t_len;
	u_int8_t t_tag;
	u_int8_t *cur = buf;

	while (cur < buf + len) {
		t_len = *cur++;
		t_tag = *cur++;

		DEBUGPC(DMI, "%s='%s' ", ipac_idtag_name(t_tag), cur);

		dec->lv[t_tag].len = t_len;
		dec->lv[t_tag].val = cur;

		cur += t_len;
	}
	return 0;
}

struct gsm_bts *find_bts_by_unitid(struct gsm_network *net,
				   u_int16_t site_id, u_int16_t bts_id)
{
	struct gsm_bts *bts;
	int i;

	llist_for_each_entry(bts, &net->bts_list, list) {

		if (!is_ipaccess_bts(bts))
			continue;

		if (bts->ip_access.site_id == site_id &&
		    bts->ip_access.bts_id == bts_id)
			return bts;
	}

	return NULL;
}

static int parse_unitid(const char *str, u_int16_t *site_id, u_int16_t *bts_id,
			u_int16_t *trx_id)
{
	unsigned long ul;
	char *endptr;
	const char *nptr;

	nptr = str;
	ul = strtoul(nptr, &endptr, 10);
	if (endptr <= nptr)
		return -EINVAL;
	if (site_id)
		*site_id = ul & 0xffff;

	if (*endptr++ != '/')
		return -EINVAL;

	nptr = endptr;
	ul = strtoul(nptr, &endptr, 10);
	if (endptr <= nptr)
		return -EINVAL;
	if (bts_id)
		*bts_id = ul & 0xffff;

	if (*endptr++ != '/')
		return -EINVAL;
	
	nptr = endptr;
	ul = strtoul(nptr, &endptr, 10);
	if (endptr <= nptr)
		return -EINVAL;
	if (trx_id)
		*trx_id = ul & 0xffff;

	return 0;
}

static int ipaccess_rcvmsg(struct e1inp_line *line, struct msgb *msg,
			   struct bsc_fd *bfd)
{
	struct tlv_parsed tlvp;
	u_int8_t msg_type = *(msg->l2h);
	u_int16_t site_id, bts_id, trx_id;
	struct gsm_bts *bts;
	int ret = 0;

	switch (msg_type) {
	case IPAC_MSGT_PING:
		ret = write(bfd->fd, pong, sizeof(pong));
		break;
	case IPAC_MSGT_PONG:
		DEBUGP(DMI, "PONG!\n");
		break;
	case IPAC_MSGT_ID_RESP:
		DEBUGP(DMI, "ID_RESP ");
		/* parse tags, search for Unit ID */
		ipac_idtag_parse(&tlvp, (u_int8_t *)msg->l2h + 2,
				 msgb_l2len(msg)-2);
		DEBUGP(DMI, "\n");

		if (!TLVP_PRESENT(&tlvp, IPAC_IDTAG_UNIT))
			break;

		/* lookup BTS, create sign_link, ... */
		parse_unitid((char *)TLVP_VAL(&tlvp, IPAC_IDTAG_UNIT),
			     &site_id, &bts_id, &trx_id);
		bts = find_bts_by_unitid(e1h->gsmnet, site_id, bts_id);
		if (!bts) {
			DEBUGP(DINP, "Unable to find BTS configuration for "
			       " %u/%u/%u, disconnecting\n", site_id, bts_id,
				trx_id);
			return -EIO;
		}
		DEBUGP(DINP, "Identified BTS %u/%u/%u\n", site_id, bts_id, trx_id);
		if (bfd->priv_nr == 1) {
			bts->oml_link = e1inp_sign_link_create(&line->ts[1-1],
						  E1INP_SIGN_OML, bts->c0,
						  0, 0xff);
		} else if (bfd->priv_nr == 2) {
			struct e1inp_ts *e1i_ts;
			struct bsc_fd *newbfd;
			
			/* FIXME: implement this for non-0 TRX */
			bfd->data = line = bts->oml_link->ts->line;
			e1i_ts = &line->ts[2-1];
			newbfd = &e1i_ts->driver.ipaccess.fd;

			bts->c0->rsl_link = 
				e1inp_sign_link_create(e1i_ts,
							E1INP_SIGN_RSL, bts->c0,
							0, 0);
			/* get rid of our old temporary bfd */
			memcpy(newbfd, bfd, sizeof(*newbfd));
			bsc_unregister_fd(bfd);
			bsc_register_fd(newbfd);
			free(bfd);
		}
		break;
	case IPAC_MSGT_ID_ACK:
		DEBUGP(DMI, "ID_ACK? -> ACK!\n");
		ret = write(bfd->fd, id_ack, sizeof(id_ack));
		break;	
	}
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
	DEBUGP(DMI, "RX %u: %s\n", ts_nr, hexdump(msgb_l2(msg), ret));

	if (hh->proto == IPAC_PROTO_IPACCESS) {
		ret = ipaccess_rcvmsg(line, msg, bfd);
		if (ret < 0) {
			e1inp_event(e1i_ts, EVT_E1_TEI_DN, 0, IPAC_PROTO_RSL);
			e1inp_event(e1i_ts, EVT_E1_TEI_DN, 0, IPAC_PROTO_OML);
			bsc_unregister_fd(bfd);
			close(bfd->fd);
			bfd->fd = -1;
		}
		msgb_free(msg);
		return ret;
	}
	/* BIG FAT WARNING: bfd might no longer exist here, since ipaccess_rcvmsg()
	 * might have free'd it !!! */

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

	/* prepend the ip.access header */
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
		fprintf(stderr, "unknown E1 TS type %u\n", e1i_ts->type);

	return rc;
}


static int ts_want_write(struct e1inp_ts *e1i_ts)
{
	e1i_ts->driver.ipaccess.fd.when |= BSC_FD_WRITE;

	return 0;
}

struct e1inp_driver ipaccess_driver = {
	.name = "ip.access",
	.want_write = ts_want_write,
};

/* callback of the OML listening filedescriptor */
static int listen_fd_cb(struct bsc_fd *listen_bfd, unsigned int what)
{
	int ret;
	int idx = 0;
	struct e1inp_line *line;
	struct e1inp_ts *e1i_ts;
	struct bsc_fd *bfd;
	struct sockaddr_in sa;
	socklen_t sa_len = sizeof(sa);

	if (!(what & BSC_FD_READ))
		return 0;

	ret = accept(listen_bfd->fd, (struct sockaddr *) &sa, &sa_len);
	if (ret < 0) {
		perror("accept");
		return ret;
	}
	DEBUGP(DINP, "accept()ed new OML link from %s\n", inet_ntoa(sa.sin_addr));

	line = talloc(tall_bsc_ctx, struct e1inp_line);
	if (!line) {
		close(ret);
		return -ENOMEM;
	}
	memset(line, 0, sizeof(*line));
	line->driver = &ipaccess_driver;
	//line->driver_data = e1h;
	/* create virrtual E1 timeslots for signalling */
	e1inp_ts_config(&line->ts[1-1], line, E1INP_TS_TYPE_SIGN);
	e1inp_ts_config(&line->ts[2-1], line, E1INP_TS_TYPE_SIGN);

	e1i_ts = &line->ts[idx];

	bfd = &e1i_ts->driver.ipaccess.fd;
	bfd->fd = ret;
	bfd->data = line;
	bfd->priv_nr = 1;
	bfd->cb = ipaccess_fd_cb;
	bfd->when = BSC_FD_READ;
	ret = bsc_register_fd(bfd);
	if (ret < 0) {
		fprintf(stderr, "could not register FD\n");
		close(bfd->fd);
		free(line);
		return ret;
	}

	/* Request ID. FIXME: request LOCATION, HW/SW VErsion, Unit Name, Serno */
	ret = write(bfd->fd, id_req, sizeof(id_req));

	return e1inp_line_register(line);
}

static int rsl_listen_fd_cb(struct bsc_fd *listen_bfd, unsigned int what)
{
	struct sockaddr_in sa;
	socklen_t sa_len = sizeof(sa);
	struct bsc_fd *bfd = talloc(tall_bsc_ctx, struct bsc_fd);
	int ret;

	if (!(what & BSC_FD_READ))
		return 0;

	/* Some BTS has connected to us, but we don't know yet which line
	 * (as created by the OML link) to associate it with.  Thus, we
	 * aloocate a temporary bfd until we have received ID from BTS */

	bfd->fd = accept(listen_bfd->fd, (struct sockaddr *) &sa, &sa_len);
	if (bfd->fd < 0) {
		perror("accept");
		return bfd->fd;
	}
	DEBUGP(DINP, "accept()ed new RSL link from %s\n", inet_ntoa(sa.sin_addr));
	bfd->priv_nr = 2;
	bfd->cb = ipaccess_fd_cb;
	bfd->when = BSC_FD_READ;
	ret = bsc_register_fd(bfd);
	if (ret < 0) {
		fprintf(stderr, "could not register FD\n");
		close(bfd->fd);
		free(bfd);
		return ret;
	}
	/* Request ID. FIXME: request LOCATION, HW/SW VErsion, Unit Name, Serno */
	ret = write(bfd->fd, id_req, sizeof(id_req));

	return 0;
}

static int make_sock(struct bsc_fd *bfd, u_int16_t port,
		     int (*cb)(struct bsc_fd *fd, unsigned int what))
{
	struct sockaddr_in addr;
	int ret, on = 1;
	
	bfd->fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	bfd->cb = cb;
	bfd->when = BSC_FD_READ;
	//bfd->data = line;

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

/* Actively connect to a BTS.  Currently used by ipaccess-config.c */
int ipaccess_connect(struct e1inp_line *line, struct sockaddr_in *sa)
{
	struct e1inp_ts *e1i_ts = &line->ts[0];
	struct bsc_fd *bfd = &e1i_ts->driver.ipaccess.fd;
	int ret, on = 1;

	bfd->fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	bfd->cb = ipaccess_fd_cb;
	bfd->when = BSC_FD_READ | BSC_FD_WRITE;
	bfd->data = line;
	bfd->priv_nr = 1;

	setsockopt(bfd->fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));

	ret = connect(bfd->fd, (struct sockaddr *) sa, sizeof(*sa));
	if (ret < 0) {
		fprintf(stderr, "could not connect socket\n");
		close(bfd->fd);
		return ret;
	}

	ret = bsc_register_fd(bfd);
	if (ret < 0) {
		close(bfd->fd);
		return ret;
	}
	
	line->driver = &ipaccess_driver;

	return e1inp_line_register(line);
}

int ipaccess_setup(struct gsm_network *gsmnet)
{
	int ret;

	/* register the driver with the core */
	/* FIXME: do this in the plugin initializer function */
	ret = e1inp_driver_register(&ipaccess_driver);
	if (ret)
		return ret;

	e1h = talloc(tall_bsc_ctx, struct ia_e1_handle);
	memset(e1h, 0, sizeof(*e1h));
	e1h->gsmnet = gsmnet;

	/* Listen for OML connections */
	ret = make_sock(&e1h->listen_fd, 3002, listen_fd_cb);
	if (ret < 0)
		return ret;

	/* Listen for RSL connections */
	ret = make_sock(&e1h->rsl_listen_fd, 3003, rsl_listen_fd_cb);

	return ret;
}
