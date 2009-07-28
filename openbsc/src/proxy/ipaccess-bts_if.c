/* OpenBSC Abis/IP proxy ip.access nanoBTS */

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
#include <netinet/in.h>

#include <openbsc/gsm_data.h>
#include <openbsc/select.h>
#include <openbsc/tlv.h>
#include <openbsc/msgb.h>
#include <openbsc/debug.h>
#include <openbsc/ipaccess.h>
#include <openbsc/talloc.h>

/* one instance of an ip.access protocol proxy */
struct ipa_proxy {
	/* socket where we listen for incoming OML from BTS */
	struct bsc_fd oml_listen_fd;
	/* socket where we listen for incoming RSL from BTS */
	struct bsc_fd rsl_listen_fd;
	/* list of BTS's (struct ipa_bts_conn */
	struct llist_head bts_list;
};

/* global pointer to the proxy structure */
static struct ipa_proxy *ipp;

struct ipa_proxy_conn {
	struct bsc_fd fd;
	struct llist_head tx_queue;
	struct ipa_bts_conn *bts_conn;
};

/* represents a particular BTS in our proxy */
struct ipa_bts_conn {
	/* list of BTS's (ipa_proxy->bts_list) */
	struct llist_head list;
	/* the unit ID as determined by CCM */
	struct {
		u_int16_t site_id;
		u_int16_t bts_id;
		u_int16_t trx_id;
	} unit_id;

	/* incoming connections from BTS */
	struct ipa_proxy_conn *oml_conn;
	struct ipa_proxy_conn *rsl_conn;

	/* outgoing connections to BSC */
	struct ipa_proxy_conn *bsc_oml_conn;
	struct ipa_proxy_conn *bsc_rsl_conn;

	/* UDP sockets for BTS and BSC injection */
	struct bsc_fd udp_bts_fd;
	struct bsc_fd udp_bsc_fd;

	char *id_tags[0xff];
	u_int8_t *id_resp;
	unsigned int id_resp_len;
};

enum ipp_fd_type {
	OML_FROM_BTS = 1,
	RSL_FROM_BTS = 2,
	OML_TO_BSC = 3,
	RSL_TO_BSC = 4,
	UDP_TO_BTS = 5,
	UDP_TO_BSC = 6,
};

/* some of the code against we link from OpenBSC needs this */
void *tall_bsc_ctx;

static char *listen_ipaddr;
static char *bsc_ipaddr;

#define PROXY_ALLOC_SIZE	300

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

static struct ipa_bts_conn *find_bts_by_unitid(struct ipa_proxy *ipp,
						u_int16_t site_id,
				 		u_int16_t bts_id)
{
	struct ipa_bts_conn *ipbc;

	llist_for_each_entry(ipbc, &ipp->bts_list, list) {
		if (ipbc->unit_id.site_id == site_id &&
		    ipbc->unit_id.bts_id == bts_id)
			return ipbc;		
	}

	return NULL;
}

struct ipa_proxy_conn *alloc_conn(void)
{
	struct ipa_proxy_conn *ipc;

	ipc = talloc_zero(tall_bsc_ctx, struct ipa_proxy_conn);
	if (!ipc)
		return NULL;

	INIT_LLIST_HEAD(&ipc->tx_queue);

	return ipc;
}

static int store_idtags(struct ipa_bts_conn *ipbc, struct tlv_parsed *tlvp)
{
	unsigned int i, len;

	for (i = 0; i <= 0xff; i++) {
		if (!TLVP_PRESENT(tlvp, i))
			continue;

		len = TLVP_LEN(tlvp, i);
#if 0
		if (!ipbc->id_tags[i])
			ipbc->id_tags[i] = talloc_size(tall_bsc_ctx, len);
		else
#endif
			ipbc->id_tags[i] = talloc_realloc_size(tall_bsc_ctx,
							  ipbc->id_tags[i], len);
		if (!ipbc->id_tags[i])
			return -ENOMEM;

		memset(ipbc->id_tags[i], 0, len);
		//memcpy(ipbc->id_tags[i], TLVP_VAL(tlvp, i), len);
	}
	return 0;
}


static struct ipa_proxy_conn *connect_bsc(struct sockaddr_in *sa, int priv_nr, void *data);

/* UDP socket handling */

static int make_sock(struct bsc_fd *bfd, u_int16_t port, int proto, int priv_nr,
		     int (*cb)(struct bsc_fd *fd, unsigned int what),
		     void *data)
{
	struct sockaddr_in addr;
	int ret, on = 1;
	
	bfd->fd = socket(AF_INET, SOCK_DGRAM, proto);
	bfd->cb = cb;
	bfd->when = BSC_FD_READ;
	bfd->data = data;
	bfd->priv_nr = priv_nr;

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

	ret = bsc_register_fd(bfd);
	if (ret < 0) {
		perror("register UDP fd");
		return ret;
	}
	return 0;
}

static int handle_udp_read(struct bsc_fd *bfd)
{
	struct ipa_bts_conn *ipbc = bfd->data;
	struct ipa_proxy_conn *other_conn = NULL;
	struct msgb *msg = msgb_alloc(PROXY_ALLOC_SIZE, "Abis/IP UDP");
	struct ipaccess_head *hh;
	int ret;

	/* with UDP sockets, we cannot read partial packets but have to read
	 * all of it in one go */
	hh = (struct ipaccess_head *) msg->data;
	ret = recv(bfd->fd, msg->data, msg->data_len, 0);
	if (ret < 0) {
		DEBUGP(DINP, "recv error  %s\n", strerror(errno));
		msgb_free(msg);
		return ret;
	}
	if (ret == 0) {
		DEBUGP(DINP, "UDP peer disappeared, dead socket\n");
		bsc_unregister_fd(bfd);
		close(bfd->fd);
		bfd->fd = -1;
		msgb_free(msg);
		return -EIO;
	}
	if (ret < sizeof(*hh)) {
		DEBUGP(DINP, "could not even read header!?!\n");
		msgb_free(msg);
		return -EIO;
	}
	msgb_put(msg, ret);
	msg->l2h = msg->data + sizeof(*hh);
	DEBUGP(DMI, "UDP RX: %s\n", hexdump(msg->data, msg->len));

	if (hh->len != msg->len - sizeof(*hh)) {
		DEBUGP(DMI, "length (%u/%u) disagrees with header(%u)\n",
			msg->len, msg->len - 3, hh->len);
		msgb_free(msg);
		return -EIO;
	}

	switch (bfd->priv_nr) {
	case UDP_TO_BTS:
		/* injection towards BTS */
		switch (hh->proto) {
		case IPAC_PROTO_RSL:
			other_conn = ipbc->rsl_conn;
			break;
		default:
			DEBUGP(DINP, "Unknown protocol 0x%02x, sending to "
				"OML FD\n", hh->proto);
			/* fall through */
		case IPAC_PROTO_IPACCESS:
		case IPAC_PROTO_OML:
			other_conn = ipbc->oml_conn;
			break;
		}
		break;
	case UDP_TO_BSC:
		/* injection towards BSC */
		switch (hh->proto) {
		case IPAC_PROTO_RSL:
			other_conn = ipbc->bsc_rsl_conn;
			break;
		default:
			DEBUGP(DINP, "Unknown protocol 0x%02x, sending to "
				"OML FD\n", hh->proto);
		case IPAC_PROTO_IPACCESS:
		case IPAC_PROTO_OML:
			other_conn = ipbc->bsc_oml_conn;
			break;
		}
		break;
	default:
		DEBUGP(DINP, "Unknown filedescriptor priv_nr=%u\n", bfd->priv_nr);
		break;
	}

	if (other_conn) {
		/* enqueue the message for TX on the respective FD */
		msgb_enqueue(&other_conn->tx_queue, msg);
		other_conn->fd.when |= BSC_FD_WRITE;
	} else
		msgb_free(msg);

	return 0;
}

static int handle_udp_write(struct bsc_fd *bfd)
{
	/* not implemented yet */
	bfd->when &= ~BSC_FD_WRITE;

	return -EIO;
}

/* callback from select.c in case one of the fd's can be read/written */
static int udp_fd_cb(struct bsc_fd *bfd, unsigned int what)
{
	int rc = 0;

	if (what & BSC_FD_READ)
		rc = handle_udp_read(bfd);
	if (what & BSC_FD_WRITE)
		rc = handle_udp_write(bfd);

	return rc;
}

static int ipaccess_rcvmsg(struct ipa_proxy_conn *ipc, struct msgb *msg,
			   struct bsc_fd *bfd)
{
	struct sockaddr_in sin;
	struct tlv_parsed tlvp;
	u_int8_t msg_type = *(msg->l2h);
	u_int16_t site_id, bts_id, trx_id;
	struct ipa_bts_conn *ipbc;
	int ret = 0;

	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	inet_aton(bsc_ipaddr, &sin.sin_addr.s_addr);

	switch (msg_type) {
	case IPAC_MSGT_PING:
		ret = write(bfd->fd, pong, sizeof(pong));
		if (ret < 0)
			return ret;
		if (ret < sizeof(pong)) {
			DEBUGP(DINP, "short write\n");
			return -EIO;
		}
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

		if (!TLVP_PRESENT(&tlvp, IPAC_IDTAG_UNIT)) {
			DEBUGP(DINP, "No Unit ID in ID RESPONSE !?!\n");
			return -EIO;
		}

		/* lookup BTS, create sign_link, ... */
		parse_unitid((char *)TLVP_VAL(&tlvp, IPAC_IDTAG_UNIT),
			     &site_id, &bts_id, &trx_id);
		ipbc = find_bts_by_unitid(ipp, site_id, bts_id);
		if (!ipbc) {
			u_int16_t udp_port;

			DEBUGP(DINP, "New BTS connection from %u/%u/%u: ",
				site_id, bts_id, trx_id);

			/* OML needs to be established before RSL */
			if (bfd->priv_nr != OML_FROM_BTS) {
				DEBUGPC(DINP, "Not a OML connection ?!?\n");
				return -EIO;
			}

			/* allocate new BTS connection data structure */
			ipbc = talloc_zero(tall_bsc_ctx, struct ipa_bts_conn);
			if (!ipbc)
				return -ENOMEM;

			DEBUGPC(DINP, "Created BTS Conn data structure\n");
			ipbc->unit_id.site_id = site_id;
			ipbc->unit_id.bts_id = bts_id;
			ipbc->unit_id.trx_id = trx_id;
			ipbc->oml_conn = ipc;
			ipc->bts_conn = ipbc;

			/* store the content of the ID TAGS for later reference */
			store_idtags(ipbc, &tlvp);
			ipbc->id_resp_len = msg->len;
			ipbc->id_resp = talloc_size(tall_bsc_ctx, ipbc->id_resp_len);
			memcpy(ipbc->id_resp, msg->data, ipbc->id_resp_len);

			/* Create OML TCP connection towards BSC */
			sin.sin_port = htons(3002);
			ipbc->bsc_oml_conn = connect_bsc(&sin, OML_TO_BSC, ipbc);
			if (!ipbc->bsc_oml_conn)
				return -EIO;
			DEBUGP(DINP, "Connected OML to BSC\n");

			/* Create UDP socket for BTS packet injection */
			udp_port = 10000 + (site_id % 1000)*100 + (bts_id % 100);
			ret = make_sock(&ipbc->udp_bts_fd, udp_port, IPPROTO_UDP,
					UDP_TO_BTS, udp_fd_cb, ipbc);
			if (ret < 0)
				return ret;
			DEBUGP(DINP, "Created UDP socket for injection "
				"towards BTS at port %u\n", udp_port);

			/* Create UDP socket for BSC packet injection */
			udp_port = 20000 + (site_id % 1000)*100 + (bts_id % 100);
			ret = make_sock(&ipbc->udp_bsc_fd, udp_port, IPPROTO_UDP,
					UDP_TO_BSC, udp_fd_cb, ipbc);
			if (ret < 0)
				return ret;
			DEBUGP(DINP, "Created UDP socket for injection "
				"towards BSC at port %u\n", udp_port);
			llist_add(&ipbc->list, &ipp->bts_list);
		} else {
			DEBUGP(DINP, "Identified BTS %u/%u/%u\n",
				site_id, bts_id, trx_id);

			if (bfd->priv_nr != RSL_FROM_BTS) {
				DEBUGP(DINP, "Second OML connection from "
					"same BTS ?!?\n");
				return 0;
			}
			ipc->bts_conn = ipbc;
			/* FIXME: implement this for non-0 TRX */
			ipbc->rsl_conn = ipc;

			/* Create RSL TCP connection towards BSC */
			sin.sin_port = htons(3003);
			ipbc->bsc_rsl_conn = connect_bsc(&sin, RSL_TO_BSC, ipbc);
			if (!ipbc->bsc_oml_conn)
				return -EIO;
			DEBUGP(DINP, "Connected RSL to BSC\n");
		}
		break;
	case IPAC_MSGT_ID_GET:
		DEBUGP(DMI, "ID_GET\n");
		if (bfd->priv_nr != OML_TO_BSC && bfd->priv_nr != RSL_TO_BSC) {
			DEBUGP(DINP, "IDentity REQuest from BTS ?!?\n");
			return -EIO;
		}
		ipbc = ipc->bts_conn;
		if (!ipbc) {
			DEBUGP(DINP, "ID_GET from BSC before we have ID_RESP from BTS\n");
			return -EIO;
		}
		ret = write(bfd->fd, ipbc->id_resp, ipbc->id_resp_len);
		break;
	case IPAC_MSGT_ID_ACK:
		DEBUGP(DMI, "ID_ACK? -> ACK!\n");
		ret = write(bfd->fd, id_ack, sizeof(id_ack));
		break;
	}
	return 0;
}

static int handle_tcp_read(struct bsc_fd *bfd)
{
	struct ipa_proxy_conn *ipc = bfd->data;
	struct ipa_bts_conn *ipbc = ipc->bts_conn;
	struct ipa_proxy_conn *bsc_conn;
	struct msgb *msg = msgb_alloc(PROXY_ALLOC_SIZE, "Abis/IP");
	struct ipaccess_head *hh;
	int ret;
	char *btsbsc;

	if (!msg)
		return -ENOMEM;

	if (bfd->priv_nr <= 2)
		btsbsc = "BTS";
	else
		btsbsc = "BSC";

	/* first read our 3-byte header */
	hh = (struct ipaccess_head *) msg->data;
	ret = recv(bfd->fd, msg->data, 3, 0);
	if (ret < 0) {
		fprintf(stderr, "recv error  %s\n", strerror(errno));
		return ret;
	}
	if (ret == 0) {
		fprintf(stderr, "%s disappeared, dead socket\n", btsbsc);
		bsc_unregister_fd(bfd);
		close(bfd->fd);
		bfd->fd = -1;
		return -EIO;
	}
	msgb_put(msg, ret);

	/* then read the length as specified in header */
	msg->l2h = msg->data + sizeof(*hh);
	ret = recv(bfd->fd, msg->l2h, hh->len, 0);
	if (ret < hh->len) {
		fprintf(stderr, "short read!\n");
		msgb_free(msg);
		return -EIO;
	}
	msgb_put(msg, ret);
	DEBUGP(DMI, "RX<-%s: %s\n", btsbsc, hexdump(msg->data, msg->len));

	if (hh->proto == IPAC_PROTO_IPACCESS) {
		ret = ipaccess_rcvmsg(ipc, msg, bfd);
		if (ret < 0) {
			bsc_unregister_fd(bfd);
			close(bfd->fd);
			bfd->fd = -1;
		}
		/* we do not forward the CCM protocol through the
		 * proxy but rather terminate it ourselves */
		msgb_free(msg);
		return ret;
	}

	if (!ipbc) {
		DEBUGP(DINP, "received %s packet but no ipc->bts_conn?!?\n",
			btsbsc);
		msgb_free(msg);
		return -EIO;
	}

	switch (bfd->priv_nr) {
	case OML_FROM_BTS: /* incoming OML data from BTS, forward to BSC OML */
		bsc_conn = ipbc->bsc_oml_conn;
		break;
	case RSL_FROM_BTS: /* incoming RSL data from BTS, forward to BSC RSL */
		bsc_conn = ipbc->bsc_rsl_conn;
		break;
	case OML_TO_BSC: /* incoming OML data from BSC, forward to BTS OML */
		bsc_conn = ipbc->oml_conn;
		break;
	case RSL_TO_BSC: /* incoming RSL data from BSC, forward to BTS RSL */
		bsc_conn = ipbc->rsl_conn;
		break;
	default:
		bsc_conn = NULL;
		break;
	}

	if (bsc_conn) {
		/* enqueue packet towards BSC */
		msgb_enqueue(&bsc_conn->tx_queue, msg);
		/* mark respective filedescriptor as 'we want to write' */
		bsc_conn->fd.when |= BSC_FD_WRITE;
	} else
		msgb_free(msg);

	return ret;
}

/* a TCP socket is ready to be written to */
static int handle_tcp_write(struct bsc_fd *bfd)
{
	struct ipa_proxy_conn *ipc = bfd->data;
	struct llist_head *lh;
	struct msgb *msg;
	int ret;

	/* get the next msg for this timeslot */
	if (llist_empty(&ipc->tx_queue)) {
		bfd->when &= ~BSC_FD_WRITE;
		return 0;
	}
	lh = ipc->tx_queue.next;
	llist_del(lh);
	msg = llist_entry(lh, struct msgb, list);

	DEBUGP(DMI, "TX %u: %s\n", bfd->priv_nr, hexdump(msg->data, msg->len));

	ret = send(bfd->fd, msg->data, msg->len, 0);
	msgb_free(msg);

	return ret;
}

/* callback from select.c in case one of the fd's can be read/written */
static int ipaccess_fd_cb(struct bsc_fd *bfd, unsigned int what)
{
	int rc = 0;

	if (what & BSC_FD_READ) {
		rc = handle_tcp_read(bfd);
		if (rc < 0)
			return rc;
	}
	if (what & BSC_FD_WRITE)
		rc = handle_tcp_write(bfd);

	return rc;
}

/* callback of the listening filedescriptor */
static int listen_fd_cb(struct bsc_fd *listen_bfd, unsigned int what)
{
	int ret;
	struct ipa_proxy_conn *ipc;
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
	DEBUGP(DINP, "accept()ed new %s link from %s\n", 
		listen_bfd->priv_nr == OML_FROM_BTS ? "OML" : "RSL",
		inet_ntoa(sa.sin_addr));

	ipc = alloc_conn();
	if (!ipc) {
		close(ret);
		return -ENOMEM;
	}

	bfd = &ipc->fd;
	bfd->fd = ret;
	bfd->data = ipc;
	bfd->priv_nr = listen_bfd->priv_nr;
	bfd->cb = ipaccess_fd_cb;
	bfd->when = BSC_FD_READ;
	ret = bsc_register_fd(bfd);
	if (ret < 0) {
		fprintf(stderr, "could not register FD\n");
		close(bfd->fd);
		talloc_free(ipc);
		return ret;
	}

	/* Request ID. FIXME: request LOCATION, HW/SW VErsion, Unit Name, Serno */
	ret = write(bfd->fd, id_req, sizeof(id_req));

	return 0;
}

static int make_listen_sock(struct bsc_fd *bfd, u_int16_t port, int priv_nr,
		     int (*cb)(struct bsc_fd *fd, unsigned int what))
{
	struct sockaddr_in addr;
	int ret, on = 1;
	
	bfd->fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	bfd->cb = cb;
	bfd->when = BSC_FD_READ;
	bfd->priv_nr = priv_nr;

	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);
	if (!listen_ipaddr)
		addr.sin_addr.s_addr = INADDR_ANY;
	else
		inet_aton(listen_ipaddr, &addr.sin_addr);

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

/* Actively connect to a BSC.  */
static struct ipa_proxy_conn *connect_bsc(struct sockaddr_in *sa, int priv_nr, void *data)
{
	struct ipa_proxy_conn *ipc;
	struct bsc_fd *bfd;
	int ret, on = 1;

	ipc = alloc_conn();
	if (!ipc)
		return NULL;

	ipc->bts_conn = data;

	bfd = &ipc->fd;
	bfd->fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	bfd->cb = ipaccess_fd_cb;
	bfd->when = BSC_FD_READ | BSC_FD_WRITE;
	bfd->data = ipc;
	bfd->priv_nr = priv_nr;

	setsockopt(bfd->fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));

	ret = connect(bfd->fd, (struct sockaddr *) sa, sizeof(*sa));
	if (ret < 0) {
		fprintf(stderr, "could not connect socket\n");
		close(bfd->fd);
		talloc_free(ipc);
		return NULL;
	}

	/* pre-fill tx_queue with identity request */
	ret = bsc_register_fd(bfd);
	if (ret < 0) {
		close(bfd->fd);
		talloc_free(ipc);
		return NULL;
	}
	
	return ipc;
}

int ipaccess_setup(void)
{
	int ret;

	ipp = talloc_zero(tall_bsc_ctx, struct ipa_proxy);
	if (!ipp)
		return -ENOMEM;
	INIT_LLIST_HEAD(&ipp->bts_list);

	/* Listen for OML connections */
	ret = make_listen_sock(&ipp->oml_listen_fd, 3002, OML_FROM_BTS, listen_fd_cb);
	if (ret < 0)
		return ret;

	/* Listen for RSL connections */
	ret = make_listen_sock(&ipp->rsl_listen_fd, 3003, RSL_FROM_BTS, listen_fd_cb);

	return ret;
}


int main(int argc, char **argv)
{
	listen_ipaddr = "172.27.8.9";
	bsc_ipaddr = "192.168.100.102";

	debug_parse_category_mask("DMI:DINP");

	ipaccess_setup();

	while (1) {
		bsc_select_main(0);
	}
}
