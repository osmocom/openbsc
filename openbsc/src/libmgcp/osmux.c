/*
 * (C) 2012-2013 by Pablo Neira Ayuso <pablo@gnumonks.org>
 * (C) 2012-2013 by On Waves ehf <http://www.on-waves.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <stdio.h> /* for printf */
#include <string.h> /* for memcpy */
#include <stdlib.h> /* for abs */
#include <netinet/in.h>
#include <osmocom/core/msgb.h>
#include <osmocom/core/talloc.h>

#include <osmocom/netif/osmux.h>
#include <osmocom/netif/rtp.h>

#include <openbsc/mgcp.h>
#include <openbsc/mgcp_internal.h>
#include <openbsc/osmux.h>

#define OSMUX_PORT	1984

static struct osmo_fd osmux_fd;

static LLIST_HEAD(osmux_handle_list);

struct osmux_handle {
	struct llist_head head;
	struct osmux_in_handle *in;
};

static void *osmux;

static void osmux_deliver(struct msgb *batch_msg, void *data)
{
	struct in_addr *addr = data;
	struct sockaddr_in out = {
		.sin_family = AF_INET,
		.sin_port = htons(OSMUX_PORT),
	};
	char buf[4096];

	memcpy(&out.sin_addr, addr, sizeof(*addr));

	osmux_snprintf(buf, sizeof(buf), batch_msg);
	LOGP(DMGCP, LOGL_DEBUG, "OSMUX delivering batch to addr=%s: %s\n",
		inet_ntoa(out.sin_addr), buf);

	sendto(osmux_fd.fd, batch_msg->data, batch_msg->len, 0,
		(struct sockaddr *)&out, sizeof(out));
}

static struct osmux_in_handle *
osmux_handle_lookup(struct mgcp_config *cfg, struct in_addr *addr)
{
	struct osmux_handle *h;

	/* Lookup for existing OSMUX handle for this destination address. */
	llist_for_each_entry(h, &osmux_handle_list, head) {
		if (memcmp(h->in->data, addr, sizeof(struct in_addr)) == 0) {
			LOGP(DMGCP, LOGL_DEBUG, "using existing OSMUX handle "
						"for addr=%s\n",
				inet_ntoa(*addr));
			goto out;
		}
	}

	/* Does not exist, allocate it. */
	h = talloc_zero(osmux, struct osmux_handle);
	if (h == NULL)
		return NULL;

	h->in = talloc_zero(osmux, struct osmux_in_handle);
	if (h->in == NULL) {
		talloc_free(h);
		return NULL;
	}

	h->in->osmux_seq = 0; /* sequence number to start OSmux message from */
	h->in->batch_factor = cfg->osmux_batch;
	h->in->deliver = osmux_deliver;
	osmux_xfrm_input_init(h->in);
	h->in->data = addr;

	llist_add(&h->head, &osmux_handle_list);

	LOGP(DMGCP, LOGL_DEBUG, "creating new OSMUX handle for addr=%s\n",
		inet_ntoa(*addr));
out:
	return h->in;
}

int osmux_xfrm_to_osmux(int type, char *buf, int rc, struct mgcp_endpoint *endp)
{
	int ret;
	struct msgb *msg;
	struct in_addr *addr;
	struct osmux_in_handle *in;

	msg = msgb_alloc(4096, "RTP");
	if (msg == NULL)
		return 0;

	memcpy(msg->data, buf, rc);
	msgb_put(msg, rc);

	switch(type) {
	case MGCP_DEST_NET:
		addr = &endp->net_end.addr;
		break;
	case MGCP_DEST_BTS:
		addr = &endp->bts_end.addr;
		break;
	default:
		/* Should not ever happen */
		LOGP(DMGCP, LOGL_ERROR, "Bad type %d. Fix your code.\n", type);
		return 0;
	}

	/* Lookup for osmux input handle that munches this RTP frame */
	in = osmux_handle_lookup(endp->cfg, addr);
	if (in == NULL) {
		LOGP(DMGCP, LOGL_ERROR, "No osmux handle, aborting\n");
		return 0;
	}

	LOGP(DMGCP, LOGL_DEBUG, "Osmux uses cid=%u from endpoint=%d (active=%d)\n",
		endp->ci, ENDPOINT_NUMBER(endp), endp->allocated);

	while ((ret = osmux_xfrm_input(in, msg, endp->ci)) > 0) {
		/* batch full, build and deliver it */
		osmux_xfrm_input_deliver(in);
	}
	return 0;
}

static struct mgcp_endpoint *
endpoint_lookup(struct mgcp_config *cfg, int cid,
		struct in_addr *from_addr, int type)
{
	struct mgcp_endpoint *tmp = NULL, *endp = NULL;
	int i;

	/* Lookup for the endpoint that corresponds to this port */
	for (i=0; i<cfg->trunk.number_endpoints; i++) {
		struct in_addr *this;

		tmp = &cfg->trunk.endpoints[i];

		if (!tmp->allocated)
			continue;

		switch(type) {
		case MGCP_DEST_NET:
			this = &tmp->net_end.addr;
			break;
		case MGCP_DEST_BTS:
			this = &tmp->bts_end.addr;
			break;
		default:
			/* Should not ever happen */
			LOGP(DMGCP, LOGL_ERROR, "Bad type %d. Fix your code.\n", type);
			return 0;
		}

		if (tmp->ci == cid &&
		    memcmp(this, from_addr, sizeof(struct in_addr)) == 0) {
			endp = tmp;
			LOGP(DMGCP, LOGL_NOTICE, "found endpoint with cid=%d\n!",
				cid);
			break;
		}
	}

	return endp;
}

static void scheduled_tx_net_cb(struct msgb *msg, void *data)
{
	struct mgcp_endpoint *endp = data;
	struct sockaddr_in addr;

	mgcp_send(endp, MGCP_DEST_NET, 1, &addr, (char *)msg->data, msg->len);
	msgb_free(msg);
}

static void scheduled_tx_bts_cb(struct msgb *msg, void *data)
{
	struct mgcp_endpoint *endp = data;
	struct sockaddr_in addr;

	mgcp_send(endp, MGCP_DEST_BTS, 1, &addr, (char *)msg->data, msg->len);
	msgb_free(msg);
}

int read_bsc_cb(struct osmo_fd *ofd, unsigned int what)
{
	struct msgb *msg;
	struct osmux_hdr *osmuxh;
	struct llist_head list;
	struct sockaddr_in addr;
	socklen_t slen = sizeof(addr);
	struct mgcp_config *cfg = ofd->data;
	char buf[4096];
	int ret;

	msg = msgb_alloc(4096, "OSMUX from BSC NAT");
	if (msg == NULL) {
		LOGP(DMGCP, LOGL_ERROR, "cannot allocate message\n");
		return -1;
	}
	ret = recvfrom(ofd->fd, msg->data, msg->data_len, 0,
			(struct sockaddr *)&addr, &slen);
	if (ret <= 0) {
		msgb_free(msg);
		LOGP(DMGCP, LOGL_ERROR, "cannot receive message\n");
		return -1;
	}
	msgb_put(msg, ret);

	/* not any further processing dummy messages */
	if (msg->data[0] == DUMMY_LOAD)
		goto out;

	osmux_snprintf(buf, sizeof(buf), msg);
	LOGP(DMGCP, LOGL_DEBUG, "received OSMUX message from "
				"BSC NAT (len=%d) %s\n", msg->len, buf);

	while((osmuxh = osmux_xfrm_output_pull(msg)) != NULL) {
		struct mgcp_endpoint *endp;

		/* Lookup for the endpoint that corresponds to this CI */
		endp = endpoint_lookup(cfg, osmuxh->circuit_id,
				       &addr.sin_addr, MGCP_DEST_NET);
		if (endp == NULL) {
			LOGP(DMGCP, LOGL_ERROR,
			     "Cannot find an endpoint for circuit_id=%d\n",
			     osmuxh->circuit_id);
			goto out;
		}

		LOGP(DMGCP, LOGL_DEBUG,
		     "sending extracted RTP from OSMUX to BSC via endpoint=%u "
		     "(allocated=%d)\n", ENDPOINT_NUMBER(endp), endp->allocated);

		osmux_xfrm_output(osmuxh, &endp->osmux.out, &list);
		osmux_tx_sched(&list, scheduled_tx_bts_cb, endp);
	}
out:
	msgb_free(msg);
	return 0;
}

int read_bsc_nat_cb(struct osmo_fd *ofd, unsigned int what)
{
	struct msgb *msg;
	struct osmux_hdr *osmuxh;
	struct llist_head list;
	struct sockaddr_in addr;
	socklen_t slen = sizeof(addr);
	struct mgcp_config *cfg = ofd->data;
	char buf[4096];
	int ret;

	msg = msgb_alloc(4096, "OSMUX from BSC");
	if (msg == NULL) {
		LOGP(DMGCP, LOGL_ERROR, "cannot allocate message\n");
		return -1;
	}
	ret = recvfrom(ofd->fd, msg->data, msg->data_len, 0,
			(struct sockaddr *)&addr, &slen);
	if (ret <= 0) {
		msgb_free(msg);
		LOGP(DMGCP, LOGL_ERROR, "cannot receive message\n");
		return -1;
	}
	msgb_put(msg, ret);

	/* not any further processing dummy messages */
	if (msg->data[0] == DUMMY_LOAD)
		goto out;

	osmux_snprintf(buf, sizeof(buf), msg);
	LOGP(DMGCP, LOGL_DEBUG, "received OSMUX message "
				"from BSC (len=%d) %s\n", msg->len, buf);

	while((osmuxh = osmux_xfrm_output_pull(msg)) != NULL) {
		struct mgcp_endpoint *endp;

		/* Lookup for the endpoint that corresponds to this CI */
		endp = endpoint_lookup(cfg, osmuxh->circuit_id,
				       &addr.sin_addr, MGCP_DEST_BTS);
		if (endp == NULL) {
			LOGP(DMGCP, LOGL_ERROR,
			     "Cannot find an endpoint for circuit_id=%d\n",
			     osmuxh->circuit_id);
			goto out;
		}

		LOGP(DMGCP, LOGL_DEBUG,
		     "sending extracted RTP from OSMUX to MSC via endpoint=%u "
		     "(allocated=%d)\n", ENDPOINT_NUMBER(endp), endp->allocated);

		osmux_xfrm_output(osmuxh, &endp->osmux.out, &list);
		osmux_tx_sched(&list, scheduled_tx_net_cb, endp);
	}
out:
	msgb_free(msg);
	return 0;
}

int osmux_init(int role, struct mgcp_config *cfg)
{
	int ret;

	switch(role) {
	case OSMUX_ROLE_BSC:
		osmux_fd.cb = read_bsc_cb;
		break;
	case OSMUX_ROLE_BSC_NAT:
		osmux_fd.cb = read_bsc_nat_cb;
		break;
	default:
		LOGP(DMGCP, LOGL_ERROR, "wrong role for OSMUX\n");
		return -1;
	}
	osmux_fd.data = cfg;

	ret = mgcp_create_bind("0.0.0.0", &osmux_fd, OSMUX_PORT);
	if (ret < 0) {
		LOGP(DMGCP, LOGL_ERROR, "cannot bind OSMUX socket\n");
		return ret;
	}
	osmux_fd.when |= BSC_FD_READ;

	ret = osmo_fd_register(&osmux_fd);
	if (ret < 0) {
		LOGP(DMGCP, LOGL_ERROR, "cannot register OSMUX socket\n");
		return ret;
	}

	return 1;
}

int osmux_change_cb(struct mgcp_trunk_config *cfg, int endpoint, int state)
{
	static char buf[] = { DUMMY_LOAD };
	struct mgcp_endpoint *endp = &cfg->endpoints[endpoint];

	if (state != MGCP_ENDP_MDCX)
		return 0;

	LOGP(DMGCP, LOGL_DEBUG, "sending OSMUX dummy load to %s\n",
		inet_ntoa(endp->net_end.addr));

	return udp_send(osmux_fd.fd, &endp->net_end.addr,
			htons(OSMUX_PORT), buf, 1);
}
