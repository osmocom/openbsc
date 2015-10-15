/*
 * (C) 2012-2013 by Pablo Neira Ayuso <pablo@gnumonks.org>
 * (C) 2012-2013 by On Waves ehf <http://www.on-waves.com>
 * All rights not specifically granted under this license are reserved.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Affero General Public License as published by the
 * Free Software Foundation; either version 3 of the License, or (at your
 * option) any later version.
 */

#include <stdio.h> /* for printf */
#include <string.h> /* for memcpy */
#include <stdlib.h> /* for abs */
#include <inttypes.h> /* for PRIu64 */
#include <netinet/in.h>
#include <osmocom/core/msgb.h>
#include <osmocom/core/talloc.h>

#include <osmocom/netif/osmux.h>
#include <osmocom/netif/rtp.h>

#include <openbsc/mgcp.h>
#include <openbsc/mgcp_internal.h>
#include <openbsc/osmux.h>

static struct osmo_fd osmux_fd;

static LLIST_HEAD(osmux_handle_list);

struct osmux_handle {
	struct llist_head head;
	struct osmux_in_handle *in;
	struct in_addr rem_addr;
	int rem_port;
	int refcnt;
};

static void *osmux;

static void osmux_deliver(struct msgb *batch_msg, void *data)
{
	struct osmux_handle *handle = data;
	struct sockaddr_in out = {
		.sin_family = AF_INET,
		.sin_port = handle->rem_port,
	};

	memcpy(&out.sin_addr, &handle->rem_addr, sizeof(handle->rem_addr));
	sendto(osmux_fd.fd, batch_msg->data, batch_msg->len, 0,
		(struct sockaddr *)&out, sizeof(out));
	msgb_free(batch_msg);
}

static struct osmux_handle *
osmux_handle_find_get(struct in_addr *addr, int rem_port)
{
	struct osmux_handle *h;

	/* Lookup for existing OSMUX handle for this destination address. */
	llist_for_each_entry(h, &osmux_handle_list, head) {
		if (memcmp(&h->rem_addr, addr, sizeof(struct in_addr)) == 0 &&
		    h->rem_port == rem_port) {
			LOGP(DMGCP, LOGL_DEBUG, "using existing OSMUX handle "
						"for addr=%s:%d\n",
				inet_ntoa(*addr), ntohs(rem_port));
			h->refcnt++;
			return h;
		}
	}

	return NULL;
}

static void osmux_handle_put(struct osmux_in_handle *in)
{
	struct osmux_handle *h;

	/* Lookup for existing OSMUX handle for this destination address. */
	llist_for_each_entry(h, &osmux_handle_list, head) {
		if (h->in == in) {
			if (--h->refcnt == 0) {
				LOGP(DMGCP, LOGL_INFO,
				     "Releasing unused osmux handle for %s:%d\n",
				     inet_ntoa(h->rem_addr),
				     ntohs(h->rem_port));
				LOGP(DMGCP, LOGL_INFO, "Stats: "
				     "input RTP msgs: %u bytes: %"PRIu64" "
				     "output osmux msgs: %u bytes: %"PRIu64"\n",
				     in->stats.input_rtp_msgs,
				     in->stats.input_rtp_bytes,
				     in->stats.output_osmux_msgs,
				     in->stats.output_osmux_bytes);
				llist_del(&h->head);
				osmux_xfrm_input_fini(h->in);
				talloc_free(h);
			}
			return;
		}
	}
	LOGP(DMGCP, LOGL_ERROR, "cannot find Osmux input handle %p\n", in);
}

static struct osmux_handle *
osmux_handle_alloc(struct mgcp_config *cfg, struct in_addr *addr, int rem_port)
{
	struct osmux_handle *h;

	h = talloc_zero(osmux, struct osmux_handle);
	if (!h)
		return NULL;
	h->rem_addr = *addr;
	h->rem_port = rem_port;
	h->refcnt++;

	h->in = talloc_zero(h, struct osmux_in_handle);
	if (!h->in) {
		talloc_free(h);
		return NULL;
	}

	h->in->osmux_seq = 0; /* sequence number to start OSmux message from */
	h->in->batch_factor = cfg->osmux_batch;
	/* If batch size is zero, the library defaults to 1470 bytes. */
	h->in->batch_size = cfg->osmux_batch_size;
	h->in->deliver = osmux_deliver;
	osmux_xfrm_input_init(h->in);
	h->in->data = h;

	llist_add(&h->head, &osmux_handle_list);

	LOGP(DMGCP, LOGL_DEBUG, "created new OSMUX handle for addr=%s:%d\n",
		inet_ntoa(*addr), ntohs(rem_port));

	return h;
}

static struct osmux_in_handle *
osmux_handle_lookup(struct mgcp_config *cfg, struct in_addr *addr, int rem_port)
{
	struct osmux_handle *h;

	h = osmux_handle_find_get(addr, rem_port);
	if (h != NULL)
		return h->in;

	h = osmux_handle_alloc(cfg, addr, rem_port);
	if (h == NULL)
		return NULL;

	return h->in;
}

int osmux_xfrm_to_osmux(int type, char *buf, int rc, struct mgcp_endpoint *endp)
{
	int ret;
	struct msgb *msg;

	msg = msgb_alloc(4096, "RTP");
	if (!msg)
		return 0;

	memcpy(msg->data, buf, rc);
	msgb_put(msg, rc);

	while ((ret = osmux_xfrm_input(endp->osmux.in, msg, endp->osmux.cid)) > 0) {
		/* batch full, build and deliver it */
		osmux_xfrm_input_deliver(endp->osmux.in);
	}
	return 0;
}

static struct mgcp_endpoint *
endpoint_lookup(struct mgcp_config *cfg, int cid,
		struct in_addr *from_addr, int type)
{
	struct mgcp_endpoint *tmp = NULL;
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
			return NULL;
		}

		if (tmp->osmux.cid == cid && this->s_addr == from_addr->s_addr)
			return tmp;
	}

	LOGP(DMGCP, LOGL_ERROR, "Cannot find endpoint with cid=%d\n", cid);

	return NULL;
}

static void scheduled_tx_net_cb(struct msgb *msg, void *data)
{
	struct mgcp_endpoint *endp = data;
	struct sockaddr_in addr = {
		.sin_addr = endp->net_end.addr,
		.sin_port = endp->net_end.rtp_port,
	};

	endp->bts_end.octets += msg->len;
	endp->bts_end.packets++;

	mgcp_send(endp, MGCP_DEST_NET, 1, &addr, (char *)msg->data, msg->len);
	msgb_free(msg);
}

static void scheduled_tx_bts_cb(struct msgb *msg, void *data)
{
	struct mgcp_endpoint *endp = data;
	struct sockaddr_in addr = {
		.sin_addr = endp->bts_end.addr,
		.sin_port = endp->bts_end.rtp_port,
	};

	endp->net_end.octets += msg->len;
	endp->net_end.packets++;

	mgcp_send(endp, MGCP_DEST_BTS, 1, &addr, (char *)msg->data, msg->len);
	msgb_free(msg);
}

static struct msgb *osmux_recv(struct osmo_fd *ofd, struct sockaddr_in *addr)
{
	struct msgb *msg;
	socklen_t slen = sizeof(*addr);
	int ret;

	msg = msgb_alloc(4096, "OSMUX");
	if (!msg) {
		LOGP(DMGCP, LOGL_ERROR, "cannot allocate message\n");
		return NULL;
	}
	ret = recvfrom(ofd->fd, msg->data, msg->data_len, 0,
			(struct sockaddr *)addr, &slen);
	if (ret <= 0) {
		msgb_free(msg);
		LOGP(DMGCP, LOGL_ERROR, "cannot receive message\n");
		return NULL;
	}
	msgb_put(msg, ret);

	return msg;
}

#define osmux_chunk_length(msg, rem) (rem - msg->len);

int osmux_read_from_bsc_nat_cb(struct osmo_fd *ofd, unsigned int what)
{
	struct msgb *msg;
	struct osmux_hdr *osmuxh;
	struct llist_head list;
	struct sockaddr_in addr;
	struct mgcp_config *cfg = ofd->data;
	uint32_t rem;

	msg = osmux_recv(ofd, &addr);
	if (!msg)
		return -1;

	/* not any further processing dummy messages */
	if (msg->data[0] == MGCP_DUMMY_LOAD)
		goto out;

	rem = msg->len;
	while((osmuxh = osmux_xfrm_output_pull(msg)) != NULL) {
		struct mgcp_endpoint *endp;

		/* Yes, we use MGCP_DEST_NET to locate the origin */
		endp = endpoint_lookup(cfg, osmuxh->circuit_id,
				       &addr.sin_addr, MGCP_DEST_NET);
		if (!endp) {
			LOGP(DMGCP, LOGL_ERROR,
			     "Cannot find an endpoint for circuit_id=%d\n",
			     osmuxh->circuit_id);
			goto out;
		}
		endp->osmux.stats.octets += osmux_chunk_length(msg, rem);
		endp->osmux.stats.chunks++;
		rem = msg->len;

		osmux_xfrm_output(osmuxh, &endp->osmux.out, &list);
		osmux_tx_sched(&list, scheduled_tx_bts_cb, endp);
	}
out:
	msgb_free(msg);
	return 0;
}

/* This is called from the bsc-nat */
static int osmux_handle_dummy(struct mgcp_config *cfg, struct sockaddr_in *addr,
			      struct msgb *msg)
{
	struct mgcp_endpoint *endp;
	uint8_t osmux_cid;

	if (msg->len < 1 + sizeof(osmux_cid)) {
		LOGP(DMGCP, LOGL_ERROR,
		     "Discarding truncated Osmux dummy load\n");
		goto out;
	}

	LOGP(DMGCP, LOGL_DEBUG, "Received Osmux dummy load from %s\n",
	     inet_ntoa(addr->sin_addr));

	if (!cfg->osmux) {
		LOGP(DMGCP, LOGL_ERROR,
		     "bsc wants to use Osmux but bsc-nat did not request it\n");
		goto out;
	}

	/* extract the osmux CID from the dummy message */
	memcpy(&osmux_cid, &msg->data[1], sizeof(osmux_cid));

	endp = endpoint_lookup(cfg, osmux_cid, &addr->sin_addr, MGCP_DEST_BTS);
	if (!endp) {
		LOGP(DMGCP, LOGL_ERROR,
		     "Cannot find endpoint for Osmux CID %d\n", osmux_cid);
		goto out;
	}

	if (endp->osmux.state == OSMUX_STATE_ENABLED)
		goto out;

	if (osmux_enable_endpoint(endp, OSMUX_ROLE_BSC_NAT,
				  &addr->sin_addr, addr->sin_port) < 0 ){
		LOGP(DMGCP, LOGL_ERROR,
		     "Could not enable osmux in endpoint %d\n",
		     ENDPOINT_NUMBER(endp));
		goto out;
	}

	LOGP(DMGCP, LOGL_INFO, "Enabling osmux in endpoint %d for %s:%u\n",
	     ENDPOINT_NUMBER(endp), inet_ntoa(addr->sin_addr),
	     ntohs(addr->sin_port));
out:
	msgb_free(msg);
	return 0;
}

int osmux_read_from_bsc_cb(struct osmo_fd *ofd, unsigned int what)
{
	struct msgb *msg;
	struct osmux_hdr *osmuxh;
	struct llist_head list;
	struct sockaddr_in addr;
	struct mgcp_config *cfg = ofd->data;
	uint32_t rem;

	msg = osmux_recv(ofd, &addr);
	if (!msg)
		return -1;

	/* not any further processing dummy messages */
	if (msg->data[0] == MGCP_DUMMY_LOAD)
		return osmux_handle_dummy(cfg, &addr, msg);

	rem = msg->len;
	while((osmuxh = osmux_xfrm_output_pull(msg)) != NULL) {
		struct mgcp_endpoint *endp;

		/* Yes, we use MGCP_DEST_BTS to locate the origin */
		endp = endpoint_lookup(cfg, osmuxh->circuit_id,
				       &addr.sin_addr, MGCP_DEST_BTS);
		if (!endp) {
			LOGP(DMGCP, LOGL_ERROR,
			     "Cannot find an endpoint for circuit_id=%d\n",
			     osmuxh->circuit_id);
			goto out;
		}
		endp->osmux.stats.octets += osmux_chunk_length(msg, rem);
		endp->osmux.stats.chunks++;
		rem = msg->len;

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
		osmux_fd.cb = osmux_read_from_bsc_nat_cb;
		break;
	case OSMUX_ROLE_BSC_NAT:
		osmux_fd.cb = osmux_read_from_bsc_cb;
		break;
	default:
		LOGP(DMGCP, LOGL_ERROR, "wrong role for OSMUX\n");
		return -1;
	}
	osmux_fd.data = cfg;

	ret = mgcp_create_bind(cfg->osmux_addr, &osmux_fd, cfg->osmux_port);
	if (ret < 0) {
		LOGP(DMGCP, LOGL_ERROR, "cannot bind OSMUX socket\n");
		return ret;
	}
	mgcp_set_ip_tos(osmux_fd.fd, cfg->endp_dscp);
	osmux_fd.when |= BSC_FD_READ;

	ret = osmo_fd_register(&osmux_fd);
	if (ret < 0) {
		LOGP(DMGCP, LOGL_ERROR, "cannot register OSMUX socket\n");
		return ret;
	}
	cfg->osmux_init = 1;

	return 0;
}

int osmux_enable_endpoint(struct mgcp_endpoint *endp, int role,
			  struct in_addr *addr, uint16_t port)
{
	/* If osmux is enabled, initialize the output handler. This handler is
	 * used to reconstruct the RTP flow from osmux. The RTP SSRC is
	 * allocated based on the circuit ID (endp->osmux.cid), which is unique
	 * in the local scope to the BSC/BSC-NAT. We use it to divide the RTP
	 * SSRC space (2^32) by the 256 possible circuit IDs, then randomly
	 * select one value from that window. Thus, we have no chance to have
	 * overlapping RTP SSRC traveling to the BTSes behind the BSC,
	 * similarly, for flows traveling to the MSC.
	 */
	static const uint32_t rtp_ssrc_winlen = UINT32_MAX / 256;

	if (endp->osmux.state == OSMUX_STATE_DISABLED) {
		LOGP(DMGCP, LOGL_ERROR, "Endpoint %u didn't request Osmux\n",
		     ENDPOINT_NUMBER(endp));
		return -1;
	}

	osmux_xfrm_output_init(&endp->osmux.out,
			       (endp->osmux.cid * rtp_ssrc_winlen) +
			       (random() % rtp_ssrc_winlen));

	endp->osmux.in = osmux_handle_lookup(endp->cfg, addr, port);
	if (!endp->osmux.in) {
		LOGP(DMGCP, LOGL_ERROR, "Cannot allocate input osmux handle\n");
		return -1;
	}
	if (!osmux_xfrm_input_open_circuit(endp->osmux.in, endp->osmux.cid,
					   endp->cfg->osmux_dummy)) {
		LOGP(DMGCP, LOGL_ERROR, "Cannot open osmux circuit %u\n",
		     endp->osmux.cid);
		return -1;
	}

	switch (endp->cfg->role) {
		case MGCP_BSC_NAT:
			endp->type = MGCP_OSMUX_BSC_NAT;
			break;
		case MGCP_BSC:
			endp->type = MGCP_OSMUX_BSC;
			break;
	}
	endp->osmux.state = OSMUX_STATE_ENABLED;

	return 0;
}

void osmux_disable_endpoint(struct mgcp_endpoint *endp)
{
	LOGP(DMGCP, LOGL_INFO, "Releasing endpoint %u using Osmux CID %u\n",
	     ENDPOINT_NUMBER(endp), endp->osmux.cid);
	osmux_xfrm_input_close_circuit(endp->osmux.in, endp->osmux.cid);
	endp->osmux.state = OSMUX_STATE_DISABLED;
	endp->osmux.cid = -1;
	osmux_handle_put(endp->osmux.in);
}

void osmux_release_cid(struct mgcp_endpoint *endp)
{
	if (endp->osmux.allocated_cid >= 0)
		osmux_put_cid(endp->osmux.allocated_cid);
	endp->osmux.allocated_cid = -1;
}

void osmux_allocate_cid(struct mgcp_endpoint *endp)
{
	osmux_release_cid(endp);
	endp->osmux.allocated_cid = osmux_get_cid();
}

/* We don't need to send the dummy load for osmux so often as another endpoint
 * may have already punched the hole in the firewall. This approach is simple
 * though.
 */
int osmux_send_dummy(struct mgcp_endpoint *endp)
{
	char buf[1 + sizeof(uint8_t)];
	struct in_addr addr_unset = {};

	buf[0] = MGCP_DUMMY_LOAD;
	memcpy(&buf[1], &endp->osmux.cid, sizeof(endp->osmux.cid));

	/* Wait until we have the connection information from MDCX */
	if (memcmp(&endp->net_end.addr, &addr_unset, sizeof(addr_unset)) == 0)
		return 0;

	if (endp->osmux.state == OSMUX_STATE_ACTIVATING) {
		if (osmux_enable_endpoint(endp, OSMUX_ROLE_BSC,
					  &endp->net_end.addr,
					  htons(endp->cfg->osmux_port)) < 0) {
			LOGP(DMGCP, LOGL_ERROR,
			     "Could not activate osmux in endpoint %d\n",
			     ENDPOINT_NUMBER(endp));
		}
		LOGP(DMGCP, LOGL_ERROR,
		     "Osmux CID %u for %s:%u is now enabled\n",
		     endp->osmux.cid, inet_ntoa(endp->net_end.addr),
		     endp->cfg->osmux_port);
	}
	LOGP(DMGCP, LOGL_DEBUG,
	     "sending OSMUX dummy load to %s CID %u\n",
	     inet_ntoa(endp->net_end.addr), endp->osmux.cid);

	return mgcp_udp_send(osmux_fd.fd, &endp->net_end.addr,
			     htons(endp->cfg->osmux_port), buf, sizeof(buf));
}

/* bsc-nat allocates/releases the Osmux circuit ID */
static uint8_t osmux_cid_bitmap[(OSMUX_CID_MAX + 1) / 8];

int osmux_used_cid(void)
{
	int i, j, used = 0;

	for (i = 0; i < sizeof(osmux_cid_bitmap); i++) {
		for (j = 0; j < 8; j++) {
			if (osmux_cid_bitmap[i] & (1 << j))
				used += 1;
		}
	}

	return used;
}

int osmux_get_cid(void)
{
	int i, j;

	for (i = 0; i < sizeof(osmux_cid_bitmap); i++) {
		for (j = 0; j < 8; j++) {
			if (osmux_cid_bitmap[i] & (1 << j))
				continue;

			osmux_cid_bitmap[i] |= (1 << j);
			LOGP(DMGCP, LOGL_DEBUG,
			     "Allocating Osmux CID %u from pool\n", (i * 8) + j);
			return (i * 8) + j;
		}
	}

	LOGP(DMGCP, LOGL_ERROR, "All Osmux circuits are in use!\n");
	return -1;
}

void osmux_put_cid(uint8_t osmux_cid)
{
	LOGP(DMGCP, LOGL_DEBUG, "Osmux CID %u is back to the pool\n", osmux_cid);
	osmux_cid_bitmap[osmux_cid / 8] &= ~(1 << (osmux_cid % 8));
}
