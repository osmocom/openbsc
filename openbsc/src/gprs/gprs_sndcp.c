/* GPRS SNDCP protocol implementation as per 3GPP TS 04.65 */

/* (C) 2010 by Harald Welte <laforge@gnumonks.org>
 * (C) 2010 by On-Waves
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

#include <errno.h>
#include <stdint.h>

#include <osmocom/core/msgb.h>
#include <osmocom/core/linuxlist.h>
#include <osmocom/core/timer.h>
#include <osmocom/core/talloc.h>
#include <osmocom/gprs/gprs_bssgp.h>

#include <openbsc/gsm_data.h>
#include <openbsc/debug.h>
#include <openbsc/gprs_llc.h>
#include <openbsc/sgsn.h>

#include "gprs_sndcp.h"

/* Chapter 7.2: SN-PDU Formats */
struct sndcp_common_hdr {
	/* octet 1 */
	uint8_t nsapi:4;
	uint8_t more:1;
	uint8_t type:1;
	uint8_t first:1;
	uint8_t spare:1;
} __attribute__((packed));

/* PCOMP / DCOMP only exist in first fragment */
struct sndcp_comp_hdr {
	/* octet 2 */
	uint8_t pcomp:4;
	uint8_t dcomp:4;
} __attribute__((packed));

struct sndcp_udata_hdr {
	/* octet 3 */
	uint8_t npdu_high:4;
	uint8_t seg_nr:4;
	/* octet 4 */
	uint8_t npdu_low;
} __attribute__((packed));


static void *tall_sndcp_ctx;

/* A fragment queue entry, containing one framgent of a N-PDU */
struct defrag_queue_entry {
	struct llist_head list;
	/* segment number of this fragment */
	uint32_t seg_nr;
	/* length of the data area of this fragment */
	uint32_t data_len;
	/* pointer to the data of this fragment */
	uint8_t *data;
};

LLIST_HEAD(gprs_sndcp_entities);

/* Enqueue a fragment into the defragment queue */
static int defrag_enqueue(struct gprs_sndcp_entity *sne, uint8_t seg_nr,
			  uint8_t *data, uint32_t data_len)
{
	struct defrag_queue_entry *dqe;

	dqe = talloc_zero(tall_sndcp_ctx, struct defrag_queue_entry);
	if (!dqe)
		return -ENOMEM;
	dqe->data = talloc_zero_size(dqe, data_len);
	if (!dqe->data) {
		talloc_free(dqe);
		return -ENOMEM;
	}
	dqe->seg_nr = seg_nr;
	dqe->data_len = data_len;

	llist_add(&dqe->list, &sne->defrag.frag_list);

	if (seg_nr > sne->defrag.highest_seg)
		sne->defrag.highest_seg = seg_nr;

	sne->defrag.seg_have |= (1 << seg_nr);
	sne->defrag.tot_len += data_len;

	memcpy(dqe->data, data, data_len);

	return 0;
}

/* return if we have all segments of this N-PDU */
static int defrag_have_all_segments(struct gprs_sndcp_entity *sne)
{
	uint32_t seg_needed = 0;
	unsigned int i;

	/* create a bitmask of needed segments */
	for (i = 0; i <= sne->defrag.highest_seg; i++)
		seg_needed |= (1 << i);

	if (seg_needed == sne->defrag.seg_have)
		return 1;

	return 0;
}

static struct defrag_queue_entry *defrag_get_seg(struct gprs_sndcp_entity *sne,
						 uint32_t seg_nr)
{
	struct defrag_queue_entry *dqe;

	llist_for_each_entry(dqe, &sne->defrag.frag_list, list) {
		if (dqe->seg_nr == seg_nr) {
			llist_del(&dqe->list);
			return dqe;
		}
	}
	return NULL;
}

/* Perform actual defragmentation and create an output packet */
static int defrag_segments(struct gprs_sndcp_entity *sne)
{
	struct msgb *msg;
	unsigned int seg_nr;
	uint8_t *npdu;

	LOGP(DSNDCP, LOGL_DEBUG, "TLLI=0x%08x NSAPI=%u: Defragment output PDU %u "
		"num_seg=%u tot_len=%u\n", sne->lle->llme->tlli, sne->nsapi,
		sne->defrag.npdu, sne->defrag.highest_seg, sne->defrag.tot_len);
	msg = msgb_alloc_headroom(sne->defrag.tot_len+256, 128, "SNDCP Defrag");
	if (!msg)
		return -ENOMEM;

	/* FIXME: message headers + identifiers */

	npdu = msg->data;

	for (seg_nr = 0; seg_nr <= sne->defrag.highest_seg; seg_nr++) {
		struct defrag_queue_entry *dqe;
		uint8_t *data;

		dqe = defrag_get_seg(sne, seg_nr);
		if (!dqe) {
			LOGP(DSNDCP, LOGL_ERROR, "Segment %u missing\n", seg_nr);
			msgb_free(msg);
			return -EIO;
		}
		/* actually append the segment to the N-PDU */
		data = msgb_put(msg, dqe->data_len);
		memcpy(data, dqe->data, dqe->data_len);

		/* release memory for the fragment queue entry */
		talloc_free(dqe);
	}

	/* FIXME: cancel timer */

	/* actually send the N-PDU to the SGSN core code, which then
	 * hands it off to the correct GTP tunnel + GGSN via gtp_data_req() */
	return sgsn_rx_sndcp_ud_ind(&sne->ra_id, sne->lle->llme->tlli,
				    sne->nsapi, msg, sne->defrag.tot_len, npdu);
}

static int defrag_input(struct gprs_sndcp_entity *sne, struct msgb *msg, uint8_t *hdr,
			unsigned int len)
{
	struct sndcp_common_hdr *sch;
	struct sndcp_comp_hdr *scomph = NULL;
	struct sndcp_udata_hdr *suh;
	uint16_t npdu_num;
	uint8_t *data;
	int rc;

	sch = (struct sndcp_common_hdr *) hdr;
	if (sch->first) {
		scomph = (struct sndcp_comp_hdr *) (hdr + 1);
		suh = (struct sndcp_udata_hdr *) (hdr + 1 + sizeof(struct sndcp_common_hdr));
	} else
		suh = (struct sndcp_udata_hdr *) (hdr + sizeof(struct sndcp_common_hdr));

	data = (uint8_t *)suh + sizeof(struct sndcp_udata_hdr);

	npdu_num = (suh->npdu_high << 8) | suh->npdu_low;

	LOGP(DSNDCP, LOGL_DEBUG, "TLLI=0x%08x NSAPI=%u: Input PDU %u Segment %u "
		"Length %u %s %s\n", sne->lle->llme->tlli, sne->nsapi, npdu_num,
		suh->seg_nr, len, sch->first ? "F " : "", sch->more ? "M" : "");

	if (sch->first) {
		/* first segment of a new packet.  Discard all leftover fragments of
		 * previous packet */
		if (!llist_empty(&sne->defrag.frag_list)) {
			struct defrag_queue_entry *dqe, *dqe2;
			LOGP(DSNDCP, LOGL_INFO, "TLLI=0x%08x NSAPI=%u: Dropping "
			     "SN-PDU %u due to insufficient segments (%04x)\n",
			     sne->lle->llme->tlli, sne->nsapi, sne->defrag.npdu,
			     sne->defrag.seg_have);
			llist_for_each_entry_safe(dqe, dqe2, &sne->defrag.frag_list, list) {
				llist_del(&dqe->list);
				talloc_free(dqe);
			}
		}
		/* store the currently de-fragmented PDU number */
		sne->defrag.npdu = npdu_num;

		/* Re-set fragmentation state */
		sne->defrag.no_more = sne->defrag.highest_seg = sne->defrag.seg_have = 0;
		sne->defrag.tot_len = 0;
		/* FIXME: (re)start timer */
	}

	if (sne->defrag.npdu != npdu_num) {
		LOGP(DSNDCP, LOGL_INFO, "Segment for different SN-PDU "
			"(%u != %u)\n", npdu_num, sne->defrag.npdu);
		/* FIXME */
	}

	/* FIXME: check if seg_nr already exists */
	/* make sure to subtract length of SNDCP header from 'len' */
	rc = defrag_enqueue(sne, suh->seg_nr, data, len - (data - hdr));
	if (rc < 0)
		return rc;

	if (!sch->more) {
		/* this is suppsed to be the last segment of the N-PDU, but it
		 * might well be not the last to arrive */
		sne->defrag.no_more = 1;
	}

	if (sne->defrag.no_more) {
		/* we have already received the last segment before, let's check
		 * if all the previous segments exist */
		if (defrag_have_all_segments(sne))
			return defrag_segments(sne);
	}

	return 0;
}

static struct gprs_sndcp_entity *gprs_sndcp_entity_by_lle(const struct gprs_llc_lle *lle,
						uint8_t nsapi)
{
	struct gprs_sndcp_entity *sne;

	llist_for_each_entry(sne, &gprs_sndcp_entities, list) {
		if (sne->lle == lle && sne->nsapi == nsapi)
			return sne;
	}
	return NULL;
}

static struct gprs_sndcp_entity *gprs_sndcp_entity_alloc(struct gprs_llc_lle *lle,
						uint8_t nsapi)
{
	struct gprs_sndcp_entity *sne;

	sne = talloc_zero(tall_sndcp_ctx, struct gprs_sndcp_entity);
	if (!sne)
		return NULL;

	sne->lle = lle;
	sne->nsapi = nsapi;
	sne->defrag.timer.data = sne;
	//sne->fqueue.timer.cb = FIXME;
	sne->rx_state = SNDCP_RX_S_FIRST;
	INIT_LLIST_HEAD(&sne->defrag.frag_list);

	llist_add(&sne->list, &gprs_sndcp_entities);

	return sne;
}

/* Entry point for the SNSM-ACTIVATE.indication */
int sndcp_sm_activate_ind(struct gprs_llc_lle *lle, uint8_t nsapi)
{
	LOGP(DSNDCP, LOGL_INFO, "SNSM-ACTIVATE.ind (lle=%p TLLI=%08x, "
	     "SAPI=%u, NSAPI=%u)\n", lle, lle->llme->tlli, lle->sapi, nsapi);

	if (gprs_sndcp_entity_by_lle(lle, nsapi)) {
		LOGP(DSNDCP, LOGL_ERROR, "Trying to ACTIVATE "
			"already-existing entity (TLLI=%08x, NSAPI=%u)\n",
			lle->llme->tlli, nsapi);
		return -EEXIST;
	}

	if (!gprs_sndcp_entity_alloc(lle, nsapi)) {
		LOGP(DSNDCP, LOGL_ERROR, "Out of memory during ACTIVATE\n");
		return -ENOMEM;
	}

	return 0;
}

/* Entry point for the SNSM-DEACTIVATE.indication */
int sndcp_sm_deactivate_ind(struct gprs_llc_lle *lle, uint8_t nsapi)
{
	struct gprs_sndcp_entity *sne;

	LOGP(DSNDCP, LOGL_INFO, "SNSM-DEACTIVATE.ind (lle=%p, TLLI=%08x, "
	     "SAPI=%u, NSAPI=%u)\n", lle, lle->llme->tlli, lle->sapi, nsapi);

	sne = gprs_sndcp_entity_by_lle(lle, nsapi);
	if (!sne) {
		LOGP(DSNDCP, LOGL_ERROR, "SNSM-DEACTIVATE.ind for non-"
		     "existing TLLI=%08x SAPI=%u NSAPI=%u\n", lle->llme->tlli,
		     lle->sapi, nsapi);
		return -ENOENT;
	}
	llist_del(&sne->list);
	/* frag queue entries are hierarchically allocated, so no need to
	 * free them explicitly here */
	talloc_free(sne);

	return 0;
}

/* Fragmenter state */
struct sndcp_frag_state {
	uint8_t frag_nr;
	struct msgb *msg;	/* original message */
	uint8_t *next_byte;	/* first byte of next fragment */

	struct gprs_sndcp_entity *sne;
	void *mmcontext;
};

/* returns '1' if there are more fragments to send, '0' if none */
static int sndcp_send_ud_frag(struct sndcp_frag_state *fs)
{
	struct gprs_sndcp_entity *sne = fs->sne;
	struct gprs_llc_lle *lle = sne->lle;
	struct sndcp_common_hdr *sch;
	struct sndcp_comp_hdr *scomph;
	struct sndcp_udata_hdr *suh;
	struct msgb *fmsg;
	unsigned int max_payload_len;
	unsigned int len;
	uint8_t *data;
	int rc, more;

	fmsg = msgb_alloc_headroom(fs->sne->lle->params.n201_u+256, 128,
				   "SNDCP Frag");
	if (!fmsg)
		return -ENOMEM;

	/* make sure lower layers route the fragment like the original */
	msgb_tlli(fmsg) = msgb_tlli(fs->msg);
	msgb_bvci(fmsg) = msgb_bvci(fs->msg);
	msgb_nsei(fmsg) = msgb_nsei(fs->msg);

	/* prepend common SNDCP header */
	sch = (struct sndcp_common_hdr *) msgb_put(fmsg, sizeof(*sch));
	sch->nsapi = sne->nsapi;
	/* Set FIRST bit if we are the first fragment in a series */
	if (fs->frag_nr == 0)
		sch->first = 1;
	sch->type = 1;

	/* append the compression header for first fragment */
	if (sch->first) {
		scomph = (struct sndcp_comp_hdr *)
				msgb_put(fmsg, sizeof(*scomph));
		scomph->pcomp = 0;
		scomph->dcomp = 0;
	}

	/* append the user-data header */
	suh = (struct sndcp_udata_hdr *) msgb_put(fmsg, sizeof(*suh));
	suh->npdu_low = sne->tx_npdu_nr & 0xff;
	suh->npdu_high = (sne->tx_npdu_nr >> 8) & 0xf;
	suh->seg_nr = fs->frag_nr % 0xf;

	/* calculate remaining length to be sent */
	len = (fs->msg->data + fs->msg->len) - fs->next_byte;
	/* how much payload can we actually send via LLC? */
	max_payload_len = lle->params.n201_u - (sizeof(*sch) + sizeof(*suh));
	if (sch->first)
		max_payload_len -= sizeof(*scomph);
	/* check if we're exceeding the max */
	if (len > max_payload_len)
		len = max_payload_len;

	/* copy the actual fragment data into our fmsg */
	data = msgb_put(fmsg, len);
	memcpy(data, fs->next_byte, len);

	/* Increment fragment number and data pointer to next fragment */
	fs->frag_nr++;
	fs->next_byte += len;

	/* determine if we have more fragemnts to send */
	if ((fs->msg->data + fs->msg->len) <= fs->next_byte)
		more = 0;
	else
		more = 1;

	/* set the MORE bit of the SNDCP header accordingly */
	sch->more = more;

	rc = gprs_llc_tx_ui(fmsg, lle->sapi, 0, fs->mmcontext);
	if (rc < 0) {
		/* abort in case of error, do not advance frag_nr / next_byte */
		msgb_free(fmsg);
		return rc;
	}

	if (!more) {
		/* we've sent all fragments */
		msgb_free(fs->msg);
		memset(fs, 0, sizeof(*fs));
		/* increment NPDU number for next frame */
		sne->tx_npdu_nr = (sne->tx_npdu_nr + 1) % 0xfff;
		return 0;
	}

	/* default: more fragments to send */
	return 1;
}

/* Request transmission of a SN-PDU over specified LLC Entity + SAPI */
int sndcp_unitdata_req(struct msgb *msg, struct gprs_llc_lle *lle, uint8_t nsapi,
			void *mmcontext)
{
	struct gprs_sndcp_entity *sne;
	struct sndcp_common_hdr *sch;
	struct sndcp_comp_hdr *scomph;
	struct sndcp_udata_hdr *suh;
	struct sndcp_frag_state fs;

	/* Identifiers from UP: (TLLI, SAPI) + (BVCI, NSEI) */

	sne = gprs_sndcp_entity_by_lle(lle, nsapi);
	if (!sne) {
		LOGP(DSNDCP, LOGL_ERROR, "Cannot find SNDCP Entity\n");
		return -EIO;
	}

	/* Check if we need to fragment this N-PDU into multiple SN-PDUs */
	if (msg->len > lle->params.n201_u - 
			(sizeof(*sch) + sizeof(*suh) + sizeof(*scomph))) {
		/* initialize the fragmenter state */
		fs.msg = msg;
		fs.frag_nr = 0;
		fs.next_byte = msg->data;
		fs.sne = sne;
		fs.mmcontext = mmcontext;

		/* call function to generate and send fragments until all
		 * of the N-PDU has been sent */
		while (1) {
			int rc = sndcp_send_ud_frag(&fs);
			if (rc == 0)
				return 0;
			if (rc < 0)
				return rc;
		}
		/* not reached */
		return 0;
	}

	/* this is the non-fragmenting case where we only build 1 SN-PDU */

	/* prepend the user-data header */
	suh = (struct sndcp_udata_hdr *) msgb_push(msg, sizeof(*suh));
	suh->npdu_low = sne->tx_npdu_nr & 0xff;
	suh->npdu_high = (sne->tx_npdu_nr >> 8) & 0xf;
	suh->seg_nr = 0;
	sne->tx_npdu_nr = (sne->tx_npdu_nr + 1) % 0xfff;

	scomph = (struct sndcp_comp_hdr *) msgb_push(msg, sizeof(*scomph));
	scomph->pcomp = 0;
	scomph->dcomp = 0;

	/* prepend common SNDCP header */
	sch = (struct sndcp_common_hdr *) msgb_push(msg, sizeof(*sch));
	sch->first = 1;
	sch->type = 1;
	sch->nsapi = nsapi;

	return gprs_llc_tx_ui(msg, lle->sapi, 0, mmcontext);
}

/* Section 5.1.2.17 LL-UNITDATA.ind */
int sndcp_llunitdata_ind(struct msgb *msg, struct gprs_llc_lle *lle,
			 uint8_t *hdr, uint16_t len)
{
	struct gprs_sndcp_entity *sne;
	struct sndcp_common_hdr *sch = (struct sndcp_common_hdr *)hdr;
	struct sndcp_comp_hdr *scomph = NULL;
	struct sndcp_udata_hdr *suh;
	uint8_t *npdu;
	uint16_t npdu_num;
	int npdu_len;

	sch = (struct sndcp_common_hdr *) hdr;
	if (sch->first) {
		scomph = (struct sndcp_comp_hdr *) (hdr + 1);
		suh = (struct sndcp_udata_hdr *) (hdr + 1 + sizeof(struct sndcp_common_hdr));
	} else
		suh = (struct sndcp_udata_hdr *) (hdr + sizeof(struct sndcp_common_hdr));

	if (sch->type == 0) {
		LOGP(DSNDCP, LOGL_ERROR, "SN-DATA PDU at unitdata_ind() function\n");
		return -EINVAL;
	}

	if (len < sizeof(*sch) + sizeof(*suh)) {
		LOGP(DSNDCP, LOGL_ERROR, "SN-UNITDATA PDU too short (%u)\n", len);
		return -EIO;
	}

	sne = gprs_sndcp_entity_by_lle(lle, sch->nsapi);
	if (!sne) {
		LOGP(DSNDCP, LOGL_ERROR, "Message for non-existing SNDCP Entity "
			"(lle=%p, TLLI=%08x, SAPI=%u, NSAPI=%u)\n", lle,
			lle->llme->tlli, lle->sapi, sch->nsapi);
		return -EIO;
	}
	/* FIXME: move this RA_ID up to the LLME or even higher */
	bssgp_parse_cell_id(&sne->ra_id, msgb_bcid(msg));

	/* any non-first segment is by definition something to defragment
	 * as is any segment that tells us there are more segments */
	if (!sch->first || sch->more)
		return defrag_input(sne, msg, hdr, len);

	if (scomph && (scomph->pcomp || scomph->dcomp)) {
		LOGP(DSNDCP, LOGL_ERROR, "We don't support compression yet\n");
		return -EIO;
	}

	npdu_num = (suh->npdu_high << 8) | suh->npdu_low;
	npdu = (uint8_t *)suh + sizeof(*suh);
	npdu_len = (msg->data + msg->len) - npdu;
	if (npdu_len <= 0) {
		LOGP(DSNDCP, LOGL_ERROR, "Short SNDCP N-PDU: %d\n", npdu_len);
		return -EIO;
	}
	/* actually send the N-PDU to the SGSN core code, which then
	 * hands it off to the correct GTP tunnel + GGSN via gtp_data_req() */
	return sgsn_rx_sndcp_ud_ind(&sne->ra_id, lle->llme->tlli, sne->nsapi, msg, npdu_len, npdu);
}

#if 0
/* Section 5.1.2.1 LL-RESET.ind */
static int sndcp_ll_reset_ind(struct gprs_sndcp_entity *se)
{
	/* treat all outstanding SNDCP-LLC request type primitives as not sent */
	/* reset all SNDCP XID parameters to default values */
	LOGP(DSNDCP, LOGL_NOTICE, "not implemented.\n");
	return 0;
}

static int sndcp_ll_status_ind()
{
	/* inform the SM sub-layer by means of SNSM-STATUS.req */
	LOGP(DSNDCP, LOGL_NOTICE, "not implemented.\n");
	return 0;
}

static struct sndcp_state_list {{
	uint32_t	states;
	unsigned int	type;
	int		(*rout)(struct gprs_sndcp_entity *se, struct msgb *msg);
} sndcp_state_list[] = {
	{ ALL_STATES,
	  LL_RESET_IND, sndcp_ll_reset_ind },
	{ ALL_STATES,
	  LL_ESTABLISH_IND, sndcp_ll_est_ind },
	{ SBIT(SNDCP_S_EST_RQD),
	  LL_ESTABLISH_RESP, sndcp_ll_est_ind },
	{ SBIT(SNDCP_S_EST_RQD),
	  LL_ESTABLISH_CONF, sndcp_ll_est_conf },
	{ SBIT(SNDCP_S_
};

static int sndcp_rx_llc_prim()
{
	case LL_ESTABLISH_REQ:
	case LL_RELEASE_REQ:
	case LL_XID_REQ:
	case LL_DATA_REQ:
	LL_UNITDATA_REQ,	/* TLLI, SN-PDU, Ref, QoS, Radio Prio, Ciph */

	switch (prim) {
	case LL_RESET_IND:
	case LL_ESTABLISH_IND:
	case LL_ESTABLISH_RESP:
	case LL_ESTABLISH_CONF:
	case LL_RELEASE_IND:
	case LL_RELEASE_CONF:
	case LL_XID_IND:
	case LL_XID_RESP:
	case LL_XID_CONF:
	case LL_DATA_IND:
	case LL_DATA_CONF:
	case LL_UNITDATA_IND:
	case LL_STATUS_IND:
}
#endif
