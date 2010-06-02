/* GPRS SNDCP protocol implementation as per 3GPP TS 04.65 */

/* (C) 2010 by Harald Welte <laforge@gnumonks.org>
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

#include <errno.h>
#include <stdint.h>

#include <osmocore/msgb.h>
#include <osmocore/linuxlist.h>
#include <osmocore/timer.h>
#include <osmocore/talloc.h>

#include <openbsc/gsm_data.h>
#include <openbsc/debug.h>
#include <openbsc/gprs_bssgp.h>
#include <openbsc/gprs_llc.h>
#include <openbsc/sgsn.h>

/* Chapter 7.2: SN-PDU Formats */
struct sndcp_common_hdr {
	/* octet 1 */
	uint8_t nsapi:4;
	uint8_t more:1;
	uint8_t type:1;
	uint8_t first:1;
	uint8_t spare:1;
	/* octet 2 */
	uint8_t pcomp;
	uint8_t dcomp;
} __attribute__((packed));

struct sndcp_udata_hdr {
	/* octet 3 */
	uint8_t npdu_high:4;
	uint8_t seg_nr:4;
	/* octet 4 */
	uint8_t npdu_low;
} __attribute__((packed));

/* See 6.7.1.2 Reassembly */
enum sndcp_rx_state {
	SNDCP_RX_S_FIRST,
	SNDCP_RX_S_SUBSEQ,
	SNDCP_RX_S_DISCARD,
};


static void *tall_sndcp_ctx;

/* A fragment queue entry, containing one framgent of a N-PDU */
struct frag_queue_entry {
	struct llist_head list;
	uint8_t seg_nr;
	uint32_t data_len;
	uint8_t data[0];
};

/* A fragment queue header, maintaining list of fragments for one N-PDU */
struct frag_queue_head {
	uint16_t npdu;

	/* linked list of frag_queue_entry: one for each fragment  */
	struct llist_head frag_list;

	struct timer_list timer;
};

struct sndcp_entity {
	struct llist_head list;

	struct gprs_llc_lle *lle;
	uint8_t nsapi;

	enum sndcp_rx_state rx_state;
	struct frag_queue_head fqueue;
};

LLIST_HEAD(sndcp_entities);

#if 0
static struct frag_queue_entry _find_fqe(struct freg_queue_head *fqh, uint8_t seg_nr)
{

}

static struct frag_queue_head _find_fqh(struct sndcp_entity *sne, uint16_t npdu)
{

}

static int ul_enqueue_fragment(struct sndcp_entity *sne, uint16_t npdu,
			       uint8_t seg_nr, uint32_t data_len, uint8_t *data)
{
	
}
#endif

static struct sndcp_entity *sndcp_entity_by_lle(const struct gprs_llc_lle *lle,
						uint8_t nsapi)
{
	struct sndcp_entity *sne;

	llist_for_each_entry(sne, &sndcp_entities, list) {
		if (sne->lle == lle && sne->nsapi == nsapi)
			return sne;
	}
	return NULL;
}

static struct sndcp_entity *sndcp_entity_alloc(struct gprs_llc_lle *lle,
						uint8_t nsapi)
{
	struct sndcp_entity *sne;

	sne = talloc_zero(tall_sndcp_ctx, struct sndcp_entity);
	if (!sne)
		return NULL;

	sne->lle = lle;
	sne->nsapi = nsapi;
	sne->fqueue.timer.data = sne;
	//sne->fqueue.timer.cb = FIXME;
	sne->rx_state = SNDCP_RX_S_FIRST;

	return sne;
}

/* Entry point for the SNSM-ACTIVATE.indication */
int sndcp_sm_activate_ind(struct gprs_llc_lle *lle, uint8_t nsapi)
{
	LOGP(DSNDCP, LOGL_INFO, "SNSM-ACTIVATE.ind (TLLI=%08x, NSAPI=%u)\n",
		lle->llme->tlli, nsapi);

	if (sndcp_entity_by_lle(lle, nsapi)) {
		LOGP(DSNDCP, LOGL_ERROR, "Trying to ACTIVATE "
			"already-existing entity (TLLI=%08x, NSAPI=%u)\n",
			lle->llme->tlli, nsapi);
		return -EEXIST;
	}

	if (!sndcp_entity_alloc(lle, nsapi)) {
		LOGP(DSNDCP, LOGL_ERROR, "Out of memory during ACTIVATE\n");
		return -ENOMEM;
	}

	return 0;
}

/* Section 5.1.2.17 LL-UNITDATA.ind */
int sndcp_llunitdata_ind(struct msgb *msg, struct gprs_llc_lle *lle, uint8_t *hdr, uint8_t len)
{
	struct sndcp_entity *sne;
	struct sndcp_common_hdr *sch = (struct sndcp_common_hdr *)hdr;
	struct sndcp_udata_hdr *suh;
	uint8_t *npdu;
	uint16_t npdu_num;
	int npdu_len;

	if (sch->type == 0) {
		LOGP(DSNDCP, LOGL_ERROR, "SN-DATA PDU at unitdata_ind() function\n");
		return -EINVAL;
	}

	if (len < sizeof(*sch) + sizeof(*suh)) {
		LOGP(DSNDCP, LOGL_ERROR, "SN-UNITDATA PDU too short (%u)\n", len);
		return -EIO;
	}

	sne = sndcp_entity_by_lle(lle, sch->nsapi);
	if (!sne) {
		LOGP(DSNDCP, LOGL_ERROR, "Message for non-existing SNDCP Entity "
			"(TLLI=%08x, NSAPI=%u)\n", lle->llme->tlli, sch->nsapi);
		return -EIO;
	}

	if (!sch->first || sch->more) {
		/* FIXME: implement fragment re-assembly */
		LOGP(DSNDCP, LOGL_ERROR, "We don't support reassembly yet\n");
		return -EIO;
	}

	if (sch->pcomp || sch->dcomp) {
		LOGP(DSNDCP, LOGL_ERROR, "We don't support compression yet\n");
		return -EIO;
	}

	suh = (struct sndcp_udata_hdr *) (hdr + sizeof(struct sndcp_common_hdr));
	npdu_num = (suh->npdu_high << 8) | suh->npdu_low;
	npdu = (uint8_t *)suh + sizeof(*suh);
	npdu_len = (msg->data + msg->len) - npdu;
	if (npdu_len) {
		LOGP(DSNDCP, LOGL_ERROR, "Short SNDCP N-PDU: %d\n", npdu_len);
		return -EIO;
	}
	/* actually send the N-PDU to the SGSN core code, which then
	 * hands it off to the correct GTP tunnel + GGSN via gtp_data_req() */
	return sgsn_rx_sndcp_ud_ind(lle->llme->tlli, sne->nsapi, msg, npdu_len, npdu);
}

/* Section 5.1.2.1 LL-RESET.ind */
static int sndcp_ll_reset_ind(struct sndcp_entity *se)
{
	/* treat all outstanding SNDCP-LLC request type primitives as not sent */
	/* reset all SNDCP XID parameters to default values */
}

static int sndcp_ll_status_ind()
{
	/* inform the SM sub-layer by means of SNSM-STATUS.req */
}

#if 0
static struct sndcp_state_list {{
	uint32_t	states;
	unsigned int	type;
	int		(*rout)(struct sndcp_entity *se, struct msgb *msg);
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
