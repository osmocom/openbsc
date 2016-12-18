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
#include <stdbool.h>

#include <osmocom/core/msgb.h>
#include <osmocom/core/linuxlist.h>
#include <osmocom/core/timer.h>
#include <osmocom/core/talloc.h>
#include <osmocom/gprs/gprs_bssgp.h>

#include <openbsc/gsm_data.h>
#include <openbsc/debug.h>
#include <openbsc/gprs_llc.h>
#include <openbsc/sgsn.h>
#include <openbsc/gprs_sndcp.h>
#include <openbsc/gprs_llc_xid.h>
#include <openbsc/gprs_sndcp_xid.h>
#include <openbsc/gprs_sndcp_pcomp.h>
#include <openbsc/gprs_sndcp_dcomp.h>
#include <openbsc/gprs_sndcp_comp.h>

#define DEBUG_IP_PACKETS 0	/* 0=Disabled, 1=Enabled */

#if DEBUG_IP_PACKETS == 1
/* Calculate TCP/IP checksum */
static uint16_t calc_ip_csum(uint8_t *data, int len)
{
	int i;
	uint32_t accumulator = 0;
	uint16_t *pointer = (uint16_t *) data;

	for (i = len; i > 1; i -= 2) {
		accumulator += *pointer;
		pointer++;
	}

	if (len % 2)
		accumulator += *pointer;

	accumulator = (accumulator & 0xffff) + ((accumulator >> 16) & 0xffff);
	accumulator += (accumulator >> 16) & 0xffff;
	return (~accumulator);
}

/* Calculate TCP/IP checksum */
static uint16_t calc_tcpip_csum(const void *ctx, uint8_t *packet, int len)
{
	uint8_t *buf;
	uint16_t csum;

	buf = talloc_zero_size(ctx, len);
	memset(buf, 0, len);
	memcpy(buf, packet + 12, 8);
	buf[9] = packet[9];
	buf[11] = (len - 20) & 0xFF;
	buf[10] = (len - 20) >> 8 & 0xFF;
	memcpy(buf + 12, packet + 20, len - 20);
	csum = calc_ip_csum(buf, len - 20 + 12);
	talloc_free(buf);
	return csum;
}

/* Show some ip packet details */
static void debug_ip_packet(uint8_t *data, int len, int dir, char *info)
{
	uint8_t tcp_flags;
	char flags_debugmsg[256];
	int len_short;
	static unsigned int packet_count = 0;
	static unsigned int tcp_csum_err_count = 0;
	static unsigned int ip_csum_err_count = 0;

	packet_count++;

	if (len > 80)
		len_short = 80;
	else
		len_short = len;

	if (dir)
		DEBUGP(DSNDCP, "%s: MS => SGSN: %s\n", info,
		       osmo_hexdump_nospc(data, len_short));
	else
		DEBUGP(DSNDCP, "%s: MS <= SGSN: %s\n", info,
		       osmo_hexdump_nospc(data, len_short));

	DEBUGP(DSNDCP, "%s: Length.: %d\n", info, len);
	DEBUGP(DSNDCP, "%s: NO.: %d\n", info, packet_count);

	if (len < 20) {
		DEBUGP(DSNDCP, "%s: Error: Short IP packet!\n", info);
		return;
	}

	if (calc_ip_csum(data, 20) != 0) {
		DEBUGP(DSNDCP, "%s: Bad IP-Header checksum!\n", info);
		ip_csum_err_count++;
	} else
		DEBUGP(DSNDCP, "%s: IP-Header checksum ok.\n", info);

	if (data[9] == 0x06) {
		if (len < 40) {
			DEBUGP(DSNDCP, "%s: Error: Short TCP packet!\n", info);
			return;
		}

		DEBUGP(DSNDCP, "%s: Protocol type: TCP\n", info);
		tcp_flags = data[33];

		if (calc_tcpip_csum(NULL, data, len) != 0) {
			DEBUGP(DSNDCP, "%s: Bad TCP checksum!\n", info);
			tcp_csum_err_count++;
		} else
			DEBUGP(DSNDCP, "%s: TCP checksum ok.\n", info);

		memset(flags_debugmsg, 0, sizeof(flags_debugmsg));
		if (tcp_flags & 1)
			strcat(flags_debugmsg, "FIN ");
		if (tcp_flags & 2)
			strcat(flags_debugmsg, "SYN ");
		if (tcp_flags & 4)
			strcat(flags_debugmsg, "RST ");
		if (tcp_flags & 8)
			strcat(flags_debugmsg, "PSH ");
		if (tcp_flags & 16)
			strcat(flags_debugmsg, "ACK ");
		if (tcp_flags & 32)
			strcat(flags_debugmsg, "URG ");
		DEBUGP(DSNDCP, "%s: FLAGS: %s\n", info, flags_debugmsg);
	} else if (data[9] == 0x11) {
		DEBUGP(DSNDCP, "%s: Protocol type: UDP\n", info);
	} else {
		DEBUGP(DSNDCP, "%s: Protocol type: (%02x)\n", info, data[9]);
	}

	DEBUGP(DSNDCP, "%s: IP-Header checksum errors: %d\n", info,
	       ip_csum_err_count);
	DEBUGP(DSNDCP, "%s: TCP-Checksum errors: %d\n", info,
	       tcp_csum_err_count);
}
#endif

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

/* Check if any compression parameters are set in the sgsn configuration */
static inline int any_pcomp_or_dcomp_active(struct sgsn_instance *sgsn) {
	if (sgsn->cfg.pcomp_rfc1144.active || sgsn->cfg.pcomp_rfc1144.passive ||
	    sgsn->cfg.dcomp_v42bis.active || sgsn->cfg.dcomp_v42bis.passive)
		return true;
	else
		return false;
}

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
	int npdu_len;
	int rc;
	uint8_t *expnd = NULL;

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

	npdu_len = sne->defrag.tot_len;

	/* FIXME: cancel timer */

	/* actually send the N-PDU to the SGSN core code, which then
	 * hands it off to the correct GTP tunnel + GGSN via gtp_data_req() */

	/* Decompress packet */
#if DEBUG_IP_PACKETS == 1
	DEBUGP(DSNDCP, "                                                   \n");
	DEBUGP(DSNDCP, ":::::::::::::::::::::::::::::::::::::::::::::::::::\n");
	DEBUGP(DSNDCP, "===================================================\n");
#endif
	if (any_pcomp_or_dcomp_active(sgsn)) {

		expnd = talloc_zero_size(msg, npdu_len * MAX_DATADECOMPR_FAC +
					 MAX_HDRDECOMPR_INCR);
		memcpy(expnd, npdu, npdu_len);

		/* Apply data decompression */
		rc = gprs_sndcp_dcomp_expand(expnd, npdu_len, sne->defrag.dcomp,
					     sne->defrag.data);
		if (rc < 0) {
			LOGP(DSNDCP, LOGL_ERROR,
			     "Data decompression failed!\n");
			talloc_free(expnd);
			return -EIO;
		}

		/* Apply header decompression */
		rc = gprs_sndcp_pcomp_expand(expnd, rc, sne->defrag.pcomp,
					     sne->defrag.proto);
		if (rc < 0) {
			LOGP(DSNDCP, LOGL_ERROR,
			     "TCP/IP Header decompression failed!\n");
			talloc_free(expnd);
			return -EIO;
		}

		/* Modify npu length, expnd is handed directly handed
		 * over to gsn_rx_sndcp_ud_ind(), see below */
		npdu_len = rc;
	} else
		expnd = npdu;
#if DEBUG_IP_PACKETS == 1
	debug_ip_packet(expnd, npdu_len, 1, "defrag_segments()");
	DEBUGP(DSNDCP, "===================================================\n");
	DEBUGP(DSNDCP, ":::::::::::::::::::::::::::::::::::::::::::::::::::\n");
	DEBUGP(DSNDCP, "                                                   \n");
#endif

	/* Hand off packet to gtp */
	rc = sgsn_rx_sndcp_ud_ind(&sne->ra_id, sne->lle->llme->tlli,
				  sne->nsapi, msg, npdu_len, expnd);

	if (any_pcomp_or_dcomp_active(sgsn))
		talloc_free(expnd);

	return rc;
}

static int defrag_input(struct gprs_sndcp_entity *sne, struct msgb *msg,
			uint8_t *hdr, unsigned int len)
{
	struct sndcp_common_hdr *sch;
	struct sndcp_udata_hdr *suh;
	uint16_t npdu_num;
	uint8_t *data;
	int rc;

	sch = (struct sndcp_common_hdr *) hdr;
	if (sch->first) {
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
static int sndcp_send_ud_frag(struct sndcp_frag_state *fs,
			      uint8_t pcomp, uint8_t dcomp)
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
	if (!fmsg) {
		msgb_free(fs->msg);
		return -ENOMEM;
	}

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
		scomph->pcomp = pcomp;
		scomph->dcomp = dcomp;
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

	rc = gprs_llc_tx_ui(fmsg, lle->sapi, 0, fs->mmcontext, true);
	/* abort in case of error, do not advance frag_nr / next_byte */
	if (rc < 0) {
		msgb_free(fs->msg);
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
	uint8_t pcomp = 0;
	uint8_t dcomp = 0;
	int rc;

	/* Identifiers from UP: (TLLI, SAPI) + (BVCI, NSEI) */

	/* Compress packet */
#if DEBUG_IP_PACKETS == 1
	DEBUGP(DSNDCP, "                                                   \n");
	DEBUGP(DSNDCP, ":::::::::::::::::::::::::::::::::::::::::::::::::::\n");
	DEBUGP(DSNDCP, "===================================================\n");
	debug_ip_packet(msg->data, msg->len, 0, "sndcp_initdata_req()");
#endif
	if (any_pcomp_or_dcomp_active(sgsn)) {

		/* Apply header compression */
		rc = gprs_sndcp_pcomp_compress(msg->data, msg->len, &pcomp,
					       lle->llme->comp.proto, nsapi);
		if (rc < 0) {
			LOGP(DSNDCP, LOGL_ERROR,
			     "TCP/IP Header compression failed!\n");
			return -EIO;
		}

		/* Fixup pointer locations and sizes in message buffer to match
		 * the new, compressed buffer size */
		msgb_get(msg, msg->len);
		msgb_put(msg, rc);

		/* Apply data compression */
		rc = gprs_sndcp_dcomp_compress(msg->data, msg->len, &dcomp,
					       lle->llme->comp.data, nsapi);
		if (rc < 0) {
			LOGP(DSNDCP, LOGL_ERROR, "Data compression failed!\n");
			return -EIO;
		}

		/* Fixup pointer locations and sizes in message buffer to match
		 * the new, compressed buffer size */
		msgb_get(msg, msg->len);
		msgb_put(msg, rc);
	}
#if DEBUG_IP_PACKETS == 1
	DEBUGP(DSNDCP, "===================================================\n");
	DEBUGP(DSNDCP, ":::::::::::::::::::::::::::::::::::::::::::::::::::\n");
	DEBUGP(DSNDCP, "                                                   \n");
#endif

	sne = gprs_sndcp_entity_by_lle(lle, nsapi);
	if (!sne) {
		LOGP(DSNDCP, LOGL_ERROR, "Cannot find SNDCP Entity\n");
		msgb_free(msg);
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
			int rc = sndcp_send_ud_frag(&fs,pcomp,dcomp);
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
	scomph->pcomp = pcomp;
	scomph->dcomp = dcomp;

	/* prepend common SNDCP header */
	sch = (struct sndcp_common_hdr *) msgb_push(msg, sizeof(*sch));
	sch->first = 1;
	sch->type = 1;
	sch->nsapi = nsapi;

	return gprs_llc_tx_ui(msg, lle->sapi, 0, mmcontext, true);
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
	uint16_t npdu_num __attribute__((unused));
	int npdu_len;
	int rc;
	uint8_t *expnd = NULL;

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

	if (scomph) {
		sne->defrag.pcomp = scomph->pcomp;
		sne->defrag.dcomp = scomph->dcomp;
		sne->defrag.proto = lle->llme->comp.proto;
		sne->defrag.data = lle->llme->comp.data;
	}

	/* any non-first segment is by definition something to defragment
	 * as is any segment that tells us there are more segments */
	if (!sch->first || sch->more)
		return defrag_input(sne, msg, hdr, len);

	npdu_num = (suh->npdu_high << 8) | suh->npdu_low;
	npdu = (uint8_t *)suh + sizeof(*suh);
	npdu_len = (msg->data + msg->len) - npdu - 3;	/* -3 'removes' the FCS */

	if (npdu_len <= 0) {
		LOGP(DSNDCP, LOGL_ERROR, "Short SNDCP N-PDU: %d\n", npdu_len);
		return -EIO;
	}
	/* actually send the N-PDU to the SGSN core code, which then
	 * hands it off to the correct GTP tunnel + GGSN via gtp_data_req() */

	/* Decompress packet */
#if DEBUG_IP_PACKETS == 1
	DEBUGP(DSNDCP, "                                                   \n");
	DEBUGP(DSNDCP, ":::::::::::::::::::::::::::::::::::::::::::::::::::\n");
	DEBUGP(DSNDCP, "===================================================\n");
#endif
	if (any_pcomp_or_dcomp_active(sgsn)) {

		expnd = talloc_zero_size(msg, npdu_len * MAX_DATADECOMPR_FAC +
					 MAX_HDRDECOMPR_INCR);
		memcpy(expnd, npdu, npdu_len);

		/* Apply data decompression */
		rc = gprs_sndcp_dcomp_expand(expnd, npdu_len, sne->defrag.dcomp,
					     sne->defrag.data);
		if (rc < 0) {
			LOGP(DSNDCP, LOGL_ERROR,
			     "Data decompression failed!\n");
			talloc_free(expnd);
			return -EIO;
		}

		/* Apply header decompression */
		rc = gprs_sndcp_pcomp_expand(expnd, rc, sne->defrag.pcomp,
					     sne->defrag.proto);
		if (rc < 0) {
			LOGP(DSNDCP, LOGL_ERROR,
			     "TCP/IP Header decompression failed!\n");
			talloc_free(expnd);
			return -EIO;
		}

		/* Modify npu length, expnd is handed directly handed
		 * over to gsn_rx_sndcp_ud_ind(), see below */
		npdu_len = rc;
	} else
		expnd = npdu;
#if DEBUG_IP_PACKETS == 1
	debug_ip_packet(expnd, npdu_len, 1, "sndcp_llunitdata_ind()");
	DEBUGP(DSNDCP, "===================================================\n");
	DEBUGP(DSNDCP, ":::::::::::::::::::::::::::::::::::::::::::::::::::\n");
	DEBUGP(DSNDCP, "                                                   \n");
#endif

	/* Hand off packet to gtp */
	rc = sgsn_rx_sndcp_ud_ind(&sne->ra_id, lle->llme->tlli,
				  sne->nsapi, msg, npdu_len, expnd);

	if (any_pcomp_or_dcomp_active(sgsn))
		talloc_free(expnd);

	return rc;
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
}
#endif

/* Generate SNDCP-XID message */
static int gprs_llc_gen_sndcp_xid(uint8_t *bytes, int bytes_len, uint8_t nsapi)
{
	int entity = 0;
	LLIST_HEAD(comp_fields);
	struct gprs_sndcp_pcomp_rfc1144_params rfc1144_params;
	struct gprs_sndcp_comp_field rfc1144_comp_field;
	struct gprs_sndcp_dcomp_v42bis_params v42bis_params;
	struct gprs_sndcp_comp_field v42bis_comp_field;

	memset(&rfc1144_comp_field, 0, sizeof(struct gprs_sndcp_comp_field));
	memset(&v42bis_comp_field, 0, sizeof(struct gprs_sndcp_comp_field));

	/* Setup rfc1144 */
	if (sgsn->cfg.pcomp_rfc1144.active) {
		rfc1144_params.nsapi[0] = nsapi;
		rfc1144_params.nsapi_len = 1;
		rfc1144_params.s01 = sgsn->cfg.pcomp_rfc1144.s01;
		rfc1144_comp_field.p = 1;
		rfc1144_comp_field.entity = entity;
		rfc1144_comp_field.algo = RFC_1144;
		rfc1144_comp_field.comp[RFC1144_PCOMP1] = 1;
		rfc1144_comp_field.comp[RFC1144_PCOMP2] = 2;
		rfc1144_comp_field.comp_len = RFC1144_PCOMP_NUM;
		rfc1144_comp_field.rfc1144_params = &rfc1144_params;
		entity++;
		llist_add(&rfc1144_comp_field.list, &comp_fields);
	}

	/* Setup V.42bis */
	if (sgsn->cfg.dcomp_v42bis.active) {
		v42bis_params.nsapi[0] = nsapi;
		v42bis_params.nsapi_len = 1;
		v42bis_params.p0 = sgsn->cfg.dcomp_v42bis.p0;
		v42bis_params.p1 = sgsn->cfg.dcomp_v42bis.p1;
		v42bis_params.p2 = sgsn->cfg.dcomp_v42bis.p2;
		v42bis_comp_field.p = 1;
		v42bis_comp_field.entity = entity;
		v42bis_comp_field.algo = V42BIS;
		v42bis_comp_field.comp[V42BIS_DCOMP1] = 1;
		v42bis_comp_field.comp_len = V42BIS_DCOMP_NUM;
		v42bis_comp_field.v42bis_params = &v42bis_params;
		entity++;
		llist_add(&v42bis_comp_field.list, &comp_fields);
	}

	/* Do not attempt to compile anything if there is no data in the list */
	if (llist_empty(&comp_fields))
		return 0;

	/* Compile bytestream */
	return gprs_sndcp_compile_xid(bytes, bytes_len, &comp_fields,
				      DEFAULT_SNDCP_VERSION);
}

/* Set of SNDCP-XID bnegotiation (See also: TS 144 065,
 * Section 6.8 XID parameter negotiation) */
int sndcp_sn_xid_req(struct gprs_llc_lle *lle, uint8_t nsapi)
{
	/* Note: The specification requires the SNDCP-User to set of an
	 * SNDCP xid request. See also 3GPP TS 44.065, 6.8 XID parameter
	 * negotiation, Figure 11: SNDCP XID negotiation procedure. In
	 * our case the SNDCP-User is sgsn_libgtp.c, which calls
	 * sndcp_sn_xid_req directly. */

	uint8_t l3params[1024];
	int xid_len;
	struct gprs_llc_xid_field xid_field_request;

	/* Wipe off all compression entities and their states to
	 * get rid of possible leftovers from a previous session */
	gprs_sndcp_comp_free(lle->llme->comp.proto);
	gprs_sndcp_comp_free(lle->llme->comp.data);
	lle->llme->comp.proto = gprs_sndcp_comp_alloc(lle->llme);
	lle->llme->comp.data = gprs_sndcp_comp_alloc(lle->llme);
	talloc_free(lle->llme->xid);
	lle->llme->xid = NULL;

	/* Generate compression parameter bytestream */
	xid_len = gprs_llc_gen_sndcp_xid(l3params, sizeof(l3params), nsapi);

	/* Send XID with the SNDCP-XID bytetsream included */
	if (xid_len > 0) {
		xid_field_request.type = GPRS_LLC_XID_T_L3_PAR;
		xid_field_request.data = l3params;
		xid_field_request.data_len = xid_len;
		return gprs_ll_xid_req(lle, &xid_field_request);
	}

	/* When bytestream can not be generated, proceed without SNDCP-XID */
	return gprs_ll_xid_req(lle, NULL);

}

/* Handle header compression entites */
static int handle_pcomp_entities(struct gprs_sndcp_comp_field *comp_field,
				 struct gprs_llc_lle *lle)
{
	/* Note: This functions also transforms the comp_field into its
	 * echo form (strips comp values, resets propose bit etc...)
	 * the processed comp_fields can then be sent back as XID-
	 * Response without further modification. */

	/* Delete propose bit */
	comp_field->p = 0;

	/* Process proposed parameters */
	switch (comp_field->algo) {
	case RFC_1144:
		if (sgsn->cfg.pcomp_rfc1144.passive
		    && comp_field->rfc1144_params->nsapi_len > 0) {
			DEBUGP(DSNDCP,
			       "Accepting RFC1144 header compression...\n");
			gprs_sndcp_comp_add(lle->llme, lle->llme->comp.proto,
					    comp_field);
		} else {
			DEBUGP(DSNDCP,
			       "Rejecting RFC1144 header compression...\n");
			gprs_sndcp_comp_delete(lle->llme->comp.proto,
					       comp_field->entity);
			comp_field->rfc1144_params->nsapi_len = 0;
		}
		break;
	case RFC_2507:
		/* RFC 2507 is not yet supported,
		 * so we set applicable nsapis to zero */
		DEBUGP(DSNDCP, "Rejecting RFC2507 header compression...\n");
		comp_field->rfc2507_params->nsapi_len = 0;
		gprs_sndcp_comp_delete(lle->llme->comp.proto,
				       comp_field->entity);
		break;
	case ROHC:
		/* ROHC is not yet supported,
		 * so we set applicable nsapis to zero */
		DEBUGP(DSNDCP, "Rejecting ROHC header compression...\n");
		comp_field->rohc_params->nsapi_len = 0;
		gprs_sndcp_comp_delete(lle->llme->comp.proto,
				       comp_field->entity);
		break;
	}

	return 0;
}

/* Hanle data compression entites */
static int handle_dcomp_entities(struct gprs_sndcp_comp_field *comp_field,
				 struct gprs_llc_lle *lle)
{
	/* See note in handle_pcomp_entities() */

	/* Delete propose bit */
	comp_field->p = 0;

	/* Process proposed parameters */
	switch (comp_field->algo) {
	case V42BIS:
		if (sgsn->cfg.dcomp_v42bis.passive &&
		    comp_field->v42bis_params->nsapi_len > 0) {
			DEBUGP(DSNDCP,
			       "Accepting V.42bis data compression...\n");
			gprs_sndcp_comp_add(lle->llme, lle->llme->comp.data,
					    comp_field);
		} else {
			LOGP(DSNDCP, LOGL_DEBUG,
			     "Rejecting V.42bis data compression...\n");
			gprs_sndcp_comp_delete(lle->llme->comp.data,
					       comp_field->entity);
			comp_field->v42bis_params->nsapi_len = 0;
		}
		break;
	case V44:
		/* V44 is not yet supported,
		 * so we set applicable nsapis to zero */
		DEBUGP(DSNDCP, "Rejecting V.44 data compression...\n");
		comp_field->v44_params->nsapi_len = 0;
		gprs_sndcp_comp_delete(lle->llme->comp.data,
				       comp_field->entity);
		break;
	}

	return 0;

}

/* Process SNDCP-XID indication
 * (See also: TS 144 065, Section 6.8 XID parameter negotiation) */
int sndcp_sn_xid_ind(struct gprs_llc_xid_field *xid_field_indication,
		     struct gprs_llc_xid_field *xid_field_response,
		     struct gprs_llc_lle *lle)
{
	/* Note: This function computes the SNDCP-XID response that is sent
	 * back to the ms when a ms originated XID is received. The
	 * Input XID fields are directly processed and the result is directly
	 * handed back. */

	int rc;
	int compclass;
	int version;

	struct llist_head *comp_fields;
	struct gprs_sndcp_comp_field *comp_field;

	OSMO_ASSERT(xid_field_indication);
	OSMO_ASSERT(xid_field_response);
	OSMO_ASSERT(lle);

	/* Parse SNDCP-CID XID-Field */
	comp_fields = gprs_sndcp_parse_xid(&version, lle->llme,
					   xid_field_indication->data,
					   xid_field_indication->data_len,
					   NULL);
	if (!comp_fields)
		return -EINVAL;

	/* Handle compression entites */
	DEBUGP(DSNDCP, "SNDCP-XID-IND (ms):\n");
	gprs_sndcp_dump_comp_fields(comp_fields, LOGL_DEBUG);

	llist_for_each_entry(comp_field, comp_fields, list) {
		compclass = gprs_sndcp_get_compression_class(comp_field);
		if (compclass == SNDCP_XID_PROTOCOL_COMPRESSION)
			rc = handle_pcomp_entities(comp_field, lle);
		else if (compclass == SNDCP_XID_DATA_COMPRESSION)
			rc = handle_dcomp_entities(comp_field, lle);
		else {
			gprs_sndcp_comp_delete(lle->llme->comp.proto,
					       comp_field->entity);
			gprs_sndcp_comp_delete(lle->llme->comp.data,
					       comp_field->entity);
			rc = 0;
		}

		if (rc < 0) {
			talloc_free(comp_fields);
			return -EINVAL;
		}
	}

	DEBUGP(DSNDCP, "SNDCP-XID-RES (sgsn):\n");
	gprs_sndcp_dump_comp_fields(comp_fields, LOGL_DEBUG);

	/* Reserve some memory to store the modified SNDCP-XID bytes */
	xid_field_response->data =
	    talloc_zero_size(lle->llme, xid_field_indication->data_len);

	/* Set Type flag for response */
	xid_field_response->type = GPRS_LLC_XID_T_L3_PAR;

	/* Compile modified SNDCP-XID bytes */
	rc = gprs_sndcp_compile_xid(xid_field_response->data,
				    xid_field_indication->data_len,
				    comp_fields, 0);

	if (rc > 0)
		xid_field_response->data_len = rc;
	else {
		talloc_free(xid_field_response->data);
		xid_field_response->data = NULL;
		xid_field_response->data_len = 0;
		return -EINVAL;
	}

	talloc_free(comp_fields);

	return 0;
}

/* Process SNDCP-XID indication
 * (See also: TS 144 065, Section 6.8 XID parameter negotiation) */
int sndcp_sn_xid_conf(struct gprs_llc_xid_field *xid_field_conf,
		      struct gprs_llc_xid_field *xid_field_request,
		      struct gprs_llc_lle *lle)
{
	/* Note: This function handles an incomming SNDCP-XID confirmiation.
	 * Since the confirmation fields may lack important parameters we
	 * will reconstruct these missing fields using the original request
	 * we have sent. After that we will create (or delete) the
	 * compression entites */

	struct llist_head *comp_fields_req;
	struct llist_head *comp_fields_conf;
	struct gprs_sndcp_comp_field *comp_field;
	int rc;
	int compclass;

	/* We need both, the confirmation that is sent back by the ms,
	 * and the original request we have sent. If one of this is missing
	 * we can not process the confirmation, the caller must check if
	 * request and confirmation fields are available. */
	OSMO_ASSERT(xid_field_conf);
	OSMO_ASSERT(xid_field_request);

	/* Parse SNDCP-CID XID-Field */
	comp_fields_req = gprs_sndcp_parse_xid(NULL, lle->llme,
					       xid_field_request->data,
					       xid_field_request->data_len,
					       NULL);
	if (!comp_fields_req)
		return -EINVAL;

	DEBUGP(DSNDCP, "SNDCP-XID-REQ (sgsn):\n");
	gprs_sndcp_dump_comp_fields(comp_fields_req, LOGL_DEBUG);

	/* Parse SNDCP-CID XID-Field */
	comp_fields_conf = gprs_sndcp_parse_xid(NULL, lle->llme,
						xid_field_conf->data,
						xid_field_conf->data_len,
						comp_fields_req);
	if (!comp_fields_conf)
		return -EINVAL;

	DEBUGP(DSNDCP, "SNDCP-XID-CONF (ms):\n");
	gprs_sndcp_dump_comp_fields(comp_fields_conf, LOGL_DEBUG);

	/* Handle compression entites */
	llist_for_each_entry(comp_field, comp_fields_conf, list) {
		compclass = gprs_sndcp_get_compression_class(comp_field);
		if (compclass == SNDCP_XID_PROTOCOL_COMPRESSION)
			rc = handle_pcomp_entities(comp_field, lle);
		else if (compclass == SNDCP_XID_DATA_COMPRESSION)
			rc = handle_dcomp_entities(comp_field, lle);
		else {
			gprs_sndcp_comp_delete(lle->llme->comp.proto,
					       comp_field->entity);
			gprs_sndcp_comp_delete(lle->llme->comp.data,
					       comp_field->entity);
			rc = 0;
		}

		if (rc < 0) {
			talloc_free(comp_fields_req);
			talloc_free(comp_fields_conf);
			return -EINVAL;
		}
	}

	talloc_free(comp_fields_req);
	talloc_free(comp_fields_conf);

	return 0;
}
