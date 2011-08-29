/*
 * (C) 2011 by Holger Hans Peter Freyther <zecke@selfish.org>
 * (C) 2011 by On-Waves
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

#include <openbsc/debug.h>
#include <openbsc/rtp_rfc.h>
#include <openbsc/mgcp_internal.h>

#include <osmocom/core/talloc.h>

#include <string.h>


struct reduced_rtp_hdr {
	/** I will need to be inflated to the SSRC */
	uint8_t		endp;
	/** I will need to be inflated to both the TS and the Sequence Number */
	uint8_t		sequence_no;
	/**
	 * I represent the type, you should know the size of each payload now.
	 * I represent the number of payloads that follow
	 */
	uint8_t		type : 4,
			payloads : 4;
	uint8_t		data[0];
} __attribute__((packed));

#define msgb_put_struct(msg, str) \
	(str *) msgb_put(msg, sizeof(str))


static void fill_rtp_hdr(struct rtp_hdr *hdr)
{
	hdr->csrc_count = 0;
	hdr->extension = 0;
	hdr->padding = 0;
	hdr->version = RTP_VERSION;

	/* detect stop of silence? */
	hdr->marker = 0;
	hdr->payload_type = 98;
}

static void fill_rtp_state(struct rtp_hdr *hdr,
			   struct mgcp_rtp_compr_state *state)
{
	hdr->ssrc = htonl(state->generated_ssrc);
	hdr->sequence = htons(state->sequence++);
	hdr->timestamp = htonl(state->timestamp);
	state->timestamp += 160;
}
			   

/**
 * I try to compress these packets into one single stream. I have various
 * limitations. I do not support packets that jump backwards, the rtp_packets
 * list must be properly sorted, everything else will be discarded.
 *
 * Also somethings like:
 *   seq_no:1, seq_no:3, seq_no: 5
 * will be folded into
 *   3 payloads, Payload:1, Payload:2, Payload:3
 *
 * And the decoder will decode it to:
 *   seq_no:1, seq_no:2, seq_no: 3
 *
 */
int rtp_compress(struct mgcp_rtp_compr_state *state, struct msgb *msg,
		 int endp, struct llist_head *rtp_packets)
{
	struct msgb *rtp, *tmp;
	struct reduced_rtp_hdr *reduced_hdr;
	uint16_t last_sequence = 0;
	int count = 0;
	uint8_t *data;

	/*
	 * sanity check if everything is a RTP packet
	 */
	llist_for_each_entry_safe(rtp, tmp, rtp_packets, list) {
		struct rtp_hdr *hdr;
		uint16_t sequence;

		if (msgb_l2len(rtp) < sizeof(struct rtp_hdr)) {
			LOGP(DMGCP, LOGL_ERROR,
			     "Packet is too small on %d/0x%x\n", endp, endp);
			llist_del(&rtp->list);
			talloc_free(rtp);
			continue;
		}

		if (msgb_l2len(rtp) < sizeof(struct rtp_hdr) + 17) {
			LOGP(DMGCP, LOGL_ERROR,
			     "We assume every payload is 17 byte: %d\n",
			     msgb_l2len(rtp) - sizeof(struct rtp_hdr));
			llist_del(&rtp->list);
			talloc_free(rtp);
			continue;
		}

		hdr = (struct rtp_hdr *) rtp->l2h;
		sequence = ntohs(hdr->sequence);
		if (sequence < last_sequence && sequence != 0) {
			LOGP(DMGCP, LOGL_ERROR, "Packet is not in sequence.\n");
			llist_del(&rtp->list);
			talloc_free(rtp);
			last_sequence = sequence;
			continue;
		}

		last_sequence = sequence;
		count += 1;
	}


	if (llist_empty(rtp_packets))
		return 0;

	reduced_hdr = msgb_put_struct(msg, struct reduced_rtp_hdr);
	reduced_hdr->endp = endp;
	reduced_hdr->sequence_no = ++state->last_ts % UCHAR_MAX;
	reduced_hdr->type = 0;
	reduced_hdr->payloads = count;


	llist_for_each_entry_safe(rtp, tmp, rtp_packets, list) {
		struct rtp_hdr *hdr = (struct rtp_hdr *) rtp->l2h;
		uint32_t len = msgb_l2len(rtp) - sizeof(*hdr);
		data = msgb_put(msg, len);
		memcpy(data, hdr->data, len);

		llist_del(&rtp->list);
		talloc_free(rtp);
	}

	return count;
}

struct llist_head rtp_decompress(struct mgcp_rtp_compr_state *state,
				  struct msgb *msg)
{
	struct reduced_rtp_hdr *rhdr;
	int i;
	struct llist_head list;
	INIT_LLIST_HEAD(&list);

	if (msgb_l2len(msg) < sizeof(*rhdr)) {
		LOGP(DMGCP, LOGL_ERROR, "Compressed header does not fit.\n");
		return list;
	}

	rhdr = (struct reduced_rtp_hdr *) msg->l2h;
	if (rhdr->type != 0) {
		LOGP(DMGCP, LOGL_ERROR,
		     "Type %d is not known.\n", rhdr->type);
		return list;
	}

	if (msgb_l2len(msg) < sizeof(*rhdr) + rhdr->payloads * 17) {
		LOGP(DMGCP, LOGL_ERROR,
		     "Payloads do not fit. %d\n", rhdr->payloads);
		return list;
	}

	for (i = 0; i < rhdr->payloads; ++i) {
		struct rtp_hdr *hdr;
		struct msgb *out = msgb_alloc_headroom(4096, 128, "RTP decompr");
		if (!out) {
			LOGP(DMGCP, LOGL_ERROR, "Failed to allocate: %d\n", i);
			continue;
		}

		out->l2h = msgb_put(out, 0);
		hdr = msgb_put_struct(out, struct rtp_hdr);
		fill_rtp_hdr(hdr);
		fill_rtp_state(hdr, state);

		out->l3h = msgb_put(out, 17);
		memcpy(out->l3h, &rhdr->data[i * 17], 17);
		msgb_enqueue(&list, out);
	}

	return list;
}
