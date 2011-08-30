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
#include <osmocom/gsm/tlv.h>

#include <string.h>

enum RTP_EXTRA_FRAME {
	/** Set a marker bit on the RFC */
	RTP_EXTRA_MARKER = 0x1,

	/** Maybe add a bit to mention no further extension bits? */
};

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

struct amr_toc {
	uint8_t		reserved : 4,
			cmd : 4;
	uint8_t 	na : 2,
			q_bit : 1,
			ft_bits: 4,
			f_bit : 1;
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

static int guess_amr_size(const uint8_t *_data)
{
	const struct amr_toc *toc;
	toc = (struct amr_toc *) _data;
	if (toc->ft_bits == 8 && toc->f_bit == 0 && toc->q_bit == 1)
		return 7;

	return 17;
}

static void write_compressed_big(struct reduced_rtp_hdr *reduced_hdr,
				 struct msgb *msg,
				 struct llist_head *rtp_packets)
{
	struct msgb *rtp, *tmp;

	reduced_hdr->type = 1;

	llist_for_each_entry_safe(rtp, tmp, rtp_packets, list) {
		struct rtp_hdr *hdr = (struct rtp_hdr *) rtp->l2h;
		uint32_t len = msgb_l2len(rtp) - sizeof(*hdr);
		uint8_t *data;

		msgb_v_put(msg, hdr->marker ? RTP_EXTRA_MARKER : 0);
		data = msgb_put(msg, len);
		memcpy(data, hdr->data, len);

		llist_del(&rtp->list);
		talloc_free(rtp);
	}
}


/**
 * I write a simple 3 byte header followed by the payloads of the
 * single RTP packets. This is assumed to be AMR.
 */
static void write_compressed_slim(struct reduced_rtp_hdr *reduced_hdr,
				  struct msgb *msg,
				  struct llist_head *rtp_packets)
{
	struct msgb *rtp, *tmp;

	reduced_hdr->type = 0;

	llist_for_each_entry_safe(rtp, tmp, rtp_packets, list) {
		struct rtp_hdr *hdr = (struct rtp_hdr *) rtp->l2h;
		uint32_t len = msgb_l2len(rtp) - sizeof(*hdr);
		uint8_t *data = msgb_put(msg, len);
		memcpy(data, hdr->data, len);

		llist_del(&rtp->list);
		talloc_free(rtp);
	}
}

static int read_compressed_big(struct msgb *msg,
			       struct reduced_rtp_hdr *rhdr,
			       struct llist_head *list,
			       struct mgcp_rtp_compr_state *state)
{
	int i;
	uint16_t offset = 0;
	const uint16_t len = msgb_l2len(msg) - sizeof(*rhdr);

	for (i = 0; i < rhdr->payloads; ++i) {
		struct rtp_hdr *hdr;
		struct msgb *out;
		int alen;

		if (len < offset + 1 + sizeof(struct amr_toc)) {
			LOGP(DMGCP, LOGL_ERROR, "Can not fit RTP/AMR in %d\n", i);
			goto clean_all;
		}

		out = msgb_alloc_headroom(4096, 128, "RTP decompr");
		if (!out) {
			LOGP(DMGCP, LOGL_ERROR, "Failed to allocate: %d\n", i);
			goto clean_all;
		}


		out->l2h = msgb_put(out, 0);
		hdr = msgb_put_struct(out, struct rtp_hdr);
		fill_rtp_hdr(hdr);
		fill_rtp_state(hdr, state);

		/* re-apply the marker bit */
		if (rhdr->data[offset] & RTP_EXTRA_MARKER)
			hdr->marker = 1;
		offset += 1;

		/* guess the size of the AMR payload */
		alen = guess_amr_size(&rhdr->data[offset]);
		if (len < offset + alen) {
			LOGP(DMGCP, LOGL_ERROR, "Payload does not fit.\n");
			goto clean_all;
		}

		out->l3h = msgb_put(out, alen);
		memcpy(out->l3h, &rhdr->data[offset], alen);
		msgb_enqueue(list, out);
		offset += alen;
	}

	return 0;

clean_all:
	while (llist_empty(list)) {
		struct msgb *msg = msgb_dequeue(list);
		talloc_free(msg);
	}

	return -8;
}

static int read_compressed_slim(struct msgb *msg,
				struct reduced_rtp_hdr *rhdr,
				struct llist_head *list,
				struct mgcp_rtp_compr_state *state)
{
	int i;

	uint16_t offset = 0;
	const uint16_t len = msgb_l2len(msg) - sizeof(*rhdr);

	for (i = 0; i < rhdr->payloads; ++i) {
		struct rtp_hdr *hdr;
		struct msgb *out;
		int alen;

		if (len < offset + 1 + sizeof(struct amr_toc)) {
			LOGP(DMGCP, LOGL_ERROR, "Can not fit RTP/AMR in %d\n", i);
			goto clean_all;
		}

		out = msgb_alloc_headroom(4096, 128, "RTP decompr");
		if (!out) {
			LOGP(DMGCP, LOGL_ERROR, "Failed to allocate: %d\n", i);
			continue;
		}

		out->l2h = msgb_put(out, 0);
		hdr = msgb_put_struct(out, struct rtp_hdr);
		fill_rtp_hdr(hdr);
		fill_rtp_state(hdr, state);

		/* guess the size of the AMR payload */
		alen = guess_amr_size(&rhdr->data[offset]);
		if (len < offset + alen) {
			LOGP(DMGCP, LOGL_ERROR, "Payload does not fit.\n");
			goto clean_all;
		}

		out->l3h = msgb_put(out, alen);
		memcpy(out->l3h, &rhdr->data[offset], alen);
		msgb_enqueue(list, out);
		offset += alen;
	}

	return 0;

clean_all:
	while (llist_empty(list)) {
		struct msgb *msg = msgb_dequeue(list);
		talloc_free(msg);
	}

	return -8;
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
	int count = 0, marker = 0;

	/*
	 * sanity check if everything is a RTP packet, or if we need to do
	 * something special.
	 */
	llist_for_each_entry_safe(rtp, tmp, rtp_packets, list) {
		struct rtp_hdr *hdr;
		uint16_t sequence;
		uint16_t payload_len;

		if (msgb_l2len(rtp) < sizeof(struct rtp_hdr)) {
			LOGP(DMGCP, LOGL_ERROR,
			     "Packet is too small on %d/0x%x\n", endp, endp);
			llist_del(&rtp->list);
			talloc_free(rtp);
			continue;
		}

		payload_len = msgb_l2len(rtp) - sizeof(struct rtp_hdr);
		if (payload_len != 7 && payload_len != 17) {
			LOGP(DMGCP, LOGL_ERROR,
			     "We assume every payload is 17 or 7 byte: %d\n",
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

		if (hdr->marker)
			marker = 1;

		state->generated_ssrc = ntohl(hdr->ssrc);
		state->timestamp = ntohl(hdr->timestamp);
		state->sequence = ntohs(hdr->sequence);
		last_sequence = sequence;
		count += 1;
	}


	if (llist_empty(rtp_packets))
		return 0;

	reduced_hdr = msgb_put_struct(msg, struct reduced_rtp_hdr);
	reduced_hdr->endp = endp;

	state->last_ts = (state->last_ts + 1) % UCHAR_MAX;
	reduced_hdr->sequence_no = state->last_ts;
	reduced_hdr->payloads = count;

	if (marker)
		write_compressed_big(reduced_hdr, msg, rtp_packets);
	else
		write_compressed_slim(reduced_hdr, msg, rtp_packets);

	return count;
}

int rtp_decompress(struct mgcp_rtp_compr_state *state,
		   struct llist_head *list,
		   struct msgb *msg)
{
	struct reduced_rtp_hdr *rhdr;

	if (msgb_l2len(msg) < sizeof(*rhdr)) {
		LOGP(DMGCP, LOGL_ERROR, "Compressed header does not fit.\n");
		return -1;
	}

	rhdr = (struct reduced_rtp_hdr *) msg->l2h;

	/* check if the state is matching */
	/**
	 * We will need some simple state with a bit of history. We will start
	 * with last_ts == -1, then we initialize it to the expected ts, and
	 * when we get something we didn't expect we will need to guess if this
	 * is a late arrival (due re-ordering or such) or if that is just some
	 * packet loss and we continue. E.g. we need to check if the sequence_no
	 * is above or below our state... but as the counter wraps, e.g. if we
	 * wait for 512 but we get 2, we have jumped to the future...
	 * This will require some testing/simulation
	 */
#warning "TODO: Deal with late arrivals, reset the state and accept late as new"

	if (rhdr->type == 0)
		return read_compressed_slim(msg, rhdr, list, state);
	else if (rhdr->type == 1)
		return read_compressed_big(msg, rhdr, list, state);
	else {
		LOGP(DMGCP, LOGL_ERROR,
		     "Type %d is not known.\n", rhdr->type);
		return -2;
	}
}
