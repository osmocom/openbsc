/* A E1 sub-channel (de)multiplexer with TRAU frame sync */

/* (C) 2009 by Harald Welte <laforge@gnumonks.org>
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

#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>

#include <openbsc/subchan_demux.h>
#include <openbsc/trau_frame.h>

static inline void append_bit(struct demux_subch *sch, u_int8_t bit)
{
	sch->out_bitbuf[sch->out_idx++] = bit;
}

#define SYNC_HDR_BITS	16
static const u_int8_t nullbytes[SYNC_HDR_BITS];

/* check if we have just completed the 16 bit zero sync header,
 * in accordance with GSM TS 08.60 Chapter 4.8.1 */
static int sync_hdr_complete(struct demux_subch *sch)
{
	int rc;
	int bits_at_end = 0;
	int bits_at_front;
 
	if (sch->out_idx < SYNC_HDR_BITS)
		bits_at_end = SYNC_HDR_BITS - sch->out_idx;
	bits_at_front = sch->out_idx;

	if (bits_at_end) {
		rc = memcmp(sch->out_bitbuf + sizeof(sch->out_bitbuf) - bits_at_end,
			    nullbytes, bits_at_end);
		if (rc)
			return 0;
	}
	rc = memcmp(sch->out_bitbuf + sch->out_idx, nullbytes,
		    bits_at_front);
	if (rc)
		return 0;
	
	return 1;
}

/* resynchronize to current location */
static void resync_to_here(struct demux_subch *sch)
{
#if 0
	u_int8_t tmp[TRAU_FRAME_BITS];
	int sync_hdr_start = sch->out_idx - SYNC_HDR_BITS;
	int bytes_at_end;

	/* first make copy of old bitbuf */
	memcpy(tmp, sch->out_bitbuf, sizeof(tmp));

	if (sync_hdr_start < 0)
		sync_hdr_start += TRAU_FRAME_BITS;

	bytes_at_end = TRAU_FRAME_BITS - sync_hdr_start;

	/* copy part after sync_hdr_start */
	memcpy(sch->out_bitbuf, tmp + sync_hdr_start, bytes_at_end);

	/* copy part before sync_hdr_start */
	memcpy(sch->out_bitbuf + bytes_at_end, tmp, 
		SYNC_HDR_BITS - bytes_at_end);
#else
	memset(sch->out_bitbuf, 0, SYNC_HDR_BITS);
#endif

	/* set index in a way that we can continue receiving bits after
	 * the end of the SYNC header */
	sch->out_idx = SYNC_HDR_BITS;
}

int subch_demux_init(struct subch_demux *dmx)
{
	int i;

	dmx->chan_activ = 0;
	for (i = 0; i < NR_SUBCH; i++) {
		struct demux_subch *sch = &dmx->subch[i];
		sch->out_idx = 0;
		memset(sch->out_bitbuf, 0xff, sizeof(sch->out_bitbuf));
	}
	return 0;
}

/* input some arbitrary (modulo 4) number of bytes of a 64k E1 channel,
 * split it into the 16k subchannels */
int subch_demux_in(struct subch_demux *dmx, u_int8_t *data, int len)
{
	int i, c;

	/* we avoid partially filled bytes in outbuf */
	if (len % 4)
		return -EINVAL;

	for (i = 0; i < len; i++) {
		u_int8_t inbyte = data[i];

		for (c = 0; c < NR_SUBCH; c++) {
			struct demux_subch *sch = &dmx->subch[c];
			u_int8_t bit;

			/* ignore inactive subchannels */
			if (!(dmx->chan_activ & (1 << c)))
				continue;

			/* two bits for each subchannel */
			if ((inbyte >> (c * 2)) & 0x01)
				bit = 1;
			else
				bit = 0;
			append_bit(sch, bit);

			if (sync_hdr_complete(sch))
				resync_to_here(sch);

			if ((inbyte >> (c * 2)) & 0x02)
				bit = 1;
			else
				bit = 0;
			append_bit(sch, bit);

			if (sync_hdr_complete(sch))
				resync_to_here(sch);

			/* FIXME: verify the first bit in octet 2, 4, 6, ...
			 * according to TS 08.60 4.8.1 */

			/* once we have reached TRAU_FRAME_BITS, call
			 * the TRAU frame handler callback function */
			if (sch->out_idx >= TRAU_FRAME_BITS) {
				dmx->out_cb(dmx, c, sch->out_bitbuf,
					    sch->out_idx, dmx->data);
				sch->out_idx = 0;
			}
		}
	}
	return i;
}

int subch_demux_activate(struct subch_demux *dmx, int subch)
{
	if (subch >= NR_SUBCH)
		return -EINVAL;

	dmx->chan_activ |= (1 << subch);
	return 0;
}

int subch_demux_deactivate(struct subch_demux *dmx, int subch)
{
	if (subch >= NR_SUBCH)
		return -EINVAL;

	dmx->chan_activ &= ~(1 << subch);
	return 0;
}

/* MULTIPLEXER */

static int alloc_add_idle_frame(struct subch_mux *mx, int sch_nr)
{
	/* FIXME: allocate and initialize with idle pattern */
	return subchan_mux_enqueue(mx, sch_nr, trau_idle_frame(),
				   TRAU_FRAME_BITS);
}

/* return the requested number of bits from the specified subchannel */
static int get_subch_bits(struct subch_mux *mx, int subch,
			  u_int8_t *bits, int num_requested)
{
	struct mux_subch *sch = &mx->subch[subch];
	int num_bits = 0;

	while (num_bits < num_requested) {
		struct subch_txq_entry *txe;
		int num_bits_left;
		int num_bits_thistime;

		/* make sure we have a valid entry at top of tx queue.
		 * if not, add an idle frame */
		if (llist_empty(&sch->tx_queue))	
			alloc_add_idle_frame(mx, subch);
	
		if (llist_empty(&sch->tx_queue))
			return -EIO;

		txe = llist_entry(&sch->tx_queue, struct subch_txq_entry, list);
		num_bits_left = txe->bit_len - txe->next_bit;

		if (num_bits_left < num_requested)
			num_bits_thistime = num_bits_left;
		else
			num_bits_thistime = num_requested;

		/* pull the bits from the txe */
		memcpy(bits + num_bits, txe->bits + txe->next_bit, num_requested);
		txe->next_bit += num_bits_thistime;

		/* free the tx_queue entry if it is fully consumed */
		if (txe->next_bit >= txe->bit_len) {
			llist_del(&txe->list);
			free(txe);
		}

		/* increment global number of bits dequeued */
		num_bits += num_bits_thistime;
	}

	return num_requested;
}

/* compact an array of 8 single-bit bytes into one byte of 8 bits */
static u_int8_t compact_bits(u_int8_t *bits)
{
	u_int8_t ret = 0;
	int i;

	for (i = 0; i < 8; i++)
		ret |= (bits[i] ? 1 : 0) << i;

	return ret;
}

/* obtain a single output byte from the subchannel muxer */
static int mux_output_byte(struct subch_mux *mx, u_int8_t *byte)
{
	u_int8_t bits[8];
	int rc;

	/* combine two bits of every subchan */
	rc = get_subch_bits(mx, 0, &bits[0], 2);
	rc = get_subch_bits(mx, 1, &bits[2], 2);
	rc = get_subch_bits(mx, 2, &bits[4], 2);
	rc = get_subch_bits(mx, 3, &bits[6], 2);

	if (!rc)
		*byte = compact_bits(bits);

	return rc;
}

/* Request the output of some muxed bytes from the subchan muxer */
int subchan_mux_out(struct subch_mux *mx, u_int8_t *data, int len)
{
	int i;

	for (i = 0; i < len; i++) {
		int rc;
		rc = mux_output_byte(mx, &data[i]);
		if (rc < 0)
			break;
	}
	return i;
}

/* enqueue some data into the tx_queue of a given subchannel */
int subchan_mux_enqueue(struct subch_mux *mx, int s_nr, const u_int8_t *data,
			int len)
{
	struct mux_subch *sch = &mx->subch[s_nr];
	struct subch_txq_entry *tqe = malloc(sizeof(*tqe) + len);

	if (!tqe)
		return -ENOMEM;

	memset(tqe, 0, sizeof(*tqe));
	tqe->bit_len = len;
	memcpy(tqe->bits, data, len);

	llist_add(&tqe->list, &sch->tx_queue);

	return 0;
}

/* initialize one subchannel muxer instance */
int subchan_mux_init(struct subch_mux *mx)
{
	int i;

	memset(mx, 0, sizeof(*mx));
	for (i = 0; i < NR_SUBCH; i++) {
		struct mux_subch *sch = &mx->subch[i];
		INIT_LLIST_HEAD(&sch->tx_queue);
	}

	return 0;
}
