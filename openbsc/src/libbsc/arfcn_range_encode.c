/* gsm 04.08 system information (si) encoding and decoding
 * 3gpp ts 04.08 version 7.21.0 release 1998 / etsi ts 100 940 v7.21.0 */

/*
 * (C) 2012 Holger Hans Peter Freyther
 * (C) 2012 by On-Waves
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
 */

#include <openbsc/arfcn_range_encode.h>
#include <openbsc/debug.h>

#include <osmocom/gsm/protocol/gsm_04_08.h>

#include <osmocom/core/utils.h>

int greatest_power_of_2_lesser_or_equal_to(int index)
{
	int power_of_2 = 1;

	do {
		power_of_2 *= 2;
	} while (power_of_2 <= index);

	/* now go back one step */
	return power_of_2 / 2;
}

static inline int mod(int data, int range)
{
	int res = data % range;
	while (res < 0)
		res += range;
	return res;
}

/**
 * Determine at which index to split the ARFCNs to create an
 * equally size partition for the given range. Return -1 if
 * no such partition exists.
 */
int range_enc_find_index(const int range, const int *freqs, const int size)
{
	int i, j, n;

	const int RANGE_DELTA = (range - 1) / 2;

	for (i = 0; i < size; ++i) {
		n = 0;
		for (j = 0; j < size; ++j) {
			if (mod(freqs[j] - freqs[i], range) <= RANGE_DELTA)
				n += 1;
		}

		if (n - 1 == (size - 1) / 2)
			return i;
	}

	return -1;
}

/**
 * Range encode the ARFCN list.
 * \param range The range to use.
 * \param arfcns The list of ARFCNs
 * \param size The size of the list of ARFCNs
 * \param out Place to store the W(i) output.
 */
int range_enc_arfcns(const int range,
		const int *arfcns, int size, int *out,
		const int index)
{
	int split_at;
	int i;

	/*
	 * The below is a GNU extension and we can remove it when
	 * we move to a quicksort like in-situ swap with the pivot.
	 */
	int arfcns_left[size / 2];
	int arfcns_right[size / 2];
	int l_size;
	int r_size;
	int l_origin;
	int r_origin;


	/* Test the two recursion anchors and stop processing */
	if (size == 0)
		return 0;

	if (size == 1) {
		out[index] = 1 + arfcns[0];
		return 0;
	}

	/* Now do the processing */
	split_at = range_enc_find_index(range, arfcns, size);

	/* we now know where to split */
	out[index] = 1 + arfcns[split_at];

	/* calculate the work that needs to be done for the leafs */
	l_origin = mod(arfcns[split_at] + ((range - 1) / 2) + 1, range);
	r_origin = mod(arfcns[split_at] + 1, range);
	for (i = 0, l_size = 0, r_size = 0; i < size; ++i) {
		if (mod(arfcns[i] - l_origin, range) < range / 2)
			arfcns_left[l_size++] = mod(arfcns[i] - l_origin, range);
		if (mod(arfcns[i] - r_origin, range) < range / 2)
			arfcns_right[r_size++] = mod(arfcns[i] - r_origin, range);
	}

	/*
	 * Now recurse and we need to make this iterative... but as the
	 * tree is balanced the stack will not be too deep.
	 */
	range_enc_arfcns(range / 2, arfcns_left, l_size,
			out, index + greatest_power_of_2_lesser_or_equal_to(index + 1));
	range_enc_arfcns((range -1 ) / 2, arfcns_right, r_size,
			 out, index + (2 * greatest_power_of_2_lesser_or_equal_to(index + 1)));
	return 0;
}

/*
 * The easiest is to use f0 == arfcns[0]. This means that under certain
 * circumstances we can encode less ARFCNs than possible with an optimal f0.
 *
 * TODO: Solve the optimisation problem and pick f0 so that the max distance
 * is the smallest. Taking into account the modulo operation. I think picking
 * size/2 will be the optimal arfcn.
 */
/**
 * This implements the range determination as described in GSM 04.08 J4. The
 * result will be a base frequency f0 and the range to use.
 *
 * \param[in] arfcns The input frequencies, they must be sorted, lowest number first
 * \param[in] size The length of the array
 * \param[out] f0 The selected F0 base frequency. It might not be inside the list
 */
int range_enc_determine_range(const int *arfcns, const int size, int *f0)
{
	int max = 0;

	/*
	 * Go for the easiest. And pick arfcns[0] == f0.
	 */
	max = arfcns[size - 1] - arfcns[0];
	*f0 = arfcns[0];

	if (max < 128 && size <= 29)
		return ARFCN_RANGE_128;
	if (max < 256 && size <= 22)
		return ARFCN_RANGE_256;
	if (max < 512 && size <= 18)
		return ARFCN_RANGE_512;
	if (max < 1024 && size <= 17)
		return ARFCN_RANGE_1024;

	return ARFCN_RANGE_INVALID;
}

/*
 * The below is easier is to write in four methods than
 * to use the max_bits. The encoding is so screwed.. as
 * the bits need to be put in place in the wrong order..
 */
#define HIGH_BITS(w, index, bits, offset) \
		(w[index - 1] >> (bits - offset))
#define LOW_BITS(w, index, bits, offset) \
		(w[index - 1])

static void write_orig_arfcn(uint8_t *chan_list, int f0)
{
	chan_list[0] |= (f0 >> 9) & 1;
	chan_list[1] = (f0 >> 1);
	chan_list[2] = (f0 & 1) << 7;
}

int range_enc_range128(uint8_t *chan_list, int f0, int *w)
{
	chan_list[0] = 0x8C;
	write_orig_arfcn(chan_list, f0);

	LOGP(DRR, LOGL_ERROR, "Range128 encoding is not implemented.\n");
	return -1;
}

int range_enc_range256(uint8_t *chan_list, int f0, int *w)
{
	chan_list[0] = 0x8A;
	write_orig_arfcn(chan_list, f0);

	LOGP(DRR, LOGL_ERROR, "Range256 encoding is not implemented.\n");
	return -1;
}

int range_enc_range512(uint8_t *chan_list, int f0, int *w)
{
	struct gsm48_range_512 *range512;
	write_orig_arfcn(chan_list, f0);

	range512 = (struct gsm48_range_512 *) &chan_list[0];
	range512->form_id = chan_list[0] = 0x44;

	/* W(1) */
	range512->w1_hi = HIGH_BITS(w, 1, 9, 7);
	range512->w1_lo = LOW_BITS (w, 1, 9, 2);
	/* W(2) */
	range512->w2_hi = HIGH_BITS(w, 2, 8, 6);
	range512->w2_lo = LOW_BITS (w, 2, 8, 2);
	/* W(3) */
	range512->w3_hi = HIGH_BITS(w, 3, 8, 6);
	range512->w3_lo = LOW_BITS (w, 3, 8, 2);
	/* W(4) */
	range512->w4_hi = HIGH_BITS(w, 4, 7, 6);
	range512->w4_lo = LOW_BITS (w, 4, 7, 1);
	/* W(5) */
	range512->w5 = HIGH_BITS(w, 5, 7, 7);
	/* W(6) */
	range512->w6 = HIGH_BITS(w, 6, 7, 7);
	/* W(7) */
	range512->w7_hi = HIGH_BITS(w, 7, 7, 1);
	range512->w7_lo = LOW_BITS (w, 7, 7, 6);
	/* W(8) */
	range512->w8_hi = HIGH_BITS(w, 8, 6, 2);
	range512->w8_lo = LOW_BITS (w, 8, 6, 4);
	/* W(9) */
	range512->w9_hi = HIGH_BITS(w, 9, 6, 4);
	range512->w9_lo = LOW_BITS(w, 9, 6, 2);
	/* W(10) */
	range512->w10 = HIGH_BITS(w, 10, 6, 6);
	/* W(11) */
	range512->w11 = HIGH_BITS(w, 11, 6, 6);
	/* W(12) */
	range512->w12_hi = HIGH_BITS(w, 12, 6, 2);
	range512->w12_lo = LOW_BITS (w, 12, 6, 4);
	/* W(13) */
	range512->w13_hi = HIGH_BITS(w, 13, 6, 4);
	range512->w13_lo = LOW_BITS(w, 13, 6, 2);
	/* W(14) */
	range512->w14 = HIGH_BITS(w, 14, 6, 6);
	/* W(15) */
	range512->w15 = HIGH_BITS(w, 15, 6, 6);
	/* W(16) */
	range512->w16_hi = HIGH_BITS(w, 16, 5, 2);
	range512->w16_lo = HIGH_BITS(w, 16, 5, 3);
	/* W(17) */
	range512->w17 = HIGH_BITS(w, 17, 5, 5);

	return 0;
}

int range_enc_range1024(uint8_t *chan_list, int f0, int f0_included, int *w)
{
	chan_list[0] = 0x80 | (f0_included << 2);

	LOGP(DRR, LOGL_ERROR, "Range1024 encoding is not implemented.\n");
	return -1;
}

int range_enc_filter_arfcns(const int range, int *arfcns,
			const int size, const int f0, int *f0_included)
{
	int i, j = 0;
	*f0_included = 0;

	if (range == ARFCN_RANGE_1024) {
		for (i = 0; i < size; ++i) {
			if (arfcns[i] == f0) {
				*f0_included = 1;
				continue;
			}

			/* copy and subtract */
			arfcns[j++] = mod(arfcns[i] - 1, 1024);
		}
	} else {
		for (i = 0; i < size; ++i) {
			/*
			 * Appendix J.4 says the following:
			 * All frequencies except F(0), minus F(0) + 1.
			 * I assume we need to exclude it here.
			 */
			if (arfcns[i] == f0)
				continue;

			arfcns[j++] = mod(arfcns[i] - (f0 + 1), 1024);
		}
	}

	return j;
}
