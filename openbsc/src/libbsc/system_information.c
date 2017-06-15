/* GSM 04.08 System Information (SI) encoding and decoding
 * 3GPP TS 04.08 version 7.21.0 Release 1998 / ETSI TS 100 940 V7.21.0 */

/* (C) 2008-2010 by Harald Welte <laforge@gnumonks.org>
 * (C) 2012 Holger Hans Peter Freyther
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
#include <string.h>
#include <stdio.h>
#include <netinet/in.h>
#include <stdbool.h>

#include <osmocom/core/bitvec.h>
#include <osmocom/core/utils.h>
#include <osmocom/gsm/sysinfo.h>

#include <openbsc/debug.h>
#include <openbsc/gsm_04_08.h>
#include <openbsc/gsm_data.h>
#include <openbsc/abis_rsl.h>
#include <openbsc/rest_octets.h>
#include <openbsc/arfcn_range_encode.h>

/*
 * DCS1800 and PCS1900 have overlapping ARFCNs. We would need to set the
 * ARFCN_PCS flag on the 1900 ARFCNs but this would increase cell_alloc
 * and other arrays to make sure (ARFCN_PCS + 1024)/8 ARFCNs fit into the
 * array. DCS1800 and PCS1900 can not be used at the same time so conserve
 * memory and do the below.
 */
static int band_compatible(const struct gsm_bts *bts, int arfcn)
{
	enum gsm_band band = gsm_arfcn2band(arfcn);

	/* normal case */
	if (band == bts->band)
		return 1;
	/* deal with ARFCN_PCS not set */
	if (band == GSM_BAND_1800 && bts->band == GSM_BAND_1900)
		return 1;

	return 0;
}

static int is_dcs_net(const struct gsm_bts *bts)
{
	if (bts->band == GSM_BAND_850)
		return 0;
	if (bts->band == GSM_BAND_1900)
		return 0;
	return 1;
}

/* Return p(n) for given NR_OF_TDD_CELLS - see Table 9.1.54.1a, 3GPP TS 44.018 */
unsigned range1024_p(unsigned n)
{
	switch (n) {
	case 0: return 0;
	case 1: return 10;
	case 2: return 19;
	case 3: return 28;
	case 4: return 36;
	case 5: return 44;
	case 6: return 52;
	case 7: return 60;
	case 8: return 67;
	case 9: return 74;
	case 10: return 81;
	case 11: return 88;
	case 12: return 95;
	case 13: return 102;
	case 14: return 109;
	case 15: return 116;
	case 16: return 122;
	default: return 0;
	}
}

/* Return q(m) for given NR_OF_TDD_CELLS - see Table 9.1.54.1b, 3GPP TS 44.018 */
unsigned range512_q(unsigned m)
{
	switch (m) {
	case 0: return 0;
	case 1: return 9;
	case 2: return 17;
	case 3: return 25;
	case 4: return 32;
	case 5: return 39;
	case 6: return 46;
	case 7: return 53;
	case 8: return 59;
	case 9: return 65;
	case 10: return 71;
	case 11: return 77;
	case 12: return 83;
	case 13: return 89;
	case 14: return 95;
	case 15: return 101;
	case 16: return 106;
	case 17: return 111;
	case 18: return 116;
	case 19: return 121;
	case 20: return 126;
	default: return 0;
	}
}

size_t si2q_earfcn_count(const struct osmo_earfcn_si2q *e)
{
	unsigned i, ret = 0;

	if (!e)
		return 0;

	for (i = 0; i < e->length; i++)
		if (e->arfcn[i] != OSMO_EARFCN_INVALID)
			ret++;

	return ret;
}

/* generate SI2quater messages, return rest octets length of last generated message or negative error code */
static int make_si2quaters(struct gsm_bts *bts, bool counting)
{
	int rc;
	bool memory_exceeded = true;
	struct gsm48_system_information_type_2quater *si2q;

	for (bts->si2q_index = 0; bts->si2q_index < SI2Q_MAX_NUM; bts->si2q_index++) {
		si2q = GSM_BTS_SI2Q(bts, bts->si2q_index);
		if (counting) { /* that's legitimate if we're called for counting purpose: */
			if (bts->si2q_count < bts->si2q_index)
				bts->si2q_count = bts->si2q_index;
		} else {
			memset(si2q, GSM_MACBLOCK_PADDING, GSM_MACBLOCK_LEN);

			si2q->header.l2_plen = GSM48_LEN2PLEN(22);
			si2q->header.rr_protocol_discriminator = GSM48_PDISC_RR;
			si2q->header.skip_indicator = 0;
			si2q->header.system_information = GSM48_MT_RR_SYSINFO_2quater;
		}

		rc = rest_octets_si2quater(si2q->rest_octets, bts);
		if (rc < 0)
			return rc;

		if (bts->u_offset >= bts->si_common.uarfcn_length &&
		    bts->e_offset >= si2q_earfcn_count(&bts->si_common.si2quater_neigh_list)) {
			memory_exceeded = false;
			break;
		}
	}

	if (memory_exceeded)
		return -ENOMEM;

	return rc;
}

/* we generate SI2q rest octets twice to get proper estimation but it's one time cost anyway */
uint8_t si2q_num(struct gsm_bts *bts)
{
	int rc = make_si2quaters(bts, true);
	uint8_t num = bts->si2q_index + 1; /* number of SI2quater messages */

	/* N. B: si2q_num() should NEVER be called during actualSI2q rest octets generation
	   we're not re-entrant because of the following code: */
	bts->u_offset = 0;
	bts->e_offset = 0;

	if (rc < 0)
		return 0xFF; /* return impossible index as an indicator of error in generating SI2quater */

	return num;
}

/* 3GPP TS 44.018, Table 9.1.54.1 - prepend diversity bit to scrambling code */
static inline uint16_t encode_fdd(uint16_t scramble, bool diversity)
{
	if (diversity)
		return scramble | (1 << 9);
	return scramble;
}

int bts_earfcn_add(struct gsm_bts *bts, uint16_t earfcn, uint8_t thresh_hi, uint8_t thresh_lo, uint8_t prio,
		   uint8_t qrx, uint8_t meas_bw)
{
	struct osmo_earfcn_si2q *e = &bts->si_common.si2quater_neigh_list;
	int r = osmo_earfcn_add(e, earfcn, (meas_bw < EARFCN_MEAS_BW_INVALID) ? meas_bw : OSMO_EARFCN_MEAS_INVALID);

	if (r < 0)
		return r;

	if (e->thresh_hi && thresh_hi != e->thresh_hi)
		r = 1;

	e->thresh_hi = thresh_hi;

	if (thresh_lo != EARFCN_THRESH_LOW_INVALID) {
		if (e->thresh_lo_valid && e->thresh_lo != thresh_lo)
			r = EARFCN_THRESH_LOW_INVALID;
		e->thresh_lo = thresh_lo;
		e->thresh_lo_valid = true;
	}

	if (qrx != EARFCN_QRXLV_INVALID) {
		if (e->qrxlm_valid && e->qrxlm != qrx)
			r = EARFCN_QRXLV_INVALID + 1;
		e->qrxlm = qrx;
		e->qrxlm_valid = true;
	}

	if (prio != EARFCN_PRIO_INVALID) {
		if (e->prio_valid && e->prio != prio)
			r = EARFCN_PRIO_INVALID;
		e->prio = prio;
		e->prio_valid = true;
	}

	return r;
}

int bts_uarfcn_del(struct gsm_bts *bts, uint16_t arfcn, uint16_t scramble)
{
	uint16_t sc0 = encode_fdd(scramble, false), sc1 = encode_fdd(scramble, true),
		*ual = bts->si_common.data.uarfcn_list,
		*scl = bts->si_common.data.scramble_list;
	size_t len = bts->si_common.uarfcn_length, i;
	for (i = 0; i < len; i++) {
		if (arfcn == ual[i] && (sc0 == scl[i] || sc1 == scl[i])) {
			/* we rely on the assumption that (uarfcn, scramble)
			   tuple is unique in the lists */
			if (i != len - 1) { /* move the tail if necessary */
				memmove(ual + i, ual + i + 1, 2 * (len - i + 1));
				memmove(scl + i, scl + i + 1, 2 * (len - i + 1));
			}
			break;
		}
	}

	if (i == len)
		return -EINVAL;

	bts->si_common.uarfcn_length--;
	return 0;
}

int bts_uarfcn_add(struct gsm_bts *bts, uint16_t arfcn, uint16_t scramble, bool diversity)
{
	size_t len = bts->si_common.uarfcn_length, i, k = 0;
	uint16_t scr, chk,
		*ual = bts->si_common.data.uarfcn_list,
		*scl = bts->si_common.data.scramble_list,
		scramble1 = encode_fdd(scramble, true),
		scramble0 = encode_fdd(scramble, false);

	scr = diversity ? scramble1 : scramble0;
	chk = diversity ? scramble0 : scramble1;

	if (len == MAX_EARFCN_LIST)
		return -ENOMEM;

	for (i = 0; i < len; i++) /* find the position of arfcn if any */
		if (arfcn == ual[i])
			break;

	for (k = 0; i < len; i++) {
		if (arfcn == ual[i] && (scr == scl[i] || chk == scl[i]))
			return -EADDRINUSE;
		if (scr > scl[i])
			k = i + 1;
	}
	/* we keep lists sorted by scramble code:
	   insert into appropriate position and move the tail */
	if (len - k) {
		memmove(ual + k + 1, ual + k, (len - k) * 2);
		memmove(scl + k + 1, scl + k, (len - k) * 2);
	}

	ual[k] = arfcn;
	scl[k] = scr;
	bts->si_common.uarfcn_length++;

	if (si2q_num(bts) <= SI2Q_MAX_NUM) {
		bts->si2q_count = si2q_num(bts) - 1;
		return 0;
	}

	bts_uarfcn_del(bts, arfcn, scramble);
	return -ENOSPC;
}

static inline int use_arfcn(const struct gsm_bts *bts, const bool bis, const bool ter,
			const bool pgsm, const int arfcn)
{
	if (bts->force_combined_si)
		return !bis && !ter;
	if (!bis && !ter && band_compatible(bts, arfcn))
		return 1;
	/* Correct but somehow broken with either the nanoBTS or the iPhone5 */
	if (bis && pgsm && band_compatible(bts, arfcn) && (arfcn < 1 || arfcn > 124))
		return 1;
	if (ter && !band_compatible(bts, arfcn))
		return 1;
	return 0;
}

/* Frequency Lists as per TS 04.08 10.5.2.13 */

/* 10.5.2.13.2: Bit map 0 format */
static int freq_list_bm0_set_arfcn(uint8_t *chan_list, unsigned int arfcn)
{
	unsigned int byte, bit;

	if (arfcn > 124 || arfcn < 1) {
		LOGP(DRR, LOGL_ERROR, "Bitmap 0 only supports ARFCN 1...124\n");
		return -EINVAL;
	}

	/* the bitmask is from 1..124, not from 0..123 */
	arfcn--;

	byte = arfcn / 8;
	bit = arfcn % 8;

	chan_list[GSM48_CELL_CHAN_DESC_SIZE-1-byte] |= (1 << bit);

	return 0;
}

/* 10.5.2.13.7: Variable bit map format */
static int freq_list_bmrel_set_arfcn(uint8_t *chan_list, unsigned int arfcn)
{
	unsigned int byte, bit;
	unsigned int min_arfcn;
	unsigned int bitno;

	min_arfcn = (chan_list[0] & 1) << 9;
	min_arfcn |= chan_list[1] << 1;
	min_arfcn |= (chan_list[2] >> 7) & 1;

	/* The lower end of our bitmaks is always implicitly included */
	if (arfcn == min_arfcn)
		return 0;

	if (((arfcn - min_arfcn) & 1023) > 111) {
		LOGP(DRR, LOGL_ERROR, "arfcn(%u) > min(%u) + 111\n", arfcn, min_arfcn);
		return -EINVAL;
	}

	bitno = (arfcn - min_arfcn) & 1023;
	byte = bitno / 8;
	bit = bitno % 8;

	chan_list[2 + byte] |= 1 << (7 - bit);

	return 0;
}

/* generate a variable bitmap */
static inline int enc_freq_lst_var_bitmap(uint8_t *chan_list,
				struct bitvec *bv, const struct gsm_bts *bts,
				bool bis, bool ter, int min, bool pgsm)
{
	int i;

	/* set it to 'Variable bitmap format' */
	chan_list[0] = 0x8e;

	chan_list[0] |= (min >> 9) & 1;
	chan_list[1] = (min >> 1);
	chan_list[2] = (min & 1) << 7;

	for (i = 0; i < bv->data_len*8; i++) {
		/* see notes in bitvec2freq_list */
		if (bitvec_get_bit_pos(bv, i)
		 && ((!bis && !ter && band_compatible(bts,i))
		  || (bis && pgsm && band_compatible(bts,i) && (i < 1 || i > 124))
		  || (ter && !band_compatible(bts, i)))) {
			int rc = freq_list_bmrel_set_arfcn(chan_list, i);
			if (rc < 0)
				return rc;
		}
	}

	return 0;
}

int range_encode(enum gsm48_range r, int *arfcns, int arfcns_used, int *w,
		 int f0, uint8_t *chan_list)
{
	/*
	 * Manipulate the ARFCN list according to the rules in J4 depending
	 * on the selected range.
	 */
	int rc, f0_included;

	range_enc_filter_arfcns(arfcns, arfcns_used, f0, &f0_included);

	rc = range_enc_arfcns(r, arfcns, arfcns_used, w, 0);
	if (rc < 0)
		return rc;

	/* Select the range and the amount of bits needed */
	switch (r) {
	case ARFCN_RANGE_128:
		return range_enc_range128(chan_list, f0, w);
	case ARFCN_RANGE_256:
		return range_enc_range256(chan_list, f0, w);
	case ARFCN_RANGE_512:
		return range_enc_range512(chan_list, f0, w);
	case ARFCN_RANGE_1024:
		return range_enc_range1024(chan_list, f0, f0_included, w);
	default:
		return -ERANGE;
	};

	return f0_included;
}

/* generate a frequency list with the range 512 format */
static inline int enc_freq_lst_range(uint8_t *chan_list,
				struct bitvec *bv, const struct gsm_bts *bts,
				bool bis, bool ter, bool pgsm)
{
	int arfcns[RANGE_ENC_MAX_ARFCNS];
	int w[RANGE_ENC_MAX_ARFCNS];
	int arfcns_used = 0;
	int i, range, f0;

	/*
	 * Select ARFCNs according to the rules in bitvec2freq_list
	 */
	for (i = 0; i < bv->data_len * 8; ++i) {
		/* More ARFCNs than the maximum */
		if (arfcns_used > ARRAY_SIZE(arfcns))
			return -1;
		/* Check if we can select it? */
		if (bitvec_get_bit_pos(bv, i) && use_arfcn(bts, bis, ter, pgsm, i))
			arfcns[arfcns_used++] = i;
	}

	/*
	 * Check if the given list of ARFCNs can be encoded.
	 */
	range = range_enc_determine_range(arfcns, arfcns_used, &f0);
	if (range == ARFCN_RANGE_INVALID)
		return -2;

	memset(w, 0, sizeof(w));
	return range_encode(range, arfcns, arfcns_used, w, f0, chan_list);
}

/* generate a cell channel list as per Section 10.5.2.1b of 04.08 */
static int bitvec2freq_list(uint8_t *chan_list, struct bitvec *bv,
			    const struct gsm_bts *bts, bool bis, bool ter)
{
	int i, rc, min = -1, max = -1, arfcns = 0;
	bool pgsm = false;
	memset(chan_list, 0, 16);

	if (bts->band == GSM_BAND_900
	 && bts->c0->arfcn >= 1 && bts->c0->arfcn <= 124)
		pgsm = true;
	/* P-GSM-only handsets only support 'bit map 0 format' */
	if (!bis && !ter && pgsm) {
		chan_list[0] = 0;

		for (i = 0; i < bv->data_len*8; i++) {
			if (i >= 1 && i <= 124
			 && bitvec_get_bit_pos(bv, i)) {
				rc = freq_list_bm0_set_arfcn(chan_list, i);
				if (rc < 0)
					return rc;
			}
		}
		return 0;
	}

	for (i = 0; i < bv->data_len*8; i++) {
		/* in case of SI2 or SI5 allow all neighbours in same band
		 * in case of SI*bis, allow neighbours in same band ouside pgsm
		 * in case of SI*ter, allow neighbours in different bands
		 */
		if (!bitvec_get_bit_pos(bv, i))
			continue;
		if (!use_arfcn(bts, bis, ter, pgsm, i))
			continue;
		/* count the arfcns we want to carry */
		arfcns += 1;

		/* 955..1023 < 0..885 */
		if (min < 0)
			min = i;
		if (i >= 955 && min < 955)
			min = i;
		if (i >= 955 && min >= 955 && i < min)
			min = i;
		if (i < 955 && min < 955 && i < min)
			min = i;
		if (max < 0)
			max = i;
		if (i < 955 && max >= 955)
			max = i;
		if (i >= 955 && max >= 955 && i > max)
			max = i;
		if (i < 955 && max < 955 && i > max)
			max = i;
	}

	if (max == -1) {
		/* Empty set, use 'bit map 0 format' */
		chan_list[0] = 0;
		return 0;
	}

	/* Now find the best encoding */
	if (((max - min) & 1023) <= 111)
		return enc_freq_lst_var_bitmap(chan_list, bv, bts, bis,
				ter, min, pgsm);

	/* Attempt to do the range encoding */
	rc = enc_freq_lst_range(chan_list, bv, bts, bis, ter, pgsm);
	if (rc >= 0)
		return 0;

	LOGP(DRR, LOGL_ERROR, "min_arfcn=%u, max_arfcn=%u, arfcns=%d "
		"can not generate ARFCN list", min, max, arfcns);
	return -EINVAL;
}

/* generate a cell channel list as per Section 10.5.2.1b of 04.08 */
/* static*/ int generate_cell_chan_list(uint8_t *chan_list, struct gsm_bts *bts)
{
	struct gsm_bts_trx *trx;
	struct bitvec *bv = &bts->si_common.cell_alloc;

	/* Zero-initialize the bit-vector */
	memset(bv->data, 0, bv->data_len);

	/* first we generate a bitvec of all TRX ARFCN's in our BTS */
	llist_for_each_entry(trx, &bts->trx_list, list) {
		unsigned int i, j;
		/* Always add the TRX's ARFCN */
		bitvec_set_bit_pos(bv, trx->arfcn, 1);
		for (i = 0; i < ARRAY_SIZE(trx->ts); i++) {
			struct gsm_bts_trx_ts *ts = &trx->ts[i];
			/* Add any ARFCNs present in hopping channels */
			for (j = 0; j < 1024; j++) {
				if (bitvec_get_bit_pos(&ts->hopping.arfcns, j))
					bitvec_set_bit_pos(bv, j, 1);
			}
		}
	}

	/* then we generate a GSM 04.08 frequency list from the bitvec */
	return bitvec2freq_list(chan_list, bv, bts, false, false);
}

/* generate a cell channel list as per Section 10.5.2.1b of 04.08 */
static int generate_bcch_chan_list(uint8_t *chan_list, struct gsm_bts *bts,
	bool si5, bool bis, bool ter)
{
	struct gsm_bts *cur_bts;
	struct bitvec *bv;

	if (si5 && bts->neigh_list_manual_mode == NL_MODE_MANUAL_SI5SEP)
		bv = &bts->si_common.si5_neigh_list;
	else
		bv = &bts->si_common.neigh_list;

	/* Generate list of neighbor cells if we are in automatic mode */
	if (bts->neigh_list_manual_mode == NL_MODE_AUTOMATIC) {
		/* Zero-initialize the bit-vector */
		memset(bv->data, 0, bv->data_len);

		/* first we generate a bitvec of the BCCH ARFCN's in our BSC */
		llist_for_each_entry(cur_bts, &bts->network->bts_list, list) {
			if (cur_bts == bts)
				continue;
			bitvec_set_bit_pos(bv, cur_bts->c0->arfcn, 1);
		}
	}

	/* then we generate a GSM 04.08 frequency list from the bitvec */
	return bitvec2freq_list(chan_list, bv, bts, bis, ter);
}

static int list_arfcn(uint8_t *chan_list, uint8_t mask, char *text)
{
	int n = 0, i;
	struct gsm_sysinfo_freq freq[1024];

	memset(freq, 0, sizeof(freq));
	gsm48_decode_freq_list(freq, chan_list, 16, 0xce, 1);
	for (i = 0; i < 1024; i++) {
		if (freq[i].mask) {
			if (!n)
				LOGP(DRR, LOGL_INFO, "%s", text);
			LOGPC(DRR, LOGL_INFO, " %d", i);
			n++;
		}
	}
	if (n)
		LOGPC(DRR, LOGL_INFO, "\n");

	return n;
}

static int generate_si1(enum osmo_sysinfo_type t, struct gsm_bts *bts)
{
	int rc;
	struct gsm48_system_information_type_1 *si1 = (struct gsm48_system_information_type_1 *) GSM_BTS_SI(bts, t);

	memset(si1, GSM_MACBLOCK_PADDING, GSM_MACBLOCK_LEN);

	si1->header.l2_plen = GSM48_LEN2PLEN(21);
	si1->header.rr_protocol_discriminator = GSM48_PDISC_RR;
	si1->header.skip_indicator = 0;
	si1->header.system_information = GSM48_MT_RR_SYSINFO_1;

	rc = generate_cell_chan_list(si1->cell_channel_description, bts);
	if (rc < 0)
		return rc;
	list_arfcn(si1->cell_channel_description, 0xce, "Serving cell:");

	si1->rach_control = bts->si_common.rach_control;

	/*
	 * SI1 Rest Octets (10.5.2.32), contains NCH position and band
	 * indicator but that is not in the 04.08.
	 */
	rc = rest_octets_si1(si1->rest_octets, NULL, is_dcs_net(bts));

	return sizeof(*si1) + rc;
}

static int generate_si2(enum osmo_sysinfo_type t, struct gsm_bts *bts)
{
	int rc;
	struct gsm48_system_information_type_2 *si2 = (struct gsm48_system_information_type_2 *) GSM_BTS_SI(bts, t);

	memset(si2, GSM_MACBLOCK_PADDING, GSM_MACBLOCK_LEN);

	si2->header.l2_plen = GSM48_LEN2PLEN(22);
	si2->header.rr_protocol_discriminator = GSM48_PDISC_RR;
	si2->header.skip_indicator = 0;
	si2->header.system_information = GSM48_MT_RR_SYSINFO_2;

	rc = generate_bcch_chan_list(si2->bcch_frequency_list, bts, false, false, false);
	if (rc < 0)
		return rc;
	list_arfcn(si2->bcch_frequency_list, 0xce,
		"SI2 Neighbour cells in same band:");

	si2->ncc_permitted = bts->si_common.ncc_permitted;
	si2->rach_control = bts->si_common.rach_control;

	return sizeof(*si2);
}

static int generate_si2bis(enum osmo_sysinfo_type t, struct gsm_bts *bts)
{
	int rc;
	struct gsm48_system_information_type_2bis *si2b =
		(struct gsm48_system_information_type_2bis *) GSM_BTS_SI(bts, t);
	int n;

	memset(si2b, GSM_MACBLOCK_PADDING, GSM_MACBLOCK_LEN);

	si2b->header.l2_plen = GSM48_LEN2PLEN(22);
	si2b->header.rr_protocol_discriminator = GSM48_PDISC_RR;
	si2b->header.skip_indicator = 0;
	si2b->header.system_information = GSM48_MT_RR_SYSINFO_2bis;

	rc = generate_bcch_chan_list(si2b->bcch_frequency_list, bts, false, true, false);
	if (rc < 0)
		return rc;
	n = list_arfcn(si2b->bcch_frequency_list, 0xce,
		"Neighbour cells in same band, but outside P-GSM:");
	if (n) {
		/* indicate in SI2 and SI2bis: there is an extension */
		struct gsm48_system_information_type_2 *si2 =
			(struct gsm48_system_information_type_2 *) GSM_BTS_SI(bts, SYSINFO_TYPE_2);
		si2->bcch_frequency_list[0] |= 0x20;
		si2b->bcch_frequency_list[0] |= 0x20;
	} else
		bts->si_valid &= ~(1 << SYSINFO_TYPE_2bis);

	si2b->rach_control = bts->si_common.rach_control;

	return sizeof(*si2b);
}

static int generate_si2ter(enum osmo_sysinfo_type t, struct gsm_bts *bts)
{
	int rc;
	struct gsm48_system_information_type_2ter *si2t =
		(struct gsm48_system_information_type_2ter *) GSM_BTS_SI(bts, t);
	int n;

	memset(si2t, GSM_MACBLOCK_PADDING, GSM_MACBLOCK_LEN);

	si2t->header.l2_plen = GSM48_LEN2PLEN(22);
	si2t->header.rr_protocol_discriminator = GSM48_PDISC_RR;
	si2t->header.skip_indicator = 0;
	si2t->header.system_information = GSM48_MT_RR_SYSINFO_2ter;

	rc = generate_bcch_chan_list(si2t->ext_bcch_frequency_list, bts, false, false, true);
	if (rc < 0)
		return rc;
	n = list_arfcn(si2t->ext_bcch_frequency_list, 0x8e,
		"Neighbour cells in different band:");
	if (!n)
		bts->si_valid &= ~(1 << SYSINFO_TYPE_2ter);

	return sizeof(*si2t);
}

/* SI2quater messages are optional - we only generate them when neighbor UARFCNs or EARFCNs are configured */
static inline bool si2quater_not_needed(struct gsm_bts *bts)
{
	unsigned i = MAX_EARFCN_LIST;

	if (bts->si_common.si2quater_neigh_list.arfcn)
		for (i = 0; i < MAX_EARFCN_LIST; i++)
			if (bts->si_common.si2quater_neigh_list.arfcn[i] != OSMO_EARFCN_INVALID)
				break;

	if (!bts->si_common.uarfcn_length && i == MAX_EARFCN_LIST) {
		bts->si_valid &= ~(1 << SYSINFO_TYPE_2quater); /* mark SI2q as invalid if no (E|U)ARFCNs are present */
		return true;
	}

	return false;
}

static int generate_si2quater(enum osmo_sysinfo_type t, struct gsm_bts *bts)
{
	int rc;
	struct gsm48_system_information_type_2quater *si2q;

	if (si2quater_not_needed(bts)) /* generate rest_octets for SI2q only when necessary */
		return GSM_MACBLOCK_LEN;

	bts->u_offset = 0;
	bts->e_offset = 0;
	bts->si2q_index = 0;
	bts->si2q_count = si2q_num(bts) - 1;

	rc = make_si2quaters(bts, false);
	if (rc < 0)
		return rc;

	OSMO_ASSERT(bts->si2q_count == bts->si2q_index);
	OSMO_ASSERT(bts->si2q_count <= SI2Q_MAX_NUM);

	return sizeof(*si2q) + rc;
}

static struct gsm48_si_ro_info si_info = {
	.selection_params = {
		.present = 0,
	},
	.power_offset = {
		.present = 0,
	},
	.si2ter_indicator = 0,
	.early_cm_ctrl = 1,
	.scheduling = {
		.present = 0,
	},
	.gprs_ind = {
		.si13_position = 0,
		.ra_colour = 0,
		.present = 1,
	},
	.si2quater_indicator = 0,
	.lsa_params = {
		.present = 0,
	},
	.cell_id = 0,	/* FIXME: doesn't the bts have this? */
	.break_ind = 0,
};

static int generate_si3(enum osmo_sysinfo_type t, struct gsm_bts *bts)
{
	int rc;
	struct gsm48_system_information_type_3 *si3 = (struct gsm48_system_information_type_3 *) GSM_BTS_SI(bts, t);

	memset(si3, GSM_MACBLOCK_PADDING, GSM_MACBLOCK_LEN);

	si3->header.l2_plen = GSM48_LEN2PLEN(18);
	si3->header.rr_protocol_discriminator = GSM48_PDISC_RR;
	si3->header.skip_indicator = 0;
	si3->header.system_information = GSM48_MT_RR_SYSINFO_3;

	si3->cell_identity = htons(bts->cell_identity);
	gsm48_generate_lai(&si3->lai, bts->network->country_code,
			   bts->network->network_code,
			   bts->location_area_code);
	si3->control_channel_desc = bts->si_common.chan_desc;
	si3->cell_options = bts->si_common.cell_options;
	si3->cell_sel_par = bts->si_common.cell_sel_par;
	si3->rach_control = bts->si_common.rach_control;

	/* allow/disallow DTXu */
	gsm48_set_dtx(&si3->cell_options, bts->dtxu, bts->dtxu, true);

	if (GSM_BTS_HAS_SI(bts, SYSINFO_TYPE_2ter)) {
		LOGP(DRR, LOGL_INFO, "SI 2ter is included.\n");
		si_info.si2ter_indicator = 1;
	} else {
		si_info.si2ter_indicator = 0;
	}
	if (GSM_BTS_HAS_SI(bts, SYSINFO_TYPE_2quater)) {
		LOGP(DRR, LOGL_INFO, "SI 2quater is included, based on %zu EARFCNs and %zu UARFCNs.\n",
		     si2q_earfcn_count(&bts->si_common.si2quater_neigh_list), bts->si_common.uarfcn_length);
		si_info.si2quater_indicator = 1;
	} else {
		si_info.si2quater_indicator = 0;
	}
	si_info.early_cm_ctrl = bts->early_classmark_allowed;

	/* SI3 Rest Octets (10.5.2.34), containing
		CBQ, CELL_RESELECT_OFFSET, TEMPORARY_OFFSET, PENALTY_TIME
		Power Offset, 2ter Indicator, Early Classmark Sending,
		Scheduling if and WHERE, GPRS Indicator, SI13 position */
	rc = rest_octets_si3(si3->rest_octets, &si_info);

	return sizeof(*si3) + rc;
}

static int generate_si4(enum osmo_sysinfo_type t, struct gsm_bts *bts)
{
	int rc;
	struct gsm48_system_information_type_4 *si4 = (struct gsm48_system_information_type_4 *) GSM_BTS_SI(bts, t);
	struct gsm_lchan *cbch_lchan;
	uint8_t *restoct = si4->data;

	/* length of all IEs present except SI4 rest octets and l2_plen */
	int l2_plen = sizeof(*si4) - 1;

	memset(si4, GSM_MACBLOCK_PADDING, GSM_MACBLOCK_LEN);

	si4->header.rr_protocol_discriminator = GSM48_PDISC_RR;
	si4->header.skip_indicator = 0;
	si4->header.system_information = GSM48_MT_RR_SYSINFO_4;

	gsm48_generate_lai(&si4->lai, bts->network->country_code,
			   bts->network->network_code,
			   bts->location_area_code);
	si4->cell_sel_par = bts->si_common.cell_sel_par;
	si4->rach_control = bts->si_common.rach_control;

	/* Optional: CBCH Channel Description + CBCH Mobile Allocation */
	cbch_lchan = gsm_bts_get_cbch(bts);
	if (cbch_lchan) {
		struct gsm48_chan_desc cd;
		gsm48_lchan2chan_desc(&cd, cbch_lchan);
		tv_fixed_put(si4->data, GSM48_IE_CBCH_CHAN_DESC, 3,
			     (uint8_t *) &cd);
		l2_plen += 3 + 1;
		restoct += 3 + 1;
		/* we don't use hopping and thus don't need a CBCH MA */
	}

	si4->header.l2_plen = GSM48_LEN2PLEN(l2_plen);

	/* SI4 Rest Octets (10.5.2.35), containing
		Optional Power offset, GPRS Indicator,
		Cell Identity, LSA ID, Selection Parameter */
	rc = rest_octets_si4(restoct, &si_info, (uint8_t *)GSM_BTS_SI(bts, t) + GSM_MACBLOCK_LEN - restoct);

	return l2_plen + 1 + rc;
}

static int generate_si5(enum osmo_sysinfo_type t, struct gsm_bts *bts)
{
	struct gsm48_system_information_type_5 *si5;
	uint8_t *output = GSM_BTS_SI(bts, t);
	int rc, l2_plen = 18;

	memset(output, GSM_MACBLOCK_PADDING, GSM_MACBLOCK_LEN);

	/* ip.access nanoBTS needs l2_plen!! */
	switch (bts->type) {
	case GSM_BTS_TYPE_NANOBTS:
	case GSM_BTS_TYPE_OSMOBTS:
		*output++ = GSM48_LEN2PLEN(l2_plen);
		l2_plen++;
		break;
	default:
		break;
	}

	si5 = (struct gsm48_system_information_type_5 *) GSM_BTS_SI(bts, t);

	/* l2 pseudo length, not part of msg: 18 */
	si5->rr_protocol_discriminator = GSM48_PDISC_RR;
	si5->skip_indicator = 0;
	si5->system_information = GSM48_MT_RR_SYSINFO_5;
	rc = generate_bcch_chan_list(si5->bcch_frequency_list, bts, true, false, false);
	if (rc < 0)
		return rc;
	list_arfcn(si5->bcch_frequency_list, 0xce,
		"SI5 Neighbour cells in same band:");

	/* 04.08 9.1.37: L2 Pseudo Length of 18 */
	return l2_plen;
}

static int generate_si5bis(enum osmo_sysinfo_type t, struct gsm_bts *bts)
{
	struct gsm48_system_information_type_5bis *si5b;
	uint8_t *output = GSM_BTS_SI(bts, t);
	int rc, l2_plen = 18;
	int n;

	memset(output, GSM_MACBLOCK_PADDING, GSM_MACBLOCK_LEN);

	/* ip.access nanoBTS needs l2_plen!! */
	switch (bts->type) {
	case GSM_BTS_TYPE_NANOBTS:
	case GSM_BTS_TYPE_OSMOBTS:
		*output++ = GSM48_LEN2PLEN(l2_plen);
		l2_plen++;
		break;
	default:
		break;
	}

	si5b = (struct gsm48_system_information_type_5bis *) GSM_BTS_SI(bts, t);

	/* l2 pseudo length, not part of msg: 18 */
	si5b->rr_protocol_discriminator = GSM48_PDISC_RR;
	si5b->skip_indicator = 0;
	si5b->system_information = GSM48_MT_RR_SYSINFO_5bis;
	rc = generate_bcch_chan_list(si5b->bcch_frequency_list, bts, true, true, false);
	if (rc < 0)
		return rc;
	n = list_arfcn(si5b->bcch_frequency_list, 0xce,
		"Neighbour cells in same band, but outside P-GSM:");
	if (n) {
		/* indicate in SI5 and SI5bis: there is an extension */
		struct gsm48_system_information_type_5 *si5 =
			(struct gsm48_system_information_type_5 *) GSM_BTS_SI(bts, SYSINFO_TYPE_5);
		si5->bcch_frequency_list[0] |= 0x20;
		si5b->bcch_frequency_list[0] |= 0x20;
	} else
		bts->si_valid &= ~(1 << SYSINFO_TYPE_5bis);

	/* 04.08 9.1.37: L2 Pseudo Length of 18 */
	return l2_plen;
}

static int generate_si5ter(enum osmo_sysinfo_type t, struct gsm_bts *bts)
{
	struct gsm48_system_information_type_5ter *si5t;
	uint8_t *output = GSM_BTS_SI(bts, t);
	int rc, l2_plen = 18;
	int n;

	memset(output, GSM_MACBLOCK_PADDING, GSM_MACBLOCK_LEN);

	/* ip.access nanoBTS needs l2_plen!! */
	switch (bts->type) {
	case GSM_BTS_TYPE_NANOBTS:
	case GSM_BTS_TYPE_OSMOBTS:
		*output++ = GSM48_LEN2PLEN(l2_plen);
		l2_plen++;
		break;
	default:
		break;
	}

	si5t = (struct gsm48_system_information_type_5ter *) GSM_BTS_SI(bts, t);

	/* l2 pseudo length, not part of msg: 18 */
	si5t->rr_protocol_discriminator = GSM48_PDISC_RR;
	si5t->skip_indicator = 0;
	si5t->system_information = GSM48_MT_RR_SYSINFO_5ter;
	rc = generate_bcch_chan_list(si5t->bcch_frequency_list, bts, true, false, true);
	if (rc < 0)
		return rc;
	n = list_arfcn(si5t->bcch_frequency_list, 0x8e,
		"Neighbour cells in different band:");
	if (!n)
		bts->si_valid &= ~(1 << SYSINFO_TYPE_5ter);

	/* 04.08 9.1.37: L2 Pseudo Length of 18 */
	return l2_plen;
}

static int generate_si6(enum osmo_sysinfo_type t, struct gsm_bts *bts)
{
	struct gsm48_system_information_type_6 *si6;
	uint8_t *output = GSM_BTS_SI(bts, t);
	int l2_plen = 11;
	int rc;

	memset(output, GSM_MACBLOCK_PADDING, GSM_MACBLOCK_LEN);

	/* ip.access nanoBTS needs l2_plen!! */
	switch (bts->type) {
	case GSM_BTS_TYPE_NANOBTS:
	case GSM_BTS_TYPE_OSMOBTS:
		*output++ = GSM48_LEN2PLEN(l2_plen);
		l2_plen++;
		break;
	default:
		break;
	}

	si6 = (struct gsm48_system_information_type_6 *) GSM_BTS_SI(bts, t);

	/* l2 pseudo length, not part of msg: 11 */
	si6->rr_protocol_discriminator = GSM48_PDISC_RR;
	si6->skip_indicator = 0;
	si6->system_information = GSM48_MT_RR_SYSINFO_6;
	si6->cell_identity = htons(bts->cell_identity);
	gsm48_generate_lai(&si6->lai, bts->network->country_code,
			   bts->network->network_code,
			   bts->location_area_code);
	si6->cell_options = bts->si_common.cell_options;
	si6->ncc_permitted = bts->si_common.ncc_permitted;
	/* allow/disallow DTXu */
	gsm48_set_dtx(&si6->cell_options, bts->dtxu, bts->dtxu, false);

	/* SI6 Rest Octets: 10.5.2.35a: PCH / NCH info, VBS/VGCS options */
	rc = rest_octets_si6(si6->rest_octets, is_dcs_net(bts));

	return l2_plen + rc;
}

static struct gsm48_si13_info si13_default = {
	.cell_opts = {
		.nmo 		= GPRS_NMO_II,
		.t3168		= 2000,
		.t3192		= 1500,
		.drx_timer_max	= 3,
		.bs_cv_max	= 15,
		.ctrl_ack_type_use_block = true,
		.ext_info_present = 0,
		.supports_egprs_11bit_rach = 0,
		.ext_info = {
			/* The values below are just guesses ! */
			.egprs_supported = 0,
			.use_egprs_p_ch_req = 1,
			.bep_period = 5,
			.pfc_supported = 0,
			.dtm_supported = 0,
			.bss_paging_coordination = 0,
		},
	},
	.pwr_ctrl_pars = {
		.alpha		= 0,	/* a = 0.0 */
		.t_avg_w	= 16,
		.t_avg_t	= 16,
		.pc_meas_chan	= 0, 	/* downling measured on CCCH */
		.n_avg_i	= 8,
	},
	.bcch_change_mark	= 1,
	.si_change_field	= 0,
	.pbcch_present		= 0,
	{
		.no_pbcch = {
			.rac		= 0,	/* needs to be patched */
			.spgc_ccch_sup 	= 0,
			.net_ctrl_ord	= 0,
			.prio_acc_thr	= 6,
		},
	},
};

static int generate_si13(enum osmo_sysinfo_type t, struct gsm_bts *bts)
{
	struct gsm48_system_information_type_13 *si13 =
		(struct gsm48_system_information_type_13 *) GSM_BTS_SI(bts, t);
	int ret;

	memset(si13, GSM_MACBLOCK_PADDING, GSM_MACBLOCK_LEN);

	si13->header.rr_protocol_discriminator = GSM48_PDISC_RR;
	si13->header.skip_indicator = 0;
	si13->header.system_information = GSM48_MT_RR_SYSINFO_13;

	si13_default.no_pbcch.rac = bts->gprs.rac;
	si13_default.no_pbcch.net_ctrl_ord = bts->gprs.net_ctrl_ord;

	si13_default.cell_opts.ctrl_ack_type_use_block =
		bts->gprs.ctrl_ack_type_use_block;

	/* Information about the other SIs */
	si13_default.bcch_change_mark = bts->bcch_change_mark;
	si13_default.cell_opts.supports_egprs_11bit_rach =
					bts->gprs.supports_egprs_11bit_rach;

	ret = rest_octets_si13(si13->rest_octets, &si13_default);
	if (ret < 0)
		return ret;

	/* length is coded in bit 2 an up */
	si13->header.l2_plen = 0x01;

	return sizeof (*si13) + ret;
}

typedef int (*gen_si_fn_t)(enum osmo_sysinfo_type t, struct gsm_bts *bts);

static const gen_si_fn_t gen_si_fn[_MAX_SYSINFO_TYPE] = {
	[SYSINFO_TYPE_1] = &generate_si1,
	[SYSINFO_TYPE_2] = &generate_si2,
	[SYSINFO_TYPE_2bis] = &generate_si2bis,
	[SYSINFO_TYPE_2ter] = &generate_si2ter,
	[SYSINFO_TYPE_2quater] = &generate_si2quater,
	[SYSINFO_TYPE_3] = &generate_si3,
	[SYSINFO_TYPE_4] = &generate_si4,
	[SYSINFO_TYPE_5] = &generate_si5,
	[SYSINFO_TYPE_5bis] = &generate_si5bis,
	[SYSINFO_TYPE_5ter] = &generate_si5ter,
	[SYSINFO_TYPE_6] = &generate_si6,
	[SYSINFO_TYPE_13] = &generate_si13,
};

int gsm_generate_si(struct gsm_bts *bts, enum osmo_sysinfo_type si_type)
{
	gen_si_fn_t gen_si;

	switch (bts->gprs.mode) {
	case BTS_GPRS_EGPRS:
		si13_default.cell_opts.ext_info_present = 1;
		si13_default.cell_opts.ext_info.egprs_supported = 1;
		/* fallthrough */
	case BTS_GPRS_GPRS:
		si_info.gprs_ind.present = 1;
		break;
	case BTS_GPRS_NONE:
		si_info.gprs_ind.present = 0;
		break;
	}

	memcpy(&si_info.selection_params,
	       &bts->si_common.cell_ro_sel_par,
	       sizeof(struct gsm48_si_selection_params));

	gen_si = gen_si_fn[si_type];
	if (!gen_si)
		return -EINVAL;

	return gen_si(si_type, bts);
}
