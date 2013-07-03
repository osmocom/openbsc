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

static int use_arfcn(const struct gsm_bts *bts, const int bis, const int ter,
			const int pgsm, const int arfcn)
{
	if (!bis && !ter && band_compatible(bts, arfcn))
		return 1;
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
static int enc_freq_lst_var_bitmap(uint8_t *chan_list,
				struct bitvec *bv, const struct gsm_bts *bts,
				int bis, int ter, int min, int pgsm)
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
		 && ((!bis && !ter && gsm_arfcn2band(i) == bts->band)
		  || (bis && pgsm && gsm_arfcn2band(i) == bts->band && (i < 1 || i > 124))
		  || (ter && gsm_arfcn2band(i) != bts->band))) {
			int rc = freq_list_bmrel_set_arfcn(chan_list, i);
			if (rc < 0)
				return rc;
		}
	}

	return 0;
}

/* generate a frequency list with the range 512 format */
static int enc_freq_lst_range(uint8_t *chan_list,
				struct bitvec *bv, const struct gsm_bts *bts,
				int bis, int ter, int pgsm)
{
	int arfcns[RANGE_ENC_MAX_ARFCNS];
	int w[RANGE_ENC_MAX_ARFCNS];
	int f0_included = 0;
	int arfcns_used = 0;
	int i, rc, range, f0;

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

	/*
	 * Manipulate the ARFCN list according to the rules in J4 depending
	 * on the selected range.
	 */
	arfcns_used = range_enc_filter_arfcns(range, arfcns, arfcns_used,
				f0, &f0_included);

	memset(w, 0, sizeof(w));
	rc = range_enc_arfcns(range, arfcns, arfcns_used, w, 0);
	if (rc != 0)
		return -3;

	/* Select the range and the amount of bits needed */
	switch (range) {
	case ARFCN_RANGE_128:
		return range_enc_range128(chan_list, f0, w);
		break;
	case ARFCN_RANGE_256:
		return range_enc_range256(chan_list, f0, w);
		break;
	case ARFCN_RANGE_512:
		return range_enc_range512(chan_list, f0, w);
		break;
	case ARFCN_RANGE_1024:
		return range_enc_range1024(chan_list, f0, f0_included, w);
		break;
	default:
		return -4;
	};
}

/* generate a cell channel list as per Section 10.5.2.1b of 04.08 */
static int bitvec2freq_list(uint8_t *chan_list, struct bitvec *bv,
			    const struct gsm_bts *bts, int bis, int ter)
{
	int i, rc, min = -1, max = -1, pgsm = 0, arfcns = 0;

	memset(chan_list, 0, 16);

	if (bts->band == GSM_BAND_900
	 && bts->c0->arfcn >= 1 && bts->c0->arfcn <= 124)
		pgsm = 1;
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
	if (rc == 0)
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
	return bitvec2freq_list(chan_list, bv, bts, 0, 0);
}

/* generate a cell channel list as per Section 10.5.2.1b of 04.08 */
static int generate_bcch_chan_list(uint8_t *chan_list, struct gsm_bts *bts,
	int si5, int bis, int ter)
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

static int generate_si1(uint8_t *output, struct gsm_bts *bts)
{
	int rc;
	struct gsm48_system_information_type_1 *si1 =
		(struct gsm48_system_information_type_1 *) output;

	memset(si1, GSM_MACBLOCK_PADDING, GSM_MACBLOCK_LEN);

	si1->header.l2_plen = (21 << 2) | 1;
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

static int generate_si2(uint8_t *output, struct gsm_bts *bts)
{
	int rc;
	struct gsm48_system_information_type_2 *si2 =
		(struct gsm48_system_information_type_2 *) output;

	memset(si2, GSM_MACBLOCK_PADDING, GSM_MACBLOCK_LEN);

	si2->header.l2_plen = (22 << 2) | 1;
	si2->header.rr_protocol_discriminator = GSM48_PDISC_RR;
	si2->header.skip_indicator = 0;
	si2->header.system_information = GSM48_MT_RR_SYSINFO_2;

	rc = generate_bcch_chan_list(si2->bcch_frequency_list, bts, 0, 0, 0);
	if (rc < 0)
		return rc;
	list_arfcn(si2->bcch_frequency_list, 0xce,
		"Neighbour cells in same band:");

	si2->ncc_permitted = bts->si_common.ncc_permitted;
	si2->rach_control = bts->si_common.rach_control;

	return sizeof(*si2);
}

static int generate_si2bis(uint8_t *output, struct gsm_bts *bts)
{
	int rc;
	struct gsm48_system_information_type_2bis *si2b =
		(struct gsm48_system_information_type_2bis *) output;
	int n;

	memset(si2b, GSM_MACBLOCK_PADDING, GSM_MACBLOCK_LEN);

	si2b->header.l2_plen = (22 << 2) | 1;
	si2b->header.rr_protocol_discriminator = GSM48_PDISC_RR;
	si2b->header.skip_indicator = 0;
	si2b->header.system_information = GSM48_MT_RR_SYSINFO_2bis;

	rc = generate_bcch_chan_list(si2b->bcch_frequency_list, bts, 0, 1, 0);
	if (rc < 0)
		return rc;
	n = list_arfcn(si2b->bcch_frequency_list, 0xce,
		"Neighbour cells in same band, but outside P-GSM:");
	if (n) {
		/* indicate in SI2 and SI2bis: there is an extension */
		struct gsm48_system_information_type_2 *si2 =
			(struct gsm48_system_information_type_2 *)
				bts->si_buf[SYSINFO_TYPE_2];
		si2->bcch_frequency_list[0] |= 0x20;
		si2b->bcch_frequency_list[0] |= 0x20;
	} else
		bts->si_valid &= ~(1 << SYSINFO_TYPE_2bis);

	si2b->rach_control = bts->si_common.rach_control;

	return sizeof(*si2b);
}

static int generate_si2ter(uint8_t *output, struct gsm_bts *bts)
{
	int rc;
	struct gsm48_system_information_type_2ter *si2t =
		(struct gsm48_system_information_type_2ter *) output;
	int n;

	memset(si2t, GSM_MACBLOCK_PADDING, GSM_MACBLOCK_LEN);

	si2t->header.l2_plen = (22 << 2) | 1;
	si2t->header.rr_protocol_discriminator = GSM48_PDISC_RR;
	si2t->header.skip_indicator = 0;
	si2t->header.system_information = GSM48_MT_RR_SYSINFO_2ter;

	rc = generate_bcch_chan_list(si2t->ext_bcch_frequency_list, bts, 0, 0, 1);
	if (rc < 0)
		return rc;
	n = list_arfcn(si2t->ext_bcch_frequency_list, 0x8e,
		"Neighbour cells in different band:");
	if (!n)
		bts->si_valid &= ~(1 << SYSINFO_TYPE_2ter);

	return sizeof(*si2t);
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
	.lsa_params = {
		.present = 0,
	},
	.cell_id = 0,	/* FIXME: doesn't the bts have this? */
	.break_ind = 0,
};

static int generate_si3(uint8_t *output, struct gsm_bts *bts)
{
	int rc;
	struct gsm48_system_information_type_3 *si3 =
		(struct gsm48_system_information_type_3 *) output;

	memset(si3, GSM_MACBLOCK_PADDING, GSM_MACBLOCK_LEN);

	si3->header.l2_plen = (18 << 2) | 1;
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

	if ((bts->si_valid & (1 << SYSINFO_TYPE_2ter))) {
		LOGP(DRR, LOGL_INFO, "SI 2ter is included.\n");
		si_info.si2ter_indicator = 1;
	} else {
		si_info.si2ter_indicator = 0;
	}

	/* SI3 Rest Octets (10.5.2.34), containing
		CBQ, CELL_RESELECT_OFFSET, TEMPORARY_OFFSET, PENALTY_TIME
		Power Offset, 2ter Indicator, Early Classmark Sending,
		Scheduling if and WHERE, GPRS Indicator, SI13 position */
	rc = rest_octets_si3(si3->rest_octets, &si_info);

	return sizeof(*si3) + rc;
}

static int generate_si4(uint8_t *output, struct gsm_bts *bts)
{
	int rc;
	struct gsm48_system_information_type_4 *si4 =
		(struct gsm48_system_information_type_4 *) output;

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

	si4->header.l2_plen = (l2_plen << 2) | 1;

	/* SI4 Rest Octets (10.5.2.35), containing
		Optional Power offset, GPRS Indicator,
		Cell Identity, LSA ID, Selection Parameter */
	rc = rest_octets_si4(si4->data, &si_info);

	return sizeof(*si4) + rc;
}

static int generate_si5(uint8_t *output, struct gsm_bts *bts)
{
	struct gsm48_system_information_type_5 *si5;
	int rc, l2_plen = 18;

	memset(output, GSM_MACBLOCK_PADDING, GSM_MACBLOCK_LEN);

	/* ip.access nanoBTS needs l2_plen!! */
	switch (bts->type) {
	case GSM_BTS_TYPE_NANOBTS:
	case GSM_BTS_TYPE_OSMO_SYSMO:
		*output++ = (l2_plen << 2) | 1;
		l2_plen++;
		break;
	default:
		break;
	}

	si5 = (struct gsm48_system_information_type_5 *) output;

	/* l2 pseudo length, not part of msg: 18 */
	si5->rr_protocol_discriminator = GSM48_PDISC_RR;
	si5->skip_indicator = 0;
	si5->system_information = GSM48_MT_RR_SYSINFO_5;
	rc = generate_bcch_chan_list(si5->bcch_frequency_list, bts, 1, 0, 0);
	if (rc < 0)
		return rc;
	list_arfcn(si5->bcch_frequency_list, 0xce,
		"Neighbour cells in same band:");

	/* 04.08 9.1.37: L2 Pseudo Length of 18 */
	return l2_plen;
}

static int generate_si5bis(uint8_t *output, struct gsm_bts *bts)
{
	struct gsm48_system_information_type_5bis *si5b;
	int rc, l2_plen = 18;
	int n;

	memset(output, GSM_MACBLOCK_PADDING, GSM_MACBLOCK_LEN);

	/* ip.access nanoBTS needs l2_plen!! */
	switch (bts->type) {
	case GSM_BTS_TYPE_NANOBTS:
	case GSM_BTS_TYPE_OSMO_SYSMO:
		*output++ = (l2_plen << 2) | 1;
		l2_plen++;
		break;
	default:
		break;
	}

	si5b = (struct gsm48_system_information_type_5bis *) output;

	/* l2 pseudo length, not part of msg: 18 */
	si5b->rr_protocol_discriminator = GSM48_PDISC_RR;
	si5b->skip_indicator = 0;
	si5b->system_information = GSM48_MT_RR_SYSINFO_5bis;
	rc = generate_bcch_chan_list(si5b->bcch_frequency_list, bts, 1, 1, 0);
	if (rc < 0)
		return rc;
	n = list_arfcn(si5b->bcch_frequency_list, 0xce,
		"Neighbour cells in same band, but outside P-GSM:");
	if (n) {
		/* indicate in SI5 and SI5bis: there is an extension */
		struct gsm48_system_information_type_5 *si5 =
			(struct gsm48_system_information_type_5 *)
				bts->si_buf[SYSINFO_TYPE_5];
		si5->bcch_frequency_list[0] |= 0x20;
		si5b->bcch_frequency_list[0] |= 0x20;
	} else
		bts->si_valid &= ~(1 << SYSINFO_TYPE_5bis);

	/* 04.08 9.1.37: L2 Pseudo Length of 18 */
	return l2_plen;
}

static int generate_si5ter(uint8_t *output, struct gsm_bts *bts)
{
	struct gsm48_system_information_type_5ter *si5t;
	int rc, l2_plen = 18;
	int n;

	memset(output, GSM_MACBLOCK_PADDING, GSM_MACBLOCK_LEN);

	/* ip.access nanoBTS needs l2_plen!! */
	switch (bts->type) {
	case GSM_BTS_TYPE_NANOBTS:
	case GSM_BTS_TYPE_OSMO_SYSMO:
		*output++ = (l2_plen << 2) | 1;
		l2_plen++;
		break;
	default:
		break;
	}

	si5t = (struct gsm48_system_information_type_5ter *) output;

	/* l2 pseudo length, not part of msg: 18 */
	si5t->rr_protocol_discriminator = GSM48_PDISC_RR;
	si5t->skip_indicator = 0;
	si5t->system_information = GSM48_MT_RR_SYSINFO_5ter;
	rc = generate_bcch_chan_list(si5t->bcch_frequency_list, bts, 1, 0, 1);
	if (rc < 0)
		return rc;
	n = list_arfcn(si5t->bcch_frequency_list, 0x8e,
		"Neighbour cells in different band:");
	if (!n)
		bts->si_valid &= ~(1 << SYSINFO_TYPE_5ter);

	/* 04.08 9.1.37: L2 Pseudo Length of 18 */
	return l2_plen;
}

static int generate_si6(uint8_t *output, struct gsm_bts *bts)
{
	struct gsm48_system_information_type_6 *si6;
	int l2_plen = 11;

	memset(output, GSM_MACBLOCK_PADDING, GSM_MACBLOCK_LEN);

	/* ip.access nanoBTS needs l2_plen!! */
	switch (bts->type) {
	case GSM_BTS_TYPE_NANOBTS:
	case GSM_BTS_TYPE_OSMO_SYSMO:
		*output++ = (l2_plen << 2) | 1;
		l2_plen++;
		break;
	default:
		break;
	}

	si6 = (struct gsm48_system_information_type_6 *) output;

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

	/* SI6 Rest Octets: 10.5.2.35a: PCH / NCH info, VBS/VGCS options */

	return l2_plen;
}

static struct gsm48_si13_info si13_default = {
	.cell_opts = {
		.nmo 		= GPRS_NMO_II,
		.t3168		= 2000,
		.t3192		= 1500,
		.drx_timer_max	= 3,
		.bs_cv_max	= 15,
		.ext_info_present = 0,
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

static int generate_si13(uint8_t *output, struct gsm_bts *bts)
{
	struct gsm48_system_information_type_13 *si13 =
		(struct gsm48_system_information_type_13 *) output;
	int ret;

	memset(si13, GSM_MACBLOCK_PADDING, GSM_MACBLOCK_LEN);

	si13->header.rr_protocol_discriminator = GSM48_PDISC_RR;
	si13->header.skip_indicator = 0;
	si13->header.system_information = GSM48_MT_RR_SYSINFO_13;

	si13_default.no_pbcch.rac = bts->gprs.rac;
	si13_default.no_pbcch.net_ctrl_ord = bts->gprs.net_ctrl_ord;

	ret = rest_octets_si13(si13->rest_octets, &si13_default);
	if (ret < 0)
		return ret;

	/* length is coded in bit 2 an up */
	si13->header.l2_plen = 0x01;

	return sizeof (*si13) + ret;
}

typedef int (*gen_si_fn_t)(uint8_t *output, struct gsm_bts *bts);

static const gen_si_fn_t gen_si_fn[_MAX_SYSINFO_TYPE] = {
	[SYSINFO_TYPE_1] = &generate_si1,
	[SYSINFO_TYPE_2] = &generate_si2,
	[SYSINFO_TYPE_2bis] = &generate_si2bis,
	[SYSINFO_TYPE_2ter] = &generate_si2ter,
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

	return gen_si(bts->si_buf[si_type], bts);
}
