/* GSM 04.08 System Information (SI) encoding and decoding
 * 3GPP TS 04.08 version 7.21.0 Release 1998 / ETSI TS 100 940 V7.21.0 */

/* (C) 2008-2009 by Harald Welte <laforge@gnumonks.org>
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
#include <string.h>
#include <stdio.h>
#include <sys/types.h>
#include <netinet/in.h>

#include <openbsc/gsm_04_08.h>
#include <openbsc/gsm_data.h>
#include <openbsc/abis_rsl.h>
#include <openbsc/rest_octets.h>
#include <osmocore/bitvec.h>
#include <openbsc/debug.h>

#define GSM48_CELL_CHAN_DESC_SIZE	16
#define GSM_MACBLOCK_LEN 		23
#define GSM_MACBLOCK_PADDING		0x2b

/* verify the sizes of the system information type structs */

/* rest octets are not part of the struct */
static_assert(sizeof(struct gsm48_system_information_type_header) == 3, _si_header_size);
static_assert(sizeof(struct gsm48_rach_control) == 3, _si_rach_control);
static_assert(sizeof(struct gsm48_system_information_type_1) == 22, _si1_size);
static_assert(sizeof(struct gsm48_system_information_type_2) == 23, _si2_size);
static_assert(sizeof(struct gsm48_system_information_type_3) == 19, _si3_size);
static_assert(sizeof(struct gsm48_system_information_type_4) == 13, _si4_size);

/* bs11 forgot the l2 len, 0-6 rest octets */
static_assert(sizeof(struct gsm48_system_information_type_5) == 18, _si5_size);
static_assert(sizeof(struct gsm48_system_information_type_6) == 11, _si6_size);

static_assert(sizeof(struct gsm48_system_information_type_13) == 3, _si13_size);

/* Frequency Lists as per TS 04.08 10.5.2.13 */

/* 10.5.2.13.2: Bit map 0 format */
static int freq_list_bm0_set_arfcn(u_int8_t *chan_list, unsigned int arfcn)
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
static int freq_list_bmrel_set_arfcn(u_int8_t *chan_list, unsigned int arfcn)
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

	if (arfcn < min_arfcn) {
		LOGP(DRR, LOGL_ERROR, "arfcn(%u) < min(%u)\n", arfcn, min_arfcn);
		return -EINVAL;
	}
	if (arfcn > min_arfcn + 111) {
		LOGP(DRR, LOGL_ERROR, "arfcn(%u) > min(%u) + 111\n", arfcn, min_arfcn);
		return -EINVAL;
	}

	bitno = (arfcn - min_arfcn);
	byte = bitno / 8;
	bit = bitno % 8;

	chan_list[2 + byte] |= 1 << (7 - bit);

	return 0;
}

/* generate a cell channel list as per Section 10.5.2.1b of 04.08 */
static int bitvec2freq_list(u_int8_t *chan_list, struct bitvec *bv,
			    const struct gsm_bts *bts)
{
	int i, rc, min = 1024, max = -1;

	memset(chan_list, 0, 16);

	/* GSM900-only handsets only support 'bit map 0 format' */
	if (bts->band == GSM_BAND_900) {
		chan_list[0] = 0;

		for (i = 0; i < bv->data_len*8; i++) {
			if (bitvec_get_bit_pos(bv, i)) {
				rc = freq_list_bm0_set_arfcn(chan_list, i);
				if (rc < 0)
					return rc;
			}
		}
		return 0;
	}

	/* We currently only support the 'Variable bitmap format' */
	chan_list[0] = 0x8e;

	for (i = 0; i < bv->data_len*8; i++) {
		if (bitvec_get_bit_pos(bv, i)) {
			if (i < min)
				min = i;
			if (i > max)
				max = i;
		}
	}

	if (max == -1) {
		/* Empty set, use 'bit map 0 format' */
		chan_list[0] = 0;
		return 0;
	}

	if ((max - min) > 111) {
		LOGP(DRR, LOGL_ERROR, "min_arfcn=%u, max_arfcn=%u, "
			"distance > 111\n", min, max);
		return -EINVAL;
	}

	chan_list[0] |= (min >> 9) & 1;
	chan_list[1] = (min >> 1);
	chan_list[2] = (min & 1) << 7;

	for (i = 0; i < bv->data_len*8; i++) {
		if (bitvec_get_bit_pos(bv, i)) {
			rc = freq_list_bmrel_set_arfcn(chan_list, i);
			if (rc < 0)
				return rc;
		}
	}

	return 0;
}

/* generate a cell channel list as per Section 10.5.2.1b of 04.08 */
static int generate_cell_chan_list(u_int8_t *chan_list, struct gsm_bts *bts)
{
	struct gsm_bts_trx *trx;
	struct bitvec *bv = &bts->si_common.cell_alloc;

	/* first we generate a bitvec of all TRX ARFCN's in our BTS */
	llist_for_each_entry(trx, &bts->trx_list, list)
		bitvec_set_bit_pos(bv, trx->arfcn, 1);

	/* then we generate a GSM 04.08 frequency list from the bitvec */
	return bitvec2freq_list(chan_list, bv, bts);
}

/* generate a cell channel list as per Section 10.5.2.1b of 04.08 */
static int generate_bcch_chan_list(u_int8_t *chan_list, struct gsm_bts *bts)
{
	struct gsm_bts *cur_bts;
	struct bitvec *bv = &bts->si_common.neigh_list;

	/* first we generate a bitvec of the BCCH ARFCN's in our BSC */
	llist_for_each_entry(cur_bts, &bts->network->bts_list, list) {
		if (cur_bts == bts)
			continue;
		bitvec_set_bit_pos(bv, cur_bts->c0->arfcn, 1);
	}

	/* then we generate a GSM 04.08 frequency list from the bitvec */
	return bitvec2freq_list(chan_list, bv, bts);
}

static int generate_si1(u_int8_t *output, struct gsm_bts *bts)
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

	si1->rach_control = bts->si_common.rach_control;

	/* SI1 Rest Octets (10.5.2.32), contains NCH position */
	rc = rest_octets_si1(si1->rest_octets, NULL);
	return sizeof(*si1) + rc;
}

static int generate_si2(u_int8_t *output, struct gsm_bts *bts)
{
	int rc;
	struct gsm48_system_information_type_2 *si2 =
		(struct gsm48_system_information_type_2 *) output;

	memset(si2, GSM_MACBLOCK_PADDING, GSM_MACBLOCK_LEN);

	si2->header.l2_plen = (22 << 2) | 1;
	si2->header.rr_protocol_discriminator = GSM48_PDISC_RR;
	si2->header.skip_indicator = 0;
	si2->header.system_information = GSM48_MT_RR_SYSINFO_2;

	rc = generate_bcch_chan_list(si2->bcch_frequency_list, bts);
	if (rc < 0)
		return rc;

	si2->ncc_permitted = bts->si_common.ncc_permitted;
	si2->rach_control = bts->si_common.rach_control;

	return sizeof(*si2);
}

struct gsm48_si_ro_info si_info = {
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
		.present = 0,
	},
	.lsa_params = {
		.present = 0,
	},
	.cell_id = 0,	/* FIXME: doesn't the bts have this? */
	.break_ind = 0,
};

static int generate_si3(u_int8_t *output, struct gsm_bts *bts)
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
	gsm0408_generate_lai(&si3->lai, bts->network->country_code,
			     bts->network->network_code,
			     bts->location_area_code);
	si3->control_channel_desc = bts->si_common.chan_desc;
	si3->cell_options = bts->si_common.cell_options;
	si3->cell_sel_par = bts->si_common.cell_sel_par;
	si3->rach_control = bts->si_common.rach_control;

	/* SI3 Rest Octets (10.5.2.34), containing
		CBQ, CELL_RESELECT_OFFSET, TEMPORARY_OFFSET, PENALTY_TIME
		Power Offset, 2ter Indicator, Early Classmark Sending,
		Scheduling if and WHERE, GPRS Indicator, SI13 position */
	rc = rest_octets_si3(si3->rest_octets, &si_info);

	return sizeof(*si3) + rc;
}

static int generate_si4(u_int8_t *output, struct gsm_bts *bts)
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

	gsm0408_generate_lai(&si4->lai, bts->network->country_code,
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

static int generate_si5(u_int8_t *output, struct gsm_bts *bts)
{
	struct gsm48_system_information_type_5 *si5;
	int rc, l2_plen = 18;

	memset(output, GSM_MACBLOCK_PADDING, GSM_MACBLOCK_LEN);

	/* ip.access nanoBTS needs l2_plen!! */
	if (is_ipaccess_bts(bts)) {
		*output++ = (l2_plen << 2) | 1;
		l2_plen++;
	}

	si5 = (struct gsm48_system_information_type_5 *) output;

	/* l2 pseudo length, not part of msg: 18 */
	si5->rr_protocol_discriminator = GSM48_PDISC_RR;
	si5->skip_indicator = 0;
	si5->system_information = GSM48_MT_RR_SYSINFO_5;
	rc = generate_bcch_chan_list(si5->bcch_frequency_list, bts);
	if (rc < 0)
		return rc;

	/* 04.08 9.1.37: L2 Pseudo Length of 18 */
	return l2_plen;
}

static int generate_si6(u_int8_t *output, struct gsm_bts *bts)
{
	struct gsm48_system_information_type_6 *si6;
	int l2_plen = 11;

	memset(output, GSM_MACBLOCK_PADDING, GSM_MACBLOCK_LEN);

	/* ip.access nanoBTS needs l2_plen!! */
	if (is_ipaccess_bts(bts)) {
		*output++ = (l2_plen << 2) | 1;
		l2_plen++;
	}

	si6 = (struct gsm48_system_information_type_6 *) output;

	/* l2 pseudo length, not part of msg: 11 */
	si6->rr_protocol_discriminator = GSM48_PDISC_RR;
	si6->skip_indicator = 0;
	si6->system_information = GSM48_MT_RR_SYSINFO_6;
	si6->cell_identity = htons(bts->cell_identity);
	gsm0408_generate_lai(&si6->lai, bts->network->country_code,
			     bts->network->network_code,
			     bts->location_area_code);
	si6->cell_options = bts->si_common.cell_options;
	si6->ncc_permitted = bts->si_common.ncc_permitted;

	/* SI6 Rest Octets: 10.5.2.35a: PCH / NCH info, VBS/VGCS options */

	return l2_plen;
}

static struct gsm48_si13_info si13_default = {
	.cell_opts = {
		.nmo 		= GPRS_NMO_III,
		.t3168		= 1000,
		.t3192		= 1000,
		.drx_timer_max	= 1,
		.bs_cv_max	= 15,
	},
	.pwr_ctrl_pars = {
		.alpha		= 10,	/* a = 1.0 */
		.t_avg_w	= 25,
		.t_avg_t	= 25,
		.pc_meas_chan	= 0, 	/* downling measured on CCCH */
		.n_avg_i	= 15,
	},
	.bcch_change_mark	= 0,
	.si_change_field	= 0,
	.pbcch_present		= 0,
	{
		.no_pbcch = {
			.rac		= 0,
			.spgc_ccch_sup 	= 0,
			.net_ctrl_ord	= 0,
			.prio_acc_thr	= 0,
		},
	},
};

static int generate_si13(u_int8_t *output, struct gsm_bts *bts)
{
	struct gsm48_system_information_type_13 *si13 =
		(struct gsm48_system_information_type_13 *) output;
	int ret;

	memset(si13, GSM_MACBLOCK_PADDING, GSM_MACBLOCK_LEN);

	si13->header.rr_protocol_discriminator = GSM48_PDISC_RR;
	si13->header.skip_indicator = 0;
	si13->header.system_information = GSM48_MT_RR_SYSINFO_13;

	ret = rest_octets_si13(si13->rest_octets, &si13_default);
	if (ret < 0)
		return ret;

	si13->header.l2_plen = ret & 0xff;

	return sizeof (*si13) + ret;
}

int gsm_generate_si(u_int8_t *output, struct gsm_bts *bts, int type)
{
	switch (type) {
	case RSL_SYSTEM_INFO_1:
		return generate_si1(output, bts);
	case RSL_SYSTEM_INFO_2:
		return generate_si2(output, bts);
	case RSL_SYSTEM_INFO_3:
		return generate_si3(output, bts);
	case RSL_SYSTEM_INFO_4:
		return generate_si4(output, bts);
	case RSL_SYSTEM_INFO_5:
		return generate_si5(output, bts);
	case RSL_SYSTEM_INFO_6:
		return generate_si6(output, bts);
	case RSL_SYSTEM_INFO_13:
		return generate_si13(output, bts);
	default:
		return -EINVAL;
	}

	return 0;
}
