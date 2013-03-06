/* GSM Mobile Radio Interface Layer 3 messages on the A-bis interface,
 * rest octet handling according to
 * 3GPP TS 04.08 version 7.21.0 Release 1998 / ETSI TS 100 940 V7.21.0 */

/* (C) 2009 by Harald Welte <laforge@gnumonks.org>
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

#include <string.h>
#include <stdlib.h>
#include <errno.h>

#include <openbsc/gsm_data.h>
#include <osmocom/core/bitvec.h>
#include <openbsc/rest_octets.h>

/* generate SI1 rest octets */
int rest_octets_si1(uint8_t *data, uint8_t *nch_pos, int is1800_net)
{
	struct bitvec bv;

	memset(&bv, 0, sizeof(bv));
	bv.data = data;
	bv.data_len = 1;

	if (nch_pos) {
		bitvec_set_bit(&bv, H);
		bitvec_set_uint(&bv, *nch_pos, 5);
	} else
		bitvec_set_bit(&bv, L);

	if (is1800_net)
		bitvec_set_bit(&bv, L);
	else
		bitvec_set_bit(&bv, H);

	bitvec_spare_padding(&bv, 6);
	return bv.data_len;
}

/* Append selection parameters to bitvec */
static void append_selection_params(struct bitvec *bv,
				    const struct gsm48_si_selection_params *sp)
{
	if (sp->present) {
		bitvec_set_bit(bv, H);
		bitvec_set_bit(bv, sp->cbq);
		bitvec_set_uint(bv, sp->cell_resel_off, 6);
		bitvec_set_uint(bv, sp->temp_offs, 3);
		bitvec_set_uint(bv, sp->penalty_time, 5);
	} else
		bitvec_set_bit(bv, L);
}

/* Append power offset to bitvec */
static void append_power_offset(struct bitvec *bv,
				const struct gsm48_si_power_offset *po)
{
	if (po->present) {
		bitvec_set_bit(bv, H);
		bitvec_set_uint(bv, po->power_offset, 2);
	} else
		bitvec_set_bit(bv, L);
}

/* Append GPRS indicator to bitvec */
static void append_gprs_ind(struct bitvec *bv,
			    const struct gsm48_si3_gprs_ind *gi)
{
	if (gi->present) {
		bitvec_set_bit(bv, H);
		bitvec_set_uint(bv, gi->ra_colour, 3);
		/* 0 == SI13 in BCCH Norm, 1 == SI13 sent on BCCH Ext */
		bitvec_set_bit(bv, gi->si13_position);
	} else
		bitvec_set_bit(bv, L);
}


/* Generate SI3 Rest Octests (Chapter 10.5.2.34 / Table 10.4.72) */
int rest_octets_si3(uint8_t *data, const struct gsm48_si_ro_info *si3)
{
	struct bitvec bv;

	memset(&bv, 0, sizeof(bv));
	bv.data = data;
	bv.data_len = 4;

	/* Optional Selection Parameters */
	append_selection_params(&bv, &si3->selection_params);

	/* Optional Power Offset */
	append_power_offset(&bv, &si3->power_offset);

	/* Do we have a SI2ter on the BCCH? */
	if (si3->si2ter_indicator)
		bitvec_set_bit(&bv, H);
	else
		bitvec_set_bit(&bv, L);

	/* Early Classmark Sending Control */
	if (si3->early_cm_ctrl)
		bitvec_set_bit(&bv, H);
	else
		bitvec_set_bit(&bv, L);

	/* Do we have a SI Type 9 on the BCCH? */
	if (si3->scheduling.present) {
		bitvec_set_bit(&bv, H);
		bitvec_set_uint(&bv, si3->scheduling.where, 3);
	} else
		bitvec_set_bit(&bv, L);

	/* GPRS Indicator */
	append_gprs_ind(&bv, &si3->gprs_ind);

	bitvec_spare_padding(&bv, (bv.data_len*8)-1);
	return bv.data_len;
}

static int append_lsa_params(struct bitvec *bv,
			     const struct gsm48_lsa_params *lsa_params)
{
	/* FIXME */
	return -1;
}

/* Generate SI4 Rest Octets (Chapter 10.5.2.35) */
int rest_octets_si4(uint8_t *data, const struct gsm48_si_ro_info *si4)
{
	struct bitvec bv;

	memset(&bv, 0, sizeof(bv));
	bv.data = data;
	bv.data_len = 10; /* FIXME: up to ? */

	/* SI4 Rest Octets O */
	append_selection_params(&bv, &si4->selection_params);
	append_power_offset(&bv, &si4->power_offset);
	append_gprs_ind(&bv, &si4->gprs_ind);

	if (0 /* FIXME */) {
		/* H and SI4 Rest Octets S */
		bitvec_set_bit(&bv, H);

		/* LSA Parameters */
		if (si4->lsa_params.present) {
			bitvec_set_bit(&bv, H);
			append_lsa_params(&bv, &si4->lsa_params);
		} else
			bitvec_set_bit(&bv, L);

		/* Cell Identity */
		if (1) {
			bitvec_set_bit(&bv, H);
			bitvec_set_uint(&bv, si4->cell_id, 16);
		} else
			bitvec_set_bit(&bv, L);

		/* LSA ID Information */
		if (0) {
			bitvec_set_bit(&bv, H);
			/* FIXME */
		} else
			bitvec_set_bit(&bv, L);
	} else {
		/* L and break indicator */
		bitvec_set_bit(&bv, L);
		bitvec_set_bit(&bv, si4->break_ind ? H : L);
	}

	return bv.data_len;
}

/* GPRS Mobile Allocation as per TS 04.60 Chapter 12.10a:
   < GPRS Mobile Allocation IE > ::=
     < HSN : bit (6) >
     { 0 | 1 < RFL number list : < RFL number list struct > > }
     { 0 < MA_LENGTH : bit (6) >
         < MA_BITMAP: bit (val(MA_LENGTH) + 1) >
     | 1 { 0 | 1 <ARFCN index list : < ARFCN index list struct > > } } ;

     < RFL number list struct > :: =
       < RFL_NUMBER : bit (4) >
       { 0 | 1 < RFL number list struct > } ;
     < ARFCN index list struct > ::=
       < ARFCN_INDEX : bit(6) >
       { 0 | 1 < ARFCN index list struct > } ;
 */
static int append_gprs_mobile_alloc(struct bitvec *bv)
{
	/* Hopping Sequence Number */
	bitvec_set_uint(bv, 0, 6);

	if (0) {
		/* We want to use a RFL number list */
		bitvec_set_bit(bv, 1);
		/* FIXME: RFL number list */
	} else
		bitvec_set_bit(bv, 0);

	if (0) {
		/* We want to use a MA_BITMAP */
		bitvec_set_bit(bv, 0);
		/* FIXME: MA_LENGTH, MA_BITMAP, ... */
	} else {
		bitvec_set_bit(bv, 1);
		if (0) {
			/* We want to provide an ARFCN index list */
			bitvec_set_bit(bv, 1);
			/* FIXME */
		} else
			bitvec_set_bit(bv, 0);
	}
	return 0;
}

static int encode_t3192(unsigned int t3192)
{
	if (t3192 == 0)
		return 3;
	else if (t3192 <= 80)
		return 4;
	else if (t3192 <= 120)
		return 5;
	else if (t3192 <= 160)
		return 6;
	else if (t3192 <= 200)
		return 7;
	else if (t3192 <= 500)
		return 0;
	else if (t3192 <= 1000)
		return 1;
	else if (t3192 <= 1500)
		return 2;
	else
		return -EINVAL;
}

static int encode_drx_timer(unsigned int drx)
{
	if (drx == 0)
		return 0;
	else if (drx == 1)
		return 1;
	else if (drx == 2)
		return 2;
	else if (drx <= 4)
		return 3;
	else if (drx <= 8)
		return 4;
	else if (drx <= 16)
		return 5;
	else if (drx <= 32)
		return 6;
	else if (drx <= 64)
		return 7;
	else
		return -EINVAL;
}

/* GPRS Cell Options as per TS 04.60 Chapter 12.24
	< GPRS Cell Options IE > ::=
		< NMO : bit(2) >
		< T3168 : bit(3) >
		< T3192 : bit(3) >
		< DRX_TIMER_MAX: bit(3) >
		< ACCESS_BURST_TYPE: bit >
		< CONTROL_ACK_TYPE : bit >
		< BS_CV_MAX: bit(4) >
		{ 0 | 1 < PAN_DEC : bit(3) >
			< PAN_INC : bit(3) >
			< PAN_MAX : bit(3) >
		{ 0 | 1 < Extension Length : bit(6) >
			< bit (val(Extension Length) + 1
			& { < Extension Information > ! { bit ** = <no string> } } ;
	< Extension Information > ::=
		{ 0 | 1 < EGPRS_PACKET_CHANNEL_REQUEST : bit >
			< BEP_PERIOD : bit(4) > }
		< PFC_FEATURE_MODE : bit >
		< DTM_SUPPORT : bit >
		<BSS_PAGING_COORDINATION: bit >
		<spare bit > ** ;
 */
static int append_gprs_cell_opt(struct bitvec *bv,
				const struct gprs_cell_options *gco)
{
	int t3192, drx_timer_max;

	t3192 = encode_t3192(gco->t3192);
	if (t3192 < 0)
		return t3192;

	drx_timer_max = encode_drx_timer(gco->drx_timer_max);
	if (drx_timer_max < 0)
		return drx_timer_max;

	bitvec_set_uint(bv, gco->nmo, 2);
	bitvec_set_uint(bv, gco->t3168 / 500, 3);
	bitvec_set_uint(bv, t3192, 3);
	bitvec_set_uint(bv, drx_timer_max, 3);
	/* ACCESS_BURST_TYPE: Hard-code 8bit */
	bitvec_set_bit(bv, 0);
	/* CONTROL_ACK_TYPE: Hard-code to RLC/MAC control block */
	bitvec_set_bit(bv, 1);
	bitvec_set_uint(bv, gco->bs_cv_max, 4);

	if (0) {
		/* hard-code no PAN_{DEC,INC,MAX} */
		bitvec_set_bit(bv, 0);
	} else {
		/* copied from ip.access BSC protocol trace */
		bitvec_set_bit(bv, 1);
		bitvec_set_uint(bv, 1, 3);	/* DEC */
		bitvec_set_uint(bv, 1, 3);	/* INC */
		bitvec_set_uint(bv, 15, 3);	/* MAX */
	}

	if (!gco->ext_info_present) {
		/* no extension information */
		bitvec_set_bit(bv, 0);
	} else {
		/* extension information */
		bitvec_set_bit(bv, 1);
		if (!gco->ext_info.egprs_supported) {
			/* 6bit length of extension */
			bitvec_set_uint(bv, (1 + 3)-1, 6);
			/* EGPRS supported in the cell */
			bitvec_set_bit(bv, 0);
		} else {
			/* 6bit length of extension */
			bitvec_set_uint(bv, (1 + 5 + 3)-1, 6);
			/* EGPRS supported in the cell */
			bitvec_set_bit(bv, 1);
			/* 1bit EGPRS PACKET CHANNEL REQUEST */
			bitvec_set_bit(bv, gco->ext_info.use_egprs_p_ch_req);
			/* 4bit BEP PERIOD */
			bitvec_set_uint(bv, gco->ext_info.bep_period, 4);
		}
		bitvec_set_bit(bv, gco->ext_info.pfc_supported);
		bitvec_set_bit(bv, gco->ext_info.dtm_supported);
		bitvec_set_bit(bv, gco->ext_info.bss_paging_coordination);
	}

	return 0;
}

static void append_gprs_pwr_ctrl_pars(struct bitvec *bv,
				      const struct gprs_power_ctrl_pars *pcp)
{
	bitvec_set_uint(bv, pcp->alpha, 4);
	bitvec_set_uint(bv, pcp->t_avg_w, 5);
	bitvec_set_uint(bv, pcp->t_avg_t, 5);
	bitvec_set_uint(bv, pcp->pc_meas_chan, 1);
	bitvec_set_uint(bv, pcp->n_avg_i, 4);
}

/* Generate SI13 Rest Octests (04.08 Chapter 10.5.2.37b) */
int rest_octets_si13(uint8_t *data, const struct gsm48_si13_info *si13)
{
	struct bitvec bv;

	memset(&bv, 0, sizeof(bv));
	bv.data = data;
	bv.data_len = 20;

	if (0) {
		/* No rest octets */
		bitvec_set_bit(&bv, L);
	} else {
		bitvec_set_bit(&bv, H);
		bitvec_set_uint(&bv, si13->bcch_change_mark, 3);
		bitvec_set_uint(&bv, si13->si_change_field, 4);
		if (1) {
			bitvec_set_bit(&bv, 0);
		} else {
			bitvec_set_bit(&bv, 1);
			bitvec_set_uint(&bv, si13->bcch_change_mark, 2);
			append_gprs_mobile_alloc(&bv);
		}
		if (!si13->pbcch_present) {
			/* PBCCH not present in cell */
			bitvec_set_bit(&bv, 0);
			bitvec_set_uint(&bv, si13->no_pbcch.rac, 8);
			bitvec_set_bit(&bv, si13->no_pbcch.spgc_ccch_sup);
			bitvec_set_uint(&bv, si13->no_pbcch.prio_acc_thr, 3);
			bitvec_set_uint(&bv, si13->no_pbcch.net_ctrl_ord, 2);
			append_gprs_cell_opt(&bv, &si13->cell_opts);
			append_gprs_pwr_ctrl_pars(&bv, &si13->pwr_ctrl_pars);
		} else {
			/* PBCCH present in cell */
			bitvec_set_bit(&bv, 1);
			bitvec_set_uint(&bv, si13->pbcch.psi1_rep_per, 4);
			/* PBCCH Descripiton */
			bitvec_set_uint(&bv, si13->pbcch.pb, 4);
			bitvec_set_uint(&bv, si13->pbcch.tsc, 3);
			bitvec_set_uint(&bv, si13->pbcch.tn, 3);
			switch (si13->pbcch.carrier_type) {
			case PBCCH_BCCH:
				bitvec_set_bit(&bv, 0);
				bitvec_set_bit(&bv, 0);
				break;
			case PBCCH_ARFCN:
				bitvec_set_bit(&bv, 0);
				bitvec_set_bit(&bv, 1);
				bitvec_set_uint(&bv, si13->pbcch.arfcn, 10);
				break;
			case PBCCH_MAIO:
				bitvec_set_bit(&bv, 1);
				bitvec_set_uint(&bv, si13->pbcch.maio, 6);
				break;
			}
		}
		/* 3GPP TS 44.018 Release 6 / 10.5.2.37b */
		bitvec_set_bit(&bv, H);	/* added Release 99 */
		/* claim our SGSN is compatible with Release 99, as EDGE and EGPRS
		 * was only added in this Release */
		bitvec_set_bit(&bv, 1);
	}
	bitvec_spare_padding(&bv, (bv.data_len*8)-1);
	return bv.data_len;
}
