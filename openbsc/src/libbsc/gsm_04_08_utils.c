/* GSM Mobile Radio Interface Layer 3 messages on the A-bis interface
 * 3GPP TS 04.08 version 7.21.0 Release 1998 / ETSI TS 100 940 V7.21.0
 * utility functions
 */

/* (C) 2008-2009 by Harald Welte <laforge@gnumonks.org>
 * (C) 2008, 2009 by Holger Hans Peter Freyther <zecke@selfish.org>
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
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <netinet/in.h>

#include <osmocom/core/msgb.h>
#include <osmocom/gsm/gsm48.h>

#include <openbsc/abis_rsl.h>
#include <openbsc/debug.h>
#include <openbsc/gsm_04_08.h>
#include <openbsc/transaction.h>
#include <openbsc/paging.h>
#include <openbsc/signal.h>
#include <openbsc/bsc_api.h>

static int gsm48_sendmsg(struct msgb *msg)
{
	if (msg->lchan)
		msg->dst = msg->lchan->ts->trx->rsl_link;

	msg->l3h = msg->data;
	return rsl_data_request(msg, 0);
}
static void mr_config_for_ms(struct gsm_lchan *lchan, struct msgb *msg)
{
	if (lchan->tch_mode == GSM48_CMODE_SPEECH_AMR)
		msgb_tlv_put(msg, GSM48_IE_MUL_RATE_CFG, lchan->mr_ms_lv[0],
			lchan->mr_ms_lv + 1);
}

/* 7.1.7 and 9.1.7: RR CHANnel RELease */
int gsm48_send_rr_release(struct gsm_lchan *lchan)
{
	struct msgb *msg = gsm48_msgb_alloc();
	struct gsm48_hdr *gh = (struct gsm48_hdr *) msgb_put(msg, sizeof(*gh));
	uint8_t *cause;

	msg->lchan = lchan;
	gh->proto_discr = GSM48_PDISC_RR;
	gh->msg_type = GSM48_MT_RR_CHAN_REL;

	cause = msgb_put(msg, 1);
	cause[0] = GSM48_RR_CAUSE_NORMAL;

	DEBUGP(DRR, "Sending Channel Release: Chan: Number: %d Type: %d\n",
		lchan->nr, lchan->type);

	/* Send actual release request to MS */
	return gsm48_sendmsg(msg);
}

int send_siemens_mrpci(struct gsm_lchan *lchan,
		       uint8_t *classmark2_lv)
{
	struct rsl_mrpci mrpci;

	if (classmark2_lv[0] < 2)
		return -EINVAL;

	mrpci.power_class = classmark2_lv[1] & 0x7;
	mrpci.vgcs_capable = classmark2_lv[2] & (1 << 1);
	mrpci.vbs_capable = classmark2_lv[2] & (1 <<2);
	mrpci.gsm_phase = (classmark2_lv[1]) >> 5 & 0x3;

	return rsl_siemens_mrpci(lchan, &mrpci);
}

int gsm48_handle_paging_resp(struct gsm_subscriber_connection *conn,
			     struct msgb *msg, struct gsm_subscriber *subscr)
{
	struct gsm_bts *bts = msg->lchan->ts->trx->bts;
	struct gsm48_hdr *gh = msgb_l3(msg);
	uint8_t *classmark2_lv = gh->data + 1;

	if (is_siemens_bts(bts))
		send_siemens_mrpci(msg->lchan, classmark2_lv);

	if (!conn->subscr) {
		conn->subscr = subscr;
	} else if (conn->subscr != subscr) {
		LOGP(DRR, LOGL_ERROR, "<- Channel already owned by someone else?\n");
		subscr_put(subscr);
		return -EINVAL;
	} else {
		DEBUGP(DRR, "<- Channel already owned by us\n");
		subscr_put(subscr);
		subscr = conn->subscr;
	}

	osmo_counter_inc(bts->network->stats.paging.completed);

	/* Stop paging on the bts we received the paging response */
	paging_request_stop(conn->bts, subscr, conn, msg);
	return 0;
}

/* Chapter 9.1.9: Ciphering Mode Command */
int gsm48_send_rr_ciph_mode(struct gsm_lchan *lchan, int want_imeisv)
{
	struct msgb *msg = gsm48_msgb_alloc();
	struct gsm48_hdr *gh;
	uint8_t ciph_mod_set;

	msg->lchan = lchan;

	DEBUGP(DRR, "TX CIPHERING MODE CMD\n");

	if (lchan->encr.alg_id <= RSL_ENC_ALG_A5(0))
		ciph_mod_set = 0;
	else
		ciph_mod_set = (lchan->encr.alg_id-2)<<1 | 1;

	gh = (struct gsm48_hdr *) msgb_put(msg, sizeof(*gh) + 1);
	gh->proto_discr = GSM48_PDISC_RR;
	gh->msg_type = GSM48_MT_RR_CIPH_M_CMD;
	gh->data[0] = (want_imeisv & 0x1) << 4 | (ciph_mod_set & 0xf);

	return rsl_encryption_cmd(msg);
}

static void gsm48_cell_desc(struct gsm48_cell_desc *cd,
			    const struct gsm_bts *bts)
{
	cd->ncc = (bts->bsic >> 3 & 0x7);
	cd->bcc = (bts->bsic & 0x7);
	cd->arfcn_hi = bts->c0->arfcn >> 8;
	cd->arfcn_lo = bts->c0->arfcn & 0xff;
}

void gsm48_lchan2chan_desc(struct gsm48_chan_desc *cd,
			   const struct gsm_lchan *lchan)
{
	uint16_t arfcn = lchan->ts->trx->arfcn & 0x3ff;

	cd->chan_nr = gsm_lchan2chan_nr(lchan);
	if (!lchan->ts->hopping.enabled) {
		cd->h0.tsc = gsm_ts_tsc(lchan->ts);
		cd->h0.h = 0;
		cd->h0.arfcn_high = arfcn >> 8;
		cd->h0.arfcn_low = arfcn & 0xff;
	} else {
		cd->h1.tsc = gsm_ts_tsc(lchan->ts);
		cd->h1.h = 1;
		cd->h1.maio_high = lchan->ts->hopping.maio >> 2;
		cd->h1.maio_low = lchan->ts->hopping.maio & 0x03;
		cd->h1.hsn = lchan->ts->hopping.hsn;
	}
}

int gsm48_multirate_config(uint8_t *lv, struct amr_multirate_conf *mr, struct amr_mode *modes)
{
	int num = 0, i;

	for (i = 0; i < 8; i++) {
		if (((mr->gsm48_ie[1] >> i) & 1))
			num++;
	}
	if (num > 4) {
		LOGP(DRR, LOGL_ERROR, "BUG: Using multirate codec with too "
				"many modes in config.\n");
		num = 4;
	}
	if (num < 1) {
		LOGP(DRR, LOGL_ERROR, "BUG: Using multirate codec with no "
				"mode in config.\n");
		num = 1;
	}

	lv[0] = (num == 1) ? 2 : (num + 2);
	memcpy(lv + 1, mr->gsm48_ie, 2);
	if (num == 1)
		return 0;

	lv[3] = modes[0].threshold & 0x3f;
	lv[4] = modes[0].hysteresis << 4;
	if (num == 2)
		return 0;
	lv[4] |= (modes[1].threshold & 0x3f) >> 2;
	lv[5] = modes[1].threshold << 6;
	lv[5] |= (modes[1].hysteresis & 0x0f) << 2;
	if (num == 3)
		return 0;
	lv[5] |= (modes[2].threshold & 0x3f) >> 4;
	lv[6] = modes[2].threshold << 4;
	lv[6] |= modes[2].hysteresis & 0x0f;

	return 0;
}

#define GSM48_HOCMD_CCHDESC_LEN	16

/* Chapter 9.1.15: Handover Command */
int gsm48_send_ho_cmd(struct gsm_lchan *old_lchan, struct gsm_lchan *new_lchan,
		      uint8_t power_command, uint8_t ho_ref)
{
	struct msgb *msg = gsm48_msgb_alloc();
	struct gsm48_hdr *gh = (struct gsm48_hdr *) msgb_put(msg, sizeof(*gh));
	struct gsm48_ho_cmd *ho =
		(struct gsm48_ho_cmd *) msgb_put(msg, sizeof(*ho));

	msg->lchan = old_lchan;
	gh->proto_discr = GSM48_PDISC_RR;
	gh->msg_type = GSM48_MT_RR_HANDO_CMD;

	/* mandatory bits */
	gsm48_cell_desc(&ho->cell_desc, new_lchan->ts->trx->bts);
	gsm48_lchan2chan_desc(&ho->chan_desc, new_lchan);
	ho->ho_ref = ho_ref;
	ho->power_command = power_command;

	if (new_lchan->ts->hopping.enabled) {
		struct gsm_bts *bts = new_lchan->ts->trx->bts;
		struct gsm48_system_information_type_1 *si1;
		uint8_t *cur;

		si1 = GSM_BTS_SI(bts, SYSINFO_TYPE_1);
		/* Copy the Cell Chan Desc (ARFCNS in this cell) */
		msgb_put_u8(msg, GSM48_IE_CELL_CH_DESC);
		cur = msgb_put(msg, GSM48_HOCMD_CCHDESC_LEN);
		memcpy(cur, si1->cell_channel_description,
			GSM48_HOCMD_CCHDESC_LEN);
		/* Copy the Mobile Allocation */
		msgb_tlv_put(msg, GSM48_IE_MA_BEFORE,
			     new_lchan->ts->hopping.ma_len,
			     new_lchan->ts->hopping.ma_data);
	}
	/* FIXME: optional bits for type of synchronization? */

	return gsm48_sendmsg(msg);
}

/* Chapter 9.1.2: Assignment Command */
int gsm48_send_rr_ass_cmd(struct gsm_lchan *dest_lchan, struct gsm_lchan *lchan, uint8_t power_command)
{
	struct msgb *msg = gsm48_msgb_alloc();
	struct gsm48_hdr *gh = (struct gsm48_hdr *) msgb_put(msg, sizeof(*gh));
	struct gsm48_ass_cmd *ass =
		(struct gsm48_ass_cmd *) msgb_put(msg, sizeof(*ass));

	DEBUGP(DRR, "-> ASSIGNMENT COMMAND tch_mode=0x%02x\n", lchan->tch_mode);

	msg->lchan = dest_lchan;
	gh->proto_discr = GSM48_PDISC_RR;
	gh->msg_type = GSM48_MT_RR_ASS_CMD;

	/*
	 * fill the channel information element, this code
	 * should probably be shared with rsl_rx_chan_rqd(),
	 * gsm48_tx_chan_mode_modify. But beware that 10.5.2.5
	 * 10.5.2.5.a have slightly different semantic for
	 * the chan_desc. But as long as multi-slot configurations
	 * are not used we seem to be fine.
	 */
	gsm48_lchan2chan_desc(&ass->chan_desc, lchan);
	ass->power_command = power_command;

	/* optional: cell channel description */

	msgb_tv_put(msg, GSM48_IE_CHANMODE_1, lchan->tch_mode);

	/* mobile allocation in case of hopping */
	if (lchan->ts->hopping.enabled) {
		msgb_tlv_put(msg, GSM48_IE_MA_BEFORE, lchan->ts->hopping.ma_len,
			     lchan->ts->hopping.ma_data);
	}

	/* in case of multi rate we need to attach a config */
	mr_config_for_ms(lchan, msg);

	return gsm48_sendmsg(msg);
}

/* 9.1.5 Channel mode modify: Modify the mode on the MS side */
int gsm48_tx_chan_mode_modify(struct gsm_lchan *lchan, uint8_t mode)
{
	struct msgb *msg = gsm48_msgb_alloc();
	struct gsm48_hdr *gh = (struct gsm48_hdr *) msgb_put(msg, sizeof(*gh));
	struct gsm48_chan_mode_modify *cmm =
		(struct gsm48_chan_mode_modify *) msgb_put(msg, sizeof(*cmm));

	DEBUGP(DRR, "-> CHANNEL MODE MODIFY mode=0x%02x\n", mode);

	lchan->tch_mode = mode;
	msg->lchan = lchan;
	gh->proto_discr = GSM48_PDISC_RR;
	gh->msg_type = GSM48_MT_RR_CHAN_MODE_MODIF;

	/* fill the channel information element, this code
	 * should probably be shared with rsl_rx_chan_rqd() */
	gsm48_lchan2chan_desc(&cmm->chan_desc, lchan);
	cmm->mode = mode;

	/* in case of multi rate we need to attach a config */
	mr_config_for_ms(lchan, msg);

	return gsm48_sendmsg(msg);
}

int gsm48_lchan_modify(struct gsm_lchan *lchan, uint8_t lchan_mode)
{
	int rc;

	rc = gsm48_tx_chan_mode_modify(lchan, lchan_mode);
	if (rc < 0)
		return rc;

	return rc;
}

int gsm48_rx_rr_modif_ack(struct msgb *msg)
{
	int rc;
	struct gsm48_hdr *gh = msgb_l3(msg);
	struct gsm48_chan_mode_modify *mod =
				(struct gsm48_chan_mode_modify *) gh->data;

	DEBUGP(DRR, "CHANNEL MODE MODIFY ACK\n");

	if (mod->mode != msg->lchan->tch_mode) {
		LOGP(DRR, LOGL_ERROR, "CHANNEL MODE change failed. Wanted: %d Got: %d\n",
			msg->lchan->tch_mode, mod->mode);
		return -1;
	}

	/* update the channel type */
	switch (mod->mode) {
	case GSM48_CMODE_SIGN:
		msg->lchan->rsl_cmode = RSL_CMOD_SPD_SIGN;
		break;
	case GSM48_CMODE_SPEECH_V1:
	case GSM48_CMODE_SPEECH_EFR:
	case GSM48_CMODE_SPEECH_AMR:
		msg->lchan->rsl_cmode = RSL_CMOD_SPD_SPEECH;
		break;
	case GSM48_CMODE_DATA_14k5:
	case GSM48_CMODE_DATA_12k0:
	case GSM48_CMODE_DATA_6k0:
	case GSM48_CMODE_DATA_3k6:
		msg->lchan->rsl_cmode = RSL_CMOD_SPD_DATA;
		break;
	}

	/* We've successfully modified the MS side of the channel,
	 * now go on to modify the BTS side of the channel */
	rc = rsl_chan_mode_modify_req(msg->lchan);

	/* FIXME: we not only need to do this after mode modify, but
	 * also after channel activation */
	if (is_ipaccess_bts(msg->lchan->ts->trx->bts) && mod->mode != GSM48_CMODE_SIGN)
		rsl_ipacc_crcx(msg->lchan);
	return rc;
}

int gsm48_parse_meas_rep(struct gsm_meas_rep *rep, struct msgb *msg)
{
	struct gsm48_hdr *gh = msgb_l3(msg);
	uint8_t *data = gh->data;
	struct gsm_bts *bts = msg->lchan->ts->trx->bts;
	struct bitvec *nbv = &bts->si_common.neigh_list;
	struct gsm_meas_rep_cell *mrc;

	if (gh->msg_type != GSM48_MT_RR_MEAS_REP)
		return -EINVAL;

	if (data[0] & 0x80)
		rep->flags |= MEAS_REP_F_BA1;
	if (data[0] & 0x40)
		rep->flags |= MEAS_REP_F_UL_DTX;
	if ((data[1] & 0x40) == 0x00)
		rep->flags |= MEAS_REP_F_DL_VALID;

	rep->dl.full.rx_lev = data[0] & 0x3f;
	rep->dl.sub.rx_lev = data[1] & 0x3f;
	rep->dl.full.rx_qual = (data[2] >> 4) & 0x7;
	rep->dl.sub.rx_qual = (data[2] >> 1) & 0x7;

	rep->num_cell = ((data[3] >> 6) & 0x3) | ((data[2] & 0x01) << 2);
	if (rep->num_cell < 1 || rep->num_cell > 6)
		return 0;

	/* an encoding nightmare in perfection */
	mrc = &rep->cell[0];
	mrc->rxlev = data[3] & 0x3f;
	mrc->neigh_idx = data[4] >> 3;
	mrc->arfcn = bitvec_get_nth_set_bit(nbv, mrc->neigh_idx + 1);
	mrc->bsic = ((data[4] & 0x07) << 3) | (data[5] >> 5);
	if (rep->num_cell < 2)
		return 0;

	mrc = &rep->cell[1];
	mrc->rxlev = ((data[5] & 0x1f) << 1) | (data[6] >> 7);
	mrc->neigh_idx = (data[6] >> 2) & 0x1f;
	mrc->arfcn = bitvec_get_nth_set_bit(nbv, mrc->neigh_idx + 1);
	mrc->bsic = ((data[6] & 0x03) << 4) | (data[7] >> 4);
	if (rep->num_cell < 3)
		return 0;

	mrc = &rep->cell[2];
	mrc->rxlev = ((data[7] & 0x0f) << 2) | (data[8] >> 6);
	mrc->neigh_idx = (data[8] >> 1) & 0x1f;
	mrc->arfcn = bitvec_get_nth_set_bit(nbv, mrc->neigh_idx + 1);
	mrc->bsic = ((data[8] & 0x01) << 5) | (data[9] >> 3);
	if (rep->num_cell < 4)
		return 0;

	mrc = &rep->cell[3];
	mrc->rxlev = ((data[9] & 0x07) << 3) | (data[10] >> 5);
	mrc->neigh_idx = data[10] & 0x1f;
	mrc->arfcn = bitvec_get_nth_set_bit(nbv, mrc->neigh_idx + 1);
	mrc->bsic = data[11] >> 2;
	if (rep->num_cell < 5)
		return 0;

	mrc = &rep->cell[4];
	mrc->rxlev = ((data[11] & 0x03) << 4) | (data[12] >> 4);
	mrc->neigh_idx = ((data[12] & 0xf) << 1) | (data[13] >> 7);
	mrc->arfcn = bitvec_get_nth_set_bit(nbv, mrc->neigh_idx + 1);
	mrc->bsic = (data[13] >> 1) & 0x3f;
	if (rep->num_cell < 6)
		return 0;

	mrc = &rep->cell[5];
	mrc->rxlev = ((data[13] & 0x01) << 5) | (data[14] >> 3);
	mrc->neigh_idx = ((data[14] & 0x07) << 2) | (data[15] >> 6);
	mrc->arfcn = bitvec_get_nth_set_bit(nbv, mrc->neigh_idx + 1);
	mrc->bsic = data[15] & 0x3f;

	return 0;
}

/* 9.2.5 CM service accept */
int gsm48_tx_mm_serv_ack(struct gsm_subscriber_connection *conn)
{
	struct msgb *msg = gsm48_msgb_alloc();
	struct gsm48_hdr *gh = (struct gsm48_hdr *) msgb_put(msg, sizeof(*gh));

	msg->lchan = conn->lchan;

	gh->proto_discr = GSM48_PDISC_MM;
	gh->msg_type = GSM48_MT_MM_CM_SERV_ACC;

	DEBUGP(DMM, "-> CM SERVICE ACK\n");

	return gsm0808_submit_dtap(conn, msg, 0, 0);
}

/* 9.2.6 CM service reject */
int gsm48_tx_mm_serv_rej(struct gsm_subscriber_connection *conn,
				enum gsm48_reject_value value)
{
	struct msgb *msg;

	msg = gsm48_create_mm_serv_rej(value);
	if (!msg) {
		LOGP(DMM, LOGL_ERROR, "Failed to allocate CM Service Reject.\n");
		return -1;
	}

	DEBUGP(DMM, "-> CM SERVICE Reject cause: %d\n", value);

	return gsm0808_submit_dtap(conn, msg, 0, 0);
}
