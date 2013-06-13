/*
 * (C) 2013 by Andreas Eversberg <jolly@eversberg.eu>
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
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include <stdio.h>
#include <stdlib.h>

#include <assert.h>

#include <osmocom/core/application.h>
#include <osmocom/core/select.h>
#include <osmocom/core/talloc.h>

#include <openbsc/abis_rsl.h>
#include <openbsc/debug.h>
#include <openbsc/gsm_subscriber.h>
#include <openbsc/chan_alloc.h>
#include <openbsc/handover_decision.h>
#include <openbsc/system_information.h>

extern void bts_model_nanobts_init();
struct gsm_lchan *lchan_lookup(struct gsm_bts_trx *trx, uint8_t chan_nr);

struct gsm_network *bsc_gsmnet;

/* measurement report */

uint8_t meas_rep_ba = 0, meas_rep_valid = 1, meas_valid = 1, meas_multi_rep = 0;
uint8_t meas_dl_rxlev = 0, meas_dl_rxqual = 0;
uint8_t meas_ul_rxlev = 0, meas_ul_rxqual = 0;
uint8_t meas_tx_power_ms = 0, meas_tx_power_bs = 0, meas_ta_ms = 0;
uint8_t meas_dtx_ms = 0, meas_dtx_bs = 0, meas_nr = 0;
uint8_t meas_num_nc = 0, meas_rxlev_nc[6], meas_bsic_nc[6], meas_bcch_f_nc[6];

static void gen_meas_rep(struct gsm_lchan *lchan)
{
	struct msgb *msg = msgb_alloc_headroom(256, 64, "RSL");
	struct abis_rsl_dchan_hdr *dh;
	uint8_t chan_nr = gsm_lchan2chan_nr(lchan);
	uint8_t ulm[3], l1i[2], *buf;
	struct gsm48_hdr *gh;
	struct gsm48_meas_res *mr;

	dh = (struct abis_rsl_dchan_hdr *) msgb_put(msg, sizeof(*dh));
	dh->c.msg_discr = ABIS_RSL_MDISC_DED_CHAN;
	dh->c.msg_type = RSL_MT_MEAS_RES;
	dh->ie_chan = RSL_IE_CHAN_NR;
	dh->chan_nr = chan_nr;

	msgb_tv_put(msg, RSL_IE_MEAS_RES_NR, meas_nr++);

	ulm[0] = meas_ul_rxlev | (meas_dtx_bs << 7);
	ulm[1] = meas_ul_rxlev;
	ulm[2] = (meas_ul_rxqual << 3) | meas_ul_rxqual;
	msgb_tlv_put(msg, RSL_IE_UPLINK_MEAS, sizeof(ulm), ulm);

	msgb_tv_put(msg, RSL_IE_BS_POWER, meas_tx_power_bs);

	l1i[0] = 0;
	l1i[1] = meas_ta_ms;
	msgb_tv_fixed_put(msg, RSL_IE_L1_INFO, sizeof(l1i), l1i);

	buf = msgb_put(msg, 3);
	buf[0] = RSL_IE_L3_INFO;
	buf[1] = (sizeof(*gh) + sizeof(*mr)) >> 8;
	buf[2] = (sizeof(*gh) + sizeof(*mr)) & 0xff;

	gh = (struct gsm48_hdr *) msgb_put(msg, sizeof(*gh));
	mr = (struct gsm48_meas_res *) msgb_put(msg, sizeof(*mr));

	gh->proto_discr = GSM48_PDISC_RR;
	gh->msg_type = GSM48_MT_RR_MEAS_REP;

	/* measurement results */
	mr->rxlev_full = meas_dl_rxlev;
	mr->rxlev_sub = meas_dl_rxlev;
	mr->rxqual_full = meas_dl_rxqual;
	mr->rxqual_sub = meas_dl_rxqual;
	mr->dtx_used = meas_dtx_ms;
	mr->ba_used = meas_rep_ba;
	mr->meas_valid = !meas_valid; /* 0 = valid */
	if (meas_rep_valid) {
		mr->no_nc_n_hi = meas_num_nc >> 2;
		mr->no_nc_n_lo = meas_num_nc & 3;
	} else {
		/* no results for serving cells */
		mr->no_nc_n_hi = 1;
		mr->no_nc_n_lo = 3;
	}
	mr->rxlev_nc1 = meas_rxlev_nc[0];
	mr->rxlev_nc2_hi = meas_rxlev_nc[1] >> 1;
	mr->rxlev_nc2_lo = meas_rxlev_nc[1] & 1;
	mr->rxlev_nc3_hi = meas_rxlev_nc[2] >> 2;
	mr->rxlev_nc3_lo = meas_rxlev_nc[2] & 3;
	mr->rxlev_nc4_hi = meas_rxlev_nc[3] >> 3;
	mr->rxlev_nc4_lo = meas_rxlev_nc[3] & 7;
	mr->rxlev_nc5_hi = meas_rxlev_nc[4] >> 4;
	mr->rxlev_nc5_lo = meas_rxlev_nc[4] & 15;
	mr->rxlev_nc6_hi = meas_rxlev_nc[5] >> 5;
	mr->rxlev_nc6_lo = meas_rxlev_nc[5] & 31;
	mr->bsic_nc1_hi = meas_bsic_nc[0] >> 3;
	mr->bsic_nc1_lo = meas_bsic_nc[0] & 7;
	mr->bsic_nc2_hi = meas_bsic_nc[1] >> 4;
	mr->bsic_nc2_lo = meas_bsic_nc[1] & 15;
	mr->bsic_nc3_hi = meas_bsic_nc[2] >> 5;
	mr->bsic_nc3_lo = meas_bsic_nc[2] & 31;
	mr->bsic_nc4 = meas_bsic_nc[3];
	mr->bsic_nc5 = meas_bsic_nc[4];
	mr->bsic_nc6 = meas_bsic_nc[5];
	mr->bcch_f_nc1 = meas_bcch_f_nc[0];
	mr->bcch_f_nc2 = meas_bcch_f_nc[1];
	mr->bcch_f_nc3 = meas_bcch_f_nc[2];
	mr->bcch_f_nc4 = meas_bcch_f_nc[3];
	mr->bcch_f_nc5_hi = meas_bcch_f_nc[4] >> 1;
	mr->bcch_f_nc5_lo = meas_bcch_f_nc[4] & 1;
	mr->bcch_f_nc6_hi = meas_bcch_f_nc[5] >> 2;
	mr->bcch_f_nc6_lo = meas_bcch_f_nc[5] & 3;

	msg->dst = lchan->ts->trx->bts->c0->rsl_link;
	msg->l2h = (unsigned char *)dh;
	msg->l3h = (unsigned char *)gh;

	abis_rsl_rcvmsg(msg);
}

/* create bts */
static struct gsm_bts *create_bts(int arfcn)
{
	struct gsm_bts *bts;
	struct e1inp_sign_link *rsl_link;
	int i;

	bts = gsm_bts_alloc_register(bsc_gsmnet, GSM_BTS_TYPE_NANOBTS,
		0x7, 0x3f);
	if (!bts) {
		printf("No resource for bts1\n");
		return NULL;
	}

	bts->location_area_code = 23;
	bts->c0->arfcn = arfcn;

	bts->handover.ho_active = 1;
	bts->handover.as_active = 1;
	bts->handover.min_rxlev = -100;
	bts->handover.win_rxlev_avg = 1;
	bts->handover.win_rxlev_avg_neigh = 1;
	bts->handover.pwr_hysteresis = 3;
	bts->handover.win_rxqual_avg = 1;
	bts->handover.pwr_interval = 1;
	bts->handover.afs_rxlev_improve = 0;
	bts->handover.min_rxqual = 5;
	bts->handover.win_rxqual_avg = 1;
	bts->handover.afs_rxqual_improve = 0;
	bts->handover.max_distance = 9999;
	bts->handover.max_unsync_ho = 9999;
	bts->handover.penalty_max_dist = 300;
	bts->handover.penalty_ho_fail = 60;
	bts->handover.penalty_as_fail = 60;

	bts->codec.efr = 1;
	bts->codec.hr = 1;
	bts->codec.afs = 1;
	bts->codec.ahs = 1;

	rsl_link = talloc_zero(0, struct e1inp_sign_link);
	rsl_link->trx = bts->c0;
	bts->c0->rsl_link = rsl_link;

	bts->c0->mo.nm_state.operational = NM_OPSTATE_ENABLED;
	bts->c0->mo.nm_state.availability = NM_AVSTATE_OK;
	bts->c0->bb_transc.mo.nm_state.operational = NM_OPSTATE_ENABLED;
	bts->c0->bb_transc.mo.nm_state.availability = NM_AVSTATE_OK;

	/* 4 full rate and 4 half rate channels */
	for (i = 1; i <= 6; i++) {
		bts->c0->ts[i].pchan =
			(i < 5) ? GSM_PCHAN_TCH_F : GSM_PCHAN_TCH_H;
		bts->c0->ts[i].mo.nm_state.operational = NM_OPSTATE_ENABLED;
		bts->c0->ts[i].mo.nm_state.availability = NM_AVSTATE_OK;
		bts->c0->ts[i].lchan[0].type = GSM_LCHAN_NONE;
		bts->c0->ts[i].lchan[0].state = LCHAN_S_NONE;
		bts->c0->ts[i].lchan[1].type = GSM_LCHAN_NONE;
		bts->c0->ts[i].lchan[1].state = LCHAN_S_NONE;
	}
	return bts;
}

/* create lchan */
struct gsm_lchan *create_lchan(struct gsm_bts *bts, int full_rate, char *codec)
{
	struct gsm_lchan *lchan;

	lchan = lchan_alloc(bts,
		(full_rate) ? GSM_LCHAN_TCH_F : GSM_LCHAN_TCH_H, 0);
	if (!lchan) {
		printf("No resource for lchan\n");
		exit(EXIT_FAILURE);
	}
	lchan->state = LCHAN_S_ACTIVE;
	lchan->conn = subscr_con_allocate(lchan);
	if (!strcasecmp(codec, "FR") && full_rate)
		lchan->tch_mode = GSM48_CMODE_SPEECH_V1;
	else if (!strcasecmp(codec, "HR") && !full_rate)
		lchan->tch_mode = GSM48_CMODE_SPEECH_V1;
	else if (!strcasecmp(codec, "EFR") && full_rate)
		lchan->tch_mode = GSM48_CMODE_SPEECH_EFR;
	else if (!strcasecmp(codec, "AMR"))
		lchan->tch_mode = GSM48_CMODE_SPEECH_AMR;
	else {
		printf("Given codec unknown\n");
		exit(EXIT_FAILURE);
	}
	lchan->conn->bcap.speech_ver[0] = 0;
	lchan->conn->bcap.speech_ver[1] = 2;
	lchan->conn->bcap.speech_ver[2] = 4;
	lchan->conn->bcap.speech_ver[3] = 1;
	lchan->conn->bcap.speech_ver[4] = 5;
	lchan->conn->bcap.speech_ver[5] = -1;

	return lchan;
}

/* parse channel request */

static int got_chan_req = 0;
static struct gsm_lchan *chan_req_lchan = NULL;

static int parse_chan_act(struct gsm_lchan *lchan, uint8_t *data)
{
	chan_req_lchan = lchan;
	return 0;
}

static int parse_chan_rel(struct gsm_lchan *lchan, uint8_t *data)
{
	chan_req_lchan = lchan;
	return 0;
}

/* parse handover request */

static int got_ho_req = 0;
static struct gsm_lchan *ho_req_lchan = NULL;

static int parse_ho_command(struct gsm_lchan *lchan, uint8_t *data, int len)
{
	struct gsm48_hdr *gh = (struct gsm48_hdr *) data;
	struct gsm48_ho_cmd *ho = (struct gsm48_ho_cmd *) gh->data;
	int arfcn;
	struct gsm_bts *neigh;

	switch (gh->msg_type) {
	case GSM48_MT_RR_HANDO_CMD:
		arfcn = (ho->cell_desc.arfcn_hi << 8) | ho->cell_desc.arfcn_lo;

		/* look up trx. since every dummy bts uses different arfcn and
		 * only one trx, it is simple */
		llist_for_each_entry(neigh, &bsc_gsmnet->bts_list, list) {
			if (neigh->c0->arfcn != arfcn)
				continue;
			ho_req_lchan = lchan;
			return 0;
		}
		break;
	case GSM48_MT_RR_ASS_CMD:
		ho_req_lchan = lchan;
		return 0;
		break;
	default:
		fprintf(stderr, "Error, expecting HO or AS command\n");
		return -EINVAL;
	}

	return -1;
}

/* send channel activation ack */
static void send_chan_act_ack(struct gsm_lchan *lchan, int act)
{
	struct msgb *msg = msgb_alloc_headroom(256, 64, "RSL");
	struct abis_rsl_dchan_hdr *dh;

	dh = (struct abis_rsl_dchan_hdr *) msgb_put(msg, sizeof(*dh));
	dh->c.msg_discr = ABIS_RSL_MDISC_DED_CHAN;
	dh->c.msg_type = (act) ? RSL_MT_CHAN_ACTIV_ACK : RSL_MT_RF_CHAN_REL_ACK;
	dh->ie_chan = RSL_IE_CHAN_NR;
	dh->chan_nr = gsm_lchan2chan_nr(lchan);

	msg->dst = lchan->ts->trx->bts->c0->rsl_link;
	msg->l2h = (unsigned char *)dh;

	abis_rsl_rcvmsg(msg);
}

/* send handover complete */
static void send_ho_complete(struct gsm_lchan *lchan, int comp)
{
	struct msgb *msg = msgb_alloc_headroom(256, 64, "RSL");
	struct abis_rsl_rll_hdr *rh;
	uint8_t chan_nr = gsm_lchan2chan_nr(lchan);
	uint8_t *buf;
	struct gsm48_hdr *gh;
	struct gsm48_ho_cpl *hc;

	rh = (struct abis_rsl_rll_hdr *) msgb_put(msg, sizeof(*rh));
	rh->c.msg_discr = ABIS_RSL_MDISC_RLL;
	rh->c.msg_type = RSL_MT_DATA_IND;
	rh->ie_chan = RSL_IE_CHAN_NR;
	rh->chan_nr = chan_nr;
	rh->ie_link_id = RSL_IE_LINK_IDENT;
	rh->link_id = 0x00;

	buf = msgb_put(msg, 3);
	buf[0] = RSL_IE_L3_INFO;
	buf[1] = (sizeof(*gh) + sizeof(*hc)) >> 8;
	buf[2] = (sizeof(*gh) + sizeof(*hc)) & 0xff;

	gh = (struct gsm48_hdr *) msgb_put(msg, sizeof(*gh));
	hc = (struct gsm48_ho_cpl *) msgb_put(msg, sizeof(*hc));

	gh->proto_discr = GSM48_PDISC_RR;
	gh->msg_type =
		(comp) ? GSM48_MT_RR_HANDO_COMPL : GSM48_MT_RR_HANDO_FAIL;

	msg->dst = lchan->ts->trx->bts->c0->rsl_link;
	msg->l2h = (unsigned char *)rh;
	msg->l3h = (unsigned char *)gh;

	abis_rsl_rcvmsg(msg);
}

/* RSL messages from BSC */
int abis_rsl_sendmsg(struct msgb *msg)
{
	struct abis_rsl_dchan_hdr *dh = (struct abis_rsl_dchan_hdr *) msg->data;
	struct e1inp_sign_link *sign_link = msg->dst;
	struct gsm_lchan *lchan = lchan_lookup(sign_link->trx, dh->chan_nr);
	int rc;

	switch (dh->c.msg_type) {
	case RSL_MT_CHAN_ACTIV:
		rc = parse_chan_act(lchan, dh->data);
		if (rc == 0)
			got_chan_req = 1;
		break;
	case RSL_MT_RF_CHAN_REL:
		rc = parse_chan_rel(lchan, dh->data);
		if (rc == 0)
			send_chan_act_ack(chan_req_lchan, 0);
		break;
	case RSL_MT_DATA_REQ:
		rc = parse_ho_command(lchan, msg->l3h, msgb_l3len(msg));
		if (rc == 0)
			got_ho_req = 1;
		break;
	case RSL_MT_IPAC_CRCX:
		break;
	default:
		printf("unknown rsl message=0x%x\n", dh->c.msg_type);
	}
	return 0;
}

/* test cases */

static char *test_case_0[] = {
	"2",

	"Stay in better cell\n\n"
	"There are many neighbor cells, but only the current cell is the best\n"
	"cell, so no handover is performed\n",

	"create-bts", "7",
	"create-ms", "0", "TCH/F", "AMR",
	"meas-rep", "0", "30","0",
		"6","0","20","1","21","2","18","3","20","4","23","5","19",
	"expect-no-chan",
	NULL
};

static char *test_case_1[] = {
	"2",

	"Handover to best better cell\n\n"
	"The best neighbor cell is selected\n",

	"create-bts", "7",
	"create-ms", "0", "TCH/F", "AMR",
	"meas-rep", "0", "10","0",
		"6","0","20","1","21","2","18","3","20","4","23","5","19",
	"expect-chan", "5", "1",
	"ack-chan",
	"expect-ho", "0", "1",
	"ho-complete",
	NULL
};

static char *test_case_2[] = {
	"2",

	"Handover and Assignment must be enabled\n\n"
	"This test will start with disabled assignment and handover.  A\n"
	"better neighbor cell (assignment enabled) will not be selected and \n"
	"also no assignment from TCH/H to TCH/F to improve quality. There\n"
	"will be no handover nor assignment. After enabling assignment on the\n"
	"current cell, the MS will assign to TCH/F. After enabling handover\n"
	"in the current cell, but disabling in the neighbor cell, handover\n"
	"will not performed until it is enabled in the neighbor cell too.\n",

	"create-bts", "2",
	"afs-rxlev-improve", "0", "5",
	"create-ms", "0", "TCH/H", "AMR",
	"as-enable", "0", "0",
	"ho-enable", "0", "0",
	"meas-rep", "0", "0","0", "1","0","30",
	"expect-no-chan",
	"as-enable", "0", "1",
	"meas-rep", "0", "0","0", "1","0","30",
	"expect-chan", "0", "1",
	"ack-chan",
	"expect-ho", "0", "5",
	"ho-complete",
	"ho-enable", "0", "1",
	"ho-enable", "1", "0",
	"meas-rep", "0", "0","0", "1","0","30",
	"expect-no-chan",
	"ho-enable", "1", "1",
	"meas-rep", "0", "0","0", "1","0","30",
	"expect-chan", "1", "1",
	"ack-chan",
	"expect-ho", "0", "1",
	"ho-complete",
	NULL
};

static char *test_case_3[] = {
	"2",

	"Penalty timer must not run\n\n"
	"The MS will try to handover to a better cell, but this will fail.\n"
	"Even though the cell is still better, handover will not be performed\n"
	"due to penalty timer after handover failure\n",

	"create-bts", "2",
	"create-ms", "0", "TCH/F", "AMR",
	"meas-rep", "0", "20","0", "1","0","30",
	"expect-chan", "1", "1",
	"ack-chan",
	"expect-ho", "0", "1",
	"ho-failed",
	"meas-rep", "0", "20","0", "1","0","30",
	"expect-no-chan",
	NULL
};

static char *test_case_4[] = {
	"2",

	"TCH/H keeping with HR codec\n\n"
	"The MS is using half rate V1 codec, but the better cell is congested\n"
	"at TCH/H slots. As the congestion is removed, the handover takes\n"
	"place.\n",

	"create-bts", "2",
	"set-min-free", "1", "TCH/H", "4",
	"create-ms", "0", "TCH/H", "HR",
	"meas-rep", "0", "20","0", "1","0","30",
	"expect-no-chan",
	"set-min-free", "1", "TCH/H", "3",
	"meas-rep", "0", "20","0", "1","0","30",
	"expect-chan", "1", "5",
	"ack-chan",
	"expect-ho", "0", "5",
	"ho-complete",
	NULL
};

static char *test_case_5[] = {
	"2",

	"TCH/F keeping with FR codec\n\n"
	"The MS is using full rate V1 codec, but the better cell is congested\n"
	"at TCH/F slots. As the congestion is removed, the handover takes\n"
	"place.\n",

	"create-bts", "2",
	"set-min-free", "1", "TCH/F", "4",
	"create-ms", "0", "TCH/F", "FR",
	"meas-rep", "0", "20","0", "1","0","30",
	"expect-no-chan",
	"set-min-free", "1", "TCH/F", "3",
	"meas-rep", "0", "20","0", "1","0","30",
	"expect-chan", "1", "1",
	"ack-chan",
	"expect-ho", "0", "1",
	"ho-complete",
	NULL
};

static char *test_case_6[] = {
	"2",

	"TCH/F keeping with EFR codec\n\n"
	"The MS is using full rate V2 codec, but the better cell is congested\n"
	"at TCH/F slots. As the congestion is removed, the handover takes\n"
	"place.\n",

	"create-bts", "2",
	"set-min-free", "1", "TCH/F", "4",
	"create-ms", "0", "TCH/F", "EFR",
	"meas-rep", "0", "20","0", "1","0","30",
	"expect-no-chan",
	"set-min-free", "1", "TCH/F", "3",
	"meas-rep", "0", "20","0", "1","0","30",
	"expect-chan", "1", "1",
	"ack-chan",
	"expect-ho", "0", "1",
	"ho-complete",
	NULL
};

static char *test_case_7[] = {
	"2",

	"TCH/F to TCH/H changing with AMR codec\n\n"
	"The MS is using AMR V3 codec, the better cell is congested at TCH/F\n"
	"slots. The handover is performed to non-congested TCH/H slots.\n",

	"create-bts", "2",
	"set-min-free", "1", "TCH/F", "4",
	"create-ms", "0", "TCH/F", "AMR",
	"meas-rep", "0", "20","0", "1","0","30",
	"expect-chan", "1", "5",
	"ack-chan",
	"expect-ho", "0", "1",
	"ho-complete",
	NULL
};

static char *test_case_8[] = {
	"2",

	"No handover to a cell with no slots available\n\n"
	"If no slot is available, no handover is performed\n",

	"create-bts", "2",
	"create-ms", "0", "TCH/F", "AMR",
	"create-ms", "1", "TCH/F", "AMR",
	"create-ms", "1", "TCH/F", "AMR",
	"create-ms", "1", "TCH/F", "AMR",
	"create-ms", "1", "TCH/F", "AMR",
	"create-ms", "1", "TCH/H", "AMR",
	"create-ms", "1", "TCH/H", "AMR",
	"create-ms", "1", "TCH/H", "AMR",
	"create-ms", "1", "TCH/H", "AMR",
	"meas-rep", "0", "0","0", "1","0","30",
	"expect-no-chan",
	NULL
};

static char *test_case_9[] = {
	"2",

	"No more parallel handovers, if max_unsync_ho is defined\n\n"
	"There are tree mobiles that want to handover, but only two can do\n"
	"it at a time, because the maximum number is limited to two.\n",

	"create-bts", "2",
	"set-max-ho", "1", "2",
	"create-ms", "0", "TCH/F", "AMR",
	"create-ms", "0", "TCH/F", "AMR",
	"create-ms", "0", "TCH/F", "AMR",
	"meas-rep", "0", "0","0", "1","0","30",
	"expect-chan", "1", "1",
	"meas-rep", "1", "0","0", "1","0","30",
	"expect-chan", "1", "2",
	"meas-rep", "2", "0","0", "1","0","30",
	"expect-no-chan",
	NULL
};

static char *test_case_10[] = {
	"2",

	"Hysteresis\n\n"
	"If neighbor cell is better, handover is only performed if the\n"
	"ammount of improvement is greater or equal hyteresis\n",

	"create-bts", "2",
	"create-ms", "0", "TCH/F", "AMR",
	"meas-rep", "0", "27","0", "1","0","30",
	"expect-no-chan",
	"meas-rep", "0", "26","0", "1","0","30",
	"expect-chan", "1", "1",
	"ack-chan",
	"expect-ho", "0", "1",
	"ho-complete",
	NULL
};

static char *test_case_11[] = {
	"2",

	"No Hysteresis and minimum RX level\n\n"
	"If current cell's RX level is below mimium level, handover must be\n"
	"performed, no matter of the hysteresis. First do not perform\n"
	"handover to better neighbor cell, because the hysteresis is not\n"
	"met. Second do not perform handover because better neighbor cell is\n"
	"below minimum RX level. Third perform handover because current cell\n"
	"is below minimum RX level, even if the better neighbor cell (minimum\n"
	"RX level reached) does not meet the hysteresis.\n",

	"create-bts", "2",
	"create-ms", "0", "TCH/F", "AMR",
	"meas-rep", "0", "10","0", "1","0","11",
	"expect-no-chan",
	"meas-rep", "0", "8","0", "1","0","9",
	"expect-no-chan",
	"meas-rep", "0", "9","0", "1","0","10",
	"expect-chan", "1", "1",
	"ack-chan",
	"expect-ho", "0", "1",
	"ho-complete",
	NULL
};

static char *test_case_12[] = {
	"2",

	"No handover to congested cell\n\n"
	"The better neighbor cell is congested, so no handover is performed.\n"
	"After the congestion is over, handover will be performed.\n",

	"create-bts", "2",
	"create-ms", "0", "TCH/F", "AMR",
	"set-min-free", "1", "TCH/F", "4",
	"set-min-free", "1", "TCH/H", "4",
	"meas-rep", "0", "20","0", "1","0","30",
	"expect-no-chan",
	"set-min-free", "1", "TCH/F", "3",
	"set-min-free", "1", "TCH/H", "3",
	"meas-rep", "0", "20","0", "1","0","30",
	"expect-chan", "1", "1",
	"ack-chan",
	"expect-ho", "0", "1",
	"ho-complete",
	NULL
};

static char *test_case_13[] = {
	"2",

	"Handover to balance congestion\n\n"
	"The current and the better cell are congested, so no handover is\n"
	"performed. This is because handover would congest the neighbor cell\n"
	"more. After congestion raises in the current cell, the handover is\n"
	"performed to balance congestion\n",

	"create-bts", "2",
	"create-ms", "0", "TCH/F", "AMR",
	"set-min-free", "0", "TCH/F", "4",
	"set-min-free", "0", "TCH/H", "4",
	"set-min-free", "1", "TCH/F", "4",
	"set-min-free", "1", "TCH/H", "4",
	"meas-rep", "0", "20","0", "1","0","30",
	"expect-no-chan",
	"create-ms", "0", "TCH/F", "AMR",
	"meas-rep", "0", "20","0", "1","0","30",
	"expect-chan", "1", "1",
	"ack-chan",
	"expect-ho", "0", "1",
	"ho-complete",
	NULL
};

static char *test_case_14[] = {
	"2",

	"Handover to congested cell, if RX level is below minimum\n\n"
	"The better neighbor cell is congested, so no handover is performed.\n"
	"If the RX level of the current cell drops below minimum acceptable\n"
	"level, the handover is performed.\n",

	"create-bts", "2",
	"create-ms", "0", "TCH/F", "AMR",
	"set-min-free", "1", "TCH/F", "4",
	"set-min-free", "1", "TCH/H", "4",
	"meas-rep", "0", "10","0", "1","0","30",
	"expect-no-chan",
	"create-ms", "0", "TCH/F", "AMR",
	"meas-rep", "0", "9","0", "1","0","30",
	"expect-chan", "1", "1",
	"ack-chan",
	"expect-ho", "0", "1",
	"ho-complete",
	NULL
};

static char *test_case_15[] = {
	"2",

	"Handover to congested cell, if RX quality is below minimum\n\n"
	"The better neighbor cell is congested, so no handover is performed.\n"
	"If the RX quality of the current cell drops below minimum acceptable\n"
	"level, the handover is performed. It is also required that 10\n"
	"resports are received, before RX quality is checked.\n",

	"create-bts", "2",
	"create-ms", "0", "TCH/F", "AMR",
	"set-min-free", "1", "TCH/F", "4",
	"set-min-free", "1", "TCH/H", "4",
	"meas-rep", "0", "40","5", "1","0","30",
	"expect-no-chan",
	"meas-rep", "0", "40","5", "1","0","30",
	"expect-no-chan",
	"meas-rep", "0", "40","5", "1","0","30",
	"expect-no-chan",
	"meas-rep", "0", "40","5", "1","0","30",
	"expect-no-chan",
	"meas-rep", "0", "40","5", "1","0","30",
	"expect-no-chan",
	"meas-rep", "0", "40","5", "1","0","30",
	"expect-no-chan",
	"meas-rep", "0", "40","5", "1","0","30",
	"expect-no-chan",
	"meas-rep", "0", "40","5", "1","0","30",
	"expect-no-chan",
	"meas-rep", "0", "40","5", "1","0","30",
	"expect-no-chan",
	"meas-rep", "0", "40","5", "1","0","30",
	"expect-no-chan",
	"create-ms", "0", "TCH/F", "AMR",
	"meas-rep", "0", "40","6", "1","0","30",
	"expect-chan", "1", "1",
	"ack-chan",
	"expect-ho", "0", "1",
	"ho-complete",
	NULL
};

static char *test_case_16[] = {
	"2",

	"Handover due to maximum TA exceeded\n\n"
	"The MS in the current (best) cell has reached maximum allowed timing\n"
	"advance. No handover is performed until the timing advance exceeds\n"
	"it. The originating cell is still the best, but no handover is\n"
	"performed back to that cell, because the penalty timer (due to\n"
	"maximum allowed timing advance) is running.\n",

	"create-bts", "2",
	"create-ms", "0", "TCH/F", "AMR",
	"set-max-ta", "0", "5", /* of cell */
	"set-ta", "0", "5", /* of ms */
	"meas-rep", "0", "30","0", "1","0","20",
	"expect-no-chan",
	"set-ta", "0", "6", /* of ms */
	"meas-rep", "0", "30","0", "1","0","20",
	"expect-chan", "1", "1",
	"ack-chan",
	"expect-ho", "0", "1",
	"ho-complete",
	"meas-rep", "0", "20","0", "1","0","30",
	"expect-no-chan",
	NULL
};

static char *test_case_17[] = {
	"2",

	"Congestion check: No congestion\n\n"
	"Three cells have different number of used slots, but there is no\n"
	"congestion in any of these cells. No handover is performed.\n",

	"create-bts", "3",
	"set-min-free", "0", "TCH/F", "2",
	"set-min-free", "0", "TCH/H", "2",
	"set-min-free", "1", "TCH/F", "2",
	"set-min-free", "1", "TCH/H", "2",
	"set-min-free", "2", "TCH/F", "2",
	"set-min-free", "2", "TCH/H", "2",
	"create-ms", "0", "TCH/F", "AMR",
	"create-ms", "0", "TCH/F", "AMR",
	"create-ms", "0", "TCH/H", "AMR",
	"create-ms", "0", "TCH/H", "AMR",
	"create-ms", "1", "TCH/F", "AMR",
	"create-ms", "1", "TCH/H", "AMR",
	"meas-rep", "0", "30","0", "2","0","20","1","20",
	"expect-no-chan",
	"meas-rep", "1", "30","0", "2","0","20","1","20",
	"expect-no-chan",
	"meas-rep", "2", "30","0", "2","0","20","1","20",
	"expect-no-chan",
	"meas-rep", "3", "30","0", "2","0","20","1","20",
	"expect-no-chan",
	"meas-rep", "4", "30","0", "2","0","20","1","20",
	"expect-no-chan",
	"meas-rep", "5", "30","0", "2","0","20","1","20",
	"expect-no-chan",
	"congestion-check",
	"expect-no-chan",
	NULL
};

static char *test_case_18[] = {
	"2",

	"Congestion check: One out of three cells is congested\n\n"
	"Three cells have different number of used slots, but there is\n"
	"congestion at TCH/F in the first cell. Handover is performed with\n"
	"the best candidate.\n",

	"create-bts", "3",
	"set-min-free", "0", "TCH/F", "2",
	"set-min-free", "0", "TCH/H", "2",
	"set-min-free", "1", "TCH/F", "2",
	"set-min-free", "1", "TCH/H", "2",
	"set-min-free", "2", "TCH/F", "2",
	"set-min-free", "2", "TCH/H", "2",
	"create-ms", "0", "TCH/F", "AMR",
	"create-ms", "0", "TCH/F", "AMR",
	"create-ms", "0", "TCH/F", "AMR",
	"create-ms", "0", "TCH/H", "AMR",
	"create-ms", "0", "TCH/H", "AMR",
	"create-ms", "1", "TCH/F", "AMR",
	"create-ms", "1", "TCH/H", "AMR",
	"meas-rep", "0", "30","0", "2","0","20","1","20",
	"expect-no-chan",
	"meas-rep", "1", "30","0", "2","0","20","1","20",
	"expect-no-chan",
	"meas-rep", "2", "30","0", "2","0","21","1","20",
	"expect-no-chan",
	"meas-rep", "3", "30","0", "2","0","20","1","20",
	"expect-no-chan",
	"meas-rep", "4", "30","0", "2","0","20","1","20",
	"expect-no-chan",
	"meas-rep", "5", "30","0", "2","0","20","1","20",
	"expect-no-chan",
	"meas-rep", "6", "30","0", "2","0","20","1","20",
	"expect-no-chan",
	"congestion-check",
	"expect-chan", "1", "2",
	"ack-chan",
	"expect-ho", "0", "3", /* best candidate is MS 2 at BTS 1, TS 3 */
	"ho-complete",
	NULL
};

static char *test_case_19[] = {
	"2",

	"Congestion check: Balancing over congested cells\n\n"
	"Two cells are congested, but the second cell is more congested.\n"
	"Handover is performed to solve the congestion.\n",

	"create-bts", "2",
	"set-min-free", "0", "TCH/F", "4",
	"set-min-free", "1", "TCH/F", "4",
	"create-ms", "0", "TCH/F", "FR",
	"create-ms", "0", "TCH/F", "FR",
	"create-ms", "0", "TCH/F", "FR",
	"create-ms", "1", "TCH/F", "FR",
	"meas-rep", "0", "30","0", "1","0","20",
	"expect-no-chan",
	"meas-rep", "1", "30","0", "1","0","21",
	"expect-no-chan",
	"meas-rep", "2", "30","0", "1","0","20",
	"expect-no-chan",
	"meas-rep", "3", "30","0", "1","0","20",
	"expect-no-chan",
	"congestion-check",
	"expect-chan", "1", "2",
	"ack-chan",
	"expect-ho", "0", "2", /* best candidate is MS 1 at BTS 0, TS 2 */
	"ho-complete",
	NULL
};

static char *test_case_20[] = {
	"2",

	"Congestion check: Solving congestion by handover TCH/F -> TCH/H\n\n"
	"Two BTS, one MS in the first congested BTS must handover to\n"
	"non-congested TCH/H of second BTS, in order to solve congestion\n",
	"create-bts", "2",
	"set-min-free", "0", "TCH/F", "4",
	"set-min-free", "0", "TCH/H", "4",
	"set-min-free", "1", "TCH/F", "4",
	"create-ms", "0", "TCH/F", "AMR",
	"meas-rep", "0", "30","0", "1","0","30",
	"expect-no-chan",
	"congestion-check",
	"expect-chan", "1", "5",
	"ack-chan",
	"expect-ho", "0", "1",
	"ho-complete",
	NULL
};

static char *test_case_21[] = {
	"2",

	"Congestion check: Balancing congestion by handover TCH/F -> TCH/H\n\n"
	"Two BTS, one MS in the first congested BTS must handover to\n"
	"less-congested TCH/H of second BTS, in order to balance congestion\n",
	"create-bts", "2",
	"set-min-free", "0", "TCH/F", "4",
	"set-min-free", "0", "TCH/H", "4",
	"set-min-free", "1", "TCH/F", "4",
	"set-min-free", "1", "TCH/H", "4",
	"create-ms", "0", "TCH/F", "AMR",
	"create-ms", "0", "TCH/F", "AMR",
	"create-ms", "0", "TCH/H", "AMR",
	"meas-rep", "0", "30","0", "1","0","30",
	"expect-no-chan",
	"congestion-check",
	"expect-chan", "1", "1",
	"ack-chan",
	"expect-ho", "0", "1",
	"ho-complete",
	NULL
};

static char *test_case_22[] = {
	"2",

	"Congestion check: Upgrading worst candidate from TCH/H -> TCH/F\n\n"
	"There is only one BTS. The TCH/H slots are congested. Since\n"
	"assignment is performed to less-congested TCH/F, the candidate with\n"
	"the worst RX level is chosen.\n",

	"create-bts", "1",
	"set-min-free", "0", "TCH/F", "4",
	"set-min-free", "0", "TCH/H", "4",
	"create-ms", "0", "TCH/H", "AMR",
	"create-ms", "0", "TCH/H", "AMR",
	"create-ms", "0", "TCH/H", "AMR",
	"meas-rep", "0", "30","0", "0",
	"meas-rep", "1", "34","0", "0",
	"meas-rep", "2", "20","0", "0",
	"expect-no-chan",
	"congestion-check",
	"expect-chan", "0", "1",
	"ack-chan",
	"expect-ho", "0", "6",
	"ho-complete",
	NULL
};

static char *test_case_23[] = {
	"2",

	"Story: 'A neighbor is your friend'\n",

	"create-bts", "3",

	"print",
	"Andreas is driving along the coast, on a sunny june afternoon.\n"
	"Suddenly he is getting a call from his friend and neighbor Axel.\n"
	"\n"
	"What happens: Two MS are created, #0 for Axel, #1 for Andreas.",
	/* Axel */
	"create-ms", "2", "TCH/F", "AMR",
	/* andreas */
	"create-ms", "0", "TCH/F", "AMR",
	"meas-rep", "1", "40","0", "1","0","30",
	"expect-no-chan",

	"print",
	"Axel asks Andreas if he would like to join them for a barbecue.\n"
	"Axel's house is right in the neighborhood and the weather is fine.\n"
	"Andreas agrees, so he drives to a close store to buy some barbecue\n"
	"skewers.\n"
	"\n"
	"What happens: While driving, a different cell (mounted atop the\n"
	"store) becomes better.",
	/* drive to bts 1 */
	"meas-rep", "1", "20","0", "1","0","35",
	"expect-chan", "1", "1",
	"ack-chan",
	"expect-ho", "0", "1",
	"ho-complete",

	"print",
	"While Andreas is walking into the store, Axel asks, if he could also\n"
	"bring some beer. Andreas has problems understanding him: \"I have a\n"
	"bad reception here. The cell tower is right atop the store, but poor\n"
	"coverage inside. Can you repeat please?\"\n"
	"\n"
	"What happens: Inside the store the close cell is so bad, that\n"
	"handover back to the previous cell is required.",
	/* bts 1 becomes bad, so bts 0 helps out */
	"meas-rep", "1", "5","0", "1","0","20",
	"expect-chan", "0", "1",
	"ack-chan",
	"expect-ho", "1", "1",
	"ho-complete",

	"print",
	"After Andreas bought skewers and beer, he leaves the store.\n"
	"\n"
	"What happens: Outside the store the close cell is better again, so\n"
	"handover back to the that cell is performed.",
	/* bts 1 becomes better again */
	"meas-rep", "1", "20","0", "1","0","35",
	"expect-chan", "1", "1",
	"ack-chan",
	"expect-ho", "0", "1",
	"ho-complete",

	"print",
	/* bts 2 becomes better */
	"Andreas drives down to the lake where Axel's house is.\n"
	"\n"
	"What happens: There is a small cell at Axel's house, which becomes\n"
	"better, because the current cell has no good comverage at the lake.",
	"meas-rep", "1", "14","0", "2","0","2","1","63",
	"expect-chan", "2", "2",
	"ack-chan",
	"expect-ho", "1", "1",
	"ho-complete",

	"print",
	"Andreas wonders why he still has good radio coverage: \"Last time it\n"
	"was so bad\". Axel sais: \"I installed a pico cell in my house,\n"
	"now we can use our mobile phones down here at the lake.\"",

	NULL
};

static char *test_case_24[] = {
	"2",
	"No (or not enough) measurements for handover\n\n"
	"Do not solve congestion in cell, because there is no measurement\n"
	"As soon as enough measurments available (1 in our case), perform\n"
	"handover. Afterwards the old cell becomes congested and the new\n"
	"cell is not. Do not perform handover until new measurements are\n"
	"received.\n",

	/* two cells, first in congested, but no handover */
	"create-bts", "2",
	"set-min-free", "0", "TCH/F", "4",
	"set-min-free", "0", "TCH/H", "4",
	"create-ms", "0", "TCH/F", "AMR",
	"congestion-check",
	"expect-no-chan",

	/* send measurement and trigger congestion check */
	"meas-rep", "0", "20","0", "1","0","20",
	"expect-no-chan",
	"congestion-check",
	"expect-chan", "1", "1",
	"ack-chan",
	"expect-ho", "0", "1",
	"ho-complete",

	/* congest the first cell and remove congestion from second cell */
	"set-min-free", "0", "TCH/F", "0",
	"set-min-free", "0", "TCH/H", "0",
	"set-min-free", "1", "TCH/F", "4",
	"set-min-free", "1", "TCH/H", "4",

	/* no handover until measurements applied */
	"congestion-check",
	"expect-no-chan",
	"meas-rep", "0", "20","0", "1","0","20",
	"expect-no-chan",
	"congestion-check",
	"expect-chan", "0", "1",
	"ack-chan",
	"expect-ho", "1", "1",
	"ho-complete",
	NULL
};

static char *test_case_25[] = {
	"1",

	"Stay in better cell\n\n"
	"There are many neighbor cells, but only the current cell is the best\n"
	"cell, so no handover is performed\n",

	"create-bts", "7",
	"create-ms", "0", "TCH/F", "AMR",
	"meas-rep", "0", "30","0",
		"6","0","20","1","21","2","18","3","20","4","23","5","19",
	"expect-no-chan",
	NULL
};

static char *test_case_26[] = {
	"1",

	"Handover to best better cell\n\n"
	"The best neighbor cell is selected\n",

	"create-bts", "7",
	"create-ms", "0", "TCH/F", "AMR",
	"meas-rep", "0", "10","0",
		"6","0","20","1","21","2","18","3","20","4","23","5","19",
	"expect-chan", "5", "1",
	"ack-chan",
	"expect-ho", "0", "1",
	"ho-complete",
	NULL
};

static char **test_cases[] =  {
	test_case_0,
	test_case_1,
	test_case_2,
	test_case_3,
	test_case_4,
	test_case_5,
	test_case_6,
	test_case_7,
	test_case_8,
	test_case_9,
	test_case_10,
	test_case_11,
	test_case_12,
	test_case_13,
	test_case_14,
	test_case_15,
	test_case_16,
	test_case_17,
	test_case_18,
	test_case_19,
	test_case_20,
	test_case_21,
	test_case_22,
	test_case_23,
	test_case_24,
	test_case_25,
	test_case_26,
	NULL
};


int main(int argc, char **argv)
{
	char **test_case;
	struct gsm_bts *bts[256];
	int bts_num = 0;
	struct gsm_lchan *lchan[256];
	int lchan_num = 0;
	int test_count = 0;
	int i;
	int algorithm;

	for (i = 0; test_cases[i]; i++)
		test_count++;

	if (argc <= 1 || atoi(argv[1]) >= test_count) {
		for (i = 0; test_cases[i]; i++) {
			printf("Test #%d (algorithm %s):\n%s\n", i,
				test_cases[i][0], test_cases[i][1]);
		}
		printf("\nPlease specify test case number 0..%d\n",
			test_count - 1);
		return EXIT_FAILURE;
	}

	osmo_init_logging(&log_info);
	osmo_stderr_target->categories[DHO].loglevel = LOGL_DEBUG;
	osmo_stderr_target->categories[DHODEC].loglevel = LOGL_DEBUG;
	osmo_stderr_target->categories[DHODEC].enabled = 1;
#if 0
	osmo_stderr_target->categories[DMEAS].loglevel = LOGL_DEBUG;
	osmo_stderr_target->categories[DMEAS].enabled = 1;
#endif

	/* Create a dummy network */
	bsc_gsmnet = gsm_network_init(1, 1, NULL);
	if (!bsc_gsmnet)
		exit(1);

	bts_model_nanobts_init();

	test_case = test_cases[atoi(argv[1])];

	fprintf(stderr, "--------------------\n");
	fprintf(stderr, "Performing the following test %d (algorithm %s):\n%s",
		atoi(argv[1]), test_case[0], test_case[1]);
	algorithm = atoi(test_case[0]);
	test_case += 2;
	fprintf(stderr, "--------------------\n");

	/* load handover support */
	switch (algorithm) {
	case 1:
		init_ho_1();
		break;
	case 2:
		init_ho_2();
		break;
	}

	while (*test_case) {
		if (!strcmp(*test_case, "create-bts")) {
			static int arfcn = 870;
			int n = atoi(test_case[1]);
			fprintf(stderr, "- Creating %d BTS (one TRX each, "
				"TS(1-4) are TCH/F, TS(5-6) are TCH/H)\n", n);
			for (i = 0; i < n; i++)
				bts[bts_num + i] = create_bts(arfcn++);
			for (i = 0; i < n; i++)
				gsm_generate_si(bts[bts_num + i],
					SYSINFO_TYPE_2);
			bts_num += n;
			test_case += 2;
		} else
		if (!strcmp(*test_case, "as-enable")) {
			fprintf(stderr, "- Set assignment enable state at "
				"BTS %s to %s\n", test_case[1], test_case[2]);
			bts[atoi(test_case[1])]->handover.as_active =
				atoi(test_case[2]);
			test_case += 3;
		} else
		if (!strcmp(*test_case, "ho-enable")) {
			fprintf(stderr, "- Set handover enable state at "
				"BTS %s to %s\n", test_case[1], test_case[2]);
			bts[atoi(test_case[1])]->handover.ho_active =
				atoi(test_case[2]);
			test_case += 3;
		} else
		if (!strcmp(*test_case, "afs-rxlev-improve")) {
			fprintf(stderr, "- Set afs RX level improvement at "
				"BTS %s to %s\n", test_case[1], test_case[2]);
			bts[atoi(test_case[1])]->handover.afs_rxlev_improve =
				atoi(test_case[2]);
			test_case += 3;
		} else
		if (!strcmp(*test_case, "afs-rxqual-improve")) {
			fprintf(stderr, "- Set afs RX quality improvement at "
				"BTS %s to %s\n", test_case[1], test_case[2]);
			bts[atoi(test_case[1])]->handover.afs_rxqual_improve =
				atoi(test_case[2]);
			test_case += 3;
		} else
		if (!strcmp(*test_case, "set-min-free")) {
			fprintf(stderr, "- Setting minimum required free %s "
				"slots at BTS %s to %s\n", test_case[2],
				test_case[1], test_case[3]);
			if (!strcmp(test_case[2], "TCH/F"))
				bts[atoi(test_case[1])]->handover.min_free_tchf
					= atoi(test_case[3]);
			else
				bts[atoi(test_case[1])]->handover.min_free_tchh
					= atoi(test_case[3]);
			test_case += 4;
		} else
		if (!strcmp(*test_case, "set-max-ho")) {
			fprintf(stderr, "- Setting maximum parallel handovers "
				"at BTS %s to %s\n", test_case[1],
				test_case[2]);
			bts[atoi(test_case[1])]->handover.max_unsync_ho
				= atoi(test_case[2]);
			test_case += 3;
		} else
		if (!strcmp(*test_case, "set-max-ta")) {
			fprintf(stderr, "- Setting maximum timing advance "
				"at BTS %s to %s\n", test_case[1],
				test_case[2]);
			bts[atoi(test_case[1])]->handover.max_distance
				= atoi(test_case[2]);
			test_case += 3;
		} else
		if (!strcmp(*test_case, "create-ms")) {
			fprintf(stderr, "- Creating mobile #%d at BTS %s on "
				"%s with %s codec\n", lchan_num, test_case[1],
				test_case[2], test_case[3]);
			lchan[lchan_num] = create_lchan(bts[atoi(test_case[1])],
				!strcmp(test_case[2], "TCH/F"), test_case[3]);
			if (!lchan[lchan_num]) {
				printf("Failed to create lchan!\n");
				return EXIT_FAILURE;
			}
			fprintf(stderr, " * New MS is at BTS %d TS %d\n",
				lchan[lchan_num]->ts->trx->bts->nr,
				lchan[lchan_num]->ts->nr);
			lchan_num++;
			test_case += 4;
		} else
		if (!strcmp(*test_case, "set-ta")) {
			fprintf(stderr, "- Setting maximum timing advance "
				"at MS %s to %s\n", test_case[1],
				test_case[2]);
			meas_ta_ms = atoi(test_case[2]);
			test_case += 3;
		} else
		if (!strcmp(*test_case, "meas-rep")) {
			int n = atoi(test_case[4]);
			struct gsm_lchan *lc = lchan[atoi(test_case[1])];
			fprintf(stderr, "- Sending measurement report from "
				"mobile #%s (rxlev=%s, rxqual=%s)\n",
				test_case[1], test_case[2], test_case[3]);
			meas_dl_rxlev = atoi(test_case[2]);
			meas_dl_rxqual = atoi(test_case[3]);
			meas_num_nc = n;
			test_case += 5;
			for (i = 0; i < n; i++) {
				int nr = atoi(test_case[0]);
				/* since our bts is not in the list of neighbor
				 * cells, we need to shift */
				if (nr >= lc->ts->trx->bts->nr)
					nr++;
				fprintf(stderr, " * Neighbor cell #%s, actual "
					"BTS %d (rxlev=%s)\n", test_case[0], nr,
					test_case[1]);
				meas_bcch_f_nc[i] = atoi(test_case[0]);
					/* bts number, not counting our own */
				meas_rxlev_nc[i] = atoi(test_case[1]);
				meas_bsic_nc[i] = 0x3f;
				test_case += 2;
			}
			got_chan_req = 0;
			gen_meas_rep(lc);
		} else
		if (!strcmp(*test_case, "congestion-check")) {
			fprintf(stderr, "- Triggering congestion check\n");
			got_chan_req = 0;
			if (algorithm == 2)
				congestion_check_2(NULL);
			test_case += 1;
		} else
		if (!strcmp(*test_case, "expect-chan")) {
			fprintf(stderr, "- Expecting channel request at BTS %s "
				"TS %s\n", test_case[1], test_case[2]);
			if (!got_chan_req) {
				printf("Test failed, because no channel was "
					"requested\n");
				return EXIT_FAILURE;
			}
			fprintf(stderr, " * Got channel request at BTS %d "
				"TS %d\n", chan_req_lchan->ts->trx->bts->nr,
				chan_req_lchan->ts->nr);
			if (chan_req_lchan->ts->trx->bts->nr
						!= atoi(test_case[1])) {
				printf("Test failed, because channel was not "
					"requested on expected BTS\n");
				return EXIT_FAILURE;
			}
			if (chan_req_lchan->ts->nr != atoi(test_case[2])) {
				printf("Test failed, because channel was not "
					"requested on expected TS\n");
				return EXIT_FAILURE;
			}
			test_case += 3;
		} else
		if (!strcmp(*test_case, "expect-no-chan")) {
			fprintf(stderr, "- Expecting no channel request\n");
			if (got_chan_req) {
				fprintf(stderr, " * Got channel request at "
					"BTS %d TS %d\n",
					chan_req_lchan->ts->trx->bts->nr,
					chan_req_lchan->ts->nr);
				printf("Test failed, because channel was "
					"requested\n");
				return EXIT_FAILURE;
			}
			fprintf(stderr, " * Got no channel request\n");
			test_case += 1;
		} else
		if (!strcmp(*test_case, "expect-ho")) {
			fprintf(stderr, "- Expecting handover/assignment "
				"request at BTS %s TS %s\n", test_case[1],
				test_case[2]);
			if (!got_ho_req) {
				printf("Test failed, because no handover was "
					"requested\n");
				return EXIT_FAILURE;
			}
			fprintf(stderr, " * Got handover/assignment request at "
				"BTS %d TS %d\n",
				ho_req_lchan->ts->trx->bts->nr,
				ho_req_lchan->ts->nr);
			if (ho_req_lchan->ts->trx->bts->nr
							!= atoi(test_case[1])) {
				printf("Test failed, because "
					"handover/assignment was not commanded "
					"at the expected BTS\n");
				return EXIT_FAILURE;
			}
			if (ho_req_lchan->ts->nr != atoi(test_case[2])) {
				printf("Test failed, because "
					"handover/assignment was not commanded "
					"at the expected TS\n");
				return EXIT_FAILURE;
			}
			test_case += 3;
		} else
		if (!strcmp(*test_case, "ack-chan")) {
			fprintf(stderr, "- Acknowledging channel request\n");
			if (!got_chan_req) {
				printf("Cannot ack channel, because no "
					"request\n");
				return EXIT_FAILURE;
			}
			test_case += 1;
			got_ho_req = 0;
			send_chan_act_ack(chan_req_lchan, 1);
		} else
		if (!strcmp(*test_case, "ho-complete")) {
			fprintf(stderr, "- Acknowledging handover/assignment "
				"request\n");
			if (!got_chan_req) {
				printf("Cannot ack handover/assignment, "
					"because no chan request\n");
				return EXIT_FAILURE;
			}
			if (!got_ho_req) {
				printf("Cannot ack handover/assignment, "
					"because no ho request\n");
				return EXIT_FAILURE;
			}
			test_case += 1;
			got_chan_req = 0;
			got_ho_req = 0;
			/* switch lchan */
			for (i = 0; i < lchan_num; i++) {
				if (lchan[i] == ho_req_lchan) {
					fprintf(stderr, " * MS %d changes from "
						"BTS=%d TS=%d to BTS=%d "
						"TS=%d\n", i,
						lchan[i]->ts->trx->bts->nr,
						lchan[i]->ts->nr,
					       chan_req_lchan->ts->trx->bts->nr,
						chan_req_lchan->ts->nr);
					lchan[i] = chan_req_lchan;
				}
			}
			send_ho_complete(chan_req_lchan, 1);
		} else
		if (!strcmp(*test_case, "ho-failed")) {
			fprintf(stderr, "- Making handover fail\n");
			if (!got_chan_req) {
				printf("Cannot fail handover, because no chan "
					"request\n");
				return EXIT_FAILURE;
			}
			test_case += 1;
			got_chan_req = 0;
			got_ho_req = 0;
			send_ho_complete(ho_req_lchan, 0);
		} else
		if (!strcmp(*test_case, "print")) {
			fprintf(stderr, "\n%s\n\n", test_case[1]);
			test_case += 2;
		} else {
			printf("Unknown test command '%s', please fix!\n",
				*test_case);
			return EXIT_FAILURE;
		}
	}

	fprintf(stderr, "--------------------\n");

	printf("Test OK\n");

	fprintf(stderr, "--------------------\n");

	return EXIT_SUCCESS;
}

void rtp_socket_free() {}
void rtp_send_frame() {}
void rtp_socket_upstream() {}
void rtp_socket_create() {}
void rtp_socket_connect() {}
void rtp_socket_proxy() {}
void trau_mux_unmap() {}
void trau_mux_map_lchan() {}
void trau_recv_lchan() {}
void trau_send_frame() {}
