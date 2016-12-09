/* pcu_sock.c: Connect from PCU via unix domain socket */

/* (C) 2008-2010 by Harald Welte <laforge@gnumonks.org>
 * (C) 2009-2012 by Andreas Eversberg <jolly@eversberg.eu>
 * (C) 2012 by Holger Hans Peter Freyther
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

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <assert.h>
#include <sys/socket.h>
#include <sys/un.h>

#include <osmocom/core/talloc.h>
#include <osmocom/core/select.h>
#include <osmocom/core/socket.h>
#include <osmocom/core/logging.h>
#include <osmocom/gsm/l1sap.h>
#include <osmocom/gsm/gsm0502.h>

#include <openbsc/gsm_data.h>
#include <openbsc/pcu_if.h>
#include <openbsc/pcuif_proto.h>
#include <openbsc/signal.h>
#include <openbsc/debug.h>
#include <openbsc/abis_rsl.h>

static int pcu_sock_send(struct gsm_bts *bts, struct msgb *msg);
uint32_t trx_get_hlayer1(struct gsm_bts_trx *trx);
int pcu_direct = 1;

static const char *sapi_string[] = {
	[PCU_IF_SAPI_RACH] =	"RACH",
	[PCU_IF_SAPI_AGCH] =	"AGCH",
	[PCU_IF_SAPI_PCH] =	"PCH",
	[PCU_IF_SAPI_BCCH] =	"BCCH",
	[PCU_IF_SAPI_PDTCH] =	"PDTCH",
	[PCU_IF_SAPI_PRACH] =	"PRACH",
	[PCU_IF_SAPI_PTCCH] = 	"PTCCH",
	[PCU_IF_SAPI_AGCH_DT] = 	"AGCH_DT",
};

/* Check if BTS has a PCU connection */
static bool pcu_connected(struct gsm_bts *bts)
{
	struct pcu_sock_state *state = bts->pcu_state;

	if (!state)
		return false;
	if (state->conn_bfd.fd <= 0)
		return false;
	return true;
}

/*
 * PCU messages
 */

/* Set up an message buffer to package an pcu interface message */
struct msgb *pcu_msgb_alloc(uint8_t msg_type, uint8_t bts_nr)
{
	struct msgb *msg;
	struct gsm_pcu_if *pcu_prim;

	msg = msgb_alloc(sizeof(struct gsm_pcu_if), "pcu_sock_tx");
	if (!msg)
		return NULL;
	
	msgb_put(msg, sizeof(struct gsm_pcu_if));
	pcu_prim = (struct gsm_pcu_if *) msg->data;
	pcu_prim->msg_type = msg_type; 
	pcu_prim->bts_nr = bts_nr; 

	return msg;
}

/* Helper function exclusivly used by pcu_if_signal_cb() */
static bool ts_should_be_pdch(struct gsm_bts_trx_ts *ts) {
	if (ts->pchan == GSM_PCHAN_PDCH)
		return true;
	if (ts->pchan == GSM_PCHAN_TCH_F_PDCH) {
		/* When we're busy deactivating the PDCH, we first set
		 * DEACT_PENDING, tell the PCU about it and wait for a
		 * response. So DEACT_PENDING means "no PDCH" to the PCU.
		 * Similarly, when we're activating PDCH, we set the
		 * ACT_PENDING and wait for an activation response from the
		 * PCU, so ACT_PENDING means "is PDCH". */
		if (ts->flags & TS_F_PDCH_ACTIVE)
			return !(ts->flags & TS_F_PDCH_DEACT_PENDING);
		else
			return (ts->flags & TS_F_PDCH_ACT_PENDING);
	}
	if (ts->pchan == GSM_PCHAN_TCH_F_TCH_H_PDCH) {
		/*
		 * When we're busy de-/activating the PDCH, we first set
		 * ts->dyn.pchan_want, tell the PCU about it and wait for a
		 * response. So only care about dyn.pchan_want here.
		 */
		return ts->dyn.pchan_want == GSM_PCHAN_PDCH;
	}
	return false;
}

/* Send BTS properties to the PCU */
static int pcu_tx_info_ind(struct gsm_bts *bts)
{
	struct msgb *msg;
	struct gsm_pcu_if *pcu_prim;
	struct gsm_pcu_if_info_ind *info_ind;
	struct gprs_rlc_cfg *rlcc;
	struct gsm_bts_gprs_nsvc *nsvc;
	struct gsm_bts_trx *trx;
	struct gsm_bts_trx_ts *ts;
	int i, j;

	OSMO_ASSERT(bts);
	OSMO_ASSERT(bts->network);

	LOGP(DPCU, LOGL_INFO, "Sending info for BTS %d\n",bts->nr);

	rlcc = &bts->gprs.cell.rlc_cfg;

	msg = pcu_msgb_alloc(PCU_IF_MSG_INFO_IND, bts->nr);
	if (!msg)
		return -ENOMEM;

	pcu_prim = (struct gsm_pcu_if *) msg->data;
	info_ind = &pcu_prim->u.info_ind;
	info_ind->version = PCU_IF_VERSION;
	info_ind->flags |= PCU_IF_FLAG_ACTIVE;

	if (pcu_direct)
		info_ind->flags |= PCU_IF_FLAG_SYSMO;

	/* RAI */
	info_ind->mcc = bts->network->country_code;
	info_ind->mnc = bts->network->network_code;
	info_ind->lac = bts->location_area_code;
	info_ind->rac = bts->gprs.rac;

	/* NSE */
	info_ind->nsei = bts->gprs.nse.nsei;
	memcpy(info_ind->nse_timer, bts->gprs.nse.timer, 7);
	memcpy(info_ind->cell_timer, bts->gprs.cell.timer, 11);

	/* cell attributes */
	info_ind->cell_id = bts->cell_identity;
	info_ind->repeat_time = rlcc->paging.repeat_time;
	info_ind->repeat_count = rlcc->paging.repeat_count;
	info_ind->bvci = bts->gprs.cell.bvci;
	info_ind->t3142 = rlcc->parameter[RLC_T3142];
	info_ind->t3169 = rlcc->parameter[RLC_T3169];
	info_ind->t3191 = rlcc->parameter[RLC_T3191];
	info_ind->t3193_10ms = rlcc->parameter[RLC_T3193];
	info_ind->t3195 = rlcc->parameter[RLC_T3195];
	info_ind->n3101 = rlcc->parameter[RLC_N3101];
	info_ind->n3103 = rlcc->parameter[RLC_N3103];
	info_ind->n3105 = rlcc->parameter[RLC_N3105];
	info_ind->cv_countdown = rlcc->parameter[CV_COUNTDOWN];
	if (rlcc->cs_mask & (1 << GPRS_CS1))
		info_ind->flags |= PCU_IF_FLAG_CS1;
	if (rlcc->cs_mask & (1 << GPRS_CS2))
		info_ind->flags |= PCU_IF_FLAG_CS2;
	if (rlcc->cs_mask & (1 << GPRS_CS3))
		info_ind->flags |= PCU_IF_FLAG_CS3;
	if (rlcc->cs_mask & (1 << GPRS_CS4))
		info_ind->flags |= PCU_IF_FLAG_CS4;
	if (rlcc->cs_mask & (1 << GPRS_MCS1))
		info_ind->flags |= PCU_IF_FLAG_MCS1;
	if (rlcc->cs_mask & (1 << GPRS_MCS2))
		info_ind->flags |= PCU_IF_FLAG_MCS2;
	if (rlcc->cs_mask & (1 << GPRS_MCS3))
		info_ind->flags |= PCU_IF_FLAG_MCS3;
	if (rlcc->cs_mask & (1 << GPRS_MCS4))
		info_ind->flags |= PCU_IF_FLAG_MCS4;
	if (rlcc->cs_mask & (1 << GPRS_MCS5))
		info_ind->flags |= PCU_IF_FLAG_MCS5;
	if (rlcc->cs_mask & (1 << GPRS_MCS6))
		info_ind->flags |= PCU_IF_FLAG_MCS6;
	if (rlcc->cs_mask & (1 << GPRS_MCS7))
		info_ind->flags |= PCU_IF_FLAG_MCS7;
	if (rlcc->cs_mask & (1 << GPRS_MCS8))
		info_ind->flags |= PCU_IF_FLAG_MCS8;
	if (rlcc->cs_mask & (1 << GPRS_MCS9))
		info_ind->flags |= PCU_IF_FLAG_MCS9;
#warning	"isn't dl_tbf_ext wrong?: * 10 and no ntohs"
	info_ind->dl_tbf_ext = rlcc->parameter[T_DL_TBF_EXT];
#warning	"isn't ul_tbf_ext wrong?: * 10 and no ntohs"
	info_ind->ul_tbf_ext = rlcc->parameter[T_UL_TBF_EXT];
	info_ind->initial_cs = rlcc->initial_cs;
	info_ind->initial_mcs = rlcc->initial_mcs;

	/* NSVC */
	for (i = 0; i < ARRAY_SIZE(info_ind->nsvci); i++) {
		nsvc = &bts->gprs.nsvc[i];
		info_ind->nsvci[i] = nsvc->nsvci;
		info_ind->local_port[i] = nsvc->local_port;
		info_ind->remote_port[i] = nsvc->remote_port;
		info_ind->remote_ip[i] = nsvc->remote_ip;
	}

	for (i = 0; i < ARRAY_SIZE(info_ind->trx); i++) {
		trx = gsm_bts_trx_num(bts, i);
		if (!trx)
			continue;
		info_ind->trx[i].hlayer1 = 0x2342;
		info_ind->trx[i].pdch_mask = 0;
		info_ind->trx[i].arfcn = trx->arfcn;
		for (j = 0; j < ARRAY_SIZE(trx->ts); j++) {
			ts = &trx->ts[j];
			if (ts->mo.nm_state.operational == NM_OPSTATE_ENABLED
			    && ts_should_be_pdch(ts)) {
				info_ind->trx[i].pdch_mask |= (1 << j);
				info_ind->trx[i].tsc[j] =
					(ts->tsc >= 0) ? ts->tsc : bts->bsic & 7;
				LOGP(DPCU, LOGL_INFO, "trx=%d ts=%d: "
					"available (tsc=%d arfcn=%d)\n",
					trx->nr, ts->nr,
					info_ind->trx[i].tsc[j],
					info_ind->trx[i].arfcn);
			}
		}
	}

	return pcu_sock_send(bts, msg);
}

void pcu_info_update(struct gsm_bts *bts)
{
	if (pcu_connected(bts))
		pcu_tx_info_ind(bts);
}

int pcu_tx_data_ind(struct gsm_bts *bts, struct gsm_bts_trx_ts *ts, uint8_t is_ptcch, uint32_t fn,
	uint16_t arfcn, uint8_t block_nr, uint8_t *data, uint8_t len,
	int8_t rssi, uint16_t ber10k, int16_t bto, int16_t lqual)
{
	struct msgb *msg;
	struct gsm_pcu_if *pcu_prim;
	struct gsm_pcu_if_data *data_ind;

	LOGP(DPCU, LOGL_DEBUG, "Sending data indication: is_ptcch=%d arfcn=%d "
		"block=%d data=%s\n", is_ptcch, arfcn, block_nr,
		osmo_hexdump(data, len));

	msg = pcu_msgb_alloc(PCU_IF_MSG_DATA_IND, bts->nr);
	if (!msg)
		return -ENOMEM;
	pcu_prim = (struct gsm_pcu_if *) msg->data;
	data_ind = &pcu_prim->u.data_ind;

	data_ind->sapi = (is_ptcch) ? PCU_IF_SAPI_PTCCH : PCU_IF_SAPI_PDTCH;
	data_ind->rssi = rssi;
	data_ind->fn = fn;
	data_ind->arfcn = arfcn;
	data_ind->trx_nr = ts->trx->nr;
	data_ind->ts_nr = ts->nr;
	data_ind->block_nr = block_nr;
	data_ind->rssi = rssi;
	data_ind->ber10k = ber10k;
	data_ind->ta_offs_qbits = bto;
	data_ind->lqual_cb = lqual;
	memcpy(data_ind->data, data, len);
	data_ind->len = len;

	return pcu_sock_send(bts, msg);
}

/* Forward rach indication to PCU */
int pcu_tx_rach_ind(struct gsm_bts *bts, int16_t qta, uint16_t ra, uint32_t fn,
	uint8_t is_11bit, enum ph_burst_type burst_type)
{
	struct msgb *msg;
	struct gsm_pcu_if *pcu_prim;
	struct gsm_pcu_if_rach_ind *rach_ind;

	/* Bail if no PCU is connected */
	if (!pcu_connected(bts)) {
		LOGP(DRSL, LOGL_ERROR, "BTS %d CHAN RQD(GPRS) but PCU not "
			"connected!\n", bts->nr);
		return -ENODEV;
	}

	LOGP(DPCU, LOGL_INFO, "Sending RACH indication: qta=%d, ra=%d, "
		"fn=%d\n", qta, ra, fn);

	msg = pcu_msgb_alloc(PCU_IF_MSG_RACH_IND, bts->nr);
	if (!msg)
		return -ENOMEM;
	pcu_prim = (struct gsm_pcu_if *) msg->data;
	rach_ind = &pcu_prim->u.rach_ind;

	rach_ind->sapi = PCU_IF_SAPI_RACH;
	rach_ind->ra = ra;
	rach_ind->qta = qta;
	rach_ind->fn = fn;
	rach_ind->is_11bit = is_11bit;
	rach_ind->burst_type = burst_type;

	return pcu_sock_send(bts, msg);
}

int pcu_tx_time_ind(struct gsm_bts *bts, uint32_t fn)
{
	struct msgb *msg;
	struct gsm_pcu_if *pcu_prim;
	struct gsm_pcu_if_time_ind *time_ind;
	uint8_t fn13 = fn % 13;

	/* omit frame numbers not starting at a MAC block */
	if (fn13 != 0 && fn13 != 4 && fn13 != 8)
		return 0;

	msg = pcu_msgb_alloc(PCU_IF_MSG_TIME_IND, 0);
	if (!msg)
		return -ENOMEM;
	pcu_prim = (struct gsm_pcu_if *) msg->data;
	time_ind = &pcu_prim->u.time_ind;

	time_ind->fn = fn;

	return pcu_sock_send(bts, msg);
}

/* Forward paging information to PCU */
int pcu_tx_pag_req(struct gsm_bts *bts, const uint8_t *identity_lv,
		   uint8_t chan_needed)
{
	struct pcu_sock_state *state = bts->pcu_state;
	struct msgb *msg;
	struct gsm_pcu_if *pcu_prim;
	struct gsm_pcu_if_pag_req *pag_req;

	/* check if identity does not fit: length > sizeof(lv) - 1 */
	if (identity_lv[0] >= sizeof(pag_req->identity_lv)) {
		LOGP(DPCU, LOGL_ERROR, "Paging identity too large (%d)\n",
			identity_lv[0]);
		return -EINVAL;
	}

	/* socket not created */
	if (!state) {
		LOGP(DPCU, LOGL_DEBUG, "PCU socket not created, ignoring "
			"paging message\n");
		return 0;
	}

	msg = pcu_msgb_alloc(PCU_IF_MSG_PAG_REQ, 0);
	if (!msg)
		return -ENOMEM;
	pcu_prim = (struct gsm_pcu_if *) msg->data;
	pag_req = &pcu_prim->u.pag_req;

	pag_req->chan_needed = chan_needed;
	memcpy(pag_req->identity_lv, identity_lv, identity_lv[0] + 1);

	return pcu_sock_send(bts, msg);
}

int pcu_tx_pch_data_cnf(struct gsm_bts *bts, uint32_t fn, uint8_t *data, uint8_t len)
{
	struct msgb *msg;
	struct gsm_pcu_if *pcu_prim;
	struct gsm_pcu_if_data *data_cnf;

	LOGP(DPCU, LOGL_INFO, "Sending PCH confirm\n");

	msg = pcu_msgb_alloc(PCU_IF_MSG_DATA_CNF, bts->nr);
	if (!msg)
		return -ENOMEM;
	pcu_prim = (struct gsm_pcu_if *) msg->data;
	data_cnf = &pcu_prim->u.data_cnf;

	data_cnf->sapi = PCU_IF_SAPI_PCH;
	data_cnf->fn = fn;
	memcpy(data_cnf->data, data, len);
	data_cnf->len = len;

	return pcu_sock_send(bts, msg);
}

/* Confirm the sending of an immediate assignment to the pcu */
int pcu_tx_imm_ass_sent(struct gsm_bts *bts, uint32_t tlli)
{
	struct msgb *msg;
	struct gsm_pcu_if *pcu_prim;
	struct gsm_pcu_if_data_cnf_dt *data_cnf_dt;

	LOGP(DPCU, LOGL_INFO, "Sending PCH confirm with direct TLLI\n");

	msg = pcu_msgb_alloc(PCU_IF_MSG_DATA_CNF_DT, bts->nr);
	if (!msg)
		return -ENOMEM;
	pcu_prim = (struct gsm_pcu_if *) msg->data;
	data_cnf_dt = &pcu_prim->u.data_cnf_dt;

	data_cnf_dt->sapi = PCU_IF_SAPI_PCH;
	data_cnf_dt->tlli = tlli;

	return pcu_sock_send(bts, msg);
}

/* we need to decode the raw RR paging messsage (see PCU code
 * Encoding::write_paging_request) and extract the mobile identity
 * (P-TMSI) from it */
static int pcu_rx_rr_paging(struct gsm_bts *bts, uint8_t paging_group,
			    const uint8_t *raw_rr_msg)
{
	struct gsm48_hdr *gsmh = (struct gsm48_hdr *) raw_rr_msg;
	struct gsm48_paging1 *p1 = (struct gsm48_paging1 *) gsmh;
	uint8_t chan_needed;
	unsigned int mi_len;
	uint8_t *mi;
	int rc;

	switch (gsmh->msg_type) {
	case GSM48_MT_RR_PAG_REQ_1:
		chan_needed = (p1->cneed2 << 2) | p1->cneed1;
		mi_len = p1->data[0];
		mi = p1->data+1;
		/* FIXME: why does rsl_paging_cmd add 2 to mi? */
		rc = rsl_paging_cmd(bts, paging_group, mi_len, mi,
				    chan_needed, true);
		break;
	case GSM48_MT_RR_PAG_REQ_2:
	case GSM48_MT_RR_PAG_REQ_3:
		LOGP(DPCU, LOGL_ERROR, "PCU Sends unsupported paging "
			"request type\n");
		rc = -EINVAL;
		break;
	}

	return rc;
}

static int pcu_rx_data_req(struct gsm_bts *bts, uint8_t msg_type,
	struct gsm_pcu_if_data *data_req)
{
	uint8_t is_ptcch;
	struct gsm_bts_trx *trx;
	struct gsm_bts_trx_ts *ts;
	struct msgb *msg;
	char imsi_digit_buf[4];
	uint32_t tlli = -1;
	uint8_t pag_grp;
	int rc = 0;

	LOGP(DPCU, LOGL_DEBUG, "Data request received: sapi=%s arfcn=%d "
		"block=%d data=%s\n", sapi_string[data_req->sapi],
		data_req->arfcn, data_req->block_nr,
		osmo_hexdump(data_req->data, data_req->len));

	switch (data_req->sapi) {
	case PCU_IF_SAPI_BCCH:
		if (data_req->len == 23) {
			bts->si_valid |= (1 << SYSINFO_TYPE_13);
			memcpy(bts->si_buf[SYSINFO_TYPE_13], data_req->data,
				data_req->len);
		} else {
			bts->si_valid &= ~(1 << SYSINFO_TYPE_13);
		}
	//	osmo_signal_dispatch(SS_GLOBAL, S_NEW_SYSINFO, bts);
		break;
	case PCU_IF_SAPI_PCH:
		/* the first three bytes are the last three digits of
		 * the IMSI, which we need to compute the paging group */
		imsi_digit_buf[0] = data_req->data[0];
		imsi_digit_buf[1] = data_req->data[1];
		imsi_digit_buf[2] = data_req->data[2];
		imsi_digit_buf[3] = '\0';
		LOGP(DPCU, LOGL_DEBUG, "SAPI PCH imsi %s", imsi_digit_buf);
		pag_grp = gsm0502_calc_paging_group(&bts->si_common.chan_desc,
						str_to_imsi(imsi_digit_buf));
		pcu_rx_rr_paging(bts, pag_grp, data_req->data+3);
		break;
	case PCU_IF_SAPI_AGCH:
		msg = msgb_alloc(data_req->len, "pcu_agch");
		if (!msg) {
			rc = -ENOMEM;
			break;
		}
		msg->l3h = msgb_put(msg, data_req->len);
		memcpy(msg->l3h, data_req->data, data_req->len);

		if (rsl_imm_assign_cmd(bts, msg->len, msg->data)) {
			msgb_free(msg);
			rc = -EIO;
		}
		break;
	case PCU_IF_SAPI_AGCH_DT:
		/* DT = direct tlli. A tlli is prefixed */

		if (data_req->len < 5) {
			LOGP(DPCU, LOGL_ERROR, "Received PCU data request with "
					"invalid/small length %d\n", data_req->len);
			break;
		}
		tlli = *((uint32_t *)data_req->data);

		msg = msgb_alloc(data_req->len - 4, "pcu_agch");
		if (!msg) {
			rc = -ENOMEM;
			break;
		}
		msg->l3h = msgb_put(msg, data_req->len - 4);
		memcpy(msg->l3h, data_req->data + 4, data_req->len - 4);

		if (bts->type == GSM_BTS_TYPE_RBS2000)
			rc = rsl_ericsson_imm_assign_cmd(bts, tlli, msg->len, msg->data);
		else
			rc = rsl_imm_assign_cmd(bts, msg->len, msg->data);

		if (rc) {
			msgb_free(msg);
			rc = -EIO;
		}
		break;

	case PCU_IF_SAPI_PDTCH:
	case PCU_IF_SAPI_PTCCH:
		trx = gsm_bts_trx_num(bts, data_req->trx_nr);
		if (!trx) {
			LOGP(DPCU, LOGL_ERROR, "Received PCU data request with "
				"not existing TRX %d\n", data_req->trx_nr);
			rc = -EINVAL;
			break;
		}
		ts = &trx->ts[data_req->ts_nr];
		is_ptcch = (data_req->sapi == PCU_IF_SAPI_PTCCH);
		printf("rc = l1sap_pdch_req(ts, is_ptcch, data_req->fn, data_req->arfcn,data_req->block_nr, data_req->data, data_req->len);\n");
		rc = -EINVAL;
		break;
	default:
		LOGP(DPCU, LOGL_ERROR, "Received PCU data request with "
			"unsupported sapi %d\n", data_req->sapi);
		rc = -EINVAL;
	}

	return rc;
}

static int pcu_rx_act_req(struct gsm_bts *bts, struct gsm_pcu_if_act_req *act_req)
{
	struct gsm_bts_trx *trx;
	struct gsm_lchan *lchan;

	LOGP(DPCU, LOGL_INFO, "%s request received: TRX=%d TX=%d\n", 
		(act_req->activate) ? "Activate" : "Deactivate",
		act_req->trx_nr, act_req->ts_nr);

	trx = gsm_bts_trx_num(bts, act_req->trx_nr);
	if (!trx || act_req->ts_nr >= 8)
		return -EINVAL;

	lchan = trx->ts[act_req->ts_nr].lchan;
//	lchan->rel_act_kind = LCHAN_REL_ACT_PCU;
	if (lchan->type != GSM_LCHAN_PDTCH) {
		LOGP(DPCU, LOGL_ERROR,
		     "%s request, but lchan is not of type PDTCH (is %s)\n",
		     (act_req->activate) ? "Activate" : "Deactivate",
		     gsm_lchant_name(lchan->type));
		return -EINVAL;
	}
	if (act_req->activate)
		printf("l1sap_chan_act(trx, gsm_lchan2chan_nr(lchan), NULL);\n");
	else
		printf("l1sap_chan_rel(trx, gsm_lchan2chan_nr(lchan));\n");

	return 0;
}

static int pcu_rx(struct gsm_network *net, uint8_t msg_type,
	struct gsm_pcu_if *pcu_prim)
{
	int rc = 0;
	struct gsm_bts *bts;

	/* FIXME: allow multiple BTS */
	bts = llist_entry(net->bts_list.next, struct gsm_bts, list);

	switch (msg_type) {
	case PCU_IF_MSG_DATA_REQ:
	case PCU_IF_MSG_PAG_REQ:
		rc = pcu_rx_data_req(bts, msg_type, &pcu_prim->u.data_req);
		break;
	case PCU_IF_MSG_ACT_REQ:
		rc = pcu_rx_act_req(bts, &pcu_prim->u.act_req);
		break;
	default:
		LOGP(DPCU, LOGL_ERROR, "Received unknwon PCU msg type %d\n",
			msg_type);
		rc = -EINVAL;
	}

	return rc;
}

/*
 * PCU socket interface
 */

static int pcu_sock_send(struct gsm_bts *bts, struct msgb *msg)
{
	struct pcu_sock_state *state = bts->pcu_state;
	struct osmo_fd *conn_bfd;
	struct gsm_pcu_if *pcu_prim = (struct gsm_pcu_if *) msg->data;

	if (!state) {
		if (pcu_prim->msg_type != PCU_IF_MSG_TIME_IND)
			LOGP(DPCU, LOGL_INFO, "PCU socket not created, "
				"dropping message\n");
		msgb_free(msg);
		return -EINVAL;
	}
	conn_bfd = &state->conn_bfd;
	if (conn_bfd->fd <= 0) {
		if (pcu_prim->msg_type != PCU_IF_MSG_TIME_IND)
			LOGP(DPCU, LOGL_NOTICE, "PCU socket not connected, "
				"dropping message\n");
		msgb_free(msg);
		return -EIO;
	}
	msgb_enqueue(&state->upqueue, msg);
	conn_bfd->when |= BSC_FD_WRITE;

	return 0;
}

static void pcu_sock_close(struct pcu_sock_state *state)
{
	struct osmo_fd *bfd = &state->conn_bfd;
	struct gsm_bts *bts;
	struct gsm_bts_trx *trx;
	struct gsm_bts_trx_ts *ts;
	int i, j;

	/* FIXME: allow multiple BTS */
	bts = llist_entry(state->net->bts_list.next, struct gsm_bts, list);

	LOGP(DPCU, LOGL_NOTICE, "PCU socket has LOST connection\n");

	close(bfd->fd);
	bfd->fd = -1;
	osmo_fd_unregister(bfd);

	/* re-enable the generation of ACCEPT for new connections */
	state->listen_bfd.when |= BSC_FD_READ;

#if 0
	/* remove si13, ... */
	bts->si_valid &= ~(1 << SYSINFO_TYPE_13);
	osmo_signal_dispatch(SS_GLOBAL, S_NEW_SYSINFO, bts);
#endif

	/* release PDCH */
	for (i = 0; i < 8; i++) {
		trx = gsm_bts_trx_num(bts, i);
		if (!trx)
			break;
		for (j = 0; j < 8; j++) {
			ts = &trx->ts[j];
			if (ts->mo.nm_state.operational == NM_OPSTATE_ENABLED
			 && ts->pchan == GSM_PCHAN_PDCH) {
//				ts->lchan->rel_act_kind = LCHAN_REL_ACT_PCU;
				printf("l1sap_chan_rel(trx,gsm_lchan2chan_nr(ts->lchan));\n");
			}
		}
	}

	/* flush the queue */
	while (!llist_empty(&state->upqueue)) {
		struct msgb *msg = msgb_dequeue(&state->upqueue);
		msgb_free(msg);
	}
}

static int pcu_sock_read(struct osmo_fd *bfd)
{
	struct pcu_sock_state *state = (struct pcu_sock_state *)bfd->data;
	struct gsm_pcu_if *pcu_prim;
	struct msgb *msg;
	int rc;

	msg = msgb_alloc(sizeof(*pcu_prim), "pcu_sock_rx");
	if (!msg)
		return -ENOMEM;

	pcu_prim = (struct gsm_pcu_if *) msg->tail;

	rc = recv(bfd->fd, msg->tail, msgb_tailroom(msg), 0);
	if (rc == 0)
		goto close;

	if (rc < 0) {
		if (errno == EAGAIN)
			return 0;
		goto close;
	}

	rc = pcu_rx(state->net, pcu_prim->msg_type, pcu_prim);

	/* as we always synchronously process the message in pcu_rx() and
	 * its callbacks, we can free the message here. */
	msgb_free(msg);

	return rc;

close:
	msgb_free(msg);
	pcu_sock_close(state);
	return -1;
}

static int pcu_sock_write(struct osmo_fd *bfd)
{
	struct pcu_sock_state *state = bfd->data;
	int rc;

	while (!llist_empty(&state->upqueue)) {
		struct msgb *msg, *msg2;
		struct gsm_pcu_if *pcu_prim;

		/* peek at the beginning of the queue */
		msg = llist_entry(state->upqueue.next, struct msgb, list);
		pcu_prim = (struct gsm_pcu_if *)msg->data;

		bfd->when &= ~BSC_FD_WRITE;

		/* bug hunter 8-): maybe someone forgot msgb_put(...) ? */
		if (!msgb_length(msg)) {
			LOGP(DPCU, LOGL_ERROR, "message type (%d) with ZERO "
				"bytes!\n", pcu_prim->msg_type);
			goto dontsend;
		}

		/* try to send it over the socket */
		rc = write(bfd->fd, msgb_data(msg), msgb_length(msg));
		if (rc == 0)
			goto close;
		if (rc < 0) {
			if (errno == EAGAIN) {
				bfd->when |= BSC_FD_WRITE;
				break;
			}
			goto close;
		}

dontsend:
		/* _after_ we send it, we can deueue */
		msg2 = msgb_dequeue(&state->upqueue);
		assert(msg == msg2);
		msgb_free(msg);
	}
	return 0;

close:
	pcu_sock_close(state);

	return -1;
}

static int pcu_sock_cb(struct osmo_fd *bfd, unsigned int flags)
{
	int rc = 0;

	if (flags & BSC_FD_READ)
		rc = pcu_sock_read(bfd);
	if (rc < 0)
		return rc;

	if (flags & BSC_FD_WRITE)
		rc = pcu_sock_write(bfd);

	return rc;
}

/* accept connection comming from PCU */
static int pcu_sock_accept(struct osmo_fd *bfd, unsigned int flags)
{
	struct pcu_sock_state *state = (struct pcu_sock_state *)bfd->data;
	struct osmo_fd *conn_bfd = &state->conn_bfd;
	struct sockaddr_un un_addr;
	socklen_t len;
	int rc;

	len = sizeof(un_addr);
	rc = accept(bfd->fd, (struct sockaddr *) &un_addr, &len);
	if (rc < 0) {
		LOGP(DPCU, LOGL_ERROR, "Failed to accept a new connection\n");
		return -1;
	}

	if (conn_bfd->fd >= 0) {
		LOGP(DPCU, LOGL_NOTICE, "PCU connects but we already have "
			"another active connection ?!?\n");
		/* We already have one PCU connected, this is all we support */
		state->listen_bfd.when &= ~BSC_FD_READ;
		close(rc);
		return 0;
	}

	conn_bfd->fd = rc;
	conn_bfd->when = BSC_FD_READ;
	conn_bfd->cb = pcu_sock_cb;
	conn_bfd->data = state;

	if (osmo_fd_register(conn_bfd) != 0) {
		LOGP(DPCU, LOGL_ERROR, "Failed to register new connection "
			"fd\n");
		close(conn_bfd->fd);
		conn_bfd->fd = -1;
		return -1;
	}

	LOGP(DPCU, LOGL_NOTICE, "PCU socket connected to external PCU\n");

	return 0;
}

/* Open connection to PCU */
int pcu_sock_init(const char *path, struct gsm_bts *bts)
{
	struct pcu_sock_state *state;
	struct osmo_fd *bfd;
	int rc;

	state = talloc_zero(NULL, struct pcu_sock_state);
	if (!state)
		return -ENOMEM;

	INIT_LLIST_HEAD(&state->upqueue);
	state->net = bts->network;
	state->conn_bfd.fd = -1;

	bfd = &state->listen_bfd;

	bfd->fd = osmo_sock_unix_init(SOCK_SEQPACKET, 0, path,
		OSMO_SOCK_F_BIND);
	if (bfd->fd < 0) {
		LOGP(DPCU, LOGL_ERROR, "Could not create unix socket: %s\n",
			strerror(errno));
		talloc_free(state);
		return -1;
	}

	bfd->when = BSC_FD_READ;
	bfd->cb = pcu_sock_accept;
	bfd->data = state;

	rc = osmo_fd_register(bfd);
	if (rc < 0) {
		LOGP(DPCU, LOGL_ERROR, "Could not register listen fd: %d\n",
			rc);
		close(bfd->fd);
		talloc_free(state);
		return rc;
	}

	bts->pcu_state = state;
	return 0;
}

/* Close connection to PCU */
void pcu_sock_exit(struct gsm_bts *bts)
{
	struct pcu_sock_state *state = bts->pcu_state;
	struct osmo_fd *bfd, *conn_bfd;

	if (!state)
		return;

	conn_bfd = &state->conn_bfd;
	if (conn_bfd->fd > 0)
		pcu_sock_close(state);
	bfd = &state->listen_bfd;
	close(bfd->fd);
	osmo_fd_unregister(bfd);
	talloc_free(state);
	bts->pcu_state = NULL;
}

