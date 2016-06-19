/* Handover Logic for Inter-BTS (Intra-BSC) Handover.  This does not
 * actually implement the handover algorithm/decision, but executes a
 * handover decision */

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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <netinet/in.h>

#include <osmocom/core/msgb.h>
#include <openbsc/debug.h>
#include <openbsc/gsm_data.h>
#include <osmocom/gsm/gsm_utils.h>
#include <openbsc/gsm_subscriber.h>
#include <openbsc/gsm_04_08.h>
#include <openbsc/abis_rsl.h>
#include <openbsc/chan_alloc.h>
#include <openbsc/signal.h>
#include <osmocom/core/talloc.h>
#include <openbsc/transaction.h>
#include <openbsc/trau_mux.h>
#include <openbsc/vlr.h>

struct bsc_handover {
	struct llist_head list;

	struct gsm_lchan *old_lchan;
	struct gsm_lchan *new_lchan;

	struct osmo_timer_list T3103;

	uint8_t ho_ref;
};

static LLIST_HEAD(bsc_handovers);

static void handover_free(struct bsc_handover *ho)
{
	osmo_timer_del(&ho->T3103);
	llist_del(&ho->list);
	talloc_free(ho);
}

static struct bsc_handover *bsc_ho_by_new_lchan(struct gsm_lchan *new_lchan)
{
	struct bsc_handover *ho;

	llist_for_each_entry(ho, &bsc_handovers, list) {
		if (ho->new_lchan == new_lchan)
			return ho;
	}

	return NULL;
}

static struct bsc_handover *bsc_ho_by_old_lchan(struct gsm_lchan *old_lchan)
{
	struct bsc_handover *ho;

	llist_for_each_entry(ho, &bsc_handovers, list) {
		if (ho->old_lchan == old_lchan)
			return ho;
	}

	return NULL;
}

/*! \brief Hand over the specified logical channel to the specified new BTS.
 * This is the main entry point for the actual handover algorithm, after the
 * decision whether to initiate HO to a specific BTS. */
int bsc_handover_start(struct gsm_lchan *old_lchan, struct gsm_bts *bts)
{
	struct gsm_lchan *new_lchan;
	struct bsc_handover *ho;
	static uint8_t ho_ref;
	int rc;

	/* don't attempt multiple handovers for the same lchan at
	 * the same time */
	if (bsc_ho_by_old_lchan(old_lchan))
		return -EBUSY;

	DEBUGP(DHO, "(old_lchan on BTS %u, new BTS %u)\n",
		old_lchan->ts->trx->bts->nr, bts->nr);

	rate_ctr_inc(&bts->network->bsc_ctrs->ctr[BSC_CTR_HANDOVER_ATTEMPTED]);

	if (!old_lchan->conn) {
		LOGP(DHO, LOGL_ERROR, "Old lchan lacks connection data.\n");
		return -ENOSPC;
	}

	new_lchan = lchan_alloc(bts, old_lchan->type, 0);
	if (!new_lchan) {
		LOGP(DHO, LOGL_NOTICE, "No free channel\n");
		rate_ctr_inc(&bts->network->bsc_ctrs->ctr[BSC_CTR_HANDOVER_NO_CHANNEL]);
		return -ENOSPC;
	}

	ho = talloc_zero(tall_bsc_ctx, struct bsc_handover);
	if (!ho) {
		LOGP(DHO, LOGL_FATAL, "Out of Memory\n");
		lchan_free(new_lchan);
		return -ENOMEM;
	}
	ho->old_lchan = old_lchan;
	ho->new_lchan = new_lchan;
	ho->ho_ref = ho_ref++;

	/* copy some parameters from old lchan */
	memcpy(&new_lchan->encr, &old_lchan->encr, sizeof(new_lchan->encr));
	new_lchan->ms_power = old_lchan->ms_power;
	new_lchan->bs_power = old_lchan->bs_power;
	new_lchan->rsl_cmode = old_lchan->rsl_cmode;
	new_lchan->tch_mode = old_lchan->tch_mode;
	memcpy(&new_lchan->mr_ms_lv, &old_lchan->mr_ms_lv, ARRAY_SIZE(new_lchan->mr_ms_lv));
	memcpy(&new_lchan->mr_bts_lv, &old_lchan->mr_bts_lv, ARRAY_SIZE(new_lchan->mr_bts_lv));

	new_lchan->conn = old_lchan->conn;
	new_lchan->conn->ho_lchan = new_lchan;

	/* FIXME: do we have a better idea of the timing advance? */
	rc = rsl_chan_activate_lchan(new_lchan, RSL_ACT_INTER_ASYNC, ho->ho_ref);
	if (rc < 0) {
		LOGP(DHO, LOGL_ERROR, "could not activate channel\n");
		new_lchan->conn->ho_lchan = NULL;
		new_lchan->conn = NULL;
		talloc_free(ho);
		lchan_free(new_lchan);
		return rc;
	}

	rsl_lchan_set_state(new_lchan, LCHAN_S_ACT_REQ);
	llist_add(&ho->list, &bsc_handovers);
	/* we continue in the SS_LCHAN handler / ho_chan_activ_ack */

	return 0;
}

void bsc_clear_handover(struct gsm_subscriber_connection *conn, int free_lchan)
{
	struct bsc_handover *ho;

	ho = bsc_ho_by_new_lchan(conn->ho_lchan);


	if (!ho && conn->ho_lchan)
		LOGP(DHO, LOGL_ERROR, "BUG: We lost some state.\n");

	if (!ho) {
		LOGP(DHO, LOGL_ERROR, "unable to find HO record\n");
		return;
	}

	conn->ho_lchan->conn = NULL;
	conn->ho_lchan = NULL;

	if (free_lchan)
		lchan_release(ho->new_lchan, 0, RSL_REL_LOCAL_END);

	handover_free(ho);
}

/* T3103 expired: Handover has failed without HO COMPLETE or HO FAIL */
static void ho_T3103_cb(void *_ho)
{
	struct bsc_handover *ho = _ho;
	struct gsm_network *net = ho->new_lchan->ts->trx->bts->network;

	DEBUGP(DHO, "HO T3103 expired\n");
	rate_ctr_inc(&net->bsc_ctrs->ctr[BSC_CTR_HANDOVER_TIMEOUT]);

	ho->new_lchan->conn->ho_lchan = NULL;
	ho->new_lchan->conn = NULL;
	lchan_release(ho->new_lchan, 0, RSL_REL_LOCAL_END);
	handover_free(ho);
}

/* RSL has acknowledged activation of the new lchan */
static int ho_chan_activ_ack(struct gsm_lchan *new_lchan)
{
	struct bsc_handover *ho;

	/* we need to check if this channel activation is related to
	 * a handover at all (and if, which particular handover) */
	ho = bsc_ho_by_new_lchan(new_lchan);
	if (!ho)
		return -ENODEV;

	DEBUGP(DHO, "handover activate ack, send HO Command\n");

	/* we can now send the 04.08 HANDOVER COMMAND to the MS
	 * using the old lchan */

	gsm48_send_ho_cmd(ho->old_lchan, new_lchan, 0, ho->ho_ref);

	/* start T3103.  We can continue either with T3103 expiration,
	 * 04.08 HANDOVER COMPLETE or 04.08 HANDOVER FAIL */
	osmo_timer_setup(&ho->T3103, ho_T3103_cb, ho);
	osmo_timer_schedule(&ho->T3103, 10, 0);

	/* create a RTP connection */
	if (is_ipaccess_bts(new_lchan->ts->trx->bts))
		rsl_ipacc_crcx(new_lchan);

	return 0;
}

/* RSL has not acknowledged activation of the new lchan */
static int ho_chan_activ_nack(struct gsm_lchan *new_lchan)
{
	struct bsc_handover *ho;

	ho = bsc_ho_by_new_lchan(new_lchan);
	if (!ho) {
		LOGP(DHO, LOGL_INFO, "ACT NACK: unable to find HO record\n");
		return -ENODEV;
	}

	new_lchan->conn->ho_lchan = NULL;
	new_lchan->conn = NULL;
	handover_free(ho);

	/* FIXME: maybe we should try to allocate a new LCHAN here? */

	return 0;
}

/* GSM 04.08 HANDOVER COMPLETE has been received on new channel */
static int ho_gsm48_ho_compl(struct gsm_lchan *new_lchan)
{
	struct gsm_network *net;
	struct bsc_handover *ho;

	ho = bsc_ho_by_new_lchan(new_lchan);
	if (!ho) {
		LOGP(DHO, LOGL_ERROR, "unable to find HO record\n");
		return -ENODEV;
	}

	net = new_lchan->ts->trx->bts->network;
	LOGP(DHO, LOGL_INFO, "Subscriber %s HO from BTS %u->%u on ARFCN "
	     "%u->%u\n", vlr_subscr_name(ho->old_lchan->conn->vsub),
	     ho->old_lchan->ts->trx->bts->nr, new_lchan->ts->trx->bts->nr,
	     ho->old_lchan->ts->trx->arfcn, new_lchan->ts->trx->arfcn);

	rate_ctr_inc(&net->bsc_ctrs->ctr[BSC_CTR_HANDOVER_COMPLETED]);

	osmo_timer_del(&ho->T3103);

	/* switch TRAU muxer for E1 based BTS from one channel to another */
	if (is_e1_bts(new_lchan->conn->bts))
		switch_trau_mux(ho->old_lchan, new_lchan);

	/* Replace the ho lchan with the primary one */
	if (ho->old_lchan != new_lchan->conn->lchan)
		LOGP(DHO, LOGL_ERROR, "Primary lchan changed during handover.\n");

	if (new_lchan != new_lchan->conn->ho_lchan)
		LOGP(DHO, LOGL_ERROR, "Handover channel changed during this handover.\n");

	new_lchan->conn->ho_lchan = NULL;
	new_lchan->conn->lchan = new_lchan;
	ho->old_lchan->conn = NULL;

	lchan_release(ho->old_lchan, 0, RSL_REL_LOCAL_END);

	handover_free(ho);
	return 0;
}

/* GSM 04.08 HANDOVER FAIL has been received */
static int ho_gsm48_ho_fail(struct gsm_lchan *old_lchan)
{
	struct gsm_network *net = old_lchan->ts->trx->bts->network;
	struct bsc_handover *ho;
	struct gsm_lchan *new_lchan;

	ho = bsc_ho_by_old_lchan(old_lchan);
	if (!ho) {
		LOGP(DHO, LOGL_ERROR, "unable to find HO record\n");
		return -ENODEV;
	}

	rate_ctr_inc(&net->bsc_ctrs->ctr[BSC_CTR_HANDOVER_FAILED]);

	new_lchan = ho->new_lchan;

	/* release the channel and forget about it */
	ho->new_lchan->conn->ho_lchan = NULL;
	ho->new_lchan->conn = NULL;
	handover_free(ho);

	lchan_release(new_lchan, 0, RSL_REL_LOCAL_END);


	return 0;
}

/* GSM 08.58 HANDOVER DETECT has been received */
static int ho_rsl_detect(struct gsm_lchan *new_lchan)
{
	struct bsc_handover *ho;

	ho = bsc_ho_by_new_lchan(new_lchan);
	if (!ho) {
		LOGP(DHO, LOGL_ERROR, "unable to find HO record\n");
		return -ENODEV;
	}

	/* FIXME: do we actually want to do something here ? */

	return 0;
}

static int ho_logic_sig_cb(unsigned int subsys, unsigned int signal,
			   void *handler_data, void *signal_data)
{
	struct lchan_signal_data *lchan_data;
	struct gsm_lchan *lchan;

	lchan_data = signal_data;
	switch (subsys) {
	case SS_LCHAN:
		lchan = lchan_data->lchan;
		switch (signal) {
		case S_LCHAN_ACTIVATE_ACK:
			return ho_chan_activ_ack(lchan);
		case S_LCHAN_ACTIVATE_NACK:
			return ho_chan_activ_nack(lchan);
		case S_LCHAN_HANDOVER_DETECT:
			return ho_rsl_detect(lchan);
		case S_LCHAN_HANDOVER_COMPL:
			return ho_gsm48_ho_compl(lchan);
		case S_LCHAN_HANDOVER_FAIL:
			return ho_gsm48_ho_fail(lchan);
		}
		break;
	default:
		break;
	}

	return 0;
}

struct gsm_lchan *bsc_handover_pending(struct gsm_lchan *new_lchan)
{
	struct bsc_handover *ho;
	ho = bsc_ho_by_new_lchan(new_lchan);
	if (!ho)
		return NULL;
	return ho->old_lchan;
}

static __attribute__((constructor)) void on_dso_load_ho_logic(void)
{
	osmo_signal_register_handler(SS_LCHAN, ho_logic_sig_cb, NULL);
}
