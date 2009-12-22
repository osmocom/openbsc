/* Handover Logic for Inter-BTS (Intra-BSC) Handover.  This does not
 * actually implement the handover algorithm/decision, but executes a
 * handover decision */

/* (C) 2009 by Harald Welte <laforge@gnumonks.org>
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <netinet/in.h>

#include <openbsc/msgb.h>
#include <openbsc/debug.h>
#include <openbsc/gsm_data.h>
#include <openbsc/gsm_utils.h>
#include <openbsc/gsm_subscriber.h>
#include <openbsc/gsm_04_08.h>
#include <openbsc/abis_rsl.h>
#include <openbsc/chan_alloc.h>
#include <openbsc/signal.h>
#include <openbsc/talloc.h>
#include <openbsc/transaction.h>
#include <openbsc/rtp_proxy.h>

struct bsc_handover {
	struct llist_head list;

	struct gsm_lchan *old_lchan;
	struct gsm_lchan *new_lchan;

	struct timer_list T3103;

	u_int8_t ho_ref;
};

static LLIST_HEAD(bsc_handovers);

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

/* Hand over the specified logical channel to the specified new BTS.
 * This is the main entry point for the actual handover algorithm,
 * after it has decided it wants to initiate HO to a specific BTS */
int bsc_handover_start(struct gsm_lchan *old_lchan, struct gsm_bts *bts)
{
	struct gsm_lchan *new_lchan;
	struct bsc_handover *ho;
	static u_int8_t ho_ref;
	int rc;

	/* don't attempt multiple handovers for the same lchan at
	 * the same time */
	if (bsc_ho_by_old_lchan(old_lchan))
		return -EBUSY;

	DEBUGP(DHO, "(old_lchan on BTS %u, new BTS %u)\n",
		old_lchan->ts->trx->bts->nr, bts->nr);

	counter_inc(bts->network->stats.handover.attempted);

	new_lchan = lchan_alloc(bts, old_lchan->type);
	if (!new_lchan) {
		LOGP(DHO, LOGL_NOTICE, "No free channel\n");
		counter_inc(bts->network->stats.handover.no_channel);
		return -ENOSPC;
	}

	ho = talloc_zero(NULL, struct bsc_handover);
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
	new_lchan->subscr = subscr_get(old_lchan->subscr);

	/* FIXME: do we have a better idea of the timing advance? */
	rc = rsl_chan_activate_lchan(new_lchan, RSL_ACT_INTER_ASYNC, 0,
				     ho->ho_ref);
	if (rc < 0) {
		LOGP(DHO, LOGL_ERROR, "could not activate channel\n");
		talloc_free(ho);
		lchan_free(new_lchan);
		return rc;
	}

	llist_add(&ho->list, &bsc_handovers);
	/* we continue in the SS_LCHAN handler / ho_chan_activ_ack */

	return 0;
}

/* T3103 expired: Handover has failed without HO COMPLETE or HO FAIL */
static void ho_T3103_cb(void *_ho)
{
	struct bsc_handover *ho = _ho;
	struct gsm_network *net = ho->new_lchan->ts->trx->bts->network;

	DEBUGP(DHO, "HO T3103 expired\n");
	counter_inc(net->stats.handover.timeout);

	lchan_free(ho->new_lchan);
	llist_del(&ho->list);
	talloc_free(ho);
}

/* RSL has acknowledged activation of the new lchan */
static int ho_chan_activ_ack(struct gsm_lchan *new_lchan)
{
	struct bsc_handover *ho;
	int rc;

	/* we need to check if this channel activation is related to
	 * a handover at all (and if, which particular handover) */
	ho = bsc_ho_by_new_lchan(new_lchan);
	if (!ho)
		return -ENODEV;

	DEBUGP(DHO, "handover activate ack, send HO Command\n");

	/* we can now send the 04.08 HANDOVER COMMAND to the MS
	 * using the old lchan */

	rc = gsm48_send_ho_cmd(ho->old_lchan, new_lchan, 0, ho->ho_ref);

	/* start T3103.  We can continue either with T3103 expiration,
	 * 04.08 HANDOVER COMPLETE or 04.08 HANDOVER FAIL */
	ho->T3103.cb = ho_T3103_cb;
	ho->T3103.data = ho;
	bsc_schedule_timer(&ho->T3103, 10, 0);

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
		LOGP(DHO, LOGL_ERROR, "unable to find HO record\n");
		return -ENODEV;
	}

	llist_del(&ho->list);
	talloc_free(ho);

	/* FIXME: maybe we should try to allocate a new LCHAN here? */

	return 0;
}

/* GSM 04.08 HANDOVER COMPLETE has been received on new channel */
static int ho_gsm48_ho_compl(struct gsm_lchan *new_lchan)
{
	struct gsm_network *net = new_lchan->ts->trx->bts->network;
	struct bsc_handover *ho;

	ho = bsc_ho_by_new_lchan(new_lchan);
	if (!ho) {
		LOGP(DHO, LOGL_ERROR, "unable to find HO record\n");
		return -ENODEV;
	}

	counter_inc(net->stats.handover.completed);

	bsc_del_timer(&ho->T3103);

	/* update lchan pointer of transaction */
	trans_lchan_change(ho->old_lchan, new_lchan);

	ho->old_lchan->state = LCHAN_S_INACTIVE;
	lchan_auto_release(ho->old_lchan);

	/* do something to re-route the actual speech frames ! */

	llist_del(&ho->list);
	talloc_free(ho);

	return 0;
}

/* GSM 04.08 HANDOVER FAIL has been received */
static int ho_gsm48_ho_fail(struct gsm_lchan *old_lchan)
{
	struct gsm_network *net = old_lchan->ts->trx->bts->network;
	struct bsc_handover *ho;

	ho = bsc_ho_by_old_lchan(old_lchan);
	if (!ho) {
		LOGP(DHO, LOGL_ERROR, "unable to find HO record\n");
		return -ENODEV;
	}

	counter_inc(net->stats.handover.failed);

	bsc_del_timer(&ho->T3103);
	llist_del(&ho->list);
	put_lchan(ho->new_lchan);
	talloc_free(ho);

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

static int ho_ipac_crcx_ack(struct gsm_lchan *new_lchan)
{
	struct bsc_handover *ho;
	struct rtp_socket *old_rs, *new_rs, *other_rs;

	ho = bsc_ho_by_new_lchan(new_lchan);
	if (!ho) {
		LOGP(DHO, LOGL_ERROR, "unable to find HO record\n");
		return -ENODEV;
	}

	if (ipacc_rtp_direct) {
		LOGP(DHO, LOGL_ERROR, "unable to handover in direct RTP mode\n");
		return 0;
	}

	/* RTP Proxy mode */
	new_rs = new_lchan->abis_ip.rtp_socket;
	old_rs = ho->old_lchan->abis_ip.rtp_socket;

	if (!new_rs) {
		LOGP(DHO, LOGL_ERROR, "no RTP socket for new_lchan\n");
		return -EIO;
	}

	rsl_ipacc_mdcx_to_rtpsock(new_lchan);

	if (!old_rs) {
		LOGP(DHO, LOGL_ERROR, "no RTP socekt for old_lchan\n");
		return -EIO;
	}

	/* copy rx_action and reference to other sock */
	new_rs->rx_action = old_rs->rx_action;
	new_rs->tx_action = old_rs->tx_action;
	new_rs->transmit = old_rs->transmit;

	switch (ho->old_lchan->abis_ip.rtp_socket->rx_action) {
	case RTP_PROXY:
		other_rs = old_rs->proxy.other_sock;
		rtp_socket_proxy(new_rs, other_rs);
		/* delete reference to other end socket to prevent
		 * rtp_socket_free() from removing the inverse reference */
		old_rs->proxy.other_sock = NULL;
		break;
	case RTP_RECV_UPSTREAM:
		new_rs->receive = old_rs->receive;
		break;
	case RTP_NONE:
		break;
	}

	return 0;
}

static int ho_logic_sig_cb(unsigned int subsys, unsigned int signal,
			   void *handler_data, void *signal_data)
{
	struct gsm_lchan *lchan;

	switch (subsys) {
	case SS_LCHAN:
		lchan = signal_data;
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
	case SS_ABISIP:
		lchan = signal_data;
		switch (signal) {
		case S_ABISIP_CRCX_ACK:
			return ho_ipac_crcx_ack(lchan);
			break;
		}
		break;
	default:
		break;
	}

	return 0;
}

static __attribute__((constructor)) void on_dso_load_ho_logic(void)
{
	register_signal_handler(SS_LCHAN, ho_logic_sig_cb, NULL);
	register_signal_handler(SS_ABISIP, ho_logic_sig_cb, NULL);
}
