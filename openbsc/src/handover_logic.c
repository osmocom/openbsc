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
	int rc;

	new_lchan = lchan_alloc(bts, old_lchan->type);
	if (!new_lchan)
		return -ENOSPC;

	ho = talloc_zero(NULL, struct bsc_handover);
	if (!ho) {
		lchan_free(new_lchan);
		return -ENOMEM;
	}
	ho->old_lchan = old_lchan;
	ho->new_lchan = new_lchan;

	/* FIXME: do we have a better idea of the timing advance? */
	rc = rsl_chan_activate_lchan(new_lchan, RSL_ACT_INTER_ASYNC, 0);
	if (rc < 0) {
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

	lchan_free(ho->new_lchan);
	llist_del(&ho->list);
	talloc_free(ho);
}

/* RSL has acknowledged activation of the new lchan */
static int ho_chan_activ_ack(struct gsm_lchan *new_lchan)
{
	struct bsc_handover *ho;
	int rc;

	ho = bsc_ho_by_new_lchan(new_lchan);
	if (!ho)
		return -ENODEV;

	/* we can now send the 04.08 HANDOVER COMMAND to the MS
	 * using the old lchan */

	rc = gsm48_send_ho_cmd(ho->old_lchan, new_lchan, 0);

	/* start T3103.  We can continue either with T3103 expiration,
	 * 04.08 HANDOVER COMPLETE or 04.08 HANDOVER FAIL */
	ho->T3103.cb = ho_T3103_cb;
	bsc_schedule_timer(&ho->T3103, 10, 0);

	return 0;
}

/* RSL has not acknowledged activation of the new lchan */
static int ho_chan_activ_nack(struct gsm_lchan *new_lchan)
{
	struct bsc_handover *ho;

	ho = bsc_ho_by_new_lchan(new_lchan);
	if (!ho)
		return -ENODEV;

	llist_del(&ho->list);
	talloc_free(ho);

	/* FIXME: maybe we should try to allocate a new LCHAN here? */

	return 0;
}

/* GSM 04.08 HANDOVER COMPLETE has been received on new channel */
static int ho_gsm48_ho_compl(struct gsm_lchan *new_lchan)
{
	struct bsc_handover *ho;

	ho = bsc_ho_by_new_lchan(new_lchan);
	if (!ho)
		return -ENODEV;

	bsc_del_timer(&ho->T3103);
	llist_del(&ho->list);

	/* do something to re-route the actual speech frames ! */
	//tch_remap(ho->old_lchan, ho->new_lchan);

	/* release old lchan */
	put_lchan(ho->old_lchan);

	talloc_free(ho);

	return 0;
}

/* GSM 04.08 HANDOVER FAIL has been received */
static int ho_gsm48_ho_fail(struct gsm_lchan *old_lchan)
{
	struct bsc_handover *ho;

	ho = bsc_ho_by_old_lchan(old_lchan);
	if (!ho)
		return -ENODEV;

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

	ho = bsc_ho_by_old_lchan(new_lchan);
	if (!ho)
		return -ENODEV;

	/* FIXME: do we actually want to do something here ? */

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
	default:
		break;
	}

	return 0;
}

static __attribute__((constructor)) void on_dso_load_ho_logic(void)
{
	register_signal_handler(SS_LCHAN, ho_logic_sig_cb, NULL);
}
