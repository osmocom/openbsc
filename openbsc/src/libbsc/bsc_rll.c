/* GSM BSC Radio Link Layer API
 * 3GPP TS 08.58 version 8.6.0 Release 1999 / ETSI TS 100 596 V8.6.0 */

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

#include <errno.h>

#include <openbsc/debug.h>
#include <osmocom/core/talloc.h>
#include <osmocom/core/timer.h>
#include <osmocom/core/linuxlist.h>
#include <openbsc/bsc_rll.h>
#include <openbsc/gsm_data.h>
#include <openbsc/chan_alloc.h>
#include <openbsc/abis_rsl.h>
#include <openbsc/signal.h>

struct bsc_rll_req {
	struct llist_head list;
	struct osmo_timer_list timer;

	struct gsm_lchan *lchan;
	uint8_t link_id;

	void (*cb)(struct gsm_lchan *lchan, uint8_t link_id,
		   void *data, enum bsc_rllr_ind);
	void *data;
};

/* we only compare C1, C2 and SAPI */
#define LINKID_MASK	0xC7

static LLIST_HEAD(bsc_rll_reqs);

static void complete_rllr(struct bsc_rll_req *rllr, enum bsc_rllr_ind type)
{
	llist_del(&rllr->list);
	rllr->cb(rllr->lchan, rllr->link_id, rllr->data, type);
	talloc_free(rllr);
}

static void timer_cb(void *_rllr)
{
	struct bsc_rll_req *rllr = _rllr;

	complete_rllr(rllr, BSC_RLLR_IND_TIMEOUT);
}

/* establish a RLL connection with given SAPI / priority */
int rll_establish(struct gsm_lchan *lchan, uint8_t sapi,
		  void (*cb)(struct gsm_lchan *, uint8_t, void *,
			     enum bsc_rllr_ind),
		  void *data)
{
	struct bsc_rll_req *rllr = talloc_zero(tall_bsc_ctx, struct bsc_rll_req);
	uint8_t link_id;
	if (!rllr)
		return -ENOMEM;

	link_id = sapi;

	/* If we are a TCH and not in signalling mode, we need to
	 * indicate that the new RLL connection is to be made on the SACCH */
	if ((lchan->type == GSM_LCHAN_TCH_F ||
	     lchan->type == GSM_LCHAN_TCH_H) && sapi != 0)
		link_id |= 0x40;

	rllr->lchan = lchan;
	rllr->link_id = link_id;
	rllr->cb = cb;
	rllr->data = data;

	llist_add(&rllr->list, &bsc_rll_reqs);

	osmo_timer_setup(&rllr->timer, timer_cb, rllr);
	osmo_timer_schedule(&rllr->timer, 7, 0);

	/* send the RSL RLL ESTablish REQuest */
	return rsl_establish_request(rllr->lchan, rllr->link_id);
}

/* Called from RSL code in case we have received an indication regarding
 * any RLL link */
void rll_indication(struct gsm_lchan *lchan, uint8_t link_id, uint8_t type)
{
	struct bsc_rll_req *rllr, *rllr2;

	llist_for_each_entry_safe(rllr, rllr2, &bsc_rll_reqs, list) {
		if (rllr->lchan == lchan &&
		    (rllr->link_id & LINKID_MASK) == (link_id & LINKID_MASK)) {
			osmo_timer_del(&rllr->timer);
			complete_rllr(rllr, type);
			return;
		}
	}
}

static int rll_lchan_signal(unsigned int subsys, unsigned int signal,
			    void *handler_data, void *signal_data)
{
	struct challoc_signal_data *challoc;
	struct bsc_rll_req *rllr, *rllr2;

	if (subsys != SS_CHALLOC || signal != S_CHALLOC_FREED)
		return 0;

	challoc = (struct challoc_signal_data *) signal_data;

	llist_for_each_entry_safe(rllr, rllr2, &bsc_rll_reqs, list) {
		if (rllr->lchan == challoc->lchan) {
			osmo_timer_del(&rllr->timer);
			complete_rllr(rllr, BSC_RLLR_IND_ERR_IND);
		}
	}

	return 0;
}

static __attribute__((constructor)) void on_dso_load_rll(void)
{
	osmo_signal_register_handler(SS_CHALLOC, rll_lchan_signal, NULL);
}
