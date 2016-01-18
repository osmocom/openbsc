/* (C) 2008-2010 by Harald Welte <laforge@gnumonks.org>
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

#include <openbsc/gsm_data.h>
#include <openbsc/osmo_msc_data.h>
#include <openbsc/gsm_subscriber.h>

struct gsm_network *gsm_network_init(uint16_t country_code, uint16_t network_code,
				     int (*mncc_recv)(struct gsm_network *, struct msgb *))
{
	struct gsm_network *net;

	net = talloc_zero(tall_bsc_ctx, struct gsm_network);
	if (!net)
		return NULL;

	net->bsc_data = talloc_zero(net, struct osmo_bsc_data);
	if (!net->bsc_data) {
		talloc_free(net);
		return NULL;
	}

	net->subscr_group = talloc_zero(net, struct gsm_subscriber_group);
	if (!net->subscr_group) {
		talloc_free(net);
		return NULL;
	}

	/* Init back pointer */
	net->bsc_data->auto_off_timeout = -1;
	net->bsc_data->network = net;
	INIT_LLIST_HEAD(&net->bsc_data->mscs);

	net->subscr_group->net = net;
	net->create_subscriber = 1;

	net->country_code = country_code;
	net->network_code = network_code;
	net->num_bts = 0;
	net->reject_cause = GSM48_REJECT_ROAMING_NOT_ALLOWED;
	net->T3101 = GSM_T3101_DEFAULT;
	net->T3105 = GSM_T3105_DEFAULT;
	net->T3113 = GSM_T3113_DEFAULT;
	net->T3122 = GSM_T3122_DEFAULT;
	/* FIXME: initialize all other timers! */

	/* default set of handover parameters */
	net->handover.win_rxlev_avg = 10;
	net->handover.win_rxqual_avg = 1;
	net->handover.win_rxlev_avg_neigh = 10;
	net->handover.pwr_interval = 6;
	net->handover.pwr_hysteresis = 3;
	net->handover.max_distance = 9999;

	INIT_LLIST_HEAD(&net->trans_list);
	INIT_LLIST_HEAD(&net->upqueue);
	INIT_LLIST_HEAD(&net->bts_list);
	INIT_LLIST_HEAD(&net->subscr_conns);

	net->stats.chreq.total = osmo_counter_alloc("net.chreq.total");
	net->stats.chreq.no_channel = osmo_counter_alloc("net.chreq.no_channel");
	net->stats.handover.attempted = osmo_counter_alloc("net.handover.attempted");
	net->stats.handover.no_channel = osmo_counter_alloc("net.handover.no_channel");
	net->stats.handover.timeout = osmo_counter_alloc("net.handover.timeout");
	net->stats.handover.completed = osmo_counter_alloc("net.handover.completed");
	net->stats.handover.failed = osmo_counter_alloc("net.handover.failed");
	net->stats.loc_upd_type.attach = osmo_counter_alloc("net.loc_upd_type.attach");
	net->stats.loc_upd_type.normal = osmo_counter_alloc("net.loc_upd_type.normal");
	net->stats.loc_upd_type.periodic = osmo_counter_alloc("net.loc_upd_type.periodic");
	net->stats.loc_upd_type.detach = osmo_counter_alloc("net.imsi_detach.count");
	net->stats.loc_upd_resp.reject = osmo_counter_alloc("net.loc_upd_resp.reject");
	net->stats.loc_upd_resp.accept = osmo_counter_alloc("net.loc_upd_resp.accept");
	net->stats.paging.attempted = osmo_counter_alloc("net.paging.attempted");
	net->stats.paging.detached = osmo_counter_alloc("net.paging.detached");
	net->stats.paging.completed = osmo_counter_alloc("net.paging.completed");
	net->stats.paging.expired = osmo_counter_alloc("net.paging.expired");
	net->stats.sms.submitted = osmo_counter_alloc("net.sms.submitted");
	net->stats.sms.no_receiver = osmo_counter_alloc("net.sms.no_receiver");
	net->stats.sms.delivered = osmo_counter_alloc("net.sms.delivered");
	net->stats.sms.rp_err_mem = osmo_counter_alloc("net.sms.rp_err_mem");
	net->stats.sms.rp_err_other = osmo_counter_alloc("net.sms.rp_err_other");
	net->stats.call.mo_setup = osmo_counter_alloc("net.call.mo_setup");
	net->stats.call.mo_connect_ack = osmo_counter_alloc("net.call.mo_connect_ack");
	net->stats.call.mt_setup = osmo_counter_alloc("net.call.mt_setup");
	net->stats.call.mt_connect = osmo_counter_alloc("net.call.mt_connect");
	net->stats.chan.rf_fail = osmo_counter_alloc("net.chan.rf_fail");
	net->stats.chan.rll_err = osmo_counter_alloc("net.chan.rll_err");
	net->stats.bts.oml_fail = osmo_counter_alloc("net.bts.oml_fail");
	net->stats.bts.rsl_fail = osmo_counter_alloc("net.bts.rsl_fail");

	net->mncc_recv = mncc_recv;

	gsm_net_update_ctype(net);

	return net;
}

