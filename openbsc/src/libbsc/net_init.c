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

#include <openbsc/common_cs.h>
#include <openbsc/osmo_bsc.h>
#include <openbsc/bsc_msc_data.h>

struct gsm_network *bsc_network_init(void *ctx,
				     uint16_t country_code,
				     uint16_t network_code,
				     mncc_recv_cb_t mncc_recv)
{
	struct gsm_network *net;

	net = gsm_network_init(ctx, country_code, network_code, mncc_recv);

	net->bsc_data = talloc_zero(net, struct osmo_bsc_data);
	if (!net->bsc_data) {
		talloc_free(net);
		return NULL;
	}

	/* Init back pointer */
	net->bsc_data->auto_off_timeout = -1;
	net->bsc_data->network = net;
	INIT_LLIST_HEAD(&net->bsc_data->mscs);

	net->num_bts = 0;
	net->reject_cause = GSM48_REJECT_ROAMING_NOT_ALLOWED;
	net->T3101 = GSM_T3101_DEFAULT;
	net->T3103 = GSM_T3103_DEFAULT;
	net->T3105 = GSM_T3105_DEFAULT;
	net->T3107 = GSM_T3107_DEFAULT;
	net->T3109 = GSM_T3109_DEFAULT;
	net->T3111 = GSM_T3111_DEFAULT;
	net->T3113 = GSM_T3113_DEFAULT;
	net->T3115 = GSM_T3115_DEFAULT;
	net->T3117 = GSM_T3117_DEFAULT;
	net->T3119 = GSM_T3119_DEFAULT;
	net->T3122 = GSM_T3122_DEFAULT;
	net->T3141 = GSM_T3141_DEFAULT;

	/* default set of handover parameters */
	net->handover.win_rxlev_avg = 10;
	net->handover.win_rxqual_avg = 1;
	net->handover.win_rxlev_avg_neigh = 10;
	net->handover.pwr_interval = 6;
	net->handover.pwr_hysteresis = 3;
	net->handover.max_distance = 9999;

	INIT_LLIST_HEAD(&net->bts_list);

	/* init statistics */
	net->bsc_ctrs = rate_ctr_group_alloc(net, &bsc_ctrg_desc, 0);
	if (!net->bsc_ctrs) {
		talloc_free(net);
		return NULL;
	}

	gsm_net_update_ctype(net);

	return net;
}

