/*
 * (C) 2010-2012 by Holger Hans Peter Freyther <zecke@selfish.org>
 * (C) 2010-2012 by On-Waves
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

#ifndef BSC_NAT_CALLSTATS_H
#define BSC_NAT_CALLSTATS_H

#include <osmocom/core/linuxlist.h>

#include <osmocom/sccp/sccp_types.h>

struct bsc_nat_call_stats {
	struct llist_head entry;

	struct sccp_source_reference remote_ref;
	struct sccp_source_reference src_ref; /* as seen by the MSC */

	/* mgcp options */
	uint32_t ci;
	int bts_rtp_port;
	int net_rtp_port;
	struct in_addr bts_addr;
	struct in_addr net_addr;


	/* as witnessed by the NAT */
	uint32_t net_ps;
	uint32_t net_os;
	uint32_t bts_pr;
	uint32_t bts_or;
	uint32_t bts_expected;
	uint32_t bts_jitter;
	int      bts_loss;

	uint32_t trans_id;
	int msc_endpoint;
};

#endif
