/* OpenBSC Debugging/Logging support code */

/* (C) 2008-2010 by Harald Welte <laforge@gnumonks.org>
 * (C) 2008 by Holger Hans Peter Freyther <zecke@selfish.org>
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

#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <time.h>
#include <errno.h>

#include <osmocom/core/talloc.h>
#include <osmocom/core/utils.h>
#include <osmocom/core/logging.h>
#include <osmocom/gprs/gprs_msgb.h>
#include <openbsc/gsm_data.h>
#include <openbsc/debug.h>

/* default categories */
static const struct log_info_cat default_categories[] = {
	[DRLL] = {
		.name = "DRLL",
		.description = "A-bis Radio Link Layer (RLL)",
		.color = "\033[1;31m",
		.enabled = 1, .loglevel = LOGL_NOTICE,
	},
	[DCC] = {
		.name = "DCC",
		.description = "Layer3 Call Control (CC)",
		.color = "\033[1;32m",
		.enabled = 1, .loglevel = LOGL_NOTICE,
	},
	[DMM] = {
		.name = "DMM",
		.description = "Layer3 Mobility Management (MM)",
		.color = "\033[1;33m",
		.enabled = 1, .loglevel = LOGL_NOTICE,
	},
	[DRR] = {
		.name = "DRR",
		.description = "Layer3 Radio Resource (RR)",
		.color = "\033[1;34m",
		.enabled = 1, .loglevel = LOGL_NOTICE,
	},
	[DRSL] = {
		.name = "DRSL",
		.description = "A-bis Radio Siganlling Link (RSL)",
		.color = "\033[1;35m",
		.enabled = 1, .loglevel = LOGL_NOTICE,
	},
	[DNM] =	{
		.name = "DNM",
		.description = "A-bis Network Management / O&M (NM/OML)",
		.color = "\033[1;36m",
		.enabled = 1, .loglevel = LOGL_INFO,
	},
	[DMNCC] = {
		.name = "DMNCC",
		.description = "MNCC API for Call Control application",
		.color = "\033[1;39m",
		.enabled = 1, .loglevel = LOGL_NOTICE,
	},
	[DPAG]	= {
		.name = "DPAG",
		.description = "Paging Subsystem",
		.color = "\033[1;38m",
		.enabled = 1, .loglevel = LOGL_NOTICE,
	},
	[DMEAS] = {
		.name = "DMEAS",
		.description = "Radio Measurement Processing",
		.enabled = 0, .loglevel = LOGL_NOTICE,
	},
	[DSCCP] = {
		.name = "DSCCP",
		.description = "SCCP Protocol",
		.enabled = 1, .loglevel = LOGL_NOTICE,
	},
	[DMSC] = {
		.name = "DMSC",
		.description = "Mobile Switching Center",
		.enabled = 1, .loglevel = LOGL_NOTICE,
	},
	[DMGCP] = {
		.name = "DMGCP",
		.description = "Media Gateway Control Protocol",
		.enabled = 1, .loglevel = LOGL_NOTICE,
	},
	[DHO] = {
		.name = "DHO",
		.description = "Hand-Over",
		.enabled = 1, .loglevel = LOGL_NOTICE,
	},
	[DDB] = {
		.name = "DDB",
		.description = "Database Layer",
		.enabled = 1, .loglevel = LOGL_NOTICE,
	},
	[DREF] = {
		.name = "DREF",
		.description = "Reference Counting",
		.enabled = 0, .loglevel = LOGL_NOTICE,
	},
	[DGPRS] = {
		.name = "DGPRS",
		.description = "GPRS Packet Service",
		.enabled = 1, .loglevel = LOGL_DEBUG,
	},
	[DNS] = {
		.name = "DNS",
		.description = "GPRS Network Service (NS)",
		.enabled = 1, .loglevel = LOGL_INFO,
	},
	[DBSSGP] = {
		.name = "DBSSGP",
		.description = "GPRS BSS Gateway Protocol (BSSGP)",
		.enabled = 1, .loglevel = LOGL_DEBUG,
	},
	[DLLC] = {
		.name = "DLLC",
		.description = "GPRS Logical Link Control Protocol (LLC)",
		.enabled = 1, .loglevel = LOGL_DEBUG,
	},
	[DSNDCP] = {
		.name = "DSNDCP",
		.description = "GPRS Sub-Network Dependent Control Protocol (SNDCP)",
		.enabled = 1, .loglevel = LOGL_DEBUG,
	},
	[DNAT] = {
		.name = "DNAT",
		.description = "GSM 08.08 NAT/Multiplexer",
		.enabled = 1, .loglevel = LOGL_NOTICE,
	},
	[DCTRL] = {
		.name = "DCTRL",
		.description = "Control interface",
		.enabled = 1, .loglevel = LOGL_NOTICE,
	},
	[DSMPP] = {
		.name = "DSMPP",
		.description = "SMPP interface for external SMS apps",
		.enabled = 1, .loglevel = LOGL_DEBUG,
	},
	[DFILTER] = {
		.name = "DFILTER",
		.description = "BSC/NAT IMSI based filtering",
		.enabled = 1, .loglevel = LOGL_DEBUG,
	},
	[DRANAP] = {
		.name = "DRANAP",
		.description = "Radio Access Network Application Part Protocol",
		.enabled = 1, .loglevel = LOGL_DEBUG,
	},
	[DSUA] = {
		.name = "DSUA",
		.description = "SCCP User Adaptation Protocol",
		.enabled = 1, .loglevel = LOGL_DEBUG,
	},
	[DPCU] = {
		.name = "DPCU",
		.description = "PCU Interface",
		.enabled = 1, .loglevel = LOGL_DEBUG,
	},
	[DVLR] = {
		.name = "DVLR",
		.description = "Visitor Location Register",
		.enabled = 1, .loglevel = LOGL_DEBUG,
	},
	[DIUCS] = {
		.name = "DIUCS",
		.description = "Iu-CS Protocol",
		.enabled = 1, .loglevel = LOGL_DEBUG,
	},
};

static int filter_fn(const struct log_context *ctx, struct log_target *tar)
{
	const struct vlr_subscr *vsub = ctx->ctx[LOG_CTX_VLR_SUBSCR];
	const struct bsc_subscr *bsub = ctx->ctx[LOG_CTX_BSC_SUBSCR];
	const struct gprs_nsvc *nsvc = ctx->ctx[LOG_CTX_GB_NSVC];
	const struct gprs_nsvc *bvc = ctx->ctx[LOG_CTX_GB_BVC];

	if ((tar->filter_map & (1 << LOG_FLT_VLR_SUBSCR)) != 0
	    && vsub && vsub == tar->filter_data[LOG_FLT_VLR_SUBSCR])
		return 1;

	if ((tar->filter_map & (1 << LOG_FLT_BSC_SUBSCR)) != 0
	    && bsub && bsub == tar->filter_data[LOG_FLT_BSC_SUBSCR])
		return 1;

	/* Filter on the NS Virtual Connection */
	if ((tar->filter_map & (1 << LOG_FLT_GB_NSVC)) != 0
	    && nsvc && (nsvc == tar->filter_data[LOG_FLT_GB_NSVC]))
		return 1;

	/* Filter on the NS Virtual Connection */
	if ((tar->filter_map & (1 << LOG_FLT_GB_BVC)) != 0
	    && bvc && (bvc == tar->filter_data[LOG_FLT_GB_BVC]))
		return 1;

	return 0;
}

const struct log_info log_info = {
	.filter_fn = filter_fn,
	.cat = default_categories,
	.num_cat = ARRAY_SIZE(default_categories),
};
