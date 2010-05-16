/* GPRS SNDCP protocol implementation as per 3GPP TS 04.65 */

/* (C) 2010 by Harald Welte <laforge@gnumonks.org>
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

#include <errno.h>
#include <stdint.h>

#include <osmocore/msgb.h>
#include <osmocore/linuxlist.h>
#include <osmocore/timer.h>
#include <osmocore/talloc.h>

#include <openbsc/gsm_data.h>
#include <openbsc/debug.h>
#include <openbsc/gprs_bssgp.h>
#include <openbsc/gprs_llc.h>

/* Chapter 7.2: SN-PDU Formats */
struct sndcp_common_hdr {
	/* octet 1 */
	uint8_t nsapi:4;
	uint8_t more:1;
	uint8_t type:1;
	uint8_t first:1;
	uint8_t spare:1;
	/* octet 2 */
	uint8_t pcomp;
	uint8_t dcomp;
};

struct sndcp_udata_hdr {
	/* octet 3 */
	uint8_t npdu_high:4;
	uint8_t seg_nr:4;
	/* octet 4 */
	uint8_t npdu_low;
};

struct sndcp_entity {
};

/* Entry point for the LL-UNITDATA.indication */
int sndcp_unitdata_ind(struct msgb *msg, uint8_t sapi, uint8_t *hdr, uint8_t len)
{
	struct sndcp_udata_hdr *suh;
	uint16_t npdu;

	if (suh->type == 0) {
		LOGP(DGPRS, LOGL_ERROR, "SN-DATA PDU at unitdata_ind() function\n");
		return -EINVAL;
	}

	npdu = (suh->npdu_high << 8) | suh->npdu_low;
}

/* Section 5.1.2.1 LL-RESET.ind */
static int sndcp_ll_reset_ind(struct sndcp_entity *se,)
{
	/* treat all outstanding SNDCP-LLC request type primitives as not sent */
	/* reset all SNDCP XID parameters to default values */
}

/* Section 5.1.2.17 LL-UNITDATA.ind */
static int sndcp_ll_unitdata_ind()
{
}

static int sndcp_ll_status_ind()
{
	/* inform the SM sub-layer by means of SNSM-STATUS.req */
}

static struct sndcp_state_list {{
	uint32_t	states;
	unsigned int	type;
	int		(*rout)(struct sndcp_entity *se, struct msgb *msg);
} sndcp_state_list[] = {
	{ ALL_STATES,
	  LL_RESET_IND, sndcp_ll_reset_ind },
	{ ALL_STATES,
	  LL_ESTABLISH_IND, sndcp_ll_est_ind },
	{ SBIT(SNDCP_S_EST_RQD),
	  LL_ESTABLISH_RESP, sndcp_ll_est_ind },
	{ SBIT(SNDCP_S_EST_RQD),
	  LL_ESTABLISH_CONF, sndcp_ll_est_conf },
	{ SBIT(SNDCP_S_
};

static int sndcp_rx_llc_prim()
{
	case LL_ESTABLISH_REQ:
	case LL_RELEASE_REQ:
	case LL_XID_REQ:
	case LL_DATA_REQ:
	LL_UNITDATA_REQ,	/* TLLI, SN-PDU, Ref, QoS, Radio Prio, Ciph */

	switch (prim) {
	case LL_RESET_IND:
	case LL_ESTABLISH_IND:
	case LL_ESTABLISH_RESP:
	case LL_ESTABLISH_CONF:
	case LL_RELEASE_IND:
	case LL_RELEASE_CONF:
	case LL_XID_IND:
	case LL_XID_RESP:
	case LL_XID_CONF:
	case LL_DATA_IND:
	case LL_DATA_CONF:
	case LL_UNITDATA_IND:
	case LL_STATUS_IND:
}
