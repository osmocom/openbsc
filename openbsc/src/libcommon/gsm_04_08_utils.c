/* GSM Mobile Radio Interface Layer 3 messages on the A-bis interface
 * 3GPP TS 04.08 version 7.21.0 Release 1998 / ETSI TS 100 940 V7.21.0
 * utility functions
 */

/* (C) 2008-2009 by Harald Welte <laforge@gnumonks.org>
 * (C) 2008, 2009 by Holger Hans Peter Freyther <zecke@selfish.org>
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
#include <errno.h>
#include <netinet/in.h>

#include <osmocom/core/msgb.h>
#include <osmocom/gsm/gsm48.h>

#include <openbsc/abis_rsl.h>
#include <openbsc/debug.h>
#include <openbsc/gsm_04_08.h>
#include <openbsc/transaction.h>
#include <openbsc/paging.h>
#include <openbsc/signal.h>

/* should ip.access BTS use direct RTP streams between each other (1),
 * or should OpenBSC always act as RTP relay/proxy in between (0) ? */
int ipacc_rtp_direct = 1;

/* Section 9.1.8 / Table 9.9 */
struct chreq {
	uint8_t val;
	uint8_t mask;
	enum chreq_type type;
};

/* If SYSTEM INFORMATION TYPE 4 NECI bit == 1 */
static const struct chreq chreq_type_neci1[] = {
	{ 0xa0, 0xe0, CHREQ_T_EMERG_CALL },
	{ 0xc0, 0xe0, CHREQ_T_CALL_REEST_TCH_F },
	{ 0x68, 0xfc, CHREQ_T_CALL_REEST_TCH_H },
	{ 0x6c, 0xfc, CHREQ_T_CALL_REEST_TCH_H_DBL },
	{ 0xe0, 0xe0, CHREQ_T_TCH_F },
	{ 0x40, 0xf0, CHREQ_T_VOICE_CALL_TCH_H },
	{ 0x50, 0xf0, CHREQ_T_DATA_CALL_TCH_H },
	{ 0x00, 0xf0, CHREQ_T_LOCATION_UPD },
	{ 0x10, 0xf0, CHREQ_T_SDCCH },
	{ 0x80, 0xe0, CHREQ_T_PAG_R_ANY_NECI1 },
	{ 0x20, 0xf0, CHREQ_T_PAG_R_TCH_F },
	{ 0x30, 0xf0, CHREQ_T_PAG_R_TCH_FH },
	{ 0x67, 0xff, CHREQ_T_LMU },
	{ 0x60, 0xf9, CHREQ_T_RESERVED_SDCCH },
	{ 0x61, 0xfb, CHREQ_T_RESERVED_SDCCH },
	{ 0x63,	0xff, CHREQ_T_RESERVED_SDCCH },
	{ 0x7f, 0xff, CHREQ_T_RESERVED_IGNORE },
};

/* If SYSTEM INFORMATION TYPE 4 NECI bit == 0 */
static const struct chreq chreq_type_neci0[] = {
	{ 0xa0, 0xe0, CHREQ_T_EMERG_CALL },
	{ 0xc0, 0xe0, CHREQ_T_CALL_REEST_TCH_H },
	{ 0xe0, 0xe0, CHREQ_T_TCH_F },
	{ 0x50, 0xf0, CHREQ_T_DATA_CALL_TCH_H },
	{ 0x00, 0xe0, CHREQ_T_LOCATION_UPD },
	{ 0x80, 0xe0, CHREQ_T_PAG_R_ANY_NECI0 },
	{ 0x20, 0xf0, CHREQ_T_PAG_R_TCH_F },
	{ 0x30, 0xf0, CHREQ_T_PAG_R_TCH_FH },
	{ 0x67, 0xff, CHREQ_T_LMU },
	{ 0x60, 0xf9, CHREQ_T_RESERVED_SDCCH },
	{ 0x61, 0xfb, CHREQ_T_RESERVED_SDCCH },
	{ 0x63,	0xff, CHREQ_T_RESERVED_SDCCH },
	{ 0x7f, 0xff, CHREQ_T_RESERVED_IGNORE },
};

static const enum gsm_chan_t ctype_by_chreq[] = {
	[CHREQ_T_EMERG_CALL]		= GSM_LCHAN_TCH_F,
	[CHREQ_T_CALL_REEST_TCH_F]	= GSM_LCHAN_TCH_F,
	[CHREQ_T_CALL_REEST_TCH_H]	= GSM_LCHAN_TCH_H,
	[CHREQ_T_CALL_REEST_TCH_H_DBL]	= GSM_LCHAN_TCH_H,
	[CHREQ_T_SDCCH]			= GSM_LCHAN_SDCCH,
	[CHREQ_T_TCH_F]			= GSM_LCHAN_TCH_F,
	[CHREQ_T_VOICE_CALL_TCH_H]	= GSM_LCHAN_TCH_H,
	[CHREQ_T_DATA_CALL_TCH_H]	= GSM_LCHAN_TCH_H,
	[CHREQ_T_LOCATION_UPD]		= GSM_LCHAN_SDCCH,
	[CHREQ_T_PAG_R_ANY_NECI1]	= GSM_LCHAN_SDCCH,
	[CHREQ_T_PAG_R_ANY_NECI0]	= GSM_LCHAN_SDCCH,
	[CHREQ_T_PAG_R_TCH_F]		= GSM_LCHAN_TCH_F,
	[CHREQ_T_PAG_R_TCH_FH]		= GSM_LCHAN_TCH_F,
	[CHREQ_T_LMU]			= GSM_LCHAN_SDCCH,
	[CHREQ_T_RESERVED_SDCCH]	= GSM_LCHAN_SDCCH,
	[CHREQ_T_RESERVED_IGNORE]	= GSM_LCHAN_UNKNOWN,
};

static const enum gsm_chreq_reason_t reason_by_chreq[] = {
	[CHREQ_T_EMERG_CALL]		= GSM_CHREQ_REASON_EMERG,
	[CHREQ_T_CALL_REEST_TCH_F]	= GSM_CHREQ_REASON_CALL,
	[CHREQ_T_CALL_REEST_TCH_H]	= GSM_CHREQ_REASON_CALL,
	[CHREQ_T_CALL_REEST_TCH_H_DBL]	= GSM_CHREQ_REASON_CALL,
	[CHREQ_T_SDCCH]			= GSM_CHREQ_REASON_OTHER,
	[CHREQ_T_TCH_F]			= GSM_CHREQ_REASON_OTHER,
	[CHREQ_T_VOICE_CALL_TCH_H]	= GSM_CHREQ_REASON_CALL,
	[CHREQ_T_DATA_CALL_TCH_H]	= GSM_CHREQ_REASON_OTHER,
	[CHREQ_T_LOCATION_UPD]		= GSM_CHREQ_REASON_LOCATION_UPD,
	[CHREQ_T_PAG_R_ANY_NECI1]	= GSM_CHREQ_REASON_PAG,
	[CHREQ_T_PAG_R_ANY_NECI0]	= GSM_CHREQ_REASON_PAG,
	[CHREQ_T_PAG_R_TCH_F]		= GSM_CHREQ_REASON_PAG,
	[CHREQ_T_PAG_R_TCH_FH]		= GSM_CHREQ_REASON_PAG,
	[CHREQ_T_LMU]			= GSM_CHREQ_REASON_OTHER,
	[CHREQ_T_RESERVED_SDCCH]	= GSM_CHREQ_REASON_OTHER,
	[CHREQ_T_RESERVED_IGNORE]	= GSM_CHREQ_REASON_OTHER,
};

/* verify that the two tables match */
osmo_static_assert(sizeof(ctype_by_chreq) ==
	      sizeof(((struct gsm_network *) NULL)->ctype_by_chreq), assert_size);

/*
 * Update channel types for request based on policy. E.g. in the
 * case of a TCH/H network/bsc use TCH/H for the emergency calls,
 * for early assignment assign a SDCCH and some other options.
 */
void gsm_net_update_ctype(struct gsm_network *network)
{
	/* copy over the data */
	memcpy(network->ctype_by_chreq, ctype_by_chreq, sizeof(ctype_by_chreq));

	/*
	 * Use TCH/H for emergency calls when this cell allows TCH/H. Maybe it
	 * is better to iterate over the BTS/TRX and check if no TCH/F is available
	 * and then set it to TCH/H.
	 */
	if (network->neci)
		network->ctype_by_chreq[CHREQ_T_EMERG_CALL] = GSM_LCHAN_TCH_H;

	if (network->pag_any_tch) {
		if (network->neci) {
			network->ctype_by_chreq[CHREQ_T_PAG_R_ANY_NECI0] = GSM_LCHAN_TCH_H;
			network->ctype_by_chreq[CHREQ_T_PAG_R_ANY_NECI1] = GSM_LCHAN_TCH_H;
		} else {
			network->ctype_by_chreq[CHREQ_T_PAG_R_ANY_NECI0] = GSM_LCHAN_TCH_F;
			network->ctype_by_chreq[CHREQ_T_PAG_R_ANY_NECI1] = GSM_LCHAN_TCH_F;
		}
	}
}

enum gsm_chan_t get_ctype_by_chreq(struct gsm_network *network, uint8_t ra)
{
	int i;
	int length;
	const struct chreq *chreq;

	if (network->neci) {
		chreq = chreq_type_neci1;
		length = ARRAY_SIZE(chreq_type_neci1);
	} else {
		chreq = chreq_type_neci0;
		length = ARRAY_SIZE(chreq_type_neci0);
	}


	for (i = 0; i < length; i++) {
		const struct chreq *chr = &chreq[i];
		if ((ra & chr->mask) == chr->val)
			return network->ctype_by_chreq[chr->type];
	}
	LOGP(DRR, LOGL_ERROR, "Unknown CHANNEL REQUEST RQD 0x%02x\n", ra);
	return GSM_LCHAN_SDCCH;
}

int get_reason_by_chreq(uint8_t ra, int neci)
{
	int i;
	int length;
	const struct chreq *chreq;

	if (neci) {
		chreq = chreq_type_neci1;
		length = ARRAY_SIZE(chreq_type_neci1);
	} else {
		chreq = chreq_type_neci0;
		length = ARRAY_SIZE(chreq_type_neci0);
	}

	for (i = 0; i < length; i++) {
		const struct chreq *chr = &chreq[i];
		if ((ra & chr->mask) == chr->val)
			return reason_by_chreq[chr->type];
	}
	LOGP(DRR, LOGL_ERROR, "Unknown CHANNEL REQUEST REASON 0x%02x\n", ra);
	return GSM_CHREQ_REASON_OTHER;
}

int gsm48_extract_mi(uint8_t *classmark2_lv, int length, char *mi_string, uint8_t *mi_type)
{
	/* Check the size for the classmark */
	if (length < 1 + *classmark2_lv)
		return -1;

	uint8_t *mi_lv = classmark2_lv + *classmark2_lv + 1;
	if (length < 2 + *classmark2_lv + mi_lv[0])
		return -2;

	*mi_type = mi_lv[1] & GSM_MI_TYPE_MASK;
	return gsm48_mi_to_string(mi_string, GSM48_MI_SIZE, mi_lv+1, *mi_lv);
}

int gsm48_paging_extract_mi(struct gsm48_pag_resp *resp, int length,
			    char *mi_string, uint8_t *mi_type)
{
	static const uint32_t classmark_offset =
		offsetof(struct gsm48_pag_resp, classmark2);
	uint8_t *classmark2_lv = (uint8_t *) &resp->classmark2;
	return gsm48_extract_mi(classmark2_lv, length - classmark_offset,
				mi_string, mi_type);
}

struct msgb *gsm48_create_loc_upd_rej(uint8_t cause)
{
	struct gsm48_hdr *gh;
	struct msgb *msg;

	msg = gsm48_msgb_alloc();
	if (!msg)
		return NULL;

	gh = (struct gsm48_hdr *) msgb_put(msg, sizeof(*gh) + 1);
	gh->proto_discr = GSM48_PDISC_MM;
	gh->msg_type = GSM48_MT_MM_LOC_UPD_REJECT;
	gh->data[0] = cause;
	return msg;
}

struct msgb *gsm48_create_mm_serv_rej(enum gsm48_reject_value value)
{
	struct msgb *msg;
	struct gsm48_hdr *gh;

	msg = gsm48_msgb_alloc();
	if (!msg)
		return NULL;

	gh = (struct gsm48_hdr *) msgb_put(msg, sizeof(*gh) + 1);
	gh->proto_discr = GSM48_PDISC_MM;
	gh->msg_type = GSM48_MT_MM_CM_SERV_REJ;
	gh->data[0] = value;

	return msg;
}
