/* ip.access nanoBTS specific code */

/* (C) 2009-2010 by Harald Welte <laforge@gnumonks.org>
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

#include <sys/types.h>

#include <openbsc/gsm_data.h>
#include <osmocore/tlv.h>
#include <openbsc/abis_nm.h>

static struct gsm_bts_model model_nanobts = {
	.type = GSM_BTS_TYPE_NANOBTS,
	.nm_att_tlvdef = {
		.def = {
			/* ip.access specifics */
			[NM_ATT_IPACC_DST_IP] =		{ TLV_TYPE_FIXED, 4 },
			[NM_ATT_IPACC_DST_IP_PORT] =	{ TLV_TYPE_FIXED, 2 },
			[NM_ATT_IPACC_STREAM_ID] =	{ TLV_TYPE_TV, },
			[NM_ATT_IPACC_FREQ_CTRL] =	{ TLV_TYPE_TV, },
			[NM_ATT_IPACC_SEC_OML_CFG] =	{ TLV_TYPE_FIXED, 6 },
			[NM_ATT_IPACC_IP_IF_CFG] =	{ TLV_TYPE_FIXED, 8 },
			[NM_ATT_IPACC_IP_GW_CFG] =	{ TLV_TYPE_FIXED, 12 },
			[NM_ATT_IPACC_IN_SERV_TIME] =	{ TLV_TYPE_FIXED, 4 },
			[NM_ATT_IPACC_LOCATION] =	{ TLV_TYPE_TL16V },
			[NM_ATT_IPACC_PAGING_CFG] =	{ TLV_TYPE_FIXED, 2 },
			[NM_ATT_IPACC_UNIT_ID] =	{ TLV_TYPE_TL16V },
			[NM_ATT_IPACC_UNIT_NAME] =	{ TLV_TYPE_TL16V },
			[NM_ATT_IPACC_SNMP_CFG] =	{ TLV_TYPE_TL16V },
			[NM_ATT_IPACC_PRIM_OML_CFG_LIST] = { TLV_TYPE_TL16V },
			[NM_ATT_IPACC_NV_FLAGS] =	{ TLV_TYPE_TL16V },
			[NM_ATT_IPACC_FREQ_CTRL] =	{ TLV_TYPE_FIXED, 2 },
			[NM_ATT_IPACC_PRIM_OML_FB_TOUT] = { TLV_TYPE_TL16V },
			[NM_ATT_IPACC_CUR_SW_CFG] =	{ TLV_TYPE_TL16V },
			[NM_ATT_IPACC_TIMING_BUS] =	{ TLV_TYPE_TL16V },
			[NM_ATT_IPACC_CGI] =		{ TLV_TYPE_TL16V },
			[NM_ATT_IPACC_RAC] =		{ TLV_TYPE_TL16V },
			[NM_ATT_IPACC_OBJ_VERSION] =	{ TLV_TYPE_TL16V },
			[NM_ATT_IPACC_GPRS_PAGING_CFG]= { TLV_TYPE_TL16V },
			[NM_ATT_IPACC_NSEI] =		{ TLV_TYPE_TL16V },
			[NM_ATT_IPACC_BVCI] =		{ TLV_TYPE_TL16V },
			[NM_ATT_IPACC_NSVCI] =		{ TLV_TYPE_TL16V },
			[NM_ATT_IPACC_NS_CFG] =		{ TLV_TYPE_TL16V },
			[NM_ATT_IPACC_BSSGP_CFG] =	{ TLV_TYPE_TL16V },
			[NM_ATT_IPACC_NS_LINK_CFG] =	{ TLV_TYPE_TL16V },
			[NM_ATT_IPACC_RLC_CFG] =	{ TLV_TYPE_TL16V },
			[NM_ATT_IPACC_ALM_THRESH_LIST]=	{ TLV_TYPE_TL16V },
			[NM_ATT_IPACC_MONIT_VAL_LIST] = { TLV_TYPE_TL16V },
			[NM_ATT_IPACC_TIB_CONTROL] =	{ TLV_TYPE_TL16V },
			[NM_ATT_IPACC_SUPP_FEATURES] =	{ TLV_TYPE_TL16V },
			[NM_ATT_IPACC_CODING_SCHEMES] =	{ TLV_TYPE_TL16V },
			[NM_ATT_IPACC_RLC_CFG_2] =	{ TLV_TYPE_TL16V },
			[NM_ATT_IPACC_HEARTB_TOUT] =	{ TLV_TYPE_TL16V },
			[NM_ATT_IPACC_UPTIME] =		{ TLV_TYPE_TL16V },
			[NM_ATT_IPACC_RLC_CFG_3] =	{ TLV_TYPE_TL16V },
			[NM_ATT_IPACC_SSL_CFG] =	{ TLV_TYPE_TL16V },
			[NM_ATT_IPACC_SEC_POSSIBLE] =	{ TLV_TYPE_TL16V },
			[NM_ATT_IPACC_IML_SSL_STATE] =	{ TLV_TYPE_TL16V },
			[NM_ATT_IPACC_REVOC_DATE] =	{ TLV_TYPE_TL16V },
		},
	},
};

int bts_model_nanobts_init(void)
{
	model_nanobts.features.data = &model_nanobts._features_data;
	model_nanobts.features.data_len = sizeof(model_nanobts._features_data);

	gsm_btsmodel_set_feature(&model_nanobts, BTS_FEAT_GPRS);
	gsm_btsmodel_set_feature(&model_nanobts, BTS_FEAT_EGPRS);

	return gsm_bts_model_register(&model_nanobts);
}
