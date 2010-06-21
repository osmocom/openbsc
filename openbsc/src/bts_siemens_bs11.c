/* Siemens BS-11 specific code */

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

static struct gsm_bts_model model_bs11 = {
	.type = GSM_BTS_TYPE_BS11,
	.nm_att_tlvdef = {
		.def = {
			[NM_ATT_AVAIL_STATUS] =		{ TLV_TYPE_TLV },
			/* BS11 specifics */
			[NM_ATT_BS11_ESN_FW_CODE_NO] =	{ TLV_TYPE_TLV },
			[NM_ATT_BS11_ESN_HW_CODE_NO] =	{ TLV_TYPE_TLV },
			[NM_ATT_BS11_ESN_PCB_SERIAL] =	{ TLV_TYPE_TLV },
			[NM_ATT_BS11_BOOT_SW_VERS] =	{ TLV_TYPE_TLV },
			[0xd5] =			{ TLV_TYPE_TLV },
			[0xa8] =			{ TLV_TYPE_TLV },
			[NM_ATT_BS11_PASSWORD] =	{ TLV_TYPE_TLV },
			[NM_ATT_BS11_TXPWR] =		{ TLV_TYPE_TLV },
			[NM_ATT_BS11_RSSI_OFFS] =	{ TLV_TYPE_TLV },
			[NM_ATT_BS11_LINE_CFG] = 	{ TLV_TYPE_TV },
			[NM_ATT_BS11_L1_PROT_TYPE] =	{ TLV_TYPE_TV },
			[NM_ATT_BS11_BIT_ERR_THESH] =	{ TLV_TYPE_FIXED, 2 },
			[NM_ATT_BS11_DIVERSITY] =	{ TLV_TYPE_TLV },
			[NM_ATT_BS11_LMT_LOGON_SESSION]={ TLV_TYPE_TLV },	
			[NM_ATT_BS11_LMT_LOGIN_TIME] =	{ TLV_TYPE_TLV },
			[NM_ATT_BS11_LMT_USER_ACC_LEV] ={ TLV_TYPE_TLV },
			[NM_ATT_BS11_LMT_USER_NAME] =	{ TLV_TYPE_TLV },
			[NM_ATT_BS11_BTS_STATE]	=	{ TLV_TYPE_TLV },
			[NM_ATT_BS11_E1_STATE]	=	{ TLV_TYPE_TLV },
			[NM_ATT_BS11_PLL_MODE]	=	{ TLV_TYPE_TLV },
			[NM_ATT_BS11_PLL]	=	{ TLV_TYPE_TLV },
			[NM_ATT_BS11_CCLK_ACCURACY] =	{ TLV_TYPE_TV },
			[NM_ATT_BS11_CCLK_TYPE] =	{ TLV_TYPE_TV },
			[0x95] =			{ TLV_TYPE_FIXED, 2 },
		},
	},
};

int bts_model_bs11_init(void)
{
	model_bs11.features.data = &model_bs11._features_data[0];
	model_bs11.features.data_len = sizeof(model_bs11._features_data);

	gsm_btsmodel_set_feature(&model_bs11, BTS_FEAT_HOPPING);
	gsm_btsmodel_set_feature(&model_bs11, BTS_FEAT_HSCSD);

	return gsm_bts_model_register(&model_bs11);
}
