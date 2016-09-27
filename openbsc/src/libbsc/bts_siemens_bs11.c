/* Siemens BS-11 specific code */

/* (C) 2009-2010 by Harald Welte <laforge@gnumonks.org>
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


#include <osmocom/gsm/tlv.h>

#include <openbsc/debug.h>
#include <openbsc/gsm_data.h>
#include <openbsc/abis_nm.h>
#include <osmocom/abis/e1_input.h>
#include <openbsc/signal.h>

static int bts_model_bs11_start(struct gsm_network *net);

static void bts_model_bs11_e1line_bind_ops(struct e1inp_line *line)
{
	e1inp_line_bind_ops(line, &bts_isdn_e1inp_line_ops);
}

static struct gsm_bts_model model_bs11 = {
	.type = GSM_BTS_TYPE_BS11,
	.name = "bs11",
	.start = bts_model_bs11_start,
	.oml_rcvmsg = &abis_nm_rcvmsg,
	.e1line_bind_ops = bts_model_bs11_e1line_bind_ops,
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

/* The following definitions are for OM and NM packets that we cannot yet
 * generate by code but we just pass on */

// BTS Site Manager, SET ATTRIBUTES

/*
  Object Class: BTS Site Manager
  Instance 1: FF
  Instance 2: FF
  Instance 3: FF
SET ATTRIBUTES
  sAbisExternalTime: 2007/09/08   14:36:11
  omLAPDRelTimer: 30sec
  shortLAPDIntTimer: 5sec
  emergencyTimer1: 10 minutes
  emergencyTimer2: 0 minutes
*/

unsigned char msg_1[] =
{
	NM_MT_BS11_SET_ATTR, NM_OC_SITE_MANAGER, 0xFF, 0xFF, 0xFF,
		NM_ATT_BS11_ABIS_EXT_TIME, 0x07,
			0xD7, 0x09, 0x08, 0x0E, 0x24, 0x0B, 0xCE,
		0x02,
			0x00, 0x1E,
		NM_ATT_BS11_SH_LAPD_INT_TIMER,
			0x01, 0x05,
		0x42, 0x02, 0x00, 0x0A,
		0x44, 0x02, 0x00, 0x00
};

// BTS, SET BTS ATTRIBUTES

/*
  Object Class: BTS
  BTS relat. Number: 0
  Instance 2: FF
  Instance 3: FF
SET BTS ATTRIBUTES
  bsIdentityCode / BSIC:
    PLMN_colour_code: 7h
    BS_colour_code:   7h
  BTS Air Timer T3105: 4  ,unit 10 ms
  btsIsHopping: FALSE
  periodCCCHLoadIndication: 1sec
  thresholdCCCHLoadIndication: 0%
  cellAllocationNumber: 00h = GSM 900
  enableInterferenceClass: 00h =  Disabled
  fACCHQual: 6 (FACCH stealing flags minus 1)
  intaveParameter: 31 SACCH multiframes
  interferenceLevelBoundaries:
    Interference Boundary 1: 0Ah
    Interference Boundary 2: 0Fh
    Interference Boundary 3: 14h
    Interference Boundary 4: 19h
    Interference Boundary 5: 1Eh
  mSTxPwrMax: 11
      GSM range:     2=39dBm, 15=13dBm, stepsize 2 dBm
      DCS1800 range: 0=30dBm, 15=0dBm, stepsize 2 dBm
      PCS1900 range: 0=30dBm, 15=0dBm, stepsize 2 dBm
                    30=33dBm, 31=32dBm
  ny1:
    Maximum number of repetitions for PHYSICAL INFORMATION message (GSM 04.08): 20
  powerOutputThresholds:
    Out Power Fault Threshold:     -10 dB
    Red Out Power Threshold:       - 6 dB
    Excessive Out Power Threshold:   5 dB
  rACHBusyThreshold: -127 dBm
  rACHLoadAveragingSlots: 250 ,number of RACH burst periods
  rfResourceIndicationPeriod: 125  SACCH multiframes
  T200:
    SDCCH:                044 in  5 ms
    FACCH/Full rate:      031 in  5 ms
    FACCH/Half rate:      041 in  5 ms
    SACCH with TCH SAPI0: 090 in 10 ms
    SACCH with SDCCH:     090 in 10 ms
    SDCCH with SAPI3:     090 in  5 ms
    SACCH with TCH SAPI3: 135 in 10 ms
  tSync: 9000 units of 10 msec
  tTrau: 9000 units of 10 msec
  enableUmLoopTest: 00h =  disabled
  enableExcessiveDistance: 00h =  Disabled
  excessiveDistance: 64km
  hoppingMode: 00h = baseband hopping
  cellType: 00h =  Standard Cell
  BCCH ARFCN / bCCHFrequency: 1
*/

static unsigned char bs11_attr_bts[] =
{
		NM_ATT_BSIC, HARDCODED_BSIC,
		NM_ATT_BTS_AIR_TIMER, 0x04,
		NM_ATT_BS11_BTSLS_HOPPING, 0x00,
		NM_ATT_CCCH_L_I_P, 0x01,
		NM_ATT_CCCH_L_T, 0x00,
		NM_ATT_BS11_CELL_ALLOC_NR, NM_BS11_CANR_GSM,
		NM_ATT_BS11_ENA_INTERF_CLASS, 0x01,
		NM_ATT_BS11_FACCH_QUAL, 0x06,
		/* interference avg. period in numbers of SACCH multifr */
		NM_ATT_INTAVE_PARAM, 0x1F,
		NM_ATT_INTERF_BOUND, 0x0A, 0x0F, 0x14, 0x19, 0x1E, 0x7B,
		NM_ATT_CCCH_L_T, 0x23,
		NM_ATT_GSM_TIME, 0x28, 0x00,
		NM_ATT_ADM_STATE, 0x03,
		NM_ATT_RACH_B_THRESH, 0x7F,
		NM_ATT_LDAVG_SLOTS, 0x00, 0xFA,
		NM_ATT_BS11_RF_RES_IND_PER, 0x7D,
		NM_ATT_T200, 0x2C, 0x1F, 0x29, 0x5A, 0x5A, 0x5A, 0x87,
		NM_ATT_BS11_TSYNC, 0x23, 0x28,
		NM_ATT_BS11_TTRAU, 0x23, 0x28,
		NM_ATT_TEST_DUR, 0x01, 0x00,
		NM_ATT_OUTST_ALARM, 0x01, 0x00,
		NM_ATT_BS11_EXCESSIVE_DISTANCE, 0x01, 0x40,
		NM_ATT_BS11_HOPPING_MODE, 0x01, 0x00,
		NM_ATT_BS11_PLL, 0x01, 0x00,
		NM_ATT_BCCH_ARFCN, 0x00, HARDCODED_ARFCN/*0x01*/,
};

// Handover Recognition, SET ATTRIBUTES

/*
Illegal Contents GSM Formatted O&M Msg
  Object Class: Handover Recognition
  BTS relat. Number: 0
  Instance 2: FF
  Instance 3: FF
SET ATTRIBUTES
  enableDelayPowerBudgetHO: 00h = Disabled
  enableDistanceHO: 00h =  Disabled
  enableInternalInterCellHandover: 00h = Disabled
  enableInternalIntraCellHandover: 00h =  Disabled
  enablePowerBudgetHO: 00h = Disabled
  enableRXLEVHO: 00h =  Disabled
  enableRXQUALHO: 00h =  Disabled
  hoAveragingDistance: 8  SACCH multiframes
  hoAveragingLev:
    A_LEV_HO: 8  SACCH multiframes
    W_LEV_HO: 1  SACCH multiframes
  hoAveragingPowerBudget:  16  SACCH multiframes
  hoAveragingQual:
    A_QUAL_HO: 8  SACCH multiframes
    W_QUAL_HO: 2  SACCH multiframes
  hoLowerThresholdLevDL: (10 - 110) dBm
  hoLowerThresholdLevUL: (5 - 110) dBm
  hoLowerThresholdQualDL: 06h =   6.4% < BER < 12.8%
  hoLowerThresholdQualUL: 06h =   6.4% < BER < 12.8%
  hoThresholdLevDLintra : (20 - 110) dBm
  hoThresholdLevULintra: (20 - 110) dBm
  hoThresholdMsRangeMax: 20 km
  nCell: 06h
  timerHORequest: 3  ,unit 2 SACCH multiframes
*/

unsigned char msg_3[] =
{
	NM_MT_BS11_SET_ATTR, NM_OC_BS11_HANDOVER, 0x00, 0xFF, 0xFF,
		0xD0, 0x00,		/* enableDelayPowerBudgetHO */
		0x64, 0x00,		/* enableDistanceHO */
		0x67, 0x00,		/* enableInternalInterCellHandover */
		0x68, 0x00,		/* enableInternalInterCellHandover */
		0x6A, 0x00,		/* enablePowerBudgetHO */
		0x6C, 0x00,		/* enableRXLEVHO */
		0x6D, 0x00,		/* enableRXQUALHO */
		0x6F, 0x08,		/* hoAveragingDistance */
		0x70, 0x08, 0x01,	/* hoAveragingLev */
		0x71, 0x10, 0x10, 0x10,
		0x72, 0x08, 0x02,	/* hoAveragingQual */
		0x73, 0x0A,		/* hoLowerThresholdLevDL */
		0x74, 0x05,		/* hoLowerThresholdLevUL */
		0x75, 0x06,		/* hoLowerThresholdQualDL */
		0x76, 0x06,		/* hoLowerThresholdQualUL */
		0x78, 0x14,		/* hoThresholdLevDLintra */
		0x79, 0x14,		/* hoThresholdLevULintra */
		0x7A, 0x14,		/* hoThresholdMsRangeMax */
		0x7D, 0x06,		/* nCell */
		NM_ATT_BS11_TIMER_HO_REQUEST, 0x03,
		0x20, 0x01, 0x00,
		0x45, 0x01, 0x00,
		0x48, 0x01, 0x00,
		0x5A, 0x01, 0x00,
		0x5B, 0x01, 0x05,
		0x5E, 0x01, 0x1A,
		0x5F, 0x01, 0x20,
		0x9D, 0x01, 0x00,
		0x47, 0x01, 0x00,
		0x5C, 0x01, 0x64,
		0x5D, 0x01, 0x1E,
		0x97, 0x01, 0x20,
		0xF7, 0x01, 0x3C,
};

// Power Control, SET ATTRIBUTES

/*
  Object Class: Power Control
  BTS relat. Number: 0
  Instance 2: FF
  Instance 3: FF
SET ATTRIBUTES
  enableMsPowerControl: 00h =  Disabled
  enablePowerControlRLFW: 00h =  Disabled
  pcAveragingLev:
    A_LEV_PC: 4  SACCH multiframes
    W_LEV_PC: 1  SACCH multiframes
  pcAveragingQual:
    A_QUAL_PC: 4  SACCH multiframes
    W_QUAL_PC: 2  SACCH multiframes
  pcLowerThresholdLevDL: 0Fh
  pcLowerThresholdLevUL: 0Ah
  pcLowerThresholdQualDL: 05h =   3.2% < BER <  6.4%
  pcLowerThresholdQualUL: 05h =   3.2% < BER <  6.4%
  pcRLFThreshold: 0Ch
  pcUpperThresholdLevDL: 14h
  pcUpperThresholdLevUL: 0Fh
  pcUpperThresholdQualDL: 04h =   1.6% < BER <  3.2%
  pcUpperThresholdQualUL: 04h =   1.6% < BER <  3.2%
  powerConfirm: 2  ,unit 2 SACCH multiframes
  powerControlInterval: 2  ,unit 2 SACCH multiframes
  powerIncrStepSize: 02h = 4 dB
  powerRedStepSize: 01h = 2 dB
  radioLinkTimeoutBs: 64  SACCH multiframes
  enableBSPowerControl: 00h =  disabled
*/

unsigned char msg_4[] =
{
	NM_MT_BS11_SET_ATTR, NM_OC_BS11_PWR_CTRL, 0x00, 0xFF, 0xFF,
		NM_ATT_BS11_ENA_MS_PWR_CTRL, 0x00,
		NM_ATT_BS11_ENA_PWR_CTRL_RLFW, 0x00,
		0x7E, 0x04, 0x01,	/* pcAveragingLev */
		0x7F, 0x04, 0x02,	/* pcAveragingQual */
		0x80, 0x0F,		/* pcLowerThresholdLevDL */
		0x81, 0x0A,		/* pcLowerThresholdLevUL */
		0x82, 0x05,		/* pcLowerThresholdQualDL */
		0x83, 0x05,		/* pcLowerThresholdQualUL */
		0x84, 0x0C, 		/* pcRLFThreshold */
		0x85, 0x14, 		/* pcUpperThresholdLevDL */
		0x86, 0x0F, 		/* pcUpperThresholdLevUL */
		0x87, 0x04,		/* pcUpperThresholdQualDL */
		0x88, 0x04,		/* pcUpperThresholdQualUL */
		0x89, 0x02,		/* powerConfirm */
		0x8A, 0x02,		/* powerConfirmInterval */
		0x8B, 0x02,		/* powerIncrStepSize */
		0x8C, 0x01,		/* powerRedStepSize */
		0x8D, 0x40,		/* radioLinkTimeoutBs */
		0x65, 0x01, 0x00 // set to 0x01 to enable BSPowerControl
};


// Transceiver, SET TRX ATTRIBUTES (TRX 0)

/*
  Object Class: Transceiver
  BTS relat. Number: 0
  Tranceiver number: 0
  Instance 3: FF
SET TRX ATTRIBUTES
  aRFCNList (HEX):  0001
  txPwrMaxReduction: 00h =   30dB
  radioMeasGran: 254  SACCH multiframes
  radioMeasRep: 01h =  enabled
  memberOfEmergencyConfig: 01h =  TRUE
  trxArea: 00h = TRX doesn't belong to a concentric cell
*/

static unsigned char bs11_attr_radio[] =
{
		NM_ATT_ARFCN_LIST, 0x01, 0x00, HARDCODED_ARFCN /*0x01*/,
		NM_ATT_RF_MAXPOWR_R, 0x00,
		NM_ATT_BS11_RADIO_MEAS_GRAN, 0x01, 0x05,
		NM_ATT_BS11_RADIO_MEAS_REP, 0x01, 0x01,
		NM_ATT_BS11_EMRG_CFG_MEMBER, 0x01, 0x01,
		NM_ATT_BS11_TRX_AREA, 0x01, 0x00,
};

/*
 * Patch the various SYSTEM INFORMATION tables to update
 * the LAI
 */
static void patch_nm_tables(struct gsm_bts *bts)
{
	uint8_t arfcn_low = bts->c0->arfcn & 0xff;
	uint8_t arfcn_high = (bts->c0->arfcn >> 8) & 0x0f;

	/* T3105 attribute in units of 10ms */
	bs11_attr_bts[2] = bts->network->T3105 / 10;

	/* patch ARFCN into BTS Attributes */
	bs11_attr_bts[69] &= 0xf0;
	bs11_attr_bts[69] |= arfcn_high;
	bs11_attr_bts[70] = arfcn_low;

	/* patch ARFCN into TRX Attributes */
	bs11_attr_radio[2] &= 0xf0;
	bs11_attr_radio[2] |= arfcn_high;
	bs11_attr_radio[3] = arfcn_low;

	/* patch the RACH attributes */
	if (bts->rach_b_thresh != -1)
		bs11_attr_bts[33] = bts->rach_b_thresh & 0xff;

	if (bts->rach_ldavg_slots != -1) {
		uint8_t avg_high = bts->rach_ldavg_slots & 0xff;
		uint8_t avg_low = (bts->rach_ldavg_slots >> 8) & 0x0f;

		bs11_attr_bts[35] = avg_high;
		bs11_attr_bts[36] = avg_low;
	}

	/* patch BSIC */
	bs11_attr_bts[1] = bts->bsic;

	/* patch the power reduction */
	bs11_attr_radio[5] = bts->c0->max_power_red / 2;
}


static void nm_reconfig_ts(struct gsm_bts_trx_ts *ts)
{
	enum abis_nm_chan_comb ccomb = abis_nm_chcomb4pchan(ts->pchan);
	struct gsm_e1_subslot *e1l = &ts->e1_link;

	abis_nm_set_channel_attr(ts, ccomb);

	if (is_ipaccess_bts(ts->trx->bts))
		return;

	if (ts_is_tch(ts))
		abis_nm_conn_terr_traf(ts, e1l->e1_nr, e1l->e1_ts,
					e1l->e1_ts_ss);
}

static void nm_reconfig_trx(struct gsm_bts_trx *trx)
{
	struct gsm_e1_subslot *e1l = &trx->rsl_e1_link;
	int i;

	patch_nm_tables(trx->bts);

	switch (trx->bts->type) {
	case GSM_BTS_TYPE_BS11:
		/* FIXME: discover this by fetching an attribute */
#if 0
		trx->nominal_power = 15; /* 15dBm == 30mW PA configuration */
#else
		trx->nominal_power = 24; /* 24dBm == 250mW PA configuration */
#endif
		abis_nm_conn_terr_sign(trx, e1l->e1_nr, e1l->e1_ts,
					e1l->e1_ts_ss);
		abis_nm_establish_tei(trx->bts, trx->nr, e1l->e1_nr,
				      e1l->e1_ts, e1l->e1_ts_ss, trx->rsl_tei);

		/* Set Radio Attributes */
		if (trx == trx->bts->c0)
			abis_nm_set_radio_attr(trx, bs11_attr_radio,
					       sizeof(bs11_attr_radio));
		else {
			uint8_t trx1_attr_radio[sizeof(bs11_attr_radio)];
			uint8_t arfcn_low = trx->arfcn & 0xff;
			uint8_t arfcn_high = (trx->arfcn >> 8) & 0x0f;
			memcpy(trx1_attr_radio, bs11_attr_radio,
				sizeof(trx1_attr_radio));

			/* patch ARFCN into TRX Attributes */
			trx1_attr_radio[2] &= 0xf0;
			trx1_attr_radio[2] |= arfcn_high;
			trx1_attr_radio[3] = arfcn_low;

			abis_nm_set_radio_attr(trx, trx1_attr_radio,
					       sizeof(trx1_attr_radio));
		}
		break;
	case GSM_BTS_TYPE_NANOBTS:
		switch (trx->bts->band) {
		case GSM_BAND_850:
		case GSM_BAND_900:
			trx->nominal_power = 20;
			break;
		case GSM_BAND_1800:
		case GSM_BAND_1900:
			trx->nominal_power = 23;
			break;
		default:
			LOGP(DNM, LOGL_ERROR, "Unsupported nanoBTS GSM band %s\n",
				gsm_band_name(trx->bts->band));
			break;
		}
		break;
	default:
		break;
	}

	for (i = 0; i < TRX_NR_TS; i++)
		nm_reconfig_ts(&trx->ts[i]);
}

static void nm_reconfig_bts(struct gsm_bts *bts)
{
	struct gsm_bts_trx *trx;

	switch (bts->type) {
	case GSM_BTS_TYPE_BS11:
		patch_nm_tables(bts);
		abis_nm_raw_msg(bts, sizeof(msg_1), msg_1); /* set BTS SiteMgr attr*/
		abis_nm_set_bts_attr(bts, bs11_attr_bts, sizeof(bs11_attr_bts));
		abis_nm_raw_msg(bts, sizeof(msg_3), msg_3); /* set BTS handover attr */
		abis_nm_raw_msg(bts, sizeof(msg_4), msg_4); /* set BTS power control attr */
		break;
	default:
		break;
	}

	llist_for_each_entry(trx, &bts->trx_list, list)
		nm_reconfig_trx(trx);
}


static void bootstrap_om_bs11(struct gsm_bts *bts)
{
	LOGP(DNM, LOGL_NOTICE, "bootstrapping OML for BTS %u\n", bts->nr);

	/* stop sending event reports */
	abis_nm_event_reports(bts, 0);

	/* begin DB transmission */
	abis_nm_bs11_db_transmission(bts, 1);

	/* end DB transmission */
	abis_nm_bs11_db_transmission(bts, 0);

	/* Reset BTS Site manager resource */
	abis_nm_bs11_reset_resource(bts);

	/* begin DB transmission */
	abis_nm_bs11_db_transmission(bts, 1);

	/* reconfigure BTS with all TRX and all TS */
	nm_reconfig_bts(bts);

	/* end DB transmission */
	abis_nm_bs11_db_transmission(bts, 0);

	/* Reset BTS Site manager resource */
	abis_nm_bs11_reset_resource(bts);

	/* restart sending event reports */
	abis_nm_event_reports(bts, 1);
}

static int shutdown_om(struct gsm_bts *bts)
{
	/* stop sending event reports */
	abis_nm_event_reports(bts, 0);

	/* begin DB transmission */
	abis_nm_bs11_db_transmission(bts, 1);

	/* end DB transmission */
	abis_nm_bs11_db_transmission(bts, 0);

	/* Reset BTS Site manager resource */
	abis_nm_bs11_reset_resource(bts);

	return 0;
}

/* Callback function to be called every time we receive a signal from INPUT */
static int gbl_sig_cb(unsigned int subsys, unsigned int signal,
		      void *handler_data, void *signal_data)
{
	struct gsm_bts *bts;

	if (subsys != SS_L_GLOBAL)
		return 0;

	switch (signal) {
	case S_GLOBAL_BTS_CLOSE_OM:
		bts = signal_data;
		if (bts->type == GSM_BTS_TYPE_BS11)
			shutdown_om(signal_data);
		break;
	}

	return 0;
}

/* Callback function to be called every time we receive a signal from INPUT */
static int inp_sig_cb(unsigned int subsys, unsigned int signal,
		      void *handler_data, void *signal_data)
{
	struct input_signal_data *isd = signal_data;

	if (subsys != SS_L_INPUT)
		return 0;

	switch (signal) {
	case S_L_INP_TEI_UP:
		switch (isd->link_type) {
		case E1INP_SIGN_OML:
			if (isd->trx->bts->type == GSM_BTS_TYPE_BS11)
				bootstrap_om_bs11(isd->trx->bts);
			break;
		}
	}

	return 0;
}

static int bts_model_bs11_start(struct gsm_network *net)
{
	model_bs11.features.data = &model_bs11._features_data[0];
	model_bs11.features.data_len = sizeof(model_bs11._features_data);

	gsm_btsmodel_set_feature(&model_bs11, BTS_FEAT_HOPPING);
	gsm_btsmodel_set_feature(&model_bs11, BTS_FEAT_HSCSD);
	gsm_btsmodel_set_feature(&model_bs11, BTS_FEAT_MULTI_TSC);

	osmo_signal_register_handler(SS_L_INPUT, inp_sig_cb, NULL);
	osmo_signal_register_handler(SS_L_GLOBAL, gbl_sig_cb, NULL);

	return 0;
}

int bts_model_bs11_init(void)
{
	return gsm_bts_model_register(&model_bs11);
}
