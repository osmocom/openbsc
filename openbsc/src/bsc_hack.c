/* A hackish minimal BSC (+MSC +HLR) implementation */

/* (C) 2008-2009 by Harald Welte <laforge@gnumonks.org>
 * (C) 2009 by Holger Hans Peter Freyther <zecke@selfish.org>
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

#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <time.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <fcntl.h>
#include <sys/stat.h>

#define _GNU_SOURCE
#include <getopt.h>

#include <openbsc/db.h>
#include <openbsc/timer.h>
#include <openbsc/gsm_data.h>
#include <openbsc/gsm_utils.h>
#include <openbsc/gsm_04_08.h>
#include <openbsc/select.h>
#include <openbsc/abis_rsl.h>
#include <openbsc/abis_nm.h>
#include <openbsc/debug.h>
#include <openbsc/misdn.h>
#include <openbsc/telnet_interface.h>
#include <openbsc/paging.h>
#include <openbsc/e1_input.h>
#include <openbsc/signal.h>
#include <openbsc/talloc.h>

/* global pointer to the gsm network data structure */
static struct gsm_network *gsmnet;

/* MCC and MNC for the Location Area Identifier */
static int MCC = 1;
static int MNC = 1;
static int cardnr = 0;
static int release_l2 = 0;
static enum gsm_bts_type BTS_TYPE = GSM_BTS_TYPE_BS11;
static const char *database_name = "hlr.sqlite3";
static const char *config_file = "openbsc.cfg";
extern int ipacc_rtp_direct;


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

static unsigned char nanobts_attr_bts[] = {
	NM_ATT_INTERF_BOUND, 0x55, 0x5b, 0x61, 0x67, 0x6d, 0x73,
	/* interference avg. period in numbers of SACCH multifr */
	NM_ATT_INTAVE_PARAM, 0x06,
	/* conn fail based on SACCH error rate */
	NM_ATT_CONN_FAIL_CRIT, 0x00, 0x02, 0x01, 0x10, 
	NM_ATT_T200, 0x1e, 0x24, 0x24, 0xa8, 0x34, 0x21, 0xa8,
	NM_ATT_MAX_TA, 0x3f,
	NM_ATT_OVERL_PERIOD, 0x00, 0x01, 10, /* seconds */
	NM_ATT_CCCH_L_T, 10, /* percent */
	NM_ATT_CCCH_L_I_P, 1, /* seconds */
	NM_ATT_RACH_B_THRESH, 10, /* busy threshold in - dBm */
	NM_ATT_LDAVG_SLOTS, 0x03, 0xe8, /* rach load averaging 1000 slots */
	NM_ATT_BTS_AIR_TIMER, 128, /* miliseconds */
	NM_ATT_NY1, 10, /* 10 retransmissions of physical config */
	NM_ATT_BCCH_ARFCN, HARDCODED_ARFCN >> 8, HARDCODED_ARFCN & 0xff,
	NM_ATT_BSIC, HARDCODED_BSIC,
};

static unsigned char nanobts_attr_radio[] = {
	NM_ATT_RF_MAXPOWR_R, 0x0c, /* number of -2dB reduction steps / Pn */
	NM_ATT_ARFCN_LIST, 0x00, 0x02, HARDCODED_ARFCN >> 8, HARDCODED_ARFCN & 0xff,
};

static unsigned char nanobts_attr_e0[] = {
	NM_ATT_IPACC_STREAM_ID, 0x00,
	NM_ATT_IPACC_DST_IP_PORT, 0x0b, 0xbb,	/* TCP PORT for RSL */
};

/* Callback function to be called whenever we get a GSM 12.21 state change event */
int nm_state_event(enum nm_evt evt, u_int8_t obj_class, void *obj,
		   struct gsm_nm_state *old_state, struct gsm_nm_state *new_state)
{
	struct gsm_bts *bts;
	struct gsm_bts_trx *trx;
	struct gsm_bts_trx_ts *ts;

	/* This is currently only required on nanoBTS */

	switch (evt) {
	case EVT_STATECHG_OPER:
		switch (obj_class) {
		case NM_OC_SITE_MANAGER:
			bts = container_of(obj, struct gsm_bts, site_mgr);
			if (old_state->operational != 2 && new_state->operational == 2) {
				abis_nm_opstart(bts, NM_OC_SITE_MANAGER, 0xff, 0xff, 0xff);
			}
			break;
		case NM_OC_BTS:
			bts = obj;
			if (new_state->availability == 5) {
				abis_nm_set_bts_attr(bts, nanobts_attr_bts,
							sizeof(nanobts_attr_bts));
				abis_nm_opstart(bts, NM_OC_BTS,
						bts->bts_nr, 0xff, 0xff);
				abis_nm_chg_adm_state(bts, NM_OC_BTS,
						      bts->bts_nr, 0xff, 0xff,
						      NM_STATE_UNLOCKED);
			}
			break;
		case NM_OC_CHANNEL:
			ts = obj;
			trx = ts->trx;
			if (new_state->availability == 5) {
				if (ts->nr == 0 && trx == trx->bts->c0)
					abis_nm_set_channel_attr(ts, NM_CHANC_BCCHComb);
				else
					abis_nm_set_channel_attr(ts, NM_CHANC_TCHFull);
				abis_nm_opstart(trx->bts, NM_OC_CHANNEL,
						trx->bts->bts_nr, trx->nr, ts->nr);
				abis_nm_chg_adm_state(trx->bts, NM_OC_CHANNEL,
						      trx->bts->bts_nr, trx->nr, ts->nr,
						      NM_STATE_UNLOCKED);
			}
			break;
		default:
			break;
		}
		break;
	default:
		//DEBUGP(DMM, "Unhandled state change in %s:%d\n", __func__, __LINE__);
		break;
	}
	return 0;
}

/* Callback function to be called every time we receive a 12.21 SW activated report */
static int sw_activ_rep(struct msgb *mb)
{
	struct abis_om_fom_hdr *foh = msgb_l3(mb);
	struct gsm_bts_trx *trx = mb->trx;

	switch (foh->obj_class) {
	case NM_OC_BASEB_TRANSC:
		/* TRX software is active, tell it to initiate RSL Link */
		abis_nm_ipaccess_msg(trx->bts, 0xe0, NM_OC_BASEB_TRANSC,
				     trx->bts->bts_nr, trx->nr, 0xff,
				     nanobts_attr_e0, sizeof(nanobts_attr_e0));
		abis_nm_opstart(trx->bts, NM_OC_BASEB_TRANSC, 
				trx->bts->bts_nr, trx->nr, 0xff);
		abis_nm_chg_adm_state(trx->bts, NM_OC_BASEB_TRANSC, 
					trx->bts->bts_nr, trx->nr, 0xff,
					NM_STATE_UNLOCKED);
		break;
	case NM_OC_RADIO_CARRIER:
		abis_nm_set_radio_attr(trx, nanobts_attr_radio,
					sizeof(nanobts_attr_radio));
		abis_nm_opstart(trx->bts, NM_OC_RADIO_CARRIER,
				trx->bts->bts_nr, trx->nr, 0xff);
		abis_nm_chg_adm_state(trx->bts, NM_OC_RADIO_CARRIER,
				      trx->bts->bts_nr, trx->nr, 0xff,
				      NM_STATE_UNLOCKED);
		break;
	}
	return 0;
}

/* Callback function for NACK on the OML NM */
static int oml_msg_nack(int mt)
{
	if (mt == NM_MT_SET_BTS_ATTR_NACK) {
		fprintf(stderr, "Failed to set BTS attributes. That is fatal. "
				"Was the bts type and frequency properly specified?\n");
		exit(-1);
	}

	return 0;
}

/* Callback function to be called every time we receive a signal from NM */
static int nm_sig_cb(unsigned int subsys, unsigned int signal,
		     void *handler_data, void *signal_data)
{
	switch (signal) {
	case S_NM_SW_ACTIV_REP:
		return sw_activ_rep(signal_data);
	case S_NM_NACK:
		return oml_msg_nack((int)signal_data);
	default:
		break;
	}
	return 0;
}

static void bootstrap_om_nanobts(struct gsm_bts *bts)
{
	/* We don't do callback based bootstrapping, but event driven (see above) */
}

static void nm_reconfig_ts(struct gsm_bts_trx_ts *ts)
{
	enum abis_nm_chan_comb ccomb = abis_nm_chcomb4pchan(ts->pchan);
	struct gsm_e1_subslot *e1l = &ts->e1_link;

	abis_nm_set_channel_attr(ts, ccomb);

	if (is_ipaccess_bts(ts->trx->bts))
		return;

	switch (ts->pchan) {
	case GSM_PCHAN_TCH_F:
	case GSM_PCHAN_TCH_H:
		abis_nm_conn_terr_traf(ts, e1l->e1_nr, e1l->e1_ts,
					e1l->e1_ts_ss);
		break;
	default:
		break;
	}
}

static void nm_reconfig_trx(struct gsm_bts_trx *trx)
{
	struct gsm_e1_subslot *e1l = &trx->rsl_e1_link;
	int i;

	switch (trx->bts->type) {
	case GSM_BTS_TYPE_BS11:
		abis_nm_conn_terr_sign(trx, e1l->e1_nr, e1l->e1_ts,
					e1l->e1_ts_ss);
		abis_nm_establish_tei(trx->bts, trx->nr, e1l->e1_nr,
				      e1l->e1_ts, e1l->e1_ts_ss, trx->rsl_tei); 

		/* Set Radio Attributes */
		if (trx == trx->bts->c0)
			abis_nm_set_radio_attr(trx, bs11_attr_radio,
					       sizeof(bs11_attr_radio));
		else {
			u_int8_t trx1_attr_radio[sizeof(bs11_attr_radio)];
			u_int8_t arfcn_low = trx->arfcn & 0xff;
			u_int8_t arfcn_high = (trx->arfcn >> 8) & 0x0f;
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

static void bootstrap_om(struct gsm_bts *bts)
{
	fprintf(stdout, "bootstrapping OML for BTS %u\n", bts->nr);

	switch (bts->type) {
	case GSM_BTS_TYPE_BS11:
		bootstrap_om_bs11(bts);
		break;
	case GSM_BTS_TYPE_NANOBTS_900:
	case GSM_BTS_TYPE_NANOBTS_1800:
		bootstrap_om_nanobts(bts);
		break;
	default:
		fprintf(stderr, "Unable to bootstrap OML: Unknown BTS type %d\n", bts->type);
	}
}

static int shutdown_om(struct gsm_bts *bts)
{
	fprintf(stdout, "shutting down OML for BTS %u\n", bts->nr);

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

static int shutdown_net(struct gsm_network *net)
{
	struct gsm_bts *bts;

	llist_for_each_entry(bts, &net->bts_list, list) {
		int rc;
		rc = shutdown_om(bts);
		if (rc < 0)
			return rc;
	}

	return 0;
}

struct bcch_info {
	u_int8_t type;
	u_int8_t len;
	const u_int8_t *data;
};

/*
SYSTEM INFORMATION TYPE 1
  Cell channel description
    Format-ID bit map 0
    CA-ARFCN Bit 124...001 (Hex): 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 01
  RACH Control Parameters
    maximum 7 retransmissions
    8 slots used to spread transmission
    cell not barred for access
    call reestablishment not allowed
    Access Control Class = 0000
*/
static u_int8_t si1[] = {
	/* header */0x55, 0x06, 0x19,
	/* ccdesc */0x04 /*0x00*/, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 /*0x01*/,
	/* rach */0xD5, 0x00, 0x00,
	/* s1 reset*/0x2B
};

/*
 SYSTEM INFORMATION TYPE 2
  Neighbour Cells Description
    EXT-IND: Carries the complete BA
    BA-IND = 0
    Format-ID bit map 0
    CA-ARFCN Bit 124...001 (Hex): 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  NCC permitted (NCC) = FF
  RACH Control Parameters
    maximum 7 retransmissions
    8 slots used to spread transmission
    cell not barred for access
    call reestablishment not allowed
    Access Control Class = 0000
*/
static u_int8_t si2[] = {
	/* header */0x59, 0x06, 0x1A,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	/* ncc */0xFF,
	/* rach*/0xD5, 0x00, 0x00
};

/*
SYSTEM INFORMATION TYPE 3
  Cell identity = 00001 (1h)
  Location area identification
    Mobile Country Code (MCC): 001
    Mobile Network Code (MNC): 01
    Location Area Code  (LAC): 00001 (1h)
  Control Channel Description
    Attach-detach: MSs in the cell are not allowed to apply IMSI attach /detach
    0 blocks reserved for access grant
    1 channel used for CCCH, with SDCCH
    5 multiframes period for PAGING REQUEST
    Time-out T3212 = 0
  Cell Options BCCH
    Power control indicator: not set
    MSs shall not use uplink DTX
    Radio link timeout = 36
  Cell Selection Parameters
    Cell reselect hysteresis = 6 dB RXLEV hysteresis for LA re-selection
    max.TX power level MS may use for CCH = 2 <- according to GSM05.05 39dBm (max)
    Additional Reselect Parameter Indication (ACS) = only SYSTEM INFO 4: The SI rest octets, if present, shall be used to derive the value of PI and possibly C2 parameters
    Half rate support (NECI): New establishment causes are not supported
    min.RX signal level for MS = 0
  RACH Control Parameters
    maximum 7 retransmissions
    8 slots used to spread transmission
    cell not barred for access
    call reestablishment not allowed
    Access Control Class = 0000
  SI 3 Rest Octets (not present)
*/
static u_int8_t si3[] = {
	/* header */0x49, 0x06, 0x1B,
	/* cell */0x00, 0x01,
	/* lai  */0x00, 0xF1, 0x10, 0x00, 0x01,
	/* desc */0x01, 0x03, 0x00,
	/* option*/0x28,
	/* selection*/0x62, 0x00,
	/* rach */0xD5, 0x00, 0x00,
	/* rest */ 0x2B, 0x2B, 0x2B, 0x2B
};

/*
SYSTEM INFORMATION TYPE 4
  Location area identification
    Mobile Country Code (MCC): 001
    Mobile Network Code (MNC): 01
    Location Area Code  (LAC): 00001 (1h)
  Cell Selection Parameters
    Cell reselect hysteresis = 6 dB RXLEV hysteresis for LA re-selection
    max.TX power level MS may use for CCH = 2
    Additional Reselect Parameter Indication (ACS) = only SYSTEM INFO 4: The SI rest octets, if present, shall be used to derive the value of PI and possibly C2 parameters
    Half rate support (NECI): New establishment causes are not supported
    min.RX signal level for MS = 0
  RACH Control Parameters
    maximum 7 retransmissions
    8 slots used to spread transmission
    cell not barred for access
    call reestablishment not allowed
    Access Control Class = 0000
  CBCH Channel Description
    Type = SDCCH/4[2]
    Timeslot Number: 0
    Training Sequence Code: 7h
    ARFCN: 1
  SI Rest Octets (not present) 
*/
static u_int8_t si4[] = {
	/* header */0x41, 0x06, 0x1C,
	/* lai */0x00, 0xF1, 0x10, 0x00, 0x01,
	/* sel */0x62, 0x00,
	/* rach*/0xD5, 0x00, 0x00,
	/* cbch chan desc */ 0x64, 0x30, 0xE0, HARDCODED_ARFCN/*0x01*/,
	/* rest octets */ 0x2B, 0x2B, 0x2B, 0x2B, 0x2B, 0x2B
};

/*
 SYSTEM INFORMATION TYPE 5
  Neighbour Cells Description
    EXT-IND: Carries the complete BA
    BA-IND = 0
    Format-ID bit map 0
    CA-ARFCN Bit 124...001 (Hex): 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
*/

static u_int8_t si5[] = {
	/* header without l2 len*/0x06, 0x1D,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};

// SYSTEM INFORMATION TYPE 6

/*
SACCH FILLING
  System Info Type: SYSTEM INFORMATION 6
  L3 Information (Hex): 06 1E 00 01 xx xx 10 00 01 28 FF

SYSTEM INFORMATION TYPE 6
  Cell identity = 00001 (1h)
  Location area identification
    Mobile Country Code (MCC): 001
    Mobile Network Code (MNC): 01
    Location Area Code  (LAC): 00001 (1h)
  Cell Options SACCH
    Power control indicator: not set
    MSs shall not use uplink DTX on a TCH-F. MS shall not use uplink DTX on TCH-H.
    Radio link timeout = 36
  NCC permitted (NCC) = FF
*/

static u_int8_t si6[] = {
	/* header */0x06, 0x1E,
	/* cell id*/ 0x00, 0x01,
	/* lai */ 0x00, 0xF1, 0x10, 0x00, 0x01,
	/* options */ 0x28,
	/* ncc */ 0xFF,
};



static const struct bcch_info bcch_infos[] = {
	{
		.type = RSL_SYSTEM_INFO_1,
		.len = sizeof(si1),
		.data = si1,
	}, {
		.type = RSL_SYSTEM_INFO_2,
		.len = sizeof(si2),
		.data = si2,
	}, {
		.type = RSL_SYSTEM_INFO_3,
		.len = sizeof(si3),
		.data = si3,
	}, {
		.type = RSL_SYSTEM_INFO_4,
		.len = sizeof(si4),
		.data = si4,
	},
};

static_assert(sizeof(si1) == sizeof(struct gsm48_system_information_type_1), type1)
static_assert(sizeof(si2) == sizeof(struct gsm48_system_information_type_2), type2)
static_assert(sizeof(si3) == sizeof(struct gsm48_system_information_type_3), type3)
static_assert(sizeof(si4) >= sizeof(struct gsm48_system_information_type_4), type4)
static_assert(sizeof(si5) == sizeof(struct gsm48_system_information_type_5), type5)
static_assert(sizeof(si6) >= sizeof(struct gsm48_system_information_type_6), type6)

/* set all system information types */
static int set_system_infos(struct gsm_bts_trx *trx)
{
	int i;

	if (trx == trx->bts->c0) {
		for (i = 0; i < ARRAY_SIZE(bcch_infos); i++) {
			rsl_bcch_info(trx, bcch_infos[i].type,
				      bcch_infos[i].data,
				      bcch_infos[i].len);
		}
	}
	rsl_sacch_filling(trx, RSL_SYSTEM_INFO_5, si5, sizeof(si5));
	rsl_sacch_filling(trx, RSL_SYSTEM_INFO_6, si6, sizeof(si6));

	return 0;
}

/*
 * Patch the various SYSTEM INFORMATION tables to update
 * the LAI
 */
static void patch_tables(struct gsm_bts *bts)
{
	u_int8_t arfcn_low = bts->c0->arfcn & 0xff;
	u_int8_t arfcn_high = (bts->c0->arfcn >> 8) & 0x0f;
	/* covert the raw packet to the struct */
	struct gsm48_system_information_type_3 *type_3 =
		(struct gsm48_system_information_type_3*)&si3;
	struct gsm48_system_information_type_4 *type_4 =
		(struct gsm48_system_information_type_4*)&si4;
	struct gsm48_system_information_type_6 *type_6 =
		(struct gsm48_system_information_type_6*)&si6;
	struct gsm48_loc_area_id lai;

	gsm0408_generate_lai(&lai, bts->network->country_code,
			     bts->network->network_code,
			     bts->location_area_code);

	/* assign the MCC and MNC */
	type_3->lai = lai;
	type_4->lai = lai;
	type_6->lai = lai;

	/* patch ARFCN into BTS Attributes */
	bs11_attr_bts[69] &= 0xf0;
	bs11_attr_bts[69] |= arfcn_high;
	bs11_attr_bts[70] = arfcn_low;
	nanobts_attr_bts[42] &= 0xf0;
	nanobts_attr_bts[42] |= arfcn_high;
	nanobts_attr_bts[43] = arfcn_low;

	/* patch ARFCN into TRX Attributes */
	bs11_attr_radio[2] &= 0xf0;
	bs11_attr_radio[2] |= arfcn_high;
	bs11_attr_radio[3] = arfcn_low;
	nanobts_attr_radio[5] &= 0xf0;
	nanobts_attr_radio[5] |= arfcn_high;
	nanobts_attr_radio[6] = arfcn_low;

	type_4->data[2] &= 0xf0;
	type_4->data[2] |= arfcn_high;
	type_4->data[3] = arfcn_low;

	/* patch Control Channel Description 10.5.2.11 */
	type_3->control_channel_desc = bts->chan_desc;

	/* patch BSIC */
	bs11_attr_bts[1] = bts->bsic;
	nanobts_attr_bts[sizeof(nanobts_attr_bts)-1] = bts->bsic;

	/* patch TSC */
	si4[15] &= ~0xe0;
	si4[15] |= (bts->tsc & 7) << 5;

	/* patch MS max power for CCH */
	type_4->cell_sel_par.ms_txpwr_max_ccch =
			ms_pwr_ctl_lvl(bts->band, 20 /* dBm == 100mW */);
}


static void bootstrap_rsl(struct gsm_bts_trx *trx)
{
	fprintf(stdout, "bootstrapping RSL for BTS/TRX (%u/%u) "
		"using MCC=%u MNC=%u BSIC=%u TSC=%u\n",
		trx->bts->nr, trx->nr, gsmnet->country_code, 
		gsmnet->network_code, trx->bts->bsic, trx->bts->tsc);
	set_system_infos(trx);
}

void input_event(int event, enum e1inp_sign_type type, struct gsm_bts_trx *trx)
{
	switch (event) {
	case EVT_E1_TEI_UP:
		switch (type) {
		case E1INP_SIGN_OML:
			bootstrap_om(trx->bts);
			break;
		case E1INP_SIGN_RSL:
			bootstrap_rsl(trx);
			break;
		default:
			break;
		}
		break;
	case EVT_E1_TEI_DN:
		fprintf(stderr, "Lost some E1 TEI link\n");
		/* FIXME: deal with TEI or L1 link loss */
		break;
	default:
		break;
	}
}

static int bootstrap_bts(struct gsm_bts *bts)
{
	switch (bts->type) {
	case GSM_BTS_TYPE_NANOBTS_1800:
		if (bts->c0->arfcn < 512 || bts->c0->arfcn > 885) {
			fprintf(stderr, "GSM1800 channel must be between 512-885.\n");
			return -EINVAL;
		}
		break;
	case GSM_BTS_TYPE_BS11:
	case GSM_BTS_TYPE_NANOBTS_900:
		/* Assume we have a P-GSM900 here */
		if (bts->c0->arfcn < 1 || bts->c0->arfcn > 124) {
			fprintf(stderr, "GSM900 channel must be between 1-124.\n");
			return -EINVAL;
		}
		break;
	case GSM_BTS_TYPE_UNKNOWN:
		fprintf(stderr, "Unknown BTS. Please specify\n");
		return -EINVAL;
	}

	/* Control Channel Description */
	memset(&bts->chan_desc, 0, sizeof(struct gsm48_control_channel_descr));
	bts->chan_desc.att = 1;
	bts->chan_desc.ccch_conf = RSL_BCCH_CCCH_CONF_1_C;
	bts->chan_desc.bs_pa_mfrms = RSL_BS_PA_MFRMS_5;
	bts->chan_desc.t3212 = 0;

	patch_tables(bts);

	paging_init(bts);

	return 0;
}

static int bootstrap_network(void)
{
	struct gsm_bts *bts;
	int rc;

	/* initialize our data structures */
	gsmnet = gsm_network_init(MCC, MNC, mncc_recv);
	if (!gsmnet)
		return -ENOMEM;

	gsmnet->name_long = talloc_strdup(gsmnet, "OpenBSC");
	gsmnet->name_short = talloc_strdup(gsmnet, "OpenBSC");

	if (db_init(database_name)) {
		printf("DB: Failed to init database. Please check the option settings.\n");
		return -1;
	}	 
	printf("DB: Database initialized.\n");

	if (db_prepare()) {
		printf("DB: Failed to prepare database.\n");
		return -1;
	}
	printf("DB: Database prepared.\n");

	telnet_init(gsmnet, 4242);
	rc = vty_read_config_file(config_file);
	if (rc < 0) {
		fprintf(stderr, "Failed to parse the config file: '%s'\n", config_file);
		return rc;
	}

	register_signal_handler(SS_NM, nm_sig_cb, NULL);

	llist_for_each_entry(bts, &gsmnet->bts_list, list) { 
		bootstrap_bts(bts);
		if (!is_ipaccess_bts(bts))
			rc = e1_reconfig_bts(bts);

		if (rc < 0)
			exit (1);
	}

	/* initialize nanoBTS support omce */
	rc = ipaccess_setup(gsmnet);

	return 0;
}

static void create_pcap_file(char *file)
{
	mode_t mode = S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH;
	int fd = open(file, O_WRONLY|O_TRUNC|O_CREAT, mode);

	if (fd < 0) {
		perror("Failed to open file for pcap");
		return;
	}

	e1_set_pcap_fd(fd);
}

static void print_usage()
{
	printf("Usage: bsc_hack\n");
}

static void print_help()
{
	printf("  Some useful help...\n");
	printf("  -h --help this text\n");
	printf("  -d option --debug=DRLL:DCC:DMM:DRR:DRSL:DNM enable debugging\n");
	printf("  -s --disable-color\n");
	printf("  -c --config-file filename The config file to use.\n");
	printf("  -l --database db-name The database to use\n");
	printf("  -a --authorize-everyone Allow everyone into the network.\n");
	printf("  -r --reject-cause number The reject cause for LOCATION UPDATING REJECT.\n");
	printf("  -p --pcap file  The filename of the pcap file\n");
	printf("  -C --cardnr number  For bs11 select E1 card number other than 0\n");
	printf("  -R --release-l2 Releases mISDN layer 2 after exit, to unload driver.\n");
}

static void handle_options(int argc, char** argv)
{
	while (1) {
		int option_index = 0, c;
		static struct option long_options[] = {
			{"help", 0, 0, 'h'},
			{"debug", 1, 0, 'd'},
			{"config-file", 1, 0, 'c'},
			{"disable-color", 0, 0, 's'},
			{"database", 1, 0, 'l'},
			{"authorize-everyone", 0, 0, 'a'},
			{"reject-cause", 1, 0, 'r'},
			{"pcap", 1, 0, 'p'},
			{"cardnr", 1, 0, 'C'},
			{"release-l2", 0, 0, 'R'},
			{"timestamp", 0, 0, 'T'},
			{"rtp-proxy", 0, 0, 'P'},
			{0, 0, 0, 0}
		};

		c = getopt_long(argc, argv, "hd:sl:ar:p:C:RTPc:",
				long_options, &option_index);
		if (c == -1)
			break;

		switch (c) {
		case 'h':
			print_usage();
			print_help();
			exit(0);
		case 's':
			debug_use_color(0);
			break;
		case 'd':
			debug_parse_category_mask(optarg);
			break;
		case 'l':
			database_name = strdup(optarg);
			break;
		case 'c':
			config_file = strdup(optarg);
			break;
		case 'a':
			gsm0408_allow_everyone(1);
			break;
		case 'r':
			gsm0408_set_reject_cause(atoi(optarg));
			break;
		case 'p':
			create_pcap_file(optarg);
			break;
		case 't':
			BTS_TYPE = parse_btstype(optarg);
			break;
		case 'C':
			cardnr = atoi(optarg);
			break;
		case 'R':
			release_l2 = 1;
			break;
		case 'T':
			debug_timestamp(1);
			break;
		case 'P':
			ipacc_rtp_direct = 0;
			break;
		default:
			/* ignore */
			break;
		}
	}
}

static void signal_handler(int signal)
{
	fprintf(stdout, "signal %u received\n", signal);

	switch (signal) {
	case SIGINT:
		shutdown_net(gsmnet);
		sleep(3);
		exit(0);
		break;
	case SIGABRT:
		/* in case of abort, we want to obtain a talloc report
		 * and then return to the caller, who will abort the process */
	case SIGUSR1:
		talloc_report_full(tall_bsc_ctx, stderr);
		break;
	default:
		break;
	}
}

int main(int argc, char **argv)
{
	int rc;

	tall_bsc_ctx = talloc_named_const(NULL, 1, "openbsc");

	/* parse options */
	handle_options(argc, argv);

	/* seed the PRNG */
	srand(time(NULL));

	rc = bootstrap_network();
	if (rc < 0)
		exit(1);

	signal(SIGINT, &signal_handler);
	signal(SIGABRT, &signal_handler);
	signal(SIGUSR1, &signal_handler);

	while (1) {
		bsc_upqueue(gsmnet);
		bsc_select_main(0);
	}
}
