/* A hackish minimal BSC (+MSC +HLR) implementation */

/* (C) 2008 by Harald Welte <laforge@gnumonks.org>
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

#define _GNU_SOURCE
#include <getopt.h>

#include <openbsc/db.h>
#include <openbsc/timer.h>
#include <openbsc/gsm_data.h>
#include <openbsc/gsm_04_08.h>
#include <openbsc/select.h>
#include <openbsc/abis_rsl.h>
#include <openbsc/abis_nm.h>
#include <openbsc/debug.h>
#include <openbsc/misdn.h>

/* global pointer to the gsm network data structure */
static struct gsm_network *gsmnet;

/* MCC and MNC for the Location Area Identifier */
static int MCC = 1;
static int MNC = 1;
static const char *database_name = "hlr.sqlite3";

/* forward declarations */
static void bsc_hack_update_request_accepted(struct gsm_bts *bts, u_int32_t assigned_tmi);
static void bsc_hack_channel_allocated(struct gsm_lchan *chan,
			enum gsm_chreq_reason_t reason);
static void bsc_hack_channel_response(struct gsm_lchan *chan, int acked);
static void bsc_hack_call_released(struct gsm_lchan *chan);


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
	0xD0, 0x00, 0xFF, 0xFF, 0xFF, 0x91, 0x07, 0xD7, 0x09, 0x08, 0x0E, 0x24,
	0x0B, 0xCE, 0x02, 0x00, 0x1E, 0xE8, 0x01, 0x05, 0x42, 0x02, 0x00, 0x0A, 0x44,
	0x02, 0x00, 0x00
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
  periodCCCHLoadIndication: 255sec
  thresholdCCCHLoadIndication: 100%
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

unsigned char msg_2[] = 
{
	0x41, 0x01, 0x00, 0xFF, 0xFF, 0x09, 0x3F, 0x0A, 0x04, 0x61, 0x00, 0x0B,
	0xFF, 0x0C, 0x64, 0x62, 0x00, 0x66, 0x00, 0x6E, 0x06, 0x18, 0x1F, 0x19,
	0x0A, 0x0F, 0x14, 0x19, 0x1E, 0x7B, 0x0B, 0x23, 0x14, 0x28, 0x00, 0x04,
	0x03, 0x2A, 0x7F, 0x2B, 0x00, 0xFA, 0x8F, 0x7D, 0x33, 0x2C, 0x1F, 0x29,
	0x5A, 0x5A, 0x5A, 0x87, 0x94, 0x23, 0x28, 0x95, 0x23, 0x28, 0x35, 0x01,
	0x00, 0x46, 0x01, 0x00, 0x58, 0x01, 0x40, 0xC5, 0x01, 0x00, 0xF2, 0x01,
	0x00, 0x08, 0x00, HARDCODED_ARFCN/*0x01*/, 
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
	0xD0, 0xA1, 0x00, 0xFF, 0xFF, 0xD0, 0x00, 0x64, 0x00, 0x67, 0x00, 0x68,
	0x00, 0x6A, 0x00, 0x6C, 0x00, 0x6D, 0x00, 0x6F, 0x08, 0x70, 0x08, 0x01,
	0x71, 0x10, 0x10, 0x10, 0x72, 0x08, 0x02, 0x73, 0x0A, 0x74, 0x05, 0x75,
	0x06, 0x76, 0x06, 0x78, 0x14, 0x79, 0x14, 0x7A, 0x14, 0x7D, 0x06, 0x92,
	0x03, 0x20, 0x01, 0x00, 0x45, 0x01, 0x00, 0x48, 0x01, 0x00, 0x5A, 0x01,
	0x00, 0x5B, 0x01, 0x05, 0x5E, 0x01, 0x1A, 0x5F, 0x01, 0x20, 0x9D, 0x01,
	0x00, 0x47, 0x01, 0x00, 0x5C, 0x01, 0x64, 0x5D, 0x01, 0x1E, 0x97, 0x01,
	0x20, 0xF7, 0x01, 0x3C,
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
	0xD0, 0xA2, 0x00, 0xFF, 0xFF, 0x69, 0x00, 0x6B, 0x00, 0x7E, 0x04, 0x01,
	0x7F, 0x04, 0x02, 0x80, 0x0F, 0x81, 0x0A, 0x82, 0x05, 0x83, 0x05, 0x84,
	0x0C, 0x85, 0x14, 0x86, 0x0F, 0x87, 0x04, 0x88, 0x04, 0x89, 0x02, 0x8A,
	0x02, 0x8B, 0x02, 0x8C, 0x01, 0x8D, 0x40, 0x65, 0x01, 0x00 // set to 0x01 to enable BSPowerControl
};


// Transceiver, SET TRX ATTRIBUTES (TRX 0)

/*
  Object Class: Transceiver
  BTS relat. Number: 0 
  Tranceiver number: 0 
  Instance 3: FF
SET TRX ATTRIBUTES
  aRFCNList (HEX):  0001
  txPwrMaxReduction: 00h =   0dB
  radioMeasGran: 254  SACCH multiframes 
  radioMeasRep: 01h =  enabled
  memberOfEmergencyConfig: 01h =  TRUE
  trxArea: 00h = TRX doesn't belong to a concentric cell
*/

unsigned char msg_6[] = 
{
	0x44, 0x02, 0x00, 0x00, 0xFF, 0x05, 0x01, 0x00, HARDCODED_ARFCN /*0x01*/, 0x2D,
	0x00, 0xDC, 0x01, 0xFE, 0xDD, 0x01, 0x01, 0x9B, 0x01, 0x01, 0x9F, 0x01, 0x00, 
};


static void bootstrap_om(struct gsm_bts *bts)
{
	struct gsm_bts_trx *trx = &bts->trx[0];

	fprintf(stdout, "bootstrapping OML\n");

	/* stop sending event reports */
	abis_nm_event_reports(bts, 0);

	/* begin DB transmission */
	abis_nm_db_transmission(bts, 1);

	/* end DB transmission */
	abis_nm_db_transmission(bts, 0);

	/* Reset BTS Site manager resource */
	abis_nm_reset_resource(bts);

	/* begin DB transmission */
	abis_nm_db_transmission(bts, 1);

	abis_nm_raw_msg(bts, sizeof(msg_1), msg_1); /* set BTS SiteMgr attr*/
	abis_nm_raw_msg(bts, sizeof(msg_2), msg_2); /* set BTS attr */
	abis_nm_raw_msg(bts, sizeof(msg_3), msg_3); /* set BTS handover attr */
	abis_nm_raw_msg(bts, sizeof(msg_4), msg_4); /* set BTS power control attr */

	/* Connect signalling of bts0/trx0 to e1_0/ts1/64kbps */
	abis_nm_conn_terr_sign(trx, 0, 1, 0xff);
	abis_nm_raw_msg(bts, sizeof(msg_6), msg_6); /* SET TRX ATTRIBUTES */

	/* Use TEI 1 for signalling */
	abis_nm_establish_tei(bts, 0, 0, 1, 0xff, 0x01);
	abis_nm_set_channel_attr(&trx->ts[0], NM_CHANC_SDCCH_CBCH);
#if 0
	/* TRX 1 */
	abis_nm_conn_terr_sign(&bts->trx[1], 0, 1, 0xff);
	/* FIXME: TRX ATTRIBUTE */
	abis_nm_establish_tei(bts, 0, 0, 1, 0xff, 0x02);
#endif

	/* SET CHANNEL ATTRIBUTE TS1 */
	abis_nm_set_channel_attr(&trx->ts[1], 0x09);
	/* Connect traffic of bts0/trx0/ts1 to e1_0/ts2/b */
	abis_nm_conn_terr_traf(&trx->ts[1], 0, 2, 1);
	
	/* SET CHANNEL ATTRIBUTE TS2 */
	abis_nm_set_channel_attr(&trx->ts[2], 0x09);
	/* Connect traffic of bts0/trx0/ts2 to e1_0/ts2/c */
	abis_nm_conn_terr_traf(&trx->ts[2], 0, 2, 2);

	/* SET CHANNEL ATTRIBUTE TS3 */
	abis_nm_set_channel_attr(&trx->ts[3], 0x09);
	/* Connect traffic of bts0/trx0/ts3 to e1_0/ts2/d */
	abis_nm_conn_terr_traf(&trx->ts[3], 0, 2, 3);

	/* SET CHANNEL ATTRIBUTE TS4 */
	abis_nm_set_channel_attr(&trx->ts[4], 0x09);
	/* Connect traffic of bts0/trx0/ts4 to e1_0/ts3/a */
	abis_nm_conn_terr_traf(&trx->ts[4], 0, 3, 0);

	/* SET CHANNEL ATTRIBUTE TS5 */
	abis_nm_set_channel_attr(&trx->ts[5], 0x09);
	/* Connect traffic of bts0/trx0/ts5 to e1_0/ts3/b */
	abis_nm_conn_terr_traf(&trx->ts[5], 0, 3, 1);

	/* SET CHANNEL ATTRIBUTE TS6 */
	abis_nm_set_channel_attr(&trx->ts[6], 0x09);
	/* Connect traffic of bts0/trx0/ts6 to e1_0/ts3/c */
	abis_nm_conn_terr_traf(&trx->ts[6], 0, 3, 2);

	/* SET CHANNEL ATTRIBUTE TS7 */
	abis_nm_set_channel_attr(&trx->ts[7], 0x09);
	/* Connect traffic of bts0/trx0/ts7 to e1_0/ts3/d */
	abis_nm_conn_terr_traf(&trx->ts[7], 0, 3, 3);

	/* end DB transmission */
	abis_nm_db_transmission(bts, 0);

	/* Reset BTS Site manager resource */
	abis_nm_reset_resource(bts);

	/* restart sending event reports */
	abis_nm_event_reports(bts, 1);
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
  SI 3 Rest Octets
    Cell Bar Qualify (CBQ): 0
    Cell Reselect Offset = 0 dB
    Temporary Offset = 0 dB
    Penalty Time = 20 s
    System Information 2ter Indicator (2TI): 0 = not available
    Early Classmark Sending Control (ECSC):  0 = forbidden
    Scheduling Information is not sent in SYSTEM INFORMATION TYPE 9 on the BCCH
*/
static u_int8_t si3[] = {
	/* header */0x49, 0x06, 0x1B,
	/* cell */0x00, 0x01,
	/* lai  */0x00, 0xF1, 0x10, 0x00, 0x01,
	/* desc */0x01, 0x03, 0x00,
	/* option*/0x28,
	/* selection*/0x62, 0x00,
	/* rach */0xD5, 0x00, 0x00,
	/* reset*/0x80, 0x00, 0x00, 0x2B
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
  Channel Description
    Type = SDCCH/4[2]
    Timeslot Number: 0
    Training Sequence Code: 7h
    ARFCN: 1
  SI Rest Octets
    Cell Bar Qualify (CBQ): 0
    Cell Reselect Offset = 0 dB
    Temporary Offset = 0 dB
    Penalty Time = 20 s
*/
static u_int8_t si4[] = {
	/* header */0x41, 0x06, 0x1C,
	/* lai */0x00, 0xF1, 0x10, 0x00, 0x01,
	/* sel */0x62, 0x00,
	/* rach*/0xD5, 0x00, 0x00,
	/* var */0x64, 0x30, 0xE0, HARDCODED_ARFCN/*0x01*/, 0x80, 0x00, 0x00,
	0x2B, 0x2B, 0x2B
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
static int set_system_infos(struct gsm_bts *bts)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(bcch_infos); i++) {
		rsl_bcch_info(bts, bcch_infos[i].type,
			      bcch_infos[i].data,
			      bcch_infos[i].len);
	}
	rsl_sacch_filling(bts, RSL_SYSTEM_INFO_5, si5, sizeof(si5));
	rsl_sacch_filling(bts, RSL_SYSTEM_INFO_6, si6, sizeof(si6));

	return 0;
}

static void activate_traffic_channels(struct gsm_bts_trx *trx)
{
	int i;

	/* channel 0 is CCCH */
	for (i = 1; i < 8; i++)
		rsl_chan_activate_tch_f(&trx->ts[i]);
}

/*
 * Patch the various SYSTEM INFORMATION tables to update
 * the LAI
 */
static void patch_tables(struct gsm_bts *bts)
{
	/* covert the raw packet to the struct */
	struct gsm48_system_information_type_3 *type_3 =
		(struct gsm48_system_information_type_3*)&si3;
	struct gsm48_system_information_type_4 *type_4 =
		(struct gsm48_system_information_type_4*)&si4;
	struct gsm48_system_information_type_6 *type_6 =
		(struct gsm48_system_information_type_6*)&si6;
	struct gsm48_loc_area_id lai;

	gsm0408_generate_lai(&lai, bts->network->country_code,
				bts->network->network_code, bts->location_area_code);

	/* assign the MCC and MNC */
	type_3->lai = lai;
	type_4->lai = lai;
	type_6->lai = lai;
}


static void bootstrap_rsl(struct gsm_bts *bts)
{
	fprintf(stdout, "bootstrapping RSL MCC=%u MNC=%u\n", MCC, MNC);
	patch_tables(bts);
	set_system_infos(bts);

	/* FIXME: defer this until the channels are used */
	//activate_traffic_channels(&bts->trx[0]);
}

static void mi_cb(int event, struct gsm_bts *bts)
{
	switch (event) {
	case EVT_E1_OML_UP:
		bootstrap_om(bts);
		break;
	case EVT_E1_RSL_UP:
		bootstrap_rsl(bts);
		break;
	default:
		/* FIXME: deal with TEI or L1 link loss */
		break;
	}
}

static int bootstrap_network(void)
{
	struct gsm_bts *bts;

	/* initialize our data structures */
	gsmnet = gsm_network_init(1, MCC, MNC);
	if (!gsmnet)
		return -ENOMEM;
		
	bts = &gsmnet->bts[0];
	bts->location_area_code = 1;
	bts->trx[0].arfcn = HARDCODED_ARFCN;
	gsmnet->update_request_accepted = bsc_hack_update_request_accepted;
	gsmnet->channel_allocated = bsc_hack_channel_allocated;
	gsmnet->channel_response = bsc_hack_channel_response;
	gsmnet->call_released = bsc_hack_call_released;

	if (mi_setup(bts, 0, mi_cb) < 0)
		return -EIO;

	return 0;
}

static void print_usage()
{
	printf("Usage: bsc_hack\n");
}

static void print_help()
{
	printf("  Some useful help...\n");
	printf("  -d option --debug=DRLL:DCC:DMM:DRR:DRSL:DNM enable debugging\n");
	printf("  -s --disable-color\n");
	printf("  -n --network-code number(MNC) \n");
	printf("  -c --country-code number (MCC) \n");
	printf("  -l --database db-name The database to use\n");
	printf("  -h --help this text\n");
}

static void handle_options(int argc, char** argv)
{
	while (1) {
		int option_index = 0, c;
		static struct option long_options[] = {
			{"help", 0, 0, 'h'},
			{"debug", 1, 0, 'd'},
			{"disable-color", 0, 0, 's'},
			{"network-code", 1, 0, 'n'},
			{"country-code", 1, 0, 'c'},
			{"database", 1, 0, 'l'},
			{0, 0, 0, 0}
		};

		c = getopt_long(argc, argv, "hc:n:d:s",
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
		case 'n':
			MNC = atoi(optarg);
			break;
		case 'c':
			MCC = atoi(optarg);
			break;
                case 'l':
			database_name = strdup(optarg);
			break;
		default:
			/* ignore */
			break;
		}
	}
}

static struct timer_list pag_timer;

/* handles uppercase decimal and hexadecimal */
static u_int8_t char2bcd(char c)
{
	if (c <= '9')
		return c - '0';
	else
		return c - 'A';
}

static int string_to_mi(u_int8_t *mi, const char *string,
			u_int8_t type)
{
	u_int8_t *cur = mi+3;

	mi[0] = GSM48_IE_MOBILE_ID;
	//mi[1] = TMSI_LEN;
	mi[2] = type & GSM_MI_TYPE_MASK;

	if (strlen(string) & 0x01)
		mi[2] |= char2bcd(*string++) << 4;
	else
		mi[2] |= 0xf0;

	while (*string && *(string+1))
		*cur++ = char2bcd(*string++) | (char2bcd(*string++) << 4);

	mi[1] = cur - mi;

	return cur - mi;
}

/*
 * Stations that registered and that we need to page
 */
struct pending_registered_station {
	struct llist_head entry;

	/* the tmsi of the subscriber */
	u_int32_t tmsi;
	int last_page_group;
};

static LLIST_HEAD(pending_stations);

static void pag_timer_cb(void *data);
static struct timer_list pag_timer = {
	.cb = pag_timer_cb,
};

/* page the tmsi and wait for the channel request */
static void pag_timer_cb(void *data)
{
	struct gsm_bts *bts = &gsmnet->bts[0];
	struct pending_registered_station *pending_station;
	u_int8_t mi[128];
	unsigned int mi_len;

	if (llist_empty(&pending_stations)) {
		DEBUGP(DPAG, "pag_timer_cb but no pending mobile stations\n");
		return;
	}

	/* get the station to page */
	pending_station = (struct pending_registered_station*) pending_stations.next;
	mi_len = generate_mid_from_tmsi(mi, pending_station->tmsi);
	rsl_paging_cmd(bts, pending_station->last_page_group, mi_len, mi, RSL_CHANNEED_TCH_F);

	/* which group to page next */
	pending_station->last_page_group = (pending_station->last_page_group+1) % 12;
	schedule_timer(&pag_timer, 1, 0);
}

/*
 * initiate the a page command for the given
 * station and retry until we get a channel request
 */
static void station_timer_cb(void *data)
{
	DEBUGP(DPAG, "Initiating paging of a channel\n");
	pag_timer_cb(0);
}

static struct timer_list station_timer = {
	.cb = station_timer_cb,
};

/*
 * schedule work
 */
static void bsc_hack_update_request_accepted(struct gsm_bts *bts, u_int32_t tmsi)
{
	struct pending_registered_station *station =
				(struct pending_registered_station*)malloc(sizeof(*station));
	station->tmsi = tmsi;
	station->last_page_group = 0;
	llist_add_tail(&station->entry, &pending_stations);

	if (!timer_pending(&station_timer))
		schedule_timer(&station_timer, 1, 0);
}

static void bsc_hack_channel_allocated(struct gsm_lchan *chan,
									enum gsm_chreq_reason_t chreq_reason)
{
	struct pending_registered_station *station;
	if (chreq_reason != GSM_CHREQ_REASON_PAG)
		return;

	if (llist_empty(&pending_stations)) {
		DEBUGP(DPAG, "Channel allocated for pag but not waitin for it\n");
		return;
	}

	station = (struct pending_registered_station*) pending_stations.next;

	DEBUGP(DPAG, "CHAN RQD due PAG %d on %d for %u\n", chan->type, chan->nr, station->tmsi);

	/* allocate some token in the chan for us */
	chan->user_data = (void*)station->tmsi;
	del_timer(&pag_timer);
}

static void bsc_hack_channel_response(struct gsm_lchan *lchan, int ack)
{
	struct pending_registered_station *station;
	if (llist_empty(&pending_stations)) {
		DEBUGP(DPAG, "Channel nacked but nothing pending\n");
		return;
	}

	station = (struct pending_registered_station*) pending_stations.next;
	if (station->tmsi != (u_int32_t)lchan->user_data) {
		DEBUGP(DPAG, "Hmmm the channel is not allocated by the"
					 "station we wanted channel: %u us:%u\n",
					  (u_int32_t)(lchan->user_data), station->tmsi);
		return;
	}

	if (ack) {
		DEBUGP(DPAG, "We have probably paged a channel for tmsi: %u on %d\n",
				station->tmsi, lchan->nr);
		
		llist_del(&station->entry);
		free(station);

		/*
		 * start a call
		 */
		gsm48_cc_tx_setup(lchan);
	} else {
		/*
		 * give up and go to the next channel
		*/
		llist_del(&station->entry);
		free(station);
		pag_timer_cb(0);
	}
}

static void bsc_hack_call_released(struct gsm_lchan *lchan)
{
	DEBUGP(DPAG, "Call released jumping to the next...\n");
	rsl_chan_release(lchan);

	/* next!!! */
	pag_timer_cb(0);
}

int main(int argc, char **argv)
{
	/* parse options */
	handle_options(argc, argv);

	if (db_init(database_name)) {
		printf("DB: Failed to init database. Please check the option settings.\n");
		return 1;
	}	 
	printf("DB: Database initialized.\n");

	if (db_prepare()) {
		printf("DB: Failed to prepare database.\n");
		return 1;
	}
	printf("DB: Database prepared.\n");

	bootstrap_network();

	while (1) {
		bsc_select_main();
	}
}
