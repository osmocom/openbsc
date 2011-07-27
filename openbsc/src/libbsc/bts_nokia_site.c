/* Nokia XXXsite family specific code */

/* (C) 2011 by Dieter Spaar <spaar@mirider.augusta.de>
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

/*
  TODO: Attention: There are some static variables used for states during
  configuration. Those variables have to be moved to a BTS specific context,
  otherwise there will most certainly be problems if more than one Nokia BTS
  is used.
*/

#include <time.h>

#include <osmocom/gsm/tlv.h>

#include <openbsc/debug.h>
#include <openbsc/gsm_data.h>
#include <openbsc/abis_nm.h>
#include <openbsc/e1_input.h>
#include <openbsc/signal.h>

#include <osmocom/core/timer.h>

#include "../libabis/input/lapd.h"

/* TODO: put in a separate file ? */

/* TODO: move statics to BTS context */
static int do_reset = 1;
/*static*/ int wait_reset = 0;
struct osmo_timer_list reset_timer;	/* timer to re-start after reset */

#define RESET_INTERVAL      0, 3000000	/* 3 seconds */

extern int abis_nm_sendmsg(struct gsm_bts *bts, struct msgb *msg);
/* was static in system_information.c */
extern int generate_cell_chan_list(uint8_t * chan_list, struct gsm_bts *bts);

static void abis_nm_queue_send_next(struct gsm_bts *bts);
static void reset_timer_cb(void *_bts);
static int abis_nm_reset(struct gsm_bts *bts, uint16_t ref);
static int dump_elements(uint8_t * data, int len);

static void bootstrap_om_bts(struct gsm_bts *bts)
{
	LOGP(DNM, LOGL_NOTICE, "bootstrapping OML for BTS %u\n", bts->nr);

	if (do_reset)
		abis_nm_reset(bts, 1);
}

static void bootstrap_om_trx(struct gsm_bts_trx *trx)
{
	LOGP(DNM, LOGL_NOTICE, "bootstrapping OML for TRX %u/%u\n",
	     trx->bts->nr, trx->nr);
}

static int shutdown_om(struct gsm_bts *bts)
{
	/* TODO !? */
	return 0;
}

#define SAPI_OML    62
#define SAPI_RSL    0

/*

  Tell LAPD to start start the SAP (send SABM requests) for all signalling
  timeslots in this line

  Attention: this has to be adapted for mISDN
*/

static void start_sabm_in_line(struct e1inp_line *line, int start, int sapi)
{
	struct e1inp_sign_link *link;
	int i;

	for (i = 0; i < ARRAY_SIZE(line->ts); i++) {
		struct e1inp_ts *ts = &line->ts[i];

		if (ts->type != E1INP_TS_TYPE_SIGN)
			continue;

		llist_for_each_entry(link, &ts->sign.sign_links, list) {
			if (sapi != -1 && link->sapi != sapi)
				continue;

#if 0				/* debugging */
			printf("sap start/stop (%d): %d tei=%d sapi=%d\n",
			       start, i + 1, link->tei, link->sapi);
#endif

			if (start)
				lapd_sap_start(ts->driver.dahdi.lapd, link->tei,
					       link->sapi);
			else
				lapd_sap_stop(ts->driver.dahdi.lapd, link->tei,
					      link->sapi);
		}
	}
}

/* Callback function to be called every time we receive a signal from INPUT */
static int gbl_sig_cb(unsigned int subsys, unsigned int signal,
		      void *handler_data, void *signal_data)
{
	struct gsm_bts *bts;

	if (subsys != SS_GLOBAL)
		return 0;

	switch (signal) {
	case S_GLOBAL_BTS_CLOSE_OM:
		bts = signal_data;
		if (bts->type == GSM_BTS_TYPE_NOKIA_SITE)
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

	if (subsys != SS_INPUT)
		return 0;

	switch (signal) {
	case S_INP_LINE_INIT:
		start_sabm_in_line(isd->line, 1, SAPI_OML);	/* start only OML */
		break;
	case S_INP_TEI_DN:
		break;
	case S_INP_TEI_UP:
		switch (isd->link_type) {
		case E1INP_SIGN_OML:
			if (isd->trx->bts->type != GSM_BTS_TYPE_NOKIA_SITE)
				break;

			if (isd->tei == isd->trx->bts->oml_tei)
				bootstrap_om_bts(isd->trx->bts);
			else
				bootstrap_om_trx(isd->trx);
			break;
		}
		break;
	}

	return 0;
}

static void nm_statechg_evt(unsigned int signal,
			    struct nm_statechg_signal_data *nsd)
{
	if (nsd->bts->type != GSM_BTS_TYPE_NOKIA_SITE)
		return;
}

static int nm_sig_cb(unsigned int subsys, unsigned int signal,
		     void *handler_data, void *signal_data)
{
	if (subsys != SS_NM)
		return 0;

	switch (signal) {
	case S_NM_STATECHG_OPER:
	case S_NM_STATECHG_ADM:
		nm_statechg_evt(signal, signal_data);
		break;
	default:
		break;
	}

	return 0;
}

/* TODO: put in a separate file ? */

static char *get_msg_type_name_string(uint8_t msg_type)
{
	switch (msg_type) {
	case 0x80:
		return "NOKIA_BTS_CONF_DATA";
	case 0x81:
		return "NOKIA_BTS_ACK";
	case 0x82:
		return "NOKIA_BTS_OMU_STARTED";
	case 0x83:
		return "NOKIA_BTS_START_DOWNLOAD_REQ";
	case 0x84:
		return "NOKIA_BTS_MF_REQ";
	case 0x85:
		return "NOKIA_BTS_AF_REQ";
	case 0x86:
		return "NOKIA_BTS_RESET_REQ";
	case 0x87:
		return "NOKIA_reserved";
	case 0x88:
		return "NOKIA_BTS_CONF_REQ";
	case 0x89:
		return "NOKIA_BTS_TEST_REQ";
	case 0x8A:
		return "NOKIA_BTS_TEST_REPORT";
	case 0x8B:
		return "NOKIA_reserved";
	case 0x8C:
		return "NOKIA_reserved";
	case 0x8D:
		return "NOKIA_reserved";
	case 0x8E:
		return "NOKIA_BTS_CONF_COMPL";
	case 0x8F:
		return "NOKIA_reserved";
	case 0x90:
		return "NOKIA_BTS_STM_TEST_REQ";
	case 0x91:
		return "NOKIA_BTS_STM_TEST_REPORT";
	case 0x92:
		return "NOKIA_BTS_TRANSMISSION_COMMAND";
	case 0x93:
		return "NOKIA_BTS_TRANSMISSION_ANSWER";
	case 0x94:
		return "NOKIA_BTS_HW_DB_UPLOAD_REQ";
	case 0x95:
		return "NOKIA_BTS_START_HW_DB_DOWNLOAD_REQ";
	case 0x96:
		return "NOKIA_BTS_HW_DB_SAVE_REQ";
	case 0x97:
		return "NOKIA_BTS_FLASH_ERASURE_REQ";
	case 0x98:
		return "NOKIA_BTS_HW_DB_DOWNLOAD_REQ";
	case 0x99:
		return "NOKIA_BTS_PWR_SUPPLY_CONTROL";
	case 0x9A:
		return "NOKIA_BTS_ATTRIBUTE_REQ";
	case 0x9B:
		return "NOKIA_BTS_ATTRIBUTE_REPORT";
	case 0x9C:
		return "NOKIA_BTS_HW_REQ";
	case 0x9D:
		return "NOKIA_BTS_HW_REPORT";
	case 0x9E:
		return "NOKIA_BTS_RTE_TEST_REQ";
	case 0x9F:
		return "NOKIA_BTS_RTE_TEST_REPORT";
	case 0xA0:
		return "NOKIA_BTS_HW_DB_VERIFICATION_REQ";
	case 0xA1:
		return "NOKIA_BTS_CLOCK_REQ";
	case 0xA2:
		return "NOKIA_AC_CIRCUIT_REQ_NACK";
	case 0xA3:
		return "NOKIA_AC_INTERRUPTED";
	case 0xA4:
		return "NOKIA_BTS_NEW_TRE_INFO";
	case 0xA5:
		return "NOKIA_AC_BSC_CIRCUITS_ALLOCATED";
	case 0xA6:
		return "NOKIA_BTS_TRE_POLL_LIST";
	case 0xA7:
		return "NOKIA_AC_CIRCUIT_REQ";
	case 0xA8:
		return "NOKIA_BTS_BLOCK_CTRL_REQ";
	case 0xA9:
		return "NOKIA_BTS_GSM_TIME_REQ";
	case 0xAA:
		return "NOKIA_BTS_GSM_TIME";
	case 0xAB:
		return "NOKIA_BTS_OUTPUT_CONTROL";
	case 0xAC:
		return "NOKIA_BTS_STATE_CHANGED";
	case 0xAD:
		return "NOKIA_BTS_SW_SAVE_REQ";
	case 0xAE:
		return "NOKIA_BTS_ALARM";
	case 0xAF:
		return "NOKIA_BTS_CHA_ADM_STATE";
	case 0xB0:
		return "NOKIA_AC_POOL_SIZE_REPORT";
	case 0xB1:
		return "NOKIA_AC_POOL_SIZE_INQUIRY";
	case 0xB2:
		return "NOKIA_BTS_COMMISS_TEST_COMPLETED";
	case 0xB3:
		return "NOKIA_BTS_COMMISS_TEST_REQ";
	case 0xB4:
		return "NOKIA_BTS_TRANSP_BTS_TO_BSC";
	case 0xB5:
		return "NOKIA_BTS_TRANSP_BSC_TO_BTS";
	case 0xB6:
		return "NOKIA_BTS_LCS_COMMAND";
	case 0xB7:
		return "NOKIA_BTS_LCS_ANSWER";
	case 0xB8:
		return "NOKIA_BTS_LMU_FN_OFFSET_COMMAND";
	case 0xB9:
		return "NOKIA_BTS_LMU_FN_OFFSET_ANSWER";
	default:
		return "unknown";
	}
}

static char *get_element_name_string(uint16_t element)
{
	switch (element) {
	case 0x01:
		return "Ny1";
	case 0x02:
		return "T3105_F";
	case 0x03:
		return "Interference band limits";
	case 0x04:
		return "Interference report timer in secs";
	case 0x05:
		return "Channel configuration per TS";
	case 0x06:
		return "BSIC";
	case 0x07:
		return "RACH report timer in secs";
	case 0x08:
		return "Hardware database status";
	case 0x09:
		return "BTS RX level";
	case 0x0A:
		return "ARFN";
	case 0x0B:
		return "STM antenna attenuation";
	case 0x0C:
		return "Cell allocation bitmap";
	case 0x0D:
		return "Radio definition per TS";
	case 0x0E:
		return "Frame number";
	case 0x0F:
		return "Antenna diversity";
	case 0x10:
		return "T3105_D";
	case 0x11:
		return "File format";
	case 0x12:
		return "Last File";
	case 0x13:
		return "BTS type";
	case 0x14:
		return "Erasure mode";
	case 0x15:
		return "Hopping mode";
	case 0x16:
		return "Floating TRX";
	case 0x17:
		return "Power supplies";
	case 0x18:
		return "Reset type";
	case 0x19:
		return "Averaging period";
	case 0x1A:
		return "RBER2";
	case 0x1B:
		return "LAC";
	case 0x1C:
		return "CI";
	case 0x1D:
		return "Failure parameters";
	case 0x1E:
		return "(RF max power reduction)";
	case 0x1F:
		return "Measured RX_SENS";
	case 0x20:
		return "Extended cell radius";
	case 0x21:
		return "reserved";
	case 0x22:
		return "Success-Failure";
	case 0x23:
		return "Ack-Nack";
	case 0x24:
		return "OMU test results";
	case 0x25:
		return "File identity";
	case 0x26:
		return "Generation and version code";
	case 0x27:
		return "SW description";
	case 0x28:
		return "BCCH LEV";
	case 0x29:
		return "Test type";
	case 0x2A:
		return "Subscriber number";
	case 0x2B:
		return "reserved";
	case 0x2C:
		return "HSN";
	case 0x2D:
		return "reserved";
	case 0x2E:
		return "MS RXLEV";
	case 0x2F:
		return "MS TXLEV";
	case 0x30:
		return "RXQUAL";
	case 0x31:
		return "RX SENS";
	case 0x32:
		return "Alarm block";
	case 0x33:
		return "Neighbouring BCCH levels";
	case 0x34:
		return "STM report type";
	case 0x35:
		return "MA";
	case 0x36:
		return "MAIO";
	case 0x37:
		return "H_FLAG";
	case 0x38:
		return "TCH_ARFN";
	case 0x39:
		return "Clock output";
	case 0x3A:
		return "Transmitted power";
	case 0x3B:
		return "Clock sync";
	case 0x3C:
		return "TMS protocol discriminator";
	case 0x3D:
		return "TMS protocol data";
	case 0x3E:
		return "FER";
	case 0x3F:
		return "SWR result";
	case 0x40:
		return "Object identity";
	case 0x41:
		return "STM RX Antenna Test";
	case 0x42:
		return "reserved";
	case 0x43:
		return "reserved";
	case 0x44:
		return "Object current state";
	case 0x45:
		return "reserved";
	case 0x46:
		return "FU channel configuration";
	case 0x47:
		return "reserved";
	case 0x48:
		return "ARFN of a CU";
	case 0x49:
		return "FU radio definition";
	case 0x4A:
		return "reserved";
	case 0x4B:
		return "Severity";
	case 0x4C:
		return "Diversity selection";
	case 0x4D:
		return "RX antenna test";
	case 0x4E:
		return "RX antenna supervision period";
	case 0x4F:
		return "RX antenna state";
	case 0x50:
		return "Sector configuration";
	case 0x51:
		return "Additional info";
	case 0x52:
		return "SWR parameters";
	case 0x53:
		return "HW inquiry mode";
	case 0x54:
		return "reserved";
	case 0x55:
		return "Availability status";
	case 0x56:
		return "reserved";
	case 0x57:
		return "EAC inputs";
	case 0x58:
		return "EAC outputs";
	case 0x59:
		return "reserved";
	case 0x5A:
		return "Position";
	case 0x5B:
		return "HW unit identity";
	case 0x5C:
		return "RF test signal attenuation";
	case 0x5D:
		return "Operational state";
	case 0x5E:
		return "Logical object identity";
	case 0x5F:
		return "reserved";
	case 0x60:
		return "BS_TXPWR_OM";
	case 0x61:
		return "Loop_Duration";
	case 0x62:
		return "LNA_Path_Selection";
	case 0x63:
		return "Serial number";
	case 0x64:
		return "HW version";
	case 0x65:
		return "Obj. identity and obj. state";
	case 0x66:
		return "reserved";
	case 0x67:
		return "EAC input definition";
	case 0x68:
		return "EAC id and text";
	case 0x69:
		return "HW unit status";
	case 0x6A:
		return "SW release version";
	case 0x6B:
		return "FW version";
	case 0x6C:
		return "Bit_Error_Ratio";
	case 0x6D:
		return "RXLEV_with_Attenuation";
	case 0x6E:
		return "RXLEV_without_Attenuation";
	case 0x6F:
		return "reserved";
	case 0x70:
		return "CU_Results";
	case 0x71:
		return "reserved";
	case 0x72:
		return "LNA_Path_Results";
	case 0x73:
		return "RTE Results";
	case 0x74:
		return "Real Time";
	case 0x75:
		return "RX diversity selection";
	case 0x76:
		return "EAC input config";
	case 0x77:
		return "Feature support";
	case 0x78:
		return "File version";
	case 0x79:
		return "Outputs";
	case 0x7A:
		return "FU parameters";
	case 0x7B:
		return "Diagnostic info";
	case 0x7C:
		return "FU BSIC";
	case 0x7D:
		return "TRX Configuration";
	case 0x7E:
		return "Download status";
	case 0x7F:
		return "RX difference limit";
	case 0x80:
		return "TRX HW capability";
	case 0x81:
		return "Common HW config";
	case 0x82:
		return "Autoconfiguration pool size";
	case 0x83:
		return "TRE diagnostic info";
	case 0x84:
		return "TRE object identity";
	case 0x85:
		return "New TRE Info";
	case 0x86:
		return "Acknowledgement period";
	case 0x87:
		return "Synchronization mode";
	case 0x88:
		return "reserved";
	case 0x89:
		return "Block Control Data";
	case 0x8A:
		return "SW load mode";
	case 0x8B:
		return "Recommended recovery action";
	case 0x8C:
		return "BSC BCF id";
	case 0x8D:
		return "Q1 baud rate";
	case 0x8E:
		return "Allocation status";
	case 0x8F:
		return "Functional entity number";
	case 0x90:
		return "Transmission delay";
	case 0x91:
		return "Loop Duration ms";
	case 0x92:
		return "Logical channel";
	case 0x93:
		return "Q1 address";
	case 0x94:
		return "Alarm detail";
	case 0x95:
		return "Cabinet type";
	case 0x96:
		return "HW unit existence";
	case 0x97:
		return "RF power parameters";
	case 0x98:
		return "Message scenario";
	case 0x99:
		return "HW unit max amount";
	case 0x9A:
		return "Master TRX";
	case 0x9B:
		return "Transparent data";
	case 0x9C:
		return "BSC topology info";
	case 0x9D:
		return "Air i/f modulation";
	case 0x9E:
		return "LCS Q1 command data";
	case 0x9F:
		return "Frame number offset";
	case 0xA0:
		return "Abis TSL";
	case 0xA1:
		return "Dynamic pool info";
	case 0xA2:
		return "LCS LLP data";
	case 0xA3:
		return "LCS Q1 answer data";
	case 0xA4:
		return "DFCA FU Radio Definition";
	case 0xA5:
		return "Antenna hopping";
	case 0xA6:
		return "Field record sequence number";
	case 0xA7:
		return "Timeslot offslot";
	case 0xA8:
		return "EPCR capability";
	case 0xA9:
		return "Connectsite optional element";
	case 0xAA:
		return "TSC";
	case 0xAB:
		return "Special TX Power Setting";
	case 0xAC:
		return "Optional sync settings";
	case 0xFA:
		return "Abis If parameters";
	default:
		return "unknown";
	}
}

static char *get_bts_type_string(uint8_t type)
{
	switch (type) {
	case 0x0A:
		return "MetroSite GSM 900";
	case 0x0B:
		return "MetroSite GSM 1800";
	case 0x0C:
		return "MetroSite GSM 1900 (PCS)";
	case 0x0D:
		return "MetroSite GSM 900 & 1800";
	case 0x0E:
		return "InSite GSM 900";
	case 0x0F:
		return "InSite GSM 1800";
	case 0x10:
		return "InSite GSM 1900";
	case 0x11:
		return "UltraSite GSM 900";
	case 0x12:
		return "UltraSite GSM 1800";
	case 0x13:
		return "UltraSite GSM/US-TDMA 1900";
	case 0x14:
		return "UltraSite GSM 900 & 1800";
	case 0x16:
		return "UltraSite GSM/US-TDMA 850";
	case 0x18:
		return "MetroSite GSM/US-TDMA 850";
	case 0x19:
		return "UltraSite GSM 800/1900";
	default:
		return "unknown";
	}
}

static char *get_severity_string(uint8_t severity)
{
	switch (severity) {
	case 0:
		return "indeterminate";
	case 1:
		return "critical";
	case 2:
		return "major";
	case 3:
		return "minor";
	case 4:
		return "warning";
	default:
		return "unknown";
	}
}

/* TODO: put in a separate file ? */

/* some message IDs */

#define NOKIA_MSG_CONF_DATA             128
#define NOKIA_MSG_ACK                   129
#define NOKIA_MSG_OMU_STARTED           130
#define NOKIA_MSG_START_DOWNLOAD_REQ    131
#define NOKIA_MSG_MF_REQ                132
#define NOKIA_MSG_RESET_REQ             134
#define NOKIA_MSG_CONF_REQ              136
#define NOKIA_MSG_CONF_COMPLETE         142
#define NOKIA_MSG_BLOCK_CTRL_REQ        168
#define NOKIA_MSG_STATE_CHANGED         172
#define NOKIA_MSG_ALARM                 174

/* some element IDs */

#define NOKIA_EI_BTS_TYPE       0x13
#define NOKIA_EI_ACK            0x23
#define NOKIA_EI_ADD_INFO       0x51
#define NOKIA_EI_SEVERITY       0x4B
#define NOKIA_EI_ALARM_DETAIL   0x94

#define OM_ALLOC_SIZE       1024
#define OM_HEADROOM_SIZE    128

static uint8_t fu_config_template[] = {
	0x7F, 0x7A, 0x39,
	/* ID = 0x7A (FU parameters) ## constructed ## */
	/* length = 57 */
	/* [3] */

	0x5F, 0x40, 0x04,
	/* ID = 0x40 (Object identity) */
	/* length = 4 */
	/* [6] */
	0x00, 0x07, 0x01, 0xFF,

	0x41, 0x02,
	/* ID = 0x01 (Ny1) */
	/* length = 2 */
	/* [12] */
	0x00, 0x05,

	0x42, 0x02,
	/* ID = 0x02 (T3105_F) */
	/* length = 2 */
	/* [16] */
	0x00, 0x28,

	0x50, 0x02,
	/* ID = 0x10 (T3105_D) */
	/* length = 2 */
	/* [20] */
	0x00, 0x28,

	0x43, 0x05,
	/* ID = 0x03 (Interference band limits) */
	/* length = 5 */
	/* [24] */
	0x0F, 0x1B, 0x27, 0x33, 0x3F,

	0x44, 0x02,
	/* ID = 0x04 (Interference report timer in secs) */
	/* length = 2 */
	/* [31] */
	0x00, 0x10,

	0x47, 0x01,
	/* ID = 0x07 (RACH report timer in secs) */
	/* length = 1 */
	/* [35] */
	0x1E,

	0x4C, 0x10,
	/* ID = 0x0C (Cell allocation bitmap) ####### */
	/* length = 16 */
	/* [38] */
	0x8F, 0xB1, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,

	0x59, 0x01,
	/* ID = 0x19 (Averaging period) */
	/* length = 1 */
	/* [56] */
	0x01,

	0x5E, 0x01,
	/* ID = 0x1E ((RF max power reduction)) */
	/* length = 1 */
	/* [59] */
	0x00,

	0x7F, 0x46, 0x11,
	/* ID = 0x46 (FU channel configuration) ## constructed ## */
	/* length = 17 */
	/* [63] */

	0x5F, 0x40, 0x04,
	/* ID = 0x40 (Object identity) */
	/* length = 4 */
	/* [66] */
	0x00, 0x07, 0x01, 0xFF,

	0x45, 0x08,
	/* ID = 0x05 (Channel configuration per TS) */
	/* length = 8 */
	/* [72] */
	0x01, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09,

	0x7F, 0x65, 0x0B,
	/* ID = 0x65 (Obj. identity and obj. state) ## constructed ## */
	/* length = 11 */
	/* [83] */

	0x5F, 0x40, 0x04,
	/* ID = 0x40 (Object identity) */
	/* length = 4 */
	/* [86] */
	0x00, 0x04, 0x01, 0xFF,

	0x5F, 0x44, 0x01,
	/* ID = 0x44 (Object current state) */
	/* length = 1 */
	/* [93] */
	0x03,

	0x7F, 0x7C, 0x0A,
	/* ID = 0x7C (FU BSIC) ## constructed ## */
	/* length = 10 */
	/* [97] */

	0x5F, 0x40, 0x04,
	/* ID = 0x40 (Object identity) */
	/* length = 4 */
	/* [100] */
	0x00, 0x07, 0x01, 0xFF,

	0x46, 0x01,
	/* ID = 0x06 (BSIC) */
	/* length = 1 */
	/* [106] */
	0x00,

	0x7F, 0x48, 0x0B,
	/* ID = 0x48 (ARFN of a CU) ## constructed ## */
	/* length = 11 */
	/* [110] */

	0x5F, 0x40, 0x04,
	/* ID = 0x40 (Object identity) */
	/* length = 4 */
	/* [113] */
	0x00, 0x08, 0x01, 0xFF,

	0x4A, 0x02,
	/* ID = 0x0A (ARFN) ####### */
	/* length = 2 */
	/* [119] */
	0x03, 0x62,

	0x7F, 0x49, 0x59,
	/* ID = 0x49 (FU radio definition) ## constructed ## */
	/* length = 89 */
	/* [124] */

	0x5F, 0x40, 0x04,
	/* ID = 0x40 (Object identity) */
	/* length = 4 */
	/* [127] */
	0x00, 0x07, 0x01, 0xFF,

	0x4D, 0x50,
	/* ID = 0x0D (Radio definition per TS) ####### */
	/* length = 80 */
	/* [133] */
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,	/* MA */
	0x03, 0x62,		/* HSN, MAIO or ARFCN if no hopping */
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x03, 0x62,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x03, 0x62,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x03, 0x62,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x03, 0x62,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x03, 0x62,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x03, 0x62,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x03, 0x62,
};

/* TODO: put in a separate file ? */

/*
  build the configuration for each TRX
*/

static int make_fu_config(struct gsm_bts_trx *trx, uint8_t id,
			  uint8_t * fu_config, int *hopping)
{
	int i;

	*hopping = 0;

	memcpy(fu_config, fu_config_template, sizeof(fu_config_template));

	/* set ID */

	fu_config[6 + 2] = id;
	fu_config[66 + 2] = id;
	fu_config[86 + 2] = id;
	fu_config[100 + 2] = id;
	fu_config[113 + 2] = id;
	fu_config[127 + 2] = id;

	/* set ARFCN */

	uint16_t arfcn = trx->arfcn;

	fu_config[119] = arfcn >> 8;
	fu_config[119 + 1] = arfcn & 0xFF;

	for (i = 0; i < ARRAY_SIZE(trx->ts); i++) {
		struct gsm_bts_trx_ts *ts = &trx->ts[i];

		if (ts->hopping.enabled) {
			/* reverse order */
			int j;
			for (j = 0; j < ts->hopping.ma_len; j++)
				fu_config[133 + (i * 10) + (7 - j)] =
				    ts->hopping.ma_data[j];
			fu_config[133 + 8 + (i * 10)] = ts->hopping.hsn;
			fu_config[133 + 8 + 1 + (i * 10)] = ts->hopping.maio;
			*hopping = 1;
		} else {
			fu_config[133 + 8 + (i * 10)] = arfcn >> 8;
			fu_config[133 + 8 + 1 + (i * 10)] = arfcn & 0xFF;
		}
	}

	/* set BSIC */

	/*
	   Attention: all TRX except the first one seem to get the TSC
	   from the CHANNEL ACTIVATION command (in CHANNEL IDENTIFICATION,
	   GSM 04.08 CHANNEL DESCRIPTION).
	   There was a bug in rsl_chan_activate_lchan() setting this parameter.
	 */

	uint8_t bsic = trx->bts->bsic;

	fu_config[106] = bsic;

	/* set CA */

	if (generate_cell_chan_list(&fu_config[38], trx->bts) != 0) {
		fprintf(stderr, "generate_cell_chan_list failed\n");
		return 0;
	}

	/* set channel configuration */

	for (i = 0; i < ARRAY_SIZE(trx->ts); i++) {
		struct gsm_bts_trx_ts *ts = &trx->ts[i];
		uint8_t chan_config;

		/*
		   0 = FCCH + SCH + BCCH + CCCH
		   1 = FCCH + SCH + BCCH + CCCH + SDCCH/4 + SACCH/4
		   2 = BCCH + CCCH (This combination is not used in any BTS)
		   3 = FCCH + SCH + BCCH + CCCH + SDCCH/4 with SDCCH2 used as CBCH
		   4 = SDCCH/8 + SACCH/8
		   5 = SDCCH/8 with SDCCH2 used as CBCH
		   6 = TCH/F + FACCH/F + SACCH/F
		   7 = E-RACH (Talk family)
		   9 = Dual rate (capability for TCH/F and TCH/H)
		   10 = reserved for BTS internal use
		   11 = PBCCH + PCCCH + PDTCH + PACCH + PTCCH (can be used in GPRS release 2).
		   0xFF = spare TS
		 */

		if (ts->pchan == GSM_PCHAN_NONE)
			chan_config = 0xFF;
		else if (ts->pchan == GSM_PCHAN_CCCH)
			chan_config = 0;
		else if (ts->pchan == GSM_PCHAN_CCCH_SDCCH4)
			chan_config = 1;
		else if (ts->pchan == GSM_PCHAN_TCH_F)
			chan_config = 6;	/* 9 should work too */
		else if (ts->pchan == GSM_PCHAN_TCH_H)
			chan_config = 9;
		else if (ts->pchan == GSM_PCHAN_SDCCH8_SACCH8C)
			chan_config = 4;
		else if (ts->pchan == GSM_PCHAN_PDCH)
			chan_config = 11;
		else {
			fprintf(stderr,
				"unsupported channel config %d for timeslot %d\n",
				ts->pchan, i);
			return 0;
		}

		fu_config[72 + i] = chan_config;
	}
	return sizeof(fu_config_template);
}

/* TODO: put in a separate file ? */

static uint8_t bts_config_1[] = {
	0x4E, 0x02,
	/* ID = 0x0E (Frame number) */
	/* length = 2 */
	/* [2] */
	0xFF, 0xFF,

	0x5F, 0x4E, 0x02,
	/* ID = 0x4E (RX antenna supervision period) */
	/* length = 2 */
	/* [7] */
	0xFF, 0xFF,

	0x5F, 0x50, 0x02,
	/* ID = 0x50 (Sector configuration) */
	/* length = 2 */
	/* [12] */
	0x01, 0x01,
};

static uint8_t bts_config_2[] = {
	0x55, 0x02,
	/* ID = 0x15 (Hopping mode) */
	/* length = 2 */
	/* [2] */
	0x01, 0x00,

	0x5F, 0x75, 0x02,
	/* ID = 0x75 (RX diversity selection) */
	/* length = 2 */
	/* [7] */
	0x01, 0x01,
};

static uint8_t bts_config_3[] = {
	0x5F, 0x20, 0x02,
	/* ID = 0x20 (Extended cell radius) */
	/* length = 2 */
	/* [3] */
	0x01, 0x00,
};

static uint8_t bts_config_4[] = {
	0x5F, 0x74, 0x09,
	/* ID = 0x74 (Real Time) */
	/* length = 9 */
	/* [3] year-high, year-low, month, day, hour, minute, second, msec-high, msec-low */
	0x07, 0xDB, 0x06, 0x02, 0x0B, 0x20, 0x0C, 0x00,
	0x00,

	0x5F, 0x76, 0x03,
	/* ID = 0x76 (EAC input config) */
	/* length = 3 */
	/* [15] */
	0x01, 0x01, 0x00,

	0x5F, 0x76, 0x03,
	/* ID = 0x76 (EAC input config) */
	/* length = 3 */
	/* [21] */
	0x02, 0x01, 0x00,

	0x5F, 0x76, 0x03,
	/* ID = 0x76 (EAC input config) */
	/* length = 3 */
	/* [27] */
	0x03, 0x01, 0x00,

	0x5F, 0x76, 0x03,
	/* ID = 0x76 (EAC input config) */
	/* length = 3 */
	/* [33] */
	0x04, 0x01, 0x00,

	0x5F, 0x76, 0x03,
	/* ID = 0x76 (EAC input config) */
	/* length = 3 */
	/* [39] */
	0x05, 0x01, 0x00,

	0x5F, 0x76, 0x03,
	/* ID = 0x76 (EAC input config) */
	/* length = 3 */
	/* [45] */
	0x06, 0x01, 0x00,

	0x5F, 0x76, 0x03,
	/* ID = 0x76 (EAC input config) */
	/* length = 3 */
	/* [51] */
	0x07, 0x01, 0x00,

	0x5F, 0x76, 0x03,
	/* ID = 0x76 (EAC input config) */
	/* length = 3 */
	/* [57] */
	0x08, 0x01, 0x00,

	0x5F, 0x76, 0x03,
	/* ID = 0x76 (EAC input config) */
	/* length = 3 */
	/* [63] */
	0x09, 0x01, 0x00,

	0x5F, 0x76, 0x03,
	/* ID = 0x76 (EAC input config) */
	/* length = 3 */
	/* [69] */
	0x0A, 0x01, 0x00,
};

static uint8_t bts_config_insite[] = {
	0x4E, 0x02,
	/* ID = 0x0E (Frame number) */
	/* length = 2 */
	/* [2] */
	0xFF, 0xFF,

	0x5F, 0x4E, 0x02,
	/* ID = 0x4E (RX antenna supervision period) */
	/* length = 2 */
	/* [7] */
	0xFF, 0xFF,

	0x5F, 0x50, 0x02,
	/* ID = 0x50 (Sector configuration) */
	/* length = 2 */
	/* [12] */
	0x01, 0x01,

	0x55, 0x02,
	/* ID = 0x15 (Hopping mode) */
	/* length = 2 */
	/* [16] */
	0x01, 0x00,

	0x5F, 0x20, 0x02,
	/* ID = 0x20 (Extended cell radius) */
	/* length = 2 */
	/* [21] */
	0x01, 0x00,

	0x5F, 0x74, 0x09,
	/* ID = 0x74 (Real Time) */
	/* length = 9 */
	/* [26] */
	0x07, 0xDB, 0x07, 0x0A, 0x0F, 0x09, 0x0B, 0x00,
	0x00,
};

void set_real_time(uint8_t * real_time)
{
	time_t t;
	struct tm *tm;

	t = time(NULL);
	tm = localtime(&t);

	/* year-high, year-low, month, day, hour, minute, second, msec-high, msec-low */

	real_time[0] = (1900 + tm->tm_year) >> 8;
	real_time[1] = (1900 + tm->tm_year) & 0xFF;
	real_time[2] = tm->tm_mon + 1;
	real_time[3] = tm->tm_mday;
	real_time[4] = tm->tm_hour;
	real_time[5] = tm->tm_min;
	real_time[6] = tm->tm_sec;
	real_time[7] = 0;
	real_time[8] = 0;
}

/* TODO: put in a separate file ? */

/*
  build the configuration data
*/

static int make_bts_config(uint8_t bts_type, int n_trx, uint8_t * fu_config,
			   int need_hopping)
{
	/* is it an InSite BTS ? */
	if (bts_type == 0x0E || bts_type == 0x0F || bts_type == 0x10) {	/* TODO */
		if (n_trx != 1) {
			fprintf(stderr, "InSite has only one TRX\n");
			return 0;
		}
		if (need_hopping != 0) {
			fprintf(stderr, "InSite does not support hopping\n");
			return 0;
		}
		memcpy(fu_config, bts_config_insite, sizeof(bts_config_insite));
		set_real_time(&fu_config[26]);
		return sizeof(bts_config_insite);
	}

	int len = 0;
	int i;

	memcpy(fu_config + len, bts_config_1, sizeof(bts_config_1));

	/* set sector configuration */
	fu_config[len + 12 - 1] = 1 + n_trx;	/* len */
	for (i = 0; i < n_trx; i++)
		fu_config[len + 12 + 1 + i] = ((i + 1) & 0xFF);

	len += (sizeof(bts_config_1) + (n_trx - 1));

	memcpy(fu_config + len, bts_config_2, sizeof(bts_config_2));
	/* set hopping mode (Baseband and RF hopping work for the MetroSite) */
	if (need_hopping)
		fu_config[len + 2 + 1] = 1;	/* 0: no hopping, 1: Baseband hopping, 2: RF hopping */
	len += sizeof(bts_config_2);

	/* set extended cell radius for each TRX */
	for (i = 0; i < n_trx; i++) {
		memcpy(fu_config + len, bts_config_3, sizeof(bts_config_3));
		fu_config[len + 3] = ((i + 1) & 0xFF);
		len += sizeof(bts_config_3);
	}

	memcpy(fu_config + len, bts_config_4, sizeof(bts_config_4));
	set_real_time(&fu_config[len + 3]);
	len += sizeof(bts_config_4);

	return len;
}

/* TODO: put in a separate file ? */

static struct msgb *nm_msgb_alloc(void)
{
	return msgb_alloc_headroom(OM_ALLOC_SIZE, OM_HEADROOM_SIZE, "OML");
}

/* TODO: put in a separate file ? */

struct abis_om_nokia_hdr {
	uint8_t msg_type;
	uint8_t spare;
	uint16_t reference;
	uint8_t data[0];
} __attribute__ ((packed));

#define ABIS_OM_NOKIA_HDR_SIZE (sizeof(struct abis_om_hdr) + sizeof(struct abis_om_nokia_hdr))

static int abis_nm_send(struct gsm_bts *bts, uint8_t msg_type, uint16_t ref,
			uint8_t * data, int len_data)
{
	struct abis_om_hdr *oh;
	struct abis_om_nokia_hdr *noh;
	struct msgb *msg = nm_msgb_alloc();

	oh = (struct abis_om_hdr *)msgb_put(msg,
					    ABIS_OM_NOKIA_HDR_SIZE + len_data);

	oh->mdisc = ABIS_OM_MDISC_FOM;
	oh->placement = ABIS_OM_PLACEMENT_ONLY;
	oh->sequence = 0;
	oh->length = sizeof(struct abis_om_nokia_hdr) + len_data;

	noh = (struct abis_om_nokia_hdr *)oh->data;

	noh->msg_type = msg_type;
	noh->spare = 0;
	noh->reference = htons(ref);
	memcpy(noh->data, data, len_data);

	DEBUGPC(DNM, "Sending %s\n", get_msg_type_name_string(msg_type));

	return abis_nm_sendmsg(bts, msg);
}

/* TODO: put in a separate file ? */

static uint8_t download_req[] = {
	0x5F, 0x25, 0x0B,
	/* ID = 0x25 (File identity) */
	/* length = 11 */
	/* [3] */
	0x2A, 0x2A, 0x2A, 0x2A, 0x2A, 0x2A, 0x2A, 0x2A,
	0x2A, 0x2A, 0x2A,

	0x5F, 0x78, 0x03,
	/* ID = 0x78 (File version) */
	/* length = 3 */
	/* [17] */
	0x2A, 0x2A, 0x2A,

	0x5F, 0x81, 0x0A, 0x01,
	/* ID = 0x8A (SW load mode) */
	/* length = 1 */
	/* [24] */
	0x01,

	0x5F, 0x81, 0x06, 0x01,
	/* ID = 0x86 (Acknowledgement period) */
	/* length = 1 */
	/* [29] */
	0x01,
};

static int abis_nm_download_req(struct gsm_bts *bts, uint16_t ref)
{
	uint8_t *data = download_req;
	int len_data = sizeof(download_req);

	return abis_nm_send(bts, NOKIA_MSG_START_DOWNLOAD_REQ, ref, data,
			    len_data);
}

/* TODO: put in a separate file ? */

static uint8_t ack[] = {
	0x5F, 0x23, 0x01,
	/* ID = 0x23 (Ack-Nack) */
	/* length = 1 */
	/* [3] */
	0x01,
};

static int abis_nm_ack(struct gsm_bts *bts, uint16_t ref)
{
	uint8_t *data = ack;
	int len_data = sizeof(ack);

	return abis_nm_send(bts, NOKIA_MSG_ACK, ref, data, len_data);
}

/* TODO: put in a separate file ? */

static uint8_t reset[] = {
	0x5F, 0x40, 0x04,
	/* ID = 0x40 (Object identity) */
	/* length = 4 */
	/* [3] */
	0x00, 0x01, 0xFF, 0xFF,
};

static int abis_nm_reset(struct gsm_bts *bts, uint16_t ref)
{
	uint8_t *data = reset;
	int len_data = sizeof(reset);

	return abis_nm_send(bts, NOKIA_MSG_RESET_REQ, ref, data, len_data);
}

/* TODO: put in a separate file ? */

static int abis_nm_send_multi_segments(struct gsm_bts *bts, uint8_t msg_type,
				       uint16_t ref, uint8_t * data, int len)
{
	int len_remain, len_to_send, max_send;
	int seq = 0;
	int ret;

	len_remain = len;

	while (len_remain) {
		struct abis_om_hdr *oh;
		struct abis_om_nokia_hdr *noh;
		struct msgb *msg = nm_msgb_alloc();

		if (seq == 0)
			max_send = 256 - sizeof(struct abis_om_nokia_hdr);
		else
			max_send = 256;

		if (len_remain > max_send) {
			len_to_send = max_send;

			if (seq == 0) {
				/* first segment */
				oh = (struct abis_om_hdr *)msgb_put(msg,
								    ABIS_OM_NOKIA_HDR_SIZE
								    +
								    len_to_send);

				oh->mdisc = ABIS_OM_MDISC_FOM;
				oh->placement = ABIS_OM_PLACEMENT_FIRST;	/* first segment of multi-segment message */
				oh->sequence = seq;
				oh->length = 0;	/* 256 bytes */

				noh = (struct abis_om_nokia_hdr *)oh->data;

				noh->msg_type = msg_type;
				noh->spare = 0;
				noh->reference = htons(ref);
				memcpy(noh->data, data, len_to_send);
			} else {
				/* segment in between */
				oh = (struct abis_om_hdr *)msgb_put(msg,
								    sizeof
								    (struct
								     abis_om_hdr)
								    +
								    len_to_send);

				oh->mdisc = ABIS_OM_MDISC_FOM;
				oh->placement = ABIS_OM_PLACEMENT_MIDDLE;	/* segment of multi-segment message */
				oh->sequence = seq;
				oh->length = 0;	/* 256 bytes */

				memcpy(oh->data, data, len_to_send);
			}
		} else {

			len_to_send = len_remain;

			/* check if message fits in a single segment */

			if (seq == 0)
				return abis_nm_send(bts, msg_type, ref, data,
						    len_to_send);

			/* last segment */

			oh = (struct abis_om_hdr *)msgb_put(msg,
							    sizeof(struct
								   abis_om_hdr)
							    + len_to_send);

			oh->mdisc = ABIS_OM_MDISC_FOM;
			oh->placement = ABIS_OM_PLACEMENT_LAST;	/* last segment of multi-segment message */
			oh->sequence = seq;
			oh->length = len_to_send;

			memcpy(oh->data, data, len_to_send);
		}

		DEBUGPC(DNM, "Sending multi-segment %d\n", seq);

		ret = abis_nm_sendmsg(bts, msg);
		if (ret < 0)
			return ret;

		abis_nm_queue_send_next(bts);

		/* next segment */
		len_remain -= len_to_send;
		data += len_to_send;
		seq++;
	}
	return ret;
}

/* TODO: put in a separate file ? */

static int abis_nm_send_config(struct gsm_bts *bts, uint8_t bts_type)
{
	struct gsm_bts_trx *trx;
	uint8_t config[2048];	/* TODO: might be too small if lots of TRX are used */
	int len = 0;
	int idx = 0;
	int ret;
	int hopping = 0;
	int need_hopping = 0;

	memset(config, 0, sizeof(config));

	llist_for_each_entry(trx, &bts->trx_list, list) {
#if 0				/* debugging */
		printf("TRX\n");
		printf("  arfcn: %d\n", trx->arfcn);
		printf("  bsic: %d\n", trx->bts->bsic);
		uint8_t ca[20];
		memset(ca, 0xFF, sizeof(ca));
		ret = generate_cell_chan_list(ca, trx->bts);
		printf("  ca (%d): %s\n", ret, osmo_hexdump(ca, sizeof(ca)));
		int i;
		for (i = 0; i < ARRAY_SIZE(trx->ts); i++) {
			struct gsm_bts_trx_ts *ts = &trx->ts[i];

			printf("  pchan %d: %d\n", i, ts->pchan);
		}
#endif
		ret = make_fu_config(trx, idx + 1, config + len, &hopping);
		need_hopping |= hopping;
		len += ret;

		idx++;
	}

	ret = make_bts_config(bts_type, idx, config + len, need_hopping);
	len += ret;

#if 0				/* debugging */
	dump_elements(config, len);
#endif

	return abis_nm_send_multi_segments(bts, NOKIA_MSG_CONF_DATA, 1, config,
					   len);
}

#define GET_NEXT_BYTE if(idx >= len) return 0; \
                        ub = data[idx++];

static int find_element(uint8_t * data, int len, uint16_t id, uint8_t * value,
			int max_value)
{
	uint8_t ub;
	int idx = 0;
	int found = 0;
	int constructed;
	uint16_t id_value;

	for (;;) {

		GET_NEXT_BYTE;

		/* encoding bit, construced means that other elements are contained */
		constructed = ((ub & 0x20) ? 1 : 0);

		if ((ub & 0x1F) == 0x1F) {
			/* fixed pattern, ID follows */
			GET_NEXT_BYTE;	/* ID */
			id_value = ub & 0x7F;
			if (ub & 0x80) {
				/* extension bit */
				GET_NEXT_BYTE;	/* ID low part */
				id_value = (id_value << 7) | (ub & 0x7F);
			}
			if (id_value == id)
				found = 1;
		} else {
			id_value = (ub & 0x3F);
			if (id_value == id)
				found = 1;
		}

		GET_NEXT_BYTE;	/* length */

		if (found) {
			/* get data */
			uint8_t n = ub;
			uint8_t i;
			for (i = 0; i < n; i++) {
				GET_NEXT_BYTE;
				if (max_value <= 0)
					return -1;	/* buffer too small */
				*value = ub;
				value++;
				max_value--;
			}
			return n;	/* length */
		} else {
			/* skip data */
			uint8_t n = ub;
			uint8_t i;
			for (i = 0; i < n; i++) {
				GET_NEXT_BYTE;
			}
		}
	}
	return 0;		/* not found */
}

static int dump_elements(uint8_t * data, int len)
{
	uint8_t ub;
	int idx = 0;
	int constructed;
	uint16_t id_value;
	static char indent[100] = "";	/* TODO: move static to BTS context */

	for (;;) {

		GET_NEXT_BYTE;

		/* encoding bit, construced means that other elements are contained */
		constructed = ((ub & 0x20) ? 1 : 0);

		if ((ub & 0x1F) == 0x1F) {
			/* fixed pattern, ID follows */
			GET_NEXT_BYTE;	/* ID */
			id_value = ub & 0x7F;
			if (ub & 0x80) {
				/* extension bit */
				GET_NEXT_BYTE;	/* ID low part */
				id_value = (id_value << 7) | (ub & 0x7F);
			}

		} else {
			id_value = (ub & 0x3F);
		}

		GET_NEXT_BYTE;	/* length */

		printf("%s--ID = 0x%02X (%s) %s\n", indent, id_value,
		       get_element_name_string(id_value),
		       constructed ? "** constructed **" : "");
		printf("%s  length = %d\n", indent, ub);
		printf("%s  %s\n", indent, osmo_hexdump(data + idx, ub));

		if (constructed) {
			int indent_len = strlen(indent);
			strcat(indent, "   ");

			dump_elements(data + idx, ub);

			indent[indent_len] = 0;
		}
		/* skip data */
		uint8_t n = ub;
		uint8_t i;
		for (i = 0; i < n; i++) {
			GET_NEXT_BYTE;
		}
	}
	return 0;
}

/* TODO: put in a separate file ? */

/* taken from abis_nm.c */

static void abis_nm_queue_send_next(struct gsm_bts *bts)
{
	int wait = 0;
	struct msgb *msg;
	/* the queue is empty */
	while (!llist_empty(&bts->abis_queue)) {
		msg = msgb_dequeue(&bts->abis_queue);
		wait = OBSC_NM_W_ACK_CB(msg);
		_abis_nm_sendmsg(msg, 0);

		if (wait)
			break;
	}

	bts->abis_nm_pend = wait;
}

/* TODO: put in a separate file ? */

/* timer for restarting OML after BTS reset */

static void reset_timer_cb(void *_bts)
{
	struct gsm_bts *bts = _bts;
	struct gsm_e1_subslot *e1_link = &bts->oml_e1_link;
	struct e1inp_line *line;

	wait_reset = 0;

	/* OML link */
	line = e1inp_line_get(e1_link->e1_nr);
	if (!line) {
		LOGP(DINP, LOGL_ERROR, "BTS %u OML link referring to "
		     "non-existing E1 line %u\n", bts->nr, e1_link->e1_nr);
		return;
	}

	start_sabm_in_line(line, 0, -1);	/* stop all first */
	start_sabm_in_line(line, 1, SAPI_OML);	/* start only OML */
}

/* TODO: put in a separate file ? */

/*
  This is how the configuration is done:
  - start OML link
  - reset BTS
  - receive ACK, wait some time and restart OML link
  - receive OMU STARTED message, send START DOWNLOAD REQ
  - receive CNF REQ message, send CONF DATA
  - receive ACK, start RSL link(s)
  ACK some other messages received from the BTS.

  Probably its also possible to configure the BTS without a reset, this 
  has not been tested yet.
*/

static int abis_nm_rcvmsg_fom(struct msgb *mb)
{
	struct gsm_bts *bts = mb->trx->bts;
	struct abis_om_hdr *oh = msgb_l2(mb);
	struct abis_om_nokia_hdr *noh = msgb_l3(mb);
	uint8_t mt = noh->msg_type;
	int ret = 0;
	uint16_t ref = ntohs(noh->reference);
	/* TODO: move statics to BTS context */
	static int conf = 0;
	static uint8_t bts_type = 0xFF;
	uint8_t info[256];
	uint8_t ack = 0xFF;
	uint8_t severity = 0xFF;
	int str_len;
	int len_data;

	if (wait_reset) {
		LOGP(DNM, LOGL_INFO,
		     "Ignore message while waiting for reset\n");
		return ret;
	}

	if (oh->length < sizeof(struct abis_om_nokia_hdr)) {
		LOGP(DNM, LOGL_ERROR, "Message too short\n");
		return -EINVAL;
	}

	len_data = oh->length - sizeof(struct abis_om_nokia_hdr);
	LOGP(DNM, LOGL_INFO, "(0x%02X) %s\n", mt, get_msg_type_name_string(mt));
#if 0				/* debugging */
	dump_elements(noh->data, len_data);
#endif

	switch (mt) {
	case NOKIA_MSG_OMU_STARTED:
		if (find_element
		    (noh->data, len_data, NOKIA_EI_BTS_TYPE, &bts_type,
		     sizeof(uint8_t)) == sizeof(uint8_t))
			LOGP(DNM, LOGL_INFO, "BTS type = %d (%s)\n", bts_type,
			     get_bts_type_string(bts_type));
		else
			LOGP(DNM, LOGL_ERROR, "BTS type not found\n");
		/* send START_DOWNLOAD_REQ */
		abis_nm_download_req(bts, ref);
		break;
	case NOKIA_MSG_MF_REQ:
		break;
	case NOKIA_MSG_CONF_REQ:
		/* send ACK */
		abis_nm_ack(bts, ref);
		abis_nm_queue_send_next(bts);
		/* send CONF_DATA */
		abis_nm_send_config(bts, bts_type);
		conf = 1;
		break;
	case NOKIA_MSG_ACK:
		if (find_element
		    (noh->data, len_data, NOKIA_EI_ACK, &ack,
		     sizeof(uint8_t)) == sizeof(uint8_t)) {
			LOGP(DNM, LOGL_INFO, "ACK = %d\n", ack);
			if (ack != 1) {
				LOGP(DNM, LOGL_ERROR, "No ACK received (%d)\n",
				     ack);
				/* TODO: properly handle failures (NACK) */
			}
		} else
			LOGP(DNM, LOGL_ERROR, "ACK not found\n");

		/* TODO: the assumption for the following is that no NACK was received */

		/* ACK for reset message ? */
		if (do_reset != 0) {
			do_reset = 0;

			/* 
			   TODO: For the InSite processing the received data is 
			   blocked in the driver during reset.
			   Otherwise the LAPD module might assert because the InSite
			   sends garbage on the E1 line during reset.
			   This is done by looking at "wait_reset" in the driver
			   (function handle_ts1_read()) and ignoring the received data.
			   It seems to be necessary for the MetroSite too.
			 */
			wait_reset = 1;

			reset_timer.cb = &reset_timer_cb;
			reset_timer.data = bts;
			osmo_timer_schedule(&reset_timer, RESET_INTERVAL);

			struct gsm_e1_subslot *e1_link = &bts->oml_e1_link;
			struct e1inp_line *line;
			/* OML link */
			line = e1inp_line_get(e1_link->e1_nr);
			if (!line) {
				LOGP(DINP, LOGL_ERROR,
				     "BTS %u OML link referring to "
				     "non-existing E1 line %u\n", bts->nr,
				     e1_link->e1_nr);
				return -ENOMEM;
			}

			start_sabm_in_line(line, 0, -1);	/* stop all first */
		}

		/* ACK for CONF DATA message ? */
		if (conf != 0) {
			/* start TRX  (RSL link) */

			struct gsm_e1_subslot *e1_link = &mb->trx->rsl_e1_link;
			struct e1inp_line *line;

			conf = 0;

			/* RSL Link */
			line = e1inp_line_get(e1_link->e1_nr);
			if (!line) {
				LOGP(DINP, LOGL_ERROR,
				     "TRX (%u/%u) RSL link referring "
				     "to non-existing E1 line %u\n",
				     mb->trx->bts->nr, mb->trx->nr,
				     e1_link->e1_nr);
				return -ENOMEM;
			}
			/* start TRX */
			start_sabm_in_line(line, 1, SAPI_RSL);	/* start only RSL */
		}
		break;
	case NOKIA_MSG_STATE_CHANGED:
		/* send ACK */
		abis_nm_ack(bts, ref);
		break;
	case NOKIA_MSG_CONF_COMPLETE:
		/* send ACK */
		abis_nm_ack(bts, ref);
		break;
	case NOKIA_MSG_BLOCK_CTRL_REQ:	/* seems to be send when something goes wrong !? */
		/* send ACK (do we have to send an ACK ?) */
		abis_nm_ack(bts, ref);
		break;
	case NOKIA_MSG_ALARM:
		find_element(noh->data, len_data, NOKIA_EI_SEVERITY, &severity,
			     sizeof(severity));
		/* TODO: there might be alarms with both elements set */
		str_len =
		    find_element(noh->data, len_data, NOKIA_EI_ADD_INFO, info,
				 sizeof(info));
		if (str_len > 0) {
			info[str_len] = 0;
			LOGP(DNM, LOGL_INFO, "ALARM Severity %s (%d) : %s\n",
			     get_severity_string(severity), severity, info);
		} else {	/* nothing found, try details */
			str_len =
			    find_element(noh->data, len_data,
					 NOKIA_EI_ALARM_DETAIL, info,
					 sizeof(info));
			if (str_len > 0) {
				uint16_t code;
				info[str_len] = 0;
				code = (info[0] << 8) + info[1];
				LOGP(DNM, LOGL_INFO,
				     "ALARM Severity %s (%d), code 0x%X : %s\n",
				     get_severity_string(severity), severity,
				     code, info + 2);
			}
		}
		/* send ACK */
		abis_nm_ack(bts, ref);
		break;
	}

	abis_nm_queue_send_next(bts);

	return ret;
}

/* TODO: put in a separate file ? */

int abis_nokia_rcvmsg(struct msgb *msg)
{
	struct abis_om_hdr *oh = msgb_l2(msg);
	int rc = 0;

	/* Various consistency checks */
	if (oh->placement != ABIS_OM_PLACEMENT_ONLY) {
		LOGP(DNM, LOGL_ERROR, "ABIS OML placement 0x%x not supported\n",
		     oh->placement);
		if (oh->placement != ABIS_OM_PLACEMENT_FIRST)
			return -EINVAL;
	}
	if (oh->sequence != 0) {
		LOGP(DNM, LOGL_ERROR, "ABIS OML sequence 0x%x != 0x00\n",
		     oh->sequence);
		return -EINVAL;
	}
	msg->l3h = (unsigned char *)oh + sizeof(*oh);

	switch (oh->mdisc) {
	case ABIS_OM_MDISC_FOM:
		LOGP(DNM, LOGL_INFO, "ABIS_OM_MDISC_FOM\n");
		rc = abis_nm_rcvmsg_fom(msg);
		break;
	case ABIS_OM_MDISC_MANUF:
		LOGP(DNM, LOGL_INFO, "ABIS_OM_MDISC_MANUF\n");
		break;
	case ABIS_OM_MDISC_MMI:
	case ABIS_OM_MDISC_TRAU:
		LOGP(DNM, LOGL_ERROR,
		     "unimplemented ABIS OML message discriminator 0x%x\n",
		     oh->mdisc);
		break;
	default:
		LOGP(DNM, LOGL_ERROR,
		     "unknown ABIS OML message discriminator 0x%x\n",
		     oh->mdisc);
		return -EINVAL;
	}

	msgb_free(msg);
	return rc;
}

static int bts_model_nokia_site_start(struct gsm_network *net);

static struct gsm_bts_model model_nokia_site = {
	.type = GSM_BTS_TYPE_NOKIA_SITE,
	.name = "nokia_site",
	.start = bts_model_nokia_site_start,
	.oml_rcvmsg = &abis_nokia_rcvmsg
};

static struct gsm_network *my_net;

static int bts_model_nokia_site_start(struct gsm_network *net)
{
	model_nokia_site.features.data = &model_nokia_site._features_data[0];
	model_nokia_site.features.data_len =
	    sizeof(model_nokia_site._features_data);

	gsm_btsmodel_set_feature(&model_nokia_site, BTS_FEAT_HOPPING);
	gsm_btsmodel_set_feature(&model_nokia_site, BTS_FEAT_HSCSD);

	osmo_signal_register_handler(SS_INPUT, inp_sig_cb, NULL);
	osmo_signal_register_handler(SS_GLOBAL, gbl_sig_cb, NULL);
	osmo_signal_register_handler(SS_NM, nm_sig_cb, NULL);

	my_net = net;

	return 0;
}

int bts_model_nokia_site_init(void)
{
	return gsm_bts_model_register(&model_nokia_site);
}
