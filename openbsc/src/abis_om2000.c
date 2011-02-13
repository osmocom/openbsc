/* Ericsson RBS 2xxx GSM O&M (OM2000) messages on the A-bis interface
 * implemented based on protocol trace analysis, no formal documentation */

/* (C) 2010-2011 by Harald Welte <laforge@gnumonks.org>
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


#include <errno.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <stdint.h>

#include <arpa/inet.h>

#include <osmocore/msgb.h>
#include <osmocore/tlv.h>
#include <osmocore/talloc.h>
#include <osmocore/utils.h>

#include <openbsc/gsm_data.h>
#include <openbsc/debug.h>
#include <openbsc/abis_nm.h>
#include <openbsc/abis_om2000.h>
#include <openbsc/signal.h>

#define OM_ALLOC_SIZE		1024
#define OM_HEADROOM_SIZE	128

/* use following functions from abis_nm.c:
	* om2k_msgb_alloc()
	* abis_om2k_sendmsg()
 */

struct abis_om2k_hdr {
	struct abis_om_hdr om;
	uint16_t msg_type;
	struct abis_om2k_mo mo;
	uint8_t data[0];
} __attribute__ ((packed));

enum abis_om2k_msgtype {
	OM2K_MSGT_ABORT_SP_CMD			= 0x0000,
	OM2K_MSGT_ABORT_SP_COMPL		= 0x0002,
	OM2K_MSGT_ALARM_REP_ACK			= 0x0004,
	OM2K_MSGT_ALARM_REP_NACK		= 0x0005,
	OM2K_MSGT_ALARM_REP			= 0x0006,
	OM2K_MSGT_ALARM_STATUS_REQ		= 0x0008,
	OM2K_MSGT_ALARM_STATUS_REQ_ACK		= 0x000a,
	OM2K_MSGT_ALARM_STATUS_REQ_REJ		= 0x000b,
	OM2K_MSGT_ALARM_STATUS_RES_ACK		= 0x000c,
	OM2K_MSGT_ALARM_STATUS_RES_NACK		= 0x000d,
	OM2K_MSGT_ALARM_STATUS_RES		= 0x000e,
	OM2K_MSGT_CAL_TIME_RESP			= 0x0010,
	OM2K_MSGT_CAL_TIME_REJ			= 0x0011,
	OM2K_MSGT_CAL_TIME_REQ			= 0x0012,

	OM2K_MSGT_CONNECT_CMD			= 0x001c,
	OM2K_MSGT_CONNECT_COMPL			= 0x001e,
	OM2K_MSGT_CONNECT_REJ			= 0x001f,

	OM2K_MSGT_DISABLE_REQ			= 0x0028,
	OM2K_MSGT_DISABLE_REQ_ACK		= 0x002a,
	OM2K_MSGT_DISABLE_REQ_REJ		= 0x002b,
	OM2K_MSGT_DISABLE_RES_ACK		= 0x002c,
	OM2K_MSGT_DISABLE_RES_NACK		= 0x002d,
	OM2K_MSGT_DISABLE_RES			= 0x002e,
	OM2K_MSGT_DISCONNECT_CMD		= 0x0030,
	OM2K_MSGT_DISCONNECT_COMPL		= 0x0032,
	OM2K_MSGT_DISCONNECT_REJ		= 0x0033,
	OM2K_MSGT_ENABLE_REQ			= 0x0034,
	OM2K_MSGT_ENABLE_REQ_ACK		= 0x0036,
	OM2K_MSGT_ENABLE_REQ_REJ		= 0x0037,
	OM2K_MSGT_ENABLE_RES_ACK		= 0x0038,
	OM2K_MSGT_ENABLE_RES_NACK		= 0x0039,
	OM2K_MSGT_ENABLE_RES			= 0x003a,

	OM2K_MSGT_FAULT_REP_ACK			= 0x0040,
	OM2K_MSGT_FAULT_REP_NACK		= 0x0041,
	OM2K_MSGT_FAULT_REP			= 0x0042,

	OM2K_MSGT_IS_CONF_REQ			= 0x0060,
	OM2K_MSGT_IS_CONF_REQ_ACK		= 0x0062,
	OM2K_MSGT_IS_CONF_REQ_REJ		= 0x0063,
	OM2K_MSGT_IS_CONF_RES_ACK		= 0x0064,
	OM2K_MSGT_IS_CONF_RES_NACK		= 0x0065,
	OM2K_MSGT_IS_CONF_RES			= 0x0066,

	OM2K_MSGT_OP_INFO			= 0x0074,
	OM2K_MSGT_OP_INFO_ACK			= 0x0076,
	OM2K_MSGT_OP_INFO_REJ			= 0x0077,
	OM2K_MSGT_RESET_CMD		 	= 0x0078,
	OM2K_MSGT_RESET_COMPL			= 0x007a,
	OM2K_MSGT_RESET_REJ			= 0x007b,

	OM2K_MSGT_START_REQ			= 0x0084,
	OM2K_MSGT_START_REQ_ACK			= 0x0086,
	OM2K_MSGT_START_REQ_REJ			= 0x0087,
	OM2K_MSGT_START_RES_ACK			= 0x0088,
	OM2K_MSGT_START_RES_NACK		= 0x0089,
	OM2K_MSGT_START_RES			= 0x008a,
	OM2K_MSGT_STATUS_REQ			= 0x008c,
	OM2K_MSGT_STATUS_RESP			= 0x008e,
	OM2K_MSGT_STATUS_REJ			= 0x008f,

	OM2K_MSGT_TEST_REQ			= 0x0094,
	OM2K_MSGT_TEST_REQ_ACK			= 0x0096,
	OM2K_MSGT_TEST_REQ_REJ			= 0x0097,
	OM2K_MSGT_TEST_RES_ACK			= 0x0098,
	OM2K_MSGT_TEST_RES_NACK			= 0x0099,
	OM2K_MSGT_TEST_RES			= 0x009a,

	OM2K_MSGT_NEGOT_REQ_ACK			= 0x0104,
	OM2K_MSGT_NEGOT_REQ_NACK		= 0x0105,
	OM2K_MSGT_NEGOT_REQ			= 0x0106,
};

enum abis_om2k_dei {
	OM2K_DEI_CAL_TIME			= 0x0d,
	OM2K_DEI_END_LIST_NR			= 0x13,
	OM2K_DEI_IS_CONN_LIST			= 0x27,
	OM2K_DEI_LIST_NR			= 0x28,
	OM2K_DEI_OP_INFO			= 0x2e,
	OM2K_DEI_NEGOT_REC1			= 0x90,
	OM2K_DEI_NEGOT_REC2			= 0x91,
};

enum abis_om2k_mo_cls {
	OM2K_MO_CLS_TRXC			= 0x01,
	OM2K_MO_CLS_TS				= 0x03,
	OM2K_MO_CLS_TF				= 0x04,
	OM2K_MO_CLS_IS				= 0x05,
	OM2K_MO_CLS_CON				= 0x06,
	OM2K_MO_CLS_DP				= 0x07,
	OM2K_MO_CLS_CF				= 0x0a,
	OM2K_MO_CLS_TX				= 0x0b,
	OM2K_MO_CLS_RX				= 0x0c,
};

static const struct value_string om2k_msgcode_vals[] = {
	{ 0x0000, "Abort SP Command" },
	{ 0x0002, "Abort SP Complete" },
	{ 0x0004, "Alarm Report ACK" },
	{ 0x0005, "Alarm Report NACK" },
	{ 0x0006, "Alarm Report" },
	{ 0x0008, "Alarm Status Request" },
	{ 0x000a, "Alarm Status Request Accept" },
	{ 0x000b, "Alarm Status Request Reject" },
	{ 0x000c, "Alarm Status Result ACK" },
	{ 0x000d, "Alarm Status Result NACK" },
	{ 0x000e, "Alarm Status Result" },
	{ 0x0010, "Calendar Time Response" },
	{ 0x0011, "Calendar Time Reject" },
	{ 0x0012, "Calendar Time Request" },
	{ 0x0014, "CON Configuration Request" },
	{ 0x0016, "CON Configuration Request Accept" },
	{ 0x0017, "CON Configuration Request Reject" },
	{ 0x0018, "CON Configuration Result ACK" },
	{ 0x0019, "CON Configuration Result NACK" },
	{ 0x001a, "CON Configuration Result" },
	{ 0x001c, "Connect Command" },
	{ 0x001e, "Connect Complete" },
	{ 0x001f, "Connect Rejecte" },
	{ 0x0028, "Disable Request" },
	{ 0x002a, "Disable Request Accept" },
	{ 0x002b, "Disable Request Reject" },
	{ 0x002c, "Disable Result ACK" },
	{ 0x002d, "Disable Result NACK" },
	{ 0x002e, "Disable Result" },
	{ 0x0030, "Disconnect Command" },
	{ 0x0032, "Disconnect Complete" },
	{ 0x0033, "Disconnect Reject" },
	{ 0x0034, "Enable Request" },
	{ 0x0036, "Enable Request Accept" },
	{ 0x0037, "Enable Request Reject" },
	{ 0x0038, "Enable Result ACK" },
	{ 0x0039, "Enable Result NACK" },
	{ 0x003a, "Enable Result" },
	{ 0x003c, "Escape Downlink Normal" },
	{ 0x003d, "Escape Downlink NACK" },
	{ 0x003e, "Escape Uplink Normal" },
	{ 0x003f, "Escape Uplink NACK" },
	{ 0x0040, "Fault Report ACK" },
	{ 0x0041, "Fault Report NACK" },
	{ 0x0042, "Fault Report" },
	{ 0x0044, "File Package End Command" },
	{ 0x0046, "File Package End Result" },
	{ 0x0047, "File Package End Reject" },
	{ 0x0048, "File Relation Request" },
	{ 0x004a, "File Relation Response" },
	{ 0x004b, "File Relation Request Reject" },
	{ 0x004c, "File Segment Transfer" },
	{ 0x004e, "File Segment Transfer Complete" },
	{ 0x004f, "File Segment Transfer Reject" },
	{ 0x0050, "HW Information Request" },
	{ 0x0052, "HW Information Request Accept" },
	{ 0x0053, "HW Information Request Reject" },
	{ 0x0054, "HW Information Result ACK" },
	{ 0x0055, "HW Information Result NACK" },
	{ 0x0056, "HW Information Result" },
	{ 0x0060, "IS Configuration Request" },
	{ 0x0062, "IS Configuration Request Accept" },
	{ 0x0063, "IS Configuration Request Reject" },
	{ 0x0064, "IS Configuration Result ACK" },
	{ 0x0065, "IS Configuration Result NACK" },
	{ 0x0066, "IS Configuration Result" },
	{ 0x0068, "Load Data End" },
	{ 0x006a, "Load Data End Result" },
	{ 0x006b, "Load Data End Reject" },
	{ 0x006c, "Load Data Init" },
	{ 0x006e, "Load Data Init Accept" },
	{ 0x006f, "Load Data Init Reject" },
	{ 0x0070, "Loop Control Command" },
	{ 0x0072, "Loop Control Complete" },
	{ 0x0073, "Loop Control Reject" },
	{ 0x0074, "Operational Information" },
	{ 0x0076, "Operational Information Accept" },
	{ 0x0077, "Operational Information Reject" },
	{ 0x0078, "Reset Command" },
	{ 0x007a, "Reset Complete" },
	{ 0x007b, "Reset Reject" },
	{ 0x007c, "RX Configuration Request" },
	{ 0x007e, "RX Configuration Request Accept" },
	{ 0x007f, "RX Configuration Request Reject" },
	{ 0x0080, "RX Configuration Result ACK" },
	{ 0x0081, "RX Configuration Result NACK" },
	{ 0x0082, "RX Configuration Result" },
	{ 0x0084, "Start Request" },
	{ 0x0086, "Start Request Accept" },
	{ 0x0087, "Start Request Reject" },
	{ 0x0088, "Start Result ACK" },
	{ 0x0089, "Start Result NACK" },
	{ 0x008a, "Start Result" },
	{ 0x008c, "Status Request" },
	{ 0x008e, "Status Response" },
	{ 0x008f, "Status Reject" },
	{ 0x0094, "Test Request" },
	{ 0x0096, "Test Request Accept" },
	{ 0x0097, "Test Request Reject" },
	{ 0x0098, "Test Result ACK" },
	{ 0x0099, "Test Result NACK" },
	{ 0x009a, "Test Result" },
	{ 0x00a0, "TF Configuration Request" },
	{ 0x00a2, "TF Configuration Request Accept" },
	{ 0x00a3, "TF Configuration Request Reject" },
	{ 0x00a4, "TF Configuration Result ACK" },
	{ 0x00a5, "TF Configuration Result NACK" },
	{ 0x00a6, "TF Configuration Result" },
	{ 0x00a8, "TS Configuration Request" },
	{ 0x00aa, "TS Configuration Request Accept" },
	{ 0x00ab, "TS Configuration Request Reject" },
	{ 0x00ac, "TS Configuration Result ACK" },
	{ 0x00ad, "TS Configuration Result NACK" },
	{ 0x00ae, "TS Configuration Result" },
	{ 0x00b0, "TX Configuration Request" },
	{ 0x00b2, "TX Configuration Request Accept" },
	{ 0x00b3, "TX Configuration Request Reject" },
	{ 0x00b4, "TX Configuration Result ACK" },
	{ 0x00b5, "TX Configuration Result NACK" },
	{ 0x00b6, "TX Configuration Result" },
	{ 0x00bc, "DIP Alarm Report ACK" },
	{ 0x00bd, "DIP Alarm Report NACK" },
	{ 0x00be, "DIP Alarm Report" },
	{ 0x00c0, "DIP Alarm Status Request" },
	{ 0x00c2, "DIP Alarm Status Response" },
	{ 0x00c3, "DIP Alarm Status Reject" },
	{ 0x00c4, "DIP Quality Report I ACK" },
	{ 0x00c5, "DIP Quality Report I NACK" },
	{ 0x00c6, "DIP Quality Report I" },
	{ 0x00c8, "DIP Quality Report II ACK" },
	{ 0x00c9, "DIP Quality Report II NACK" },
	{ 0x00ca, "DIP Quality Report II" },
	{ 0x00dc, "DP Configuration Request" },
	{ 0x00de, "DP Configuration Request Accept" },
	{ 0x00df, "DP Configuration Request Reject" },
	{ 0x00e0, "DP Configuration Result ACK" },
	{ 0x00e1, "DP Configuration Result NACK" },
	{ 0x00e2, "DP Configuration Result" },
	{ 0x00e4, "Capabilities HW Info Report ACK" },
	{ 0x00e5, "Capabilities HW Info Report NACK" },
	{ 0x00e6, "Capabilities HW Info Report" },
	{ 0x00e8, "Capabilities Request" },
	{ 0x00ea, "Capabilities Request Accept" },
	{ 0x00eb, "Capabilities Request Reject" },
	{ 0x00ec, "Capabilities Result ACK" },
	{ 0x00ed, "Capabilities Result NACK" },
	{ 0x00ee, "Capabilities Result" },
	{ 0x00f0, "FM Configuration Request" },
	{ 0x00f2, "FM Configuration Request Accept" },
	{ 0x00f3, "FM Configuration Request Reject" },
	{ 0x00f4, "FM Configuration Result ACK" },
	{ 0x00f5, "FM Configuration Result NACK" },
	{ 0x00f6, "FM Configuration Result" },
	{ 0x00f8, "FM Report Request" },
	{ 0x00fa, "FM Report Response" },
	{ 0x00fb, "FM Report Reject" },
	{ 0x00fc, "FM Start Command" },
	{ 0x00fe, "FM Start Complete" },
	{ 0x00ff, "FM Start Reject" },
	{ 0x0100, "FM Stop Command" },
	{ 0x0102, "FM Stop Complete" },
	{ 0x0103, "FM Stop Reject" },
	{ 0x0104, "Negotiation Request ACK" },
	{ 0x0105, "Negotiation Request NACK" },
	{ 0x0106, "Negotiation Request" },
	{ 0x0108, "BTS Initiated Request ACK" },
	{ 0x0109, "BTS Initiated Request NACK" },
	{ 0x010a, "BTS Initiated Request" },
	{ 0x010c, "Radio Channels Release Command" },
	{ 0x010e, "Radio Channels Release Complete" },
	{ 0x010f, "Radio Channels Release Reject" },
	{ 0x0118, "Feature Control Command" },
	{ 0x011a, "Feature Control Complete" },
	{ 0x011b, "Feature Control Reject" },

	{ 0, NULL }
};

/* TS 12.21 Section 9.4: Attributes */
static const struct value_string om2k_attr_vals[] = {
	{ 0x00, "Accordance indication" },
	{ 0x01, "Alarm Id" },
	{ 0x02, "Alarm Data" },
	{ 0x03, "Alarm Severity" },
	{ 0x04, "Alarm Status" },
	{ 0x05, "Alarm Status Type" },
	{ 0x06, "BCC" },
	{ 0x07, "BS_AG_BKS_RES" },
	{ 0x09, "BSIC" },
	{ 0x0a, "BA_PA_MFRMS" },
	{ 0x0b, "CBCH Indicator" },
	{ 0x0c, "CCCH Options" },
	{ 0x0d, "Calendar Time" },
	{ 0x0f, "Channel Combination" },
	{ 0x10, "CON Connection List" },
	{ 0x11, "Data End Indication" },
	{ 0x12, "DRX_DEV_MAX" },
	{ 0x13, "End List Number" },
	{ 0x14, "External Condition Map Class 1" },
	{ 0x15, "External Condition Map Class 2" },
	{ 0x16, "File Relation Indication" },
	{ 0x17, "File Revision" },
	{ 0x18, "File Segment Data" },
	{ 0x19, "File Segment Length" },
	{ 0x1a, "File Segment Sequence Number" },
	{ 0x1b, "File Size" },
	{ 0x1c, "Filling Marker" },
	{ 0x1d, "FN Offset" },
	{ 0x1e, "Frequency List" },
	{ 0x1f, "Frequency Specifier RX" },
	{ 0x20, "Frequency Specifier TX" },
	{ 0x21, "HSN" },
	{ 0x22, "ICM Indicator" },
	{ 0x23, "Internal Fault Map Class 1A" },
	{ 0x24, "Internal Fault Map Class 1B" },
	{ 0x25, "Internal Fault Map Class 2A" },
	{ 0x26, "Internal Fault Map Class 2A Extension" },
	{ 0x27, "IS Connection List" },
	{ 0x28, "List Number" },
	{ 0x29, "File Package State Indication" },
	{ 0x2a, "Local Access State" },
	{ 0x2b, "MAIO" },
	{ 0x2c, "MO State" },
	{ 0x2d, "Ny1" },
	{ 0x2e, "Operational Information" },
	{ 0x2f, "Power" },
	{ 0x30, "RU Position Data" },
	{ 0x31, "Protocol Error" },
	{ 0x32, "Reason Code" },
	{ 0x33, "Receiver Diversity" },
	{ 0x34, "Replacement Unit Map" },
	{ 0x35, "Result Code" },
	{ 0x36, "RU Revision Data" },
	{ 0x38, "T3105" },
	{ 0x39, "Test Loop Setting" },
	{ 0x3a, "TF Mode" },
	{ 0x3b, "TF Compensation Value" },
	{ 0x3c, "Time Slot Number" },
	{ 0x3d, "TSC" },
	{ 0x3e, "RU Logical Id" },
	{ 0x3f, "RU Serial Number Data" },
	{ 0x40, "BTS Version" },
	{ 0x41, "OML IWD Version" },
	{ 0x42, "RWL IWD Version" },
	{ 0x43, "OML Function Map 1" },
	{ 0x44, "OML Function Map 2" },
	{ 0x45, "RSL Function Map 1" },
	{ 0x46, "RSL Function Map 2" },
	{ 0x47, "Extended Range Indicator" },
	{ 0x48, "Request Indicators" },
	{ 0x49, "DIP Alarm Condition Map" },
	{ 0x4a, "ES Incoming" },
	{ 0x4b, "ES Outgoing" },
	{ 0x4e, "SES Incoming" },
	{ 0x4f, "SES Outgoing" },
	{ 0x50, "Replacement Unit Map Extension" },
	{ 0x52, "UAS Incoming" },
	{ 0x53, "UAS Outgoing" },
	{ 0x58, "DF Incoming" },
	{ 0x5a, "DF Outgoing" },
	{ 0x5c, "SF" },
	{ 0x60, "S Bits Setting" },
	{ 0x61, "CRC-4 Use Option" },
	{ 0x62, "T Parameter" },
	{ 0x63, "N Parameter" },
	{ 0x64, "N1 Parameter" },
	{ 0x65, "N3 Parameter" },
	{ 0x66, "N4 Parameter" },
	{ 0x67, "P Parameter" },
	{ 0x68, "Q Parameter" },
	{ 0x69, "BI_Q1" },
	{ 0x6a, "BI_Q2" },
	{ 0x74, "ICM Boundary Parameters" },
	{ 0x77, "AFT" },
	{ 0x78, "AFT RAI" },
	{ 0x79, "Link Supervision Control" },
	{ 0x7a, "Link Supervision Filtering Time" },
	{ 0x7b, "Call Supervision Time" },
	{ 0x7c, "Interval Length UAS Incoming" },
	{ 0x7d, "Interval Length UAS Outgoing" },
	{ 0x7e, "ICM Channel Rate" },
	{ 0x7f, "Attribute Identifier" },
	{ 0x80, "FM Frequency List" },
	{ 0x81, "FM Frequency Report" },
	{ 0x82, "FM Percentile" },
	{ 0x83, "FM Clear Indication" },
	{ 0x84, "HW Info Signature" },
	{ 0x85, "MO Record" },
	{ 0x86, "TF Synchronisation Source" },
	{ 0x87, "TTA" },
	{ 0x88, "End Segment Number" },
	{ 0x89, "Segment Number" },
	{ 0x8a, "Capabilities Signature" },
	{ 0x8c, "File Relation List" },
	{ 0x90, "Negotiation Record I" },
	{ 0x91, "Negotiation Record II" },
	{ 0x92, "Encryption Algorithm" },
	{ 0x94, "Interference Rejection Combining" },
	{ 0x95, "Dedication Information" },
	{ 0x97, "Feature Code" },
	{ 0x98, "FS Offset" },
	{ 0x99, "ESB Timeslot" },
	{ 0x9a, "Master TG Instance" },
	{ 0x9b, "Master TX Chain Delay" },
	{ 0x9c, "External Condition Class 2 Extension" },
	{ 0x9d, "TSs MO State" },
	{ 0, NULL }
};

const struct value_string om2k_mo_class_short_vals[] = {
	{ 0x01, "TRXC" },
	{ 0x03, "TS" },
	{ 0x04, "TF" },
	{ 0x05, "IS" },
	{ 0x06, "CON" },
	{ 0x07, "DP" },
	{ 0x0a, "CF" },
	{ 0x0b, "TX" },
	{ 0x0c, "RX" },
	{ 0, NULL }
};

static struct msgb *om2k_msgb_alloc(void)
{
	return msgb_alloc_headroom(OM_ALLOC_SIZE, OM_HEADROOM_SIZE,
				   "OM2000");
}

static int abis_om2k_sendmsg(struct gsm_bts *bts, struct msgb *msg)
{
	msg->trx = bts->c0;

	return _abis_nm_sendmsg(msg);
}

static void fill_om2k_hdr(struct abis_om2k_hdr *o2h, const struct abis_om2k_mo *mo,
			 uint16_t msg_type, uint8_t attr_len)
{
	o2h->om.mdisc = ABIS_OM_MDISC_FOM;
	o2h->om.placement = ABIS_OM_PLACEMENT_ONLY;
	o2h->om.sequence = 0;
	o2h->om.length = 6 + attr_len;
	o2h->msg_type = htons(msg_type);
	memcpy(&o2h->mo, mo, sizeof(o2h->mo));
}

static char *om2k_mo_name(const struct abis_om2k_mo *mo)
{
	static char mo_buf[64];

	memset(mo_buf, 0, sizeof(mo_buf));
	snprintf(mo_buf, sizeof(mo_buf), "%s/%02x/%02x/%02x",
		 get_value_string(om2k_mo_class_short_vals, mo->class),
		 mo->bts, mo->assoc_so, mo->inst);
	return mo_buf;
}

const struct abis_om2k_mo om2k_mo_cf = { OM2K_MO_CLS_CF, 0, 0xFF, 0 };
const struct abis_om2k_mo om2k_mo_is = { OM2K_MO_CLS_IS, 0, 0xFF, 0 };

static int abis_om2k_cal_time_resp(struct gsm_bts *bts)
{
	struct msgb *msg = om2k_msgb_alloc();
	struct abis_om2k_hdr *o2k;
	time_t tm_t;
	struct tm *tm;

	o2k = (struct abis_om2k_hdr *) msgb_put(msg, sizeof(*o2k));
	fill_om2k_hdr(o2k, &om2k_mo_cf, OM2K_MSGT_CAL_TIME_RESP, 7);

	tm_t = time(NULL);
	tm = localtime(&tm_t);

	msgb_put_u8(msg, OM2K_DEI_CAL_TIME);
	msgb_put_u8(msg, tm->tm_year % 100);
	msgb_put_u8(msg, tm->tm_mon + 1);
	msgb_put_u8(msg, tm->tm_mday);
	msgb_put_u8(msg, tm->tm_hour);
	msgb_put_u8(msg, tm->tm_min);
	msgb_put_u8(msg, tm->tm_sec);

	return abis_om2k_sendmsg(bts, msg);
}

static int abis_om2k_tx_simple(struct gsm_bts *bts, const struct abis_om2k_mo *mo,
				uint8_t msg_type)
{
	struct msgb *msg = om2k_msgb_alloc();
	struct abis_om2k_hdr *o2k;

	o2k = (struct abis_om2k_hdr *) msgb_put(msg, sizeof(*o2k));
	fill_om2k_hdr(o2k, mo, msg_type, 0);

	DEBUGP(DNM, "Tx MO=%s %s\n", om2k_mo_name(mo),
		get_value_string(om2k_msgcode_vals, msg_type));

	return abis_om2k_sendmsg(bts, msg);
}

int abis_om2k_tx_reset_cmd(struct gsm_bts *bts, const struct abis_om2k_mo *mo)
{
	return abis_om2k_tx_simple(bts, mo, OM2K_MSGT_RESET_CMD);
}

int abis_om2k_tx_start_req(struct gsm_bts *bts, const struct abis_om2k_mo *mo)
{
	return abis_om2k_tx_simple(bts, mo, OM2K_MSGT_START_REQ);
}

int abis_om2k_tx_status_req(struct gsm_bts *bts, const struct abis_om2k_mo *mo)
{
	return abis_om2k_tx_simple(bts, mo, OM2K_MSGT_STATUS_REQ);
}

int abis_om2k_tx_connect_cmd(struct gsm_bts *bts, const struct abis_om2k_mo *mo)
{
	return abis_om2k_tx_simple(bts, mo, OM2K_MSGT_CONNECT_CMD);
}

int abis_om2k_tx_disconnect_cmd(struct gsm_bts *bts, const struct abis_om2k_mo *mo)
{
	return abis_om2k_tx_simple(bts, mo, OM2K_MSGT_DISCONNECT_CMD);
}

int abis_om2k_tx_test_req(struct gsm_bts *bts, const struct abis_om2k_mo *mo)
{
	return abis_om2k_tx_simple(bts, mo, OM2K_MSGT_TEST_REQ);
}

int abis_om2k_tx_enable_req(struct gsm_bts *bts, const struct abis_om2k_mo *mo)
{
	return abis_om2k_tx_simple(bts, mo, OM2K_MSGT_ENABLE_REQ);
}

int abis_om2k_tx_disable_req(struct gsm_bts *bts, const struct abis_om2k_mo *mo)
{
	return abis_om2k_tx_simple(bts, mo, OM2K_MSGT_DISABLE_REQ);
}

int abis_om2k_tx_op_info(struct gsm_bts *bts, const struct abis_om2k_mo *mo,
			 uint8_t operational)
{
	struct msgb *msg = om2k_msgb_alloc();
	struct abis_om2k_hdr *o2k;

	o2k = (struct abis_om2k_hdr *) msgb_put(msg, sizeof(*o2k));
	fill_om2k_hdr(o2k, mo, OM2K_MSGT_OP_INFO, 2);

	msgb_tv_put(msg, OM2K_DEI_OP_INFO, operational);

	DEBUGP(DNM, "Tx MO=%s %s\n", om2k_mo_name(mo),
		get_value_string(om2k_msgcode_vals, OM2K_MSGT_OP_INFO));

	return abis_om2k_sendmsg(bts, msg);
}

int abis_om2k_tx_is_conf_req(struct gsm_bts *bts, struct om2k_is_conn_grp *cg,
			     unsigned int num_cg )
{
	struct msgb *msg = om2k_msgb_alloc();
	struct abis_om2k_hdr *o2k;

	o2k = (struct abis_om2k_hdr *) msgb_put(msg, sizeof(*o2k));
	fill_om2k_hdr(o2k, &om2k_mo_is, OM2K_MSGT_IS_CONF_REQ,
		      2 + 2 + TLV_GROSS_LEN(num_cg * sizeof(*cg)));

	msgb_tv_put(msg, OM2K_DEI_LIST_NR, 1);
	msgb_tv_put(msg, OM2K_DEI_END_LIST_NR, 1);

	msgb_tlv_put(msg, OM2K_DEI_IS_CONN_LIST,
		     num_cg * sizeof(*cg), (uint8_t *)cg);

	return abis_om2k_sendmsg(bts, msg);
}

static int abis_om2k_tx_negot_req_ack(struct gsm_bts *bts, const struct abis_om2k_mo *mo,
				      uint8_t *data, unsigned int len)
{
	struct msgb *msg = om2k_msgb_alloc();
	struct abis_om2k_hdr *o2k;

	o2k = (struct abis_om2k_hdr *) msgb_put(msg, sizeof(*o2k));
	fill_om2k_hdr(o2k, mo, OM2K_MSGT_NEGOT_REQ_ACK, 2+len);

	msgb_tlv_put(msg, OM2K_DEI_NEGOT_REC2, len, data);

	DEBUGP(DNM, "Tx MO=%s %s\n", om2k_mo_name(mo),
		get_value_string(om2k_msgcode_vals, OM2K_MSGT_NEGOT_REQ_ACK));

	return abis_om2k_sendmsg(bts, msg);
}

struct iwd_version {
	uint8_t gen_char[3+1];
	uint8_t rev_char[3+1];
};

struct iwd_type {
	uint8_t num_vers;
	struct iwd_version v[8];
};

static int om2k_rx_negot_req(struct msgb *msg)
{
	struct abis_om2k_hdr *o2h = msgb_l2(msg);
	struct iwd_type iwd_types[16];
	uint8_t num_iwd_types = o2h->data[2];
	uint8_t *cur = o2h->data+3;
	unsigned int i, v;

	uint8_t out_buf[1024];
	uint8_t *out_cur = out_buf+1;
	uint8_t out_num_types = 0;

	memset(iwd_types, 0, sizeof(iwd_types));

	/* Parse the RBS-supported IWD versions into iwd_types array */
	for (i = 0; i < num_iwd_types; i++) {
		uint8_t num_versions = *cur++;
		uint8_t iwd_type = *cur++;

		iwd_types[iwd_type].num_vers = num_versions;

		for (v = 0; v < num_versions; v++) {
			struct iwd_version *iwd_v = &iwd_types[iwd_type].v[v];

			memcpy(iwd_v->gen_char, cur, 3);
			cur += 3;
			memcpy(iwd_v->rev_char, cur, 3);
			cur += 3;

			DEBUGP(DNM, "\tIWD Type %u Gen %s Rev %s\n", iwd_type,
				iwd_v->gen_char, iwd_v->rev_char);
		}
	}

	/* Select the last version for each IWD type */
	for (i = 0; i < ARRAY_SIZE(iwd_types); i++) {
		struct iwd_type *type = &iwd_types[i];
		struct iwd_version *last_v;

		if (type->num_vers == 0)
			continue;

		out_num_types++;

		last_v = &type->v[type->num_vers-1];

		*out_cur++ = i;
		memcpy(out_cur, last_v->gen_char, 3);
		out_cur += 3;
		memcpy(out_cur, last_v->rev_char, 3);
		out_cur += 3;
	}

	out_buf[0] = out_num_types;

	return abis_om2k_tx_negot_req_ack(msg->trx->bts, &o2h->mo, out_buf, out_cur - out_buf);
}

static int om2k_rx_start_res(struct msgb *msg)
{
	struct abis_om2k_hdr *o2h = msgb_l2(msg);
	int rc;

	rc = abis_om2k_tx_simple(msg->trx->bts, &o2h->mo, OM2K_MSGT_START_RES_ACK);
	rc = abis_om2k_tx_op_info(msg->trx->bts, &o2h->mo, 1);

	return rc;
}

static int om2k_rx_op_info_ack(struct msgb *msg)
{
	struct abis_om2k_hdr *o2h = msgb_l2(msg);

	/* FIXME: update Operational state in our structures */

	return 0;
}

int abis_om2k_rcvmsg(struct msgb *msg)
{
	struct gsm_bts *bts = msg->trx->bts;
	struct abis_om2k_hdr *o2h = msgb_l2(msg);
	struct abis_om_hdr *oh = &o2h->om;
	uint16_t msg_type = ntohs(o2h->msg_type);
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

	msg->l3h = (unsigned char *)o2h + sizeof(*o2h);

	if (oh->mdisc != ABIS_OM_MDISC_FOM) {
		LOGP(DNM, LOGL_ERROR, "unknown ABIS OM2000 message discriminator 0x%x\n",
			oh->mdisc);
		return -EINVAL;
	}

	DEBUGP(DNM, "Rx MO=%s %s (%s)\n", om2k_mo_name(&o2h->mo),
		get_value_string(om2k_msgcode_vals, msg_type),
		hexdump(msg->l2h, msgb_l2len(msg)));

	switch (msg_type) {
	case OM2K_MSGT_CAL_TIME_REQ:
		rc = abis_om2k_cal_time_resp(bts);
		break;
	case OM2K_MSGT_FAULT_REP:
		rc = abis_om2k_tx_simple(bts, &o2h->mo, OM2K_MSGT_FAULT_REP_ACK);
		break;
	case OM2K_MSGT_NEGOT_REQ:
		rc = om2k_rx_negot_req(msg);
		break;
	case OM2K_MSGT_START_RES:
		rc = om2k_rx_start_res(msg);
		break;
	case OM2K_MSGT_OP_INFO_ACK:
		rc = om2k_rx_op_info_ack(msg);
		break;
	case OM2K_MSGT_IS_CONF_RES:
		rc = abis_om2k_tx_simple(bts, &o2h->mo, OM2K_MSGT_IS_CONF_RES_ACK);
		break;
	case OM2K_MSGT_CONNECT_COMPL:
		rc = abis_om2k_tx_simple(bts, &o2h->mo, OM2K_MSGT_RESET_CMD);
		break;
	case OM2K_MSGT_RESET_COMPL:
		rc = abis_om2k_tx_simple(bts, &o2h->mo, OM2K_MSGT_START_REQ);
		break;
	case OM2K_MSGT_ENABLE_RES:
		rc = abis_om2k_tx_simple(bts, &o2h->mo, OM2K_MSGT_ENABLE_RES_ACK);
		break;
	case OM2K_MSGT_START_REQ_ACK:
		break;
	case OM2K_MSGT_STATUS_RESP:
		break;
	default:
		LOGP(DNM, LOGL_NOTICE, "Rx unhandled OM2000 msg %s\n",
			get_value_string(om2k_msgcode_vals, msg_type));
	}

	msgb_free(msg);
	return rc;
}
