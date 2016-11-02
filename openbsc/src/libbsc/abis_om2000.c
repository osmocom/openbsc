/* Ericsson RBS 2xxx GSM O&M (OM2000) messages on the A-bis interface
 * implemented based on protocol trace analysis, no formal documentation */

/* (C) 2010-2011,2016 by Harald Welte <laforge@gnumonks.org>
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

#include <osmocom/core/msgb.h>
#include <osmocom/gsm/tlv.h>
#include <osmocom/core/talloc.h>
#include <osmocom/core/utils.h>
#include <osmocom/core/fsm.h>

#include <openbsc/gsm_data.h>
#include <openbsc/debug.h>
#include <openbsc/abis_nm.h>
#include <openbsc/abis_rsl.h>
#include <openbsc/abis_om2000.h>
#include <openbsc/signal.h>
#include <osmocom/abis/e1_input.h>

/* FIXME: move to libosmocore */
struct osmo_fsm_inst *osmo_fsm_inst_alloc_child_id(struct osmo_fsm *fsm,
						   struct osmo_fsm_inst *parent,
						   uint32_t parent_term_event,
						   const char *id)
{
	struct osmo_fsm_inst *fi;

	fi = osmo_fsm_inst_alloc(fsm, parent, NULL, parent->log_level,
				 id ? id : parent->id);
	if (!fi) {
		/* indicate immediate termination to caller */
		osmo_fsm_inst_dispatch(parent, parent_term_event, NULL);
		return NULL;
	}

	LOGPFSM(fi, "is child of %s\n", osmo_fsm_inst_name(parent));

	fi->proc.parent = parent;
	fi->proc.parent_term_event = parent_term_event;
	llist_add(&fi->proc.child, &parent->proc.children);

	return fi;
}


#define OM_ALLOC_SIZE		1024
#define OM_HEADROOM_SIZE	128

#define OM2K_TIMEOUT	10
#define TRX_FSM_TIMEOUT	60
#define BTS_FSM_TIMEOUT	60

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

	OM2K_MSGT_CON_CONF_REQ			= 0x0014,
	OM2K_MSGT_CON_CONF_REQ_ACK		= 0x0016,
	OM2K_MSGT_CON_CONF_REQ_REJ		= 0x0017,
	OM2K_MSGT_CON_CONF_RES_ACK		= 0x0018,
	OM2K_MSGT_CON_CONF_RES_NACK		= 0x0019,
	OM2K_MSGT_CON_CONF_RES			= 0x001a,

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
	OM2K_MSGT_RX_CONF_REQ			= 0x007c,
	OM2K_MSGT_RX_CONF_REQ_ACK		= 0x007e,
	OM2K_MSGT_RX_CONF_REQ_REJ		= 0x007f,
	OM2K_MSGT_RX_CONF_RES_ACK		= 0x0080,
	OM2K_MSGT_RX_CONF_RES_NACK		= 0x0081,
	OM2K_MSGT_RX_CONF_RES			= 0x0082,
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

	OM2K_MSGT_TF_CONF_REQ			= 0x00a0,
	OM2K_MSGT_TF_CONF_REQ_ACK		= 0x00a2,
	OM2K_MSGT_TF_CONF_REQ_REJ		= 0x00a3,
	OM2K_MSGT_TF_CONF_RES_ACK		= 0x00a4,
	OM2K_MSGT_TF_CONF_RES_NACK		= 0x00a5,
	OM2K_MSGT_TF_CONF_RES			= 0x00a6,
	OM2K_MSGT_TS_CONF_REQ			= 0x00a8,
	OM2K_MSGT_TS_CONF_REQ_ACK		= 0x00aa,
	OM2K_MSGT_TS_CONF_REQ_REJ		= 0x00ab,
	OM2K_MSGT_TS_CONF_RES_ACK		= 0x00ac,
	OM2K_MSGT_TS_CONF_RES_NACK		= 0x00ad,
	OM2K_MSGT_TS_CONF_RES			= 0x00ae,
	OM2K_MSGT_TX_CONF_REQ			= 0x00b0,
	OM2K_MSGT_TX_CONF_REQ_ACK		= 0x00b2,
	OM2K_MSGT_TX_CONF_REQ_REJ		= 0x00b3,
	OM2K_MSGT_TX_CONF_RES_ACK		= 0x00b4,
	OM2K_MSGT_TX_CONF_RES_NACK		= 0x00b5,
	OM2K_MSGT_TX_CONF_RES			= 0x00b6,

	OM2K_MSGT_CAPA_REQ			= 0x00e8,
	OM2K_MSGT_CAPA_REQ_ACK			= 0x00ea,
	OM2K_MSGT_CAPA_REQ_REJ			= 0x00eb,
	OM2K_MSGT_CAPA_RES			= 0x00ee,
	OM2K_MSGT_CAPA_RES_ACK			= 0x00ec,
	OM2K_MSGT_CAPA_RES_NACK			= 0x00ed,

	OM2K_MSGT_NEGOT_REQ_ACK			= 0x0104,
	OM2K_MSGT_NEGOT_REQ_NACK		= 0x0105,
	OM2K_MSGT_NEGOT_REQ			= 0x0106,
};

enum abis_om2k_dei {
	OM2K_DEI_ACCORDANCE_IND			= 0x00,
	OM2K_DEI_BCC				= 0x06,
	OM2K_DEI_BS_AG_BKS_RES			= 0x07,
	OM2K_DEI_BSIC				= 0x09,
	OM2K_DEI_BA_PA_MFRMS			= 0x0a,
	OM2K_DEI_CBCH_INDICATOR			= 0x0b,
	OM2K_DEI_CCCH_OPTIONS			= 0x0c,
	OM2K_DEI_CAL_TIME			= 0x0d,
	OM2K_DEI_COMBINATION			= 0x0f,
	OM2K_DEI_CON_CONN_LIST			= 0x10,
	OM2K_DEI_DRX_DEV_MAX			= 0x12,
	OM2K_DEI_END_LIST_NR			= 0x13,
	OM2K_DEI_EXT_COND_MAP_1			= 0x14,
	OM2K_DEI_EXT_COND_MAP_2			= 0x15,
	OM2K_DEI_FILLING_MARKER			= 0x1c,
	OM2K_DEI_FN_OFFSET			= 0x1d,
	OM2K_DEI_FREQ_LIST			= 0x1e,
	OM2K_DEI_FREQ_SPEC_RX			= 0x1f,
	OM2K_DEI_FREQ_SPEC_TX			= 0x20,
	OM2K_DEI_HSN				= 0x21,
	OM2K_DEI_ICM_INDICATOR			= 0x22,
	OM2K_DEI_INT_FAULT_MAP_1A		= 0x23,
	OM2K_DEI_INT_FAULT_MAP_1B		= 0x24,
	OM2K_DEI_INT_FAULT_MAP_2A		= 0x25,
	OM2K_DEI_INT_FAULT_MAP_2A_EXT		= 0x26,
	OM2K_DEI_IS_CONN_LIST			= 0x27,
	OM2K_DEI_LIST_NR			= 0x28,
	OM2K_DEI_LOCAL_ACCESS			= 0x2a,
	OM2K_DEI_MAIO				= 0x2b,
	OM2K_DEI_MO_STATE			= 0x2c,
	OM2K_DEI_NY1				= 0x2d,
	OM2K_DEI_OP_INFO			= 0x2e,
	OM2K_DEI_POWER				= 0x2f,
	OM2K_DEI_REASON_CODE			= 0x32,
	OM2K_DEI_RX_DIVERSITY			= 0x33,
	OM2K_DEI_REPL_UNIT_MAP			= 0x34,
	OM2K_DEI_RESULT_CODE			= 0x35,
	OM2K_DEI_T3105				= 0x38,
	OM2K_DEI_TF_MODE			= 0x3a,
	OM2K_DEI_TS_NR				= 0x3c,
	OM2K_DEI_TSC				= 0x3d,
	OM2K_DEI_BTS_VERSION			= 0x40,
	OM2K_DEI_OML_IWD_VERSION		= 0x41,
	OM2K_DEI_RSL_IWD_VERSION		= 0x42,
	OM2K_DEI_OML_FUNC_MAP_1			= 0x43,
	OM2K_DEI_OML_FUNC_MAP_2			= 0x44,
	OM2K_DEI_RSL_FUNC_MAP_1			= 0x45,
	OM2K_DEI_RSL_FUNC_MAP_2			= 0x46,
	OM2K_DEI_EXT_RANGE			= 0x47,
	OM2K_DEI_REQ_IND			= 0x48,
	OM2K_DEI_REPL_UNIT_MAP_EXT		= 0x50,
	OM2K_DEI_ICM_BOUND_PARAMS		= 0x74,
	OM2K_DEI_LSC				= 0x79,
	OM2K_DEI_LSC_FILT_TIME			= 0x7a,
	OM2K_DEI_CALL_SUPV_TIME			= 0x7b,
	OM2K_DEI_ICM_CHAN_RATE			= 0x7e,
	OM2K_DEI_HW_INFO_SIG			= 0x84,
	OM2K_DEI_TF_SYNC_SRC			= 0x86,
	OM2K_DEI_TTA				= 0x87,
	OM2K_DEI_CAPA_SIG			= 0x8a,
	OM2K_DEI_NEGOT_REC1			= 0x90,
	OM2K_DEI_NEGOT_REC2			= 0x91,
	OM2K_DEI_ENCR_ALG			= 0x92,
	OM2K_DEI_INTERF_REJ_COMB		= 0x94,
	OM2K_DEI_FS_OFFSET			= 0x98,
	OM2K_DEI_EXT_COND_MAP_2_EXT		= 0x9c,
	OM2K_DEI_TSS_MO_STATE			= 0x9d,
};

const struct tlv_definition om2k_att_tlvdef = {
	.def = {
		[OM2K_DEI_ACCORDANCE_IND] =	{ TLV_TYPE_TV },
		[OM2K_DEI_BCC] =		{ TLV_TYPE_TV },
		[OM2K_DEI_BS_AG_BKS_RES] =	{ TLV_TYPE_TV },
		[OM2K_DEI_BSIC] =		{ TLV_TYPE_TV },
		[OM2K_DEI_BA_PA_MFRMS] =	{ TLV_TYPE_TV },
		[OM2K_DEI_CBCH_INDICATOR] =	{ TLV_TYPE_TV },
		[OM2K_DEI_INT_FAULT_MAP_1A] =	{ TLV_TYPE_FIXED, 6 },
		[OM2K_DEI_INT_FAULT_MAP_1B] =	{ TLV_TYPE_FIXED, 6 },
		[OM2K_DEI_INT_FAULT_MAP_2A] =	{ TLV_TYPE_FIXED, 6 },
		[OM2K_DEI_INT_FAULT_MAP_2A_EXT]={ TLV_TYPE_FIXED, 6 },
		[OM2K_DEI_CCCH_OPTIONS] =	{ TLV_TYPE_TV },
		[OM2K_DEI_CAL_TIME] =		{ TLV_TYPE_FIXED, 6 },
		[OM2K_DEI_COMBINATION] =	{ TLV_TYPE_TV },
		[OM2K_DEI_CON_CONN_LIST] =	{ TLV_TYPE_TLV },
		[OM2K_DEI_DRX_DEV_MAX] =	{ TLV_TYPE_TV },
		[OM2K_DEI_END_LIST_NR] =	{ TLV_TYPE_TV },
		[OM2K_DEI_EXT_COND_MAP_1] =	{ TLV_TYPE_FIXED, 2 },
		[OM2K_DEI_EXT_COND_MAP_2] =	{ TLV_TYPE_FIXED, 2 },
		[OM2K_DEI_FILLING_MARKER] =	{ TLV_TYPE_TV },
		[OM2K_DEI_FN_OFFSET] =		{ TLV_TYPE_FIXED, 2 },
		[OM2K_DEI_FREQ_LIST] =		{ TLV_TYPE_TLV },
		[OM2K_DEI_FREQ_SPEC_RX] =	{ TLV_TYPE_FIXED, 2 },
		[OM2K_DEI_FREQ_SPEC_TX] =	{ TLV_TYPE_FIXED, 2 },
		[OM2K_DEI_HSN] =		{ TLV_TYPE_TV },
		[OM2K_DEI_ICM_INDICATOR] =	{ TLV_TYPE_TV },
		[OM2K_DEI_IS_CONN_LIST] =	{ TLV_TYPE_TLV },
		[OM2K_DEI_LIST_NR] =		{ TLV_TYPE_TV },
		[OM2K_DEI_LOCAL_ACCESS] =	{ TLV_TYPE_TV },
		[OM2K_DEI_MAIO] =		{ TLV_TYPE_TV },
		[OM2K_DEI_MO_STATE] =		{ TLV_TYPE_TV },
		[OM2K_DEI_NY1] =		{ TLV_TYPE_TV },
		[OM2K_DEI_OP_INFO] =		{ TLV_TYPE_TV },
		[OM2K_DEI_POWER] =		{ TLV_TYPE_TV },
		[OM2K_DEI_REASON_CODE] =	{ TLV_TYPE_TV },
		[OM2K_DEI_RX_DIVERSITY] =	{ TLV_TYPE_TV },
		[OM2K_DEI_RESULT_CODE] =	{ TLV_TYPE_TV },
		[OM2K_DEI_T3105] = 		{ TLV_TYPE_TV },
		[OM2K_DEI_TF_MODE] =		{ TLV_TYPE_TV },
		[OM2K_DEI_TS_NR] =		{ TLV_TYPE_TV },
		[OM2K_DEI_TSC] =		{ TLV_TYPE_TV },
		[OM2K_DEI_BTS_VERSION] =	{ TLV_TYPE_FIXED, 12 },
		[OM2K_DEI_OML_IWD_VERSION] =	{ TLV_TYPE_FIXED, 6 },
		[OM2K_DEI_RSL_IWD_VERSION] =	{ TLV_TYPE_FIXED, 6 },
		[OM2K_DEI_OML_FUNC_MAP_1] =	{ TLV_TYPE_TLV },
		[OM2K_DEI_OML_FUNC_MAP_2] =	{ TLV_TYPE_TLV },
		[OM2K_DEI_RSL_FUNC_MAP_1] =	{ TLV_TYPE_TLV },
		[OM2K_DEI_RSL_FUNC_MAP_2] =	{ TLV_TYPE_TLV },
		[OM2K_DEI_EXT_RANGE] =		{ TLV_TYPE_TV },
		[OM2K_DEI_REQ_IND] =		{ TLV_TYPE_TV },
		[OM2K_DEI_REPL_UNIT_MAP] =	{ TLV_TYPE_FIXED, 6 },
		[OM2K_DEI_REPL_UNIT_MAP_EXT] =	{TLV_TYPE_FIXED, 6},
		[OM2K_DEI_ICM_BOUND_PARAMS] =	{ TLV_TYPE_FIXED, 5 },
		[OM2K_DEI_LSC] =		{ TLV_TYPE_TV },
		[OM2K_DEI_LSC_FILT_TIME] =	{ TLV_TYPE_TV },
		[OM2K_DEI_CALL_SUPV_TIME] =	{ TLV_TYPE_TV },
		[OM2K_DEI_ICM_CHAN_RATE] =	{ TLV_TYPE_TV },
		[OM2K_DEI_HW_INFO_SIG] =	{ TLV_TYPE_FIXED, 2 },
		[OM2K_DEI_TF_SYNC_SRC] =	{ TLV_TYPE_TV },
		[OM2K_DEI_TTA] =		{ TLV_TYPE_TV },
		[OM2K_DEI_CAPA_SIG] =		{ TLV_TYPE_FIXED, 2 },
		[OM2K_DEI_NEGOT_REC1] =		{ TLV_TYPE_TLV },
		[OM2K_DEI_NEGOT_REC2] =		{ TLV_TYPE_TLV },
		[OM2K_DEI_ENCR_ALG] =		{ TLV_TYPE_TV },
		[OM2K_DEI_INTERF_REJ_COMB] =	{ TLV_TYPE_TV },
		[OM2K_DEI_FS_OFFSET] =		{ TLV_TYPE_FIXED, 5 },
		[OM2K_DEI_EXT_COND_MAP_2_EXT] = { TLV_TYPE_FIXED, 4 },
		[OM2K_DEI_TSS_MO_STATE] = 	{ TLV_TYPE_FIXED, 4 },
	},
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
	{ 0x001f, "Connect Reject" },
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

const struct value_string om2k_result_strings[] = {
	{ 0x02, "Wrong state or out of sequence" },
	{ 0x03, "File error" },
	{ 0x04, "Fault, unspecified" },
	{ 0x05, "Tuning fault" },
	{ 0x06, "Protocol error" },
	{ 0x07, "MO not connected" },
	{ 0x08, "Parameter error" },
	{ 0x09, "Optional function not supported" },
	{ 0x0a, "Local access state LOCALLY DISCONNECTED" },
	{ 0, NULL }
};

const struct value_string om2k_accordance_strings[] = {
	{ 0x00, "Data according to request" },
	{ 0x01, "Data not according to request" },
	{ 0x02, "Inconsistent MO data" },
	{ 0x03, "Capability constraint violation" },
	{ 0, NULL }
};

const struct value_string om2k_mostate_vals[] = {
	{ 0x00, "RESET" },
	{ 0x01, "STARTED" },
	{ 0x02, "ENABLED" },
	{ 0x03, "DISABLED" },
	{ 0, NULL }
};

/* entire decoded OM2K message (header + parsed TLV) */
struct om2k_decoded_msg {
	struct abis_om2k_hdr o2h;
	uint16_t msg_type;
	struct tlv_parsed tp;
};

/* resolve the OM2000 Managed Object by BTS + MO Address */
static struct om2k_mo *
get_om2k_mo(struct gsm_bts *bts, const struct abis_om2k_mo *abis_mo)
{
	struct om2k_mo *mo = NULL;
	struct gsm_bts_trx *trx;

	switch (abis_mo->class) {
	case OM2K_MO_CLS_CF:
		mo = &bts->rbs2000.cf.om2k_mo;
		break;
	case OM2K_MO_CLS_CON:
		mo = &bts->rbs2000.con.om2k_mo;
		break;
	case OM2K_MO_CLS_IS:
		mo = &bts->rbs2000.is.om2k_mo;
		break;
	case OM2K_MO_CLS_TF:
		mo = &bts->rbs2000.tf.om2k_mo;
		break;

	case OM2K_MO_CLS_TRXC:
		trx = gsm_bts_trx_num(bts, abis_mo->inst);
		if (!trx)
			return NULL;
		mo = &trx->rbs2000.trxc.om2k_mo;
		break;
	case OM2K_MO_CLS_TX:
		trx = gsm_bts_trx_num(bts, abis_mo->inst);
		if (!trx)
			return NULL;
		mo = &trx->rbs2000.tx.om2k_mo;
		break;
	case OM2K_MO_CLS_RX:
		trx = gsm_bts_trx_num(bts, abis_mo->inst);
		if (!trx)
			return NULL;
		mo = &trx->rbs2000.rx.om2k_mo;
		break;
	case OM2K_MO_CLS_TS:
		trx = gsm_bts_trx_num(bts, abis_mo->assoc_so);
		if (!trx)
			return NULL;
		if (abis_mo->inst >= ARRAY_SIZE(trx->ts))
			return NULL;
		mo = &trx->ts[abis_mo->inst].rbs2000.om2k_mo;
		break;
	default:
		return NULL;
	};

	return mo;
}

static struct msgb *om2k_msgb_alloc(void)
{
	return msgb_alloc_headroom(OM_ALLOC_SIZE, OM_HEADROOM_SIZE,
				   "OM2000");
}

static int abis_om2k_tlv_parse(struct tlv_parsed *tp, const uint8_t *buf, int len)
{
	return tlv_parse(tp, &om2k_att_tlvdef, buf, len, 0, 0);
}

static int abis_om2k_msg_tlv_parse(struct tlv_parsed *tp, struct abis_om2k_hdr *oh)
{
	return abis_om2k_tlv_parse(tp, oh->data, oh->om.length - 6);
}

/* decode/parse the message */
static int om2k_decode_msg(struct om2k_decoded_msg *odm, struct msgb *msg)
{
	struct abis_om2k_hdr *o2h = msgb_l2(msg);
	odm->msg_type = ntohs(o2h->msg_type);
	odm->o2h = *o2h;
	return abis_om2k_msg_tlv_parse(&odm->tp, o2h);
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

/* resolve the gsm_nm_state data structure for a given MO */
static struct gsm_nm_state *
mo2nm_state(struct gsm_bts *bts, const struct abis_om2k_mo *mo)
{
	struct gsm_bts_trx *trx;
	struct gsm_nm_state *nm_state = NULL;

	switch (mo->class) {
	case OM2K_MO_CLS_TRXC:
		trx = gsm_bts_trx_num(bts, mo->inst);
		if (!trx)
			return NULL;
		nm_state = &trx->mo.nm_state;
		break;
	case OM2K_MO_CLS_TS:
		trx = gsm_bts_trx_num(bts, mo->assoc_so);
		if (!trx)
			return NULL;
		if (mo->inst >= ARRAY_SIZE(trx->ts))
			return NULL;
		nm_state = &trx->ts[mo->inst].mo.nm_state;
		break;
	case OM2K_MO_CLS_TF:
		nm_state = &bts->rbs2000.tf.mo.nm_state;
		break;
	case OM2K_MO_CLS_IS:
		nm_state = &bts->rbs2000.is.mo.nm_state;
		break;
	case OM2K_MO_CLS_CON:
		nm_state = &bts->rbs2000.con.mo.nm_state;
		break;
	case OM2K_MO_CLS_DP:
		nm_state = &bts->rbs2000.con.mo.nm_state;
		break;
	case OM2K_MO_CLS_CF:
		nm_state = &bts->mo.nm_state;
		break;
	case OM2K_MO_CLS_TX:
		trx = gsm_bts_trx_num(bts, mo->inst);
		if (!trx)
			return NULL;
		/* FIXME */
		break;
	case OM2K_MO_CLS_RX:
		trx = gsm_bts_trx_num(bts, mo->inst);
		if (!trx)
			return NULL;
		/* FIXME */
		break;
	}

	return nm_state;
}

static void *mo2obj(struct gsm_bts *bts, struct abis_om2k_mo *mo)
{
	struct gsm_bts_trx *trx;

	switch (mo->class) {
	case OM2K_MO_CLS_TX:
	case OM2K_MO_CLS_RX:
	case OM2K_MO_CLS_TRXC:
		return gsm_bts_trx_num(bts, mo->inst);
	case OM2K_MO_CLS_TS:
		trx = gsm_bts_trx_num(bts, mo->assoc_so);
		if (!trx)
			return NULL;
		if (mo->inst >= ARRAY_SIZE(trx->ts))
			return NULL;
		return &trx->ts[mo->inst];
	case OM2K_MO_CLS_TF:
	case OM2K_MO_CLS_IS:
	case OM2K_MO_CLS_CON:
	case OM2K_MO_CLS_DP:
	case OM2K_MO_CLS_CF:
		return bts;
	}

	return NULL;
}

static void update_mo_state(struct gsm_bts *bts, struct abis_om2k_mo *mo,
			    uint8_t mo_state)
{
	struct gsm_nm_state *nm_state = mo2nm_state(bts, mo);
	struct gsm_nm_state new_state;
	struct nm_statechg_signal_data nsd;

	if (!nm_state)
		return;

	new_state = *nm_state;
	/* NOTICE: 12.21 Availability state values != OM2000 */
	new_state.availability = mo_state;

	memset(&nsd, 0, sizeof(nsd));

	nsd.bts = bts;
	nsd.obj = mo2obj(bts, mo);
	nsd.old_state = nm_state;
	nsd.new_state = &new_state;
	nsd.om2k_mo = mo;

	osmo_signal_dispatch(SS_NM, S_NM_STATECHG_ADM, &nsd);

	nm_state->availability = new_state.availability;
}

static void update_op_state(struct gsm_bts *bts, const struct abis_om2k_mo *mo,
			    uint8_t op_state)
{
	struct gsm_nm_state *nm_state = mo2nm_state(bts, mo);
	struct gsm_nm_state new_state;

	if (!nm_state)
		return;

	new_state = *nm_state;
	switch (op_state) {
	case 1:
		new_state.operational = NM_OPSTATE_ENABLED;
		break;
	case 0:
		new_state.operational = NM_OPSTATE_DISABLED;
		break;
	default:
		new_state.operational = NM_OPSTATE_NULL;
		break;
	}

	nm_state->operational = new_state.operational;
}

static int abis_om2k_sendmsg(struct gsm_bts *bts, struct msgb *msg)
{
	struct abis_om2k_hdr *o2h;
	struct gsm_bts_trx *trx;

	msg->l2h = msg->data;
	o2h = (struct abis_om2k_hdr *) msg->l2h;

	/* Compute the length in the OML header */
	o2h->om.length = 6 + msgb_l2len(msg)-sizeof(*o2h);

	switch (o2h->mo.class) {
	case OM2K_MO_CLS_TRXC:
	case OM2K_MO_CLS_TX:
	case OM2K_MO_CLS_RX:
		/* Route through per-TRX OML Link to the appropriate TRX */
		trx = gsm_bts_trx_by_nr(bts, o2h->mo.inst);
		if (!trx) {
			LOGP(DNM, LOGL_ERROR, "MO=%s Tx Dropping msg to "
				"non-existing TRX\n", om2k_mo_name(&o2h->mo));
			return -ENODEV;
		}
		msg->dst = trx->oml_link;
		break;
	case OM2K_MO_CLS_TS:
		/* Route through per-TRX OML Link to the appropriate TRX */
		trx = gsm_bts_trx_by_nr(bts, o2h->mo.assoc_so);
		if (!trx) {
			LOGP(DNM, LOGL_ERROR, "MO=%s Tx Dropping msg to "
				"non-existing TRX\n", om2k_mo_name(&o2h->mo));
			return -ENODEV;
		}
		msg->dst = trx->oml_link;
		break;
	default:
		/* Route through the IXU/DXU OML Link */
		msg->dst = bts->oml_link;
		break;
	}

	return _abis_nm_sendmsg(msg);
}

static void fill_om2k_hdr(struct abis_om2k_hdr *o2h, const struct abis_om2k_mo *mo,
			  uint16_t msg_type)
{
	o2h->om.mdisc = ABIS_OM_MDISC_FOM;
	o2h->om.placement = ABIS_OM_PLACEMENT_ONLY;
	o2h->om.sequence = 0;
	/* We fill o2h->om.length later during om2k_sendmsg() */
	o2h->msg_type = htons(msg_type);
	memcpy(&o2h->mo, mo, sizeof(o2h->mo));
}

static int abis_om2k_cal_time_resp(struct gsm_bts *bts)
{
	struct msgb *msg = om2k_msgb_alloc();
	struct abis_om2k_hdr *o2k;
	time_t tm_t;
	struct tm *tm;

	o2k = (struct abis_om2k_hdr *) msgb_put(msg, sizeof(*o2k));
	fill_om2k_hdr(o2k, &bts->rbs2000.cf.om2k_mo.addr,
			OM2K_MSGT_CAL_TIME_RESP);

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
	fill_om2k_hdr(o2k, mo, msg_type);

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
	fill_om2k_hdr(o2k, mo, OM2K_MSGT_OP_INFO);

	msgb_tv_put(msg, OM2K_DEI_OP_INFO, operational);

	DEBUGP(DNM, "Tx MO=%s %s\n", om2k_mo_name(mo),
		get_value_string(om2k_msgcode_vals, OM2K_MSGT_OP_INFO));

	/* we update the state here... and send the signal at ACK */
	update_op_state(bts, mo, operational);

	return abis_om2k_sendmsg(bts, msg);
}

int abis_om2k_tx_cap_req(struct gsm_bts *bts, const struct abis_om2k_mo *mo)
{
	return abis_om2k_tx_simple(bts, mo, OM2K_MSGT_CAPA_REQ);
}

static void om2k_fill_is_conn_grp(struct om2k_is_conn_grp *grp, uint16_t icp1,
				  uint16_t icp2, uint8_t cont_idx)
{
	grp->icp1 = htons(icp1);
	grp->icp2 = htons(icp2);
	grp->cont_idx = cont_idx;
}

int abis_om2k_tx_is_conf_req(struct gsm_bts *bts)
{
	struct msgb *msg = om2k_msgb_alloc();
	struct abis_om2k_hdr *o2k;
	struct is_conn_group *grp;
	unsigned int num_grps = 0, i = 0;
	struct om2k_is_conn_grp *cg;

	/* count number of groups in linked list */
	llist_for_each_entry(grp, &bts->rbs2000.is.conn_groups, list)
		num_grps++;

	if (!num_grps)
		return -EINVAL;

	/* allocate buffer for oml group array */
	cg = talloc_zero_array(bts, struct om2k_is_conn_grp, num_grps);

	/* fill array with data from linked list */
	llist_for_each_entry(grp, &bts->rbs2000.is.conn_groups, list)
		om2k_fill_is_conn_grp(&cg[i++], grp->icp1, grp->icp2, grp->ci);

	o2k = (struct abis_om2k_hdr *) msgb_put(msg, sizeof(*o2k));
	fill_om2k_hdr(o2k, &bts->rbs2000.is.om2k_mo.addr,
			OM2K_MSGT_IS_CONF_REQ);

	msgb_tv_put(msg, OM2K_DEI_LIST_NR, 1);
	msgb_tv_put(msg, OM2K_DEI_END_LIST_NR, 1);

	msgb_tlv_put(msg, OM2K_DEI_IS_CONN_LIST,
		     num_grps * sizeof(*cg), (uint8_t *)cg);

	talloc_free(cg);

	DEBUGP(DNM, "Tx MO=%s %s\n",
		om2k_mo_name(&bts->rbs2000.is.om2k_mo.addr),
		get_value_string(om2k_msgcode_vals, OM2K_MSGT_IS_CONF_REQ));

	return abis_om2k_sendmsg(bts, msg);
}

int abis_om2k_tx_con_conf_req(struct gsm_bts *bts)
{
	struct msgb *msg = om2k_msgb_alloc();
	struct abis_om2k_hdr *o2k;
	struct con_group *grp;
	unsigned int num_grps = 0;

	/* count number of groups in linked list */
	llist_for_each_entry(grp, &bts->rbs2000.con.conn_groups, list)
		num_grps++;

	if (!num_grps)
		return -EINVAL;

	/* first build the value part of the OM2K_DEI_CON_CONN_LIST DEI */
	msgb_put_u8(msg, num_grps);
	llist_for_each_entry(grp, &bts->rbs2000.con.conn_groups, list) {
		struct con_path *cp;
		unsigned int num_paths = 0;
		llist_for_each_entry(cp, &grp->paths, list)
			num_paths++;
		msgb_put_u8(msg, num_paths);
		llist_for_each_entry(cp, &grp->paths, list) {
			struct om2k_con_path *om2k_cp;
			om2k_cp = (struct om2k_con_path *) msgb_put(msg, sizeof(*om2k_cp));
			om2k_cp->ccp = htons(cp->ccp);
			om2k_cp->ci = cp->ci;
			om2k_cp->tag = cp->tag;
			om2k_cp->tei = cp->tei;
		}
	}
	msgb_push_u8(msg, msgb_length(msg));
	msgb_push_u8(msg, OM2K_DEI_CON_CONN_LIST);

	/* pre-pend the list number DEIs */
	msgb_tv_push(msg, OM2K_DEI_END_LIST_NR, 1);
	msgb_tv_push(msg, OM2K_DEI_LIST_NR, 1);

	/* pre-pend the OM2K header */
	o2k = (struct abis_om2k_hdr *) msgb_push(msg, sizeof(*o2k));
	fill_om2k_hdr(o2k, &bts->rbs2000.con.om2k_mo.addr,
			OM2K_MSGT_CON_CONF_REQ);

	DEBUGP(DNM, "Tx MO=%s %s\n",
		om2k_mo_name(&bts->rbs2000.con.om2k_mo.addr),
		get_value_string(om2k_msgcode_vals, OM2K_MSGT_CON_CONF_REQ));

	return abis_om2k_sendmsg(bts, msg);
}

static void om2k_trx_to_mo(struct abis_om2k_mo *mo,
			   const struct gsm_bts_trx *trx,
			   enum abis_om2k_mo_cls cls)
{
	mo->class = cls;
	mo->bts = 0;
	mo->inst = trx->nr;
	mo->assoc_so = 255;
}

static void om2k_ts_to_mo(struct abis_om2k_mo *mo,
			  const struct gsm_bts_trx_ts *ts)
{
	mo->class = OM2K_MO_CLS_TS;
	mo->bts = 0;
	mo->inst = ts->nr;
	mo->assoc_so = ts->trx->nr;
}

/* Configure a Receiver MO */
int abis_om2k_tx_rx_conf_req(struct gsm_bts_trx *trx)
{
	struct msgb *msg = om2k_msgb_alloc();
	struct abis_om2k_hdr *o2k;
	struct abis_om2k_mo mo;

	om2k_trx_to_mo(&mo, trx, OM2K_MO_CLS_RX);

	o2k = (struct abis_om2k_hdr *) msgb_put(msg, sizeof(*o2k));
	fill_om2k_hdr(o2k, &mo, OM2K_MSGT_RX_CONF_REQ);

	msgb_tv16_put(msg, OM2K_DEI_FREQ_SPEC_RX, trx->arfcn);
	msgb_tv_put(msg, OM2K_DEI_RX_DIVERSITY, 0x02); /* A */

	return abis_om2k_sendmsg(trx->bts, msg);
}

/* Configure a Transmitter MO */
int abis_om2k_tx_tx_conf_req(struct gsm_bts_trx *trx)
{
	struct msgb *msg = om2k_msgb_alloc();
	struct abis_om2k_hdr *o2k;
	struct abis_om2k_mo mo;

	om2k_trx_to_mo(&mo, trx, OM2K_MO_CLS_TX);

	o2k = (struct abis_om2k_hdr *) msgb_put(msg, sizeof(*o2k));
	fill_om2k_hdr(o2k, &mo, OM2K_MSGT_TX_CONF_REQ);

	msgb_tv16_put(msg, OM2K_DEI_FREQ_SPEC_TX, trx->arfcn);
	msgb_tv_put(msg, OM2K_DEI_POWER, trx->nominal_power-trx->max_power_red);
	msgb_tv_put(msg, OM2K_DEI_FILLING_MARKER, 0);	/* Filling enabled */
	msgb_tv_put(msg, OM2K_DEI_BCC, trx->bts->bsic & 0x7);
	/* Dedication Information is optional */

	return abis_om2k_sendmsg(trx->bts, msg);
}

enum abis_om2k_tf_mode {
	OM2K_TF_MODE_MASTER	= 0x00,
	OM2K_TF_MODE_STANDALONE	= 0x01,
	OM2K_TF_MODE_SLAVE	= 0x02,
	OM2K_TF_MODE_UNDEFINED	= 0xff,
};

static const uint8_t fs_offset_undef[5] = { 0xff, 0xff, 0xff, 0xff, 0xff };

int abis_om2k_tx_tf_conf_req(struct gsm_bts *bts)
{
	struct msgb *msg = om2k_msgb_alloc();
	struct abis_om2k_hdr *o2k;

	o2k = (struct abis_om2k_hdr *) msgb_put(msg, sizeof(*o2k));
	fill_om2k_hdr(o2k, &bts->rbs2000.tf.om2k_mo.addr,
			OM2K_MSGT_TF_CONF_REQ);

	msgb_tv_put(msg, OM2K_DEI_TF_MODE, OM2K_TF_MODE_STANDALONE);
	msgb_tv_put(msg, OM2K_DEI_TF_SYNC_SRC, 0x00);
	msgb_tv_fixed_put(msg, OM2K_DEI_FS_OFFSET,
			  sizeof(fs_offset_undef), fs_offset_undef);

	DEBUGP(DNM, "Tx MO=%s %s\n",
		om2k_mo_name(&bts->rbs2000.tf.om2k_mo.addr),
		get_value_string(om2k_msgcode_vals, OM2K_MSGT_TF_CONF_REQ));

	return abis_om2k_sendmsg(bts, msg);
}

static uint8_t pchan2comb(enum gsm_phys_chan_config pchan)
{
	switch (pchan) {
	case GSM_PCHAN_CCCH:
		return 4;
	case GSM_PCHAN_CCCH_SDCCH4:
		return 5;
	case GSM_PCHAN_SDCCH8_SACCH8C:
		return 3;
	case GSM_PCHAN_TCH_F:
	case GSM_PCHAN_TCH_H:
	case GSM_PCHAN_PDCH:
	case GSM_PCHAN_TCH_F_PDCH:
	case GSM_PCHAN_TCH_F_TCH_H_PDCH:
		return 8;
	default:
		return 0;
	}
}

static uint8_t ts2comb(struct gsm_bts_trx_ts *ts)
{
	switch (ts->pchan) {
	case GSM_PCHAN_TCH_F_PDCH:
		LOGP(DNM, LOGL_ERROR, "%s pchan %s not intended for use"
		     " with OM2000, use %s instead\n",
		     gsm_ts_and_pchan_name(ts),
		     gsm_pchan_name(GSM_PCHAN_TCH_F_PDCH),
		     gsm_pchan_name(GSM_PCHAN_TCH_F_TCH_H_PDCH));
		/* If we allowed initialization of TCH/F_PDCH, it would fail
		 * when we try to send the ip.access specific RSL PDCH Act
		 * message for it. Rather fail completely right now: */
		return 0;
	case GSM_PCHAN_TCH_F_TCH_H_PDCH:
		return pchan2comb(GSM_PCHAN_TCH_F);
	default:
		return pchan2comb(ts->pchan);
	}
}

static int put_freq_list(uint8_t *buf, uint16_t arfcn)
{
	buf[0] = 0x00; /* TX/RX address */
	buf[1] = (arfcn >> 8);
	buf[2] = (arfcn & 0xff);

	return 3;
}

/* Compute a frequency list in OM2000 fomrmat */
static int om2k_gen_freq_list(uint8_t *list, struct gsm_bts_trx_ts *ts)
{
	uint8_t *cur = list;
	int len;

	if (ts->hopping.enabled) {
		unsigned int i;
		for (i = 0; i < ts->hopping.arfcns.data_len*8; i++) {
			if (bitvec_get_bit_pos(&ts->hopping.arfcns, i))
				cur += put_freq_list(cur, i);
		}
	} else
		cur += put_freq_list(cur, ts->trx->arfcn);

	len = cur - list;

	return len;
}

const uint8_t icm_bound_params[] = { 0x02, 0x06, 0x0c, 0x16, 0x06 };

int abis_om2k_tx_ts_conf_req(struct gsm_bts_trx_ts *ts)
{
	struct msgb *msg = om2k_msgb_alloc();
	struct abis_om2k_hdr *o2k;
	struct abis_om2k_mo mo;
	uint8_t freq_list[64*3]; /* BA max size: 64 ARFCN */
	int freq_list_len;

	om2k_ts_to_mo(&mo, ts);

	memset(freq_list, 0, sizeof(freq_list));
	freq_list_len = om2k_gen_freq_list(freq_list, ts);
	if (freq_list_len < 0)
		return freq_list_len;

	o2k = (struct abis_om2k_hdr *) msgb_put(msg, sizeof(*o2k));
	fill_om2k_hdr(o2k, &mo, OM2K_MSGT_TS_CONF_REQ);

	msgb_tv_put(msg, OM2K_DEI_COMBINATION, ts2comb(ts));
	msgb_tv_put(msg, OM2K_DEI_TS_NR, ts->nr);
	msgb_tlv_put(msg, OM2K_DEI_FREQ_LIST, freq_list_len, freq_list);
	msgb_tv_put(msg, OM2K_DEI_HSN, ts->hopping.hsn);
	msgb_tv_put(msg, OM2K_DEI_MAIO, ts->hopping.maio);
	msgb_tv_put(msg, OM2K_DEI_BSIC, ts->trx->bts->bsic);
	msgb_tv_put(msg, OM2K_DEI_RX_DIVERSITY, 0x02); /* A */
	msgb_tv16_put(msg, OM2K_DEI_FN_OFFSET, 0);
	msgb_tv_put(msg, OM2K_DEI_EXT_RANGE, 0); /* Off */
	/* Optional: Interference Rejection Combining */
	msgb_tv_put(msg, OM2K_DEI_INTERF_REJ_COMB, 0x00);
	switch (ts->pchan) {
	case GSM_PCHAN_CCCH:
		msgb_tv_put(msg, OM2K_DEI_BA_PA_MFRMS, 0x06);
		msgb_tv_put(msg, OM2K_DEI_BS_AG_BKS_RES, 0x01);
		msgb_tv_put(msg, OM2K_DEI_DRX_DEV_MAX, 0x05);
		/* Repeat Paging/IMM.ASS: True, Allow Paging Type 3: Yes, Page for 5 seconds (default) */
		msgb_tv_put(msg, OM2K_DEI_CCCH_OPTIONS, 0x01);
		break;
	case GSM_PCHAN_CCCH_SDCCH4:
		msgb_tv_put(msg, OM2K_DEI_T3105, ts->trx->bts->network->T3105 / 10);
		msgb_tv_put(msg, OM2K_DEI_NY1, 35);
		msgb_tv_put(msg, OM2K_DEI_BA_PA_MFRMS, 0x06);
		msgb_tv_put(msg, OM2K_DEI_CBCH_INDICATOR, 0);
		msgb_tv_put(msg, OM2K_DEI_TSC, gsm_ts_tsc(ts));
		msgb_tv_put(msg, OM2K_DEI_BS_AG_BKS_RES, 0x01);
		msgb_tv_put(msg, OM2K_DEI_ICM_INDICATOR, 0);
		msgb_tv_put(msg, OM2K_DEI_DRX_DEV_MAX, 0x05);
		/* Repeat Paging/IMM.ASS: True, Allow Paging Type 3: Yes, Page for 5 seconds (default) */
		msgb_tv_put(msg, OM2K_DEI_CCCH_OPTIONS, 0x01);
		msgb_tv_fixed_put(msg, OM2K_DEI_ICM_BOUND_PARAMS,
				  sizeof(icm_bound_params), icm_bound_params);
		break;
	case GSM_PCHAN_SDCCH8_SACCH8C:
		msgb_tv_put(msg, OM2K_DEI_T3105, ts->trx->bts->network->T3105 / 10);
		msgb_tv_put(msg, OM2K_DEI_NY1, 35);
		msgb_tv_put(msg, OM2K_DEI_CBCH_INDICATOR, 0);
		msgb_tv_put(msg, OM2K_DEI_TSC, gsm_ts_tsc(ts));
		/* Disable RF RESOURCE INDICATION on idle channels */
		msgb_tv_put(msg, OM2K_DEI_ICM_INDICATOR, 0);
		msgb_tv_fixed_put(msg, OM2K_DEI_ICM_BOUND_PARAMS,
				  sizeof(icm_bound_params), icm_bound_params);
		break;
	default:
		msgb_tv_put(msg, OM2K_DEI_T3105, ts->trx->bts->network->T3105 / 10);
		msgb_tv_put(msg, OM2K_DEI_NY1, 35);
		msgb_tv_put(msg, OM2K_DEI_TSC, gsm_ts_tsc(ts));
		/* Disable RF RESOURCE INDICATION on idle channels */
		msgb_tv_put(msg, OM2K_DEI_ICM_INDICATOR, 0);
		msgb_tv_fixed_put(msg, OM2K_DEI_ICM_BOUND_PARAMS,
				  sizeof(icm_bound_params), icm_bound_params);
		msgb_tv_put(msg, OM2K_DEI_TTA, 10); /* Timer for Time Alignment */
		if (ts->pchan == GSM_PCHAN_TCH_H)
			msgb_tv_put(msg, OM2K_DEI_ICM_CHAN_RATE, 1); /* TCH/H */
		else
			msgb_tv_put(msg, OM2K_DEI_ICM_CHAN_RATE, 0); /* TCH/F */
		msgb_tv_put(msg, OM2K_DEI_LSC, 1); /* enabled */
		msgb_tv_put(msg, OM2K_DEI_LSC_FILT_TIME, 10);	/* units of 100ms */
		msgb_tv_put(msg, OM2K_DEI_CALL_SUPV_TIME, 8);
		msgb_tv_put(msg, OM2K_DEI_ENCR_ALG, 0x00);
		/* Not sure what those below mean */
		msgb_tv_put(msg, 0x9e, 0x00);
		msgb_tv_put(msg, 0x9f, 0x37);
		msgb_tv_put(msg, 0xa0, 0x01);
		break;
	}

	DEBUGP(DNM, "Tx MO=%s %s\n",
		om2k_mo_name(&mo),
		get_value_string(om2k_msgcode_vals, OM2K_MSGT_TS_CONF_REQ));

	return abis_om2k_sendmsg(ts->trx->bts, msg);
}


/***********************************************************************
 * OM2000 Managed Object (MO) FSM
 ***********************************************************************/

#define S(x)	(1 << (x))

enum om2k_event_name {
	OM2K_MO_EVT_START,
	OM2K_MO_EVT_RX_CONN_COMPL,
	OM2K_MO_EVT_RX_RESET_COMPL,
	OM2K_MO_EVT_RX_START_REQ_ACCEPT,
	OM2K_MO_EVT_RX_START_RES,
	OM2K_MO_EVT_RX_CFG_REQ_ACCEPT,
	OM2K_MO_EVT_RX_CFG_RES,
	OM2K_MO_EVT_RX_ENA_REQ_ACCEPT,
	OM2K_MO_EVT_RX_ENA_RES,
	OM2K_MO_EVT_RX_OPINFO_ACC,
};

static const struct value_string om2k_event_names[] = {
	{ OM2K_MO_EVT_START,			"START" },
	{ OM2K_MO_EVT_RX_CONN_COMPL,		"RX-CONN-COMPL" },
	{ OM2K_MO_EVT_RX_RESET_COMPL,		"RX-RESET-COMPL" },
	{ OM2K_MO_EVT_RX_START_REQ_ACCEPT,	"RX-RESET-REQ-ACCEPT" },
	{ OM2K_MO_EVT_RX_START_RES,		"RX-START-RESULT" },
	{ OM2K_MO_EVT_RX_CFG_REQ_ACCEPT,	"RX-CFG-REQ-ACCEPT" },
	{ OM2K_MO_EVT_RX_CFG_RES,		"RX-CFG-RESULT" },
	{ OM2K_MO_EVT_RX_ENA_REQ_ACCEPT,	"RX-ENABLE-REQ-ACCEPT" },
	{ OM2K_MO_EVT_RX_ENA_RES,		"RX-ENABLE-RESULT" },
	{ OM2K_MO_EVT_RX_OPINFO_ACC,		"RX-OPINFO-ACCEPT" },
	{ 0, NULL }
};

enum om2k_mo_fsm_state {
	OM2K_ST_INIT,
	OM2K_ST_WAIT_CONN_COMPL,
	OM2K_ST_WAIT_RES_COMPL,
	OM2K_ST_WAIT_START_ACCEPT,
	OM2K_ST_WAIT_START_RES,
	OM2K_ST_WAIT_CFG_ACCEPT,
	OM2K_ST_WAIT_CFG_RES,
	OM2K_ST_WAIT_ENABLE_ACCEPT,
	OM2K_ST_WAIT_ENABLE_RES,
	OM2K_ST_WAIT_OPINFO_ACCEPT,
	OM2K_ST_DONE,
	OM2K_ST_ERROR,
};

struct om2k_mo_fsm_priv {
	struct gsm_bts_trx *trx;
	struct om2k_mo *mo;
	uint8_t ts_nr;
};

static void om2k_mo_st_init(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct om2k_mo_fsm_priv *omfp = fi->priv;

	OSMO_ASSERT(event == OM2K_MO_EVT_START);

	switch (omfp->mo->addr.class) {
	case OM2K_MO_CLS_CF:
		/* no Connect required, is always connected */
		osmo_fsm_inst_state_chg(fi, OM2K_ST_WAIT_START_ACCEPT,
					OM2K_TIMEOUT, 0);
		abis_om2k_tx_start_req(omfp->trx->bts, &omfp->mo->addr);
		break;
	case OM2K_MO_CLS_TRXC:
		/* no Connect required, start with Reset */
		osmo_fsm_inst_state_chg(fi, OM2K_ST_WAIT_RES_COMPL,
					OM2K_TIMEOUT, 0);
		abis_om2k_tx_reset_cmd(omfp->trx->bts, &omfp->mo->addr);
		break;
	default:
		/* start with Connect */
		osmo_fsm_inst_state_chg(fi, OM2K_ST_WAIT_CONN_COMPL,
					OM2K_TIMEOUT, 0);
		abis_om2k_tx_connect_cmd(omfp->trx->bts, &omfp->mo->addr);
		break;
	}
}

static void om2k_mo_st_wait_conn_compl(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct om2k_mo_fsm_priv *omfp = fi->priv;

	switch (omfp->mo->addr.class) {
#if 0
	case OM2K_MO_CLS_TF:
		/* skip the reset, hope that helps */
		osmo_fsm_inst_state_chg(fi, OM2K_ST_WAIT_START_ACCEPT,
					OM2K_TIMEOUT, 0);
		abis_om2k_tx_start_req(omfp->trx->bts, &omfp->mo->addr);
		break;
#endif
	default:
		osmo_fsm_inst_state_chg(fi, OM2K_ST_WAIT_RES_COMPL,
					OM2K_TIMEOUT, 0);
		abis_om2k_tx_reset_cmd(omfp->trx->bts, &omfp->mo->addr);
		break;
	}
}

static void om2k_mo_st_wait_res_compl(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct om2k_mo_fsm_priv *omfp = fi->priv;

	osmo_fsm_inst_state_chg(fi, OM2K_ST_WAIT_START_ACCEPT,
				OM2K_TIMEOUT, 0);
	abis_om2k_tx_start_req(omfp->trx->bts, &omfp->mo->addr);
}

static void om2k_mo_st_wait_start_accept(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct om2k_decoded_msg *omd = data;

	switch (omd->msg_type) {
	case OM2K_MSGT_START_REQ_ACK:
		osmo_fsm_inst_state_chg(fi, OM2K_ST_WAIT_START_RES,
					OM2K_TIMEOUT, 0);
		break;
	case OM2K_MSGT_START_REQ_REJ:
		osmo_fsm_inst_state_chg(fi, OM2K_ST_ERROR, 0, 0);
		break;
	}
}

static void om2k_mo_st_wait_start_res(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct om2k_mo_fsm_priv *omfp = fi->priv;
	struct gsm_bts_trx_ts *ts;

	switch (omfp->mo->addr.class) {
	case OM2K_MO_CLS_CF:
	case OM2K_MO_CLS_TRXC:
		/* Transition directly to Operational Info */
		osmo_fsm_inst_state_chg(fi, OM2K_ST_WAIT_OPINFO_ACCEPT,
				OM2K_TIMEOUT, 0);
		abis_om2k_tx_op_info(omfp->trx->bts, &omfp->mo->addr, 1);
		return;
	case OM2K_MO_CLS_DP:
		/* Transition directoy to WAIT_ENABLE_ACCEPT */
		osmo_fsm_inst_state_chg(fi, OM2K_ST_WAIT_ENABLE_ACCEPT,
					OM2K_TIMEOUT, 0);
		abis_om2k_tx_enable_req(omfp->trx->bts, &omfp->mo->addr);
		return;
#if 0
	case OM2K_MO_CLS_TF:
		/* skip the config, hope that helps speeding things up */
		osmo_fsm_inst_state_chg(fi, OM2K_ST_WAIT_ENABLE_ACCEPT,
					OM2K_TIMEOUT, 0);
		abis_om2k_tx_enable_req(omfp->trx->bts, &omfp->mo->addr);
		return;
#endif
	}

	osmo_fsm_inst_state_chg(fi, OM2K_ST_WAIT_CFG_ACCEPT,
				OM2K_TIMEOUT, 0);
	switch (omfp->mo->addr.class) {
	case OM2K_MO_CLS_TF:
		abis_om2k_tx_tf_conf_req(omfp->trx->bts);
		break;
	case OM2K_MO_CLS_IS:
		abis_om2k_tx_is_conf_req(omfp->trx->bts);
		break;
	case OM2K_MO_CLS_CON:
		abis_om2k_tx_con_conf_req(omfp->trx->bts);
		break;
	case OM2K_MO_CLS_TX:
		abis_om2k_tx_tx_conf_req(omfp->trx);
		break;
	case OM2K_MO_CLS_RX:
		abis_om2k_tx_rx_conf_req(omfp->trx);
		break;
	case OM2K_MO_CLS_TS:
		ts = mo2obj(omfp->trx->bts, &omfp->mo->addr);
		abis_om2k_tx_ts_conf_req(ts);
		break;
	}
}

static void om2k_mo_st_wait_cfg_accept(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct om2k_mo_fsm_priv *omfp = fi->priv;
	uint32_t timeout = OM2K_TIMEOUT;

	if (omfp->mo->addr.class == OM2K_MO_CLS_TF)
		timeout = 600;

	osmo_fsm_inst_state_chg(fi, OM2K_ST_WAIT_CFG_RES, timeout, 0);
}

static void om2k_mo_st_wait_cfg_res(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct om2k_mo_fsm_priv *omfp = fi->priv;
	struct om2k_decoded_msg *omd = data;
	uint8_t accordance;

	if (!TLVP_PRESENT(&omd->tp, OM2K_DEI_ACCORDANCE_IND)) {
		osmo_fsm_inst_state_chg(fi, OM2K_ST_ERROR, 0, 0);
		return;
	}
	accordance = *TLVP_VAL(&omd->tp, OM2K_DEI_ACCORDANCE_IND);

	if (accordance != 0) {
		/* accordance not OK */
		osmo_fsm_inst_state_chg(fi, OM2K_ST_ERROR, 0, 0);
		return;
	}

	osmo_fsm_inst_state_chg(fi, OM2K_ST_WAIT_ENABLE_ACCEPT,
				OM2K_TIMEOUT, 0);
	abis_om2k_tx_enable_req(omfp->trx->bts, &omfp->mo->addr);
}

static void om2k_mo_st_wait_enable_accept(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct om2k_mo_fsm_priv *omfp = fi->priv;
	struct om2k_decoded_msg *omd = data;

	switch (omd->msg_type) {
	case OM2K_MSGT_ENABLE_REQ_REJ:
		osmo_fsm_inst_state_chg(fi, OM2K_ST_ERROR, 0, 0);
		break;
	case OM2K_MSGT_ENABLE_REQ_ACK:
		if (omfp->mo->addr.class == OM2K_MO_CLS_IS &&
		    omfp->trx->bts->rbs2000.use_superchannel)
			e1inp_ericsson_set_altc(omfp->trx->bts->oml_link->ts->line, 1);
		osmo_fsm_inst_state_chg(fi, OM2K_ST_WAIT_ENABLE_RES,
					OM2K_TIMEOUT, 0);
	}
}

static void om2k_mo_st_wait_enable_res(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct om2k_mo_fsm_priv *omfp = fi->priv;
	//struct om2k_decoded_msg *omd = data;
	/* TODO: check if state is actually enabled now? */

	osmo_fsm_inst_state_chg(fi, OM2K_ST_WAIT_OPINFO_ACCEPT,
				OM2K_TIMEOUT, 0);
	abis_om2k_tx_op_info(omfp->trx->bts, &omfp->mo->addr, 1);
}

static void om2k_mo_st_wait_opinfo_accept(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct om2k_mo_fsm_priv *omfp = fi->priv;

	/* if we have just received opinfo accept for the timeslot,
	 * start dynamic TCH switching procedures */
	if (omfp->mo->addr.class == OM2K_MO_CLS_TS) {
		struct gsm_bts_trx_ts *ts;
		ts = mo2obj(omfp->trx->bts, &omfp->mo->addr);
		dyn_ts_init(ts);
	}
	osmo_fsm_inst_state_chg(fi, OM2K_ST_DONE, 0, 0);
}

static void om2k_mo_s_done_onenter(struct osmo_fsm_inst *fi, uint32_t prev_state)
{
	struct om2k_mo_fsm_priv *omfp = fi->priv;
	omfp->mo->fsm = NULL;
	osmo_fsm_inst_term(fi, OSMO_FSM_TERM_REGULAR, NULL);
}

static void om2k_mo_s_error_onenter(struct osmo_fsm_inst *fi, uint32_t prev_state)
{
	struct om2k_mo_fsm_priv *omfp = fi->priv;

	omfp->mo->fsm = NULL;
	osmo_fsm_inst_term(fi, OSMO_FSM_TERM_ERROR, NULL);
}

static const struct osmo_fsm_state om2k_is_states[] = {
	[OM2K_ST_INIT] = {
		.name = "INIT",
		.in_event_mask = S(OM2K_MO_EVT_START),
		.out_state_mask = S(OM2K_ST_DONE) |
				  S(OM2K_ST_ERROR) |
				  S(OM2K_ST_WAIT_CONN_COMPL) |
				  S(OM2K_ST_WAIT_START_ACCEPT) |
				  S(OM2K_ST_WAIT_RES_COMPL),
		.action = om2k_mo_st_init,
	},
	[OM2K_ST_WAIT_CONN_COMPL] = {
		.name = "WAIT-CONN-COMPL",
		.in_event_mask = S(OM2K_MO_EVT_RX_CONN_COMPL),
		.out_state_mask = S(OM2K_ST_DONE) |
				  S(OM2K_ST_ERROR) |
				  S(OM2K_ST_WAIT_START_ACCEPT) |
				  S(OM2K_ST_WAIT_RES_COMPL),
		.action = om2k_mo_st_wait_conn_compl,
	},
	[OM2K_ST_WAIT_RES_COMPL] = {
		.name = "WAIT-RES-COMPL",
		.in_event_mask = S(OM2K_MO_EVT_RX_RESET_COMPL),
		.out_state_mask = S(OM2K_ST_DONE) |
				  S(OM2K_ST_ERROR) |
				  S(OM2K_ST_WAIT_START_ACCEPT),
		.action = om2k_mo_st_wait_res_compl,
	},
	[OM2K_ST_WAIT_START_ACCEPT] = {
		.name = "WAIT-START-ACCEPT",
		.in_event_mask = S(OM2K_MO_EVT_RX_START_REQ_ACCEPT),
		.out_state_mask = S(OM2K_ST_DONE) |
				  S(OM2K_ST_ERROR) |
				  S(OM2K_ST_WAIT_START_RES),
		.action =om2k_mo_st_wait_start_accept,
	},
	[OM2K_ST_WAIT_START_RES] = {
		.name = "WAIT-START-RES",
		.in_event_mask = S(OM2K_MO_EVT_RX_START_RES),
		.out_state_mask = S(OM2K_ST_DONE) |
				  S(OM2K_ST_ERROR) |
				  S(OM2K_ST_WAIT_CFG_ACCEPT) |
				  S(OM2K_ST_WAIT_OPINFO_ACCEPT),
		.action = om2k_mo_st_wait_start_res,
	},
	[OM2K_ST_WAIT_CFG_ACCEPT] = {
		.name = "WAIT-CFG-ACCEPT",
		.in_event_mask = S(OM2K_MO_EVT_RX_CFG_REQ_ACCEPT),
		.out_state_mask = S(OM2K_ST_DONE) |
				  S(OM2K_ST_ERROR) |
				  S(OM2K_ST_WAIT_CFG_RES),
		.action = om2k_mo_st_wait_cfg_accept,
	},
	[OM2K_ST_WAIT_CFG_RES] = {
		.name = "WAIT-CFG-RES",
		.in_event_mask = S(OM2K_MO_EVT_RX_CFG_RES),
		.out_state_mask = S(OM2K_ST_DONE) |
				  S(OM2K_ST_ERROR) |
				  S(OM2K_ST_WAIT_ENABLE_ACCEPT),
		.action = om2k_mo_st_wait_cfg_res,
	},
	[OM2K_ST_WAIT_ENABLE_ACCEPT] = {
		.name = "WAIT-ENABLE-ACCEPT",
		.in_event_mask = S(OM2K_MO_EVT_RX_ENA_REQ_ACCEPT),
		.out_state_mask = S(OM2K_ST_DONE) |
				  S(OM2K_ST_ERROR) |
				  S(OM2K_ST_WAIT_ENABLE_RES),
		.action = om2k_mo_st_wait_enable_accept,
	},
	[OM2K_ST_WAIT_ENABLE_RES] = {
		.name = "WAIT-ENABLE-RES",
		.in_event_mask = S(OM2K_MO_EVT_RX_ENA_RES),
		.out_state_mask = S(OM2K_ST_DONE) |
				  S(OM2K_ST_ERROR) |
				  S(OM2K_ST_WAIT_OPINFO_ACCEPT),
		.action = om2k_mo_st_wait_enable_res,
	},
	[OM2K_ST_WAIT_OPINFO_ACCEPT] = {
		.name = "WAIT-OPINFO-ACCEPT",
		.in_event_mask = S(OM2K_MO_EVT_RX_OPINFO_ACC),
		.out_state_mask = S(OM2K_ST_DONE) |
				  S(OM2K_ST_ERROR),
		.action = om2k_mo_st_wait_opinfo_accept,
	},
	[OM2K_ST_DONE] = {
		.name = "DONE",
		.in_event_mask = 0,
		.out_state_mask = 0,
		.onenter = om2k_mo_s_done_onenter,
	},
	[OM2K_ST_ERROR] = {
		.name = "ERROR",
		.in_event_mask = 0,
		.out_state_mask = 0,
		.onenter = om2k_mo_s_error_onenter,
	},

};

static int om2k_mo_timer_cb(struct osmo_fsm_inst *fi)
{
	osmo_fsm_inst_state_chg(fi, OM2K_ST_ERROR, 0, 0);
	return 0;
}

static struct osmo_fsm om2k_mo_fsm = {
	.name = "OM2000-MO",
	.states = om2k_is_states,
	.num_states = ARRAY_SIZE(om2k_is_states),
	.log_subsys = DNM,
	.event_names = om2k_event_names,
	.timer_cb = om2k_mo_timer_cb,
};

struct osmo_fsm_inst *om2k_mo_fsm_start(struct osmo_fsm_inst *parent,
					uint32_t term_event,
					struct gsm_bts_trx *trx, struct om2k_mo *mo)
{
	struct osmo_fsm_inst *fi;
	struct om2k_mo_fsm_priv *omfp;
	char idbuf[64];

	snprintf(idbuf, sizeof(idbuf), "%s-%s", parent->id,
		 om2k_mo_name(&mo->addr));

	fi = osmo_fsm_inst_alloc_child_id(&om2k_mo_fsm, parent,
					  term_event, idbuf);
	if (!fi)
		return NULL;

	mo->fsm = fi;
	omfp = talloc_zero(fi, struct om2k_mo_fsm_priv);
	omfp->mo = mo;
	omfp->trx = trx;
	fi->priv = omfp;

	osmo_fsm_inst_dispatch(fi, OM2K_MO_EVT_START, NULL);

	return fi;
}

int om2k_mo_fsm_recvmsg(struct gsm_bts *bts, struct om2k_mo *mo,
			struct om2k_decoded_msg *odm)
{
	switch (odm->msg_type) {
	case OM2K_MSGT_CONNECT_COMPL:
	case OM2K_MSGT_CONNECT_REJ:
		osmo_fsm_inst_dispatch(mo->fsm,
				OM2K_MO_EVT_RX_CONN_COMPL, odm);
		break;

	case OM2K_MSGT_RESET_COMPL:
	case OM2K_MSGT_RESET_REJ:
		osmo_fsm_inst_dispatch(mo->fsm,
				OM2K_MO_EVT_RX_RESET_COMPL, odm);
		break;

	case OM2K_MSGT_START_REQ_ACK:
	case OM2K_MSGT_START_REQ_REJ:
		osmo_fsm_inst_dispatch(mo->fsm,
				OM2K_MO_EVT_RX_START_REQ_ACCEPT, odm);
		break;

	case OM2K_MSGT_START_RES:
		osmo_fsm_inst_dispatch(mo->fsm,
				OM2K_MO_EVT_RX_START_RES, odm);
		break;

	case OM2K_MSGT_CON_CONF_REQ_ACK:
	case OM2K_MSGT_IS_CONF_REQ_ACK:
	case OM2K_MSGT_RX_CONF_REQ_ACK:
	case OM2K_MSGT_TF_CONF_REQ_ACK:
	case OM2K_MSGT_TS_CONF_REQ_ACK:
	case OM2K_MSGT_TX_CONF_REQ_ACK:
		osmo_fsm_inst_dispatch(mo->fsm,
				OM2K_MO_EVT_RX_CFG_REQ_ACCEPT, odm);
		break;

	case OM2K_MSGT_CON_CONF_RES:
	case OM2K_MSGT_IS_CONF_RES:
	case OM2K_MSGT_RX_CONF_RES:
	case OM2K_MSGT_TF_CONF_RES:
	case OM2K_MSGT_TS_CONF_RES:
	case OM2K_MSGT_TX_CONF_RES:
		osmo_fsm_inst_dispatch(mo->fsm,
				OM2K_MO_EVT_RX_CFG_RES, odm);
		break;

	case OM2K_MSGT_ENABLE_REQ_ACK:
	case OM2K_MSGT_ENABLE_REQ_REJ:
		osmo_fsm_inst_dispatch(mo->fsm,
				OM2K_MO_EVT_RX_ENA_REQ_ACCEPT, odm);
		break;
	case OM2K_MSGT_ENABLE_RES:
		osmo_fsm_inst_dispatch(mo->fsm,
				OM2K_MO_EVT_RX_ENA_RES, odm);
		break;

	case OM2K_MSGT_OP_INFO_ACK:
	case OM2K_MSGT_OP_INFO_REJ:
		osmo_fsm_inst_dispatch(mo->fsm,
				OM2K_MO_EVT_RX_OPINFO_ACC, odm);
		break;
	default:
		return -1;
	}

	return 0;
}

/***********************************************************************
 * OM2000 TRX Finite State Machine, initializes TRXC and all siblings
 ***********************************************************************/

enum om2k_trx_event {
	OM2K_TRX_EVT_START,
	OM2K_TRX_EVT_TRXC_DONE,
	OM2K_TRX_EVT_TX_DONE,
	OM2K_TRX_EVT_RX_DONE,
	OM2K_TRX_EVT_TS_DONE,
	OM2K_TRX_EVT_STOP,
};

static struct value_string om2k_trx_events[] = {
	{ OM2K_TRX_EVT_START,		"START" },
	{ OM2K_TRX_EVT_TRXC_DONE,	"TRXC-DONE" },
	{ OM2K_TRX_EVT_TX_DONE,		"TX-DONE" },
	{ OM2K_TRX_EVT_RX_DONE,		"RX-DONE" },
	{ OM2K_TRX_EVT_TS_DONE,		"TS-DONE" },
	{ OM2K_TRX_EVT_STOP,		"STOP" },
	{ 0, NULL }
};

enum om2k_trx_state {
	 OM2K_TRX_S_INIT,
	 OM2K_TRX_S_WAIT_TRXC,
	 OM2K_TRX_S_WAIT_TX,
	 OM2K_TRX_S_WAIT_RX,
	 OM2K_TRX_S_WAIT_TS,
	 OM2K_TRX_S_DONE,
	 OM2K_TRX_S_ERROR
};

struct om2k_trx_fsm_priv {
	struct gsm_bts_trx *trx;
	uint8_t next_ts_nr;
};

static void om2k_trx_s_init(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct om2k_trx_fsm_priv *otfp = fi->priv;

	/* First initialize TRXC */
	osmo_fsm_inst_state_chg(fi, OM2K_TRX_S_WAIT_TRXC,
				TRX_FSM_TIMEOUT, 0);
	om2k_mo_fsm_start(fi, OM2K_TRX_EVT_TRXC_DONE, otfp->trx,
			  &otfp->trx->rbs2000.trxc.om2k_mo);
}

static void om2k_trx_s_wait_trxc(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct om2k_trx_fsm_priv *otfp = fi->priv;

	/* Initialize TX after TRXC */
	osmo_fsm_inst_state_chg(fi, OM2K_TRX_S_WAIT_TX,
				TRX_FSM_TIMEOUT, 0);
	om2k_mo_fsm_start(fi, OM2K_TRX_EVT_TX_DONE, otfp->trx,
			  &otfp->trx->rbs2000.tx.om2k_mo);
}

static void om2k_trx_s_wait_tx(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct om2k_trx_fsm_priv *otfp = fi->priv;

	/* Initialize RX after TX */
	osmo_fsm_inst_state_chg(fi, OM2K_TRX_S_WAIT_RX,
				TRX_FSM_TIMEOUT, 0);
	om2k_mo_fsm_start(fi, OM2K_TRX_EVT_RX_DONE, otfp->trx,
			  &otfp->trx->rbs2000.rx.om2k_mo);
}

static void om2k_trx_s_wait_rx(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct om2k_trx_fsm_priv *otfp = fi->priv;
	struct gsm_bts_trx_ts *ts;

	/* Initialize Timeslots after TX */
	osmo_fsm_inst_state_chg(fi, OM2K_TRX_S_WAIT_TS,
				TRX_FSM_TIMEOUT, 0);
	otfp->next_ts_nr = 0;
	ts = &otfp->trx->ts[otfp->next_ts_nr++];
	om2k_mo_fsm_start(fi, OM2K_TRX_EVT_TS_DONE, otfp->trx,
			  &ts->rbs2000.om2k_mo);
}

static void om2k_trx_s_wait_ts(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct om2k_trx_fsm_priv *otfp = fi->priv;
	struct gsm_bts_trx_ts *ts;

	if (otfp->next_ts_nr < 8) {
		/* iterate to the next timeslot */
		ts = &otfp->trx->ts[otfp->next_ts_nr++];
		om2k_mo_fsm_start(fi, OM2K_TRX_EVT_TS_DONE, otfp->trx,
				  &ts->rbs2000.om2k_mo);
	} else {
		/* only after all 8 TS */
		osmo_fsm_inst_state_chg(fi, OM2K_TRX_S_DONE, 0, 0);
	}
}

static void om2k_trx_s_done_onenter(struct osmo_fsm_inst *fi, uint32_t prev_state)
{
	struct om2k_trx_fsm_priv *otfp = fi->priv;
	gsm_bts_trx_set_system_infos(otfp->trx);
	osmo_fsm_inst_term(fi, OSMO_FSM_TERM_REGULAR, NULL);
}

static const struct osmo_fsm_state om2k_trx_states[] = {
	[OM2K_TRX_S_INIT] = {
		.in_event_mask = S(OM2K_TRX_EVT_START),
		.out_state_mask = S(OM2K_TRX_S_WAIT_TRXC),
		.name = "INIT",
		.action = om2k_trx_s_init,
	},
	[OM2K_TRX_S_WAIT_TRXC] = {
		.in_event_mask = S(OM2K_TRX_EVT_TRXC_DONE),
		.out_state_mask = S(OM2K_TRX_S_ERROR) |
				  S(OM2K_TRX_S_WAIT_TX),
		.name = "WAIT-TRXC",
		.action = om2k_trx_s_wait_trxc,
	},
	[OM2K_TRX_S_WAIT_TX] = {
		.in_event_mask = S(OM2K_TRX_EVT_TX_DONE),
		.out_state_mask = S(OM2K_TRX_S_ERROR) |
				  S(OM2K_TRX_S_WAIT_RX),
		.name = "WAIT-TX",
		.action = om2k_trx_s_wait_tx,
	},
	[OM2K_TRX_S_WAIT_RX] = {
		.in_event_mask = S(OM2K_TRX_EVT_RX_DONE),
		.out_state_mask = S(OM2K_TRX_S_ERROR) |
				  S(OM2K_TRX_S_WAIT_TS),
		.name = "WAIT-RX",
		.action = om2k_trx_s_wait_rx,
	},
	[OM2K_TRX_S_WAIT_TS] = {
		.in_event_mask = S(OM2K_TRX_EVT_TS_DONE),
		.out_state_mask = S(OM2K_TRX_S_ERROR) |
				  S(OM2K_TRX_S_DONE),
		.name = "WAIT-TS",
		.action = om2k_trx_s_wait_ts,
	},
	[OM2K_TRX_S_DONE] = {
		.name = "DONE",
		.onenter = om2k_trx_s_done_onenter,
	},
	[OM2K_TRX_S_ERROR] = {
		.name = "ERROR",
	},
};

static int om2k_trx_timer_cb(struct osmo_fsm_inst *fi)
{
	osmo_fsm_inst_state_chg(fi, OM2K_TRX_S_ERROR, 0, 0);
	return 0;
}

static struct osmo_fsm om2k_trx_fsm = {
	.name = "OM2000-TRX",
	.states = om2k_trx_states,
	.num_states = ARRAY_SIZE(om2k_trx_states),
	.log_subsys = DNM,
	.event_names = om2k_trx_events,
	.timer_cb = om2k_trx_timer_cb,
};

struct osmo_fsm_inst *om2k_trx_fsm_start(struct osmo_fsm_inst *parent,
					 struct gsm_bts_trx *trx,
					 uint32_t term_event)
{
	struct osmo_fsm_inst *fi;
	struct om2k_trx_fsm_priv *otfp;
	char idbuf[32];

	snprintf(idbuf, sizeof(idbuf), "%u/%u", trx->bts->nr, trx->nr);

	fi = osmo_fsm_inst_alloc_child_id(&om2k_trx_fsm, parent, term_event,
					  idbuf);
	if (!fi)
		return NULL;

	otfp = talloc_zero(fi, struct om2k_trx_fsm_priv);
	otfp->trx = trx;
	fi->priv = otfp;

	osmo_fsm_inst_dispatch(fi, OM2K_TRX_EVT_START, NULL);

	return fi;
}


/***********************************************************************
 * OM2000 BTS Finite State Machine, initializes CF and all siblings
 ***********************************************************************/

enum om2k_bts_event {
	OM2K_BTS_EVT_START,
	OM2K_BTS_EVT_CF_DONE,
	OM2K_BTS_EVT_IS_DONE,
	OM2K_BTS_EVT_CON_DONE,
	OM2K_BTS_EVT_TF_DONE,
	OM2K_BTS_EVT_TRX_DONE,
	OM2K_BTS_EVT_STOP,
};

static const struct value_string om2k_bts_events[] = {
	{ OM2K_BTS_EVT_START,		"START" },
	{ OM2K_BTS_EVT_CF_DONE,		"CF-DONE" },
	{ OM2K_BTS_EVT_IS_DONE,		"IS-DONE" },
	{ OM2K_BTS_EVT_CON_DONE,	"CON-DONE" },
	{ OM2K_BTS_EVT_TF_DONE,		"TF-DONE" },
	{ OM2K_BTS_EVT_TRX_DONE,	"TRX-DONE" },
	{ OM2K_BTS_EVT_STOP,		"STOP" },
	{ 0, NULL }
};

enum om2k_bts_state {
	OM2K_BTS_S_INIT,
	OM2K_BTS_S_WAIT_CF,
	OM2K_BTS_S_WAIT_IS,
	OM2K_BTS_S_WAIT_CON,
	OM2K_BTS_S_WAIT_TF,
	OM2K_BTS_S_WAIT_TRX,
	OM2K_BTS_S_DONE,
	OM2K_BTS_S_ERROR,
};

struct om2k_bts_fsm_priv {
	struct gsm_bts *bts;
	uint8_t next_trx_nr;
};

static void om2k_bts_s_init(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct om2k_bts_fsm_priv *obfp = fi->priv;
	struct gsm_bts *bts = obfp->bts;

	OSMO_ASSERT(event == OM2K_BTS_EVT_START);
	osmo_fsm_inst_state_chg(fi, OM2K_BTS_S_WAIT_CF,
				BTS_FSM_TIMEOUT, 0);
	om2k_mo_fsm_start(fi, OM2K_BTS_EVT_CF_DONE, bts->c0,
			  &bts->rbs2000.cf.om2k_mo);
}

static void om2k_bts_s_wait_cf(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct om2k_bts_fsm_priv *obfp = fi->priv;
	struct gsm_bts *bts = obfp->bts;

	OSMO_ASSERT(event == OM2K_BTS_EVT_CF_DONE);
	/* TF can take a long time to initialize, wait for 10min */
	osmo_fsm_inst_state_chg(fi, OM2K_BTS_S_WAIT_TF, 600, 0);
	om2k_mo_fsm_start(fi, OM2K_BTS_EVT_TF_DONE, bts->c0,
			  &bts->rbs2000.tf.om2k_mo);
}

static void om2k_bts_s_wait_tf(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct om2k_bts_fsm_priv *obfp = fi->priv;
	struct gsm_bts *bts = obfp->bts;

	OSMO_ASSERT(event == OM2K_BTS_EVT_TF_DONE);

	osmo_fsm_inst_state_chg(fi, OM2K_BTS_S_WAIT_CON,
				BTS_FSM_TIMEOUT, 0);
	om2k_mo_fsm_start(fi, OM2K_BTS_EVT_CON_DONE, bts->c0,
			  &bts->rbs2000.con.om2k_mo);
}

static void om2k_bts_s_wait_con(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct om2k_bts_fsm_priv *obfp = fi->priv;
	struct gsm_bts *bts = obfp->bts;

	OSMO_ASSERT(event == OM2K_BTS_EVT_CON_DONE);

	osmo_fsm_inst_state_chg(fi, OM2K_BTS_S_WAIT_IS,
				BTS_FSM_TIMEOUT, 0);
	om2k_mo_fsm_start(fi, OM2K_BTS_EVT_IS_DONE, bts->c0,
			  &bts->rbs2000.is.om2k_mo);
}

static void om2k_bts_s_wait_is(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct om2k_bts_fsm_priv *obfp = fi->priv;
	struct gsm_bts_trx *trx;

	OSMO_ASSERT(event == OM2K_BTS_EVT_IS_DONE);

	osmo_fsm_inst_state_chg(fi, OM2K_BTS_S_WAIT_TRX,
				BTS_FSM_TIMEOUT, 0);
	obfp->next_trx_nr = 0;
	trx = gsm_bts_trx_num(obfp->bts, obfp->next_trx_nr++);
	om2k_trx_fsm_start(fi, trx, OM2K_BTS_EVT_TRX_DONE);
}

static void om2k_bts_s_wait_trx(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct om2k_bts_fsm_priv *obfp = fi->priv;

	OSMO_ASSERT(event == OM2K_BTS_EVT_TRX_DONE);

	if (obfp->next_trx_nr < obfp->bts->num_trx) {
		struct gsm_bts_trx *trx;
		trx = gsm_bts_trx_num(obfp->bts, obfp->next_trx_nr++);
		om2k_trx_fsm_start(fi, trx, OM2K_BTS_EVT_TRX_DONE);
	} else {
		osmo_fsm_inst_state_chg(fi, OM2K_BTS_S_DONE, 0, 0);
	}
}

static void om2k_bts_s_done_onenter(struct osmo_fsm_inst *fi, uint32_t prev_state)
{
	osmo_fsm_inst_term(fi, OSMO_FSM_TERM_REGULAR, NULL);
}

static const struct osmo_fsm_state om2k_bts_states[] = {
	[OM2K_BTS_S_INIT] = {
		.in_event_mask = S(OM2K_BTS_EVT_START),
		.out_state_mask = S(OM2K_BTS_S_WAIT_CF),
		.name = "INIT",
		.action = om2k_bts_s_init,
	},
	[OM2K_BTS_S_WAIT_CF] = {
		.in_event_mask = S(OM2K_BTS_EVT_CF_DONE),
		.out_state_mask = S(OM2K_BTS_S_ERROR) |
				  S(OM2K_BTS_S_WAIT_TF),
		.name = "WAIT-CF",
		.action = om2k_bts_s_wait_cf,
	},
	[OM2K_BTS_S_WAIT_TF] = {
		.in_event_mask = S(OM2K_BTS_EVT_TF_DONE),
		.out_state_mask = S(OM2K_BTS_S_ERROR) |
				  S(OM2K_BTS_S_WAIT_CON),
		.name = "WAIT-TF",
		.action = om2k_bts_s_wait_tf,
	},
	[OM2K_BTS_S_WAIT_CON] = {
		.in_event_mask = S(OM2K_BTS_EVT_CON_DONE),
		.out_state_mask = S(OM2K_BTS_S_ERROR) |
				  S(OM2K_BTS_S_WAIT_IS),
		.name = "WAIT-CON",
		.action = om2k_bts_s_wait_con,
	},
	[OM2K_BTS_S_WAIT_IS] = {
		.in_event_mask = S(OM2K_BTS_EVT_IS_DONE),
		.out_state_mask = S(OM2K_BTS_S_ERROR) |
				  S(OM2K_BTS_S_WAIT_TRX),
		.name = "WAIT-IS",
		.action = om2k_bts_s_wait_is,
	},
	[OM2K_BTS_S_WAIT_TRX] = {
		.in_event_mask = S(OM2K_BTS_EVT_TRX_DONE),
		.out_state_mask = S(OM2K_BTS_S_ERROR) |
				  S(OM2K_BTS_S_DONE),
		.name = "WAIT-TRX",
		.action = om2k_bts_s_wait_trx,
	},
	[OM2K_BTS_S_DONE] = {
		.name = "DONE",
		.onenter = om2k_bts_s_done_onenter,
	},
	[OM2K_BTS_S_ERROR] = {
		.name = "ERROR",
	},
};

static int om2k_bts_timer_cb(struct osmo_fsm_inst *fi)
{
	osmo_fsm_inst_state_chg(fi, OM2K_BTS_S_ERROR, 0, 0);
	return 0;
}

static struct osmo_fsm om2k_bts_fsm = {
	.name = "OM2000-BTS",
	.states = om2k_bts_states,
	.num_states = ARRAY_SIZE(om2k_bts_states),
	.log_subsys = DNM,
	.event_names = om2k_bts_events,
	.timer_cb = om2k_bts_timer_cb,
};

struct osmo_fsm_inst *
om2k_bts_fsm_start(struct gsm_bts *bts)
{
	struct osmo_fsm_inst *fi;
	struct om2k_bts_fsm_priv *obfp;
	char idbuf[16];

	snprintf(idbuf, sizeof(idbuf), "%u", bts->nr);

	fi = osmo_fsm_inst_alloc(&om2k_bts_fsm, bts, NULL,
				 LOGL_DEBUG, idbuf);
	if (!fi)
		return NULL;
	fi->priv = obfp = talloc_zero(fi, struct om2k_bts_fsm_priv);
	obfp->bts = bts;

	osmo_fsm_inst_dispatch(fi, OM2K_BTS_EVT_START, NULL);

	return fi;
}


/***********************************************************************
 * OM2000 Negotiation
 ***********************************************************************/

static int abis_om2k_tx_negot_req_ack(struct gsm_bts *bts, const struct abis_om2k_mo *mo,
				      uint8_t *data, unsigned int len)
{
	struct msgb *msg = om2k_msgb_alloc();
	struct abis_om2k_hdr *o2k;

	o2k = (struct abis_om2k_hdr *) msgb_put(msg, sizeof(*o2k));
	fill_om2k_hdr(o2k, mo, OM2K_MSGT_NEGOT_REQ_ACK);

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
	struct e1inp_sign_link *sign_link = (struct e1inp_sign_link *)msg->dst;
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

	return abis_om2k_tx_negot_req_ack(sign_link->trx->bts, &o2h->mo, out_buf, out_cur - out_buf);
}


/***********************************************************************
 * OM2000 Receive Message Handler
 ***********************************************************************/

static int om2k_rx_nack(struct msgb *msg)
{
	struct abis_om2k_hdr *o2h = msgb_l2(msg);
	uint16_t msg_type = ntohs(o2h->msg_type);
	struct tlv_parsed tp;

	LOGP(DNM, LOGL_ERROR, "Rx MO=%s %s", om2k_mo_name(&o2h->mo),
		get_value_string(om2k_msgcode_vals, msg_type));

	abis_om2k_msg_tlv_parse(&tp, o2h);
	if (TLVP_PRESENT(&tp, OM2K_DEI_REASON_CODE))
		LOGPC(DNM, LOGL_ERROR, ", Reason 0x%02x",
			*TLVP_VAL(&tp, OM2K_DEI_REASON_CODE));

	if (TLVP_PRESENT(&tp, OM2K_DEI_RESULT_CODE))
		LOGPC(DNM, LOGL_ERROR, ", Result %s",
			get_value_string(om2k_result_strings,
					 *TLVP_VAL(&tp, OM2K_DEI_RESULT_CODE)));
	LOGPC(DNM, LOGL_ERROR, "\n");

	return 0;
}

static int process_mo_state(struct gsm_bts *bts, struct om2k_decoded_msg *odm)
{
	uint8_t mo_state;

	if (!TLVP_PRESENT(&odm->tp, OM2K_DEI_MO_STATE))
		return -EIO;
	mo_state = *TLVP_VAL(&odm->tp, OM2K_DEI_MO_STATE);

	LOGP(DNM, LOGL_DEBUG, "Rx MO=%s %s, MO State: %s\n",
		om2k_mo_name(&odm->o2h.mo),
		get_value_string(om2k_msgcode_vals, odm->msg_type),
		get_value_string(om2k_mostate_vals, mo_state));

	/* Throw error message in case we see an enable rsponse that does
	 * not yield an enabled mo-state */
	if (odm->msg_type == OM2K_MSGT_ENABLE_RES
	    && mo_state != OM2K_MO_S_ENABLED) {
		LOGP(DNM, LOGL_ERROR,
		     "Rx MO=%s %s Failed to enable MO State!\n",
		     om2k_mo_name(&odm->o2h.mo),
		     get_value_string(om2k_msgcode_vals, odm->msg_type));
	}

	update_mo_state(bts, &odm->o2h.mo, mo_state);

	return 0;
}

/* Display fault report bits (helper function of display_fault_maps()) */
static bool display_fault_bits(const uint8_t *vect, uint16_t len,
			       uint8_t dei, const struct abis_om2k_mo *mo)
{
	uint16_t i;
	int k;
	bool faults_present = false;
	int first = 1;
	char string[255];

	/* Check if errors are present at all */
	for (i = 0; i < len; i++)
		if (vect[i])
			faults_present = true;
	if (!faults_present)
		return false;

	sprintf(string, "Fault Report: %s (",
		get_value_string(om2k_attr_vals, dei));

	for (i = 0; i < len; i++) {
		for (k = 0; k < 8; k++) {
			if ((vect[i] >> k) & 1) {
				if (!first)
					sprintf(string + strlen(string), ",");
				sprintf(string + strlen(string), "%d", k + i*8);
				first = 0;
			}
		}
	}

	sprintf(string + strlen(string), ")\n");
	DEBUGP(DNM, "Rx MO=%s %s", om2k_mo_name(mo), string);

	return true;
}

/* Display fault report maps */
static void display_fault_maps(const uint8_t *src, unsigned int src_len,
			       const struct abis_om2k_mo *mo)
{
	uint8_t tag;
	uint16_t tag_len;
	const uint8_t *val;
	int src_pos = 0;
	int rc;
	int tlv_count = 0;
	uint16_t msg_code;
	bool faults_present = false;

	/* Chop off header */
	src+=4;
	src_len-=4;

	/* Check message type */
	msg_code = (*src & 0xff) << 8;
	src++;
	src_len--;
	msg_code |= (*src & 0xff);
	src++;
	src_len--;
	if (msg_code != OM2K_MSGT_FAULT_REP) {
		LOGP(DNM, LOGL_ERROR, "Rx MO=%s Fault report: invalid message code!\n",
		     om2k_mo_name(mo));
		return;
	}

	/* Chop off mo-interface */
	src += 4;
	src_len -= 4;

	/* Iterate over each TLV element */
	while (1) {

		/* Bail if an the maximum number of TLV fields
		 * have been parsed */
		if (tlv_count >= 11) {
			LOGP(DNM, LOGL_ERROR,
			     "Rx MO=%s Fault Report: too many tlv elements!\n",
			     om2k_mo_name(mo));
			return;
		}

		/* Parse TLV field */
		rc = tlv_parse_one(&tag, &tag_len, &val, &om2k_att_tlvdef,
				   src + src_pos, src_len - src_pos);
		if (rc > 0)
			src_pos += rc;
		else {
			LOGP(DNM, LOGL_ERROR,
			     "Rx MO=%s Fault Report: invalid tlv element!\n",
			     om2k_mo_name(mo));
			return;
		}

		switch (tag) {
		case OM2K_DEI_INT_FAULT_MAP_1A:
		case OM2K_DEI_INT_FAULT_MAP_1B:
		case OM2K_DEI_INT_FAULT_MAP_2A:
		case OM2K_DEI_EXT_COND_MAP_1:
		case OM2K_DEI_EXT_COND_MAP_2:
		case OM2K_DEI_REPL_UNIT_MAP:
		case OM2K_DEI_INT_FAULT_MAP_2A_EXT:
		case OM2K_DEI_EXT_COND_MAP_2_EXT:
		case OM2K_DEI_REPL_UNIT_MAP_EXT:
			faults_present |= display_fault_bits(val, tag_len,
							     tag, mo);
			break;
		}

		/* Stop when no further TLV elements can be expected */
		if (src_len - src_pos < 2)
			break;

		tlv_count++;
	}

	if (!faults_present) {
		DEBUGP(DNM, "Rx MO=%s Fault Report: All faults ceased!\n",
		       om2k_mo_name(mo));
	}
}

int abis_om2k_rcvmsg(struct msgb *msg)
{
	struct e1inp_sign_link *sign_link = (struct e1inp_sign_link *)msg->dst;
	struct gsm_bts *bts = sign_link->trx->bts;
	struct abis_om2k_hdr *o2h = msgb_l2(msg);
	struct abis_om_hdr *oh = &o2h->om;
	uint16_t msg_type = ntohs(o2h->msg_type);
	struct om2k_decoded_msg odm;
	struct om2k_mo *mo;
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
		osmo_hexdump(msg->l2h, msgb_l2len(msg)));

	om2k_decode_msg(&odm, msg);

	process_mo_state(bts, &odm);

	switch (msg_type) {
	case OM2K_MSGT_CAL_TIME_REQ:
		rc = abis_om2k_cal_time_resp(bts);
		break;
	case OM2K_MSGT_FAULT_REP:
		display_fault_maps(msg->l2h, msgb_l2len(msg), &o2h->mo);
		rc = abis_om2k_tx_simple(bts, &o2h->mo, OM2K_MSGT_FAULT_REP_ACK);
		break;
	case OM2K_MSGT_NEGOT_REQ:
		rc = om2k_rx_negot_req(msg);
		break;
	case OM2K_MSGT_START_RES:
		/* common processing here */
		rc = abis_om2k_tx_simple(bts, &o2h->mo, OM2K_MSGT_START_RES_ACK);
		/* below we dispatch into MO */
		break;
	case OM2K_MSGT_IS_CONF_RES:
		rc = abis_om2k_tx_simple(bts, &o2h->mo, OM2K_MSGT_IS_CONF_RES_ACK);
		break;
	case OM2K_MSGT_CON_CONF_RES:
		rc = abis_om2k_tx_simple(bts, &o2h->mo, OM2K_MSGT_CON_CONF_RES_ACK);
		break;
	case OM2K_MSGT_TX_CONF_RES:
		rc = abis_om2k_tx_simple(bts, &o2h->mo, OM2K_MSGT_TX_CONF_RES_ACK);
		break;
	case OM2K_MSGT_RX_CONF_RES:
		rc = abis_om2k_tx_simple(bts, &o2h->mo, OM2K_MSGT_RX_CONF_RES_ACK);
		break;
	case OM2K_MSGT_TS_CONF_RES:
		rc = abis_om2k_tx_simple(bts, &o2h->mo, OM2K_MSGT_TS_CONF_RES_ACK);
		break;
	case OM2K_MSGT_TF_CONF_RES:
		rc = abis_om2k_tx_simple(bts, &o2h->mo, OM2K_MSGT_TF_CONF_RES_ACK);
		break;
	case OM2K_MSGT_ENABLE_RES:
		rc = abis_om2k_tx_simple(bts, &o2h->mo, OM2K_MSGT_ENABLE_RES_ACK);
		break;
	case OM2K_MSGT_DISABLE_RES:
		rc = abis_om2k_tx_simple(bts, &o2h->mo, OM2K_MSGT_DISABLE_RES_ACK);
		break;
	case OM2K_MSGT_TEST_RES:
		rc = abis_om2k_tx_simple(bts, &o2h->mo, OM2K_MSGT_TEST_RES_ACK);
		break;
	case OM2K_MSGT_CAPA_RES:
		rc = abis_om2k_tx_simple(bts, &o2h->mo, OM2K_MSGT_CAPA_RES_ACK);
		break;
	/* ERrors */
	case OM2K_MSGT_START_REQ_REJ:
	case OM2K_MSGT_CONNECT_REJ:
	case OM2K_MSGT_OP_INFO_REJ:
	case OM2K_MSGT_DISCONNECT_REJ:
	case OM2K_MSGT_TEST_REQ_REJ:
	case OM2K_MSGT_CON_CONF_REQ_REJ:
	case OM2K_MSGT_IS_CONF_REQ_REJ:
	case OM2K_MSGT_TX_CONF_REQ_REJ:
	case OM2K_MSGT_RX_CONF_REQ_REJ:
	case OM2K_MSGT_TS_CONF_REQ_REJ:
	case OM2K_MSGT_TF_CONF_REQ_REJ:
	case OM2K_MSGT_ENABLE_REQ_REJ:
	case OM2K_MSGT_ALARM_STATUS_REQ_REJ:
	case OM2K_MSGT_DISABLE_REQ_REJ:
		rc = om2k_rx_nack(msg);
		break;
	}

	/* Resolve the MO for this message */
	mo = get_om2k_mo(bts, &o2h->mo);
	if (!mo) {
		LOGP(DNM, LOGL_ERROR, "Couldn't resolve MO for OM2K msg "
		     "%s: %s\n", get_value_string(om2k_msgcode_vals, msg_type),
		     msgb_hexdump(msg));
		return 0;
	}
	if (!mo->fsm) {
		LOGP(DNM, LOGL_ERROR, "MO object should not generate any message. fsm == NULL "
		     "%s: %s\n", get_value_string(om2k_msgcode_vals, msg_type),
		     msgb_hexdump(msg));
		return 0;
	}

	/* Dispatch message to that MO */
	om2k_mo_fsm_recvmsg(bts, mo, &odm);

	msgb_free(msg);
	return rc;
}

static void om2k_mo_init(struct om2k_mo *mo, uint8_t class,
			 uint8_t bts_nr, uint8_t assoc_so, uint8_t inst)
{
	mo->addr.class = class;
	mo->addr.bts = bts_nr;
	mo->addr.assoc_so = assoc_so;
	mo->addr.inst = inst;
}

/* initialize the OM2K_MO members of gsm_bts_trx and its timeslots */
void abis_om2k_trx_init(struct gsm_bts_trx *trx)
{
	struct gsm_bts *bts = trx->bts;
	unsigned int i;

	OSMO_ASSERT(bts->type == GSM_BTS_TYPE_RBS2000);

	om2k_mo_init(&trx->rbs2000.trxc.om2k_mo, OM2K_MO_CLS_TRXC,
		     bts->nr, 255, trx->nr);
	om2k_mo_init(&trx->rbs2000.tx.om2k_mo, OM2K_MO_CLS_TX,
		     bts->nr, 255, trx->nr);
	om2k_mo_init(&trx->rbs2000.rx.om2k_mo, OM2K_MO_CLS_RX,
		     bts->nr, 255, trx->nr);

	for (i = 0; i < ARRAY_SIZE(trx->ts); i++) {
		om2k_mo_init(&trx->ts[i].rbs2000.om2k_mo, OM2K_MO_CLS_TS,
				bts->nr, trx->nr, i);
	}
}

/* initialize the OM2K_MO members of gsm_bts */
void abis_om2k_bts_init(struct gsm_bts *bts)
{
	OSMO_ASSERT(bts->type == GSM_BTS_TYPE_RBS2000);

	om2k_mo_init(&bts->rbs2000.cf.om2k_mo, OM2K_MO_CLS_CF,
			bts->nr, 0xFF, 0);
	om2k_mo_init(&bts->rbs2000.is.om2k_mo, OM2K_MO_CLS_IS,
			bts->nr, 0xFF, 0);
	om2k_mo_init(&bts->rbs2000.con.om2k_mo, OM2K_MO_CLS_CON,
			bts->nr, 0xFF, 0);
	om2k_mo_init(&bts->rbs2000.dp.om2k_mo, OM2K_MO_CLS_DP,
			bts->nr, 0xFF, 0);
	om2k_mo_init(&bts->rbs2000.tf.om2k_mo, OM2K_MO_CLS_TF,
			bts->nr, 0xFF, 0);
}

static __attribute__((constructor)) void abis_om2k_init(void)
{
	osmo_fsm_register(&om2k_mo_fsm);
	osmo_fsm_register(&om2k_bts_fsm);
	osmo_fsm_register(&om2k_trx_fsm);
}
