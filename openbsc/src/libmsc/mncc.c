/* mncc.c - utility routines for the MNCC API between the 04.08
 *	    message parsing and the actual Call Control logic */

/* (C) 2008-2009 by Harald Welte <laforge@gnumonks.org>
 * (C) 2009 by Andreas Eversberg <Andreas.Eversberg@versatel.de>
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
#include <string.h>
#include <errno.h>

#include <openbsc/gsm_04_08.h>
#include <openbsc/debug.h>
#include <openbsc/mncc.h>
#include <osmocom/core/talloc.h>
#include <openbsc/gsm_data.h>
#include <openbsc/transaction.h>
#include <openbsc/rtp_proxy.h>

struct name_value {
	char *name;
	int value;
};

static struct name_value mncc_names[] = {
	{"MNCC_SETUP_REQ",	0x0101},
	{"MNCC_SETUP_IND",	0x0102},
	{"MNCC_SETUP_RSP",	0x0103},
	{"MNCC_SETUP_CNF",	0x0104},
	{"MNCC_SETUP_COMPL_REQ",0x0105},
	{"MNCC_SETUP_COMPL_IND",0x0106},
	{"MNCC_CALL_CONF_IND",	0x0107},
	{"MNCC_CALL_PROC_REQ",	0x0108},
	{"MNCC_PROGRESS_REQ",	0x0109},
	{"MNCC_ALERT_REQ",	0x010a},
	{"MNCC_ALERT_IND",	0x010b},
	{"MNCC_NOTIFY_REQ",	0x010c},
	{"MNCC_NOTIFY_IND",	0x010d},
	{"MNCC_DISC_REQ",	0x010e},
	{"MNCC_DISC_IND",	0x010f},
	{"MNCC_REL_REQ",	0x0110},
	{"MNCC_REL_IND",	0x0111},
	{"MNCC_REL_CNF",	0x0112},
	{"MNCC_FACILITY_REQ",	0x0113},
	{"MNCC_FACILITY_IND",	0x0114},
	{"MNCC_START_DTMF_IND",	0x0115},
	{"MNCC_START_DTMF_RSP",	0x0116},
	{"MNCC_START_DTMF_REJ",	0x0117},
	{"MNCC_STOP_DTMF_IND",	0x0118},
	{"MNCC_STOP_DTMF_RSP",	0x0119},
	{"MNCC_MODIFY_REQ",	0x011a},
	{"MNCC_MODIFY_IND",	0x011b},
	{"MNCC_MODIFY_RSP",	0x011c},
	{"MNCC_MODIFY_CNF",	0x011d},
	{"MNCC_MODIFY_REJ",	0x011e},
	{"MNCC_HOLD_IND",	0x011f},
	{"MNCC_HOLD_CNF",	0x0120},
	{"MNCC_HOLD_REJ",	0x0121},
	{"MNCC_RETRIEVE_IND",	0x0122},
	{"MNCC_RETRIEVE_CNF",	0x0123},
	{"MNCC_RETRIEVE_REJ",	0x0124},
	{"MNCC_USERINFO_REQ",	0x0125},
	{"MNCC_USERINFO_IND",	0x0126},
	{"MNCC_REJ_REQ",	0x0127},
	{"MNCC_REJ_IND",	0x0128},

	{"MNCC_BRIDGE",		0x0200},
	{"MNCC_FRAME_RECV",	0x0201},
	{"MNCC_FRAME_DROP",	0x0202},
	{"MNCC_LCHAN_MODIFY",	0x0203},

	{"GSM_TCHF_FRAME",	0x0300},
	{"GSM_TCHF_FRAME_EFR",	0x0301},
	{"GSM_TCHH_FRAME",	0x0302},
	{"GSM_TCH_FRAME_AMR",	0x0303},
	{"GSM_BAD_FRAME",	0x03ff},

	{NULL, 0} };

static struct name_value mncc_locations[] = {
	{"GSM48_CAUSE_LOC_USER",		0x00},
	{"GSM48_CAUSE_LOC_PRN_S_LU",	0x01},
	{"GSM48_CAUSE_LOC_PUN_S_LU",	0x02},
	{"GSM48_CAUSE_LOC_TRANS_NET",	0x03},
	{"GSM48_CAUSE_LOC_PUN_S_RU",	0x04},
	{"GSM48_CAUSE_LOC_PRN_S_RU",	0x05},
	/* not defined */
	{"GSM48_CAUSE_LOC_INN_NET",		0x07},
	{"GSM48_CAUSE_LOC_NET_BEYOND",	0x0a},

	{NULL, 0} };

static struct name_value mncc_causes[] = {
	{"GSM48_CC_CAUSE_UNASSIGNED_NR",	1},
	{"GSM48_CC_CAUSE_NO_ROUTE",	3},
	{"GSM48_CC_CAUSE_CHAN_UNACCEPT",	6},
	{"GSM48_CC_CAUSE_OP_DET_BARRING",	8},
	{"GSM48_CC_CAUSE_NORM_CALL_CLEAR",	16},
	{"GSM48_CC_CAUSE_USER_BUSY",	17},
	{"GSM48_CC_CAUSE_USER_NOTRESPOND",	18},
	{"GSM48_CC_CAUSE_USER_ALERTING_NA",	19},
	{"GSM48_CC_CAUSE_CALL_REJECTED",	21},
	{"GSM48_CC_CAUSE_NUMBER_CHANGED",	22},
	{"GSM48_CC_CAUSE_PRE_EMPTION",	25},
	{"GSM48_CC_CAUSE_NONSE_USER_CLR",	26},
	{"GSM48_CC_CAUSE_DEST_OOO",	27},
	{"GSM48_CC_CAUSE_INV_NR_FORMAT",	28},
	{"GSM48_CC_CAUSE_FACILITY_REJ",	29},
	{"GSM48_CC_CAUSE_RESP_STATUS_INQ",	30},
	{"GSM48_CC_CAUSE_NORMAL_UNSPEC",	31},
	{"GSM48_CC_CAUSE_NO_CIRCUIT_CHAN",	34},
	{"GSM48_CC_CAUSE_NETWORK_OOO",	38},
	{"GSM48_CC_CAUSE_TEMP_FAILURE",	41},
	{"GSM48_CC_CAUSE_SWITCH_CONG",	42},
	{"GSM48_CC_CAUSE_ACC_INF_DISCARD",	43},
	{"GSM48_CC_CAUSE_REQ_CHAN_UNAVAIL",	44},
	{"GSM48_CC_CAUSE_RESOURCE_UNAVAIL",	47},
	{"GSM48_CC_CAUSE_QOS_UNAVAIL",	49},
	{"GSM48_CC_CAUSE_REQ_FAC_NOT_SUBSC",	50},
	{"GSM48_CC_CAUSE_INC_BARRED_CUG",	55},
	{"GSM48_CC_CAUSE_BEARER_CAP_UNAUTH",	57},
	{"GSM48_CC_CAUSE_BEARER_CA_UNAVAIL",	58},
	{"GSM48_CC_CAUSE_SERV_OPT_UNAVAIL",	63},
	{"GSM48_CC_CAUSE_BEARERSERV_UNIMPL",	65},
	{"GSM48_CC_CAUSE_ACM_GE_ACM_MAX",	68},
	{"GSM48_CC_CAUSE_REQ_FAC_NOTIMPL",	69},
	{"GSM48_CC_CAUSE_RESTR_BCAP_AVAIL",	70},
	{"GSM48_CC_CAUSE_SERV_OPT_UNIMPL",	79},
	{"GSM48_CC_CAUSE_INVAL_TRANS_ID",	81},
	{"GSM48_CC_CAUSE_USER_NOT_IN_CUG",	87},
	{"GSM48_CC_CAUSE_INCOMPAT_DEST",	88},
	{"GSM48_CC_CAUSE_INVAL_TRANS_NET",	91},
	{"GSM48_CC_CAUSE_SEMANTIC_INCORR",	95},
	{"GSM48_CC_CAUSE_INVAL_MAND_INF",	96},
	{"GSM48_CC_CAUSE_MSGTYPE_NOTEXIST",	97},
	{"GSM48_CC_CAUSE_MSGTYPE_INCOMPAT",	98},
	{"GSM48_CC_CAUSE_IE_NOTEXIST",	99},
	{"GSM48_CC_CAUSE_COND_IE_ERR",	100},
	{"GSM48_CC_CAUSE_MSG_INCOMP_STATE",	101},
	{"GSM48_CC_CAUSE_RECOVERY_TIMER",	102},
	{"GSM48_CC_CAUSE_PROTO_ERR",	111},
	{"GSM48_CC_CAUSE_INTERWORKING",	127},

	{NULL, 0} };

const char *get_name_by_value(struct name_value *pairs, int value, const char *default_val)
{
	int i;

	for (i = 0; pairs[i].name; i++) {
		if (pairs[i].value == value)
			return pairs[i].name;
	}

	return default_val;
}


const char *get_mncc_name(int value)
{
	return get_name_by_value(mncc_names, value, "MNCC_Unknown");
}

const char *get_mncc_location(int value)
{
	return get_name_by_value(mncc_locations, value, "GSM48_CAUSE_LOC_Unknown");
}

const char *get_mncc_cause(int value)
{
	return get_name_by_value(mncc_causes, value, "GSM48_CC_CAUSE_Unknown");
}

int mncc_has_cause(struct gsm_mncc *data)
{
	return data->fields & MNCC_F_CAUSE;
}

void mncc_set_cause(struct gsm_mncc *data, int loc, int val)
{
	data->fields |= MNCC_F_CAUSE;
	data->cause.location = loc;
	data->cause.value = val;
}

