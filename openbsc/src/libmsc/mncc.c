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

#include <osmocom/core/talloc.h>
#include <osmocom/core/utils.h>

#include <openbsc/gsm_04_08.h>
#include <openbsc/debug.h>
#include <openbsc/mncc.h>
#include <openbsc/gsm_data.h>
#include <openbsc/transaction.h>
#include <openbsc/rtp_proxy.h>


static const struct value_string mncc_names[] = {
	{ MNCC_SETUP_REQ, "MNCC_SETUP_REQ" },
	{ MNCC_SETUP_IND, "MNCC_SETUP_IND" },
	{ MNCC_SETUP_RSP, "MNCC_SETUP_RSP" },
	{ MNCC_SETUP_CNF, "MNCC_SETUP_CNF" },
	{ MNCC_SETUP_COMPL_REQ, "MNCC_SETUP_COMPL_REQ" },
	{ MNCC_SETUP_COMPL_IND, "MNCC_SETUP_COMPL_IND" },
	{ MNCC_CALL_CONF_IND, "MNCC_CALL_CONF_IND" },
	{ MNCC_CALL_PROC_REQ, "MNCC_CALL_PROC_REQ" },
	{ MNCC_PROGRESS_REQ, "MNCC_PROGRESS_REQ" },
	{ MNCC_ALERT_REQ, "MNCC_ALERT_REQ" },
	{ MNCC_ALERT_IND, "MNCC_ALERT_IND" },
	{ MNCC_NOTIFY_REQ, "MNCC_NOTIFY_REQ" },
	{ MNCC_NOTIFY_IND, "MNCC_NOTIFY_IND" },
	{ MNCC_DISC_REQ, "MNCC_DISC_REQ" },
	{ MNCC_DISC_IND, "MNCC_DISC_IND" },
	{ MNCC_REL_REQ, "MNCC_REL_REQ" },
	{ MNCC_REL_IND, "MNCC_REL_IND" },
	{ MNCC_REL_CNF, "MNCC_REL_CNF" },
	{ MNCC_FACILITY_REQ, "MNCC_FACILITY_REQ" },
	{ MNCC_FACILITY_IND, "MNCC_FACILITY_IND" },
	{ MNCC_START_DTMF_IND, "MNCC_START_DTMF_IND" },
	{ MNCC_START_DTMF_RSP, "MNCC_START_DTMF_RSP" },
	{ MNCC_START_DTMF_REJ, "MNCC_START_DTMF_REJ" },
	{ MNCC_STOP_DTMF_IND, "MNCC_STOP_DTMF_IND" },
	{ MNCC_STOP_DTMF_RSP, "MNCC_STOP_DTMF_RSP" },
	{ MNCC_MODIFY_REQ, "MNCC_MODIFY_REQ" },
	{ MNCC_MODIFY_IND, "MNCC_MODIFY_IND" },
	{ MNCC_MODIFY_RSP, "MNCC_MODIFY_RSP" },
	{ MNCC_MODIFY_CNF, "MNCC_MODIFY_CNF" },
	{ MNCC_MODIFY_REJ, "MNCC_MODIFY_REJ" },
	{ MNCC_HOLD_IND, "MNCC_HOLD_IND" },
	{ MNCC_HOLD_CNF, "MNCC_HOLD_CNF" },
	{ MNCC_HOLD_REJ, "MNCC_HOLD_REJ" },
	{ MNCC_RETRIEVE_IND, "MNCC_RETRIEVE_IND" },
	{ MNCC_RETRIEVE_CNF, "MNCC_RETRIEVE_CNF" },
	{ MNCC_RETRIEVE_REJ, "MNCC_RETRIEVE_REJ" },
	{ MNCC_USERINFO_REQ, "MNCC_USERINFO_REQ" },
	{ MNCC_USERINFO_IND, "MNCC_USERINFO_IND" },
	{ MNCC_REJ_REQ, "MNCC_REJ_REQ" },
	{ MNCC_REJ_IND, "MNCC_REJ_IND" },
	{ MNCC_BRIDGE, "MNCC_BRIDGE" },
	{ MNCC_FRAME_RECV, "MNCC_FRAME_RECV" },
	{ MNCC_FRAME_DROP, "MNCC_FRAME_DROP" },
	{ MNCC_LCHAN_MODIFY, "MNCC_LCHAN_MODIFY" },
	{ MNCC_RTP_CREATE, "MNCC_RTP_CREATE" },
	{ MNCC_RTP_CONNECT, "MNCC_RTP_CONNECT" },
	{ MNCC_RTP_FREE, "MNCC_RTP_FREE" },
	{ GSM_TCHF_FRAME, "GSM_TCHF_FRAME" },
	{ GSM_TCHF_FRAME_EFR, "GSM_TCHF_FRAME_EFR" },
	{ GSM_TCHH_FRAME, "GSM_TCHH_FRAME" },
	{ GSM_TCH_FRAME_AMR, "GSM_TCH_FRAME_AMR" },
	{ GSM_BAD_FRAME, "GSM_BAD_FRAME" },
	{ 0, NULL },
};

const char *get_mncc_name(int value)
{
	return get_value_string(mncc_names, value);
}

void mncc_set_cause(struct gsm_mncc *data, int loc, int val)
{
	data->fields |= MNCC_F_CAUSE;
	data->cause.location = loc;
	data->cause.value = val;
}

