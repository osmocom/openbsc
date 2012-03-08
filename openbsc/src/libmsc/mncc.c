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

static struct mncc_names {
	char *name;
	int value;
} mncc_names[] = {
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

	{NULL, 0} };

char *get_mncc_name(int value)
{
	int i;

	for (i = 0; mncc_names[i].name; i++) {
		if (mncc_names[i].value == value)
			return mncc_names[i].name;
	}

	return "MNCC_Unknown";
}

void mncc_set_cause(struct gsm_mncc *data, int loc, int val)
{
	data->fields |= MNCC_F_CAUSE;
	data->cause.location = loc;
	data->cause.value = val;
}

