/* USSD Filter Code */

/*
 * (C) 2010 by Holger Hans Peter Freyther <zecke@selfish.org>
 * (C) 2010 by On-Waves
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

#include <openbsc/bsc_nat.h>
#include <openbsc/bsc_nat_sccp.h>

#include <osmocore/protocol/gsm_08_08.h>

#include <osmocore/gsm0480.h>

#include <string.h>


int bsc_check_ussd(struct sccp_connections *con, struct bsc_nat_parsed *parsed,
		   struct msgb *msg)
{
	uint32_t len;
	uint8_t msg_type;
	struct gsm48_hdr *hdr48;
	struct bsc_nat_acc_lst *lst;
	struct ussd_request req;

	/*
	 * various checks to avoid the decoding work. Right now we only want to
	 * decode if the connection was created for USSD, we do have a USSD access
	 * list, a query, a IMSI and such...
	 */
	if (con->con_type != NAT_CON_TYPE_SSA)
		return 0;

	if (!con->imsi)
		return 0;

	if (!con->bsc->nat->ussd_lst_name)
		return 0;
	if (!con->bsc->nat->ussd_query)
		return 0;

	if (parsed->bssap != BSSAP_MSG_DTAP)
		return 0;

	if (strlen(con->imsi) > GSM_IMSI_LENGTH)
		return 0;

	hdr48 = bsc_unpack_dtap(parsed, msg, &len);
	if (!hdr48)
		return 0;

	msg_type = hdr48->msg_type & 0xbf;
	if (hdr48->proto_discr != GSM48_PDISC_NC_SS || msg_type != GSM0480_MTYPE_REGISTER)
		return 0;

	/* now check if it is a IMSI we care about */
	lst = bsc_nat_acc_lst_find(con->bsc->nat, con->bsc->nat->ussd_lst_name);
	if (!lst)
		return 0;

	if (bsc_nat_lst_check_allow(lst, con->imsi) != 0)
		return 0;

	/* now decode the message and see if we really want to handle it */
	memset(&req, 0, sizeof(req));
	if (gsm0480_decode_ussd_request(hdr48, len, &req) != 1)
		return 0;
	if (req.text[0] == 0xff)
		return 0;

	if (strcmp(req.text, con->bsc->nat->ussd_query) != 0)
		return 0;

	/* found a USSD query for our subscriber */
	LOGP(DNAT, LOGL_NOTICE, "Found USSD query for %s\n", con->imsi);
	return 1;
}
