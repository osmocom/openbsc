/* Interaction with the SCCP subsystem */
/*
 * (C) 2009-2010 by Holger Hans Peter Freyther <zecke@selfish.org>
 * (C) 2009-2010 by On-Waves
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

#include <openbsc/gsm_data.h>
#include <openbsc/osmo_msc_data.h>
#include <openbsc/debug.h>

#include <osmocore/gsm0808.h>
#include <osmocore/protocol/gsm_08_08.h>

#include <osmocom/sccp/sccp.h>

static void msc_sccp_write_ipa(struct sccp_connection *conn, struct msgb *msg, void *data)
{
	LOGP(DMSC, LOGL_ERROR, "Writing is not implemented.\n");
	msgb_free(msg);
}

static int msc_sccp_accept(struct sccp_connection *connection, void *data)
{
	LOGP(DMSC, LOGL_DEBUG, "Rejecting incoming SCCP connection.\n");
	return -1;
}

static int msc_sccp_read(struct msgb *msgb, unsigned int length, void *data)
{
	struct bssmap_header *bs;

	LOGP(DMSC, LOGL_DEBUG, "Incoming SCCP message ftom MSC: %s\n",
		hexdump(msgb->l3h, length));

	if (length < sizeof(*bs)) {
		LOGP(DMSC, LOGL_ERROR, "The header is too short.\n");
		return -1;
	}

	bs = (struct bssmap_header *) msgb->l3h;
	if (bs->length < length - sizeof(*bs))
		return -1;

	switch (bs->type) {
	case BSSAP_MSG_BSS_MANAGEMENT:
		LOGP(DMSC, LOGL_ERROR, "BSS management not implemented.\n");
		break;
	default:
		LOGP(DMSC, LOGL_ERROR, "Unimplemented msg type: %d\n", bs->type);
	}

	return 0;
}

int bsc_queue_for_msc(struct gsm_subscriber_connection *conn, struct msgb *msg)
{
	LOGP(DMSC, LOGL_ERROR, "Sending SCCP messages is not yet implemented.\n");
	msgb_free(msg);
	return 0;
}

int osmo_bsc_sccp_init(struct gsm_network *gsmnet)
{
	sccp_set_log_area(DSCCP);
	sccp_system_init(msc_sccp_write_ipa, gsmnet);
	sccp_connection_set_incoming(&sccp_ssn_bssap, msc_sccp_accept, NULL);
	sccp_set_read(&sccp_ssn_bssap, msc_sccp_read, NULL);

	return 0;
}
