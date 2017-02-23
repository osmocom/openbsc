/*
 * ipaccess audio handling
 *
 * (C) 2009-2010 by Holger Hans Peter Freyther <zecke@selfish.org>
 * (C) 2009-2010 by On-Waves
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

#include <openbsc/bsc_msc_data.h>
#include <openbsc/osmo_bsc.h>
#include <openbsc/abis_rsl.h>
#include <openbsc/gsm_data.h>
#include <openbsc/debug.h>
#include <openbsc/signal.h>

#include <arpa/inet.h>

static int handle_abisip_signal(unsigned int subsys, unsigned int signal,
				 void *handler_data, void *signal_data)
{
	struct gsm_subscriber_connection *con;
	struct gsm_lchan *lchan = signal_data;
	int rc;

	if (subsys != SS_ABISIP)
		return 0;

	con = lchan->conn;
	if (!con || !con->sccp_con)
		return 0;

	switch (signal) {
	case S_ABISIP_CRCX_ACK:
		/*
		 * TODO: handle handover here... then the audio should go to
		 * the old mgcp port..
		 */
		/* we can ask it to connect now */
		LOGP(DMSC, LOGL_DEBUG, "Connecting BTS to port: %d conn: %d\n",
		     con->sccp_con->rtp_port, lchan->abis_ip.conn_id);

		rc = rsl_ipacc_mdcx(lchan, ntohl(INADDR_ANY),
				    con->sccp_con->rtp_port,
				    lchan->abis_ip.rtp_payload2);
		if (rc < 0) {
			LOGP(DMSC, LOGL_ERROR, "Failed to send MDCX: %d\n", rc);
			return rc;
		}
		break;
	}

	return 0;
}

int osmo_bsc_audio_init(struct gsm_network *net)
{
	osmo_signal_register_handler(SS_ABISIP, handle_abisip_signal, net);
	return 0;
}
