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
#include <osmocom/gsm/gsm0808.h>
#include <osmocom/gsm/gsm0808_utils.h>
#include <openbsc/osmo_bsc_sigtran.h>

#include <arpa/inet.h>

/* Generate and send assignment complete message */
static int send_aoip_ass_compl(struct gsm_subscriber_connection *conn, struct gsm_lchan *lchan)
{
	struct msgb *resp;
	struct sockaddr_storage rtp_addr;
	struct sockaddr_in rtp_addr_in;
	struct gsm0808_speech_codec sc;

	OSMO_ASSERT(lchan->abis_ip.ass_compl.valid == true);

	/* Package RTP-Address data */
	memset(&rtp_addr_in, 0, sizeof(rtp_addr_in));
	rtp_addr_in.sin_family = AF_INET;
	rtp_addr_in.sin_port = htons(lchan->abis_ip.bound_port);
	rtp_addr_in.sin_addr.s_addr = htonl(lchan->abis_ip.bound_ip);
	memset(&rtp_addr, 0, sizeof(rtp_addr));
	memcpy(&rtp_addr, &rtp_addr_in, sizeof(rtp_addr_in));

	/* Extrapolate speech codec from speech mode */
	gsm0808_speech_codec_from_chan_type(&sc, lchan->abis_ip.ass_compl.speech_mode);

	/* Generate message */
	resp = gsm0808_create_ass_compl(lchan->abis_ip.ass_compl.rr_cause,
					lchan->abis_ip.ass_compl.chosen_channel,
					lchan->abis_ip.ass_compl.encr_alg_id,
					lchan->abis_ip.ass_compl.speech_mode,
					&rtp_addr,
					&sc,
					NULL);

	if (!resp) {
		LOGP(DMSC, LOGL_ERROR, "Failed to generate assignment completed message!\n"); \
		return -EINVAL;
	}

	return osmo_bsc_sigtran_send(conn->sccp_con, resp);
}

static int handle_abisip_signal(unsigned int subsys, unsigned int signal,
				 void *handler_data, void *signal_data)
{
	struct gsm_subscriber_connection *con;
	struct gsm_lchan *lchan = signal_data;
	int rc;
	uint32_t rtp_ip;

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

		/* If AoIP is in use, the rtp_ip, which has been communicated
		 * via the A interface as connect_ip */
		if(con->sccp_con->rtp_ip)
			rtp_ip = con->sccp_con->rtp_ip;
		else
			rtp_ip = ntohl(INADDR_ANY);

		rc = rsl_ipacc_mdcx(lchan, rtp_ip,
				    con->sccp_con->rtp_port,
				    lchan->abis_ip.rtp_payload2);
		if (rc < 0) {
			LOGP(DMSC, LOGL_ERROR, "Failed to send MDCX: %d\n", rc);
			return rc;
		}
		break;

	case S_ABISIP_MDCX_ACK:
		if (con->ho_lchan) {
			/* NOTE: When an ho_lchan exists, the MDCX is part of an
			 * handover operation (intra-bsc). This means we will not
			 * inform the MSC about the event, which means that no
			 * assignment complete message is transmitted */
			LOGP(DMSC, LOGL_INFO," RTP connection handover complete\n");
		} else if (is_ipaccess_bts(con->bts) && con->sccp_con->rtp_ip) {
			/* NOTE: This is only relevant on AoIP networks with
			 * IPA based base stations. See also osmo_bsc_api.c,
			 * function bsc_assign_compl() */
			LOGP(DMSC, LOGL_INFO, "Tx MSC ASSIGN COMPL (POSTPONED)\n");
			if (send_aoip_ass_compl(con, lchan) != 0)
				return -EINVAL;
		}
		break;
	break;
	}

	return 0;
}

int osmo_bsc_audio_init(struct gsm_network *net)
{
	osmo_signal_register_handler(SS_ABISIP, handle_abisip_signal, net);
	return 0;
}
