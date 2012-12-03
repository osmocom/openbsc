/* (C) 2009-2011 by Holger Hans Peter Freyther <zecke@selfish.org>
 * (C) 2009-2011 by On-Waves
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

#include <openbsc/osmo_bsc.h>
#include <openbsc/osmo_msc_data.h>
#include <openbsc/gsm_04_80.h>
#include <openbsc/gsm_subscriber.h>
#include <openbsc/debug.h>
#include <openbsc/paging.h>

#include <stdlib.h>

static void handle_lu_request(struct gsm_subscriber_connection *conn,
			      struct msgb *msg)
{
	struct gsm48_hdr *gh;
	struct gsm48_loc_upd_req *lu;
	struct gsm48_loc_area_id lai;
	struct gsm_network *net;

	if (msgb_l3len(msg) < sizeof(*gh) + sizeof(*lu)) {
		LOGP(DMSC, LOGL_ERROR, "LU too small to look at: %u\n", msgb_l3len(msg));
		return;
	}

	net = conn->bts->network;

	gh = msgb_l3(msg);
	lu = (struct gsm48_loc_upd_req *) gh->data;

	gsm48_generate_lai(&lai, net->country_code, net->network_code,
			   conn->bts->location_area_code);

	if (memcmp(&lai, &lu->lai, sizeof(lai)) != 0) {
		LOGP(DMSC, LOGL_DEBUG, "Marking con for welcome USSD.\n");
		conn->sccp_con->new_subscriber = 1;
	}
}

/* extract a subscriber from the paging response */
static struct gsm_subscriber *extract_sub(struct gsm_subscriber_connection *conn,
					  struct msgb *msg)
{
	uint8_t mi_type;
	char mi_string[GSM48_MI_SIZE];
	struct gsm48_hdr *gh;
	struct gsm48_pag_resp *resp;
	struct gsm_subscriber *subscr;

	if (msgb_l3len(msg) < sizeof(*gh) + sizeof(*resp)) {
		LOGP(DMSC, LOGL_ERROR, "PagingResponse too small: %u\n", msgb_l3len(msg));
		return NULL;
	}

	gh = msgb_l3(msg);
	resp = (struct gsm48_pag_resp *) &gh->data[0];

	gsm48_paging_extract_mi(resp, msgb_l3len(msg) - sizeof(*gh),
				mi_string, &mi_type);
	DEBUGP(DRR, "PAGING RESPONSE: mi_type=0x%02x MI(%s)\n",
		mi_type, mi_string);

	switch (mi_type) {
	case GSM_MI_TYPE_TMSI:
		subscr = subscr_active_by_tmsi(conn->bts->network,
					       tmsi_from_string(mi_string));
		break;
	case GSM_MI_TYPE_IMSI:
		subscr = subscr_active_by_imsi(conn->bts->network, mi_string);
		break;
	default:
		subscr = NULL;
		break;
	}

	return subscr;
}

/* we will need to stop the paging request */
static int handle_page_resp(struct gsm_subscriber_connection *conn, struct msgb *msg)
{
	struct gsm_subscriber *subscr = extract_sub(conn, msg);

	if (!subscr) {
		LOGP(DMSC, LOGL_ERROR, "Non active subscriber got paged.\n");
		return -1;
	}

	paging_request_stop(conn->bts, subscr, conn, msg);
	subscr_put(subscr);
	return 0;
}

static int is_cm_service_for_emerg(struct msgb *msg)
{
	struct gsm48_service_request *cm;
	struct gsm48_hdr *gh = msgb_l3(msg);

	if (msgb_l3len(msg) < sizeof(*gh) + sizeof(*cm)) {
		LOGP(DMSC, LOGL_ERROR, "CM ServiceRequest does not fit.\n");
		return 0;
	}

	cm = (struct gsm48_service_request *) &gh->data[0];
	return cm->cm_service_type == GSM48_CMSERV_EMERGENCY;
}

struct osmo_msc_data *bsc_find_msc(struct gsm_subscriber_connection *conn,
				   struct msgb *msg)
{
	struct gsm48_hdr *gh;
	int8_t pdisc;
	uint8_t mtype;
	struct osmo_bsc_data *bsc;
	struct osmo_msc_data *msc, *pag_msc;
	struct gsm_subscriber *subscr;
	int is_emerg = 0;

	bsc = conn->bts->network->bsc_data;

	if (msgb_l3len(msg) < sizeof(*gh)) {
		LOGP(DMSC, LOGL_ERROR, "There is no GSM48 header here.\n");
		return NULL;
	}

	gh = msgb_l3(msg);
	pdisc = gh->proto_discr & 0x0f;
	mtype = gh->msg_type & 0xbf;

	/*
	 * We are asked to select a MSC here but they are not equal. We
	 * want to respond to a paging request on the MSC where we got the
	 * request from. This is where we need to decide where this connection
	 * will go.
	 */
	if (pdisc == GSM48_PDISC_RR && mtype == GSM48_MT_RR_PAG_RESP)
		goto paging;
	else if (pdisc == GSM48_PDISC_MM && mtype == GSM48_MT_MM_CM_SERV_REQ) {
		is_emerg = is_cm_service_for_emerg(msg);
		goto round_robin;
	} else
		goto round_robin;

round_robin:
	llist_for_each_entry(msc, &bsc->mscs, entry) {
		if (!msc->msc_con->is_authenticated)
			continue;
		if (!is_emerg && msc->type != MSC_CON_TYPE_NORMAL)
			continue;
		if (is_emerg && !msc->allow_emerg)
			continue;

		/* force round robin by moving it to the end */
		llist_move_tail(&msc->entry, &bsc->mscs);
		return msc;
	}

	return NULL;

paging:
	subscr = extract_sub(conn, msg);

	if (!subscr) {
		LOGP(DMSC, LOGL_ERROR, "Got paged but no subscriber found.\n");
		return NULL;
	}

	pag_msc = paging_get_data(conn->bts, subscr);
	subscr_put(subscr);

	llist_for_each_entry(msc, &bsc->mscs, entry) {
		if (msc != pag_msc)
			continue;

		/*
		 * We don't check if the MSC is connected. In case it
		 * is not the connection will be dropped.
		 */

		/* force round robin by moving it to the end */
		llist_move_tail(&msc->entry, &bsc->mscs);
		return msc;
	}

	LOGP(DMSC, LOGL_ERROR, "Got paged but no request found.\n");
	return NULL;
}


/**
 * This is used to scan a message for extra functionality of the BSC. This
 * includes scanning for location updating requests/acceptd and then send
 * a welcome USSD message to the subscriber.
 */
int bsc_scan_bts_msg(struct gsm_subscriber_connection *conn, struct msgb *msg)
{
	struct gsm48_hdr *gh = msgb_l3(msg);
	uint8_t pdisc = gh->proto_discr & 0x0f;
	uint8_t mtype = gh->msg_type & 0xbf;

	if (pdisc == GSM48_PDISC_MM) {
		if (mtype == GSM48_MT_MM_LOC_UPD_REQUEST)
			handle_lu_request(conn, msg);
	} else if (pdisc == GSM48_PDISC_RR) {
		if (mtype == GSM48_MT_RR_PAG_RESP)
			handle_page_resp(conn, msg);
	}

	return 0;
}

static int send_welcome_ussd(struct gsm_subscriber_connection *conn)
{
	struct osmo_bsc_sccp_con *bsc_con;

	bsc_con = conn->sccp_con;
	if (!bsc_con) {
		LOGP(DMSC, LOGL_DEBUG, "No SCCP connection associated.\n");
		return 0;
	}

	if (!bsc_con->msc->ussd_welcome_txt) {
		LOGP(DMSC, LOGL_DEBUG, "No USSD Welcome text defined.\n");
		return 0;
	}

	return BSS_SEND_USSD;
}

int bsc_send_welcome_ussd(struct gsm_subscriber_connection *conn)
{
	gsm0480_send_ussdNotify(conn, 1, conn->sccp_con->msc->ussd_welcome_txt);
	gsm0480_send_releaseComplete(conn);

	return 0;
}

/**
 * Messages coming back from the MSC.
 */
int bsc_scan_msc_msg(struct gsm_subscriber_connection *conn, struct msgb *msg)
{
	struct osmo_msc_data *msc;
	struct gsm_network *net;
	struct gsm48_loc_area_id *lai;
	struct gsm48_hdr *gh;
	uint8_t mtype;

	if (msgb_l3len(msg) < sizeof(*gh)) {
		LOGP(DMSC, LOGL_ERROR, "GSM48 header does not fit.\n");
		return -1;
	}

	gh = (struct gsm48_hdr *) msgb_l3(msg);
	mtype = gh->msg_type & 0xbf;
	net = conn->bts->network;
	msc = conn->sccp_con->msc;

	if (mtype == GSM48_MT_MM_LOC_UPD_ACCEPT) {
		if (msc->core_ncc != -1 || msc->core_mcc != -1) {
			if (msgb_l3len(msg) >= sizeof(*gh) + sizeof(*lai)) {
				lai = (struct gsm48_loc_area_id *) &gh->data[0];
				gsm48_generate_lai(lai, net->country_code,
						   net->network_code,
						   conn->bts->location_area_code);
			}
		}

		if (conn->sccp_con->new_subscriber)
			return send_welcome_ussd(conn);
		return 0;
	}

	return 0;
}
