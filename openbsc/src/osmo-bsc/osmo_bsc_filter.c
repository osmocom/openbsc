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
#include <openbsc/bsc_msc_data.h>
#include <openbsc/gsm_04_80.h>
#include <openbsc/gsm_subscriber.h>
#include <openbsc/bsc_subscriber.h>
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
static struct bsc_subscr *extract_sub(struct gsm_subscriber_connection *conn,
				   struct msgb *msg)
{
	uint8_t mi_type;
	char mi_string[GSM48_MI_SIZE];
	struct gsm48_hdr *gh;
	struct gsm48_pag_resp *resp;
	struct bsc_subscr *subscr;

	if (msgb_l3len(msg) < sizeof(*gh) + sizeof(*resp)) {
		LOGP(DMSC, LOGL_ERROR, "PagingResponse too small: %u\n", msgb_l3len(msg));
		return NULL;
	}

	gh = msgb_l3(msg);
	resp = (struct gsm48_pag_resp *) &gh->data[0];

	gsm48_paging_extract_mi(resp, msgb_l3len(msg) - sizeof(*gh),
				mi_string, &mi_type);
	DEBUGP(DRR, "PAGING RESPONSE: MI(%s)=%s\n",
		gsm48_mi_type_name(mi_type), mi_string);

	switch (mi_type) {
	case GSM_MI_TYPE_TMSI:
		subscr = bsc_subscr_find_by_tmsi(conn->network->bsc_subscribers,
					      tmsi_from_string(mi_string));
		break;
	case GSM_MI_TYPE_IMSI:
		subscr = bsc_subscr_find_by_imsi(conn->network->bsc_subscribers,
					      mi_string);
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
	struct bsc_subscr *subscr = extract_sub(conn, msg);

	if (!subscr) {
		LOGP(DMSC, LOGL_ERROR, "Non active subscriber got paged.\n");
		return -1;
	}

	paging_request_stop(&conn->network->bts_list, conn->bts, subscr, conn,
			    msg);
	bsc_subscr_put(subscr);
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

struct bsc_msc_data *bsc_find_msc(struct gsm_subscriber_connection *conn,
				   struct msgb *msg)
{
	struct gsm48_hdr *gh;
	int8_t pdisc;
	uint8_t mtype;
	struct osmo_bsc_data *bsc;
	struct bsc_msc_data *msc, *pag_msc;
	struct bsc_subscr *subscr;
	int is_emerg = 0;

	bsc = conn->bts->network->bsc_data;

	if (msgb_l3len(msg) < sizeof(*gh)) {
		LOGP(DMSC, LOGL_ERROR, "There is no GSM48 header here.\n");
		return NULL;
	}

	gh = msgb_l3(msg);
	pdisc = gsm48_hdr_pdisc(gh);
	mtype = gsm48_hdr_msg_type(gh);

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
	bsc_subscr_put(subscr);

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
	uint8_t pdisc = gsm48_hdr_pdisc(gh);
	uint8_t mtype = gsm48_hdr_msg_type(gh);

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
	bsc_send_ussd_notify(conn, 1, conn->sccp_con->msc->ussd_welcome_txt);
	bsc_send_ussd_release_complete(conn);

	return 0;
}

static int bsc_patch_mm_info(struct gsm_subscriber_connection *conn,
		uint8_t *data, unsigned int length)
{
	struct tlv_parsed tp;
	int parse_res;
	struct gsm_bts *bts = conn->bts;
	int tzunits;
	uint8_t tzbsd = 0;
	uint8_t dst = 0;

	parse_res = tlv_parse(&tp, &gsm48_mm_att_tlvdef, data, length, 0, 0);
	if (parse_res <= 0 && parse_res != -3)
		/* FIXME: -3 means unknown IE error, so this accepts messages
		 * with unknown IEs. But parsing has aborted with the unknown
		 * IE and the message is broken or parsed incompletely. */
		return 0;

	/* Is TZ patching enabled? */
	struct gsm_tz *tz = &bts->network->tz;
	if (!tz->override)
		return 0;

	/* Convert tz.hr and tz.mn to units */
	if (tz->hr < 0) {
		tzunits = -tz->hr*4;
		tzbsd |= 0x08;
	} else
		tzunits = tz->hr*4;

	tzunits = tzunits + (tz->mn/15);

	tzbsd |= (tzunits % 10)*0x10 + (tzunits / 10);

	/* Convert DST value */
	if (tz->dst >= 0 && tz->dst <= 2)
		dst = tz->dst;

	if (TLVP_PRESENT(&tp, GSM48_IE_UTC)) {
		LOGP(DMSC, LOGL_DEBUG,
			"Changing 'Local time zone' from 0x%02x to 0x%02x.\n",
			TLVP_VAL(&tp, GSM48_IE_UTC)[6], tzbsd);
		((uint8_t *)(TLVP_VAL(&tp, GSM48_IE_UTC)))[0] = tzbsd;
	}
	if (TLVP_PRESENT(&tp, GSM48_IE_NET_TIME_TZ)) {
		LOGP(DMSC, LOGL_DEBUG,
			"Changing 'Universal time and local time zone' TZ from "
			"0x%02x to 0x%02x.\n",
			TLVP_VAL(&tp, GSM48_IE_NET_TIME_TZ)[6], tzbsd);
		((uint8_t *)(TLVP_VAL(&tp, GSM48_IE_NET_TIME_TZ)))[6] = tzbsd;
	}
#ifdef GSM48_IE_NET_DST
	if (TLVP_PRESENT(&tp, GSM48_IE_NET_DST)) {
		LOGP(DMSC, LOGL_DEBUG,
			"Changing 'Network daylight saving time' from "
			"0x%02x to 0x%02x.\n",
			TLVP_VAL(&tp, GSM48_IE_NET_DST)[0], dst);
		((uint8_t *)(TLVP_VAL(&tp, GSM48_IE_NET_DST)))[0] = dst;
	}
#endif

	return 0;
}

static int has_core_identity(struct bsc_msc_data *msc)
{
	if (msc->core_mnc != -1)
		return 1;
	if (msc->core_mcc != -1)
		return 1;
	if (msc->core_lac != -1)
		return 1;
	if (msc->core_ci != -1)
		return 1;
	return 0;
}

/**
 * Messages coming back from the MSC.
 */
int bsc_scan_msc_msg(struct gsm_subscriber_connection *conn, struct msgb *msg)
{
	struct bsc_msc_data *msc;
	struct gsm_network *net;
	struct gsm48_loc_area_id *lai;
	struct gsm48_hdr *gh;
	uint8_t pdisc;
	uint8_t mtype;
	int length = msgb_l3len(msg);

	if (length < sizeof(*gh)) {
		LOGP(DMSC, LOGL_ERROR, "GSM48 header does not fit.\n");
		return -1;
	}

	gh = (struct gsm48_hdr *) msgb_l3(msg);
	length -= (const char *)&gh->data[0] - (const char *)gh;

	pdisc = gsm48_hdr_pdisc(gh);
	if (pdisc != GSM48_PDISC_MM)
		return 0;

	mtype = gsm48_hdr_msg_type(gh);
	net = conn->bts->network;
	msc = conn->sccp_con->msc;

	if (mtype == GSM48_MT_MM_LOC_UPD_ACCEPT) {
		if (has_core_identity(msc)) {
			if (msgb_l3len(msg) >= sizeof(*gh) + sizeof(*lai)) {
				/* overwrite LAI in the message */
				lai = (struct gsm48_loc_area_id *) &gh->data[0];
				gsm48_generate_lai(lai, net->country_code,
						   net->network_code,
						   conn->bts->location_area_code);
			}
		}

		if (conn->sccp_con->new_subscriber)
			return send_welcome_ussd(conn);
		return 0;
	} else if (mtype == GSM48_MT_MM_INFO) {
		bsc_patch_mm_info(conn, &gh->data[0], length);
	}

	return 0;
}
