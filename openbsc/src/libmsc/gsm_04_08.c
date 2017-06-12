/* GSM Mobile Radio Interface Layer 3 messages on the A-bis interface
 * 3GPP TS 04.08 version 7.21.0 Release 1998 / ETSI TS 100 940 V7.21.0 */

/* (C) 2008-2016 by Harald Welte <laforge@gnumonks.org>
 * (C) 2008-2012 by Holger Hans Peter Freyther <zecke@selfish.org>
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


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <errno.h>
#include <time.h>
#include <netinet/in.h>
#include <regex.h>
#include <sys/types.h>
#include <openssl/rand.h>

#include "bscconfig.h"

#include <openbsc/auth.h>
#include <openbsc/db.h>
#include <openbsc/debug.h>
#include <openbsc/gsm_data.h>
#include <openbsc/gsm_subscriber.h>
#include <openbsc/gsm_04_11.h>
#include <openbsc/gsm_04_08.h>
#include <openbsc/gsm_04_80.h>
#include <openbsc/abis_rsl.h>
#include <openbsc/chan_alloc.h>
#include <openbsc/paging.h>
#include <openbsc/signal.h>
#include <osmocom/abis/trau_frame.h>
#include <openbsc/trau_mux.h>
#include <openbsc/rtp_proxy.h>
#include <openbsc/transaction.h>
#include <openbsc/ussd.h>
#include <openbsc/silent_call.h>
#include <openbsc/bsc_api.h>
#include <openbsc/osmo_msc.h>
#include <openbsc/handover.h>
#include <openbsc/mncc_int.h>
#include <osmocom/abis/e1_input.h>
#include <osmocom/core/bitvec.h>
#include <openbsc/vlr.h>
#include <openbsc/msc_ifaces.h>

#include <osmocom/gsm/gsm48.h>
#include <osmocom/gsm/gsm0480.h>
#include <osmocom/gsm/gsm_utils.h>
#include <osmocom/gsm/protocol/gsm_04_08.h>
#include <osmocom/core/msgb.h>
#include <osmocom/core/talloc.h>
#include <osmocom/core/utils.h>
#include <osmocom/gsm/tlv.h>
#include <osmocom/crypt/auth.h>

#include <openbsc/msc_ifaces.h>
#include <openbsc/iu.h>
#include <openbsc/a_iface.h>

#include <assert.h>


/* These debug statements were removed during the BSC/MSC split. It may make
 * sense to replace them with debug statements that do not access BTS data. */
#define BEFORE_MSCSPLIT 0

void *tall_locop_ctx;
void *tall_authciphop_ctx;

#if BEFORE_MSCSPLIT
static int tch_rtp_signal(struct gsm_lchan *lchan, int signal);
#endif

static int gsm0408_loc_upd_acc(struct gsm_subscriber_connection *conn,
			       uint32_t send_tmsi);
static int gsm48_tx_simple(struct gsm_subscriber_connection *conn,
			   uint8_t pdisc, uint8_t msg_type);

struct gsm_lai {
	uint16_t mcc;
	uint16_t mnc;
	uint16_t lac;
};

static uint32_t new_callref = 0x80000001;

void cc_tx_to_mncc(struct gsm_network *net, struct msgb *msg)
{
	net->mncc_recv(net, msg);
}

static int gsm48_conn_sendmsg(struct msgb *msg, struct gsm_subscriber_connection *conn,
			      struct gsm_trans *trans)
{
	struct gsm48_hdr *gh = (struct gsm48_hdr *) msg->data;

	/* if we get passed a transaction reference, do some common
	 * work that the caller no longer has to do */
	if (trans) {
		gh->proto_discr = trans->protocol | (trans->transaction_id << 4);
	}

	return msc_tx_dtap(conn, msg);
}

int gsm48_cc_tx_notify_ss(struct gsm_trans *trans, const char *message)
{
	struct gsm48_hdr *gh;
	struct msgb *ss_notify;

	ss_notify = gsm0480_create_notifySS(message);
	if (!ss_notify)
		return -1;

	gsm0480_wrap_invoke(ss_notify, GSM0480_OP_CODE_NOTIFY_SS, 0);
	uint8_t *data = msgb_push(ss_notify, 1);
	data[0] = ss_notify->len - 1;
	gh = (struct gsm48_hdr *) msgb_push(ss_notify, sizeof(*gh));
	gh->msg_type = GSM48_MT_CC_FACILITY;
	return gsm48_conn_sendmsg(ss_notify, trans->conn, trans);
}

/* clear all transactions globally; used in case of MNCC socket disconnect */
void gsm0408_clear_all_trans(struct gsm_network *net, int protocol)
{
	struct gsm_trans *trans, *temp;

	LOGP(DCC, LOGL_NOTICE, "Clearing all currently active transactions!!!\n");

	llist_for_each_entry_safe(trans, temp, &net->trans_list, entry) {
		if (trans->protocol == protocol) {
			trans->callref = 0;
			trans_free(trans);
		}
	}
}

/* Chapter 9.2.14 : Send LOCATION UPDATING REJECT */
static int gsm0408_loc_upd_rej(struct gsm_subscriber_connection *conn, uint8_t cause)
{
	struct msgb *msg;

	msg = gsm48_create_loc_upd_rej(cause);
	if (!msg) {
		LOGP(DMM, LOGL_ERROR, "Failed to create msg for LOCATION UPDATING REJECT.\n");
		return -1;
	}

	LOGP(DMM, LOGL_INFO, "Subscriber %s: LOCATION UPDATING REJECT\n",
	     vlr_subscr_name(conn->vsub));

	return gsm48_conn_sendmsg(msg, conn, NULL);
}

/* Chapter 9.2.13 : Send LOCATION UPDATE ACCEPT */
static int gsm0408_loc_upd_acc(struct gsm_subscriber_connection *conn,
			       uint32_t send_tmsi)
{
	struct msgb *msg = gsm48_msgb_alloc_name("GSM 04.08 LOC UPD ACC");
	struct gsm48_hdr *gh;
	struct gsm48_loc_area_id *lai;
	uint8_t *mid;

	gh = (struct gsm48_hdr *) msgb_put(msg, sizeof(*gh));
	gh->proto_discr = GSM48_PDISC_MM;
	gh->msg_type = GSM48_MT_MM_LOC_UPD_ACCEPT;

	lai = (struct gsm48_loc_area_id *) msgb_put(msg, sizeof(*lai));
	gsm48_generate_lai(lai, conn->network->country_code,
			   conn->network->network_code,
			   conn->lac);

	if (send_tmsi == GSM_RESERVED_TMSI) {
		/* we did not allocate a TMSI to the MS, so we need to
		 * include the IMSI in order for the MS to delete any
		 * old TMSI that might still be allocated */
		uint8_t mi[10];
		int len;
		len = gsm48_generate_mid_from_imsi(mi, conn->vsub->imsi);
		mid = msgb_put(msg, len);
		memcpy(mid, mi, len);
		DEBUGP(DMM, "-> %s LOCATION UPDATE ACCEPT\n",
		       vlr_subscr_name(conn->vsub));
	} else {
		/* Include the TMSI, which means that the MS will send a
		 * TMSI REALLOCATION COMPLETE, and we should wait for
		 * that until T3250 expiration */
		mid = msgb_put(msg, GSM48_MID_TMSI_LEN);
		gsm48_generate_mid_from_tmsi(mid, send_tmsi);
		DEBUGP(DMM, "-> %s LOCATION UPDATE ACCEPT (TMSI = 0x%08x)\n",
		       vlr_subscr_name(conn->vsub),
		       send_tmsi);
	}
	/* TODO: Follow-on proceed */
	/* TODO: CTS permission */
	/* TODO: Equivalent PLMNs */
	/* TODO: Emergency Number List */
	/* TODO: Per-MS T3312 */


	return gsm48_conn_sendmsg(msg, conn, NULL);
}

/* Transmit Chapter 9.2.10 Identity Request */
static int mm_tx_identity_req(struct gsm_subscriber_connection *conn, uint8_t id_type)
{
	struct msgb *msg = gsm48_msgb_alloc_name("GSM 04.08 ID REQ");
	struct gsm48_hdr *gh;

	gh = (struct gsm48_hdr *) msgb_put(msg, sizeof(*gh) + 1);
	gh->proto_discr = GSM48_PDISC_MM;
	gh->msg_type = GSM48_MT_MM_ID_REQ;
	gh->data[0] = id_type;

	return gsm48_conn_sendmsg(msg, conn, NULL);
}

/* Parse Chapter 9.2.11 Identity Response */
static int mm_rx_id_resp(struct gsm_subscriber_connection *conn, struct msgb *msg)
{
	struct gsm48_hdr *gh = msgb_l3(msg);
	uint8_t mi_type = gh->data[1] & GSM_MI_TYPE_MASK;
	char mi_string[GSM48_MI_SIZE];

	if (!conn->vsub) {
		LOGP(DMM, LOGL_ERROR,
		     "Rx MM Identity Response: invalid: no subscriber\n");
		return -EINVAL;
	}

	gsm48_mi_to_string(mi_string, sizeof(mi_string), &gh->data[1], gh->data[0]);
	DEBUGP(DMM, "IDENTITY RESPONSE: MI(%s)=%s\n",
		gsm48_mi_type_name(mi_type), mi_string);

	osmo_signal_dispatch(SS_SUBSCR, S_SUBSCR_IDENTITY, gh->data);

	return vlr_subscr_rx_id_resp(conn->vsub, gh->data+1, gh->data[0]);
}

/* FIXME: to libosmogsm */
static const struct value_string lupd_names[] = {
	{ GSM48_LUPD_NORMAL, "NORMAL" },
	{ GSM48_LUPD_PERIODIC, "PERIODIC" },
	{ GSM48_LUPD_IMSI_ATT, "IMSI ATTACH" },
	{ 0, NULL }
};

/* Chapter 9.2.15: Receive Location Updating Request.
 * Keep this function non-static for direct invocation by unit tests. */
int mm_rx_loc_upd_req(struct gsm_subscriber_connection *conn, struct msgb *msg)
{
	static const enum subscr_conn_from conn_from_lu = SUBSCR_CONN_FROM_LU;
	struct gsm_network *net = conn->network;
	struct gsm48_hdr *gh = msgb_l3(msg);
	struct gsm48_loc_upd_req *lu;
	uint8_t mi_type;
	char mi_string[GSM48_MI_SIZE];
	enum vlr_lu_type vlr_lu_type = VLR_LU_TYPE_REGULAR;
	uint32_t tmsi;
	char *imsi;
	struct osmo_location_area_id old_lai, new_lai;
	struct osmo_fsm_inst *lu_fsm;
	bool is_utran;
	int rc;

 	lu = (struct gsm48_loc_upd_req *) gh->data;

	mi_type = lu->mi[0] & GSM_MI_TYPE_MASK;

	gsm48_mi_to_string(mi_string, sizeof(mi_string), lu->mi, lu->mi_len);

	rc = msc_create_conn_fsm(conn, mi_string);
	if (rc)
		/* logging already happened in msc_create_conn_fsm() */
		return rc;

	conn->classmark.classmark1 = lu->classmark1;
	conn->classmark.classmark1_set = true;

	DEBUGP(DMM, "LOCATION UPDATING REQUEST: MI(%s)=%s type=%s\n",
	       gsm48_mi_type_name(mi_type), mi_string,
	       get_value_string(lupd_names, lu->type));

	osmo_signal_dispatch(SS_SUBSCR, S_SUBSCR_IDENTITY, &lu->mi_len);

	switch (lu->type) {
	case GSM48_LUPD_NORMAL:
		rate_ctr_inc(&conn->network->msc_ctrs->ctr[MSC_CTR_LOC_UPDATE_TYPE_NORMAL]);
		vlr_lu_type = VLR_LU_TYPE_REGULAR;
		break;
	case GSM48_LUPD_IMSI_ATT:
		rate_ctr_inc(&conn->network->msc_ctrs->ctr[MSC_CTR_LOC_UPDATE_TYPE_ATTACH]);
		vlr_lu_type = VLR_LU_TYPE_IMSI_ATTACH;
		break;
	case GSM48_LUPD_PERIODIC:
		rate_ctr_inc(&conn->network->msc_ctrs->ctr[MSC_CTR_LOC_UPDATE_TYPE_PERIODIC]);
		vlr_lu_type = VLR_LU_TYPE_PERIODIC;
		break;
	}

	/* TODO: 10.5.1.6 MS Classmark for UMTS / Classmark 2 */
	/* TODO: 10.5.3.14 Aditional update parameters (CS fallback calls) */
	/* TODO: 10.5.7.8 Device properties */
	/* TODO: 10.5.1.15 MS network feature support */

	switch (mi_type) {
	case GSM_MI_TYPE_IMSI:
		tmsi = GSM_RESERVED_TMSI;
		imsi = mi_string;
		break;
	case GSM_MI_TYPE_TMSI:
		tmsi = tmsi_from_string(mi_string);
		imsi = NULL;
		break;
	default:
		DEBUGPC(DMM, "unknown mobile identity type\n");
		tmsi = GSM_RESERVED_TMSI;
		imsi = NULL;
		break;
	}

	gsm48_decode_lai(&lu->lai, &old_lai.plmn.mcc,
			 &old_lai.plmn.mnc, &old_lai.lac);
	new_lai.plmn.mcc = conn->network->country_code;
	new_lai.plmn.mnc = conn->network->network_code;
	new_lai.lac = conn->lac;
	DEBUGP(DMM, "LU/new-LAC: %u/%u\n", old_lai.lac, new_lai.lac);

	is_utran = (conn->via_ran == RAN_UTRAN_IU);
	lu_fsm = vlr_loc_update(conn->conn_fsm,
				SUBSCR_CONN_E_ACCEPTED,
				SUBSCR_CONN_E_CN_CLOSE,
				(void*)&conn_from_lu,
				net->vlr, conn, vlr_lu_type, tmsi, imsi,
				&old_lai, &new_lai,
				is_utran || conn->network->authentication_required,
				is_utran? VLR_CIPH_A5_3
					: conn->network->a5_encryption,
				classmark_is_r99(&conn->classmark),
				is_utran,
				net->vlr->cfg.assign_tmsi);
	if (!lu_fsm) {
		DEBUGP(DRR, "%s: Can't start LU FSM\n", mi_string);
		return 0;
	}

	/* From vlr_loc_update() we expect an implicit dispatch of
	 * VLR_ULA_E_UPDATE_LA, and thus we expect msc_vlr_subscr_assoc() to
	 * already have been called and completed. Has an error occured? */

	if (!conn->vsub || conn->vsub->lu_fsm != lu_fsm) {
		LOGP(DRR, LOGL_ERROR,
		     "%s: internal error during Location Updating attempt\n",
		     mi_string);
		return -EIO;
	}

	return 0;
}

/* Turn int into semi-octet representation: 98 => 0x89 */
/* FIXME: libosmocore/libosmogsm */
static uint8_t bcdify(uint8_t value)
{
        uint8_t ret;

        ret = value / 10;
        ret |= (value % 10) << 4;

        return ret;
}


/* Section 9.2.15a */
int gsm48_tx_mm_info(struct gsm_subscriber_connection *conn)
{
	struct msgb *msg = gsm48_msgb_alloc_name("GSM 04.08 MM INF");
	struct gsm48_hdr *gh;
	struct gsm_network *net = conn->network;
	uint8_t *ptr8;
	int name_len, name_pad;

	time_t cur_t;
	struct tm* gmt_time;
	struct tm* local_time;
	int tzunits;
	int dst = 0;

	gh = (struct gsm48_hdr *) msgb_put(msg, sizeof(*gh));
	gh->proto_discr = GSM48_PDISC_MM;
	gh->msg_type = GSM48_MT_MM_INFO;

	if (net->name_long) {
#if 0
		name_len = strlen(net->name_long);
		/* 10.5.3.5a */
		ptr8 = msgb_put(msg, 3);
		ptr8[0] = GSM48_IE_NAME_LONG;
		ptr8[1] = name_len*2 +1;
		ptr8[2] = 0x90; /* UCS2, no spare bits, no CI */

		ptr16 = (uint16_t *) msgb_put(msg, name_len*2);
		for (i = 0; i < name_len; i++)
			ptr16[i] = htons(net->name_long[i]);

		/* FIXME: Use Cell Broadcast, not UCS-2, since
		 * UCS-2 is only supported by later revisions of the spec */
#endif
		name_len = (strlen(net->name_long)*7)/8;
		name_pad = (8 - strlen(net->name_long)*7)%8;
		if (name_pad > 0)
			name_len++;
		/* 10.5.3.5a */
		ptr8 = msgb_put(msg, 3);
		ptr8[0] = GSM48_IE_NAME_LONG;
		ptr8[1] = name_len +1;
		ptr8[2] = 0x80 | name_pad; /* Cell Broadcast DCS, no CI */

		ptr8 = msgb_put(msg, name_len);
		gsm_7bit_encode_n(ptr8, name_len, net->name_long, NULL);

	}

	if (net->name_short) {
#if 0
		name_len = strlen(net->name_short);
		/* 10.5.3.5a */
		ptr8 = (uint8_t *) msgb_put(msg, 3);
		ptr8[0] = GSM48_IE_NAME_SHORT;
		ptr8[1] = name_len*2 + 1;
		ptr8[2] = 0x90; /* UCS2, no spare bits, no CI */

		ptr16 = (uint16_t *) msgb_put(msg, name_len*2);
		for (i = 0; i < name_len; i++)
			ptr16[i] = htons(net->name_short[i]);
#endif
		name_len = (strlen(net->name_short)*7)/8;
		name_pad = (8 - strlen(net->name_short)*7)%8;
		if (name_pad > 0)
			name_len++;
		/* 10.5.3.5a */
		ptr8 = (uint8_t *) msgb_put(msg, 3);
		ptr8[0] = GSM48_IE_NAME_SHORT;
		ptr8[1] = name_len +1;
		ptr8[2] = 0x80 | name_pad; /* Cell Broadcast DCS, no CI */

		ptr8 = msgb_put(msg, name_len);
		gsm_7bit_encode_n(ptr8, name_len, net->name_short, NULL);

	}

	/* Section 10.5.3.9 */
	cur_t = time(NULL);
	gmt_time = gmtime(&cur_t);

	ptr8 = msgb_put(msg, 8);
	ptr8[0] = GSM48_IE_NET_TIME_TZ;
	ptr8[1] = bcdify(gmt_time->tm_year % 100);
	ptr8[2] = bcdify(gmt_time->tm_mon + 1);
	ptr8[3] = bcdify(gmt_time->tm_mday);
	ptr8[4] = bcdify(gmt_time->tm_hour);
	ptr8[5] = bcdify(gmt_time->tm_min);
	ptr8[6] = bcdify(gmt_time->tm_sec);

	if (net->tz.override) {
		/* Convert tz.hr and tz.mn to units */
		if (net->tz.hr < 0) {
			tzunits = ((net->tz.hr/-1)*4);
			tzunits = tzunits + (net->tz.mn/15);
			ptr8[7] = bcdify(tzunits);
			/* Set negative time */
			ptr8[7] |= 0x08;
		}
		else {
			tzunits = net->tz.hr*4;
			tzunits = tzunits + (net->tz.mn/15);
			ptr8[7] = bcdify(tzunits);
		}
		/* Convert DST value */
		if (net->tz.dst >= 0 && net->tz.dst <= 2)
			dst = net->tz.dst;
	}
	else {
		/* Need to get GSM offset and convert into 15 min units */
		/* This probably breaks if gmtoff returns a value not evenly divisible by 15? */
		local_time = localtime(&cur_t);
#ifdef HAVE_TM_GMTOFF_IN_TM
		tzunits = (local_time->tm_gmtoff/60)/15;
#else
#warning find a portable way to obtain the timezone offset
		tzunits = 0;
#endif
		if (tzunits < 0) {
			tzunits = tzunits/-1;
			ptr8[7] = bcdify(tzunits);
			/* Flip it to negative */
			ptr8[7] |= 0x08;
		}
		else
			ptr8[7] = bcdify(tzunits);

		/* Does not support DST +2 */
		if (local_time->tm_isdst)
			dst = 1;
	}

	if (dst) {
		ptr8 = msgb_put(msg, 3);
		ptr8[0] = GSM48_IE_NET_DST;
		ptr8[1] = 1;
		ptr8[2] = dst;
	}

	DEBUGP(DMM, "-> MM INFO\n");

	return gsm48_conn_sendmsg(msg, conn, NULL);
}

/*! Send an Authentication Request to MS on the given subscriber connection
 * according to 3GPP/ETSI TS 24.008, Section 9.2.2.
 * \param[in] conn  Subscriber connection to send on.
 * \param[in] rand  Random challenge token to send, must be 16 bytes long.
 * \param[in] autn  r99: In case of UMTS mutual authentication, AUTN token to
 * 	send; must be 16 bytes long, or pass NULL for plain GSM auth.
 * \param[in] key_seq  auth tuple's sequence number.
 */
int gsm48_tx_mm_auth_req(struct gsm_subscriber_connection *conn, uint8_t *rand,
			 uint8_t *autn, int key_seq)
{
	struct msgb *msg = gsm48_msgb_alloc_name("GSM 04.08 AUTH REQ");
	struct gsm48_hdr *gh = (struct gsm48_hdr *) msgb_put(msg, sizeof(*gh));
	struct gsm48_auth_req *ar = (struct gsm48_auth_req *) msgb_put(msg, sizeof(*ar));

	DEBUGP(DMM, "-> AUTH REQ (rand = %s)\n", osmo_hexdump_nospc(rand, 16));
	if (autn)
		DEBUGP(DMM, "   AUTH REQ (autn = %s)\n", osmo_hexdump_nospc(autn, 16));

	gh->proto_discr = GSM48_PDISC_MM;
	gh->msg_type = GSM48_MT_MM_AUTH_REQ;

	ar->key_seq = key_seq;

	/* 16 bytes RAND parameters */
	osmo_static_assert(sizeof(ar->rand) == 16, sizeof_auth_req_r99_rand);
	if (rand)
		memcpy(ar->rand, rand, 16);


	/* 16 bytes AUTN */
	if (autn)
		msgb_tlv_put(msg, GSM48_IE_AUTN, 16, autn);

	return gsm48_conn_sendmsg(msg, conn, NULL);
}

/* Section 9.2.1 */
int gsm48_tx_mm_auth_rej(struct gsm_subscriber_connection *conn)
{
	DEBUGP(DMM, "-> AUTH REJECT\n");
	return gsm48_tx_simple(conn, GSM48_PDISC_MM, GSM48_MT_MM_AUTH_REJ);
}

#define CONN_REUSE 1
#if CONN_REUSE
static int msc_vlr_tx_cm_serv_acc(void *msc_conn_ref);
static int msc_vlr_tx_cm_serv_rej(void *msc_conn_ref, enum vlr_proc_arq_result result);

int cm_serv_conn_reuse(struct gsm_subscriber_connection *conn,
		       const uint8_t *mi_lv)
{
	uint8_t mi_type;
	char mi_string[GSM48_MI_SIZE];
	uint32_t tmsi;

	gsm48_mi_to_string(mi_string, sizeof(mi_string), mi_lv+1, mi_lv[0]);
	mi_type = mi_lv[1] & GSM_MI_TYPE_MASK;

	switch (mi_type) {
	case GSM_MI_TYPE_IMSI:
		if (vlr_subscr_matches_imsi(conn->vsub, mi_string))
			goto accept_reuse;
		break;
	case GSM_MI_TYPE_TMSI:
		tmsi = osmo_load32be(mi_lv+2);
		if (vlr_subscr_matches_tmsi(conn->vsub, tmsi))
			goto accept_reuse;
		break;
	case GSM_MI_TYPE_IMEI:
		if (vlr_subscr_matches_imei(conn->vsub, mi_string))
			goto accept_reuse;
		break;
	default:
		break;
	}

	LOGP(DMM, LOGL_ERROR, "%s: CM Service Request with mismatching"
	     " mobile identity: %s %s\n",
	     vlr_subscr_name(conn->vsub), gsm48_mi_type_name(mi_type),
	     mi_string);
	msc_vlr_tx_cm_serv_rej(conn, VLR_PR_ARQ_RES_ILLEGAL_SUBSCR);
	return -EINVAL;

accept_reuse:
	DEBUGP(DMM, "%s: re-using already accepted connection\n",
	       vlr_subscr_name(conn->vsub));
	conn->received_cm_service_request = true;
	return conn->network->vlr->ops.tx_cm_serv_acc(conn);
}
#endif

/*
 * Handle CM Service Requests
 * a) Verify that the packet is long enough to contain the information
 *    we require otherwsie reject with INCORRECT_MESSAGE
 * b) Try to parse the TMSI. If we do not have one reject
 * c) Check that we know the subscriber with the TMSI otherwise reject
 *    with a HLR cause
 * d) Set the subscriber on the conn and accept
 *
 * Keep this function non-static for direct invocation by unit tests.
 */
int gsm48_rx_mm_serv_req(struct gsm_subscriber_connection *conn, struct msgb *msg)
{
	static const enum subscr_conn_from conn_from_cm_service_req =
		SUBSCR_CONN_FROM_CM_SERVICE_REQ;
	struct gsm_network *net = conn->network;
	uint8_t mi_type;
	char mi_string[GSM48_MI_SIZE];

	struct gsm48_hdr *gh = msgb_l3(msg);
	struct gsm48_service_request *req =
			(struct gsm48_service_request *)gh->data;
	/* unfortunately in Phase1 the classmark2 length is variable */
	uint8_t classmark2_len = gh->data[1];
	uint8_t *classmark2 = gh->data+2;
	uint8_t mi_len = *(classmark2 + classmark2_len);
	uint8_t *mi = (classmark2 + classmark2_len + 1);
	struct osmo_location_area_id lai;
	bool is_utran;
	int rc;

	lai.plmn.mcc = conn->network->country_code;
	lai.plmn.mnc = conn->network->network_code;
	lai.lac = conn->lac;

	DEBUGP(DMM, "<- CM SERVICE REQUEST ");
	if (msg->data_len < sizeof(struct gsm48_service_request*)) {
		DEBUGPC(DMM, "wrong sized message\n");
		return msc_gsm48_tx_mm_serv_rej(conn,
						GSM48_REJECT_INCORRECT_MESSAGE);
	}

	if (msg->data_len < req->mi_len + 6) {
		DEBUGPC(DMM, "does not fit in packet\n");
		return msc_gsm48_tx_mm_serv_rej(conn,
						GSM48_REJECT_INCORRECT_MESSAGE);
	}

	gsm48_mi_to_string(mi_string, sizeof(mi_string), mi, mi_len);
	mi_type = mi[0] & GSM_MI_TYPE_MASK;

	if (mi_type == GSM_MI_TYPE_IMSI) {
		DEBUGPC(DMM, "serv_type=0x%02x MI(%s)=%s\n",
			req->cm_service_type, gsm48_mi_type_name(mi_type),
			mi_string);
	} else if (mi_type == GSM_MI_TYPE_TMSI) {
		DEBUGPC(DMM, "serv_type=0x%02x MI(%s)=%s\n",
			req->cm_service_type, gsm48_mi_type_name(mi_type),
			mi_string);
	} else {
		DEBUGPC(DMM, "mi_type is not expected: %d\n", mi_type);
		return msc_gsm48_tx_mm_serv_rej(conn,
						GSM48_REJECT_INCORRECT_MESSAGE);
	}

	osmo_signal_dispatch(SS_SUBSCR, S_SUBSCR_IDENTITY, (classmark2 + classmark2_len));
	memcpy(conn->classmark.classmark2, classmark2, classmark2_len);
	conn->classmark.classmark2_len = classmark2_len;

#if CONN_REUSE
	if (conn->conn_fsm) {
		if (msc_subscr_conn_is_accepted(conn))
			return cm_serv_conn_reuse(conn, mi-1);
		LOGP(DMM, LOGL_ERROR, "%s: connection already in use\n",
		     vlr_subscr_name(conn->vsub));
		msc_vlr_tx_cm_serv_rej(conn, VLR_PR_ARQ_RES_UNKNOWN_ERROR);
		return -EINVAL;
	}
#endif

	rc = msc_create_conn_fsm(conn, mi_string);
	if (rc) {
		msc_vlr_tx_cm_serv_rej(conn, VLR_PR_ARQ_RES_UNKNOWN_ERROR);
		/* logging already happened in msc_create_conn_fsm() */
		return rc;
	}

#if BEFORE_MSCSPLIT
	/* see mail on openbsc@ 9 Feb 2016 22:30:15 +0100
	 * We need to hook sending of MRPCI to Siemens BS11 somewhere else */
	if (is_siemens_bts(conn->bts))
		send_siemens_mrpci(msg->lchan, classmark2-1);
#endif

	is_utran = (conn->via_ran == RAN_UTRAN_IU);
	vlr_proc_acc_req(conn->conn_fsm,
			 SUBSCR_CONN_E_ACCEPTED,
			 SUBSCR_CONN_E_CN_CLOSE,
			 (void*)&conn_from_cm_service_req,
			 net->vlr, conn,
			 VLR_PR_ARQ_T_CM_SERV_REQ, mi-1, &lai,
			 is_utran || conn->network->authentication_required,
			 is_utran? VLR_CIPH_A5_3
				 : conn->network->a5_encryption,
			 classmark_is_r99(&conn->classmark),
			 is_utran);

	return 0;
}

static int gsm48_rx_mm_imsi_detach_ind(struct gsm_subscriber_connection *conn, struct msgb *msg)
{
	struct gsm_network *network = conn->network;
	struct gsm48_hdr *gh = msgb_l3(msg);
	struct gsm48_imsi_detach_ind *idi =
				(struct gsm48_imsi_detach_ind *) gh->data;
	uint8_t mi_type = idi->mi[0] & GSM_MI_TYPE_MASK;
	char mi_string[GSM48_MI_SIZE];
	struct vlr_subscr *vsub = NULL;

	gsm48_mi_to_string(mi_string, sizeof(mi_string), idi->mi, idi->mi_len);
	DEBUGP(DMM, "IMSI DETACH INDICATION: MI(%s)=%s",
		gsm48_mi_type_name(mi_type), mi_string);

	rate_ctr_inc(&network->msc_ctrs->ctr[MSC_CTR_LOC_UPDATE_TYPE_DETACH]);

	switch (mi_type) {
	case GSM_MI_TYPE_TMSI:
		DEBUGPC(DMM, "\n");
		vsub = vlr_subscr_find_by_tmsi(network->vlr,
					       tmsi_from_string(mi_string));
		break;
	case GSM_MI_TYPE_IMSI:
		DEBUGPC(DMM, "\n");
		vsub = vlr_subscr_find_by_imsi(network->vlr, mi_string);
		break;
	case GSM_MI_TYPE_IMEI:
	case GSM_MI_TYPE_IMEISV:
		/* no sim card... FIXME: what to do ? */
		DEBUGPC(DMM, ": unimplemented mobile identity type\n");
		break;
	default:
		DEBUGPC(DMM, ": unknown mobile identity type\n");
		break;
	}

	/* TODO? We used to remember the subscriber's classmark1 here and
	 * stored it in the old sqlite db, but now we store it in a conn that
	 * will be discarded anyway: */
	conn->classmark.classmark1 = idi->classmark1;

	if (!vsub) {
		DEBUGP(DMM, "Unknown Subscriber ?!?\n");
		return 0;
	}

	LOGP(DMM, LOGL_INFO, "Subscriber %s DETACHED\n",
	     vlr_subscr_name(vsub));
	vlr_subscr_rx_imsi_detach(vsub);
	osmo_signal_dispatch(SS_SUBSCR, S_SUBSCR_DETACHED, vsub);
	vlr_subscr_put(vsub);

	msc_subscr_conn_close(conn, 0);
	return 0;
}

static int gsm48_rx_mm_status(struct msgb *msg)
{
	struct gsm48_hdr *gh = msgb_l3(msg);

	DEBUGP(DMM, "MM STATUS (reject cause 0x%02x)\n", gh->data[0]);

	return 0;
}

static int parse_gsm_auth_resp(uint8_t *res, uint8_t *res_len,
			       struct gsm_subscriber_connection *conn,
			       struct msgb *msg)
{
	struct gsm48_hdr *gh = msgb_l3(msg);
	struct gsm48_auth_resp *ar = (struct gsm48_auth_resp*) gh->data;

	if (msgb_l3len(msg) < sizeof(*gh) + sizeof(*ar)) {
		LOGP(DMM, LOGL_ERROR,
		     "%s: MM AUTHENTICATION RESPONSE:"
		     " l3 length invalid: %u\n",
		     vlr_subscr_name(conn->vsub), msgb_l3len(msg));
		return -EINVAL;
	}

	*res_len = sizeof(ar->sres);
	memcpy(res, ar->sres, sizeof(ar->sres));
	return 0;
}

static int parse_umts_auth_resp(uint8_t *res, uint8_t *res_len,
				struct gsm_subscriber_connection *conn,
				struct msgb *msg)
{
	struct gsm48_hdr *gh;
	uint8_t *data;
	uint8_t iei;
	uint8_t ie_len;
	unsigned int data_len;

	/* First parse the GSM part */
	if (parse_gsm_auth_resp(res, res_len, conn, msg))
		return -EINVAL;
	OSMO_ASSERT(*res_len == 4);

	/* Then add the extended res part */
	gh = msgb_l3(msg);
	data = gh->data + sizeof(struct gsm48_auth_resp);
	data_len = msgb_l3len(msg) - (data - (uint8_t*)msgb_l3(msg));

	if (data_len < 3) {
		LOGP(DMM, LOGL_ERROR,
		     "%s: MM AUTHENTICATION RESPONSE:"
		     " l3 length invalid: %u\n",
		     vlr_subscr_name(conn->vsub), msgb_l3len(msg));
		return -EINVAL;
	}

	iei = data[0];
	ie_len = data[1];
	if (iei != GSM48_IE_AUTH_RES_EXT) {
		LOGP(DMM, LOGL_ERROR,
		     "%s: MM R99 AUTHENTICATION RESPONSE:"
		     " expected IEI 0x%02x, got 0x%02x\n",
		     vlr_subscr_name(conn->vsub),
		     GSM48_IE_AUTH_RES_EXT, iei);
		return -EINVAL;
	}

	if (ie_len > 12) {
		LOGP(DMM, LOGL_ERROR,
		     "%s: MM R99 AUTHENTICATION RESPONSE:"
		     " extended Auth Resp IE 0x%02x is too large: %u bytes\n",
		     vlr_subscr_name(conn->vsub), GSM48_IE_AUTH_RES_EXT, ie_len);
		return -EINVAL;
	}

	*res_len += ie_len;
	memcpy(res + 4, &data[2], ie_len);
	return 0;
}

/* Chapter 9.2.3: Authentication Response */
static int gsm48_rx_mm_auth_resp(struct gsm_subscriber_connection *conn, struct msgb *msg)
{
	uint8_t res[16];
	uint8_t res_len;
	int rc;
	bool is_r99;

	if (!conn->vsub) {
		LOGP(DMM, LOGL_ERROR,
		     "MM AUTHENTICATION RESPONSE: invalid: no subscriber\n");
		msc_subscr_conn_close(conn, GSM_CAUSE_AUTH_FAILED);
		return -EINVAL;
	}

	if (msgb_l3len(msg) >
	    sizeof(struct gsm48_hdr) + sizeof(struct gsm48_auth_resp)) {
		rc = parse_umts_auth_resp(res, &res_len, conn, msg);
		is_r99 = true;
	} else {
		rc = parse_gsm_auth_resp(res, &res_len, conn, msg);
		is_r99 = false;
	}

	if (rc) {
		msc_subscr_conn_close(conn, GSM_CAUSE_AUTH_FAILED);
		return -EINVAL;
	}

	DEBUGP(DMM, "%s: MM %s AUTHENTICATION RESPONSE (%s = %s)\n",
	       vlr_subscr_name(conn->vsub),
	       is_r99 ? "R99" : "GSM", is_r99 ? "res" : "sres",
	       osmo_hexdump_nospc(res, res_len));

	return vlr_subscr_rx_auth_resp(conn->vsub, is_r99,
				       conn->via_ran == RAN_UTRAN_IU,
				       res, res_len);
}

static int gsm48_rx_mm_auth_fail(struct gsm_subscriber_connection *conn, struct msgb *msg)
{
	struct gsm48_hdr *gh = msgb_l3(msg);
	uint8_t cause;
	uint8_t auts_tag;
	uint8_t auts_len;
	uint8_t *auts;

	if (!conn->vsub) {
		LOGP(DMM, LOGL_ERROR,
		     "MM R99 AUTHENTICATION FAILURE: invalid: no subscriber\n");
		msc_subscr_conn_close(conn, GSM_CAUSE_AUTH_FAILED);
		return -EINVAL;
	}

	if (msgb_l3len(msg) < sizeof(*gh) + 1) {
		LOGP(DMM, LOGL_ERROR,
		     "%s: MM R99 AUTHENTICATION FAILURE:"
		     " l3 length invalid: %u\n",
		     vlr_subscr_name(conn->vsub), msgb_l3len(msg));
		msc_subscr_conn_close(conn, GSM_CAUSE_AUTH_FAILED);
		return -EINVAL;
	}

	cause = gh->data[0];

	if (cause != GSM48_REJECT_SYNCH_FAILURE) {
		LOGP(DMM, LOGL_INFO,
		     "%s: MM R99 AUTHENTICATION FAILURE: cause 0x%0x\n",
		     vlr_subscr_name(conn->vsub), cause);
		vlr_subscr_rx_auth_fail(conn->vsub, NULL);
		return 0;
	}

	/* This is a Synch Failure procedure, which should pass an AUTS to
	 * resynchronize the sequence nr with the HLR. Expecting exactly one
	 * TLV with 14 bytes of AUTS. */

	if (msgb_l3len(msg) < sizeof(*gh) + 1 + 2) {
		LOGP(DMM, LOGL_INFO,
		     "%s: MM R99 AUTHENTICATION FAILURE:"
		     " invalid Synch Failure: missing AUTS IE\n",
		     vlr_subscr_name(conn->vsub));
		msc_subscr_conn_close(conn, GSM_CAUSE_AUTH_FAILED);
		return -EINVAL;
	}

	auts_tag = gh->data[1];
	auts_len = gh->data[2];
	auts = &gh->data[3];

	if (auts_tag != GSM48_IE_AUTS
	    || auts_len != 14) {
		LOGP(DMM, LOGL_INFO,
		     "%s: MM R99 AUTHENTICATION FAILURE:"
		     " invalid Synch Failure:"
		     " expected AUTS IE 0x%02x of 14 bytes,"
		     " got IE 0x%02x of %u bytes\n",
		     vlr_subscr_name(conn->vsub),
		     GSM48_IE_AUTS, auts_tag, auts_len);
		msc_subscr_conn_close(conn, GSM_CAUSE_AUTH_FAILED);
		return -EINVAL;
	}

	if (msgb_l3len(msg) < sizeof(*gh) + 1 + 2 + auts_len) {
		LOGP(DMM, LOGL_INFO,
		     "%s: MM R99 AUTHENTICATION FAILURE:"
		     " invalid Synch Failure msg: message truncated (%u)\n",
		     vlr_subscr_name(conn->vsub), msgb_l3len(msg));
		msc_subscr_conn_close(conn, GSM_CAUSE_AUTH_FAILED);
		return -EINVAL;
	}

	/* We have an AUTS IE with exactly 14 bytes of AUTS and the msgb is
	 * large enough. */

	DEBUGP(DMM, "%s: MM R99 AUTHENTICATION SYNCH (AUTS = %s)\n",
	       vlr_subscr_name(conn->vsub), osmo_hexdump_nospc(auts, 14));

	return vlr_subscr_rx_auth_fail(conn->vsub, auts);
}

static int gsm48_rx_mm_tmsi_reall_compl(struct gsm_subscriber_connection *conn)
{
	DEBUGP(DMM, "TMSI Reallocation Completed. Subscriber: %s\n",
	       vlr_subscr_name(conn->vsub));
	if (!conn->vsub) {
		LOGP(DMM, LOGL_ERROR,
		     "Rx MM TMSI Reallocation Complete: invalid: no subscriber\n");
		return -EINVAL;
	}
	return vlr_subscr_rx_tmsi_reall_compl(conn->vsub);
}

/* Receive a GSM 04.08 Mobility Management (MM) message */
static int gsm0408_rcv_mm(struct gsm_subscriber_connection *conn, struct msgb *msg)
{
	struct gsm48_hdr *gh = msgb_l3(msg);
	int rc = 0;

	switch (gsm48_hdr_msg_type(gh)) {
	case GSM48_MT_MM_LOC_UPD_REQUEST:
		rc = mm_rx_loc_upd_req(conn, msg);
		break;
	case GSM48_MT_MM_ID_RESP:
		rc = mm_rx_id_resp(conn, msg);
		break;
	case GSM48_MT_MM_CM_SERV_REQ:
		rc = gsm48_rx_mm_serv_req(conn, msg);
		break;
	case GSM48_MT_MM_STATUS:
		rc = gsm48_rx_mm_status(msg);
		break;
	case GSM48_MT_MM_TMSI_REALL_COMPL:
		rc = gsm48_rx_mm_tmsi_reall_compl(conn);
		break;
	case GSM48_MT_MM_IMSI_DETACH_IND:
		rc = gsm48_rx_mm_imsi_detach_ind(conn, msg);
		break;
	case GSM48_MT_MM_CM_REEST_REQ:
		DEBUGP(DMM, "CM REESTABLISH REQUEST: Not implemented\n");
		break;
	case GSM48_MT_MM_AUTH_RESP:
		rc = gsm48_rx_mm_auth_resp(conn, msg);
		break;
	case GSM48_MT_MM_AUTH_FAIL:
		rc = gsm48_rx_mm_auth_fail(conn, msg);
		break;
	default:
		LOGP(DMM, LOGL_NOTICE, "Unknown GSM 04.08 MM msg type 0x%02x\n",
			gh->msg_type);
		break;
	}

	return rc;
}

static uint8_t *gsm48_cm2_get_mi(uint8_t *classmark2_lv, unsigned int tot_len)
{
	/* Check the size for the classmark */
	if (tot_len < 1 + *classmark2_lv)
		return NULL;

	uint8_t *mi_lv = classmark2_lv + *classmark2_lv + 1;
	if (tot_len < 2 + *classmark2_lv + mi_lv[0])
		return NULL;

	return mi_lv;
}

/* Receive a PAGING RESPONSE message from the MS */
static int gsm48_rx_rr_pag_resp(struct gsm_subscriber_connection *conn, struct msgb *msg)
{
	static const enum subscr_conn_from conn_from_paging_resp =
		SUBSCR_CONN_FROM_PAGING_RESP;
	struct gsm_network *net = conn->network;
	struct gsm48_hdr *gh = msgb_l3(msg);
	struct gsm48_pag_resp *resp;
	uint8_t *classmark2_lv = gh->data + 1;
	uint8_t *mi_lv;
	uint8_t mi_type;
	char mi_string[GSM48_MI_SIZE];
	int rc = 0;
	struct osmo_location_area_id lai;
	bool is_utran;

	lai.plmn.mcc = conn->network->country_code;
	lai.plmn.mnc = conn->network->network_code;
	lai.lac = 23; /* FIXME bts->location_area_code; */

	resp = (struct gsm48_pag_resp *) &gh->data[0];
	gsm48_paging_extract_mi(resp, msgb_l3len(msg) - sizeof(*gh),
				mi_string, &mi_type);
	DEBUGP(DRR, "PAGING RESPONSE: MI(%s)=%s\n",
		gsm48_mi_type_name(mi_type), mi_string);

	mi_lv = gsm48_cm2_get_mi(classmark2_lv, msgb_l3len(msg) - sizeof(*gh));
	if (!mi_lv) {
		/* FIXME */
		return -1;
	}

	rc = msc_create_conn_fsm(conn, mi_string);
	if (rc)
		/* logging already happened in msc_create_conn_fsm() */
		return rc;

	memcpy(conn->classmark.classmark2, classmark2_lv+1, *classmark2_lv);
	conn->classmark.classmark2_len = *classmark2_lv;

	is_utran = (conn->via_ran == RAN_UTRAN_IU);
	vlr_proc_acc_req(conn->conn_fsm,
			 SUBSCR_CONN_E_ACCEPTED,
			 SUBSCR_CONN_E_CN_CLOSE,
			 (void*)&conn_from_paging_resp,
			 net->vlr, conn,
			 VLR_PR_ARQ_T_PAGING_RESP, mi_lv, &lai,
			 is_utran || conn->network->authentication_required,
			 is_utran? VLR_CIPH_A5_3
				 : conn->network->a5_encryption,
			 classmark_is_r99(&conn->classmark),
			 is_utran);

	return 0;
}

static int gsm48_rx_rr_app_info(struct gsm_subscriber_connection *conn, struct msgb *msg)
{
	struct gsm48_hdr *gh = msgb_l3(msg);
	uint8_t apdu_id_flags;
	uint8_t apdu_len;
	uint8_t *apdu_data;

	apdu_id_flags = gh->data[0];
	apdu_len = gh->data[1];
	apdu_data = gh->data+2;

	DEBUGP(DRR, "RX APPLICATION INFO id/flags=0x%02x apdu_len=%u apdu=%s\n",
		apdu_id_flags, apdu_len, osmo_hexdump(apdu_data, apdu_len));

	/* we're not using the app info blob anywhere, so ignore. */
#if 0
	return db_apdu_blob_store(conn->subscr, apdu_id_flags, apdu_len, apdu_data);
#else
	return 0;
#endif
}

/* Receive a GSM 04.08 Radio Resource (RR) message */
static int gsm0408_rcv_rr(struct gsm_subscriber_connection *conn, struct msgb *msg)
{
	struct gsm48_hdr *gh = msgb_l3(msg);
	int rc = 0;

	switch (gh->msg_type) {
	case GSM48_MT_RR_PAG_RESP:
		rc = gsm48_rx_rr_pag_resp(conn, msg);
		break;
	case GSM48_MT_RR_APP_INFO:
		rc = gsm48_rx_rr_app_info(conn, msg);
		break;
	default:
		LOGP(DRR, LOGL_NOTICE, "MSC: Unimplemented %s GSM 04.08 RR "
		     "message\n", gsm48_rr_msg_name(gh->msg_type));
		break;
	}

	return rc;
}

int gsm48_send_rr_app_info(struct gsm_subscriber_connection *conn, uint8_t apdu_id,
			   uint8_t apdu_len, const uint8_t *apdu)
{
	struct msgb *msg = gsm48_msgb_alloc_name("GSM 04.08 APP INF");
	struct gsm48_hdr *gh;

	DEBUGP(DRR, "TX APPLICATION INFO id=0x%02x, len=%u\n",
		apdu_id, apdu_len);

	gh = (struct gsm48_hdr *) msgb_put(msg, sizeof(*gh) + 2 + apdu_len);
	gh->proto_discr = GSM48_PDISC_RR;
	gh->msg_type = GSM48_MT_RR_APP_INFO;
	gh->data[0] = apdu_id;
	gh->data[1] = apdu_len;
	memcpy(gh->data+2, apdu, apdu_len);

	return gsm48_conn_sendmsg(msg, conn, NULL);
}

/* FIXME: this count_statistics is a state machine behaviour. we should convert
 * the complete call control into a state machine. Afterwards we can move this
 * code into state transitions.
 */
static void count_statistics(struct gsm_trans *trans, int new_state)
{
	int old_state = trans->cc.state;
	struct rate_ctr_group *msc = trans->net->msc_ctrs;

	if (old_state == new_state)
		return;

	/* state incoming */
	switch (new_state) {
	case GSM_CSTATE_ACTIVE:
		osmo_counter_inc(trans->net->active_calls);
		rate_ctr_inc(&msc->ctr[MSC_CTR_CALL_ACTIVE]);
		break;
	}

	/* state outgoing */
	switch (old_state) {
	case GSM_CSTATE_ACTIVE:
		osmo_counter_dec(trans->net->active_calls);
		if (new_state == GSM_CSTATE_DISCONNECT_REQ ||
				new_state == GSM_CSTATE_DISCONNECT_IND)
			rate_ctr_inc(&msc->ctr[MSC_CTR_CALL_COMPLETE]);
		else
			rate_ctr_inc(&msc->ctr[MSC_CTR_CALL_INCOMPLETE]);
		break;
	}
}

/* Call Control */

/* The entire call control code is written in accordance with Figure 7.10c
 * for 'very early assignment', i.e. we allocate a TCH/F during IMMEDIATE
 * ASSIGN, then first use that TCH/F for signalling and later MODE MODIFY
 * it for voice */

static void new_cc_state(struct gsm_trans *trans, int state)
{
	if (state > 31 || state < 0)
		return;

	DEBUGP(DCC, "new state %s -> %s\n",
		gsm48_cc_state_name(trans->cc.state),
		gsm48_cc_state_name(state));

	count_statistics(trans, state);
	trans->cc.state = state;
}

static int gsm48_cc_tx_status(struct gsm_trans *trans, void *arg)
{
	struct msgb *msg = gsm48_msgb_alloc_name("GSM 04.08 CC STATUS");
	struct gsm48_hdr *gh = (struct gsm48_hdr *) msgb_put(msg, sizeof(*gh));
	uint8_t *cause, *call_state;

	gh->msg_type = GSM48_MT_CC_STATUS;

	cause = msgb_put(msg, 3);
	cause[0] = 2;
	cause[1] = GSM48_CAUSE_CS_GSM | GSM48_CAUSE_LOC_USER;
	cause[2] = 0x80 | 30;	/* response to status inquiry */

	call_state = msgb_put(msg, 1);
	call_state[0] = 0xc0 | 0x00;

	return gsm48_conn_sendmsg(msg, trans->conn, trans);
}

static int gsm48_tx_simple(struct gsm_subscriber_connection *conn,
			   uint8_t pdisc, uint8_t msg_type)
{
	struct msgb *msg = gsm48_msgb_alloc_name("GSM 04.08 TX SIMPLE");
	struct gsm48_hdr *gh = (struct gsm48_hdr *) msgb_put(msg, sizeof(*gh));

	gh->proto_discr = pdisc;
	gh->msg_type = msg_type;

	return gsm48_conn_sendmsg(msg, conn, NULL);
}

static void gsm48_stop_cc_timer(struct gsm_trans *trans)
{
	if (osmo_timer_pending(&trans->cc.timer)) {
		DEBUGP(DCC, "stopping pending timer T%x\n", trans->cc.Tcurrent);
		osmo_timer_del(&trans->cc.timer);
		trans->cc.Tcurrent = 0;
	}
}

static int mncc_recvmsg(struct gsm_network *net, struct gsm_trans *trans,
			int msg_type, struct gsm_mncc *mncc)
{
	struct msgb *msg;
	unsigned char *data;

#if BEFORE_MSCSPLIT
	if (trans)
		if (trans->conn && trans->conn->lchan)
			DEBUGP(DCC, "(bts %d trx %d ts %d ti %x sub %s) "
				"Sending '%s' to MNCC.\n",
				trans->conn->lchan->ts->trx->bts->nr,
				trans->conn->lchan->ts->trx->nr,
				trans->conn->lchan->ts->nr, trans->transaction_id,
				vlr_subscr_msisdn_or_name(trans->vsub),
				get_mncc_name(msg_type));
		else
			DEBUGP(DCC, "(bts - trx - ts - ti -- sub %s) "
				"Sending '%s' to MNCC.\n",
				vlr_subscr_msisdn_or_name(trans->vsub),
				get_mncc_name(msg_type));
	else
		DEBUGP(DCC, "(bts - trx - ts - ti -- sub -) "
			"Sending '%s' to MNCC.\n", get_mncc_name(msg_type));
#endif

	mncc->msg_type = msg_type;

	msg = msgb_alloc(sizeof(struct gsm_mncc), "MNCC");
	if (!msg)
		return -ENOMEM;

	data = msgb_put(msg, sizeof(struct gsm_mncc));
	memcpy(data, mncc, sizeof(struct gsm_mncc));

	cc_tx_to_mncc(net, msg);

	return 0;
}

int mncc_release_ind(struct gsm_network *net, struct gsm_trans *trans,
		     uint32_t callref, int location, int value)
{
	struct gsm_mncc rel;

	memset(&rel, 0, sizeof(rel));
	rel.callref = callref;
	mncc_set_cause(&rel, location, value);
	if (trans && trans->cc.state == GSM_CSTATE_RELEASE_REQ)
		return mncc_recvmsg(net, trans, MNCC_REL_CNF, &rel);
	return mncc_recvmsg(net, trans, MNCC_REL_IND, &rel);
}

/* Call Control Specific transaction release.
 * gets called by trans_free, DO NOT CALL YOURSELF! */
void _gsm48_cc_trans_free(struct gsm_trans *trans)
{
	gsm48_stop_cc_timer(trans);

	/* Make sure call also gets released on the mgcp side */
	msc_call_release(trans);

	/* send release to L4, if callref still exists */
	if (trans->callref) {
		/* Ressource unavailable */
		mncc_release_ind(trans->net, trans, trans->callref,
				 GSM48_CAUSE_LOC_PRN_S_LU,
				 GSM48_CC_CAUSE_RESOURCE_UNAVAIL);
	}
	if (trans->cc.state != GSM_CSTATE_NULL)
		new_cc_state(trans, GSM_CSTATE_NULL);
#if BEFORE_MSCSPLIT
	if (trans->conn)
		trau_mux_unmap(&trans->conn->lchan->ts->e1_link, trans->callref);
#endif
}

static int gsm48_cc_tx_setup(struct gsm_trans *trans, void *arg);

/* call-back from paging the B-end of the connection */
static int setup_trig_pag_evt(unsigned int hooknum, unsigned int event,
			      struct msgb *msg, void *_conn, void *_transt)
{
	struct gsm_subscriber_connection *conn = _conn;
	struct gsm_trans *transt = _transt;

	OSMO_ASSERT(!transt->conn);

	switch (event) {
	case GSM_PAGING_SUCCEEDED:
		DEBUGP(DCC, "Paging subscr %s succeeded!\n",
		       vlr_subscr_msisdn_or_name(transt->vsub));
		OSMO_ASSERT(conn);
		/* Assign conn */
		transt->conn = conn;
		/* send SETUP request to called party */
		gsm48_cc_tx_setup(transt, &transt->cc.msg);
		break;
	case GSM_PAGING_EXPIRED:
	case GSM_PAGING_BUSY:
		DEBUGP(DCC, "Paging subscr %s expired!\n",
		       vlr_subscr_msisdn_or_name(transt->vsub));
		/* Temporarily out of order */
		mncc_release_ind(transt->net, transt,
				 transt->callref,
				 GSM48_CAUSE_LOC_PRN_S_LU,
				 GSM48_CC_CAUSE_DEST_OOO);
		transt->callref = 0;
		transt->paging_request = NULL;
		trans_free(transt);
		break;
	default:
		LOGP(DCC, LOGL_ERROR, "Unknown paging event %d\n", event);
		break;
	}

	transt->paging_request = NULL;
	return 0;
}

static int tch_recv_mncc(struct gsm_network *net, uint32_t callref, int enable);

#if BEFORE_MSCSPLIT
/* handle audio path for handover */
static int switch_for_handover(struct gsm_lchan *old_lchan,
			struct gsm_lchan *new_lchan)
{
	struct rtp_socket *old_rs, *new_rs, *other_rs;

	/* Ask the new socket to send to the already known port. */
	if (new_lchan->conn->mncc_rtp_bridge) {
		LOGP(DHO, LOGL_DEBUG, "Forwarding RTP\n");
		rsl_ipacc_mdcx(new_lchan,
					old_lchan->abis_ip.connect_ip,
					old_lchan->abis_ip.connect_port, 0);
		return 0;
	}

	if (ipacc_rtp_direct) {
		LOGP(DHO, LOGL_ERROR, "unable to handover in direct RTP mode\n");
		return 0;
	}

	/* RTP Proxy mode */
	new_rs = new_lchan->abis_ip.rtp_socket;
	old_rs = old_lchan->abis_ip.rtp_socket;

	if (!new_rs) {
		LOGP(DHO, LOGL_ERROR, "no RTP socket for new_lchan\n");
		return -EIO;
	}

	rsl_ipacc_mdcx_to_rtpsock(new_lchan);

	if (!old_rs) {
		LOGP(DHO, LOGL_ERROR, "no RTP socket for old_lchan\n");
		return -EIO;
	}

	/* copy rx_action and reference to other sock */
	new_rs->rx_action = old_rs->rx_action;
	new_rs->tx_action = old_rs->tx_action;
	new_rs->transmit = old_rs->transmit;

	switch (old_lchan->abis_ip.rtp_socket->rx_action) {
	case RTP_PROXY:
		other_rs = old_rs->proxy.other_sock;
		rtp_socket_proxy(new_rs, other_rs);
		/* delete reference to other end socket to prevent
		 * rtp_socket_free() from removing the inverse reference */
		old_rs->proxy.other_sock = NULL;
		break;
	case RTP_RECV_UPSTREAM:
		new_rs->receive = old_rs->receive;
		break;
	case RTP_NONE:
		break;
	}

	return 0;
}

static void maybe_switch_for_handover(struct gsm_lchan *lchan)
{
	struct gsm_lchan *old_lchan;
	old_lchan = bsc_handover_pending(lchan);
	if (old_lchan)
		switch_for_handover(old_lchan, lchan);
}


/* map two ipaccess RTP streams onto each other */
static int tch_map(struct gsm_lchan *lchan, struct gsm_lchan *remote_lchan)
{
	struct gsm_bts *bts = lchan->ts->trx->bts;
	struct gsm_bts *remote_bts = remote_lchan->ts->trx->bts;
	enum gsm_chan_t lt = lchan->type, rt = remote_lchan->type;
	enum gsm48_chan_mode lm = lchan->tch_mode, rm = remote_lchan->tch_mode;
	int rc;

	DEBUGP(DCC, "Setting up TCH map between (bts=%u,trx=%u,ts=%u,%s) and "
	       "(bts=%u,trx=%u,ts=%u,%s)\n",
	       bts->nr, lchan->ts->trx->nr, lchan->ts->nr,
	       get_value_string(gsm_chan_t_names, lt),
	       remote_bts->nr, remote_lchan->ts->trx->nr, remote_lchan->ts->nr,
	       get_value_string(gsm_chan_t_names, rt));

	if (bts->type != remote_bts->type) {
		LOGP(DCC, LOGL_ERROR, "Cannot switch calls between different BTS types yet\n");
		return -EINVAL;
	}

	if (lt != rt) {
		LOGP(DCC, LOGL_ERROR, "Cannot patch through call with different"
		     " channel types: local = %s, remote = %s\n",
		     get_value_string(gsm_chan_t_names, lt),
		     get_value_string(gsm_chan_t_names, rt));
		return -EBADSLT;
	}

	if (lm != rm) {
		LOGP(DCC, LOGL_ERROR, "Cannot patch through call with different"
		     " channel modes: local = %s, remote = %s\n",
		     get_value_string(gsm48_chan_mode_names, lm),
		     get_value_string(gsm48_chan_mode_names, rm));
		return -EMEDIUMTYPE;
	}

	// todo: map between different bts types
	switch (bts->type) {
	case GSM_BTS_TYPE_NANOBTS:
	case GSM_BTS_TYPE_OSMOBTS:
		if (!ipacc_rtp_direct) {
			if (!lchan->abis_ip.rtp_socket) {
				LOGP(DHO, LOGL_ERROR, "no RTP socket for "
					"lchan\n");
				return -EIO;
			}
			if (!remote_lchan->abis_ip.rtp_socket) {
				LOGP(DHO, LOGL_ERROR, "no RTP socket for "
					"remote_lchan\n");
				return -EIO;
			}

			/* connect the TCH's to our RTP proxy */
			rc = rsl_ipacc_mdcx_to_rtpsock(lchan);
			if (rc < 0)
				return rc;
			rc = rsl_ipacc_mdcx_to_rtpsock(remote_lchan);
			if (rc < 0)
				return rc;
			/* connect them with each other */
			rtp_socket_proxy(lchan->abis_ip.rtp_socket,
					 remote_lchan->abis_ip.rtp_socket);
		} else {
			/* directly connect TCH RTP streams to each other */
			rc = rsl_ipacc_mdcx(lchan, remote_lchan->abis_ip.bound_ip,
						remote_lchan->abis_ip.bound_port,
						remote_lchan->abis_ip.rtp_payload2);
			if (rc < 0)
				return rc;
			rc = rsl_ipacc_mdcx(remote_lchan, lchan->abis_ip.bound_ip,
						lchan->abis_ip.bound_port,
						lchan->abis_ip.rtp_payload2);
		}
		break;
	case GSM_BTS_TYPE_BS11:
	case GSM_BTS_TYPE_RBS2000:
	case GSM_BTS_TYPE_NOKIA_SITE:
		trau_mux_map_lchan(lchan, remote_lchan);
		break;
	default:
		LOGP(DCC, LOGL_ERROR, "Unknown BTS type %u\n", bts->type);
		return -EINVAL;
	}

	return 0;
}
#endif

/* bridge channels of two transactions */
static int tch_bridge(struct gsm_network *net, struct gsm_mncc_bridge *bridge)
{
	struct gsm_trans *trans1 = trans_find_by_callref(net, bridge->callref[0]);
	struct gsm_trans *trans2 = trans_find_by_callref(net, bridge->callref[1]);

	if (!trans1 || !trans2)
		return -EIO;

	if (!trans1->conn || !trans2->conn)
		return -EIO;

	/* Which subscriber do we want to track trans1 or trans2? */
	log_set_context(LOG_CTX_VLR_SUBSCR, trans1->vsub);

#if BEFORE_MSCSPLIT
	/* through-connect channel */
	return tch_map(trans1->conn->lchan, trans2->conn->lchan);
#else
	return msc_call_bridge(trans1, trans2);
#endif
}

/* enable receive of channels to MNCC upqueue */
static int tch_recv_mncc(struct gsm_network *net, uint32_t callref, int enable)
{
#if BEFORE_MSCSPLIT
	struct gsm_trans *trans;
	struct gsm_lchan *lchan;
	struct gsm_bts *bts;
	int rc;

	/* Find callref */
	trans = trans_find_by_callref(net, callref);
	if (!trans)
		return -EIO;
	if (!trans->conn)
		return 0;

	log_set_context(LOG_CTX_VLR_SUBSCR, trans->vsub);
	lchan = trans->conn->lchan;
	bts = lchan->ts->trx->bts;

	/* store receive state */
	trans->tch_recv = enable;

	switch (bts->type) {
	case GSM_BTS_TYPE_NANOBTS:
	case GSM_BTS_TYPE_OSMOBTS:
		if (ipacc_rtp_direct) {
			LOGP(DCC, LOGL_ERROR, "Error: RTP proxy is disabled\n");
			return -EINVAL;
		}
		/* In case, we don't have a RTP socket to the BTS yet, the BTS
		 * will not be connected to our RTP proxy and the socket will
		 * not be assigned to the application interface. This method
		 * will be called again, once the audio socket is created and
		 * connected. */
		if (!lchan->abis_ip.rtp_socket) {
			DEBUGP(DCC, "queue tch_recv_mncc request (%d)\n", enable);
			return 0;
		}
		if (enable) {
			/* connect the TCH's to our RTP proxy */
			rc = rsl_ipacc_mdcx_to_rtpsock(lchan);
			if (rc < 0)
				return rc;
			/* assign socket to application interface */
			rtp_socket_upstream(lchan->abis_ip.rtp_socket,
				net, callref);
		} else
			rtp_socket_upstream(lchan->abis_ip.rtp_socket,
				net, 0);
		break;
	case GSM_BTS_TYPE_BS11:
	case GSM_BTS_TYPE_RBS2000:
	case GSM_BTS_TYPE_NOKIA_SITE:
		/* In case we don't have a TCH with correct mode, the TRAU muxer
		 * will not be asigned to the application interface. This is
		 * performed by switch_trau_mux() after successful handover or
		 * assignment. */
		if (lchan->tch_mode == GSM48_CMODE_SIGN) {
			DEBUGP(DCC, "queue tch_recv_mncc request (%d)\n", enable);
			return 0;
		}
		if (enable)
			return trau_recv_lchan(lchan, callref);
		return trau_mux_unmap(NULL, callref);
		break;
	default:
		LOGP(DCC, LOGL_ERROR, "Unknown BTS type %u\n", bts->type);
		return -EINVAL;
	}

	return 0;
#else
	/* not implemented yet! */
	return -1;
#endif
}

static int gsm48_cc_rx_status_enq(struct gsm_trans *trans, struct msgb *msg)
{
	DEBUGP(DCC, "-> STATUS ENQ\n");
	return gsm48_cc_tx_status(trans, msg);
}

static int gsm48_cc_tx_release(struct gsm_trans *trans, void *arg);
static int gsm48_cc_tx_disconnect(struct gsm_trans *trans, void *arg);

static void gsm48_cc_timeout(void *arg)
{
	struct gsm_trans *trans = arg;
	int disconnect = 0, release = 0;
	int mo_cause = GSM48_CC_CAUSE_RECOVERY_TIMER;
	int mo_location = GSM48_CAUSE_LOC_USER;
	int l4_cause = GSM48_CC_CAUSE_NORMAL_UNSPEC;
	int l4_location = GSM48_CAUSE_LOC_PRN_S_LU;
	struct gsm_mncc mo_rel, l4_rel;

	memset(&mo_rel, 0, sizeof(struct gsm_mncc));
	mo_rel.callref = trans->callref;
	memset(&l4_rel, 0, sizeof(struct gsm_mncc));
	l4_rel.callref = trans->callref;

	switch(trans->cc.Tcurrent) {
	case 0x303:
		release = 1;
		l4_cause = GSM48_CC_CAUSE_USER_NOTRESPOND;
		break;
	case 0x310:
		disconnect = 1;
		l4_cause = GSM48_CC_CAUSE_USER_NOTRESPOND;
		break;
	case 0x313:
		disconnect = 1;
		/* unknown, did not find it in the specs */
		break;
	case 0x301:
		disconnect = 1;
		l4_cause = GSM48_CC_CAUSE_USER_NOTRESPOND;
		break;
	case 0x308:
		if (!trans->cc.T308_second) {
			/* restart T308 a second time */
			gsm48_cc_tx_release(trans, &trans->cc.msg);
			trans->cc.T308_second = 1;
			break; /* stay in release state */
		}
		trans_free(trans);
		return;
//		release = 1;
//		l4_cause = 14;
//		break;
	case 0x306:
		release = 1;
		mo_cause = trans->cc.msg.cause.value;
		mo_location = trans->cc.msg.cause.location;
		break;
	case 0x323:
		disconnect = 1;
		break;
	default:
		release = 1;
	}

	if (release && trans->callref) {
		/* process release towards layer 4 */
		mncc_release_ind(trans->net, trans, trans->callref,
				 l4_location, l4_cause);
		trans->callref = 0;
	}

	if (disconnect && trans->callref) {
		/* process disconnect towards layer 4 */
		mncc_set_cause(&l4_rel, l4_location, l4_cause);
		mncc_recvmsg(trans->net, trans, MNCC_DISC_IND, &l4_rel);
	}

	/* process disconnect towards mobile station */
	if (disconnect || release) {
		mncc_set_cause(&mo_rel, mo_location, mo_cause);
		mo_rel.cause.diag[0] = ((trans->cc.Tcurrent & 0xf00) >> 8) + '0';
		mo_rel.cause.diag[1] = ((trans->cc.Tcurrent & 0x0f0) >> 4) + '0';
		mo_rel.cause.diag[2] = (trans->cc.Tcurrent & 0x00f) + '0';
		mo_rel.cause.diag_len = 3;

		if (disconnect)
			gsm48_cc_tx_disconnect(trans, &mo_rel);
		if (release)
			gsm48_cc_tx_release(trans, &mo_rel);
	}

}

/* disconnect both calls from the bridge */
static inline void disconnect_bridge(struct gsm_network *net,
				     struct gsm_mncc_bridge *bridge, int err)
{
	struct gsm_trans *trans0 = trans_find_by_callref(net, bridge->callref[0]);
	struct gsm_trans *trans1 = trans_find_by_callref(net, bridge->callref[1]);
	struct gsm_mncc mx_rel;
	if (!trans0 || !trans1)
		return;

	DEBUGP(DCC, "Failed to bridge TCH for calls %x <-> %x :: %s \n",
	       trans0->callref, trans1->callref, strerror(err));

	memset(&mx_rel, 0, sizeof(struct gsm_mncc));
	mncc_set_cause(&mx_rel, GSM48_CAUSE_LOC_INN_NET,
		       GSM48_CC_CAUSE_CHAN_UNACCEPT);

	mx_rel.callref = trans0->callref;
	gsm48_cc_tx_disconnect(trans0, &mx_rel);

	mx_rel.callref = trans1->callref;
	gsm48_cc_tx_disconnect(trans1, &mx_rel);
}

static void gsm48_start_cc_timer(struct gsm_trans *trans, int current,
				 int sec, int micro)
{
	DEBUGP(DCC, "starting timer T%x with %d seconds\n", current, sec);
	osmo_timer_setup(&trans->cc.timer, gsm48_cc_timeout, trans);
	osmo_timer_schedule(&trans->cc.timer, sec, micro);
	trans->cc.Tcurrent = current;
}

static int gsm48_cc_rx_setup(struct gsm_trans *trans, struct msgb *msg)
{
	struct gsm48_hdr *gh = msgb_l3(msg);
	uint8_t msg_type = gsm48_hdr_msg_type(gh);
	unsigned int payload_len = msgb_l3len(msg) - sizeof(*gh);
	struct tlv_parsed tp;
	struct gsm_mncc setup;

	memset(&setup, 0, sizeof(struct gsm_mncc));
	setup.callref = trans->callref;
#if BEFORE_MSCSPLIT
	setup.lchan_type = trans->conn->lchan->type;
#else
	setup.lchan_type = GSM_LCHAN_NONE;
#endif
	tlv_parse(&tp, &gsm48_att_tlvdef, gh->data, payload_len, 0, 0);
	/* emergency setup is identified by msg_type */
	if (msg_type == GSM48_MT_CC_EMERG_SETUP)
		setup.emergency = 1;

	/* use subscriber as calling party number */
	setup.fields |= MNCC_F_CALLING;
	osmo_strlcpy(setup.calling.number, trans->vsub->msisdn, sizeof(setup.calling.number));
	osmo_strlcpy(setup.imsi, trans->vsub->imsi, sizeof(setup.imsi));

	/* bearer capability */
	if (TLVP_PRESENT(&tp, GSM48_IE_BEARER_CAP)) {
		setup.fields |= MNCC_F_BEARER_CAP;
		gsm48_decode_bearer_cap(&setup.bearer_cap,
				  TLVP_VAL(&tp, GSM48_IE_BEARER_CAP)-1);

		/* Create a copy of the bearer capability
		 * in the transaction struct, so we can use
		 * this information later */
		memcpy(&trans->bearer_cap,&setup.bearer_cap,
		       sizeof(trans->bearer_cap));
	}
	/* facility */
	if (TLVP_PRESENT(&tp, GSM48_IE_FACILITY)) {
		setup.fields |= MNCC_F_FACILITY;
		gsm48_decode_facility(&setup.facility,
				TLVP_VAL(&tp, GSM48_IE_FACILITY)-1);
	}
	/* called party bcd number */
	if (TLVP_PRESENT(&tp, GSM48_IE_CALLED_BCD)) {
		setup.fields |= MNCC_F_CALLED;
		gsm48_decode_called(&setup.called,
			      TLVP_VAL(&tp, GSM48_IE_CALLED_BCD)-1);
	}
	/* user-user */
	if (TLVP_PRESENT(&tp, GSM48_IE_USER_USER)) {
		setup.fields |= MNCC_F_USERUSER;
		gsm48_decode_useruser(&setup.useruser,
				TLVP_VAL(&tp, GSM48_IE_USER_USER)-1);
	}
	/* ss-version */
	if (TLVP_PRESENT(&tp, GSM48_IE_SS_VERS)) {
		setup.fields |= MNCC_F_SSVERSION;
		gsm48_decode_ssversion(&setup.ssversion,
				 TLVP_VAL(&tp, GSM48_IE_SS_VERS)-1);
	}
	/* CLIR suppression */
	if (TLVP_PRESENT(&tp, GSM48_IE_CLIR_SUPP))
		setup.clir.sup = 1;
	/* CLIR invocation */
	if (TLVP_PRESENT(&tp, GSM48_IE_CLIR_INVOC))
		setup.clir.inv = 1;
	/* cc cap */
	if (TLVP_PRESENT(&tp, GSM48_IE_CC_CAP)) {
		setup.fields |= MNCC_F_CCCAP;
		gsm48_decode_cccap(&setup.cccap,
			     TLVP_VAL(&tp, GSM48_IE_CC_CAP)-1);
	}

	new_cc_state(trans, GSM_CSTATE_INITIATED);

	LOGP(DCC, LOGL_INFO, "Subscriber %s (%s) sends SETUP to %s\n",
	     vlr_subscr_name(trans->vsub), trans->vsub->msisdn,
	     setup.called.number);

	rate_ctr_inc(&trans->net->msc_ctrs->ctr[MSC_CTR_CALL_MO_SETUP]);

	/* indicate setup to MNCC */
	mncc_recvmsg(trans->net, trans, MNCC_SETUP_IND, &setup);

	/* MNCC code will modify the channel asynchronously, we should
	 * ipaccess-bind only after the modification has been made to the
	 * lchan->tch_mode */
	return 0;
}

static int gsm48_cc_tx_setup(struct gsm_trans *trans, void *arg)
{
	struct msgb *msg = gsm48_msgb_alloc_name("GSM 04.08 CC STUP");
	struct gsm48_hdr *gh;
	struct gsm_mncc *setup = arg;
	int rc, trans_id;

	gh = (struct gsm48_hdr *) msgb_put(msg, sizeof(*gh));

	/* transaction id must not be assigned */
	if (trans->transaction_id != 0xff) { /* unasssigned */
		DEBUGP(DCC, "TX Setup with assigned transaction. "
			"This is not allowed!\n");
		/* Temporarily out of order */
		rc = mncc_release_ind(trans->net, trans, trans->callref,
				      GSM48_CAUSE_LOC_PRN_S_LU,
				      GSM48_CC_CAUSE_RESOURCE_UNAVAIL);
		trans->callref = 0;
		trans_free(trans);
		return rc;
	}

	/* Get free transaction_id */
	trans_id = trans_assign_trans_id(trans->net, trans->vsub,
					 GSM48_PDISC_CC, 0);
	if (trans_id < 0) {
		/* no free transaction ID */
		rc = mncc_release_ind(trans->net, trans, trans->callref,
				      GSM48_CAUSE_LOC_PRN_S_LU,
				      GSM48_CC_CAUSE_RESOURCE_UNAVAIL);
		trans->callref = 0;
		trans_free(trans);
		return rc;
	}
	trans->transaction_id = trans_id;

	gh->msg_type = GSM48_MT_CC_SETUP;

	gsm48_start_cc_timer(trans, 0x303, GSM48_T303);

	/* bearer capability */
	if (setup->fields & MNCC_F_BEARER_CAP)
		gsm48_encode_bearer_cap(msg, 0, &setup->bearer_cap);
	/* facility */
	if (setup->fields & MNCC_F_FACILITY)
		gsm48_encode_facility(msg, 0, &setup->facility);
	/* progress */
	if (setup->fields & MNCC_F_PROGRESS)
		gsm48_encode_progress(msg, 0, &setup->progress);
	/* calling party BCD number */
	if (setup->fields & MNCC_F_CALLING)
		gsm48_encode_calling(msg, &setup->calling);
	/* called party BCD number */
	if (setup->fields & MNCC_F_CALLED)
		gsm48_encode_called(msg, &setup->called);
	/* user-user */
	if (setup->fields & MNCC_F_USERUSER)
		gsm48_encode_useruser(msg, 0, &setup->useruser);
	/* redirecting party BCD number */
	if (setup->fields & MNCC_F_REDIRECTING)
		gsm48_encode_redirecting(msg, &setup->redirecting);
	/* signal */
	if (setup->fields & MNCC_F_SIGNAL)
		gsm48_encode_signal(msg, setup->signal);

	new_cc_state(trans, GSM_CSTATE_CALL_PRESENT);

	rate_ctr_inc(&trans->net->msc_ctrs->ctr[MSC_CTR_CALL_MT_SETUP]);

	return gsm48_conn_sendmsg(msg, trans->conn, trans);
}

static int gsm48_cc_rx_call_conf(struct gsm_trans *trans, struct msgb *msg)
{
	struct gsm48_hdr *gh = msgb_l3(msg);
	unsigned int payload_len = msgb_l3len(msg) - sizeof(*gh);
	struct tlv_parsed tp;
	struct gsm_mncc call_conf;

	gsm48_stop_cc_timer(trans);
	gsm48_start_cc_timer(trans, 0x310, GSM48_T310);

	memset(&call_conf, 0, sizeof(struct gsm_mncc));
	call_conf.callref = trans->callref;
#if BEFORE_MSCSPLIT
	call_conf.lchan_type = trans->conn->lchan->type;
#else
	call_conf.lchan_type = GSM_LCHAN_NONE;
#endif
	tlv_parse(&tp, &gsm48_att_tlvdef, gh->data, payload_len, 0, 0);
#if 0
	/* repeat */
	if (TLVP_PRESENT(&tp, GSM48_IE_REPEAT_CIR))
		call_conf.repeat = 1;
	if (TLVP_PRESENT(&tp, GSM48_IE_REPEAT_SEQ))
		call_conf.repeat = 2;
#endif
	/* bearer capability */
	if (TLVP_PRESENT(&tp, GSM48_IE_BEARER_CAP)) {
		call_conf.fields |= MNCC_F_BEARER_CAP;
		gsm48_decode_bearer_cap(&call_conf.bearer_cap,
				  TLVP_VAL(&tp, GSM48_IE_BEARER_CAP)-1);

		/* Create a copy of the bearer capability
		 * in the transaction struct, so we can use
		 * this information later */
		memcpy(&trans->bearer_cap,&call_conf.bearer_cap,
		       sizeof(trans->bearer_cap));
	}
	/* cause */
	if (TLVP_PRESENT(&tp, GSM48_IE_CAUSE)) {
		call_conf.fields |= MNCC_F_CAUSE;
		gsm48_decode_cause(&call_conf.cause,
			     TLVP_VAL(&tp, GSM48_IE_CAUSE)-1);
	}
	/* cc cap */
	if (TLVP_PRESENT(&tp, GSM48_IE_CC_CAP)) {
		call_conf.fields |= MNCC_F_CCCAP;
		gsm48_decode_cccap(&call_conf.cccap,
			     TLVP_VAL(&tp, GSM48_IE_CC_CAP)-1);
	}

	/* IMSI of called subscriber */
	osmo_strlcpy(call_conf.imsi, trans->vsub->imsi, sizeof(call_conf.imsi));

	new_cc_state(trans, GSM_CSTATE_MO_TERM_CALL_CONF);

	msc_call_assignment(trans);

	return mncc_recvmsg(trans->net, trans, MNCC_CALL_CONF_IND,
			    &call_conf);
}

static int gsm48_cc_tx_call_proc_and_assign(struct gsm_trans *trans, void *arg)
{
	struct gsm_mncc *proceeding = arg;
	struct msgb *msg = gsm48_msgb_alloc_name("GSM 04.08 CC PROC");
	struct gsm48_hdr *gh = (struct gsm48_hdr *) msgb_put(msg, sizeof(*gh));
	int rc;

	gh->msg_type = GSM48_MT_CC_CALL_PROC;

	new_cc_state(trans, GSM_CSTATE_MO_CALL_PROC);

	/* bearer capability */
	if (proceeding->fields & MNCC_F_BEARER_CAP)
		gsm48_encode_bearer_cap(msg, 0, &proceeding->bearer_cap);
	/* facility */
	if (proceeding->fields & MNCC_F_FACILITY)
		gsm48_encode_facility(msg, 0, &proceeding->facility);
	/* progress */
	if (proceeding->fields & MNCC_F_PROGRESS)
		gsm48_encode_progress(msg, 0, &proceeding->progress);

	rc = gsm48_conn_sendmsg(msg, trans->conn, trans);
	if (rc)
		return rc;

	return msc_call_assignment(trans);
}

static int gsm48_cc_rx_alerting(struct gsm_trans *trans, struct msgb *msg)
{
	struct gsm48_hdr *gh = msgb_l3(msg);
	unsigned int payload_len = msgb_l3len(msg) - sizeof(*gh);
	struct tlv_parsed tp;
	struct gsm_mncc alerting;

	gsm48_stop_cc_timer(trans);
	gsm48_start_cc_timer(trans, 0x301, GSM48_T301);

	memset(&alerting, 0, sizeof(struct gsm_mncc));
	alerting.callref = trans->callref;
	tlv_parse(&tp, &gsm48_att_tlvdef, gh->data, payload_len, 0, 0);
	/* facility */
	if (TLVP_PRESENT(&tp, GSM48_IE_FACILITY)) {
		alerting.fields |= MNCC_F_FACILITY;
		gsm48_decode_facility(&alerting.facility,
				TLVP_VAL(&tp, GSM48_IE_FACILITY)-1);
	}

	/* progress */
	if (TLVP_PRESENT(&tp, GSM48_IE_PROGR_IND)) {
		alerting.fields |= MNCC_F_PROGRESS;
		gsm48_decode_progress(&alerting.progress,
				TLVP_VAL(&tp, GSM48_IE_PROGR_IND)-1);
	}
	/* ss-version */
	if (TLVP_PRESENT(&tp, GSM48_IE_SS_VERS)) {
		alerting.fields |= MNCC_F_SSVERSION;
		gsm48_decode_ssversion(&alerting.ssversion,
				 TLVP_VAL(&tp, GSM48_IE_SS_VERS)-1);
	}

	new_cc_state(trans, GSM_CSTATE_CALL_RECEIVED);

	return mncc_recvmsg(trans->net, trans, MNCC_ALERT_IND,
			    &alerting);
}

static int gsm48_cc_tx_alerting(struct gsm_trans *trans, void *arg)
{
	struct gsm_mncc *alerting = arg;
	struct msgb *msg = gsm48_msgb_alloc_name("GSM 04.08 CC ALERT");
	struct gsm48_hdr *gh = (struct gsm48_hdr *) msgb_put(msg, sizeof(*gh));

	gh->msg_type = GSM48_MT_CC_ALERTING;

	/* facility */
	if (alerting->fields & MNCC_F_FACILITY)
		gsm48_encode_facility(msg, 0, &alerting->facility);
	/* progress */
	if (alerting->fields & MNCC_F_PROGRESS)
		gsm48_encode_progress(msg, 0, &alerting->progress);
	/* user-user */
	if (alerting->fields & MNCC_F_USERUSER)
		gsm48_encode_useruser(msg, 0, &alerting->useruser);

	new_cc_state(trans, GSM_CSTATE_CALL_DELIVERED);

	return gsm48_conn_sendmsg(msg, trans->conn, trans);
}

static int gsm48_cc_tx_progress(struct gsm_trans *trans, void *arg)
{
	struct gsm_mncc *progress = arg;
	struct msgb *msg = gsm48_msgb_alloc_name("GSM 04.08 CC PROGRESS");
	struct gsm48_hdr *gh = (struct gsm48_hdr *) msgb_put(msg, sizeof(*gh));

	gh->msg_type = GSM48_MT_CC_PROGRESS;

	/* progress */
	gsm48_encode_progress(msg, 1, &progress->progress);
	/* user-user */
	if (progress->fields & MNCC_F_USERUSER)
		gsm48_encode_useruser(msg, 0, &progress->useruser);

	return gsm48_conn_sendmsg(msg, trans->conn, trans);
}

static int gsm48_cc_tx_connect(struct gsm_trans *trans, void *arg)
{
	struct gsm_mncc *connect = arg;
	struct msgb *msg = gsm48_msgb_alloc_name("GSN 04.08 CC CON");
	struct gsm48_hdr *gh = (struct gsm48_hdr *) msgb_put(msg, sizeof(*gh));

	gh->msg_type = GSM48_MT_CC_CONNECT;

	gsm48_stop_cc_timer(trans);
	gsm48_start_cc_timer(trans, 0x313, GSM48_T313);

	/* facility */
	if (connect->fields & MNCC_F_FACILITY)
		gsm48_encode_facility(msg, 0, &connect->facility);
	/* progress */
	if (connect->fields & MNCC_F_PROGRESS)
		gsm48_encode_progress(msg, 0, &connect->progress);
	/* connected number */
	if (connect->fields & MNCC_F_CONNECTED)
		gsm48_encode_connected(msg, &connect->connected);
	/* user-user */
	if (connect->fields & MNCC_F_USERUSER)
		gsm48_encode_useruser(msg, 0, &connect->useruser);

	new_cc_state(trans, GSM_CSTATE_CONNECT_IND);

	return gsm48_conn_sendmsg(msg, trans->conn, trans);
}

static int gsm48_cc_rx_connect(struct gsm_trans *trans, struct msgb *msg)
{
	struct gsm48_hdr *gh = msgb_l3(msg);
	unsigned int payload_len = msgb_l3len(msg) - sizeof(*gh);
	struct tlv_parsed tp;
	struct gsm_mncc connect;

	gsm48_stop_cc_timer(trans);

	memset(&connect, 0, sizeof(struct gsm_mncc));
	connect.callref = trans->callref;
	tlv_parse(&tp, &gsm48_att_tlvdef, gh->data, payload_len, 0, 0);
	/* use subscriber as connected party number */
	connect.fields |= MNCC_F_CONNECTED;
	osmo_strlcpy(connect.connected.number, trans->vsub->msisdn, sizeof(connect.connected.number));
	osmo_strlcpy(connect.imsi, trans->vsub->imsi, sizeof(connect.imsi));

	/* facility */
	if (TLVP_PRESENT(&tp, GSM48_IE_FACILITY)) {
		connect.fields |= MNCC_F_FACILITY;
		gsm48_decode_facility(&connect.facility,
				TLVP_VAL(&tp, GSM48_IE_FACILITY)-1);
	}
	/* user-user */
	if (TLVP_PRESENT(&tp, GSM48_IE_USER_USER)) {
		connect.fields |= MNCC_F_USERUSER;
		gsm48_decode_useruser(&connect.useruser,
				TLVP_VAL(&tp, GSM48_IE_USER_USER)-1);
	}
	/* ss-version */
	if (TLVP_PRESENT(&tp, GSM48_IE_SS_VERS)) {
		connect.fields |= MNCC_F_SSVERSION;
		gsm48_decode_ssversion(&connect.ssversion,
				 TLVP_VAL(&tp, GSM48_IE_SS_VERS)-1);
	}

	new_cc_state(trans, GSM_CSTATE_CONNECT_REQUEST);
	rate_ctr_inc(&trans->net->msc_ctrs->ctr[MSC_CTR_CALL_MT_CONNECT]);

	return mncc_recvmsg(trans->net, trans, MNCC_SETUP_CNF, &connect);
}


static int gsm48_cc_rx_connect_ack(struct gsm_trans *trans, struct msgb *msg)
{
	struct gsm_mncc connect_ack;

	gsm48_stop_cc_timer(trans);

	new_cc_state(trans, GSM_CSTATE_ACTIVE);
	rate_ctr_inc(&trans->net->msc_ctrs->ctr[MSC_CTR_CALL_MO_CONNECT_ACK]);

	memset(&connect_ack, 0, sizeof(struct gsm_mncc));
	connect_ack.callref = trans->callref;

	return mncc_recvmsg(trans->net, trans, MNCC_SETUP_COMPL_IND,
			    &connect_ack);
}

static int gsm48_cc_tx_connect_ack(struct gsm_trans *trans, void *arg)
{
	struct msgb *msg = gsm48_msgb_alloc_name("GSM 04.08 CC CON ACK");
	struct gsm48_hdr *gh = (struct gsm48_hdr *) msgb_put(msg, sizeof(*gh));

	gh->msg_type = GSM48_MT_CC_CONNECT_ACK;

	new_cc_state(trans, GSM_CSTATE_ACTIVE);

	return gsm48_conn_sendmsg(msg, trans->conn, trans);
}

static int gsm48_cc_rx_disconnect(struct gsm_trans *trans, struct msgb *msg)
{
	struct gsm48_hdr *gh = msgb_l3(msg);
	unsigned int payload_len = msgb_l3len(msg) - sizeof(*gh);
	struct tlv_parsed tp;
	struct gsm_mncc disc;

	gsm48_stop_cc_timer(trans);

	new_cc_state(trans, GSM_CSTATE_DISCONNECT_REQ);

	memset(&disc, 0, sizeof(struct gsm_mncc));
	disc.callref = trans->callref;
	tlv_parse(&tp, &gsm48_att_tlvdef, gh->data, payload_len, GSM48_IE_CAUSE, 0);
	/* cause */
	if (TLVP_PRESENT(&tp, GSM48_IE_CAUSE)) {
		disc.fields |= MNCC_F_CAUSE;
		gsm48_decode_cause(&disc.cause,
			     TLVP_VAL(&tp, GSM48_IE_CAUSE)-1);
	}
	/* facility */
	if (TLVP_PRESENT(&tp, GSM48_IE_FACILITY)) {
		disc.fields |= MNCC_F_FACILITY;
		gsm48_decode_facility(&disc.facility,
				TLVP_VAL(&tp, GSM48_IE_FACILITY)-1);
	}
	/* user-user */
	if (TLVP_PRESENT(&tp, GSM48_IE_USER_USER)) {
		disc.fields |= MNCC_F_USERUSER;
		gsm48_decode_useruser(&disc.useruser,
				TLVP_VAL(&tp, GSM48_IE_USER_USER)-1);
	}
	/* ss-version */
	if (TLVP_PRESENT(&tp, GSM48_IE_SS_VERS)) {
		disc.fields |= MNCC_F_SSVERSION;
		gsm48_decode_ssversion(&disc.ssversion,
				 TLVP_VAL(&tp, GSM48_IE_SS_VERS)-1);
	}

	return mncc_recvmsg(trans->net, trans, MNCC_DISC_IND, &disc);

}

static struct gsm_mncc_cause default_cause = {
	.location	= GSM48_CAUSE_LOC_PRN_S_LU,
	.coding		= 0,
	.rec		= 0,
	.rec_val	= 0,
	.value		= GSM48_CC_CAUSE_NORMAL_UNSPEC,
	.diag_len	= 0,
	.diag		= { 0 },
};

static int gsm48_cc_tx_disconnect(struct gsm_trans *trans, void *arg)
{
	struct gsm_mncc *disc = arg;
	struct msgb *msg = gsm48_msgb_alloc_name("GSM 04.08 CC DISC");
	struct gsm48_hdr *gh = (struct gsm48_hdr *) msgb_put(msg, sizeof(*gh));

	gh->msg_type = GSM48_MT_CC_DISCONNECT;

	gsm48_stop_cc_timer(trans);
	gsm48_start_cc_timer(trans, 0x306, GSM48_T306);

	/* cause */
	if (disc->fields & MNCC_F_CAUSE)
		gsm48_encode_cause(msg, 1, &disc->cause);
	else
		gsm48_encode_cause(msg, 1, &default_cause);

	/* facility */
	if (disc->fields & MNCC_F_FACILITY)
		gsm48_encode_facility(msg, 0, &disc->facility);
	/* progress */
	if (disc->fields & MNCC_F_PROGRESS)
		gsm48_encode_progress(msg, 0, &disc->progress);
	/* user-user */
	if (disc->fields & MNCC_F_USERUSER)
		gsm48_encode_useruser(msg, 0, &disc->useruser);

	/* store disconnect cause for T306 expiry */
	memcpy(&trans->cc.msg, disc, sizeof(struct gsm_mncc));

	new_cc_state(trans, GSM_CSTATE_DISCONNECT_IND);

	return gsm48_conn_sendmsg(msg, trans->conn, trans);
}

static int gsm48_cc_rx_release(struct gsm_trans *trans, struct msgb *msg)
{
	struct gsm48_hdr *gh = msgb_l3(msg);
	unsigned int payload_len = msgb_l3len(msg) - sizeof(*gh);
	struct tlv_parsed tp;
	struct gsm_mncc rel;
	int rc;

	gsm48_stop_cc_timer(trans);

	memset(&rel, 0, sizeof(struct gsm_mncc));
	rel.callref = trans->callref;
	tlv_parse(&tp, &gsm48_att_tlvdef, gh->data, payload_len, 0, 0);
	/* cause */
	if (TLVP_PRESENT(&tp, GSM48_IE_CAUSE)) {
		rel.fields |= MNCC_F_CAUSE;
		gsm48_decode_cause(&rel.cause,
			     TLVP_VAL(&tp, GSM48_IE_CAUSE)-1);
	}
	/* facility */
	if (TLVP_PRESENT(&tp, GSM48_IE_FACILITY)) {
		rel.fields |= MNCC_F_FACILITY;
		gsm48_decode_facility(&rel.facility,
				TLVP_VAL(&tp, GSM48_IE_FACILITY)-1);
	}
	/* user-user */
	if (TLVP_PRESENT(&tp, GSM48_IE_USER_USER)) {
		rel.fields |= MNCC_F_USERUSER;
		gsm48_decode_useruser(&rel.useruser,
				TLVP_VAL(&tp, GSM48_IE_USER_USER)-1);
	}
	/* ss-version */
	if (TLVP_PRESENT(&tp, GSM48_IE_SS_VERS)) {
		rel.fields |= MNCC_F_SSVERSION;
		gsm48_decode_ssversion(&rel.ssversion,
				 TLVP_VAL(&tp, GSM48_IE_SS_VERS)-1);
	}

	if (trans->cc.state == GSM_CSTATE_RELEASE_REQ) {
		/* release collision 5.4.5 */
		rc = mncc_recvmsg(trans->net, trans, MNCC_REL_CNF, &rel);
	} else {
		rc = gsm48_tx_simple(trans->conn,
				     GSM48_PDISC_CC | (trans->transaction_id << 4),
				     GSM48_MT_CC_RELEASE_COMPL);
		rc = mncc_recvmsg(trans->net, trans, MNCC_REL_IND, &rel);
	}

	new_cc_state(trans, GSM_CSTATE_NULL);

	trans->callref = 0;
	trans_free(trans);

	return rc;
}

static int gsm48_cc_tx_release(struct gsm_trans *trans, void *arg)
{
	struct gsm_mncc *rel = arg;
	struct msgb *msg = gsm48_msgb_alloc_name("GSM 04.08 CC REL");
	struct gsm48_hdr *gh = (struct gsm48_hdr *) msgb_put(msg, sizeof(*gh));

	gh->msg_type = GSM48_MT_CC_RELEASE;

	gsm48_stop_cc_timer(trans);
	gsm48_start_cc_timer(trans, 0x308, GSM48_T308);

	/* cause */
	if (rel->fields & MNCC_F_CAUSE)
		gsm48_encode_cause(msg, 0, &rel->cause);
	/* facility */
	if (rel->fields & MNCC_F_FACILITY)
		gsm48_encode_facility(msg, 0, &rel->facility);
	/* user-user */
	if (rel->fields & MNCC_F_USERUSER)
		gsm48_encode_useruser(msg, 0, &rel->useruser);

	trans->cc.T308_second = 0;
	memcpy(&trans->cc.msg, rel, sizeof(struct gsm_mncc));

	if (trans->cc.state != GSM_CSTATE_RELEASE_REQ)
		new_cc_state(trans, GSM_CSTATE_RELEASE_REQ);

	return gsm48_conn_sendmsg(msg, trans->conn, trans);
}

static int gsm48_cc_rx_release_compl(struct gsm_trans *trans, struct msgb *msg)
{
	struct gsm48_hdr *gh = msgb_l3(msg);
	unsigned int payload_len = msgb_l3len(msg) - sizeof(*gh);
	struct tlv_parsed tp;
	struct gsm_mncc rel;
	int rc = 0;

	gsm48_stop_cc_timer(trans);

	memset(&rel, 0, sizeof(struct gsm_mncc));
	rel.callref = trans->callref;
	tlv_parse(&tp, &gsm48_att_tlvdef, gh->data, payload_len, 0, 0);
	/* cause */
	if (TLVP_PRESENT(&tp, GSM48_IE_CAUSE)) {
		rel.fields |= MNCC_F_CAUSE;
		gsm48_decode_cause(&rel.cause,
			     TLVP_VAL(&tp, GSM48_IE_CAUSE)-1);
	}
	/* facility */
	if (TLVP_PRESENT(&tp, GSM48_IE_FACILITY)) {
		rel.fields |= MNCC_F_FACILITY;
		gsm48_decode_facility(&rel.facility,
				TLVP_VAL(&tp, GSM48_IE_FACILITY)-1);
	}
	/* user-user */
	if (TLVP_PRESENT(&tp, GSM48_IE_USER_USER)) {
		rel.fields |= MNCC_F_USERUSER;
		gsm48_decode_useruser(&rel.useruser,
				TLVP_VAL(&tp, GSM48_IE_USER_USER)-1);
	}
	/* ss-version */
	if (TLVP_PRESENT(&tp, GSM48_IE_SS_VERS)) {
		rel.fields |= MNCC_F_SSVERSION;
		gsm48_decode_ssversion(&rel.ssversion,
				 TLVP_VAL(&tp, GSM48_IE_SS_VERS)-1);
	}

	if (trans->callref) {
		switch (trans->cc.state) {
		case GSM_CSTATE_CALL_PRESENT:
			rc = mncc_recvmsg(trans->net, trans,
					  MNCC_REJ_IND, &rel);
			break;
		case GSM_CSTATE_RELEASE_REQ:
			rc = mncc_recvmsg(trans->net, trans,
					  MNCC_REL_CNF, &rel);
			break;
		default:
			rc = mncc_recvmsg(trans->net, trans,
					  MNCC_REL_IND, &rel);
		}
	}

	trans->callref = 0;
	trans_free(trans);

	return rc;
}

static int gsm48_cc_tx_release_compl(struct gsm_trans *trans, void *arg)
{
	struct gsm_mncc *rel = arg;
	struct msgb *msg = gsm48_msgb_alloc_name("GSM 04.08 CC REL COMPL");
	struct gsm48_hdr *gh = (struct gsm48_hdr *) msgb_put(msg, sizeof(*gh));
	int ret;

	gh->msg_type = GSM48_MT_CC_RELEASE_COMPL;

	trans->callref = 0;

	gsm48_stop_cc_timer(trans);

	/* cause */
	if (rel->fields & MNCC_F_CAUSE)
		gsm48_encode_cause(msg, 0, &rel->cause);
	/* facility */
	if (rel->fields & MNCC_F_FACILITY)
		gsm48_encode_facility(msg, 0, &rel->facility);
	/* user-user */
	if (rel->fields & MNCC_F_USERUSER)
		gsm48_encode_useruser(msg, 0, &rel->useruser);

	ret =  gsm48_conn_sendmsg(msg, trans->conn, trans);

	trans_free(trans);

	return ret;
}

static int gsm48_cc_rx_facility(struct gsm_trans *trans, struct msgb *msg)
{
	struct gsm48_hdr *gh = msgb_l3(msg);
	unsigned int payload_len = msgb_l3len(msg) - sizeof(*gh);
	struct tlv_parsed tp;
	struct gsm_mncc fac;

	memset(&fac, 0, sizeof(struct gsm_mncc));
	fac.callref = trans->callref;
	tlv_parse(&tp, &gsm48_att_tlvdef, gh->data, payload_len, GSM48_IE_FACILITY, 0);
	/* facility */
	if (TLVP_PRESENT(&tp, GSM48_IE_FACILITY)) {
		fac.fields |= MNCC_F_FACILITY;
		gsm48_decode_facility(&fac.facility,
				TLVP_VAL(&tp, GSM48_IE_FACILITY)-1);
	}
	/* ss-version */
	if (TLVP_PRESENT(&tp, GSM48_IE_SS_VERS)) {
		fac.fields |= MNCC_F_SSVERSION;
		gsm48_decode_ssversion(&fac.ssversion,
				 TLVP_VAL(&tp, GSM48_IE_SS_VERS)-1);
	}

	return mncc_recvmsg(trans->net, trans, MNCC_FACILITY_IND, &fac);
}

static int gsm48_cc_tx_facility(struct gsm_trans *trans, void *arg)
{
	struct gsm_mncc *fac = arg;
	struct msgb *msg = gsm48_msgb_alloc_name("GSM 04.08 CC FAC");
	struct gsm48_hdr *gh = (struct gsm48_hdr *) msgb_put(msg, sizeof(*gh));

	gh->msg_type = GSM48_MT_CC_FACILITY;

	/* facility */
	gsm48_encode_facility(msg, 1, &fac->facility);

	return gsm48_conn_sendmsg(msg, trans->conn, trans);
}

static int gsm48_cc_rx_hold(struct gsm_trans *trans, struct msgb *msg)
{
	struct gsm_mncc hold;

	memset(&hold, 0, sizeof(struct gsm_mncc));
	hold.callref = trans->callref;
	return mncc_recvmsg(trans->net, trans, MNCC_HOLD_IND, &hold);
}

static int gsm48_cc_tx_hold_ack(struct gsm_trans *trans, void *arg)
{
	struct msgb *msg = gsm48_msgb_alloc_name("GSM 04.08 CC HLD ACK");
	struct gsm48_hdr *gh = (struct gsm48_hdr *) msgb_put(msg, sizeof(*gh));

	gh->msg_type = GSM48_MT_CC_HOLD_ACK;

	return gsm48_conn_sendmsg(msg, trans->conn, trans);
}

static int gsm48_cc_tx_hold_rej(struct gsm_trans *trans, void *arg)
{
	struct gsm_mncc *hold_rej = arg;
	struct msgb *msg = gsm48_msgb_alloc_name("GSM 04.08 CC HLD REJ");
	struct gsm48_hdr *gh = (struct gsm48_hdr *) msgb_put(msg, sizeof(*gh));

	gh->msg_type = GSM48_MT_CC_HOLD_REJ;

	/* cause */
	if (hold_rej->fields & MNCC_F_CAUSE)
		gsm48_encode_cause(msg, 1, &hold_rej->cause);
	else
		gsm48_encode_cause(msg, 1, &default_cause);

	return gsm48_conn_sendmsg(msg, trans->conn, trans);
}

static int gsm48_cc_rx_retrieve(struct gsm_trans *trans, struct msgb *msg)
{
	struct gsm_mncc retrieve;

	memset(&retrieve, 0, sizeof(struct gsm_mncc));
	retrieve.callref = trans->callref;
	return mncc_recvmsg(trans->net, trans, MNCC_RETRIEVE_IND,
			    &retrieve);
}

static int gsm48_cc_tx_retrieve_ack(struct gsm_trans *trans, void *arg)
{
	struct msgb *msg = gsm48_msgb_alloc_name("GSM 04.08 CC RETR ACK");
	struct gsm48_hdr *gh = (struct gsm48_hdr *) msgb_put(msg, sizeof(*gh));

	gh->msg_type = GSM48_MT_CC_RETR_ACK;

	return gsm48_conn_sendmsg(msg, trans->conn, trans);
}

static int gsm48_cc_tx_retrieve_rej(struct gsm_trans *trans, void *arg)
{
	struct gsm_mncc *retrieve_rej = arg;
	struct msgb *msg = gsm48_msgb_alloc_name("GSM 04.08 CC RETR REJ");
	struct gsm48_hdr *gh = (struct gsm48_hdr *) msgb_put(msg, sizeof(*gh));

	gh->msg_type = GSM48_MT_CC_RETR_REJ;

	/* cause */
	if (retrieve_rej->fields & MNCC_F_CAUSE)
		gsm48_encode_cause(msg, 1, &retrieve_rej->cause);
	else
		gsm48_encode_cause(msg, 1, &default_cause);

	return gsm48_conn_sendmsg(msg, trans->conn, trans);
}

static int gsm48_cc_rx_start_dtmf(struct gsm_trans *trans, struct msgb *msg)
{
	struct gsm48_hdr *gh = msgb_l3(msg);
	unsigned int payload_len = msgb_l3len(msg) - sizeof(*gh);
	struct tlv_parsed tp;
	struct gsm_mncc dtmf;

	memset(&dtmf, 0, sizeof(struct gsm_mncc));
	dtmf.callref = trans->callref;
	tlv_parse(&tp, &gsm48_att_tlvdef, gh->data, payload_len, 0, 0);
	/* keypad facility */
	if (TLVP_PRESENT(&tp, GSM48_IE_KPD_FACILITY)) {
		dtmf.fields |= MNCC_F_KEYPAD;
		gsm48_decode_keypad(&dtmf.keypad,
			      TLVP_VAL(&tp, GSM48_IE_KPD_FACILITY)-1);
	}

	return mncc_recvmsg(trans->net, trans, MNCC_START_DTMF_IND, &dtmf);
}

static int gsm48_cc_tx_start_dtmf_ack(struct gsm_trans *trans, void *arg)
{
	struct gsm_mncc *dtmf = arg;
	struct msgb *msg = gsm48_msgb_alloc_name("GSM 04.08 DTMF ACK");
	struct gsm48_hdr *gh = (struct gsm48_hdr *) msgb_put(msg, sizeof(*gh));

	gh->msg_type = GSM48_MT_CC_START_DTMF_ACK;

	/* keypad */
	if (dtmf->fields & MNCC_F_KEYPAD)
		gsm48_encode_keypad(msg, dtmf->keypad);

	return gsm48_conn_sendmsg(msg, trans->conn, trans);
}

static int gsm48_cc_tx_start_dtmf_rej(struct gsm_trans *trans, void *arg)
{
	struct gsm_mncc *dtmf = arg;
	struct msgb *msg = gsm48_msgb_alloc_name("GSM 04.08 DTMF REJ");
	struct gsm48_hdr *gh = (struct gsm48_hdr *) msgb_put(msg, sizeof(*gh));

	gh->msg_type = GSM48_MT_CC_START_DTMF_REJ;

	/* cause */
	if (dtmf->fields & MNCC_F_CAUSE)
		gsm48_encode_cause(msg, 1, &dtmf->cause);
	else
		gsm48_encode_cause(msg, 1, &default_cause);

	return gsm48_conn_sendmsg(msg, trans->conn, trans);
}

static int gsm48_cc_tx_stop_dtmf_ack(struct gsm_trans *trans, void *arg)
{
	struct msgb *msg = gsm48_msgb_alloc_name("GSM 04.08 DTMF STP ACK");
	struct gsm48_hdr *gh = (struct gsm48_hdr *) msgb_put(msg, sizeof(*gh));

	gh->msg_type = GSM48_MT_CC_STOP_DTMF_ACK;

	return gsm48_conn_sendmsg(msg, trans->conn, trans);
}

static int gsm48_cc_rx_stop_dtmf(struct gsm_trans *trans, struct msgb *msg)
{
	struct gsm_mncc dtmf;

	memset(&dtmf, 0, sizeof(struct gsm_mncc));
	dtmf.callref = trans->callref;

	return mncc_recvmsg(trans->net, trans, MNCC_STOP_DTMF_IND, &dtmf);
}

static int gsm48_cc_rx_modify(struct gsm_trans *trans, struct msgb *msg)
{
	struct gsm48_hdr *gh = msgb_l3(msg);
	unsigned int payload_len = msgb_l3len(msg) - sizeof(*gh);
	struct tlv_parsed tp;
	struct gsm_mncc modify;

	memset(&modify, 0, sizeof(struct gsm_mncc));
	modify.callref = trans->callref;
	tlv_parse(&tp, &gsm48_att_tlvdef, gh->data, payload_len, GSM48_IE_BEARER_CAP, 0);
	/* bearer capability */
	if (TLVP_PRESENT(&tp, GSM48_IE_BEARER_CAP)) {
		modify.fields |= MNCC_F_BEARER_CAP;
		gsm48_decode_bearer_cap(&modify.bearer_cap,
				  TLVP_VAL(&tp, GSM48_IE_BEARER_CAP)-1);

		/* Create a copy of the bearer capability
		 * in the transaction struct, so we can use
		 * this information later */
		memcpy(&trans->bearer_cap,&modify.bearer_cap,
		       sizeof(trans->bearer_cap));
	}

	new_cc_state(trans, GSM_CSTATE_MO_ORIG_MODIFY);

	return mncc_recvmsg(trans->net, trans, MNCC_MODIFY_IND, &modify);
}

static int gsm48_cc_tx_modify(struct gsm_trans *trans, void *arg)
{
	struct gsm_mncc *modify = arg;
	struct msgb *msg = gsm48_msgb_alloc_name("GSM 04.08 CC MOD");
	struct gsm48_hdr *gh = (struct gsm48_hdr *) msgb_put(msg, sizeof(*gh));

	gh->msg_type = GSM48_MT_CC_MODIFY;

	gsm48_start_cc_timer(trans, 0x323, GSM48_T323);

	/* bearer capability */
	gsm48_encode_bearer_cap(msg, 1, &modify->bearer_cap);

	new_cc_state(trans, GSM_CSTATE_MO_TERM_MODIFY);

	return gsm48_conn_sendmsg(msg, trans->conn, trans);
}

static int gsm48_cc_rx_modify_complete(struct gsm_trans *trans, struct msgb *msg)
{
	struct gsm48_hdr *gh = msgb_l3(msg);
	unsigned int payload_len = msgb_l3len(msg) - sizeof(*gh);
	struct tlv_parsed tp;
	struct gsm_mncc modify;

	gsm48_stop_cc_timer(trans);

	memset(&modify, 0, sizeof(struct gsm_mncc));
	modify.callref = trans->callref;
	tlv_parse(&tp, &gsm48_att_tlvdef, gh->data, payload_len, GSM48_IE_BEARER_CAP, 0);
	/* bearer capability */
	if (TLVP_PRESENT(&tp, GSM48_IE_BEARER_CAP)) {
		modify.fields |= MNCC_F_BEARER_CAP;
		gsm48_decode_bearer_cap(&modify.bearer_cap,
				  TLVP_VAL(&tp, GSM48_IE_BEARER_CAP)-1);

		/* Create a copy of the bearer capability
		 * in the transaction struct, so we can use
		 * this information later */
		memcpy(&trans->bearer_cap,&modify.bearer_cap,
		       sizeof(trans->bearer_cap));
	}

	new_cc_state(trans, GSM_CSTATE_ACTIVE);

	return mncc_recvmsg(trans->net, trans, MNCC_MODIFY_CNF, &modify);
}

static int gsm48_cc_tx_modify_complete(struct gsm_trans *trans, void *arg)
{
	struct gsm_mncc *modify = arg;
	struct msgb *msg = gsm48_msgb_alloc_name("GSM 04.08 CC MOD COMPL");
	struct gsm48_hdr *gh = (struct gsm48_hdr *) msgb_put(msg, sizeof(*gh));

	gh->msg_type = GSM48_MT_CC_MODIFY_COMPL;

	/* bearer capability */
	gsm48_encode_bearer_cap(msg, 1, &modify->bearer_cap);

	new_cc_state(trans, GSM_CSTATE_ACTIVE);

	return gsm48_conn_sendmsg(msg, trans->conn, trans);
}

static int gsm48_cc_rx_modify_reject(struct gsm_trans *trans, struct msgb *msg)
{
	struct gsm48_hdr *gh = msgb_l3(msg);
	unsigned int payload_len = msgb_l3len(msg) - sizeof(*gh);
	struct tlv_parsed tp;
	struct gsm_mncc modify;

	gsm48_stop_cc_timer(trans);

	memset(&modify, 0, sizeof(struct gsm_mncc));
	modify.callref = trans->callref;
	tlv_parse(&tp, &gsm48_att_tlvdef, gh->data, payload_len, GSM48_IE_BEARER_CAP, GSM48_IE_CAUSE);
	/* bearer capability */
	if (TLVP_PRESENT(&tp, GSM48_IE_BEARER_CAP)) {
		modify.fields |= GSM48_IE_BEARER_CAP;
		gsm48_decode_bearer_cap(&modify.bearer_cap,
				  TLVP_VAL(&tp, GSM48_IE_BEARER_CAP)-1);

		/* Create a copy of the bearer capability
		 * in the transaction struct, so we can use
		 * this information later */
		memcpy(&trans->bearer_cap,&modify.bearer_cap,
		       sizeof(trans->bearer_cap));
	}
	/* cause */
	if (TLVP_PRESENT(&tp, GSM48_IE_CAUSE)) {
		modify.fields |= MNCC_F_CAUSE;
		gsm48_decode_cause(&modify.cause,
			     TLVP_VAL(&tp, GSM48_IE_CAUSE)-1);
	}

	new_cc_state(trans, GSM_CSTATE_ACTIVE);

	return mncc_recvmsg(trans->net, trans, MNCC_MODIFY_REJ, &modify);
}

static int gsm48_cc_tx_modify_reject(struct gsm_trans *trans, void *arg)
{
	struct gsm_mncc *modify = arg;
	struct msgb *msg = gsm48_msgb_alloc_name("GSM 04.08 CC MOD REJ");
	struct gsm48_hdr *gh = (struct gsm48_hdr *) msgb_put(msg, sizeof(*gh));

	gh->msg_type = GSM48_MT_CC_MODIFY_REJECT;

	/* bearer capability */
	gsm48_encode_bearer_cap(msg, 1, &modify->bearer_cap);
	/* cause */
	gsm48_encode_cause(msg, 1, &modify->cause);

	new_cc_state(trans, GSM_CSTATE_ACTIVE);

	return gsm48_conn_sendmsg(msg, trans->conn, trans);
}

static int gsm48_cc_tx_notify(struct gsm_trans *trans, void *arg)
{
	struct gsm_mncc *notify = arg;
	struct msgb *msg = gsm48_msgb_alloc_name("GSM 04.08 CC NOT");
	struct gsm48_hdr *gh = (struct gsm48_hdr *) msgb_put(msg, sizeof(*gh));

	gh->msg_type = GSM48_MT_CC_NOTIFY;

	/* notify */
	gsm48_encode_notify(msg, notify->notify);

	return gsm48_conn_sendmsg(msg, trans->conn, trans);
}

static int gsm48_cc_rx_notify(struct gsm_trans *trans, struct msgb *msg)
{
	struct gsm48_hdr *gh = msgb_l3(msg);
	unsigned int payload_len = msgb_l3len(msg) - sizeof(*gh);
//	struct tlv_parsed tp;
	struct gsm_mncc notify;

	memset(&notify, 0, sizeof(struct gsm_mncc));
	notify.callref = trans->callref;
//	tlv_parse(&tp, &gsm48_att_tlvdef, gh->data, payload_len);
	if (payload_len >= 1)
		gsm48_decode_notify(&notify.notify, gh->data);

	return mncc_recvmsg(trans->net, trans, MNCC_NOTIFY_IND, &notify);
}

static int gsm48_cc_tx_userinfo(struct gsm_trans *trans, void *arg)
{
	struct gsm_mncc *user = arg;
	struct msgb *msg = gsm48_msgb_alloc_name("GSM 04.08 USR INFO");
	struct gsm48_hdr *gh = (struct gsm48_hdr *) msgb_put(msg, sizeof(*gh));

	gh->msg_type = GSM48_MT_CC_USER_INFO;

	/* user-user */
	if (user->fields & MNCC_F_USERUSER)
		gsm48_encode_useruser(msg, 1, &user->useruser);
	/* more data */
	if (user->more)
		gsm48_encode_more(msg);

	return gsm48_conn_sendmsg(msg, trans->conn, trans);
}

static int gsm48_cc_rx_userinfo(struct gsm_trans *trans, struct msgb *msg)
{
	struct gsm48_hdr *gh = msgb_l3(msg);
	unsigned int payload_len = msgb_l3len(msg) - sizeof(*gh);
	struct tlv_parsed tp;
	struct gsm_mncc user;

	memset(&user, 0, sizeof(struct gsm_mncc));
	user.callref = trans->callref;
	tlv_parse(&tp, &gsm48_att_tlvdef, gh->data, payload_len, GSM48_IE_USER_USER, 0);
	/* user-user */
	if (TLVP_PRESENT(&tp, GSM48_IE_USER_USER)) {
		user.fields |= MNCC_F_USERUSER;
		gsm48_decode_useruser(&user.useruser,
				TLVP_VAL(&tp, GSM48_IE_USER_USER)-1);
	}
	/* more data */
	if (TLVP_PRESENT(&tp, GSM48_IE_MORE_DATA))
		user.more = 1;

	return mncc_recvmsg(trans->net, trans, MNCC_USERINFO_IND, &user);
}

static int _gsm48_lchan_modify(struct gsm_trans *trans, void *arg)
{
#if BEFORE_MSCSPLIT
	struct gsm_mncc *mode = arg;
	struct gsm_lchan *lchan = trans->conn->lchan;

	/*
	 * We were forced to make an assignment a lot earlier and
	 * we should avoid sending another assignment that might
	 * even lead to a different kind of lchan (TCH/F vs. TCH/H).
	 * In case of rtp-bridge it is too late to change things
	 * here.
	 */
	if (trans->conn->mncc_rtp_bridge && lchan->tch_mode != GSM48_CMODE_SIGN)
		return 0;

	return gsm0808_assign_req(trans->conn, mode->lchan_mode,
		trans->conn->lchan->type != GSM_LCHAN_TCH_H);
#else
	/* not implemented yet! */
	return -1;
#endif

}

#if BEFORE_MSCSPLIT
static void mncc_recv_rtp(struct gsm_network *net, uint32_t callref,
		int cmd, uint32_t addr, uint16_t port, uint32_t payload_type,
		uint32_t payload_msg_type)
{
	uint8_t data[sizeof(struct gsm_mncc)];
	struct gsm_mncc_rtp *rtp;

	memset(&data, 0, sizeof(data));
	rtp = (struct gsm_mncc_rtp *) &data[0];

	rtp->callref = callref;
	rtp->msg_type = cmd;
	rtp->ip = addr;
	rtp->port = port;
	rtp->payload_type = payload_type;
	rtp->payload_msg_type = payload_msg_type;
	mncc_recvmsg(net, NULL, cmd, (struct gsm_mncc *)data);
}

static void mncc_recv_rtp_sock(struct gsm_network *net, struct gsm_trans *trans, int cmd)
{
	struct gsm_lchan *lchan;
	int msg_type;

	lchan = trans->conn->lchan;
	switch (lchan->abis_ip.rtp_payload) {
	case RTP_PT_GSM_FULL:
		msg_type = GSM_TCHF_FRAME;
		break;
	case RTP_PT_GSM_EFR:
		msg_type = GSM_TCHF_FRAME_EFR;
		break;
	case RTP_PT_GSM_HALF:
		msg_type = GSM_TCHH_FRAME;
		break;
	case RTP_PT_AMR:
		msg_type = GSM_TCH_FRAME_AMR;
		break;
	default:
		LOGP(DMNCC, LOGL_ERROR, "%s unknown payload type %d\n",
			gsm_lchan_name(lchan), lchan->abis_ip.rtp_payload);
		msg_type = 0;
		break;
	}

	return mncc_recv_rtp(net, trans->callref, cmd,
			lchan->abis_ip.bound_ip,
			lchan->abis_ip.bound_port,
			lchan->abis_ip.rtp_payload,
			msg_type);
}

static void mncc_recv_rtp_err(struct gsm_network *net, uint32_t callref, int cmd)
{
	return mncc_recv_rtp(net, callref, cmd, 0, 0, 0, 0);
}
#endif

static int tch_rtp_create(struct gsm_network *net, uint32_t callref)
{
#if BEFORE_MSCSPLIT
	struct gsm_bts *bts;
	struct gsm_lchan *lchan;
	struct gsm_trans *trans;
	enum gsm48_chan_mode m;

	/* Find callref */
	trans = trans_find_by_callref(net, callref);
	if (!trans) {
		LOGP(DMNCC, LOGL_ERROR, "RTP create for non-existing trans\n");
		mncc_recv_rtp_err(net, callref, MNCC_RTP_CREATE);
		return -EIO;
	}
	log_set_context(LOG_CTX_VLR_SUBSCR, trans->vsub);
	if (!trans->conn) {
		LOGP(DMNCC, LOGL_NOTICE, "RTP create for trans without conn\n");
		mncc_recv_rtp_err(net, callref, MNCC_RTP_CREATE);
		return 0;
	}

	lchan = trans->conn->lchan;
	bts = lchan->ts->trx->bts;
	if (!is_ipaccess_bts(bts)) {
		/*
		 * I want this to be straight forward and have no audio flow
		 * through the nitb/osmo-mss system. This currently means that
		 * this will not work with BS11/Nokia type BTS. We would need
		 * to have a trau<->rtp bridge for these but still preferable
		 * in another process.
		 */
		LOGP(DMNCC, LOGL_ERROR, "RTP create only works with IP systems\n");
		mncc_recv_rtp_err(net, callref, MNCC_RTP_CREATE);
		return -EINVAL;
	}

	trans->conn->mncc_rtp_bridge = 1;
	/*
	 * *sigh* we need to pick a codec now. Pick the most generic one
	 * right now and hope we could fix that later on. This is very
	 * similiar to the routine above.
	 * Fallback to the internal MNCC mode to select a route.
	 */
	if (lchan->tch_mode == GSM48_CMODE_SIGN) {
		trans->conn->mncc_rtp_create_pending = 1;
		m = mncc_codec_for_mode(lchan->type);
		LOGP(DMNCC, LOGL_DEBUG, "RTP create: codec=%s, chan_type=%s\n",
		     get_value_string(gsm48_chan_mode_names, m),
		     get_value_string(gsm_chan_t_names, lchan->type));
		return gsm0808_assign_req(trans->conn, m,
				lchan->type != GSM_LCHAN_TCH_H);
	}

	mncc_recv_rtp_sock(trans->net, trans, MNCC_RTP_CREATE);
	return 0;
#else
	/* not implemented yet! */
	return -1;
#endif
}

static int tch_rtp_connect(struct gsm_network *net, void *arg)
{
#if BEFORE_MSCSPLIT
	struct gsm_lchan *lchan;
	struct gsm_trans *trans;
	struct gsm_mncc_rtp *rtp = arg;

	/* Find callref */
	trans = trans_find_by_callref(net, rtp->callref);
	if (!trans) {
		LOGP(DMNCC, LOGL_ERROR, "RTP connect for non-existing trans\n");
		mncc_recv_rtp_err(net, rtp->callref, MNCC_RTP_CONNECT);
		return -EIO;
	}
	log_set_context(LOG_CTX_VLR_SUBSCR, trans->vsub);
	if (!trans->conn) {
		LOGP(DMNCC, LOGL_ERROR, "RTP connect for trans without conn\n");
		mncc_recv_rtp_err(net, rtp->callref, MNCC_RTP_CONNECT);
		return 0;
	}

	lchan = trans->conn->lchan;
	LOGP(DMNCC, LOGL_DEBUG, "RTP connect: codec=%s, chan_type=%s\n",
		     get_value_string(gsm48_chan_mode_names,
				      mncc_codec_for_mode(lchan->type)),
		     get_value_string(gsm_chan_t_names, lchan->type));

	/* TODO: Check if payload_msg_type is compatible with what we have */
	if (rtp->payload_type != lchan->abis_ip.rtp_payload) {
		LOGP(DMNCC, LOGL_ERROR, "RTP connect with different RTP payload\n");
		mncc_recv_rtp_err(net, rtp->callref, MNCC_RTP_CONNECT);
	}

	/*
	 * FIXME: payload2 can't be sent with MDCX as the osmo-bts code
	 * complains about both rtp and rtp payload2 being present in the
	 * same package!
	 */
	trans->conn->mncc_rtp_connect_pending = 1;
	return rsl_ipacc_mdcx(lchan, rtp->ip, rtp->port, 0);
#else
	/* not implemented yet! */
	return -1;
#endif
}

#if BEFORE_MSCSPLIT
static int tch_rtp_signal(struct gsm_lchan *lchan, int signal)
{
	struct gsm_network *net;
	struct gsm_trans *tmp, *trans = NULL;

	net = lchan->ts->trx->bts->network;
	llist_for_each_entry(tmp, &net->trans_list, entry) {
		if (!tmp->conn)
			continue;
		if (tmp->conn->lchan != lchan && tmp->conn->ho_lchan != lchan)
			continue;
		trans = tmp;
		break;
	}

	if (!trans) {
		LOGP(DMNCC, LOGL_ERROR, "%s IPA abis signal but no transaction.\n",
			gsm_lchan_name(lchan));
		return 0;
	}

	switch (signal) {
	case S_ABISIP_CRCX_ACK:
		if (lchan->conn->mncc_rtp_create_pending) {
			lchan->conn->mncc_rtp_create_pending = 0;
			LOGP(DMNCC, LOGL_NOTICE, "%s sending pending RTP create ind.\n",
				gsm_lchan_name(lchan));
			mncc_recv_rtp_sock(net, trans, MNCC_RTP_CREATE);
		}
		/*
		 * TODO: this appears to be too early? Why not until after
		 * the handover detect or the handover complete?
		 */
		maybe_switch_for_handover(lchan);
		break;
	case S_ABISIP_MDCX_ACK:
		if (lchan->conn->mncc_rtp_connect_pending) {
			lchan->conn->mncc_rtp_connect_pending = 0;
			LOGP(DMNCC, LOGL_NOTICE, "%s sending pending RTP connect ind.\n",
				gsm_lchan_name(lchan));
			mncc_recv_rtp_sock(net, trans, MNCC_RTP_CONNECT);
		}
		break;
	}

	return 0;
}
#endif


static struct downstate {
	uint32_t	states;
	int		type;
	int		(*rout) (struct gsm_trans *trans, void *arg);
} downstatelist[] = {
	/* mobile originating call establishment */
	{SBIT(GSM_CSTATE_INITIATED), /* 5.2.1.2 */
	 MNCC_CALL_PROC_REQ, gsm48_cc_tx_call_proc_and_assign},
	{SBIT(GSM_CSTATE_INITIATED) | SBIT(GSM_CSTATE_MO_CALL_PROC), /* 5.2.1.2 | 5.2.1.5 */
	 MNCC_ALERT_REQ, gsm48_cc_tx_alerting},
	{SBIT(GSM_CSTATE_INITIATED) | SBIT(GSM_CSTATE_MO_CALL_PROC) | SBIT(GSM_CSTATE_CALL_DELIVERED), /* 5.2.1.2 | 5.2.1.6 | 5.2.1.6 */
	 MNCC_SETUP_RSP, gsm48_cc_tx_connect},
	{SBIT(GSM_CSTATE_MO_CALL_PROC), /* 5.2.1.4.2 */
	 MNCC_PROGRESS_REQ, gsm48_cc_tx_progress},
	/* mobile terminating call establishment */
	{SBIT(GSM_CSTATE_NULL), /* 5.2.2.1 */
	 MNCC_SETUP_REQ, gsm48_cc_tx_setup},
	{SBIT(GSM_CSTATE_CONNECT_REQUEST),
	 MNCC_SETUP_COMPL_REQ, gsm48_cc_tx_connect_ack},
	 /* signalling during call */
	{SBIT(GSM_CSTATE_ACTIVE),
	 MNCC_NOTIFY_REQ, gsm48_cc_tx_notify},
	{ALL_STATES - SBIT(GSM_CSTATE_NULL) - SBIT(GSM_CSTATE_RELEASE_REQ),
	 MNCC_FACILITY_REQ, gsm48_cc_tx_facility},
	{ALL_STATES,
	 MNCC_START_DTMF_RSP, gsm48_cc_tx_start_dtmf_ack},
	{ALL_STATES,
	 MNCC_START_DTMF_REJ, gsm48_cc_tx_start_dtmf_rej},
	{ALL_STATES,
	 MNCC_STOP_DTMF_RSP, gsm48_cc_tx_stop_dtmf_ack},
	{SBIT(GSM_CSTATE_ACTIVE),
	 MNCC_HOLD_CNF, gsm48_cc_tx_hold_ack},
	{SBIT(GSM_CSTATE_ACTIVE),
	 MNCC_HOLD_REJ, gsm48_cc_tx_hold_rej},
	{SBIT(GSM_CSTATE_ACTIVE),
	 MNCC_RETRIEVE_CNF, gsm48_cc_tx_retrieve_ack},
	{SBIT(GSM_CSTATE_ACTIVE),
	 MNCC_RETRIEVE_REJ, gsm48_cc_tx_retrieve_rej},
	{SBIT(GSM_CSTATE_ACTIVE),
	 MNCC_MODIFY_REQ, gsm48_cc_tx_modify},
	{SBIT(GSM_CSTATE_MO_ORIG_MODIFY),
	 MNCC_MODIFY_RSP, gsm48_cc_tx_modify_complete},
	{SBIT(GSM_CSTATE_MO_ORIG_MODIFY),
	 MNCC_MODIFY_REJ, gsm48_cc_tx_modify_reject},
	{SBIT(GSM_CSTATE_ACTIVE),
	 MNCC_USERINFO_REQ, gsm48_cc_tx_userinfo},
	/* clearing */
	{SBIT(GSM_CSTATE_INITIATED),
	 MNCC_REJ_REQ, gsm48_cc_tx_release_compl},
	{ALL_STATES - SBIT(GSM_CSTATE_NULL) - SBIT(GSM_CSTATE_DISCONNECT_IND) - SBIT(GSM_CSTATE_RELEASE_REQ) - SBIT(GSM_CSTATE_DISCONNECT_REQ), /* 5.4.4 */
	 MNCC_DISC_REQ, gsm48_cc_tx_disconnect},
	{ALL_STATES - SBIT(GSM_CSTATE_NULL) - SBIT(GSM_CSTATE_RELEASE_REQ), /* 5.4.3.2 */
	 MNCC_REL_REQ, gsm48_cc_tx_release},
	/* special */
	{ALL_STATES,
	 MNCC_LCHAN_MODIFY, _gsm48_lchan_modify},
};

#define DOWNSLLEN \
	(sizeof(downstatelist) / sizeof(struct downstate))


int mncc_tx_to_cc(struct gsm_network *net, int msg_type, void *arg)
{
	int i, rc = 0;
	struct gsm_trans *trans = NULL, *transt;
	struct gsm_subscriber_connection *conn = NULL;
#if BEFORE_MSCSPLIT
	struct gsm_bts *bts = NULL;
#endif
	struct gsm_mncc *data = arg, rel;

	DEBUGP(DMNCC, "receive message %s\n", get_mncc_name(msg_type));

	/* handle special messages */
	switch(msg_type) {
	case MNCC_BRIDGE:
		rc = tch_bridge(net, arg);
		if (rc < 0)
			disconnect_bridge(net, arg, -rc);
		return rc;
	case MNCC_FRAME_DROP:
		return tch_recv_mncc(net, data->callref, 0);
	case MNCC_FRAME_RECV:
		return tch_recv_mncc(net, data->callref, 1);
	case MNCC_RTP_CREATE:
		return tch_rtp_create(net, data->callref);
	case MNCC_RTP_CONNECT:
		return tch_rtp_connect(net, arg);
	case MNCC_RTP_FREE:
		/* unused right now */
		return -EIO;
	case GSM_TCHF_FRAME:
	case GSM_TCHF_FRAME_EFR:
	case GSM_TCHH_FRAME:
	case GSM_TCH_FRAME_AMR:
		/* Find callref */
		trans = trans_find_by_callref(net, data->callref);
		if (!trans) {
			LOGP(DMNCC, LOGL_ERROR, "TCH frame for non-existing trans\n");
			return -EIO;
		}
		log_set_context(LOG_CTX_VLR_SUBSCR, trans->vsub);
		if (!trans->conn) {
			LOGP(DMNCC, LOGL_NOTICE, "TCH frame for trans without conn\n");
			return 0;
		}
#if BEFORE_MSCSPLIT
		if (!trans->conn->lchan) {
			LOGP(DMNCC, LOGL_NOTICE, "TCH frame for trans without lchan\n");
			return 0;
		}
		if (trans->conn->lchan->type != GSM_LCHAN_TCH_F
		 && trans->conn->lchan->type != GSM_LCHAN_TCH_H) {
			/* This should be LOGL_ERROR or NOTICE, but
			 * unfortuantely it happens for a couple of frames at
			 * the beginning of every RTP connection */
			LOGP(DMNCC, LOGL_DEBUG, "TCH frame for lchan != TCH_F/TCH_H\n");
			return 0;
		}
		bts = trans->conn->lchan->ts->trx->bts;
		switch (bts->type) {
		case GSM_BTS_TYPE_NANOBTS:
		case GSM_BTS_TYPE_OSMOBTS:
			if (!trans->conn->lchan->abis_ip.rtp_socket) {
				DEBUGP(DMNCC, "TCH frame to lchan without RTP connection\n");
				return 0;
			}
			return rtp_send_frame(trans->conn->lchan->abis_ip.rtp_socket, arg);
		case GSM_BTS_TYPE_BS11:
		case GSM_BTS_TYPE_RBS2000:
		case GSM_BTS_TYPE_NOKIA_SITE:
			return trau_send_frame(trans->conn->lchan, arg);
		default:
			LOGP(DCC, LOGL_ERROR, "Unknown BTS type %u\n", bts->type);
		}
		return -EINVAL;
#else
		/* not implemented yet! */
		return -1;
#endif
	}

	memset(&rel, 0, sizeof(struct gsm_mncc));
	rel.callref = data->callref;

	/* Find callref */
	trans = trans_find_by_callref(net, data->callref);

	/* Callref unknown */
	if (!trans) {
		struct vlr_subscr *vsub;

		if (msg_type != MNCC_SETUP_REQ) {
			DEBUGP(DCC, "(bts - trx - ts - ti -- sub %s) "
				"Received '%s' from MNCC with "
				"unknown callref %d\n", data->called.number,
				get_mncc_name(msg_type), data->callref);
			/* Invalid call reference */
			return mncc_release_ind(net, NULL, data->callref,
						GSM48_CAUSE_LOC_PRN_S_LU,
						GSM48_CC_CAUSE_INVAL_TRANS_ID);
		}
		if (!data->called.number[0] && !data->imsi[0]) {
			DEBUGP(DCC, "(bts - trx - ts - ti) "
				"Received '%s' from MNCC with "
				"no number or IMSI\n", get_mncc_name(msg_type));
			/* Invalid number */
			return mncc_release_ind(net, NULL, data->callref,
						GSM48_CAUSE_LOC_PRN_S_LU,
						GSM48_CC_CAUSE_INV_NR_FORMAT);
		}
		/* New transaction due to setup, find subscriber */
		if (data->called.number[0])
			vsub = vlr_subscr_find_by_msisdn(net->vlr,
							 data->called.number);
		else
			vsub = vlr_subscr_find_by_imsi(net->vlr, data->imsi);

		/* update the subscriber we deal with */
		log_set_context(LOG_CTX_VLR_SUBSCR, vsub);

		/* If subscriber is not found */
		if (!vsub) {
			DEBUGP(DCC, "(bts - trx - ts - ti -- sub %s) "
				"Received '%s' from MNCC with "
				"unknown subscriber %s\n", data->called.number,
				get_mncc_name(msg_type), data->called.number);
			/* Unknown subscriber */
			return mncc_release_ind(net, NULL, data->callref,
						GSM48_CAUSE_LOC_PRN_S_LU,
						GSM48_CC_CAUSE_UNASSIGNED_NR);
		}
		/* If subscriber is not "attached" */
		if (!vsub->lac) {
			DEBUGP(DCC, "(bts - trx - ts - ti -- sub %s) "
				"Received '%s' from MNCC with "
				"detached subscriber %s\n", data->called.number,
				get_mncc_name(msg_type), data->called.number);
			vlr_subscr_put(vsub);
			/* Temporarily out of order */
			return mncc_release_ind(net, NULL, data->callref,
						GSM48_CAUSE_LOC_PRN_S_LU,
						GSM48_CC_CAUSE_DEST_OOO);
		}
		/* Create transaction */
		trans = trans_alloc(net, vsub, GSM48_PDISC_CC, 0xff, data->callref);
		if (!trans) {
			DEBUGP(DCC, "No memory for trans.\n");
			vlr_subscr_put(vsub);
			/* Ressource unavailable */
			mncc_release_ind(net, NULL, data->callref,
					 GSM48_CAUSE_LOC_PRN_S_LU,
					 GSM48_CC_CAUSE_RESOURCE_UNAVAIL);
			return -ENOMEM;
		}

		/* Find conn */
		conn = connection_for_subscr(vsub);

		/* If subscriber has no conn */
		if (!conn) {
			/* find transaction with this subscriber already paging */
			llist_for_each_entry(transt, &net->trans_list, entry) {
				/* Transaction of our conn? */
				if (transt == trans ||
				    transt->vsub != vsub)
					continue;
				DEBUGP(DCC, "(bts - trx - ts - ti -- sub %s) "
					"Received '%s' from MNCC with "
					"unallocated channel, paging already "
					"started for lac %d.\n",
					data->called.number,
					get_mncc_name(msg_type), vsub->lac);
				vlr_subscr_put(vsub);
				trans_free(trans);
				return 0;
			}
			/* store setup information until paging succeeds */
			memcpy(&trans->cc.msg, data, sizeof(struct gsm_mncc));

			/* Request a channel */
			trans->paging_request = subscr_request_conn(
							vsub,
							setup_trig_pag_evt,
							trans,
							"MNCC: establish call");
			if (!trans->paging_request) {
				LOGP(DCC, LOGL_ERROR, "Failed to allocate paging token.\n");
				vlr_subscr_put(vsub);
				trans_free(trans);
				return 0;
			}
			vlr_subscr_put(vsub);
			return 0;
		}

		/* Assign conn */
		trans->conn = msc_subscr_conn_get(conn);
		vlr_subscr_put(vsub);
	} else {
		/* update the subscriber we deal with */
		log_set_context(LOG_CTX_VLR_SUBSCR, trans->vsub);
	}

	if (trans->conn)
		conn = trans->conn;

	/* if paging did not respond yet */
	if (!conn) {
		DEBUGP(DCC, "(sub %s) "
			"Received '%s' from MNCC in paging state\n",
			vlr_subscr_msisdn_or_name(trans->vsub),
			get_mncc_name(msg_type));
		mncc_set_cause(&rel, GSM48_CAUSE_LOC_PRN_S_LU,
				GSM48_CC_CAUSE_NORM_CALL_CLEAR);
		if (msg_type == MNCC_REL_REQ)
			rc = mncc_recvmsg(net, trans, MNCC_REL_CNF, &rel);
		else
			rc = mncc_recvmsg(net, trans, MNCC_REL_IND, &rel);
		trans->callref = 0;
		trans_free(trans);
		return rc;
	}

	DEBUGP(DCC, "(ti %02x sub %s) "
		"Received '%s' from MNCC in state %d (%s)\n",
		trans->transaction_id,
		vlr_subscr_msisdn_or_name(trans->conn->vsub),
		get_mncc_name(msg_type), trans->cc.state,
		gsm48_cc_state_name(trans->cc.state));

	/* Find function for current state and message */
	for (i = 0; i < DOWNSLLEN; i++)
		if ((msg_type == downstatelist[i].type)
		 && ((1 << trans->cc.state) & downstatelist[i].states))
			break;
	if (i == DOWNSLLEN) {
		DEBUGP(DCC, "Message unhandled at this state.\n");
		return 0;
	}

	rc = downstatelist[i].rout(trans, arg);

	return rc;
}


static struct datastate {
	uint32_t	states;
	int		type;
	int		(*rout) (struct gsm_trans *trans, struct msgb *msg);
} datastatelist[] = {
	/* mobile originating call establishment */
	{SBIT(GSM_CSTATE_NULL), /* 5.2.1.2 */
	 GSM48_MT_CC_SETUP, gsm48_cc_rx_setup},
	{SBIT(GSM_CSTATE_NULL), /* 5.2.1.2 */
	 GSM48_MT_CC_EMERG_SETUP, gsm48_cc_rx_setup},
	{SBIT(GSM_CSTATE_CONNECT_IND), /* 5.2.1.2 */
	 GSM48_MT_CC_CONNECT_ACK, gsm48_cc_rx_connect_ack},
	/* mobile terminating call establishment */
	{SBIT(GSM_CSTATE_CALL_PRESENT), /* 5.2.2.3.2 */
	 GSM48_MT_CC_CALL_CONF, gsm48_cc_rx_call_conf},
	{SBIT(GSM_CSTATE_CALL_PRESENT) | SBIT(GSM_CSTATE_MO_TERM_CALL_CONF), /* ???? | 5.2.2.3.2 */
	 GSM48_MT_CC_ALERTING, gsm48_cc_rx_alerting},
	{SBIT(GSM_CSTATE_CALL_PRESENT) | SBIT(GSM_CSTATE_MO_TERM_CALL_CONF) | SBIT(GSM_CSTATE_CALL_RECEIVED), /* (5.2.2.6) | 5.2.2.6 | 5.2.2.6 */
	 GSM48_MT_CC_CONNECT, gsm48_cc_rx_connect},
	 /* signalling during call */
	{ALL_STATES - SBIT(GSM_CSTATE_NULL),
	 GSM48_MT_CC_FACILITY, gsm48_cc_rx_facility},
	{SBIT(GSM_CSTATE_ACTIVE),
	 GSM48_MT_CC_NOTIFY, gsm48_cc_rx_notify},
	{ALL_STATES,
	 GSM48_MT_CC_START_DTMF, gsm48_cc_rx_start_dtmf},
	{ALL_STATES,
	 GSM48_MT_CC_STOP_DTMF, gsm48_cc_rx_stop_dtmf},
	{ALL_STATES,
	 GSM48_MT_CC_STATUS_ENQ, gsm48_cc_rx_status_enq},
	{SBIT(GSM_CSTATE_ACTIVE),
	 GSM48_MT_CC_HOLD, gsm48_cc_rx_hold},
	{SBIT(GSM_CSTATE_ACTIVE),
	 GSM48_MT_CC_RETR, gsm48_cc_rx_retrieve},
	{SBIT(GSM_CSTATE_ACTIVE),
	 GSM48_MT_CC_MODIFY, gsm48_cc_rx_modify},
	{SBIT(GSM_CSTATE_MO_TERM_MODIFY),
	 GSM48_MT_CC_MODIFY_COMPL, gsm48_cc_rx_modify_complete},
	{SBIT(GSM_CSTATE_MO_TERM_MODIFY),
	 GSM48_MT_CC_MODIFY_REJECT, gsm48_cc_rx_modify_reject},
	{SBIT(GSM_CSTATE_ACTIVE),
	 GSM48_MT_CC_USER_INFO, gsm48_cc_rx_userinfo},
	/* clearing */
	{ALL_STATES - SBIT(GSM_CSTATE_NULL) - SBIT(GSM_CSTATE_RELEASE_REQ), /* 5.4.3.2 */
	 GSM48_MT_CC_DISCONNECT, gsm48_cc_rx_disconnect},
	{ALL_STATES - SBIT(GSM_CSTATE_NULL), /* 5.4.4.1.2.2 */
	 GSM48_MT_CC_RELEASE, gsm48_cc_rx_release},
	{ALL_STATES, /* 5.4.3.4 */
	 GSM48_MT_CC_RELEASE_COMPL, gsm48_cc_rx_release_compl},
};

#define DATASLLEN \
	(sizeof(datastatelist) / sizeof(struct datastate))

static int gsm0408_rcv_cc(struct gsm_subscriber_connection *conn, struct msgb *msg)
{
	struct gsm48_hdr *gh = msgb_l3(msg);
	uint8_t msg_type = gsm48_hdr_msg_type(gh);
	uint8_t transaction_id = gsm48_hdr_trans_id_flip_ti(gh);
	struct gsm_trans *trans = NULL;
	int i, rc = 0;

	if (msg_type & 0x80) {
		DEBUGP(DCC, "MSG 0x%2x not defined for PD error\n", msg_type);
		return -EINVAL;
	}

	if (!conn->vsub) {
		LOGP(DCC, LOGL_ERROR, "Invalid conn: no subscriber\n");
		return -EINVAL;
	}

	/* Find transaction */
	trans = trans_find_by_id(conn, GSM48_PDISC_CC, transaction_id);

#if BEFORE_MSCSPLIT
	DEBUGP(DCC, "(bts %d trx %d ts %d ti %x sub %s) "
		"Received '%s' from MS in state %d (%s)\n",
		conn->bts->nr, conn->lchan->ts->trx->nr, conn->lchan->ts->nr,
		transaction_id, vlr_subscr_msisdn_or_name(conn->vsub),
		gsm48_cc_msg_name(msg_type), trans?(trans->cc.state):0,
		gsm48_cc_state_name(trans?(trans->cc.state):0));
#endif

	/* Create transaction */
	if (!trans) {
		DEBUGP(DCC, "Unknown transaction ID %x, "
			"creating new trans.\n", transaction_id);
		/* Create transaction */
		trans = trans_alloc(conn->network, conn->vsub,
				    GSM48_PDISC_CC,
				    transaction_id, new_callref++);
		if (!trans) {
			DEBUGP(DCC, "No memory for trans.\n");
			rc = gsm48_tx_simple(conn,
					     GSM48_PDISC_CC | (transaction_id << 4),
					     GSM48_MT_CC_RELEASE_COMPL);
			return -ENOMEM;
		}
		/* Assign transaction */
		trans->conn = msc_subscr_conn_get(conn);
		cm_service_request_concludes(conn, msg);
	}

	/* find function for current state and message */
	for (i = 0; i < DATASLLEN; i++)
		if ((msg_type == datastatelist[i].type)
		 && ((1 << trans->cc.state) & datastatelist[i].states))
			break;
	if (i == DATASLLEN) {
		DEBUGP(DCC, "Message unhandled at this state.\n");
		return 0;
	}

	assert(trans->vsub);

	rc = datastatelist[i].rout(trans, msg);

	msc_subscr_conn_communicating(conn);
	return rc;
}

static bool msg_is_initially_permitted(const struct gsm48_hdr *hdr)
{
	uint8_t pdisc = gsm48_hdr_pdisc(hdr);
	uint8_t msg_type = gsm48_hdr_msg_type(hdr);

	switch (pdisc) {
	case GSM48_PDISC_MM:
		switch (msg_type) {
		case GSM48_MT_MM_LOC_UPD_REQUEST:
		case GSM48_MT_MM_CM_SERV_REQ:
		case GSM48_MT_MM_AUTH_RESP:
		case GSM48_MT_MM_AUTH_FAIL:
		case GSM48_MT_MM_ID_RESP:
		case GSM48_MT_MM_TMSI_REALL_COMPL:
		case GSM48_MT_MM_IMSI_DETACH_IND:
			return true;
		default:
			break;
		}
		break;
	case GSM48_PDISC_RR:
		switch (msg_type) {
		case GSM48_MT_RR_CIPH_M_COMPL:
		case GSM48_MT_RR_PAG_RESP:
			return true;
		default:
			break;
		}
		break;
	default:
		break;
	}

	return false;
}

void cm_service_request_concludes(struct gsm_subscriber_connection *conn,
				  struct msgb *msg)
{

	/* If a CM Service Request was received before, this is the request the
	 * conn was opened for. No need to wait for further messages. */

	if (!conn->received_cm_service_request)
		return;

	if (log_check_level(DMM, LOGL_DEBUG)) {
		struct gsm48_hdr *gh = msgb_l3(msg);
		uint8_t pdisc = gsm48_hdr_pdisc(gh);
		uint8_t msg_type = gsm48_hdr_msg_type(gh);

		DEBUGP(DMM, "%s: rx msg %s:"
		       " received_cm_service_request changes to false\n",
		       vlr_subscr_name(conn->vsub),
		       gsm48_pdisc_msgtype_name(pdisc, msg_type));
	}
	conn->received_cm_service_request = false;
}


/* Main entry point for GSM 04.08/44.008 Layer 3 data (e.g. from the BSC). */
int gsm0408_dispatch(struct gsm_subscriber_connection *conn, struct msgb *msg)
{
	struct gsm48_hdr *gh;
	uint8_t pdisc;
	int rc = 0;

	OSMO_ASSERT(msg->l3h)
	OSMO_ASSERT(conn);
	OSMO_ASSERT(msg);

	gh = msgb_l3(msg);
	pdisc = gsm48_hdr_pdisc(gh);

	LOGP(DRLL, LOGL_DEBUG, "Dispatching 04.08 message %s (0x%x:0x%x)\n",
	     gsm48_pdisc_msgtype_name(pdisc, gsm48_hdr_msg_type(gh)),
	     pdisc, gsm48_hdr_msg_type(gh));

	if (!msc_subscr_conn_is_accepted(conn)
	    && !msg_is_initially_permitted(gh)) {
		LOGP(DRLL, LOGL_ERROR,
		     "subscr %s: Message not permitted for initial conn: %s\n",
		     vlr_subscr_name(conn->vsub),
		     gsm48_pdisc_msgtype_name(pdisc, gsm48_hdr_msg_type(gh)));
		return -EACCES;
	}

	if (conn->vsub && conn->vsub->cs.attached_via_ran != conn->via_ran) {
		LOGP(DMM, LOGL_ERROR,
		     "%s: Illegal situation: RAN type mismatch:"
		     " attached via %s, received message via %s\n",
		     vlr_subscr_name(conn->vsub),
		     ran_type_name(conn->vsub->cs.attached_via_ran),
		     ran_type_name(conn->via_ran));
		return -EACCES;
	}

#if 0
	if (silent_call_reroute(conn, msg))
		return silent_call_rx(conn, msg);
#endif

	switch (pdisc) {
	case GSM48_PDISC_CC:
		rc = gsm0408_rcv_cc(conn, msg);
		break;
	case GSM48_PDISC_MM:
		rc = gsm0408_rcv_mm(conn, msg);
		break;
	case GSM48_PDISC_RR:
		rc = gsm0408_rcv_rr(conn, msg);
		break;
	case GSM48_PDISC_SMS:
		rc = gsm0411_rcv_sms(conn, msg);
		break;
	case GSM48_PDISC_MM_GPRS:
	case GSM48_PDISC_SM_GPRS:
		LOGP(DRLL, LOGL_NOTICE, "Unimplemented "
			"GSM 04.08 discriminator 0x%02x\n", pdisc);
		rc = -ENOTSUP;
		break;
	case GSM48_PDISC_NC_SS:
		rc = handle_rcv_ussd(conn, msg);
		break;
	default:
		LOGP(DRLL, LOGL_NOTICE, "Unknown "
			"GSM 04.08 discriminator 0x%02x\n", pdisc);
		rc = -EINVAL;
		break;
	}

	return rc;
}

/***********************************************************************
 * VLR integration
 ***********************************************************************/

/* VLR asks us to send an authentication request */
static int msc_vlr_tx_auth_req(void *msc_conn_ref, struct gsm_auth_tuple *at,
			       bool send_autn)
{
	struct gsm_subscriber_connection *conn = msc_conn_ref;
	return gsm48_tx_mm_auth_req(conn, at->vec.rand,
				    send_autn? at->vec.autn : NULL,
				    at->key_seq);
}

/* VLR asks us to send an authentication reject */
static int msc_vlr_tx_auth_rej(void *msc_conn_ref)
{
	struct gsm_subscriber_connection *conn = msc_conn_ref;
	return gsm48_tx_mm_auth_rej(conn);
}

/* VLR asks us to transmit an Identity Request of given type */
static int msc_vlr_tx_id_req(void *msc_conn_ref, uint8_t mi_type)
{
	struct gsm_subscriber_connection *conn = msc_conn_ref;
	return mm_tx_identity_req(conn, mi_type);
}

/* VLR asks us to transmit a Location Update Accept */
static int msc_vlr_tx_lu_acc(void *msc_conn_ref, uint32_t send_tmsi)
{
	struct gsm_subscriber_connection *conn = msc_conn_ref;
	return gsm0408_loc_upd_acc(conn, send_tmsi);
}

/* VLR asks us to transmit a Location Update Reject */
static int msc_vlr_tx_lu_rej(void *msc_conn_ref, uint8_t cause)
{
	struct gsm_subscriber_connection *conn = msc_conn_ref;
	return gsm0408_loc_upd_rej(conn, cause);
}

/* VLR asks us to transmit a CM Service Accept */
static int msc_vlr_tx_cm_serv_acc(void *msc_conn_ref)
{
	struct gsm_subscriber_connection *conn = msc_conn_ref;
	return msc_gsm48_tx_mm_serv_ack(conn);
}

static int msc_vlr_tx_common_id(void *msc_conn_ref)
{
	struct gsm_subscriber_connection *conn = msc_conn_ref;
	return msc_tx_common_id(conn);
}

/* VLR asks us to transmit a CM Service Reject */
static int msc_vlr_tx_cm_serv_rej(void *msc_conn_ref, enum vlr_proc_arq_result result)
{
	uint8_t cause;
	struct gsm_subscriber_connection *conn = msc_conn_ref;
	conn->received_cm_service_request = false;

	switch (result) {
	default:
	case VLR_PR_ARQ_RES_NONE:
	case VLR_PR_ARQ_RES_SYSTEM_FAILURE:
	case VLR_PR_ARQ_RES_UNKNOWN_ERROR:
		cause = GSM48_REJECT_NETWORK_FAILURE;
		break;
	case VLR_PR_ARQ_RES_ILLEGAL_SUBSCR:
		cause = GSM48_REJECT_LOC_NOT_ALLOWED;
		break;
	case VLR_PR_ARQ_RES_UNIDENT_SUBSCR:
		cause = GSM48_REJECT_INVALID_MANDANTORY_INF;
		break;
	case VLR_PR_ARQ_RES_ROAMING_NOTALLOWED:
		cause = GSM48_REJECT_ROAMING_NOT_ALLOWED;
		break;
	case VLR_PR_ARQ_RES_ILLEGAL_EQUIP:
		cause = GSM48_REJECT_ILLEGAL_MS;
		break;
	case VLR_PR_ARQ_RES_TIMEOUT:
		cause = GSM48_REJECT_CONGESTION;
		break;
	};

	return msc_gsm48_tx_mm_serv_rej(conn, cause);
}

/* VLR asks us to start using ciphering */
static int msc_vlr_set_ciph_mode(void *msc_conn_ref,
				 enum vlr_ciph ciph,
				 bool retrieve_imeisv)
{
	struct gsm_subscriber_connection *conn = msc_conn_ref;
	struct vlr_subscr *vsub;
	struct gsm_auth_tuple *tuple;

	if (!conn || !conn->vsub) {
		LOGP(DMM, LOGL_ERROR, "Cannot send Ciphering Mode Command to"
		     " NULL conn/subscriber");
		return -EINVAL;
	}

	vsub = conn->vsub;
	tuple = vsub->last_tuple;

	if (!tuple) {
		LOGP(DMM, LOGL_ERROR, "subscr %s: Cannot send Ciphering Mode"
		     " Command: no auth tuple available\n",
		     vlr_subscr_name(vsub));
		return -EINVAL;
	}

	switch (conn->via_ran) {
	case RAN_GERAN_A:
		DEBUGP(DMM, "-> CIPHER MODE COMMAND %s\n",
		       vlr_subscr_name(conn->vsub));
		return a_iface_tx_cipher_mode(conn, ciph, tuple->vec.kc, 8,
					      retrieve_imeisv);
	case RAN_UTRAN_IU:
		DEBUGP(DMM, "-> SECURITY MODE CONTROL %s\n",
		       vlr_subscr_name(conn->vsub));
		return iu_tx_sec_mode_cmd(conn->iu.ue_ctx, tuple, 0, 1);

	default:
		break;
	}
	LOGP(DMM, LOGL_ERROR,
	     "%s: cannot start ciphering, unknown RAN type %d\n",
	     vlr_subscr_name(conn->vsub), conn->via_ran);
	return -ENOTSUP;
}

void msc_rx_sec_mode_compl(struct gsm_subscriber_connection *conn)
{
	struct vlr_ciph_result vlr_res = {};

	if (!conn || !conn->vsub) {
		LOGP(DMM, LOGL_ERROR,
		     "Rx Security Mode Complete for invalid conn\n");
		return;
	}

	DEBUGP(DMM, "<- SECURITY MODE COMPLETE %s\n",
	       vlr_subscr_name(conn->vsub));

	vlr_res.cause = VLR_CIPH_COMPL;
	vlr_subscr_rx_ciph_res(conn->vsub, &vlr_res);
}

/* VLR informs us that the subscriber data has somehow been modified */
static void msc_vlr_subscr_update(struct vlr_subscr *subscr)
{
	/* FIXME */
}

/* VLR informs us that the subscriber has been associated with a conn */
static void msc_vlr_subscr_assoc(void *msc_conn_ref,
				 struct vlr_subscr *vsub)
{
	struct gsm_subscriber_connection *conn = msc_conn_ref;
	OSMO_ASSERT(!conn->vsub);
	conn->vsub = vlr_subscr_get(vsub);
	conn->vsub->cs.attached_via_ran = conn->via_ran;
}

/* operations that we need to implement for libvlr */
static const struct vlr_ops msc_vlr_ops = {
	.tx_auth_req = msc_vlr_tx_auth_req,
	.tx_auth_rej = msc_vlr_tx_auth_rej,
	.tx_id_req = msc_vlr_tx_id_req,
	.tx_lu_acc = msc_vlr_tx_lu_acc,
	.tx_lu_rej = msc_vlr_tx_lu_rej,
	.tx_cm_serv_acc = msc_vlr_tx_cm_serv_acc,
	.tx_cm_serv_rej = msc_vlr_tx_cm_serv_rej,
	.set_ciph_mode = msc_vlr_set_ciph_mode,
	.tx_common_id = msc_vlr_tx_common_id,
	.subscr_update = msc_vlr_subscr_update,
	.subscr_assoc = msc_vlr_subscr_assoc,
};

/* Allocate net->vlr so that the VTY may configure the VLR's data structures */
int msc_vlr_alloc(struct gsm_network *net)
{
	net->vlr = vlr_alloc(net, &msc_vlr_ops);
	if (!net->vlr)
		return -ENOMEM;
	net->vlr->user_ctx = net;
	return 0;
}

/* Launch the VLR, i.e. its GSUP connection */
int msc_vlr_start(struct gsm_network *net)
{
	OSMO_ASSERT(net->vlr);
	return vlr_start("MSC", net->vlr, net->gsup_server_addr_str,
			 net->gsup_server_port);
}

#if BEFORE_MSCSPLIT
/*
 * This will be run by the linker when loading the DSO. We use it to
 * do system initialization, e.g. registration of signal handlers.
 */
static __attribute__((constructor)) void on_dso_load_0408(void)
{
	osmo_signal_register_handler(SS_ABISIP, handle_abisip_signal, NULL);
}
#endif
