/* GSM Mobile Radio Interface Layer 3 messages on the A-bis interface 
 * 3GPP TS 04.08 version 7.21.0 Release 1998 / ETSI TS 100 940 V7.21.0 */

/* (C) 2008-2009 by Harald Welte <laforge@gnumonks.org>
 * (C) 2008, 2009 by Holger Hans Peter Freyther <zecke@selfish.org>
 *
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


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <netinet/in.h>

#include <openbsc/db.h>
#include <openbsc/msgb.h>
#include <openbsc/tlv.h>
#include <openbsc/debug.h>
#include <openbsc/gsm_data.h>
#include <openbsc/gsm_utils.h>
#include <openbsc/gsm_subscriber.h>
#include <openbsc/gsm_04_11.h>
#include <openbsc/gsm_04_08.h>
#include <openbsc/abis_rsl.h>
#include <openbsc/chan_alloc.h>
#include <openbsc/paging.h>
#include <openbsc/signal.h>
#include <openbsc/trau_frame.h>
#include <openbsc/trau_mux.h>
#include <openbsc/rtp_proxy.h>
#include <openbsc/talloc.h>
#include <openbsc/transaction.h>
#include <openbsc/ussd.h>

#define GSM_MAX_FACILITY       128
#define GSM_MAX_SSVERSION      128
#define GSM_MAX_USERUSER       128

void *tall_locop_ctx;

extern int ipacc_rtp_direct;

static const struct tlv_definition rsl_att_tlvdef = {
	.def = {
		[GSM48_IE_MOBILE_ID]	= { TLV_TYPE_TLV },
		[GSM48_IE_NAME_LONG]	= { TLV_TYPE_TLV },
		[GSM48_IE_NAME_SHORT]	= { TLV_TYPE_TLV },
		[GSM48_IE_UTC]		= { TLV_TYPE_TV },
		[GSM48_IE_NET_TIME_TZ]	= { TLV_TYPE_FIXED, 7 },
		[GSM48_IE_LSA_IDENT]	= { TLV_TYPE_TLV },

		[GSM48_IE_BEARER_CAP]	= { TLV_TYPE_TLV },
		[GSM48_IE_CAUSE]	= { TLV_TYPE_TLV },
		[GSM48_IE_CC_CAP]	= { TLV_TYPE_TLV },
		[GSM48_IE_ALERT]	= { TLV_TYPE_TLV },
		[GSM48_IE_FACILITY]	= { TLV_TYPE_TLV },
		[GSM48_IE_PROGR_IND]	= { TLV_TYPE_TLV },
		[GSM48_IE_AUX_STATUS]	= { TLV_TYPE_TLV },
		[GSM48_IE_NOTIFY]	= { TLV_TYPE_TV },
		[GSM48_IE_KPD_FACILITY]	= { TLV_TYPE_TV },
		[GSM48_IE_SIGNAL]	= { TLV_TYPE_TV },
		[GSM48_IE_CONN_BCD]	= { TLV_TYPE_TLV },
		[GSM48_IE_CONN_SUB]	= { TLV_TYPE_TLV },
		[GSM48_IE_CALLING_BCD]	= { TLV_TYPE_TLV },
		[GSM48_IE_CALLING_SUB]	= { TLV_TYPE_TLV },
		[GSM48_IE_CALLED_BCD]	= { TLV_TYPE_TLV },
		[GSM48_IE_CALLED_SUB]	= { TLV_TYPE_TLV },
		[GSM48_IE_REDIR_BCD]	= { TLV_TYPE_TLV },
		[GSM48_IE_REDIR_SUB]	= { TLV_TYPE_TLV },
		[GSM48_IE_LOWL_COMPAT]	= { TLV_TYPE_TLV },
		[GSM48_IE_HIGHL_COMPAT]	= { TLV_TYPE_TLV },
		[GSM48_IE_USER_USER]	= { TLV_TYPE_TLV },
		[GSM48_IE_SS_VERS]	= { TLV_TYPE_TLV },
		[GSM48_IE_MORE_DATA]	= { TLV_TYPE_T },
		[GSM48_IE_CLIR_SUPP]	= { TLV_TYPE_T },
		[GSM48_IE_CLIR_INVOC]	= { TLV_TYPE_T },
		[GSM48_IE_REV_C_SETUP]	= { TLV_TYPE_T },
		[GSM48_IE_REPEAT_CIR]   = { TLV_TYPE_T },
		[GSM48_IE_REPEAT_SEQ]   = { TLV_TYPE_T },
		/* FIXME: more elements */
	},
};

static const char *rr_cause_names[] = {
	[GSM48_RR_CAUSE_NORMAL]			= "Normal event",
	[GSM48_RR_CAUSE_ABNORMAL_UNSPEC]	= "Abnormal release, unspecified",
	[GSM48_RR_CAUSE_ABNORMAL_UNACCT]	= "Abnormal release, channel unacceptable",
	[GSM48_RR_CAUSE_ABNORMAL_TIMER]		= "Abnormal release, timer expired",
	[GSM48_RR_CAUSE_ABNORMAL_NOACT]		= "Abnormal release, no activity on radio path",
	[GSM48_RR_CAUSE_PREMPTIVE_REL]		= "Preemptive release",
	[GSM48_RR_CAUSE_HNDOVER_IMP]		= "Handover impossible, timing advance out of range",
	[GSM48_RR_CAUSE_CHAN_MODE_UNACCT]	= "Channel mode unacceptable",
	[GSM48_RR_CAUSE_FREQ_NOT_IMPL]		= "Frequency not implemented",
	[GSM48_RR_CAUSE_CALL_CLEARED]		= "Call already cleared",
	[GSM48_RR_CAUSE_SEMANT_INCORR]		= "Semantically incorrect message",
	[GSM48_RR_CAUSE_INVALID_MAND_INF]	= "Invalid mandatory information",
	[GSM48_RR_CAUSE_MSG_TYPE_N]		= "Message type non-existant or not implemented",
	[GSM48_RR_CAUSE_MSG_TYPE_N_COMPAT]	= "Message type not compatible with protocol state",
	[GSM48_RR_CAUSE_COND_IE_ERROR]		= "Conditional IE error",
	[GSM48_RR_CAUSE_NO_CELL_ALLOC_A]	= "No cell allocation available",
	[GSM48_RR_CAUSE_PROT_ERROR_UNSPC]	= "Protocol error unspecified",
};

static const char *cc_state_names[] = {
	"NULL",
	"INITIATED",
	"illegal state 2",
	"MO_CALL_PROC",
	"CALL_DELIVERED",
	"illegal state 5",
	"CALL_PRESENT",
	"CALL_RECEIVED",
	"CONNECT_REQUEST",
	"MO_TERM_CALL_CONF",
	"ACTIVE",
	"DISCONNECT_REQ",
	"DISCONNECT_IND",
	"illegal state 13",
	"illegal state 14",
	"illegal state 15",
	"illegal state 16",
	"illegal state 17",
	"illegal state 18",
	"RELEASE_REQ",
	"illegal state 20",
	"illegal state 21",
	"illegal state 22",
	"illegal state 23",
	"illegal state 24",
	"illegal state 25",
	"MO_ORIG_MODIFY",
	"MO_TERM_MODIFY",
	"CONNECT_IND",
	"illegal state 29",
	"illegal state 30",
	"illegal state 31",
};

static char strbuf[64];

static const char *rr_cause_name(u_int8_t cause)
{
	if (cause < ARRAY_SIZE(rr_cause_names) &&
	    rr_cause_names[cause])
		return rr_cause_names[cause];

	snprintf(strbuf, sizeof(strbuf), "0x%02x", cause);
	return strbuf;
}

static void parse_meas_rep(struct gsm_meas_rep *rep, const u_int8_t *data,
			   int len)
{
	memset(rep, 0, sizeof(*rep));

	if (data[0] & 0x80)
		rep->flags |= MEAS_REP_F_BA1;
	if (data[0] & 0x40)
		rep->flags |= MEAS_REP_F_DTX;
	if ((data[1] & 0x40) == 0x00)
		rep->flags |= MEAS_REP_F_VALID;

	rep->rxlev_full = data[0] & 0x3f;
	rep->rxlev_sub = data[1] & 0x3f;
	rep->rxqual_full = (data[3] >> 4) & 0x7;
	rep->rxqual_sub = (data[3] >> 1) & 0x7;
	rep->num_cell = data[4] >> 6 | ((data[3] & 0x01) << 2);
	if (rep->num_cell < 1)
		return;

	/* an encoding nightmare in perfection */

	rep->cell[0].rxlev = data[4] & 0x3f;
	rep->cell[0].bcch_freq = data[5] >> 2;
	rep->cell[0].bsic = ((data[5] & 0x03) << 3) | (data[6] >> 5);
	if (rep->num_cell < 2)
		return;

	rep->cell[1].rxlev = ((data[6] & 0x1f) << 1) | (data[7] >> 7);
	rep->cell[1].bcch_freq = (data[7] >> 2) & 0x1f;
	rep->cell[1].bsic = ((data[7] & 0x03) << 4) | (data[8] >> 4);
	if (rep->num_cell < 3)
		return;

	rep->cell[2].rxlev = ((data[8] & 0x0f) << 2) | (data[9] >> 6);
	rep->cell[2].bcch_freq = (data[9] >> 1) & 0x1f;
	rep->cell[2].bsic = ((data[9] & 0x01) << 6) | (data[10] >> 3);
	if (rep->num_cell < 4)
		return;

	rep->cell[3].rxlev = ((data[10] & 0x07) << 3) | (data[11] >> 5);
	rep->cell[3].bcch_freq = data[11] & 0x1f;
	rep->cell[3].bsic = data[12] >> 2;
	if (rep->num_cell < 5)
		return;

	rep->cell[4].rxlev = ((data[12] & 0x03) << 4) | (data[13] >> 4);
	rep->cell[4].bcch_freq = ((data[13] & 0xf) << 1) | (data[14] >> 7);
	rep->cell[4].bsic = (data[14] >> 1) & 0x3f;
	if (rep->num_cell < 6)
		return;

	rep->cell[5].rxlev = ((data[14] & 0x01) << 5) | (data[15] >> 3);
	rep->cell[5].bcch_freq = ((data[15] & 0x07) << 2) | (data[16] >> 6);
	rep->cell[5].bsic = data[16] & 0x3f;
}

int gsm0408_loc_upd_acc(struct gsm_lchan *lchan, u_int32_t tmsi);
static int gsm48_tx_simple(struct gsm_lchan *lchan,
			   u_int8_t pdisc, u_int8_t msg_type);
static void schedule_reject(struct gsm_lchan *lchan);

struct gsm_lai {
	u_int16_t mcc;
	u_int16_t mnc;
	u_int16_t lac;
};

static int reject_cause = 0;
void gsm0408_set_reject_cause(int cause)
{
	reject_cause = cause;
}

static u_int32_t new_callref = 0x80000001;

static int authorize_subscriber(struct gsm_loc_updating_operation *loc,
				struct gsm_subscriber *subscriber)
{
	if (!subscriber)
		return 0;

	/*
	 * Do not send accept yet as more information should arrive. Some
	 * phones will not send us the information and we will have to check
	 * what we want to do with that.
	 */
	if (loc && (loc->waiting_for_imsi || loc->waiting_for_imei))
		return 0;

	switch (subscriber->net->auth_policy) {
	case GSM_AUTH_POLICY_CLOSED:
		return subscriber->authorized;
	case GSM_AUTH_POLICY_TOKEN:
		if (subscriber->authorized)
			return subscriber->authorized;
		return (subscriber->flags & GSM_SUBSCRIBER_FIRST_CONTACT);
	case GSM_AUTH_POLICY_ACCEPT_ALL:
		return 1;
	default:
		return 0;
	}
}

static void release_loc_updating_req(struct gsm_lchan *lchan)
{
	if (!lchan->loc_operation)
		return;

	bsc_del_timer(&lchan->loc_operation->updating_timer);
	talloc_free(lchan->loc_operation);
	lchan->loc_operation = 0;
	put_lchan(lchan);
}

static void allocate_loc_updating_req(struct gsm_lchan *lchan)
{
	use_lchan(lchan);
	release_loc_updating_req(lchan);

	lchan->loc_operation = talloc_zero(tall_locop_ctx,
					   struct gsm_loc_updating_operation);
}

static int gsm0408_authorize(struct gsm_lchan *lchan, struct msgb *msg)
{
	if (authorize_subscriber(lchan->loc_operation, lchan->subscr)) {
		int rc;

		db_subscriber_alloc_tmsi(lchan->subscr);
		release_loc_updating_req(lchan);
		rc = gsm0408_loc_upd_acc(msg->lchan, lchan->subscr->tmsi);
		/* call subscr_update after putting the loc_upd_acc
		 * in the transmit queue, since S_SUBSCR_ATTACHED might
		 * trigger further action like SMS delivery */
		subscr_update(lchan->subscr, msg->trx->bts,
			      GSM_SUBSCRIBER_UPDATE_ATTACHED);
		return rc;
	}

	return 0;
}

static int gsm0408_handle_lchan_signal(unsigned int subsys, unsigned int signal,
					void *handler_data, void *signal_data)
{
	struct gsm_trans *trans, *temp;

	if (subsys != SS_LCHAN || signal != S_LCHAN_UNEXPECTED_RELEASE)
		return 0;

	/*
	 * Cancel any outstanding location updating request
	 * operation taking place on the lchan.
	 */
	struct gsm_lchan *lchan = (struct gsm_lchan *)signal_data;
	if (!lchan)
		return 0;

	release_loc_updating_req(lchan);

	/* Free all transactions that are associated with the released lchan */
	/* FIXME: this is not neccessarily the right thing to do, we should
	 * only set trans->lchan to NULL and wait for another lchan to be
	 * established to the same MM entity (phone/subscriber) */
	llist_for_each_entry_safe(trans, temp, &lchan->ts->trx->bts->network->trans_list, entry) {
		if (trans->lchan == lchan)
			trans_free(trans);
	}

	return 0;
}

static const char bcd_num_digits[] = {
	'0', '1', '2', '3', '4', '5', '6', '7', 
	'8', '9', '*', '#', 'a', 'b', 'c', '\0'
};

/* decode a 'called/calling/connect party BCD number' as in 10.5.4.7 */
int decode_bcd_number(char *output, int output_len, const u_int8_t *bcd_lv,
		      int h_len)
{
	u_int8_t in_len = bcd_lv[0];
	int i;

	for (i = 1 + h_len; i <= in_len; i++) {
		/* lower nibble */
		output_len--;
		if (output_len <= 1)
			break;
		*output++ = bcd_num_digits[bcd_lv[i] & 0xf];

		/* higher nibble */
		output_len--;
		if (output_len <= 1)
			break;
		*output++ = bcd_num_digits[bcd_lv[i] >> 4];
	}
	if (output_len >= 1)
		*output++ = '\0';

	return 0;
}

/* convert a single ASCII character to call-control BCD */
static int asc_to_bcd(const char asc)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(bcd_num_digits); i++) {
		if (bcd_num_digits[i] == asc)
			return i;
	}
	return -EINVAL;
}

/* convert a ASCII phone number to 'called/calling/connect party BCD number' */
int encode_bcd_number(u_int8_t *bcd_lv, u_int8_t max_len,
		      int h_len, const char *input)
{
	int in_len = strlen(input);
	int i;
	u_int8_t *bcd_cur = bcd_lv + 1 + h_len;

	/* two digits per byte, plus type byte */
	bcd_lv[0] = in_len/2 + h_len;
	if (in_len % 2)
		bcd_lv[0]++;

	if (bcd_lv[0] > max_len)
		return -EIO;

	for (i = 0; i < in_len; i++) {
		int rc = asc_to_bcd(input[i]);
		if (rc < 0)
			return rc;
		if (i % 2 == 0)
			*bcd_cur = rc;	
		else
			*bcd_cur++ |= (rc << 4);
	}
	/* append padding nibble in case of odd length */
	if (i % 2)
		*bcd_cur++ |= 0xf0;

	/* return how many bytes we used */
	return (bcd_cur - bcd_lv);
}

/* decode 'bearer capability' */
static int decode_bearer_cap(struct gsm_mncc_bearer_cap *bcap,
			     const u_int8_t *lv)
{
	u_int8_t in_len = lv[0];
	int i, s;

	if (in_len < 1)
		return -EINVAL;

	bcap->speech_ver[0] = -1; /* end of list, of maximum 7 values */

	/* octet 3 */
	bcap->transfer = lv[1] & 0x07;
	bcap->mode = (lv[1] & 0x08) >> 3;
	bcap->coding = (lv[1] & 0x10) >> 4;
	bcap->radio = (lv[1] & 0x60) >> 5;

	i = 1;
	s = 0;
	while(!(lv[i] & 0x80)) {
		i++; /* octet 3a etc */
		if (in_len < i)
			return 0;
		bcap->speech_ver[s++] = lv[i] & 0x0f;
		bcap->speech_ver[s] = -1; /* end of list */
		if (i == 2) /* octet 3a */
			bcap->speech_ctm = (lv[i] & 0x20) >> 5;
		if (s == 7) /* maximum speech versions + end of list */
			return 0;
	}

	return 0;
}

/* encode 'bearer capability' */
static int encode_bearer_cap(struct msgb *msg, int lv_only,
			     const struct gsm_mncc_bearer_cap *bcap)
{
	u_int8_t lv[32 + 1];
	int i, s;

	lv[1] = bcap->transfer;
	lv[1] |= bcap->mode << 3;
	lv[1] |= bcap->coding << 4;
	lv[1] |= bcap->radio << 5;

	i = 1;
	for (s = 0; bcap->speech_ver[s] >= 0; s++) {
		i++; /* octet 3a etc */
		lv[i] = bcap->speech_ver[s];
		if (i == 2) /* octet 3a */
			lv[i] |= bcap->speech_ctm << 5;
	}
	lv[i] |= 0x80; /* last IE of octet 3 etc */

	lv[0] = i;
	if (lv_only)
		msgb_lv_put(msg, lv[0], lv+1);
	else
		msgb_tlv_put(msg, GSM48_IE_BEARER_CAP, lv[0], lv+1);

	return 0;
}

/* decode 'call control cap' */
static int decode_cccap(struct gsm_mncc_cccap *ccap, const u_int8_t *lv)
{
	u_int8_t in_len = lv[0];

	if (in_len < 1)
		return -EINVAL;

	/* octet 3 */
	ccap->dtmf = lv[1] & 0x01;
	ccap->pcp = (lv[1] & 0x02) >> 1;
	
	return 0;
}

/* decode 'called party BCD number' */
static int decode_called(struct gsm_mncc_number *called,
			 const u_int8_t *lv)
{
	u_int8_t in_len = lv[0];

	if (in_len < 1)
		return -EINVAL;

	/* octet 3 */
	called->plan = lv[1] & 0x0f;
	called->type = (lv[1] & 0x70) >> 4;

	/* octet 4..N */
	decode_bcd_number(called->number, sizeof(called->number), lv, 1);
	
	return 0;
}

/* encode 'called party BCD number' */
static int encode_called(struct msgb *msg,
			 const struct gsm_mncc_number *called)
{
	u_int8_t lv[18];
	int ret;

	/* octet 3 */
	lv[1] = called->plan;
	lv[1] |= called->type << 4;

	/* octet 4..N, octet 2 */
	ret = encode_bcd_number(lv, sizeof(lv), 1, called->number);
	if (ret < 0)
		return ret;

	msgb_tlv_put(msg, GSM48_IE_CALLED_BCD, lv[0], lv+1);

	return 0;
}

/* encode callerid of various IEs */
static int encode_callerid(struct msgb *msg, int ie, 
			   const struct gsm_mncc_number *callerid)
{
	u_int8_t lv[13];
	int h_len = 1;
	int ret;

	/* octet 3 */
	lv[1] = callerid->plan;
	lv[1] |= callerid->type << 4;

	if (callerid->present || callerid->screen) {
		/* octet 3a */
		lv[2] = callerid->screen;
		lv[2] |= callerid->present << 5;
		lv[2] |= 0x80;
		h_len++;
	} else
		lv[1] |= 0x80;

	/* octet 4..N, octet 2 */
	ret = encode_bcd_number(lv, sizeof(lv), h_len, callerid->number);
	if (ret < 0)
		return ret;

	msgb_tlv_put(msg, ie, lv[0], lv+1);

	return 0;
}

/* decode 'cause' */
static int decode_cause(struct gsm_mncc_cause *cause,
			const u_int8_t *lv)
{
	u_int8_t in_len = lv[0];
	int i;

	if (in_len < 2)
		return -EINVAL;

	cause->diag_len = 0;

	/* octet 3 */
	cause->location = lv[1] & 0x0f;
	cause->coding = (lv[1] & 0x60) >> 5;
	
	i = 1;
	if (!(lv[i] & 0x80)) {
		i++; /* octet 3a */
		if (in_len < i+1)
			return 0;
		cause->rec = 1;
		cause->rec_val = lv[i] & 0x7f;
		
	}
	i++;

	/* octet 4 */
	cause->value = lv[i] & 0x7f;
	i++;

	if (in_len < i) /* no diag */
		return 0;

	if (in_len - (i-1) > 32) /* maximum 32 octets */
		return 0;

	/* octet 5-N */
	memcpy(cause->diag, lv + i, in_len - (i-1));
	cause->diag_len = in_len - (i-1);

	return 0;
}

/* encode 'cause' */
static int encode_cause(struct msgb *msg, int lv_only,
			const struct gsm_mncc_cause *cause)
{
	u_int8_t lv[32+4];
	int i;

	if (cause->diag_len > 32)
		return -EINVAL;

	/* octet 3 */
	lv[1] = cause->location;
	lv[1] |= cause->coding << 5;

	i = 1;
	if (cause->rec) {
		i++; /* octet 3a */
		lv[i] = cause->rec_val;
	}
	lv[i] |= 0x80; /* end of octet 3 */

	/* octet 4 */
	i++;
	lv[i] = 0x80 | cause->value;

	/* octet 5-N */
	if (cause->diag_len) {
		memcpy(lv + i, cause->diag, cause->diag_len);
		i += cause->diag_len;
	}

	lv[0] = i;
	if (lv_only)
		msgb_lv_put(msg, lv[0], lv+1);
	else
		msgb_tlv_put(msg, GSM48_IE_CAUSE, lv[0], lv+1);

	return 0;
}

/* encode 'calling number' */
static int encode_calling(struct msgb *msg, 
			  const struct gsm_mncc_number *calling)
{
	return encode_callerid(msg, GSM48_IE_CALLING_BCD, calling);
}

/* encode 'connected number' */
static int encode_connected(struct msgb *msg, 
			    const struct gsm_mncc_number *connected)
{
	return encode_callerid(msg, GSM48_IE_CONN_BCD, connected);
}

/* encode 'redirecting number' */
static int encode_redirecting(struct msgb *msg,
			      const struct gsm_mncc_number *redirecting)
{
	return encode_callerid(msg, GSM48_IE_REDIR_BCD, redirecting);
}

/* decode 'facility' */
static int decode_facility(struct gsm_mncc_facility *facility,
			   const u_int8_t *lv)
{
	u_int8_t in_len = lv[0];

	if (in_len < 1)
		return -EINVAL;

	if (in_len > sizeof(facility->info))
		return -EINVAL;

	memcpy(facility->info, lv+1, in_len);
	facility->len = in_len;

	return 0;
}

/* encode 'facility' */
static int encode_facility(struct msgb *msg, int lv_only,
			   const struct gsm_mncc_facility *facility)
{
	u_int8_t lv[GSM_MAX_FACILITY + 1];

	if (facility->len < 1 || facility->len > GSM_MAX_FACILITY)
		return -EINVAL;

	memcpy(lv+1, facility->info, facility->len);
	lv[0] = facility->len;
	if (lv_only)
		msgb_lv_put(msg, lv[0], lv+1);
	else
		msgb_tlv_put(msg, GSM48_IE_FACILITY, lv[0], lv+1);

	return 0;
}

/* decode 'notify' */
static int decode_notify(int *notify, const u_int8_t *v)
{
	*notify = v[0] & 0x7f;
	
	return 0;
}

/* encode 'notify' */
static int encode_notify(struct msgb *msg, int notify)
{
	msgb_v_put(msg, notify | 0x80);

	return 0;
}

/* encode 'signal' */
static int encode_signal(struct msgb *msg, int signal)
{
	msgb_tv_put(msg, GSM48_IE_SIGNAL, signal);

	return 0;
}

/* decode 'keypad' */
static int decode_keypad(int *keypad, const u_int8_t *lv)
{
	u_int8_t in_len = lv[0];

	if (in_len < 1)
		return -EINVAL;

	*keypad = lv[1] & 0x7f;
	
	return 0;
}

/* encode 'keypad' */
static int encode_keypad(struct msgb *msg, int keypad)
{
	msgb_tv_put(msg, GSM48_IE_KPD_FACILITY, keypad);

	return 0;
}

/* decode 'progress' */
static int decode_progress(struct gsm_mncc_progress *progress,
			   const u_int8_t *lv)
{
	u_int8_t in_len = lv[0];

	if (in_len < 2)
		return -EINVAL;

	progress->coding = (lv[1] & 0x60) >> 5;
	progress->location = lv[1] & 0x0f;
	progress->descr = lv[2] & 0x7f;
	
	return 0;
}

/* encode 'progress' */
static int encode_progress(struct msgb *msg, int lv_only,
			   const struct gsm_mncc_progress *p)
{
	u_int8_t lv[3];

	lv[0] = 2;
	lv[1] = 0x80 | ((p->coding & 0x3) << 5) | (p->location & 0xf);
	lv[2] = 0x80 | (p->descr & 0x7f);
	if (lv_only)
		msgb_lv_put(msg, lv[0], lv+1);
	else
		msgb_tlv_put(msg, GSM48_IE_PROGR_IND, lv[0], lv+1);

	return 0;
}

/* decode 'user-user' */
static int decode_useruser(struct gsm_mncc_useruser *uu,
			   const u_int8_t *lv)
{
	u_int8_t in_len = lv[0];
	char *info = uu->info;
	int info_len = sizeof(uu->info);
	int i;

	if (in_len < 1)
		return -EINVAL;

	uu->proto = lv[1];

	for (i = 2; i <= in_len; i++) {
		info_len--;
		if (info_len <= 1)
			break;
		*info++ = lv[i];
	}
	if (info_len >= 1)
		*info++ = '\0';
	
	return 0;
}

/* encode 'useruser' */
static int encode_useruser(struct msgb *msg, int lv_only,
			   const struct gsm_mncc_useruser *uu)
{
	u_int8_t lv[GSM_MAX_USERUSER + 2];

	if (strlen(uu->info) > GSM_MAX_USERUSER)
		return -EINVAL;

	lv[0] = 1 + strlen(uu->info);
	lv[1] = uu->proto;
	memcpy(lv + 2, uu->info, strlen(uu->info));
	if (lv_only)
		msgb_lv_put(msg, lv[0], lv+1);
	else
		msgb_tlv_put(msg, GSM48_IE_USER_USER, lv[0], lv+1);

	return 0;
}

/* decode 'ss version' */
static int decode_ssversion(struct gsm_mncc_ssversion *ssv,
			    const u_int8_t *lv)
{
	u_int8_t in_len = lv[0];

	if (in_len < 1 || in_len < sizeof(ssv->info))
		return -EINVAL;

	memcpy(ssv->info, lv + 1, in_len);
	ssv->len = in_len;

	return 0;
}

/* encode 'more data' */
static int encode_more(struct msgb *msg)
{
	u_int8_t *ie;

	ie = msgb_put(msg, 1);
	ie[0] = GSM48_IE_MORE_DATA;

	return 0;
}

/* Chapter 9.2.14 : Send LOCATION UPDATING REJECT */
int gsm0408_loc_upd_rej(struct gsm_lchan *lchan, u_int8_t cause)
{
	struct msgb *msg = gsm48_msgb_alloc();
	struct gsm48_hdr *gh;
	
	msg->lchan = lchan;

	gh = (struct gsm48_hdr *) msgb_put(msg, sizeof(*gh) + 1);
	gh->proto_discr = GSM48_PDISC_MM;
	gh->msg_type = GSM48_MT_MM_LOC_UPD_REJECT;
	gh->data[0] = cause;

	DEBUGP(DMM, "-> LOCATION UPDATING REJECT on channel: %d\n", lchan->nr);
	
	return gsm48_sendmsg(msg, NULL);
}

/* Chapter 9.2.13 : Send LOCATION UPDATE ACCEPT */
int gsm0408_loc_upd_acc(struct gsm_lchan *lchan, u_int32_t tmsi)
{
	struct gsm_bts *bts = lchan->ts->trx->bts;
	struct msgb *msg = gsm48_msgb_alloc();
	struct gsm48_hdr *gh;
	struct gsm48_loc_area_id *lai;
	u_int8_t *mid;
	int ret;
	
	msg->lchan = lchan;

	gh = (struct gsm48_hdr *) msgb_put(msg, sizeof(*gh));
	gh->proto_discr = GSM48_PDISC_MM;
	gh->msg_type = GSM48_MT_MM_LOC_UPD_ACCEPT;

	lai = (struct gsm48_loc_area_id *) msgb_put(msg, sizeof(*lai));
	gsm0408_generate_lai(lai, bts->network->country_code,
		     bts->network->network_code, bts->location_area_code);

	mid = msgb_put(msg, GSM48_MID_TMSI_LEN);
	gsm48_generate_mid_from_tmsi(mid, tmsi);

	DEBUGP(DMM, "-> LOCATION UPDATE ACCEPT\n");

	ret = gsm48_sendmsg(msg, NULL);

	/* send MM INFO with network name */
	ret = gsm48_tx_mm_info(lchan);

	return ret;
}

/* Transmit Chapter 9.2.10 Identity Request */
static int mm_tx_identity_req(struct gsm_lchan *lchan, u_int8_t id_type)
{
	struct msgb *msg = gsm48_msgb_alloc();
	struct gsm48_hdr *gh;

	msg->lchan = lchan;

	gh = (struct gsm48_hdr *) msgb_put(msg, sizeof(*gh) + 1);
	gh->proto_discr = GSM48_PDISC_MM;
	gh->msg_type = GSM48_MT_MM_ID_REQ;
	gh->data[0] = id_type;

	return gsm48_sendmsg(msg, NULL);
}


/* Parse Chapter 9.2.11 Identity Response */
static int mm_rx_id_resp(struct msgb *msg)
{
	struct gsm48_hdr *gh = msgb_l3(msg);
	struct gsm_lchan *lchan = msg->lchan;
	struct gsm_bts *bts = lchan->ts->trx->bts;
	struct gsm_network *net = bts->network;
	u_int8_t mi_type = gh->data[1] & GSM_MI_TYPE_MASK;
	char mi_string[GSM48_MI_SIZE];

	gsm48_mi_to_string(mi_string, sizeof(mi_string), &gh->data[1], gh->data[0]);
	DEBUGP(DMM, "IDENTITY RESPONSE: mi_type=0x%02x MI(%s)\n",
		mi_type, mi_string);

	switch (mi_type) {
	case GSM_MI_TYPE_IMSI:
		/* look up subscriber based on IMSI, create if not found */
		if (!lchan->subscr) {
			lchan->subscr = subscr_get_by_imsi(net, mi_string);
			if (!lchan->subscr)
				lchan->subscr = db_create_subscriber(net, mi_string);
		}
		if (lchan->loc_operation)
			lchan->loc_operation->waiting_for_imsi = 0;
		break;
	case GSM_MI_TYPE_IMEI:
	case GSM_MI_TYPE_IMEISV:
		/* update subscribe <-> IMEI mapping */
		if (lchan->subscr) {
			db_subscriber_assoc_imei(lchan->subscr, mi_string);
			db_sync_equipment(&lchan->subscr->equipment);
		}
		if (lchan->loc_operation)
			lchan->loc_operation->waiting_for_imei = 0;
		break;
	}

	/* Check if we can let the mobile station enter */
	return gsm0408_authorize(lchan, msg);
}


static void loc_upd_rej_cb(void *data)
{
	struct gsm_lchan *lchan = data;

	release_loc_updating_req(lchan);
	gsm0408_loc_upd_rej(lchan, reject_cause);
	lchan_auto_release(lchan);
}

static void schedule_reject(struct gsm_lchan *lchan)
{
	lchan->loc_operation->updating_timer.cb = loc_upd_rej_cb;
	lchan->loc_operation->updating_timer.data = lchan;
	bsc_schedule_timer(&lchan->loc_operation->updating_timer, 5, 0);
}

static const char *lupd_name(u_int8_t type)
{
	switch (type) {
	case GSM48_LUPD_NORMAL:
		return "NORMAL";
	case GSM48_LUPD_PERIODIC:
		return "PEROIDOC";
	case GSM48_LUPD_IMSI_ATT:
		return "IMSI ATTACH";
	default:
		return "UNKNOWN";
	}
}

/* Chapter 9.2.15: Receive Location Updating Request */
static int mm_rx_loc_upd_req(struct msgb *msg)
{
	struct gsm48_hdr *gh = msgb_l3(msg);
	struct gsm48_loc_upd_req *lu;
	struct gsm_subscriber *subscr = NULL;
	struct gsm_lchan *lchan = msg->lchan;
	struct gsm_bts *bts = lchan->ts->trx->bts;
	u_int8_t mi_type;
	char mi_string[GSM48_MI_SIZE];
	int rc;

 	lu = (struct gsm48_loc_upd_req *) gh->data;

	mi_type = lu->mi[0] & GSM_MI_TYPE_MASK;

	gsm48_mi_to_string(mi_string, sizeof(mi_string), lu->mi, lu->mi_len);

	DEBUGPC(DMM, "mi_type=0x%02x MI(%s) type=%s ", mi_type, mi_string,
		lupd_name(lu->type));

	/*
	 * Pseudo Spoof detection: Just drop a second/concurrent
	 * location updating request.
	 */
	if (lchan->loc_operation) {
		DEBUGPC(DMM, "ignoring request due an existing one: %p.\n",
			lchan->loc_operation);
		gsm0408_loc_upd_rej(lchan, GSM48_REJECT_PROTOCOL_ERROR);
		return 0;
	}

	allocate_loc_updating_req(lchan);

	switch (mi_type) {
	case GSM_MI_TYPE_IMSI:
		DEBUGPC(DMM, "\n");
		/* we always want the IMEI, too */
		rc = mm_tx_identity_req(lchan, GSM_MI_TYPE_IMEI);
		lchan->loc_operation->waiting_for_imei = 1;

		/* look up subscriber based on IMSI, create if not found */
		subscr = subscr_get_by_imsi(bts->network, mi_string);
		if (!subscr) {
			subscr = db_create_subscriber(bts->network, mi_string);
		}
		break;
	case GSM_MI_TYPE_TMSI:
		DEBUGPC(DMM, "\n");
		/* we always want the IMEI, too */
		rc = mm_tx_identity_req(lchan, GSM_MI_TYPE_IMEI);
		lchan->loc_operation->waiting_for_imei = 1;

		/* look up the subscriber based on TMSI, request IMSI if it fails */
		subscr = subscr_get_by_tmsi(bts->network,
					    tmsi_from_string(mi_string));
		if (!subscr) {
			/* send IDENTITY REQUEST message to get IMSI */
			rc = mm_tx_identity_req(lchan, GSM_MI_TYPE_IMSI);
			lchan->loc_operation->waiting_for_imsi = 1;
		}
		break;
	case GSM_MI_TYPE_IMEI:
	case GSM_MI_TYPE_IMEISV:
		/* no sim card... FIXME: what to do ? */
		DEBUGPC(DMM, "unimplemented mobile identity type\n");
		break;
	default:	
		DEBUGPC(DMM, "unknown mobile identity type\n");
		break;
	}

	/* schedule the reject timer */
	schedule_reject(lchan);

	if (!subscr) {
		DEBUGPC(DRR, "<- Can't find any subscriber for this ID\n");
		/* FIXME: request id? close channel? */
		return -EINVAL;
	}

	lchan->subscr = subscr;
	lchan->subscr->equipment.classmark1 = lu->classmark1;

	/* check if we can let the subscriber into our network immediately
	 * or if we need to wait for identity responses. */
	return gsm0408_authorize(lchan, msg);
}

#if 0
static u_int8_t to_bcd8(u_int8_t val)
{
       return ((val / 10) << 4) | (val % 10);
}
#endif

/* Section 9.2.15a */
int gsm48_tx_mm_info(struct gsm_lchan *lchan)
{
	struct msgb *msg = gsm48_msgb_alloc();
	struct gsm48_hdr *gh;
	struct gsm_network *net = lchan->ts->trx->bts->network;
	u_int8_t *ptr8;
	int name_len, name_pad;
#if 0
	time_t cur_t;
	struct tm* cur_time;
	int tz15min;
#endif

	msg->lchan = lchan;

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

		ptr16 = (u_int16_t *) msgb_put(msg, name_len*2);
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
		gsm_7bit_encode(ptr8, net->name_long);

	}

	if (net->name_short) {
#if 0
		name_len = strlen(net->name_short);
		/* 10.5.3.5a */
		ptr8 = (u_int8_t *) msgb_put(msg, 3);
		ptr8[0] = GSM48_IE_NAME_SHORT;
		ptr8[1] = name_len*2 + 1;
		ptr8[2] = 0x90; /* UCS2, no spare bits, no CI */

		ptr16 = (u_int16_t *) msgb_put(msg, name_len*2);
		for (i = 0; i < name_len; i++)
			ptr16[i] = htons(net->name_short[i]);
#endif
		name_len = (strlen(net->name_short)*7)/8;
		name_pad = (8 - strlen(net->name_short)*7)%8;
		if (name_pad > 0)
			name_len++;
		/* 10.5.3.5a */
		ptr8 = (u_int8_t *) msgb_put(msg, 3);
		ptr8[0] = GSM48_IE_NAME_SHORT;
		ptr8[1] = name_len +1;
		ptr8[2] = 0x80 | name_pad; /* Cell Broadcast DCS, no CI */

		ptr8 = msgb_put(msg, name_len);
		gsm_7bit_encode(ptr8, net->name_short);

	}

#if 0
	/* Section 10.5.3.9 */
	cur_t = time(NULL);
	cur_time = gmtime(&cur_t);
	ptr8 = msgb_put(msg, 8);
	ptr8[0] = GSM48_IE_NET_TIME_TZ;
	ptr8[1] = to_bcd8(cur_time->tm_year % 100);
	ptr8[2] = to_bcd8(cur_time->tm_mon);
	ptr8[3] = to_bcd8(cur_time->tm_mday);
	ptr8[4] = to_bcd8(cur_time->tm_hour);
	ptr8[5] = to_bcd8(cur_time->tm_min);
	ptr8[6] = to_bcd8(cur_time->tm_sec);
	/* 02.42: coded as BCD encoded signed value in units of 15 minutes */
	tz15min = (cur_time->tm_gmtoff)/(60*15);
	ptr8[7] = to_bcd8(tz15min);
	if (tz15min < 0)
		ptr8[7] |= 0x80;
#endif

	DEBUGP(DMM, "-> MM INFO\n");

	return gsm48_sendmsg(msg, NULL);
}

/* Section 9.2.2 */
int gsm48_tx_mm_auth_req(struct gsm_lchan *lchan, u_int8_t *rand)
{
	struct msgb *msg = gsm48_msgb_alloc();
	struct gsm48_hdr *gh = (struct gsm48_hdr *) msgb_put(msg, sizeof(*gh));
	struct gsm48_auth_req *ar = (struct gsm48_auth_req *) msgb_put(msg, sizeof(*ar));

	DEBUGP(DMM, "-> AUTH REQ\n");

	msg->lchan = lchan;
	gh->proto_discr = GSM48_PDISC_MM;
	gh->msg_type = GSM48_MT_MM_AUTH_REQ;

	/* Key Sequence: FIXME fixed to 0 */
	ar->key_seq = 0;

	/* 16 bytes RAND parameters */
	if (rand)
		memcpy(ar->rand, rand, 16);

	return gsm48_sendmsg(msg, NULL);
}

/* Section 9.2.1 */
int gsm48_tx_mm_auth_rej(struct gsm_lchan *lchan)
{
	DEBUGP(DMM, "-> AUTH REJECT\n");
	return gsm48_tx_simple(lchan, GSM48_PDISC_MM, GSM48_MT_MM_AUTH_REJ);
}

static int gsm48_tx_mm_serv_ack(struct gsm_lchan *lchan)
{
	DEBUGP(DMM, "-> CM SERVICE ACK\n");
	return gsm48_tx_simple(lchan, GSM48_PDISC_MM, GSM48_MT_MM_CM_SERV_ACC);
}

/* 9.2.6 CM service reject */
static int gsm48_tx_mm_serv_rej(struct gsm_lchan *lchan,
				enum gsm48_reject_value value)
{
	struct msgb *msg = gsm48_msgb_alloc();
	struct gsm48_hdr *gh;

	gh = (struct gsm48_hdr *) msgb_put(msg, sizeof(*gh) + 1);

	msg->lchan = lchan;
	use_lchan(lchan);

	gh->proto_discr = GSM48_PDISC_MM;
	gh->msg_type = GSM48_MT_MM_CM_SERV_REJ;
	gh->data[0] = value;
	DEBUGP(DMM, "-> CM SERVICE Reject cause: %d\n", value);

	return gsm48_sendmsg(msg, NULL);
}

/*
 * Handle CM Service Requests
 * a) Verify that the packet is long enough to contain the information
 *    we require otherwsie reject with INCORRECT_MESSAGE
 * b) Try to parse the TMSI. If we do not have one reject
 * c) Check that we know the subscriber with the TMSI otherwise reject
 *    with a HLR cause
 * d) Set the subscriber on the gsm_lchan and accept
 */
static int gsm48_rx_mm_serv_req(struct msgb *msg)
{
	u_int8_t mi_type;
	char mi_string[GSM48_MI_SIZE];

	struct gsm_bts *bts = msg->lchan->ts->trx->bts;
	struct gsm_subscriber *subscr;
	struct gsm48_hdr *gh = msgb_l3(msg);
	struct gsm48_service_request *req =
			(struct gsm48_service_request *)gh->data;
	/* unfortunately in Phase1 the classmar2 length is variable */
	u_int8_t classmark2_len = gh->data[1];
	u_int8_t *classmark2 = gh->data+2;
	u_int8_t mi_len = *(classmark2 + classmark2_len);
	u_int8_t *mi = (classmark2 + classmark2_len + 1);

	DEBUGP(DMM, "<- CM SERVICE REQUEST ");
	if (msg->data_len < sizeof(struct gsm48_service_request*)) {
		DEBUGPC(DMM, "wrong sized message\n");
		return gsm48_tx_mm_serv_rej(msg->lchan,
					    GSM48_REJECT_INCORRECT_MESSAGE);
	}

	if (msg->data_len < req->mi_len + 6) {
		DEBUGPC(DMM, "does not fit in packet\n");
		return gsm48_tx_mm_serv_rej(msg->lchan,
					    GSM48_REJECT_INCORRECT_MESSAGE);
	}

	mi_type = mi[0] & GSM_MI_TYPE_MASK;
	if (mi_type != GSM_MI_TYPE_TMSI) {
		DEBUGPC(DMM, "mi_type is not TMSI: %d\n", mi_type);
		return gsm48_tx_mm_serv_rej(msg->lchan,
					    GSM48_REJECT_INCORRECT_MESSAGE);
	}

	gsm48_mi_to_string(mi_string, sizeof(mi_string), mi, mi_len);
	DEBUGPC(DMM, "serv_type=0x%02x mi_type=0x%02x M(%s)\n",
		req->cm_service_type, mi_type, mi_string);

	if (is_siemens_bts(bts))
		send_siemens_mrpci(msg->lchan, classmark2-1);

	subscr = subscr_get_by_tmsi(bts->network,
				    tmsi_from_string(mi_string));

	/* FIXME: if we don't know the TMSI, inquire abit IMSI and allocate new TMSI */
	if (!subscr)
		return gsm48_tx_mm_serv_rej(msg->lchan,
					    GSM48_REJECT_IMSI_UNKNOWN_IN_HLR);

	if (!msg->lchan->subscr)
		msg->lchan->subscr = subscr;
	else if (msg->lchan->subscr != subscr) {
		DEBUGP(DMM, "<- CM Channel already owned by someone else?\n");
		subscr_put(subscr);
	}

	subscr->equipment.classmark2_len = classmark2_len;
	memcpy(subscr->equipment.classmark2, classmark2, classmark2_len);
	db_sync_equipment(&subscr->equipment);

	return gsm48_tx_mm_serv_ack(msg->lchan);
}

static int gsm48_rx_mm_imsi_detach_ind(struct msgb *msg)
{
	struct gsm_bts *bts = msg->lchan->ts->trx->bts;
	struct gsm48_hdr *gh = msgb_l3(msg);
	struct gsm48_imsi_detach_ind *idi =
				(struct gsm48_imsi_detach_ind *) gh->data;
	u_int8_t mi_type = idi->mi[0] & GSM_MI_TYPE_MASK;
	char mi_string[GSM48_MI_SIZE];
	struct gsm_subscriber *subscr = NULL;

	gsm48_mi_to_string(mi_string, sizeof(mi_string), idi->mi, idi->mi_len);
	DEBUGP(DMM, "IMSI DETACH INDICATION: mi_type=0x%02x MI(%s): ",
		mi_type, mi_string);

	switch (mi_type) {
	case GSM_MI_TYPE_TMSI:
		subscr = subscr_get_by_tmsi(bts->network,
					    tmsi_from_string(mi_string));
		break;
	case GSM_MI_TYPE_IMSI:
		subscr = subscr_get_by_imsi(bts->network, mi_string);
		break;
	case GSM_MI_TYPE_IMEI:
	case GSM_MI_TYPE_IMEISV:
		/* no sim card... FIXME: what to do ? */
		DEBUGPC(DMM, "unimplemented mobile identity type\n");
		break;
	default:	
		DEBUGPC(DMM, "unknown mobile identity type\n");
		break;
	}

	if (subscr) {
		subscr_update(subscr, msg->trx->bts,
				GSM_SUBSCRIBER_UPDATE_DETACHED);
		DEBUGP(DMM, "Subscriber: %s\n",
		       subscr->name ? subscr->name : subscr->imsi);

		subscr->equipment.classmark1 = idi->classmark1;
		db_sync_equipment(&subscr->equipment);

		subscr_put(subscr);
	} else
		DEBUGP(DMM, "Unknown Subscriber ?!?\n");

	return 0;
}

static int gsm48_rx_mm_status(struct msgb *msg)
{
	struct gsm48_hdr *gh = msgb_l3(msg);

	DEBUGP(DMM, "MM STATUS (reject cause 0x%02x)\n", gh->data[0]);

	return 0;
}

/* Receive a GSM 04.08 Mobility Management (MM) message */
static int gsm0408_rcv_mm(struct msgb *msg)
{
	struct gsm48_hdr *gh = msgb_l3(msg);
	int rc = 0;

	switch (gh->msg_type & 0xbf) {
	case GSM48_MT_MM_LOC_UPD_REQUEST:
		DEBUGP(DMM, "LOCATION UPDATING REQUEST: ");
		rc = mm_rx_loc_upd_req(msg);
		break;
	case GSM48_MT_MM_ID_RESP:
		rc = mm_rx_id_resp(msg);
		break;
	case GSM48_MT_MM_CM_SERV_REQ:
		rc = gsm48_rx_mm_serv_req(msg);
		break;
	case GSM48_MT_MM_STATUS:
		rc = gsm48_rx_mm_status(msg);
		break;
	case GSM48_MT_MM_TMSI_REALL_COMPL:
		DEBUGP(DMM, "TMSI Reallocation Completed. Subscriber: %s\n",
		       msg->lchan->subscr ?
				msg->lchan->subscr->imsi :
				"unknown subscriber");
		break;
	case GSM48_MT_MM_IMSI_DETACH_IND:
		rc = gsm48_rx_mm_imsi_detach_ind(msg);
		break;
	case GSM48_MT_MM_CM_REEST_REQ:
		DEBUGP(DMM, "CM REESTABLISH REQUEST: Not implemented\n");
		break;
	case GSM48_MT_MM_AUTH_RESP:
		DEBUGP(DMM, "AUTHENTICATION RESPONSE: Not implemented\n");
		break;
	default:
		fprintf(stderr, "Unknown GSM 04.08 MM msg type 0x%02x\n",
			gh->msg_type);
		break;
	}

	return rc;
}

/* Receive a PAGING RESPONSE message from the MS */
static int gsm48_rx_rr_pag_resp(struct msgb *msg)
{
	struct gsm_bts *bts = msg->lchan->ts->trx->bts;
	struct gsm48_hdr *gh = msgb_l3(msg);
	u_int8_t *classmark2_lv = gh->data + 1;
	u_int8_t mi_type;
	char mi_string[GSM48_MI_SIZE];
	struct gsm_subscriber *subscr = NULL;
	int rc = 0;

	gsm48_paging_extract_mi(msg, mi_string, &mi_type);
	DEBUGP(DRR, "PAGING RESPONSE: mi_type=0x%02x MI(%s)\n",
		mi_type, mi_string);

	switch (mi_type) {
	case GSM_MI_TYPE_TMSI:
		subscr = subscr_get_by_tmsi(bts->network,
					    tmsi_from_string(mi_string));
		break;
	case GSM_MI_TYPE_IMSI:
		subscr = subscr_get_by_imsi(bts->network, mi_string);
		break;
	}

	if (!subscr) {
		DEBUGP(DRR, "<- Can't find any subscriber for this ID\n");
		/* FIXME: request id? close channel? */
		return -EINVAL;
	}
	DEBUGP(DRR, "<- Channel was requested by %s\n",
		subscr->name && strlen(subscr->name) ? subscr->name : subscr->imsi);

	subscr->equipment.classmark2_len = *classmark2_lv;
	memcpy(subscr->equipment.classmark2, classmark2_lv+1, *classmark2_lv);
	db_sync_equipment(&subscr->equipment);

	rc = gsm48_handle_paging_resp(msg, subscr);
	return rc;
}

static int gsm48_rx_rr_classmark(struct msgb *msg)
{
	struct gsm48_hdr *gh = msgb_l3(msg);
	struct gsm_subscriber *subscr = msg->lchan->subscr;
	unsigned int payload_len = msgb_l3len(msg) - sizeof(*gh);
	u_int8_t cm2_len, cm3_len = 0;
	u_int8_t *cm2, *cm3 = NULL;

	DEBUGP(DRR, "CLASSMARK CHANGE ");

	/* classmark 2 */
	cm2_len = gh->data[0];
	cm2 = &gh->data[1];
	DEBUGPC(DRR, "CM2(len=%u) ", cm2_len);

	if (payload_len > cm2_len + 1) {
		/* we must have a classmark3 */
		if (gh->data[cm2_len+1] != 0x20) {
			DEBUGPC(DRR, "ERR CM3 TAG\n");
			return -EINVAL;
		}
		if (cm2_len > 3) {
			DEBUGPC(DRR, "CM2 too long!\n");
			return -EINVAL;
		}
		
		cm3_len = gh->data[cm2_len+2];
		cm3 = &gh->data[cm2_len+3];
		if (cm3_len > 14) {
			DEBUGPC(DRR, "CM3 len %u too long!\n", cm3_len);
			return -EINVAL;
		}
		DEBUGPC(DRR, "CM3(len=%u)\n", cm3_len);
	}
	if (subscr) {
		subscr->equipment.classmark2_len = cm2_len;
		memcpy(subscr->equipment.classmark2, cm2, cm2_len);
		if (cm3) {
			subscr->equipment.classmark3_len = cm3_len;
			memcpy(subscr->equipment.classmark3, cm3, cm3_len);
		}
		db_sync_equipment(&subscr->equipment);
	}

	return 0;
}

static int gsm48_rx_rr_status(struct msgb *msg)
{
	struct gsm48_hdr *gh = msgb_l3(msg);

	DEBUGP(DRR, "STATUS rr_cause = %s\n", 
		rr_cause_name(gh->data[0]));

	return 0;
}

static int gsm48_rx_rr_meas_rep(struct msgb *msg)
{
	struct gsm48_hdr *gh = msgb_l3(msg);
	unsigned int payload_len = msgb_l3len(msg) - sizeof(*gh);
	static struct gsm_meas_rep meas_rep;

	DEBUGP(DMEAS, "MEASUREMENT REPORT ");
	parse_meas_rep(&meas_rep, gh->data, payload_len);
	if (meas_rep.flags & MEAS_REP_F_DTX)
		DEBUGPC(DMEAS, "DTX ");
	if (meas_rep.flags & MEAS_REP_F_BA1)
		DEBUGPC(DMEAS, "BA1 ");
	if (!(meas_rep.flags & MEAS_REP_F_VALID))
		DEBUGPC(DMEAS, "NOT VALID ");
	else
		DEBUGPC(DMEAS, "FULL(lev=%u, qual=%u) SUB(lev=%u, qual=%u) ",
		meas_rep.rxlev_full, meas_rep.rxqual_full, meas_rep.rxlev_sub,
		meas_rep.rxqual_sub);

	DEBUGPC(DMEAS, "NUM_NEIGH=%u\n", meas_rep.num_cell);

	/* FIXME: put the results somwhere */

	return 0;
}

static int gsm48_rx_rr_app_info(struct msgb *msg)
{
	struct gsm48_hdr *gh = msgb_l3(msg);
	u_int8_t apdu_id_flags;
	u_int8_t apdu_len;
	u_int8_t *apdu_data;

	apdu_id_flags = gh->data[0];
	apdu_len = gh->data[1];
	apdu_data = gh->data+2;
	
	DEBUGP(DNM, "RX APPLICATION INFO id/flags=0x%02x apdu_len=%u apdu=%s",
		apdu_id_flags, apdu_len, hexdump(apdu_data, apdu_len));

	return db_apdu_blob_store(msg->lchan->subscr, apdu_id_flags, apdu_len, apdu_data);
}


/* Receive a GSM 04.08 Radio Resource (RR) message */
static int gsm0408_rcv_rr(struct msgb *msg)
{
	struct gsm48_hdr *gh = msgb_l3(msg);
	int rc = 0;

	switch (gh->msg_type) {
	case GSM48_MT_RR_CLSM_CHG:
		rc = gsm48_rx_rr_classmark(msg);
		break;
	case GSM48_MT_RR_GPRS_SUSP_REQ:
		DEBUGP(DRR, "GRPS SUSPEND REQUEST\n");
		break;
	case GSM48_MT_RR_PAG_RESP:
		rc = gsm48_rx_rr_pag_resp(msg);
		break;
	case GSM48_MT_RR_CHAN_MODE_MODIF_ACK:
		DEBUGP(DRR, "CHANNEL MODE MODIFY ACK\n");
		/* We've successfully modified the MS side of the channel,
		 * now go on to modify the BTS side of the channel */
		msg->lchan->rsl_cmode = RSL_CMOD_SPD_SPEECH;
		rc = rsl_chan_mode_modify_req(msg->lchan);
		break;
	case GSM48_MT_RR_STATUS:
		rc = gsm48_rx_rr_status(msg);
		break;
	case GSM48_MT_RR_MEAS_REP:
		rc = gsm48_rx_rr_meas_rep(msg);
		break;
	case GSM48_MT_RR_APP_INFO:
		rc = gsm48_rx_rr_app_info(msg);
		break;
	case GSM48_MT_RR_CIPH_M_COMPL:
		DEBUGP(DRR, "CIPHERING MODE COMPLETE\n");
		/* FIXME: check for MI (if any) */
		break;
	default:
		fprintf(stderr, "Unimplemented GSM 04.08 RR msg type 0x%02x\n",
			gh->msg_type);
		break;
	}

	return rc;
}

int gsm48_send_rr_app_info(struct gsm_lchan *lchan, u_int8_t apdu_id,
			   u_int8_t apdu_len, const u_int8_t *apdu)
{
	struct msgb *msg = gsm48_msgb_alloc();
	struct gsm48_hdr *gh;

	msg->lchan = lchan;
	
	DEBUGP(DRR, "TX APPLICATION INFO id=0x%02x, len=%u\n",
		apdu_id, apdu_len);
	
	gh = (struct gsm48_hdr *) msgb_put(msg, sizeof(*gh) + 2 + apdu_len);
	gh->proto_discr = GSM48_PDISC_RR;
	gh->msg_type = GSM48_MT_RR_APP_INFO;
	gh->data[0] = apdu_id;
	gh->data[1] = apdu_len;
	memcpy(gh->data+2, apdu, apdu_len);

	return gsm48_sendmsg(msg, NULL);
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
		cc_state_names[trans->cc.state], cc_state_names[state]);

	trans->cc.state = state;
}

static int gsm48_cc_tx_status(struct gsm_trans *trans, void *arg)
{
	struct msgb *msg = gsm48_msgb_alloc();
	struct gsm48_hdr *gh = (struct gsm48_hdr *) msgb_put(msg, sizeof(*gh));
	u_int8_t *cause, *call_state;

	gh->msg_type = GSM48_MT_CC_STATUS;

	cause = msgb_put(msg, 3);
	cause[0] = 2;
	cause[1] = GSM48_CAUSE_CS_GSM | GSM48_CAUSE_LOC_USER;
	cause[2] = 0x80 | 30;	/* response to status inquiry */

	call_state = msgb_put(msg, 1);
	call_state[0] = 0xc0 | 0x00;

	return gsm48_sendmsg(msg, trans);
}

static int gsm48_tx_simple(struct gsm_lchan *lchan,
			   u_int8_t pdisc, u_int8_t msg_type)
{
	struct msgb *msg = gsm48_msgb_alloc();
	struct gsm48_hdr *gh = (struct gsm48_hdr *) msgb_put(msg, sizeof(*gh));

	msg->lchan = lchan;

	gh->proto_discr = pdisc;
	gh->msg_type = msg_type;

	return gsm48_sendmsg(msg, NULL);
}

static void gsm48_stop_cc_timer(struct gsm_trans *trans)
{
	if (bsc_timer_pending(&trans->cc.timer)) {
		DEBUGP(DCC, "stopping pending timer T%x\n", trans->cc.Tcurrent);
		bsc_del_timer(&trans->cc.timer);
		trans->cc.Tcurrent = 0;
	}
}
 
static int mncc_recvmsg(struct gsm_network *net, struct gsm_trans *trans,
			int msg_type, struct gsm_mncc *mncc)
{
	struct msgb *msg;

	if (trans)
		if (trans->lchan)
			DEBUGP(DCC, "(bts %d trx %d ts %d ti %x sub %s) "
				"Sending '%s' to MNCC.\n",
				trans->lchan->ts->trx->bts->nr,
				trans->lchan->ts->trx->nr,
				trans->lchan->ts->nr, trans->transaction_id,
				(trans->subscr)?(trans->subscr->extension):"-",
				get_mncc_name(msg_type));
		else
			DEBUGP(DCC, "(bts - trx - ts - ti -- sub %s) "
				"Sending '%s' to MNCC.\n",
				(trans->subscr)?(trans->subscr->extension):"-",
				get_mncc_name(msg_type));
	else
		DEBUGP(DCC, "(bts - trx - ts - ti -- sub -) "
			"Sending '%s' to MNCC.\n", get_mncc_name(msg_type));

	mncc->msg_type = msg_type;
	
	msg = msgb_alloc(sizeof(struct gsm_mncc), "MNCC");
	if (!msg)
		return -ENOMEM;
	memcpy(msg->data, mncc, sizeof(struct gsm_mncc));
	msgb_enqueue(&net->upqueue, msg);

	return 0;
}

int mncc_release_ind(struct gsm_network *net, struct gsm_trans *trans,
		     u_int32_t callref, int location, int value)
{
	struct gsm_mncc rel;

	memset(&rel, 0, sizeof(rel));
	rel.callref = callref;
	mncc_set_cause(&rel, location, value);
	return mncc_recvmsg(net, trans, MNCC_REL_IND, &rel);
}

/* Call Control Specific transaction release.
 * gets called by trans_free, DO NOT CALL YOURSELF! */
void _gsm48_cc_trans_free(struct gsm_trans *trans)
{
	gsm48_stop_cc_timer(trans);

	/* send release to L4, if callref still exists */
	if (trans->callref) {
		/* Ressource unavailable */
		mncc_release_ind(trans->subscr->net, trans, trans->callref,
				 GSM48_CAUSE_LOC_PRN_S_LU,
				 GSM48_CC_CAUSE_RESOURCE_UNAVAIL);
	}
	if (trans->cc.state != GSM_CSTATE_NULL)
		new_cc_state(trans, GSM_CSTATE_NULL);
	if (trans->lchan)
		trau_mux_unmap(&trans->lchan->ts->e1_link, trans->callref);
}

static int gsm48_cc_tx_setup(struct gsm_trans *trans, void *arg);
 
/* call-back from paging the B-end of the connection */
static int setup_trig_pag_evt(unsigned int hooknum, unsigned int event,
			      struct msgb *msg, void *_lchan, void *param)
{
	struct gsm_lchan *lchan = _lchan;
	struct gsm_subscriber *subscr = param;
	struct gsm_trans *transt, *tmp;
	struct gsm_network *net;

	if (hooknum != GSM_HOOK_RR_PAGING)
		return -EINVAL;
  
	if (!subscr)
		return -EINVAL;
	net = subscr->net;
	if (!net) {
		DEBUGP(DCC, "Error Network not set!\n");
		return -EINVAL;
	}

	/* check all tranactions (without lchan) for subscriber */
	llist_for_each_entry_safe(transt, tmp, &net->trans_list, entry) {
		if (transt->subscr != subscr || transt->lchan)
			continue;
		switch (event) {
		case GSM_PAGING_SUCCEEDED:
			if (!lchan) // paranoid
				break;
			DEBUGP(DCC, "Paging subscr %s succeeded!\n",
				subscr->extension);
			/* Assign lchan */
			if (!transt->lchan) {
				transt->lchan = lchan;
				use_lchan(lchan);
			}
			/* send SETUP request to called party */
			gsm48_cc_tx_setup(transt, &transt->cc.msg);
			break;
		case GSM_PAGING_EXPIRED:
			DEBUGP(DCC, "Paging subscr %s expired!\n",
				subscr->extension);
			/* Temporarily out of order */
			mncc_release_ind(transt->subscr->net, transt,
					 transt->callref,
					 GSM48_CAUSE_LOC_PRN_S_LU,
					 GSM48_CC_CAUSE_DEST_OOO);
			transt->callref = 0;
			trans_free(transt);
			break;
		}
	}
	return 0;
}

/* some other part of the code sends us a signal */
static int handle_abisip_signal(unsigned int subsys, unsigned int signal,
				 void *handler_data, void *signal_data)
{
	struct gsm_lchan *lchan = signal_data;
	struct gsm_bts_trx_ts *ts;
	int rc;

	if (subsys != SS_ABISIP)
		return 0;

	/* in case we use direct BTS-to-BTS RTP */
	if (ipacc_rtp_direct)
		return 0;

	ts = lchan->ts;

	switch (signal) {
	case S_ABISIP_BIND_ACK:
		/* the BTS has successfully bound a TCH to a local ip/port,
		 * which means we can connect our UDP socket to it */
		if (ts->abis_ip.rtp_socket) {
			rtp_socket_free(ts->abis_ip.rtp_socket);
			ts->abis_ip.rtp_socket = NULL;
		}

		ts->abis_ip.rtp_socket = rtp_socket_create();
		if (!ts->abis_ip.rtp_socket)
			goto out_err;

		rc = rtp_socket_connect(ts->abis_ip.rtp_socket,
				   ts->abis_ip.bound_ip,
				   ts->abis_ip.bound_port);
		if (rc < 0)
			goto out_err;
		break;
	case S_ABISIP_DISC_IND:
		/* the BTS tells us a RTP stream has been disconnected */
		if (ts->abis_ip.rtp_socket) {
			rtp_socket_free(ts->abis_ip.rtp_socket);
			ts->abis_ip.rtp_socket = NULL;
		}
		break;
	}

	return 0;
out_err:
	/* FIXME: do something */
	return 0;
}

/* bind rtp proxy to local IP/port and tell BTS to connect to it */
static int ipacc_connect_proxy_bind(struct gsm_lchan *lchan)
{
	struct gsm_bts_trx_ts *ts = lchan->ts;
	struct rtp_socket *rs = ts->abis_ip.rtp_socket;
	int rc;

	rc = rsl_ipacc_connect(lchan, ntohl(rs->rtp.sin_local.sin_addr.s_addr),
				ntohs(rs->rtp.sin_local.sin_port),
				ts->abis_ip.conn_id, 
			/* FIXME: use RTP payload of bound socket, not BTS*/
				ts->abis_ip.rtp_payload2);

	return rc;
}

/* map two ipaccess RTP streams onto each other */
static int tch_map(struct gsm_lchan *lchan, struct gsm_lchan *remote_lchan)
{
	struct gsm_bts *bts = lchan->ts->trx->bts;
	struct gsm_bts *remote_bts = remote_lchan->ts->trx->bts;
	struct gsm_bts_trx_ts *ts;
	int rc;

	DEBUGP(DCC, "Setting up TCH map between (bts=%u,trx=%u,ts=%u) and (bts=%u,trx=%u,ts=%u)\n",
		bts->nr, lchan->ts->trx->nr, lchan->ts->nr,
		remote_bts->nr, remote_lchan->ts->trx->nr, remote_lchan->ts->nr);

	if (bts->type != remote_bts->type) {
		DEBUGP(DCC, "Cannot switch calls between different BTS types yet\n");
		return -EINVAL;
	}
	
	switch (bts->type) {
	case GSM_BTS_TYPE_NANOBTS:
		if (!ipacc_rtp_direct) {
			/* connect the TCH's to our RTP proxy */
			rc = ipacc_connect_proxy_bind(lchan);
			if (rc < 0)
				return rc;
			rc = ipacc_connect_proxy_bind(remote_lchan);

			/* connect them with each other */
			rtp_socket_proxy(lchan->ts->abis_ip.rtp_socket,
					 remote_lchan->ts->abis_ip.rtp_socket);
		} else {
			/* directly connect TCH RTP streams to each other */
			ts = remote_lchan->ts;
			rc = rsl_ipacc_connect(lchan, ts->abis_ip.bound_ip,
						ts->abis_ip.bound_port,
						lchan->ts->abis_ip.conn_id,
						ts->abis_ip.rtp_payload2);
			if (rc < 0)
				return rc;
			ts = lchan->ts;
			rc = rsl_ipacc_connect(remote_lchan, ts->abis_ip.bound_ip,
						ts->abis_ip.bound_port,
						remote_lchan->ts->abis_ip.conn_id,
						ts->abis_ip.rtp_payload2);
		}
		break;
	case GSM_BTS_TYPE_BS11:
		trau_mux_map_lchan(lchan, remote_lchan);
		break;
	default:
		DEBUGP(DCC, "Unknown BTS type %u\n", bts->type);
		rc = -EINVAL;
		break;
	}

	return 0;
}

/* bridge channels of two transactions */
static int tch_bridge(struct gsm_network *net, u_int32_t *refs)
{
	struct gsm_trans *trans1 = trans_find_by_callref(net, refs[0]);
	struct gsm_trans *trans2 = trans_find_by_callref(net, refs[1]);

	if (!trans1 || !trans2)
		return -EIO;

	if (!trans1->lchan || !trans2->lchan)
		return -EIO;

	/* through-connect channel */
	return tch_map(trans1->lchan, trans2->lchan);
}

/* enable receive of channels to upqueue */
static int tch_recv(struct gsm_network *net, struct gsm_mncc *data, int enable)
{
	struct gsm_trans *trans;

	/* Find callref */
	trans = trans_find_by_callref(net, data->callref);
	if (!trans)
		return -EIO;
	if (!trans->lchan)
		return 0;

	// todo IPACCESS
	if (enable)
		return trau_recv_lchan(trans->lchan, data->callref);
	return trau_mux_unmap(NULL, data->callref);
}

/* send a frame to channel */
static int tch_frame(struct gsm_network *net, struct gsm_trau_frame *frame)
{
	struct gsm_trans *trans;

	/* Find callref */
	trans = trans_find_by_callref(net, frame->callref);
	if (!trans)
		return -EIO;
	if (!trans->lchan)
		return 0;
	if (trans->lchan->type != GSM_LCHAN_TCH_F &&
	    trans->lchan->type != GSM_LCHAN_TCH_H)
		return 0;

	// todo IPACCESS
	return trau_send_lchan(trans->lchan, 
				(struct decoded_trau_frame *)frame->data);
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
		mncc_release_ind(trans->subscr->net, trans, trans->callref,
				 l4_location, l4_cause);
		trans->callref = 0;
	}

	if (disconnect && trans->callref) {
		/* process disconnect towards layer 4 */
		mncc_set_cause(&l4_rel, l4_location, l4_cause);
		mncc_recvmsg(trans->subscr->net, trans, MNCC_DISC_IND, &l4_rel);
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

static void gsm48_start_cc_timer(struct gsm_trans *trans, int current,
				 int sec, int micro)
{
	DEBUGP(DCC, "starting timer T%x with %d seconds\n", current, sec);
	trans->cc.timer.cb = gsm48_cc_timeout;
	trans->cc.timer.data = trans;
	bsc_schedule_timer(&trans->cc.timer, sec, micro);
	trans->cc.Tcurrent = current;
}

static int gsm48_cc_rx_setup(struct gsm_trans *trans, struct msgb *msg)
{
	struct gsm48_hdr *gh = msgb_l3(msg);
	u_int8_t msg_type = gh->msg_type & 0xbf;
	unsigned int payload_len = msgb_l3len(msg) - sizeof(*gh);
	struct tlv_parsed tp;
	struct gsm_mncc setup;

	memset(&setup, 0, sizeof(struct gsm_mncc));
	setup.callref = trans->callref;
	tlv_parse(&tp, &rsl_att_tlvdef, gh->data, payload_len, 0, 0);
	/* emergency setup is identified by msg_type */
	if (msg_type == GSM48_MT_CC_EMERG_SETUP)
		setup.emergency = 1;

	/* use subscriber as calling party number */
	if (trans->subscr) {
		setup.fields |= MNCC_F_CALLING;
		strncpy(setup.calling.number, trans->subscr->extension,
			sizeof(setup.calling.number)-1);
		strncpy(setup.imsi, trans->subscr->imsi,
			sizeof(setup.imsi)-1);
	}
	/* bearer capability */
	if (TLVP_PRESENT(&tp, GSM48_IE_BEARER_CAP)) {
		setup.fields |= MNCC_F_BEARER_CAP;
		decode_bearer_cap(&setup.bearer_cap,
				  TLVP_VAL(&tp, GSM48_IE_BEARER_CAP)-1);
	}
	/* facility */
	if (TLVP_PRESENT(&tp, GSM48_IE_FACILITY)) {
		setup.fields |= MNCC_F_FACILITY;
		decode_facility(&setup.facility,
				TLVP_VAL(&tp, GSM48_IE_FACILITY)-1);
	}
	/* called party bcd number */
	if (TLVP_PRESENT(&tp, GSM48_IE_CALLED_BCD)) {
		setup.fields |= MNCC_F_CALLED;
		decode_called(&setup.called,
			      TLVP_VAL(&tp, GSM48_IE_CALLED_BCD)-1);
	}
	/* user-user */
	if (TLVP_PRESENT(&tp, GSM48_IE_USER_USER)) {
		setup.fields |= MNCC_F_USERUSER;
		decode_useruser(&setup.useruser,
				TLVP_VAL(&tp, GSM48_IE_USER_USER)-1);
	}
	/* ss-version */
	if (TLVP_PRESENT(&tp, GSM48_IE_SS_VERS)) {
		setup.fields |= MNCC_F_SSVERSION;
		decode_ssversion(&setup.ssversion,
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
		decode_cccap(&setup.cccap,
			     TLVP_VAL(&tp, GSM48_IE_CC_CAP)-1);
	}

	new_cc_state(trans, GSM_CSTATE_INITIATED);

	/* indicate setup to MNCC */
	mncc_recvmsg(trans->subscr->net, trans, MNCC_SETUP_IND, &setup);

	/* MNCC code will modify the channel asynchronously, we should
	 * ipaccess-bind only after the modification has been made to the
	 * lchan->tch_mode */
	return 0;
}

static int gsm48_cc_tx_setup(struct gsm_trans *trans, void *arg)
{
	struct msgb *msg = gsm48_msgb_alloc();
	struct gsm48_hdr *gh;
	struct gsm_mncc *setup = arg;
	int rc, trans_id;

	gh = (struct gsm48_hdr *) msgb_put(msg, sizeof(*gh));

	/* transaction id must not be assigned */
	if (trans->transaction_id != 0xff) { /* unasssigned */
		DEBUGP(DCC, "TX Setup with assigned transaction. "
			"This is not allowed!\n");
		/* Temporarily out of order */
		rc = mncc_release_ind(trans->subscr->net, trans, trans->callref,
				      GSM48_CAUSE_LOC_PRN_S_LU,
				      GSM48_CC_CAUSE_RESOURCE_UNAVAIL);
		trans->callref = 0;
		trans_free(trans);
		return rc;
	}
	
	/* Get free transaction_id */
	trans_id = trans_assign_trans_id(trans->subscr, GSM48_PDISC_CC, 0);
	if (trans_id < 0) {
		/* no free transaction ID */
		rc = mncc_release_ind(trans->subscr->net, trans, trans->callref,
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
		encode_bearer_cap(msg, 0, &setup->bearer_cap);
	/* facility */
	if (setup->fields & MNCC_F_FACILITY)
		encode_facility(msg, 0, &setup->facility);
	/* progress */
	if (setup->fields & MNCC_F_PROGRESS)
		encode_progress(msg, 0, &setup->progress);
	/* calling party BCD number */
	if (setup->fields & MNCC_F_CALLING)
		encode_calling(msg, &setup->calling);
	/* called party BCD number */
	if (setup->fields & MNCC_F_CALLED)
		encode_called(msg, &setup->called);
	/* user-user */
	if (setup->fields & MNCC_F_USERUSER)
		encode_useruser(msg, 0, &setup->useruser);
	/* redirecting party BCD number */
	if (setup->fields & MNCC_F_REDIRECTING)
		encode_redirecting(msg, &setup->redirecting);
	/* signal */
	if (setup->fields & MNCC_F_SIGNAL)
		encode_signal(msg, setup->signal);
	
	new_cc_state(trans, GSM_CSTATE_CALL_PRESENT);

	return gsm48_sendmsg(msg, trans);
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
	tlv_parse(&tp, &rsl_att_tlvdef, gh->data, payload_len, 0, 0);
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
		decode_bearer_cap(&call_conf.bearer_cap,
				  TLVP_VAL(&tp, GSM48_IE_BEARER_CAP)-1);
	}
	/* cause */
	if (TLVP_PRESENT(&tp, GSM48_IE_CAUSE)) {
		call_conf.fields |= MNCC_F_CAUSE;
		decode_cause(&call_conf.cause,
			     TLVP_VAL(&tp, GSM48_IE_CAUSE)-1);
	}
	/* cc cap */
	if (TLVP_PRESENT(&tp, GSM48_IE_CC_CAP)) {
		call_conf.fields |= MNCC_F_CCCAP;
		decode_cccap(&call_conf.cccap,
			     TLVP_VAL(&tp, GSM48_IE_CC_CAP)-1);
	}

	new_cc_state(trans, GSM_CSTATE_MO_TERM_CALL_CONF);

	return mncc_recvmsg(trans->subscr->net, trans, MNCC_CALL_CONF_IND,
			    &call_conf);
}

static int gsm48_cc_tx_call_proc(struct gsm_trans *trans, void *arg)
{
	struct gsm_mncc *proceeding = arg;
	struct msgb *msg = gsm48_msgb_alloc();
	struct gsm48_hdr *gh = (struct gsm48_hdr *) msgb_put(msg, sizeof(*gh));

	gh->msg_type = GSM48_MT_CC_CALL_PROC;

	new_cc_state(trans, GSM_CSTATE_MO_CALL_PROC);

	/* bearer capability */
	if (proceeding->fields & MNCC_F_BEARER_CAP)
		encode_bearer_cap(msg, 0, &proceeding->bearer_cap);
	/* facility */
	if (proceeding->fields & MNCC_F_FACILITY)
		encode_facility(msg, 0, &proceeding->facility);
	/* progress */
	if (proceeding->fields & MNCC_F_PROGRESS)
		encode_progress(msg, 0, &proceeding->progress);

	return gsm48_sendmsg(msg, trans);
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
	tlv_parse(&tp, &rsl_att_tlvdef, gh->data, payload_len, 0, 0);
	/* facility */
	if (TLVP_PRESENT(&tp, GSM48_IE_FACILITY)) {
		alerting.fields |= MNCC_F_FACILITY;
		decode_facility(&alerting.facility,
				TLVP_VAL(&tp, GSM48_IE_FACILITY)-1);
	}

	/* progress */
	if (TLVP_PRESENT(&tp, GSM48_IE_PROGR_IND)) {
		alerting.fields |= MNCC_F_PROGRESS;
		decode_progress(&alerting.progress,
				TLVP_VAL(&tp, GSM48_IE_PROGR_IND)-1);
	}
	/* ss-version */
	if (TLVP_PRESENT(&tp, GSM48_IE_SS_VERS)) {
		alerting.fields |= MNCC_F_SSVERSION;
		decode_ssversion(&alerting.ssversion,
				 TLVP_VAL(&tp, GSM48_IE_SS_VERS)-1);
	}

	new_cc_state(trans, GSM_CSTATE_CALL_RECEIVED);

	return mncc_recvmsg(trans->subscr->net, trans, MNCC_ALERT_IND,
			    &alerting);
}

static int gsm48_cc_tx_alerting(struct gsm_trans *trans, void *arg)
{
	struct gsm_mncc *alerting = arg;
	struct msgb *msg = gsm48_msgb_alloc();
	struct gsm48_hdr *gh = (struct gsm48_hdr *) msgb_put(msg, sizeof(*gh));

	gh->msg_type = GSM48_MT_CC_ALERTING;

	/* facility */
	if (alerting->fields & MNCC_F_FACILITY)
		encode_facility(msg, 0, &alerting->facility);
	/* progress */
	if (alerting->fields & MNCC_F_PROGRESS)
		encode_progress(msg, 0, &alerting->progress);
	/* user-user */
	if (alerting->fields & MNCC_F_USERUSER)
		encode_useruser(msg, 0, &alerting->useruser);

	new_cc_state(trans, GSM_CSTATE_CALL_DELIVERED);
	
	return gsm48_sendmsg(msg, trans);
}

static int gsm48_cc_tx_progress(struct gsm_trans *trans, void *arg)
{
	struct gsm_mncc *progress = arg;
	struct msgb *msg = gsm48_msgb_alloc();
	struct gsm48_hdr *gh = (struct gsm48_hdr *) msgb_put(msg, sizeof(*gh));

	gh->msg_type = GSM48_MT_CC_PROGRESS;

	/* progress */
	encode_progress(msg, 1, &progress->progress);
	/* user-user */
	if (progress->fields & MNCC_F_USERUSER)
		encode_useruser(msg, 0, &progress->useruser);

	return gsm48_sendmsg(msg, trans);
}

static int gsm48_cc_tx_connect(struct gsm_trans *trans, void *arg)
{
	struct gsm_mncc *connect = arg;
	struct msgb *msg = gsm48_msgb_alloc();
	struct gsm48_hdr *gh = (struct gsm48_hdr *) msgb_put(msg, sizeof(*gh));

	gh->msg_type = GSM48_MT_CC_CONNECT;

	gsm48_stop_cc_timer(trans);
	gsm48_start_cc_timer(trans, 0x313, GSM48_T313);

	/* facility */
	if (connect->fields & MNCC_F_FACILITY)
		encode_facility(msg, 0, &connect->facility);
	/* progress */
	if (connect->fields & MNCC_F_PROGRESS)
		encode_progress(msg, 0, &connect->progress);
	/* connected number */
	if (connect->fields & MNCC_F_CONNECTED)
		encode_connected(msg, &connect->connected);
	/* user-user */
	if (connect->fields & MNCC_F_USERUSER)
		encode_useruser(msg, 0, &connect->useruser);

	new_cc_state(trans, GSM_CSTATE_CONNECT_IND);

	return gsm48_sendmsg(msg, trans);
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
	tlv_parse(&tp, &rsl_att_tlvdef, gh->data, payload_len, 0, 0);
	/* use subscriber as connected party number */
	if (trans->subscr) {
		connect.fields |= MNCC_F_CONNECTED;
		strncpy(connect.connected.number, trans->subscr->extension,
			sizeof(connect.connected.number)-1);
		strncpy(connect.imsi, trans->subscr->imsi,
			sizeof(connect.imsi)-1);
	}
	/* facility */
	if (TLVP_PRESENT(&tp, GSM48_IE_FACILITY)) {
		connect.fields |= MNCC_F_FACILITY;
		decode_facility(&connect.facility,
				TLVP_VAL(&tp, GSM48_IE_FACILITY)-1);
	}
	/* user-user */
	if (TLVP_PRESENT(&tp, GSM48_IE_USER_USER)) {
		connect.fields |= MNCC_F_USERUSER;
		decode_useruser(&connect.useruser,
				TLVP_VAL(&tp, GSM48_IE_USER_USER)-1);
	}
	/* ss-version */
	if (TLVP_PRESENT(&tp, GSM48_IE_SS_VERS)) {
		connect.fields |= MNCC_F_SSVERSION;
		decode_ssversion(&connect.ssversion,
				 TLVP_VAL(&tp, GSM48_IE_SS_VERS)-1);
	}

	new_cc_state(trans, GSM_CSTATE_CONNECT_REQUEST);

	return mncc_recvmsg(trans->subscr->net, trans, MNCC_SETUP_CNF, &connect);
}


static int gsm48_cc_rx_connect_ack(struct gsm_trans *trans, struct msgb *msg)
{
	struct gsm_mncc connect_ack;

	gsm48_stop_cc_timer(trans);

	new_cc_state(trans, GSM_CSTATE_ACTIVE);
	
	memset(&connect_ack, 0, sizeof(struct gsm_mncc));
	connect_ack.callref = trans->callref;
	return mncc_recvmsg(trans->subscr->net, trans, MNCC_SETUP_COMPL_IND,
			    &connect_ack);
}

static int gsm48_cc_tx_connect_ack(struct gsm_trans *trans, void *arg)
{
	struct msgb *msg = gsm48_msgb_alloc();
	struct gsm48_hdr *gh = (struct gsm48_hdr *) msgb_put(msg, sizeof(*gh));

	gh->msg_type = GSM48_MT_CC_CONNECT_ACK;

	new_cc_state(trans, GSM_CSTATE_ACTIVE);

	return gsm48_sendmsg(msg, trans);
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
	tlv_parse(&tp, &rsl_att_tlvdef, gh->data, payload_len, GSM48_IE_CAUSE, 0);
	/* cause */
	if (TLVP_PRESENT(&tp, GSM48_IE_CAUSE)) {
		disc.fields |= MNCC_F_CAUSE;
		decode_cause(&disc.cause,
			     TLVP_VAL(&tp, GSM48_IE_CAUSE)-1);
	}
	/* facility */
	if (TLVP_PRESENT(&tp, GSM48_IE_FACILITY)) {
		disc.fields |= MNCC_F_FACILITY;
		decode_facility(&disc.facility,
				TLVP_VAL(&tp, GSM48_IE_FACILITY)-1);
	}
	/* user-user */
	if (TLVP_PRESENT(&tp, GSM48_IE_USER_USER)) {
		disc.fields |= MNCC_F_USERUSER;
		decode_useruser(&disc.useruser,
				TLVP_VAL(&tp, GSM48_IE_USER_USER)-1);
	}
	/* ss-version */
	if (TLVP_PRESENT(&tp, GSM48_IE_SS_VERS)) {
		disc.fields |= MNCC_F_SSVERSION;
		decode_ssversion(&disc.ssversion,
				 TLVP_VAL(&tp, GSM48_IE_SS_VERS)-1);
	}

	return mncc_recvmsg(trans->subscr->net, trans, MNCC_DISC_IND, &disc);

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
	struct msgb *msg = gsm48_msgb_alloc();
	struct gsm48_hdr *gh = (struct gsm48_hdr *) msgb_put(msg, sizeof(*gh));

	gh->msg_type = GSM48_MT_CC_DISCONNECT;

	gsm48_stop_cc_timer(trans);
	gsm48_start_cc_timer(trans, 0x306, GSM48_T306);

	/* cause */
	if (disc->fields & MNCC_F_CAUSE)
		encode_cause(msg, 1, &disc->cause);
	else
		encode_cause(msg, 1, &default_cause);

	/* facility */
	if (disc->fields & MNCC_F_FACILITY)
		encode_facility(msg, 0, &disc->facility);
	/* progress */
	if (disc->fields & MNCC_F_PROGRESS)
		encode_progress(msg, 0, &disc->progress);
	/* user-user */
	if (disc->fields & MNCC_F_USERUSER)
		encode_useruser(msg, 0, &disc->useruser);

	/* store disconnect cause for T306 expiry */
	memcpy(&trans->cc.msg, disc, sizeof(struct gsm_mncc));

	new_cc_state(trans, GSM_CSTATE_DISCONNECT_IND);

	return gsm48_sendmsg(msg, trans);
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
	tlv_parse(&tp, &rsl_att_tlvdef, gh->data, payload_len, 0, 0);
	/* cause */
	if (TLVP_PRESENT(&tp, GSM48_IE_CAUSE)) {
		rel.fields |= MNCC_F_CAUSE;
		decode_cause(&rel.cause,
			     TLVP_VAL(&tp, GSM48_IE_CAUSE)-1);
	}
	/* facility */
	if (TLVP_PRESENT(&tp, GSM48_IE_FACILITY)) {
		rel.fields |= MNCC_F_FACILITY;
		decode_facility(&rel.facility,
				TLVP_VAL(&tp, GSM48_IE_FACILITY)-1);
	}
	/* user-user */
	if (TLVP_PRESENT(&tp, GSM48_IE_USER_USER)) {
		rel.fields |= MNCC_F_USERUSER;
		decode_useruser(&rel.useruser,
				TLVP_VAL(&tp, GSM48_IE_USER_USER)-1);
	}
	/* ss-version */
	if (TLVP_PRESENT(&tp, GSM48_IE_SS_VERS)) {
		rel.fields |= MNCC_F_SSVERSION;
		decode_ssversion(&rel.ssversion,
				 TLVP_VAL(&tp, GSM48_IE_SS_VERS)-1);
	}

	if (trans->cc.state == GSM_CSTATE_RELEASE_REQ) {
		/* release collision 5.4.5 */
		rc = mncc_recvmsg(trans->subscr->net, trans, MNCC_REL_CNF, &rel);
	} else {
		rc = gsm48_tx_simple(msg->lchan,
				     GSM48_PDISC_CC | (trans->transaction_id << 4),
				     GSM48_MT_CC_RELEASE_COMPL);
		rc = mncc_recvmsg(trans->subscr->net, trans, MNCC_REL_IND, &rel);
	}

	new_cc_state(trans, GSM_CSTATE_NULL);

	trans->callref = 0;
	trans_free(trans);

	return rc;
}

static int gsm48_cc_tx_release(struct gsm_trans *trans, void *arg)
{
	struct gsm_mncc *rel = arg;
	struct msgb *msg = gsm48_msgb_alloc();
	struct gsm48_hdr *gh = (struct gsm48_hdr *) msgb_put(msg, sizeof(*gh));

	gh->msg_type = GSM48_MT_CC_RELEASE;

	trans->callref = 0;
	
	gsm48_stop_cc_timer(trans);
	gsm48_start_cc_timer(trans, 0x308, GSM48_T308);

	/* cause */
	if (rel->fields & MNCC_F_CAUSE)
		encode_cause(msg, 0, &rel->cause);
	/* facility */
	if (rel->fields & MNCC_F_FACILITY)
		encode_facility(msg, 0, &rel->facility);
	/* user-user */
	if (rel->fields & MNCC_F_USERUSER)
		encode_useruser(msg, 0, &rel->useruser);

	trans->cc.T308_second = 0;
	memcpy(&trans->cc.msg, rel, sizeof(struct gsm_mncc));

	if (trans->cc.state != GSM_CSTATE_RELEASE_REQ)
		new_cc_state(trans, GSM_CSTATE_RELEASE_REQ);

	return gsm48_sendmsg(msg, trans);
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
	tlv_parse(&tp, &rsl_att_tlvdef, gh->data, payload_len, 0, 0);
	/* cause */
	if (TLVP_PRESENT(&tp, GSM48_IE_CAUSE)) {
		rel.fields |= MNCC_F_CAUSE;
		decode_cause(&rel.cause,
			     TLVP_VAL(&tp, GSM48_IE_CAUSE)-1);
	}
	/* facility */
	if (TLVP_PRESENT(&tp, GSM48_IE_FACILITY)) {
		rel.fields |= MNCC_F_FACILITY;
		decode_facility(&rel.facility,
				TLVP_VAL(&tp, GSM48_IE_FACILITY)-1);
	}
	/* user-user */
	if (TLVP_PRESENT(&tp, GSM48_IE_USER_USER)) {
		rel.fields |= MNCC_F_USERUSER;
		decode_useruser(&rel.useruser,
				TLVP_VAL(&tp, GSM48_IE_USER_USER)-1);
	}
	/* ss-version */
	if (TLVP_PRESENT(&tp, GSM48_IE_SS_VERS)) {
		rel.fields |= MNCC_F_SSVERSION;
		decode_ssversion(&rel.ssversion,
				 TLVP_VAL(&tp, GSM48_IE_SS_VERS)-1);
	}

	if (trans->callref) {
		switch (trans->cc.state) {
		case GSM_CSTATE_CALL_PRESENT:
			rc = mncc_recvmsg(trans->subscr->net, trans,
					  MNCC_REJ_IND, &rel);
			break;
		case GSM_CSTATE_RELEASE_REQ:
			rc = mncc_recvmsg(trans->subscr->net, trans,
					  MNCC_REL_CNF, &rel);
			break;
		default:
			rc = mncc_recvmsg(trans->subscr->net, trans,
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
	struct msgb *msg = gsm48_msgb_alloc();
	struct gsm48_hdr *gh = (struct gsm48_hdr *) msgb_put(msg, sizeof(*gh));

	gh->msg_type = GSM48_MT_CC_RELEASE_COMPL;

	trans->callref = 0;
	
	gsm48_stop_cc_timer(trans);

	/* cause */
	if (rel->fields & MNCC_F_CAUSE)
		encode_cause(msg, 0, &rel->cause);
	/* facility */
	if (rel->fields & MNCC_F_FACILITY)
		encode_facility(msg, 0, &rel->facility);
	/* user-user */
	if (rel->fields & MNCC_F_USERUSER)
		encode_useruser(msg, 0, &rel->useruser);

	trans_free(trans);

	return gsm48_sendmsg(msg, trans);
}

static int gsm48_cc_rx_facility(struct gsm_trans *trans, struct msgb *msg)
{
	struct gsm48_hdr *gh = msgb_l3(msg);
	unsigned int payload_len = msgb_l3len(msg) - sizeof(*gh);
	struct tlv_parsed tp;
	struct gsm_mncc fac;

	memset(&fac, 0, sizeof(struct gsm_mncc));
	fac.callref = trans->callref;
	tlv_parse(&tp, &rsl_att_tlvdef, gh->data, payload_len, GSM48_IE_FACILITY, 0);
	/* facility */
	if (TLVP_PRESENT(&tp, GSM48_IE_FACILITY)) {
		fac.fields |= MNCC_F_FACILITY;
		decode_facility(&fac.facility,
				TLVP_VAL(&tp, GSM48_IE_FACILITY)-1);
	}
	/* ss-version */
	if (TLVP_PRESENT(&tp, GSM48_IE_SS_VERS)) {
		fac.fields |= MNCC_F_SSVERSION;
		decode_ssversion(&fac.ssversion,
				 TLVP_VAL(&tp, GSM48_IE_SS_VERS)-1);
	}

	return mncc_recvmsg(trans->subscr->net, trans, MNCC_FACILITY_IND, &fac);
}

static int gsm48_cc_tx_facility(struct gsm_trans *trans, void *arg)
{
	struct gsm_mncc *fac = arg;
	struct msgb *msg = gsm48_msgb_alloc();
	struct gsm48_hdr *gh = (struct gsm48_hdr *) msgb_put(msg, sizeof(*gh));

	gh->msg_type = GSM48_MT_CC_FACILITY;

	/* facility */
	encode_facility(msg, 1, &fac->facility);

	return gsm48_sendmsg(msg, trans);
}

static int gsm48_cc_rx_hold(struct gsm_trans *trans, struct msgb *msg)
{
	struct gsm_mncc hold;

	memset(&hold, 0, sizeof(struct gsm_mncc));
	hold.callref = trans->callref;
	return mncc_recvmsg(trans->subscr->net, trans, MNCC_HOLD_IND, &hold);
}

static int gsm48_cc_tx_hold_ack(struct gsm_trans *trans, void *arg)
{
	struct msgb *msg = gsm48_msgb_alloc();
	struct gsm48_hdr *gh = (struct gsm48_hdr *) msgb_put(msg, sizeof(*gh));

	gh->msg_type = GSM48_MT_CC_HOLD_ACK;

	return gsm48_sendmsg(msg, trans);
}

static int gsm48_cc_tx_hold_rej(struct gsm_trans *trans, void *arg)
{
	struct gsm_mncc *hold_rej = arg;
	struct msgb *msg = gsm48_msgb_alloc();
	struct gsm48_hdr *gh = (struct gsm48_hdr *) msgb_put(msg, sizeof(*gh));

	gh->msg_type = GSM48_MT_CC_HOLD_REJ;

	/* cause */
	if (hold_rej->fields & MNCC_F_CAUSE)
		encode_cause(msg, 1, &hold_rej->cause);
	else
		encode_cause(msg, 1, &default_cause);

	return gsm48_sendmsg(msg, trans);
}

static int gsm48_cc_rx_retrieve(struct gsm_trans *trans, struct msgb *msg)
{
	struct gsm_mncc retrieve;

	memset(&retrieve, 0, sizeof(struct gsm_mncc));
	retrieve.callref = trans->callref;
	return mncc_recvmsg(trans->subscr->net, trans, MNCC_RETRIEVE_IND,
			    &retrieve);
}

static int gsm48_cc_tx_retrieve_ack(struct gsm_trans *trans, void *arg)
{
	struct msgb *msg = gsm48_msgb_alloc();
	struct gsm48_hdr *gh = (struct gsm48_hdr *) msgb_put(msg, sizeof(*gh));

	gh->msg_type = GSM48_MT_CC_RETR_ACK;

	return gsm48_sendmsg(msg, trans);
}

static int gsm48_cc_tx_retrieve_rej(struct gsm_trans *trans, void *arg)
{
	struct gsm_mncc *retrieve_rej = arg;
	struct msgb *msg = gsm48_msgb_alloc();
	struct gsm48_hdr *gh = (struct gsm48_hdr *) msgb_put(msg, sizeof(*gh));

	gh->msg_type = GSM48_MT_CC_RETR_REJ;

	/* cause */
	if (retrieve_rej->fields & MNCC_F_CAUSE)
		encode_cause(msg, 1, &retrieve_rej->cause);
	else
		encode_cause(msg, 1, &default_cause);

	return gsm48_sendmsg(msg, trans);
}

static int gsm48_cc_rx_start_dtmf(struct gsm_trans *trans, struct msgb *msg)
{
	struct gsm48_hdr *gh = msgb_l3(msg);
	unsigned int payload_len = msgb_l3len(msg) - sizeof(*gh);
	struct tlv_parsed tp;
	struct gsm_mncc dtmf;

	memset(&dtmf, 0, sizeof(struct gsm_mncc));
	dtmf.callref = trans->callref;
	tlv_parse(&tp, &rsl_att_tlvdef, gh->data, payload_len, 0, 0);
	/* keypad facility */
	if (TLVP_PRESENT(&tp, GSM48_IE_KPD_FACILITY)) {
		dtmf.fields |= MNCC_F_KEYPAD;
		decode_keypad(&dtmf.keypad,
			      TLVP_VAL(&tp, GSM48_IE_KPD_FACILITY)-1);
	}

	return mncc_recvmsg(trans->subscr->net, trans, MNCC_START_DTMF_IND, &dtmf);
}

static int gsm48_cc_tx_start_dtmf_ack(struct gsm_trans *trans, void *arg)
{
	struct gsm_mncc *dtmf = arg;
	struct msgb *msg = gsm48_msgb_alloc();
	struct gsm48_hdr *gh = (struct gsm48_hdr *) msgb_put(msg, sizeof(*gh));

	gh->msg_type = GSM48_MT_CC_START_DTMF_ACK;

	/* keypad */
	if (dtmf->fields & MNCC_F_KEYPAD)
		encode_keypad(msg, dtmf->keypad);

	return gsm48_sendmsg(msg, trans);
}

static int gsm48_cc_tx_start_dtmf_rej(struct gsm_trans *trans, void *arg)
{
	struct gsm_mncc *dtmf = arg;
	struct msgb *msg = gsm48_msgb_alloc();
	struct gsm48_hdr *gh = (struct gsm48_hdr *) msgb_put(msg, sizeof(*gh));

	gh->msg_type = GSM48_MT_CC_START_DTMF_REJ;

	/* cause */
	if (dtmf->fields & MNCC_F_CAUSE)
		encode_cause(msg, 1, &dtmf->cause);
	else
		encode_cause(msg, 1, &default_cause);

	return gsm48_sendmsg(msg, trans);
}

static int gsm48_cc_tx_stop_dtmf_ack(struct gsm_trans *trans, void *arg)
{
	struct msgb *msg = gsm48_msgb_alloc();
	struct gsm48_hdr *gh = (struct gsm48_hdr *) msgb_put(msg, sizeof(*gh));

	gh->msg_type = GSM48_MT_CC_STOP_DTMF_ACK;

	return gsm48_sendmsg(msg, trans);
}

static int gsm48_cc_rx_stop_dtmf(struct gsm_trans *trans, struct msgb *msg)
{
	struct gsm_mncc dtmf;

	memset(&dtmf, 0, sizeof(struct gsm_mncc));
	dtmf.callref = trans->callref;

	return mncc_recvmsg(trans->subscr->net, trans, MNCC_STOP_DTMF_IND, &dtmf);
}

static int gsm48_cc_rx_modify(struct gsm_trans *trans, struct msgb *msg)
{
	struct gsm48_hdr *gh = msgb_l3(msg);
	unsigned int payload_len = msgb_l3len(msg) - sizeof(*gh);
	struct tlv_parsed tp;
	struct gsm_mncc modify;

	memset(&modify, 0, sizeof(struct gsm_mncc));
	modify.callref = trans->callref;
	tlv_parse(&tp, &rsl_att_tlvdef, gh->data, payload_len, GSM48_IE_BEARER_CAP, 0);
	/* bearer capability */
	if (TLVP_PRESENT(&tp, GSM48_IE_BEARER_CAP)) {
		modify.fields |= MNCC_F_BEARER_CAP;
		decode_bearer_cap(&modify.bearer_cap,
				  TLVP_VAL(&tp, GSM48_IE_BEARER_CAP)-1);
	}

	new_cc_state(trans, GSM_CSTATE_MO_ORIG_MODIFY);

	return mncc_recvmsg(trans->subscr->net, trans, MNCC_MODIFY_IND, &modify);
}

static int gsm48_cc_tx_modify(struct gsm_trans *trans, void *arg)
{
	struct gsm_mncc *modify = arg;
	struct msgb *msg = gsm48_msgb_alloc();
	struct gsm48_hdr *gh = (struct gsm48_hdr *) msgb_put(msg, sizeof(*gh));

	gh->msg_type = GSM48_MT_CC_MODIFY;

	gsm48_start_cc_timer(trans, 0x323, GSM48_T323);

	/* bearer capability */
	encode_bearer_cap(msg, 1, &modify->bearer_cap);

	new_cc_state(trans, GSM_CSTATE_MO_TERM_MODIFY);

	return gsm48_sendmsg(msg, trans);
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
	tlv_parse(&tp, &rsl_att_tlvdef, gh->data, payload_len, GSM48_IE_BEARER_CAP, 0);
	/* bearer capability */
	if (TLVP_PRESENT(&tp, GSM48_IE_BEARER_CAP)) {
		modify.fields |= MNCC_F_BEARER_CAP;
		decode_bearer_cap(&modify.bearer_cap,
				  TLVP_VAL(&tp, GSM48_IE_BEARER_CAP)-1);
	}

	new_cc_state(trans, GSM_CSTATE_ACTIVE);

	return mncc_recvmsg(trans->subscr->net, trans, MNCC_MODIFY_CNF, &modify);
}

static int gsm48_cc_tx_modify_complete(struct gsm_trans *trans, void *arg)
{
	struct gsm_mncc *modify = arg;
	struct msgb *msg = gsm48_msgb_alloc();
	struct gsm48_hdr *gh = (struct gsm48_hdr *) msgb_put(msg, sizeof(*gh));

	gh->msg_type = GSM48_MT_CC_MODIFY_COMPL;

	/* bearer capability */
	encode_bearer_cap(msg, 1, &modify->bearer_cap);

	new_cc_state(trans, GSM_CSTATE_ACTIVE);

	return gsm48_sendmsg(msg, trans);
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
	tlv_parse(&tp, &rsl_att_tlvdef, gh->data, payload_len, GSM48_IE_BEARER_CAP, GSM48_IE_CAUSE);
	/* bearer capability */
	if (TLVP_PRESENT(&tp, GSM48_IE_BEARER_CAP)) {
		modify.fields |= GSM48_IE_BEARER_CAP;
		decode_bearer_cap(&modify.bearer_cap,
				  TLVP_VAL(&tp, GSM48_IE_BEARER_CAP)-1);
	}
	/* cause */
	if (TLVP_PRESENT(&tp, GSM48_IE_CAUSE)) {
		modify.fields |= MNCC_F_CAUSE;
		decode_cause(&modify.cause,
			     TLVP_VAL(&tp, GSM48_IE_CAUSE)-1);
	}

	new_cc_state(trans, GSM_CSTATE_ACTIVE);

	return mncc_recvmsg(trans->subscr->net, trans, MNCC_MODIFY_REJ, &modify);
}

static int gsm48_cc_tx_modify_reject(struct gsm_trans *trans, void *arg)
{
	struct gsm_mncc *modify = arg;
	struct msgb *msg = gsm48_msgb_alloc();
	struct gsm48_hdr *gh = (struct gsm48_hdr *) msgb_put(msg, sizeof(*gh));

	gh->msg_type = GSM48_MT_CC_MODIFY_REJECT;

	/* bearer capability */
	encode_bearer_cap(msg, 1, &modify->bearer_cap);
	/* cause */
	encode_cause(msg, 1, &modify->cause);

	new_cc_state(trans, GSM_CSTATE_ACTIVE);

	return gsm48_sendmsg(msg, trans);
}

static int gsm48_cc_tx_notify(struct gsm_trans *trans, void *arg)
{
	struct gsm_mncc *notify = arg;
	struct msgb *msg = gsm48_msgb_alloc();
	struct gsm48_hdr *gh = (struct gsm48_hdr *) msgb_put(msg, sizeof(*gh));

	gh->msg_type = GSM48_MT_CC_NOTIFY;

	/* notify */
	encode_notify(msg, notify->notify);

	return gsm48_sendmsg(msg, trans);
}

static int gsm48_cc_rx_notify(struct gsm_trans *trans, struct msgb *msg)
{
	struct gsm48_hdr *gh = msgb_l3(msg);
	unsigned int payload_len = msgb_l3len(msg) - sizeof(*gh);
//	struct tlv_parsed tp;
	struct gsm_mncc notify;

	memset(&notify, 0, sizeof(struct gsm_mncc));
	notify.callref = trans->callref;
//	tlv_parse(&tp, &rsl_att_tlvdef, gh->data, payload_len);
	if (payload_len >= 1)
		decode_notify(&notify.notify, gh->data);

	return mncc_recvmsg(trans->subscr->net, trans, MNCC_NOTIFY_IND, &notify);
}

static int gsm48_cc_tx_userinfo(struct gsm_trans *trans, void *arg)
{
	struct gsm_mncc *user = arg;
	struct msgb *msg = gsm48_msgb_alloc();
	struct gsm48_hdr *gh = (struct gsm48_hdr *) msgb_put(msg, sizeof(*gh));

	gh->msg_type = GSM48_MT_CC_USER_INFO;

	/* user-user */
	if (user->fields & MNCC_F_USERUSER)
		encode_useruser(msg, 1, &user->useruser);
	/* more data */
	if (user->more)
		encode_more(msg);

	return gsm48_sendmsg(msg, trans);
}

static int gsm48_cc_rx_userinfo(struct gsm_trans *trans, struct msgb *msg)
{
	struct gsm48_hdr *gh = msgb_l3(msg);
	unsigned int payload_len = msgb_l3len(msg) - sizeof(*gh);
	struct tlv_parsed tp;
	struct gsm_mncc user;

	memset(&user, 0, sizeof(struct gsm_mncc));
	user.callref = trans->callref;
	tlv_parse(&tp, &rsl_att_tlvdef, gh->data, payload_len, GSM48_IE_USER_USER, 0);
	/* user-user */
	if (TLVP_PRESENT(&tp, GSM48_IE_USER_USER)) {
		user.fields |= MNCC_F_USERUSER;
		decode_useruser(&user.useruser,
				TLVP_VAL(&tp, GSM48_IE_USER_USER)-1);
	}
	/* more data */
	if (TLVP_PRESENT(&tp, GSM48_IE_MORE_DATA))
		user.more = 1;

	return mncc_recvmsg(trans->subscr->net, trans, MNCC_USERINFO_IND, &user);
}

static int _gsm48_lchan_modify(struct gsm_trans *trans, void *arg)
{
	struct gsm_mncc *mode = arg;

	return gsm48_lchan_modify(trans->lchan, mode->lchan_mode);
}

static struct downstate {
	u_int32_t	states;
	int		type;
	int		(*rout) (struct gsm_trans *trans, void *arg);
} downstatelist[] = {
	/* mobile originating call establishment */
	{SBIT(GSM_CSTATE_INITIATED), /* 5.2.1.2 */
	 MNCC_CALL_PROC_REQ, gsm48_cc_tx_call_proc},
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


int mncc_send(struct gsm_network *net, int msg_type, void *arg)
{
	int i, rc = 0;
	struct gsm_trans *trans = NULL, *transt;
	struct gsm_subscriber *subscr;
	struct gsm_lchan *lchan = NULL;
	struct gsm_bts *bts = NULL;
	struct gsm_mncc *data = arg, rel;

	/* handle special messages */
	switch(msg_type) {
	case MNCC_BRIDGE:
		return tch_bridge(net, arg);
	case MNCC_FRAME_DROP:
		return tch_recv(net, arg, 0);
	case MNCC_FRAME_RECV:
		return tch_recv(net, arg, 1);
	case GSM_TRAU_FRAME:
		return tch_frame(net, arg);
	}

	memset(&rel, 0, sizeof(struct gsm_mncc));
	rel.callref = data->callref;

	/* Find callref */
	trans = trans_find_by_callref(net, data->callref);

	/* Callref unknown */
	if (!trans) {
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
			subscr = subscr_get_by_extension(net,
							data->called.number);
		else
			subscr = subscr_get_by_imsi(net, data->imsi);
		/* If subscriber is not found */
		if (!subscr) {
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
		if (!subscr->lac) {
			DEBUGP(DCC, "(bts - trx - ts - ti -- sub %s) "
				"Received '%s' from MNCC with "
				"detached subscriber %s\n", data->called.number,
				get_mncc_name(msg_type), data->called.number);
			subscr_put(subscr);
			/* Temporarily out of order */
			return mncc_release_ind(net, NULL, data->callref,
						GSM48_CAUSE_LOC_PRN_S_LU,
						GSM48_CC_CAUSE_DEST_OOO);
		}
		/* Create transaction */
		trans = trans_alloc(subscr, GSM48_PDISC_CC, 0xff, data->callref);
		if (!trans) {
			DEBUGP(DCC, "No memory for trans.\n");
			subscr_put(subscr);
			/* Ressource unavailable */
			mncc_release_ind(net, NULL, data->callref,
					 GSM48_CAUSE_LOC_PRN_S_LU,
					 GSM48_CC_CAUSE_RESOURCE_UNAVAIL);
			return -ENOMEM;
		}
		/* Find lchan */
		lchan = lchan_for_subscr(subscr);
		/* If subscriber has no lchan */
		if (!lchan) {
			/* find transaction with this subscriber already paging */
			llist_for_each_entry(transt, &net->trans_list, entry) {
				/* Transaction of our lchan? */
				if (transt == trans ||
				    transt->subscr != subscr)
					continue;
				DEBUGP(DCC, "(bts %d trx - ts - ti -- sub %s) "
					"Received '%s' from MNCC with "
					"unallocated channel, paging already "
					"started.\n", bts->nr,
					data->called.number,
					get_mncc_name(msg_type));
				return 0;
			}
			/* store setup informations until paging was successfull */
			memcpy(&trans->cc.msg, data, sizeof(struct gsm_mncc));
			/* Trigger paging */
			paging_request(net, subscr, RSL_CHANNEED_TCH_F,
					setup_trig_pag_evt, subscr);
			return 0;
		}
		/* Assign lchan */
		trans->lchan = lchan;
		use_lchan(lchan);
	}
	lchan = trans->lchan;

	/* if paging did not respond yet */
	if (!lchan) {
		DEBUGP(DCC, "(bts - trx - ts - ti -- sub %s) "
			"Received '%s' from MNCC in paging state\n", 
			(trans->subscr)?(trans->subscr->extension):"-",
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

	DEBUGP(DCC, "(bts %d trx %d ts %d ti %02x sub %s) "
		"Received '%s' from MNCC in state %d (%s)\n",
		lchan->ts->trx->bts->nr, lchan->ts->trx->nr, lchan->ts->nr,
		trans->transaction_id,
		(lchan->subscr)?(lchan->subscr->extension):"-",
		get_mncc_name(msg_type), trans->cc.state,
		cc_state_names[trans->cc.state]);

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
	u_int32_t	states;
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

static int gsm0408_rcv_cc(struct msgb *msg)
{
	struct gsm48_hdr *gh = msgb_l3(msg);
	u_int8_t msg_type = gh->msg_type & 0xbf;
	u_int8_t transaction_id = ((gh->proto_discr & 0xf0) ^ 0x80) >> 4; /* flip */
	struct gsm_lchan *lchan = msg->lchan;
	struct gsm_trans *trans = NULL;
	int i, rc = 0;

	if (msg_type & 0x80) {
		DEBUGP(DCC, "MSG 0x%2x not defined for PD error\n", msg_type);
		return -EINVAL;
	}
	
	/* Find transaction */
	trans = trans_find_by_id(lchan->subscr, GSM48_PDISC_CC, transaction_id);

	DEBUGP(DCC, "(bts %d trx %d ts %d ti %x sub %s) "
		"Received '%s' from MS in state %d (%s)\n",
		lchan->ts->trx->bts->nr, lchan->ts->trx->nr, lchan->ts->nr,
		transaction_id, (lchan->subscr)?(lchan->subscr->extension):"-",
		gsm0408_cc_msg_names[msg_type], trans?(trans->cc.state):0,
		cc_state_names[trans?(trans->cc.state):0]);

	/* Create transaction */
	if (!trans) {
		DEBUGP(DCC, "Unknown transaction ID %x, "
			"creating new trans.\n", transaction_id);
		/* Create transaction */
		trans = trans_alloc(lchan->subscr, GSM48_PDISC_CC,
				    transaction_id, new_callref++);
		if (!trans) {
			DEBUGP(DCC, "No memory for trans.\n");
			rc = gsm48_tx_simple(msg->lchan,
					     GSM48_PDISC_CC | (transaction_id << 4),
					     GSM48_MT_CC_RELEASE_COMPL);
			return -ENOMEM;
		}
		/* Assign transaction */
		trans->lchan = lchan;
		use_lchan(lchan);
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

	rc = datastatelist[i].rout(trans, msg);

	return rc;
}

/* here we pass in a msgb from the RSL->RLL.  We expect the l3 pointer to be set */
int gsm0408_rcvmsg(struct msgb *msg, u_int8_t link_id)
{
	struct gsm48_hdr *gh = msgb_l3(msg);
	u_int8_t pdisc = gh->proto_discr & 0x0f;
	int rc = 0;
	
	switch (pdisc) {
	case GSM48_PDISC_CC:
		rc = gsm0408_rcv_cc(msg);
		break;
	case GSM48_PDISC_MM:
		rc = gsm0408_rcv_mm(msg);
		break;
	case GSM48_PDISC_RR:
		rc = gsm0408_rcv_rr(msg);
		break;
	case GSM48_PDISC_SMS:
		rc = gsm0411_rcv_sms(msg, link_id);
		break;
	case GSM48_PDISC_MM_GPRS:
	case GSM48_PDISC_SM_GPRS:
		fprintf(stderr, "Unimplemented GSM 04.08 discriminator 0x%02x\n",
			pdisc);
		break;
	case GSM48_PDISC_NC_SS:
		rc = handle_rcv_ussd(msg);
		break;
	default:
		fprintf(stderr, "Unknown GSM 04.08 discriminator 0x%02x\n",
			pdisc);
		break;
	}

	return rc;
}

/* dequeue messages to layer 4 */
int bsc_upqueue(struct gsm_network *net)
{
	struct gsm_mncc *mncc;
	struct msgb *msg;
	int work = 0;

	if (net)
		while ((msg = msgb_dequeue(&net->upqueue))) {
			mncc = (struct gsm_mncc *)msg->data;
			if (net->mncc_recv)
				net->mncc_recv(net, mncc->msg_type, mncc);
			work = 1; /* work done */
			talloc_free(msg);
		}

	return work;
}

/*
 * This will be ran by the linker when loading the DSO. We use it to
 * do system initialization, e.g. registration of signal handlers.
 */
static __attribute__((constructor)) void on_dso_load_0408(void)
{
	register_signal_handler(SS_LCHAN, gsm0408_handle_lchan_signal, NULL);
	register_signal_handler(SS_ABISIP, handle_abisip_signal, NULL);
}
