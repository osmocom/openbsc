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
#include <openbsc/gsm_subscriber.h>
#include <openbsc/gsm_04_11.h>
#include <openbsc/gsm_04_08.h>
#include <openbsc/abis_rsl.h>
#include <openbsc/chan_alloc.h>
#include <openbsc/paging.h>
#include <openbsc/signal.h>
#include <openbsc/trau_frame.h>
#include <openbsc/trau_mux.h>

#define GSM48_ALLOC_SIZE	1024
#define GSM48_ALLOC_HEADROOM	128

#define GSM_MAX_FACILITY       128
#define GSM_MAX_SSVERSION      128
#define GSM_MAX_USERUSER       128

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
	if (data[1] & 0x40)
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

static int authorize_everonye = 0;
void gsm0408_allow_everyone(int everyone)
{
	printf("Allowing everyone?\n");
	authorize_everonye = everyone;
}

static int reject_cause = 0;
void gsm0408_set_reject_cause(int cause)
{
	reject_cause = cause;
}

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

	if (authorize_everonye)
		return 1;

	return subscriber->authorized;
}

static void release_loc_updating_req(struct gsm_lchan *lchan)
{
	if (!lchan->loc_operation)
		return;

	bsc_del_timer(&lchan->loc_operation->updating_timer);
	free(lchan->loc_operation);
	lchan->loc_operation = 0;
	put_lchan(lchan);
}

static void allocate_loc_updating_req(struct gsm_lchan *lchan)
{
	use_lchan(lchan);
	release_loc_updating_req(lchan);

	lchan->loc_operation = (struct gsm_loc_updating_operation *)
				malloc(sizeof(*lchan->loc_operation));
	memset(lchan->loc_operation, 0, sizeof(*lchan->loc_operation));
}

static int gsm0408_authorize(struct gsm_lchan *lchan, struct msgb *msg)
{
	u_int32_t tmsi;

	if (authorize_subscriber(lchan->loc_operation, lchan->subscr)) {
		db_subscriber_alloc_tmsi(lchan->subscr);
		subscr_update(lchan->subscr, msg->trx->bts, GSM_SUBSCRIBER_UPDATE_ATTACHED);
		tmsi = strtoul(lchan->subscr->tmsi, NULL, 10);
		release_loc_updating_req(lchan);
		return gsm0408_loc_upd_acc(msg->lchan, tmsi);
	}

	return 0;
}

static int gsm0408_handle_lchan_signal(unsigned int subsys, unsigned int signal,
					void *handler_data, void *signal_data)
{
	if (subsys != SS_LCHAN || signal != S_LCHAN_UNEXPECTED_RELEASE)
		return 0;

	/*
	 * Cancel any outstanding location updating request
	 * operation taking place on the lchan.
	 */
	struct gsm_lchan *lchan = (struct gsm_lchan *)handler_data;
	release_loc_updating_req(lchan);

	return 0;
}

/*
 * This will be ran by the linker when loading the DSO. We use it to
 * do system initialization, e.g. registration of signal handlers.
 */
static __attribute__((constructor)) void on_dso_load_0408(void)
{
	register_signal_handler(SS_LCHAN, gsm0408_handle_lchan_signal, NULL);
}

static void to_bcd(u_int8_t *bcd, u_int16_t val)
{
	bcd[2] = val % 10;
	val = val / 10;
	bcd[1] = val % 10;
	val = val / 10;
	bcd[0] = val % 10;
	val = val / 10;
}

void gsm0408_generate_lai(struct gsm48_loc_area_id *lai48, u_int16_t mcc, 
			 u_int16_t mnc, u_int16_t lac)
{
	u_int8_t bcd[3];

	to_bcd(bcd, mcc);
	lai48->digits[0] = bcd[0] | (bcd[1] << 4);
	lai48->digits[1] = bcd[2];

	to_bcd(bcd, mnc);
	/* FIXME: do we need three-digit MNC? See Table 10.5.3 */
#if 0
	lai48->digits[1] |= bcd[2] << 4;
	lai48->digits[2] = bcd[0] | (bcd[1] << 4);
#else
	lai48->digits[1] |= 0xf << 4;
	lai48->digits[2] = bcd[1] | (bcd[2] << 4);
#endif
	
	lai48->lac = htons(lac);
}

#define TMSI_LEN	5
#define MID_TMSI_LEN	(TMSI_LEN + 2)

int generate_mid_from_tmsi(u_int8_t *buf, u_int32_t tmsi)
{
	u_int32_t *tptr = (u_int32_t *) &buf[3];

	buf[0] = GSM48_IE_MOBILE_ID;
	buf[1] = TMSI_LEN;
	buf[2] = 0xf0 | GSM_MI_TYPE_TMSI;
	*tptr = htonl(tmsi);

	return 7;
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
static int decode_bearer_cap(int *transfer, int *mode, int *coding,
			     int *radio, int *speech_ctm, int *speech_ver,
			     const u_int8_t *lv)
{
	u_int8_t in_len = lv[0];
	int i, s;

	if (in_len < 1)
		return -EINVAL;

	speech_ver[0] = -1; /* end of list, of maximum 7 values */

	/* octet 3 */
	*transfer = lv[1] & 0x07;
	*mode = (lv[1] & 0x08) >> 3;
	*coding = (lv[1] & 0x10) >> 4;
	*radio = (lv[1] & 0x60) >> 5;

	i = 1;
	s = 0;
	while(!(lv[i] & 0x80)) {
		i++; /* octet 3a etc */
		if (in_len < i)
			return 0;
		speech_ver[s++] = lv[i] & 0x0f;
		speech_ver[s] = -1; /* end of list */
		if (i == 2) /* octet 3a */
			*speech_ctm = (lv[i] & 0x20) >> 5;
		if (s == 7) /* maximum speech versions + end of list */
			return 0;
	}

	return 0;
}

/* encode 'bearer capability' */
static int encode_bearer_cap(int lv_only, struct msgb *msg, int transfer,
			     int mode, int coding, int radio, int speech_ctm,
			     int *speech_ver)
{
	u_int8_t lv[32 + 1];
	int i, s;

	lv[1] = transfer;
	lv[1] |= mode << 3;
	lv[1] |= coding << 4;
	lv[1] |= radio << 5;

	i = 1;
	for (s = 0; speech_ver[s] >= 0; s++) {
		i++; /* octet 3a etc */
		lv[i] = speech_ver[s];
		if (i == 2) /* octet 3a */
			lv[i] |= speech_ctm << 5;
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
static int decode_cccap(int *dtmf, int *pcp, const u_int8_t *lv)
{
	u_int8_t in_len = lv[0];

	if (in_len < 1)
		return -EINVAL;

	/* octet 3 */
	*dtmf = lv[1] & 0x01;
	*pcp = (lv[1] & 0x02) >> 1;
	
	return 0;
}

/* decode 'called party BCD number' */
static int decode_called(int *type, int *plan, char *number,
			 int number_len, const u_int8_t *lv)
{
	u_int8_t in_len = lv[0];

	if (in_len < 1)
		return -EINVAL;

	/* octet 3 */
	*plan = lv[1] & 0x0f;
	*type = (lv[1] & 0x70) >> 4;

	/* octet 4..N */
	decode_bcd_number(number, number_len, lv, 1);
	
	return 0;
}

/* encode 'called party BCD number' */
static int encode_called(struct msgb *msg, int type, int plan, char *number)
{
	u_int8_t lv[18];
	int ret;

	/* octet 3 */
	lv[1] = plan;
	lv[1] |= type << 4;

	/* octet 4..N, octet 2 */
	ret = encode_bcd_number(lv, sizeof(lv), 1, number);
	if (ret < 0)
		return ret;

	msgb_tlv_put(msg, GSM48_IE_CALLED_BCD, lv[0], lv+1);

	return 0;
}

/* encode callerid of various IEs */
static int encode_callerid(struct msgb *msg, int ie, int type, int plan,
			   int present, int screen, char *number)
{
	u_int8_t lv[13];
	int h_len = 1;
	int ret;

	/* octet 3 */
	lv[1] = plan;
	lv[1] |= type << 4;

	if (present || screen) {
		/* octet 3a */
		lv[2] = screen;
		lv[2] |= present << 5;
		lv[2] |= 0x80;
		h_len++;
	} else
		lv[1] |= 0x80;

	/* octet 4..N, octet 2 */
	ret = encode_bcd_number(lv, sizeof(lv), h_len, number);
	if (ret < 0)
		return ret;

	msgb_tlv_put(msg, ie, lv[0], lv+1);

	return 0;
}

/* decode 'cause' */
static int decode_cause(int *location, int *coding, int *rec, int *rec_val,
			int *value, u_char *diag, u_int *diag_len,
			const u_int8_t *lv)
{
	u_int8_t in_len = lv[0];
	int i;

	if (in_len < 2)
		return -EINVAL;

	*diag_len = 0;

	/* octet 3 */
	*location = lv[1] & 0x0f;
	*coding = (lv[1] & 0x60) >> 5;
	
	i = 1;
	if (!(lv[i] & 0x80)) {
		i++; /* octet 3a */
		if (in_len < i+1)
			return 0;
		*rec = 1;
		*rec_val = lv[i] & 0x7f;
		
	}
	i++;

	/* octet 4 */
	*value = lv[i] & 0x7f;
	i++;

	if (in_len < i) /* no diag */
		return 0;

	if (in_len - (i-1) > 32) /* maximum 32 octets */
		return 0;

	/* octet 5-N */
	memcpy(diag, lv + i, in_len - (i-1));
	*diag_len = in_len - (i-1);

	return 0;
}

/* encode 'cause' */
static int encode_cause(int lv_only, struct msgb *msg, int location,
			int coding, int rec, int rec_val, int value,
			u_char *diag, u_int diag_len)
{
	u_int8_t lv[32+4];
	int i;

	if (diag_len > 32)
		return -EINVAL;

	/* octet 3 */
	lv[1] = location;
	lv[1] |= coding << 5;

	i = 1;
	if (rec) {
		i++; /* octet 3a */
		lv[i] = rec_val;
	}
	lv[i] |= 0x80; /* end of octet 3 */

	/* octet 4 */
	i++;
	lv[i] = 0x80 | value;

	/* octet 5-N */
	if (diag_len) {
		memcpy(lv + i, diag, diag_len);
		i += diag_len;
	}

	lv[0] = i;
	if (lv_only)
		msgb_lv_put(msg, lv[0], lv+1);
	else
		msgb_tlv_put(msg, GSM48_IE_CAUSE, lv[0], lv+1);

	return 0;
}

/* encode 'calling number' */
static int encode_calling(struct msgb *msg, int type, int plan, int present,
			  int screen, char *number)
{
	return encode_callerid(msg, GSM48_IE_CALLING_BCD, type, plan,
				present, screen, number);
}

/* encode 'connected number' */
static int encode_connected(struct msgb *msg, int type, int plan, int present,
			    int screen, char *number)
{
	return encode_callerid(msg, GSM48_IE_CONN_BCD, type, plan,
				present, screen, number);
}

/* encode 'redirecting number' */
static int encode_redirecting(struct msgb *msg, int type, int plan, int present,
			      int screen, char *number)
{
	return encode_callerid(msg, GSM48_IE_REDIR_BCD, type, plan,
				present, screen, number);
}

/* decode 'facility' */
static int decode_facility(char *info, int info_len, int *len,
			   const u_int8_t *lv)
{
	u_int8_t in_len = lv[0];

	if (in_len < 1)
		return -EINVAL;

	if (in_len > info_len)
		return -EINVAL;

	memcpy(info, lv+1, in_len);
	*len = in_len;

	return 0;
}

/* encode 'facility' */
static int encode_facility(int lv_only, struct msgb *msg, char *info, int len)
{
	u_int8_t lv[GSM_MAX_FACILITY + 1];

	if (len < 1 || len > GSM_MAX_FACILITY)
		return -EINVAL;

	memcpy(lv+1, info, len);
	lv[0] = len;
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
static int decode_progress(int *coding, int *location, int *descr,
			   const u_int8_t *lv)
{
	u_int8_t in_len = lv[0];

	if (in_len < 2)
		return -EINVAL;

	*coding = (lv[1] & 0x60) >> 5;
	*location = lv[1] & 0x0f;
	*descr = lv[2] & 0x7f;
	
	return 0;
}

/* encode 'progress' */
static int encode_progress(int lv_only, struct msgb *msg, int coding,
			   int location, int descr)
{
	u_int8_t lv[3];

	lv[0] = 2;
	lv[1] = 0x80 | ((coding & 0x3) << 5) | (location & 0xf);
	lv[2] = 0x80 | (descr & 0x7f);
	if (lv_only)
		msgb_lv_put(msg, lv[0], lv+1);
	else
		msgb_tlv_put(msg, GSM48_IE_PROGR_IND, lv[0], lv+1);

	return 0;
}

/* decode 'user-user' */
static int decode_useruser(int *proto, char *info, int info_len,
			   const u_int8_t *lv)
{
	u_int8_t in_len = lv[0];
	int i;

	if (in_len < 1)
		return -EINVAL;

	*proto = lv[1];

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
static int encode_useruser(int lv_only, struct msgb *msg, int proto, char *info)
{
	u_int8_t lv[GSM_MAX_USERUSER + 2];

	if (strlen(info) > GSM_MAX_USERUSER)
		return -EINVAL;

	lv[0] = 1 + strlen(info);
	lv[1] = proto;
	memcpy(lv + 2, info, strlen(info));
	if (lv_only)
		msgb_lv_put(msg, lv[0], lv+1);
	else
		msgb_tlv_put(msg, GSM48_IE_USER_USER, lv[0], lv+1);

	return 0;
}

/* decode 'ss version' */
static int decode_ssversion(char *info, int info_len, int *len,
			    const u_int8_t *lv)
{
	u_int8_t in_len = lv[0];

	if (in_len < 1 || in_len < info_len)
		return -EINVAL;

	memcpy(info, lv + 1, in_len);
	*len = in_len;

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

struct msgb *gsm48_msgb_alloc(void)
{
	return msgb_alloc_headroom(GSM48_ALLOC_SIZE, GSM48_ALLOC_HEADROOM);
}

int gsm48_sendmsg(struct msgb *msg)
{
	struct gsm48_hdr *gh = (struct gsm48_hdr *) msg->data;

	if (msg->lchan) {
		msg->trx = msg->lchan->ts->trx;

		if ((gh->proto_discr & GSM48_PDISC_MASK) == GSM48_PDISC_CC) {
			/* Send a 04.08 call control message, add transaction
			 * ID and TI flag */
			gh->proto_discr |= msg->lchan->call.transaction_id;

			/* GSM 04.07 Section 11.2.3.1.3 */
			switch (msg->lchan->call.type) {
			case GSM_CT_MO:
				gh->proto_discr |= 0x80;
				break;
			case GSM_CT_MT:
				break;
			case GSM_CT_NONE:
				break;
			}
		}
	}

	msg->l3h = msg->data;

	return rsl_data_request(msg, 0);
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
	
	return gsm48_sendmsg(msg);
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

	mid = msgb_put(msg, MID_TMSI_LEN);
	generate_mid_from_tmsi(mid, tmsi);

	DEBUGP(DMM, "-> LOCATION UPDATE ACCEPT\n");

	ret = gsm48_sendmsg(msg);

	ret = gsm48_tx_mm_info(lchan);

	return ret;
}

static char bcd2char(u_int8_t bcd)
{
	if (bcd < 0xa)
		return '0' + bcd;
	else
		return 'A' + (bcd - 0xa);
}

/* Convert Mobile Identity (10.5.1.4) to string */
static int mi_to_string(char *string, int str_len, u_int8_t *mi, int mi_len)
{
	int i;
	u_int8_t mi_type;
	char *str_cur = string;
	u_int32_t tmsi;

	mi_type = mi[0] & GSM_MI_TYPE_MASK;

	switch (mi_type) {
	case GSM_MI_TYPE_NONE:
		break;
	case GSM_MI_TYPE_TMSI:
		/* Table 10.5.4.3, reverse generate_mid_from_tmsi */
		if (mi_len == TMSI_LEN && mi[0] == (0xf0 | GSM_MI_TYPE_TMSI)) {
			memcpy(&tmsi, &mi[1], 4);
			tmsi = ntohl(tmsi);
			return snprintf(string, str_len, "%u", tmsi);
		}
		break;
	case GSM_MI_TYPE_IMSI:
	case GSM_MI_TYPE_IMEI:
	case GSM_MI_TYPE_IMEISV:
		*str_cur++ = bcd2char(mi[0] >> 4);
		
                for (i = 1; i < mi_len; i++) {
			if (str_cur + 2 >= string + str_len)
				return str_cur - string;
			*str_cur++ = bcd2char(mi[i] & 0xf);
			/* skip last nibble in last input byte when GSM_EVEN */
			if( (i != mi_len-1) || (mi[0] & GSM_MI_ODD))
				*str_cur++ = bcd2char(mi[i] >> 4);
		}
		break;
	default:
		break;
	}
	*str_cur++ = '\0';

	return str_cur - string;
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

	return gsm48_sendmsg(msg);
}

#define MI_SIZE 32

/* Parse Chapter 9.2.11 Identity Response */
static int mm_rx_id_resp(struct msgb *msg)
{
	struct gsm48_hdr *gh = msgb_l3(msg);
	struct gsm_lchan *lchan = msg->lchan;
	u_int8_t mi_type = gh->data[1] & GSM_MI_TYPE_MASK;
	char mi_string[MI_SIZE];

	mi_to_string(mi_string, sizeof(mi_string), &gh->data[1], gh->data[0]);
	DEBUGP(DMM, "IDENTITY RESPONSE: mi_type=0x%02x MI(%s)\n",
		mi_type, mi_string);

	switch (mi_type) {
	case GSM_MI_TYPE_IMSI:
		if (!lchan->subscr)
			lchan->subscr = db_create_subscriber(mi_string);
		if (lchan->loc_operation)
			lchan->loc_operation->waiting_for_imsi = 0;
		break;
	case GSM_MI_TYPE_IMEI:
	case GSM_MI_TYPE_IMEISV:
		/* update subscribe <-> IMEI mapping */
		if (lchan->subscr)
			db_subscriber_assoc_imei(lchan->subscr, mi_string);
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

#define MI_SIZE 32
/* Chapter 9.2.15: Receive Location Updating Request */
static int mm_rx_loc_upd_req(struct msgb *msg)
{
	struct gsm48_hdr *gh = msgb_l3(msg);
	struct gsm48_loc_upd_req *lu;
	struct gsm_subscriber *subscr;
	struct gsm_lchan *lchan = msg->lchan;
	u_int8_t mi_type;
	char mi_string[MI_SIZE];
	int rc;

 	lu = (struct gsm48_loc_upd_req *) gh->data;

	mi_type = lu->mi[0] & GSM_MI_TYPE_MASK;

	mi_to_string(mi_string, sizeof(mi_string), lu->mi, lu->mi_len);

	DEBUGP(DMM, "LUPDREQ: mi_type=0x%02x MI(%s) type=%s\n", mi_type, mi_string,
		lupd_name(lu->type));

	/*
	 * Pseudo Spoof detection: Just drop a second/concurrent
	 * location updating request.
	 */
	if (lchan->loc_operation) {
		DEBUGP(DMM, "LUPDREQ: ignoring request due an existing one: %p.\n",
			lchan->loc_operation);
		gsm0408_loc_upd_rej(lchan, GSM48_REJECT_PROTOCOL_ERROR);
		return 0;
	}

	allocate_loc_updating_req(lchan);

	switch (mi_type) {
	case GSM_MI_TYPE_IMSI:
		/* we always want the IMEI, too */
		rc = mm_tx_identity_req(lchan, GSM_MI_TYPE_IMEI);
		lchan->loc_operation->waiting_for_imei = 1;

		/* look up subscriber based on IMSI */
		subscr = db_create_subscriber(mi_string);
		break;
	case GSM_MI_TYPE_TMSI:
		/* we always want the IMEI, too */
		rc = mm_tx_identity_req(lchan, GSM_MI_TYPE_IMEI);
		lchan->loc_operation->waiting_for_imei = 1;

		/* look up the subscriber based on TMSI, request IMSI if it fails */
		subscr = subscr_get_by_tmsi(mi_string);
		if (!subscr) {
			/* send IDENTITY REQUEST message to get IMSI */
			rc = mm_tx_identity_req(lchan, GSM_MI_TYPE_IMSI);
			lchan->loc_operation->waiting_for_imsi = 1;
		}
		break;
	case GSM_MI_TYPE_IMEI:
	case GSM_MI_TYPE_IMEISV:
		/* no sim card... FIXME: what to do ? */
		DEBUGP(DMM, "unimplemented mobile identity type\n");
		break;
	default:	
		DEBUGP(DMM, "unknown mobile identity type\n");
		break;
	}

	lchan->subscr = subscr;

	/*
	 * Schedule the reject timer and check if we can let the
	 * subscriber into our network immediately or if we need to wait
	 * for identity responses.
	 */
	schedule_reject(lchan);
	return gsm0408_authorize(lchan, msg);
}

/* 9.1.5 Channel mode modify */
int gsm48_tx_chan_mode_modify(struct gsm_lchan *lchan, u_int8_t mode)
{
	struct msgb *msg = gsm48_msgb_alloc();
	struct gsm48_hdr *gh = (struct gsm48_hdr *) msgb_put(msg, sizeof(*gh));
	struct gsm48_chan_mode_modify *cmm =
		(struct gsm48_chan_mode_modify *) msgb_put(msg, sizeof(*cmm));
	u_int16_t arfcn = lchan->ts->trx->arfcn & 0x3ff;

	DEBUGP(DRR, "-> CHANNEL MODE MODIFY mode=0x%02x\n", mode);

	lchan->tch_mode = mode;
	msg->lchan = lchan;
	gh->proto_discr = GSM48_PDISC_RR;
	gh->msg_type = GSM48_MT_RR_CHAN_MODE_MODIF;

	/* fill the channel information element, this code
	 * should probably be shared with rsl_rx_chan_rqd() */
	cmm->chan_desc.chan_nr = lchan2chan_nr(lchan);
	cmm->chan_desc.h0.tsc = lchan->ts->trx->bts->tsc;
	cmm->chan_desc.h0.h = 0;
	cmm->chan_desc.h0.arfcn_high = arfcn >> 8;
	cmm->chan_desc.h0.arfcn_low = arfcn & 0xff;
	cmm->mode = mode;

	return gsm48_sendmsg(msg);
}

/* Section 9.2.15a */
int gsm48_tx_mm_info(struct gsm_lchan *lchan)
{
	struct msgb *msg = gsm48_msgb_alloc();
	struct gsm48_hdr *gh;
	struct gsm_network *net = lchan->ts->trx->bts->network;
	u_int8_t *ptr8;
	u_int16_t *ptr16;
	int name_len;
	int i;

	msg->lchan = lchan;

	gh = (struct gsm48_hdr *) msgb_put(msg, sizeof(*gh));
	gh->proto_discr = GSM48_PDISC_MM;
	gh->msg_type = GSM48_MT_MM_INFO;

	if (net->name_long) {
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
	}

	if (net->name_short) {
		name_len = strlen(net->name_short);
		/* 10.5.3.5a */
		ptr8 = (u_int8_t *) msgb_put(msg, 3);
		ptr8[0] = GSM48_IE_NAME_LONG;
		ptr8[1] = name_len*2 + 1;
		ptr8[2] = 0x90; /* UCS2, no spare bits, no CI */

		ptr16 = (u_int16_t *) msgb_put(msg, name_len*2);
		for (i = 0; i < name_len; i++)
			ptr16[i] = htons(net->name_short[i]);
	}

#if 0
	/* move back to the top */
	time_t cur_t;
	struct tm* cur_time;
	int tz15min;
	/* Section 10.5.3.9 */
	cur_t = time(NULL);
	cur_time = gmtime(cur_t);
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
	ptr8[6] = to_bcd8(tz15min);
	if (tz15min < 0)
		ptr8[6] |= 0x80;
#endif

	return gsm48_sendmsg(msg);
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

	return gsm48_sendmsg(msg);
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
	char mi_string[MI_SIZE];

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

	mi_to_string(mi_string, sizeof(mi_string), mi, mi_len);
	DEBUGPC(DMM, "serv_type=0x%02x mi_type=0x%02x M(%s)\n",
		req->cm_service_type, mi_type, mi_string);

	subscr = subscr_get_by_tmsi(mi_string);

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

	subscr->classmark2_len = classmark2_len;
	memcpy(subscr->classmark2, classmark2, classmark2_len);

	return gsm48_tx_mm_serv_ack(msg->lchan);
}

static int gsm48_rx_mm_imsi_detach_ind(struct msgb *msg)
{
	struct gsm48_hdr *gh = msgb_l3(msg);
	struct gsm48_imsi_detach_ind *idi =
				(struct gsm48_imsi_detach_ind *) gh->data;
	u_int8_t mi_type = idi->mi[0] & GSM_MI_TYPE_MASK;
	char mi_string[MI_SIZE];
	struct gsm_subscriber *subscr;

	mi_to_string(mi_string, sizeof(mi_string), idi->mi, idi->mi_len);
	DEBUGP(DMM, "IMSI DETACH INDICATION: mi_type=0x%02x MI(%s): ",
		mi_type, mi_string);

	switch (mi_type) {
	case GSM_MI_TYPE_TMSI:
		subscr = subscr_get_by_tmsi(mi_string);
		break;
	case GSM_MI_TYPE_IMSI:
		subscr = subscr_get_by_imsi(mi_string);
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
		subscr_put(subscr);
	} else
		DEBUGP(DMM, "Unknown Subscriber ?!?\n");

	put_lchan(msg->lchan);

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
	int rc;

	switch (gh->msg_type & 0xbf) {
	case GSM48_MT_MM_LOC_UPD_REQUEST:
		DEBUGP(DMM, "LOCATION UPDATING REQUEST\n");
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
static int gsm48_rr_rx_pag_resp(struct msgb *msg)
{
	struct gsm48_hdr *gh = msgb_l3(msg);
	u_int8_t *classmark2_lv = gh->data + 1;
	u_int8_t *mi_lv = gh->data + 2 + *classmark2_lv;
	u_int8_t mi_type = mi_lv[1] & GSM_MI_TYPE_MASK;
	char mi_string[MI_SIZE];
	struct gsm_subscriber *subscr;
	struct paging_signal_data sig_data;
	int rc = 0;

	mi_to_string(mi_string, sizeof(mi_string), mi_lv+1, *mi_lv);
	DEBUGP(DRR, "PAGING RESPONSE: mi_type=0x%02x MI(%s)\n",
		mi_type, mi_string);
	switch (mi_type) {
	case GSM_MI_TYPE_TMSI:
		subscr = subscr_get_by_tmsi(mi_string);
		break;
	case GSM_MI_TYPE_IMSI:
		subscr = subscr_get_by_imsi(mi_string);
		break;
	}

	if (!subscr) {
		DEBUGP(DRR, "<- Can't find any subscriber for this ID\n");
		/* FIXME: request id? close channel? */
		return -EINVAL;
	}
	DEBUGP(DRR, "<- Channel was requested by %s\n",
		subscr->name ? subscr->name : subscr->imsi);

	subscr->classmark2_len = *classmark2_lv;
	memcpy(subscr->classmark2, classmark2_lv+1, *classmark2_lv);

	if (!msg->lchan->subscr) {
		msg->lchan->subscr = subscr;
	} else if (msg->lchan->subscr != subscr) {
		DEBUGP(DRR, "<- Channel already owned by someone else?\n");
		subscr_put(subscr);
		return -EINVAL;
	} else {
		DEBUGP(DRR, "<- Channel already owned by us\n");
		subscr_put(subscr);
		subscr = msg->lchan->subscr;
	}

	sig_data.subscr = subscr;
	sig_data.bts	= msg->lchan->ts->trx->bts;
	sig_data.lchan	= msg->lchan;

	dispatch_signal(SS_PAGING, S_PAGING_COMPLETED, &sig_data);

	/* Stop paging on the bts we received the paging response */
	paging_request_stop(msg->trx->bts, subscr, msg->lchan);

	/* FIXME: somehow signal the completion of the PAGING to
	 * the entity that requested the paging */

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
		subscr->classmark2_len = cm2_len;
		memcpy(subscr->classmark2, cm2, cm2_len);
		if (cm3) {
			subscr->classmark3_len = cm3_len;
			memcpy(subscr->classmark3, cm3, cm3_len);
		}
	}

	/* FIXME: store the classmark2/3 values with the equipment register */

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

	DEBUGP(DRR, "MEASUREMENT REPORT ");
	parse_meas_rep(&meas_rep, gh->data, payload_len);
	if (meas_rep.flags & MEAS_REP_F_DTX)
		DEBUGPC(DRR, "DTX ");
	if (meas_rep.flags & MEAS_REP_F_BA1)
		DEBUGPC(DRR, "BA1 ");
	if (!(meas_rep.flags & MEAS_REP_F_VALID))
		DEBUGPC(DRR, "NOT VALID ");
	else
		DEBUGPC(DRR, "FULL(lev=%u, qual=%u) SUB(lev=%u, qual=%u) ",
		meas_rep.rxlev_full, meas_rep.rxqual_full, meas_rep.rxlev_sub,
		meas_rep.rxqual_sub);

	DEBUGPC(DRR, "NUM_NEIGH=%u\n", meas_rep.num_cell);

	/* FIXME: put the results somwhere */

	return 0;
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
		rc = gsm48_rr_rx_pag_resp(msg);
		break;
	case GSM48_MT_RR_CHAN_MODE_MODIF_ACK:
		DEBUGP(DRR, "CHANNEL MODE MODIFY ACK\n");
		rc = rsl_chan_mode_modify_req(msg->lchan);
		break;
	case GSM48_MT_RR_STATUS:
		rc = gsm48_rx_rr_status(msg);
		break;
	case GSM48_MT_RR_MEAS_REP:
		rc = gsm48_rx_rr_meas_rep(msg);
		break;
	default:
		fprintf(stderr, "Unimplemented GSM 04.08 RR msg type 0x%02x\n",
			gh->msg_type);
		break;
	}

	return rc;
}

/* 7.1.7 and 9.1.7 Channel release*/
int gsm48_send_rr_release(struct gsm_lchan *lchan)
{
	struct msgb *msg = gsm48_msgb_alloc();
	struct gsm48_hdr *gh = (struct gsm48_hdr *) msgb_put(msg, sizeof(*gh));
	u_int8_t *cause;

	msg->lchan = lchan;
	gh->proto_discr = GSM48_PDISC_RR;
	gh->msg_type = GSM48_MT_RR_CHAN_REL;

	cause = msgb_put(msg, 1);
	cause[0] = GSM48_RR_CAUSE_NORMAL;

	DEBUGP(DRR, "Sending Channel Release: Chan: Number: %d Type: %d\n",
		lchan->nr, lchan->type);

	return gsm48_sendmsg(msg);
}

/* Call Control */

/* The entire call control code is written in accordance with Figure 7.10c
 * for 'very early assignment', i.e. we allocate a TCH/F during IMMEDIATE
 * ASSIGN, then first use that TCH/F for signalling and later MODE MODIFY
 * it for voice */

static int gsm48_cc_tx_status(struct gsm_lchan *lchan)
{
	struct msgb *msg = gsm48_msgb_alloc();
	struct gsm48_hdr *gh = (struct gsm48_hdr *) msgb_put(msg, sizeof(*gh));
	u_int8_t *cause, *call_state;

	gh->proto_discr = GSM48_PDISC_CC;

	msg->lchan = lchan;

	gh->msg_type = GSM48_MT_CC_STATUS;

	cause = msgb_put(msg, 3);
	cause[0] = 2;
	cause[1] = GSM48_CAUSE_CS_GSM | GSM48_CAUSE_LOC_USER;
	cause[2] = 0x80 | 30;	/* response to status inquiry */

	call_state = msgb_put(msg, 1);
	call_state[0] = 0xc0 | 0x00;

	return gsm48_sendmsg(msg);
}

static int gsm48_tx_simple(struct gsm_lchan *lchan,
			   u_int8_t pdisc, u_int8_t msg_type)
{
	struct msgb *msg = gsm48_msgb_alloc();
	struct gsm48_hdr *gh = (struct gsm48_hdr *) msgb_put(msg, sizeof(*gh));

	msg->lchan = lchan;

	gh->proto_discr = pdisc;
	gh->msg_type = msg_type;

	return gsm48_sendmsg(msg);
}

/* call-back from paging the B-end of the connection */
static int setup_trig_pag_evt(unsigned int hooknum, unsigned int event,
			      struct msgb *msg, void *_lchan, void *param)
{
	struct gsm_lchan *lchan = _lchan;
	struct gsm_call *remote_call = param;
	struct gsm_call *call = &lchan->call;
	int rc = 0;

	if (hooknum != GSM_HOOK_RR_PAGING)
		return -EINVAL;

	switch (event) {
	case GSM_PAGING_SUCCEEDED:
		DEBUGP(DCC, "paging succeeded!\n");
		remote_call->remote_lchan = lchan;
		call->remote_lchan = remote_call->local_lchan;
		/* send SETUP request to called party */
		rc = gsm48_cc_tx_setup(lchan, call->remote_lchan->subscr);
		if (is_ipaccess_bts(lchan->ts->trx->bts))
			rsl_ipacc_bind(lchan);
		break;
	case GSM_PAGING_EXPIRED:
		DEBUGP(DCC, "paging expired!\n");
		/* notify caller that we cannot reach called party */
		/* FIXME: correct cause, etc */
		rc = gsm48_tx_simple(remote_call->local_lchan, GSM48_PDISC_CC,
				     GSM48_MT_CC_RELEASE_COMPL);
		break;
	}
	return rc;
}

static int gsm48_cc_rx_status_enq(struct msgb *msg)
{
	DEBUGP(DCC, "-> STATUS ENQ\n");
	return gsm48_cc_tx_status(msg->lchan);
}

static int gsm48_cc_rx_setup(struct msgb *msg)
{
	struct gsm_call *call = &msg->lchan->call;
	struct gsm48_hdr *gh = msgb_l3(msg);
	unsigned int payload_len = msgb_l3len(msg) - sizeof(*gh);
	struct gsm_subscriber *called_subscr;
	char called_number[(43-2)*2 + 1] = "\0";
	struct tlv_parsed tp;
	int ret;

	if (call->state == GSM_CSTATE_NULL ||
	    call->state == GSM_CSTATE_RELEASE_REQ)
		use_lchan(msg->lchan);

	call->type = GSM_CT_MO;
	call->state = GSM_CSTATE_INITIATED;
	call->local_lchan = msg->lchan;
	call->transaction_id = gh->proto_discr & 0xf0;

	tlv_parse(&tp, &rsl_att_tlvdef, gh->data, payload_len, 0, 0);
	if (!TLVP_PRESENT(&tp, GSM48_IE_CALLED_BCD))
		goto err;

	/* Parse the number that was dialed and lookup subscriber */
	decode_bcd_number(called_number, sizeof(called_number),
				     TLVP_VAL(&tp, GSM48_IE_CALLED_BCD)-1, 1);

	DEBUGP(DCC, "A -> SETUP(tid=0x%02x,number='%s')\n", call->transaction_id,
		called_number);

	called_subscr = subscr_get_by_extension(called_number);
	if (!called_subscr) {
		DEBUGP(DCC, "could not find subscriber, RELEASE\n");
		put_lchan(msg->lchan);
		return gsm48_tx_simple(msg->lchan, GSM48_PDISC_CC,
				GSM48_MT_CC_RELEASE_COMPL);
	}
	if (called_subscr == msg->lchan->subscr) {
		DEBUGP(DCC, "subscriber calling himself ?!?\n");
		put_lchan(msg->lchan);
		subscr_put(called_subscr);
		return gsm48_tx_simple(msg->lchan, GSM48_PDISC_CC,
				GSM48_MT_CC_RELEASE_COMPL);
	}

	subscr_get(msg->lchan->subscr);
	call->called_subscr = called_subscr;

	/* Start paging subscriber on all BTS in LAC of subscriber */
	subscr_get_channel(called_subscr, msg->trx->bts->network, RSL_CHANNEED_TCH_F,
		       setup_trig_pag_evt, call);

	/* send a CALL PROCEEDING message to the MO */
	ret = gsm48_tx_simple(msg->lchan, GSM48_PDISC_CC,
			       GSM48_MT_CC_CALL_PROC);

	if (is_ipaccess_bts(msg->trx->bts))
		rsl_ipacc_bind(msg->lchan);

	/* change TCH/F mode to voice */ 
	return gsm48_tx_chan_mode_modify(msg->lchan, GSM48_CMODE_SPEECH_EFR);

err:
	/* FIXME: send some kind of RELEASE */
	return 0;
}

static int gsm48_cc_rx_alerting(struct msgb *msg)
{
	struct gsm_call *call = &msg->lchan->call;

	DEBUGP(DCC, "A -> ALERTING\n");

	/* forward ALERTING to other party */
	if (!call->remote_lchan)
		return -EIO;

	DEBUGP(DCC, "B <- ALERTING\n");
	return gsm48_tx_simple(call->remote_lchan, GSM48_PDISC_CC,
			       GSM48_MT_CC_ALERTING);
}

/* map two ipaccess RTP streams onto each other */
static int tch_map(struct gsm_lchan *lchan, struct gsm_lchan *remote_lchan)
{
	struct gsm_bts *bts = lchan->ts->trx->bts;
	struct gsm_bts *remote_bts = remote_lchan->ts->trx->bts;
	struct gsm_bts_trx_ts *ts;

	DEBUGP(DCC, "Setting up TCH map between (bts=%u,trx=%u,ts=%u) and (bts=%u,trx=%u,ts=%u)\n",
		bts->nr, lchan->ts->trx->nr, lchan->ts->nr,
		remote_bts->nr, remote_lchan->ts->trx->nr, remote_lchan->ts->nr);

	if (bts->type != remote_bts->type) {
		DEBUGP(DCC, "Cannot switch calls between different BTS types yet\n");
		return -EINVAL;
	}
	
	switch (bts->type) {
	case GSM_BTS_TYPE_NANOBTS_900:
	case GSM_BTS_TYPE_NANOBTS_1800:
		ts = remote_lchan->ts;
		rsl_ipacc_connect(lchan, ts->abis_ip.bound_ip, ts->abis_ip.bound_port,
				  lchan->ts->abis_ip.attr_f8, ts->abis_ip.attr_fc);
	
		ts = lchan->ts;
		rsl_ipacc_connect(remote_lchan, ts->abis_ip.bound_ip, ts->abis_ip.bound_port,
				  remote_lchan->ts->abis_ip.attr_f8, ts->abis_ip.attr_fc);
		break;
	case GSM_BTS_TYPE_BS11:
		trau_mux_map_lchan(lchan, remote_lchan);
		break;
	default:
		DEBUGP(DCC, "Unknown BTS type %u\n", bts->type);
		break;
	}

	return 0;
}

static int gsm48_cc_rx_connect(struct msgb *msg)
{
	struct gsm_call *call = &msg->lchan->call;
	int rc;

	DEBUGP(DCC, "A -> CONNECT\n");
	
	rc = tch_map(msg->lchan, call->remote_lchan);
	if (rc)
		return -EIO;
		
	if (!call->remote_lchan)
		return -EIO;

	DEBUGP(DCC, "A <- CONNECT ACK\n");
	/* MT+MO: need to respond with CONNECT_ACK and pass on */
	rc = gsm48_tx_simple(msg->lchan, GSM48_PDISC_CC,
			     GSM48_MT_CC_CONNECT_ACK);


	/* forward CONNECT to other party */
	DEBUGP(DCC, "B <- CONNECT\n");
	return gsm48_tx_simple(call->remote_lchan, GSM48_PDISC_CC,
			       GSM48_MT_CC_CONNECT);
}

static int gsm48_cc_rx_disconnect(struct msgb *msg)
{
	struct gsm_call *call = &msg->lchan->call;
	int rc;


	/* Section 5.4.3.2 */
	DEBUGP(DCC, "A -> DISCONNECT (state->RELEASE_REQ)\n");
	call->state = GSM_CSTATE_RELEASE_REQ;
	/* FIXME: clear the network connection */
	DEBUGP(DCC, "A <- RELEASE\n");
	rc = gsm48_tx_simple(msg->lchan, GSM48_PDISC_CC,
			     GSM48_MT_CC_RELEASE);

	/*
	 * FIXME: This looks wrong! We should have a single
	 * place to do MMCC-REL-CNF/-REQ/-IND and then switch
	 * to the NULL state and relase the call
	 */
	subscr_put_channel(msg->lchan);

	/* forward DISCONNECT to other party */
	if (!call->remote_lchan)
		return -EIO;

	DEBUGP(DCC, "B <- DISCONNECT\n");
	return gsm48_tx_simple(call->remote_lchan, GSM48_PDISC_CC,
			       GSM48_MT_CC_DISCONNECT);
}

static const u_int8_t calling_bcd[] = { 0xb9, 0x32, 0x24 };

int gsm48_cc_tx_setup(struct gsm_lchan *lchan, 
		      struct gsm_subscriber *calling_subscr)
{
	struct msgb *msg = gsm48_msgb_alloc();
	struct gsm48_hdr *gh;
	struct gsm_call *call = &lchan->call;
	u_int8_t bcd_lv[19];

	gh = (struct gsm48_hdr *) msgb_put(msg, sizeof(*gh));

	call->type = GSM_CT_MT;

	call->local_lchan = msg->lchan = lchan;
	use_lchan(lchan);

	gh->proto_discr = GSM48_PDISC_CC;
	gh->msg_type = GSM48_MT_CC_SETUP;

	msgb_tv_put(msg, GSM48_IE_SIGNAL, GSM48_SIGNAL_DIALTONE);
	if (calling_subscr) {
		bcd_lv[1] = 0xb9;
		encode_bcd_number(bcd_lv, sizeof(bcd_lv), 1,
				  calling_subscr->extension);
		msgb_tlv_put(msg, GSM48_IE_CALLING_BCD,
			     bcd_lv[0], bcd_lv+1);
	}
	if (lchan->subscr) {
		bcd_lv[1] = 0xb9;
		encode_bcd_number(bcd_lv, sizeof(bcd_lv), 1,
				  lchan->subscr->extension);
		msgb_tlv_put(msg, GSM48_IE_CALLED_BCD,
			     bcd_lv[0], bcd_lv+1);
	}

	DEBUGP(DCC, "B <- SETUP\n");

	return gsm48_sendmsg(msg);
}

static int gsm0408_rcv_cc(struct msgb *msg)
{
	struct gsm48_hdr *gh = msgb_l3(msg);
	u_int8_t msg_type = gh->msg_type & 0xbf;
	struct gsm_call *call = &msg->lchan->call;
	int rc = 0;

	switch (msg_type) {
	case GSM48_MT_CC_CALL_CONF:
		/* Response to SETUP */
		DEBUGP(DCC, "-> CALL CONFIRM\n");
		/* we now need to MODIFY the channel */
		rc = gsm48_tx_chan_mode_modify(msg->lchan, GSM48_CMODE_SPEECH_EFR);
		break;
	case GSM48_MT_CC_RELEASE_COMPL:
		/* Answer from MS to RELEASE */
		DEBUGP(DCC, "-> RELEASE COMPLETE (state->NULL)\n");
		call->state = GSM_CSTATE_NULL;
		break;
	case GSM48_MT_CC_ALERTING:
		rc = gsm48_cc_rx_alerting(msg);
		break;
	case GSM48_MT_CC_CONNECT:
		rc = gsm48_cc_rx_connect(msg);
		break;
	case GSM48_MT_CC_CONNECT_ACK:
		/* MO: Answer to CONNECT */
		call->state = GSM_CSTATE_ACTIVE;
		DEBUGP(DCC, "-> CONNECT_ACK (state->ACTIVE)\n");
		break;
	case GSM48_MT_CC_RELEASE:
		DEBUGP(DCC, "-> RELEASE\n");
		DEBUGP(DCC, "<- RELEASE_COMPLETE\n");
		/* need to respond with RELEASE_COMPLETE */
		rc = gsm48_tx_simple(msg->lchan, GSM48_PDISC_CC,
				     GSM48_MT_CC_RELEASE_COMPL);
		subscr_put_channel(msg->lchan);
                call->state = GSM_CSTATE_NULL;
		break;
	case GSM48_MT_CC_STATUS_ENQ:
		rc = gsm48_cc_rx_status_enq(msg);
		break;
	case GSM48_MT_CC_DISCONNECT:
		rc = gsm48_cc_rx_disconnect(msg);
		break;
	case GSM48_MT_CC_SETUP:
		/* MO: wants to establish a call */
		rc = gsm48_cc_rx_setup(msg);
		break;
	case GSM48_MT_CC_EMERG_SETUP:
		DEBUGP(DCC, "-> EMERGENCY SETUP\n");
		/* FIXME: continue with CALL_PROCEEDING, ALERTING, CONNECT, RELEASE_COMPLETE */
		break;
	case GSM48_MT_CC_HOLD:
		DEBUGP(DCC, "-> HOLD (rejecting)\n");
		rc = gsm48_tx_simple(msg->lchan, GSM48_PDISC_CC,
				     GSM48_MT_CC_HOLD_REJ);
		break;
	case GSM48_MT_CC_RETR:
		DEBUGP(DCC, "-> RETR (rejecting)\n");
		rc = gsm48_tx_simple(msg->lchan, GSM48_PDISC_CC,
				     GSM48_MT_CC_RETR_REJ);
		break;
	default:
		fprintf(stderr, "Unimplemented GSM 04.08 CC msg type 0x%02x\n",
			msg_type);
		break;
	}

	return rc;
}

/* here we pass in a msgb from the RSL->RLL.  We expect the l3 pointer to be set */
int gsm0408_rcvmsg(struct msgb *msg)
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
		rc = gsm0411_rcv_sms(msg);
		break;
	case GSM48_PDISC_MM_GPRS:
	case GSM48_PDISC_SM_GPRS:
		fprintf(stderr, "Unimplemented GSM 04.08 discriminator 0x%02d\n",
			pdisc);
		break;
	default:
		fprintf(stderr, "Unknown GSM 04.08 discriminator 0x%02d\n",
			pdisc);
		break;
	}

	return rc;
}

enum chreq_type {
	CHREQ_T_EMERG_CALL,
	CHREQ_T_CALL_REEST_TCH_F,
	CHREQ_T_CALL_REEST_TCH_H,
	CHREQ_T_CALL_REEST_TCH_H_DBL,
	CHREQ_T_SDCCH,
	CHREQ_T_TCH_F,
	CHREQ_T_VOICE_CALL_TCH_H,
	CHREQ_T_DATA_CALL_TCH_H,
	CHREQ_T_LOCATION_UPD,
	CHREQ_T_PAG_R_ANY,
	CHREQ_T_PAG_R_TCH_F,
	CHREQ_T_PAG_R_TCH_FH,
};

/* Section 9.1.8 / Table 9.9 */
struct chreq {
	u_int8_t val;
	u_int8_t mask;
	enum chreq_type type;
};

/* If SYSTEM INFORMATION TYPE 4 NECI bit == 1 */
static const struct chreq chreq_type_neci1[] = {
	{ 0xa0, 0xe0, CHREQ_T_EMERG_CALL },
	{ 0xc0, 0xe0, CHREQ_T_CALL_REEST_TCH_F },
	{ 0x68, 0xfc, CHREQ_T_CALL_REEST_TCH_H },
	{ 0x6c, 0xfc, CHREQ_T_CALL_REEST_TCH_H_DBL },
	{ 0xe0, 0xe0, CHREQ_T_SDCCH },
	{ 0x40, 0xf0, CHREQ_T_VOICE_CALL_TCH_H },
	{ 0x50, 0xf0, CHREQ_T_DATA_CALL_TCH_H },
	{ 0x00, 0xf0, CHREQ_T_LOCATION_UPD },
	{ 0x10, 0xf0, CHREQ_T_SDCCH },
	{ 0x80, 0xe0, CHREQ_T_PAG_R_ANY },
	{ 0x20, 0xf0, CHREQ_T_PAG_R_TCH_F },
	{ 0x30, 0xf0, CHREQ_T_PAG_R_TCH_FH },
};

/* If SYSTEM INFORMATION TYPE 4 NECI bit == 0 */
static const struct chreq chreq_type_neci0[] = {
	{ 0xa0, 0xe0, CHREQ_T_EMERG_CALL },
	{ 0xc0, 0xe0, CHREQ_T_CALL_REEST_TCH_H },
	{ 0xe0, 0xe0, CHREQ_T_TCH_F },
	{ 0x50, 0xf0, CHREQ_T_DATA_CALL_TCH_H },
	{ 0x00, 0xe0, CHREQ_T_LOCATION_UPD },
	{ 0x80, 0xe0, CHREQ_T_PAG_R_ANY },
	{ 0x20, 0xf0, CHREQ_T_PAG_R_TCH_F },
	{ 0x30, 0xf0, CHREQ_T_PAG_R_TCH_FH },
};

static const enum gsm_chan_t ctype_by_chreq[] = {
	[CHREQ_T_EMERG_CALL]		= GSM_LCHAN_TCH_F,
	[CHREQ_T_CALL_REEST_TCH_F]	= GSM_LCHAN_TCH_F,
	[CHREQ_T_CALL_REEST_TCH_H]	= GSM_LCHAN_TCH_H,
	[CHREQ_T_CALL_REEST_TCH_H_DBL]	= GSM_LCHAN_TCH_H,
	[CHREQ_T_SDCCH]			= GSM_LCHAN_SDCCH,
	[CHREQ_T_TCH_F]			= GSM_LCHAN_TCH_F,
	[CHREQ_T_VOICE_CALL_TCH_H]	= GSM_LCHAN_TCH_H,
	[CHREQ_T_DATA_CALL_TCH_H]	= GSM_LCHAN_TCH_H,
	[CHREQ_T_LOCATION_UPD]		= GSM_LCHAN_SDCCH,
	[CHREQ_T_PAG_R_ANY]		= GSM_LCHAN_SDCCH,
	[CHREQ_T_PAG_R_TCH_F]		= GSM_LCHAN_TCH_F,
	[CHREQ_T_PAG_R_TCH_FH]		= GSM_LCHAN_TCH_F,
};

static const enum gsm_chreq_reason_t reason_by_chreq[] = {
	[CHREQ_T_EMERG_CALL]		= GSM_CHREQ_REASON_EMERG,
	[CHREQ_T_CALL_REEST_TCH_F]	= GSM_CHREQ_REASON_CALL,
	[CHREQ_T_CALL_REEST_TCH_H]	= GSM_CHREQ_REASON_CALL,
	[CHREQ_T_CALL_REEST_TCH_H_DBL]	= GSM_CHREQ_REASON_CALL,
	[CHREQ_T_SDCCH]			= GSM_CHREQ_REASON_OTHER,
	[CHREQ_T_TCH_F]			= GSM_CHREQ_REASON_OTHER,
	[CHREQ_T_VOICE_CALL_TCH_H]	= GSM_CHREQ_REASON_OTHER,
	[CHREQ_T_DATA_CALL_TCH_H]	= GSM_CHREQ_REASON_OTHER,
	[CHREQ_T_LOCATION_UPD]		= GSM_CHREQ_REASON_LOCATION_UPD,
	[CHREQ_T_PAG_R_ANY]		= GSM_CHREQ_REASON_PAG,
	[CHREQ_T_PAG_R_TCH_F]		= GSM_CHREQ_REASON_PAG,
	[CHREQ_T_PAG_R_TCH_FH]		= GSM_CHREQ_REASON_PAG,
};

enum gsm_chan_t get_ctype_by_chreq(struct gsm_bts *bts, u_int8_t ra)
{
	int i;
	/* FIXME: determine if we set NECI = 0 in the BTS SI4 */

	for (i = 0; i < ARRAY_SIZE(chreq_type_neci0); i++) {
		const struct chreq *chr = &chreq_type_neci0[i];
		if ((ra & chr->mask) == chr->val)
			return ctype_by_chreq[chr->type];
	}
	fprintf(stderr, "Unknown CHANNEL REQUEST RQD 0x%02x\n", ra);
	return GSM_LCHAN_SDCCH;
}

enum gsm_chreq_reason_t get_reason_by_chreq(struct gsm_bts *bts, u_int8_t ra)
{
	int i;
	/* FIXME: determine if we set NECI = 0 in the BTS SI4 */

	for (i = 0; i < ARRAY_SIZE(chreq_type_neci0); i++) {
		const struct chreq *chr = &chreq_type_neci0[i];
		if ((ra & chr->mask) == chr->val)
			return reason_by_chreq[chr->type];
	}
	fprintf(stderr, "Unknown CHANNEL REQUEST REASON 0x%02x\n", ra);
	return GSM_CHREQ_REASON_OTHER;
}
