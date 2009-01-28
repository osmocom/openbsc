/* GSM Network Management (OML) messages on the A-bis interface 
 * 3GPP TS 12.21 version 8.0.0 Release 1999 / ETSI TS 100 623 V8.0.0 */

/* (C) 2008-2009 by Harald Welte <laforge@gnumonks.org>
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


#include <errno.h>
#include <unistd.h>
#include <stdio.h>
#include <fcntl.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <netinet/in.h>

#include <openbsc/gsm_data.h>
#include <openbsc/debug.h>
#include <openbsc/msgb.h>
#include <openbsc/tlv.h>
#include <openbsc/abis_nm.h>
#include <openbsc/misdn.h>

#define OM_ALLOC_SIZE		1024
#define OM_HEADROOM_SIZE	128

/* unidirectional messages from BTS to BSC */
static const enum abis_nm_msgtype reports[] = {
	NM_MT_SW_ACTIVATED_REP,
	NM_MT_TEST_REP,
	NM_MT_STATECHG_EVENT_REP,
	NM_MT_FAILURE_EVENT_REP,
};

/* messages without ACK/NACK */
static const enum abis_nm_msgtype no_ack_nack[] = {
	NM_MT_MEAS_RES_REQ,
	NM_MT_STOP_MEAS,
	NM_MT_START_MEAS,
};

/* Messages related to software load */
static const enum abis_nm_msgtype sw_load_msgs[] = {
	NM_MT_LOAD_INIT_ACK,
	NM_MT_LOAD_INIT_NACK,
	NM_MT_LOAD_SEG_ACK,
	NM_MT_LOAD_ABORT,
	NM_MT_LOAD_END_ACK,
	NM_MT_LOAD_END_NACK,
	NM_MT_SW_ACT_REQ,
	NM_MT_ACTIVATE_SW_ACK,
	NM_MT_ACTIVATE_SW_NACK,
	NM_MT_SW_ACTIVATED_REP,
};

/* Attributes that the BSC can set, not only get, according to Section 9.4 */
static const enum abis_nm_attr nm_att_settable[] = {
	NM_ATT_ADD_INFO,
	NM_ATT_ADD_TEXT,
	NM_ATT_DEST,
	NM_ATT_EVENT_TYPE,
	NM_ATT_FILE_DATA,
	NM_ATT_GET_ARI,
	NM_ATT_HW_CONF_CHG,
	NM_ATT_LIST_REQ_ATTR,
	NM_ATT_MDROP_LINK,
	NM_ATT_MDROP_NEXT,
	NM_ATT_NACK_CAUSES,
	NM_ATT_OUTST_ALARM,
	NM_ATT_PHYS_CONF,
	NM_ATT_PROB_CAUSE,
	NM_ATT_RAD_SUBC,
	NM_ATT_SOURCE,
	NM_ATT_SPEC_PROB,
	NM_ATT_START_TIME,
	NM_ATT_TEST_DUR,
	NM_ATT_TEST_NO,
	NM_ATT_TEST_REPORT,
	NM_ATT_WINDOW_SIZE,
	NM_ATT_SEVERITY,
	NM_ATT_MEAS_RES,
	NM_ATT_MEAS_TYPE,
};

static int is_in_arr(enum abis_nm_msgtype mt, const enum abis_nm_msgtype *arr, int size)
{
	int i;

	for (i = 0; i < size; i++) {
		if (arr[i] == mt)
			return 1;
	}

	return 0;
}

#if 0
/* is this msgtype the usual ACK/NACK type ? */
static int is_ack_nack(enum abis_nm_msgtype mt)
{
	return !is_in_arr(mt, no_ack_nack, ARRAY_SIZE(no_ack_nack));
}
#endif

/* is this msgtype a report ? */
static int is_report(enum abis_nm_msgtype mt)
{
	return is_in_arr(mt, reports, ARRAY_SIZE(reports));
}

#define MT_ACK(x)	(x+1)
#define MT_NACK(x)	(x+2)

static void fill_om_hdr(struct abis_om_hdr *oh, u_int8_t len)
{
	oh->mdisc = ABIS_OM_MDISC_FOM;
	oh->placement = ABIS_OM_PLACEMENT_ONLY;
	oh->sequence = 0;
	oh->length = len;
}

static void fill_om_fom_hdr(struct abis_om_hdr *oh, u_int8_t len,
			    u_int8_t msg_type, u_int8_t obj_class,
			    u_int8_t bts_nr, u_int8_t trx_nr, u_int8_t ts_nr)
{
	struct abis_om_fom_hdr *foh =
			(struct abis_om_fom_hdr *) oh->data;

	fill_om_hdr(oh, len+sizeof(*foh));
	foh->msg_type = msg_type;
	foh->obj_class = obj_class;
	foh->obj_inst.bts_nr = bts_nr;
	foh->obj_inst.trx_nr = trx_nr;
	foh->obj_inst.ts_nr = ts_nr;
}

static struct msgb *nm_msgb_alloc(void)
{
	return msgb_alloc_headroom(OM_ALLOC_SIZE, OM_HEADROOM_SIZE);
}

/* Send a OML NM Message from BSC to BTS */
int abis_nm_sendmsg(struct gsm_bts *bts, struct msgb *msg)
{
	return _abis_nm_sendmsg(msg);
}

static int abis_nm_rcvmsg_sw(struct msgb *mb);

/* Receive a OML NM Message from BTS */
static int abis_nm_rcvmsg_fom(struct msgb *mb)
{
	struct abis_om_fom_hdr *foh = msgb_l3(mb);
	u_int8_t mt = foh->msg_type;

	/* check for unsolicited message */
	if (is_report(mt)) {
		DEBUGP(DNM, "reporting NM MT 0x%02x\n", mt);
		//nmh->cfg->report_cb(mb, foh);
		return 0;
	}

	if (is_in_arr(mt, sw_load_msgs, ARRAY_SIZE(sw_load_msgs)))
		return abis_nm_rcvmsg_sw(mb);

#if 0
	/* check if last message is to be acked */
	if (is_ack_nack(nmh->last_msgtype)) {
		if (mt == MT_ACK(nmh->last_msgtype)) {
			fprintf(stderr, "received ACK (0x%x)\n",
				foh->msg_type);
			/* we got our ACK, continue sending the next msg */
		} else if (mt == MT_NACK(nmh->last_msgtype)) {
			/* we got a NACK, signal this to the caller */
			fprintf(stderr, "received NACK (0x%x)\n",
				foh->msg_type);
			/* FIXME: somehow signal this to the caller */
		} else {
			/* really strange things happen */
			return -EINVAL;
		}
	}
#endif

	return 0;
}

/* High-Level API */
/* Entry-point where L2 OML from BTS enters the NM code */
int abis_nm_rcvmsg(struct msgb *msg)
{
	int rc;
	struct abis_om_hdr *oh = msgb_l2(msg);

	/* Various consistency checks */
	if (oh->placement != ABIS_OM_PLACEMENT_ONLY) {
		fprintf(stderr, "ABIS OML placement 0x%x not supported\n",
			oh->placement);
		return -EINVAL;
	}
	if (oh->sequence != 0) {
		fprintf(stderr, "ABIS OML sequence 0x%x != 0x00\n",
			oh->sequence);
		return -EINVAL;
	}
#if 0
	unsigned int l2_len = msg->tail - (u_int8_t *)msgb_l2(msg);
	unsigned int hlen = sizeof(*oh) + sizeof(struct abis_om_fom_hdr);
	if (oh->length + hlen > l2_len) {
		fprintf(stderr, "ABIS OML truncated message (%u > %u)\n",
			oh->length + sizeof(*oh), l2_len);
		return -EINVAL;
	}
	if (oh->length + hlen < l2_len)
		fprintf(stderr, "ABIS OML message with extra trailer?!? (oh->len=%d, sizeof_oh=%d l2_len=%d\n", oh->length, sizeof(*oh), l2_len);
#endif
	msg->l3h = (unsigned char *)oh + sizeof(*oh);

	switch (oh->mdisc) {
	case ABIS_OM_MDISC_FOM:
		rc = abis_nm_rcvmsg_fom(msg);
		break;
	case ABIS_OM_MDISC_MMI:
	case ABIS_OM_MDISC_TRAU:
	case ABIS_OM_MDISC_MANUF:
	default:
		fprintf(stderr, "unknown ABIS OML message discriminator 0x%x\n",
			oh->mdisc);
		return -EINVAL;
	}

	msgb_free(msg);
	return rc;
}

#if 0
/* initialized all resources */
struct abis_nm_h *abis_nm_init(struct abis_nm_cfg *cfg)
{
	struct abis_nm_h *nmh;

	nmh = malloc(sizeof(*nmh));
	if (!nmh)
		return NULL;

	nmh->cfg = cfg;

	return nmh;
}

/* free all resources */
void abis_nm_fini(struct abis_nm_h *nmh)
{
	free(nmh);
}
#endif

/* Here we are trying to define a high-level API that can be used by
 * the actual BSC implementation.  However, the architecture is currently
 * still under design.  Ideally the calls to this API would be synchronous,
 * while the underlying stack behind the APi runs in a traditional select
 * based state machine.
 */

/* 6.2 Software Load: */
enum sw_state {
	SW_STATE_NONE,
	SW_STATE_WAIT_INITACK,
	SW_STATE_WAIT_SEGACK,
	SW_STATE_WAIT_ENDACK,
	SW_STATE_WAIT_ACTACK,
	SW_STATE_ERROR,
};

struct abis_nm_sw {
	struct gsm_bts *bts;
	/* this will become part of the SW LOAD INITIATE */
	u_int8_t obj_class;
	u_int8_t obj_instance[3];

	u_int8_t file_id[255];
	u_int8_t file_id_len;

	u_int8_t file_version[255];
	u_int8_t file_version_len;

	u_int8_t window_size;
	u_int8_t seg_in_window;

	int fd;
	FILE *stream;
	enum sw_state state;
};

static struct abis_nm_sw g_sw;

/* 6.2.1 / 8.3.1: Load Data Initiate */
static int sw_load_init(struct abis_nm_sw *sw)
{
	struct abis_om_hdr *oh;
	struct msgb *msg = nm_msgb_alloc();
	u_int8_t len = 3*2 + sw->file_id_len + sw->file_version_len;

	oh = (struct abis_om_hdr *) msgb_put(msg, ABIS_OM_FOM_HDR_SIZE);
	fill_om_fom_hdr(oh, len, NM_MT_LOAD_INIT, sw->obj_class,
			sw->obj_instance[0], sw->obj_instance[1],
			sw->obj_instance[2]);
	
	/* FIXME: this is BS11 specific format */
	msgb_tlv_put(msg, NM_ATT_FILE_ID, sw->file_id_len, sw->file_id);
	msgb_tlv_put(msg, NM_ATT_FILE_VERSION, sw->file_version_len,
		     sw->file_version);
	msgb_tv_put(msg, NM_ATT_WINDOW_SIZE, sw->window_size);
	
	return abis_nm_sendmsg(sw->bts, msg);
}

/* 6.2.2 / 8.3.2 Load Data Segment */
static int sw_load_segment(struct abis_nm_sw *sw)
{
	struct abis_om_hdr *oh;
	struct msgb *msg = nm_msgb_alloc();
	char seg_buf[256];
	char *line_buf = seg_buf+2;
	u_int8_t len;
	int rc;

	oh = (struct abis_om_hdr *) msgb_put(msg, ABIS_OM_FOM_HDR_SIZE);
	/* FIXME: this is BS11 specific format */
	rc = fscanf(sw->stream, "%s\r\n", line_buf);
	if (rc < 1) {
		perror("fscanf reading segment");
		return -EINVAL;
	}
	seg_buf[0] = 0x00;
	seg_buf[1] = sw->seg_in_window++;

	msgb_tlv_put(msg, NM_ATT_FILE_DATA, 2+strlen(line_buf), 
		     (u_int8_t *)seg_buf);
	/* BS11 wants CR + LF in excess of the TLV length !?! */
	msgb_tv_put(msg, 0x0d, 0x0a);

	/* we only now know the exact length for the OM hdr */
	len = 2+strlen(line_buf)+2;
	fill_om_fom_hdr(oh, len, NM_MT_LOAD_SEG, sw->obj_class,
			sw->obj_instance[0], sw->obj_instance[1],
			sw->obj_instance[2]);

	return abis_nm_sendmsg(sw->bts, msg);
}

/* 6.2.4 / 8.3.4 Load Data End */
static int sw_load_end(struct abis_nm_sw *sw)
{
	struct abis_om_hdr *oh;
	struct msgb *msg = nm_msgb_alloc();
	u_int8_t len = 2*2 + sw->file_id_len + sw->file_version_len;

	oh = (struct abis_om_hdr *) msgb_put(msg, ABIS_OM_FOM_HDR_SIZE);
	fill_om_fom_hdr(oh, len, NM_MT_LOAD_END, sw->obj_class,
			sw->obj_instance[0], sw->obj_instance[1],
			sw->obj_instance[2]);

	/* FIXME: this is BS11 specific format */
	msgb_tlv_put(msg, NM_ATT_FILE_ID, sw->file_id_len, sw->file_id);
	msgb_tlv_put(msg, NM_ATT_FILE_VERSION, sw->file_version_len,
		     sw->file_version);

	return abis_nm_sendmsg(sw->bts, msg);
}
/* Activate the specified software into the BTS */
static int sw_activate(struct abis_nm_sw *sw)
{
	struct abis_om_hdr *oh;
	struct msgb *msg = nm_msgb_alloc();
	u_int8_t len = 2*2 + sw->file_id_len + sw->file_version_len;

	oh = (struct abis_om_hdr *) msgb_put(msg, ABIS_OM_FOM_HDR_SIZE);
	fill_om_fom_hdr(oh, len, NM_MT_ACTIVATE_SW, sw->obj_class,
			sw->obj_instance[0], sw->obj_instance[1],
			sw->obj_instance[2]);

	/* FIXME: this is BS11 specific format */
	msgb_tlv_put(msg, NM_ATT_FILE_ID, sw->file_id_len, sw->file_id);
	msgb_tlv_put(msg, NM_ATT_FILE_VERSION, sw->file_version_len,
		     sw->file_version);

	return abis_nm_sendmsg(sw->bts, msg);
}

static int sw_open_file(struct abis_nm_sw *sw, const char *fname)
{
	char file_id[12+1];
	char file_version[80+1];
	int rc;

	sw->fd = open(fname, O_RDONLY);
	if (sw->fd < 0)
		return sw->fd;

	switch (sw->bts->type) {
	case GSM_BTS_TYPE_BS11:
		sw->stream = fdopen(sw->fd, "r");
		if (!sw->stream) {
			perror("fdopen");
			return -1;
		}
		/* read first line and parse file ID and VERSION */
		rc = fscanf(sw->stream, "@(@)%12s:%80s\r\n", 
			    file_id, file_version);
		if (rc != 2) {
			perror("parsing header line of software file");
			return -1;
		}
		strcpy((char *)sw->file_id, file_id);
		sw->file_id_len = strlen(file_id);
		strcpy((char *)sw->file_version, file_version);
		sw->file_version_len = strlen(file_version);
		/* rewind to start of file */
		fseek(sw->stream, 0, SEEK_SET);
		break;	
	default:
		/* We don't know how to treat them yet */
		close(sw->fd);
		return -EINVAL;
	}

	return 0;
}
	
static void sw_close_file(struct abis_nm_sw *sw)
{
	switch (sw->bts->type) {
	case GSM_BTS_TYPE_BS11:
		fclose(sw->stream);
		break;
	default:
		close(sw->fd);
		break;
	}
}

/* Fill the window */
static int sw_fill_window(struct abis_nm_sw *sw)
{
	int rc;

	while (sw->seg_in_window < sw->window_size) {
		rc = sw_load_segment(sw);
		if (rc < 0)
			return rc;
		if (rc == 1) {
			sw->state = SW_STATE_WAIT_ENDACK;
			return sw_load_end(sw);
		}
	}
	return 0;
}

/* callback function from abis_nm_rcvmsg() handler */
static int abis_nm_rcvmsg_sw(struct msgb *mb)
{
	struct abis_om_fom_hdr *foh = msgb_l3(mb);
	int rc = -1;
	struct abis_nm_sw *sw = &g_sw;
	enum sw_state old_state = sw->state;
	
	DEBUGP(DNM, "state %u, NM MT 0x%02x\n", sw->state, foh->msg_type);

	switch (sw->state) {
	case SW_STATE_WAIT_INITACK:
		switch (foh->msg_type) {
		case NM_MT_LOAD_INIT_ACK:
			/* fill window with segments */
			rc = sw_fill_window(sw);
			sw->state = SW_STATE_WAIT_SEGACK;
			break;
		case NM_MT_LOAD_INIT_NACK:
			sw->state = SW_STATE_ERROR;
			break;
		}
		break;
	case SW_STATE_WAIT_SEGACK:
		switch (foh->msg_type) {
		case NM_MT_LOAD_SEG_ACK:
			sw->seg_in_window = 0;
			/* fill window with more segments */
			rc = sw_fill_window(sw);
			sw->state = SW_STATE_WAIT_SEGACK;
			break;
		}
		break;
	case SW_STATE_WAIT_ENDACK:
		switch (foh->msg_type) {
		case NM_MT_LOAD_END_ACK:
			sw_close_file(sw);
			/* send activate request */
			sw->state = SW_STATE_WAIT_ACTACK;
			rc = sw_activate(sw);
			break;
		case NM_MT_LOAD_END_NACK:
			sw->state = SW_STATE_ERROR;
			break;
		}
	case SW_STATE_WAIT_ACTACK:
		switch (foh->msg_type) {
		case NM_MT_ACTIVATE_SW_ACK:
			/* we're done */
			sw->state = SW_STATE_NONE;
			rc = 0;
			DEBUGP(DMM, "DONE!\n");
			break;
		case NM_MT_ACTIVATE_SW_NACK:
			sw->state = SW_STATE_ERROR;
			break;
		}
	case SW_STATE_NONE:
	case SW_STATE_ERROR:
		break;
	}

	if (rc)
		fprintf(stderr, "unexpected NM MT 0x%02x in state %u -> %u\n",
			foh->msg_type, old_state, sw->state);

	return rc;
}

/* Load the specified software into the BTS */
int abis_nm_software_load(struct gsm_bts *bts, const char *fname,
			  u_int8_t win_size)
{
	struct abis_nm_sw *sw = &g_sw;
	int rc;

	if (sw->state != SW_STATE_NONE)
		return -EBUSY;

	sw->bts = bts;
	sw->obj_class = NM_OC_SITE_MANAGER;
	sw->obj_instance[0] = 0xff;
	sw->obj_instance[1] = 0xff;
	sw->obj_instance[2] = 0xff;
	sw->window_size = win_size;
	sw->state = SW_STATE_WAIT_INITACK;

	rc = sw_open_file(sw, fname);
	if (rc < 0) {
		sw->state = SW_STATE_NONE;
		return rc;
	}

	return sw_load_init(sw);
}

static void fill_nm_channel(struct abis_nm_channel *ch, u_int8_t bts_port,
		       u_int8_t ts_nr, u_int8_t subslot_nr)
{
	ch->attrib = NM_ATT_ABIS_CHANNEL;
	ch->bts_port = bts_port;
	ch->timeslot = ts_nr;
	ch->subslot = subslot_nr;	
}

int abis_nm_establish_tei(struct gsm_bts *bts, u_int8_t trx_nr,
			  u_int8_t e1_port, u_int8_t e1_timeslot, u_int8_t e1_subslot,
			  u_int8_t tei)
{
	struct abis_om_hdr *oh;
	struct abis_nm_channel *ch;
	u_int8_t len = sizeof(*ch) + 2;
	struct msgb *msg = nm_msgb_alloc();

	oh = (struct abis_om_hdr *) msgb_put(msg, ABIS_OM_FOM_HDR_SIZE);
	fill_om_fom_hdr(oh, len, NM_MT_ESTABLISH_TEI, NM_OC_RADIO_CARRIER,
			bts->bts_nr, trx_nr, 0xff);
	
	msgb_tv_put(msg, NM_ATT_TEI, tei);

	ch = (struct abis_nm_channel *) msgb_put(msg, sizeof(*ch));
	fill_nm_channel(ch, e1_port, e1_timeslot, e1_subslot);

	return abis_nm_sendmsg(bts, msg);
}

/* connect signalling of one (BTS,TRX) to a particular timeslot on the E1 */
int abis_nm_conn_terr_sign(struct gsm_bts_trx *trx,
			   u_int8_t e1_port, u_int8_t e1_timeslot, u_int8_t e1_subslot)
{
	struct gsm_bts *bts = trx->bts;
	struct abis_om_hdr *oh;
	struct abis_nm_channel *ch;
	struct msgb *msg = nm_msgb_alloc();

	oh = (struct abis_om_hdr *) msgb_put(msg, ABIS_OM_FOM_HDR_SIZE);
	fill_om_fom_hdr(oh, sizeof(*ch), NM_MT_CONN_TERR_SIGN,
			NM_OC_RADIO_CARRIER, bts->bts_nr, trx->nr, 0xff);
	
	ch = (struct abis_nm_channel *) msgb_put(msg, sizeof(*ch));
	fill_nm_channel(ch, e1_port, e1_timeslot, e1_subslot);

	return abis_nm_sendmsg(bts, msg);
}

#if 0
int abis_nm_disc_terr_sign(struct abis_nm_h *h, struct abis_om_obj_inst *inst,
			   struct abis_nm_abis_channel *chan)
{
}
#endif

int abis_nm_conn_terr_traf(struct gsm_bts_trx_ts *ts,
			   u_int8_t e1_port, u_int8_t e1_timeslot,
			   u_int8_t e1_subslot)
{
	struct gsm_bts *bts = ts->trx->bts;
	struct abis_om_hdr *oh;
	struct abis_nm_channel *ch;
	struct msgb *msg = nm_msgb_alloc();

	oh = (struct abis_om_hdr *) msgb_put(msg, ABIS_OM_FOM_HDR_SIZE);
	fill_om_fom_hdr(oh, sizeof(*ch), NM_MT_CONN_TERR_TRAF,
			NM_OC_BASEB_TRANSC, bts->bts_nr, ts->trx->nr, ts->nr);

	ch = (struct abis_nm_channel *) msgb_put(msg, sizeof(*ch));
	fill_nm_channel(ch, e1_port, e1_timeslot, e1_subslot);

	return abis_nm_sendmsg(bts, msg);
}

#if 0
int abis_nm_disc_terr_traf(struct abis_nm_h *h, struct abis_om_obj_inst *inst,
			   struct abis_nm_abis_channel *chan,
			   u_int8_t subchan)
{
}
#endif

int abis_nm_set_channel_attr(struct gsm_bts_trx_ts *ts, u_int8_t chan_comb)
{
	struct gsm_bts *bts = ts->trx->bts;
	struct abis_om_hdr *oh;
	u_int16_t arfcn = htons(ts->trx->arfcn);
	u_int8_t zero = 0x00;
	struct msgb *msg = nm_msgb_alloc();
	u_int8_t len = 4 + 2 + 2 + 2 + 2 +3;

	oh = (struct abis_om_hdr *) msgb_put(msg, ABIS_OM_FOM_HDR_SIZE);
	fill_om_fom_hdr(oh, len, NM_MT_SET_CHAN_ATTR,
			NM_OC_BASEB_TRANSC, bts->bts_nr,
			ts->trx->nr, ts->nr);
	/* FIXME: don't send ARFCN list, hopping sequence, mAIO, ...*/
	msgb_tlv16_put(msg, NM_ATT_ARFCN_LIST, 1, &arfcn);
	msgb_tv_put(msg, NM_ATT_CHAN_COMB, chan_comb);
	msgb_tv_put(msg, NM_ATT_HSN, 0x00);
	msgb_tv_put(msg, NM_ATT_MAIO, 0x00);
	msgb_tv_put(msg, NM_ATT_TSC, 0x07);	/* training sequence */
	msgb_tlv_put(msg, 0x59, 1, &zero);

	return abis_nm_sendmsg(bts, msg);
}

int abis_nm_raw_msg(struct gsm_bts *bts, int len, u_int8_t *rawmsg)
{
	struct msgb *msg = nm_msgb_alloc();
	struct abis_om_hdr *oh;
	u_int8_t *data;

	oh = (struct abis_om_hdr *) msgb_put(msg, sizeof(*oh));
	fill_om_hdr(oh, len);
	data = msgb_put(msg, len);
	memcpy(data, rawmsg, len);

	return abis_nm_sendmsg(bts, msg);
}

/* Siemens specific commands */
static int __simple_cmd(struct gsm_bts *bts, u_int8_t msg_type)
{
	struct abis_om_hdr *oh;
	struct msgb *msg = nm_msgb_alloc();

	oh = (struct abis_om_hdr *) msgb_put(msg, ABIS_OM_FOM_HDR_SIZE);
	fill_om_fom_hdr(oh, 0, msg_type, NM_OC_SITE_MANAGER,
			0xff, 0xff, 0xff);

	return abis_nm_sendmsg(bts, msg);
}

int abis_nm_event_reports(struct gsm_bts *bts, int on)
{
	if (on == 0)
		return __simple_cmd(bts, NM_MT_STOP_EVENT_REP);
	else
		return __simple_cmd(bts, NM_MT_REST_EVENT_REP);
}

/* Siemens (or BS-11) specific commands */

int abis_nm_bs11_reset_resource(struct gsm_bts *bts)
{
	return __simple_cmd(bts, NM_MT_BS11_RESET_RESOURCE);
}

int abis_nm_bs11_db_transmission(struct gsm_bts *bts, int begin)
{
	if (begin)
		return __simple_cmd(bts, NM_MT_BS11_BEGIN_DB_TX);
	else
		return __simple_cmd(bts, NM_MT_BS11_END_DB_TX);
}

int abis_nm_bs11_create_object(struct gsm_bts *bts,
				enum abis_bs11_objtype type, u_int8_t idx,
				u_int8_t attr_len, const u_int8_t *attr)
{
	struct abis_om_hdr *oh;
	struct msgb *msg = nm_msgb_alloc();
	u_int8_t *cur;

	oh = (struct abis_om_hdr *) msgb_put(msg, ABIS_OM_FOM_HDR_SIZE);
	fill_om_fom_hdr(oh, attr_len, NM_MT_BS11_CREATE_OBJ,
			NM_OC_BS11, type, idx, 0);
	cur = msgb_put(msg, attr_len);
	memcpy(cur, attr, attr_len);

	return abis_nm_sendmsg(bts, msg);
}

int abis_nm_bs11_create_envaBTSE(struct gsm_bts *bts, u_int8_t idx)
{
	struct abis_om_hdr *oh;
	struct msgb *msg = nm_msgb_alloc();
	u_int8_t zero = 0x00;

	oh = (struct abis_om_hdr *) msgb_put(msg, ABIS_OM_FOM_HDR_SIZE);
	fill_om_fom_hdr(oh, 3, NM_MT_BS11_CREATE_OBJ,
			NM_OC_BS11_ENVABTSE, 0, idx, 0xff);
	msgb_tlv_put(msg, 0x99, 1, &zero);

	return abis_nm_sendmsg(bts, msg);
}

int abis_nm_bs11_create_bport(struct gsm_bts *bts, u_int8_t idx)
{
	struct abis_om_hdr *oh;
	struct msgb *msg = nm_msgb_alloc();

	oh = (struct abis_om_hdr *) msgb_put(msg, ABIS_OM_FOM_HDR_SIZE);
	fill_om_fom_hdr(oh, 0, NM_MT_BS11_CREATE_OBJ, NM_OC_BS11_BPORT,
			idx, 0, 0);

	return abis_nm_sendmsg(bts, msg);
}

int abis_nm_bs11_set_oml_tei(struct gsm_bts *bts, u_int8_t tei)
{
	struct abis_om_hdr *oh;
	struct msgb *msg = nm_msgb_alloc();

	oh = (struct abis_om_hdr *) msgb_put(msg, ABIS_OM_FOM_HDR_SIZE);
	fill_om_fom_hdr(oh, 2, NM_MT_BS11_SET_ATTR, NM_OC_SITE_MANAGER,
			0xff, 0xff, 0xff);
	msgb_tv_put(msg, NM_ATT_TEI, tei);

	return abis_nm_sendmsg(bts, msg);
}

/* like abis_nm_conn_terr_traf */
int abis_nm_bs11_conn_oml(struct gsm_bts *bts, u_int8_t e1_port, 
			  u_int8_t e1_timeslot, u_int8_t e1_subslot)
{
	struct abis_om_hdr *oh;
	struct abis_nm_channel *ch;
	struct msgb *msg = nm_msgb_alloc();

	oh = (struct abis_om_hdr *) msgb_put(msg, ABIS_OM_FOM_HDR_SIZE);
	fill_om_fom_hdr(oh, sizeof(*ch), NM_MT_BS11_SET_ATTR,
			NM_OC_SITE_MANAGER, 0xff, 0xff, 0xff);

	ch = (struct abis_nm_channel *) msgb_put(msg, sizeof(*ch));
	fill_nm_channel(ch, e1_port, e1_timeslot, e1_subslot);

	return abis_nm_sendmsg(bts, msg);
}

int abis_nm_bs11_set_trx_power(struct gsm_bts_trx *trx, u_int8_t level)
{
	struct abis_om_hdr *oh;
	struct msgb *msg = nm_msgb_alloc();

	oh = (struct abis_om_hdr *) msgb_put(msg, ABIS_OM_FOM_HDR_SIZE);
	fill_om_fom_hdr(oh, 3, NM_MT_BS11_SET_ATTR,
			NM_OC_BS11, BS11_OBJ_PA, 0x00, trx->nr);
	msgb_tlv_put(msg, NM_ATT_BS11_TXPWR, 1, &level);

	return abis_nm_sendmsg(trx->bts, msg);
}

static const u_int8_t bs11_logon_c7[] = 
	{ 0x07, 0xd9, 0x01, 0x11, 0x0d, 0x10, 0x20 };
static const u_int8_t bs11_logon_c8[] = { 0x02 };
static const u_int8_t bs11_logon_c9[] = "FACTORY";

int abis_nm_bs11_factory_logon(struct gsm_bts *bts, int on)
{
	struct abis_om_hdr *oh;
	struct msgb *msg = nm_msgb_alloc();

	oh = (struct abis_om_hdr *) msgb_put(msg, ABIS_OM_FOM_HDR_SIZE);
	if (on) {
		u_int8_t len = 3*2 + sizeof(bs11_logon_c7)
				+ sizeof(bs11_logon_c8) + sizeof(bs11_logon_c9);
		fill_om_fom_hdr(oh, len, NM_MT_BS11_FACTORY_LOGON,
				NM_OC_BS11_A3, 0xff, 0xff, 0xff);
		msgb_tlv_put(msg, 0xc7, sizeof(bs11_logon_c7), bs11_logon_c7);
		msgb_tlv_put(msg, 0xc8, sizeof(bs11_logon_c8), bs11_logon_c8);
		msgb_tlv_put(msg, 0xc9, sizeof(bs11_logon_c9), bs11_logon_c9);
	} else {
		fill_om_fom_hdr(oh, 0, NM_MT_BS11_LOGOFF,
				NM_OC_BS11_A3, 0xff, 0xff, 0xff);
	}
	
	return abis_nm_sendmsg(bts, msg);
}

int abis_nm_bs11_set_trx1_pw(struct gsm_bts *bts, const char *password)
{
	struct abis_om_hdr *oh;
	struct msgb *msg;

	if (strlen(password) != 10)
		return -EINVAL;

 	msg = nm_msgb_alloc();
	oh = (struct abis_om_hdr *) msgb_put(msg, ABIS_OM_FOM_HDR_SIZE);
	fill_om_fom_hdr(oh, 2+strlen(password), NM_MT_BS11_SET_ATTR,
			NM_OC_BS11, BS11_OBJ_TRX1, 0x00, 0x00);
	msgb_tlv_put(msg, NM_ATT_BS11_PASSWORD, 10, (const u_int8_t *)password);

	return abis_nm_sendmsg(bts, msg);
}

int abis_nm_bs11_get_state(struct gsm_bts *bts)
{
	return __simple_cmd(bts, NM_MT_BS11_GET_STATE);
}
